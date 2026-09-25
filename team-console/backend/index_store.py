"""Credential-free, read-only projection of legacy files; queries never scan JSON."""
from __future__ import annotations

import json
import logging
import math
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

logger = logging.getLogger(__name__)
SAFE_FIELDS = (
    "id", "email", "user_name", "note", "registration_driver", "email_source",
    "plan_type", "current_plan_type", "subscription_plan", "registration_batch_id",
    "created_at", "updated_at", "codex_last_failure_stage", "codex_status",
    "quota_status", "quota_checked_at", "quota_ok", "quota_plan_type", "quota_source",
    "quota_primary_used_percent", "quota_primary_limit_window_seconds", "quota_primary_reset_at",
    "quota_secondary_used_percent", "quota_secondary_limit_window_seconds", "quota_secondary_reset_at",
    "team_status", "team_workspace_id", "team_seat_type", "team_seat_status",
    "team_parent_id", "codex_plan_type", "web_cookie_capture_status",
)
DERIVED_FIELDS = ("archived", "has_codex_refresh_token", "has_web_cookie", "totp_status", "codex_connection_state")
ACCOUNT_FIELDS = (*SAFE_FIELDS, *DERIVED_FIELDS)
# A progress file must not be able to replace identity or credential-presence flags.
PROGRESS_FIELDS = set(SAFE_FIELDS) - {"id", "email", "created_at", "registration_batch_id"}
PROGRESS_FIELDS.add("totp_status")
BATCH_FIELDS = ("batch_id", "created_at", "updated_at", "email_source", "registration_driver", "count")


def scalar(value):
    return value if isinstance(value, (str, int, float, bool)) or value is None else None


def safe_projection(row: dict) -> dict:
    out = {key: scalar(row.get(key)) for key in SAFE_FIELDS}
    for key in ('quota_primary_used_percent', 'quota_secondary_used_percent'):
        try:
            number = float(out[key])
            out[key] = number if math.isfinite(number) else None
        except (ValueError, TypeError):
            out[key] = None
    try:
        out["id"] = int(row.get("id") or 0)
    except (ValueError, TypeError):
        out["id"] = 0
    out["email"] = str(scalar(row.get("email")) or "")
    out["archived"] = bool(row.get("archived"))
    out["has_codex_refresh_token"] = bool(row.get("codex_refresh_token") or row.get("has_codex_refresh_token"))
    out["has_web_cookie"] = bool(row.get("has_web_cookies") or row.get("web_cookie_has_session") or row.get("has_web_cookie"))
    status = str(row.get("totp_status") or "").lower()
    out["totp_status"] = status if status in {"active", "active_external", "queued", "running", "activation_uncertain", "failed", "not_configured"} else ("active" if row.get("totp_secret") else "not_configured")
    out["codex_connection_state"] = "connected" if out["has_codex_refresh_token"] else (
        "running" if str(row.get("codex_status") or "").lower() in {"queued", "running", "retrying"} else "not_connected")
    out["quota_status"] = out["quota_status"] or ("success" if row.get("quota_ok") is True else "unchecked")
    out["registration_driver"] = out["registration_driver"] or "legacy"
    out["codex_plan_type"] = str(out["codex_plan_type"] or "").strip().lower()
    return out


def safe_batch_projection(row: dict) -> dict:
    snapshot = row.get("flow_snapshot") if isinstance(row.get("flow_snapshot"), dict) else {}
    raw_drivers = row.get("registration_drivers")
    if not isinstance(raw_drivers, list):
        raw_drivers = [row.get("registration_driver") or snapshot.get("registration_driver") or "legacy"]
    drivers = sorted({value.strip().lower() for value in raw_drivers if isinstance(value, str) and value.strip()}) or ["legacy"]
    out = {key: scalar(row.get(key)) for key in BATCH_FIELDS}
    out["batch_id"] = str(row.get("batch_id") or row.get("id") or "")
    out["registration_driver"] = drivers[0] if len(drivers) == 1 else "mixed"
    out["registration_drivers"] = drivers
    sources = row.get("email_sources")
    out["email_source"] = ", ".join(value for value in sources if isinstance(value, str)) if isinstance(sources, list) else str(out["email_source"] or "")
    # Never copy flow_snapshot, merge_sources, provider responses or arbitrary keys.
    return out


def file_signature(path: Path):
    try:
        stat = path.stat()
        return (stat.st_mtime_ns, stat.st_size, stat.st_ino)
    except FileNotFoundError:
        return None


class SourceChanged(RuntimeError):
    pass


class JsonProjectionSource:
    """Read legacy checkpoints without invoking their write/recovery helpers.

    Keep only public projections in memory. Journal-only changes do not reread
    the large checkpoint. Reject mismatched journals and unstable snapshots.
    """
    def __init__(self, path: Path, *, batch=False):
        self.path = Path(path)
        self.batch = batch
        self.project = safe_batch_projection if batch else safe_projection
        self._signature = object()
        self._base = {}

    def signature(self):
        target = self.path.resolve(strict=False)
        return (str(target), file_signature(target), file_signature(target.with_name(target.name + ".progress.json")))

    def __call__(self):
        before = self.signature()
        target = Path(before[0])
        base_signature = before[:2]
        if base_signature != self._signature:
            if before[1] is None:
                # Missing after a successful load is an error, not a mass deletion.
                if self._base:
                    raise SourceChanged("source_missing")
                raw_rows = []
            else:
                raw_rows = json.loads(target.read_text(encoding="utf-8"))
                if not isinstance(raw_rows, list):
                    raise ValueError("invalid_checkpoint")
            base = {}
            for row in raw_rows:
                if not isinstance(row, dict):
                    raise ValueError("invalid_checkpoint_row")
                item = self.project(row)
                key = item["batch_id" if self.batch else "id"]
                if not key or key in base:
                    raise ValueError("invalid_checkpoint_identity")
                base[key] = item
        else:
            base = self._base
        journal = {}
        if before[2] is not None:
            journal = json.loads(target.with_name(target.name + ".progress.json").read_text(encoding="utf-8"))
            if not isinstance(journal, dict):
                raise ValueError("invalid_journal")
        signature_key = "batches_signature" if self.batch else "accounts_signature"
        updates = journal.get("updates") if before[1] and journal.get(signature_key) == list(before[1]) else {}
        if not isinstance(updates, dict):
            updates = {}
        merged = dict(base)
        allowed = {"updated_at"} if self.batch else PROGRESS_FIELDS
        for key, item in base.items():
            update = updates.get(str(key))
            if not isinstance(update, dict) or update.get("created_at") != item.get("created_at"):
                continue
            if not self.batch and update.get("email") != item.get("email"):
                continue
            fields = update.get("fields")
            if isinstance(fields, dict):
                patch = {name: scalar(value) for name, value in fields.items() if name in allowed}
                merged[key] = self.project({**item, **patch})
        if before != self.signature():
            raise SourceChanged("source_changed_during_read")
        self._base, self._signature = base, base_signature
        return list(merged.values())


class SQLiteStore:
    def __init__(self, path):
        self.index_path = Path(path)
        self.index_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.index_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA synchronous=NORMAL")
            with conn:
                yield conn
        finally:
            conn.close()


class AccountIndex(SQLiteStore):
    def __init__(self, source_path, index_path, loader: Callable[[], Iterable[dict]] | None = None):
        super().__init__(index_path)
        self.source_path = Path(source_path)
        self.source = JsonProjectionSource(self.source_path)
        self.loader = loader or self.source
        self._lock = threading.Lock()
        self._signature = object()
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            columns = ",".join(f"{name} {'INTEGER PRIMARY KEY' if name == 'id' else 'REAL' if name.endswith('_percent') else 'INTEGER' if name in {'archived', 'has_codex_refresh_token', 'has_web_cookie', 'quota_ok'} else 'TEXT'}" for name in ACCOUNT_FIELDS)
            conn.execute(f"CREATE TABLE IF NOT EXISTS accounts ({columns})")
            existing = {row[1] for row in conn.execute("PRAGMA table_info(accounts)")}
            for name in ACCOUNT_FIELDS:
                if name not in existing:
                    conn.execute(f"ALTER TABLE accounts ADD COLUMN {name} {'REAL' if name.endswith('_percent') else 'TEXT'}")
            for name in ("email", "registration_batch_id", "codex_connection_state", "codex_plan_type", "totp_status", "quota_status"):
                conn.execute(f"CREATE INDEX IF NOT EXISTS account_{name}_ci ON accounts({name} COLLATE NOCASE)")
            conn.execute("CREATE INDEX IF NOT EXISTS account_batch_plan_ci ON accounts(registration_batch_id COLLATE NOCASE, codex_plan_type COLLATE NOCASE, id DESC) WHERE archived=0")
        self.index_path.chmod(0o600)

    def refresh_if_stale(self, *, force=False):
        with self._lock:
            signature = self.source.signature()
            if not force and signature == self._signature:
                return {"refreshed": False, "changed": 0, "deleted": 0}
            projected = [safe_projection(row) for row in self.loader() if isinstance(row, dict)]
            incoming = {row["id"]: row for row in projected if row["id"] > 0}
            if signature != self.source.signature():
                raise SourceChanged("source_changed_during_projection")
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                current = {row["id"]: dict(row) for row in conn.execute(f"SELECT {','.join(ACCOUNT_FIELDS)} FROM accounts")}
                # Compare with SQLite's storage affinities so numeric text fields
                # do not cause repeated updates after reading the checkpoint.
                def values(row):
                    return tuple(None if row.get(key) is None else float(row[key]) if key.endswith('_percent') else str(int(row[key])) if isinstance(row[key], bool) else str(row[key]) for key in ACCOUNT_FIELDS)
                changed = [row for key, row in incoming.items() if key not in current or values(row) != values(current[key])]
                removed = set(current) - set(incoming)
                if changed:
                    conn.executemany(f"INSERT INTO accounts ({','.join(ACCOUNT_FIELDS)}) VALUES ({','.join('?' for _ in ACCOUNT_FIELDS)}) ON CONFLICT(id) DO UPDATE SET " + ",".join(f"{key}=excluded.{key}" for key in ACCOUNT_FIELDS if key != "id"),
                                     [[row.get(key) for key in ACCOUNT_FIELDS] for row in changed])
                conn.executemany("DELETE FROM accounts WHERE id=?", [(key,) for key in removed])
            self._signature = signature
            return {"refreshed": True, "changed": len(changed), "deleted": len(removed), "count": len(incoming)}

    @staticmethod
    def _where(params):
        clauses, args = ["archived = 0"], []
        q = str(params.get("q") or "").strip()
        if q:
            clauses.append("(email LIKE ? ESCAPE '\\' OR note LIKE ? ESCAPE '\\' OR user_name LIKE ? ESCAPE '\\')")
            needle = '%' + q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
            args.extend([needle] * 3)
        for key, column in (("batch_id", "registration_batch_id"), ("totp_status", "totp_status"), ("codex_state", "codex_connection_state"), ("codex_plan_type", "codex_plan_type"), ("quota_status", "quota_status"), ("team_parent_id", "team_parent_id"), ("team_seat_type", "team_seat_type"), ("team_seat_status", "team_seat_status"), ("driver", "registration_driver"), ("email_source", "email_source")):
            value = str(params.get(key) or "").strip()
            if not value or value in {"all", "any"}:
                continue
            if key == "totp_status" and value == "active":
                clauses.append("totp_status IN ('active','active_external')")
            else:
                clauses.append(f"{column} = ? COLLATE NOCASE")
                args.append(value)
        return ' AND '.join(clauses), args

    def query(self, *, page=1, page_size=50, **params):
        page, page_size = max(1, int(page or 1)), max(1, min(500, int(page_size or 50)))
        where, args = self._where(params)
        sort = params.get("sort_by")
        sort = sort if sort in {"id", "email", "created_at", "updated_at", "registration_driver", "quota_status"} else "id"
        direction = 'ASC' if params.get("sort_order") == 'asc' else 'DESC'
        with self._connect() as conn:
            conn.execute("BEGIN")
            summary = self._summary(conn, where, args)
            total = summary['total']
            page = min(page, max(1, (total + page_size - 1) // page_size))
            rows = conn.execute(f"SELECT {','.join(ACCOUNT_FIELDS)} FROM accounts WHERE {where} ORDER BY {sort} {direction}, id DESC LIMIT ? OFFSET ?", [*args, page_size, (page - 1) * page_size]).fetchall()
        return {"items": [dict(row) for row in rows], "total": total, "page": page, "page_size": page_size, "summary": summary}

    def get(self, account_id):
        with self._connect() as conn:
            row = conn.execute(f"SELECT {','.join(ACCOUNT_FIELDS)} FROM accounts WHERE id=?", (account_id,)).fetchone()
            return dict(row) if row else None

    def by_emails(self, emails):
        wanted = sorted({str(value).strip().casefold() for value in emails if value})
        if not wanted:
            return {}
        if len(wanted) > 100:
            raise ValueError('单页最多匹配 100 个成员')
        matches = {}
        with self._connect() as conn:
            rows = conn.execute(f"SELECT {','.join(ACCOUNT_FIELDS)} FROM accounts WHERE archived=0 AND email COLLATE NOCASE IN ({','.join('?' for _ in wanted)})", wanted)
            for row in rows:
                key = row['email'].strip().casefold()
                matches[key] = None if key in matches else dict(row)
        return matches

    def count(self):
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]

    @staticmethod
    def _summary(conn, where, args):
        row = conn.execute(f"SELECT COUNT(*) total, SUM(codex_connection_state='connected') codex_connected, SUM(totp_status IN ('active','active_external')) totp_active, SUM(quota_status='success') quota_checked FROM accounts WHERE {where}", args).fetchone()
        return {key: int(row[key] or 0) for key in row.keys()}

    def summary(self, *, params=None):
        with self._connect() as conn:
            return self._summary(conn, *self._where(params or {}))


class BatchIndex(SQLiteStore):
    def __init__(self, index_path, loader, account_index, *, source_path=None):
        super().__init__(index_path)
        self.account_index = account_index
        self.source = JsonProjectionSource(source_path or account_index.source_path.parent / '注册批次.json', batch=True)
        self.loader = loader or self.source
        self._signature = object()
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.execute("PRAGMA secure_delete=ON")
            conn.execute("CREATE TABLE IF NOT EXISTS index_meta (key TEXT PRIMARY KEY, value TEXT)")
            version = conn.execute("SELECT value FROM index_meta WHERE key='batch_schema'").fetchone()
            migrate = not version or version[0] != '2'
            if migrate:
                # This is disposable cache only. Never carry raw v1 snapshots forward.
                conn.execute("DROP TABLE IF EXISTS batches")
                conn.execute("DROP TABLE IF EXISTS batch_drivers")
            conn.execute("CREATE TABLE IF NOT EXISTS batches (batch_id TEXT PRIMARY KEY, created_at TEXT, driver TEXT, email_source TEXT, data TEXT NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS batch_drivers (batch_id TEXT, driver TEXT COLLATE NOCASE, PRIMARY KEY(batch_id, driver))")
            conn.execute("CREATE INDEX IF NOT EXISTS batches_created ON batches(created_at)")
            conn.execute("INSERT OR REPLACE INTO index_meta VALUES('batch_schema','2')")
        if migrate:
            # Remove old raw snapshots from freed pages and truncate our cache WAL.
            with self._connect() as conn:
                conn.execute("VACUUM")
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def refresh_if_stale(self, *, force=False):
        with self._lock:
            signature = self.source.signature()
            if not force and signature == self._signature:
                return {"refreshed": False, "changed": 0}
            rows = [safe_batch_projection(row) for row in self.loader() if isinstance(row, dict)]
            incoming = {row['batch_id']: row for row in rows if row['batch_id']}
            if signature != self.source.signature():
                raise SourceChanged('source_changed_during_projection')
            with self._connect() as conn:
                conn.execute('BEGIN IMMEDIATE')
                current = {row[0]: row[1] for row in conn.execute('SELECT batch_id,data FROM batches')}
                changed = 0
                for key, row in incoming.items():
                    data = json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
                    if data == current.get(key):
                        continue
                    conn.execute('INSERT INTO batches VALUES(?,?,?,?,?) ON CONFLICT(batch_id) DO UPDATE SET created_at=excluded.created_at,driver=excluded.driver,email_source=excluded.email_source,data=excluded.data', (key, row['created_at'], row['registration_driver'], row['email_source'], data))
                    conn.execute('DELETE FROM batch_drivers WHERE batch_id=?', (key,))
                    conn.executemany('INSERT INTO batch_drivers VALUES(?,?)', [(key, driver) for driver in row['registration_drivers']])
                    changed += 1
                removed = set(current) - set(incoming)
                conn.executemany('DELETE FROM batches WHERE batch_id=?', [(key,) for key in removed])
                conn.executemany('DELETE FROM batch_drivers WHERE batch_id=?', [(key,) for key in removed])
            self._signature = signature
            return {'refreshed': True, 'changed': changed, 'deleted': len(removed)}

    def query(self, *, page=1, page_size=50, q='', driver=''):
        page, page_size = max(1, int(page or 1)), max(1, min(200, int(page_size or 50)))
        clauses, args = ['1=1'], []
        if q:
            clauses.append("instr(lower(batch_id || ' ' || driver || ' ' || email_source),lower(?))>0")
            args.append(str(q))
        if driver and driver not in {'all', 'any'}:
            clauses.append('EXISTS (SELECT 1 FROM batch_drivers d WHERE d.batch_id=batches.batch_id AND d.driver=? COLLATE NOCASE)')
            args.append(driver)
        where = ' AND '.join(clauses)
        with self._connect() as conn:
            conn.execute('BEGIN')
            total = conn.execute(f'SELECT COUNT(*) FROM batches WHERE {where}', args).fetchone()[0]
            page = min(page, max(1, (total + page_size - 1) // page_size))
            rows = conn.execute(f"SELECT batch_id,data,(SELECT COUNT(*) FROM accounts a WHERE a.registration_batch_id=batches.batch_id AND a.archived=0) account_total FROM batches WHERE {where} ORDER BY created_at DESC,batch_id DESC LIMIT ? OFFSET ?", [*args, page_size, (page - 1) * page_size]).fetchall()
            items = [{**json.loads(row['data']), 'account_total': row['account_total']} for row in rows]
        return {'items': items, 'total': total, 'page': page, 'page_size': page_size}


class IndexRefresher:
    """One bounded background writer. Request handlers only read the last snapshot."""
    def __init__(self, accounts, batches, interval=2.0):
        self.accounts, self.batches = accounts, batches
        self.interval = max(0.1, interval)
        self._wake, self._stop = threading.Event(), threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._state = {'ready': False, 'refreshing': False, 'last_updated_at': None, 'error': None}

    def status(self):
        with self._lock:
            return dict(self._state)

    def refresh_once(self):
        with self._lock:
            self._state['refreshing'] = True
        try:
            account_result = self.accounts.refresh_if_stale()
            batch_result = self.batches.refresh_if_stale()
            with self._lock:
                self._state.update(ready=True, error=None)
                if account_result['refreshed'] or batch_result['refreshed']:
                    self._state['last_updated_at'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
            return account_result, batch_result
        except Exception as exc:
            with self._lock:
                self._state['error'] = '源数据正在更新或读取失败，保留上次索引，将自动重试'
            logger.warning('[Team Console] 索引刷新未完成: %s', type(exc).__name__)
            return None
        finally:
            with self._lock:
                self._state['refreshing'] = False

    def request_refresh(self):
        self._wake.set()

    def start(self):
        if self._thread is not None:
            return
        def loop():
            while not self._stop.is_set():
                self._wake.clear()
                self.refresh_once()
                self._wake.wait(self.interval)
        self._thread = threading.Thread(target=loop, name='team-console-index', daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=5)
