"""Small, independent Team admin store; never rewrites registration JSON files."""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

from cryptography.fernet import Fernet, InvalidToken

from core import db


class TeamAdminError(ValueError):
    def __init__(self, message: str, *, code: str = "invalid_request", status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def location():
    return db._DATA_DIR / "data" / "team-admin" / "management.sqlite3"


def _dump(value) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


@contextmanager
def connection():
    path = location()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    conn = sqlite3.connect(path, timeout=5)
    try:
        path.chmod(0o600)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS parents (
                id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE,
                data TEXT NOT NULL, credentials TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS workspaces (
                parent_id INTEGER NOT NULL REFERENCES parents(id) ON DELETE CASCADE,
                id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(parent_id, id)
            );
            CREATE TABLE IF NOT EXISTS members (
                parent_id INTEGER NOT NULL, workspace_id TEXT NOT NULL,
                id TEXT NOT NULL, email TEXT NOT NULL, data TEXT NOT NULL,
                PRIMARY KEY(parent_id, workspace_id, id),
                FOREIGN KEY(parent_id, workspace_id) REFERENCES workspaces(parent_id, id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS seat_holds (
                parent_id INTEGER NOT NULL, workspace_id TEXT NOT NULL,
                id TEXT NOT NULL, seat_type TEXT NOT NULL, email TEXT NOT NULL, data TEXT NOT NULL,
                PRIMARY KEY(parent_id, workspace_id, id, seat_type),
                FOREIGN KEY(parent_id, workspace_id) REFERENCES workspaces(parent_id, id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS invites (
                parent_id INTEGER NOT NULL, workspace_id TEXT NOT NULL,
                id TEXT NOT NULL, email TEXT NOT NULL, data TEXT NOT NULL,
                PRIMARY KEY(parent_id, workspace_id, id),
                FOREIGN KEY(parent_id, workspace_id) REFERENCES workspaces(parent_id, id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                parent_id INTEGER NOT NULL REFERENCES parents(id) ON DELETE CASCADE,
                status TEXT NOT NULL, data TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_parent_job ON jobs(parent_id)
                WHERE status IN ('queued', 'running');
            CREATE INDEX IF NOT EXISTS parent_jobs ON jobs(parent_id, created_at);
            CREATE TABLE IF NOT EXISTS schedule_previews (
                id TEXT PRIMARY KEY,
                parent_id INTEGER NOT NULL REFERENCES parents(id) ON DELETE CASCADE,
                data TEXT NOT NULL, expires_at REAL NOT NULL
            );
        """)
        with conn:
            yield conn
    finally:
        conn.close()


def _cipher() -> Fernet:
    path = location().with_name("credentials.key")
    try:
        key = path.read_bytes()
    except FileNotFoundError:
        key = Fernet.generate_key()
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            key = path.read_bytes()
        else:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(key)
    return Fernet(key)


def _parent(conn, parent_id: int) -> dict:
    row = conn.execute("SELECT id, email, data FROM parents WHERE id=?", (parent_id,)).fetchone()
    if not row:
        raise TeamAdminError("母号不存在", code="parent_not_found", status=404)
    return {**json.loads(row["data"]), "id": row["id"], "email": row["email"]}


def _idle(conn, parent_id: int):
    if conn.execute("SELECT 1 FROM jobs WHERE parent_id=? AND status IN ('queued','running')", (parent_id,)).fetchone():
        raise TeamAdminError("该母号已有任务，请等待完成或取消任务", code="parent_busy", status=409)


def save_parent(email: str, fields: dict, credentials: dict | None, *, parent_id: int | None = None) -> dict:
    with connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if parent_id is None:
            fields = {**fields, "created_at": now(), "updated_at": now(), "status": "not_synced", "error": ""}
            encrypted = _cipher().encrypt(_dump(credentials or {}).encode()).decode()
            try:
                cursor = conn.execute("INSERT INTO parents(email,data,credentials) VALUES(?,?,?)", (email, _dump(fields), encrypted))
            except sqlite3.IntegrityError:
                raise TeamAdminError("这个母号已添加", code="parent_exists", status=409) from None
            parent_id = cursor.lastrowid
        else:
            current = _parent(conn, parent_id)
            _idle(conn, parent_id)
            current.update(fields, updated_at=now(), error="")
            if credentials is not None:
                encrypted = _cipher().encrypt(_dump(credentials).encode()).decode()
                conn.execute("UPDATE parents SET credentials=? WHERE id=?", (encrypted, parent_id))
            conn.execute("UPDATE parents SET data=? WHERE id=?", (_dump(current), parent_id))
        return _parent(conn, parent_id)


def get_parent(parent_id: int) -> dict:
    with connection() as conn:
        return _parent(conn, parent_id)


def credentials(parent_id: int) -> dict:
    with connection() as conn:
        _parent(conn, parent_id)
        raw = conn.execute("SELECT credentials FROM parents WHERE id=?", (parent_id,)).fetchone()[0]
        try:
            return json.loads(_cipher().decrypt(raw.encode()))
        except (InvalidToken, ValueError, OSError):
            raise TeamAdminError("母号凭证无法解密，请更新凭证", code="credentials_unreadable", status=422) from None


def update_credentials(parent_id: int, material: dict):
    with connection() as conn:
        _parent(conn, parent_id)
        encrypted = _cipher().encrypt(_dump(material).encode()).decode()
        conn.execute("UPDATE parents SET credentials=? WHERE id=?", (encrypted, parent_id))


def list_parents() -> list[dict]:
    with connection() as conn:
        rows = conn.execute("SELECT id FROM parents ORDER BY id DESC").fetchall()
        active = {r["parent_id"]: r["id"] for r in conn.execute("SELECT parent_id,id FROM jobs WHERE status IN ('queued','running')")}
        counts = {r[0]: r[1] for r in conn.execute("SELECT parent_id,COUNT(*) FROM workspaces GROUP BY parent_id")}
        return [{**_parent(conn, r["id"]), "active_job_id": active.get(r["id"]), "workspace_count": counts.get(r["id"], 0)} for r in rows]


def delete_parent(parent_id: int):
    with connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        _parent(conn, parent_id)
        _idle(conn, parent_id)
        conn.execute("DELETE FROM parents WHERE id=?", (parent_id,))


def set_parent_state(parent_id: int, status: str, error: str = ""):
    with connection() as conn:
        item = _parent(conn, parent_id)
        item.update(status=status, error=error, updated_at=now())
        conn.execute("UPDATE parents SET data=? WHERE id=?", (_dump(item), parent_id))


def replace_workspaces(parent_id: int, items: list[dict]):
    with connection() as conn:
        old = {r["id"]: json.loads(r["data"]) for r in conn.execute("SELECT * FROM workspaces WHERE parent_id=?", (parent_id,))}
        incoming = {item["id"] for item in items}
        for workspace_id in set(old) - incoming:
            conn.execute("DELETE FROM workspaces WHERE parent_id=? AND id=?", (parent_id, workspace_id))
        for item in items:
            # Keep the last complete member snapshot while workspace metadata refreshes.
            merged = {**old.get(item["id"], {}), **item}
            conn.execute("INSERT INTO workspaces VALUES(?,?,?) ON CONFLICT(parent_id,id) DO UPDATE SET data=excluded.data", (parent_id, item["id"], _dump(merged)))


def workspaces(parent_id: int) -> list[dict]:
    with connection() as conn:
        _parent(conn, parent_id)
        return [json.loads(r[0]) for r in conn.execute("SELECT data FROM workspaces WHERE parent_id=? ORDER BY id", (parent_id,))]


def replace_members(parent_id: int, workspace_id: str, items: list[dict], summary: dict):
    with connection() as conn:
        row = conn.execute("SELECT data FROM workspaces WHERE parent_id=? AND id=?", (parent_id, workspace_id)).fetchone()
        if not row:
            raise TeamAdminError("工作区不存在，请同步工作区", code="workspace_missing", status=404)
        conn.execute("DELETE FROM members WHERE parent_id=? AND workspace_id=?", (parent_id, workspace_id))
        conn.executemany("INSERT INTO members VALUES(?,?,?,?,?)", [(parent_id, workspace_id, item["id"], item["email"], _dump(item)) for item in items])
        metadata = {**json.loads(row[0]), **summary, "member_count": len(items), "members_synced_at": now()}
        conn.execute("UPDATE workspaces SET data=? WHERE parent_id=? AND id=?", (_dump(metadata), parent_id, workspace_id))


def replace_seat_holds(parent_id: int, workspace_id: str, items: list[dict]):
    """Keep departed holders separate from the current member snapshot."""
    with connection() as conn:
        row = conn.execute("SELECT data FROM workspaces WHERE parent_id=? AND id=?", (parent_id, workspace_id)).fetchone()
        if not row:
            raise TeamAdminError("工作区不存在，请同步工作区", code="workspace_missing", status=404)
        conn.execute("DELETE FROM seat_holds WHERE parent_id=? AND workspace_id=?", (parent_id, workspace_id))
        conn.executemany("INSERT INTO seat_holds VALUES(?,?,?,?,?,?)", [
            (parent_id, workspace_id, item["id"], item["reclaimable_seat_type"], item["email"], _dump(item))
            for item in items
        ])
        metadata = {**json.loads(row[0]), "holds_synced_at": now(), "holds_stale": False, "holds_error": ""}
        conn.execute("UPDATE workspaces SET data=? WHERE parent_id=? AND id=?", (_dump(metadata), parent_id, workspace_id))


def member_page(parent_id: int, workspace_id: str, *, page: int = 1, page_size: int | None = 100,
                query: str = "", seat_type: str = "", seat_status: str = "", emails: str = "",
                email_status: str = "") -> dict:
    """Read cached members; page_size=None returns all matches without remote requests."""
    from core.email_search import parse_email_search
    try:
        wanted_emails = parse_email_search(emails)
    except ValueError as exc:
        raise TeamAdminError(str(exc)) from None
    seat_type = str(seat_type or "").strip().lower()
    if seat_type not in {"", "default", "usage_based", "prolite"}:
        raise TeamAdminError("席位筛选仅支持 default、usage_based 和 prolite")
    seat_status = str(seat_status or "").strip().lower()
    if seat_status not in {"", "hold"}:
        raise TeamAdminError("席位状态筛选仅支持当前成员和 hold")
    email_status = str(email_status or "").strip().lower()
    if email_status not in {"", "present", "missing"}:
        raise TeamAdminError("邮箱状态筛选仅支持 present 和 missing")
    table = "seat_holds" if seat_status == "hold" else "members"
    seat_field = "reclaimable_seat_type" if seat_status == "hold" else "seat_type"
    with connection() as conn:
        _parent(conn, parent_id)
        args = [parent_id, workspace_id]
        clause = "parent_id=? AND workspace_id=?"
        if wanted_emails:
            clause += " AND lower(trim(email)) IN (" + ",".join("?" for _ in wanted_emails) + ")"
            args.extend(wanted_emails)
        if query:
            clause += " AND (instr(lower(email),lower(?))>0 OR instr(lower(COALESCE(json_extract(data,'$.name'),'')),lower(?))>0 OR instr(lower(id),lower(?))>0)"
            args.extend((query, query, query))
        if email_status:
            clause += " AND trim(COALESCE(email,'')) " + ("= ''" if email_status == "missing" else "<> ''")
        if seat_type:
            clause += f" AND json_extract(data,'$.{seat_field}')=?"
            args.append(seat_type)
        total = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {clause}", args).fetchone()[0]
        statement = f"SELECT data FROM {table} WHERE {clause} ORDER BY email,id,json_extract(data,'$.{seat_field}')"
        if page_size is not None:
            statement += " LIMIT ? OFFSET ?"
            args.extend((page_size, (page - 1) * page_size))
        rows = conn.execute(statement, args)
        return {"items": [json.loads(r[0]) for r in rows], "total": total,
                "page": 1 if page_size is None else page,
                "page_size": total if page_size is None else page_size}


def members_by_ids(parent_id: int, workspace_id: str, user_ids: list[str]) -> list[dict]:
    if not user_ids:
        return []
    with connection() as conn:
        _parent(conn, parent_id)
        placeholders = ",".join("?" for _ in user_ids)
        rows = conn.execute(
            f"SELECT data FROM members WHERE parent_id=? AND workspace_id=? AND id IN ({placeholders})",
            (parent_id, workspace_id, *user_ids),
        )
        return [json.loads(row[0]) for row in rows]


def workspace_members(parent_id: int, workspace_id: str) -> list[dict]:
    with connection() as conn:
        _parent(conn, parent_id)
        if not conn.execute("SELECT 1 FROM workspaces WHERE parent_id=? AND id=?", (parent_id, workspace_id)).fetchone():
            raise TeamAdminError("工作区不存在", status=404)
        return [json.loads(row[0]) for row in conn.execute(
            "SELECT data FROM members WHERE parent_id=? AND workspace_id=? ORDER BY email,id",
            (parent_id, workspace_id),
        )]


def child_account_emails(parent_id: str, workspace_id: str, seat_type: str = "", seat_status: str = "") -> set[str]:
    """Resolve the complete cached scope before account pagination/export."""
    try:
        parent_id = int(parent_id)
    except (ValueError, TypeError):
        raise TeamAdminError("母号筛选 ID 无效") from None
    if seat_type not in {"", "default", "usage_based", "prolite"} or seat_status not in {"", "hold"}:
        raise TeamAdminError("席位筛选无效")
    parent = get_parent(parent_id)
    space = next((row for row in workspaces(parent_id) if row["id"] == workspace_id), None)
    if not space:
        raise TeamAdminError("筛选的工作区不存在", status=404)
    if not space.get("holds_synced_at" if seat_status == "hold" else "members_synced_at"):
        raise TeamAdminError("请先同步该母号的成员名单", status=409)
    with connection() as conn:
        table, field = ("seat_holds", "reclaimable_seat_type") if seat_status == "hold" else ("members", "seat_type")
        rows = conn.execute(f"SELECT email,data FROM {table} WHERE parent_id=? AND workspace_id=?", (parent_id, workspace_id))
        return {row["email"].strip().casefold() for row in rows
                if row["email"].strip().casefold() != parent["email"].strip().casefold()
                and (item := json.loads(row["data"])).get("role") not in {"account-owner", "account-admin"}
                and (not seat_type or item.get(field) == seat_type)}


def save_schedule_preview(parent_id: int, plan: dict) -> dict:
    import time
    preview_id = uuid.uuid4().hex
    expires = time.time() + 900
    with connection() as conn:
        _parent(conn, parent_id)
        _idle(conn, parent_id)
        conn.execute("DELETE FROM schedule_previews WHERE expires_at<?", (time.time(),))
        conn.execute("INSERT INTO schedule_previews VALUES(?,?,?,?)", (preview_id, parent_id, _dump(plan), expires))
    return {**plan, "preview_id": preview_id, "expires_at": expires}


def schedule_preview(parent_id: int, preview_id: str) -> dict:
    import time
    with connection() as conn:
        row = conn.execute("SELECT data FROM schedule_previews WHERE id=? AND parent_id=? AND expires_at>?",
                           (preview_id, parent_id, time.time())).fetchone()
        if not row:
            raise TeamAdminError("调度预览已过期或已提交，请重新预览", code="preview_expired", status=409)
        return json.loads(row[0])


def waiting_schedule_jobs() -> list[dict]:
    if not location().exists():
        return []
    with connection() as conn:
        return [json.loads(row[0]) for row in conn.execute(
            "SELECT data FROM jobs WHERE status='running' AND json_extract(data,'$.kind')='schedule' "
            "AND json_extract(data,'$.stage')='completion_waiting'",
        )]


def update_workspace(parent_id: int, workspace_id: str, changes: dict):
    with connection() as conn:
        row = conn.execute("SELECT data FROM workspaces WHERE parent_id=? AND id=?", (parent_id, workspace_id)).fetchone()
        if row:
            data = {**json.loads(row[0]), **changes}
            conn.execute("UPDATE workspaces SET data=? WHERE parent_id=? AND id=?", (_dump(data), parent_id, workspace_id))


def replace_invites(parent_id: int, workspace_id: str, items: list[dict]):
    with connection() as conn:
        row = conn.execute("SELECT data FROM workspaces WHERE parent_id=? AND id=?", (parent_id, workspace_id)).fetchone()
        if not row:
            raise TeamAdminError("工作区不存在，请同步工作区", code="workspace_missing", status=404)
        conn.execute("DELETE FROM invites WHERE parent_id=? AND workspace_id=?", (parent_id, workspace_id))
        conn.executemany("INSERT INTO invites VALUES(?,?,?,?,?)", [
            (parent_id, workspace_id, item["id"], item["email"], _dump(item)) for item in items
        ])
        metadata = {**json.loads(row[0]), "invite_count": len(items), "invites_synced_at": now(),
                    "invites_stale": False, "invites_error": ""}
        conn.execute("UPDATE workspaces SET data=? WHERE parent_id=? AND id=?", (_dump(metadata), parent_id, workspace_id))


def upsert_invites(parent_id: int, workspace_id: str, items: list[dict]):
    with connection() as conn:
        for item in items:
            conn.execute("DELETE FROM invites WHERE parent_id=? AND workspace_id=? AND email=? AND id<>?",
                         (parent_id, workspace_id, item["email"], item["id"]))
            conn.execute("INSERT INTO invites VALUES(?,?,?,?,?) ON CONFLICT(parent_id,workspace_id,id) DO UPDATE SET email=excluded.email,data=excluded.data",
                         (parent_id, workspace_id, item["id"], item["email"], _dump(item)))


def invite_page(parent_id: int, workspace_id: str, *, page: int = 1, page_size: int = 100, query: str = "") -> dict:
    with connection() as conn:
        _parent(conn, parent_id)
        args = [parent_id, workspace_id]
        clause = "parent_id=? AND workspace_id=?"
        if query:
            clause += " AND instr(lower(email),lower(?))>0"
            args.append(query)
        total = conn.execute(f"SELECT COUNT(*) FROM invites WHERE {clause}", args).fetchone()[0]
        rows = conn.execute(f"SELECT data FROM invites WHERE {clause} ORDER BY email,id LIMIT ? OFFSET ?",
                            (*args, page_size, (page - 1) * page_size))
        return {"items": [json.loads(r[0]) for r in rows], "total": total, "page": page, "page_size": page_size}


def mark_invites_stale(workspace_id: str):
    with connection() as conn:
        for row in conn.execute("SELECT parent_id,data FROM workspaces WHERE id=?", (workspace_id,)).fetchall():
            data = json.loads(row["data"])
            data["invites_stale"] = True
            conn.execute("UPDATE workspaces SET data=? WHERE parent_id=? AND id=?", (_dump(data), row["parent_id"], workspace_id))


def update_member(parent_id: int, workspace_id: str, item: dict):
    with connection() as conn:
        conn.execute("UPDATE members SET email=?,data=? WHERE parent_id=? AND workspace_id=? AND id=?", (item["email"], _dump(item), parent_id, workspace_id, item["id"]))


def remove_member(parent_id: int, workspace_id: str, member_id: str) -> bool:
    with connection() as conn:
        cursor = conn.execute(
            "DELETE FROM members WHERE parent_id=? AND workspace_id=? AND id=?",
            (parent_id, workspace_id, member_id),
        )
        if cursor.rowcount != 1:
            return False
        row = conn.execute(
            "SELECT data FROM workspaces WHERE parent_id=? AND id=?", (parent_id, workspace_id),
        ).fetchone()
        if row:
            metadata = json.loads(row[0])
            metadata["member_count"] = max(0, int(metadata.get("member_count") or 0) - 1)
            metadata["members_stale"] = False
            metadata["members_synced_at"] = now()
            conn.execute(
                "UPDATE workspaces SET data=? WHERE parent_id=? AND id=?",
                (_dump(metadata), parent_id, workspace_id),
            )
        return True


def mark_workspace_stale(workspace_id: str):
    with connection() as conn:
        for row in conn.execute("SELECT parent_id,data FROM workspaces WHERE id=?", (workspace_id,)).fetchall():
            data = json.loads(row["data"])
            data["members_stale"] = True
            data["holds_stale"] = True
            conn.execute("UPDATE workspaces SET data=? WHERE parent_id=? AND id=?", (_dump(data), row["parent_id"], workspace_id))


def create_job(parent_id: int, kind: str, workspace_id: str, user_ids: list[str], seat_type: str,
               *, email_addresses: list[str] | None = None, resend_emails: bool = False,
               schedule_preview_id: str = "", removal_plan: dict | None = None,
               account_plan: dict | None = None) -> dict:
    with connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        _parent(conn, parent_id)
        _idle(conn, parent_id)
        item = {"id": uuid.uuid4().hex, "parent_id": parent_id, "kind": kind, "workspace_id": workspace_id,
                "user_ids": user_ids, "seat_type": seat_type, "status": "queued", "cancel_requested": False,
                "total": len(user_ids), "completed": 0, "results": [], "message": "等待执行", "created_at": now()}
        if kind == "remove" and removal_plan is not None:
            item["removal_plan"] = removal_plan
        if kind == "switch" and account_plan is not None:
            item["account_plan"] = account_plan
        if kind == "invite":
            item.update(email_addresses=list(email_addresses or []), resend_emails=resend_emails,
                        total=len(email_addresses or []), flow_id=str(uuid.uuid4()),
                        submission_id=str(uuid.uuid4()), inflight_emails=[])
        if kind == "schedule":
            import time
            row = conn.execute("SELECT data FROM schedule_previews WHERE id=? AND parent_id=? AND expires_at>?",
                               (schedule_preview_id, parent_id, time.time())).fetchone()
            if not row:
                raise TeamAdminError("调度预览已过期或已提交，请重新预览", code="preview_expired", status=409)
            plan = json.loads(row[0])
            if plan["workspace_id"] != workspace_id:
                raise TeamAdminError("调度工作区不一致")
            item.update(schedule_plan=plan, preview_id=schedule_preview_id, stage="members",
                        total=len(plan["members"]) + 2 * len(plan["accounts"]),
                        completion_ids=[], inflight_emails=[],
                        flow_id=str(uuid.uuid4()), submission_id=str(uuid.uuid4()))
            conn.execute("DELETE FROM schedule_previews WHERE id=?", (schedule_preview_id,))
        conn.execute("INSERT INTO jobs VALUES(?,?,?,?,?)", (item["id"], parent_id, "queued", _dump(item), item["created_at"]))
        conn.execute("DELETE FROM jobs WHERE parent_id=? AND status NOT IN ('queued','running') AND id NOT IN (SELECT id FROM jobs WHERE parent_id=? ORDER BY created_at DESC, rowid DESC LIMIT 50)", (parent_id, parent_id))
        return item


def get_job(job_id: str) -> dict:
    with connection() as conn:
        row = conn.execute("SELECT data FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            raise TeamAdminError("任务不存在", code="job_not_found", status=404)
        return json.loads(row[0])


def update_job(job_id: str, **changes) -> dict:
    with connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT data FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            raise TeamAdminError("任务不存在", code="job_not_found", status=404)
        item = {**json.loads(row[0]), **changes, "updated_at": now()}
        conn.execute("UPDATE jobs SET status=?,data=? WHERE id=?", (item["status"], _dump(item), job_id))
        return item


def update_schedule_progress(job_id: str, **changes):
    """Do not let a late observer overwrite a cancellation or a worker failure."""
    with connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT data FROM jobs WHERE id=?", (job_id,)).fetchone()
        item = json.loads(row[0]) if row else {}
        if (item.get("status") != "running" or item.get("stage") != "completion_waiting"
                or item.get("cancel_requested")):
            return
        item.update(changes, updated_at=now())
        conn.execute("UPDATE jobs SET status=?,data=? WHERE id=?", (item["status"], _dump(item), job_id))


def recent_jobs(parent_id: int) -> list[dict]:
    with connection() as conn:
        return [{k: v for k, v in json.loads(r[0]).items() if k not in {"user_ids", "results", "email_addresses", "inflight_emails", "schedule_plan", "completion_ids", "removal_plan", "account_plan"}} for r in conn.execute("SELECT data FROM jobs WHERE parent_id=? ORDER BY created_at DESC,rowid DESC LIMIT 10", (parent_id,))]


def recover_interrupted():
    if not location().exists():
        return
    with connection() as conn:
        for row in conn.execute("SELECT id,data FROM jobs WHERE status IN ('queued','running')").fetchall():
            item = json.loads(row["data"])
            if item["kind"] == "schedule" and item.get("stage") == "completion_waiting":
                # Remote mutations are done. Only observe the already persisted pipelines.
                continue
            item.update(status="interrupted", message="服务重启中断；席位修改未自动重试，请先同步成员", updated_at=now())
            if item["kind"] in {"invite", "schedule"}:
                item["message"] = "服务重启中断；邀请未自动重发，请先同步待接受邀请"
                results = item.get("results") or []
                completed = {result.get("email") for result in results}
                results.extend({"email": email, "target": item["seat_type"], "status": "unconfirmed",
                                "message": "提交时服务中断，远端结果待确认"}
                               for email in item.get("inflight_emails", []) if email not in completed)
                item.update(results=results, completed=len(results), inflight_emails=[])
            conn.execute("UPDATE jobs SET status='interrupted',data=? WHERE id=?", (_dump(item), row["id"]))
