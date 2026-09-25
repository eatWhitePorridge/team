"""Opt-in, protocol-only management of multiple Team owner accounts."""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from core import account_cookie_store, db, team_admin_store as store
from core.chatgpt_plan import ACCOUNTS_CHECK_PATH, decode_jwt_payload_unverified, normalize_token
from core.nextauth_cookies import reconcile_session_cookies
from core.session import BrowserSession

TeamAdminError = store.TeamAdminError
logger = logging.getLogger(__name__)
_EXECUTOR = ThreadPoolExecutor(max_workers=3, thread_name_prefix="team-admin")
_SLOTS = threading.BoundedSemaphore(30)
_LOCKS_GUARD = threading.Lock()
_WORKSPACE_LOCKS: dict[str, threading.Lock] = {}
_SEAT_SWITCH_INTERVAL = 10.0
_SEAT_NEXT_AT: dict[str, float] = {}
_SEAT_429_MAX_ATTEMPTS = 3
_SEAT_429_DEFAULT_WAIT = 60.0
_SEAT_429_MAX_WAIT = 180.0
_MANAGER_ROLES = {"account-owner", "account-admin"}
_TEAM_PLANS = {"team", "business", "self_serve_business", "self_serve_business_usage_based"}
_TEAM_SUBSCRIPTIONS = {"chatgptteamplan", "chatgptbusinessplan"}
_SEAT_TYPES = {"default", "usage_based", "prolite"}
_HOLD_SEAT_TYPES = {"default", "prolite"}
_MEMBER_PAGE_SIZE = 100
_MEMBER_SNAPSHOT_ATTEMPTS = 3
_MEMBER_REPAIR_REQUESTS = 8
_MAX_MEMBERS = 5000
_INVITE_PAGE_SIZE = 25
_INVITE_BATCH_SIZE = 25
_INVITE_REQUEST_TIMEOUT = 60
_ID = re.compile(r"[A-Za-z0-9_-]{1,200}")
_EMAIL = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")


def _text(value, limit: int = 200) -> str:
    return str(value or "").strip()[:limit] if isinstance(value, (str, int, float)) else ""


def _valid_invite_email(email) -> bool:
    return (isinstance(email, str) and len(email.strip()) <= 254
            and bool(_EMAIL.fullmatch(email.strip()))
            and not any(ord(ch) < 32 or ch in '<>,;"\\' for ch in email.strip()))


def _material(data: dict) -> dict:
    at = normalize_token(str(data.get("access_token") or ""))
    st = str(data.get("session_token") or "").strip()
    if any(ch.isspace() for ch in at) or len(at) > 32768:
        raise TeamAdminError("Web AT 格式无效")
    if any(ch.isspace() or ch == ";" for ch in st) or len(st) > 32768:
        raise TeamAdminError("Session Token 格式无效")
    cookies = account_cookie_store.normalize_cookies(data.get("cookies") or [])
    if not at and not st and not cookies:
        raise TeamAdminError("需要母号 Web AT 或 Session 登录态", code="credentials_missing")
    return {"access_token": at, "session_token": st, "cookies": cookies}


def _linked_material(parent: dict) -> dict:
    account = db.get_account(parent["source_account_id"])
    if not account or _text(account.get("email")).casefold() != parent["email"].casefold():
        raise TeamAdminError("关联账号不存在或邮箱已变化", code="linked_account_missing", status=422)
    cookies = []
    if account.get("web_cookie_credential_path"):
        try:
            payload = db.load_account_web_cookie_credential(account["id"])
            cookies = (payload or {}).get("cookies") or []
        except ValueError:
            if not account.get("access_token"):
                raise TeamAdminError("关联账号的 Cookie 不可用，且没有 Web AT", code="credentials_missing") from None
    return _material({"access_token": account.get("access_token"), "cookies": cookies})


def add_parent(data: dict) -> dict:
    source = data.get("source_account_id")
    if source is not None:
        if isinstance(source, bool) or not isinstance(source, int) or source < 1:
            raise TeamAdminError("关联账号 ID 无效")
        account = db.get_account(source)
        if not account:
            raise TeamAdminError("关联账号不存在", status=404)
        email = _text(account.get("email"), 254).casefold()
        material = _linked_material({"source_account_id": source, "email": email})
    else:
        email = _text(data.get("email"), 254).casefold()
        material = _material(data)
    if not _EMAIL.fullmatch(email):
        raise TeamAdminError("母号邮箱格式无效")
    return store.save_parent(email, {
        "label": _text(data.get("label"), 80), "source_account_id": source,
        "has_access_token": bool(material["access_token"]),
        "has_session": bool(material["session_token"] or material["cookies"]),
    }, material if source is None else {})


def edit_parent(parent_id: int, data: dict) -> dict:
    parent = store.get_parent(parent_id)
    fields = {"label": _text(data.get("label", parent.get("label")), 80)}
    material = None
    if not parent.get("source_account_id"):
        material = store.credentials(parent_id)
        if data.get("access_token"):
            material["access_token"] = data["access_token"]
        if data.get("session_token"):
            material.update(session_token=data["session_token"], cookies=[])
        material = _material(material)
        fields.update(has_access_token=bool(material["access_token"]), has_session=bool(material["session_token"] or material["cookies"]))
    return store.save_parent(parent["email"], fields, material, parent_id=parent_id)


def _check_cancel(job_id: str | None):
    if not job_id:
        return
    if store.get_job(job_id).get("cancel_requested"):
        raise TeamAdminError("任务已取消；已提交的操作不会撤销", code="cancelled", status=409)


class RemoteError(TeamAdminError):
    def __init__(self, message: str, http_status: int = 0):
        super().__init__(message, code=f"upstream_{http_status}", status=422)
        self.http_status = http_status


class SeatUnconfirmedError(TeamAdminError):
    def __init__(self, cause: TeamAdminError):
        super().__init__(f"席位修改结果未确认：{cause}；未自动回查或重复提交", code=cause.code, status=cause.status)


class MemberPaginationError(RemoteError):
    """An inconsistent member scan that can be retried from offset zero."""


class TeamAdminClient:
    def __init__(self, parent: dict, job_id: str = ""):
        self.parent = parent
        self.job_id = job_id
        self.workspace_id = ""
        self.material = _linked_material(parent) if parent.get("source_account_id") else store.credentials(parent["id"])
        self.token = self.material.get("access_token") or ""
        self.env = BrowserSession(detect_exit_geo=False)
        for cookie in self.material.get("cookies") or []:
            if cookie.get("expires", -1) not in (None, -1, 0) and float(cookie["expires"]) < time.time():
                continue
            self.env.session.cookies.set(cookie["name"], cookie["value"], domain=cookie["domain"], path=cookie.get("path") or "/", secure=bool(cookie.get("secure")) or cookie["name"].startswith(("__Secure-", "__Host-")))
        if self.material.get("session_token"):
            self.env.session.cookies.set("__Secure-next-auth.session-token", self.material["session_token"], domain="chatgpt.com", path="/", secure=True)

    def close(self):
        self.env.session.close()

    def _token_email(self) -> str:
        claims = decode_jwt_payload_unverified(self.token)
        profile = claims.get("https://api.openai.com/profile") or {}
        return _text(claims.get("email") or (profile.get("email") if isinstance(profile, dict) else ""), 254).casefold()

    def _check_email(self, email: str):
        if not email:
            raise TeamAdminError("接口未返回母号邮箱，无法确认身份", code="identity_unverified", status=422)
        if email.casefold() != self.parent["email"].casefold():
            raise TeamAdminError("母号凭证身份与所选邮箱不一致，已停止", code="identity_mismatch", status=422)

    def _refresh(self):
        _check_cancel(self.job_id)
        if not self.material.get("session_token") and not self.material.get("cookies"):
            raise RemoteError("母号 Web AT 已失效，且没有 Session 可刷新", 401)
        params = None
        if self.workspace_id:
            params = {"exchange_workspace_token": "true", "workspace_id": self.workspace_id, "reason": "setCurrentAccount"}
        try:
            resp = self.env.get("https://chatgpt.com/api/auth/session", params=params,
                                headers=self.env.get_nextauth_headers(), allow_redirects=False, timeout=20)
        except Exception:
            raise RemoteError("刷新母号 Session 时网络请求失败") from None
        if resp.status_code != 200:
            raise RemoteError(f"刷新母号 Session 失败：HTTP {resp.status_code}", resp.status_code)
        reconcile_session_cookies(self.env.session.cookies, resp, "https://chatgpt.com/api/auth/session")
        try:
            payload = resp.json()
        except ValueError:
            payload = {}
        if not isinstance(payload, dict) or not payload.get("accessToken"):
            raise RemoteError("Session 未返回 Web AT，请更新母号登录态", 401)
        user = payload.get("user") or {}
        self._check_email(_text(user.get("email") if isinstance(user, dict) else "", 254))
        self.token = str(payload["accessToken"])
        if self._token_email():
            self._check_email(self._token_email())
        self.material = {"access_token": self.token, "session_token": "", "cookies": account_cookie_store.normalize_cookies(self.env.session.cookies)}
        if not self.parent.get("source_account_id"):
            store.update_credentials(self.parent["id"], self.material)

    def request(self, method: str, path: str, *, params=None, body=None, retry_auth: bool = True,
                retry_rate_limit: bool = False, timeout: float = 20) -> dict:
        if not self.token:
            self._refresh()
        token_email = self._token_email()
        if token_email:
            self._check_email(token_email)
        rate_limit_attempts = _SEAT_429_MAX_ATTEMPTS if retry_rate_limit else 1
        for attempt in range(max(2 if method == "GET" else 1, rate_limit_attempts)):
            _check_cancel(self.job_id)
            headers = self.env.get_chatgpt_headers("https://chatgpt.com/admin/members")
            headers.update({"authorization": f"Bearer {self.token}", "origin": "https://chatgpt.com"})
            if self.workspace_id:
                headers["chatgpt-account-id"] = self.workspace_id
            try:
                if method == "GET":
                    resp = self.env.get("https://chatgpt.com" + path, headers=headers, params=params, allow_redirects=False, timeout=timeout)
                elif method == "DELETE":
                    resp = self.env.delete("https://chatgpt.com" + path, headers=headers, allow_redirects=False, timeout=timeout)
                else:
                    resp = self.env.post("https://chatgpt.com" + path, headers=headers, json=body, allow_redirects=False, timeout=timeout)
            except Exception:
                if method == "GET" and attempt == 0:
                    continue
                raise RemoteError("母号管理网络请求失败；未自动重试写入操作") from None
            status = int(resp.status_code)
            if status == 401 and method == "GET" and retry_auth:
                self._refresh()
                return self.request(method, path, params=params, retry_auth=False, timeout=timeout)
            if status >= 500 and method == "GET" and attempt == 0:
                continue
            if status == 429 and retry_rate_limit and attempt + 1 < rate_limit_attempts:
                response_headers = getattr(resp, "headers", {}) or {}
                raw_wait = response_headers.get("retry-after") or response_headers.get("Retry-After") or ""
                try:
                    wait = float(str(raw_wait).strip())
                except (TypeError, ValueError):
                    wait = _SEAT_429_DEFAULT_WAIT * (2 ** attempt)
                wait = max(0.0, min(_SEAT_429_MAX_WAIT, wait))
                logger.warning("[母号管理] 席位写入收到 429，冷却 %.1fs 后重试 attempt=%s/%s workspace=%s",
                               wait, attempt + 1, rate_limit_attempts, self.workspace_id)
                with _LOCKS_GUARD:
                    _SEAT_NEXT_AT[self.workspace_id] = max(
                        _SEAT_NEXT_AT.get(self.workspace_id, 0), time.monotonic() + wait
                    )
                _check_cancel(self.job_id)
                time.sleep(wait)
                continue
            if not 200 <= status < 300:
                message = {401: "母号登录态失效", 403: "当前请求被拒绝，请检查管理权限或网络出口", 429: "母号管理请求被限流"}.get(status, "母号管理接口请求失败")
                raise RemoteError(f"{message}：HTTP {status}", status)
            try:
                data = resp.json()
            except ValueError:
                data = None
            if not isinstance(data, dict):
                raise RemoteError("母号管理接口未返回 JSON 对象", status)
            return data
        raise RemoteError("母号管理请求未完成")

    def discover(self) -> list[dict]:
        data = self.request("GET", ACCOUNTS_CHECK_PATH)
        # Cookie and Bearer may disagree. Verify the identity actually served by the API.
        identity = self.request("GET", "/backend-api/me")
        self._check_email(_text(identity.get("email"), 254))
        accounts = data.get("accounts")
        if not isinstance(accounts, dict):
            raise RemoteError("工作区响应缺少 accounts 对象")
        result = {}
        for key, item in accounts.items():
            if not isinstance(item, dict):
                continue
            account, entitlement = item.get("account") or {}, item.get("entitlement") or {}
            if not isinstance(account, dict) or not isinstance(entitlement, dict):
                continue
            plan = _text(account.get("plan_type"), 80).casefold()
            subscription = _text(entitlement.get("subscription_plan"), 80).casefold()
            # Business usage-based workspaces still have the Team subscription.
            if plan not in _TEAM_PLANS and subscription not in _TEAM_SUBSCRIPTIONS:
                continue
            workspace_id = _text(account.get("account_id") or key)
            if workspace_id == "default" or not _ID.fullmatch(workspace_id):
                continue
            if key == "default" and workspace_id in result:
                continue
            role = _text(account.get("account_user_role"), 60)
            result[workspace_id] = {"id": workspace_id, "name": _text(account.get("name")), "role": role,
                                    "can_manage": role in _MANAGER_ROLES, "plan_type": plan,
                                    "is_usage_based_seat_enabled": account.get("is_usage_based_seat_enabled") is True,
                                    "subscription_plan": subscription,
                                    "has_active_subscription": bool(entitlement.get("has_active_subscription")),
                                    "expires_at": _text(entitlement.get("expires_at")),
                                    "renewal_date": _text(entitlement.get("renewal_date")),
                                    "synced_at": store.now()}
        logger.info("[母号管理] 工作区识别 parent=%s workspaces=%s manageable=%s", self.parent["id"], len(result), sum(item["can_manage"] for item in result.values()))
        return list(result.values())

    def members(self, query: str = "", *, active_vacancy_hold_seat_type: str = "") -> list[dict]:
        if active_vacancy_hold_seat_type and active_vacancy_hold_seat_type not in _HOLD_SEAT_TYPES:
            raise TeamAdminError("Hold 查询仅支持 default 和 prolite 席位")
        for attempt in range(1, _MEMBER_SNAPSHOT_ATTEMPTS + 1):
            _check_cancel(self.job_id)
            try:
                return self._member_snapshot(query, active_vacancy_hold_seat_type)
            except MemberPaginationError as exc:
                logger.warning(
                    "[母号管理] 成员分页异常 parent=%s workspace=%s hold=%s attempt=%s/%s error=%s",
                    self.parent["id"], self.workspace_id, active_vacancy_hold_seat_type or "-",
                    attempt, _MEMBER_SNAPSHOT_ATTEMPTS, exc,
                )
                if attempt == _MEMBER_SNAPSHOT_ATTEMPTS:
                    raise
                # A changed total invalidates this scan, including its repair
                # reads. Never carry collected members into another attempt.
                _check_cancel(self.job_id)
                time.sleep(0.5 * attempt)

    def _member_snapshot(self, query: str, active_vacancy_hold_seat_type: str) -> list[dict]:
        found = {}
        first_seen = {}
        repair_offsets = {}
        overlap_offsets = {}
        expected_total = None
        requests = 0

        def read_page(offset: int) -> tuple[int, set[int]]:
            nonlocal expected_total, requests
            _check_cancel(self.job_id)
            if requests >= 200:
                raise RemoteError("成员分页超过单次同步请求上限，保留上次完整缓存")
            requests += 1
            params = {"offset": offset, "limit": _MEMBER_PAGE_SIZE, "query": query}
            if active_vacancy_hold_seat_type:
                params["active_vacancy_hold_seat_type"] = active_vacancy_hold_seat_type
            data = self.request("GET", f"/backend-api/accounts/{self.workspace_id}/users", params=params)
            items, total = data.get("items"), data.get("total")
            if not isinstance(items, list) or isinstance(total, bool) or not isinstance(total, int) or total < 0:
                raise RemoteError("成员分页响应格式无效")
            if total > _MAX_MEMBERS:
                raise RemoteError(f"成员数量超过单次同步上限 {_MAX_MEMBERS}，保留上次完整缓存")
            diagnostic = (f"offset={offset}, returned={len(items)}, unique={len(found)}, "
                          f"total={total}, initial_total={expected_total}")
            if expected_total is not None and total != expected_total:
                raise MemberPaginationError(f"成员分页期间总数变化（{diagnostic}），保留上次完整缓存")
            expected_total = total
            if "offset" in data and (type(data["offset"]) is not int or data["offset"] != offset):
                raise MemberPaginationError(f"成员分页返回位置不符（{diagnostic}），保留上次完整缓存")
            duplicate_origins = set()
            for item in items:
                if not isinstance(item, dict) or not _ID.fullmatch(str(item.get("id") or "")):
                    raise RemoteError("成员响应缺少有效 user id")
                member = {k: _text(item.get(k), 254) for k in ("id", "account_user_id", "email", "name", "role", "seat_type", "pending_seat_type", "reclaimable_seat_type", "created_time", "deactivated_time")}
                if active_vacancy_hold_seat_type and member["reclaimable_seat_type"] != active_vacancy_hold_seat_type:
                    raise RemoteError("Hold 名单返回的保留席位类型不一致，保留上次完整缓存")
                if member["id"] in found:
                    duplicate_origins.add(first_seen[member["id"]])
                else:
                    first_seen[member["id"]] = offset
                member["observed_at"] = store.now()
                found[member["id"]] = member
            if len(found) > _MAX_MEMBERS:
                raise RemoteError(f"成员数量超过单次同步上限 {_MAX_MEMBERS}，保留上次完整缓存")
            if len(found) > total:
                raise MemberPaginationError(f"成员分页条数超过返回总数（{diagnostic}），保留上次完整缓存")
            if not items and len(found) < total:
                raise MemberPaginationError(f"成员分页未前进（{diagnostic}），保留上次完整缓存")
            return len(items), duplicate_origins

        offset = 0
        while True:
            count, duplicate_origins = read_page(offset)
            if duplicate_origins:
                # Equal sort keys can move a user between neighboring pages
                # without changing total. Keep scanning and then reread the
                # affected pages plus an overlapping window across the boundary.
                for origin in sorted(duplicate_origins):
                    repair_offsets[origin] = None
                repair_offsets[offset] = None
                overlap = max(1, count // 2)
                overlap_offsets[max(0, offset - overlap)] = None
                for boundary in (*sorted(duplicate_origins), offset):
                    overlap_offsets[max(0, boundary - overlap)] = None
                    if boundary + overlap < expected_total:
                        overlap_offsets[boundary + overlap] = None
                logger.info(
                    "[母号管理] 成员分页重叠，去重后继续 parent=%s workspace=%s hold=%s "
                    "offset=%s returned=%s unique=%s total=%s",
                    self.parent["id"], self.workspace_id, active_vacancy_hold_seat_type or "-",
                    offset, count, len(found), expected_total,
                )
            if len(found) == expected_total:
                _check_cancel(self.job_id)
                return list(found.values())
            offset += count
            if offset >= expected_total:
                break

        # Repair only within this scan and only while every response agrees on
        # total. Even after deduplication, unique count must match total exactly.
        # Cover all affected pages before probing extra windows around one
        # boundary, otherwise a late-page gap can exhaust the repair budget.
        repair_offsets.update(overlap_offsets)
        repairs = 0
        for repair_offset in list(repair_offsets)[:_MEMBER_REPAIR_REQUESTS]:
            _check_cancel(self.job_id)
            time.sleep(0.25)
            read_page(repair_offset)
            repairs += 1
            if len(found) == expected_total:
                _check_cancel(self.job_id)
                logger.info(
                    "[母号管理] 成员分页补齐 parent=%s workspace=%s hold=%s members=%s repair_requests=%s",
                    self.parent["id"], self.workspace_id, active_vacancy_hold_seat_type or "-",
                    len(found), repairs,
                )
                return list(found.values())
        raise MemberPaginationError(
            f"成员分页补齐未完成（unique={len(found)}, total={expected_total}, repairs={repairs}），保留上次完整缓存"
        )

    def summary(self) -> dict:
        out = {"summary_error": ""}
        try:
            counts = self.request("GET", f"/backend-api/accounts/{self.workspace_id}/users/seat_type_counts")
            subscriptions = self.request("GET", "/backend-api/subscriptions", params={"account_id": self.workspace_id})
            for key, source in (("seat_type_counts", counts), ("assigned", subscriptions)):
                value = source.get(key)
                if isinstance(value, dict):
                    out[key] = {name: count for name, count in value.items() if name in {"default", "usage_based", "automation", "prolite"} and type(count) is int and count >= 0}
            for key, source in (("maximum_seats", counts), ("seats_in_use", subscriptions), ("seats_entitled", subscriptions)):
                value = source.get(key)
                if type(value) is int and value >= 0:
                    out[key] = value
            capacity = subscriptions.get("seat_capacity")
            if isinstance(capacity, list):
                out["seat_capacity"] = [{"type": row["type"], **{k: row[k] for k in ("available", "paid", "held") if type(row.get(k)) is int and row[k] >= 0}}
                                        for row in capacity if isinstance(row, dict) and isinstance(row.get("type"), str) and row["type"] in {"default", "usage_based", "automation", "prolite"}]
        except RemoteError as exc:
            out["summary_error"] = str(exc)
        out["summary_synced_at"] = store.now()
        return out

    def subscription_preview(self) -> dict:
        """Read the subscription renewal date without submitting a seat change.

        The preview endpoint expects the desired total seat count.  The web
        client starts with a small probe and follows the server's reported
        current quantity so a concurrent seat change does not make the probe
        stale.  All requests remain GET-only.
        """
        if not self.workspace_id:
            raise TeamAdminError("未选择工作区", code="workspace_missing", status=422)
        target_seats = 3
        for _ in range(3):
            preview = self.request(
                "GET", "/backend-api/subscriptions/update/preview",
                params={"account_id": self.workspace_id, "updated_seats": target_seats},
            )
            current = preview.get("current_seat_quantity")
            if isinstance(current, bool):
                current = None
            if isinstance(current, int):
                current_seats = current
            elif isinstance(current, str) and current.strip().isdigit():
                current_seats = int(current.strip())
            else:
                current_seats = -1
            if current_seats < 1:
                raise RemoteError("费用预览未返回有效的当前席位数")
            desired = current_seats + 1
            if target_seats == desired:
                return preview
            target_seats = desired
        raise RemoteError("检测期间当前席位数连续变化，请稍后重试")


    def invites(self) -> list[dict]:
        found = {}
        offset = 0
        for _ in range(200):
            data = self.request("GET", f"/backend-api/accounts/{self.workspace_id}/invites",
                                params={"offset": offset, "limit": _INVITE_PAGE_SIZE, "query": ""})
            items, total = data.get("items"), data.get("total")
            if not isinstance(items, list) or type(total) is not int or not 0 <= total <= _MAX_MEMBERS:
                raise RemoteError("邀请分页响应无效或超过 5000 条，保留上次完整缓存")
            before = len(found)
            for item in items:
                invite = _normalize_invite(item)
                found[invite["id"]] = invite
            if len(found) > _MAX_MEMBERS:
                raise RemoteError("邀请数量超过 5000 条，保留上次完整缓存")
            if len(found) >= total:
                return list(found.values())
            if not items or len(found) == before:
                raise RemoteError("邀请分页未前进，保留上次完整缓存")
            offset += len(items)
        raise RemoteError("邀请分页超过同步上限，保留上次完整缓存")


def _normalize_invite(item: dict) -> dict:
    if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not _ID.fullmatch(item["id"]):
        raise RemoteError("邀请响应缺少有效 invitation id")
    email = str(item.get("email_address") or "").strip().casefold()
    if len(email) > 254 or not _EMAIL.fullmatch(email):
        raise RemoteError("邀请响应缺少有效邮箱")
    return {"id": item["id"], "email": email, "role": _text(item.get("role"), 60),
            "seat_type": _text(item.get("seat_type"), 60),
            "status": item.get("status") if type(item.get("status")) is int else None,
            "created_time": _text(item.get("created_time"), 80), "observed_at": store.now()}


def _sync_invites(client: TeamAdminClient) -> list[dict]:
    try:
        items = client.invites()
    except TeamAdminError as exc:
        store.update_workspace(client.parent["id"], client.workspace_id, {"invites_stale": True, "invites_error": str(exc)})
        raise
    store.replace_invites(client.parent["id"], client.workspace_id, items)
    return items


def _invite_matches(item: dict, seat: str) -> bool:
    return item.get("status") == 2 and item.get("seat_type") == seat and item.get("role") == "standard-user"


def _invite_error_text(client: TeamAdminClient, value) -> str:
    if isinstance(value, dict):
        value = value.get("message") or value.get("code")
    text = str(value or "远端拒绝该邮箱的邀请")
    secrets = [client.token, client.material.get("session_token")]
    secrets.extend(cookie.get("value") for cookie in client.material.get("cookies", []))
    for secret in secrets:
        if secret:
            text = text.replace(str(secret), "[redacted]")
    return " ".join(text.split())[:300]


def _invite_batch(client: TeamAdminClient, job: dict, emails: list[str]) -> tuple[list[dict], TeamAdminError | None]:
    """Submit once and record the POST response without polling remote state."""
    results = {email: {"email": email, "target": job["seat_type"], "status": "unconfirmed",
                       "message": "未收到明确的邀请结果，未自动回查或重发"} for email in emails}
    try:
        data = client.request("POST", f"/backend-api/accounts/{client.workspace_id}/invites", timeout=_INVITE_REQUEST_TIMEOUT,
                              body={"email_addresses": emails, "role": "standard-user", "seat_type": job["seat_type"],
                                    "resend_emails": job["resend_emails"], "flow_id": job["flow_id"],
                                    "submission_id": job["submission_id"]})
        accepted, errors = data.get("account_invites"), data.get("errored_emails")
        if isinstance(accepted, list) and isinstance(errors, list):
            grouped: dict[str, list[tuple[str, dict]]] = {}
            for raw in accepted:
                try:
                    item = _normalize_invite(raw)
                except RemoteError:
                    continue
                grouped.setdefault(item["email"], []).append(("accepted", item))
            for raw in errors:
                if isinstance(raw, dict):
                    email = str(raw.get("email_address") or "").strip().casefold()
                    grouped.setdefault(email, []).append(("error", raw))
            confirmed = []
            for email in emails:
                matches = grouped.get(email, [])
                if len(matches) != 1:
                    continue
                kind, item = matches[0]
                if kind == "error":
                    results[email].update(status="failed", message=_invite_error_text(client, item.get("error")))
                elif _invite_matches(item, job["seat_type"]):
                    confirmed.append(item)
                    results[email].update(status="success", invite_id=item["id"], message="邀请接口已受理，等待接受")
            if confirmed:
                try:
                    store.upsert_invites(client.parent["id"], client.workspace_id, confirmed)
                except Exception as exc:
                    logger.error("[母号管理] 邀请缓存保存失败 parent=%s error=%s", client.parent["id"], type(exc).__name__)
                    return list(results.values()), TeamAdminError(
                        "邀请已受理，但缓存保存失败；已保留已知结果，请同步邀请", code="invite_cache_failed", status=500,
                    )
    except RemoteError as exc:
        if 300 <= exc.http_status < 500:
            for result in results.values():
                result.update(status="failed", message=str(exc))
            return list(results.values()), exc if exc.http_status in {401, 403, 429} else None
        logger.warning("[母号管理] 邀请响应待确认 parent=%s workspace=%s count=%s；未自动回查或重发",
                       client.parent["id"], client.workspace_id, len(emails))
    except TeamAdminError as exc:
        return list(results.values()), exc

    # A timeout or incomplete body remains unknown. Only explicit per-email
    # acknowledgements are successful; no follow-up GETs or repeated POSTs.
    return list(results.values()), None


def _run_invitations(client: TeamAdminClient, job: dict, results: list[dict], members: list[dict]) -> str:
    member_emails = {item["email"].casefold() for item in members}
    before = {item["email"]: item for item in _sync_invites(client)}
    pending = []
    for email in job["email_addresses"]:
        existing = before.get(email)
        if email in member_emails or (existing and existing["status"] == 2 and not job["resend_emails"]):
            results.append({"email": email, "target": job["seat_type"], "status": "unchanged",
                            "message": "已在工作区，无需邀请" if email in member_emails else "已有待接受邀请，未重发"})
        else:
            pending.append(email)
    store.update_job(job["id"], results=results, completed=len(results))
    for offset in range(0, len(pending), _INVITE_BATCH_SIZE):
        _check_cancel(job["id"])
        emails = pending[offset:offset + _INVITE_BATCH_SIZE]
        store.mark_invites_stale(client.workspace_id)
        store.update_job(job["id"], inflight_emails=emails, message=f"正在邀请：已处理 {len(results)}/{job['total']}")
        batch, stop = _invite_batch(client, job, emails)
        results.extend(batch)
        store.update_job(job["id"], results=results, completed=len(results), inflight_emails=[],
                         message=f"已处理 {len(results)}/{job['total']} 个邮箱")
        logger.info("[母号管理] 邀请分组完成 parent=%s workspace=%s processed=%s/%s",
                    client.parent["id"], client.workspace_id, len(results), job["total"])
        if stop:
            raise stop
    sent = sum(result["status"] == "success" for result in results)
    skipped = sum(result["status"] == "unchanged" for result in results)
    return f"邀请接口已受理 {sent} 个，无需发送 {skipped} 个"


def _wait_seat_switch_slot(client: TeamAdminClient):
    """Space writes across all parent records for the same workspace."""
    while True:
        _check_cancel(client.job_id)
        with _LOCKS_GUARD:
            now = time.monotonic()
            remaining = _SEAT_NEXT_AT.get(client.workspace_id, 0) - now
            if remaining <= 0:
                _SEAT_NEXT_AT[client.workspace_id] = now + _SEAT_SWITCH_INTERVAL
                return
        time.sleep(min(remaining, 0.25))


def _switch(client: TeamAdminClient, member: dict, target: str) -> dict:
    """Trust explicit mutation success; never query members after a seat write."""
    result = {"user_id": member["id"], "email": member["email"], "target": target}
    if member["seat_type"] == target and not member.get("pending_seat_type"):
        return {**result, "status": "unchanged", "message": "已是目标席位"}
    path = f"/backend-api/accounts/{client.workspace_id}/users/{member['id']}/seat/update"
    _wait_seat_switch_slot(client)
    store.mark_workspace_stale(client.workspace_id)
    try:
        response = client.request(
            "POST", path, retry_rate_limit=True,
            body={"operation": "switch", "seat_type": target,
                  "flow_id": str(uuid.uuid4()), "mutation_attempt_id": str(uuid.uuid4())},
        )
        if response.get("success") is not True:
            raise TeamAdminError("席位接口未确认接受修改", code="switch_rejected", status=422)
    except RemoteError as exc:
        if 300 <= exc.http_status < 500:
            raise
        # Timeouts/5xx/malformed replies are ambiguous. Stop without further HTTP.
        raise SeatUnconfirmedError(exc) from None
    with _LOCKS_GUARD:
        _SEAT_NEXT_AT[client.workspace_id] = max(
            _SEAT_NEXT_AT.get(client.workspace_id, 0),
            time.monotonic() + _SEAT_SWITCH_INTERVAL,
        )
    return {**result, "status": "success", "message": "切换接口已确认成功；成员列表待手动同步"}


def _remove(client: TeamAdminClient, member: dict) -> dict:
    """Remove one member; a successful upstream response is the confirmation."""
    result = {"user_id": member["id"], "email": member["email"], "target": "removed"}
    path = f"/backend-api/accounts/{client.workspace_id}/users/{member['id']}"
    store.mark_workspace_stale(client.workspace_id)
    response = client.request("DELETE", path)
    if response.get("success") is not True:
        raise TeamAdminError("移除接口未确认成功", code="remove_rejected", status=422)
    store.remove_member(client.parent["id"], client.workspace_id, member["id"])
    return {**result, "status": "success", "message": "已从工作区移除"}


def _sync_members(client: TeamAdminClient) -> list[dict]:
    try:
        members = client.members()
    except TeamAdminError as exc:
        store.update_workspace(client.parent["id"], client.workspace_id, {"members_stale": True, "members_error": str(exc)})
        raise
    store.replace_members(client.parent["id"], client.workspace_id, members, {"members_stale": False, "members_error": ""})
    logger.info("[母号管理] 成员同步 parent=%s workspace=%s members=%s", client.parent["id"], client.workspace_id, len(members))
    return members


def _sync_seat_summary(client: TeamAdminClient):
    summary = client.summary()
    store.update_workspace(client.parent["id"], client.workspace_id, {**summary, "holds_stale": True})
    try:
        capacity = [row for row in summary.get("seat_capacity", []) if row["type"] in _HOLD_SEAT_TYPES]
        if summary.get("summary_error") or not capacity or any("held" not in row for row in capacity):
            raise RemoteError("未取得完整 Hold 席位统计，请重新同步成员")
        holders = []
        for row in capacity:
            _check_cancel(client.job_id)
            if not row["held"]:
                continue
            items = client.members(active_vacancy_hold_seat_type=row["type"])
            if len(items) != row["held"]:
                raise RemoteError(f"{row['type']} Hold 数量与名单不一致，请重新同步成员")
            holders.extend(items)
        # Replace both seat types together only after every page is confirmed.
        _check_cancel(client.job_id)
        store.replace_seat_holds(client.parent["id"], client.workspace_id, holders)
        logger.info("[母号管理] Hold 同步 parent=%s workspace=%s holds=%s", client.parent["id"], client.workspace_id, len(holders))
    except TeamAdminError as exc:
        if exc.code == "cancelled":
            raise
        store.update_workspace(client.parent["id"], client.workspace_id, {"holds_stale": True, "holds_error": str(exc)})
        logger.warning("[母号管理] Hold 同步未完成 parent=%s workspace=%s error=%s", client.parent["id"], client.workspace_id, exc)


def check_workspace_expiration(parent_id: int, workspace_id: str) -> dict:
    """Fetch and cache a workspace renewal date using only its Web AT.

    This is deliberately separate from the member-management job queue: it is
    a read-only request and should remain usable while a member operation is
    running.  A failed refresh records the error while preserving the last
    successful renewal date.
    """
    if not _ID.fullmatch(str(workspace_id or "")):
        raise TeamAdminError("工作区 ID 无效")
    parent = store.get_parent(parent_id)
    workspace = next((row for row in store.workspaces(parent_id) if row["id"] == workspace_id), None)
    if not workspace:
        raise TeamAdminError("工作区不存在，请先同步工作区", code="workspace_missing", status=404)
    if not workspace.get("can_manage"):
        raise TeamAdminError("当前母号没有这个工作区的管理权限", code="workspace_forbidden", status=422)

    client = None
    try:
        client = TeamAdminClient(parent)
        if not client.token:
            raise TeamAdminError("查询订阅到期时间需要母号 Web AT，请补充 AT", code="credentials_missing", status=422)
        client.workspace_id = workspace_id
        preview = client.subscription_preview()
        renewal_date = _text(preview.get("renewal_date"), 120)
        if not renewal_date:
            raise RemoteError("费用预览未返回续费日期")
        checked_at = store.now()
        store.update_workspace(parent_id, workspace_id, {
            "renewal_date": renewal_date,
            "expiration_checked_at": checked_at,
            "expiration_error": "",
        })
        logger.info("[母号管理] 订阅到期时间已更新 parent=%s workspace=%s renewal_date=%s",
                    parent_id, workspace_id, renewal_date)
    except TeamAdminError as exc:
        store.update_workspace(parent_id, workspace_id, {
            "expiration_checked_at": store.now(),
            "expiration_error": str(exc),
        })
        raise
    finally:
        if client:
            try:
                client.close()
            except Exception:
                pass
    return next((row for row in store.workspaces(parent_id) if row["id"] == workspace_id), workspace)


def _require_seat_support(workspace: dict, seat_type: str):
    if seat_type == "usage_based" and workspace.get("is_usage_based_seat_enabled") is not True:
        raise TeamAdminError("当前工作区未开放 Codex（usage_based）席位", code="seat_type_not_supported", status=422)


def _run(job_id: str):
    client = None
    held = None
    results = []
    job = None
    try:
        job = store.get_job(job_id)
        _check_cancel(job_id)
        store.update_job(job_id, status="running", message="正在验证母号与工作区")
        client = TeamAdminClient(store.get_parent(job["parent_id"]), job_id)
        spaces = client.discover()
        store.replace_workspaces(job["parent_id"], spaces)
        done_message = "已完成"
        if job["kind"] == "discover":
            if not spaces:
                raise TeamAdminError("未识别到 Team/Business 工作区，未同步任何成员", code="workspace_missing", status=422)
            manageable = [space for space in spaces if space["can_manage"]]
            if not manageable:
                raise TeamAdminError("已找到工作区，但当前母号没有成员管理权限", code="workspace_forbidden", status=422)
            store.update_job(job_id, total=len(manageable))
            member_count = 0
            for index, workspace in enumerate(manageable):
                _check_cancel(job_id)
                client.workspace_id = workspace["id"]
                store.update_job(job_id, message=f"正在同步工作区 {index + 1}/{len(manageable)} 的成员")
                member_count += len(_sync_members(client))
                _sync_seat_summary(client)
                store.update_job(job_id, completed=index + 1)
            done_message = f"已同步 {len(manageable)} 个工作区，共 {member_count} 名成员"
        else:
            workspace = next((row for row in spaces if row["id"] == job["workspace_id"]), None)
            if not workspace or not workspace["can_manage"]:
                raise TeamAdminError("当前母号没有这个工作区的管理权限", code="workspace_forbidden", status=422)
            if job["kind"] in {"switch", "invite"}:
                _require_seat_support(workspace, job["seat_type"])
            client.workspace_id = workspace["id"]
            if job["kind"] in {"switch", "remove", "invite", "schedule"}:
                with _LOCKS_GUARD:
                    lock = _WORKSPACE_LOCKS.setdefault(client.workspace_id, threading.Lock())
                store.update_job(job_id, message="等待当前工作区的成员管理操作")
                while not lock.acquire(timeout=0.25):
                    _check_cancel(job_id)
                held = lock
            store.update_job(job_id, message="正在同步邀请" if job["kind"] == "invites" else "正在同步成员")
            members = [] if job["kind"] == "invites" else _sync_members(client)
            if job["kind"] == "schedule":
                from core import team_schedule_service
                team_schedule_service.run(client, job, members, workspace)
                store.set_parent_state(job["parent_id"], "ready")
                return
            if job["kind"] == "members":
                done_message = f"已同步 {len(members)} 名成员"
            elif job["kind"] == "invites":
                done_message = f"已同步 {len(_sync_invites(client))} 条邀请"
            elif job["kind"] == "invite":
                done_message = _run_invitations(client, job, results, members)
            if job["kind"] in {"switch", "remove"}:
                from core import team_account_removal
                indexed = {item["id"]: item for item in members}
                removal_targets = {}
                account_targets = {}
                if job.get("removal_plan"):
                    team_account_removal.validate_plan(job["removal_plan"])
                    removal_targets = {item["user_id"]: item for item in job["removal_plan"]["items"] if item["status"] == "ready"}
                    if set(job["user_ids"]) != set(removal_targets):
                        raise TeamAdminError("移除任务的成员列表与授权预览不一致")
                if job.get("account_plan"):
                    from core import team_account_switch
                    team_account_switch.validate_plan(job["account_plan"])
                    account_targets = {item["user_id"]: item for item in job["account_plan"]["items"] if item["status"] == "ready"}
                    if set(job["user_ids"]) != set(account_targets):
                        raise TeamAdminError("切换任务的成员列表与授权预览不一致")
                for user_id in job["user_ids"]:
                    _check_cancel(job_id)
                    member = indexed.get(user_id)
                    removal_target = removal_targets.get(user_id)
                    account_target = account_targets.get(user_id)
                    if member is None:
                        result = {"user_id": user_id, "status": "unchanged" if removal_target else "failed",
                                  "message": "成员已不在该工作区，无需移除" if removal_target else "目标不在当前成员列表中"}
                    else:
                        try:
                            if removal_target:
                                team_account_removal.check_live_member(member, removal_target)
                            elif account_target:
                                team_account_removal.check_live_member(member, account_target)
                            result = (_switch(client, member, job["seat_type"])
                                      if job["kind"] == "switch" else _remove(client, member))
                        except (RemoteError, SeatUnconfirmedError) as exc:
                            status = "unconfirmed" if isinstance(exc, SeatUnconfirmedError) else "failed"
                            result = {"user_id": user_id, "email": member["email"], "status": status, "message": str(exc)}
                            if job["kind"] == "switch":
                                target_record = account_target or {}
                                if target_record:
                                    result.update(account_id=target_record["account_id"], email=target_record["email"])
                                results.append(result)
                                store.update_job(job_id, results=results, completed=len(results))
                                raise
                        except TeamAdminError as exc:
                            if exc.code == "cancelled":
                                raise
                            result = {"user_id": user_id, "email": member["email"], "status": "failed", "message": str(exc)}
                    if removal_target:
                        result.update(account_id=removal_target["account_id"], email=removal_target["email"])
                    elif account_target:
                        result.update(account_id=account_target["account_id"], email=account_target["email"])
                    results.append(result)
                    store.update_job(job_id, results=results, completed=len(results), message=f"已处理 {len(results)}/{len(job['user_ids'])}")
            if job["kind"] != "switch":
                _sync_seat_summary(client)
        _check_cancel(job_id)
        failed = sum(row["status"] not in {"success", "unchanged"} for row in results)
        store.set_parent_state(job["parent_id"], "ready")
        failed_message = f"{failed} 个邮箱未确认成功" if job["kind"] == "invite" else f"{failed} 个成员未确认成功"
        store.update_job(job_id, status="partial" if failed else "success", message=failed_message if failed else done_message, finished_at=store.now())
        logger.info("[母号管理] 任务完成 parent=%s kind=%s status=%s", job["parent_id"], job["kind"], "partial" if failed else "success")
    except Exception as exc:
        cancelled = isinstance(exc, TeamAdminError) and exc.code == "cancelled"
        message = str(exc) if isinstance(exc, TeamAdminError) else f"母号管理失败：{type(exc).__name__}"
        if job and not cancelled:
            store.set_parent_state(job["parent_id"], "error", message)
        if job:
            store.update_job(job_id, status="cancelled" if cancelled else "failed", message=message, finished_at=store.now())
            if job["kind"] == "schedule":
                from core import account_completion_service
                try:
                    account_completion_service.cancel_source(job_id)
                except Exception as cancellation_error:
                    logger.error("[母号管理] 调度后续状态保存失败 job=%s error=%s", job_id, type(cancellation_error).__name__)
        logger.warning("[母号管理] parent=%s kind=%s %s", (job or {}).get("parent_id"), (job or {}).get("kind"), message)
    finally:
        if held:
            held.release()
        if client:
            try:
                client.close()
            except Exception:
                pass
        _SLOTS.release()


def _members_with_local_quota(members: list[dict]) -> list[dict]:
    accounts = db.get_account_quota_summaries_by_emails([str(row.get("email") or "") for row in members])
    result = []
    for member in members:
        email = str(member.get("email") or "").strip().casefold()
        account = accounts.get(email)
        match = "matched" if account is not None else "ambiguous" if email in accounts else "missing"
        result.append({**member, "local_account": account, "local_account_match": match})
    return result


def member_page_with_quota(parent_id: int, workspace_id: str, **options) -> dict:
    page = store.member_page(parent_id, workspace_id, **options)
    return {**page, "items": _members_with_local_quota(page["items"])}


def enqueue_member_quota_check(parent_id: int, workspace_id: str, data: dict) -> dict:
    from core.quota_check_service import enqueue_accounts_quota_check

    user_ids = data.get("user_ids")
    if not isinstance(user_ids, list) or not 1 <= len(user_ids) <= 500 or any(
        not isinstance(value, str) or not _ID.fullmatch(value) for value in user_ids
    ):
        raise TeamAdminError("一次请选择 1-500 个成员")
    if not any(item["id"] == workspace_id for item in store.workspaces(parent_id)):
        raise TeamAdminError("工作区不存在", status=404)
    user_ids = list(dict.fromkeys(user_ids))
    members = {row["id"]: row for row in _members_with_local_quota(
        store.members_by_ids(parent_id, workspace_id, user_ids),
    )}
    account_ids, unmatched = [], []
    for user_id in user_ids:
        member = members.get(user_id)
        account = member.get("local_account") if member else None
        if account is not None:
            account_ids.append(account["id"])
            continue
        reason = "成员不在当前缓存，请同步成员" if member is None else (
            "我的账号中有多条同邮箱记录" if member["local_account_match"] == "ambiguous" else "我的账号中未找到此邮箱"
        )
        unmatched.append({"user_id": user_id, "email": member.get("email") if member else None, "reason": reason})
    result = enqueue_accounts_quota_check(list(dict.fromkeys(account_ids)), trigger="team_admin")
    return {**result, "unmatched": unmatched, "unmatched_count": len(unmatched)}


def invite_account_targets(data: dict) -> dict:
    ids = data.get("account_ids")
    if not isinstance(ids, list) or not 1 <= len(ids) <= 200 or any(type(value) is not int or value <= 0 for value in ids):
        raise TeamAdminError("一次请选择 1-200 个账号")
    ids = list(dict.fromkeys(ids))
    accounts = db.get_account_supplement_candidates(ids)
    missing = [value for value in ids if value not in accounts]
    if missing:
        raise TeamAdminError(f"选中的账号已不存在，请重新选择：{', '.join(map(str, missing[:10]))}",
                             code="account_not_found", status=409)
    invalid = [value for value in ids if not _valid_invite_email(accounts[value]["email"])]
    if invalid:
        raise TeamAdminError(f"选中账号的邮箱格式无效：{', '.join(map(str, invalid[:10]))}", code="invalid_email")
    items = [{"id": value, "email": accounts[value]["email"].strip().casefold()} for value in ids]
    selection_hash = hashlib.sha256(json.dumps(items, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"items": items, "email_count": len({item["email"] for item in items}), "selection_hash": selection_hash}


def enqueue_account_invitations(parent_id: int, data: dict) -> dict:
    workspace_id = data.get("workspace_id")
    workspace = next((item for item in store.workspaces(parent_id) if item["id"] == workspace_id), None)
    if not workspace:
        raise TeamAdminError("工作区不存在，请先同步母号", code="workspace_missing", status=404)
    if not workspace.get("can_manage"):
        raise TeamAdminError("当前母号没有这个工作区的管理权限", code="workspace_forbidden", status=422)
    targets = invite_account_targets(data)
    if targets["selection_hash"] != data.get("selection_hash"):
        raise TeamAdminError("选中账号信息已变化，请刷新邮箱列表后重新提交", code="selection_changed", status=409)
    return enqueue(parent_id, {
        "kind": "invite", "workspace_id": workspace_id,
        "email_addresses": list(dict.fromkeys(item["email"] for item in targets["items"])),
        "seat_type": data.get("seat_type"), "resend_emails": data.get("resend_emails", False),
        "role": data.get("role", "standard-user"),
    })


def enqueue(parent_id: int, data: dict) -> dict:
    kind = data.get("kind")
    if not isinstance(kind, str) or kind not in {"discover", "members", "switch", "remove", "invite", "invites"}:
        raise TeamAdminError("不支持的母号管理操作")
    workspace_id = str(data.get("workspace_id") or "")
    if kind != "discover" and not _ID.fullmatch(workspace_id):
        raise TeamAdminError("工作区 ID 无效")
    user_ids = data.get("user_ids") or []
    target = str(data.get("seat_type") or "")
    invite_fields = {}
    if kind in {"switch", "remove"}:
        max_members = 200 if kind == "switch" else None
        if (not isinstance(user_ids, list) or not user_ids
                or (max_members is not None and len(user_ids) > max_members)
                or any(not isinstance(v, str) or not _ID.fullmatch(v) for v in user_ids)):
            raise TeamAdminError("一次请选择 1-200 个成员" if max_members else "一次至少选择 1 个成员")
        if kind == "switch" and target not in _SEAT_TYPES:
            raise TeamAdminError("目前仅支持 default、usage_based 和 prolite 席位")
        if kind == "remove":
            target = ""
        user_ids = list(dict.fromkeys(user_ids))
    elif kind == "invite":
        emails = data.get("email_addresses")
        if not isinstance(emails, list) or not 1 <= len(emails) <= 200:
            raise TeamAdminError("一次请提交 1-200 个邮箱")
        if any(not _valid_invite_email(email) for email in emails):
            raise TeamAdminError("邀请邮箱格式无效，请检查邮箱列表")
        target = target or "prolite"
        if target not in _SEAT_TYPES:
            raise TeamAdminError("目前仅支持 default、usage_based 和 prolite 席位")
        if data.get("role", "standard-user") != "standard-user":
            raise TeamAdminError("邀请仅支持普通成员角色")
        resend = data.get("resend_emails", False)
        if type(resend) is not bool:
            raise TeamAdminError("resend_emails 必须为布尔值")
        invite_fields = {"email_addresses": list(dict.fromkeys(email.strip().casefold() for email in emails)),
                         "resend_emails": resend}
        user_ids = []
    else:
        user_ids, target = [], ""
    if kind in {"switch", "invite"} and target == "usage_based":
        workspace = next((item for item in store.workspaces(parent_id) if item["id"] == workspace_id), None)
        # Legacy snapshots may lack this field; the worker rechecks live discovery.
        if workspace is not None and workspace.get("is_usage_based_seat_enabled") is False:
            _require_seat_support(workspace, target)
    return _enqueue_job(parent_id, kind, workspace_id, user_ids, target, **invite_fields)


def enqueue_account_removal(plan: dict) -> dict:
    """Only the validated local-account path can enqueue a whole batch (>200)."""
    user_ids = [item["user_id"] for item in plan["items"] if item["status"] == "ready"]
    return _enqueue_job(plan["parent_id"], "remove", plan["workspace_id"], user_ids, "", removal_plan=plan)


def enqueue_account_switch(plan: dict) -> dict:
    """Enqueue a validated local-account seat switch (batches may exceed 200)."""
    user_ids = [item["user_id"] for item in plan["items"] if item["status"] == "ready"]
    return _enqueue_job(plan["parent_id"], "switch", plan["workspace_id"], user_ids,
                       plan["seat_type"], account_plan=plan)


def _enqueue_job(parent_id: int, kind: str, workspace_id: str, user_ids: list[str], target: str, **fields) -> dict:
    if not _SLOTS.acquire(blocking=False):
        raise TeamAdminError("母号管理队列已满，请稍后提交", code="queue_full", status=429)
    job = None
    try:
        job = store.create_job(parent_id, kind, workspace_id, user_ids, target, **fields)
        _EXECUTOR.submit(_run, job["id"])
    except BaseException:
        _SLOTS.release()
        if job:
            store.update_job(job["id"], status="failed", message="任务入队失败")
        raise
    return {k: v for k, v in job.items() if k not in {"user_ids", "results", "email_addresses", "inflight_emails", "removal_plan", "account_plan"}}
