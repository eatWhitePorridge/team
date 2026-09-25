# -*- coding: utf-8 -*-
"""Read-only Codex usage checks with an independent bounded worker pool."""
from __future__ import annotations

import json
import logging
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

from config import proxy as proxy_cfg
from core import db
from core.chatgpt_plan import (
    normalize_token, resolve_plan_check_browser_family, resolve_plan_check_route, token_claims,
)
from core.session import BrowserSession

logger = logging.getLogger(__name__)
USAGE_PATH = "/backend-api/wham/usage"


class QuotaCredentialError(ValueError):
    """Only fixed, credential-free messages may cross the API boundary."""


def _setting(name: str, default: float, lower: float, upper: float) -> float:
    try:
        value = float(getattr(proxy_cfg, name, default))
        if not math.isfinite(value):
            value = default
    except (TypeError, ValueError):
        value = default
    return max(lower, min(upper, value))


_WORKERS = int(_setting("QUOTA_CHECK_WORKERS", 3, 1, 16))
_QUEUE_LIMIT = int(_setting("QUOTA_CHECK_QUEUE_LIMIT", 500, _WORKERS, 5000))
_EXECUTOR = ThreadPoolExecutor(max_workers=_WORKERS, thread_name_prefix="quota-check")
_QUEUE_SLOTS = threading.BoundedSemaphore(_QUEUE_LIMIT)
_RATE_LOCK = threading.Lock()
_NEXT_REQUEST_AT = 0.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _wait_for_rate_slot() -> None:
    global _NEXT_REQUEST_AT
    with _RATE_LOCK:
        now = time.monotonic()
        scheduled = max(now, _NEXT_REQUEST_AT)
        _NEXT_REQUEST_AT = scheduled + _setting("QUOTA_CHECK_MIN_INTERVAL", 0.25, 0, 30)
    if scheduled > now:
        time.sleep(scheduled - now)


def _number(value: Any, *, integer: bool = False) -> int | float | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(parsed) or parsed < 0 or (integer and not parsed.is_integer()):
        return None
    return int(parsed) if integer else parsed


def _bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _window(window: Any, now: int) -> dict | None:
    if not isinstance(window, dict):
        return None
    used = _number(window.get("used_percent"))
    if used is None:
        return None
    out = {"used_percent": used}
    for key in ("limit_window_seconds", "reset_after_seconds", "reset_at"):
        value = _number(window.get(key), integer=True)
        # Keep timestamps within the range supported by datetime and JS Date.
        if value is not None and value < 253402300800:
            out[key] = value
    if "reset_at" not in out and "reset_after_seconds" in out:
        reset_at = now + out["reset_after_seconds"]
        if reset_at < 253402300800:
            out["reset_at"] = reset_at
    return out


def _rate_limit(value: Any, now: int) -> dict | None:
    if not isinstance(value, dict):
        return None
    return {
        "allowed": _bool(value.get("allowed")),
        "limit_reached": _bool(value.get("limit_reached")),
        "primary_window": _window(value.get("primary_window"), now),
        "secondary_window": _window(value.get("secondary_window"), now),
    }


def parse_usage(data: Any, *, now: int | None = None) -> dict:
    """Preserve absent windows as unknown, never fabricate a zero usage value."""
    if not isinstance(data, dict) or data.get("error") or not any(
        key in data for key in ("rate_limit", "additional_rate_limits", "rate_limit_reset_credits")
    ):
        raise ValueError("额度接口未返回有效的额度结构")
    if "rate_limit" in data and data["rate_limit"] is not None and not isinstance(data["rate_limit"], dict):
        raise ValueError("额度窗口结构无效")
    now = int(time.time()) if now is None else now
    rate = _rate_limit(data.get("rate_limit"), now) or {}
    result = {
        "ok": True,
        "checked_at": datetime.fromtimestamp(now, timezone.utc).isoformat().replace("+00:00", "Z"),
        "quota_plan_type": str(data.get("plan_type") or "").strip()[:80] or None,
        "quota_allowed": rate.get("allowed"),
        "quota_limit_reached": rate.get("limit_reached"),
        "quota_additional_rate_limits": [],
    }
    for name in ("primary", "secondary"):
        window = rate.get(f"{name}_window") or {}
        for key in ("used_percent", "limit_window_seconds", "reset_after_seconds", "reset_at"):
            result[f"quota_{name}_{key}"] = window.get(key)
    additional = data.get("additional_rate_limits")
    for item in additional[:16] if isinstance(additional, list) else []:
        if not isinstance(item, dict):
            continue
        limit = _rate_limit(item.get("rate_limit"), now)
        if limit:
            result["quota_additional_rate_limits"].append({
                "limit_name": str(item.get("limit_name") or "")[:120],
                "metered_feature": str(item.get("metered_feature") or "")[:120],
                "rate_limit": limit,
            })
    reset = data.get("rate_limit_reset_credits")
    reset = reset if isinstance(reset, dict) else {}
    result["quota_reset_credits_available_count"] = _number(reset.get("available_count"), integer=True)
    expirations = []
    credits = reset.get("credits")
    for credit in credits[:100] if isinstance(credits, list) else []:
        try:
            stamp = datetime.fromisoformat(credit["expires_at"].replace("Z", "+00:00"))
            if stamp.tzinfo is not None:
                expirations.append(stamp.isoformat())
        except (AttributeError, KeyError, TypeError, ValueError):
            pass
    result["quota_reset_credit_expirations"] = expirations
    return result


def _credential(account: dict) -> tuple[str, str, str]:
    """Read existing tokens only. Quota checks never rotate RT or start OAuth."""
    email = str(account.get("email") or "").strip().lower()
    credential = {}
    raw_path = str(account.get("codex_credential_path") or "").strip()
    if raw_path:
        # Resolve the stored filename against this machine's managed directory.
        root = db._CODEX_DIR.resolve()
        path = (root / Path(raw_path).name).resolve()
        if not path.is_relative_to(root):
            raise QuotaCredentialError("Codex 凭证路径无效")
        if not path.is_file():
            raise QuotaCredentialError("Codex 凭证文件缺失，请先重新授权 Codex")
        if path.stat().st_size > 512 * 1024:
            raise QuotaCredentialError("Codex 凭证文件过大")
        credential = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(credential, dict):
            raise QuotaCredentialError("Codex 凭证格式无效")
    codex_token = normalize_token(str(credential.get("access_token") or ""))
    codex_claims = token_claims(codex_token) if codex_token else {}
    for candidate_email in (
        credential.get("email"), codex_claims.get("email"),
        (codex_claims.get("payload") or {}).get("email"),
    ):
        if candidate_email and str(candidate_email).strip().lower() != email:
            raise QuotaCredentialError("Codex 凭证邮箱与当前账号不符")
    codex_workspace = str(codex_claims.get("account_id") or credential.get("account_id") or "").strip()
    if (codex_claims.get("account_id") and credential.get("account_id")
            and codex_claims["account_id"] != credential["account_id"]):
        raise QuotaCredentialError("Codex 凭证工作空间不一致")
    if raw_path and not codex_workspace:
        raise QuotaCredentialError("Codex 凭证缺少工作空间，请先重新授权 Codex")
    expired = codex_claims.get("token_expired") is True
    if credential.get("expired"):
        try:
            expiry = datetime.fromisoformat(str(credential["expired"]).replace("Z", "+00:00"))
            expired |= expiry.replace(tzinfo=expiry.tzinfo or timezone.utc).timestamp() <= time.time()
        except (ValueError, OverflowError):
            expired = True
    if codex_token and codex_workspace and not expired:
        return codex_token, codex_workspace, "codex"

    token = normalize_token(str(account.get("access_token") or ""))
    if not token:
        raise QuotaCredentialError("缺少有效 Web AT / Codex AT，请先重新授权")
    claims = token_claims(token)
    for candidate_email in (claims.get("email"), (claims.get("payload") or {}).get("email")):
        if candidate_email and str(candidate_email).strip().lower() != email:
            raise QuotaCredentialError("Web AT 邮箱与当前账号不符")
    if claims.get("token_expired") is True:
        raise QuotaCredentialError("Web AT / Codex AT 已过期，请先验活刷新或重新授权")
    workspace = str(claims.get("account_id") or account.get("account_id") or "").strip()
    if codex_workspace and workspace != codex_workspace:
        raise QuotaCredentialError("Codex AT 不可用，Web AT 属于其他工作空间，请先重新授权 Codex")
    if not workspace:
        raise QuotaCredentialError("缺少 chatgpt_account_id，请先查询套餐或重新授权")
    return token, workspace, "web"


def _headers(env: BrowserSession, token: str, workspace: str) -> dict:
    headers = env._get_common_headers()
    headers.update({
        "accept": "application/json", "authorization": f"Bearer {token}",
        "chatgpt-account-id": workspace, "openai-beta": "codex-1",
        "oai-language": "zh-CN", "originator": "Codex Desktop",
        "sec-fetch-site": "none", "sec-fetch-mode": "no-cors", "sec-fetch-dest": "empty",
        "priority": "u=4, i", "oai-device-id": env.device_id, "oai-session-id": env.oai_session_id,
    })
    return headers


def _failure(error: str, code: str, **fields) -> dict:
    return {"ok": False, "checked_at": _now_iso(), "error": error, "error_code": code, **fields}


def _retry_after(response) -> float:
    value = str((getattr(response, "headers", {}) or {}).get("retry-after") or "")
    try:
        seconds = float(value)
        return max(0, seconds) if math.isfinite(seconds) else 60
    except ValueError:
        try:
            return max(0, parsedate_to_datetime(value).timestamp() - time.time())
        except (ValueError, TypeError, OverflowError):
            return 0


def query_account_quota(account: dict) -> dict:
    try:
        token, workspace, source = _credential(account)
        if any(c in token + workspace for c in ("\r", "\n")) or len(workspace) > 200:
            raise QuotaCredentialError("额度查询凭证格式无效")
    except QuotaCredentialError as exc:
        return _failure(str(exc), "credential_invalid")
    except Exception as exc:
        return _failure(f"凭证读取失败: {type(exc).__name__}", "credential_invalid")

    timeout = _setting("QUOTA_CHECK_TIMEOUT", 20, 1, 60)
    attempts = int(_setting("QUOTA_CHECK_MAX_ATTEMPTS", 2, 1, 4))
    meta = {"quota_request_timeout": timeout, "quota_max_attempts": attempts}
    for attempt in range(1, attempts + 1):
        env = None
        retryable, retry_after = False, 0
        meta["quota_attempt_count"] = attempt
        try:
            route = resolve_plan_check_route(None)
            meta.update({f"quota_{key}": route.get(key) for key in (
                "network_route", "proxy_mode", "proxy_used", "proxy_fallback_reason",
            )})
            _wait_for_rate_slot()
            env = BrowserSession(
                proxy=route["proxy"], detect_exit_geo=False,
                browser_family=resolve_plan_check_browser_family(),
            )
            response = env.session.get(
                f"https://chatgpt.com{USAGE_PATH}", headers=_headers(env, token, workspace),
                allow_redirects=False, timeout=timeout,
            )
            status = int(response.status_code)
            if status == 200:
                try:
                    data = response.json()
                    parsed = parse_usage(data)
                except (TypeError, ValueError):
                    return _failure("额度接口返回格式异常", "invalid_response", http_status=status, **meta)
                if data.get("account_id") and str(data["account_id"]) != workspace:
                    return _failure("额度响应工作空间与请求不符", "workspace_mismatch", http_status=status, **meta)
                if data.get("email") and str(data["email"]).strip().lower() != str(account.get("email") or "").strip().lower():
                    return _failure("额度响应邮箱与账号不符", "email_mismatch", http_status=status, **meta)
                return {**parsed, **meta, "http_status": status, "quota_workspace_id": workspace, "quota_source": source}
            error = {
                401: "额度凭证已失效，请先刷新 AT 或重新授权",
                403: "额度接口拒绝访问，可能为访问挑战或工作空间权限不足",
                429: "额度查询被限频，请稍后重试",
            }.get(status, f"额度接口 HTTP {status}")
            result = _failure(error, f"http_{status}", http_status=status, **meta)
            retryable = status in {408, 425, 429} or status >= 500
            retry_after = _retry_after(response)
        except Exception as exc:
            result = _failure(f"额度请求失败: {type(exc).__name__}", "request_failed", **meta)
            retryable = not isinstance(exc, ValueError)
        finally:
            if env is not None:
                try:
                    env.session.close()
                except Exception:
                    pass
        if not retryable or attempt == attempts or retry_after > 30:
            return result
        time.sleep(max(retry_after, min(30, _setting("QUOTA_CHECK_RETRY_DELAY", 1, 0, 30) * attempt)))
    return _failure("额度查询失败", "query_failed", **meta)


def _run_quota_check(*, account_id: int, email: str, check_id: str, trigger: str) -> dict:
    try:
        if not db.mark_account_quota_check_running(account_id, check_id=check_id):
            return _failure("额度任务已被取消或替换", "claim_lost")
        account = db.get_account(account_id)
        result = query_account_quota(account) if account else _failure("账号已删除", "account_not_found")
        if not db.update_account_quota_check(account_id, result=result, check_id=check_id):
            return _failure("额度结果未保存，任务已被替换", "claim_lost")
        logger.log(
            logging.INFO if result.get("ok") else logging.WARNING,
            "[Quota] 查询完成: account_id=%s ok=%s source=%s workspace=%s code=%s",
            account_id, result.get("ok"), result.get("quota_source", "-"),
            result.get("quota_workspace_id", "-"), result.get("error_code", "-"),
        )
        return result
    except Exception as exc:
        result = _failure(f"额度查询内部异常: {type(exc).__name__}", "internal_error")
        try:
            db.update_account_quota_check(account_id, result=result, check_id=check_id)
        except Exception as persist_exc:
            logger.error("[Quota] 状态保存失败: account_id=%s error=%s", account_id, type(persist_exc).__name__)
        return result
    finally:
        _QUEUE_SLOTS.release()


def enqueue_accounts_quota_check(account_ids: list, *, trigger: str = "manual_bulk") -> dict:
    from core.supplement_queue import enqueue_supplement_batch

    def submit(*, account_id: int, email: str, claim_id: str, trigger: str):
        return _EXECUTOR.submit(
            _run_quota_check, account_id=account_id, email=email, check_id=claim_id, trigger=trigger,
        )

    return enqueue_supplement_batch(
        account_ids, kind="quota", trigger=trigger, slots=_QUEUE_SLOTS, submit=submit,
    )


def queue_settings() -> dict:
    return {
        "workers": _WORKERS, "queue_limit": _QUEUE_LIMIT,
        "min_interval": _setting("QUOTA_CHECK_MIN_INTERVAL", 0.25, 0, 30),
    }
