# -*- coding: utf-8 -*-
"""
本地文件持久化层。

根目录文件分工：
    - 用于注册的邮箱.txt      仅保留可继续注册的邮箱素材
    - 注册成功的邮箱.txt      仅保存注册成功的邮箱素材，不追加 token
    - 注册成功的token.txt     每行只保存一个 access token
    - 用于注册的邮箱.json     Outlook 账号池完整状态
    - 注册成功的邮箱.json     注册成功账号完整状态
"""
import json
import hashlib
import os
import re
import secrets
import sqlite3
import tempfile
import threading
import uuid
from copy import deepcopy
from datetime import datetime, timedelta
from html import escape
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DATA_DIR = _PROJECT_ROOT
_LEGACY_DATA_DIR = _PROJECT_ROOT / "data"
_LOG_DIR = _PROJECT_ROOT / "注册日志"
_PLAN_CHECK_STALE_SECONDS = 120
_PLAN_CHECK_QUEUE_STALE_SECONDS = 1800

_OUTLOOK_JSON = _PROJECT_ROOT / "用于注册的邮箱.json"
_OUTLOOK_TXT = _PROJECT_ROOT / "用于注册的邮箱.txt"
_GENERIC_API_EMAIL_JSON = _PROJECT_ROOT / "用于注册的API邮箱.json"
_GENERIC_API_EMAIL_TXT = _PROJECT_ROOT / "用于注册的API邮箱.txt"
_ICLOUD_EMAIL_JSON = _PROJECT_ROOT / "用于注册的iCloud邮箱.json"
_ICLOUD_EMAIL_TXT = _PROJECT_ROOT / "用于注册的iCloud邮箱.txt"
_MAILCOM_JSON = _PROJECT_ROOT / "用于注册的Mailcom邮箱.json"
_MAILCOM_TXT = _PROJECT_ROOT / "用于注册的Mailcom邮箱.txt"
_ACCOUNTS_JSON = _PROJECT_ROOT / "注册成功的邮箱.json"
_ACCOUNTS_TXT = _PROJECT_ROOT / "注册成功的邮箱.txt"
_TOKENS_TXT = _PROJECT_ROOT / "注册成功的token.txt"
_JOBS_JSON = _PROJECT_ROOT / "注册任务.json"
_BATCHES_JSON = _PROJECT_ROOT / "注册批次.json"
_EMAIL_ALLOCATIONS_JSON = _PROJECT_ROOT / "邮箱分配记录.json"
_VIEWER_HTML = _PROJECT_ROOT / "accounts_viewer.html"
_CODEX_DIR = _PROJECT_ROOT / "codex_accounts"
_CODEX_AGENT_DIR = _PROJECT_ROOT / "codex_agent_accounts"
_COOKIE_DIR = _PROJECT_ROOT / "account_cookies"
# 导出状态单独存：{ "codex-邮箱-plan.json": {"exported_at": "...", "exported_count": N} }
# 不污染 CPA 兼容的原文件
_CODEX_EXPORT_STATE = _PROJECT_ROOT / "codex_导出状态.json"

_LEGACY_SQLITE = _LEGACY_DATA_DIR / "registrations.db"
_LEGACY_OUTLOOK_JSON = _LEGACY_DATA_DIR / "outlook_accounts.json"
_LEGACY_ACCOUNTS_JSON = _LEGACY_DATA_DIR / "registered_accounts.json"
_LEGACY_JOBS_JSON = _LEGACY_DATA_DIR / "registration_jobs.json"
_LOCK = threading.RLock()
_JSON_CACHE_LOCK = threading.RLock()
_JSON_CACHE: dict[str, tuple[tuple[int, int, int], Any]] = {}
_BATCH_MERGE_RECOVERING = False
_ACCOUNT_IMPORT_RECOVERING = False
_CODEX_METADATA_LOCK = threading.RLock()
_CODEX_METADATA_CACHE: dict[str, tuple[tuple[int, int, int], dict | None]] = {}
_DERIVED_TEXT_SIGNATURES: dict[str, str] = {}
_PAYPAL_EVENT_CONDITION = threading.Condition()
_PAYPAL_EVENT_REVISION = 0
_EMAIL_LEASE_MINUTES = 30
_MAILCOM_ALIAS_RELEASE_LOCK_SECONDS = 15 * 60

_ROXY_TRAFFIC_FIELDS = frozenset({
    "schema_version", "driver", "measurement", "status",
    "uploaded_bytes", "downloaded_bytes", "total_bytes", "connection_count",
    "upstream_proxy", "unavailable_reason", "registration_outcome",
    "started_at", "finished_at", "updated_at", "partial", "finalization_reason",
})
_PROXY_CREDENTIAL_RE = re.compile(r"(?i)(https?|socks5h?)://[^/\s]+@")
_JOB_FAILURE_ERROR_FALLBACK = "任务失败，未记录错误详情"

# Account progress journal is deliberately explicit.  Never use a broad
# ``paypal_*``/``*_context`` prefix here: payment URLs, cookies and provider
# payloads can contain credentials.  These fields are bounded UI state only.
_ACCOUNT_PROGRESS_SAFE_FIELDS = frozenset({
    "plan_check_status", "plan_check_trigger", "plan_check_queued_at",
    "plan_check_started_at", "plan_check_completed_at", "plan_check_error",
    "plan_check_ok", "plan_checked_at", "plan_check_http_status",
    "plan_check_proxy_mode", "plan_check_network_route", "plan_check_proxy_used",
    "plan_check_proxy_fallback_reason", "token_expired", "token_expires_at",
    "current_plan_type", "plan_type", "subscription_plan",
    "has_active_subscription", "plan_expires_at", "plan_renews_at",
    "plan_cancels_at", "billing_period", "billing_currency", "is_delinquent",
    "discount_type", "discount_amount", "discount_duration_num_periods",
    "discount_expires_at", "discount_cancellation_policy",
    "discount_promo_campaign_id", "last_purchase_origin_platform", "last_will_renew",
    "plus_trial_eligible", "plus_trial_campaign_id", "plus_trial_title",
    "plus_trial_discount_percentage", "plus_trial_duration_num_periods",
    "plus_trial_duration_period", "eligible_offer_ids", "plan_last_success_at",
    "promo_coupon", "promo_state", "promo_redeemed_at", "promo_expires_at",
    "promo_promotion_length_days", "promo_check_http_status", "promo_check_error",
    "promo_checked_at", "promo_response_bytes", "promo_retry_after", "promo_retryable",
    "promo_redeemed", "promo_redeemed_by_user", "promo_redeemed_by_workspace",
    "promo_check_ok", "billing_page_config_ok", "billing_page_config_http_status",
    "billing_page_config_error", "billing_account_eligible",
    "billing_plan_management_eligible", "billing_free_workspace_upgrade_eligible",
    "app_store_billing_retry_check_ok", "app_store_billing_retry_http_status",
    "app_store_billing_retry_error", "app_store_subscription_in_billing_retry",
    "plus_trial_status", "plus_trial_actionable",
    "quota_status", "quota_trigger", "quota_queued_at", "quota_started_at",
    "quota_completed_at", "quota_checked_at", "quota_ok", "quota_error",
    "quota_http_status", "quota_plan_type", "quota_allowed",
    "quota_limit_reached", "quota_primary_used_percent",
    "quota_primary_limit_window_seconds", "quota_primary_reset_after_seconds",
    "quota_primary_reset_at", "quota_secondary_used_percent",
    "quota_secondary_limit_window_seconds", "quota_secondary_reset_after_seconds",
    "quota_secondary_reset_at", "quota_reset_credits_available_count",
    "quota_reset_credit_expirations", "quota_additional_rate_limits",
    "quota_network_route", "quota_proxy_mode", "quota_proxy_used",
    "quota_proxy_fallback_reason", "quota_attempt_count", "quota_max_attempts",
    "quota_request_timeout", "quota_check_id", "quota_last_success_at",
    "quota_workspace_id", "quota_source", "quota_error_code",
    "extract_link_status", "extract_link_ok", "extract_link_trigger",
    "extract_link_type", "extract_link_queued_at", "extract_link_started_at",
    "extract_link_completed_at", "extract_link_checked_at", "extract_link_error",
    "extract_link_message", "extract_link_job_id", "extract_link_cdk_remaining",
    "extract_link_failure_stage",
    "momo_status", "momo_trigger", "momo_force", "momo_queued_at",
    "momo_started_at", "momo_completed_at", "momo_checked_at", "momo_message",
    "momo_error", "momo_failure_stage", "momo_attempt_count",
    "paypal_zero_offer_status", "paypal_zero_offer_checked_at",
    "paypal_zero_offer_error",
    "paypal_extract_status", "paypal_extract_queued_at", "paypal_extract_started_at",
    "paypal_extract_checked_at", "paypal_extract_completed_at",
    "paypal_extract_error", "paypal_extract_failure_stage", "paypal_extract_message",
    "paypal_extract_attempt_count", "paypal_extract_requested_mode",
    "paypal_extract_actual_mode", "paypal_extract_fallback_reason",
    "paypal_payment_status", "paypal_payment_queued_at", "paypal_payment_started_at",
    "paypal_payment_authorized_at", "paypal_payment_verified_at",
    "paypal_payment_completed_at", "paypal_payment_message", "paypal_payment_error",
    "paypal_payment_failure_stage", "paypal_payment_failure_code",
    "paypal_payment_replay_safe", "paypal_payment_attempt_count",
    "paypal_sms_status", "paypal_sms_checked_at", "paypal_sms_error",
    "paypal_sms_message", "paypal_sms_failure_stage", "paypal_sms_attempt_count",
    "registration_driver", "registration_job_id", "registration_batch_id",
    "email_allocation_id", "oauth_requested",
    "web_cookie_credential_path", "web_cookie_saved_at", "web_cookie_count",
    "web_cookie_has_session", "web_cookie_capture_status", "web_cookie_capture_error",
    "codex_agent_status", "codex_agent_ok", "codex_agent_trigger",
    "codex_agent_queued_at", "codex_agent_started_at", "codex_agent_completed_at",
    "codex_agent_checked_at", "codex_agent_error", "codex_agent_message",
    "codex_agent_runtime_id", "codex_agent_network_route", "codex_agent_proxy_mode",
    "codex_agent_proxy_used", "codex_agent_proxy_fallback_reason",
    "codex_agent_device_id", "codex_agent_attempt_count", "codex_agent_max_attempts",
    "codex_agent_request_timeout", "codex_agent_sub2api_mode", "codex_agent_sub2api_total",
    "note", "note_updated_at", "archived", "archived_at",
    "paypal_mode", "paypal_requested_action", "paypal_trigger",
    "paypal_extract_proxy_pool_ref", "paypal_extract_proxy_pool_version",
    "paypal_payment_proxy_pool_ref", "paypal_payment_proxy_pool_version",
    # Normalized PP events are bounded and secret-redacted by
    # ``_normalize_paypal_event`` before they reach this journal.
    "paypal_events",
    "updated_at",
})

_PAYPAL_SENSITIVE_FIELDS = (
    "paypal_ba_url",
    "paypal_ba_token",
    "paypal_payment_context",
    "paypal_otp_context",
    "paypal_sms_request_id",
    "paypal_sms_context",
)
_PAYPAL_ACTIONS = frozenset({"extract", "pay", "extract_and_pay", "reauthorize"})
_PAYPAL_ZERO_OFFER_STATUSES = frozenset({
    "unchecked", "checking", "eligible", "not_eligible", "retryable_error", "failed",
})
_PAYPAL_EXTRACT_STATUSES = frozenset({
    "unchecked", "queued", "running", "success", "unavailable", "failed",
})
_PAYPAL_PAYMENT_STATUSES = frozenset({
    "not_started", "queued", "running", "waiting_otp", "authorized", "verifying",
    "confirmed", "pending", "verification_blocked", "failed",
})
_PAYPAL_EXTRACT_ACTIVE_STATUSES = frozenset({"queued", "running"})
_PAYPAL_PAYMENT_ACTIVE_STATUSES = frozenset({"queued", "running", "verifying"})
_PAYPAL_SMS_STATUSES = frozenset({
    "not_started", "acquiring", "acquired", "polling", "waiting",
    "code_received", "submitted", "consumed", "timeout", "rejected",
    "failed", "ambiguous",
})
_PAYPAL_SMS_ACTIVE_STATUSES = frozenset({"acquiring", "polling", "submitted"})
_PAYPAL_EVENT_LIMIT = 200
_PAYPAL_EVENT_PHASES = frozenset({
    "system", "zero_offer", "extract", "payment", "sms", "verify",
})
_PAYPAL_EVENT_SECRET_RE = re.compile(
    r"(?i)(?P<label>ba[_-]?token|access[_-]?token|refresh[_-]?token|authorization|"
    r"api[_-]?key|otp|验证码)(?P<sep>\s*[:=]\s*)(?P<value>[^\s&,;]+)"
)
_PAYPAL_EVENT_BEARER_RE = re.compile(r"(?i)\bBearer\s+[^\s,;]+")
_PAYPAL_EVENT_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]{10,}){1,2}\b")
_PAYPAL_EVENT_PREFIX_TOKEN_RE = re.compile(
    r"(?i)\b(?:BA-|EC-|tok_|cs_(?:live|test)_|seti_|pi_)[A-Za-z0-9._-]{6,}\b"
)
_PAYPAL_EVENT_PHONE_RE = re.compile(
    r"(?i)(?P<label>phone|mobile|手机号|手机号码|号码)(?P<sep>\s*[:=]?\s*)"
    r"(?P<value>\+?\d[\d ()-]{6,}\d)"
)

# Account-level Team invitation reconciliation states.  These values are kept
# deliberately separate from ``plan_type`` and ``access_token``: accepting an
# invitation changes the browser workspace cookie, but must not silently
# replace the account's personal Web AT.
_TEAM_INVITE_STATUSES = frozenset({
    "not_checked", "queued", "running", "invite_found", "needs_acceptance",
    "joined", "already_member", "no_invite", "expired", "wrong_account",
    "not_confirmed", "session_required", "unsupported", "failed",
})


def _paypal_account_is_active(row: dict) -> bool:
    return (
        str(row.get("paypal_zero_offer_status") or "unchecked").strip().lower() == "checking"
        or str(row.get("paypal_extract_status") or "unchecked").strip().lower()
        in _PAYPAL_EXTRACT_ACTIVE_STATUSES
        or str(row.get("paypal_payment_status") or "not_started").strip().lower()
        in _PAYPAL_PAYMENT_ACTIVE_STATUSES
        or str(row.get("paypal_sms_status") or "not_started").strip().lower()
        in _PAYPAL_SMS_ACTIVE_STATUSES
    )


def _notify_paypal_event() -> None:
    global _PAYPAL_EVENT_REVISION
    with _PAYPAL_EVENT_CONDITION:
        _PAYPAL_EVENT_REVISION += 1
        _PAYPAL_EVENT_CONDITION.notify_all()


def paypal_event_revision() -> int:
    with _PAYPAL_EVENT_CONDITION:
        return _PAYPAL_EVENT_REVISION


def wait_for_paypal_event_revision(after: int, timeout: float = 15.0) -> int:
    """Block an SSE producer until a PayPal event is appended or timeout expires."""
    expected = max(0, int(after or 0))
    with _PAYPAL_EVENT_CONDITION:
        _PAYPAL_EVENT_CONDITION.wait_for(
            lambda: _PAYPAL_EVENT_REVISION > expected,
            timeout=max(0.0, min(60.0, float(timeout))),
        )
        return _PAYPAL_EVENT_REVISION


def _reset_paypal_sms(row: dict) -> None:
    row.update({
        "paypal_sms_channel": None,
        "paypal_sms_provider": None,
        "paypal_sms_service_id": None,
        "paypal_sms_request_id": None,
        "paypal_sms_status": "not_started",
        "paypal_sms_cost": None,
        "paypal_sms_country": None,
        "paypal_sms_phone_masked": None,
        "paypal_sms_acquired_at": None,
        "paypal_sms_completed_at": None,
        "paypal_sms_error": None,
        "paypal_sms_context": None,
    })


def _paypal_event_text(value: Any, *, limit: int = 500) -> str:
    """Sanitize one persisted PP event field before it reaches disk or API output."""
    text = _redact_proxy_text(value, limit=max(limit * 2, 600))
    text = _PAYPAL_EVENT_BEARER_RE.sub("Bearer ***", text)
    text = _PAYPAL_EVENT_JWT_RE.sub("***", text)
    text = _PAYPAL_EVENT_PREFIX_TOKEN_RE.sub("***", text)
    text = _PAYPAL_EVENT_SECRET_RE.sub(
        lambda match: f"{match.group('label')}{match.group('sep')}***", text,
    )

    def _mask_phone(match: re.Match) -> str:
        digits = "".join(ch for ch in match.group("value") if ch.isdigit())
        suffix = digits[-4:] if digits else ""
        return f"{match.group('label')}{match.group('sep')}+**{suffix}"

    text = _PAYPAL_EVENT_PHONE_RE.sub(_mask_phone, text)
    return text[:limit]


def _normalize_paypal_event(event: Any) -> dict | None:
    if not isinstance(event, dict):
        return None
    phase = str(event.get("phase") or "system").strip().lower()
    if phase not in _PAYPAL_EVENT_PHASES:
        phase = "system"
    status = re.sub(r"[^a-z0-9_-]", "_", str(event.get("status") or "info").lower())[:80]
    try:
        attempt = max(0, int(event.get("attempt"))) if event.get("attempt") is not None else None
    except (TypeError, ValueError):
        attempt = None
    timestamp = str(event.get("time") or _now())[:64]
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        timestamp = _now()
    event_id = re.sub(r"[^A-Za-z0-9_-]", "", str(event.get("id") or ""))[:64]
    method = re.sub(r"[^A-Z]", "", str(event.get("method") or "").upper())[:12] or None
    target = _paypal_event_text(event.get("target") or "", limit=240)
    target = re.split(r"[?#]", target, maxsplit=1)[0] or None
    try:
        http_status = int(event.get("http_status")) if event.get("http_status") is not None else None
    except (TypeError, ValueError):
        http_status = None
    if http_status is not None and not 100 <= http_status <= 599:
        http_status = None
    try:
        duration_ms = max(0, min(3_600_000, int(event.get("duration_ms")))) if event.get("duration_ms") is not None else None
    except (TypeError, ValueError):
        duration_ms = None
    normalized = {
        "id": event_id or uuid.uuid4().hex,
        "time": timestamp,
        "phase": phase,
        "status": status or "info",
        "message": _paypal_event_text(event.get("message") or ""),
        "attempt": attempt,
        "stage": _paypal_event_text(event.get("stage") or "", limit=80) or None,
        "method": method,
        "target": target,
        "http_status": http_status,
        "duration_ms": duration_ms,
        "mutation": bool(event.get("mutation")) if event.get("mutation") is not None else None,
        "failure_stage": _paypal_event_text(event.get("failure_stage") or "", limit=80) or None,
        "action": _paypal_event_text(event.get("action") or "", limit=80) or None,
        "trigger": _paypal_event_text(event.get("trigger") or "", limit=80) or None,
        "mode": _paypal_event_text(event.get("mode") or "", limit=80) or None,
    }
    if event.get("legacy") is True:
        normalized["legacy"] = True
    return normalized


def _derive_legacy_paypal_events(row: dict) -> list[dict]:
    """Create read-only summaries for accounts created before PP event persistence."""
    candidates = (
        (
            row.get("paypal_zero_offer_checked_at"), "zero_offer",
            row.get("paypal_zero_offer_status") or "unchecked",
            row.get("paypal_zero_offer_error") or "历史 0 元优惠检测状态",
            None, None,
        ),
        (
            row.get("paypal_extract_completed_at") or row.get("paypal_extract_started_at")
            or row.get("paypal_extract_queued_at"),
            "extract", row.get("paypal_extract_status") or "unchecked",
            row.get("paypal_extract_error") or row.get("paypal_extract_message")
            or "历史 PayPal 提链状态",
            row.get("paypal_extract_attempt_count"), row.get("paypal_extract_failure_stage"),
        ),
        (
            row.get("paypal_payment_completed_at") or row.get("paypal_payment_confirmed_at")
            or row.get("paypal_payment_authorized_at") or row.get("paypal_payment_started_at")
            or row.get("paypal_payment_queued_at"),
            "payment", row.get("paypal_payment_status") or "not_started",
            row.get("paypal_payment_error") or row.get("paypal_payment_message")
            or "历史 PayPal 授权状态",
            row.get("paypal_payment_attempt_count"), row.get("paypal_payment_failure_stage"),
        ),
        (
            row.get("paypal_sms_completed_at") or row.get("paypal_sms_acquired_at"),
            "sms", row.get("paypal_sms_status") or "not_started",
            row.get("paypal_sms_error") or "历史 PayPal 接码状态",
            row.get("paypal_payment_attempt_count"), None,
        ),
    )
    events = []
    for index, (timestamp, phase, status, message, attempt, failure_stage) in enumerate(candidates):
        if not timestamp:
            continue
        event = _normalize_paypal_event({
            "id": f"legacy-{phase}-{index}",
            "time": timestamp,
            "phase": phase,
            "status": status,
            "message": message,
            "attempt": attempt,
            "failure_stage": failure_stage,
            "action": row.get("paypal_requested_action"),
            "trigger": row.get("paypal_trigger"),
            "mode": row.get("paypal_extract_actual_mode") or row.get("paypal_mode"),
            "legacy": True,
        })
        if event:
            events.append(event)
    events.sort(key=lambda item: str(item.get("time") or ""))
    return events


def _paypal_events_for_row(row: dict) -> list[dict]:
    raw = row.get("paypal_events")
    events = [
        normalized
        for normalized in (
            _normalize_paypal_event(item) for item in (raw or [])[-_PAYPAL_EVENT_LIMIT:]
        )
        if normalized is not None
    ] if isinstance(raw, list) else []
    return events or _derive_legacy_paypal_events(row)


_LEGACY_RESTARTABLE_PAYPAL_SIGNUP_CODES = frozenset({
    "OAS_ERROR",
})

_RESTARTABLE_PAYPAL_OTP_INIT_CODES = frozenset({
    "OTP_INITIATE_RESPONSE_UNCERTAIN",
    "OTP_CHALLENGE_MISSING",
})


def _paypal_has_legacy_restartable_signup_failure(row: dict) -> bool:
    """Recognize records written before explicit replay-safety was persisted."""
    if row.get("paypal_payment_reference") or row.get("paypal_agreement_id"):
        return False
    for event in reversed(_paypal_events_for_row(row)):
        if str(event.get("phase") or "").strip().lower() != "payment":
            continue
        status = str(event.get("status") or "").strip().lower()
        stage = str(event.get("stage") or event.get("failure_stage") or "").strip().lower()
        if status == "checkpoint" and stage == "pending_verification":
            return False
        if status == "failed" and stage == "signup":
            message = str(event.get("message") or "").upper()
            return any(code in message for code in _LEGACY_RESTARTABLE_PAYPAL_SIGNUP_CODES)
        if status in {"authorized", "confirmed"}:
            return False
        if status == "queued":
            break
    return False


def _paypal_payment_can_restart(row: dict, *, action: str) -> bool:
    if str(action or "").strip().lower() == "reauthorize":
        return True
    if str(action or "").strip().lower() not in {"pay", "extract_and_pay"}:
        return False
    status = str(row.get("paypal_payment_status") or "not_started").strip().lower()
    stage = str(row.get("paypal_payment_failure_stage") or "").strip().lower()
    if status == "verification_blocked" and stage in {
        "phone_required", "sms_acquire", "locale_metadata",
    }:
        return True
    if (
        status == "verification_blocked"
        and stage == "otp_initiate"
        and not row.get("paypal_payment_reference")
        and not row.get("paypal_agreement_id")
    ):
        error_text = " ".join((
            str(row.get("paypal_payment_failure_code") or ""),
            str(row.get("paypal_payment_error") or ""),
        )).upper()
        if any(code in error_text for code in _RESTARTABLE_PAYPAL_OTP_INIT_CODES):
            # OTP initiation cannot create a buyer or authorize the BA. Older
            # builds also misclassified PayPal's valid INITIATED state here.
            return True
    if (
        status in {"pending", "verification_blocked"}
        and stage in {"", "signup"}
        and bool(row.get("paypal_payment_replay_safe"))
        and not row.get("paypal_payment_reference")
        and not row.get("paypal_agreement_id")
    ):
        return True
    return (
        status in {"pending", "verification_blocked"}
        and _paypal_has_legacy_restartable_signup_failure(row)
    )


def _seed_paypal_events(row: dict) -> None:
    """Freeze legacy summaries before the first mutation of an old account."""
    if not isinstance(row.get("paypal_events"), list):
        row["paypal_events"] = _derive_legacy_paypal_events(row)


def _append_paypal_event(
    row: dict,
    *,
    phase: str,
    status: str,
    message: str,
    attempt: int | None = None,
    stage: str | None = None,
    method: str | None = None,
    target: str | None = None,
    http_status: int | None = None,
    duration_ms: int | None = None,
    mutation: bool | None = None,
    failure_stage: str | None = None,
    action: str | None = None,
    trigger: str | None = None,
    mode: str | None = None,
    timestamp: str | None = None,
) -> None:
    """Append a bounded, secret-free PP state transition to an account row."""
    _seed_paypal_events(row)
    raw = row.get("paypal_events")
    if isinstance(raw, list) and raw:
        events = [
            normalized
            for normalized in (
                _normalize_paypal_event(item) for item in raw[-_PAYPAL_EVENT_LIMIT:]
            )
            if normalized is not None
        ]
    else:
        events = []
    event = _normalize_paypal_event({
        "id": uuid.uuid4().hex,
        "time": timestamp or _now(),
        "phase": phase,
        "status": status,
        "message": message,
        "attempt": attempt,
        "stage": stage,
        "method": method,
        "target": target,
        "http_status": http_status,
        "duration_ms": duration_ms,
        "mutation": mutation,
        "failure_stage": failure_stage,
        "action": action if action is not None else row.get("paypal_requested_action"),
        "trigger": trigger if trigger is not None else row.get("paypal_trigger"),
        "mode": mode if mode is not None else (
            row.get("paypal_extract_actual_mode") or row.get("paypal_extract_requested_mode")
            or row.get("paypal_mode")
        ),
    })
    if event is None:
        return
    if events:
        comparable = (
            "phase", "status", "message", "attempt", "stage", "method",
            "target", "http_status", "duration_ms", "mutation",
            "failure_stage", "action", "trigger", "mode",
        )
        if all(events[-1].get(key) == event.get(key) for key in comparable):
            return
    events.append(event)
    row["paypal_events"] = events[-_PAYPAL_EVENT_LIMIT:]
    _notify_paypal_event()


def append_account_paypal_events(acc_id: int, events: list[dict] | tuple[dict, ...]) -> bool:
    """Append detailed, sanitized adapter traces with one accounts-file write."""
    if not isinstance(events, (list, tuple)):
        raise ValueError("PayPal events 必须是列表")
    with _LOCK:
        accounts = _load_accounts()
        row = next((item for item in accounts if int(item.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        previous = dict(row)
        for raw in events:
            if not isinstance(raw, dict):
                continue
            _append_paypal_event(
                row,
                phase=str(raw.get("phase") or "system"),
                status=str(raw.get("status") or "info"),
                message=str(raw.get("message") or ""),
                attempt=raw.get("attempt"),
                stage=raw.get("stage"),
                method=raw.get("method"),
                target=raw.get("target"),
                http_status=raw.get("http_status"),
                duration_ms=raw.get("duration_ms"),
                mutation=raw.get("mutation"),
                failure_stage=raw.get("failure_stage"),
                action=raw.get("action"),
                trigger=raw.get("trigger"),
                mode=raw.get("mode"),
                timestamp=raw.get("time"),
            )
        row["updated_at"] = _now()
        _save_account_progress_fields(accounts, row, previous, ("paypal_events", "updated_at"))
        return True


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _redact_proxy_text(value: Any, *, limit: int = 300) -> str:
    """先抹掉 URL userinfo，再限制长度；顺序不可反，否则超长凭证会漏出。"""
    text = str(value or "")
    text = _PROXY_CREDENTIAL_RE.sub(r"\1://***:***@", text)
    return text[:limit]


def _roxy_traffic_timestamp(value: Any) -> str | None:
    text = str(value or "").strip()[:64]
    if not text:
        return None
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return text


def _ensure_storage() -> None:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _LOG_DIR.mkdir(parents=True, exist_ok=True)


def _read_json(path: Path, default: Any) -> Any:
    _ensure_storage()
    if not path.exists():
        return default
    try:
        target = path.resolve(strict=False) if path.is_symlink() else path
        stat = target.stat()
        signature = (int(stat.st_mtime_ns), int(stat.st_size), int(stat.st_ino))
        cache_key = str(target)
        with _JSON_CACHE_LOCK:
            cached = _JSON_CACHE.get(cache_key)
            if cached is not None and cached[0] == signature:
                return cached[1]
        value = json.loads(target.read_text(encoding="utf-8"))
        with _JSON_CACHE_LOCK:
            _JSON_CACHE[cache_key] = (signature, value)
        return value
    except Exception:
        return default


def _dump_storage_json(data: Any, handle: Any) -> None:
    """Encode table rows in C, buffering writes without copying the whole table.

    json.dump walks nested containers in Python and emits many tiny writes.
    Encoding one row at a time keeps peak temporary memory bounded by a row
    plus the write buffer, while retaining the existing compact JSON format.
    """
    if not isinstance(data, list):
        json.dump(data, handle, ensure_ascii=False, separators=(",", ":"))
        return
    handle.write("[")
    chunks: list[str] = []
    size = 0
    for index, row in enumerate(data):
        chunk = ("," if index else "") + json.dumps(
            row, ensure_ascii=False, separators=(",", ":"),
        )
        chunks.append(chunk)
        size += len(chunk)
        if size >= 256 * 1024:
            handle.write("".join(chunks))
            chunks.clear()
            size = 0
    if chunks:
        handle.write("".join(chunks))
    handle.write("]")


def _write_json(path: Path, data: Any) -> None:
    _ensure_storage()
    # Docker entrypoint exposes persistent files as /app -> /runtime symlinks.
    # Replacing the link path would detach it from the volume, so perform the
    # atomic write beside the resolved target while keeping the link intact.
    target = path.resolve(strict=False) if path.is_symlink() else path
    target.parent.mkdir(parents=True, exist_ok=True)
    # These files are application storage rather than hand-edited config.  A
    # compact encoding materially shortens every whole-file rewrite (accounts
    # and jobs can grow to tens of MiB) without changing the JSON contract.
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=str(target.parent),
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            _dump_storage_json(data, handle)
        tmp.replace(target)
    except BaseException:
        # KeyboardInterrupt/SystemExit 也必须清理未完成的临时文件；原目标尚未
        # replace，保持不变，然后原样抛出中断信号。
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    stat = target.stat()
    signature = (int(stat.st_mtime_ns), int(stat.st_size), int(stat.st_ino))
    with _JSON_CACHE_LOCK:
        _JSON_CACHE[str(target)] = (signature, data)


def _next_id(items: list[dict]) -> int:
    ids = [int(item.get("id") or 0) for item in items]
    return (max(ids) if ids else 0) + 1


def _outlook_line(row: dict) -> str:
    return "----".join([
        row.get("email") or "",
        row.get("password") or "",
        row.get("client_id") or "",
        row.get("refresh_token") or "",
    ])


def _generic_api_email_line(row: dict) -> str:
    return "----".join([
        row.get("email") or "",
        row.get("code_url") or "",
    ])


def _icloud_email_line(row: dict) -> str:
    if str(row.get("protocol") or "").strip().lower() == "generic_api":
        return "----".join([
            row.get("email") or "",
            row.get("pickup_url") or "",
        ])
    return "---".join([
        row.get("email") or "",
        row.get("token") or "",
        row.get("pickup_url") or "",
    ])


def _mailcom_line(row: dict) -> str:
    return "----".join([
        str(row.get("email") or ""),
        str(row.get("password") or ""),
    ])


def _icloud_pickup_url_preview(raw_url: str) -> str:
    """生成不暴露 query、fragment 或分享链接路径凭证的预览。"""
    raw = str(raw_url or "").strip()
    base = raw.split("?", 1)[0].split("#", 1)[0]
    base = re.sub(
        r"(?i)(https?://(?:mail\.mczero\.top|icloud-api\.top)/(?:s|sq)/)[^/]+(/)",
        r"\1***\2",
        base,
        count=1,
    )
    if "?" in raw:
        return base + "?..."
    if "#" in raw:
        return base + "#..."
    return base


def _generic_api_code_url_preview(raw_url: str) -> str:
    """生成不会暴露 query、fragment 或 `/code/<secret>` 路径凭证的预览。"""
    from core.generic_api_mail_client import mask_code_url

    return mask_code_url(raw_url)


def _account_line(row: dict) -> str:
    base = row.get("original_email_line") or row.get("email") or ""
    token = row.get("access_token") or ""
    totp = row.get("totp_secret") or ""
    return f"{base}----{token}----{totp}" if totp else f"{base}----{token}"


def _registered_email_line(row: dict) -> str:
    """生成注册成功邮箱 TXT 的行内容；token 由注册成功的token.txt 单独保存。"""
    return row.get("original_email_line") or row.get("email") or ""


def _mailbox_import_line(source: str, row: dict) -> str:
    """返回邮箱素材的原始导入行；旧数据按来源重建兼容格式。"""
    original = str(row.get("original_email_line") or "").strip()
    if original:
        return original
    if source == "outlook":
        return _outlook_line(row)
    if source == "generic_api":
        return _generic_api_email_line(row)
    if source == "icloud":
        return _icloud_email_line(row)
    if source == "mailcom":
        return _mailcom_line(row)
    return str(row.get("email") or "")


def _sync_derived_lines(path: Path, lines: list[str]) -> None:
    """Rewrite a derived text export only when its content actually changed."""
    digest = hashlib.blake2b(digest_size=16)
    for line in lines:
        digest.update(line.encode("utf-8"))
        digest.update(b"\n")
    signature = digest.hexdigest()
    key = str(path)
    if _DERIVED_TEXT_SIGNATURES.get(key) == signature and path.exists():
        return
    path.write_text(("\n".join(lines) + ("\n" if lines else "")), encoding="utf-8")
    _DERIVED_TEXT_SIGNATURES[key] = signature


def _sync_outlook_txt(rows: list[dict]) -> None:
    available_rows = [r for r in rows if r.get("status") == "available"]
    lines = [_outlook_line(r) for r in sorted(available_rows, key=lambda x: int(x.get("id") or 0))]
    _sync_derived_lines(_OUTLOOK_TXT, lines)


def _sync_generic_api_email_txt(rows: list[dict]) -> None:
    available_rows = [r for r in rows if r.get("status") == "available"]
    lines = [_generic_api_email_line(r) for r in sorted(available_rows, key=lambda x: int(x.get("id") or 0))]
    _sync_derived_lines(_GENERIC_API_EMAIL_TXT, lines)


def _sync_icloud_email_txt(rows: list[dict]) -> None:
    available_rows = [r for r in rows if r.get("status") == "available"]
    lines = [
        _mailbox_import_line("icloud", r)
        for r in sorted(available_rows, key=lambda x: int(x.get("id") or 0))
    ]
    _sync_derived_lines(_ICLOUD_EMAIL_TXT, lines)


def _sync_mailcom_txt(rows: list[dict]) -> None:
    available_rows = [r for r in rows if r.get("status") == "available"]
    lines = [
        _mailbox_import_line("mailcom", row)
        for row in sorted(available_rows, key=lambda item: int(item.get("id") or 0))
    ]
    _sync_derived_lines(_MAILCOM_TXT, lines)


def _sync_accounts_txt(rows: list[dict]) -> None:
    lines = [_registered_email_line(r) for r in sorted(rows, key=lambda x: int(x.get("id") or 0))]
    _sync_derived_lines(_ACCOUNTS_TXT, lines)


def _sync_tokens_txt(rows: list[dict]) -> None:
    tokens = [
        r.get("access_token") or ""
        for r in sorted(rows, key=lambda x: int(x.get("id") or 0))
        if r.get("access_token")
    ]
    _sync_derived_lines(_TOKENS_TXT, tokens)


def _viewer_snapshot(outlook_rows: list[dict], account_rows: list[dict]) -> dict:
    account_by_email = {
        (a.get("email") or "").lower(): a
        for a in account_rows
    }
    return {
        "generated_at": _now(),
        "accounts": [
            _decorate_account(r)
            for r in sorted(account_rows, key=lambda x: int(x.get("id") or 0), reverse=True)
        ],
        "outlook": [
            _decorate_outlook(r, account_by_email)
            for r in sorted(outlook_rows, key=lambda x: int(x.get("id") or 0), reverse=True)
        ],
        "summary": {
            "accounts": len(account_rows),
            "outlook_total": len(outlook_rows),
            "outlook_available": sum(1 for r in outlook_rows if r.get("status") == "available"),
            "outlook_used": sum(1 for r in outlook_rows if r.get("status") == "used"),
            "outlook_failed": sum(1 for r in outlook_rows if r.get("status") == "failed"),
        },
    }


def _render_static_viewer(outlook_rows: list[dict] | None = None, account_rows: list[dict] | None = None) -> Path:
    """生成可直接双击打开的静态账号查看页。"""
    outlook_rows = _load_outlook() if outlook_rows is None else outlook_rows
    account_rows = _load_accounts() if account_rows is None else account_rows
    snapshot = _viewer_snapshot(outlook_rows, account_rows)
    data_json = json.dumps(snapshot, ensure_ascii=False).replace("</", "<\\/")
    title = escape(f"账号查看器 - {snapshot['generated_at']}")
    html_text = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>
    * {{ box-sizing: border-box; }}
    :root {{
      --bg: #eef3f8;
      --surface: #ffffff;
      --soft: #f7f9fc;
      --text: #172033;
      --muted: #667085;
      --line: #d9e2ec;
      --blue: #2563eb;
      --green: #16803c;
      --red: #c2413a;
      --amber: #b7791f;
    }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    header {{
      padding: 22px 28px;
      background: #101827;
      color: #fff;
      display: flex;
      justify-content: space-between;
      gap: 20px;
      align-items: center;
      flex-wrap: wrap;
    }}
    h1, h2, p {{ margin: 0; }}
    h1 {{ font-size: 28px; }}
    .meta {{ margin-top: 6px; color: #b8c7d9; font-size: 13px; }}
    .stats {{ display: flex; gap: 10px; flex-wrap: wrap; }}
    .stat {{
      min-width: 116px;
      padding: 10px 12px;
      border: 1px solid rgba(255,255,255,.16);
      border-radius: 8px;
      background: rgba(255,255,255,.08);
    }}
    .stat span {{ display: block; color: #b8c7d9; font-size: 12px; }}
    .stat strong {{ display: block; margin-top: 4px; font-size: 18px; }}
    main {{ width: min(1500px, calc(100vw - 32px)); margin: 16px auto 30px; display: grid; gap: 16px; }}
    .toolbar, section {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface);
      box-shadow: 0 8px 22px rgba(15,23,42,.06);
    }}
    .toolbar {{ padding: 14px; display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; }}
    .search {{ min-width: min(520px, 100%); flex: 1; }}
    input {{
      width: 100%;
      min-height: 36px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 0 12px;
      font: inherit;
    }}
    .buttons {{ display: flex; gap: 8px; flex-wrap: wrap; }}
    button {{
      min-height: 32px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      padding: 0 12px;
      font-weight: 700;
      cursor: pointer;
    }}
    button:hover {{ background: var(--soft); }}
    button.primary {{ border-color: var(--blue); background: var(--blue); color: #fff; }}
    button.good {{ border-color: #2f855a; background: #edf8f1; color: #166534; }}
    button:disabled {{ color: #98a2b3; cursor: not-allowed; background: #f2f4f7; }}
    .head {{ padding: 14px 16px; border-bottom: 1px solid var(--line); background: var(--soft); }}
    .head p {{ margin-top: 4px; color: var(--muted); font-size: 12px; }}
    .table-wrap {{ overflow: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid #edf1f5; text-align: left; white-space: nowrap; vertical-align: middle; }}
    th {{ position: sticky; top: 0; background: #fbfcfe; color: #475467; z-index: 1; font-size: 12px; }}
    tr:hover td {{ background: #fbfdff; }}
    .main-cell {{ font-weight: 700; }}
    .sub-cell {{ margin-top: 3px; color: var(--muted); font-size: 12px; }}
    .mono {{ font-family: ui-monospace, "JetBrains Mono", Consolas, monospace; font-size: 12px; }}
    .muted {{ color: var(--muted); }}
    .pill {{ display: inline-flex; min-width: 48px; justify-content: center; padding: 3px 8px; border-radius: 999px; font-size: 12px; font-weight: 700; }}
    .status-available {{ color: var(--blue); background: #eef4ff; }}
    .status-used {{ color: #475467; background: #f2f4f7; }}
    .status-failed {{ color: var(--red); background: #fff0ef; }}
    .actions {{ display: flex; gap: 8px; flex-wrap: wrap; }}
    #toast {{
      position: fixed;
      right: 18px;
      bottom: 18px;
      padding: 10px 14px;
      border-radius: 8px;
      background: #101827;
      color: #fff;
      box-shadow: 0 14px 30px rgba(15,23,42,.24);
      opacity: 0;
      transform: translateY(8px);
      pointer-events: none;
      transition: opacity .18s ease, transform .18s ease;
    }}
    #toast.show {{ opacity: 1; transform: translateY(0); }}
    @media (max-width: 820px) {{
      header {{ align-items: flex-start; }}
      .stats {{ width: 100%; }}
      .stat {{ flex: 1; }}
    }}
  </style>
</head>
<body>
<header>
  <div>
    <h1>账号查看器</h1>
    <p class="meta">静态快照，无需启动 Web Server。生成时间：<span id="generated"></span></p>
  </div>
  <div class="stats">
    <div class="stat"><span>已完成</span><strong id="statAccounts">0</strong></div>
    <div class="stat"><span>邮箱总数</span><strong id="statOutlook">0</strong></div>
    <div class="stat"><span>可用邮箱</span><strong id="statAvailable">0</strong></div>
  </div>
</header>
<main>
  <div class="toolbar">
    <div class="search"><input id="q" placeholder="搜索邮箱、token、clientId、状态"></div>
    <div class="buttons">
      <button class="primary" id="copyAllTokens">复制全部 Token</button>
      <button class="good" id="copyAllLines">复制全部整行</button>
      <button id="copyAllEmails">复制全部邮箱素材</button>
    </div>
  </div>
  <section>
    <div class="head">
      <h2>已完成账号</h2>
      <p>整行格式：邮箱----密码----clientId----邮箱刷新令牌----accessToken----totpSecret（如有）</p>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>ID</th><th>邮箱</th><th>来源</th><th>Token</th><th>备注</th><th>2FA</th><th>创建时间</th><th>操作</th></tr></thead>
        <tbody id="accountsBody"></tbody>
      </table>
    </div>
  </section>
  <section>
    <div class="head">
      <h2>邮箱素材库</h2>
      <p>原始格式：邮箱----密码----clientId----邮箱刷新令牌；注册完成后可直接复制对应 Token 或整行。</p>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>邮箱</th><th>状态</th><th>Token</th><th>导入时间</th><th>已用时间</th><th>操作</th></tr></thead>
        <tbody id="outlookBody"></tbody>
      </table>
    </div>
  </section>
</main>
<div id="toast"></div>
<script id="snapshot" type="application/json">{data_json}</script>
<script>
const SNAPSHOT = JSON.parse(document.getElementById('snapshot').textContent);
const $ = (s) => document.querySelector(s);
let copySeq = 0;
const copyStore = new Map();

function fmt(v) {{ return v == null || v === '' ? '-' : String(v); }}
function esc(v) {{
  return fmt(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}}
function short(v, n = 34) {{
  const s = v || '';
  return s.length > n ? `${{s.slice(0, n)}}...` : s;
}}
function copyId(v) {{
  if (!v) return '';
  const id = `c${{++copySeq}}`;
  copyStore.set(id, v);
  return id;
}}
function btn(label, value, cls = '') {{
  const id = copyId(value);
  return `<button class="${{cls}}" data-copy-id="${{id}}" ${{id ? '' : 'disabled'}}>${{label}}</button>`;
}}
function pill(status) {{
  const map = {{ available: '可用', used: '已用', failed: '失败' }};
  const label = map[status] || status || '-';
  return `<span class="pill status-${{esc(status)}}">${{esc(label)}}</span>`;
}}
function showToast(text) {{
  const toast = $('#toast');
  toast.textContent = text;
  toast.classList.add('show');
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove('show'), 1400);
}}
async function copyText(text) {{
  if (!text) return;
  if (navigator.clipboard && window.isSecureContext) {{
    await navigator.clipboard.writeText(text);
  }} else {{
    const area = document.createElement('textarea');
    area.value = text;
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    document.execCommand('copy');
    area.remove();
  }}
  showToast('已复制');
}}
function haystack(row) {{
  return Object.values(row).join('\\n').toLowerCase();
}}
function totpState(row) {{
  const status = String(row.totp_status || (row.totp_secret ? 'active' : 'not_configured'));
  if (status === 'active') return '已启用';
  if (status === 'active_external') return '已启用/无密钥';
  if (status === 'queued') return '排队中';
  if (status === 'running') return '补接中';
  if (status === 'activation_uncertain') return '待确认';
  if (status === 'failed') return '失败';
  return '<span class="muted">未启用</span>';
}}
function render() {{
  copyStore.clear();
  copySeq = 0;
  const q = $('#q').value.trim().toLowerCase();
  const accounts = SNAPSHOT.accounts.filter((r) => !q || haystack(r).includes(q));
  const outlook = SNAPSHOT.outlook.filter((r) => !q || haystack(r).includes(q));
  $('#generated').textContent = SNAPSHOT.generated_at;
  $('#statAccounts').textContent = SNAPSHOT.summary.accounts;
  $('#statOutlook').textContent = SNAPSHOT.summary.outlook_total;
  $('#statAvailable').textContent = SNAPSHOT.summary.outlook_available;
  $('#accountsBody').innerHTML = accounts.map((r) => `
    <tr>
      <td class="muted">#${{esc(r.id)}}</td>
      <td><div class="main-cell">${{esc(r.email)}}</div><div class="sub-cell">${{esc(r.user_name || '-')}}</div></td>
      <td>${{esc(r.email_source || '-')}}</td>
      <td><span class="mono">${{esc(short(r.access_token || '', 42))}}</span></td>
      <td title="${{esc(r.note || '')}}">${{r.note ? esc(short(r.note, 60)) : '<span class="muted">-</span>'}}</td>
      <td>${{totpState(r)}}</td>
      <td class="muted">${{esc(r.created_at || '-')}}</td>
      <td class="actions">${{btn('复制Token', r.access_token, 'primary')}} ${{btn('复制整行', r.copy_line, 'good')}}</td>
    </tr>`).join('');
  $('#outlookBody').innerHTML = outlook.map((r) => `
    <tr>
      <td><div class="main-cell">${{esc(r.email)}}</div><div class="sub-cell mono">${{esc(short(r.copy_line, 76))}}</div></td>
      <td>${{pill(r.status)}}</td>
      <td><span class="mono">${{esc(short(r.access_token || '', 36) || '未生成')}}</span></td>
      <td class="muted">${{esc(r.imported_at || r.created_at || '-')}}</td>
      <td class="muted">${{esc(r.used_at || '-')}}</td>
      <td class="actions">${{btn('复制邮箱', r.copy_line)}} ${{btn('复制Token', r.access_token, 'primary')}} ${{btn('复制整行', r.account_copy_line, 'good')}}</td>
    </tr>`).join('');
}}
document.addEventListener('click', (e) => {{
  const target = e.target.closest('[data-copy-id]');
  if (!target) return;
  copyText(copyStore.get(target.dataset.copyId));
}});
$('#q').addEventListener('input', render);
$('#copyAllTokens').addEventListener('click', () => copyText(SNAPSHOT.accounts.map((r) => r.access_token).filter(Boolean).join('\\n')));
$('#copyAllLines').addEventListener('click', () => copyText(SNAPSHOT.accounts.map((r) => r.copy_line).filter(Boolean).join('\\n')));
$('#copyAllEmails').addEventListener('click', () => copyText(SNAPSHOT.outlook.map((r) => r.copy_line).filter(Boolean).join('\\n')));
render();
</script>
</body>
</html>
"""
    tmp = _VIEWER_HTML.with_suffix(".html.tmp")
    tmp.write_text(html_text, encoding="utf-8")
    try:
        tmp.replace(_VIEWER_HTML)
        return _VIEWER_HTML
    except PermissionError:
        # Windows 下如果目标 HTML 正被浏览器或编辑器短暂占用，原子替换可能失败。
        # 先尝试直接覆盖；仍失败时写一个时间戳快照，避免注册流程被查看页刷新阻断。
        try:
            _VIEWER_HTML.write_text(html_text, encoding="utf-8")
            try:
                tmp.unlink()
            except OSError:
                pass
            return _VIEWER_HTML
        except PermissionError:
            fallback = _DATA_DIR / f"accounts_viewer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            fallback.write_text(html_text, encoding="utf-8")
            try:
                tmp.unlink()
            except OSError:
                pass
            return fallback


def _load_outlook() -> list[dict]:
    rows = _read_json(_OUTLOOK_JSON, None)
    if not isinstance(rows, list):
        rows = _read_json(_LEGACY_OUTLOOK_JSON, [])
    return rows if isinstance(rows, list) else []


def _save_outlook(rows: list[dict]) -> None:
    _write_json(_OUTLOOK_JSON, rows)
    _sync_outlook_txt(rows)


def _load_generic_api_emails() -> list[dict]:
    rows = _read_json(_GENERIC_API_EMAIL_JSON, [])
    return rows if isinstance(rows, list) else []


def _save_generic_api_emails(rows: list[dict]) -> None:
    for row in rows:
        row["copy_line"] = _generic_api_email_line(row)
    _write_json(_GENERIC_API_EMAIL_JSON, rows)
    _sync_generic_api_email_txt(rows)


def _load_icloud_emails() -> list[dict]:
    rows = _read_json(_ICLOUD_EMAIL_JSON, [])
    return rows if isinstance(rows, list) else []


def _save_icloud_emails(rows: list[dict]) -> None:
    for row in rows:
        row["copy_line"] = _icloud_email_line(row)
    _write_json(_ICLOUD_EMAIL_JSON, rows)
    _sync_icloud_email_txt(rows)


def _load_mailcom() -> list[dict]:
    rows = _read_json(_MAILCOM_JSON, [])
    return rows if isinstance(rows, list) else []


def _save_mailcom(rows: list[dict]) -> None:
    for row in rows:
        row["copy_line"] = _mailcom_line(row)
    _write_json(_MAILCOM_JSON, rows)
    _sync_mailcom_txt(rows)


def _account_progress_context() -> tuple[Path, list[int] | None]:
    target = _ACCOUNTS_JSON.resolve(strict=False) if _ACCOUNTS_JSON.is_symlink() else _ACCOUNTS_JSON
    journal = target.with_name(target.name + ".progress.json")
    try:
        stat = target.stat()
    except FileNotFoundError:
        return journal, None
    return journal, [int(stat.st_mtime_ns), int(stat.st_size), int(stat.st_ino)]


def _account_progress_updates(journal: Path, signature: list[int] | None) -> dict:
    if signature is None:
        return {}
    state = _read_json(journal, {})
    if not isinstance(state, dict) or state.get("accounts_signature") != signature:
        return {}
    updates = state.get("updates")
    return updates if isinstance(updates, dict) else {}


def _save_account_progress(rows: list[dict], row: dict, previous: dict) -> None:
    """Durably save transient status deltas without rewriting credentials/exports.

    Called under _LOCK only for Team/TOTP/health claims and running transitions, or
    queued/running Codex state. Terminal results and credential changes still
    checkpoint the normal accounts file, including all outstanding deltas.
    """
    _save_account_progress_many(rows, [(row, previous)])


def _save_account_progress_fields(
    rows: list[dict],
    row: dict,
    previous: dict,
    fields: set[str] | frozenset[str] | tuple[str, ...],
) -> None:
    """Journal only the explicitly selected transient fields.

    A number of workflow transitions also append an in-memory event or carry
    private provider context.  Passing the whole row to the journal would
    therefore force a full accounts JSON rewrite.  Build a shadow row that
    contains only the bounded fields needed for recovery/UI progress, while
    leaving the live row untouched.  On journal failure restore the caller's
    row just like ``_save_account_progress_many`` does.
    """
    selected = set(fields)
    journal_row = dict(previous)
    for key in selected:
        if key in row:
            journal_row[key] = row[key]
        else:
            journal_row[key] = None
    try:
        _save_account_progress_many(rows, [(journal_row, previous)])
    except BaseException:
        row.clear()
        row.update(previous)
        raise


def _save_account_progress_many(rows: list[dict], changes: list[tuple[dict, dict]]) -> None:
    """One atomic journal write for a batch; restore all cached rows on failure."""
    journal, signature = _account_progress_context()
    updates = dict(_account_progress_updates(journal, signature))
    full_save = signature is None
    changed = False
    try:
        for row, previous in changes:
            fields = {key: value for key, value in row.items() if key not in previous or value != previous[key]}
            if not fields:
                continue
            changed = True
            allowed = all(
                (key.startswith(("team_", "totp_", "codex_last_", "health_"))
                 or key in {"codex_status", "codex_error"}
                 or key in _ACCOUNT_PROGRESS_SAFE_FIELDS)
                and key not in {"totp_secret", "totp_factor_id"}
                for key in fields
            )
            full_save |= not allowed or bool(previous.keys() - row.keys())
            key = str(row["id"])
            prior = updates.get(key) or {}
            previous_fields = (
                prior.get("fields", {})
                if isinstance(prior, dict)
                and prior.get("email") == row.get("email")
                and prior.get("created_at") == row.get("created_at")
                else {}
            )
            if not isinstance(previous_fields, dict):
                previous_fields = {}
            updates[key] = {
                "email": row.get("email"), "created_at": row.get("created_at"),
                "fields": {**previous_fields, **fields},
            }
        if changed:
            if full_save:
                _save_accounts(rows)
            else:
                _write_json(journal, {"accounts_signature": signature, "updates": updates})
    except BaseException:
        for row, previous in changes:
            row.clear()
            row.update(previous)
        raise


def _load_accounts() -> list[dict]:
    _recover_password_totp_import()
    _recover_registration_batch_merge()
    rows = _read_json(_ACCOUNTS_JSON, None)
    if not isinstance(rows, list):
        rows = _read_json(_LEGACY_ACCOUNTS_JSON, [])
    if not isinstance(rows, list):
        return []
    journal, signature = _account_progress_context()
    updates = _account_progress_updates(journal, signature)
    if updates:
        for row in rows:
            update = updates.get(str(row.get("id"))) if isinstance(row, dict) else None
            if (
                isinstance(update, dict)
                and update.get("email") == row.get("email")
                and update.get("created_at") == row.get("created_at")
                and isinstance(update.get("fields"), dict)
            ):
                row.update(update["fields"])
    return rows


def _save_accounts(rows: list[dict]) -> None:
    for row in rows:
        # copy_line is fully derived from the credential fields.  Persisting it
        # duplicates every access token and makes all account-state writes
        # larger; decorators/export paths recreate it when it is requested.
        row.pop("copy_line", None)
    _write_json(_ACCOUNTS_JSON, rows)
    _sync_accounts_txt(rows)
    _sync_tokens_txt(rows)
    # React is the live account UI.  The legacy standalone viewer is refreshed
    # only through ``refresh_static_viewer`` so ordinary state updates do not
    # synchronously serialize tens of megabytes of duplicate HTML.


def _normalize_failed_job_error(row: dict) -> bool:
    """确保失败任务在持久化和 API 中始终带有可读错误。"""
    if str(row.get("status") or "").strip().lower() != "failed":
        return False

    current = str(row.get("error_message") or "").strip()
    if current.lower() in {"none", "null"}:
        current = ""
    if not current:
        legacy = str(row.get("error") or "").strip()
        if legacy.lower() not in {"none", "null"}:
            current = legacy
    normalized = (current or _JOB_FAILURE_ERROR_FALLBACK)[:500]
    if row.get("error_message") == normalized:
        return False
    row["error_message"] = normalized
    return True


def _job_traffic_journal_context() -> tuple[Path, list[int] | None]:
    # Resolve first so Docker's /app -> /runtime links keep the journal beside
    # the real jobs file on the persistent volume. Tests patch _JOBS_JSON.
    target = _JOBS_JSON.resolve(strict=False) if _JOBS_JSON.is_symlink() else _JOBS_JSON
    journal = target.with_name(target.name + ".traffic.json")
    try:
        stat = target.stat()
    except FileNotFoundError:
        return journal, None
    return journal, [int(stat.st_mtime_ns), int(stat.st_size), int(stat.st_ino)]


def _job_traffic_updates(journal: Path, signature: list[int] | None) -> dict:
    if signature is None:
        return {}
    state = _read_json(journal, {})
    # A successful main-file commit invalidates the old journal atomically.
    # Even a crash immediately after replace cannot replay stale heartbeats
    # over a completed/deleted/recreated job. No second cleanup write is needed.
    if not isinstance(state, dict) or state.get("jobs_signature") != signature:
        return {}
    updates = state.get("updates")
    return updates if isinstance(updates, dict) else {}


def _save_running_job_traffic(row: dict, traffic: dict) -> bool:
    """Persist only small active counters; caller holds _LOCK."""
    journal, signature = _job_traffic_journal_context()
    if signature is None:
        # Legacy installations can still be reading data/registration_jobs.json;
        # let the caller perform the first ordinary save before journaling.
        return False
    updates = dict(_job_traffic_updates(journal, signature))
    updates[str(row["id"])] = {
        "job_uuid": row.get("job_uuid"),
        "traffic": traffic,
    }
    _write_json(journal, {"jobs_signature": signature, "updates": updates})
    return True


def _job_progress_context() -> tuple[Path, list[int] | None]:
    traffic_path, signature = _job_traffic_journal_context()
    return traffic_path.with_name(traffic_path.name.removesuffix(".traffic.json") + ".progress.json"), signature


def _job_progress_fields(row: dict) -> frozenset[str]:
    kind = row.get("job_type") or "registration"
    if kind == "registration":
        # These fields are bounded execution metadata.  Keeping them in the
        # small progress journal avoids rewriting the full jobs table whenever
        # the registration pipeline updates OAuth bookkeeping while running.
        return frozenset({
            "status", "started_at", "email", "email_allocation_id",
            "oauth_status", "oauth_error",
        })
    if kind in {"codex_oauth", "codex_retry"}:
        return frozenset({"status", "started_at", "oauth_status", "oauth_error"})
    return frozenset()


def _save_job_progress(rows: list[dict], row: dict, previous: dict) -> None:
    """Persist one whitelisted startup/progress delta."""
    _save_job_progress_many(rows, [(row, previous)])


def _save_job_progress_many(
    rows: list[dict], changes: list[tuple[dict, dict]],
) -> None:
    """Persist several job progress deltas with one small journal write."""
    journal, signature = _job_progress_context()
    full_save = signature is None
    updates = dict(_job_traffic_updates(journal, signature))
    changed = False
    try:
        for row, previous in changes:
            fields = {key: value for key, value in row.items() if previous.get(key) != value}
            if not fields:
                continue
            changed = True
            allowed = _job_progress_fields(row)
            if (
                not allowed or not fields.keys() <= allowed
                or previous.get("status") not in {"pending", "running"}
                or row.get("status") != "running"
            ):
                full_save = True
            updates[str(row["id"])] = {
                "job_uuid": row.get("job_uuid"),
                # Snapshot all allowed fields so a later email/OAuth write
                # retains the earlier running delta after a cold restart.
                "fields": {key: row[key] for key in allowed if key in row},
            }
        if not changed:
            return
        if full_save:
            _save_jobs(rows)
        else:
            _write_json(journal, {"jobs_signature": signature, "updates": updates})
    except BaseException:
        for row, previous in changes:
            row.clear()
            row.update(previous)
        raise


def _save_codex_job_start(rows: list[dict], row: dict, previous: dict) -> None:
    _save_job_progress(rows, row, previous)


def _load_jobs() -> list[dict]:
    _recover_registration_batch_merge()
    rows = _read_json(_JOBS_JSON, None)
    if not isinstance(rows, list):
        rows = _read_json(_LEGACY_JOBS_JSON, [])
    if not isinstance(rows, list):
        return []
    journal, signature = _job_traffic_journal_context()
    updates = _job_traffic_updates(journal, signature)
    progress_path, progress_signature = _job_progress_context()
    progress = _job_traffic_updates(progress_path, progress_signature)
    changed = False
    for row in rows:
        if not isinstance(row, dict):
            continue
        start = progress.get(str(row.get("id")))
        if (
            isinstance(start, dict) and start.get("job_uuid") == row.get("job_uuid")
            and row.get("status") in {"pending", "running"}
        ):
            # Older Codex-only journals stored these fields at the top level.
            fields = start.get("fields", {
                "status": start.get("status"), "started_at": start.get("started_at"),
            })
            allowed = _job_progress_fields(row)
            if (
                isinstance(fields, dict) and fields.get("status") == "running"
                and allowed and fields.keys() <= allowed
            ):
                row.update(fields)
        update = updates.get(str(row.get("id")))
        if (
            isinstance(update, dict)
            and update.get("job_uuid") == row.get("job_uuid")
            and isinstance(update.get("traffic"), dict)
        ):
            # Keep journal cache independent of later status mutations.
            row["roxy_traffic"] = dict(update["traffic"])
        if _normalize_failed_job_error(row):
            changed = True
    if changed:
        # JSON v2 读时迁移：历史 failed/null 记录在首次读取后同步修复。
        _write_json(_JOBS_JSON, rows)
    return rows


def _save_jobs(rows: list[dict]) -> None:
    for row in rows:
        if isinstance(row, dict):
            _normalize_failed_job_error(row)
    _write_json(_JOBS_JSON, rows)


def mask_job_secrets(value: Any) -> Any:
    """返回可安全用于 API 输出的任务副本，不改变内部执行快照。"""
    if isinstance(value, list):
        return [mask_job_secrets(item) for item in value]
    if not isinstance(value, dict):
        return value

    out = {key: mask_job_secrets(item) for key, item in value.items()}
    if "job_uuid" in out or "log_file" in out:
        _normalize_failed_job_error(out)
    # 旧版误加入的注册阶段追踪不再属于公开任务契约。
    out.pop("registration_trace", None)
    traffic = out.get("roxy_traffic")
    if isinstance(traffic, dict):
        # 对历史文件也执行读时白名单，避免旧数据或人工编辑字段经 API 外泄。
        traffic = {key: traffic.get(key) for key in _ROXY_TRAFFIC_FIELDS if key in traffic}
        traffic["upstream_proxy"] = _redact_proxy_text(traffic.get("upstream_proxy"))
        traffic["unavailable_reason"] = _redact_proxy_text(traffic.get("unavailable_reason"))
        traffic["finalization_reason"] = _redact_proxy_text(
            traffic.get("finalization_reason"), limit=120
        )
        outcome = str(traffic.get("registration_outcome") or "").strip().lower()
        traffic["registration_outcome"] = (
            outcome if outcome in {"success", "failed", "stopped", "cancelled"} else None
        )
        measurement = str(traffic.get("measurement") or "unavailable").strip().lower()
        traffic["measurement"] = (
            measurement if measurement in {"socks5_tunnel_payload", "unavailable"} else "unavailable"
        )
        state = str(traffic.get("status") or "unavailable").strip().lower()
        traffic["status"] = (
            state if state in {"running", "complete", "unavailable", "failed"} else "unavailable"
        )
        for key in ("uploaded_bytes", "downloaded_bytes", "connection_count"):
            try:
                traffic[key] = max(0, int(traffic.get(key) or 0))
            except (TypeError, ValueError):
                traffic[key] = 0
        traffic["total_bytes"] = traffic["uploaded_bytes"] + traffic["downloaded_bytes"]
        traffic["schema_version"] = 1
        traffic["driver"] = "roxy"
        traffic["partial"] = bool(traffic.get("partial") is True)
        for key in ("started_at", "finished_at", "updated_at"):
            traffic[key] = _roxy_traffic_timestamp(traffic.get(key))
        out["roxy_traffic"] = traffic
    snapshot = out.get("flow_snapshot")
    if isinstance(snapshot, dict):
        sms = snapshot.get("sms")
        if isinstance(sms, dict):
            sms["has_api_key"] = bool(sms.get("api_key"))
            sms.pop("api_key", None)
            sms["has_proxy"] = bool(str(sms.get("proxy") or "").strip())
            sms.pop("proxy", None)
            # handler_url 的 query string 可能带 token，和 api_key 同等对待。
            sms["has_handler_url"] = bool(sms.get("handler_url"))
            sms.pop("handler_url", None)
        paypal = snapshot.get("paypal")
        if isinstance(paypal, dict):
            paypal["has_phone"] = bool(str(paypal.get("phone") or "").strip())
            paypal.pop("phone", None)
            paypal_sms = paypal.get("sms")
            if isinstance(paypal_sms, dict):
                luban = paypal_sms.get("luban")
                if isinstance(luban, dict):
                    luban["has_api_key"] = bool(str(luban.get("api_key") or "").strip())
                    luban["has_proxy"] = bool(str(luban.get("proxy") or "").strip())
                    luban.pop("api_key", None)
                    luban.pop("proxy", None)
                smsbower = paypal_sms.get("smsbower")
                if isinstance(smsbower, dict):
                    smsbower["has_api_key"] = bool(
                        str(smsbower.get("api_key") or "").strip()
                    )
                    smsbower["has_proxy"] = bool(
                        str(smsbower.get("proxy") or "").strip()
                    )
                    smsbower["has_handler_url"] = bool(
                        str(smsbower.get("handler_url") or "").strip()
                    )
                    smsbower.pop("api_key", None)
                    smsbower.pop("proxy", None)
                    smsbower.pop("handler_url", None)
                herosms = paypal_sms.get("herosms")
                if isinstance(herosms, dict):
                    herosms["has_api_key"] = bool(
                        str(herosms.get("api_key") or "").strip()
                    )
                    herosms["has_proxy"] = bool(
                        str(herosms.get("proxy") or "").strip()
                    )
                    herosms["has_handler_url"] = bool(
                        str(herosms.get("handler_url") or "").strip()
                    )
                    herosms.pop("api_key", None)
                    herosms.pop("proxy", None)
                    herosms.pop("handler_url", None)
    return out


def _load_batches() -> list[dict]:
    _recover_password_totp_import()
    _recover_registration_batch_merge()
    rows = _read_json(_BATCHES_JSON, [])
    if not isinstance(rows, list):
        return []
    journal, signature = _batch_progress_context()
    updates = _batch_progress_updates(journal, signature)
    if updates:
        for row in rows:
            if not isinstance(row, dict):
                continue
            update = updates.get(str(row.get("batch_id") or ""))
            if (
                isinstance(update, dict)
                and update.get("created_at") == row.get("created_at")
                and isinstance(update.get("fields"), dict)
            ):
                row.update(update["fields"])
    return rows


def _save_batches(rows: list[dict]) -> None:
    _write_json(_BATCHES_JSON, rows)


_BATCH_PROGRESS_FIELDS = frozenset({
    "sms_budget_spent", "sms_budget_reserved", "updated_at",
})


def _batch_progress_context() -> tuple[Path, list[int] | None]:
    target = _BATCHES_JSON.resolve(strict=False) if _BATCHES_JSON.is_symlink() else _BATCHES_JSON
    journal = target.with_name(target.name + ".progress.json")
    try:
        stat = target.stat()
    except FileNotFoundError:
        return journal, None
    return journal, [int(stat.st_mtime_ns), int(stat.st_size), int(stat.st_ino)]


def _batch_progress_updates(journal: Path, signature: list[int] | None) -> dict:
    if signature is None:
        return {}
    state = _read_json(journal, {})
    if not isinstance(state, dict) or state.get("batches_signature") != signature:
        return {}
    updates = state.get("updates")
    return updates if isinstance(updates, dict) else {}


def _save_batch_progress(rows: list[dict], row: dict, previous: dict) -> None:
    """Persist bounded SMS budget counters without rewriting batch snapshots."""
    journal, signature = _batch_progress_context()
    fields = {key: value for key, value in row.items() if previous.get(key) != value}
    try:
        if (
            signature is None
            or not fields
            or not fields.keys() <= _BATCH_PROGRESS_FIELDS
        ):
            _save_batches(rows)
            return
        updates = dict(_batch_progress_updates(journal, signature))
        key = str(row.get("batch_id") or "")
        updates[key] = {
            "created_at": row.get("created_at"),
            "fields": {name: row[name] for name in _BATCH_PROGRESS_FIELDS if name in row},
        }
        _write_json(journal, {"batches_signature": signature, "updates": updates})
    except BaseException:
        row.clear()
        row.update(previous)
        raise


def _load_email_allocations() -> list[dict]:
    _recover_registration_batch_merge()
    rows = _read_json(_EMAIL_ALLOCATIONS_JSON, [])
    return rows if isinstance(rows, list) else []


def _save_email_allocations(rows: list[dict]) -> None:
    _write_json(_EMAIL_ALLOCATIONS_JSON, rows)


def _find_by_email(rows: list[dict], email: str) -> dict | None:
    target = (email or "").lower()
    return next((r for r in rows if (r.get("email") or "").lower() == target), None)


def _account_health_status(row: dict) -> str:
    status = str(row.get("health_status") or "unchecked").strip().lower()
    return status if status in {
        "unchecked", "queued", "running", "alive", "dead", "token_invalid", "error", "no_token",
    } else "unchecked"


def _account_codex_state(row: dict) -> str:
    if str(row.get("codex_refresh_token") or ""):
        return "connected"
    return (
        "running" if str(row.get("codex_status") or "").lower() in {"queued", "retrying", "running"}
        else "not_connected"
    )


def _normalize_plan_check_status(out: dict) -> None:
    plan_status = out.get("plan_check_status")
    if plan_status in {"queued", "running"}:
        try:
            stamp_key = "plan_check_queued_at" if plan_status == "queued" else "plan_check_started_at"
            stale_after = _PLAN_CHECK_QUEUE_STALE_SECONDS if plan_status == "queued" else _PLAN_CHECK_STALE_SECONDS
            started_at = datetime.fromisoformat(str(out.get(stamp_key) or ""))
            if (datetime.now() - started_at).total_seconds() >= stale_after:
                out["plan_check_status"] = "failed"
                out["plan_check_error"] = "上次套餐查询状态已超时，可重新查询"
                out["plan_check_stale"] = True
        except (TypeError, ValueError):
            out["plan_check_status"] = "failed"
            out["plan_check_error"] = "上次套餐查询状态异常，可重新查询"
            out["plan_check_stale"] = True


def _account_totp_status(row: dict) -> str:
    status = str(row.get("totp_status") or "").strip().lower()
    if status in {
        "not_configured", "queued", "running", "active", "active_external",
        "activation_uncertain", "failed",
    }:
        return status
    return "active" if str(row.get("totp_secret") or "").strip() else "not_configured"


def _account_quota_status(row: dict) -> str:
    status = str(row.get("quota_status") or "").strip().lower()
    if status in {"unchecked", "queued", "running", "success", "failed"}:
        return status
    return "success" if row.get("quota_ok") is True else "unchecked"


def _account_query_fields(row: dict, *, include_codex_plan: bool = False) -> dict:
    """Small, credential-free projection with the same filter/sort semantics.

    Do not expand hundreds of display fields, token previews and PayPal event
    history for every stored account just to display one page.
    """
    out = {key: row.get(key) for key in (
        "id", "email", "user_name", "note", "registration_driver", "email_source",
        "plan_type", "current_plan_type", "registration_batch_id", "created_at", "updated_at",
        "codex_last_failure_stage", "health_checked_at", "plus_trial_status", "promo_state",
        "plus_trial_eligible", "plus_trial_actionable", "plan_check_status",
        "plan_check_queued_at", "plan_check_started_at",
    )}
    if out["registration_driver"] is None:
        out["registration_driver"] = "legacy"
    if out["plus_trial_actionable"] is None:
        out["plus_trial_actionable"] = False
    out["note"] = out["note"] or ""
    out["health_status"] = _account_health_status(row)
    out["codex_connection_state"] = _account_codex_state(row)
    out["has_codex_refresh_token"] = bool(str(row.get("codex_refresh_token") or ""))
    out["totp_status"] = _account_totp_status(row)
    if include_codex_plan:
        # Resolving the saved OAuth claim is intentionally opt-in.  A normal
        # page query should only inspect the credential files for the rows
        # returned on that page; a cross-page Codex plan filter opts in here.
        from core.codex_plan import account_plan
        out["codex_plan_type"] = account_plan(row, _CODEX_DIR)
    _normalize_plan_check_status(out)
    return out


def _decorate_account(row: dict) -> dict:
    out = dict(row)
    # JSON v2 采用读时补齐，旧账号无需一次性迁移也能稳定返回新管理字段。
    defaults = {
        "registration_driver": "legacy",
        "registration_job_id": None,
        "registration_batch_id": None,
        "email_allocation_id": None,
        "oauth_requested": False,
        "codex_refresh_token": "",
        "codex_credential_path": "",
        "web_cookie_credential_path": "",
        "web_cookie_saved_at": None,
        "web_cookie_count": 0,
        "web_cookie_has_session": False,
        "web_cookie_capture_status": "missing",
        "web_cookie_capture_error": None,
        # Team invite reconciliation is an account operation, not a second
        # credential slot.  Keep only masked/structural metadata here; the
        # actual session remains in the managed Web Cookie credential file.
        "team_status": "not_checked",
        "team_invite_status": "not_checked",
        "team_invite_trigger": None,
        "team_invite_queued_at": None,
        "team_invite_started_at": None,
        "team_invite_completed_at": None,
        "team_invite_checked_at": None,
        "team_invite_message": None,
        "team_invite_error": None,
        "team_invite_error_code": None,
        "team_invite_retryable": None,
        "team_invite_claim_id": None,
        "team_invite_previous_status": None,
        "team_invite_last_attempt_status": None,
        "team_invite_attempt_count": 0,
        "team_invite_link_fingerprint": None,
        "team_invite_recipient_verified": None,
        "team_workspace_id": None,
        "team_workspace_name": None,
        "team_session_account_id": None,
        "team_session_refreshed": False,
        "team_cookie_count": 0,
        "team_joined_at": None,
        "web_at_refreshed_at": None,
        "web_at_refresh_source": None,
        "promo_coupon": None,
        "promo_state": None,
        "promo_redeemed": False,
        "promo_redeemed_at": None,
        "promo_redeemed_by_user": False,
        "promo_redeemed_by_workspace": False,
        "promo_expires_at": None,
        "promo_promotion_length_days": None,
        "promo_check_ok": None,
        "promo_check_http_status": None,
        "promo_check_error": None,
        "promo_checked_at": None,
        "promo_response_bytes": None,
        "promo_retry_after": None,
        "promo_retryable": None,
        "billing_page_config_ok": None,
        "billing_page_config_http_status": None,
        "billing_page_config_error": None,
        "billing_account_eligible": None,
        "billing_plan_management_eligible": None,
        "billing_free_workspace_upgrade_eligible": None,
        "app_store_billing_retry_check_ok": None,
        "app_store_billing_retry_http_status": None,
        "app_store_billing_retry_error": None,
        "app_store_subscription_in_billing_retry": None,
        "plus_trial_status": None,
        "plus_trial_actionable": False,
        "quota_status": "unchecked",
        "quota_trigger": None,
        "quota_queued_at": None,
        "quota_started_at": None,
        "quota_completed_at": None,
        "quota_checked_at": None,
        "quota_ok": None,
        "quota_error": None,
        "quota_http_status": None,
        "quota_plan_type": None,
        "quota_allowed": None,
        "quota_limit_reached": None,
        "quota_primary_used_percent": None,
        "quota_primary_limit_window_seconds": None,
        "quota_primary_reset_after_seconds": None,
        "quota_primary_reset_at": None,
        "quota_secondary_used_percent": None,
        "quota_secondary_limit_window_seconds": None,
        "quota_secondary_reset_after_seconds": None,
        "quota_secondary_reset_at": None,
        "quota_reset_credits_available_count": None,
        "quota_reset_credit_expirations": [],
        "quota_additional_rate_limits": [],
        "quota_network_route": None,
        "quota_proxy_mode": None,
        "quota_proxy_used": None,
        "quota_proxy_fallback_reason": None,
        "quota_attempt_count": 0,
        "quota_max_attempts": 0,
        "quota_request_timeout": None,
        "quota_last_success_at": None,
        "quota_workspace_id": None,
        "quota_source": None,
        "quota_error_code": None,
        "codex_last_attempt_at": None,
        "codex_last_attempt_status": None,
        "codex_last_failure_stage": None,
        "codex_last_error": None,
        "sms_country": None,
        "sms_provider_id": None,
        "sms_cost": None,
        "roxy_traffic": None,
        "health_status": "unchecked",
        "health_alive": None,
        "health_checked_at": None,
        "health_queued_at": None,
        "health_started_at": None,
        "health_completed_at": None,
        "health_http_status": None,
        "health_error": None,
        "health_token_refresh_error": None,
        "health_reason": None,
        "health_message": None,
        "health_trigger": None,
        "health_network_route": None,
        "health_proxy_mode": None,
        "health_proxy_used": None,
        "health_proxy_fallback_reason": None,
        "health_token_expires_at": None,
        "health_last_alive_at": None,
        "health_last_dead_at": None,
        "health_last_token_invalid_at": None,
        "health_attempt_count": 0,
        "health_check_id": None,
        "momo_status": "unchecked",
        "momo_url": "",
        "momo_message": "",
        "momo_error": None,
        "momo_checked_at": None,
        "momo_queued_at": None,
        "momo_started_at": None,
        "momo_completed_at": None,
        "momo_trigger": None,
        "momo_currency": None,
        "momo_amount": None,
        "momo_payment_method_types": [],
        "momo_proxy_key": None,
        "momo_failure_stage": None,
        "momo_attempt_count": 0,
        "momo_force": False,
        "paypal_mode": "none",
        "paypal_requested_action": None,
        "paypal_trigger": None,
        "paypal_zero_offer_status": "unchecked",
        "paypal_zero_offer_campaign": None,
        "paypal_zero_offer_amount": None,
        "paypal_zero_offer_currency": None,
        "paypal_zero_offer_checked_at": None,
        "paypal_zero_offer_error": None,
        "paypal_extract_status": "unchecked",
        "paypal_extract_requested_mode": None,
        "paypal_extract_actual_mode": None,
        "paypal_extract_fallback_reason": None,
        "paypal_extract_message": "",
        "paypal_extract_error": None,
        "paypal_extract_failure_stage": None,
        "paypal_extract_queued_at": None,
        "paypal_extract_started_at": None,
        "paypal_extract_checked_at": None,
        "paypal_extract_completed_at": None,
        "paypal_extract_attempt_count": 0,
        "paypal_ba_url": "",
        "paypal_ba_token": "",
        "paypal_payment_status": "not_started",
        "paypal_payment_message": "",
        "paypal_payment_error": None,
        "paypal_payment_failure_stage": None,
        "paypal_payment_failure_code": None,
        "paypal_payment_replay_safe": False,
        "paypal_payment_reference": None,
        "paypal_agreement_id": None,
        "paypal_payment_queued_at": None,
        "paypal_payment_started_at": None,
        "paypal_payment_authorized_at": None,
        "paypal_payment_verified_at": None,
        "paypal_payment_confirmed_at": None,
        "paypal_payment_completed_at": None,
        "paypal_payment_attempt_count": 0,
        "paypal_payment_context": None,
        "paypal_otp_context": None,
        "paypal_extract_proxy_pool_ref": None,
        "paypal_extract_proxy_pool_version": None,
        "paypal_payment_proxy_pool_ref": None,
        "paypal_payment_proxy_pool_version": None,
        "paypal_sms_channel": None,
        "paypal_sms_provider": None,
        "paypal_sms_service_id": None,
        "paypal_sms_request_id": None,
        "paypal_sms_status": "not_started",
        "paypal_sms_cost": None,
        "paypal_sms_country": None,
        "paypal_sms_phone_masked": None,
        "paypal_sms_acquired_at": None,
        "paypal_sms_completed_at": None,
        "paypal_sms_error": None,
        "paypal_sms_context": None,
    }
    for key, value in defaults.items():
        if out.get(key) is None:
            out[key] = value
    for key, allowed, fallback in (
        ("paypal_zero_offer_status", _PAYPAL_ZERO_OFFER_STATUSES, "unchecked"),
        ("paypal_extract_status", _PAYPAL_EXTRACT_STATUSES, "unchecked"),
        ("paypal_payment_status", _PAYPAL_PAYMENT_STATUSES, "not_started"),
        ("paypal_sms_status", _PAYPAL_SMS_STATUSES, "not_started"),
    ):
        normalized = str(out.get(key) or fallback).strip().lower()
        out[key] = normalized if normalized in allowed else fallback
    out["health_status"] = _account_health_status(out)
    team_status = str(
        out.get("team_status") or out.get("team_invite_status") or "not_checked"
    ).strip().lower()
    if team_status not in _TEAM_INVITE_STATUSES:
        team_status = "not_checked"
    out["team_status"] = team_status
    # ``team_invite_status`` is retained as a compatibility alias for older
    # clients; both fields always describe the same terminal/queue state.
    out["team_invite_status"] = team_status
    last_attempt = str(out.get("team_invite_last_attempt_status") or "").strip().lower()
    out["team_invite_last_attempt_status"] = (
        last_attempt
        if last_attempt in _TEAM_INVITE_STATUSES - {"not_checked", "queued", "running"}
        else None
    )
    try:
        out["team_invite_attempt_count"] = max(
            0, int(out.get("team_invite_attempt_count") or 0)
        )
    except (TypeError, ValueError):
        out["team_invite_attempt_count"] = 0
    try:
        out["team_cookie_count"] = max(0, int(out.get("team_cookie_count") or 0))
    except (TypeError, ValueError):
        out["team_cookie_count"] = 0
    out["note"] = out.get("note") or ""
    out["note_updated_at"] = out.get("note_updated_at") or ""
    _normalize_plan_check_status(out)
    out["quota_status"] = _account_quota_status(out)
    if not isinstance(out.get("quota_reset_credit_expirations"), list):
        out["quota_reset_credit_expirations"] = []
    if not isinstance(out.get("quota_additional_rate_limits"), list):
        out["quota_additional_rate_limits"] = []
    web_at = str(out.get("access_token") or "")
    codex_rt = str(out.get("codex_refresh_token") or "")
    out["has_access_token"] = bool(web_at)
    out["has_quota_credential"] = bool(web_at or out.get("codex_credential_path"))
    out["has_codex_refresh_token"] = bool(codex_rt)
    out["has_codex_agent_token"] = bool(out.get("codex_agent_token"))
    out["has_totp_secret"] = bool(out.get("totp_secret"))
    raw_totp_status = _account_totp_status(out)
    out["totp_status"] = raw_totp_status
    out["has_totp"] = raw_totp_status in {"active", "active_external"}
    try:
        out["web_cookie_count"] = max(0, int(out.get("web_cookie_count") or 0))
    except (TypeError, ValueError):
        out["web_cookie_count"] = 0
    out["has_web_cookies"] = bool(
        str(out.get("web_cookie_credential_path") or "").strip()
        and out["web_cookie_count"] > 0
    )
    out["access_token_preview"] = f"{web_at[:12]}...{web_at[-6:]}" if len(web_at) > 20 else ("***" if web_at else "")
    out["codex_refresh_token_preview"] = (
        f"{codex_rt[:10]}...{codex_rt[-6:]}" if len(codex_rt) > 18 else ("***" if codex_rt else "")
    )
    out["codex_connection_state"] = _account_codex_state(out)
    # `_mask_account_secrets` may receive an already decorated row from the
    # server-side query path. Preserve its derived booleans on that second pass.
    out["has_paypal_ba_url"] = bool(
        out.get("has_paypal_ba_url") or str(out.get("paypal_ba_url") or "").strip()
    )
    out["has_paypal_ba_token"] = bool(
        out.get("has_paypal_ba_token") or str(out.get("paypal_ba_token") or "").strip()
    )
    out["has_paypal_payment_context"] = bool(
        out.get("has_paypal_payment_context") or out.get("paypal_payment_context")
    )
    out["has_paypal_otp_context"] = bool(
        out.get("has_paypal_otp_context") or out.get("paypal_otp_context")
    )
    out["has_paypal_sms_context"] = bool(
        out.get("has_paypal_sms_context") or out.get("paypal_sms_context")
    )
    raw_sms_mask = "".join(
        ch for ch in str(out.get("paypal_sms_phone_masked") or "") if ch.isdigit()
    )
    out["paypal_sms_phone_masked"] = (
        f"+**{raw_sms_mask[-4:]}" if raw_sms_mask else ""
    )
    raw_paypal_events = out.get("paypal_events")
    if isinstance(raw_paypal_events, list):
        bounded_events = raw_paypal_events[-_PAYPAL_EVENT_LIMIT:]
        out["paypal_event_count"] = sum(1 for event in bounded_events if isinstance(event, dict))
        last_event = next((event for event in reversed(bounded_events) if isinstance(event, dict)), None)
        normalized_last = _normalize_paypal_event(last_event) if last_event else None
        out["paypal_last_event_at"] = normalized_last.get("time") if normalized_last else None
    elif "paypal_event_count" not in out:
        paypal_events = _derive_legacy_paypal_events(out)
        out["paypal_event_count"] = len(paypal_events)
        out["paypal_last_event_at"] = (
            str(paypal_events[-1].get("time") or "") if paypal_events else None
        )
    else:
        try:
            out["paypal_event_count"] = max(0, int(out.get("paypal_event_count") or 0))
        except (TypeError, ValueError):
            out["paypal_event_count"] = 0
    payment_status = str(out.get("paypal_payment_status") or "not_started")
    extract_status = str(out.get("paypal_extract_status") or "unchecked")
    zero_offer_status = str(out.get("paypal_zero_offer_status") or "unchecked")
    sms_status = str(out.get("paypal_sms_status") or "not_started")
    if payment_status == "confirmed":
        management_state = "confirmed"
    elif payment_status == "waiting_otp":
        management_state = "waiting_otp"
    elif payment_status in {"authorized", "pending", "verification_blocked"}:
        management_state = payment_status
    elif _paypal_account_is_active(out):
        management_state = "running"
    elif payment_status == "failed" or extract_status == "failed":
        management_state = "failed"
    elif extract_status == "unavailable" or zero_offer_status == "not_eligible":
        management_state = "unavailable"
    elif extract_status == "success":
        management_state = "link_ready"
    elif sms_status in {"timeout", "failed", "ambiguous"}:
        management_state = "sms_failed"
    else:
        management_state = "not_started"
    out["paypal_management_state"] = management_state
    out.pop("paypal_events", None)
    for key in _PAYPAL_SENSITIVE_FIELDS:
        out.pop(key, None)
    out["copy_line"] = _account_line(out)
    return out


def _mask_account_secrets(row: dict) -> dict:
    out = _decorate_account(row)
    from core.codex_plan import account_plan
    # This runs only for returned page/detail rows, outside list filtering.
    # Existing credentials acquire a label without rewriting account storage.
    out["codex_plan_type"] = account_plan(row, _CODEX_DIR)
    for key in (
        "access_token", "codex_refresh_token", "refresh_token", "password", "client_id",
        "totp_secret", "totp_factor_id", "totp_claim_id", "totp_previous_status",
        "team_invite_claim_id",
        "quota_check_id",
        "team_invite_previous_status",
        "totp_token_update_error", "totp_cookie_update_error",
        "codex_credential_path", "codex_agent_token", "codex_agent_auth_path",
        "web_cookie_credential_path", "cookies", "web_cookies", "cookie_header", "session_token",
        "proxy_used",
        "extra_json",
        # Full plan responses are internal audit blobs.  List/detail APIs
        # already expose their normalized fields and should not send both
        # multi-kilobyte copies for every account row.
        "plan_check_result_json", "plan_last_success_result_json",
        "health_check_id",
        *_PAYPAL_SENSITIVE_FIELDS,
    ):
        out.pop(key, None)
    out.pop("copy_line", None)
    out.pop("original_email_line", None)
    return out


# update_account_codex_result / update_account_codex_status 实际会写入的阶段值。
# 任何不在这里的阶段统一归到 unknown，避免诊断面板被脏数据撑出无穷多分桶。
_CODEX_FAILURE_STAGES = (
    "oauth", "sms_budget", "plus_required", "cancelled", "restart", "stopped",
)


def _codex_failure_stage_of(row: dict) -> str:
    """账号当前卡在的 Codex 阶段；已接通或从未失败返回空串。"""
    codex_rt = str(row.get("codex_refresh_token") or "")
    if codex_rt or row.get("has_codex_refresh_token"):
        return ""
    stage = str(row.get("codex_last_failure_stage") or "").strip().lower()
    if not stage:
        return ""
    return stage if stage in _CODEX_FAILURE_STAGES else "unknown"


def _account_matches_plan_filter(row: dict, plan_filter: str | None = None) -> bool:
    """账号套餐过滤。plus 表示已开通 Plus（兼容 plus/chatgpt_plus/plus_trial 等标记）。"""
    f = str(plan_filter or "").strip().lower()
    if not f or f in {"all", "any"}:
        return True
    plan = str(row.get("current_plan_type") or row.get("plan_type") or "").strip().lower()
    if f == "plus":
        # “free(可Plus试用)”/plus_trial_eligible 只是可试用，不算已开通 Plus。
        # 只有套餐字段本身是 Plus/ChatGPT Plus/plus_* 且不含 free 时才命中。
        return "plus" in plan and "free" not in plan
    if f == "free":
        return plan == "free"
    return plan == f


_PLUS_OFFER_FILTERS = frozenset({
    "", "all", "any", "eligible", "not_eligible", "checking", "failed", "unchecked",
})


def _account_plus_offer_state(row: dict) -> str:
    """Return one stable management state for the account's Plus offer check."""
    trial_status = str(row.get("plus_trial_status") or "").strip().lower()
    promo_state = str(row.get("promo_state") or "").strip().lower()
    check_status = str(row.get("plan_check_status") or "").strip().lower()
    if (
        bool(row.get("plus_trial_eligible"))
        or bool(row.get("plus_trial_actionable"))
        or trial_status == "available"
        or promo_state == "eligible"
    ):
        return "eligible"
    if check_status in {"queued", "running"}:
        return "checking"
    if check_status == "failed":
        return "failed"
    if (
        trial_status == "not_eligible"
        or promo_state in {"not_eligible", "ineligible"}
        or check_status == "success"
    ):
        return "not_eligible"
    return "unchecked"


def _account_matches_plus_offer(row: dict, plus_offer: str | None = None) -> bool:
    wanted = str(plus_offer or "").strip().lower()
    if wanted not in _PLUS_OFFER_FILTERS:
        raise ValueError("plus_offer 非法")
    return wanted in {"", "all", "any"} or _account_plus_offer_state(row) == wanted


def _decorate_outlook(row: dict, account_by_email: dict[str, dict] | None = None) -> dict:
    out = dict(row)
    out["copy_line"] = _outlook_line(out)
    account = None
    if account_by_email is not None:
        account = account_by_email.get((out.get("email") or "").lower())
    if account:
        out["registered_account_id"] = account.get("id")
        out["access_token"] = account.get("access_token")
        out["access_token_preview"] = (
            (account.get("access_token") or "")[:40] + "..."
            if account.get("access_token")
            else ""
        )
        out["account_copy_line"] = _account_line(account)
        out["totp_secret"] = account.get("totp_secret")
    return out


def _decorate_generic_api_email(row: dict, account_by_email: dict[str, dict] | None = None) -> dict:
    out = dict(row)
    out["copy_line"] = _generic_api_email_line(out)
    out["password"] = out.get("password") or ""
    out["client_id"] = out.get("client_id") or ""
    out["refresh_token"] = out.get("refresh_token") or ""
    account = None
    if account_by_email is not None:
        account = account_by_email.get((out.get("email") or "").lower())
    if account:
        out["registered_account_id"] = account.get("id")
        out["access_token"] = account.get("access_token")
        out["access_token_preview"] = (
            (account.get("access_token") or "")[:40] + "..."
            if account.get("access_token")
            else ""
        )
        out["account_copy_line"] = _account_line(account)
        out["totp_secret"] = account.get("totp_secret")
    return out


def _decorate_icloud_email(row: dict, account_by_email: dict[str, dict] | None = None) -> dict:
    out = dict(row)
    out["copy_line"] = _icloud_email_line(out)
    account = account_by_email.get((out.get("email") or "").lower()) if account_by_email is not None else None
    if account:
        out["registered_account_id"] = account.get("id")
        out["access_token"] = account.get("access_token")
        out["account_copy_line"] = _account_line(account)
        out["totp_secret"] = account.get("totp_secret")
    return out


def _decorate_mailcom(row: dict, account_by_email: dict[str, dict] | None = None) -> dict:
    out = dict(row)
    out["copy_line"] = _mailcom_line(out)
    account = account_by_email.get((out.get("email") or "").lower()) if account_by_email is not None else None
    if account:
        out["registered_account_id"] = account.get("id")
        out["access_token"] = account.get("access_token")
        out["account_copy_line"] = _account_line(account)
        out["totp_secret"] = account.get("totp_secret")
    return out


def _mask_email_pool_secrets(row: dict, *, include_code_url: bool = False) -> dict:
    """保留邮箱运营字段和脱敏摘要，明文素材只允许显式凭证接口读取。"""
    out = dict(row)
    access_token = str(out.get("access_token") or "")
    code_url = str(out.get("code_url") or "")
    pickup_url = str(out.get("pickup_url") or "")
    out["has_access_token"] = bool(access_token)
    out["has_mailbox_refresh_token"] = bool(out.get("refresh_token"))
    out["has_mailbox_token"] = bool(out.get("token"))
    out["has_imap_credential"] = bool(out.get("password"))
    out["has_totp_secret"] = bool(out.get("totp_secret"))
    out["access_token_preview"] = (
        f"{access_token[:12]}...{access_token[-6:]}"
        if len(access_token) > 20 else ("***" if access_token else "")
    )
    if code_url:
        out["code_url_preview"] = _generic_api_code_url_preview(code_url)
    if pickup_url:
        out["pickup_url_preview"] = (
            _generic_api_code_url_preview(pickup_url)
            if str(out.get("protocol") or "").strip().lower() == "generic_api"
            else _icloud_pickup_url_preview(pickup_url)
        )
    for key in (
        "password", "client_id", "refresh_token", "access_token", "copy_line",
        "account_copy_line", "totp_secret", "original_email_line", "token", "pickup_url",
    ):
        out.pop(key, None)
    if not include_code_url:
        out.pop("code_url", None)
    return out


def _get_conn() -> None:
    """兼容旧入口：初始化文件存储目录。"""
    _ensure_storage()
    return None


def _row_to_dict(row: dict | None) -> dict | None:
    return dict(row) if row is not None else None


# ============================================================
# registered_accounts
# ============================================================

def import_password_totp_accounts(records: list[dict]) -> dict:
    """Import new login-only accounts into one batch with one account checkpoint."""
    from core.codex_password_totp import login_material

    if not records or len(records) > 500:
        raise ValueError("单次导入 1-500 个账号")
    for record in records:
        login_material(record)
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", str(record.get("email") or "")):
            raise ValueError("导入邮箱格式无效")
    with _LOCK:
        accounts = list(_load_accounts())
        existing = {str(row.get("email") or "").casefold() for row in accounts}
        next_id = _next_id(accounts)
        batch_id = str(uuid.uuid4())
        now = _now()
        imported, skipped = [], []
        for record in records:
            email = record["email"].strip().lower()
            if email in existing:
                skipped.append({"email": email, "reason": "账号已存在，未覆盖已有凭证"})
                continue
            password, secret = login_material(record)
            row = {
                "id": next_id, "email": email, "created_at": now, "updated_at": now,
                "access_token": "", "totp_secret": secret, "totp_status": "activation_uncertain",
                "totp_message": "已导入 2FA 密钥，等待登录验证", "codex_status": "missing",
                "extra_json": json.dumps({"registration_password": password}, ensure_ascii=False),
                "registration_driver": "imported", "email_source": "existing_account",
                "registration_batch_id": batch_id,
            }
            accounts.append(row)
            existing.add(email)
            imported.append({"id": next_id, "email": email})
            next_id += 1
        if imported:
            batch = _registration_batch_row(
                _load_batches(), batch_id=batch_id, count=len(imported), workers=0,
                email_source="existing_account",
                flow_snapshot={"registration_driver": "imported", "import_format": "password_totp"},
            )
            # Only batch metadata goes in the intent. The account checkpoint is
            # the commit point, without another copy of passwords or TOTP keys.
            _write_json(_account_import_journal_path(), {"version": 1, "batch": batch})
            try:
                _save_accounts(accounts)
            finally:
                _recover_password_totp_import()
        return {
            "batch_id": batch_id if imported else None,
            "imported": imported, "imported_count": len(imported), "skipped": skipped,
        }


def _account_import_journal_path() -> Path:
    target = _BATCHES_JSON.resolve(strict=False) if _BATCHES_JSON.is_symlink() else _BATCHES_JSON
    return target.with_name(target.name + ".import.json")


def _recover_password_totp_import() -> None:
    """Expose imported accounts and their batch together, including after a crash."""
    global _ACCOUNT_IMPORT_RECOVERING
    with _LOCK:
        if _ACCOUNT_IMPORT_RECOVERING:
            return
        journal = _account_import_journal_path()
        if not journal.exists():
            return
        plan = json.loads(journal.read_text(encoding="utf-8"))
        batch = plan.get("batch") if isinstance(plan, dict) else None
        if (
            not isinstance(batch, dict) or plan.get("version") != 1
            or not isinstance(batch.get("batch_id"), str) or not batch["batch_id"]
            or type(batch.get("count")) is not int or not 1 <= batch["count"] <= 500
            or _registration_job_driver(batch) != "imported"
        ):
            raise RuntimeError("账号导入批次恢复记录无效")
        _ACCOUNT_IMPORT_RECOVERING = True
        try:
            accounts = _load_accounts()
            imported_count = sum(row.get("registration_batch_id") == batch["batch_id"] for row in accounts)
            if imported_count:
                if imported_count != batch["count"]:
                    raise RuntimeError("账号导入批次数量不一致")
                batches = _load_batches()
                if not any(row.get("batch_id") == batch["batch_id"] for row in batches):
                    _save_batches([*batches, batch])
            # No matching accounts means the account checkpoint never committed;
            # discard the intent without creating an empty batch.
            journal.unlink()
            with _JSON_CACHE_LOCK:
                _JSON_CACHE.pop(str(journal), None)
        finally:
            _ACCOUNT_IMPORT_RECOVERING = False


def password_totp_account_errors(account_ids: list[int]) -> dict[int, str]:
    """Batch admission reads credentials once and only returns validation errors."""
    from core.codex_password_totp import login_material, PasswordTotpLoginError

    wanted = set(account_ids)
    errors = {}
    with _LOCK:
        for row in _load_accounts():
            account_id = int(row.get("id") or 0)
            if account_id not in wanted:
                continue
            try:
                login_material(row)
                if str(row.get("codex_status") or "").lower() == "deactivated":
                    errors[account_id] = "账号已废号"
            except PasswordTotpLoginError as exc:
                errors[account_id] = str(exc)
    return errors


def save_password_totp_web_session(account: dict, payload: dict, cookies: list[dict], *, claim_id: str,
                                  factor_id: str = "") -> None:
    """Persist a verified Web login without replacing a deleted/reclaimed account."""
    from core.account_cookie_store import has_session_cookie, persist_cookie_credential
    from core.codex_password_totp import login_material

    email = str(account.get("email") or "").strip().casefold()
    if (not payload.get("accessToken") or not has_session_cookie(cookies)
            or str((payload.get("user") or {}).get("email") or "").strip().casefold() != email):
        raise ValueError("Web 登录态未通过账号校验")
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if r.get("id") == account.get("id")), None)
        if (row is None or not claim_id or row.get("team_invite_claim_id") != claim_id
                or str(row.get("email") or "").casefold() != email
                or login_material(row) != login_material(account)):
            raise ValueError("账号或登录凭证已变化，未保存 Web 登录态")
        # A fresh file keeps the previous Cookie intact if the account write fails.
        metadata = persist_cookie_credential(email, cookies, source="password_totp_web", account_id=row["id"],
                                             version=uuid.uuid4().hex)
        previous = dict(row)
        row.update({
            "access_token": payload["accessToken"], "expires_at": payload.get("expires"),
            "user_id": (payload.get("user") or {}).get("id") or row.get("user_id"),
            "web_cookie_credential_path": metadata["credential_path"], "web_cookie_saved_at": metadata["saved_at"],
            "web_cookie_count": metadata["count"], "web_cookie_has_session": True,
            "web_cookie_capture_status": "saved", "web_cookie_capture_error": None, "updated_at": _now(),
        })
        if factor_id:
            row.update({"totp_status": "active", "totp_factor_id": factor_id,
                        "totp_message": "已通过密码 + 2FA 登录验证", "totp_error": None,
                        "totp_checked_at": _now()})
        try:
            _save_accounts(accounts)
        except BaseException:
            row.clear()
            row.update(previous)
            from core.account_cookie_store import delete_cookie_credential
            delete_cookie_credential(metadata["credential_path"])
            raise


def insert_account(
    *,
    email: str,
    access_token: str,
    totp_secret: str | None = None,
    user_id: str | None = None,
    user_name: str | None = None,
    plan_type: str | None = None,
    expires_at: str | None = None,
    device_id: str | None = None,
    proxy_used: str | None = None,
    email_source: str | None = None,
    extra: dict | None = None,
    codex_status: str | None = None,   # success / failed / skipped / missing
    codex_error: str | None = None,    # 失败原因（仅 codex_status=failed 时有意义）
    registration_driver: str | None = None,
    registration_job_id: int | None = None,
    registration_batch_id: str | None = None,
    email_allocation_id: int | None = None,
    oauth_requested: bool | None = None,
) -> int:
    """插入或更新注册成功账号，返回本地文件中的 id。"""
    with _LOCK:
        accounts = _load_accounts()
        outlook_rows = _load_outlook()
        existing = _find_by_email(accounts, email)
        allocation = get_email_allocation_by_actual_email(email)
        allocation_source = str((allocation or {}).get("source") or "generic_api").strip().lower()
        if allocation and allocation_source == "outlook":
            outlook_email = str(allocation.get("base_email") or email)
            outlook_row = _find_by_email(outlook_rows, outlook_email)
        elif allocation or str(email_source or "").strip().lower() not in {"", "outlook"}:
            outlook_row = None
        else:
            outlook_row = _find_by_email(outlook_rows, email)
        extra_json = json.dumps(extra, ensure_ascii=False) if extra else None

        if existing is None:
            row_id = _next_id(accounts)
            row = {
                "id": row_id,
                "email": email,
                "created_at": _now(),
            }
            accounts.append(row)
        else:
            row = existing
            row_id = int(row["id"])

        row.update({
            "access_token": access_token,
            "totp_secret": totp_secret if totp_secret is not None else row.get("totp_secret"),
            "user_id": user_id if user_id is not None else row.get("user_id"),
            "user_name": user_name if user_name is not None else row.get("user_name"),
            "plan_type": plan_type if plan_type is not None else row.get("plan_type"),
            "expires_at": expires_at if expires_at is not None else row.get("expires_at"),
            "device_id": device_id if device_id is not None else row.get("device_id"),
            "proxy_used": proxy_used if proxy_used is not None else row.get("proxy_used"),
            "email_source": email_source if email_source is not None else row.get("email_source"),
            "extra_json": extra_json if extra_json is not None else row.get("extra_json"),
            "codex_status": codex_status if codex_status is not None else row.get("codex_status"),
            "codex_error": codex_error if codex_error is not None else row.get("codex_error"),
            "registration_driver": registration_driver if registration_driver is not None else row.get("registration_driver"),
            "registration_job_id": registration_job_id if registration_job_id is not None else row.get("registration_job_id"),
            "registration_batch_id": registration_batch_id if registration_batch_id is not None else row.get("registration_batch_id"),
            "email_allocation_id": (
                email_allocation_id
                if email_allocation_id is not None
                else (allocation or {}).get("id") or row.get("email_allocation_id")
            ),
            "oauth_requested": bool(oauth_requested) if oauth_requested is not None else bool(row.get("oauth_requested")),
            "updated_at": _now(),
        })

        if outlook_row:
            row["password"] = outlook_row.get("password")
            row["client_id"] = outlook_row.get("client_id")
            row["refresh_token"] = outlook_row.get("refresh_token")
            material_row = dict(outlook_row)
            material_row["email"] = email
            row["original_email_line"] = _outlook_line(material_row)
            # Alias 注册必须把基础邮箱租约保留到注册和可选 Codex OAuth 都收尾。
            # 没有分配记录的旧 single 路径继续维持原来的直接 used 行为。
            if not allocation or allocation_source != "outlook":
                outlook_row["status"] = "used"
                outlook_row["used_at"] = outlook_row.get("used_at") or _now()
                outlook_row["registered_account_id"] = row_id
                outlook_row["access_token"] = access_token
                outlook_row["completed_at"] = _now()
                if totp_secret:
                    outlook_row["totp_secret"] = totp_secret

        row["copy_line"] = _account_line(row)
        _save_accounts(accounts)
        _save_outlook(outlook_rows)
        return row_id


def update_account_registration_context(
    acc_id: int,
    *,
    registration_driver: str | None = None,
    registration_job_id: int | None = None,
    registration_batch_id: str | None = None,
    email_allocation_id: int | None = None,
    oauth_requested: bool | None = None,
) -> bool:
    """注册驱动返回账号后补齐任务关联，不触碰任何 token。"""
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        previous = dict(row)
        values = {
            "registration_driver": registration_driver,
            "registration_job_id": registration_job_id,
            "registration_batch_id": _resolve_registration_batch_id(registration_batch_id),
            "email_allocation_id": email_allocation_id,
        }
        for key, value in values.items():
            if value is not None:
                row[key] = value
        if oauth_requested is not None:
            row["oauth_requested"] = bool(oauth_requested)
        job = None
        if registration_job_id is not None:
            job = next((
                item for item in _load_jobs()
                if int(item.get("id") or 0) == int(registration_job_id)
            ), None)
            traffic = (job or {}).get("roxy_traffic")
            if isinstance(traffic, dict):
                row["roxy_traffic"] = json.loads(json.dumps(traffic, ensure_ascii=False))
        row["updated_at"] = _now()
        # Registration linkage is bounded metadata.  If the job also carries
        # a traffic snapshot, keep the normal checkpoint because that payload
        # is not part of the transient journal whitelist.
        if isinstance((job or {}).get("roxy_traffic"), dict):
            _save_accounts(rows)
        else:
            _save_account_progress_fields(
                rows, row, previous,
                ("registration_driver", "registration_job_id", "registration_batch_id",
                 "email_allocation_id", "oauth_requested", "updated_at"),
            )
        return True


def update_account_web_cookie_credential(
    acc_id: int,
    *,
    credential_path: str | None = None,
    saved_at: str | None = None,
    cookie_count: int | None = None,
    has_session_cookie: bool | None = None,
    status: str = "saved",
    error: str | None = None,
) -> bool:
    """更新 Web Cookie 凭证元数据；Cookie 内容始终保存在独立受管文件。"""
    normalized_status = str(status or "missing").strip().lower()
    if normalized_status not in {"saved", "empty", "failed", "missing"}:
        normalized_status = "failed"
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        previous = dict(row)
        if credential_path is not None:
            row["web_cookie_credential_path"] = str(credential_path or "")
        if saved_at is not None:
            row["web_cookie_saved_at"] = saved_at
        if cookie_count is not None:
            row["web_cookie_count"] = max(0, int(cookie_count or 0))
        if has_session_cookie is not None:
            row["web_cookie_has_session"] = bool(has_session_cookie)
        row["web_cookie_capture_status"] = normalized_status
        row["web_cookie_capture_error"] = str(error or "")[:1000] or None
        row["updated_at"] = _now()
        _save_account_progress_fields(
            rows, row, previous,
            ("web_cookie_credential_path", "web_cookie_saved_at", "web_cookie_count",
             "web_cookie_has_session", "web_cookie_capture_status",
             "web_cookie_capture_error", "updated_at"),
        )
        return True


def update_account_codex_status(
    email: str,
    codex_status: str,
    codex_error: str | None = None,
    *,
    failure_stage: str | None = None,
) -> bool:
    """
    单独更新某账号的 codex_status / codex_error（手动补跑 Codex 时用）。
    返回是否找到该账号。
    """
    with _LOCK:
        accounts = _load_accounts()
        row = _find_by_email(accounts, email)
        if row is None:
            return False
        previous = dict(row)
        row["codex_status"] = codex_status
        row["codex_error"] = codex_error
        row["codex_last_attempt_status"] = codex_status
        row["codex_last_attempt_at"] = _now()
        row["codex_last_error"] = codex_error
        row["codex_last_failure_stage"] = failure_stage if codex_error else None
        row["updated_at"] = _now()
        if str(codex_status or "").lower() in {"queued", "running", "retrying"}:
            _save_account_progress(accounts, row, previous)
        else:
            # A terminal status is used by admission/error recovery and must
            # be visible in the canonical snapshot immediately.
            _save_accounts(accounts)
        return True


def update_account_codex_statuses_bulk(updates: list[dict]) -> None:
    """Batch queue/dispatch bookkeeping; never changes account credentials."""
    if not updates:
        return
    with _LOCK:
        rows = _load_accounts()
        by_id = {int(row.get("id") or 0): row for row in rows}
        changes = []
        now = _now()
        try:
            for item in updates:
                row = by_id.get(int(item["account_id"]))
                if row is None or str(row.get("email") or "").strip() != item["email"]:
                    continue
                changes.append((row, dict(row)))
                status, error = item["status"], item.get("error")
                row.update({
                    "codex_status": status, "codex_error": error,
                    "codex_last_attempt_status": status, "codex_last_attempt_at": now,
                    "codex_last_error": error, "codex_last_failure_stage": None, "updated_at": now,
                })
            if any(item["status"] not in {"queued", "running", "retrying"} for item in updates):
                _save_accounts(rows)
            else:
                _save_account_progress_many(rows, changes)
        except BaseException:
            for row, previous in reversed(changes):
                row.clear()
                row.update(previous)
            raise


def update_account_codex_result(email: str, result: dict | None) -> bool:
    """同步 Codex 结果；Web access_token 永远不会在此函数中写入。"""
    result = result or {}
    credential = result.get("credential") if isinstance(result.get("credential"), dict) else {}
    path_text = str(result.get("file_path") or "").strip()
    if path_text and not credential:
        try:
            loaded = json.loads(Path(path_text).read_text(encoding="utf-8"))
            credential = loaded if isinstance(loaded, dict) else {}
        except Exception:
            credential = {}
    refresh_token = str(result.get("refresh_token") or credential.get("refresh_token") or "").strip()
    requested_ok = bool(result.get("ok"))
    status = (
        "success" if refresh_token else "failed"
    ) if requested_ok else str(result.get("status") or "failed")
    error = None if status == "success" else str(
        result.get("message") or ("Codex OAuth 未返回 refresh_token" if requested_ok else "Codex OAuth 未完成")
    )[:1000]
    with _LOCK:
        accounts = _load_accounts()
        row = _find_by_email(accounts, email)
        if row is None:
            return False
        previous = dict(row)
        now = _now()
        row["codex_status"] = status
        row["codex_error"] = error
        row["codex_last_attempt_status"] = status
        row["codex_last_attempt_at"] = now
        row["codex_last_error"] = error
        row["codex_last_failure_stage"] = (
            str(result.get("failure_stage") or result.get("stage") or "oauth")
            if error else None
        )
        if refresh_token:
            from core.codex_plan import credential_summary
            row["codex_refresh_token"] = refresh_token
            row["codex_workspace_id"] = str(credential.get("account_id") or "")
            row["codex_plan_type"] = credential_summary(credential)["plan_type"]
            row["codex_credential_path"] = path_text or row.get("codex_credential_path")
            row["codex_token_expires_at"] = credential.get("expired") or result.get("expires_at")
            row["codex_last_refresh_at"] = credential.get("last_refresh") or now
        verification = result.get("totp_login_verification")
        if status == "success" and result.get("login_mode") == "password_totp" and isinstance(verification, dict):
            from core.codex_password_totp import login_material_fingerprint, PasswordTotpLoginError
            try:
                matches = login_material_fingerprint(row) == verification.get("material_fingerprint")
            except PasswordTotpLoginError:
                matches = False
            factor_id = str(verification.get("factor_id") or "")
            if matches and re.fullmatch(r"[A-Za-z0-9_-]{8,256}", factor_id):
                row.update({"totp_status": "active", "totp_factor_id": factor_id,
                            "totp_message": "已通过密码 + 2FA 授权验证", "totp_error": None,
                            "totp_checked_at": now})
        for key in ("sms_country", "sms_provider_id", "sms_cost", "codex_phone_status"):
            if result.get(key) is not None:
                row[key] = result.get(key)
        row["updated_at"] = now
        _save_accounts(accounts)
        return True


def claim_account_codex_agent(acc_id: int, trigger: str = "manual") -> bool:
    """原子占用账号 Codex Agent Token 生成任务；已有未超时任务时返回 False。"""
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        current_status = row.get("codex_agent_status")
        if current_status in {"queued", "running"}:
            try:
                stamp_key = "codex_agent_queued_at" if current_status == "queued" else "codex_agent_started_at"
                stale_after = _PLAN_CHECK_QUEUE_STALE_SECONDS if current_status == "queued" else _PLAN_CHECK_STALE_SECONDS
                started_at = datetime.fromisoformat(str(row.get(stamp_key) or ""))
                if (datetime.now() - started_at).total_seconds() < stale_after:
                    return False
            except (TypeError, ValueError):
                pass
        previous = dict(row)
        now = _now()
        row["codex_agent_status"] = "queued"
        row["codex_agent_ok"] = False
        row["codex_agent_trigger"] = str(trigger or "manual")
        row["codex_agent_queued_at"] = now
        row["codex_agent_started_at"] = None
        row["codex_agent_completed_at"] = None
        row["codex_agent_error"] = None
        row["codex_agent_message"] = "已入队"
        row["updated_at"] = now
        _save_account_progress_fields(
            accounts, row, previous,
            ("codex_agent_status", "codex_agent_ok", "codex_agent_trigger",
             "codex_agent_queued_at", "codex_agent_started_at", "codex_agent_completed_at",
             "codex_agent_error", "codex_agent_message", "updated_at"),
        )
        return True


def mark_account_codex_agent_running(acc_id: int) -> bool:
    """把 Codex Agent Token 生成任务标记为运行中。"""
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None or row.get("codex_agent_status") not in {"queued", "running"}:
            return False
        previous = dict(row)
        row["codex_agent_status"] = "running"
        row["codex_agent_started_at"] = _now()
        row["codex_agent_error"] = None
        row["codex_agent_message"] = "正在生成 Codex Agent Token"
        row["updated_at"] = _now()
        _save_account_progress_fields(
            accounts, row, previous,
            ("codex_agent_status", "codex_agent_started_at", "codex_agent_error",
             "codex_agent_message", "updated_at"),
        )
        return True


def update_account_codex_agent(acc_id: int, result: dict | None = None) -> bool:
    """更新账号 Codex Agent Token 生成结果/进度。"""
    result = result or {}
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        previous = dict(row)
        status = str(result.get("status") or ("success" if result.get("ok") else "failed"))
        ok = bool(result.get("ok")) and status == "success"
        row["codex_agent_status"] = status
        row["codex_agent_ok"] = ok
        row["codex_agent_checked_at"] = result.get("checked_at") or _now()
        if status in {"success", "failed", "stopped"}:
            row["codex_agent_completed_at"] = _now()
        row["codex_agent_error"] = None if ok or status == "running" else result.get("error")
        if result.get("message") is not None:
            row["codex_agent_message"] = result.get("message")
        if result.get("agent_runtime_id") is not None:
            row["codex_agent_runtime_id"] = result.get("agent_runtime_id")
        if result.get("auth_path") is not None:
            row["codex_agent_auth_path"] = result.get("auth_path")
        if isinstance(result.get("auth_json"), dict):
            row["codex_agent_token"] = json.dumps(result.get("auth_json"), ensure_ascii=False)
        for _k in (
            "codex_agent_network_route",
            "codex_agent_proxy_mode",
            "codex_agent_proxy_used",
            "codex_agent_proxy_fallback_reason",
            "codex_agent_device_id",
            "codex_agent_oai_session_id",
            "codex_agent_attempt_count",
            "codex_agent_max_attempts",
            "codex_agent_request_timeout",
            "codex_agent_sub2api_path",
            "codex_agent_sub2api_url",
            "codex_agent_sub2api_mode",
            "codex_agent_sub2api_total",
        ):
            src_key = _k.replace("codex_agent_", "", 1)
            if result.get(src_key) is not None:
                row[_k] = result.get(src_key)
        row["updated_at"] = _now()
        if status in {"queued", "running"} and not any(
            key in result for key in ("auth_json", "auth_path", "agent_runtime_id")
        ):
            _save_account_progress_fields(
                accounts, row, previous,
                ("codex_agent_status", "codex_agent_ok", "codex_agent_checked_at",
                 "codex_agent_completed_at", "codex_agent_error", "codex_agent_message",
                 "codex_agent_network_route", "codex_agent_proxy_mode", "codex_agent_proxy_used",
                 "codex_agent_proxy_fallback_reason", "codex_agent_device_id",
                 "codex_agent_attempt_count", "codex_agent_max_attempts",
                 "codex_agent_request_timeout", "codex_agent_sub2api_mode",
                 "codex_agent_sub2api_total", "updated_at"),
            )
        else:
            _save_accounts(accounts)
        return True


def recover_interrupted_codex_agents() -> int:
    """服务启动时恢复上次进程中断的 Codex Agent 任务状态。"""
    with _LOCK:
        accounts = _load_accounts()
        recovered = 0
        now = _now()
        changes = []
        for row in accounts:
            if row.get("codex_agent_status") not in {"queued", "running"}:
                continue
            previous = dict(row)
            row["codex_agent_status"] = "failed"
            row["codex_agent_ok"] = False
            row["codex_agent_error"] = "WebUI 重启导致 Codex Agent Token 任务中断，请重新生成"
            row["codex_agent_completed_at"] = now
            row["updated_at"] = now
            changes.append((row, previous))
            recovered += 1
        if recovered:
            _save_account_progress_many(accounts, changes)
        return recovered


def claim_account_totp(acc_id: int, *, trigger: str = "manual") -> str | None:
    """Atomically claim one account for TOTP reconciliation/enrollment."""
    with _LOCK:
        accounts = _load_accounts()
        row = next((item for item in accounts if int(item.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return None
        previous = dict(row)
        claim_id = _claim_totp_row(row, trigger=trigger)
        if claim_id:
            _save_account_progress(accounts, row, previous)
        return claim_id


def _claim_totp_row(row: dict, *, trigger: str) -> str | None:
    if str(row.get("totp_status") or "").strip().lower() in {"queued", "running"}:
        return None
    previous_status = str(row.get("totp_status") or "").strip().lower()
    if not previous_status:
        previous_status = "active" if row.get("totp_secret") else "not_configured"
    try:
        attempts = max(0, int(row.get("totp_attempt_count") or 0))
    except (TypeError, ValueError):
        attempts = 0
    now = _now()
    claim_id = uuid.uuid4().hex
    row.update({
        "totp_previous_status": previous_status, "totp_status": "queued",
        "totp_ok": previous_status in {"active", "active_external"},
        "totp_claim_id": claim_id, "totp_trigger": str(trigger or "manual")[:100],
        "totp_queued_at": now, "totp_started_at": None, "totp_completed_at": None,
        "totp_error": None, "totp_error_code": None, "totp_failure_stage": None,
        "totp_http_status": None, "totp_retryable": None,
        "totp_message": "TOTP 补接任务已入队", "totp_attempt_count": attempts + 1,
        "updated_at": now,
    })
    return claim_id


def mark_account_totp_running(acc_id: int, *, claim_id: str) -> bool:
    """Only the current claim may transition a queued TOTP task to running."""
    with _LOCK:
        accounts = _load_accounts()
        row = next((item for item in accounts if int(item.get("id") or 0) == int(acc_id)), None)
        if (
            row is None
            or str(row.get("totp_claim_id") or "") != str(claim_id or "")
            or str(row.get("totp_status") or "") not in {"queued", "running"}
        ):
            return False
        previous = dict(row)
        now = _now()
        row["totp_status"] = "running"
        row["totp_started_at"] = row.get("totp_started_at") or now
        row["totp_error"] = None
        row["totp_error_code"] = None
        row["totp_failure_stage"] = None
        row["totp_http_status"] = None
        row["totp_retryable"] = None
        row["totp_message"] = "正在查询并补接 TOTP"
        row["updated_at"] = now
        _save_account_progress(accounts, row, previous)
        return True


def update_account_totp(
    acc_id: int,
    *,
    result: dict | None = None,
    claim_id: str,
) -> bool:
    """Persist a claim-validated TOTP terminal state without exposing secrets."""
    result = dict(result or {})
    incoming_status = str(result.get("status") or "failed").strip().lower()
    if incoming_status not in {
        "active", "already_active", "activation_uncertain", "failed",
    }:
        raise ValueError(f"TOTP 状态无效: {incoming_status}")

    with _LOCK:
        accounts = _load_accounts()
        row = next((item for item in accounts if int(item.get("id") or 0) == int(acc_id)), None)
        if row is None or str(row.get("totp_claim_id") or "") != str(claim_id or ""):
            return False

        previous = dict(row)
        previous_status = str(row.get("totp_previous_status") or "not_configured")
        if incoming_status == "active":
            stored_status = "active"
        elif incoming_status == "already_active":
            stored_status = "active" if row.get("totp_secret") else "active_external"
        elif previous_status in {"active", "active_external"}:
            # A failed reconciliation must not downgrade a previously confirmed
            # remote factor. The attempt failure remains visible separately.
            stored_status = previous_status
        else:
            stored_status = incoming_status

        secret = str(result.get("secret") or "").strip()
        factor_id = str(result.get("factor_id") or "").strip()
        if secret:
            row["totp_secret"] = secret
        if factor_id:
            row["totp_factor_id"] = factor_id

        now = _now()
        ok = stored_status in {"active", "active_external"}
        row["totp_status"] = stored_status
        row["totp_ok"] = ok
        row["totp_last_attempt_status"] = incoming_status
        row["totp_checked_at"] = str(result.get("checked_at") or now)
        row["totp_completed_at"] = now
        row["totp_http_status"] = result.get("http_status")
        row["totp_retryable"] = (
            None
            if incoming_status in {"active", "already_active"}
            else bool(result.get("retryable"))
        )
        row["totp_error"] = (
            None if incoming_status in {"active", "already_active"}
            else str(result.get("error") or "")[:500] or None
        )
        row["totp_error_code"] = (
            None if incoming_status in {"active", "already_active"}
            else str(result.get("error_code") or "")[:100] or None
        )
        row["totp_failure_stage"] = (
            None
            if incoming_status in {"active", "already_active"}
            else str(result.get("failure_stage") or "")[:100] or None
        )
        row["totp_message"] = str(result.get("message") or "")[:500] or None
        if result.get("factor_count") is not None:
            try:
                row["totp_factor_count"] = max(0, int(result.get("factor_count") or 0))
            except (TypeError, ValueError):
                pass
        if ok:
            row["totp_enabled_at"] = row.get("totp_enabled_at") or now
        if result.get("token_update_error"):
            row["totp_token_update_error"] = str(result.get("token_update_error"))[:300]
        else:
            row["totp_token_update_error"] = None
        if result.get("cookie_update_error"):
            row["totp_cookie_update_error"] = str(result.get("cookie_update_error"))[:300]
        else:
            row["totp_cookie_update_error"] = None
        row["totp_claim_id"] = None
        row["totp_previous_status"] = None
        row["updated_at"] = now
        # Terminal TOTP state (and any newly issued secret/factor) is
        # checkpointed in the canonical account snapshot.  Only queued/running
        # transitions use the incremental journal above.
        _save_accounts(accounts)
        return True


def recover_interrupted_totp_tasks() -> int:
    """Make in-memory TOTP queue states retryable after a WebUI restart."""
    with _LOCK:
        accounts = _load_accounts()
        recovered = 0
        now = _now()
        changes = []
        for row in accounts:
            if str(row.get("totp_status") or "") not in {"queued", "running"}:
                continue
            previous = dict(row)
            previous_status = str(row.get("totp_previous_status") or "not_configured")
            row["totp_status"] = (
                previous_status
                if previous_status in {"active", "active_external"}
                else "failed"
            )
            row["totp_ok"] = row["totp_status"] in {"active", "active_external"}
            row["totp_last_attempt_status"] = "failed"
            row["totp_error"] = "WebUI 重启导致 TOTP 补接任务中断，请重新补接"
            row["totp_error_code"] = "restart_interrupted"
            row["totp_message"] = row["totp_error"]
            row["totp_completed_at"] = now
            row["totp_claim_id"] = None
            row["totp_previous_status"] = None
            row["updated_at"] = now
            changes.append((row, previous))
            recovered += 1
        if recovered:
            _save_account_progress_many(accounts, changes)
        return recovered


def claim_account_team_invite(acc_id: int, *, trigger: str = "manual") -> str | None:
    """Atomically claim one account for Team invitation reconciliation."""
    with _LOCK:
        accounts = _load_accounts()
        row = next(
            (item for item in accounts if int(item.get("id") or 0) == int(acc_id)),
            None,
        )
        if row is None:
            return None
        previous = dict(row)
        claim_id = _claim_team_row(row, trigger=trigger)
        if claim_id:
            _save_account_progress(accounts, row, previous)
        return claim_id


def _claim_team_row(row: dict, *, trigger: str) -> str | None:
    previous_status = str(
        row.get("team_status") or row.get("team_invite_status") or "not_checked"
    ).strip().lower()
    if previous_status in {"queued", "running"}:
        return None
    if previous_status not in _TEAM_INVITE_STATUSES:
        previous_status = "not_checked"
    now = _now()
    claim_id = uuid.uuid4().hex
    row.update({
        "team_invite_previous_status": previous_status, "team_invite_last_attempt_status": None,
        "team_status": "queued", "team_invite_status": "queued", "team_invite_claim_id": claim_id,
        "team_invite_trigger": str(trigger or "manual")[:100], "team_invite_queued_at": now,
        "team_invite_started_at": None, "team_invite_completed_at": None, "team_invite_checked_at": None,
        "team_invite_message": "补 Team 任务已入队", "team_invite_error": None,
        "team_invite_error_code": None, "team_invite_retryable": None, "updated_at": now,
    })
    # Preserve confirmed membership during retries, exactly as the single path.
    if previous_status not in {"joined", "already_member"}:
        row.update({
            "team_invite_recipient_verified": None, "team_invite_link_fingerprint": None,
            "team_workspace_id": None, "team_workspace_name": None, "team_session_account_id": None,
            "team_session_refreshed": False, "team_cookie_count": 0,
        })
    try:
        attempts = max(0, int(row.get("team_invite_attempt_count") or 0))
    except (TypeError, ValueError):
        attempts = 0
    row["team_invite_attempt_count"] = attempts + 1
    return claim_id


def claim_account_supplements_bulk(candidates: list[dict], *, kind: str, trigger: str) -> dict:
    """Revalidate and durably claim supplementation/health rows in one scan/write.

    Candidates contain id/email and an optional health record_no_token marker;
    no caller-supplied credentials or states are trusted. The caller owns queue
    slots for worker entries and must submit only after this function returns.
    """
    if kind not in {"team", "totp", "health", "quota"}:
        raise ValueError("unsupported supplement kind")
    claim_row = {"team": _claim_team_row, "totp": _claim_totp_row, "health": _claim_health_row, "quota": _claim_quota_row}[kind]
    busy_error = {"team": "该账号正在补 Team", "totp": "该账号正在补接 TOTP", "health": "该账号正在验活", "quota": "该账号正在查询额度"}[kind]
    credential_key = {"team": "has_web_cookies", "quota": "has_quota_credential"}.get(kind, "has_access_token")
    with _LOCK:
        rows = _load_accounts()
        wanted = {int(item["id"]) for item in candidates}
        by_id = {int(row.get("id") or 0): row for row in rows if int(row.get("id") or 0) in wanted}
        changes = []
        results = {}
        has_terminal = False
        try:
            for item in candidates:
                account_id = int(item["id"])
                if account_id in results:
                    continue
                row = by_id.get(account_id)
                if row is None or str(row.get("email") or "").strip() != item["email"]:
                    results[account_id] = {"error": "账号已删除或邮箱已变化"}
                    continue
                candidate = _account_supplement_candidate(row)
                if kind == "health" and item.get("record_no_token") and candidate["has_access_token"]:
                    # A token appeared after the snapshot. This entry did not
                    # reserve a worker slot: never enqueue it or mark it empty.
                    results[account_id] = {"error": "账号凭证已变化，请重新验活"}
                    continue
                if kind != "health" and not candidate[credential_key]:
                    results[account_id] = {"error": "账号登录凭证已变化，请刷新后重试"}
                    continue
                previous = dict(row)
                claim_id = claim_row(row, trigger=trigger)
                if claim_id:
                    changes.append((row, previous))
                    if kind == "health" and not candidate["has_access_token"]:
                        _apply_health_result(row, {
                            "reason": "missing_token", "message": "账号缺少 Web AT",
                        }, status="no_token")
                        has_terminal = True
                        results[account_id] = {"recorded": True, "status": "no_token", "error": None}
                    else:
                        results[account_id] = {"claim_id": claim_id}
                else:
                    results[account_id] = {"busy": True, "error": busy_error}
            if has_terminal:
                # Persist all no_token final results once, together with any
                # claims, before returning recorded=True to the API.
                _save_accounts(rows)
            else:
                _save_account_progress_many(rows, changes)
        except BaseException:
            for row, previous in changes:
                row.clear()
                row.update(previous)
            raise
        return results


def mark_account_team_invite_running(acc_id: int, *, claim_id: str) -> bool:
    """Move the current Team invitation claim from queued to running."""
    with _LOCK:
        accounts = _load_accounts()
        row = next(
            (item for item in accounts if int(item.get("id") or 0) == int(acc_id)),
            None,
        )
        if (
            row is None
            or str(row.get("team_invite_claim_id") or "") != str(claim_id or "")
            or str(row.get("team_status") or row.get("team_invite_status") or "")
            not in {"queued", "running"}
        ):
            return False
        previous = dict(row)
        now = _now()
        row["team_status"] = "running"
        row["team_invite_status"] = "running"
        row["team_invite_started_at"] = row.get("team_invite_started_at") or now
        trigger = str(row.get("team_invite_trigger") or "").lower()
        row["team_invite_message"] = (
            "正在读取 Team 邀请并使用协议登录态处理"
            if "protocol" in trigger
            else "正在读取 Team 邀请并复用 Roxy 登录态"
        )
        row["team_invite_error"] = None
        row["team_invite_error_code"] = None
        row["team_invite_retryable"] = None
        row["updated_at"] = now
        _save_account_progress(accounts, row, previous)
        return True


def update_account_team_invite(
    acc_id: int,
    *,
    result: dict | None = None,
    claim_id: str,
) -> bool:
    """Persist a sanitized Team invite result for the current claim.

    The invite URL and any access-token value are intentionally not accepted as
    persisted fields.  Only a fingerprint, workspace metadata, and cookie
    counts are retained for the account UI/audit trail.
    """
    result = dict(result or {})
    incoming_status = str(result.get("status") or "failed").strip().lower()
    if incoming_status not in _TEAM_INVITE_STATUSES - {"not_checked", "queued", "running"}:
        raise ValueError(f"Team 邀请状态无效: {incoming_status}")

    with _LOCK:
        accounts = _load_accounts()
        row = next(
            (item for item in accounts if int(item.get("id") or 0) == int(acc_id)),
            None,
        )
        if row is None or str(row.get("team_invite_claim_id") or "") != str(claim_id or ""):
            return False

        # Keep a rollback snapshot before applying the terminal metadata.  The
        # progress-journal writer uses it both to compute the delta and to
        # restore the in-memory row if the write fails.
        previous = dict(row)
        previous_status = str(row.get("team_invite_previous_status") or "not_checked").strip().lower()
        if incoming_status in {"joined", "already_member"}:
            stored_status = incoming_status
        elif previous_status in {"joined", "already_member"} and incoming_status in {
            "failed", "no_invite", "expired", "wrong_account", "not_confirmed",
            "session_required", "unsupported", "needs_acceptance",
        }:
            # Preserve the effective membership state; expose the failed
            # retry through team_invite_last_attempt_status/error fields.
            stored_status = previous_status
        else:
            stored_status = incoming_status

        now = _now()
        row["team_status"] = stored_status
        row["team_invite_status"] = stored_status
        row["team_invite_last_attempt_status"] = incoming_status
        row["team_invite_checked_at"] = str(result.get("checked_at") or now)
        row["team_invite_completed_at"] = now
        row["team_invite_message"] = str(result.get("message") or "")[:500] or None
        row["team_invite_error"] = (
            None
            if incoming_status in {"joined", "already_member", "invite_found"}
            else str(result.get("error") or "")[:500] or None
        )
        row["team_invite_error_code"] = (
            None
            if incoming_status in {"joined", "already_member", "invite_found"}
            else str(result.get("error_code") or "")[:120] or None
        )
        row["team_invite_retryable"] = (
            None
            if incoming_status in {"joined", "already_member"}
            else bool(result.get("retryable"))
        )

        fingerprint = str(
            result.get("invite_link_fingerprint")
            or result.get("link_fingerprint")
            or ""
        ).strip().lower()
        if re.fullmatch(r"[0-9a-f]{16,128}", fingerprint):
            row["team_invite_link_fingerprint"] = fingerprint[:128]
        recipient_verified = result.get("recipient_verified")
        if recipient_verified is not None:
            row["team_invite_recipient_verified"] = bool(recipient_verified)

        for source, target, limit in (
            ("workspace_id", "team_workspace_id", 200),
            ("workspace_name", "team_workspace_name", 200),
            ("session_account_id", "team_session_account_id", 200),
        ):
            value = str(result.get(source) or "").strip()
            if value:
                row[target] = value[:limit]
        if result.get("session_refreshed") is not None:
            row["team_session_refreshed"] = bool(result.get("session_refreshed"))
        if result.get("cookie_count") is not None:
            try:
                row["team_cookie_count"] = max(0, int(result.get("cookie_count") or 0))
            except (TypeError, ValueError):
                row["team_cookie_count"] = 0
        if incoming_status in {"joined", "already_member"}:
            row["team_joined_at"] = row.get("team_joined_at") or now

        row["team_invite_claim_id"] = None
        row["team_invite_previous_status"] = None
        row["updated_at"] = now
        # Terminal Team state is a canonical checkpoint.  The invitation URL
        # and browser cookies remain in their dedicated stores.
        _save_accounts(accounts)
        return True


def recover_interrupted_team_invites() -> int:
    """Make queued/running Team invite tasks retryable after a restart."""
    with _LOCK:
        accounts = _load_accounts()
        recovered = 0
        now = _now()
        changes = []
        for row in accounts:
            status = str(
                row.get("team_status") or row.get("team_invite_status") or ""
            ).strip().lower()
            if status not in {"queued", "running"}:
                continue
            previous = dict(row)
            previous_status = str(row.get("team_invite_previous_status") or "not_checked").strip().lower()
            stored_status = previous_status if previous_status in {"joined", "already_member"} else "failed"
            row["team_status"] = stored_status
            row["team_invite_status"] = stored_status
            row["team_invite_last_attempt_status"] = "failed"
            row["team_invite_error"] = "WebUI 重启导致补 Team 任务中断，请重新补 Team"
            row["team_invite_error_code"] = "restart_interrupted"
            row["team_invite_retryable"] = True
            row["team_invite_message"] = row["team_invite_error"]
            row["team_invite_completed_at"] = now
            row["team_invite_checked_at"] = now
            row["team_invite_claim_id"] = None
            row["team_invite_previous_status"] = None
            row["updated_at"] = now
            changes.append((row, previous))
            recovered += 1
        if recovered:
            _save_account_progress_many(accounts, changes)
        return recovered


def claim_account_plan_check(
    acc_id: int | None = None,
    email: str | None = None,
    trigger: str = "manual",
) -> bool:
    """原子占用账号的套餐查询；已有未超时查询时返回 False。"""
    with _LOCK:
        accounts = _load_accounts()
        target_email = (email or "").lower()
        row = next((
            r for r in accounts
            if (acc_id is not None and int(r.get("id") or 0) == int(acc_id))
            or (target_email and (r.get("email") or "").lower() == target_email)
        ), None)
        if row is None:
            return False

        current_status = row.get("plan_check_status")
        if current_status in {"queued", "running"}:
            try:
                stamp_key = "plan_check_queued_at" if current_status == "queued" else "plan_check_started_at"
                stale_after = _PLAN_CHECK_QUEUE_STALE_SECONDS if current_status == "queued" else _PLAN_CHECK_STALE_SECONDS
                started_at = datetime.fromisoformat(str(row.get(stamp_key) or ""))
                if (datetime.now() - started_at).total_seconds() < stale_after:
                    return False
            except (TypeError, ValueError):
                pass

        previous = dict(row)
        now = _now()
        row["plan_check_status"] = "queued"
        row["plan_check_trigger"] = str(trigger or "manual")
        row["plan_check_queued_at"] = now
        row["plan_check_started_at"] = None
        row["plan_check_completed_at"] = None
        row["plan_check_error"] = None
        row["updated_at"] = now
        _save_account_progress_fields(
            accounts, row, previous,
            ("plan_check_status", "plan_check_trigger", "plan_check_queued_at",
             "plan_check_started_at", "plan_check_completed_at", "plan_check_error",
             "updated_at"),
        )
        return True


def mark_account_plan_check_running(acc_id: int) -> bool:
    """把已排队的套餐查询标记为执行中。"""
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None or row.get("plan_check_status") not in {"queued", "running"}:
            return False
        previous = dict(row)
        row["plan_check_status"] = "running"
        row["plan_check_started_at"] = _now()
        row["plan_check_error"] = None
        row["updated_at"] = _now()
        _save_account_progress_fields(
            accounts, row, previous,
            ("plan_check_status", "plan_check_started_at", "plan_check_error", "updated_at"),
        )
        return True


def recover_interrupted_plan_checks() -> int:
    """服务启动时把上次进程遗留的内存队列状态恢复为可重试失败。"""
    with _LOCK:
        accounts = _load_accounts()
        recovered = 0
        now = _now()
        changes = []
        for row in accounts:
            if row.get("plan_check_status") not in {"queued", "running"}:
                continue
            previous = dict(row)
            row["plan_check_status"] = "failed"
            row["plan_check_ok"] = False
            row["plan_check_error"] = "WebUI 重启导致套餐查询中断，请重新查询"
            row["plan_check_completed_at"] = now
            row["updated_at"] = now
            changes.append((row, previous))
            recovered += 1
        if recovered:
            _save_account_progress_many(accounts, changes)
        return recovered


def update_account_plan_check(acc_id: int | None = None, email: str | None = None, result: dict | None = None) -> bool:
    """更新账号套餐/Plus 试用资格查询结果。"""
    result = result or {}
    with _LOCK:
        accounts = _load_accounts()
        target_email = (email or "").lower()
        row = next((
            r for r in accounts
            if (acc_id is not None and int(r.get("id") or 0) == int(acc_id))
            or (target_email and (r.get("email") or "").lower() == target_email)
        ), None)
        if row is None:
            return False

        ok = bool(result.get("ok"))
        row["plan_check_status"] = "success" if ok else "failed"
        row["plan_check_ok"] = ok
        row["plan_checked_at"] = result.get("checked_at") or _now()
        row["plan_check_completed_at"] = _now()
        row["plan_check_http_status"] = result.get("http_status")
        row["plan_check_error"] = None if ok else result.get("error")

        if result.get("account_id"):
            row["account_id"] = result.get("account_id")
        # 查询失败只更新本次错误和网络信息，不覆盖上一次成功拿到的套餐、
        # 试用资格、优惠及有效期，避免临时网络故障把真实权益清空。
        if ok:
            if result.get("current_plan_type"):
                row["current_plan_type"] = result.get("current_plan_type")
                row["plan_type"] = result.get("current_plan_type")
            if result.get("subscription_plan") is not None:
                row["subscription_plan"] = result.get("subscription_plan")
            if result.get("has_active_subscription") is not None:
                row["has_active_subscription"] = bool(result.get("has_active_subscription"))
            if result.get("expires_at") is not None:
                row["plan_expires_at"] = result.get("expires_at")
            if result.get("renews_at") is not None:
                row["plan_renews_at"] = result.get("renews_at")
            if result.get("cancels_at") is not None:
                row["plan_cancels_at"] = result.get("cancels_at")
            if result.get("billing_period") is not None:
                row["billing_period"] = result.get("billing_period")
            if result.get("billing_currency") is not None:
                row["billing_currency"] = result.get("billing_currency")
            if result.get("is_delinquent") is not None:
                row["is_delinquent"] = bool(result.get("is_delinquent"))
            for _k in (
                "discount_type",
                "discount_amount",
                "discount_duration_num_periods",
                "discount_expires_at",
                "discount_cancellation_policy",
                "discount_promo_campaign_id",
                "last_purchase_origin_platform",
                "last_will_renew",
            ):
                if result.get(_k) is not None:
                    row[_k] = result.get(_k)

            row["plus_trial_eligible"] = bool(result.get("plus_trial_eligible"))
            row["plus_trial_campaign_id"] = result.get("plus_trial_campaign_id")
            row["plus_trial_title"] = result.get("plus_trial_title")
            row["plus_trial_discount_percentage"] = result.get("plus_trial_discount_percentage")
            row["plus_trial_duration_num_periods"] = result.get("plus_trial_duration_num_periods")
            row["plus_trial_duration_period"] = result.get("plus_trial_duration_period")
            row["eligible_offer_ids"] = result.get("eligible_offer_ids") or []
            # A successful accounts/check is authoritative for the current
            # campaign set. Clear stale coupon metadata when a later check says
            # the account is no longer eligible.
            if not bool(result.get("plus_trial_eligible")):
                for _k in (
                    "plus_trial_campaign_id", "plus_trial_title",
                    "plus_trial_discount_percentage", "plus_trial_duration_num_periods",
                    "plus_trial_duration_period", "promo_coupon", "promo_state",
                    "promo_redeemed_at", "promo_expires_at",
                    "promo_promotion_length_days", "promo_check_error",
                ):
                    row[_k] = None
                for _k in (
                    "promo_redeemed", "promo_redeemed_by_user",
                    "promo_redeemed_by_workspace", "plus_trial_actionable",
                ):
                    row[_k] = False
            for _k in (
                "promo_coupon",
                "promo_state",
                "promo_redeemed_at",
                "promo_expires_at",
                "promo_promotion_length_days",
                "promo_check_http_status",
                "promo_check_error",
                "promo_checked_at",
                "promo_response_bytes",
                "promo_retry_after",
                "promo_retryable",
            ):
                if _k in result:
                    row[_k] = result.get(_k)
            for _k in (
                "promo_redeemed",
                "promo_redeemed_by_user",
                "promo_redeemed_by_workspace",
                "promo_check_ok",
            ):
                if _k in result:
                    row[_k] = (
                        None if result.get(_k) is None else bool(result.get(_k))
                    )
            for _k in (
                "billing_page_config_ok",
                "billing_page_config_http_status",
                "billing_page_config_error",
                "billing_account_eligible",
                "billing_plan_management_eligible",
                "billing_free_workspace_upgrade_eligible",
                "app_store_billing_retry_check_ok",
                "app_store_billing_retry_http_status",
                "app_store_billing_retry_error",
                "app_store_subscription_in_billing_retry",
            ):
                if _k in result:
                    value = result.get(_k)
                    if _k.endswith("_ok") or _k.endswith("_eligible") or _k.endswith("_retry"):
                        value = None if value is None else bool(value)
                    row[_k] = value
            for _k in ("plus_trial_status", "plus_trial_actionable"):
                if _k in result:
                    row[_k] = (
                        bool(result.get(_k))
                        if _k == "plus_trial_actionable"
                        else str(result.get(_k) or "")
                    )
            row["plan_last_success_at"] = result.get("checked_at") or _now()
            row["plan_last_success_result_json"] = json.dumps(result, ensure_ascii=False)
        row["plan_check_proxy_mode"] = result.get("proxy_mode")
        row["plan_check_network_route"] = result.get("network_route")
        row["plan_check_proxy_used"] = result.get("proxy_used")
        row["plan_check_proxy_fallback_reason"] = result.get("proxy_fallback_reason")
        row["token_expired"] = result.get("token_expired")
        row["token_expires_at"] = result.get("token_expires_at")
        row["plan_check_result_json"] = json.dumps(result, ensure_ascii=False)
        row["updated_at"] = _now()
        _save_accounts(accounts)
        return True


def _claim_quota_row(row: dict, *, trigger: str) -> str | None:
    if _account_quota_status(row) in {"queued", "running"}:
        return None
    check_id = uuid.uuid4().hex
    now = _now()
    row.update({
        "quota_status": "queued", "quota_check_id": check_id,
        "quota_trigger": str(trigger or "manual")[:40], "quota_queued_at": now,
        "quota_started_at": None, "quota_completed_at": None,
        "quota_ok": None, "quota_error": None, "quota_error_code": None, "updated_at": now,
    })
    return check_id


def mark_account_quota_check_running(acc_id: int, *, check_id: str) -> bool:
    with _LOCK:
        accounts = _load_accounts()
        row = next((item for item in accounts if int(item.get("id") or 0) == int(acc_id)), None)
        if (row is None or not check_id or row.get("quota_check_id") != check_id
                or _account_quota_status(row) != "queued"):
            return False
        previous = dict(row)
        now = _now()
        row["quota_status"] = "running"
        row["quota_started_at"] = now
        row["quota_error"] = None
        row["updated_at"] = now
        _save_account_progress_fields(
            accounts, row, previous,
            ("quota_status", "quota_started_at", "quota_error", "updated_at"),
        )
        return True


def recover_interrupted_quota_checks() -> int:
    """服务重启后把内存队列遗留状态恢复为可重试失败。"""
    with _LOCK:
        accounts = _load_accounts()
        changes = []
        now = _now()
        for row in accounts:
            if _account_quota_status(row) not in {"queued", "running"}:
                continue
            previous = dict(row)
            row.update({
                "quota_status": "failed",
                "quota_ok": False,
                "quota_error": "WebUI 重启导致额度查询中断，请重新查询",
                "quota_completed_at": now,
                "quota_checked_at": now,
                "quota_check_id": None,
                "quota_error_code": "restart_interrupted",
                "updated_at": now,
            })
            changes.append((row, previous))
        if changes:
            _save_account_progress_many(accounts, changes)
        return len(changes)


def update_account_quota_check(acc_id: int, *, result: dict | None = None, check_id: str) -> bool:
    """写入额度查询终态；错误不会覆盖上一次成功的额度窗口。"""
    result = result or {}
    with _LOCK:
        accounts = _load_accounts()
        row = next((item for item in accounts if int(item.get("id") or 0) == int(acc_id)), None)
        if row is None or not check_id or row.get("quota_check_id") != check_id:
            return False
        previous = dict(row)
        ok = bool(result.get("ok"))
        now = _now()
        row["quota_status"] = "success" if ok else "failed"
        row["quota_ok"] = ok
        row["quota_checked_at"] = result.get("checked_at") or now
        row["quota_completed_at"] = now
        row["quota_error"] = None if ok else _redact_proxy_text(result.get("error") or "额度查询失败", limit=500)
        row["quota_error_code"] = None if ok else str(result.get("error_code") or "query_failed")[:80]
        row["quota_http_status"] = result.get("http_status")
        row["quota_check_id"] = None
        for key in ("quota_network_route", "quota_proxy_mode", "quota_proxy_used",
                    "quota_proxy_fallback_reason", "quota_attempt_count", "quota_max_attempts",
                    "quota_request_timeout"):
            row[key] = result.get(key)
        if result.get("quota_trigger"):
            row["quota_trigger"] = str(result.get("quota_trigger"))[:40]
        if ok:
            row["quota_last_success_at"] = row["quota_checked_at"]
            fields = (
                "quota_plan_type", "quota_allowed", "quota_limit_reached",
                "quota_primary_used_percent", "quota_primary_limit_window_seconds",
                "quota_primary_reset_after_seconds", "quota_primary_reset_at",
                "quota_secondary_used_percent", "quota_secondary_limit_window_seconds",
                "quota_secondary_reset_after_seconds", "quota_secondary_reset_at",
                "quota_reset_credits_available_count", "quota_reset_credit_expirations",
                "quota_additional_rate_limits", "quota_network_route", "quota_proxy_mode",
                "quota_proxy_used", "quota_proxy_fallback_reason", "quota_attempt_count",
                "quota_max_attempts", "quota_request_timeout",
                "quota_workspace_id", "quota_source",
            )
            for key in fields:
                if key in result:
                    value = result.get(key)
                    if key == "quota_reset_credit_expirations":
                        value = list(value)[:100] if isinstance(value, list) else []
                    elif key == "quota_additional_rate_limits":
                        value = list(value)[:16] if isinstance(value, list) else []
                    row[key] = value
        row["updated_at"] = now
        progress_fields = (
            "quota_status", "quota_trigger", "quota_completed_at", "quota_checked_at",
            "quota_ok", "quota_error", "quota_http_status", "quota_plan_type",
            "quota_allowed", "quota_limit_reached", "quota_primary_used_percent",
            "quota_primary_limit_window_seconds", "quota_primary_reset_after_seconds",
            "quota_primary_reset_at", "quota_secondary_used_percent",
            "quota_secondary_limit_window_seconds", "quota_secondary_reset_after_seconds",
            "quota_secondary_reset_at", "quota_reset_credits_available_count",
            "quota_reset_credit_expirations", "quota_additional_rate_limits",
            "quota_network_route", "quota_proxy_mode", "quota_proxy_used",
            "quota_proxy_fallback_reason", "quota_attempt_count", "quota_max_attempts",
            "quota_request_timeout", "updated_at",
            "quota_check_id", "quota_last_success_at", "quota_workspace_id", "quota_source", "quota_error_code",
        )
        _save_account_progress_fields(accounts, row, previous, progress_fields)
        return True


def claim_account_health_check(
    acc_id: int | None = None,
    email: str | None = None,
    trigger: str = "manual",
) -> str | None:
    """原子占用账号验活任务，返回本次不可变 check_id。"""
    with _LOCK:
        accounts = _load_accounts()
        target_email = str(email or "").lower()
        row = next((
            item for item in accounts
            if (acc_id is not None and int(item.get("id") or 0) == int(acc_id))
            or (target_email and str(item.get("email") or "").lower() == target_email)
        ), None)
        if row is None:
            return None
        previous = dict(row)
        check_id = _claim_health_row(row, trigger=trigger)
        if check_id:
            _save_account_progress(accounts, row, previous)
        return check_id


def _claim_health_row(row: dict, *, trigger: str) -> str | None:
    if str(row.get("health_status") or "").strip().lower() in {"queued", "running"}:
        return None
    try:
        attempts = max(0, int(row.get("health_attempt_count") or 0))
    except (TypeError, ValueError):
        attempts = 0
    now = _now()
    check_id = uuid.uuid4().hex
    row.update({
        "health_status": "queued", "health_alive": None, "health_check_id": check_id,
        "health_trigger": str(trigger or "manual"), "health_queued_at": now,
        "health_started_at": None, "health_completed_at": None, "health_http_status": None,
        "health_error": None, "health_token_refresh_error": None, "health_reason": None,
        "health_message": "验活任务已入队", "health_attempt_count": attempts + 1, "updated_at": now,
    })
    return check_id


def mark_account_health_check_running(acc_id: int, *, check_id: str) -> bool:
    """仅允许本次 check_id 把已排队任务标记为运行中。"""
    with _LOCK:
        accounts = _load_accounts()
        row = next((item for item in accounts if int(item.get("id") or 0) == int(acc_id)), None)
        if (
            row is None
            or str(row.get("health_check_id") or "") != str(check_id or "")
            or str(row.get("health_status") or "") not in {"queued", "running"}
        ):
            return False
        previous = dict(row)
        now = _now()
        row["health_status"] = "running"
        row["health_started_at"] = row.get("health_started_at") or now
        row["health_error"] = None
        row["health_message"] = "正在验证 Web AT"
        row["updated_at"] = now
        _save_account_progress(accounts, row, previous)
        return True


def update_account_health_check(
    acc_id: int,
    *,
    result: dict | None = None,
    check_id: str,
) -> bool:
    """写入验活终态；过期 worker 的 check_id 无权覆盖较新的结果。"""
    result = result or {}
    status = str(result.get("status") or "error").strip().lower()
    if status not in {"alive", "dead", "token_invalid", "error", "no_token"}:
        raise ValueError(f"账号验活状态无效: {status}")

    with _LOCK:
        accounts = _load_accounts()
        row = next((item for item in accounts if int(item.get("id") or 0) == int(acc_id)), None)
        if row is None or str(row.get("health_check_id") or "") != str(check_id or ""):
            return False

        previous = dict(row)
        _apply_health_result(row, result, status=status)
        try:
            _save_accounts(accounts)
        except BaseException:
            row.clear()
            row.update(previous)
            raise
        return True


def _apply_health_result(row: dict, result: dict, *, status: str) -> None:
    """Apply one verified terminal result; the caller validates the claim and saves."""
    checked_at = str(result.get("checked_at") or _now())
    now = _now()
    row["health_status"] = status
    row["health_alive"] = True if status == "alive" else False if status == "dead" else None
    row["health_checked_at"] = checked_at
    row["health_completed_at"] = now
    row["health_http_status"] = result.get("http_status")
    row["health_error"] = str(result.get("error") or "")[:500] if status == "error" else None
    row["health_token_refresh_error"] = (
        _redact_proxy_text(result.get("token_refresh_error"), limit=300)
        if result.get("token_refresh_error") else None
    )
    row["health_reason"] = str(result.get("reason") or "")[:100] or None
    row["health_message"] = str(result.get("message") or "")[:500] or None
    row["health_network_route"] = result.get("network_route")
    row["health_proxy_mode"] = result.get("proxy_mode")
    row["health_proxy_used"] = result.get("proxy_used")
    row["health_proxy_fallback_reason"] = result.get("proxy_fallback_reason")
    row["health_token_expires_at"] = result.get("token_expires_at")
    if status == "alive":
        row["health_last_alive_at"] = checked_at
    elif status == "dead":
        row["health_last_dead_at"] = checked_at
    elif status == "token_invalid":
        row["health_last_token_invalid_at"] = checked_at
    row["health_check_id"] = None
    row["updated_at"] = now


def recover_interrupted_account_health_checks() -> int:
    """服务启动时把遗留的验活任务恢复为可重新执行的异常状态。"""
    with _LOCK:
        accounts = _load_accounts()
        recovered = 0
        now = _now()
        changes = []
        for row in accounts:
            if str(row.get("health_status") or "") not in {"queued", "running"}:
                continue
            previous = dict(row)
            row["health_status"] = "error"
            row["health_alive"] = None
            row["health_error"] = "WebUI 重启导致验活任务中断，请重新验活"
            row["health_reason"] = "restart_interrupted"
            row["health_message"] = row["health_error"]
            row["health_completed_at"] = now
            row["health_check_id"] = None
            row["updated_at"] = now
            changes.append((row, previous))
            recovered += 1
        if recovered:
            _save_account_progress_many(accounts, changes)
        return recovered


def migrate_legacy_401_health_statuses() -> int:
    """把旧版“401=账号失活”记录迁移为 Web AT 失效。"""
    with _LOCK:
        accounts = _load_accounts()
        migrated = 0
        for row in accounts:
            reason = str(row.get("health_reason") or "").strip().lower()
            if (
                str(row.get("health_status") or "").strip().lower() != "dead"
                or str(row.get("health_http_status") or "") != "401"
                or reason not in {"", "auth_rejected", "token_rejected", "token_expired"}
            ):
                continue
            checked_at = str(row.get("health_checked_at") or _now())
            row["health_status"] = "token_invalid"
            row["health_alive"] = None
            row["health_reason"] = "token_rejected"
            row["health_message"] = "Web AT 已失效；不能据此判定账号失活"
            row["health_last_token_invalid_at"] = checked_at
            if row.get("health_last_dead_at") == checked_at:
                row["health_last_dead_at"] = None
            row["updated_at"] = _now()
            migrated += 1
        if migrated:
            _save_accounts(accounts)
        return migrated


def claim_account_extract(acc_id: int, trigger: str = "manual", link_type: str = "pix") -> bool:
    """原子占用账号提链任务；已有未超时任务时返回 False。"""
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        current_status = row.get("extract_link_status")
        if current_status in {"queued", "running"}:
            try:
                stamp_key = "extract_link_queued_at" if current_status == "queued" else "extract_link_started_at"
                stale_after = _PLAN_CHECK_QUEUE_STALE_SECONDS if current_status == "queued" else _PLAN_CHECK_STALE_SECONDS
                started_at = datetime.fromisoformat(str(row.get(stamp_key) or ""))
                if (datetime.now() - started_at).total_seconds() < stale_after:
                    return False
            except (TypeError, ValueError):
                pass
        previous = dict(row)
        now = _now()
        row["extract_link_status"] = "queued"
        row["extract_link_ok"] = False
        row["extract_link_trigger"] = str(trigger or "manual")
        row["extract_link_type"] = str(link_type or "pix").lower()
        row["extract_link_queued_at"] = now
        row["extract_link_started_at"] = None
        row["extract_link_completed_at"] = None
        row["extract_link_error"] = None
        row["extract_link_message"] = "已入队"
        row["updated_at"] = now
        _save_account_progress_fields(
            accounts, row, previous,
            ("extract_link_status", "extract_link_ok", "extract_link_trigger",
             "extract_link_type", "extract_link_queued_at", "extract_link_started_at",
             "extract_link_completed_at", "extract_link_error", "extract_link_message",
             "updated_at"),
        )
        return True


def mark_account_extract_running(acc_id: int) -> bool:
    """把提链任务标记为运行中。"""
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None or row.get("extract_link_status") not in {"queued", "running"}:
            return False
        previous = dict(row)
        row["extract_link_status"] = "running"
        row["extract_link_started_at"] = _now()
        row["extract_link_error"] = None
        row["extract_link_message"] = "任务运行中"
        row["updated_at"] = _now()
        _save_account_progress_fields(
            accounts, row, previous,
            ("extract_link_status", "extract_link_started_at", "extract_link_error",
             "extract_link_message", "updated_at"),
        )
        return True


def update_account_extract(acc_id: int, result: dict | None = None) -> bool:
    """更新账号提链任务结果/进度。"""
    result = result or {}
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        previous = dict(row)
        status = str(result.get("status") or ("success" if result.get("ok") else "failed"))
        ok = bool(result.get("ok")) and status == "success"
        row["extract_link_status"] = status
        row["extract_link_ok"] = ok
        row["extract_link_checked_at"] = result.get("checked_at") or _now()
        if status in {"success", "failed", "stopped"}:
            row["extract_link_completed_at"] = _now()
        row["extract_link_error"] = None if ok or status == "running" else result.get("error")
        if result.get("message") is not None:
            row["extract_link_message"] = result.get("message")
        if result.get("job_id") is not None:
            row["extract_link_job_id"] = result.get("job_id")
        if result.get("link_type") is not None:
            row["extract_link_type"] = result.get("link_type")
        if result.get("cdk_remaining") is not None:
            row["extract_link_cdk_remaining"] = result.get("cdk_remaining")
        payload = result.get("result") if isinstance(result.get("result"), dict) else {}
        if payload:
            row["extract_link_long_url"] = payload.get("long_url")
            row["extract_link_copy_paste"] = payload.get("copy_paste")
            row["extract_link_image_url_png"] = payload.get("image_url_png")
            row["extract_link_image_url_svg"] = payload.get("image_url_svg")
            row["extract_link_payment_method"] = payload.get("payment_method")
            row["extract_link_payment_link_type"] = payload.get("payment_link_type")
            row["extract_link_expires_at"] = payload.get("expires_at")
            if payload.get("cdk_remaining") is not None:
                row["extract_link_cdk_remaining"] = payload.get("cdk_remaining")
            row["extract_link_result_json"] = json.dumps(payload, ensure_ascii=False)
        row["updated_at"] = _now()
        if status in {"queued", "running"} and not payload:
            _save_account_progress_fields(
                accounts, row, previous,
                ("extract_link_status", "extract_link_ok", "extract_link_checked_at",
                 "extract_link_completed_at", "extract_link_error", "extract_link_message",
                 "extract_link_job_id", "extract_link_type", "extract_link_cdk_remaining",
                 "updated_at"),
            )
        else:
            _save_accounts(accounts)
        return True


def claim_account_momo(
    acc_id: int,
    *,
    trigger: str = "manual",
    force: bool = False,
) -> str:
    """原子占用 MoMo 任务，返回 claimed/missing/busy/no_momo/success。"""
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return "missing"

        current = str(row.get("momo_status") or "unchecked").lower()
        if current in {"queued", "running"}:
            # MoMo 明确要求一个账号只能有一个 Checkout。HTTP/轮询本身已有超时，
            # 进程重启则由 recover_interrupted_momo() 统一恢复，不能按墙钟时间抢占。
            return "busy"
        elif current in {"no_momo", "success"} and not force:
            return current

        previous = dict(row)
        now = _now()
        row["momo_status"] = "queued"
        row["momo_trigger"] = str(trigger or "manual")
        row["momo_force"] = bool(force)
        row["momo_queued_at"] = now
        row["momo_started_at"] = None
        row["momo_completed_at"] = None
        row["momo_message"] = "MoMo 提链已入队"
        row["momo_error"] = None
        row["momo_url"] = ""
        row["momo_currency"] = None
        row["momo_amount"] = None
        row["momo_payment_method_types"] = []
        row["momo_proxy_key"] = None
        row["momo_failure_stage"] = None
        row["momo_attempt_count"] = int(row.get("momo_attempt_count") or 0) + 1
        row["updated_at"] = now
        _save_account_progress_fields(
            accounts, row, previous,
            ("momo_status", "momo_trigger", "momo_force", "momo_queued_at",
             "momo_started_at", "momo_completed_at", "momo_message", "momo_error",
             "momo_failure_stage", "momo_attempt_count", "updated_at"),
        )
        return "claimed"


def mark_account_momo_running(acc_id: int, *, message: str = "正在创建 VN/VND Checkout") -> bool:
    """将已入队 MoMo 任务标记为运行中。"""
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None or str(row.get("momo_status") or "") not in {"queued", "running"}:
            return False
        previous = dict(row)
        row["momo_status"] = "running"
        row["momo_started_at"] = row.get("momo_started_at") or _now()
        row["momo_message"] = str(message or "MoMo 提链运行中")[:300]
        row["momo_error"] = None
        row["updated_at"] = _now()
        _save_account_progress_fields(
            accounts, row, previous,
            ("momo_status", "momo_started_at", "momo_message", "momo_error", "updated_at"),
        )
        return True


def update_account_momo(acc_id: int, result: dict | None = None) -> bool:
    """更新独立 MoMo 状态；no_momo 是正常业务终态，不写入 error。"""
    result = result or {}
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        previous = dict(row)

        status = str(result.get("status") or ("success" if result.get("ok") else "failed")).lower()
        if status not in {"queued", "running", "no_momo", "success", "failed"}:
            raise ValueError(f"MoMo 状态无效: {status}")
        row["momo_status"] = status
        row["momo_checked_at"] = result.get("checked_at") or _now()
        if status in {"no_momo", "success", "failed"}:
            row["momo_completed_at"] = result.get("completed_at") or _now()
        if result.get("message") is not None:
            row["momo_message"] = str(result.get("message") or "")[:500]
        if status == "failed":
            row["momo_error"] = str(result.get("error") or result.get("message") or "MoMo 提链失败")[:500]
            row["momo_failure_stage"] = str(result.get("stage") or "unknown")[:80]
        else:
            row["momo_error"] = None
            row["momo_failure_stage"] = None
        if status != "success":
            row["momo_url"] = ""
        elif result.get("url") is not None:
            row["momo_url"] = str(result.get("url") or "")

        for result_key, row_key in (
            ("currency", "momo_currency"),
            ("amount", "momo_amount"),
            ("proxy_key", "momo_proxy_key"),
        ):
            if result_key in result:
                row[row_key] = result.get(result_key)
        if "payment_method_types" in result:
            methods = result.get("payment_method_types")
            row["momo_payment_method_types"] = [str(item).lower() for item in methods] if isinstance(methods, list) else []
        row["updated_at"] = _now()
        if status in {"queued", "running"} and not any(
            key in result for key in ("url", "currency", "amount", "payment_method_types", "proxy_key")
        ):
            _save_account_progress_fields(
                accounts, row, previous,
                ("momo_status", "momo_checked_at", "momo_completed_at", "momo_message",
                 "momo_error", "momo_failure_stage", "updated_at"),
            )
        else:
            _save_accounts(accounts)
        return True


def claim_account_paypal(
    acc_id: int,
    *,
    action: str,
    trigger: str = "manual",
    mode: str | None = None,
    requested_mode: str | None = None,
    force: bool = False,
    extract_proxy_pool_ref: str | None = None,
    extract_proxy_pool_version: str | int | None = None,
    payment_proxy_pool_ref: str | None = None,
    payment_proxy_pool_version: str | int | None = None,
) -> str:
    """Atomically claim one PP extraction/payment workflow.

    Returns claimed/missing/busy/success/unavailable/link_required or an
    existing non-repeatable payment status such as waiting_otp/confirmed.
    ``force`` only permits a fresh extraction; it never repeats a payment whose
    outcome may already have been committed.
    """
    selected_action = str(action or "").strip().lower()
    if selected_action not in _PAYPAL_ACTIONS:
        raise ValueError("PayPal action 仅支持 extract / pay / extract_and_pay / reauthorize")

    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return "missing"
        if _paypal_account_is_active(row):
            return "busy"
        previous = dict(row)

        extract_status = str(row.get("paypal_extract_status") or "unchecked").strip().lower()
        if extract_status not in _PAYPAL_EXTRACT_STATUSES:
            extract_status = "unchecked"
        payment_status = str(row.get("paypal_payment_status") or "not_started").strip().lower()
        if payment_status not in _PAYPAL_PAYMENT_STATUSES:
            payment_status = "not_started"

        # A confirmed agreement is never automatically repeated, including
        # force requests. The caller must create an explicit new-account flow.
        if payment_status == "confirmed" and selected_action != "reauthorize":
            return "confirmed"

        # Check non-repeatable payment states before any extraction branch.
        # A fresh BA would no longer match the persisted OTP/authorization
        # context, even when the requested action is extract-only.
        preflight_payment_retry = _paypal_payment_can_restart(
            row, action=selected_action,
        )
        if (
            payment_status in {"waiting_otp", "authorized", "pending", "verification_blocked"}
            and not preflight_payment_retry
        ):
            return payment_status

        _seed_paypal_events(row)
        row["paypal_requested_action"] = selected_action
        row["paypal_trigger"] = str(trigger or "manual")[:80]
        if mode is not None:
            row["paypal_mode"] = str(mode or "none")[:80]
        now = _now()

        needs_extract = selected_action in {"extract", "extract_and_pay"}
        has_link = bool(
            str(row.get("paypal_ba_url") or "").strip()
            or str(row.get("paypal_ba_token") or "").strip()
        )
        if selected_action == "reauthorize":
            if extract_status != "success" or not has_link:
                return "link_required"
            # Explicit reauthorization is the only path allowed to discard a
            # prior authorization context, including a previously confirmed
            # state. Keep the imported BA and zero-offer result intact.
            row["paypal_payment_status"] = "queued"
            row["paypal_payment_message"] = "重新授权已入队"
            row["paypal_payment_error"] = None
            row["paypal_payment_failure_stage"] = None
            row["paypal_payment_failure_code"] = None
            row["paypal_payment_replay_safe"] = False
            row["paypal_payment_reference"] = None
            row["paypal_agreement_id"] = None
            row["paypal_payment_context"] = None
            row["paypal_otp_context"] = None
            _reset_paypal_sms(row)
            row["paypal_payment_queued_at"] = now
            row["paypal_payment_started_at"] = None
            row["paypal_payment_authorized_at"] = None
            row["paypal_payment_verified_at"] = None
            row["paypal_payment_confirmed_at"] = None
            row["paypal_payment_completed_at"] = None
            row["paypal_payment_attempt_count"] = int(row.get("paypal_payment_attempt_count") or 0) + 1
            if payment_proxy_pool_ref is not None:
                row["paypal_payment_proxy_pool_ref"] = str(payment_proxy_pool_ref or "") or None
            if payment_proxy_pool_version is not None:
                row["paypal_payment_proxy_pool_version"] = str(payment_proxy_pool_version)
            _append_paypal_event(
                row,
                phase="payment",
                status="queued",
                message=row["paypal_payment_message"],
                attempt=row.get("paypal_payment_attempt_count"),
                action=selected_action,
                trigger=row.get("paypal_trigger"),
                timestamp=now,
            )
            row["updated_at"] = now
            _save_account_progress_fields(
                accounts, row, previous,
                ("paypal_mode", "paypal_requested_action", "paypal_trigger",
                 "paypal_payment_status", "paypal_payment_queued_at", "paypal_payment_started_at",
                 "paypal_payment_authorized_at", "paypal_payment_verified_at",
                 "paypal_payment_confirmed_at", "paypal_payment_completed_at",
                 "paypal_payment_message", "paypal_payment_error", "paypal_payment_failure_stage",
                 "paypal_payment_failure_code", "paypal_payment_replay_safe",
                 "paypal_payment_attempt_count", "paypal_payment_proxy_pool_ref",
                 "paypal_payment_proxy_pool_version", "paypal_sms_status", "updated_at"),
            )
            return "claimed"
        if needs_extract and has_link and not force and extract_status != "success":
            # A previous worker could persist the BA and then lose its Future,
            # leaving extraction failed while payment remained queued.  The BA
            # credential is authoritative: normalize the state and continue to
            # payment instead of creating a second Checkout.
            extract_status = "success"
            row["paypal_extract_status"] = "success"
            row["paypal_extract_error"] = None
            row["paypal_extract_failure_stage"] = None
            row["paypal_extract_message"] = "已恢复现有 PayPal BA 链"
            row["paypal_extract_completed_at"] = row.get("paypal_extract_completed_at") or now
            _append_paypal_event(
                row,
                phase="extract",
                status="recovered",
                message="检测到现有 BA 链，已跳过重复提链并继续支付",
                action=selected_action,
                trigger=row.get("paypal_trigger"),
                timestamp=now,
            )
        if needs_extract and not (extract_status == "success" and has_link and not force):
            if extract_status == "unavailable" and not force:
                return "unavailable"
            row["paypal_zero_offer_status"] = "unchecked"
            row["paypal_zero_offer_error"] = None
            row["paypal_extract_status"] = "queued"
            row["paypal_extract_requested_mode"] = (
                str(requested_mode)[:80]
                if requested_mode is not None
                else row.get("paypal_extract_requested_mode")
            )
            row["paypal_extract_actual_mode"] = None
            row["paypal_extract_fallback_reason"] = None
            row["paypal_extract_message"] = "PayPal 提链已入队"
            row["paypal_extract_error"] = None
            row["paypal_extract_failure_stage"] = None
            row["paypal_extract_queued_at"] = now
            row["paypal_extract_started_at"] = None
            row["paypal_extract_checked_at"] = None
            row["paypal_extract_completed_at"] = None
            row["paypal_extract_attempt_count"] = int(row.get("paypal_extract_attempt_count") or 0) + 1
            if extract_proxy_pool_ref is not None:
                row["paypal_extract_proxy_pool_ref"] = str(extract_proxy_pool_ref or "") or None
            if extract_proxy_pool_version is not None:
                row["paypal_extract_proxy_pool_version"] = str(extract_proxy_pool_version)
            if selected_action == "extract_and_pay":
                row["paypal_payment_status"] = "not_started"
                row["paypal_payment_message"] = "等待 PayPal 提链完成"
                row["paypal_payment_error"] = None
                row["paypal_payment_failure_stage"] = None
                row["paypal_payment_failure_code"] = None
                row["paypal_payment_replay_safe"] = False
                row["paypal_payment_reference"] = None
                row["paypal_agreement_id"] = None
                row["paypal_payment_context"] = None
                row["paypal_otp_context"] = None
                _reset_paypal_sms(row)
            _append_paypal_event(
                row,
                phase="extract",
                status="queued",
                message=row["paypal_extract_message"],
                attempt=row.get("paypal_extract_attempt_count"),
                action=selected_action,
                trigger=row.get("paypal_trigger"),
                mode=row.get("paypal_extract_requested_mode") or row.get("paypal_mode"),
                timestamp=now,
            )
            row["updated_at"] = now
            _save_account_progress_fields(
                accounts, row, previous,
                ("paypal_mode", "paypal_requested_action", "paypal_trigger",
                 "paypal_zero_offer_status", "paypal_zero_offer_error",
                 "paypal_extract_status", "paypal_extract_requested_mode",
                 "paypal_extract_actual_mode", "paypal_extract_fallback_reason",
                 "paypal_extract_queued_at", "paypal_extract_started_at",
                 "paypal_extract_checked_at", "paypal_extract_completed_at",
                 "paypal_extract_attempt_count", "paypal_extract_message",
                 "paypal_extract_error", "paypal_extract_failure_stage",
                 "paypal_extract_proxy_pool_ref", "paypal_extract_proxy_pool_version",
                 "paypal_payment_status", "paypal_payment_message", "updated_at"),
            )
            return "claimed"

        if selected_action == "extract":
            return "success"
        if extract_status != "success" or not has_link:
            return "link_required"
        row["paypal_payment_status"] = "queued"
        row["paypal_payment_message"] = "PayPal 支付已入队"
        row["paypal_payment_error"] = None
        row["paypal_payment_failure_stage"] = None
        row["paypal_payment_failure_code"] = None
        row["paypal_payment_replay_safe"] = False
        row["paypal_payment_reference"] = None
        row["paypal_agreement_id"] = None
        row["paypal_payment_context"] = None
        row["paypal_otp_context"] = None
        _reset_paypal_sms(row)
        row["paypal_payment_queued_at"] = now
        row["paypal_payment_started_at"] = None
        row["paypal_payment_authorized_at"] = None
        row["paypal_payment_verified_at"] = None
        row["paypal_payment_confirmed_at"] = None
        row["paypal_payment_completed_at"] = None
        row["paypal_payment_attempt_count"] = int(row.get("paypal_payment_attempt_count") or 0) + 1
        if payment_proxy_pool_ref is not None:
            row["paypal_payment_proxy_pool_ref"] = str(payment_proxy_pool_ref or "") or None
        if payment_proxy_pool_version is not None:
            row["paypal_payment_proxy_pool_version"] = str(payment_proxy_pool_version)
        _append_paypal_event(
            row,
            phase="payment",
            status="queued",
            message=row["paypal_payment_message"],
            attempt=row.get("paypal_payment_attempt_count"),
            action=selected_action,
            trigger=row.get("paypal_trigger"),
            timestamp=now,
        )
        row["updated_at"] = now
        _save_account_progress_fields(
            accounts, row, previous,
            ("paypal_mode", "paypal_requested_action", "paypal_trigger",
             "paypal_payment_status", "paypal_payment_queued_at", "paypal_payment_started_at",
             "paypal_payment_authorized_at", "paypal_payment_verified_at",
             "paypal_payment_confirmed_at", "paypal_payment_completed_at",
             "paypal_payment_message", "paypal_payment_error", "paypal_payment_failure_stage",
             "paypal_payment_failure_code", "paypal_payment_replay_safe",
             "paypal_payment_attempt_count", "paypal_payment_proxy_pool_ref",
             "paypal_payment_proxy_pool_version", "paypal_sms_status", "updated_at"),
        )
        return "claimed"


def claim_account_paypal_verification(
    acc_id: int,
    *,
    trigger: str = "manual_verify",
) -> str:
    """Atomically resume verification without authorizing a second payment."""
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return "missing"
        if _paypal_account_is_active(row):
            return "busy"
        previous = dict(row)
        current = str(row.get("paypal_payment_status") or "not_started").strip().lower()
        if current not in {"authorized", "pending", "verification_blocked"}:
            return current if current in _PAYPAL_PAYMENT_STATUSES else "not_started"
        now = _now()
        _seed_paypal_events(row)
        row["paypal_trigger"] = str(trigger or "manual_verify")[:80]
        row["paypal_payment_status"] = "verifying"
        row["paypal_payment_message"] = "正在核验 PayPal 支付结果"
        row["paypal_payment_error"] = None
        row["paypal_payment_failure_stage"] = None
        row["paypal_payment_failure_code"] = None
        row["paypal_payment_replay_safe"] = False
        row["paypal_payment_started_at"] = row.get("paypal_payment_started_at") or now
        _append_paypal_event(
            row,
            phase="verify",
            status="verifying",
            message=row["paypal_payment_message"],
            attempt=row.get("paypal_payment_attempt_count"),
            trigger=row.get("paypal_trigger"),
            timestamp=now,
        )
        row["updated_at"] = now
        _save_account_progress_fields(
            accounts, row, previous,
            ("paypal_trigger", "paypal_payment_status", "paypal_payment_started_at",
             "paypal_payment_message", "paypal_payment_error", "paypal_payment_failure_stage",
             "paypal_payment_failure_code", "paypal_payment_replay_safe", "updated_at"),
        )
        return "claimed"


def claim_account_paypal_otp(acc_id: int) -> bool:
    """Atomically claim a pending PayPal OTP submission.

    The OTP continuation is part of the existing payment attempt, so this does
    not increment ``paypal_payment_attempt_count`` or replace either persisted
    context.  Moving directly to an active state prevents two workers from
    submitting the same code concurrently.
    """
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        current = str(row.get("paypal_payment_status") or "not_started").strip().lower()
        sms_status = str(row.get("paypal_sms_status") or "not_started").strip().lower()
        if current != "waiting_otp" or sms_status == "polling":
            return False
        previous = dict(row)
        now = _now()
        _seed_paypal_events(row)
        row["paypal_payment_status"] = "running"
        row["paypal_payment_message"] = "正在提交 PayPal 短信验证码"
        row["paypal_payment_error"] = None
        row["paypal_payment_failure_stage"] = None
        row["paypal_payment_failure_code"] = None
        row["paypal_payment_replay_safe"] = False
        row["paypal_payment_started_at"] = row.get("paypal_payment_started_at") or now
        if row.get("paypal_sms_context"):
            row["paypal_sms_status"] = "submitted"
        _append_paypal_event(
            row,
            phase="sms",
            status="submitted",
            message=row["paypal_payment_message"],
            attempt=row.get("paypal_payment_attempt_count"),
            timestamp=now,
        )
        row["updated_at"] = now
        _save_account_progress_fields(
            accounts, row, previous,
            ("paypal_payment_status", "paypal_payment_started_at", "paypal_payment_message",
             "paypal_payment_error", "paypal_payment_failure_stage", "paypal_payment_failure_code",
             "paypal_payment_replay_safe", "paypal_sms_status", "updated_at"),
        )
        return True


def claim_account_paypal_sms(acc_id: int) -> bool:
    """Atomically claim polling for a persisted SMS activation."""
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        payment_status = str(row.get("paypal_payment_status") or "not_started").strip().lower()
        sms_status = str(row.get("paypal_sms_status") or "not_started").strip().lower()
        if (
            payment_status != "waiting_otp"
            or sms_status not in {"acquired", "waiting", "timeout", "failed"}
            or not isinstance(row.get("paypal_sms_context"), dict)
        ):
            return False
        previous = dict(row)
        _seed_paypal_events(row)
        row["paypal_sms_status"] = "polling"
        row["paypal_sms_error"] = None
        row["paypal_payment_message"] = "正在自动等待 PayPal 短信验证码"
        now = _now()
        _append_paypal_event(
            row,
            phase="sms",
            status="polling",
            message=row["paypal_payment_message"],
            attempt=row.get("paypal_payment_attempt_count"),
            timestamp=now,
        )
        row["updated_at"] = now
        _save_account_progress_fields(
            accounts, row, previous,
            ("paypal_sms_status", "paypal_sms_error", "paypal_payment_message", "updated_at"),
        )
        return True


def mark_account_paypal_running(
    acc_id: int,
    *,
    stage: str,
    message: str = "",
    proxy_pool_ref: str | None = None,
    proxy_pool_version: str | int | None = None,
    mode: str | None = None,
) -> bool:
    """Move a claimed PP workflow to its active zero-offer/extract/payment stage."""
    selected_stage = str(stage or "").strip().lower()
    if selected_stage not in {"zero_offer", "extract", "payment"}:
        raise ValueError("PayPal stage 仅支持 zero_offer / extract / payment")
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        previous = dict(row)
        now = _now()
        _seed_paypal_events(row)
        if selected_stage in {"zero_offer", "extract"}:
            current = str(row.get("paypal_extract_status") or "unchecked").strip().lower()
            if current not in {"queued", "running"}:
                return False
            row["paypal_zero_offer_status"] = (
                "checking" if selected_stage == "zero_offer"
                else row.get("paypal_zero_offer_status") or "checking"
            )
            row["paypal_extract_status"] = "running"
            row["paypal_extract_started_at"] = row.get("paypal_extract_started_at") or now
            row["paypal_extract_message"] = str(
                message or ("正在检查 0 元优惠" if selected_stage == "zero_offer" else "正在提取 PayPal BA 链")
            )[:500]
            row["paypal_extract_error"] = None
            if proxy_pool_ref is not None:
                row["paypal_extract_proxy_pool_ref"] = str(proxy_pool_ref or "") or None
            if proxy_pool_version is not None:
                row["paypal_extract_proxy_pool_version"] = str(proxy_pool_version)
        else:
            current = str(row.get("paypal_payment_status") or "not_started").strip().lower()
            if current not in {"queued", "running"}:
                return False
            row["paypal_payment_status"] = "running"
            row["paypal_payment_started_at"] = row.get("paypal_payment_started_at") or now
            row["paypal_payment_message"] = str(message or "正在执行 PayPal 支付")[:500]
            row["paypal_payment_error"] = None
            if proxy_pool_ref is not None:
                row["paypal_payment_proxy_pool_ref"] = str(proxy_pool_ref or "") or None
            if proxy_pool_version is not None:
                row["paypal_payment_proxy_pool_version"] = str(proxy_pool_version)
        event_message = (
            row.get("paypal_extract_message")
            if selected_stage in {"zero_offer", "extract"}
            else row.get("paypal_payment_message")
        )
        _append_paypal_event(
            row,
            phase=selected_stage,
            status="checking" if selected_stage == "zero_offer" else "running",
            message=str(event_message or ""),
            attempt=(
                row.get("paypal_extract_attempt_count")
                if selected_stage in {"zero_offer", "extract"}
                else row.get("paypal_payment_attempt_count")
            ),
            mode=mode,
            timestamp=now,
        )
        row["updated_at"] = now
        if selected_stage in {"zero_offer", "extract"}:
            progress_fields = (
                "paypal_zero_offer_status", "paypal_extract_status", "paypal_extract_started_at",
                "paypal_extract_message", "paypal_extract_error", "paypal_extract_requested_mode",
                "paypal_extract_actual_mode", "paypal_extract_fallback_reason", "updated_at",
            )
        else:
            progress_fields = (
                "paypal_payment_status", "paypal_payment_started_at", "paypal_payment_message",
                "paypal_payment_error", "paypal_payment_failure_stage", "updated_at",
            )
        _save_account_progress_fields(accounts, row, previous, progress_fields)
        return True


def update_account_paypal_zero_offer(acc_id: int, result: dict | None = None) -> bool:
    result = dict(result or {})
    status = str(result.get("status") or "failed").strip().lower()
    if status not in _PAYPAL_ZERO_OFFER_STATUSES:
        raise ValueError(f"PayPal 0 元优惠状态无效: {status}")
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        previous = dict(row)
        _seed_paypal_events(row)
        row["paypal_zero_offer_status"] = status
        if "campaign" in result or "campaign_id" in result:
            row["paypal_zero_offer_campaign"] = result.get("campaign", result.get("campaign_id"))
        for result_key, row_key in (
            ("amount", "paypal_zero_offer_amount"),
            ("currency", "paypal_zero_offer_currency"),
        ):
            if result_key in result:
                row[row_key] = result.get(result_key)
        if status != "checking":
            row["paypal_zero_offer_checked_at"] = result.get("checked_at") or _now()
        if status in {"retryable_error", "failed"}:
            row["paypal_zero_offer_error"] = str(
                result.get("error") or result.get("message") or "0 元优惠检测失败"
            )[:500]
        else:
            row["paypal_zero_offer_error"] = None
        now = _now()
        zero_messages = {
            "checking": "正在检查 0 元优惠",
            "eligible": "已确认账号存在 0 元优惠",
            "not_eligible": "当前账号没有可用的 0 元优惠",
            "retryable_error": "0 元优惠检测临时失败，可重试",
            "failed": "0 元优惠检测失败",
            "unchecked": "0 元优惠状态已重置",
        }
        _append_paypal_event(
            row,
            phase="zero_offer",
            status=status,
            message=str(
                result.get("error") or result.get("message") or zero_messages.get(status) or status
            ),
            attempt=row.get("paypal_extract_attempt_count"),
            failure_stage=result.get("stage") if status in {"retryable_error", "failed"} else None,
            timestamp=now,
        )
        row["updated_at"] = now
        if status == "checking" and not any(
            key in result for key in ("campaign", "campaign_id", "amount", "currency")
        ):
            _save_account_progress_fields(
                accounts, row, previous,
                ("paypal_zero_offer_status", "paypal_zero_offer_checked_at",
                 "paypal_zero_offer_error", "updated_at"),
            )
        else:
            _save_accounts(accounts)
        return True


def update_account_paypal_extract(acc_id: int, result: dict | None = None) -> bool:
    result = dict(result or {})
    status = str(result.get("status") or "failed").strip().lower()
    if status not in _PAYPAL_EXTRACT_STATUSES:
        raise ValueError(f"PayPal 提链状态无效: {status}")
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        previous = dict(row)
        _seed_paypal_events(row)
        next_url = result.get("ba_url") if "ba_url" in result else row.get("paypal_ba_url")
        next_token = result.get("ba_token") if "ba_token" in result else row.get("paypal_ba_token")
        if status == "success" and not (
            str(next_url or "").strip() or str(next_token or "").strip()
        ):
            raise ValueError("PayPal 提链成功状态必须包含 ba_url 或 ba_token")

        now = _now()
        row["paypal_extract_status"] = status
        if status == "queued":
            row["paypal_extract_queued_at"] = row.get("paypal_extract_queued_at") or now
        if status == "running":
            row["paypal_extract_started_at"] = row.get("paypal_extract_started_at") or now
        if status in {"success", "unavailable", "failed"}:
            row["paypal_extract_checked_at"] = result.get("checked_at") or now
            row["paypal_extract_completed_at"] = result.get("completed_at") or now
        if result.get("message") is not None:
            row["paypal_extract_message"] = str(result.get("message") or "")[:500]
        if result.get("requested_mode") is not None:
            row["paypal_extract_requested_mode"] = str(result.get("requested_mode") or "")[:80] or None
        if result.get("actual_mode") is not None:
            row["paypal_extract_actual_mode"] = str(result.get("actual_mode") or "")[:80] or None
        if "fallback_reason" in result:
            row["paypal_extract_fallback_reason"] = str(result.get("fallback_reason") or "")[:500] or None
        if "ba_url" in result:
            row["paypal_ba_url"] = str(result.get("ba_url") or "")
        if "ba_token" in result:
            row["paypal_ba_token"] = str(result.get("ba_token") or "")
        if "proxy_pool_ref" in result:
            row["paypal_extract_proxy_pool_ref"] = str(result.get("proxy_pool_ref") or "") or None
        if "proxy_pool_version" in result:
            value = result.get("proxy_pool_version")
            row["paypal_extract_proxy_pool_version"] = str(value) if value is not None else None

        if status == "failed":
            row["paypal_extract_error"] = str(
                result.get("error") or result.get("message") or "PayPal 提链失败"
            )[:500]
            row["paypal_extract_failure_stage"] = str(result.get("stage") or "unknown")[:80]
        else:
            row["paypal_extract_error"] = None
            row["paypal_extract_failure_stage"] = None
        if status == "unavailable":
            row["paypal_ba_url"] = ""
            row["paypal_ba_token"] = ""
            row["paypal_payment_status"] = "not_started"
            row["paypal_payment_context"] = None
            row["paypal_otp_context"] = None
        extract_messages = {
            "queued": "PayPal 提链已入队",
            "running": "正在提取 PayPal BA 链",
            "success": "PayPal BA 链提取成功",
            "unavailable": "本次 Checkout 未取得 PayPal BA 链",
            "failed": "PayPal 提链失败",
            "unchecked": "PayPal 提链状态未检查",
        }
        _append_paypal_event(
            row,
            phase="extract",
            status=status,
            message=str(
                result.get("error") or result.get("message") or extract_messages.get(status) or status
            ),
            attempt=row.get("paypal_extract_attempt_count"),
            failure_stage=result.get("stage") if status in {"failed", "unavailable"} else None,
            mode=result.get("actual_mode") or result.get("requested_mode"),
            timestamp=now,
        )
        row["updated_at"] = now
        if status in {"queued", "running"} and not any(
            key in result for key in ("ba_url", "ba_token", "proxy_pool_ref", "proxy_pool_version")
        ):
            _save_account_progress_fields(
                accounts, row, previous,
                ("paypal_extract_status", "paypal_extract_queued_at", "paypal_extract_started_at",
                 "paypal_extract_checked_at", "paypal_extract_completed_at", "paypal_extract_error",
                 "paypal_extract_failure_stage", "paypal_extract_message", "updated_at"),
            )
        else:
            _save_accounts(accounts)
        return True


def import_paypal_ba_records(records: list[dict]) -> dict:
    """Persist manually supplied BA credentials without starting a workflow.

    The caller validates the PayPal URL/token before reaching this function.
    Existing payment context is cleared because it belongs to a different BA
    chain; zero-offer eligibility is intentionally preserved.
    """
    if not isinstance(records, list):
        raise ValueError("records 必须是数组")
    if len(records) > 5000:
        raise ValueError("单次最多导入 5000 条 BA 链")
    result = {"imported": [], "skipped": [], "busy": [], "missing": []}
    changed = False
    with _LOCK:
        accounts = _load_accounts()
        seen_ids: set[int] = set()
        now = _now()
        for raw in records:
            email = str((raw or {}).get("email") or "").strip()
            ba_url = str((raw or {}).get("ba_url") or "").strip()
            ba_token = str((raw or {}).get("ba_token") or "").strip()
            row = _find_by_email(accounts, email)
            if row is None:
                result["missing"].append({"email": email, "reason": "账号不存在"})
                continue
            acc_id = int(row.get("id") or 0)
            if acc_id in seen_ids:
                result["skipped"].append({"email": email, "reason": "重复邮箱，已取第一条"})
                continue
            seen_ids.add(acc_id)
            if _paypal_account_is_active(row):
                result["busy"].append({"id": acc_id, "email": email, "reason": "账号有正在执行的 PayPal 任务"})
                continue
            if str(row.get("paypal_payment_status") or "").strip().lower() == "confirmed":
                result["skipped"].append({"id": acc_id, "email": email, "reason": "账号已确认 Plus，未覆盖现有状态"})
                continue
            if (
                str(row.get("paypal_ba_url") or "").strip() == ba_url
                and str(row.get("paypal_ba_token") or "").strip() == ba_token
                and str(row.get("paypal_extract_status") or "").strip().lower() == "success"
            ):
                result["skipped"].append({"id": acc_id, "email": email, "reason": "BA 链已存在"})
                continue

            _seed_paypal_events(row)
            row.update({
                "paypal_mode": "manual",
                "paypal_requested_action": None,
                "paypal_trigger": "manual_import",
                "paypal_extract_status": "success",
                "paypal_extract_requested_mode": "manual",
                "paypal_extract_actual_mode": "manual",
                "paypal_extract_fallback_reason": None,
                "paypal_extract_message": "已手动导入 PayPal BA 链，等待授权",
                "paypal_extract_error": None,
                "paypal_extract_failure_stage": None,
                "paypal_extract_checked_at": now,
                "paypal_extract_completed_at": now,
                "paypal_ba_url": ba_url,
                "paypal_ba_token": ba_token,
                "paypal_payment_status": "not_started",
                "paypal_payment_message": "已导入 BA 链，等待手动授权",
                "paypal_payment_error": None,
                "paypal_payment_failure_stage": None,
                "paypal_payment_failure_code": None,
                "paypal_payment_replay_safe": False,
                "paypal_payment_reference": None,
                "paypal_agreement_id": None,
                "paypal_payment_queued_at": None,
                "paypal_payment_started_at": None,
                "paypal_payment_authorized_at": None,
                "paypal_payment_verified_at": None,
                "paypal_payment_confirmed_at": None,
                "paypal_payment_completed_at": None,
                "paypal_payment_attempt_count": 0,
                "paypal_payment_context": None,
                "paypal_otp_context": None,
            })
            _reset_paypal_sms(row)
            _append_paypal_event(
                row,
                phase="extract",
                status="success",
                message="已手动导入 PayPal BA 链，未启动提链或支付",
                action="manual_import",
                trigger="manual_import",
                mode="manual",
                stage="manual_import",
                timestamp=now,
            )
            row["updated_at"] = now
            result["imported"].append({"id": acc_id, "email": email})
            changed = True
        if changed:
            _save_accounts(accounts)
    result["imported_count"] = len(result["imported"])
    result["skipped_count"] = len(result["skipped"])
    result["busy_count"] = len(result["busy"])
    result["missing_count"] = len(result["missing"])
    return result


def update_account_paypal_payment(acc_id: int, result: dict | None = None) -> bool:
    result = dict(result or {})
    status = str(result.get("status") or "failed").strip().lower()
    if status not in _PAYPAL_PAYMENT_STATUSES:
        raise ValueError(f"PayPal 支付状态无效: {status}")
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        previous = dict(row)
        _seed_paypal_events(row)
        now = _now()
        row["paypal_payment_status"] = status
        if status == "queued":
            row["paypal_payment_queued_at"] = row.get("paypal_payment_queued_at") or now
        if status in {"running", "verifying"}:
            row["paypal_payment_started_at"] = row.get("paypal_payment_started_at") or now
        if status == "authorized":
            row["paypal_payment_authorized_at"] = result.get("authorized_at") or now
        if status in {"pending", "verification_blocked", "confirmed"}:
            row["paypal_payment_verified_at"] = result.get("verified_at") or now
        if status == "confirmed":
            row["paypal_payment_confirmed_at"] = result.get("confirmed_at") or now
        if status in {"confirmed", "verification_blocked", "failed"}:
            row["paypal_payment_completed_at"] = result.get("completed_at") or now
        if result.get("message") is not None:
            row["paypal_payment_message"] = str(result.get("message") or "")[:500]
        if "reference" in result:
            row["paypal_payment_reference"] = str(result.get("reference") or "")[:300] or None
        if "agreement_id" in result:
            row["paypal_agreement_id"] = str(result.get("agreement_id") or "")[:300] or None
        if "payment_context" in result:
            value = result.get("payment_context")
            row["paypal_payment_context"] = json.loads(json.dumps(value, ensure_ascii=False)) if value is not None else None
        if "otp_context" in result:
            value = result.get("otp_context")
            row["paypal_otp_context"] = json.loads(json.dumps(value, ensure_ascii=False)) if value is not None else None
        if "proxy_pool_ref" in result:
            row["paypal_payment_proxy_pool_ref"] = str(result.get("proxy_pool_ref") or "") or None
        if "proxy_pool_version" in result:
            value = result.get("proxy_pool_version")
            row["paypal_payment_proxy_pool_version"] = str(value) if value is not None else None

        if status in {"failed", "verification_blocked"}:
            row["paypal_payment_error"] = str(
                result.get("error") or result.get("message") or "PayPal 支付失败"
            )[:500]
            row["paypal_payment_failure_stage"] = str(result.get("stage") or "unknown")[:80]
            row["paypal_payment_failure_code"] = str(
                result.get("code") or result.get("failure_code") or ""
            )[:80] or None
            row["paypal_payment_replay_safe"] = bool(result.get("replay_safe", False))
        else:
            row["paypal_payment_error"] = None
            row["paypal_payment_failure_stage"] = None
            row["paypal_payment_failure_code"] = None
            row["paypal_payment_replay_safe"] = False
        payment_messages = {
            "not_started": "PayPal 授权尚未开始",
            "queued": "PayPal 授权已入队",
            "running": "正在执行 PayPal 授权",
            "waiting_otp": "PayPal 授权等待短信验证码",
            "authorized": "PayPal 协议已授权，等待套餐核验",
            "verifying": "正在核验 PayPal 授权结果",
            "confirmed": "PayPal 授权成功且 Plus 已确认",
            "pending": "PayPal 已授权，Plus 状态仍待确认",
            "verification_blocked": "PayPal 授权结果暂时无法核验",
            "failed": "PayPal 授权失败",
        }
        event_phase = "verify" if status in {
            "verifying", "confirmed", "pending", "verification_blocked"
        } else "payment"
        _append_paypal_event(
            row,
            phase=event_phase,
            status=status,
            message=str(
                result.get("error") or result.get("message") or payment_messages.get(status) or status
            ),
            attempt=row.get("paypal_payment_attempt_count"),
            failure_stage=result.get("stage") if status in {"failed", "verification_blocked"} else None,
            timestamp=now,
        )
        row["updated_at"] = now
        transient = status in {"queued", "running", "verifying"} and not any(
            key in result for key in ("payment_context", "otp_context", "reference", "agreement_id",
                                      "proxy_pool_ref", "proxy_pool_version")
        )
        if transient:
            _save_account_progress_fields(
                accounts, row, previous,
                ("paypal_payment_status", "paypal_payment_queued_at", "paypal_payment_started_at",
                 "paypal_payment_authorized_at", "paypal_payment_verified_at",
                 "paypal_payment_completed_at", "paypal_payment_message", "paypal_payment_error",
                 "paypal_payment_failure_stage", "paypal_payment_failure_code",
                 "paypal_payment_replay_safe", "updated_at"),
            )
        else:
            _save_accounts(accounts)
        return True


def checkpoint_account_paypal_payment_context(
    acc_id: int,
    payment_context: dict,
) -> bool:
    """Persist a private payment resume checkpoint without appending a UI event."""
    if not isinstance(payment_context, dict):
        raise ValueError("PayPal payment_context 必须是对象")
    serialized = json.dumps(payment_context, ensure_ascii=False, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > 128 * 1024:
        raise ValueError("PayPal payment_context 过大")
    copied = json.loads(serialized)
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        status = str(row.get("paypal_payment_status") or "not_started").strip().lower()
        if status not in {"queued", "running", "waiting_otp", "verifying"}:
            return False
        row["paypal_payment_context"] = copied
        row["updated_at"] = _now()
        _save_accounts(accounts)
        return True


def list_resumable_remote_paypal_account_ids() -> list[int]:
    """Return account IDs whose private remote job context can be queried again."""
    with _LOCK:
        rows = _load_accounts()
        result: list[int] = []
        for row in rows:
            status = str(row.get("paypal_payment_status") or "not_started").strip().lower()
            if status not in {"queued", "running", "waiting_otp", "verifying"}:
                continue
            contexts = (row.get("paypal_payment_context"), row.get("paypal_otp_context"))
            remote = next((
                value for value in contexts
                if isinstance(value, dict)
                and str(value.get("executor") or "").strip().lower() == "remote"
                and str(value.get("job_id") or "").strip()
                and str(value.get("device_cookie") or "").strip()
            ), None)
            if remote is None:
                continue
            if status == "waiting_otp" and not isinstance(row.get("paypal_sms_context"), dict):
                continue
            try:
                result.append(int(row.get("id")))
            except (TypeError, ValueError):
                continue
        return result


def update_account_paypal_sms(acc_id: int, result: dict | None = None) -> bool:
    """Persist a PayPal SMS activation without exposing its number or request ID."""
    result = dict(result or {})
    status = str(result.get("status") or "failed").strip().lower()
    if status not in _PAYPAL_SMS_STATUSES:
        raise ValueError(f"PayPal 接码状态无效: {status}")
    with _LOCK:
        accounts = _load_accounts()
        row = next((r for r in accounts if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        previous = dict(row)
        _seed_paypal_events(row)
        now = _now()
        row["paypal_sms_status"] = status
        fields = (
            ("channel", "paypal_sms_channel", 80),
            ("provider", "paypal_sms_provider", 100),
            ("service_id", "paypal_sms_service_id", 120),
            ("request_id", "paypal_sms_request_id", 160),
            ("country", "paypal_sms_country", 80),
            ("phone_masked", "paypal_sms_phone_masked", 40),
        )
        for source, target, limit in fields:
            if source in result:
                row[target] = str(result.get(source) or "")[:limit] or None
        if "cost" in result:
            try:
                row["paypal_sms_cost"] = float(result.get("cost"))
            except (TypeError, ValueError):
                row["paypal_sms_cost"] = None
        if "context" in result:
            value = result.get("context")
            row["paypal_sms_context"] = (
                json.loads(json.dumps(value, ensure_ascii=False)) if value is not None else None
            )
        if status in {"acquired", "polling", "waiting", "code_received", "submitted"}:
            row["paypal_sms_acquired_at"] = (
                result.get("acquired_at") or row.get("paypal_sms_acquired_at") or now
            )
        if status in {"consumed", "rejected"}:
            row["paypal_sms_completed_at"] = result.get("completed_at") or now
        if status in {"timeout", "failed", "ambiguous"}:
            row["paypal_sms_error"] = str(
                result.get("error") or result.get("message") or "PayPal 接码失败"
            )[:500]
        else:
            row["paypal_sms_error"] = None
        sms_messages = {
            "not_started": "PayPal 接码尚未开始",
            "acquiring": "正在申请 PayPal 接码号码",
            "acquired": "PayPal 接码号码已取得",
            "polling": "正在等待 PayPal 短信验证码",
            "waiting": "PayPal 短信验证码尚未到达",
            "code_received": "已收到 PayPal 短信验证码",
            "submitted": "PayPal 短信验证码已提交",
            "consumed": "PayPal 接码已完成",
            "timeout": "等待 PayPal 短信验证码超时",
            "rejected": "PayPal 接码号码已拒绝",
            "failed": "PayPal 接码失败",
            "ambiguous": "PayPal 接码状态不确定",
        }
        _append_paypal_event(
            row,
            phase="sms",
            status=status,
            message=str(
                result.get("error") or result.get("message") or sms_messages.get(status) or status
            ),
            attempt=row.get("paypal_payment_attempt_count"),
            failure_stage=result.get("stage") if status in {"timeout", "failed", "ambiguous"} else None,
            timestamp=now,
        )
        row["updated_at"] = now
        transient = status in {"acquiring", "polling", "waiting", "code_received", "submitted"} \
            and "context" not in result
        if transient:
            _save_account_progress_fields(
                accounts, row, previous,
                ("paypal_sms_status", "paypal_sms_checked_at", "paypal_sms_error",
                 "paypal_sms_message", "paypal_sms_failure_stage", "paypal_sms_attempt_count",
                 "updated_at"),
            )
        else:
            _save_accounts(accounts)
        return True


def update_account_paypal(
    acc_id: int,
    *,
    stage: str,
    result: dict | None = None,
) -> bool:
    """Dispatch a PP state update while keeping stage-specific validation."""
    selected_stage = str(stage or "").strip().lower()
    if selected_stage == "zero_offer":
        return update_account_paypal_zero_offer(acc_id, result)
    if selected_stage == "extract":
        return update_account_paypal_extract(acc_id, result)
    if selected_stage == "payment":
        return update_account_paypal_payment(acc_id, result)
    raise ValueError("PayPal stage 仅支持 zero_offer / extract / payment")


def reset_account_paypal(acc_id: int) -> str:
    """Discard a completed/stalled PP workflow so it can start from extraction.

    Active database states are rejected because an in-flight worker could write
    its old result back after the reset. Waiting OTP and other terminal or
    blocked states are intentionally resettable through this explicit action.
    """
    with _LOCK:
        accounts = _load_accounts()
        row = next((item for item in accounts if int(item.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return "missing"
        if _paypal_account_is_active(row):
            return "busy"

        row.update({
            "paypal_mode": "none",
            "paypal_requested_action": None,
            "paypal_trigger": None,
            "paypal_zero_offer_status": "unchecked",
            "paypal_zero_offer_campaign": None,
            "paypal_zero_offer_amount": None,
            "paypal_zero_offer_currency": None,
            "paypal_zero_offer_checked_at": None,
            "paypal_zero_offer_error": None,
            "paypal_extract_status": "unchecked",
            "paypal_extract_requested_mode": None,
            "paypal_extract_actual_mode": None,
            "paypal_extract_fallback_reason": None,
            "paypal_extract_message": "",
            "paypal_extract_error": None,
            "paypal_extract_failure_stage": None,
            "paypal_extract_queued_at": None,
            "paypal_extract_started_at": None,
            "paypal_extract_checked_at": None,
            "paypal_extract_completed_at": None,
            "paypal_extract_attempt_count": 0,
            "paypal_ba_url": "",
            "paypal_ba_token": "",
            "paypal_payment_status": "not_started",
            "paypal_payment_message": "",
            "paypal_payment_error": None,
            "paypal_payment_failure_stage": None,
            "paypal_payment_failure_code": None,
            "paypal_payment_replay_safe": False,
            "paypal_payment_reference": None,
            "paypal_agreement_id": None,
            "paypal_payment_queued_at": None,
            "paypal_payment_started_at": None,
            "paypal_payment_authorized_at": None,
            "paypal_payment_verified_at": None,
            "paypal_payment_confirmed_at": None,
            "paypal_payment_completed_at": None,
            "paypal_payment_attempt_count": 0,
            "paypal_payment_context": None,
            "paypal_otp_context": None,
            "paypal_extract_proxy_pool_ref": None,
            "paypal_extract_proxy_pool_version": None,
            "paypal_payment_proxy_pool_ref": None,
            "paypal_payment_proxy_pool_version": None,
        })
        _reset_paypal_sms(row)
        row["paypal_events"] = []
        now = _now()
        _append_paypal_event(
            row,
            phase="system",
            status="reset",
            message="PayPal 历史任务状态已重置，准备重新提链并支付",
            action="extract_and_pay",
            trigger="manual_reset",
            timestamp=now,
        )
        row["updated_at"] = now
        _save_accounts(accounts)
        return "reset"


def recover_interrupted_paypal() -> int:
    """Recover PP workers without blindly repeating an ambiguous payment."""
    with _LOCK:
        accounts = _load_accounts()
        recovered = 0
        now = _now()
        for row in accounts:
            changed = False
            extract_status = str(row.get("paypal_extract_status") or "unchecked").strip().lower()
            zero_status = str(row.get("paypal_zero_offer_status") or "unchecked").strip().lower()
            payment_status = str(row.get("paypal_payment_status") or "not_started").strip().lower()
            sms_status = str(row.get("paypal_sms_status") or "not_started").strip().lower()
            remote_context = next((
                value for value in (
                    row.get("paypal_payment_context"), row.get("paypal_otp_context"),
                )
                if isinstance(value, dict)
                and str(value.get("executor") or "").strip().lower() == "remote"
                and str(value.get("job_id") or "").strip()
                and str(value.get("device_cookie") or "").strip()
            ), None)
            if (
                extract_status in _PAYPAL_EXTRACT_ACTIVE_STATUSES
                or zero_status == "checking"
                or payment_status in _PAYPAL_PAYMENT_ACTIVE_STATUSES
                or sms_status in {"acquiring", "polling", "submitted"}
            ):
                _seed_paypal_events(row)
            if extract_status in _PAYPAL_EXTRACT_ACTIVE_STATUSES:
                row["paypal_extract_status"] = "failed"
                row["paypal_extract_error"] = "服务重启导致 PayPal 提链中断，请重新提链"
                row["paypal_extract_failure_stage"] = "restart"
                row["paypal_extract_completed_at"] = now
                _append_paypal_event(
                    row, phase="extract", status="failed",
                    message=row["paypal_extract_error"],
                    attempt=row.get("paypal_extract_attempt_count"),
                    failure_stage="restart", timestamp=now,
                )
                changed = True
            if zero_status == "checking":
                row["paypal_zero_offer_status"] = "retryable_error"
                row["paypal_zero_offer_error"] = "服务重启导致 0 元优惠检测中断"
                row["paypal_zero_offer_checked_at"] = now
                _append_paypal_event(
                    row, phase="zero_offer", status="retryable_error",
                    message=row["paypal_zero_offer_error"],
                    attempt=row.get("paypal_extract_attempt_count"),
                    failure_stage="restart", timestamp=now,
                )
                changed = True
            if payment_status in {"queued", "running", "verifying"} and remote_context is not None:
                row["paypal_payment_status"] = "running"
                row["paypal_payment_message"] = "正在恢复远程 PayPal 任务查询"
                row["paypal_payment_error"] = None
                row["paypal_payment_failure_stage"] = None
                row["paypal_payment_failure_code"] = None
                row["paypal_payment_replay_safe"] = False
                _append_paypal_event(
                    row, phase="payment", status="recovering",
                    message="已找到远程任务与设备 Cookie，准备从原任务续查",
                    attempt=row.get("paypal_payment_attempt_count"),
                    failure_stage="restart_resume", timestamp=now,
                )
                changed = True
            elif payment_status == "queued":
                row["paypal_payment_status"] = "failed"
                row["paypal_payment_error"] = "服务重启导致排队中的 PayPal 支付中断，请重新提交"
                row["paypal_payment_failure_stage"] = "restart_before_run"
                row["paypal_payment_failure_code"] = "RESTART_BEFORE_RUN"
                row["paypal_payment_replay_safe"] = True
                row["paypal_payment_completed_at"] = now
                _append_paypal_event(
                    row, phase="payment", status="failed",
                    message=row["paypal_payment_error"],
                    attempt=row.get("paypal_payment_attempt_count"),
                    failure_stage="restart_before_run", timestamp=now,
                )
                changed = True
            elif payment_status in {"running", "verifying"}:
                row["paypal_payment_status"] = "verification_blocked"
                row["paypal_payment_error"] = "服务重启时支付结果不确定，必须先核验，禁止直接重付"
                row["paypal_payment_failure_stage"] = "restart_ambiguous"
                row["paypal_payment_failure_code"] = "RESTART_AMBIGUOUS"
                row["paypal_payment_replay_safe"] = False
                row["paypal_payment_verified_at"] = now
                row["paypal_payment_completed_at"] = now
                _append_paypal_event(
                    row, phase="verify", status="verification_blocked",
                    message=row["paypal_payment_error"],
                    attempt=row.get("paypal_payment_attempt_count"),
                    failure_stage="restart_ambiguous", timestamp=now,
                )
                changed = True
            if sms_status in {"acquiring", "polling", "submitted"}:
                if str(row.get("paypal_payment_status") or "") == "waiting_otp":
                    row["paypal_sms_status"] = "timeout"
                    row["paypal_sms_error"] = "服务重启中断自动等码，可继续自动接码"
                elif remote_context is not None:
                    row["paypal_sms_status"] = "waiting"
                    row["paypal_sms_error"] = None
                else:
                    row["paypal_sms_status"] = "ambiguous"
                    row["paypal_sms_error"] = "服务重启时接码/支付阶段不确定"
                _append_paypal_event(
                    row, phase="sms", status=row["paypal_sms_status"],
                    message=(
                        row["paypal_sms_error"]
                        or "服务重启后将继续跟踪远程 PayPal 任务与接码状态"
                    ),
                    attempt=row.get("paypal_payment_attempt_count"),
                    failure_stage="restart", timestamp=now,
                )
                changed = True
            if changed:
                row["updated_at"] = now
                recovered += 1
        if recovered:
            _save_accounts(accounts)
        return recovered


def recover_interrupted_extract_links() -> int:
    """服务启动时恢复上次进程中断的提链状态。"""
    with _LOCK:
        accounts = _load_accounts()
        recovered = 0
        now = _now()
        for row in accounts:
            if row.get("extract_link_status") not in {"queued", "running"}:
                continue
            row["extract_link_status"] = "failed"
            row["extract_link_ok"] = False
            row["extract_link_error"] = "WebUI 重启导致提链任务中断，请重新提链"
            row["extract_link_completed_at"] = now
            row["updated_at"] = now
            recovered += 1
        if recovered:
            _save_accounts(accounts)
        return recovered


def recover_interrupted_momo() -> int:
    """服务启动时把未完成的本地 MoMo 任务恢复为可人工重试的失败状态。"""
    with _LOCK:
        accounts = _load_accounts()
        recovered = 0
        now = _now()
        for row in accounts:
            if str(row.get("momo_status") or "") not in {"queued", "running"}:
                continue
            row["momo_status"] = "failed"
            row["momo_error"] = "WebUI 重启导致 MoMo 提链中断，请重新提链"
            row["momo_message"] = row["momo_error"]
            row["momo_completed_at"] = now
            row["updated_at"] = now
            recovered += 1
        if recovered:
            _save_accounts(accounts)
        return recovered


def list_account_plan_check_statuses(limit: int = 5000, archived: str | bool | None = False, plan_filter: str | None = None) -> dict:
    """返回不含 Token/邮箱密码的套餐查询轻量状态快照。"""
    fields = (
        "id", "email", "updated_at", "archived", "archived_at", "plan_type", "current_plan_type",
        "plan_check_status", "plan_check_trigger", "plan_check_queued_at",
        "plan_check_started_at", "plan_check_completed_at", "plan_check_ok",
        "plan_check_error", "plan_checked_at", "plan_last_success_at",
        "plus_trial_eligible", "plan_check_network_route",
        "plus_trial_campaign_id", "plus_trial_title",
        "plus_trial_discount_percentage", "plus_trial_duration_num_periods",
        "plus_trial_duration_period", "promo_coupon", "promo_state",
        "plus_trial_status", "plus_trial_actionable",
        "promo_redeemed", "promo_redeemed_at", "promo_redeemed_by_user",
        "promo_redeemed_by_workspace", "promo_expires_at",
        "promo_promotion_length_days", "promo_check_ok",
        "promo_check_http_status", "promo_check_error", "promo_checked_at",
        "promo_response_bytes", "promo_retry_after", "promo_retryable",
        "billing_page_config_ok", "billing_page_config_http_status", "billing_page_config_error",
        "billing_account_eligible", "billing_plan_management_eligible",
        "billing_free_workspace_upgrade_eligible",
        "app_store_billing_retry_check_ok", "app_store_billing_retry_http_status",
        "app_store_billing_retry_error", "app_store_subscription_in_billing_retry",
        "health_status", "health_alive", "health_checked_at", "health_queued_at",
        "health_started_at", "health_completed_at", "health_http_status",
        "health_error", "health_reason", "health_message", "health_trigger",
        "health_network_route", "health_proxy_mode", "health_proxy_used",
        "health_proxy_fallback_reason", "health_token_expires_at", "health_token_refresh_error",
        "health_last_alive_at", "health_last_dead_at", "health_last_token_invalid_at",
        "health_attempt_count",
        "team_status", "team_invite_status", "team_invite_message", "team_invite_error",
        "team_invite_error_code", "team_invite_checked_at", "team_invite_completed_at",
        "team_invite_last_attempt_status", "team_invite_retryable", "team_invite_attempt_count",
        "team_invite_recipient_verified",
        "team_workspace_id", "team_workspace_name", "team_session_refreshed", "team_cookie_count",
        "extract_link_status", "extract_link_ok", "extract_link_type",
        "extract_link_job_id", "extract_link_message", "extract_link_error",
        "extract_link_long_url", "extract_link_copy_paste",
        "extract_link_image_url_png", "extract_link_image_url_svg",
        "extract_link_expires_at", "extract_link_payment_method",
        "extract_link_payment_link_type",
        "extract_link_checked_at", "extract_link_completed_at",
        "momo_status", "momo_url", "momo_message", "momo_error", "momo_trigger",
        "momo_checked_at", "momo_queued_at", "momo_started_at", "momo_completed_at",
        "momo_currency", "momo_amount", "momo_payment_method_types",
        "momo_proxy_key", "momo_failure_stage", "momo_attempt_count", "momo_force",
        "paypal_mode", "paypal_requested_action", "paypal_trigger",
        "paypal_zero_offer_status", "paypal_zero_offer_campaign",
        "paypal_zero_offer_amount", "paypal_zero_offer_currency",
        "paypal_zero_offer_checked_at", "paypal_zero_offer_error",
        "paypal_extract_status", "paypal_extract_requested_mode", "paypal_extract_actual_mode",
        "paypal_extract_fallback_reason", "paypal_extract_message", "paypal_extract_error",
        "paypal_extract_failure_stage", "paypal_extract_queued_at", "paypal_extract_started_at",
        "paypal_extract_checked_at", "paypal_extract_completed_at", "paypal_extract_attempt_count",
        "has_paypal_ba_url", "has_paypal_ba_token",
        "paypal_payment_status", "paypal_payment_message", "paypal_payment_error",
        "paypal_payment_failure_stage", "paypal_payment_failure_code",
        "paypal_payment_replay_safe", "paypal_payment_reference", "paypal_agreement_id",
        "paypal_payment_queued_at", "paypal_payment_started_at", "paypal_payment_authorized_at",
        "paypal_payment_verified_at", "paypal_payment_confirmed_at", "paypal_payment_completed_at",
        "paypal_payment_attempt_count", "has_paypal_payment_context", "has_paypal_otp_context",
        "paypal_extract_proxy_pool_ref", "paypal_extract_proxy_pool_version",
        "paypal_payment_proxy_pool_ref", "paypal_payment_proxy_pool_version",
        "codex_agent_status", "codex_agent_ok", "codex_agent_message",
        "codex_agent_error", "codex_agent_runtime_id", "has_codex_agent_token",
        "codex_agent_checked_at", "codex_agent_completed_at",
        "codex_agent_network_route", "codex_agent_proxy_mode", "codex_agent_proxy_used",
        "codex_agent_proxy_fallback_reason", "codex_agent_device_id", "codex_agent_oai_session_id",
        "codex_agent_attempt_count", "codex_agent_max_attempts", "codex_agent_request_timeout",
        "codex_agent_sub2api_path", "codex_agent_sub2api_url", "codex_agent_sub2api_mode", "codex_agent_sub2api_total",
    )
    with _LOCK:
        all_rows = _load_accounts()
        if archived in (True, "1", "true", "yes", "only"):
            all_rows = [r for r in all_rows if bool(r.get("archived"))]
        elif archived in ("all", "include"):
            pass
        else:
            all_rows = [r for r in all_rows if not bool(r.get("archived"))]
        decorated_rows = [_decorate_account(r) for r in all_rows]
        decorated_rows = [r for r in decorated_rows if _account_matches_plan_filter(r, plan_filter)]
        rows = sorted(decorated_rows, key=lambda x: int(x.get("id") or 0), reverse=True)[:max(1, int(limit))]
        items = []
        for row in rows:
            items.append({key: row.get(key) for key in fields})
        latest = max((str(row.get("updated_at") or "") for row in rows), default="")
        # updated_at 只有秒精度，快速任务可能在同一秒经历 queued/running/终态。
        # 把各后台状态纳入摘要，保证前端轮询不会漏掉终态刷新。
        state_digest = hash(tuple(
            (
                int(row.get("id") or 0),
                row.get("plan_check_status"),
                row.get("health_status"),
                row.get("extract_link_status"),
                row.get("momo_status"),
                row.get("paypal_zero_offer_status"),
                row.get("paypal_extract_status"),
                row.get("paypal_payment_status"),
                row.get("codex_agent_status"),
                row.get("team_status"),
                row.get("team_cookie_count"),
            )
            for row in rows
        ))
        return {"items": items, "revision": f"{len(rows)}:{latest}:{state_digest}"}


def list_accounts(
    limit: int = 500, offset: int = 0, archived: str | bool | None = False,
    plan_filter: str | None = None, plus_offer: str | None = None,
    totp_status: str = "",
    mask_secrets: bool = True,
    quota_window: str = "",
    codex_plan: str = "",
) -> list[dict]:
    with _LOCK:
        rows = _filter_and_sort_accounts(
            _load_accounts(), archived=archived, plan_filter=plan_filter,
            plus_offer=plus_offer, totp_status=totp_status, quota_window=quota_window,
            codex_plan=codex_plan,
            decorate=False,
        )
        selected = deepcopy(rows[offset: offset + limit])
    return [(_mask_account_secrets(r) if mask_secrets else _decorate_account(r)) for r in selected]


def list_job_retry_accounts() -> list[dict]:
    """Return only fields needed to annotate retry actions in the job list.

    The normal account listing intentionally expands many management fields and
    performs credential masking.  Jobs only need an ID/email lookup plus the
    Codex state; keeping this projection small avoids a multi-second full
    account decoration pass on every paginated task request.
    """
    with _LOCK:
        return [
            {
                "id": row.get("id"),
                "email": row.get("email"),
                "codex_status": row.get("codex_status"),
            }
            for row in _load_accounts()
        ]


def _filter_and_sort_accounts(
    rows: list[dict],
    *,
    q: str = "",
    emails: str = "",
    archived: str | bool | None = False,
    plan_filter: str | None = None,
    plus_offer: str | None = None,
    registration_driver: str = "",
    codex_state: str = "",
    health_state: str = "",
    has_codex_rt: str | bool | None = None,
    email_source: str = "",
    totp_status: str = "",
    quota_window: str = "",
    codex_plan: str = "",
    codex_failure_stage: str = "",
    batch_id: str = "",
    team_parent_id: str = "",
    team_workspace_id: str = "",
    team_seat_type: str = "",
    team_seat_status: str = "",
    sort_by: str = "id",
    sort_order: str = "desc",
    decorate: bool = True,
) -> list[dict]:
    """应用账号管理列表的完整筛选和排序语义；调用方负责持有 _LOCK。"""
    from core.email_search import parse_email_search
    wanted_emails = frozenset(parse_email_search(emails))
    query = str(q or "").strip().lower()
    driver = str(registration_driver or "").strip().lower()
    state = str(codex_state or "").strip().lower()
    health = str(health_state or "").strip().lower()
    source = str(email_source or "").strip().lower()
    totp = str(totp_status or "").strip().lower()
    quota = str(quota_window or "").strip().lower()
    quota_windows = {"": None, "all": None, "7d": 604800, "30d": 2592000, "31d": 2678400}
    if quota not in quota_windows:
        raise ValueError("quota_window 非法，可选 7d、30d、31d")
    quota_seconds = quota_windows[quota]
    wanted_codex_plan = str(codex_plan or "").strip().lower()
    if wanted_codex_plan not in {"", "all", "team", "non_team", "unknown"}:
        raise ValueError("codex_plan 非法，可选 team、non_team、unknown")
    team_plans = frozenset()
    if wanted_codex_plan in {"team", "non_team"}:
        from core.codex_plan import TEAM_PLANS
        team_plans = TEAM_PLANS
    stage = str(codex_failure_stage or "").strip().lower()
    batch = str(batch_id or "").strip()
    if archived in (True, "1", "true", "yes", "only"):
        rows = [r for r in rows if bool(r.get("archived"))]
    elif archived not in ("all", "include"):
        rows = [r for r in rows if not bool(r.get("archived"))]
    scope = None
    if team_parent_id or team_workspace_id or team_seat_type or team_seat_status:
        from core import team_admin_store
        scope = team_admin_store.child_account_emails(
            team_parent_id, team_workspace_id, team_seat_type, team_seat_status,
        )
    selected = []
    for row in rows:
        if wanted_emails and str(row.get("email") or "").strip().casefold() not in wanted_emails:
            continue
        if scope is not None and str(row.get("email") or "").strip().casefold() not in scope:
            continue
        # Match the last successful snapshot shown in the list, even while a
        # refresh is queued or failed. Additional model limits are separate.
        if quota_seconds is not None and (
            not row.get("quota_last_success_at")
            or quota_seconds not in (
                row.get("quota_primary_limit_window_seconds"),
                row.get("quota_secondary_limit_window_seconds"),
            )
        ):
            continue
        r = _account_query_fields(row, include_codex_plan=bool(wanted_codex_plan and wanted_codex_plan != "all"))
        if not _account_matches_plan_filter(r, plan_filter) or not _account_matches_plus_offer(r, plus_offer):
            continue
        if wanted_codex_plan not in {"", "all"}:
            actual_codex_plan = str(r.get("codex_plan_type") or "").strip().lower()
            is_team = actual_codex_plan in team_plans
            if wanted_codex_plan == "team" and not is_team:
                continue
            if wanted_codex_plan == "non_team" and (not actual_codex_plan or is_team):
                continue
            if wanted_codex_plan == "unknown" and actual_codex_plan:
                continue
        if query and query not in " ".join(str(r.get(k) or "").lower() for k in (
            "email", "user_name", "note", "registration_driver", "email_source", "plan_type", "current_plan_type"
        )):
            continue
        if driver and str(r.get("registration_driver") or "").lower() != driver:
            continue
        if state and r["codex_connection_state"] != state:
            continue
        if health and r["health_status"] != health:
            continue
        if source and str(r.get("email_source") or "").lower() != source:
            continue
        if totp in {"connected", "not_connected"}:
            connected = r["totp_status"] in {"active", "active_external"}
            if connected != (totp == "connected"):
                continue
        elif totp not in {"", "all"} and r["totp_status"] != totp:
            continue
        if has_codex_rt not in (None, "", "all"):
            wanted = has_codex_rt in (True, "1", "true", "yes")
            if r["has_codex_refresh_token"] != wanted:
                continue
        if stage and _codex_failure_stage_of(r) != stage:
            continue
        if batch and str(r.get("registration_batch_id") or "") != batch:
            continue
        selected.append((row, r))

    allowed_sort = {
        "id", "email", "created_at", "updated_at", "registration_driver",
        "email_source", "codex_connection_state", "health_status", "health_checked_at", "plan_type",
    }
    key = sort_by if sort_by in allowed_sort else "id"
    reverse = str(sort_order or "desc").lower() != "asc"
    if key == "id":
        selected.sort(key=lambda pair: int(pair[1].get("id") or 0), reverse=reverse)
    else:
        selected.sort(key=lambda pair: (
            pair[1].get(key) is not None, str(pair[1].get(key) or "").lower(),
        ), reverse=reverse)
    return [_decorate_account(row) if decorate else row for row, _ in selected]


def query_accounts(
    *,
    page: int = 1,
    page_size: int = 50,
    q: str = "",
    emails: str = "",
    archived: str | bool | None = False,
    plan_filter: str | None = None,
    plus_offer: str | None = None,
    registration_driver: str = "",
    codex_state: str = "",
    health_state: str = "",
    has_codex_rt: str | bool | None = None,
    email_source: str = "",
    totp_status: str = "",
    quota_window: str = "",
    codex_plan: str = "",
    codex_failure_stage: str = "",
    batch_id: str = "",
    team_parent_id: str = "",
    team_workspace_id: str = "",
    team_seat_type: str = "",
    team_seat_status: str = "",
    sort_by: str = "id",
    sort_order: str = "desc",
) -> dict:
    """服务端账号管理查询；列表结果不暴露原始凭证。"""
    page = max(1, int(page or 1))
    page_size = max(1, min(500, int(page_size or 50)))
    with _LOCK:
        rows = _filter_and_sort_accounts(
            _load_accounts(),
            q=q,
            emails=emails,
            archived=archived,
            plan_filter=plan_filter,
            plus_offer=plus_offer,
            registration_driver=registration_driver,
            codex_state=codex_state,
            health_state=health_state,
            has_codex_rt=has_codex_rt,
            email_source=email_source,
            totp_status=totp_status,
            quota_window=quota_window,
            codex_plan=codex_plan,
            codex_failure_stage=codex_failure_stage,
            batch_id=batch_id,
            team_parent_id=team_parent_id, team_workspace_id=team_workspace_id,
            team_seat_type=team_seat_type, team_seat_status=team_seat_status,
            sort_by=sort_by,
            sort_order=sort_order,
            decorate=False,
        )
        total = len(rows)
        start = (page - 1) * page_size
        # The JSON cache contains mutable rows. Snapshot only this page while
        # holding the lock, then do display expansion/masking outside the lock.
        selected = deepcopy(rows[start:start + page_size])
        summary = {
            "total": total,
            "connected": 0, "not_connected": 0, "running": 0,
            "health_alive": 0, "health_dead": 0, "health_token_invalid": 0,
            "health_error": 0, "health_unchecked": 0, "health_no_token": 0,
            "health_checking": 0,
        }
        for row in rows:
            summary[_account_codex_state(row)] += 1
            health = _account_health_status(row)
            summary["health_checking" if health in {"queued", "running"} else f"health_{health}"] += 1
    items = [_mask_account_secrets(r) for r in selected]
    return {"items": items, "total": total, "page": page, "page_size": page_size, "summary": summary}


def _paypal_management_item(row: dict) -> dict:
    item = _mask_account_secrets(row)
    for key in (
        "paypal_zero_offer_error",
        "paypal_extract_message",
        "paypal_extract_error",
        "paypal_extract_fallback_reason",
        "paypal_payment_message",
        "paypal_payment_error",
        "paypal_sms_error",
        "paypal_payment_reference",
    ):
        if item.get(key) is not None:
            item[key] = _paypal_event_text(item.get(key), limit=500)
    item["paypal_last_error"] = next((
        str(item.get(key) or "")
        for key in (
            "paypal_payment_error", "paypal_sms_error", "paypal_extract_error",
            "paypal_zero_offer_error",
        )
        if str(item.get(key) or "").strip()
    ), "")
    item["paypal_failure_stage"] = next((
        str(item.get(key) or "")
        for key in ("paypal_payment_failure_stage", "paypal_extract_failure_stage")
        if str(item.get(key) or "").strip()
    ), "")
    return item


def query_paypal_accounts(
    *,
    page: int = 1,
    page_size: int = 50,
    q: str = "",
    archived: str | bool | None = False,
    management_state: str = "",
    zero_offer_status: str = "",
    extract_status: str = "",
    payment_status: str = "",
    sms_status: str = "",
    has_ba: str | bool | None = None,
    sort_by: str = "paypal_last_event_at",
    sort_order: str = "desc",
) -> dict:
    """Account-centric PP management query with server-side filters and pagination."""
    page = max(1, int(page or 1))
    page_size = max(1, min(200, int(page_size or 50)))
    query = str(q or "").strip().lower()
    wanted_management = str(management_state or "").strip().lower()
    wanted_zero = str(zero_offer_status or "").strip().lower()
    wanted_extract = str(extract_status or "").strip().lower()
    wanted_payment = str(payment_status or "").strip().lower()
    wanted_sms = str(sms_status or "").strip().lower()
    with _LOCK:
        rows = _load_accounts()
        if archived in (True, "1", "true", "yes", "only"):
            rows = [row for row in rows if bool(row.get("archived"))]
        elif archived not in ("all", "include"):
            rows = [row for row in rows if not bool(row.get("archived"))]
        decorated = [_decorate_account(row) for row in rows]
        if query:
            search_fields = (
                "email", "note", "paypal_extract_message", "paypal_extract_error",
                "paypal_extract_failure_stage", "paypal_payment_message",
                "paypal_payment_error", "paypal_payment_failure_stage",
                "paypal_sms_error", "paypal_sms_provider", "paypal_sms_country",
            )
            decorated = [
                row for row in decorated
                if query in " ".join(str(row.get(key) or "").lower() for key in search_fields)
            ]
        if wanted_management:
            decorated = [
                row for row in decorated
                if str(row.get("paypal_management_state") or "not_started") == wanted_management
            ]
        if wanted_zero:
            decorated = [
                row for row in decorated
                if str(row.get("paypal_zero_offer_status") or "unchecked") == wanted_zero
            ]
        if wanted_extract:
            decorated = [
                row for row in decorated
                if str(row.get("paypal_extract_status") or "unchecked") == wanted_extract
            ]
        if wanted_payment:
            decorated = [
                row for row in decorated
                if str(row.get("paypal_payment_status") or "not_started") == wanted_payment
            ]
        if wanted_sms:
            decorated = [
                row for row in decorated
                if str(row.get("paypal_sms_status") or "not_started") == wanted_sms
            ]
        if has_ba not in (None, "", "all"):
            wanted = has_ba in (True, "1", "true", "yes")
            decorated = [row for row in decorated if bool(row.get("has_paypal_ba_url")) == wanted]

        allowed_sort = {
            "id", "email", "created_at", "updated_at", "paypal_last_event_at",
            "paypal_extract_attempt_count", "paypal_payment_attempt_count",
            "paypal_management_state", "paypal_extract_status", "paypal_payment_status",
        }
        selected_sort = sort_by if sort_by in allowed_sort else "paypal_last_event_at"
        reverse = str(sort_order or "desc").strip().lower() != "asc"
        if selected_sort in {"id", "paypal_extract_attempt_count", "paypal_payment_attempt_count"}:
            decorated.sort(
                key=lambda row: (int(row.get(selected_sort) or 0), int(row.get("id") or 0)),
                reverse=reverse,
            )
        else:
            decorated.sort(
                key=lambda row: (
                    bool(row.get(selected_sort)), str(row.get(selected_sort) or "").lower(),
                    int(row.get("id") or 0),
                ),
                reverse=reverse,
            )

        total = len(decorated)
        start = (page - 1) * page_size
        items = [_paypal_management_item(row) for row in decorated[start:start + page_size]]
        summary = {
            "total": total,
            "active": sum(1 for row in decorated if _paypal_account_is_active(row)),
            "eligible": sum(1 for row in decorated if row.get("paypal_zero_offer_status") == "eligible"),
            "link_ready": sum(1 for row in decorated if row.get("paypal_extract_status") == "success"),
            "waiting_otp": sum(1 for row in decorated if row.get("paypal_payment_status") == "waiting_otp"),
            "authorized": sum(1 for row in decorated if row.get("paypal_payment_status") in {"authorized", "pending"}),
            "confirmed": sum(1 for row in decorated if row.get("paypal_payment_status") == "confirmed"),
            "failed": sum(1 for row in decorated if row.get("paypal_management_state") in {"failed", "sms_failed"}),
            "unavailable": sum(1 for row in decorated if row.get("paypal_management_state") == "unavailable"),
            "event_total": sum(int(row.get("paypal_event_count") or 0) for row in decorated),
        }
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "summary": summary,
        }


def get_paypal_account_detail(acc_id: int) -> dict | None:
    """Return a masked account snapshot for the dedicated PP management view."""
    with _LOCK:
        row = next((item for item in _load_accounts() if int(item.get("id") or 0) == int(acc_id)), None)
        return _paypal_management_item(row) if row else None


def get_account_paypal_events(
    acc_id: int,
    *,
    page: int = 1,
    page_size: int = 100,
    phase: str = "",
    status: str = "",
) -> dict | None:
    """Return newest-first, sanitized PP events for one account."""
    page = max(1, int(page or 1))
    page_size = max(1, min(_PAYPAL_EVENT_LIMIT, int(page_size or 100)))
    wanted_phase = str(phase or "").strip().lower()
    wanted_status = str(status or "").strip().lower()
    with _LOCK:
        row = next((item for item in _load_accounts() if int(item.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return None
        events = _paypal_events_for_row(row)
        if wanted_phase:
            events = [event for event in events if event.get("phase") == wanted_phase]
        if wanted_status:
            events = [event for event in events if event.get("status") == wanted_status]
        events = [
            event
            for _, event in sorted(
                enumerate(events),
                key=lambda pair: (str(pair[1].get("time") or ""), pair[0]),
                reverse=True,
            )
        ]
        total = len(events)
        start = (page - 1) * page_size
        selected = [dict(event) for event in events[start:start + page_size]]
        return {
            "account": {
                "id": int(row.get("id") or 0),
                "email": str(row.get("email") or ""),
            },
            "items": selected,
            "total": total,
            "page": page,
            "page_size": page_size,
            "summary": {
                "legacy": sum(1 for event in events if event.get("legacy") is True),
                "failed": sum(1 for event in events if event.get("status") in {
                    "failed", "retryable_error", "verification_blocked", "timeout", "ambiguous",
                }),
            },
        }


def get_paypal_event_feed(*, limit: int = 300, include_archived: bool = False) -> dict:
    """Return an oldest-first, account-labelled feed for the live PayPal console."""
    limit = max(1, min(1000, int(limit or 300)))
    error_statuses = {
        "failed", "http_error", "retryable_error", "verification_blocked",
        "timeout", "ambiguous", "sms_failed", "error",
    }
    warning_statuses = {
        "fallback", "unavailable", "not_eligible", "waiting_otp", "pending",
        "warning", "warn", "rejected",
    }
    with _LOCK:
        rows = [
            row for row in _load_accounts()
            if include_archived or not bool(row.get("archived"))
        ]
        feed: list[tuple[tuple[str, int, int], dict]] = []
        total = 0
        for row in rows:
            account_id = int(row.get("id") or 0)
            email = str(row.get("email") or "")
            active = _paypal_account_is_active(row)
            events = _paypal_events_for_row(row)
            total += len(events)
            for local_index, event in enumerate(events):
                item = dict(event)
                status = str(item.get("status") or "info").strip().lower()
                level = (
                    "error" if status in error_statuses
                    else "warn" if status in warning_statuses
                    else "info"
                )
                item.update({
                    "feed_id": f"{account_id}:{item.get('id') or local_index}",
                    "account_id": account_id,
                    "email": email,
                    "account_active": active,
                    "level": level,
                })
                feed.append(((str(item.get("time") or ""), account_id, local_index), item))
        feed.sort(key=lambda pair: pair[0])
        selected = [item for _, item in feed[-limit:]]
        return {
            "items": selected,
            "total": total,
            "active_count": sum(1 for row in rows if _paypal_account_is_active(row)),
            "revision": paypal_event_revision(),
        }


def get_account_web_access_tokens(
    *,
    max_accounts: int = 5000,
    q: str = "",
    emails: str = "",
    archived: str | bool | None = False,
    plan_filter: str | None = None,
    plus_offer: str | None = None,
    registration_driver: str = "",
    codex_state: str = "",
    health_state: str = "",
    totp_status: str = "",
    quota_window: str = "",
    codex_plan: str = "",
    has_codex_rt: str | bool | None = None,
    email_source: str = "",
    codex_failure_stage: str = "",
    batch_id: str = "",
    team_parent_id: str = "",
    team_workspace_id: str = "",
    team_seat_type: str = "",
    team_seat_status: str = "",
    sort_by: str = "id",
    sort_order: str = "desc",
) -> dict:
    """显式读取筛选结果的 Web AT；仅供禁止缓存的凭证接口使用。"""
    limit = max(1, int(max_accounts or 1))
    with _LOCK:
        rows = _filter_and_sort_accounts(
            _load_accounts(),
            q=q,
            emails=emails,
            archived=archived,
            plan_filter=plan_filter,
            plus_offer=plus_offer,
            registration_driver=registration_driver,
            codex_state=codex_state,
            health_state=health_state,
            totp_status=totp_status,
            quota_window=quota_window,
            codex_plan=codex_plan,
            has_codex_rt=has_codex_rt,
            email_source=email_source,
            codex_failure_stage=codex_failure_stage,
            batch_id=batch_id,
            team_parent_id=team_parent_id, team_workspace_id=team_workspace_id,
            team_seat_type=team_seat_type, team_seat_status=team_seat_status,
            sort_by=sort_by,
            sort_order=sort_order,
        )
        if len(rows) > limit:
            raise ValueError(f"匹配账号数量超过上限 {limit}")
        tokens = []
        for row in rows:
            token = "".join(str(row.get("access_token") or "").strip().splitlines())
            if token:
                tokens.append(token)
        return {
            "tokens": tokens,
            "selected_count": len(rows),
            "empty_count": len(rows) - len(tokens),
        }


def get_account_web_access_tokens_by_ids(
    account_ids: list[int], *, max_accounts: int = 5000,
) -> dict:
    """按请求顺序批量读取 Web AT，并且只加载一次账号数据。"""
    limit = max(1, int(max_accounts or 1))
    ordered_ids = []
    seen = set()
    for raw_id in account_ids or []:
        account_id = int(raw_id)
        if account_id <= 0 or account_id in seen:
            continue
        seen.add(account_id)
        ordered_ids.append(account_id)
    if len(ordered_ids) > limit:
        raise ValueError(f"账号数量超过上限 {limit}")

    with _LOCK:
        rows_by_id = {
            int(row.get("id") or 0): row
            for row in _load_accounts()
            if int(row.get("id") or 0) > 0
        }
        rows = [rows_by_id[account_id] for account_id in ordered_ids if account_id in rows_by_id]
        tokens = []
        for row in rows:
            token = "".join(str(row.get("access_token") or "").strip().splitlines())
            if token:
                tokens.append(token)
        return {
            "tokens": tokens,
            "requested_count": len(ordered_ids),
            "selected_count": len(rows),
            "missing_count": len(ordered_ids) - len(rows),
            "empty_count": len(rows) - len(tokens),
        }


def account_completion_snapshot(
    account_ids: list[int], job_ids: list[int] | None = None,
) -> dict[str, dict[int, dict]]:
    """Read minimal coordinator state with one scan per table, without credentials.

    This is only a waiting-state hint. Before releasing an operation the
    coordinator re-reads the individual account/job using its normal checks.
    """
    wanted_accounts = set(account_ids)
    wanted_jobs = set(job_ids or ())
    account_fields = (
        "id", "email", "team_status", "team_invite_status", "team_invite_attempt_count",
        "totp_status", "totp_attempt_count",
    )
    with _LOCK:
        accounts = {
            int(row["id"]): {key: row.get(key) for key in account_fields}
            for row in (_load_accounts() if wanted_accounts else [])
            if int(row.get("id") or 0) in wanted_accounts
        }
        jobs = {
            int(row["id"]): {"id": row["id"], "status": row.get("status")}
            for row in (_load_jobs() if wanted_jobs else [])
            if int(row.get("id") or 0) in wanted_jobs
        }
    return {"accounts": accounts, "jobs": jobs}


def _account_supplement_candidate(row: dict) -> dict:
    try:
        cookie_count = int(row.get("web_cookie_count") or 0)
    except (TypeError, ValueError):
        cookie_count = 0
    return {
        "id": row.get("id"), "email": str(row.get("email") or "").strip(),
        "email_source": row.get("email_source"), "codex_status": row.get("codex_status"),
        "has_codex_refresh_token": bool(row.get("codex_refresh_token")),
        "codex_workspace_id": str(row.get("codex_workspace_id") or ""),
        "has_access_token": bool(str(row.get("access_token") or "").strip()),
        "has_quota_credential": bool(row.get("access_token") or row.get("codex_credential_path")),
        "has_web_cookies": bool(str(row.get("web_cookie_credential_path") or "").strip() and cookie_count > 0),
        "team_busy": str(row.get("team_status") or row.get("team_invite_status") or "").strip().lower() in {"queued", "running"},
        "totp_busy": str(row.get("totp_status") or "").strip().lower() in {"queued", "running"},
        "health_busy": str(row.get("health_status") or "").strip().lower() in {"queued", "running"},
        "quota_busy": _account_quota_status(row) in {"queued", "running"},
    }


def get_account_supplement_candidates(account_ids: list[int]) -> dict[int, dict]:
    """One scan for batch admission, without copying tokens or audit blobs."""
    wanted = set(account_ids)
    with _LOCK:
        return {
            int(row.get("id") or 0): _account_supplement_candidate(row)
            for row in _load_accounts() if int(row.get("id") or 0) in wanted
        }


def get_batch_schedule_candidates(batch_id: str) -> list[dict]:
    """Read only local registered accounts, once per scheduling snapshot."""
    with _LOCK:
        return sorted([
            _account_supplement_candidate(row)
            for row in _load_accounts()
            if str(row.get("registration_batch_id") or "") == batch_id and not row.get("archived")
        ], key=lambda row: int(row["id"]))


def get_account_totp_export_candidates(account_ids: list[int]) -> dict[int, dict]:
    """One explicit export snapshot; never copy Web/mailbox/OAuth credentials."""
    wanted = set(account_ids)
    if not wanted:
        return {}
    result = {}
    with _LOCK:
        for row in _load_accounts():
            account_id = int(row.get("id") or 0)
            if account_id not in wanted:
                continue
            extra = row.get("extra_json") or {}
            if isinstance(extra, str):
                try:
                    extra = json.loads(extra)
                except (ValueError, TypeError):
                    extra = {}
            if not isinstance(extra, dict):
                extra = {}
            result[account_id] = {
                key: row.get(key) for key in ("id", "email", "totp_secret", "totp_status", "archived")
            }
            # Match login_material() precedence, preserving every password byte.
            # row['password'] belongs to the mailbox, NOT the ChatGPT account.
            result[account_id]["registration_password"] = extra.get("registration_password") or row.get("registration_password") or ""
    return result


def get_account_codex_export_candidates(account_ids: list[int]) -> dict[int, dict]:
    """Read batch export references in one scan, without Web/mailbox tokens."""
    wanted = set(account_ids)
    with _LOCK:
        return {
            int(row["id"]): {
                key: row.get(key) for key in ("id", "email", "codex_credential_path")
            }
            for row in _load_accounts() if int(row.get("id") or 0) in wanted
        }


def get_team_removal_candidates(*, account_ids: list[int] | None = None, batch_id: str = "") -> list[dict]:
    """One narrow snapshot for remote member removal, including archived accounts."""
    wanted = set(account_ids or ())
    fields = ("id", "email", "registration_batch_id", "codex_credential_path", "codex_workspace_id")
    with _LOCK:
        return sorted([
            {key: row.get(key) for key in fields}
            for row in _load_accounts()
            if (str(row.get("registration_batch_id") or "") == batch_id if batch_id
                else int(row.get("id") or 0) in wanted)
        ], key=lambda row: int(row["id"]))


def get_account_quota_summaries_by_emails(emails: list[str]) -> dict[str, dict | None]:
    """One credential-free snapshot scan; None marks an ambiguous email match."""
    wanted = {email.strip().casefold() for email in emails if email.strip()}
    if not wanted:
        return {}
    fields = (
        "id", "email", "quota_ok", "quota_error", "quota_error_code", "quota_checked_at",
        "quota_last_success_at", "quota_source", "quota_workspace_id", "quota_plan_type",
        "quota_allowed", "quota_limit_reached", "quota_primary_used_percent",
        "quota_primary_limit_window_seconds", "quota_primary_reset_at",
        "quota_secondary_used_percent", "quota_secondary_limit_window_seconds",
        "quota_secondary_reset_at", "quota_reset_credits_available_count",
        "quota_reset_credit_expirations", "quota_additional_rate_limits",
    )
    result = {}
    with _LOCK:
        for row in _load_accounts():
            email = str(row.get("email") or "").strip().casefold()
            if email not in wanted:
                continue
            if email in result:
                result[email] = None
                continue
            item = {key: deepcopy(row.get(key)) for key in fields}
            item["quota_status"] = _account_quota_status(row)
            item["has_quota_credential"] = bool(row.get("access_token") or row.get("codex_credential_path"))
            for key in ("quota_reset_credit_expirations", "quota_additional_rate_limits"):
                if not isinstance(item[key], list):
                    item[key] = []
            result[email] = item
    return result


def codex_mailbox_presence(candidates: list[dict]) -> dict[int, bool]:
    """Batch equivalent of the three mailbox lookups used during admission."""
    loaders = {"generic_api": _load_generic_api_emails, "icloud": _load_icloud_emails, "mailcom": _load_mailcom}
    sources = {str(item.get("email_source") or "").strip().lower() for item in candidates} & loaders.keys()
    if not sources:
        return {}
    with _LOCK:
        pools = {source: {str(row.get("email") or "").lower() for row in loaders[source]()} for source in sources}
        # The existing lookup selects the last matching allocation, even when
        # it belongs to another source; do not resurrect an older alias.
        allocations = {str(row.get("actual_email") or "").lower(): row for row in _load_email_allocations()}
        result = {}
        for item in candidates:
            source = str(item.get("email_source") or "").strip().lower()
            if source not in pools:
                continue
            email = str(item.get("email") or "").lower()
            allocation = allocations.get(email)
            base = (
                str(allocation.get("base_email") or "").lower()
                if allocation and _email_allocation_source(allocation) == source else ""
            )
            result[int(item["id"])] = email in pools[source] or bool(base and base in pools[source])
        return result


def get_account(acc_id: int) -> dict | None:
    with _LOCK:
        row = next((r for r in _load_accounts() if int(r.get("id") or 0) == int(acc_id)), None)
        return _decorate_account(row) if row else None


def get_account_by_email(email: str) -> dict | None:
    with _LOCK:
        row = _find_by_email(_load_accounts(), email)
        return _decorate_account(row) if row else None


def get_account_paypal_context(acc_id: int) -> dict | None:
    """Return one account with PP secrets for the dedicated workflow service only."""
    with _LOCK:
        row = next((r for r in _load_accounts() if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return None
        out = _decorate_account(row)
        for key in _PAYPAL_SENSITIVE_FIELDS:
            value = row.get(key)
            if isinstance(value, (dict, list)):
                value = json.loads(json.dumps(value, ensure_ascii=False))
            out[key] = value
        return out


def replace_account_access_token(
    acc_id: int,
    *,
    expected_access_token: str,
    access_token: str,
    source: str = "cookie_refresh",
) -> bool:
    """Compare-and-swap Web AT so a late health worker cannot overwrite a newer token."""
    replacement = str(access_token or "").strip()
    if not replacement:
        return False
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None or str(row.get("access_token") or "") != str(expected_access_token or ""):
            return False
        row["access_token"] = replacement
        row["web_at_refreshed_at"] = _now()
        row["web_at_refresh_source"] = str(source or "cookie_refresh")[:100]
        row["updated_at"] = _now()
        _save_accounts(rows)
        return True


def get_account_detail(acc_id: int, *, mask_secrets: bool = True) -> dict | None:
    with _LOCK:
        raw = next((r for r in _load_accounts() if int(r.get("id") or 0) == int(acc_id)), None)
        if raw is None:
            return None
        out = _mask_account_secrets(raw) if mask_secrets else _decorate_account(raw)
        jobs = [
            dict(r) for r in _load_jobs()
            if int(r.get("account_id") or 0) == int(acc_id)
        ]
        out["jobs"] = mask_job_secrets(jobs) if mask_secrets else jobs
        allocations = [
            dict(r) for r in _load_email_allocations()
            if int(r.get("account_id") or 0) == int(acc_id)
            or str(r.get("actual_email") or "").lower() == str(raw.get("email") or "").lower()
        ]
        out["email_allocations"] = allocations
        batch_ids = {str(j.get("batch_id") or "") for j in jobs if j.get("batch_id")}
        out["registration_batches"] = mask_job_secrets([
            dict(r) for r in _load_batches() if str(r.get("batch_id") or "") in batch_ids
        ])
        base_email = str((allocations[0] if allocations else {}).get("base_email") or "")
        source = str(raw.get("email_source") or "").lower()
        if base_email:
            allocation_source = _email_allocation_source(allocations[0])
            mailbox = _find_by_email(_email_pool_for_source(allocation_source), base_email)
            out["base_mailbox"] = (
                _mask_email_pool_secrets({**mailbox, "source": allocation_source})
                if mailbox else None
            )
        elif source == "outlook":
            mailbox = _find_by_email(_load_outlook(), str(raw.get("email") or ""))
            out["base_mailbox"] = _mask_email_pool_secrets({**mailbox, "source": "outlook"}) if mailbox else None
        elif source == "icloud":
            mailbox = _find_by_email(_load_icloud_emails(), str(raw.get("email") or ""))
            out["base_mailbox"] = _mask_email_pool_secrets({**mailbox, "source": "icloud"}) if mailbox else None
        elif source == "mailcom":
            mailbox = _find_by_email(_load_mailcom(), str(raw.get("email") or ""))
            out["base_mailbox"] = _mask_email_pool_secrets({**mailbox, "source": "mailcom"}) if mailbox else None
        elif source in {"cloudflare_domain", "domain"}:
            mailbox = _find_domain_email(_load_domain_pool(), str(raw.get("email") or ""))
            out["base_mailbox"] = _mask_email_pool_secrets({**mailbox, "source": "cloudflare_domain"}) if mailbox else None
        else:
            out["base_mailbox"] = None
        return out


def _resolve_account_web_cookie_path(row: dict) -> Path | None:
    raw = str(row.get("web_cookie_credential_path") or "").strip()
    if not raw:
        return None
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = _COOKIE_DIR / candidate
    try:
        resolved = candidate.resolve()
        managed = _COOKIE_DIR.resolve()
    except Exception as exc:
        raise ValueError("Web Cookie 凭证路径无效") from exc
    if not resolved.is_relative_to(managed):
        raise ValueError("Web Cookie 凭证路径不在受管目录")
    return resolved


def load_account_web_cookie_credential(acc_id: int) -> dict | None:
    """显式读取可重新注入浏览器的 Web Cookie JSON。"""
    with _LOCK:
        row = next((r for r in _load_accounts() if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return None
        path = _resolve_account_web_cookie_path(row)
        if path is None:
            raise ValueError("该账号没有保存 Web Cookie")
        from core.account_cookie_store import CookieCredentialError, load_cookie_credential

        try:
            payload = load_cookie_credential(path)
        except FileNotFoundError as exc:
            raise ValueError("Web Cookie 凭证文件不存在") from exc
        except (OSError, CookieCredentialError) as exc:
            raise ValueError("Web Cookie 凭证文件无法读取") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("cookies"), list):
            raise ValueError("Web Cookie 凭证格式无效")
        payload_account_id = payload.get("account_id")
        if payload_account_id is not None and int(payload_account_id) != int(acc_id):
            raise ValueError("Web Cookie 凭证与账号不匹配")
        return payload


def get_account_credential(acc_id: int, kind: str) -> str | None:
    with _LOCK:
        row = next((r for r in _load_accounts() if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return None
        normalized_kind = str(kind or "").strip().lower()
        if normalized_kind == "email_original":
            allocations = _load_email_allocations()
            account_source = str(row.get("email_source") or "").strip().lower()
            allocation_id = int(row.get("email_allocation_id") or 0)
            allocation = next((
                item for item in allocations
                if allocation_id and int(item.get("id") or 0) == allocation_id
            ), None)
            if allocation is None:
                matching_allocations = [
                    item for item in reversed(allocations)
                    if str(item.get("actual_email") or "").lower()
                    == str(row.get("email") or "").lower()
                ]
                if account_source in {"outlook", "generic_api", "icloud", "mailcom"}:
                    matching_allocations = [
                        item for item in matching_allocations
                        if _email_allocation_source(item) == account_source
                    ]
                allocation = matching_allocations[0] if matching_allocations else None

            mailbox = None
            source = ""
            if allocation is not None:
                source = _email_allocation_source(allocation)
                pool = _email_pool_for_source(source)
                base_email_id = int(allocation.get("base_email_id") or 0)
                if base_email_id:
                    mailbox = next((
                        item for item in pool
                        if int(item.get("id") or 0) == base_email_id
                    ), None)
                if mailbox is None:
                    mailbox = _find_by_email(pool, str(allocation.get("base_email") or ""))
            else:
                source = account_source
                if source in {"outlook", "generic_api", "icloud", "mailcom"}:
                    mailbox = _find_by_email(_email_pool_for_source(source), str(row.get("email") or ""))

            if mailbox is not None:
                return _mailbox_import_line(source, mailbox)
            return str(row.get("original_email_line") or row.get("email") or "")
        if normalized_kind == "icloud_pickup_url":
            mailbox = _find_by_email(_load_icloud_emails(), str(row.get("email") or ""))
            pickup_url = str((mailbox or {}).get("pickup_url") or "").strip()
            if not pickup_url:
                raise ValueError("该账号没有关联的 iCloud 取码链接")
            return pickup_url
        if normalized_kind == "web_cookies":
            payload = load_account_web_cookie_credential(acc_id)
            return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        if normalized_kind == "web_cookies_browser":
            from core.account_cookie_store import to_browser_import_cookies

            payload = load_account_web_cookie_credential(acc_id)
            return json.dumps(
                to_browser_import_cookies(payload["cookies"]),
                ensure_ascii=False,
                indent=2,
            ) + "\n"
        if normalized_kind == "registration_proxy":
            from core.account_proxy import resolve_registration_proxy

            proxy = resolve_registration_proxy(row)
            if not proxy:
                raise ValueError("该账号没有可复用的注册代理")
            return proxy
        fields = {
            "web_at": "access_token",
            "codex_rt": "codex_refresh_token",
            "copy_line": "copy_line",
            "codex_agent": "codex_agent_token",
            "paypal_ba_url": "paypal_ba_url",
            "paypal_ba_token": "paypal_ba_token",
        }
        field = fields.get(normalized_kind)
        if not field:
            raise ValueError(
                "kind 仅支持 web_at / web_cookies / web_cookies_browser / registration_proxy / "
                "codex_rt / copy_line / codex_agent / paypal_ba_url / paypal_ba_token / "
                "email_original / icloud_pickup_url"
            )
        return _account_line(row) if field == "copy_line" else str(row.get(field) or "")


def update_account_note(acc_id: int, note: str) -> bool:
    """更新单个已注册账号备注。note 为空字符串时表示清空备注。"""
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        previous = dict(row)
        now = _now()
        row["note"] = str(note or "")
        row["note_updated_at"] = now
        row["updated_at"] = now
        _save_account_progress_fields(
            rows, row, previous,
            ("note", "note_updated_at", "updated_at"),
        )
        return True


def update_accounts_note(account_ids: list[int] | None, note: str) -> tuple[list[dict], list[dict]]:
    """
    批量更新已注册账号备注。
    返回 (updated, skipped)，updated/skipped 元素含 id/email。
    """
    ids = {int(x) for x in (account_ids or []) if str(x).strip().lstrip("-").isdigit()}
    updated: list[dict] = []
    skipped: list[dict] = []
    with _LOCK:
        rows = _load_accounts()
        seen_ids: set[int] = set()
        now = _now()
        changes = []
        text = str(note or "")
        for row in rows:
            row_id = int(row.get("id") or 0)
            if row_id not in ids:
                continue
            previous = dict(row)
            row["note"] = text
            row["note_updated_at"] = now
            row["updated_at"] = now
            changes.append((row, previous))
            updated.append({"id": row_id, "email": row.get("email"), "note": text, "note_updated_at": now})
            seen_ids.add(row_id)
        for item in ids - seen_ids:
            skipped.append({"id": item, "reason": "账号不存在"})
        if updated:
            _save_account_progress_many(rows, changes)
    return updated, skipped


def archive_account(acc_id: int, archived: bool = True) -> bool:
    """归档/取消归档单个已注册账号。归档不会删除 token，只影响默认账号列表查询。"""
    with _LOCK:
        rows = _load_accounts()
        row = next((r for r in rows if int(r.get("id") or 0) == int(acc_id)), None)
        if row is None:
            return False
        now = _now()
        previous = dict(row)
        row["archived"] = bool(archived)
        row["archived_at"] = now if archived else None
        row["updated_at"] = now
        _save_account_progress_fields(
            rows, row, previous,
            ("archived", "archived_at", "updated_at"),
        )
        return True


def archive_accounts(account_ids: list[int] | None, archived: bool = True) -> tuple[list[dict], list[dict]]:
    """批量归档/取消归档账号。返回 (updated, skipped)。"""
    ids = {int(x) for x in (account_ids or []) if str(x).strip().lstrip("-").isdigit()}
    updated: list[dict] = []
    skipped: list[dict] = []
    with _LOCK:
        rows = _load_accounts()
        seen_ids: set[int] = set()
        now = _now()
        changes = []
        for row in rows:
            row_id = int(row.get("id") or 0)
            if row_id not in ids:
                continue
            previous = dict(row)
            row["archived"] = bool(archived)
            row["archived_at"] = now if archived else None
            row["updated_at"] = now
            changes.append((row, previous))
            updated.append({"id": row_id, "email": row.get("email"), "archived": bool(archived), "archived_at": row.get("archived_at")})
            seen_ids.add(row_id)
        for item in ids - seen_ids:
            skipped.append({"id": item, "reason": "账号不存在"})
        if updated:
            _save_account_progress_many(rows, changes)
    return updated, skipped


def count_accounts() -> int:
    with _LOCK:
        return len(_load_accounts())


def account_delete_block_reason(acc_id: int | None = None, email: str | None = None) -> str | None:
    """返回永久删除账号的阻塞原因；无阻塞时返回 None。"""
    with _LOCK:
        rows = _load_accounts()
        target_email = (email or "").lower()
        target = next((r for r in rows if (
            (acc_id is not None and int(r.get("id") or 0) == int(acc_id))
            or (bool(target_email) and str(r.get("email") or "").lower() == target_email)
        )), None)
        if target is None:
            return "账号不存在"
        if str(target.get("momo_status") or "unchecked").lower() in {"queued", "running"}:
            return "MoMo 提链任务仍在执行，请等待任务结束后再删除账号"
        if _paypal_account_is_active(target):
            return "PayPal 提链或支付任务仍在执行，请等待任务结束后再删除账号"
        if str(target.get("health_status") or "unchecked").lower() in {"queued", "running"}:
            return "账号验活任务仍在执行，请等待任务结束后再删除账号"

        target_id = int(target.get("id") or 0)
        target_email = str(target.get("email") or "").lower()
        allocations = _load_email_allocations()
        linked_job_ids = {
            int(value)
            for value in (
                target.get("registration_job_id"),
                *(
                    allocation.get("job_id")
                    for allocation in allocations
                    if int(allocation.get("account_id") or 0) == target_id
                    or str(allocation.get("actual_email") or "").lower() == target_email
                ),
            )
            if str(value or "").isdigit()
        }
        active_job = next((
            job for job in _load_jobs()
            if (
                int(job.get("id") or 0) in linked_job_ids
                or int(job.get("account_id") or 0) == target_id
                or str(job.get("email") or "").lower() == target_email
            )
            and job.get("status") in {"pending", "running", "stopping"}
        ), None)
        if active_job:
            return "账号仍有关联运行任务，请先停止任务"
        return None


def _deleted_allocation_used_bases(allocations: list[dict]) -> dict[str, set[int]]:
    """保留基础地址已注册的证据；派生 Alias 注册成功不消耗基础地址。"""
    used: dict[str, set[int]] = {}
    for allocation in allocations:
        if (
            str(allocation.get("mode") or "single").lower() == "single"
            and allocation.get("status") == "registered"
        ) or allocation.get("base_status_before_lease") == "used":
            used.setdefault(_email_allocation_source(allocation), set()).add(
                int(allocation.get("base_email_id") or 0),
            )
    return used


def _release_deleted_account_mailbox(mailbox: dict, *, keep_used: bool) -> None:
    mailbox["status"] = "used" if keep_used else "available"
    mailbox["used_at"] = (mailbox.get("used_at") or _now()) if keep_used else None
    if keep_used:
        mailbox["note"] = mailbox.get("note") or "关联账号已删除，邮箱保留为已用"
    mailbox["lease_job_id"] = None
    mailbox["lease_allocation_id"] = None
    mailbox["lease_expires_at"] = None


def delete_account(acc_id: int | None = None, email: str | None = None) -> bool:
    """永久删除账号，并级联凭证、邮箱分配、关联任务和日志。"""
    files_to_delete: list[Path] = []
    with _LOCK:
        rows = _load_accounts()
        target_email = (email or "").lower()
        target = next((r for r in rows if (
            (acc_id is not None and int(r.get("id") or 0) == int(acc_id))
            or (bool(target_email) and str(r.get("email") or "").lower() == target_email)
        )), None)
        if target is None:
            return False
        if str(target.get("momo_status") or "unchecked").lower() in {"queued", "running"}:
            return False
        if _paypal_account_is_active(target):
            return False
        if str(target.get("health_status") or "unchecked").lower() in {"queued", "running"}:
            return False
        target_id = int(target.get("id") or 0)
        target_email = str(target.get("email") or "").lower()
        allocations = _load_email_allocations()
        deleted_allocations = [
            a for a in allocations
            if int(a.get("account_id") or 0) == target_id
            or str(a.get("actual_email") or "").lower() == target_email
        ]
        target_uses_plus_alias = any(
            str(a.get("mode") or "single").strip().lower() == "plus_alias"
            for a in deleted_allocations
        )
        # 删除本地账号不会注销远端注册；基础地址不能重新进入待注册池。
        # Plus Alias 只消耗派生地址，未注册过的基础邮箱仍可继续使用。
        keep_mailbox_used = not target_uses_plus_alias
        consumed_bases = _deleted_allocation_used_bases(deleted_allocations)

        def preserve_mailbox_used(source: str, mailbox: dict) -> bool:
            return (
                keep_mailbox_used
                or str(mailbox.get("email") or "").lower() == target_email
                or mailbox.get("status") == "used"
                or int(mailbox.get("id") or 0) in consumed_bases.get(source, set())
            )

        linked_job_ids = {
            int(value)
            for value in (
                target.get("registration_job_id"),
                *(a.get("job_id") for a in deleted_allocations),
            )
            if str(value or "").isdigit()
        }
        jobs = _load_jobs()
        active_job = next((
            j for j in jobs
            if (
                int(j.get("id") or 0) in linked_job_ids
                or int(j.get("account_id") or 0) == target_id
                or str(j.get("email") or "").lower() == target_email
            )
            and j.get("status") in {"pending", "running", "stopping"}
        ), None)
        if active_job:
            return False
        credential_path = str(target.get("codex_credential_path") or "").strip()
        if credential_path:
            candidate = Path(credential_path)
            if not candidate.is_absolute():
                candidate = _PROJECT_ROOT / candidate
            try:
                resolved = candidate.resolve()
                if resolved.is_relative_to(_CODEX_DIR.resolve()):
                    files_to_delete.append(resolved)
            except Exception:
                pass
        agent_credential_path = str(target.get("codex_agent_auth_path") or "").strip()
        if agent_credential_path:
            candidate = Path(agent_credential_path)
            if not candidate.is_absolute():
                candidate = _CODEX_AGENT_DIR / candidate
            try:
                resolved = candidate.resolve()
                if resolved.is_relative_to(_CODEX_AGENT_DIR.resolve()):
                    files_to_delete.append(resolved)
            except Exception:
                pass
        try:
            cookie_path = _resolve_account_web_cookie_path(target)
            if cookie_path is not None:
                files_to_delete.append(cookie_path)
        except ValueError:
            # 永久删除账号绝不能跟随越界路径；只忽略异常元数据。
            pass
        # 写凭证后、账号元数据落盘前进程中断时的确定性兜底文件。
        try:
            fallback_cookie_path = (_COOKIE_DIR / f"account-{target_id}.json").resolve()
            if fallback_cookie_path.is_relative_to(_COOKIE_DIR.resolve()):
                files_to_delete.append(fallback_cookie_path)
        except Exception:
            pass
        # 兼容没有 codex_credential_path 的旧账号：只按 JSON 内的精确邮箱匹配，
        # 不依赖可能含有连字符的文件名推断。
        if _CODEX_DIR.exists():
            for candidate in _CODEX_DIR.glob("codex-*.json"):
                try:
                    payload = json.loads(candidate.read_text(encoding="utf-8"))
                    if str(payload.get("email") or "").strip().lower() == target_email:
                        files_to_delete.append(candidate.resolve())
                except Exception:
                    continue

        remaining_allocations = [a for a in allocations if a not in deleted_allocations]
        generic_base_ids = {
            int(a.get("base_email_id") or 0) for a in deleted_allocations
            if _email_allocation_source(a) == "generic_api"
        }
        outlook_base_ids = {
            int(a.get("base_email_id") or 0) for a in deleted_allocations
            if _email_allocation_source(a) == "outlook"
        }
        icloud_base_ids = {
            int(a.get("base_email_id") or 0) for a in deleted_allocations
            if _email_allocation_source(a) == "icloud"
        }
        mailcom_base_ids = {
            int(a.get("base_email_id") or 0) for a in deleted_allocations
            if _email_allocation_source(a) == "mailcom"
        }
        mailboxes = _load_generic_api_emails()
        for mailbox in mailboxes:
            linked_to_target = (
                int(mailbox.get("id") or 0) in generic_base_ids
                or int(mailbox.get("registered_account_id") or 0) == target_id
                or str(mailbox.get("email") or "").lower() == target_email
            )
            if not linked_to_target:
                continue
            for key in ("registered_account_id", "access_token", "totp_secret", "account_copy_line", "completed_at"):
                mailbox.pop(key, None)
            still_used = any(
                _email_allocation_source(a) == "generic_api"
                and int(a.get("base_email_id") or 0) == int(mailbox.get("id") or 0)
                for a in remaining_allocations
            )
            if not still_used and mailbox.get("status") != "disabled":
                _release_deleted_account_mailbox(mailbox, keep_used=preserve_mailbox_used("generic_api", mailbox))

        removed_jobs = [
            j for j in jobs
            if int(j.get("id") or 0) in linked_job_ids
            or int(j.get("account_id") or 0) == target_id
            or (str(j.get("email") or "").lower() == target_email and j.get("status") not in {"running", "stopping"})
        ]
        for job in removed_jobs:
            if job.get("log_file"):
                candidate = Path(str(job["log_file"]))
                if not candidate.is_absolute():
                    candidate = _PROJECT_ROOT / candidate
                try:
                    resolved = candidate.resolve()
                    if resolved.is_relative_to(_LOG_DIR.resolve()):
                        files_to_delete.append(resolved)
                except Exception:
                    pass
        remaining_jobs = [j for j in jobs if j not in removed_jobs]
        remaining_accounts = [r for r in rows if int(r.get("id") or 0) != target_id]

        outlook_rows = _load_outlook()
        icloud_rows = _load_icloud_emails()
        mailcom_rows = _load_mailcom()
        domain_rows = _load_domain_pool()
        for mailbox in outlook_rows:
            linked_to_target = (
                int(mailbox.get("id") or 0) in outlook_base_ids
                or int(mailbox.get("registered_account_id") or 0) == target_id
                or str(mailbox.get("email") or "").lower() == target_email
            )
            if not linked_to_target:
                continue
            for key in ("registered_account_id", "access_token", "totp_secret", "account_copy_line", "completed_at"):
                mailbox.pop(key, None)
            still_used = any(
                _email_allocation_source(a) == "outlook"
                and int(a.get("base_email_id") or 0) == int(mailbox.get("id") or 0)
                for a in remaining_allocations
            )
            if not still_used and mailbox.get("status") != "disabled":
                _release_deleted_account_mailbox(mailbox, keep_used=preserve_mailbox_used("outlook", mailbox))

        for mailbox in icloud_rows:
            linked_to_target = (
                int(mailbox.get("id") or 0) in icloud_base_ids
                or int(mailbox.get("registered_account_id") or 0) == target_id
                or str(mailbox.get("email") or "").lower() == target_email
            )
            if not linked_to_target:
                continue
            for key in ("registered_account_id", "access_token", "totp_secret", "account_copy_line", "completed_at"):
                mailbox.pop(key, None)
            still_used = any(
                _email_allocation_source(a) == "icloud"
                and int(a.get("base_email_id") or 0) == int(mailbox.get("id") or 0)
                for a in remaining_allocations
            )
            if not still_used and mailbox.get("status") != "disabled":
                _release_deleted_account_mailbox(mailbox, keep_used=preserve_mailbox_used("icloud", mailbox))

        for mailbox in mailcom_rows:
            linked_to_target = (
                int(mailbox.get("id") or 0) in mailcom_base_ids
                or int(mailbox.get("registered_account_id") or 0) == target_id
                or str(mailbox.get("email") or "").lower() == target_email
            )
            if not linked_to_target:
                continue
            for key in ("registered_account_id", "access_token", "totp_secret", "account_copy_line", "completed_at"):
                mailbox.pop(key, None)
            still_used = any(
                _email_allocation_source(a) == "mailcom"
                and int(a.get("base_email_id") or 0) == int(mailbox.get("id") or 0)
                for a in remaining_allocations
            )
            if not still_used and mailbox.get("status") != "disabled":
                _release_deleted_account_mailbox(mailbox, keep_used=preserve_mailbox_used("mailcom", mailbox))

        for mailbox in domain_rows:
            if (
                int(mailbox.get("registered_account_id") or 0) != target_id
                and str(mailbox.get("email") or "").lower() != target_email
            ):
                continue
            for key in ("registered_account_id", "access_token", "totp_secret", "account_copy_line", "completed_at"):
                mailbox.pop(key, None)
            if keep_mailbox_used and mailbox.get("status") != "disabled":
                mailbox["status"] = "used"
                mailbox["used_at"] = mailbox.get("used_at") or _now()
                mailbox["note"] = mailbox.get("note") or "关联账号已删除，邮箱保留为已用"

        candidate_batch_ids = {
            str(value)
            for value in (
                target.get("registration_batch_id"),
                *(j.get("batch_id") for j in removed_jobs),
                *(a.get("batch_id") for a in deleted_allocations),
            )
            if value
        }
        referenced_batch_ids = {
            str(value)
            for value in (
                *(j.get("batch_id") for j in remaining_jobs),
                *(r.get("registration_batch_id") for r in remaining_accounts),
                *(a.get("batch_id") for a in remaining_allocations),
            )
            if value
        }
        batches = _load_batches()
        remaining_batches = [
            batch for batch in batches
            if not (
                str(batch.get("batch_id") or "") in candidate_batch_ids
                and str(batch.get("batch_id") or "") not in referenced_batch_ids
            )
        ]

        legacy_safe_email = target_email.replace("/", "_").replace("\\", "_").replace(":", "_")
        try:
            legacy_log = (_LOG_DIR / f"codex-retry-{legacy_safe_email}.log").resolve()
            if legacy_log.is_relative_to(_LOG_DIR.resolve()):
                files_to_delete.append(legacy_log)
        except Exception:
            pass

        _save_accounts(remaining_accounts)
        _save_email_allocations(remaining_allocations)
        _save_generic_api_emails(mailboxes)
        _save_outlook(outlook_rows)
        _save_icloud_emails(icloud_rows)
        _save_mailcom(mailcom_rows)
        _save_domain_pool(domain_rows)
        _save_jobs(remaining_jobs)
        if len(remaining_batches) != len(batches):
            _save_batches(remaining_batches)

    for path in files_to_delete:
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass
    return True


def delete_accounts(
    account_ids: list[int] | None = None,
    emails: list[str] | None = None,
    *,
    _batch_ids: frozenset[str] = frozenset(),
) -> tuple[list[dict], list[dict]]:
    """
    批量删除已注册账号。
    返回 (deleted, skipped)，deleted 元素含 id/email。
    """
    ids = {int(x) for x in (account_ids or []) if str(x).strip().isdigit()}
    email_set = {(e or "").lower() for e in (emails or []) if e}
    deleted: list[dict] = []
    skipped: list[dict] = []
    files_to_delete: list[Path] = []
    with _LOCK:
        rows = _load_accounts()
        targets = [
            r
            for r in rows
            if int(r.get("id") or 0) in ids or str(r.get("email") or "").lower() in email_set
        ]
        seen_ids = {int(r.get("id") or 0) for r in targets}
        seen_emails = {str(r.get("email") or "").lower() for r in targets}
        allocations = _load_email_allocations()
        jobs = _load_jobs()
        allocations_by_account: dict[int, list[dict]] = {}
        allocations_by_email: dict[str, list[dict]] = {}
        for allocation in allocations:
            allocations_by_account.setdefault(int(allocation.get("account_id") or 0), []).append(allocation)
            allocations_by_email.setdefault(str(allocation.get("actual_email") or "").lower(), []).append(allocation)
        active_jobs = [job for job in jobs if job.get("status") in {"pending", "queued", "running", "stopping"}]
        active_job_ids = {int(job.get("id") or 0) for job in active_jobs}
        active_account_ids = {int(job.get("account_id") or 0) for job in active_jobs}
        active_emails = {str(job.get("email") or "").lower() for job in active_jobs}

        accepted: list[dict] = []
        target_allocations: dict[int, list[dict]] = {}
        keep_mailbox_used: dict[int, bool] = {}
        for target in targets:
            target_id = int(target.get("id") or 0)
            target_email = str(target.get("email") or "").lower()
            public_target = {"id": target_id, "email": target.get("email")}
            reason = None
            if str(target.get("momo_status") or "unchecked").lower() in {"queued", "running"}:
                reason = "MoMo 提链任务仍在执行，请等待任务结束后再删除账号"
            elif _paypal_account_is_active(target):
                reason = "PayPal 提链或支付任务仍在执行，请等待任务结束后再删除账号"
            elif str(target.get("health_status") or "unchecked").lower() in {"queued", "running"}:
                reason = "账号验活任务仍在执行，请等待任务结束后再删除账号"

            linked_allocations = list({id(allocation): allocation for allocation in (
                *allocations_by_account.get(target_id, []),
                *allocations_by_email.get(target_email, []),
            )}.values())
            target_allocations[target_id] = linked_allocations
            linked_job_ids = {
                int(value)
                for value in (
                    target.get("registration_job_id"),
                    *(allocation.get("job_id") for allocation in linked_allocations),
                )
                if str(value or "").isdigit()
            }
            if reason is None and (
                linked_job_ids & active_job_ids
                or target_id in active_account_ids
                or (target_email and target_email in active_emails)
            ):
                reason = "账号仍有关联运行任务，请先停止任务"
            if reason:
                skipped.append({**public_target, "reason": reason})
                continue

            uses_plus_alias = any(
                str(allocation.get("mode") or "single").strip().lower() == "plus_alias"
                for allocation in linked_allocations
            )
            # 与单账号删除一致：是否已用不取决于账号验活结果。
            keep_mailbox_used[target_id] = not uses_plus_alias
            accepted.append(target)
            deleted.append(public_target)

        for item in ids - seen_ids:
            skipped.append({"id": item, "reason": "账号不存在"})
        for item in email_set - seen_emails:
            skipped.append({"email": item, "reason": "账号不存在"})
        # Batch deletion is validated as a whole before any table is changed.
        if _batch_ids and skipped:
            raise BatchDeleteConflict(f"关联账号 {skipped[0].get('id')}：{skipped[0]['reason']}")
        if not accepted and not _batch_ids:
            return deleted, skipped

        accepted_ids = {int(target.get("id") or 0) for target in accepted}
        accepted_emails = {
            str(target.get("email") or "").lower(): int(target.get("id") or 0)
            for target in accepted
        }
        deleted_allocations = [
            allocation for allocation in allocations
            if int(allocation.get("account_id") or 0) in accepted_ids
            or str(allocation.get("actual_email") or "").lower() in accepted_emails
            or str(allocation.get("batch_id") or "") in _batch_ids
        ]
        deleted_allocation_objects = {id(allocation) for allocation in deleted_allocations}
        consumed_bases = _deleted_allocation_used_bases(deleted_allocations)
        remaining_allocations = [
            allocation for allocation in allocations if id(allocation) not in deleted_allocation_objects
        ]
        linked_job_ids = {
            int(value)
            for target in accepted
            for value in (
                target.get("registration_job_id"),
                *(allocation.get("job_id") for allocation in target_allocations[int(target.get("id") or 0)]),
            )
            if str(value or "").isdigit()
        }
        removed_jobs = [
            job for job in jobs
            if int(job.get("id") or 0) in linked_job_ids
            or int(job.get("account_id") or 0) in accepted_ids
            or str(job.get("batch_id") or "") in _batch_ids
            or (
                str(job.get("email") or "").lower() in accepted_emails
                and job.get("status") not in {"running", "stopping"}
            )
        ]
        removed_job_ids = {int(job.get("id") or 0) for job in removed_jobs}
        remaining_jobs = [job for job in jobs if int(job.get("id") or 0) not in removed_job_ids]
        remaining_accounts = [
            row for row in rows if int(row.get("id") or 0) not in accepted_ids
        ]
        remaining_account_ids = {int(row.get("id") or 0) for row in remaining_accounts}

        def add_scoped_file(raw_path: object, root: Path, *, relative_root: Path | None = None) -> None:
            value = str(raw_path or "").strip()
            if not value:
                return
            candidate = Path(value)
            if not candidate.is_absolute():
                candidate = (relative_root or _PROJECT_ROOT) / candidate
            try:
                resolved = candidate.resolve()
                if resolved.is_relative_to(root.resolve()):
                    files_to_delete.append(resolved)
            except Exception:
                pass

        for target in accepted:
            target_id = int(target.get("id") or 0)
            target_email = str(target.get("email") or "").lower()
            add_scoped_file(target.get("codex_credential_path"), _CODEX_DIR)
            add_scoped_file(
                target.get("codex_agent_auth_path"),
                _CODEX_AGENT_DIR,
                relative_root=_CODEX_AGENT_DIR,
            )
            try:
                cookie_path = _resolve_account_web_cookie_path(target)
                if cookie_path is not None:
                    files_to_delete.append(cookie_path)
            except ValueError:
                pass
            add_scoped_file(
                _COOKIE_DIR / f"account-{target_id}.json",
                _COOKIE_DIR,
            )
            legacy_name = target_email.replace("/", "_").replace("\\", "_").replace(":", "_")
            add_scoped_file(_LOG_DIR / f"codex-retry-{legacy_name}.log", _LOG_DIR)

        if _CODEX_DIR.exists():
            for candidate in _CODEX_DIR.glob("codex-*.json"):
                try:
                    if not candidate.resolve().is_relative_to(_CODEX_DIR.resolve()):
                        continue
                    payload = json.loads(candidate.read_text(encoding="utf-8"))
                    if str(payload.get("email") or "").strip().lower() in accepted_emails:
                        files_to_delete.append(candidate.resolve())
                except Exception:
                    continue
        for job in removed_jobs:
            add_scoped_file(job.get("log_file"), _LOG_DIR)

        source_base_targets: dict[str, dict[int, set[int]]] = {
            "generic_api": {}, "outlook": {}, "icloud": {}, "mailcom": {},
        }
        for allocation in deleted_allocations:
            source = _email_allocation_source(allocation)
            if source not in source_base_targets:
                continue
            base_id = int(allocation.get("base_email_id") or 0)
            target_id = int(allocation.get("account_id") or 0)
            if target_id not in accepted_ids:
                target_id = accepted_emails.get(
                    str(allocation.get("actual_email") or "").lower(), 0,
                )
            if base_id:
                # Zero marks an allocation whose registration produced no
                # account. Its mailbox lease still needs to be released.
                source_base_targets[source].setdefault(base_id, set()).add(target_id)
        remaining_base_ids = {
            source: {
                int(allocation.get("base_email_id") or 0)
                for allocation in remaining_allocations
                if _email_allocation_source(allocation) == source
            }
            for source in source_base_targets
        }

        generic_rows = _load_generic_api_emails()
        outlook_rows = _load_outlook()
        icloud_rows = _load_icloud_emails()
        mailcom_rows = _load_mailcom()
        domain_rows = _load_domain_pool()

        def release_mailboxes(source: str, mailboxes: list[dict]) -> None:
            base_targets = source_base_targets[source]
            for mailbox in mailboxes:
                mailbox_id = int(mailbox.get("id") or 0)
                linked_ids = set(base_targets.get(mailbox_id, set()))
                registered_id = int(mailbox.get("registered_account_id") or 0)
                if registered_id in remaining_account_ids:
                    continue
                if registered_id in accepted_ids:
                    linked_ids.add(registered_id)
                email_target_id = accepted_emails.get(
                    str(mailbox.get("email") or "").lower(), 0,
                )
                if email_target_id:
                    linked_ids.add(email_target_id)
                if not linked_ids:
                    continue
                for key in (
                    "registered_account_id", "access_token", "totp_secret",
                    "account_copy_line", "completed_at",
                ):
                    mailbox.pop(key, None)
                if mailbox_id not in remaining_base_ids[source] and mailbox.get("status") != "disabled":
                    preserve_used = (
                        any(keep_mailbox_used.get(target_id, False) for target_id in linked_ids)
                        or bool(email_target_id)
                        or (mailbox.get("status") == "used" and bool(linked_ids & accepted_ids))
                        or mailbox_id in consumed_bases.get(source, set())
                    )
                    _release_deleted_account_mailbox(mailbox, keep_used=preserve_used)

        release_mailboxes("generic_api", generic_rows)
        release_mailboxes("outlook", outlook_rows)
        release_mailboxes("icloud", icloud_rows)
        release_mailboxes("mailcom", mailcom_rows)
        for mailbox in domain_rows:
            linked_ids: set[int] = set()
            registered_id = int(mailbox.get("registered_account_id") or 0)
            if registered_id in accepted_ids:
                linked_ids.add(registered_id)
            email_target_id = accepted_emails.get(str(mailbox.get("email") or "").lower(), 0)
            if email_target_id:
                linked_ids.add(email_target_id)
            if not linked_ids:
                continue
            for key in (
                "registered_account_id", "access_token", "totp_secret",
                "account_copy_line", "completed_at",
            ):
                mailbox.pop(key, None)
            if any(keep_mailbox_used.get(target_id, False) for target_id in linked_ids) and mailbox.get("status") != "disabled":
                mailbox["status"] = "used"
                mailbox["used_at"] = mailbox.get("used_at") or _now()
                mailbox["note"] = mailbox.get("note") or "关联账号已删除，邮箱保留为已用"

        candidate_batch_ids = {
            str(value)
            for value in (
                *(target.get("registration_batch_id") for target in accepted),
                *(job.get("batch_id") for job in removed_jobs),
                *(allocation.get("batch_id") for allocation in deleted_allocations),
            )
            if value
        }
        referenced_batch_ids = {
            str(value)
            for value in (
                *(job.get("batch_id") for job in remaining_jobs),
                *(row.get("registration_batch_id") for row in remaining_accounts),
                *(allocation.get("batch_id") for allocation in remaining_allocations),
            )
            if value
        }
        batches = _load_batches()
        remaining_batches = [
            batch for batch in batches
            if str(batch.get("batch_id") or "") not in _batch_ids and not (
                not _batch_ids
                and str(batch.get("batch_id") or "") in candidate_batch_ids
                and str(batch.get("batch_id") or "") not in referenced_batch_ids
            )
        ]

        if accepted:
            _save_accounts(remaining_accounts)
        _save_email_allocations(remaining_allocations)
        _save_generic_api_emails(generic_rows)
        _save_outlook(outlook_rows)
        _save_icloud_emails(icloud_rows)
        _save_mailcom(mailcom_rows)
        _save_domain_pool(domain_rows)
        _save_jobs(remaining_jobs)
        if len(remaining_batches) != len(batches):
            _save_batches(remaining_batches)

        export_state = _load_codex_export_state()
        removed_filenames = {
            path.name for path in files_to_delete
            if path.is_relative_to(_CODEX_DIR.resolve())
        }
        if removed_filenames & export_state.keys():
            _save_codex_export_state({
                name: value for name, value in export_state.items() if name not in removed_filenames
            })

    for path in set(files_to_delete):
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass
    return deleted, skipped


# ============================================================
# outlook_pool
# ============================================================

def import_outlook_accounts(records: list[dict]) -> tuple[int, int]:
    """
    批量导入 Outlook 账号。
    records 元素：{email, password, client_id, refresh_token}
    返回 (新增数, 跳过数)。
    """
    with _LOCK:
        rows = _load_outlook()
        inserted = skipped = 0
        for raw in records:
            email = (raw.get("email") or "").strip()
            if not email:
                skipped += 1
                continue
            if _find_by_email(rows, email):
                skipped += 1
                continue
            row = {
                "id": _next_id(rows),
                "email": email,
                "password": (raw.get("password") or "").strip(),
                "client_id": (raw.get("client_id") or raw.get("clientId") or "").strip(),
                "refresh_token": (raw.get("refresh_token") or raw.get("refreshToken") or "").strip(),
                "status": "available",
                "used_at": None,
                "note": None,
                "imported_at": _now(),
            }
            row["copy_line"] = _outlook_line(row)
            row["original_email_line"] = (
                str(raw.get("original_email_line") or "").strip() or row["copy_line"]
            )
            rows.append(row)
            inserted += 1
        _save_outlook(rows)
        return inserted, skipped


def import_registered_email_accounts(records: list[dict], source: str | None) -> tuple[int, int]:
    """
    把邮箱素材直接导入为“已注册成功账号”，用于跳过注册、直接在账号页补跑 Codex 授权。

    source:
      - outlook: records 元素 {email,password,client_id,refresh_token[,access_token,totp_secret]}
      - generic_api: records 元素 {email,code_url[,access_token,totp_secret]}
      - icloud: records 元素 {email,token,pickup_url[,access_token,totp_secret]}
      - mailcom: records 元素 {email,password[,access_token,totp_secret]}

    返回 (新增账号数, 跳过数)。已存在账号会跳过；邮箱池中已存在的素材会复用并标记 used。
    """
    source = (source or "").strip().lower()
    if source not in ("outlook", "generic_api", "icloud", "mailcom"):
        raise ValueError("source 必须显式传入 outlook / generic_api / icloud / mailcom")

    with _LOCK:
        accounts = _load_accounts()
        outlook_rows = _load_outlook()
        generic_rows = _load_generic_api_emails()
        icloud_rows = _load_icloud_emails()
        mailcom_rows = _load_mailcom()
        inserted = skipped = 0

        for raw in records:
            email = (raw.get("email") or "").strip()
            if not email:
                skipped += 1
                continue
            if _find_by_email(accounts, email):
                skipped += 1
                continue

            now = _now()
            provided_original_line = str(raw.get("original_email_line") or "").strip()
            original_line = provided_original_line or email
            pool_row = None

            if source == "generic_api":
                code_url = (raw.get("code_url") or raw.get("url") or "").strip()
                if not code_url:
                    skipped += 1
                    continue
                pool_row = _find_by_email(generic_rows, email)
                if pool_row is None:
                    pool_row = {
                        "id": _next_id(generic_rows),
                        "email": email,
                        "code_url": code_url,
                        "status": "used",
                        "used_at": now,
                        "note": "导入为已注册账号，用于 Codex 授权",
                        "imported_at": now,
                    }
                    generic_rows.append(pool_row)
                else:
                    pool_row["code_url"] = code_url or pool_row.get("code_url")
                pool_row["status"] = "used"
                pool_row["used_at"] = pool_row.get("used_at") or now
                pool_row["completed_at"] = pool_row.get("completed_at") or now
                pool_row["note"] = pool_row.get("note") or "导入为已注册账号，用于 Codex 授权"
                pool_row["copy_line"] = _generic_api_email_line(pool_row)
                pool_row["original_email_line"] = (
                    provided_original_line
                    or pool_row.get("original_email_line")
                    or pool_row["copy_line"]
                )
                original_line = pool_row["original_email_line"]
            elif source == "icloud":
                token = str(raw.get("token") or "").strip()
                pickup_url = str(raw.get("pickup_url") or raw.get("url") or "").strip()
                protocol = str(raw.get("protocol") or "").strip().lower()
                if not pickup_url or (not token and protocol != "generic_api"):
                    skipped += 1
                    continue
                pool_row = _find_by_email(icloud_rows, email)
                if pool_row is None:
                    pool_row = {
                        "id": _next_id(icloud_rows),
                        "email": email,
                        "token": token,
                        "pickup_url": pickup_url,
                        "protocol": protocol,
                        "status": "used",
                        "used_at": now,
                        "note": "导入为已注册账号，用于 Codex 授权",
                        "imported_at": now,
                    }
                    icloud_rows.append(pool_row)
                else:
                    pool_row["token"] = token or pool_row.get("token")
                    pool_row["pickup_url"] = pickup_url or pool_row.get("pickup_url")
                    pool_row["protocol"] = protocol or pool_row.get("protocol")
                pool_row["status"] = "used"
                pool_row["used_at"] = pool_row.get("used_at") or now
                pool_row["completed_at"] = pool_row.get("completed_at") or now
                pool_row["note"] = pool_row.get("note") or "导入为已注册账号，用于 Codex 授权"
                pool_row["copy_line"] = _icloud_email_line(pool_row)
                pool_row["original_email_line"] = (
                    provided_original_line
                    or pool_row.get("original_email_line")
                    or pool_row["copy_line"]
                )
                original_line = pool_row["original_email_line"]
            elif source == "mailcom":
                password = str(raw.get("password") or "").strip()
                if not password:
                    skipped += 1
                    continue
                pool_row = _find_by_email(mailcom_rows, email)
                if pool_row is None:
                    pool_row = {
                        "id": _next_id(mailcom_rows),
                        "email": email,
                        "password": password,
                        "status": "used",
                        "used_at": now,
                        "note": "导入为已注册账号，用于 Codex 授权",
                        "imported_at": now,
                    }
                    mailcom_rows.append(pool_row)
                else:
                    pool_row["password"] = password or pool_row.get("password")
                pool_row["status"] = "used"
                pool_row["used_at"] = pool_row.get("used_at") or now
                pool_row["completed_at"] = pool_row.get("completed_at") or now
                pool_row["note"] = pool_row.get("note") or "导入为已注册账号，用于 Codex 授权"
                pool_row["copy_line"] = _mailcom_line(pool_row)
                pool_row["original_email_line"] = (
                    provided_original_line
                    or pool_row.get("original_email_line")
                    or pool_row["copy_line"]
                )
                original_line = pool_row["original_email_line"]
            else:
                password = (raw.get("password") or "").strip()
                client_id = (raw.get("client_id") or raw.get("clientId") or "").strip()
                refresh_token = (raw.get("refresh_token") or raw.get("refreshToken") or "").strip()
                if not (password and client_id and refresh_token):
                    skipped += 1
                    continue
                pool_row = _find_by_email(outlook_rows, email)
                if pool_row is None:
                    pool_row = {
                        "id": _next_id(outlook_rows),
                        "email": email,
                        "password": password,
                        "client_id": client_id,
                        "refresh_token": refresh_token,
                        "status": "used",
                        "used_at": now,
                        "note": "导入为已注册账号，用于 Codex 授权",
                        "imported_at": now,
                    }
                    outlook_rows.append(pool_row)
                else:
                    pool_row["password"] = password or pool_row.get("password")
                    pool_row["client_id"] = client_id or pool_row.get("client_id")
                    pool_row["refresh_token"] = refresh_token or pool_row.get("refresh_token")
                pool_row["status"] = "used"
                pool_row["used_at"] = pool_row.get("used_at") or now
                pool_row["completed_at"] = pool_row.get("completed_at") or now
                pool_row["note"] = pool_row.get("note") or "导入为已注册账号，用于 Codex 授权"
                pool_row["copy_line"] = _outlook_line(pool_row)
                pool_row["original_email_line"] = (
                    provided_original_line
                    or pool_row.get("original_email_line")
                    or pool_row["copy_line"]
                )
                original_line = pool_row["original_email_line"]

            row_id = _next_id(accounts)
            # iCloud 的 token 是邮箱取码凭证，不能当成 ChatGPT Web AT。
            access_token = str(raw.get("access_token") or "").strip()
            totp_secret = (raw.get("totp_secret") or raw.get("totp") or "").strip() or None
            account = {
                "id": row_id,
                "email": email,
                "created_at": now,
                "access_token": access_token,
                "totp_secret": totp_secret,
                "user_id": raw.get("user_id"),
                "user_name": raw.get("user_name") or "Imported Account",
                "plan_type": raw.get("plan_type"),
                "expires_at": raw.get("expires_at"),
                "device_id": raw.get("device_id"),
                "proxy_used": raw.get("proxy_used"),
                "email_source": source,
                "extra_json": json.dumps({"imported_registered": True}, ensure_ascii=False),
                "codex_status": raw.get("codex_status") or "",
                "codex_error": raw.get("codex_error"),
                "updated_at": now,
                "original_email_line": original_line,
            }
            if source in {"outlook", "mailcom"}:
                account["password"] = pool_row.get("password")
            if source == "outlook":
                account["client_id"] = pool_row.get("client_id")
                account["refresh_token"] = pool_row.get("refresh_token")
            account["copy_line"] = _account_line(account)
            accounts.append(account)

            pool_row["registered_account_id"] = row_id
            pool_row["access_token"] = access_token
            if totp_secret:
                pool_row["totp_secret"] = totp_secret
            inserted += 1

        _save_outlook(outlook_rows)
        _save_generic_api_emails(generic_rows)
        _save_icloud_emails(icloud_rows)
        _save_mailcom(mailcom_rows)
        _save_accounts(accounts)
        return inserted, skipped


def claim_next_outlook() -> dict | None:
    """兼容无任务上下文的旧 CLI：领取后立即标记 used。"""
    with _LOCK:
        rows = sorted(_load_outlook(), key=lambda x: int(x.get("id") or 0))
        row = next((r for r in rows if r.get("status") == "available"), None)
        if row is None:
            return None
        row["status"] = "used"
        row["used_at"] = _now()
        row["note"] = None
        _save_outlook(rows)
        return _decorate_outlook(row)


def release_outlook(email: str, status: str = "available", note: str | None = None) -> bool:
    """把账号状态改回 available，或标记为 used/failed/disabled。"""
    with _LOCK:
        rows = _load_outlook()
        allocation = get_email_allocation_by_actual_email(email)
        if allocation and _email_allocation_source(allocation) != "outlook":
            allocation = None
        base_email = str((allocation or {}).get("base_email") or email)
        row = _find_by_email(rows, base_email)
        if row is None:
            return False
        if row.get("status") == "leased" and status != "leased":
            raise RuntimeError("邮箱存在活跃取码租约，不能直接修改状态")
        row["status"] = status
        if status == "available":
            row["used_at"] = None
        elif status in ("used", "failed", "disabled"):
            row["used_at"] = row.get("used_at") or _now()
        if note is not None:
            row["note"] = note
        _save_outlook(rows)
        return True


def release_unconsumed_outlook(email: str, note: str | None = None) -> bool:
    """原子回收未生成本地账号的 Outlook 领取或 Alias 租约。"""
    with _LOCK:
        if _find_by_email(_load_accounts(), email) is not None:
            return False
        allocation = get_email_allocation_by_actual_email(email)
        if allocation and _email_allocation_source(allocation) == "outlook" and allocation.get("status") == "leased":
            return complete_email_allocation(email, status="failed", error=note)
        rows = _load_outlook()
        base_email = str((allocation or {}).get("base_email") or email)
        row = _find_by_email(rows, base_email)
        if row is None or row.get("status") != "used":
            return False
        row["status"] = "available"
        row["used_at"] = None
        if note is not None:
            row["note"] = note
        _save_outlook(rows)
        return True


def delete_outlook(email: str) -> bool:
    """从邮箱池彻底删除一个邮箱（按 email 匹配）。返回是否删到。"""
    with _LOCK:
        rows = _load_outlook()
        target = (email or "").lower()
        row = _find_by_email(rows, target)
        if row is None or row.get("status") == "leased":
            return False
        allocations = [
            a for a in _load_email_allocations()
            if str(a.get("base_email") or "").lower() == target
            and _email_allocation_source(a) == "outlook"
        ]
        related_emails = {target}
        related_emails.update(str(a.get("actual_email") or "").lower() for a in allocations)
        account_ids = {int(a.get("account_id") or 0) for a in allocations if a.get("account_id")}
        if any(
            str(account.get("email") or "").lower() in related_emails
            or int(account.get("id") or 0) in account_ids
            for account in _load_accounts()
        ):
            return False
        if any(
            str(job.get("email") or "").lower() in related_emails
            and job.get("status") in {"pending", "running", "stopping"}
            for job in _load_jobs()
        ):
            return False
        new_rows = [r for r in rows if (r.get("email") or "").lower() != target]
        if len(new_rows) == len(rows):
            return False
        _save_outlook(new_rows)
        return True


def list_outlook_pool(status: str | None = None, limit: int = 500) -> list[dict]:
    with _LOCK:
        account_by_email = {
            (a.get("email") or "").lower(): a
            for a in _load_accounts()
        }
        rows = _load_outlook()
        allocations = [
            a for a in _load_email_allocations()
            if _email_allocation_source(a) == "outlook"
        ]
        counts = _allocation_counts(allocations, source="outlook")
        if status:
            rows = [r for r in rows if r.get("status") == status]
        rows = sorted(rows, key=lambda x: int(x.get("id") or 0), reverse=True)
        out = []
        for row in rows[:limit]:
            decorated = _decorate_outlook(row, account_by_email)
            base = str(row.get("email") or "").lower()
            base_allocations = [
                a for a in allocations if str(a.get("base_email") or "").lower() == base
            ]
            decorated["allocation_count"] = counts.get(base, 0)
            decorated["registered_count"] = sum(1 for a in base_allocations if a.get("status") == "registered")
            decorated["allocation_modes"] = sorted({
                str(a.get("mode") or "single") for a in base_allocations
            })
            decorated["email_modes"] = ["single"]
            if "+" not in base.partition("@")[0]:
                decorated["email_modes"].append("plus_alias")
            decorated["alias_claimable"] = (
                row.get("status") in {None, "", "available", "used"}
                and "plus_alias" in decorated["email_modes"]
            )
            decorated["single_count"] = sum(1 for a in base_allocations if a.get("mode") == "single")
            decorated["alias_count"] = sum(1 for a in base_allocations if a.get("mode") == "plus_alias")
            stored_limits = [
                int(a.get("alias_limit") or 0)
                for a in base_allocations
                if int(a.get("alias_limit") or 0) > 0
            ]
            decorated["last_alias_limit"] = stored_limits[-1] if stored_limits else None
            decorated["active_allocation"] = next((
                dict(a) for a in base_allocations if a.get("status") == "leased"
            ), None)
            out.append(decorated)
        return out


def outlook_pool_summary() -> dict:
    with _LOCK:
        out = {"available": 0, "used": 0, "failed": 0}
        for row in _load_outlook():
            status = row.get("status") or "available"
            out[status] = out.get(status, 0) + 1
        out["total"] = sum(v for k, v in out.items() if k != "total")
        return out


def get_outlook_by_email(email: str) -> dict | None:
    with _LOCK:
        rows = _load_outlook()
        row = _find_by_email(rows, email)
        allocation = None
        if row is None:
            candidate = get_email_allocation_by_actual_email(email)
            if candidate and _email_allocation_source(candidate) == "outlook":
                allocation = candidate
                row = _find_by_email(rows, str(candidate.get("base_email") or ""))
        if row is None:
            return None
        out = _decorate_outlook(row)
        if allocation:
            out["email"] = allocation.get("actual_email")
            out["base_email"] = allocation.get("base_email")
            out["allocation_id"] = allocation.get("id")
            out["email_mode"] = allocation.get("mode")
        return out


# ============================================================
# generic_api email pool
# ============================================================

def _parse_iso(value: object) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value or ""))
    except (TypeError, ValueError):
        return None


def _email_allocation_source(allocation: dict | None) -> str:
    """旧分配记录来自 generic_api；新记录显式保存来源。"""
    return str((allocation or {}).get("source") or "generic_api").strip().lower()


def _allocation_consumes_capacity(allocation: dict) -> bool:
    """Whether a historical allocation still occupies one provider slot."""
    if bool(allocation.get("slot_released")):
        return False
    return (
        allocation.get("status") != "failed"
        or bool(allocation.get("account_id"))
        or bool(allocation.get("provider_alias_created"))
    )


def _mailcom_alias_release_is_active(
    mailbox: dict,
    *,
    now: datetime | None = None,
) -> bool:
    if not bool(mailbox.get("alias_release_in_progress")):
        return False
    started_at = _parse_iso(mailbox.get("alias_release_started_at"))
    if started_at is None:
        return True
    current = now or datetime.now()
    try:
        return (current - started_at).total_seconds() < _MAILCOM_ALIAS_RELEASE_LOCK_SECONDS
    except TypeError:
        return True


def _email_pool_for_source(source: str) -> list[dict]:
    if source == "outlook":
        return _load_outlook()
    if source == "icloud":
        return _load_icloud_emails()
    if source == "mailcom":
        return _load_mailcom()
    return _load_generic_api_emails()


def _save_email_pool_for_source(source: str, rows: list[dict]) -> None:
    if source == "outlook":
        _save_outlook(rows)
    elif source == "icloud":
        _save_icloud_emails(rows)
    elif source == "mailcom":
        _save_mailcom(rows)
    else:
        _save_generic_api_emails(rows)


def _recover_expired_email_leases_locked(
    mailboxes: list[dict],
    allocations: list[dict],
    *,
    source: str | None = None,
    now: datetime | None = None,
) -> int:
    current = now or datetime.now()
    recovered = 0
    # Most claims have no expired lease. Do not load the large account store
    # (and replay its progress journal) just to allocate one available mailbox.
    accounts = None
    account_by_email = None

    def saved_account(email: str) -> dict | None:
        nonlocal accounts, account_by_email
        if account_by_email is None:
            accounts = _load_accounts()
            account_by_email = {}
            for account in accounts:
                account_by_email.setdefault(str(account.get("email") or "").lower(), account)
        return account_by_email.get(email.lower())

    accounts_changed = False
    for row in mailboxes:
        if row.get("status") != "leased":
            continue
        if source == "mailcom":
            active = _active_allocations_for_mailbox(
                allocations,
                source="mailcom",
                base_email_id=row.get("id"),
            )
            expired: list[dict] = []
            for allocation in active:
                expires = _parse_iso(allocation.get("lease_expires_at"))
                if expires is None and int(allocation.get("id") or 0) == int(
                    row.get("lease_allocation_id") or 0
                ):
                    expires = _parse_iso(row.get("lease_expires_at"))
                if expires is None or expires <= current:
                    expired.append(allocation)
            if not expired:
                _set_mailbox_active_lease(row, active)
                continue
            for allocation in expired:
                actual_email = str(allocation.get("actual_email") or "")
                account = saved_account(actual_email)
                if account is not None:
                    allocation["status"] = "registered"
                    allocation["account_id"] = account.get("id")
                    allocation["error"] = "进程中断后根据已保存账号恢复关联"
                    account["email_allocation_id"] = allocation.get("id")
                    account["updated_at"] = _now()
                    accounts_changed = True
                else:
                    allocation["status"] = "failed"
                    allocation["error"] = "进程中断或租约超时，已自动释放"
                allocation["completed_at"] = _now()
            remaining = _active_allocations_for_mailbox(
                allocations,
                source="mailcom",
                base_email_id=row.get("id"),
            )
            if remaining:
                _set_mailbox_active_lease(row, remaining)
            else:
                row["status"] = _mailbox_status_after_allocation(expired[-1])
                row["lease_job_id"] = None
                row["lease_allocation_id"] = None
                row["lease_expires_at"] = None
            recovered += 1
            continue
        expires = _parse_iso(row.get("lease_expires_at"))
        if expires and expires > current:
            continue
        allocation_id = int(row.get("lease_allocation_id") or 0)
        allocation = next((a for a in allocations if int(a.get("id") or 0) == allocation_id), None)
        if allocation and allocation.get("status") == "leased":
            actual_email = str(allocation.get("actual_email") or "")
            account = saved_account(actual_email)
            if account is not None:
                allocation["status"] = "registered"
                allocation["account_id"] = account.get("id")
                allocation["error"] = "进程中断后根据已保存账号恢复关联"
                account["email_allocation_id"] = allocation.get("id")
                account["updated_at"] = _now()
                accounts_changed = True
                row["status"] = _mailbox_status_after_allocation(allocation)
                if allocation.get("mode") == "single":
                    row["used_at"] = row.get("used_at") or _now()
            else:
                allocation["status"] = "failed"
                allocation["error"] = "进程中断或租约超时，已自动释放"
                row["status"] = _mailbox_status_after_allocation(allocation)
            allocation["completed_at"] = _now()
        else:
            row["status"] = "available"
        row["lease_job_id"] = None
        row["lease_allocation_id"] = None
        row["lease_expires_at"] = None
        recovered += 1
    if accounts_changed:
        _save_accounts(accounts)
    return recovered


def recover_expired_email_leases() -> int:
    with _LOCK:
        allocations = _load_email_allocations()
        recovered = 0
        for source in ("generic_api", "outlook", "icloud", "mailcom"):
            mailboxes = _email_pool_for_source(source)
            source_recovered = _recover_expired_email_leases_locked(
                mailboxes,
                allocations,
                source=source,
            )
            if source_recovered:
                _save_email_pool_for_source(source, mailboxes)
                recovered += source_recovered
        if recovered:
            _save_email_allocations(allocations)
        return recovered


def _allocation_counts(allocations: list[dict], *, source: str | None = None) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in allocations:
        if source and _email_allocation_source(row) != source:
            continue
        if bool(row.get("slot_released")):
            continue
        key = str(row.get("base_email") or "").lower()
        if key:
            counts[key] = counts.get(key, 0) + 1
    return counts


def _consumed_single_allocation_counts(
    allocations: list[dict], *, source: str
) -> dict[str, int]:
    """Count single-mode allocations that actually consumed the base address."""
    counts: dict[str, int] = {}
    for row in allocations:
        if _email_allocation_source(row) != source:
            continue
        if str(row.get("mode") or "single").strip().lower() != "single":
            continue
        # Failed leases without a saved account are retained for audit, but the
        # registration service explicitly returned their mailbox to available.
        if row.get("status") == "failed" and not row.get("account_id"):
            continue
        key = str(row.get("base_email") or "").strip().lower()
        if key:
            counts[key] = counts.get(key, 0) + 1
    return counts


def _single_allocation_bases_in_batch(
    allocations: list[dict], *, source: str, batch_id: str | None
) -> set[str]:
    """Return base addresses already attempted in one explicit registration batch."""
    target_batch = str(batch_id or "").strip()
    if not target_batch:
        # Legacy/CLI callers without a batch keep the historical reclaim behavior.
        return set()

    return {
        str(row.get("base_email") or "").strip().lower()
        for row in allocations
        if _email_allocation_source(row) == source
        and str(row.get("mode") or "single").strip().lower() == "single"
        and str(row.get("batch_id") or "").strip() == target_batch
        and str(row.get("base_email") or "").strip()
    }


def _plus_alias_base_cooldown_seconds() -> int:
    from config.email import PLUS_ALIAS_BASE_COOLDOWN_SECONDS

    try:
        return max(0, int(PLUS_ALIAS_BASE_COOLDOWN_SECONDS or 0))
    except (TypeError, ValueError):
        return 300


def _plus_alias_allocation_stats(
    allocations: list[dict], *, source: str
) -> dict[str, dict[str, Any]]:
    """汇总基础邮箱的 Alias 历史、最近活动和所有模式的活跃租约。"""
    stats: dict[str, dict[str, Any]] = {}
    for allocation in allocations:
        if _email_allocation_source(allocation) != source:
            continue
        base_email = str(allocation.get("base_email") or "").strip().lower()
        if not base_email:
            continue
        item = stats.setdefault(base_email, {
            "alias_count": 0,
            "last_allocated_at": None,
            "last_activity_at": None,
            "active_lease": False,
        })
        if str(allocation.get("mode") or "").strip().lower() == "plus_alias":
            item["alias_count"] += 1
        if allocation.get("status") == "leased":
            item["active_lease"] = True
        created_at = _parse_iso(allocation.get("created_at"))
        last_allocated_at = item["last_allocated_at"]
        if created_at and (
            last_allocated_at is None
            or created_at.timestamp() > last_allocated_at.timestamp()
        ):
            item["last_allocated_at"] = created_at
        for field in ("created_at", "completed_at", "lease_renewed_at"):
            timestamp = _parse_iso(allocation.get(field))
            current = item["last_activity_at"]
            if timestamp and (current is None or timestamp.timestamp() > current.timestamp()):
                item["last_activity_at"] = timestamp
    return stats


def _select_plus_alias_mailbox(
    mailboxes: list[dict],
    allocations: list[dict],
    *,
    source: str,
    ceiling: int,
    claimable_statuses: set[str | None],
    allow_active_lease: bool = False,
    bypass_cooldown: bool = False,
    count_failed_allocations: bool = True,
    now: datetime | None = None,
) -> dict | None:
    """公平选择 Alias 基础邮箱；调用方必须持有 _LOCK。"""
    capacity_allocations = [
        allocation
        for allocation in allocations
        if not bool(allocation.get("slot_released"))
        and (count_failed_allocations or _allocation_consumes_capacity(allocation))
    ]
    allocation_counts = _allocation_counts(capacity_allocations, source=source)
    stats = _plus_alias_allocation_stats(capacity_allocations, source=source)
    current_timestamp = (now or datetime.now()).timestamp()
    cooldown_seconds = _plus_alias_base_cooldown_seconds()
    candidates: list[tuple[int, float, int, dict]] = []

    for row in mailboxes:
        if row.get("status") not in claimable_statuses:
            continue
        if source == "mailcom" and _mailcom_alias_release_is_active(row, now=now):
            continue
        base_email = str(row.get("email") or "").strip().lower()
        if not base_email or "+" in base_email.partition("@")[0]:
            continue
        if allocation_counts.get(base_email, 0) >= ceiling:
            continue

        item = stats.get(base_email, {})
        if item.get("active_lease") and not allow_active_lease:
            continue
        last_allocated_at = item.get("last_allocated_at")
        last_activity_at = item.get("last_activity_at")
        row_last_used_at = _parse_iso(row.get("last_used_at"))
        if row_last_used_at and (
            last_allocated_at is None
            or row_last_used_at.timestamp() > last_allocated_at.timestamp()
        ):
            last_allocated_at = row_last_used_at
        if row_last_used_at and (
            last_activity_at is None
            or row_last_used_at.timestamp() > last_activity_at.timestamp()
        ):
            last_activity_at = row_last_used_at
        last_timestamp = (
            last_allocated_at.timestamp()
            if last_allocated_at is not None
            else float("-inf")
        )
        cooldown_timestamp = (
            last_activity_at.timestamp()
            if last_activity_at is not None
            else last_timestamp
        )
        if (
            not bypass_cooldown
            and cooldown_seconds
            and current_timestamp - cooldown_timestamp < cooldown_seconds
        ):
            continue
        candidates.append((
            int(item.get("alias_count") or 0),
            last_timestamp,
            int(row.get("id") or 0),
            row,
        ))

    return min(candidates, key=lambda item: item[:3])[3] if candidates else None


def _new_plus_alias(base_email: str, allocations: list[dict]) -> str:
    local, sep, domain = str(base_email or "").strip().lower().partition("@")
    if not sep or not local or not domain or "+" in local:
        raise ValueError(f"基础邮箱不支持 Plus alias: {base_email}")
    existing = {str(r.get("actual_email") or "").lower() for r in allocations}
    for _ in range(50):
        candidate = f"{local}+oai{secrets.token_hex(3)}@{domain}"
        if candidate not in existing:
            return candidate
    raise RuntimeError("生成唯一 Plus alias 失败")


def _new_mailcom_alias(base_email: str, allocations: list[dict]) -> str:
    """Generate a Mail.com-managed alias local part, not a plus-address tag."""
    local, sep, domain = str(base_email or "").strip().lower().partition("@")
    if not sep or not local or not domain:
        raise ValueError(f"Mail.com 基础邮箱格式无效: {base_email}")
    existing = {str(row.get("actual_email") or "").lower() for row in allocations}
    for _ in range(50):
        suffix = secrets.token_hex(3)
        prefix = local[:max(1, 64 - len(suffix) - len("-split-"))]
        candidate = f"{prefix}-split-{suffix}@{domain}"
        if candidate not in existing:
            return candidate
    raise RuntimeError("生成唯一 Mail.com Alias 失败")


def _mailbox_status_after_allocation(allocation: dict) -> str:
    """结束租约后恢复基础邮箱状态；已注册过的 Outlook 基础地址继续保持 used。"""
    if allocation.get("mode") == "single":
        return "used"
    return "used" if allocation.get("base_status_before_lease") == "used" else "available"


def _active_allocations_for_mailbox(
    allocations: list[dict],
    *,
    source: str,
    base_email_id: object,
) -> list[dict]:
    target_id = int(base_email_id or 0)
    return [
        allocation
        for allocation in allocations
        if _email_allocation_source(allocation) == source
        and int(allocation.get("base_email_id") or 0) == target_id
        and allocation.get("status") == "leased"
    ]


def _set_mailbox_active_lease(mailbox: dict, active: list[dict]) -> None:
    """Point legacy mailbox lease fields at one of its active allocations."""
    if not active:
        return
    selected = max(
        active,
        key=lambda allocation: (
            str(allocation.get("lease_expires_at") or ""),
            int(allocation.get("id") or 0),
        ),
    )
    mailbox["status"] = "leased"
    mailbox["lease_job_id"] = selected.get("job_id")
    mailbox["lease_allocation_id"] = selected.get("id")
    mailbox["lease_expires_at"] = selected.get("lease_expires_at")


def claim_outlook_email(
    *,
    mode: str = "single",
    alias_limit: int | None = None,
    job_id: int | None = None,
    batch_id: str | None = None,
) -> dict | None:
    """原子领取 Outlook 基础邮箱；Alias 只改变注册地址，凭证仍属于基础邮箱。"""
    selected_mode = str(mode or "single").strip().lower()
    if selected_mode not in {"single", "plus_alias"}:
        raise ValueError("email_mode 仅支持 single / plus_alias")
    if selected_mode == "plus_alias":
        try:
            ceiling = int(alias_limit or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("alias_limit 必须是正整数") from exc
        if ceiling <= 0:
            raise ValueError("alias_limit 必须是正整数")
    else:
        ceiling = 1

    with _LOCK:
        mailboxes = _load_outlook()
        allocations = _load_email_allocations()
        recovered = _recover_expired_email_leases_locked(mailboxes, allocations)
        if recovered:
            _save_outlook(mailboxes)
            _save_email_allocations(allocations)
        selected = None
        if selected_mode == "plus_alias":
            selected = _select_plus_alias_mailbox(
                mailboxes,
                allocations,
                source="outlook",
                ceiling=ceiling,
                claimable_statuses={None, "", "available", "used"},
            )
        else:
            counts = _consumed_single_allocation_counts(
                allocations, source="outlook"
            )
            attempted_in_batch = _single_allocation_bases_in_batch(
                allocations, source="outlook", batch_id=batch_id
            )
            for row in sorted(mailboxes, key=lambda r: int(r.get("id") or 0)):
                if row.get("status") not in {None, "", "available"}:
                    continue
                base = str(row.get("email") or "").strip().lower()
                if base in attempted_in_batch or counts.get(base, 0) >= ceiling:
                    continue
                selected = row
                break
        if selected is None:
            return None

        base_email = str(selected.get("email") or "").strip().lower()
        actual_email = base_email if selected_mode == "single" else _new_plus_alias(base_email, allocations)
        allocation = {
            "id": _next_id(allocations),
            "source": "outlook",
            "base_email_id": selected.get("id"),
            "base_email": base_email,
            "actual_email": actual_email,
            "mode": selected_mode,
            "base_status_before_lease": selected.get("status") or "available",
            "alias_limit": ceiling,
            "job_id": job_id,
            "batch_id": batch_id,
            "account_id": None,
            "status": "leased",
            "error": None,
            "created_at": _now(),
            "completed_at": None,
        }
        allocations.append(allocation)
        expires = datetime.now() + timedelta(minutes=_EMAIL_LEASE_MINUTES)
        selected["status"] = "leased"
        selected["lease_job_id"] = job_id
        selected["lease_allocation_id"] = allocation["id"]
        selected["lease_expires_at"] = expires.isoformat(timespec="seconds")
        selected["last_used_at"] = _now()
        selected["note"] = None
        _save_outlook(mailboxes)
        _save_email_allocations(allocations)
        out = _decorate_outlook(selected)
        out.update({
            "email": actual_email,
            "base_email": base_email,
            "allocation_id": allocation["id"],
            "email_mode": selected_mode,
        })
        return out


def claim_generic_api_email(
    *,
    mode: str = "single",
    alias_limit: int | None = None,
    job_id: int | None = None,
    batch_id: str | None = None,
) -> dict | None:
    """原子领取 URL 邮箱并创建分配记录；同一基础邮箱一次只发一个租约。"""
    selected_mode = str(mode or "single").strip().lower()
    if selected_mode not in {"single", "plus_alias"}:
        raise ValueError("email_mode 仅支持 single / plus_alias")
    if selected_mode == "plus_alias":
        try:
            ceiling = int(alias_limit or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("alias_limit 必须是正整数") from exc
        if ceiling <= 0:
            raise ValueError("alias_limit 必须是正整数")
    else:
        ceiling = 1

    with _LOCK:
        mailboxes = _load_generic_api_emails()
        allocations = _load_email_allocations()
        recovered = _recover_expired_email_leases_locked(mailboxes, allocations)
        if recovered:
            _save_generic_api_emails(mailboxes)
            _save_email_allocations(allocations)
        selected = None
        if selected_mode == "plus_alias":
            selected = _select_plus_alias_mailbox(
                mailboxes,
                allocations,
                source="generic_api",
                ceiling=ceiling,
                claimable_statuses={None, "", "available"},
            )
        else:
            counts = _consumed_single_allocation_counts(
                allocations, source="generic_api"
            )
            attempted_in_batch = _single_allocation_bases_in_batch(
                allocations, source="generic_api", batch_id=batch_id
            )
            for row in sorted(mailboxes, key=lambda r: int(r.get("id") or 0)):
                if row.get("status") not in {None, "", "available"}:
                    continue
                base = str(row.get("email") or "").lower()
                used = counts.get(base, 0)
                if base in attempted_in_batch or used >= ceiling:
                    continue
                selected = row
                break
        if selected is None:
            return None

        base_email = str(selected.get("email") or "").strip().lower()
        actual_email = base_email if selected_mode == "single" else _new_plus_alias(base_email, allocations)
        allocation = {
            "id": _next_id(allocations),
            "source": "generic_api",
            "base_email_id": selected.get("id"),
            "base_email": base_email,
            "actual_email": actual_email,
            "mode": selected_mode,
            "alias_limit": ceiling,
            "job_id": job_id,
            "batch_id": batch_id,
            "account_id": None,
            "status": "leased",
            "error": None,
            "created_at": _now(),
            "completed_at": None,
        }
        allocations.append(allocation)
        expires = datetime.now() + timedelta(minutes=_EMAIL_LEASE_MINUTES)
        selected["status"] = "leased"
        selected["lease_job_id"] = job_id
        selected["lease_allocation_id"] = allocation["id"]
        selected["lease_expires_at"] = expires.isoformat(timespec="seconds")
        selected["last_used_at"] = _now()
        _save_generic_api_emails(mailboxes)
        _save_email_allocations(allocations)
        out = _decorate_generic_api_email(selected)
        out.update({
            "email": actual_email,
            "base_email": base_email,
            "allocation_id": allocation["id"],
            "email_mode": selected_mode,
        })
        return out


def complete_email_allocation(
    actual_email: str,
    *,
    account_id: int | None = None,
    status: str = "registered",
    error: str | None = None,
) -> bool:
    with _LOCK:
        allocations = _load_email_allocations()
        target = str(actual_email or "").lower()
        accounts: list[dict] | None = None
        linked_account: dict | None = None
        allocation = next((
            r for r in reversed(allocations)
            if str(r.get("actual_email") or "").lower() == target and r.get("status") == "leased"
        ), None)
        # A restart can settle a live lease as failed while the old worker is
        # already committing the account. Permit that worker (or reconciliation)
        # to repair the terminal allocation only when a persisted account id and
        # email prove that registration actually completed.
        if allocation is None and status == "registered" and account_id is not None:
            accounts = _load_accounts()
            linked_account = next((
                row for row in accounts
                if int(row.get("id") or 0) == int(account_id)
                and str(row.get("email") or "").strip().lower() == target
            ), None)
            if linked_account is not None:
                linked_allocation_id = int(linked_account.get("email_allocation_id") or 0)
                candidates = [
                    row for row in allocations
                    if str(row.get("actual_email") or "").strip().lower() == target
                ]
                if linked_allocation_id:
                    allocation = next((
                        row for row in reversed(candidates)
                        if int(row.get("id") or 0) == linked_allocation_id
                    ), None)
                if allocation is None and candidates:
                    allocation = candidates[-1]
        if allocation is None:
            return False
        source = _email_allocation_source(allocation)
        mailboxes = _email_pool_for_source(source)
        allocation["status"] = status
        allocation["account_id"] = account_id
        allocation["error"] = error
        allocation["completed_at"] = _now()
        mailbox = next((r for r in mailboxes if int(r.get("id") or 0) == int(allocation.get("base_email_id") or 0)), None)
        if mailbox:
            remaining = _active_allocations_for_mailbox(
                allocations,
                source=source,
                base_email_id=allocation.get("base_email_id"),
            )
            if source == "mailcom" and remaining:
                _set_mailbox_active_lease(mailbox, remaining)
            else:
                mailbox["lease_job_id"] = None
                mailbox["lease_allocation_id"] = None
                mailbox["lease_expires_at"] = None
                mailbox["status"] = _mailbox_status_after_allocation(allocation)
                if allocation.get("mode") == "single":
                    mailbox["used_at"] = mailbox.get("used_at") or _now()
                if status == "registered":
                    mailbox["note"] = None
                else:
                    mailbox["note"] = error
        _save_email_pool_for_source(source, mailboxes)
        _save_email_allocations(allocations)
        if account_id is not None:
            accounts = accounts if accounts is not None else _load_accounts()
            account = linked_account or next((
                r for r in accounts if int(r.get("id") or 0) == int(account_id)
            ), None)
            if account:
                account["email_allocation_id"] = allocation.get("id")
                account["updated_at"] = _now()
                _save_accounts(accounts)
        return True


def renew_email_allocation_lease(actual_email: str) -> bool:
    """续期正在取码的基础邮箱租约，防止长流程被并发 Alias 任务抢占。"""
    with _LOCK:
        target = str(actual_email or "").strip().lower()
        if not target:
            return False
        allocations = _load_email_allocations()
        allocation = next((
            row for row in reversed(allocations)
            if str(row.get("actual_email") or "").lower() == target and row.get("status") == "leased"
        ), None)
        if allocation is None:
            return False
        source = _email_allocation_source(allocation)
        mailboxes = _email_pool_for_source(source)
        mailbox = next((
            row for row in mailboxes
            if int(row.get("id") or 0) == int(allocation.get("base_email_id") or 0)
        ), None)
        if mailbox is None or mailbox.get("status") != "leased":
            return False
        expires = datetime.now() + timedelta(minutes=_EMAIL_LEASE_MINUTES)
        allocation["lease_expires_at"] = expires.isoformat(timespec="seconds")
        allocation["lease_renewed_at"] = _now()
        if source == "mailcom":
            active = _active_allocations_for_mailbox(
                allocations,
                source=source,
                base_email_id=allocation.get("base_email_id"),
            )
            _set_mailbox_active_lease(mailbox, active)
        else:
            mailbox["lease_expires_at"] = allocation["lease_expires_at"]
        _save_email_pool_for_source(source, mailboxes)
        _save_email_allocations(allocations)
        return True


def get_email_allocation_by_actual_email(email: str) -> dict | None:
    with _LOCK:
        target = str(email or "").lower()
        row = next((r for r in reversed(_load_email_allocations()) if str(r.get("actual_email") or "").lower() == target), None)
        return dict(row) if row else None


# ============================================================
# Mail.com email pool
# ============================================================

def import_mailcom_accounts(records: list[dict]) -> tuple[int, int]:
    """Import Mail.com IMAP credentials in ``email----password`` form."""
    with _LOCK:
        rows = _load_mailcom()
        inserted = skipped = 0
        for raw in records:
            email_address = str(raw.get("email") or "").strip()
            password = str(raw.get("password") or "").strip()
            if not email_address or not password or _find_by_email(rows, email_address):
                skipped += 1
                continue
            row = {
                "id": _next_id(rows),
                "email": email_address,
                "password": password,
                "status": "available",
                "used_at": None,
                "note": None,
                "imported_at": _now(),
            }
            row["copy_line"] = _mailcom_line(row)
            row["original_email_line"] = (
                str(raw.get("original_email_line") or "").strip() or row["copy_line"]
            )
            rows.append(row)
            inserted += 1
        _save_mailcom(rows)
        return inserted, skipped


def mark_mailcom_web_login_state(
    base_email: str,
    status: str,
    error: str | None = None,
) -> bool:
    """Record Web-login health without changing allocation/account ownership."""
    normalized_status = str(status or "").strip().lower()
    if normalized_status not in {"ready", "verification_required", "interception_required"}:
        raise ValueError("Mail.com Web 登录状态无效")
    with _LOCK:
        rows = _load_mailcom()
        row = _find_by_email(rows, str(base_email or "").strip().lower())
        if row is None:
            return False
        rendered_error = str(error or "").strip()[:300] or None
        if normalized_status == "ready":
            rendered_error = None
        if (
            str(row.get("web_login_status") or "") == normalized_status
            and row.get("web_login_error") == rendered_error
        ):
            return True
        row["web_login_status"] = normalized_status
        row["web_login_error"] = rendered_error
        row["web_login_checked_at"] = _now()
        _save_mailcom(rows)
        return True


def _mailcom_web_login_is_blocked(row: dict) -> bool:
    return str(row.get("web_login_status") or "").strip().lower() in {
        "verification_required", "interception_required",
    }


def claim_mailcom_email(
    *,
    mode: str = "single",
    alias_limit: int | None = None,
    job_id: int | None = None,
    batch_id: str | None = None,
) -> dict | None:
    """Lease one Mail.com address within the configured provider cap."""
    from config.email import MAILCOM_ALIAS_MAX

    provider_ceiling = max(1, min(10, int(MAILCOM_ALIAS_MAX or 7)))
    selected_mode = str(mode or "single").strip().lower()
    if selected_mode not in {"single", "plus_alias"}:
        raise ValueError("email_mode 仅支持 single / plus_alias")
    if selected_mode == "plus_alias":
        try:
            requested_ceiling = int(alias_limit or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("alias_limit 必须是正整数") from exc
        if requested_ceiling <= 0:
            raise ValueError("alias_limit 必须是正整数")
        ceiling = min(provider_ceiling, requested_ceiling)
    else:
        ceiling = 1

    with _LOCK:
        mailboxes = _load_mailcom()
        allocations = _load_email_allocations()
        recovered = _recover_expired_email_leases_locked(
            mailboxes,
            allocations,
            source="mailcom",
        )
        if recovered:
            _save_mailcom(mailboxes)
            _save_email_allocations(allocations)
        selected = None
        if selected_mode == "plus_alias":
            selected = _select_plus_alias_mailbox(
                [row for row in mailboxes if not _mailcom_web_login_is_blocked(row)],
                allocations,
                source="mailcom",
                ceiling=ceiling,
                claimable_statuses={None, "", "available", "used", "leased"},
                allow_active_lease=True,
                bypass_cooldown=True,
                count_failed_allocations=False,
            )
        else:
            counts = _consumed_single_allocation_counts(allocations, source="mailcom")
            attempted_in_batch = _single_allocation_bases_in_batch(
                allocations,
                source="mailcom",
                batch_id=batch_id,
            )
            for row in sorted(mailboxes, key=lambda item: int(item.get("id") or 0)):
                if row.get("status") not in {None, "", "available"}:
                    continue
                if _mailcom_web_login_is_blocked(row):
                    continue
                if _mailcom_alias_release_is_active(row):
                    continue
                base = str(row.get("email") or "").strip().lower()
                if base in attempted_in_batch or counts.get(base, 0) >= 1:
                    continue
                selected = row
                break
        if selected is None:
            return None

        base_email = str(selected.get("email") or "").strip().lower()
        actual_email = (
            base_email
            if selected_mode == "single"
            else _new_mailcom_alias(base_email, allocations)
        )
        active = _active_allocations_for_mailbox(
            allocations,
            source="mailcom",
            base_email_id=selected.get("id"),
        )
        base_status_before_lease = (
            active[0].get("base_status_before_lease")
            if active
            else selected.get("status") or "available"
        )
        expires_at = (
            datetime.now() + timedelta(minutes=_EMAIL_LEASE_MINUTES)
        ).isoformat(timespec="seconds")
        allocation = {
            "id": _next_id(allocations),
            "source": "mailcom",
            "base_email_id": selected.get("id"),
            "base_email": base_email,
            "actual_email": actual_email,
            "mode": selected_mode,
            "base_status_before_lease": base_status_before_lease,
            "alias_limit": ceiling,
            "job_id": job_id,
            "batch_id": batch_id,
            "account_id": None,
            "status": "leased",
            "error": None,
            "created_at": _now(),
            "completed_at": None,
            "lease_expires_at": expires_at,
            "provider_alias_created": False,
            "provider_alias_deleted": False,
            "slot_released": False,
        }
        allocations.append(allocation)
        _set_mailbox_active_lease(selected, [*active, allocation])
        selected["last_used_at"] = _now()
        selected["note"] = None
        _save_mailcom(mailboxes)
        _save_email_allocations(allocations)
        out = _decorate_mailcom(selected)
        out.update({
            "email": actual_email,
            "base_email": base_email,
            "allocation_id": allocation["id"],
            "email_mode": selected_mode,
        })
        return out


def mark_mailcom_alias_created(email_address: str) -> bool:
    """Persist that a reserved address now exists in the Mail.com account."""
    with _LOCK:
        target = str(email_address or "").strip().lower()
        allocations = _load_email_allocations()
        allocation = next((
            row
            for row in reversed(allocations)
            if _email_allocation_source(row) == "mailcom"
            and str(row.get("actual_email") or "").strip().lower() == target
        ), None)
        if allocation is None:
            return False
        allocation["provider_alias_created"] = True
        allocation["provider_alias_created_at"] = allocation.get(
            "provider_alias_created_at"
        ) or _now()
        _save_email_allocations(allocations)
        return True


def release_mailcom_email(
    email_address: str,
    status: str = "available",
    note: str | None = None,
) -> bool:
    with _LOCK:
        rows = _load_mailcom()
        allocation = get_email_allocation_by_actual_email(email_address)
        if allocation and _email_allocation_source(allocation) != "mailcom":
            allocation = None
        base_email = str((allocation or {}).get("base_email") or email_address)
        row = _find_by_email(rows, base_email)
        if row is None:
            return False
        if row.get("status") == "leased" and status != "leased":
            raise RuntimeError("邮箱存在活跃取码租约，不能直接修改状态")
        row["status"] = status
        if status == "available":
            row["used_at"] = None
        elif status in {"used", "failed", "disabled"}:
            row["used_at"] = row.get("used_at") or _now()
        if note is not None:
            row["note"] = note
        _save_mailcom(rows)
        return True


def release_unconsumed_mailcom_email(email_address: str, note: str | None = None) -> bool:
    with _LOCK:
        if _find_by_email(_load_accounts(), email_address) is not None:
            return False
        allocation = get_email_allocation_by_actual_email(email_address)
        if (
            allocation
            and _email_allocation_source(allocation) == "mailcom"
            and allocation.get("status") == "leased"
        ):
            return complete_email_allocation(email_address, status="failed", error=note)
        rows = _load_mailcom()
        base_email = str((allocation or {}).get("base_email") or email_address)
        row = _find_by_email(rows, base_email)
        if row is None or row.get("status") != "used":
            return False
        row["status"] = "available"
        row["used_at"] = None
        if note is not None:
            row["note"] = note
        _save_mailcom(rows)
        return True


def _mailcom_alias_active_task_reason(
    allocation: dict,
    *,
    jobs: list[dict],
    accounts: list[dict],
) -> str | None:
    if allocation.get("status") == "leased":
        return "Alias 存在活跃取码租约"
    actual_email = str(allocation.get("actual_email") or "").strip().lower()
    allocation_job_id = int(allocation.get("job_id") or 0)
    allocation_account_id = int(allocation.get("account_id") or 0)
    if any(
        job.get("status") in {"pending", "running", "stopping"}
        and (
            str(job.get("email") or "").strip().lower() == actual_email
            or (allocation_job_id and int(job.get("id") or 0) == allocation_job_id)
            or (
                allocation_account_id
                and int(job.get("account_id") or 0) == allocation_account_id
            )
        )
        for job in jobs
    ):
        return "Alias 仍有关联运行任务"
    account = next((
        item
        for item in accounts
        if (
            allocation_account_id
            and int(item.get("id") or 0) == allocation_account_id
        )
        or str(item.get("email") or "").strip().lower() == actual_email
    ), None)
    if account and (
        str(account.get("codex_status") or "").strip().lower()
        in {"queued", "retrying", "running"}
        or str(account.get("codex_agent_status") or "").strip().lower()
        in {"queued", "retrying", "running"}
    ):
        return "Alias 的 Codex 接码任务仍在执行"
    return None


def prepare_mailcom_alias_slot_release(base_email: str) -> dict:
    """Lock one base mailbox and snapshot aliases that can be removed remotely.

    Persisted accounts are deliberately allowed. Their allocation history stays
    intact and continues to feed promotion statistics after the slot is released.
    """
    with _LOCK:
        target = str(base_email or "").strip().lower()
        mailboxes = _load_mailcom()
        mailbox = _find_by_email(mailboxes, target)
        if mailbox is None:
            raise LookupError("Mail.com 母号不存在")
        if _mailcom_alias_release_is_active(mailbox):
            raise RuntimeError("该 Mail.com 母号正在释放 Alias 槽位")

        allocations = _load_email_allocations()
        jobs = _load_jobs()
        accounts = _load_accounts()
        candidates: list[dict] = []
        skipped: list[dict] = []
        for allocation in allocations:
            if (
                _email_allocation_source(allocation) != "mailcom"
                or str(allocation.get("base_email") or "").strip().lower() != target
                or str(allocation.get("mode") or "single").strip().lower() != "plus_alias"
                or bool(allocation.get("slot_released"))
                or not _allocation_consumes_capacity(allocation)
            ):
                continue
            actual_email = str(allocation.get("actual_email") or "").strip().lower()
            if not actual_email or actual_email == target:
                continue
            reason = _mailcom_alias_active_task_reason(
                allocation,
                jobs=jobs,
                accounts=accounts,
            )
            item = {
                "allocation_id": int(allocation.get("id") or 0),
                "email": actual_email,
                "status": str(allocation.get("status") or ""),
                "has_account": bool(allocation.get("account_id")) or any(
                    str(account.get("email") or "").strip().lower() == actual_email
                    for account in accounts
                ),
            }
            if reason:
                skipped.append({**item, "reason": reason})
            else:
                candidates.append(item)

        if not candidates:
            return {
                "base_email": target,
                "release_id": None,
                "candidates": [],
                "skipped": skipped,
            }

        release_id = uuid.uuid4().hex
        mailbox["alias_release_in_progress"] = True
        mailbox["alias_release_id"] = release_id
        mailbox["alias_release_started_at"] = _now()
        mailbox["alias_release_last_error"] = None
        _save_mailcom(mailboxes)
        return {
            "base_email": target,
            "release_id": release_id,
            "candidates": candidates,
            "skipped": skipped,
        }


def finalize_mailcom_alias_slot_release(
    base_email: str,
    release_id: str,
    results: list[dict],
    *,
    fatal_error: str | None = None,
) -> dict:
    """Persist provider outcomes and always release the base-mailbox lock."""
    with _LOCK:
        target = str(base_email or "").strip().lower()
        mailboxes = _load_mailcom()
        mailbox = _find_by_email(mailboxes, target)
        if mailbox is None:
            raise LookupError("Mail.com 母号不存在")
        if str(mailbox.get("alias_release_id") or "") != str(release_id or ""):
            raise RuntimeError("Mail.com Alias 释放事务已失效，请刷新后重试")

        allocations = _load_email_allocations()
        result_rows: list[dict] = []
        now = _now()
        changed = False
        for raw in results or []:
            allocation_id = int(raw.get("allocation_id") or 0)
            actual_email = str(raw.get("email") or "").strip().lower()
            outcome = str(raw.get("status") or "failed").strip().lower()
            allocation = next((
                item
                for item in allocations
                if int(item.get("id") or 0) == allocation_id
                and _email_allocation_source(item) == "mailcom"
                and str(item.get("base_email") or "").strip().lower() == target
                and str(item.get("actual_email") or "").strip().lower() == actual_email
            ), None)
            if allocation is None:
                result_rows.append({
                    "allocation_id": allocation_id,
                    "email": actual_email,
                    "status": "failed",
                    "error": "本地分配记录不存在",
                })
                continue
            if outcome in {"deleted", "missing"}:
                allocation["provider_alias_deleted"] = True
                allocation["provider_alias_deleted_at"] = now
                allocation["provider_alias_delete_result"] = outcome
                allocation["slot_released"] = True
                allocation["slot_released_at"] = now
                allocation["slot_release_error"] = None
                changed = True
                result_rows.append({
                    "allocation_id": allocation_id,
                    "email": actual_email,
                    "status": outcome,
                })
            else:
                error = str(raw.get("error") or "远端删除失败")
                allocation["slot_release_error"] = error
                allocation["slot_release_failed_at"] = now
                changed = True
                result_rows.append({
                    "allocation_id": allocation_id,
                    "email": actual_email,
                    "status": "failed",
                    "error": error,
                })

        mailbox["alias_release_in_progress"] = False
        mailbox["alias_release_id"] = None
        mailbox["alias_release_started_at"] = None
        mailbox["alias_release_last_completed_at"] = now
        mailbox["alias_release_last_error"] = str(fatal_error or "") or None
        mailbox["alias_release_last_released_count"] = sum(
            row.get("status") in {"deleted", "missing"} for row in result_rows
        )
        mailbox["alias_release_last_failed_count"] = sum(
            row.get("status") == "failed" for row in result_rows
        )
        if changed:
            _save_email_allocations(allocations)
        _save_mailcom(mailboxes)
        return {
            "base_email": target,
            "released_count": int(mailbox["alias_release_last_released_count"]),
            "failed_count": int(mailbox["alias_release_last_failed_count"]),
            "results": result_rows,
            "error": mailbox.get("alias_release_last_error"),
        }


def mailcom_delete_block_reason(email_address: str) -> str | None:
    with _LOCK:
        target = str(email_address or "").strip().lower()
        row = _find_by_email(_load_mailcom(), target)
        if row is None:
            return "邮箱不存在"
        allocations = [
            allocation
            for allocation in _load_email_allocations()
            if str(allocation.get("base_email") or "").lower() == target
            and _email_allocation_source(allocation) == "mailcom"
        ]
        if row.get("status") == "leased" or any(
            allocation.get("status") == "leased" for allocation in allocations
        ):
            return "邮箱存在活跃取码租约"
        related_emails = {
            target,
            *(str(allocation.get("actual_email") or "").lower() for allocation in allocations),
        }
        account_ids = {
            int(allocation.get("account_id") or 0)
            for allocation in allocations
            if allocation.get("account_id")
        }
        if any(
            str(account.get("email") or "").lower() in related_emails
            or int(account.get("id") or 0) in account_ids
            for account in _load_accounts()
        ):
            return "邮箱仍有关联账号，请先删除关联账号"
        if any(
            str(job.get("email") or "").lower() in related_emails
            and job.get("status") in {"pending", "running", "stopping"}
            for job in _load_jobs()
        ):
            return "邮箱仍有关联运行任务，请先停止任务"
        return None


def delete_mailcom_email(email_address: str) -> bool:
    if mailcom_delete_block_reason(email_address) is not None:
        return False
    with _LOCK:
        target = str(email_address or "").strip().lower()
        rows = _load_mailcom()
        remaining = [
            row for row in rows if str(row.get("email") or "").lower() != target
        ]
        if len(remaining) == len(rows):
            return False
        _save_mailcom(remaining)
        return True


def list_mailcom_pool(status: str | None = None, limit: int = 500) -> list[dict]:
    from config.email import MAILCOM_ALIAS_MAX

    provider_ceiling = max(1, min(10, int(MAILCOM_ALIAS_MAX or 7)))
    with _LOCK:
        accounts = _load_accounts()
        account_by_email = {
            str(account.get("email") or "").lower(): account
            for account in accounts
        }
        jobs = _load_jobs()
        rows = _load_mailcom()
        allocations = [
            allocation
            for allocation in _load_email_allocations()
            if _email_allocation_source(allocation) == "mailcom"
        ]
        if status:
            rows = [row for row in rows if row.get("status") == status]
        output: list[dict] = []
        for row in sorted(rows, key=lambda item: int(item.get("id") or 0), reverse=True)[:limit]:
            decorated = _decorate_mailcom(row, account_by_email)
            base = str(row.get("email") or "").lower()
            linked = [
                allocation
                for allocation in allocations
                if str(allocation.get("base_email") or "").lower() == base
            ]
            capacity_linked = [
                allocation
                for allocation in linked
                if _allocation_consumes_capacity(allocation)
            ]
            releasable_aliases = [
                allocation
                for allocation in capacity_linked
                if str(allocation.get("mode") or "single").strip().lower() == "plus_alias"
                and _mailcom_alias_active_task_reason(
                    allocation,
                    jobs=jobs,
                    accounts=accounts,
                ) is None
            ]
            decorated["attempt_count"] = len(linked)
            decorated["allocation_count"] = len(capacity_linked)
            decorated["registered_count"] = sum(
                1 for allocation in linked if allocation.get("status") == "registered"
            )
            decorated["allocation_modes"] = sorted({
                str(allocation.get("mode") or "single") for allocation in linked
            })
            decorated["email_modes"] = ["single"]
            if "+" not in base.partition("@")[0]:
                decorated["email_modes"].append("plus_alias")
            decorated["single_count"] = sum(
                1 for allocation in capacity_linked if allocation.get("mode") == "single"
            )
            decorated["alias_count"] = sum(
                1 for allocation in capacity_linked if allocation.get("mode") == "plus_alias"
            )
            decorated["historical_alias_count"] = sum(
                1 for allocation in linked if allocation.get("mode") == "plus_alias"
            )
            decorated["released_slot_count"] = sum(
                1
                for allocation in linked
                if allocation.get("mode") == "plus_alias" and allocation.get("slot_released")
            )
            decorated["releasable_alias_count"] = len(releasable_aliases)
            decorated["alias_release_in_progress"] = _mailcom_alias_release_is_active(row)
            decorated["provider_alias_limit"] = provider_ceiling
            decorated["last_alias_limit"] = provider_ceiling
            decorated["effective_alias_limit"] = provider_ceiling
            decorated["remaining_capacity"] = max(
                0,
                provider_ceiling - int(decorated["allocation_count"] or 0),
            )
            decorated["alias_claimable"] = (
                row.get("status") in {None, "", "available", "used"}
                and "plus_alias" in decorated["email_modes"]
                and decorated["remaining_capacity"] > 0
                and not decorated["alias_release_in_progress"]
            )
            decorated["active_allocation"] = next(
                (dict(allocation) for allocation in linked if allocation.get("status") == "leased"),
                None,
            )
            output.append(decorated)
        return output


def mailcom_pool_summary() -> dict:
    with _LOCK:
        output = {"available": 0, "used": 0, "failed": 0}
        for row in _load_mailcom():
            status = row.get("status") or "available"
            output[status] = output.get(status, 0) + 1
        output["total"] = sum(value for key, value in output.items() if key != "total")
        return output


def mailcom_promotion_statistics() -> dict:
    """Aggregate Mail.com registrations and Plus-offer outcomes by base/domain."""
    from config.email import MAILCOM_ALIAS_MAX

    provider_ceiling = max(1, min(10, int(MAILCOM_ALIAS_MAX or 7)))
    with _LOCK:
        mailboxes = _load_mailcom()
        allocations = [
            item
            for item in _load_email_allocations()
            if _email_allocation_source(item) == "mailcom"
        ]
        accounts = _load_accounts()
        account_by_id = {
            int(account.get("id") or 0): account
            for account in accounts
            if int(account.get("id") or 0)
        }
        account_by_email = {
            str(account.get("email") or "").strip().lower(): account
            for account in accounts
            if str(account.get("email") or "").strip()
        }

        by_base: list[dict] = []
        for mailbox in mailboxes:
            base_email = str(mailbox.get("email") or "").strip().lower()
            if not base_email:
                continue
            domain = base_email.partition("@")[2] or "unknown"
            linked = [
                item
                for item in allocations
                if str(item.get("base_email") or "").strip().lower() == base_email
            ]
            related_accounts: dict[str, dict] = {}
            for allocation in linked:
                account = account_by_id.get(int(allocation.get("account_id") or 0))
                if account is None:
                    account = account_by_email.get(
                        str(allocation.get("actual_email") or "").strip().lower()
                    )
                if account is not None:
                    key = str(account.get("id") or account.get("email") or "")
                    related_accounts[key] = account
            direct_account = account_by_email.get(base_email)
            if direct_account is not None:
                key = str(direct_account.get("id") or direct_account.get("email") or "")
                related_accounts[key] = direct_account

            offer_states = [
                _account_plus_offer_state(account)
                for account in related_accounts.values()
            ]
            eligible = offer_states.count("eligible")
            not_eligible = offer_states.count("not_eligible")
            checked = eligible + not_eligible
            historical_registered = sum(
                str(item.get("status") or "").strip().lower() == "registered"
                for item in linked
            )
            registered = max(historical_registered, len(related_accounts))
            attempts = max(len(linked), registered)
            plus_activated = sum(
                _account_matches_plan_filter(account, "plus")
                for account in related_accounts.values()
            )
            used_slots = sum(_allocation_consumes_capacity(item) for item in linked)
            released_slots = sum(
                bool(item.get("slot_released"))
                and str(item.get("mode") or "").strip().lower() == "plus_alias"
                for item in linked
            )
            by_base.append({
                "base_email": base_email,
                "domain": domain,
                "attempts": attempts,
                "registered": registered,
                "checked": checked,
                "eligible": eligible,
                "not_eligible": not_eligible,
                "unknown": max(0, registered - checked),
                "checking": offer_states.count("checking"),
                "failed_checks": offer_states.count("failed"),
                "plus_activated": plus_activated,
                "zero_offer_eligible": sum(
                    str(account.get("paypal_zero_offer_status") or "").strip().lower()
                    == "eligible"
                    for account in related_accounts.values()
                ),
                "used_slots": used_slots,
                "released_slots": released_slots,
                "remaining_slots": max(0, provider_ceiling - used_slots),
            })

        numeric_fields = (
            "attempts", "registered", "checked", "eligible", "not_eligible",
            "unknown", "checking", "failed_checks", "plus_activated",
            "zero_offer_eligible", "used_slots", "released_slots", "remaining_slots",
        )

        def finish(row: dict) -> dict:
            attempts = int(row.get("attempts") or 0)
            registered = int(row.get("registered") or 0)
            checked = int(row.get("checked") or 0)
            row["success_rate"] = round(registered * 100 / attempts, 1) if attempts else None
            row["offer_rate"] = round(int(row.get("eligible") or 0) * 100 / checked, 1) if checked else None
            row["offer_rate_of_registered"] = (
                round(int(row.get("eligible") or 0) * 100 / registered, 1)
                if registered else None
            )
            return row

        by_domain_map: dict[str, dict] = {}
        for row in by_base:
            finish(row)
            domain_row = by_domain_map.setdefault(row["domain"], {
                "domain": row["domain"],
                "base_mailboxes": 0,
                **{field: 0 for field in numeric_fields},
            })
            domain_row["base_mailboxes"] += 1
            for field in numeric_fields:
                domain_row[field] += int(row.get(field) or 0)

        by_domain = [finish(row) for row in by_domain_map.values()]
        summary = {
            "base_mailboxes": len(by_base),
            **{
                field: sum(int(row.get(field) or 0) for row in by_base)
                for field in numeric_fields
            },
        }
        finish(summary)
        by_base.sort(
            key=lambda row: (
                float(row.get("offer_rate") or 0),
                int(row.get("eligible") or 0),
                int(row.get("registered") or 0),
                row.get("base_email") or "",
            ),
            reverse=True,
        )
        by_domain.sort(
            key=lambda row: (
                float(row.get("offer_rate") or 0),
                int(row.get("eligible") or 0),
                int(row.get("registered") or 0),
                row.get("domain") or "",
            ),
            reverse=True,
        )
        return {"summary": summary, "by_domain": by_domain, "by_base": by_base}


def get_mailcom_by_email(email_address: str) -> dict | None:
    with _LOCK:
        rows = _load_mailcom()
        row = _find_by_email(rows, email_address)
        allocation = None
        if row is None:
            candidate = get_email_allocation_by_actual_email(email_address)
            allocation = (
                candidate
                if candidate and _email_allocation_source(candidate) == "mailcom"
                else None
            )
            row = _find_by_email(rows, str((allocation or {}).get("base_email") or ""))
        if row is None:
            return None
        output = _decorate_mailcom(row)
        if allocation:
            output["email"] = allocation.get("actual_email")
            output["base_email"] = allocation.get("base_email")
            output["allocation_id"] = allocation.get("id")
            output["email_mode"] = allocation.get("mode")
        return output

def import_generic_api_emails(records: list[dict]) -> tuple[int, int]:
    """
    批量导入通用 API 取码邮箱。
    records 元素：{email, code_url}
    返回 (新增数, 跳过数)。
    """
    generic_records = []
    icloud_records = []
    for raw in records:
        email = str(raw.get("email") or "").strip()
        code_url = str(raw.get("code_url") or raw.get("url") or "").strip()
        if email.lower().endswith("@icloud.com") and code_url:
            icloud_records.append({
                **raw,
                "email": email,
                "token": "",
                "pickup_url": code_url,
                "protocol": "generic_api",
            })
        else:
            generic_records.append(raw)

    icloud_inserted = icloud_skipped = 0
    if icloud_records:
        icloud_inserted, icloud_skipped = import_icloud_emails(icloud_records)

    with _LOCK:
        rows = _load_generic_api_emails()
        inserted = skipped = 0
        for raw in generic_records:
            email = (raw.get("email") or "").strip()
            code_url = (raw.get("code_url") or raw.get("url") or "").strip()
            if not email or not code_url:
                skipped += 1
                continue
            if _find_by_email(rows, email):
                skipped += 1
                continue
            row = {
                "id": _next_id(rows),
                "email": email,
                "code_url": code_url,
                "status": "available",
                "used_at": None,
                "note": None,
                "imported_at": _now(),
            }
            row["copy_line"] = _generic_api_email_line(row)
            row["original_email_line"] = (
                str(raw.get("original_email_line") or "").strip() or row["copy_line"]
            )
            rows.append(row)
            inserted += 1
        _save_generic_api_emails(rows)
        return inserted + icloud_inserted, skipped + icloud_skipped


def claim_next_generic_api_email() -> dict | None:
    """原子领取一个可用通用 API 邮箱并标记为 used。"""
    return claim_generic_api_email(mode="single")


def release_generic_api_email(email: str, status: str = "available", note: str | None = None) -> bool:
    """把通用 API 邮箱状态改回 available，或标记为 failed/used。"""
    with _LOCK:
        rows = _load_generic_api_emails()
        allocation = get_email_allocation_by_actual_email(email)
        if allocation and _email_allocation_source(allocation) != "generic_api":
            allocation = None
        base_email = str((allocation or {}).get("base_email") or email)
        row = _find_by_email(rows, base_email)
        if row is None:
            return False
        if row.get("status") == "leased" and status != "leased":
            raise RuntimeError("邮箱存在活跃取码租约，不能直接修改状态")
        row["status"] = status
        if status == "available":
            row["used_at"] = None
        elif status in ("used", "failed", "disabled"):
            row["used_at"] = row.get("used_at") or _now()
        if note is not None:
            row["note"] = note
        _save_generic_api_emails(rows)
        return True


def release_unconsumed_generic_api_email(email: str, note: str | None = None) -> bool:
    """原子回收未生成本地账号且仍为 used 的通用 API 邮箱。"""
    with _LOCK:
        if _find_by_email(_load_accounts(), email) is not None:
            return False
        allocation = get_email_allocation_by_actual_email(email)
        if allocation and _email_allocation_source(allocation) == "generic_api" and allocation.get("status") == "leased":
            return complete_email_allocation(email, status="failed", error=note)
        rows = _load_generic_api_emails()
        row = _find_by_email(rows, email)
        if row is None or row.get("status") != "used":
            return False
        row["status"] = "available"
        row["used_at"] = None
        if note is not None:
            row["note"] = note
        _save_generic_api_emails(rows)
        return True


def delete_generic_api_email(email: str) -> bool:
    """从通用 API 邮箱池彻底删除一个邮箱。"""
    with _LOCK:
        rows = _load_generic_api_emails()
        target = (email or "").lower()
        row = _find_by_email(rows, target)
        if row and row.get("status") == "leased":
            return False
        linked = [
            a for a in _load_email_allocations()
            if str(a.get("base_email") or "").lower() == target and a.get("account_id")
            and _email_allocation_source(a) == "generic_api"
        ]
        if linked:
            return False
        new_rows = [r for r in rows if (r.get("email") or "").lower() != target]
        if len(new_rows) == len(rows):
            return False
        _save_generic_api_emails(new_rows)
        return True


def generic_api_email_delete_block_reason(email: str) -> str | None:
    """返回基础邮箱不能删除的原因；None 表示可以删除。"""
    with _LOCK:
        target = str(email or "").strip().lower()
        row = _find_by_email(_load_generic_api_emails(), target)
        if row is None:
            return "邮箱不存在"
        allocations = [
            allocation for allocation in _load_email_allocations()
            if str(allocation.get("base_email") or "").lower() == target
            and _email_allocation_source(allocation) == "generic_api"
        ]
        if row.get("status") == "leased" or any(a.get("status") == "leased" for a in allocations):
            return "邮箱存在活跃取码租约"
        if any(a.get("account_id") for a in allocations):
            return "邮箱仍有关联账号，请先删除关联账号"
        return None


def list_generic_api_email_pool(status: str | None = None, limit: int = 500) -> list[dict]:
    with _LOCK:
        account_by_email = {
            (a.get("email") or "").lower(): a
            for a in _load_accounts()
        }
        rows = _load_generic_api_emails()
        allocations = _load_email_allocations()
        counts = _allocation_counts(allocations, source="generic_api")
        if status:
            rows = [r for r in rows if r.get("status") == status]
        rows = sorted(rows, key=lambda x: int(x.get("id") or 0), reverse=True)
        out = []
        for row in rows[:limit]:
            decorated = _decorate_generic_api_email(row, account_by_email)
            base = str(row.get("email") or "").lower()
            base_allocations = [
                a for a in allocations
                if str(a.get("base_email") or "").lower() == base
                and _email_allocation_source(a) == "generic_api"
            ]
            decorated["allocation_count"] = counts.get(base, 0)
            decorated["registered_count"] = sum(
                1 for a in base_allocations if a.get("status") == "registered"
            )
            decorated["allocation_modes"] = sorted({
                str(a.get("mode") or "single") for a in base_allocations
            })
            decorated["email_modes"] = ["single"]
            if "+" not in base.partition("@")[0]:
                decorated["email_modes"].append("plus_alias")
            decorated["single_count"] = sum(1 for a in base_allocations if a.get("mode") == "single")
            decorated["alias_count"] = sum(1 for a in base_allocations if a.get("mode") == "plus_alias")
            stored_limits = [int(a.get("alias_limit") or 0) for a in base_allocations if int(a.get("alias_limit") or 0) > 0]
            decorated["last_alias_limit"] = stored_limits[-1] if stored_limits else None
            decorated["active_allocation"] = next((
                dict(a) for a in base_allocations if a.get("status") == "leased"
            ), None)
            out.append(decorated)
        return out


def generic_api_email_pool_summary() -> dict:
    with _LOCK:
        out = {"available": 0, "used": 0, "failed": 0}
        for row in _load_generic_api_emails():
            status = row.get("status") or "available"
            out[status] = out.get(status, 0) + 1
        out["total"] = sum(v for k, v in out.items() if k != "total")
        return out


def get_generic_api_email_by_email(email: str) -> dict | None:
    with _LOCK:
        rows = _load_generic_api_emails()
        row = _find_by_email(rows, email)
        allocation = None
        if row is None:
            candidate = get_email_allocation_by_actual_email(email)
            allocation = candidate if candidate and _email_allocation_source(candidate) == "generic_api" else None
            row = _find_by_email(rows, str((allocation or {}).get("base_email") or ""))
        if row is None:
            return None
        out = _decorate_generic_api_email(row)
        if allocation:
            out["email"] = allocation.get("actual_email")
            out["base_email"] = allocation.get("base_email")
            out["allocation_id"] = allocation.get("id")
            out["email_mode"] = allocation.get("mode")
        return out


def query_generic_api_email_pool(
    *, page: int = 1, page_size: int = 50, q: str = "", status: str = "", mode: str = "",
    alias_limit: int | None = None, capacity: str = "", sort_by: str = "id",
    sort_order: str = "desc",
) -> dict:
    rows = list_generic_api_email_pool(status=status or None, limit=1000000)
    query = str(q or "").strip().lower()
    if query:
        rows = [r for r in rows if query in " ".join(str(r.get(k) or "").lower() for k in ("email", "note", "status"))]
    if mode in {"single", "plus_alias"}:
        rows = [r for r in rows if mode in set(r.get("email_modes") or [])]
    try:
        requested_limit = int(alias_limit or 0)
    except (TypeError, ValueError):
        requested_limit = 0
    for row in rows:
        effective_limit = requested_limit or int(row.get("last_alias_limit") or 0)
        row["effective_alias_limit"] = effective_limit or None
        row["remaining_capacity"] = (
            max(0, effective_limit - int(row.get("allocation_count") or 0))
            if effective_limit > 0 else None
        )
    capacity_filter = str(capacity or "").strip().lower()
    if capacity_filter in {"available", "remaining", "gt0"}:
        rows = [r for r in rows if r.get("remaining_capacity") is None or int(r.get("remaining_capacity") or 0) > 0]
    elif capacity_filter in {"exhausted", "full", "zero"}:
        rows = [r for r in rows if r.get("remaining_capacity") == 0]
    allowed_sort = {
        "id", "email", "status", "imported_at", "used_at", "note",
        "allocation_count", "registered_count", "remaining_capacity",
    }
    sort_key = sort_by if sort_by in allowed_sort else "id"
    reverse = str(sort_order or "desc").lower() != "asc"
    numeric_sort = {"id", "allocation_count", "registered_count", "remaining_capacity"}
    if sort_key in numeric_sort:
        rows.sort(key=lambda r: int(r.get(sort_key) or 0), reverse=reverse)
    else:
        rows.sort(key=lambda r: str(r.get(sort_key) or "").lower(), reverse=reverse)
    page = max(1, int(page or 1))
    page_size = max(1, min(500, int(page_size or 50)))
    total = len(rows)
    start = (page - 1) * page_size
    items = []
    for row in rows[start:start + page_size]:
        item = _mask_email_pool_secrets(row)
        item["source"] = "generic_api"
        items.append(item)
    summary = generic_api_email_pool_summary()
    return {"items": items, "total": total, "page": page, "page_size": page_size, "summary": summary}


def get_generic_api_mailbox_detail(mailbox_id: int, *, include_code_url: bool = False) -> dict | None:
    with _LOCK:
        row = next((r for r in _load_generic_api_emails() if int(r.get("id") or 0) == int(mailbox_id)), None)
        if row is None:
            return None
        out = dict(row)
        allocations = [
            dict(a) for a in _load_email_allocations()
            if int(a.get("base_email_id") or 0) == int(mailbox_id)
            and _email_allocation_source(a) == "generic_api"
        ]
        account_ids = {int(a.get("account_id") or 0) for a in allocations if a.get("account_id")}
        out["allocations"] = sorted(allocations, key=lambda a: int(a.get("id") or 0), reverse=True)
        out["accounts"] = [
            _mask_account_secrets(a) for a in _load_accounts()
            if int(a.get("id") or 0) in account_ids
        ]
        out["allocation_count"] = len(allocations)
        out["registered_count"] = sum(1 for a in allocations if a.get("status") == "registered")
        out.update(get_mailbox_relationships("generic_api", str(row.get("email") or "")))
        return _mask_email_pool_secrets(out, include_code_url=include_code_url)


# ============================================================
# FlySMS iCloud email pool
# ============================================================

def import_icloud_emails(records: list[dict]) -> tuple[int, int]:
    """批量导入 FlySMS、query.php、分享链接或通用 GET API 素材。"""
    with _LOCK:
        # Auto-import runs at every worker start. Index once instead of scanning
        # the entire pool for every line, and don't rewrite unchanged material.
        # Work on copies so a failed atomic JSON save cannot leak new records
        # or changed credentials into the live cache.
        rows = [dict(row) for row in _load_icloud_emails()]
        by_email = {}
        for row in rows:
            by_email.setdefault(str(row.get("email") or "").lower(), row)
        next_id = None
        inserted = skipped = 0
        for raw in records:
            email = str(raw.get("email") or "").strip()
            token = str(raw.get("token") or "").strip()
            pickup_url = str(raw.get("pickup_url") or raw.get("url") or "").strip()
            protocol = str(raw.get("protocol") or "").strip().lower()
            original_line = str(raw.get("original_email_line") or "").strip()
            if not email or not pickup_url or (not token and protocol != "generic_api"):
                skipped += 1
                continue
            existing = by_email.get(email.lower())
            if existing:
                credentials_changed = (
                    str(existing.get("token") or "") != token
                    or str(existing.get("pickup_url") or "") != pickup_url
                    or str(existing.get("protocol") or "") != protocol
                    or bool(original_line and str(existing.get("original_email_line") or "") != original_line)
                )
                if not credentials_changed:
                    skipped += 1
                    continue
                existing["token"] = token
                existing["pickup_url"] = pickup_url
                existing["protocol"] = protocol
                existing["copy_line"] = _icloud_email_line(existing)
                existing["original_email_line"] = original_line or existing["copy_line"]
                existing["updated_at"] = _now()
                existing["note"] = "iCloud 凭证已重新导入"
                if existing.get("status") in {"failed", "disabled"} and _find_by_email(_load_accounts(), email) is None:
                    existing["status"] = "available"
                    existing["used_at"] = None
                inserted += 1
                continue
            if next_id is None:
                next_id = _next_id(rows)
            row = {
                "id": next_id,
                "email": email,
                "token": token,
                "pickup_url": pickup_url,
                "protocol": protocol,
                "status": "available",
                "used_at": None,
                "note": None,
                "imported_at": _now(),
            }
            row["copy_line"] = _icloud_email_line(row)
            row["original_email_line"] = original_line or row["copy_line"]
            rows.append(row)
            by_email[email.lower()] = row
            next_id += 1
            inserted += 1
        if inserted:
            _save_icloud_emails(rows)
        return inserted, skipped


def migrate_generic_api_icloud_emails() -> dict:
    """把无关联的 `@icloud.com` URL 邮箱从 generic_api 原子迁入 iCloud 池。"""
    with _LOCK:
        generic_rows = _load_generic_api_emails()
        icloud_rows = _load_icloud_emails()
        allocations = _load_email_allocations()
        accounts = _load_accounts()
        jobs = _load_jobs()
        moved = []
        skipped = []

        for row in generic_rows:
            email = str(row.get("email") or "").strip()
            if not email.lower().endswith("@icloud.com"):
                continue
            target = email.lower()
            if _find_by_email(icloud_rows, email):
                skipped.append({"email": email, "reason": "iCloud 池已存在同名邮箱"})
                continue
            related = any(
                _email_allocation_source(item) == "generic_api"
                and (
                    int(item.get("base_email_id") or 0) == int(row.get("id") or 0)
                    or str(item.get("base_email") or "").lower() == target
                    or str(item.get("actual_email") or "").lower() == target
                )
                for item in allocations
            )
            related = related or _find_by_email(accounts, email) is not None
            related = related or any(
                str(item.get("email") or "").lower() == target for item in jobs
            )
            if related:
                skipped.append({"email": email, "reason": "存在账号、任务或邮箱分配关联"})
                continue
            code_url = str(row.get("code_url") or "").strip()
            if not code_url:
                skipped.append({"email": email, "reason": "取码 URL 为空"})
                continue

            migrated = {
                "id": _next_id(icloud_rows),
                "email": email,
                "token": "",
                "pickup_url": code_url,
                "protocol": "generic_api",
                "status": row.get("status") or "available",
                "used_at": row.get("used_at"),
                "note": row.get("note"),
                "imported_at": row.get("imported_at") or _now(),
                "original_email_line": (
                    str(row.get("original_email_line") or "").strip()
                    or _generic_api_email_line(row)
                ),
            }
            migrated["copy_line"] = _icloud_email_line(migrated)
            icloud_rows.append(migrated)
            moved.append({"email": email, "from_id": row.get("id"), "to_id": migrated["id"]})

        if moved:
            moved_emails = {item["email"].lower() for item in moved}
            generic_rows = [
                row for row in generic_rows
                if str(row.get("email") or "").lower() not in moved_emails
            ]
            _save_generic_api_emails(generic_rows)
            _save_icloud_emails(icloud_rows)
        return {
            "moved": moved,
            "moved_count": len(moved),
            "skipped": skipped,
            "skipped_count": len(skipped),
        }


def claim_icloud_email(*, job_id: int | None = None, batch_id: str | None = None) -> dict | None:
    """原子领取一个 iCloud 邮箱并创建 single 租约。"""
    with _LOCK:
        mailboxes = _load_icloud_emails()
        allocations = _load_email_allocations()
        recovered = _recover_expired_email_leases_locked(mailboxes, allocations)
        if recovered:
            _save_icloud_emails(mailboxes)
            _save_email_allocations(allocations)
        counts = _consumed_single_allocation_counts(allocations, source="icloud")
        attempted_in_batch = _single_allocation_bases_in_batch(
            allocations, source="icloud", batch_id=batch_id
        )
        selected = min((
            row for row in mailboxes
            if row.get("status") in {None, "", "available"}
            and str(row.get("email") or "").strip().lower() not in attempted_in_batch
            and counts.get(str(row.get("email") or "").lower(), 0) < 1
        ), key=lambda r: int(r.get("id") or 0), default=None)
        if selected is None:
            return None

        email = str(selected.get("email") or "").strip()
        allocation = {
            "id": _next_id(allocations),
            "source": "icloud",
            "base_email_id": selected.get("id"),
            "base_email": email.lower(),
            "actual_email": email,
            "mode": "single",
            "alias_limit": 1,
            "job_id": job_id,
            "batch_id": batch_id,
            "account_id": None,
            "status": "leased",
            "error": None,
            "created_at": _now(),
            "completed_at": None,
        }
        allocations.append(allocation)
        selected["status"] = "leased"
        selected["lease_job_id"] = job_id
        selected["lease_allocation_id"] = allocation["id"]
        selected["lease_expires_at"] = (datetime.now() + timedelta(minutes=_EMAIL_LEASE_MINUTES)).isoformat(timespec="seconds")
        selected["last_used_at"] = _now()
        _save_icloud_emails(mailboxes)
        _save_email_allocations(allocations)
        out = _decorate_icloud_email(selected)
        out.update({"allocation_id": allocation["id"], "email_mode": "single"})
        return out


def release_icloud_email(email: str, status: str = "available", note: str | None = None) -> bool:
    with _LOCK:
        rows = _load_icloud_emails()
        allocation = get_email_allocation_by_actual_email(email)
        if allocation and _email_allocation_source(allocation) != "icloud":
            allocation = None
        row = _find_by_email(rows, str((allocation or {}).get("base_email") or email))
        if row is None:
            return False
        if row.get("status") == "leased" and status != "leased":
            raise RuntimeError("邮箱存在活跃取码租约，不能直接修改状态")
        row["status"] = status
        if status == "available":
            row["used_at"] = None
        elif status in {"used", "failed", "disabled"}:
            row["used_at"] = row.get("used_at") or _now()
        if note is not None:
            row["note"] = note
        _save_icloud_emails(rows)
        return True


def release_unconsumed_icloud_email(email: str, note: str | None = None) -> bool:
    with _LOCK:
        if _find_by_email(_load_accounts(), email) is not None:
            return False
        allocation = get_email_allocation_by_actual_email(email)
        if allocation and _email_allocation_source(allocation) == "icloud" and allocation.get("status") == "leased":
            return complete_email_allocation(email, status="failed", error=note)
        rows = _load_icloud_emails()
        row = _find_by_email(rows, email)
        if row is None or row.get("status") != "used":
            return False
        row["status"] = "available"
        row["used_at"] = None
        if note is not None:
            row["note"] = note
        _save_icloud_emails(rows)
        return True


def icloud_email_delete_block_reason(email: str) -> str | None:
    with _LOCK:
        target = str(email or "").strip().lower()
        row = _find_by_email(_load_icloud_emails(), target)
        if row is None:
            return "邮箱不存在"
        allocations = [
            item for item in _load_email_allocations()
            if str(item.get("base_email") or "").lower() == target
            and _email_allocation_source(item) == "icloud"
        ]
        if row.get("status") == "leased" or any(item.get("status") == "leased" for item in allocations):
            return "邮箱存在活跃取码租约"
        if any(item.get("account_id") for item in allocations) or _find_by_email(_load_accounts(), target):
            return "邮箱仍有关联账号，请先删除关联账号"
        if any(
            str(job.get("email") or "").lower() == target
            and job.get("status") in {"pending", "running", "stopping"}
            for job in _load_jobs()
        ):
            return "邮箱仍有关联运行任务，请先停止任务"
        return None


def delete_icloud_email(email: str) -> bool:
    if icloud_email_delete_block_reason(email) is not None:
        return False
    with _LOCK:
        target = str(email or "").strip().lower()
        rows = _load_icloud_emails()
        new_rows = [row for row in rows if str(row.get("email") or "").lower() != target]
        if len(new_rows) == len(rows):
            return False
        _save_icloud_emails(new_rows)
        return True


def list_icloud_email_pool(status: str | None = None, limit: int = 500) -> list[dict]:
    with _LOCK:
        accounts = {(row.get("email") or "").lower(): row for row in _load_accounts()}
        allocations = _load_email_allocations()
        rows = _load_icloud_emails()
        if status:
            rows = [row for row in rows if row.get("status") == status]
        out = []
        for row in sorted(rows, key=lambda item: int(item.get("id") or 0), reverse=True)[:limit]:
            decorated = _decorate_icloud_email(row, accounts)
            base = str(row.get("email") or "").lower()
            linked = [
                item for item in allocations
                if str(item.get("base_email") or "").lower() == base
                and _email_allocation_source(item) == "icloud"
            ]
            decorated["allocation_count"] = len(linked)
            decorated["registered_count"] = sum(1 for item in linked if item.get("status") == "registered")
            decorated["email_modes"] = ["single"]
            decorated["allocation_modes"] = ["single"] if linked else []
            decorated["active_allocation"] = next((dict(item) for item in linked if item.get("status") == "leased"), None)
            out.append(decorated)
        return out


def icloud_email_pool_summary() -> dict:
    with _LOCK:
        out = {"available": 0, "used": 0, "failed": 0}
        for row in _load_icloud_emails():
            status = row.get("status") or "available"
            out[status] = out.get(status, 0) + 1
        out["total"] = sum(value for key, value in out.items() if key != "total")
        return out


def get_icloud_email_by_email(email: str) -> dict | None:
    with _LOCK:
        rows = _load_icloud_emails()
        row = _find_by_email(rows, email)
        allocation = None
        if row is None:
            candidate = get_email_allocation_by_actual_email(email)
            allocation = candidate if candidate and _email_allocation_source(candidate) == "icloud" else None
            row = _find_by_email(rows, str((allocation or {}).get("base_email") or ""))
        if row is None:
            return None
        out = _decorate_icloud_email(row)
        if allocation:
            out["email"] = allocation.get("actual_email")
            out["base_email"] = allocation.get("base_email")
            out["allocation_id"] = allocation.get("id")
            out["email_mode"] = allocation.get("mode")
        return out


def get_mailbox_relationships(source: str, email: str) -> dict:
    """Return masked allocations/accounts/jobs/batches linked to one mailbox resource."""
    source = str(source or "").strip().lower()
    target = str(email or "").strip().lower()
    with _LOCK:
        allocations: list[dict] = []
        related_emails = {target}
        if source in {"generic_api", "outlook", "icloud", "mailcom"}:
            allocation = next((
                a for a in _load_email_allocations()
                if str(a.get("actual_email") or "").lower() == target
                and _email_allocation_source(a) == source
            ), None)
            base_email = str((allocation or {}).get("base_email") or target).lower()
            allocations = [
                dict(a) for a in _load_email_allocations()
                if str(a.get("base_email") or "").lower() == base_email
                and _email_allocation_source(a) == source
            ]
            related_emails.add(base_email)
            related_emails.update(str(a.get("actual_email") or "").lower() for a in allocations)

        allocation_account_ids = {
            int(a.get("account_id") or 0) for a in allocations if a.get("account_id")
        }
        account_rows = [
            a for a in _load_accounts()
            if int(a.get("id") or 0) in allocation_account_ids
            or str(a.get("email") or "").lower() in related_emails
        ]
        account_ids = {int(a.get("id") or 0) for a in account_rows}
        allocation_job_ids = {int(a.get("job_id") or 0) for a in allocations if a.get("job_id")}
        jobs = [
            dict(j) for j in _load_jobs()
            if int(j.get("id") or 0) in allocation_job_ids
            or int(j.get("account_id") or 0) in account_ids
            or str(j.get("email") or "").lower() in related_emails
        ]
        batch_ids = {
            str(j.get("batch_id") or "") for j in jobs if j.get("batch_id")
        }
        batch_ids.update(str(a.get("batch_id") or "") for a in allocations if a.get("batch_id"))
        batches = [
            dict(b) for b in _load_batches()
            if str(b.get("batch_id") or "") in batch_ids
        ]
        return {
            "allocations": sorted(allocations, key=lambda a: int(a.get("id") or 0), reverse=True),
            "accounts": [_mask_account_secrets(a) for a in account_rows],
            "jobs": mask_job_secrets(sorted(jobs, key=lambda j: int(j.get("id") or 0), reverse=True)),
            "registration_batches": mask_job_secrets(batches),
        }


def mailbox_delete_block_reason(source: str, email: str) -> str | None:
    source = str(source or "").strip().lower()
    target = str(email or "").strip().lower()
    if source == "generic_api":
        return generic_api_email_delete_block_reason(target)
    if source == "icloud":
        return icloud_email_delete_block_reason(target)
    if source == "mailcom":
        return mailcom_delete_block_reason(target)
    with _LOCK:
        exists = (
            _find_by_email(_load_outlook(), target) is not None
            if source == "outlook"
            else _find_domain_email(_load_domain_pool(), target) is not None
            if source == "cloudflare_domain"
            else False
        )
        if not exists:
            return "邮箱不存在"
        allocations = [
            a for a in _load_email_allocations()
            if str(a.get("base_email") or "").lower() == target
            and _email_allocation_source(a) == source
        ]
        if any(a.get("status") == "leased" for a in allocations):
            return "邮箱存在活跃取码租约"
        related_emails = {target, *(str(a.get("actual_email") or "").lower() for a in allocations)}
        if any(
            str(account.get("email") or "").lower() in related_emails
            or int(account.get("id") or 0) in {int(a.get("account_id") or 0) for a in allocations}
            for account in _load_accounts()
        ):
            return "邮箱仍有关联账号，请先删除关联账号"
        if any(
            str(job.get("email") or "").lower() in related_emails
            and job.get("status") in {"pending", "running", "stopping"}
            for job in _load_jobs()
        ):
            return "邮箱仍有关联运行任务，请先停止任务"
        return None


def update_mailbox_note(source: str, email: str, note: str) -> bool:
    """独立更新邮箱备注，不改变邮箱状态或租约。"""
    source = str(source or "").strip().lower()
    target = str(email or "").strip()
    with _LOCK:
        if source == "generic_api":
            rows = _load_generic_api_emails()
            candidate = get_email_allocation_by_actual_email(target)
            allocation = candidate if candidate and _email_allocation_source(candidate) == "generic_api" else None
            row = _find_by_email(rows, str((allocation or {}).get("base_email") or target))
            save = _save_generic_api_emails
        elif source == "icloud":
            rows = _load_icloud_emails()
            candidate = get_email_allocation_by_actual_email(target)
            allocation = candidate if candidate and _email_allocation_source(candidate) == "icloud" else None
            row = _find_by_email(rows, str((allocation or {}).get("base_email") or target))
            save = _save_icloud_emails
        elif source == "mailcom":
            rows = _load_mailcom()
            candidate = get_email_allocation_by_actual_email(target)
            allocation = candidate if candidate and _email_allocation_source(candidate) == "mailcom" else None
            row = _find_by_email(rows, str((allocation or {}).get("base_email") or target))
            save = _save_mailcom
        elif source == "cloudflare_domain":
            rows = _load_domain_pool()
            row = _find_domain_email(rows, target)
            save = _save_domain_pool
        elif source == "outlook":
            rows = _load_outlook()
            allocation = get_email_allocation_by_actual_email(target)
            if allocation and _email_allocation_source(allocation) != "outlook":
                allocation = None
            row = _find_by_email(rows, str((allocation or {}).get("base_email") or target))
            save = _save_outlook
        else:
            raise ValueError("source 非法")
        if row is None:
            return False
        row["note"] = str(note or "")
        row["note_updated_at"] = _now()
        save(rows)
        return True


# ============================================================
# Codex 授权账号（来自 codex_accounts/codex-邮箱-plan.json）
# ============================================================

def _load_codex_export_state() -> dict:
    """读导出状态映射 {filename: {exported_at, exported_count}}。不存在返回 {}。"""
    data = _read_json(_CODEX_EXPORT_STATE, {})
    return data if isinstance(data, dict) else {}


def _save_codex_export_state(state: dict) -> None:
    _write_json(_CODEX_EXPORT_STATE, state)


def _codex_metadata_rows() -> list[dict]:
    """Refresh changed credential metadata without holding the main DB lock.

    Check file stat signatures on every scan (including atomic replacements).
    Cache only display metadata, never full credential JSON / refresh tokens.
    """
    with _CODEX_METADATA_LOCK:
        out = []
        seen = set()
        for path in _CODEX_DIR.glob("codex-*.json"):
            cache_key = str(path.absolute())
            try:
                stat = path.stat()
            except OSError:
                continue  # A concurrent export/delete can remove a file.
            signature = (int(stat.st_mtime_ns), int(stat.st_size), int(stat.st_ino))
            seen.add(cache_key)
            cached = _CODEX_METADATA_CACHE.get(cache_key)
            if cached is not None and cached[0] == signature:
                if cached[1] is not None:
                    out.append(dict(cached[1]))
                continue
            try:
                content = json.loads(path.read_text(encoding="utf-8"))
            except OSError:
                # Retry unreadable files on the next request, even if their
                # content/stat did not change (e.g. permissions restored).
                _CODEX_METADATA_CACHE.pop(cache_key, None)
                continue
            except (ValueError, UnicodeError):
                _CODEX_METADATA_CACHE[cache_key] = (signature, None)
                continue
            if not isinstance(content, dict):
                _CODEX_METADATA_CACHE[cache_key] = (signature, None)
                continue
            fname = path.name
            # 从文件名抽 email 和 plan：codex-{email}.json 或 codex-{email}-{plan}.json
            stem = path.stem  # codex-邮箱-plan
            without_prefix = stem[len("codex-"):] if stem.startswith("codex-") else stem
            # plan 可能为空。简单做法：直接读 JSON 里的 email（更准），文件名只做 fallback
            email = content.get("email") or ""
            if not email:
                # JSON 里 email 为空（旧 bug 产物），从文件名兜底
                # 文件名格式 codex-{email}-{plan}.json，email 里可能有 - 但是常见邮箱不会有
                # 简单做法：去掉末尾 -plan（如 -free / -plus / -team），剩下的当 email
                parts = without_prefix.rsplit("-", 1)
                if len(parts) == 2 and parts[1].lower() in ("free", "plus", "team", "pro", "enterprise"):
                    email = parts[0]
                else:
                    email = without_prefix
            # 推断 plan
            plan = ""
            if "-" in without_prefix:
                tail = without_prefix.rsplit("-", 1)[-1].lower()
                if tail in ("free", "plus", "team", "pro", "enterprise"):
                    plan = tail
            item = {
                "filename": fname,
                "path": str(path),
                "email": email,
                "plan": plan,
                "account_id": content.get("account_id", ""),
                "type": content.get("type", "codex"),
                "last_refresh": content.get("last_refresh", ""),
                "expired": content.get("expired", ""),
                "access_token_preview": (content.get("access_token", "") or "")[:32],
                "size": stat.st_size,
                "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
                "_mtime_ns": stat.st_mtime_ns,
            }
            _CODEX_METADATA_CACHE[cache_key] = (signature, item)
            out.append(dict(item))
        for cache_key in list(_CODEX_METADATA_CACHE):
            if cache_key not in seen:
                del _CODEX_METADATA_CACHE[cache_key]
        return out


def list_codex_accounts() -> list[dict]:
    """Return credential metadata with fresh export state, not full tokens."""
    rows = _codex_metadata_rows()
    rows.sort(key=lambda r: r["_mtime_ns"], reverse=True)
    with _LOCK:
        export_state = _load_codex_export_state()
        for row in rows:
            es = export_state.get(row["filename"]) or {}
            row["exported_at"] = es.get("exported_at")
            row["exported_count"] = es.get("exported_count", 0)
            row.pop("_mtime_ns", None)
    return rows


def read_codex_credential(filename: str) -> tuple[str, str]:
    """
    读取一个 codex-*.json 文件原始内容。
    Returns: (content_string, filename)
    抛 ValueError：文件名不合法（防目录穿越）/ 不存在。
    """
    with _LOCK:
        # 防注入：只允许 codex-*.json 模式，不允许路径分隔符
        if not filename.startswith("codex-") or not filename.endswith(".json"):
            raise ValueError(f"非法文件名: {filename}")
        if "/" in filename or "\\" in filename or ".." in filename:
            raise ValueError(f"非法文件名: {filename}")
        path = _CODEX_DIR / filename
        if not path.exists() or not path.is_file():
            raise ValueError(f"文件不存在: {filename}")
        return path.read_text(encoding="utf-8"), filename


def mark_codex_exported(filename: str) -> dict:
    """
    标记某个 codex 凭证已导出（导出计数 +1，记录最近导出时间）。
    Returns: 该 filename 当前的导出状态记录。
    """
    return mark_codex_exported_bulk([filename])[filename]


def mark_codex_exported_bulk(filenames: list[str]) -> dict[str, dict]:
    """Save one export marker per unique file with one atomic state write."""
    filenames = list(dict.fromkeys(filenames))
    if not filenames:
        return {}
    with _LOCK:
        # Failed replace must not leave an exported marker in the live cache.
        state = dict(_load_codex_export_state())
        updated = {}
        stamp = _now()
        for filename in filenames:
            rec = dict(state.get(filename) or {"exported_count": 0})
            rec["exported_count"] = int(rec.get("exported_count", 0)) + 1
            rec["exported_at"] = stamp
            state[filename] = rec
            updated[filename] = dict(rec)
        _save_codex_export_state(state)
        return updated


def reset_codex_exported(filename: str) -> None:
    """清掉某个 codex 凭证的导出状态（用户想重置时用）。"""
    with _LOCK:
        state = _load_codex_export_state()
        if filename in state:
            del state[filename]
            _save_codex_export_state(state)


def delete_codex_credential(filename: str) -> bool:
    """删除一个本地 codex-*.json 凭证文件，并清理导出状态。"""
    with _LOCK:
        if not filename.startswith("codex-") or not filename.endswith(".json"):
            raise ValueError(f"非法文件名: {filename}")
        if "/" in filename or "\\" in filename or ".." in filename:
            raise ValueError(f"非法文件名: {filename}")
        path = _CODEX_DIR / filename
        if not path.exists() or not path.is_file():
            return False
        path.unlink()
        state = _load_codex_export_state()
        if filename in state:
            del state[filename]
            _save_codex_export_state(state)
        return True


def codex_accounts_summary(*, _rows: list[dict] | None = None) -> dict:
    """codex 账号汇总：总数 / 已导出 / 未导出。"""
    rows = _codex_metadata_rows() if _rows is None else _rows
    with _LOCK:
        export_state = _load_codex_export_state()
        total = len(rows)
        exported = sum(
            1 for r in rows
            if (export_state.get(r["filename"]) or {}).get("exported_count", 0) > 0
        )
        return {
            "total": total,
            "exported": exported,
            "pending": total - exported,
        }


# ============================================================
# registration_jobs
# ============================================================

def _new_job_row(
    rows: list[dict],
    *,
    email_source: str,
    job_type: str = "registration",
    parent_job_id: int | None = None,
    root_job_id: int | None = None,
    retry_attempt: int = 0,
    retry_action: str | None = None,
    email: str | None = None,
    account_id: int | None = None,
    batch_id: str | None = None,
    flow_snapshot: dict | None = None,
    job_id: int | None = None,
) -> dict:
    job_uuid = str(uuid.uuid4())
    log_file = str(_LOG_DIR / f"{job_uuid}.log")
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    return {
        "id": _next_id(rows) if job_id is None else job_id,
        "job_uuid": job_uuid,
        "job_type": job_type,
        "parent_job_id": parent_job_id,
        "root_job_id": root_job_id,
        "retry_attempt": int(retry_attempt or 0),
        "retry_action": retry_action,
        "email_source": email_source,
        "email": email,
        "status": "pending",
        "error_message": None,
        "log_file": log_file,
        "started_at": None,
        "completed_at": None,
        "account_id": account_id,
        "batch_id": batch_id,
        "flow_snapshot": dict(flow_snapshot or {}),
        "roxy_traffic": None,
        "created_at": _now(),
    }


def _registration_batch_row(
    rows: list[dict], *, count: int, workers: int, email_source: str,
    flow_snapshot: dict, batch_id: str | None = None,
) -> dict:
    snapshot = json.loads(json.dumps(flow_snapshot, ensure_ascii=False))
    sms = snapshot.get("sms") if isinstance(snapshot.get("sms"), dict) else {}
    now = _now()
    return {
        "id": _next_id(rows),
        "batch_id": batch_id or str(uuid.uuid4()),
        "count": int(count),
        "workers": int(workers),
        "email_source": email_source,
        "flow_snapshot": snapshot,
        "sms_budget_limit": sms.get("budget"),
        "sms_budget_spent": 0.0,
        "sms_budget_reserved": 0.0,
        "sms_budget_exhausted": False,
        "sms_budget_exhausted_at": None,
        "sms_budget_error": None,
        "created_at": now,
        "updated_at": now,
    }


def create_registration_batch(
    *, count: int, workers: int, email_source: str, flow_snapshot: dict,
) -> dict:
    """创建一次批量提交的不可变配置快照。"""
    with _LOCK:
        rows = _load_batches()
        row = _registration_batch_row(
            rows, count=count, workers=workers, email_source=email_source, flow_snapshot=flow_snapshot,
        )
        rows.append(row)
        _save_batches(rows)
        return dict(row)


def get_registration_batch(batch_id: str) -> dict | None:
    with _LOCK:
        row = next((r for r in _load_batches() if str(r.get("batch_id")) == str(batch_id)), None)
        return dict(row) if row else None


class BatchMergeConflict(ValueError):
    pass


class BatchDeleteConflict(ValueError):
    pass


def delete_registration_batches(*, batch_ids: list[str]) -> dict:
    """Delete selected batches and their local account data with one bulk save.

    Resolve ownership and validate every selected batch while holding the same
    lock as the cascade. A busy member rejects the request before any deletion.
    """
    if not isinstance(batch_ids, list) or not 1 <= len(batch_ids) <= 200:
        raise ValueError("请选择 1 至 200 个批次")
    if any(not isinstance(value, str) or not value.strip() or len(value) > 128 for value in batch_ids):
        raise ValueError("批次 ID 必须是非空字符串")
    selected = frozenset(value.strip() for value in batch_ids)
    with _LOCK:
        batches = _load_batches()
        by_id = {str(row.get("batch_id") or ""): row for row in batches}
        if selected - by_id.keys():
            raise LookupError("部分批次已不存在或已合并，请刷新列表")
        jobs = _load_jobs()
        accounts = _load_accounts()
        allocations = _load_email_allocations()
        selected_jobs = [row for row in jobs if str(row.get("batch_id") or "") in selected]
        selected_job_ids = {int(row.get("id") or 0) for row in selected_jobs}
        legacy_account_ids = {
            int(row.get("account_id") or 0)
            for row in (*selected_jobs, *(a for a in allocations if str(a.get("batch_id") or "") in selected))
        } - {0}
        targets = [row for row in accounts if (
            str(row.get("registration_batch_id") or "") in selected
            or (
                not row.get("registration_batch_id")
                and (
                    int(row.get("registration_job_id") or 0) in selected_job_ids
                    or (not row.get("registration_job_id") and int(row.get("id") or 0) in legacy_account_ids)
                )
            )
        )]
        jobs_by_batch = _index_by(selected_jobs, "batch_id")
        reason = _batch_delete_block_reason({}, [], targets)
        if reason:
            raise BatchDeleteConflict(f"所选批次{reason}，暂不能删除")
        for batch_id in sorted(selected):
            reason = _batch_delete_block_reason(by_id[batch_id], jobs_by_batch.get(batch_id, []), [])
            if reason:
                raise BatchDeleteConflict(f"批次 {batch_id} {reason}，暂不能删除")
        if any(str(row.get("batch_id") or "") in selected and row.get("status") == "leased" for row in allocations):
            raise BatchDeleteConflict("所选批次仍有活跃邮箱租约，暂不能删除")

        deleted, _ = delete_accounts(
            account_ids=[int(row["id"]) for row in targets], _batch_ids=selected,
        )
        return {
            "deleted_batch_ids": sorted(selected),
            "deleted_count": len(selected),
            "deleted_account_count": len(deleted),
            "deleted_job_count": len(jobs) - len(_load_jobs()),
            "deleted_allocation_count": len(allocations) - len(_load_email_allocations()),
        }


def _resolve_registration_batch_id(batch_id: str | None) -> str | None:
    """Resolve stale producer context under _LOCK; bulk callers resolve once."""
    if not batch_id:
        return batch_id
    for row in _load_batches():
        if row.get("batch_id") == batch_id or batch_id in (row.get("merged_batch_ids") or []):
            return str(row["batch_id"])
    return batch_id


def _batch_merge_journal_path() -> Path:
    target = _BATCHES_JSON.resolve(strict=False) if _BATCHES_JSON.is_symlink() else _BATCHES_JSON
    return target.with_name(target.name + ".merge.json")


def _recover_registration_batch_merge() -> None:
    """Roll a committed merge forward before exposing any of its four tables."""
    global _BATCH_MERGE_RECOVERING
    with _LOCK:
        if _BATCH_MERGE_RECOVERING:
            return
        journal = _batch_merge_journal_path()
        if not journal.exists():
            return
        # Unlike ordinary optional storage, an unreadable merge intent must not
        # be ignored: some tables may already have been moved before a crash.
        plan = json.loads(journal.read_text(encoding="utf-8"))
        if (
            not isinstance(plan, dict) or plan.get("version") != 1
            or not isinstance(plan.get("target_batch"), dict)
            or not isinstance(plan.get("source_batch_ids"), list)
            or not plan.get("target_batch", {}).get("merge_revision")
        ):
            raise RuntimeError("批次合并恢复记录无效")
        _BATCH_MERGE_RECOVERING = True
        try:
            target = plan["target_batch"]
            target_id = target["batch_id"]
            source_ids = set(plan["source_batch_ids"])
            jobs = _load_jobs()
            if any(row.get("batch_id") in source_ids for row in jobs):
                _save_jobs([
                    {**row, "batch_id": target_id} if row.get("batch_id") in source_ids else row
                    for row in jobs
                ])

            accounts = _load_accounts()
            changes = [
                ({**row, "registration_batch_id": target_id, "updated_at": target["updated_at"]}, row)
                for row in accounts if row.get("registration_batch_id") in source_ids
            ]
            if changes:
                replacements = {row["id"]: row for row, _ in changes}
                _save_account_progress_many(
                    [replacements.get(row["id"], row) for row in accounts], changes,
                )

            allocations = _load_email_allocations()
            if any(row.get("batch_id") in source_ids for row in allocations):
                _save_email_allocations([
                    {**row, "batch_id": target_id} if row.get("batch_id") in source_ids else row
                    for row in allocations
                ])

            batches = _load_batches()
            current = next((row for row in batches if row.get("batch_id") == target_id), None)
            if current is None:
                raise RuntimeError("批次合并恢复失败：目标批次不存在")
            if current.get("merge_revision") != target["merge_revision"]:
                _save_batches([
                    target if row.get("batch_id") == target_id else row
                    for row in batches if row.get("batch_id") not in source_ids
                ])
            journal.unlink()
            with _JSON_CACHE_LOCK:
                _JSON_CACHE.pop(str(journal), None)
        finally:
            _BATCH_MERGE_RECOVERING = False


def _batch_merge_block_reason(batch: dict, jobs: list[dict], accounts: list[dict]) -> str | None:
    if any(str(job.get("status") or "").lower() not in {
        "success", "failed", "stopped", "cancelled",
    } for job in jobs):
        return "仍有排队、运行或停止中的任务"
    if float(batch.get("sms_budget_reserved") or 0.0) > 0:
        return "仍有未结算的短信预算"
    for account in accounts:
        if any(str(account.get(field) or "").lower() in {"queued", "running", "retrying"} for field in (
            "codex_status", "codex_agent_status", "team_status", "team_invite_status", "totp_status",
        )):
            return "仍有排队或运行中的账号补接任务"
    return None


def _batch_delete_block_reason(batch: dict, jobs: list[dict], accounts: list[dict]) -> str | None:
    reason = _batch_merge_block_reason(batch, jobs, accounts)
    if reason:
        return reason
    for account in accounts:
        if str(account.get("momo_status") or "").lower() in {"queued", "running"}:
            return "仍有 MoMo 提链任务在执行"
        if _paypal_account_is_active(account):
            return "仍有 PayPal 提链或支付任务在执行"
        if str(account.get("health_status") or "").lower() in {"queued", "running"}:
            return "仍有账号验活任务在执行"
    return None


def merge_registration_batches(*, target_batch_id: str, batch_ids: list[str]) -> dict:
    """Move completed batches into one retained ID, preserving task snapshots."""
    if not isinstance(target_batch_id, str) or not target_batch_id.strip():
        raise ValueError("请选择保留的目标批次")
    if not isinstance(batch_ids, list) or not 2 <= len(batch_ids) <= 200:
        raise ValueError("请选择 2 至 200 个批次")
    if any(not isinstance(value, str) or not value.strip() or len(value) > 128 for value in batch_ids):
        raise ValueError("批次 ID 必须是非空字符串")
    selected = list(dict.fromkeys(value.strip() for value in batch_ids))
    target_id = target_batch_id.strip()
    if len(selected) < 2 or target_id not in selected:
        raise ValueError("至少选择两个不同批次，目标批次必须在所选批次中")

    with _LOCK:
        batches = _load_batches()
        by_id = {str(row.get("batch_id") or ""): row for row in batches}
        target = by_id.get(target_id)
        if target is None:
            raise LookupError("目标批次不存在，请刷新列表")
        already_merged = set(target.get("merged_batch_ids") or [])
        if any(value not in by_id and value not in already_merged for value in selected):
            raise LookupError("部分批次已不存在或已合并到其他批次，请刷新列表")
        source_ids = {value for value in selected if value != target_id and value in by_id}
        result = {
            "target_batch_id": target_id, "merged_batch_ids": sorted(source_ids),
            "merged_count": len(source_ids), "moved_accounts": 0, "moved_jobs": 0,
            "moved_allocations": 0, "already_merged": not source_ids,
        }
        if not source_ids:
            return result

        selected_ids = source_ids | {target_id}
        jobs = _load_jobs()
        accounts = _load_accounts()
        allocations = _load_email_allocations()
        jobs_by_batch = _index_by(jobs, "batch_id")
        accounts_by_batch = _index_by(accounts, "registration_batch_id")
        for batch_id in selected_ids:
            reason = _batch_merge_block_reason(
                by_id[batch_id], jobs_by_batch.get(batch_id, []), accounts_by_batch.get(batch_id, []),
            )
            if reason:
                raise BatchMergeConflict(f"批次 {batch_id} {reason}，暂不能合并")
        if any(row.get("batch_id") in selected_ids and row.get("status") == "leased" for row in allocations):
            raise BatchMergeConflict("所选批次仍有活跃邮箱租约，暂不能合并")
        account_ids = {row["id"] for row in accounts if row.get("registration_batch_id") in selected_ids}
        if any(row.get("account_id") in account_ids and row.get("status") in {
            "pending", "queued", "running", "stopping",
        } for row in jobs):
            raise BatchMergeConflict("所选批次的账号仍有关联活跃任务，暂不能合并")

        members = [target, *(by_id[value] for value in sorted(source_ids))]
        originals = [original for row in members for original in (row.get("merge_sources") or [row])]
        merged = deepcopy(target)
        merged.update({
            "count": sum(int(row.get("count") or 0) for row in members),
            "sms_budget_spent": round(sum(float(row.get("sms_budget_spent") or 0.0) for row in members), 6),
            "sms_budget_reserved": 0.0,
            "sms_budget_limit": (
                None if any(row.get("sms_budget_limit") in (None, "") for row in members)
                else round(sum(float(row["sms_budget_limit"]) for row in members), 6)
            ),
            "merge_sources": deepcopy(originals),
            "merged_batch_ids": sorted((
                already_merged | source_ids
                | {value for row in members for value in (row.get("merged_batch_ids") or [])}
            ) - {target_id}),
            "email_sources": sorted({str(row.get("email_source") or "") for row in originals} - {""}),
            "registration_drivers": sorted({_registration_job_driver(row) for row in originals} - {""}),
            "merge_revision": uuid.uuid4().hex,
            "merged_at": _now(), "updated_at": _now(),
        })
        # A merge is not permission to reset a tripped spending circuit breaker.
        exhausted = next((row for row in members if row.get("sms_budget_exhausted")), None)
        if exhausted:
            for key in ("sms_budget_exhausted", "sms_budget_exhausted_at", "sms_budget_error"):
                merged[key] = exhausted.get(key)
        result.update({
            "moved_jobs": sum(row.get("batch_id") in source_ids for row in jobs),
            "moved_accounts": sum(row.get("registration_batch_id") in source_ids for row in accounts),
            "moved_allocations": sum(row.get("batch_id") in source_ids for row in allocations),
        })
        # The small intent is the commit point. Every step is idempotent; an
        # interrupted write is completed on the next table read, even after restart.
        _write_json(_batch_merge_journal_path(), {
            "version": 1, "source_batch_ids": sorted(source_ids), "target_batch": merged,
        })
        _recover_registration_batch_merge()
        return result


# ============================================================
# 管理聚合：批次 / SMS 成本 / Codex 失败阶段 / 仪表盘
# 这些函数只读不写，返回值全部要经 mask_job_secrets 或 _mask_account_secrets。
# ============================================================

def _batch_budget_state(row: dict, spent: float) -> str:
    """批次预算档位：unlimited / exhausted / over / near / ok。"""
    if row.get("sms_budget_exhausted"):
        return "exhausted"
    limit = row.get("sms_budget_limit")
    try:
        limit_value = float(limit)
    except (TypeError, ValueError):
        return "unlimited"
    if limit_value <= 0:
        return "unlimited"
    ratio = spent / limit_value
    return "over" if ratio >= 1.0 else "near" if ratio >= 0.8 else "ok"


def _index_by(rows: list[dict], key: str) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for row in rows:
        out.setdefault(str(row.get(key) or ""), []).append(row)
    return out


def _registration_job_driver(job: dict) -> str:
    snapshot = job.get("flow_snapshot") if isinstance(job.get("flow_snapshot"), dict) else {}
    return str(snapshot.get("registration_driver") or "").strip().lower()


def roxy_traffic_summary(
    *, batch_id: str | None = None, _rows: list[dict] | None = None
) -> dict:
    """聚合 Roxy 任务的 SOCKS5 隧道载荷；旧任务单列为未采集。"""
    if _rows is None:
        with _LOCK:
            _rows = _load_jobs()
    target_batch = str(batch_id or "").strip() or None
    jobs = [
        row for row in (_rows or [])
        if str(row.get("job_type") or "registration") == "registration"
        and _registration_job_driver(row) == "roxy"
        and (target_batch is None or str(row.get("batch_id") or "") == target_batch)
    ]

    uploaded = 0
    downloaded = 0
    connections = 0
    measured = 0
    completed = 0
    running = 0
    missing = 0
    unavailable = 0
    by_job_status: dict[str, dict] = {}
    last_updated_at = ""
    for job in jobs:
        traffic = job.get("roxy_traffic") if isinstance(job.get("roxy_traffic"), dict) else None
        if not traffic:
            missing += 1
            continue
        if traffic.get("measurement") != "socks5_tunnel_payload":
            unavailable += 1
            continue
        measured += 1
        state = str(traffic.get("status") or "unknown").strip().lower()
        if state == "complete":
            completed += 1
        elif state == "running":
            running += 1
        try:
            up = max(0, int(traffic.get("uploaded_bytes") or 0))
            down = max(0, int(traffic.get("downloaded_bytes") or 0))
            one_connections = max(0, int(traffic.get("connection_count") or 0))
        except (TypeError, ValueError):
            up = down = one_connections = 0
        uploaded += up
        downloaded += down
        connections += one_connections
        job_status = str(job.get("status") or "unknown")
        bucket = by_job_status.setdefault(job_status, {
            "status": job_status,
            "jobs": 0,
            "uploaded_bytes": 0,
            "downloaded_bytes": 0,
            "total_bytes": 0,
        })
        bucket["jobs"] += 1
        bucket["uploaded_bytes"] += up
        bucket["downloaded_bytes"] += down
        bucket["total_bytes"] += up + down
        stamp = str(traffic.get("updated_at") or traffic.get("finished_at") or traffic.get("started_at") or "")
        if stamp > last_updated_at:
            last_updated_at = stamp

    total = uploaded + downloaded
    status_rows = sorted(by_job_status.values(), key=lambda row: (-row["total_bytes"], row["status"]))
    return {
        "schema_version": 1,
        "driver": "roxy",
        "batch_id": target_batch,
        "measurement": "socks5_tunnel_payload",
        "total_jobs": len(jobs),
        "measured_jobs": measured,
        "unmeasured_jobs": missing + unavailable,
        "missing_jobs": missing,
        "completed_jobs": completed,
        "running_jobs": running,
        "unavailable_jobs": unavailable,
        "uploaded_bytes": uploaded,
        "downloaded_bytes": downloaded,
        "total_bytes": total,
        "average_total_bytes": round(total / measured, 2) if measured else 0.0,
        "connection_count": connections,
        "by_job_status": status_rows,
        "last_updated_at": last_updated_at or None,
    }


def _account_sms_cost_value(row: dict) -> float | None:
    raw = row.get("sms_cost")
    if raw is None or raw == "":
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _batch_stats(batch: dict, jobs: list[dict], accounts: list[dict]) -> dict:
    """把一个批次的任务/账号聚合成列表页要用的统计字段。"""
    job_status: dict[str, int] = {}
    for job in jobs:
        status = str(job.get("status") or "unknown")
        job_status[status] = job_status.get(status, 0) + 1

    sms_cost_actual = 0.0
    sms_cost_accounts = 0
    codex_connected = 0
    for account in accounts:
        if str(account.get("codex_refresh_token") or ""):
            codex_connected += 1
        cost = _account_sms_cost_value(account)
        if cost is None:
            continue
        sms_cost_actual += cost
        sms_cost_accounts += 1

    spent = float(batch.get("sms_budget_spent") or 0.0)
    limit = batch.get("sms_budget_limit")
    try:
        ratio = spent / float(limit) if float(limit) > 0 else None
    except (TypeError, ValueError, ZeroDivisionError):
        ratio = None

    last_job_at = ""
    for job in jobs:
        stamp = str(job.get("completed_at") or job.get("started_at") or job.get("created_at") or "")
        if stamp > last_job_at:
            last_job_at = stamp

    traffic = roxy_traffic_summary(
        batch_id=str(batch.get("batch_id") or "") or None,
        _rows=jobs,
    )

    return {
        "job_total": len(jobs),
        "job_success": job_status.get("success", 0),
        "job_failed": job_status.get("failed", 0),
        "job_running": job_status.get("running", 0),
        "job_pending": job_status.get("pending", 0),
        "job_stopping": job_status.get("stopping", 0),
        "job_stopped": job_status.get("stopped", 0),
        "job_cancelled": job_status.get("cancelled", 0),
        "account_total": len(accounts),
        "account_codex_connected": codex_connected,
        "sms_cost_actual": round(sms_cost_actual, 6),
        "sms_cost_accounts": sms_cost_accounts,
        "budget_usage_ratio": round(ratio, 4) if ratio is not None else None,
        "budget_state": _batch_budget_state(batch, spent),
        "last_job_at": last_job_at or None,
        "roxy_traffic": traffic,
        "merge_block_reason": _batch_merge_block_reason(batch, jobs, accounts),
        "delete_block_reason": _batch_delete_block_reason(batch, jobs, accounts),
    }


def query_registration_batches(
    *,
    page: int = 1,
    page_size: int = 20,
    q: str = "",
    driver: str = "",
    budget_state: str = "",
    sort_by: str = "id",
    sort_order: str = "desc",
) -> dict:
    """批次管理分页查询，附带任务/账号统计与 SMS 花费。

    返回值含 flow_snapshot（内有 SMS 密钥），调用方必须套 mask_job_secrets。
    """
    page = max(1, int(page or 1))
    page_size = max(1, min(200, int(page_size or 20)))
    query = str(q or "").strip().lower()
    driver_filter = str(driver or "").strip().lower()
    state_filter = str(budget_state or "").strip().lower()

    with _LOCK:
        batches = _load_batches()
        jobs_by_batch = _index_by(_load_jobs(), "batch_id")
        accounts_by_batch = _index_by(_load_accounts(), "registration_batch_id")

    candidates = []
    for batch in batches:
        snapshot = batch.get("flow_snapshot") if isinstance(batch.get("flow_snapshot"), dict) else {}
        drivers = batch.get("registration_drivers") or [str(snapshot.get("registration_driver") or "")]
        if driver_filter and driver_filter not in {str(value).strip().lower() for value in drivers}:
            continue
        batch_id = str(batch.get("batch_id") or "")
        row = dict(batch)
        row.pop("merge_sources", None)
        row["registration_driver"] = drivers[0] if len(drivers) == 1 else "mixed"
        row["codex_oauth"] = bool(snapshot.get("codex_oauth"))
        if query and query not in " ".join(str(row.get(k) or "").lower() for k in (
            "batch_id", "email_source", "registration_driver", "email_sources", "registration_drivers",
            "merged_batch_ids",
        )):
            continue
        row["budget_state"] = _batch_budget_state(batch, float(batch.get("sms_budget_spent") or 0.0))
        if state_filter and row["budget_state"] != state_filter:
            continue
        candidates.append((batch, row, batch_id))

    allowed_sort = {"id", "created_at", "sms_budget_spent", "job_total", "account_total"}
    key = sort_by if sort_by in allowed_sort else "id"
    reverse = str(sort_order or "desc").lower() != "asc"
    if key == "job_total":
        candidates.sort(key=lambda entry: len(jobs_by_batch.get(entry[2], [])), reverse=reverse)
    elif key == "account_total":
        candidates.sort(key=lambda entry: len(accounts_by_batch.get(entry[2], [])), reverse=reverse)
    elif key == "id":
        candidates.sort(key=lambda entry: float(entry[1].get("id") or 0), reverse=reverse)
    elif key == "sms_budget_spent":
        candidates.sort(key=lambda entry: float(entry[1].get("sms_budget_spent") or 0.0), reverse=reverse)
    else:
        candidates.sort(key=lambda entry: str(entry[1].get(key) or ""), reverse=reverse)

    total = len(candidates)
    sms_cost_total = 0.0
    for _batch, _row, batch_id in candidates:
        batch_cost = 0.0
        for account in accounts_by_batch.get(batch_id, []):
            cost = _account_sms_cost_value(account)
            if cost is not None:
                batch_cost += cost
        sms_cost_total += round(batch_cost, 6)
    start = (page - 1) * page_size
    page_entries = candidates[start:start + page_size]
    page_items = []
    for batch, row, batch_id in page_entries:
        row.update(_batch_stats(
            batch, jobs_by_batch.get(batch_id, []), accounts_by_batch.get(batch_id, []),
        ))
        page_items.append(row)
    return {
        "items": page_items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "summary": {
            "total": total,
            "exhausted": sum(1 for _batch, row, _id in candidates if row["budget_state"] == "exhausted"),
            "over": sum(1 for _batch, row, _id in candidates if row["budget_state"] == "over"),
            "near": sum(1 for _batch, row, _id in candidates if row["budget_state"] == "near"),
            "sms_cost_total": round(sms_cost_total, 6),
        },
    }


def get_registration_batch_detail(batch_id: str) -> dict | None:
    """单批次详情：快照 + 全部任务 + 关联账号（账号已脱敏）。

    jobs 仍含 flow_snapshot，调用方必须套 mask_job_secrets。
    """
    target = str(batch_id or "").strip()
    if not target:
        return None
    with _LOCK:
        batch = next((r for r in _load_batches() if str(r.get("batch_id")) == target), None)
        if batch is None:
            return None
        jobs = [r for r in _load_jobs() if str(r.get("batch_id") or "") == target]
        raw_accounts = [r for r in _load_accounts() if str(r.get("registration_batch_id") or "") == target]

    out = dict(batch)
    out["stats"] = _batch_stats(batch, jobs, raw_accounts)
    out["roxy_traffic"] = roxy_traffic_summary(batch_id=target, _rows=jobs)
    # 与 list_jobs 保持一致：db 层只返回原始行，retry_info 由 webui 层补。
    out["jobs"] = sorted((dict(r) for r in jobs), key=lambda r: int(r.get("id") or 0), reverse=True)
    out["accounts"] = [_mask_account_secrets(r) for r in raw_accounts]
    return out


def registration_batches_summary(
    *, _accounts: list[dict] | None = None, _jobs: list[dict] | None = None,
) -> dict:
    """全局批次汇总，供仪表盘使用。不含 flow_snapshot，无需脱敏。"""
    with _LOCK:
        batches = _load_batches()
        jobs = _load_jobs() if _jobs is None else _jobs
        accounts = _load_accounts() if _accounts is None else _accounts
    jobs_by_batch = _index_by(jobs, "batch_id")
    accounts_by_batch = _index_by(accounts, "registration_batch_id")

    job_status: dict[str, int] = {}
    for job in jobs:
        status = str(job.get("status") or "unknown").strip().lower()
        job_status[status] = job_status.get(status, 0) + 1
    job_pending = job_status.get("pending", 0)
    job_running = job_status.get("running", 0)
    job_stopping = job_status.get("stopping", 0)
    today = _now()[:10]
    job_today_success = sum(
        1 for job in jobs
        if job.get("status") == "success" and str(job.get("completed_at") or "")[:10] == today
    )
    codex_connected = sum(
        1 for account in accounts
        if not bool(account.get("archived")) and str(account.get("codex_refresh_token") or "")
    )

    budget_limit_total = 0.0
    budget_spent_total = 0.0
    sms_cost_total = 0.0
    exhausted = 0
    with_budget = 0
    # Totals need only costs and budgets; traffic and operation eligibility
    # checks are page/detail fields and must not run for every historic batch.
    for batch in batches:
        batch_id = str(batch.get("batch_id") or "")
        budget_spent_total += float(batch.get("sms_budget_spent") or 0.0)
        batch_cost = 0.0
        for account in accounts_by_batch.get(batch_id, []):
            cost = _account_sms_cost_value(account)
            if cost is not None:
                batch_cost += cost
        sms_cost_total += round(batch_cost, 6)
        if batch.get("sms_budget_exhausted"):
            exhausted += 1
        try:
            limit_value = float(batch.get("sms_budget_limit"))
        except (TypeError, ValueError):
            limit_value = 0.0
        if limit_value > 0:
            with_budget += 1
            budget_limit_total += limit_value

    recent = []
    for batch in sorted(batches, key=lambda r: str(r.get("created_at") or ""), reverse=True)[:5]:
        batch_id = str(batch.get("batch_id") or "")
        stats = _batch_stats(batch, jobs_by_batch.get(batch_id, []), accounts_by_batch.get(batch_id, []))
        recent.append({
            "batch_id": batch_id,
            "created_at": batch.get("created_at"),
            "count": batch.get("count"),
            "email_source": batch.get("email_source"),
            "job_total": stats["job_total"],
            "job_success": stats["job_success"],
            "job_failed": stats["job_failed"],
            "budget_state": stats["budget_state"],
            "sms_cost_actual": stats["sms_cost_actual"],
        })

    return {
        "total": len(batches),
        "with_budget": with_budget,
        "exhausted": exhausted,
        "budget_limit_total": round(budget_limit_total, 6),
        "budget_spent_total": round(budget_spent_total, 6),
        "sms_cost_total": round(sms_cost_total, 6),
        "job_pending": job_pending,
        "job_running": job_running,
        "job_stopping": job_stopping,
        "active_jobs": job_pending + job_running + job_stopping,
        "job_today_success": job_today_success,
        "codex_connected": codex_connected,
        "recent": recent,
    }


def _bucket_totals(buckets: dict[str, dict]) -> list[dict]:
    out = []
    for name, agg in buckets.items():
        count = agg["count"]
        out.append({
            **agg["label"],
            "count": count,
            "cost": round(agg["cost"], 6),
            "avg": round(agg["cost"] / count, 6) if count else 0.0,
        })
    out.sort(key=lambda r: r["cost"], reverse=True)
    return out


def sms_cost_summary(*, _rows: list[dict] | None = None) -> dict:
    """SMS 成本聚合，按国家 / 供应商 / 日期分组。

    只读账号的 sms_cost / sms_country / sms_provider_id / created_at，不含任何凭证。
    """
    if _rows is None:
        with _LOCK:
            _rows = _load_accounts()

    by_country: dict[str, dict] = {}
    by_provider: dict[str, dict] = {}
    by_day: dict[str, dict] = {}
    total_cost = 0.0
    total_count = 0
    missing_cost = 0

    for row in _rows:
        raw = row.get("sms_cost")
        if raw is None or raw == "":
            if str(row.get("sms_provider_id") or ""):
                missing_cost += 1
            continue
        try:
            cost = float(raw)
        except (TypeError, ValueError):
            missing_cost += 1
            continue

        total_cost += cost
        total_count += 1
        country = str(row.get("sms_country") or "未知")
        provider = str(row.get("sms_provider_id") or "未知")
        day = str(row.get("created_at") or "")[:10] or "未知"

        for bucket, name, label in (
            (by_country, country, {"country": country}),
            (by_provider, provider, {"provider": provider}),
            (by_day, day, {"day": day}),
        ):
            agg = bucket.setdefault(name, {"count": 0, "cost": 0.0, "label": label})
            agg["count"] += 1
            agg["cost"] += cost

    days = _bucket_totals(by_day)
    days.sort(key=lambda r: r["day"])
    return {
        "total_cost": round(total_cost, 6),
        "total_count": total_count,
        "avg_cost": round(total_cost / total_count, 6) if total_count else 0.0,
        "missing_cost_count": missing_cost,
        "by_country": _bucket_totals(by_country),
        "by_provider": _bucket_totals(by_provider),
        "by_day": days[-30:],
    }


def codex_failure_stage_summary(*, _rows: list[dict] | None = None) -> dict:
    """Codex 失败阶段诊断聚合。只投影 id/email/stage/error/at，绝不整行复制。"""
    if _rows is None:
        with _LOCK:
            _rows = _load_accounts()

    live = [r for r in _rows if not bool(r.get("archived"))]
    stages: dict[str, dict] = {}
    by_driver: dict[str, dict] = {}
    recent: list[dict] = []

    for row in live:
        driver = str(row.get("registration_driver") or "unknown")
        agg = by_driver.setdefault(driver, {"driver": driver, "failed": 0, "total": 0})
        agg["total"] += 1

        stage = _codex_failure_stage_of(row)
        if not stage:
            continue
        agg["failed"] += 1

        item = {
            "id": row.get("id"),
            "email": row.get("email"),
            "stage": stage,
            "error": str(row.get("codex_last_error") or row.get("codex_error") or "")[:300],
            "at": row.get("codex_last_attempt_at"),
        }
        bucket = stages.setdefault(stage, {"stage": stage, "count": 0, "sample_errors": [], "account_ids": []})
        bucket["count"] += 1
        if len(bucket["sample_errors"]) < 5 and item["error"]:
            bucket["sample_errors"].append(item)
        if len(bucket["account_ids"]) < 200:
            bucket["account_ids"].append(row.get("id"))
        recent.append(item)

    total_failed = sum(b["count"] for b in stages.values())
    for bucket in stages.values():
        bucket["ratio"] = round(bucket["count"] / total_failed, 4) if total_failed else 0.0

    drivers = list(by_driver.values())
    for agg in drivers:
        agg["fail_ratio"] = round(agg["failed"] / agg["total"], 4) if agg["total"] else 0.0
    drivers.sort(key=lambda r: r["failed"], reverse=True)

    recent.sort(key=lambda r: str(r.get("at") or ""), reverse=True)
    return {
        "total_failed": total_failed,
        "stages": sorted(stages.values(), key=lambda r: r["count"], reverse=True),
        "by_driver": drivers,
        "recent_failures": recent[:20],
    }


def dashboard_summary() -> dict:
    """仪表盘聚合：一次调用覆盖账号 / 任务 / 邮箱池 / Codex / SMS / 批次。

    账号相关的三个聚合共用一次 _load_accounts()，避免重复读盘。
    """
    with _LOCK:
        accounts = _load_accounts()
        jobs = _load_jobs()

    live = [r for r in accounts if not bool(r.get("archived"))]
    job_status: dict[str, int] = {}
    for job in jobs:
        job_status[str(job.get("status") or "unknown")] = job_status.get(str(job.get("status") or "unknown"), 0) + 1

    today = _now()[:10]
    today_jobs = [j for j in jobs if str(j.get("completed_at") or "")[:10] == today]
    by_driver: dict[str, dict] = {}
    for row in live:
        driver = str(row.get("registration_driver") or "unknown")
        agg = by_driver.setdefault(driver, {"driver": driver, "total": 0, "codex_connected": 0})
        agg["total"] += 1
        if str(row.get("codex_refresh_token") or ""):
            agg["codex_connected"] += 1

    plans: dict[str, int] = {}
    for row in live:
        plan = str(row.get("current_plan_type") or row.get("plan_type") or "unknown")
        plans[plan] = plans.get(plan, 0) + 1

    connected = sum(1 for r in live if str(r.get("codex_refresh_token") or ""))
    health_alive = sum(1 for r in live if str(r.get("health_status") or "unchecked") == "alive")
    health_dead = sum(1 for r in live if str(r.get("health_status") or "unchecked") == "dead")
    health_token_invalid = sum(
        1 for r in live if str(r.get("health_status") or "unchecked") == "token_invalid"
    )
    health_error = sum(1 for r in live if str(r.get("health_status") or "unchecked") == "error")
    return {
        "accounts": {
            "total": len(accounts),
            # live 是旧 API 键，历史含义实际为“未归档”，保留兼容。
            "live": len(live),
            "unarchived": len(live),
            "archived": len(accounts) - len(live),
            "health_alive": health_alive,
            "health_dead": health_dead,
            "health_token_invalid": health_token_invalid,
            "health_error": health_error,
            "codex_connected": connected,
            "codex_not_connected": len(live) - connected,
            "by_driver": sorted(by_driver.values(), key=lambda r: r["total"], reverse=True),
            "by_plan": sorted(
                ({"plan": k, "count": v} for k, v in plans.items()),
                key=lambda r: r["count"], reverse=True,
            ),
        },
        "jobs": {
            "total": len(jobs),
            "running": job_status.get("running", 0),
            "pending": job_status.get("pending", 0),
            "success": job_status.get("success", 0),
            "failed": job_status.get("failed", 0),
            "today_success": sum(1 for j in today_jobs if j.get("status") == "success"),
            "today_failed": sum(1 for j in today_jobs if j.get("status") == "failed"),
        },
        "pools": {
            "outlook": outlook_pool_summary(),
            "generic_api": generic_api_email_pool_summary(),
            "icloud": icloud_email_pool_summary(),
            "mailcom": mailcom_pool_summary(),
            "domain": domain_email_pool_summary(),
        },
        "codex": {
            **codex_accounts_summary(),
            "failures": codex_failure_stage_summary(_rows=accounts),
        },
        "sms": sms_cost_summary(_rows=accounts),
        "batches": registration_batches_summary(_accounts=accounts, _jobs=jobs),
        "roxy_traffic": roxy_traffic_summary(_rows=jobs),
        "generated_at": _now(),
    }


def delete_registration_batch_if_orphan(batch_id: str) -> bool:
    """仅删除不再被任务、账号或邮箱分配引用的空批次。"""
    target = str(batch_id or "").strip()
    if not target:
        return False
    with _LOCK:
        if any(str(row.get("batch_id") or "") == target for row in _load_jobs()):
            return False
        if any(str(row.get("registration_batch_id") or "") == target for row in _load_accounts()):
            return False
        if any(str(row.get("batch_id") or "") == target for row in _load_email_allocations()):
            return False
        rows = _load_batches()
        remaining = [row for row in rows if str(row.get("batch_id") or "") != target]
        if len(remaining) == len(rows):
            return False
        _save_batches(remaining)
        return True


def update_batch_sms_budget(batch_id: str, *, spent: float, reserved: float = 0.0) -> bool:
    with _LOCK:
        rows = _load_batches()
        row = next((r for r in rows if str(r.get("batch_id")) == str(batch_id)), None)
        if row is None:
            return False
        previous = dict(row)
        # Concurrent workers may persist snapshots out of order. Money already
        # spent is monotonic even though transient reservations may go down.
        row["sms_budget_spent"] = round(max(
            float(row.get("sms_budget_spent") or 0.0),
            float(spent or 0.0),
        ), 6)
        row["sms_budget_reserved"] = round(float(reserved or 0.0), 6)
        row["updated_at"] = _now()
        _save_batch_progress(rows, row, previous)
        return True


def mark_batch_sms_budget_exhausted(batch_id: str, error: str) -> bool:
    """Persist a one-way batch circuit breaker once no SMS budget remains."""
    with _LOCK:
        rows = _load_batches()
        row = next((r for r in rows if str(r.get("batch_id")) == str(batch_id)), None)
        if row is None:
            return False
        row["sms_budget_exhausted"] = True
        row["sms_budget_exhausted_at"] = row.get("sms_budget_exhausted_at") or _now()
        row["sms_budget_error"] = str(error or "短信预算已耗尽")[:1000]
        row["updated_at"] = _now()
        _save_batches(rows)
        return True


def get_batch_sms_budget_error(batch_id: str | None) -> str | None:
    if not batch_id:
        return None
    batch = get_registration_batch(str(batch_id)) or {}
    if not batch.get("sms_budget_exhausted"):
        return None
    return str(batch.get("sms_budget_error") or "短信预算已耗尽")


def create_job(
    email_source: str,
    *,
    batch_id: str | None = None,
    flow_snapshot: dict | None = None,
) -> dict:
    """创建一个首次执行的 pending 注册任务。"""
    return create_registration_jobs_bulk(
        count=1, email_source=email_source, batch_id=batch_id, flow_snapshot=flow_snapshot,
    )[0]


def create_registration_jobs_bulk(
    *, count: int, email_source: str, batch_id: str | None = None,
    flow_snapshot: dict | None = None,
) -> list[dict]:
    """Allocate IDs once and durably save the batch before dispatching workers."""
    count = int(count)
    if count <= 0:
        raise ValueError("count 必须是正整数")
    with _LOCK:
        rows = _load_jobs()
        batch_id = _resolve_registration_batch_id(batch_id)
        next_id = _next_id(rows)
        created = [
            _new_job_row(
                rows, job_id=next_id + offset, email_source=email_source,
                batch_id=batch_id, flow_snapshot=deepcopy(flow_snapshot or {}),
            )
            for offset in range(count)
        ]
        # Don't append to _JSON_CACHE's list before replace has succeeded.
        _save_jobs([*rows, *created])
        return deepcopy(created)


def create_retry_job(
    source_job_id: int,
    *,
    job_type: str,
    email_source: str,
    email: str | None = None,
    account_id: int | None = None,
) -> tuple[dict, bool]:
    """原子创建重试子任务；同一任务链已有活跃任务时直接复用。"""
    with _LOCK:
        rows = _load_jobs()
        source = next((r for r in rows if int(r.get("id") or 0) == int(source_job_id)), None)
        if source is None:
            raise LookupError("任务不存在")
        if source.get("status") not in ("failed", "stopped", "cancelled"):
            raise ValueError(f"当前状态不支持重试：{source.get('status')}")

        root_id = int(source.get("root_job_id") or source.get("id"))
        active_states = {"pending", "running", "stopping"}
        active = next((
            r for r in rows
            if int(r.get("id") or 0) != int(source_job_id)
            and int(r.get("root_job_id") or 0) == root_id
            and r.get("status") in active_states
        ), None)
        if active is not None:
            if active.get("job_type", "registration") != job_type:
                raise ValueError(f"已有其他类型重试任务 #{active.get('id')} 在排队或运行中")
            return dict(active), False

        attempts = [
            int(r.get("retry_attempt") or 0)
            for r in rows
            if int(r.get("id") or 0) == root_id or int(r.get("root_job_id") or 0) == root_id
        ]
        row = _new_job_row(
            rows,
            email_source=email_source,
            job_type=job_type,
            parent_job_id=int(source_job_id),
            root_job_id=root_id,
            retry_attempt=(max(attempts) if attempts else 0) + 1,
            retry_action=("codex" if job_type == "codex_retry" else "registration"),
            email=email,
            account_id=account_id,
            batch_id=source.get("batch_id"),
            flow_snapshot=source.get("flow_snapshot") if isinstance(source.get("flow_snapshot"), dict) else {},
        )
        rows.append(row)
        _save_jobs(rows)
        return dict(row), True


def create_account_codex_job(
    *, account_id: int, email: str, email_source: str, sms_snapshot: dict | None = None,
    batch_id: str | None = None, parent_job_id: int | None = None,
) -> tuple[dict, bool]:
    """为已注册账号创建独立 Codex OAuth 任务，同账号只允许一个活跃任务。"""
    with _LOCK:
        rows = _load_jobs()
        batch_id = _resolve_registration_batch_id(batch_id)
        if parent_job_id is not None:
            # 注册自动链路以原注册任务作为持久化幂等键。PayPal 套餐核验可能
            # 重复回调，但同一次注册只能自动派生一个 Codex 子任务。
            derived = next((
                r for r in rows
                if int(r.get("account_id") or 0) == int(account_id)
                and int(r.get("parent_job_id") or 0) == int(parent_job_id)
                and r.get("job_type") == "codex_oauth"
            ), None)
            if derived:
                return dict(derived), False
        active = next((
            r for r in rows
            if int(r.get("account_id") or 0) == int(account_id)
            and r.get("job_type") in {"codex_oauth", "codex_retry"}
            and r.get("status") in {"pending", "running", "stopping"}
        ), None)
        if active:
            return dict(active), False
        snapshot = {
            "codex_oauth": True,
            "registration_driver": "existing_account",
            "email_mode": "existing",
            "alias_limit": None,
            "sms": dict(sms_snapshot or {}),
        }
        row = _new_job_row(
            rows,
            email_source=email_source,
            job_type="codex_oauth",
            parent_job_id=parent_job_id,
            retry_action="codex",
            email=email,
            account_id=account_id,
            batch_id=batch_id,
            flow_snapshot=snapshot,
        )
        rows.append(row)
        _save_jobs(rows)
        return dict(row), True


def create_account_codex_jobs_bulk(
    candidates: list[dict], *, sms_snapshot: dict | None = None, batch_id: str | None = None,
    login_mode: str = "email_otp", expected_workspace_id: str = "",
    team_authorization: bool = False,
) -> dict:
    """Validate active jobs once, allocate IDs once, persist pending jobs once."""
    if login_mode not in {"email_otp", "password_totp"}:
        raise ValueError("不支持的 Codex 登录模式")
    with _LOCK:
        rows = _load_jobs()
        batch_id = _resolve_registration_batch_id(batch_id)
        accounts = {int(row.get("id") or 0): row for row in _load_accounts()}
        active = {}
        for row in rows:
            if row.get("job_type") in {"codex_oauth", "codex_retry"} and row.get("status") in {"pending", "running", "stopping"}:
                active.setdefault(int(row.get("account_id") or 0), row)
        next_id = _next_id(rows)
        created, skipped = [], []
        for item in candidates:
            account_id, email = int(item["id"]), item["email"]
            account = accounts.get(account_id)
            reason = None
            if account is None or str(account.get("email") or "").strip() != email:
                reason = "账号已删除或邮箱已变化"
            elif (login_mode == "email_otp" and account.get("codex_refresh_token")
                  and (not expected_workspace_id or account.get("codex_workspace_id") == expected_workspace_id)):
                reason = "已有 Codex RT"
            elif str(account.get("codex_status") or "").lower() == "deactivated":
                reason = "账号已废号"
            elif login_mode == "password_totp":
                from core.codex_password_totp import login_material, PasswordTotpLoginError

                try:
                    login_material(account)
                except PasswordTotpLoginError as exc:
                    reason = str(exc)
            if reason:
                skipped.append({"id": account_id, "email": email, "reason": reason})
                continue
            if account_id in active:
                job = active[account_id]
                skipped.append({"id": account_id, "email": email, "reason": f"已有活跃任务 #{job['id']}", "job_id": job["id"]})
                continue
            job = _new_job_row(
                [], job_id=next_id, email_source=item["email_source"], job_type="codex_oauth",
                retry_action="codex", email=email, account_id=account_id, batch_id=batch_id,
                flow_snapshot={
                    **({"team_authorization": True} if team_authorization else {}),
                    **({"expected_workspace_id": expected_workspace_id} if expected_workspace_id else {}),
                    "codex_oauth": True, "registration_driver": "existing_account",
                    "email_mode": "existing", "alias_limit": None, "sms": dict(sms_snapshot or {}),
                    **({"codex_login_mode": login_mode} if login_mode != "email_otp" else {}),
                },
            )
            next_id += 1
            created.append(job)
            active[account_id] = job
        if created:
            # Do not append to the mutable read cache until the atomic write
            # succeeds; failed writes must not invent pending jobs in memory.
            _save_jobs([*rows, *created])
        return {"created": deepcopy(created), "skipped": skipped}


def requeue_restart_interrupted_codex_job(job_id: int) -> dict | None:
    """重新排队一个明确由服务重启中断的自动 Codex 子任务。"""
    with _LOCK:
        rows = _load_jobs()
        row = next((r for r in rows if int(r.get("id") or 0) == int(job_id)), None)
        if (
            row is None
            or row.get("job_type") != "codex_oauth"
            or not row.get("parent_job_id")
            or row.get("status") not in {"failed", "stopped", "cancelled"}
            or row.get("restart_recoverable") is not True
        ):
            return None
        row["status"] = "pending"
        row["error_message"] = None
        row["started_at"] = None
        row["completed_at"] = None
        row["restart_recoverable"] = False
        _save_jobs(rows)
        return dict(row)


def update_job(
    job_id: int,
    *,
    status: str | None = None,
    email: str | None = None,
    error: str | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    account_id: int | None = None,
    oauth_status: str | None = None,
    oauth_error: str | None = None,
    email_allocation_id: int | None = None,
    restart_recoverable: bool | None = None,
    codex_authorization: dict | None = None,
) -> None:
    with _LOCK:
        rows = _load_jobs()
        row = next((r for r in rows if int(r.get("id") or 0) == int(job_id)), None)
        if row is None:
            return
        previous = dict(row)
        if status is not None:
            row["status"] = status
            if status in {"success", "failed", "stopped", "cancelled"} and isinstance(row.get("roxy_traffic"), dict):
                traffic = row["roxy_traffic"]
                traffic["registration_outcome"] = status
                if traffic.get("status") == "running":
                    traffic["status"] = "complete"
                    traffic["partial"] = True
                    traffic["finalization_reason"] = "job_terminal_without_final_snapshot"
                    traffic["finished_at"] = completed_at or _now()
                    traffic["updated_at"] = _now()
        if email is not None:
            row["email"] = email
        if error is not None:
            row["error_message"] = error
        if started_at is not None:
            row["started_at"] = started_at
        if completed_at is not None:
            row["completed_at"] = completed_at
        if account_id is not None:
            row["account_id"] = account_id
        if oauth_status is not None:
            row["oauth_status"] = oauth_status
        if oauth_error is not None:
            row["oauth_error"] = oauth_error
        if email_allocation_id is not None:
            row["email_allocation_id"] = email_allocation_id
        if restart_recoverable is not None:
            row["restart_recoverable"] = bool(restart_recoverable)
        if codex_authorization is not None:
            # Keep a per-attempt result; never persist tokens in job metadata.
            row["codex_authorization"] = {
                key: str(codex_authorization.get(key) or "")[:320]
                for key in ("email", "account_id", "plan_type")
            }
        _normalize_failed_job_error(row)
        if (
            row.get("job_type") in {"codex_oauth", "codex_retry"}
            and row.get("status") == "running"
        ):
            _save_codex_job_start(rows, row, previous)
        elif (row.get("job_type") or "registration") == "registration" and row.get("status") == "running":
            _save_job_progress(rows, row, previous)
        else:
            _save_jobs(rows)


def update_jobs_bulk(updates: list[dict]) -> int:
    """一次落盘更新多个任务，避免大任务文件被逐条完整重写。"""
    if not isinstance(updates, list):
        raise ValueError("updates 必须是数组")
    normalized: list[tuple[int, dict]] = []
    for item in updates:
        if not isinstance(item, dict):
            continue
        try:
            job_id = int(item.get("job_id") or item.get("id") or 0)
        except (TypeError, ValueError):
            continue
        if job_id > 0:
            normalized.append((job_id, item))
    if not normalized:
        return 0

    with _LOCK:
        rows = _load_jobs()
        by_id = {
            int(row.get("id") or 0): row
            for row in rows
            if isinstance(row, dict)
        }
        changed = 0
        changes_by_id: dict[int, tuple[dict, dict]] = {}
        for job_id, item in normalized:
            row = by_id.get(job_id)
            if row is None:
                continue
            changes_by_id.setdefault(job_id, (row, dict(row)))
            status = item.get("status")
            completed_at = item.get("completed_at")
            if status is not None:
                row["status"] = status
                if status in {"success", "failed", "stopped", "cancelled"} and isinstance(row.get("roxy_traffic"), dict):
                    traffic = row["roxy_traffic"]
                    traffic["registration_outcome"] = status
                    if traffic.get("status") == "running":
                        traffic["status"] = "complete"
                        traffic["partial"] = True
                        traffic["finalization_reason"] = "job_terminal_without_final_snapshot"
                        traffic["finished_at"] = completed_at or _now()
                        traffic["updated_at"] = _now()
            field_map = {
                "email": "email",
                "error": "error_message",
                "started_at": "started_at",
                "completed_at": "completed_at",
                "account_id": "account_id",
                "oauth_status": "oauth_status",
                "oauth_error": "oauth_error",
                "email_allocation_id": "email_allocation_id",
            }
            for source, target in field_map.items():
                if item.get(source) is not None:
                    row[target] = item[source]
            if item.get("restart_recoverable") is not None:
                row["restart_recoverable"] = bool(item["restart_recoverable"])
            _normalize_failed_job_error(row)
            changed += 1
        if changed:
            changes = list(changes_by_id.values())
            # A bulk dispatch/status heartbeat that only moves jobs to running
            # (or updates bounded OAuth metadata) should not rewrite the full
            # jobs table.  Terminal rows or any result field automatically
            # fall back to the durable main-file checkpoint.
            _save_job_progress_many(rows, changes)
        return changed


def update_job_roxy_traffic(job_id: int, traffic: dict) -> bool:
    """原子保存任务流量快照；计数只增不减，终态不会被旧心跳覆盖。"""
    if not isinstance(traffic, dict):
        raise ValueError("roxy_traffic 必须是对象")
    try:
        value = json.loads(json.dumps(traffic, ensure_ascii=False))
    except (TypeError, ValueError) as exc:
        raise ValueError("roxy_traffic 必须可 JSON 序列化") from exc
    value = {key: value.get(key) for key in _ROXY_TRAFFIC_FIELDS if key in value}

    measurement = str(value.get("measurement") or "unavailable").strip().lower()
    if measurement not in {"socks5_tunnel_payload", "unavailable"}:
        raise ValueError("roxy_traffic.measurement 非法")
    status = str(value.get("status") or "running").strip().lower()
    if status not in {"running", "complete", "unavailable", "failed"}:
        raise ValueError("roxy_traffic.status 非法")

    numbers: dict[str, int] = {}
    for key in ("uploaded_bytes", "downloaded_bytes", "connection_count"):
        try:
            number = int(value.get(key) or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"roxy_traffic.{key} 必须是非负整数") from exc
        if number < 0:
            raise ValueError(f"roxy_traffic.{key} 必须是非负整数")
        numbers[key] = number

    value.update(numbers)
    value["schema_version"] = 1
    value["driver"] = "roxy"
    value["measurement"] = measurement
    value["status"] = status
    registration_outcome = str(value.get("registration_outcome") or "").strip().lower()
    value["registration_outcome"] = (
        registration_outcome
        if registration_outcome in {"success", "failed", "stopped", "cancelled"}
        else None
    )
    value["total_bytes"] = numbers["uploaded_bytes"] + numbers["downloaded_bytes"]
    value["upstream_proxy"] = _redact_proxy_text(value.get("upstream_proxy"))
    value["unavailable_reason"] = _redact_proxy_text(value.get("unavailable_reason"))
    value["finalization_reason"] = _redact_proxy_text(
        value.get("finalization_reason"), limit=120
    )
    value["updated_at"] = _now()

    with _LOCK:
        rows = _load_jobs()
        row = next((item for item in rows if int(item.get("id") or 0) == int(job_id)), None)
        if row is None:
            return False
        previous = row.get("roxy_traffic") if isinstance(row.get("roxy_traffic"), dict) else None
        if previous:
            previous_measurement = str(previous.get("measurement") or "unavailable").strip().lower()
            previous_status = str(previous.get("status") or "").strip().lower()
            # 同一计数桥的快照天然单调。取最大值可抵御落后的心跳线程，
            # 同时保留终止任务前最后一次成功刷新的字节数。
            if previous_measurement == "socks5_tunnel_payload" and measurement == "socks5_tunnel_payload":
                for key in ("uploaded_bytes", "downloaded_bytes", "connection_count"):
                    try:
                        value[key] = max(int(previous.get(key) or 0), int(value.get(key) or 0))
                    except (TypeError, ValueError):
                        pass
                value["total_bytes"] = value["uploaded_bytes"] + value["downloaded_bytes"]
            elif previous_measurement == "socks5_tunnel_payload" and measurement == "unavailable":
                # 已经拿到真实计数后，不允许后续异常快照降级成“不可采集”。
                value["measurement"] = previous_measurement
                for key in ("uploaded_bytes", "downloaded_bytes", "connection_count"):
                    try:
                        value[key] = max(0, int(previous.get(key) or 0))
                    except (TypeError, ValueError):
                        value[key] = 0
                value["total_bytes"] = value["uploaded_bytes"] + value["downloaded_bytes"]
                value["upstream_proxy"] = _redact_proxy_text(
                    previous.get("upstream_proxy") or value.get("upstream_proxy")
                )
                if value.get("status") == "unavailable":
                    value["status"] = (
                        previous_status
                        if previous_status in {"complete", "failed"}
                        else "complete"
                    )
                    value["partial"] = True
                    value["finalization_reason"] = "traffic_source_unavailable_after_measurement"

            upgraded_to_measured = (
                previous_measurement == "unavailable"
                and measurement == "socks5_tunnel_payload"
            )
            if (
                previous_status in {"complete", "failed", "unavailable"}
                and value.get("status") == "running"
                and not upgraded_to_measured
            ):
                value["status"] = previous_status
                for key in (
                    "registration_outcome", "finished_at", "partial", "finalization_reason",
                ):
                    if previous.get(key) is not None:
                        value[key] = previous.get(key)
            if previous.get("registration_outcome") and not value.get("registration_outcome"):
                value["registration_outcome"] = previous.get("registration_outcome")
            # 多 Profile 重试必须保留任务第一次开始计量的时间；每轮上报都带
            # started_at，不能让后续 Profile 覆盖成最后一轮的开始时间。
            if previous.get("started_at"):
                value["started_at"] = previous.get("started_at")
        outcome = str(value.get("registration_outcome") or "").strip().lower()
        value["registration_outcome"] = (
            outcome if outcome in {"success", "failed", "stopped", "cancelled"} else None
        )
        value["upstream_proxy"] = _redact_proxy_text(value.get("upstream_proxy"))
        value["unavailable_reason"] = _redact_proxy_text(value.get("unavailable_reason"))
        value["finalization_reason"] = _redact_proxy_text(
            value.get("finalization_reason"), limit=120
        )
        for key in ("started_at", "finished_at"):
            value[key] = _roxy_traffic_timestamp(value.get(key))
        value["partial"] = bool(value.get("partial") is True)
        if value["status"] == "running" and _save_running_job_traffic(row, value):
            # Five-second heartbeats must not rewrite the entire jobs table.
            # They remain durable and visible through _load_jobs; the next
            # ordinary job save checkpoints all outstanding counters together.
            row["roxy_traffic"] = value
        else:
            row["roxy_traffic"] = value
            _save_jobs(rows)
        return True


def list_jobs(limit: int = 100) -> list[dict]:
    with _LOCK:
        rows = sorted(_load_jobs(), key=lambda x: int(x.get("id") or 0), reverse=True)
        return [dict(r) for r in rows[:limit]]


def get_job(job_id: int) -> dict | None:
    with _LOCK:
        row = next((r for r in _load_jobs() if int(r.get("id") or 0) == int(job_id)), None)
        return dict(row) if row else None


def get_successful_retry_for_job(job_id: int) -> dict | None:
    """返回同一任务链中已成功的其他重试任务，用于保留原任务历史状态并阻止重复重试。"""
    with _LOCK:
        rows = _load_jobs()
        source = next((r for r in rows if int(r.get("id") or 0) == int(job_id)), None)
        if source is None:
            return None
        root_id = int(source.get("root_job_id") or source.get("id") or 0)
        matches = [
            r for r in rows
            if int(r.get("id") or 0) != int(job_id)
            and int(r.get("root_job_id") or 0) == root_id
            and r.get("status") == "success"
        ]
        if not matches:
            return None
        return dict(max(matches, key=lambda r: int(r.get("id") or 0)))


def delete_job(job_id: int, *, delete_log: bool = True, allow_running: bool = False) -> bool:
    """
    删除一个注册任务记录；默认同时删除该任务日志文件。返回是否删除到记录。
    默认不删除 running 任务，避免后台线程仍在执行但前端记录消失。
    """
    with _LOCK:
        rows = _load_jobs()
        idx = next((i for i, r in enumerate(rows) if int(r.get("id") or 0) == int(job_id)), None)
        if idx is None:
            return False
        if not allow_running and rows[idx].get("status") in ("running", "stopping"):
            return False
        row = rows.pop(idx)
        _save_jobs(rows)

    if delete_log:
        log_file = row.get("log_file")
        if log_file:
            try:
                Path(log_file).unlink(missing_ok=True)
            except Exception:
                pass
    return True


# ============================================================
# 迁移与路径
# ============================================================

def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return row is not None


def _migrate_legacy_sqlite() -> dict:
    summary = {"sqlite_accounts_imported": 0, "sqlite_outlook_imported": 0, "sqlite_outlook_skipped": 0}
    if not _LEGACY_SQLITE.exists():
        return summary
    try:
        conn = sqlite3.connect(str(_LEGACY_SQLITE))
        conn.row_factory = sqlite3.Row
        if _table_exists(conn, "outlook_pool"):
            records = []
            statuses = []
            for row in conn.execute("SELECT * FROM outlook_pool").fetchall():
                records.append({
                    "email": row["email"],
                    "password": row["password"],
                    "client_id": row["client_id"],
                    "refresh_token": row["refresh_token"],
                })
                statuses.append({
                    "email": row["email"],
                    "status": row["status"],
                    "note": row["note"],
                })
            ins, skip = import_outlook_accounts(records)
            for item in statuses:
                if item["status"] != "available":
                    release_outlook(item["email"], status=item["status"], note=item["note"])
            summary["sqlite_outlook_imported"] += ins
            summary["sqlite_outlook_skipped"] += skip
        if _table_exists(conn, "registered_accounts"):
            for row in conn.execute("SELECT * FROM registered_accounts").fetchall():
                insert_account(
                    email=row["email"],
                    access_token=row["access_token"],
                    totp_secret=row["totp_secret"],
                    user_id=row["user_id"],
                    user_name=row["user_name"],
                    plan_type=row["plan_type"],
                    expires_at=row["expires_at"],
                    device_id=row["device_id"],
                    proxy_used=row["proxy_used"],
                    email_source=row["email_source"],
                    extra=json.loads(row["extra_json"]) if row["extra_json"] else None,
                )
                summary["sqlite_accounts_imported"] += 1
        conn.close()
    except Exception as exc:
        summary["sqlite_error"] = f"{type(exc).__name__}: {exc}"
    return summary


def migrate_legacy_files() -> dict:
    """
    把历史 SQLite、accounts/*.json、outlook_accounts.txt、outlook_accounts_used.json
    迁移到当前 JSON/TXT 文件存储。多次调用是幂等的。
    """
    summary = {
        "accounts_imported": 0,
        "outlook_imported": 0,
        "outlook_skipped": 0,
    }
    summary.update(_migrate_legacy_sqlite())

    accounts_dir = _PROJECT_ROOT / "accounts"
    if accounts_dir.exists():
        for jf in accounts_dir.glob("*.json"):
            try:
                data = json.loads(jf.read_text(encoding="utf-8"))
                if not data.get("email") or not data.get("access_token"):
                    continue
                extra = data.get("extra") or {}
                user = extra.get("user") or {}
                account = extra.get("account") or {}
                insert_account(
                    email=data["email"],
                    access_token=data["access_token"],
                    totp_secret=data.get("totp_secret"),
                    user_id=user.get("id"),
                    user_name=user.get("name"),
                    plan_type=account.get("planType"),
                    expires_at=extra.get("expires"),
                    device_id=extra.get("device_id"),
                    extra=extra,
                )
                summary["accounts_imported"] += 1
            except Exception:
                continue

    for txt in (_PROJECT_ROOT / "outlook_accounts.txt", _OUTLOOK_TXT):
        if txt.exists():
            records = []
            for line in txt.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("----")
                # 支持 4 段或 6 段格式
                if len(parts) == 4:
                    email, password, client_id, refresh_token = (p.strip() for p in parts)
                elif len(parts) == 6:
                    email, password, client_id, refresh_token, _, _ = (p.strip() for p in parts)
                else:
                    continue
                records.append({
                    "email": email,
                    "password": password,
                    "client_id": client_id,
                    "refresh_token": refresh_token,
                })
            ins, skip = import_outlook_accounts(records)
            summary["outlook_imported"] += ins
            summary["outlook_skipped"] += skip

    used = _PROJECT_ROOT / "outlook_accounts_used.json"
    if used.exists():
        try:
            emails = json.loads(used.read_text(encoding="utf-8"))
            for email in emails:
                release_outlook(email, status="used")
        except Exception:
            pass

    return summary


def db_path() -> Path:
    """兼容旧名称，返回当前文件存储目录。"""
    return _DATA_DIR


def storage_paths() -> dict:
    return {
        "outlook_json": str(_OUTLOOK_JSON),
        "outlook_txt": str(_OUTLOOK_TXT),
        "accounts_json": str(_ACCOUNTS_JSON),
        "accounts_txt": str(_ACCOUNTS_TXT),
        "tokens_txt": str(_TOKENS_TXT),
        "viewer_html": str(_VIEWER_HTML),
        "jobs_json": str(_JOBS_JSON),
        "logs_dir": str(_LOG_DIR),
    }


def refresh_static_viewer() -> Path:
    """手动刷新静态查看器，返回 HTML 路径。"""
    with _LOCK:
        outlook_rows = _load_outlook()
        account_rows = _load_accounts()
        _sync_outlook_txt(outlook_rows)
        _sync_accounts_txt(account_rows)
        _sync_tokens_txt(account_rows)
        return _render_static_viewer(outlook_rows=outlook_rows, account_rows=account_rows)


# ============================================================
# Domain email pool（Cloudflare 域名邮箱跟踪）
# ============================================================

_DOMAIN_EMAIL_JSON = _PROJECT_ROOT / "用于注册的域名邮箱.json"


def _load_domain_pool() -> list[dict]:
    rows = _read_json(_DOMAIN_EMAIL_JSON, [])
    return rows if isinstance(rows, list) else []


def _save_domain_pool(rows: list[dict]) -> None:
    _write_json(_DOMAIN_EMAIL_JSON, rows)


def _find_domain_email(rows: list[dict], email: str) -> dict | None:
    target = (email or "").lower()
    return next((r for r in rows if (r.get("email") or "").lower() == target), None)


def claim_next_domain_email(email: str) -> dict:
    """记录一个新的域名邮箱地址到池中（标记为 available）。"""
    with _LOCK:
        rows = _load_domain_pool()
        if _find_domain_email(rows, email):
            # 已存在，直接返回
            row = _find_domain_email(rows, email)
            return row
        row = {
            "id": _next_id(rows),
            "email": email,
            "status": "available",
            "used_at": None,
            "note": None,
            "created_at": _now(),
        }
        rows.append(row)
        _save_domain_pool(rows)
        return dict(row)


def release_domain_email(email: str, status: str = "available", note: str | None = None) -> bool:
    """更新域名邮箱状态。"""
    with _LOCK:
        rows = _load_domain_pool()
        row = _find_domain_email(rows, email)
        if row is None:
            return False
        row["status"] = status
        if status == "available":
            row["used_at"] = None
        elif status in ("used", "failed", "disabled"):
            row["used_at"] = row.get("used_at") or _now()
        if note is not None:
            row["note"] = note
        _save_domain_pool(rows)
        return True


def release_unconsumed_domain_email(email: str, note: str | None = None) -> bool:
    """原子回收未生成本地账号且仍为 used 的域名邮箱。"""
    with _LOCK:
        if _find_by_email(_load_accounts(), email) is not None:
            return False
        rows = _load_domain_pool()
        row = _find_domain_email(rows, email)
        if row is None or row.get("status") != "used":
            return False
        row["status"] = "available"
        row["used_at"] = None
        if note is not None:
            row["note"] = note
        _save_domain_pool(rows)
        return True


def get_domain_email_by_email(email: str) -> dict | None:
    with _LOCK:
        row = _find_domain_email(_load_domain_pool(), email)
        return dict(row) if row else None


def list_domain_email_pool(status: str | None = None, limit: int = 500) -> list[dict]:
    with _LOCK:
        rows = sorted(_load_domain_pool(), key=lambda x: int(x.get("id") or 0), reverse=True)
        if status:
            rows = [r for r in rows if r.get("status") == status]
        account_by_email = {
            str(a.get("email") or "").lower(): a for a in _load_accounts()
        }
        out = []
        for row in rows[:limit]:
            item = dict(row)
            account = account_by_email.get(str(row.get("email") or "").lower())
            if account:
                item["registered_account_id"] = account.get("id")
                item["access_token"] = account.get("access_token")
                item["account_copy_line"] = _account_line(account)
                item["totp_secret"] = account.get("totp_secret")
            out.append(item)
        return out


def domain_email_pool_summary() -> dict:
    with _LOCK:
        out: dict[str, int] = {"available": 0, "used": 0, "failed": 0}
        for row in _load_domain_pool():
            s = row.get("status") or "available"
            out[s] = out.get(s, 0) + 1
        out["total"] = sum(v for k, v in out.items() if k != "total")
        return out


def delete_domain_email(email: str) -> bool:
    """从域名邮箱池删除一个邮箱。"""
    with _LOCK:
        rows = _load_domain_pool()
        target = (email or "").lower()
        if _find_by_email(_load_accounts(), target) is not None:
            return False
        if any(
            str(job.get("email") or "").lower() == target
            and job.get("status") in {"pending", "running", "stopping"}
            for job in _load_jobs()
        ):
            return False
        new_rows = [r for r in rows if (r.get("email") or "").lower() != target]
        if len(new_rows) == len(rows):
            return False
        _save_domain_pool(new_rows)
        return True
