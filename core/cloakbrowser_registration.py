# -*- coding: utf-8 -*-
"""通过 CloakBrowser + Playwright 适配层执行 ChatGPT 注册。"""
from __future__ import annotations

import logging
import time
from pathlib import Path

from config import cloakbrowser as _cfg
from config import twofa as _twofa_cfg  # noqa: F401 - compatibility for driver tests
from core.account_cookie_store import capture_selenium_cookies
from core.account_export import save_account_data
from core.cloakbrowser_driver import build_cloak_driver
from core.email_provider import resolve_email_source
from core.humanize import delay as human_delay

# 复用 Roxy 注册流程里已维护好的页面操作函数。
from core.roxy_registration import (  # noqa: F401
    _maybe_accept, _submit_email_and_wait_next, _prepare_registration_password,
    _complete_email_otp_challenge,
    _advance_from_email_verified_page, _complete_profile_page,
    _fetch_chatgpt_session, _check_manual_stop,
)

logger = logging.getLogger(__name__)


def run_cloak_registration(
    email: str, name: str, birthday: str, proxy: str = None, otp_code: str = None,
    batch_dir: Path | None = None, codex_oauth: bool | None = None,
) -> dict:
    """CloakBrowser 自动化注册入口。"""
    driver = None
    opened = None
    create_acknowledged = False
    email_submit_attempted = False
    email_submitted = False
    email_otp_entered = False
    email_verified = False
    openai_password: str | None = None

    def mark_email_submit_attempted() -> None:
        nonlocal email_submit_attempted
        email_submit_attempted = True

    def mark_email_submitted() -> None:
        nonlocal email_submitted
        email_submitted = True

    def mark_email_otp_entered() -> None:
        nonlocal email_otp_entered
        email_otp_entered = True

    try:
        driver, opened = build_cloak_driver(proxy=proxy)
        logger.info("[Cloak注册] 开始：%s，profile=%s", email, opened.profile_id)

        otp_after_ts = time.time()
        logger.info("[Cloak注册] 打开登录页：https://chatgpt.com/auth/login")
        driver.get("https://chatgpt.com/auth/login")
        human_delay("navigate")
        _maybe_accept(driver)
        _check_manual_stop()

        next_state = _submit_email_and_wait_next(
            driver,
            email,
            attempts=3,
            on_email_submitted=mark_email_submitted,
            on_email_submit_attempted=mark_email_submit_attempted,
        )
        _check_manual_stop()

        openai_password = _prepare_registration_password(
            driver,
            email,
            next_state,
            timeout=25,
        )
        _check_manual_stop()

        if next_state == "logged_in":
            logger.info("[Cloak注册][OTP] 邮箱提交后已检测到登录态，跳过邮箱取码")
        else:
            _complete_email_otp_challenge(
                driver,
                email,
                otp_code=otp_code,
                otp_after_ts=otp_after_ts,
                max_otp_attempts=3,
                on_otp_entered=mark_email_otp_entered,
            )
            _check_manual_stop()
            _advance_from_email_verified_page(driver)
        email_verified = True
        profile_submitted = _complete_profile_page(driver, name, birthday, timeout=60)
        if profile_submitted:
            create_acknowledged = True
            human_delay("post_auth")

        session_info = _fetch_chatgpt_session(driver, timeout=120, expected_email=email)
        access_token = session_info["accessToken"]
        logger.info("[Cloak注册] 已拿到 accessToken：%s", email)

        # Codex 会清理并复用当前浏览器状态；在此之前冻结 Web Cookie。
        try:
            web_cookies = capture_selenium_cookies(driver)
            logger.info("[Cloak注册][Cookie] 已捕获 Web Cookie：%s，共 %s 条", email, len(web_cookies))
        except Exception as exc:
            web_cookies = []
            logger.warning(
                "[Cloak注册][Cookie] 捕获失败（不影响账号保存）：%s: %s",
                type(exc).__name__,
                str(exc)[:180],
            )

        totp_secret = None

        codex_result = {
            "status": "skipped",
            "ok": True,
            "message": "ENABLE_CODEX_AUTO=False，跳过 Codex",
        }
        try:
            from config import codex as _codex_cfg
            should_run_codex = bool(codex_oauth) if codex_oauth is not None else bool(getattr(_codex_cfg, "ENABLE_CODEX_AUTO", False))
            if should_run_codex:
                from core.roxy_codex_oauth import run_roxy_codex_oauth
                logger.info("[Cloak注册][Codex] ENABLE_CODEX_AUTO=True，复用当前 CloakBrowser 窗口执行 Codex 授权")
                _check_manual_stop()
                codex_result = run_roxy_codex_oauth(
                    email,
                    reuse_existing_profile=True,
                    existing_driver=driver,
                    existing_opened=opened,
                    force=True,
                    clear_existing_state=True,
                )
            else:
                logger.info("[Cloak注册][Codex] ENABLE_CODEX_AUTO=False，注册后跳过 Codex OAuth")
        except Exception as exc:
            codex_result = {"status": "failed", "ok": False, "message": f"{type(exc).__name__}: {str(exc)[:180]}"}

        account_id = save_account_data(
            email=email,
            access_token=access_token,
            totp_secret=totp_secret,
            email_source=resolve_email_source(email),
            proxy_used=((opened.raw or {}).get("proxy") if opened else None) or proxy or None,
            batch_dir=batch_dir,
            web_cookies=web_cookies,
            web_cookie_source="cloak",
            extra={
                "user": session_info.get("user"),
                "account": session_info.get("account"),
                "expires": session_info.get("expires"),
                "cloakbrowser": {"profile_id": opened.profile_id, "open_result": opened.raw},
                "registration_password": openai_password,
                "codex": codex_result,
            },
        )
        return {
            "success": True,
            "email": email,
            "account_id": account_id,
            "access_token": access_token,
            "totp_secret": totp_secret,
            "codex": codex_result,
            "error": None,
            "email_submit_attempted": True,
            "email_submitted": True,
            "email_consumed": True,
            "email_verified": True,
        }
    except Exception as exc:
        logger.error("[Cloak注册] 失败：%s: %s", type(exc).__name__, exc)
        logger.debug("[Cloak注册] 失败详情", exc_info=True)
        email_consumed = bool(
            email_submitted or email_otp_entered or email_verified or create_acknowledged
        )
        try:
            from core.email_provider import release_email
            release_email(
                email,
                status="failed" if email_consumed else "available",
                note=f"Cloak注册失败: {str(exc)[:180]}",
            )
        except Exception:
            pass
        return {
            "success": False,
            "email": email,
            "error": f"{type(exc).__name__}: {str(exc)[:300]}",
            "email_submit_attempted": email_submit_attempted,
            "email_submitted": email_submitted,
            "email_consumed": email_consumed,
            "email_verified": email_verified,
        }
    finally:
        if driver and not bool(_cfg.CLOAK_KEEP_BROWSER_OPEN):
            try:
                driver.quit()
            except Exception:
                pass
