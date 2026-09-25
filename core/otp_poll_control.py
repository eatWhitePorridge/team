# -*- coding: utf-8 -*-
"""Shared cancellation helpers for mailbox polling loops."""
from __future__ import annotations

import time


def check_stop_requested(email: str | None = None) -> None:
    from core.registration_service import check_stop_requested as check_registration_stop

    check_registration_stop()
    if email:
        from core.codex_retry_service import check_stop_requested as check_codex_stop

        check_codex_stop(email)


def sleep_with_stop(email: str | None, seconds: float) -> None:
    remaining = max(0.0, float(seconds or 0.0))
    while remaining > 0:
        check_stop_requested(email)
        step = min(0.5, remaining)
        time.sleep(step)
        remaining -= step
    check_stop_requested(email)
