# -*- coding: utf-8 -*-
"""Process resource-limit helpers used by long-running workers."""
from __future__ import annotations

try:
    import resource
except ImportError:  # pragma: no cover - Windows
    resource = None


def ensure_open_file_limit(minimum: int = 8192) -> dict:
    """Raise the soft open-file limit when the inherited value is too small."""
    target = max(256, int(minimum or 8192))
    if resource is None or not hasattr(resource, "RLIMIT_NOFILE"):
        return {
            "supported": False,
            "changed": False,
            "soft_before": None,
            "soft_after": None,
            "hard": None,
            "error": None,
        }

    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        infinity = getattr(resource, "RLIM_INFINITY", -1)
        hard_is_infinite = hard == infinity or hard < 0
        desired = max(int(soft), target)
        if not hard_is_infinite:
            desired = min(desired, int(hard))
        if desired != soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (desired, hard))
        after, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        return {
            "supported": True,
            "changed": int(after) != int(soft),
            "soft_before": int(soft),
            "soft_after": int(after),
            "hard": int(hard),
            "error": None,
        }
    except (OSError, ValueError) as exc:
        return {
            "supported": True,
            "changed": False,
            "soft_before": None,
            "soft_after": None,
            "hard": None,
            "error": f"{type(exc).__name__}: {exc}",
        }
