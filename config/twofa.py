# -*- coding: utf-8 -*-
"""TOTP 补接与注册后自动触发配置。"""
from config.env_loader import apply_env_overrides

# 旧配置兼容：历史版本中该开关表示注册过程中自动设置 2FA。
# 新版本把设置动作改为账号落库后的统一补接任务。
ENABLE_2FA = False
AUTO_SETUP_2FA_AFTER_REGISTRATION = False

TOTP_WORKERS = 6
TOTP_QUEUE_LIMIT = 500
TOTP_REQUEST_TIMEOUT = 20
TOTP_MFA_INFO_ATTEMPTS = 3
TOTP_MFA_INFO_RETRY_DELAY = 0.75
TOTP_FINAL_CHECK_ATTEMPTS = 3
TOTP_MIN_WINDOW_SECONDS = 5.0
TOTP_REAUTH_ATTEMPTS = 3
TOTP_REAUTH_SESSION_ATTEMPTS = 10
TOTP_REAUTH_SESSION_INTERVAL = 1.0

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {
    'ENABLE_2FA': 'bool',
    'AUTO_SETUP_2FA_AFTER_REGISTRATION': 'bool',
    'TOTP_WORKERS': 'int',
    'TOTP_QUEUE_LIMIT': 'int',
    'TOTP_REQUEST_TIMEOUT': 'int',
    'TOTP_MFA_INFO_ATTEMPTS': 'int',
    'TOTP_MFA_INFO_RETRY_DELAY': 'float',
    'TOTP_FINAL_CHECK_ATTEMPTS': 'int',
    'TOTP_MIN_WINDOW_SECONDS': 'float',
    'TOTP_REAUTH_ATTEMPTS': 'int',
    'TOTP_REAUTH_SESSION_ATTEMPTS': 'int',
    'TOTP_REAUTH_SESSION_INTERVAL': 'float',
})


def auto_setup_after_registration_enabled() -> bool:
    """新开关优先；旧 ENABLE_2FA=True 继续保持原来的自动行为。"""
    return bool(AUTO_SETUP_2FA_AFTER_REGISTRATION or ENABLE_2FA)
