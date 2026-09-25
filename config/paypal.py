# -*- coding: utf-8 -*-
"""PayPal zero-value Checkout extraction and agreement payment settings."""
from config.env_loader import apply_env_overrides, env_str


# Registration-time default remains opt-in.  The registration form stores the
# selected mode in each immutable flow snapshot.
PAYPAL_DEFAULT_MODE: str = "none"

# Extraction uses hosted Stripe directly. Legacy OAICS snapshots are upgraded at runtime.
PAYPAL_EXTRACT_REQUESTED_MODE: str = "stripe"
PAYPAL_STRIPE_PROMO_STRATEGY: str = "post_update"
PAYPAL_PROMO_ID: str = "plus-1-month-free"
PAYPAL_EXTRACT_COUNTRY: str = "BR"
PAYPAL_BILLING_COUNTRY: str = "DE"

# Pools are intentionally independent.  Every task leases one entry and keeps
# it for the complete protocol chain; a retry leases another entry.
PAYPAL_EXTRACT_PROXY_POOL: list[str] = []
PAYPAL_PAYMENT_PROXY_POOL: list[str] = []
PAYPAL_EXTRACT_POOL_ID: str = "paypal_extract_pool"
PAYPAL_PAYMENT_POOL_ID: str = "paypal_payment_pool"

PAYPAL_WORKERS: int = 20
PAYPAL_QUEUE_LIMIT: int = 500
# Total hosted Stripe attempts, including generic_decline/no redirect.
PAYPAL_CHECKOUT_MAX_ATTEMPTS: int = 5
PAYPAL_EXTRACT_MAX_ATTEMPTS: int = 3
PAYPAL_PAYMENT_MAX_ATTEMPTS: int = 2
PAYPAL_REQUEST_TIMEOUT: int = 30
PAYPAL_RETRY_INTERVAL: float = 1.0
# A registration-time free/available/eligible result is stronger than a later
# request-only edge probe. Stripe still rejects any checkout whose amount is
# not exactly zero, so retaining this evidence does not permit a paid flow.
PAYPAL_ELIGIBLE_PLAN_RESULT_TTL: int = 86400

# PayPal agreement defaults.  Phone acquisition/OTP can be supplied per manual
# task; registration automation records a blocked verification when no phone is
# available instead of losing the extracted BA credential.
PAYPAL_PAYMENT_COUNTRY: str = "GB"
PAYPAL_BUYER_MODE: str = "identity_elevation"
PAYPAL_PAYMENT_PHONE: str = ""

# Payment protocol executor. ``local`` keeps the in-process implementation;
# ``remote`` delegates the agreement flow while local code still owns SMS,
# proxy leases, durable account state, and final Plus verification.
PAYPAL_PAYMENT_EXECUTOR: str = "local"
PAYPAL_REMOTE_API_BASE: str = "https://paypal.173.249.205.56.sslip.io/paypal-pay/api"
PAYPAL_REMOTE_POLL_INTERVAL: float = 1.0
PAYPAL_REMOTE_JOB_TIMEOUT: int = 600

# PayPal SMS verification.  Manual phone input always wins.  In auto mode the
# selected channel acquires a number before the payment mutation and polls it
# only after the PayPal OTP context has been durably persisted.
PAYPAL_SMS_MODE: str = "manual"
PAYPAL_SMS_CHANNELS: str = "herosms"
# Maximum number of distinct phone activations used by one automatic payment
# task after an explicit, replay-safe PayPal rejection.
PAYPAL_SMS_MAX_RETRIES: int = 3

# HeroSMS channel. The credential defaults to the global Codex HeroSMS key,
# while PayPal keeps its country/service/price policy independent.
PAYPAL_HEROSMS_HANDLER_URL: str = env_str(
    "HEROSMS_HANDLER_URL", "https://hero-sms.com/stubs/handler_api.php"
)
PAYPAL_HEROSMS_API_KEY: str = env_str("HEROSMS_API_KEY", "")
PAYPAL_HEROSMS_COUNTRY_ID: str = "16"
PAYPAL_HEROSMS_SERVICE: str = "ts"
PAYPAL_HEROSMS_MAX_PRICE: float = 0.2
PAYPAL_HEROSMS_OPERATOR: str = ""
PAYPAL_HEROSMS_FIXED_PRICE: str = ""
PAYPAL_HEROSMS_PHONE_EXCEPTION: str = ""
PAYPAL_HEROSMS_CODE_WAIT: int = 120
PAYPAL_HEROSMS_POLL_INTERVAL: float = 5.0
PAYPAL_HEROSMS_REQUEST_TIMEOUT: int = 20
PAYPAL_HEROSMS_PROXY: str = ""

# SMSBower channel. PayPal can reuse the global SMSBower credential while all
# routing, country, price, and polling limits remain independently configurable.
PAYPAL_SMSBOWER_HANDLER_URL: str = env_str(
    "SMSBOWER_HANDLER_URL", "https://smsbower.page/stubs/handler_api.php"
)
PAYPAL_SMSBOWER_API_KEY: str = env_str("SMSBOWER_API_KEY", "")
PAYPAL_SMSBOWER_COUNTRY_ID: str = "16"
PAYPAL_SMSBOWER_SERVICE: str = "ts"
PAYPAL_SMSBOWER_MIN_PRICE: float = 0.07
PAYPAL_SMSBOWER_MAX_PRICE: float = 0.2
PAYPAL_SMSBOWER_CODE_WAIT: int = 120
PAYPAL_SMSBOWER_POLL_INTERVAL: float = 5.0
PAYPAL_SMSBOWER_REQUEST_TIMEOUT: int = 20
PAYPAL_SMSBOWER_PROXY: str = ""

# Luban channel (https://lubansms.com/v2/api).  ``PROVIDERS`` is an ordered
# allow-list: ``acsim,at8`` tries acsim offers first, then at8.  Empty means all
# providers sorted by price.  ``SERVICE_IDS`` is an optional additional
# allow-list discovered through /List; it is never sent as a provider value.
PAYPAL_LUBAN_API_BASE: str = "https://lubansms.com/v2/api"
PAYPAL_LUBAN_API_KEY: str = ""
PAYPAL_LUBAN_COUNTRY: str = "England"
PAYPAL_LUBAN_SERVICE: str = "PayPal"
PAYPAL_LUBAN_PROVIDERS: str = "acsim,at8,selfsms"
PAYPAL_LUBAN_SERVICE_IDS: str = ""
PAYPAL_LUBAN_MAX_PRICE: str = ""
PAYPAL_LUBAN_MAX_ATTEMPTS: int = 3
PAYPAL_LUBAN_LIST_MAX_PAGES: int = 5
PAYPAL_LUBAN_CODE_WAIT: int = 120
PAYPAL_LUBAN_POLL_INTERVAL: float = 5.0
PAYPAL_LUBAN_REQUEST_TIMEOUT: int = 20
PAYPAL_LUBAN_PROXY: str = ""

# Verify the ChatGPT plan with the current AT first.  Values are delayed checks
# after PayPal authorization; a real plan=plus response is the only success.
PAYPAL_PLUS_VERIFY_DELAYS: str = "5,30,120"


apply_env_overrides(globals(), {
    "PAYPAL_DEFAULT_MODE": "str",
    "PAYPAL_EXTRACT_REQUESTED_MODE": "str",
    "PAYPAL_STRIPE_PROMO_STRATEGY": "str",
    "PAYPAL_PROMO_ID": "str",
    "PAYPAL_EXTRACT_COUNTRY": "str",
    "PAYPAL_BILLING_COUNTRY": "str",
    "PAYPAL_EXTRACT_PROXY_POOL": "list_str_multiline",
    "PAYPAL_PAYMENT_PROXY_POOL": "list_str_multiline",
    "PAYPAL_EXTRACT_POOL_ID": "str",
    "PAYPAL_PAYMENT_POOL_ID": "str",
    "PAYPAL_WORKERS": "int",
    "PAYPAL_QUEUE_LIMIT": "int",
    "PAYPAL_CHECKOUT_MAX_ATTEMPTS": "int",
    "PAYPAL_EXTRACT_MAX_ATTEMPTS": "int",
    "PAYPAL_PAYMENT_MAX_ATTEMPTS": "int",
    "PAYPAL_REQUEST_TIMEOUT": "int",
    "PAYPAL_RETRY_INTERVAL": "float",
    "PAYPAL_ELIGIBLE_PLAN_RESULT_TTL": "int",
    "PAYPAL_PAYMENT_COUNTRY": "str",
    "PAYPAL_BUYER_MODE": "str",
    "PAYPAL_PAYMENT_PHONE": "str",
    "PAYPAL_PAYMENT_EXECUTOR": "str",
    "PAYPAL_REMOTE_API_BASE": "str",
    "PAYPAL_REMOTE_POLL_INTERVAL": "float",
    "PAYPAL_REMOTE_JOB_TIMEOUT": "int",
    "PAYPAL_SMS_MODE": "str",
    "PAYPAL_SMS_CHANNELS": "str",
    "PAYPAL_SMS_MAX_RETRIES": "int",
    "PAYPAL_HEROSMS_HANDLER_URL": "str",
    "PAYPAL_HEROSMS_API_KEY": "str",
    "PAYPAL_HEROSMS_COUNTRY_ID": "str",
    "PAYPAL_HEROSMS_SERVICE": "str",
    "PAYPAL_HEROSMS_MAX_PRICE": "float",
    "PAYPAL_HEROSMS_OPERATOR": "str",
    "PAYPAL_HEROSMS_FIXED_PRICE": "str",
    "PAYPAL_HEROSMS_PHONE_EXCEPTION": "str",
    "PAYPAL_HEROSMS_CODE_WAIT": "int",
    "PAYPAL_HEROSMS_POLL_INTERVAL": "float",
    "PAYPAL_HEROSMS_REQUEST_TIMEOUT": "int",
    "PAYPAL_HEROSMS_PROXY": "str",
    "PAYPAL_SMSBOWER_HANDLER_URL": "str",
    "PAYPAL_SMSBOWER_API_KEY": "str",
    "PAYPAL_SMSBOWER_COUNTRY_ID": "str",
    "PAYPAL_SMSBOWER_SERVICE": "str",
    "PAYPAL_SMSBOWER_MIN_PRICE": "float",
    "PAYPAL_SMSBOWER_MAX_PRICE": "float",
    "PAYPAL_SMSBOWER_CODE_WAIT": "int",
    "PAYPAL_SMSBOWER_POLL_INTERVAL": "float",
    "PAYPAL_SMSBOWER_REQUEST_TIMEOUT": "int",
    "PAYPAL_SMSBOWER_PROXY": "str",
    "PAYPAL_LUBAN_API_BASE": "str",
    "PAYPAL_LUBAN_API_KEY": "str",
    "PAYPAL_LUBAN_COUNTRY": "str",
    "PAYPAL_LUBAN_SERVICE": "str",
    "PAYPAL_LUBAN_PROVIDERS": "str",
    "PAYPAL_LUBAN_SERVICE_IDS": "str",
    "PAYPAL_LUBAN_MAX_PRICE": "str",
    "PAYPAL_LUBAN_MAX_ATTEMPTS": "int",
    "PAYPAL_LUBAN_LIST_MAX_PAGES": "int",
    "PAYPAL_LUBAN_CODE_WAIT": "int",
    "PAYPAL_LUBAN_POLL_INTERVAL": "float",
    "PAYPAL_LUBAN_REQUEST_TIMEOUT": "int",
    "PAYPAL_LUBAN_PROXY": "str",
    "PAYPAL_PLUS_VERIFY_DELAYS": "str",
})

# An explicitly empty PayPal-specific key still means "reuse the global key".
if not str(PAYPAL_HEROSMS_API_KEY or "").strip():
    PAYPAL_HEROSMS_API_KEY = env_str("HEROSMS_API_KEY", "")
