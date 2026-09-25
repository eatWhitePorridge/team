# -*- coding: utf-8 -*-
"""Roxy 注册失败分类与任务级重试策略。"""
from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class RoxyFailureDecision:
    failure_code: str
    failure_stage: str
    retryable: bool
    retry_action: str

    def to_dict(self) -> dict:
        return asdict(self)


_PERMANENT_MARKERS = (
    "用户手动停止",
    "stoprequested",
    "no module named 'selenium'",
    'no module named "selenium"',
    "未找到 node 可执行文件",
    "workspaceid",
    "roxy_one_profile_per_account",
    "不能配置/传入固定 roxy_profile_id",
    "invalid pickup credentials",
    "invalid_pickup_credentials",
    "query api 凭证无效",
    "邮箱提交后进入登录密码页",
    "/log-in/password",
    "已注册/不可用邮箱",
    "邮箱验证码连续错误/过期",
    "邮箱池没有可用",
    "没有可用账号",
)

_BROWSER_NETWORK_MARKERS = (
    "chrome-error://chromewebdata",
    "err_ssl_protocol_error",
    "err_socks",
    "err_proxy",
    "err_connection",
    "curl: (7)",
    "curl: (28)",
    "curl: (35)",
    "curl: (56)",
    "curl: (97)",
    "connection to proxy closed",
    "proxy connection closed",
    "socks connection failed",
    "ssl protocol error",
    "remote end closed connection",
)

_RENDERER_MARKERS = (
    "timed out receiving message from renderer",
    "renderer timeout",
    "disconnected: not connected to devtools",
    "target window already closed",
    "invalid session id",
)

_ROXY_TRANSIENT_MARKERS = (
    "正在创建中",
    "创建中，请稍等",
    "creation in progress",
    "already creating",
    "http 429",
    "http 500",
    "http 502",
    "http 503",
    "http 504",
    "status code 429",
    "status code 500",
    "status code 502",
    "status code 503",
    "status code 504",
    "client network socket disconnected before secure tls connection was established",
)

_ROXY_QUOTA_MARKERS = (
    "窗口单日创建次数已经超出",
    "单日创建次数已经超出",
    "daily profile creation limit",
    "daily browser creation limit",
    "profile creation quota exceeded",
)

_ROXY_PERMISSION_MARKERS = (
    "用户没有该团队权限",
    "没有该团队权限",
    "没有团队权限",
    "请在团队中检查是否关联该项目",
    "检查是否关联该项目",
    "项目未关联到团队",
    "team permission denied",
    "project is not associated with the team",
)

_ROXY_CONFIGURATION_MARKERS = (
    "http 400",
    "http 401",
    "http 403",
    "http 404",
    "http 405",
    "http 409",
    "http 410",
    "http 422",
    "status code 400",
    "status code 401",
    "status code 403",
    "status code 404",
    "status code 405",
    "status code 409",
    "status code 410",
    "status code 422",
    "unauthorized",
    "forbidden",
    "invalid token",
    "token invalid",
    "token expired",
    "鉴权失败",
    "认证失败",
    "未授权",
    "无权限",
    "暂不支持该代理协议",
    "unsupported proxy scheme",
    "代理格式缺少 host/port",
    "port could not be cast",
    "invalid parameter",
    "invalid params",
    "参数错误",
    "参数异常",
)

_PAGE_STATE_MARKERS = (
    "邮箱提交未跳转",
    "找不到邮箱输入框/邮箱入口",
    "otp 提交后 route error",
    "otp 提交后页面未返回明确结果",
    "otp 提交后浏览器网络异常",
)

_LOCAL_PROCESS_ENVIRONMENT_MARKERS = (
    "argument list too long",
    "errno 7",
    "e2big",
)

_PROXY_POOL_UNAVAILABLE_MARKERS = (
    "roxy 代理预检失败：抽测",
    "roxy 代理预检失败",
    "roxy 显式代理预检失败",
)


def classify_roxy_failure(
    error: object,
    *,
    failure_stage: str = "unknown",
    email_verified: bool = False,
    email_consumed: bool = False,
    email_submitted: bool = False,
) -> dict:
    """返回可持久化的失败分类，不把不确定状态当作可恢复错误。"""
    stage = str(failure_stage or "unknown").strip().lower() or "unknown"
    text = f"{type(error).__name__}: {error}".lower()

    if "chatgptaccountmissingerror" in text or "chatgpt_account_missing" in text:
        return RoxyFailureDecision(
            "chatgpt_account_missing", stage, False, "inspect_account"
        ).to_dict()

    if "registrationaccountexistserror" in text or "user_already_exists" in text:
        return RoxyFailureDecision(
            "user_already_exists", stage, False, "inspect_account"
        ).to_dict()

    if "browsersessionlosterror" in text:
        return RoxyFailureDecision(
            "browser_session_lost", stage, False, "inspect_account"
        ).to_dict()

    if "registrationpasswordrequirederror" in text:
        return RoxyFailureDecision(
            "password_required", stage, False, "none"
        ).to_dict()

    if any(marker in text for marker in _LOCAL_PROCESS_ENVIRONMENT_MARKERS):
        return RoxyFailureDecision(
            "local_process_environment", stage, False, "fix_configuration"
        ).to_dict()

    # _pick_working_proxy already samples multiple distinct entries without
    # replacement. Rebuilding a Profile repeats the same upstream failure and
    # multiplies traffic without ever reaching Roxy create/open.
    if any(marker in text for marker in _PROXY_POOL_UNAVAILABLE_MARKERS):
        return RoxyFailureDecision(
            "proxy_pool_unavailable", stage, False, "fix_configuration"
        ).to_dict()

    if any(marker in text for marker in _PERMANENT_MARKERS):
        if "停止" in text or "stoprequested" in text:
            code = "stopped"
        elif "selenium" in text or "node" in text or "workspaceid" in text or "roxy_" in text:
            code = "configuration"
        elif "pickup" in text or "凭证无效" in text:
            code = "email_credentials"
        elif "password" in text or "已注册" in text:
            code = "email_already_registered"
        elif "验证码连续错误" in text:
            code = "otp_rejected"
        else:
            code = "email_unavailable"
        return RoxyFailureDecision(code, stage, False, "none").to_dict()

    # /browser/create 的连接/读取超时可能已经在 Roxy 侧创建成功。没有 profile id
    # 时再次 create 会制造孤儿环境，因此只允许明确的服务端 429/502/503/504 重试。
    ambiguous_create_timeout = (
        ("/browser/create" in text or stage == "profile_create")
        and ("timeout" in text or "timed out" in text)
        and not any(marker in text for marker in _ROXY_TRANSIENT_MARKERS)
    )
    if ambiguous_create_timeout:
        return RoxyFailureDecision("profile_create_unknown", stage, False, "manual_cleanup").to_dict()

    if email_consumed:
        return RoxyFailureDecision("account_state_uncertain", stage, False, "inspect_account").to_dict()

    # 页面已经确认进入 password/OTP/login 分支后，账号状态可能已被服务端改变。
    # 只能继续当前 Profile 内恢复，不能由外层换设备、换代理重走同一邮箱。
    if email_submitted:
        return RoxyFailureDecision("account_state_uncertain", stage, False, "inspect_account").to_dict()

    if any(marker in text for marker in _ROXY_QUOTA_MARKERS):
        return RoxyFailureDecision("roxy_quota", stage, False, "none").to_dict()
    if any(marker in text for marker in _ROXY_PERMISSION_MARKERS):
        return RoxyFailureDecision("roxy_configuration", stage, False, "fix_configuration").to_dict()
    if any(marker in text for marker in _ROXY_TRANSIENT_MARKERS):
        return RoxyFailureDecision("roxy_api_transient", stage, True, "new_profile").to_dict()
    if stage in {"profile_open", "profile_create", "driver_attach"} and any(
        marker in text for marker in _ROXY_CONFIGURATION_MARKERS
    ):
        return RoxyFailureDecision("roxy_configuration", stage, False, "fix_configuration").to_dict()
    if any(marker in text for marker in _BROWSER_NETWORK_MARKERS):
        return RoxyFailureDecision("browser_network", stage, True, "new_profile").to_dict()
    if any(marker in text for marker in _RENDERER_MARKERS):
        return RoxyFailureDecision("browser_renderer", stage, True, "new_profile").to_dict()
    if any(marker in text for marker in _PAGE_STATE_MARKERS) and not email_verified:
        return RoxyFailureDecision("page_state_transient", stage, True, "new_profile").to_dict()
    if stage in {"profile_open", "driver_attach", "login_navigation"} and not email_verified:
        return RoxyFailureDecision("browser_startup", stage, True, "new_profile").to_dict()

    return RoxyFailureDecision("registration_failed", stage, False, "none").to_dict()


def retry_delay_seconds(completed_attempt: int, *, base_delay: float = 2.0) -> float:
    """短指数退避；completed_attempt=1 表示第一次失败后等待。"""
    attempt = max(1, int(completed_attempt or 1))
    base = max(0.0, float(base_delay or 0.0))
    return min(30.0, base * (2 ** (attempt - 1)))
