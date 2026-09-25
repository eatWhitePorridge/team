# -*- coding: utf-8 -*-
"""从项目根目录 .env 加载密钥/敏感配置。

设计目标：
  - 重要 API Key 不进 git 跟踪的 config/*.py 默认值
  - config 模块启动 / reload 时读取环境变量
  - WebUI 可读写 .env 中的密钥字段
"""
from __future__ import annotations

import errno
import os
import re
import threading
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_PATH = _PROJECT_ROOT / ".env"
_LOADED = False

# Large multiline pools are application data, not child-process settings.  On
# macOS, execve rejects argv + environment above kern.argmax (normally 1 MiB).
# Keep oversized .env values available through env_value/env_list without
# copying them into os.environ, where Selenium/Node/Go subprocesses inherit them.
_MAX_INHERITED_ENV_VALUE_BYTES = 32 * 1024
_FILE_ONLY_VALUES: dict[str, str] = {}
_ENV_LOCK = threading.RLock()

# 这些多行列表字段允许用空值显式覆盖为 []。
# 例如 WebUI 清空代理池后会写入 PROXY_POOL="" / PROXY_POOL="[]"，不能再回退到源码默认本地代理。
EXPLICIT_EMPTY_LIST_ENV_KEYS = {"PROXY_POOL"}

# 统一管理：env key -> 说明（.env.example 用）
SECRET_ENV_KEYS: dict[str, str] = {
    "WEBUI_AUTH_CODE": "WebUI 登录授权码",
    "WEBUI_SESSION_SECRET": "WebUI Session Cookie 签名密钥",
    "BROWSER_USE_API_KEY": "Browser Use Cloud API Key",
    "SKYVERN_API_KEY": "Skyvern API Key",
    "ROXY_API_TOKEN": "RoxyBrowser 本地 API Token",
    "PLAN_CHECK_PROXY": "套餐查询专用代理（可能包含认证信息）",
    "QQ_IMAP_PASSWORD": "QQ 邮箱 IMAP 授权码（不是 QQ 密码）",
    "GPTMAIL_API_KEY": "GPTMail API Key",
    "LOF_MAIL_API_TOKEN": "LOF Mail API Token",
    "CLOUDFLARE_API_KEY": "Cloudflare Worker 临时邮箱 API Key / ADMIN_PASSWORD",
    "CLOUDFLARE_CUSTOM_AUTH": "Cloudflare Worker 全局密码 x-custom-auth",
    "MAIL_NEST_API_KEY": "MailNest API Key",
    "CLOUDMAIL_AUTH_TOKEN": "CloudMail Authorization Token",
    "CLOUDMAIL_PASSWORD": "CloudMail 登录密码",
    "FASTMAIL_API_TOKEN": "Fastmail JMAP API Token",
    "FASTMAIL_SESSION_COOKIE": "Fastmail Web Session Cookie",
    "FASTMAIL_SUDO_PASSWORD": "Fastmail Alias 回收 sudo 密码",
    "CPA_MANAGEMENT_KEY": "CPA 管理接口密钥",
    "NEXUSVAULT_API_KEY": "NexusVault 入库 API Key",
    "EXTRACT_LINK_CDK": "提链服务 CDK",
    "MOMO_PROXY_API_URL": "MoMo 动态代理生成接口（可能包含授权参数）",
    "SUB2API_API_KEY": "sub2api 管理接口 API Key",
    "SUB2API_API_TOKEN": "sub2api 管理接口鉴权 Token（旧配置名，兼容）",
    "SMS_API_KEY": "接码平台 API Key（如 GrizzlySMS）",
    "SMSBOWER_API_KEY": "SMSBower API Key",
    "HEROSMS_API_KEY": "HeroSMS API Key",
    "HEROSMS_PROXY": "HeroSMS API 专用代理",
    "PAYPAL_SMSBOWER_API_KEY": "PayPal SMSBower API Key（留空时复用 SMSBOWER_API_KEY）",
    "PAYPAL_SMSBOWER_PROXY": "PayPal SMSBower API 专用代理",
    "PAYPAL_HEROSMS_API_KEY": "PayPal HeroSMS API Key（留空时复用 HEROSMS_API_KEY）",
    "PAYPAL_HEROSMS_PROXY": "PayPal HeroSMS API 专用代理",
    "L_ADMIN_AUTH_CODE": "本地 L 接码服务 ADMIN_AUTH_CODE",
    "H_ADMIN_AUTH_CODE": "本地 H 接码服务 ADMIN_AUTH_CODE",
}


def env_path() -> Path:
    return _ENV_PATH


def load_env(*, override: bool = False) -> Path:
    """加载项目根 .env 到进程环境。可重复调用（reload 时用 override=True）。

    优先使用 python-dotenv；未安装时使用本文件内置的轻量 parser，避免配置读取强依赖。
    """
    global _FILE_ONLY_VALUES, _LOADED
    with _ENV_LOCK:
        disabled = os.environ.get("PYTHON_DOTENV_DISABLED", "").casefold() in {
            "1", "true", "t", "yes", "y",
        }
        if disabled:
            _LOADED = True
            return _ENV_PATH

        values: dict[str, str] = {}
        if _ENV_PATH.exists():
            try:
                from dotenv.main import DotEnv

                parsed = DotEnv(_ENV_PATH, override=override).dict()
                values = {
                    str(key): str(value)
                    for key, value in parsed.items()
                    if key and value is not None
                }
            except ImportError:  # pragma: no cover
                values = read_env_file()

        file_only: dict[str, str] = {}
        for key, value in values.items():
            value_bytes = len(value.encode("utf-8", errors="replace"))
            if value_bytes > _MAX_INHERITED_ENV_VALUE_BYTES:
                file_only[key] = value
                # override=True must replace a previous value loaded into the
                # process environment. The equality branch also repairs a
                # process first loaded with an older version of this loader.
                if override or os.environ.get(key) == value:
                    os.environ.pop(key, None)
                continue
            if override or key not in os.environ:
                os.environ[key] = value

        _FILE_ONLY_VALUES = file_only
        _LOADED = True
    return _ENV_PATH


def ensure_loaded() -> None:
    if not _LOADED:
        load_env(override=False)


def env_str(key: str, default: str = "") -> str:
    ensure_loaded()
    value = _raw_env_value(key)
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip()


def _raw_env_value(key: str) -> str | None:
    """Return an explicit process value, then an oversized file-only value."""
    with _ENV_LOCK:
        if key in os.environ:
            return os.environ[key]
        return _FILE_ONLY_VALUES.get(key)


def build_subprocess_env(
    *,
    max_value_bytes: int = _MAX_INHERITED_ENV_VALUE_BYTES,
    max_total_bytes: int = 256 * 1024,
) -> dict[str, str]:
    """Build a bounded environment for local helper processes.

    Normal system variables are retained. Oversized application values and any
    tail beyond the conservative total cap are omitted; helpers never consume
    proxy-pool configuration directly from their environment.
    """
    essential = {
        "PATH", "HOME", "TMPDIR", "TMP", "TEMP", "USER", "LOGNAME", "SHELL",
        "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT", "WINDIR", "COMSPEC",
        "PATHEXT", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
        "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "__CF_USER_TEXT_ENCODING",
    }
    with _ENV_LOCK:
        rows = list(os.environ.items())
    rows.sort(key=lambda item: (item[0] not in essential, item[0]))
    result: dict[str, str] = {}
    total = 0
    value_limit = max(1024, int(max_value_bytes or 0))
    total_limit = max(value_limit, int(max_total_bytes or 0))
    for key, value in rows:
        entry_size = len(key.encode("utf-8", errors="replace")) + len(
            value.encode("utf-8", errors="replace")
        ) + 2
        if entry_size > value_limit or total + entry_size > total_limit:
            continue
        result[key] = value
        total += entry_size
    return result


def _escape_env_value(value: str) -> str:
    # 统一双引号，避免空格/特殊字符问题
    escaped = (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "")
    )
    return f'"{escaped}"'


def read_env_file() -> dict[str, str]:
    """解析 .env 文件为 dict（不依赖 os.environ）。"""
    if not _ENV_PATH.exists():
        return {}
    out: dict[str, str] = {}
    for raw in _ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if not key:
            continue
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
            val = val.replace("\\n", "\n").replace("\\\"", '"').replace("\\\\", "\\")
        out[key] = val
    return out


def write_env_values(updates: dict[str, str]) -> list[str]:
    """更新 .env 中的若干 key；不存在则追加。返回实际写入的 key 列表。"""
    if not updates:
        return []

    existing_lines: list[str] = []
    if _ENV_PATH.exists():
        existing_lines = _ENV_PATH.read_text(encoding="utf-8").splitlines()

    remaining = {str(k): ("" if v is None else str(v)) for k, v in updates.items()}
    written: list[str] = []
    out_lines: list[str] = []
    key_re = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")

    for line in existing_lines:
        m = key_re.match(line)
        if not m:
            out_lines.append(line)
            continue
        key = m.group(1)
        if key in remaining:
            out_lines.append(f"{key}={_escape_env_value(remaining.pop(key))}")
            written.append(key)
        else:
            out_lines.append(line)

    if remaining:
        if out_lines and out_lines[-1].strip():
            out_lines.append("")
        out_lines.append("# ---- updated by WebUI / config.env_loader ----")
        for key, value in remaining.items():
            out_lines.append(f"{key}={_escape_env_value(value)}")
            written.append(key)

    text = "\n".join(out_lines).rstrip() + "\n"
    target = _ENV_PATH.resolve(strict=False) if _ENV_PATH.is_symlink() else _ENV_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".env.tmp")
    tmp.write_text(text, encoding="utf-8")
    try:
        tmp.replace(target)
    except OSError as exc:
        # A single-file Docker bind mount cannot be replaced as a directory
        # entry. Keep configuration persistence working by updating that
        # mounted inode in place and flushing it before reloading.
        if exc.errno not in {errno.EBUSY, errno.EXDEV, errno.EPERM}:
            raise
        with target.open("w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass

    # 让当前进程立刻看到新值
    load_env(override=True)
    return written


def _coerce_env_value(raw: str, default, vtype: str | None = None):
    if vtype is None:
        if isinstance(default, bool):
            vtype = "bool"
        elif isinstance(default, int) and not isinstance(default, bool):
            vtype = "int"
        elif isinstance(default, float):
            vtype = "float"
        elif isinstance(default, (list, tuple)):
            vtype = "list_str_multiline"
        else:
            vtype = "str"
    if vtype == "bool":
        return str(raw).strip().lower() in ("true", "1", "yes", "on", "y")
    if vtype == "int":
        return int(str(raw).strip())
    if vtype == "float":
        return float(str(raw).strip())
    if vtype == "list_str_multiline":
        text = str(raw)
        # systemd EnvironmentFile 会保留双引号内的字面 `\n`，而
        # python-dotenv 会把它还原成真实换行。列表配置需兼容两种来源。
        text = text.replace("\\r\\n", "\n").replace("\\n", "\n")
        # 兼容旧值：PROXY_POOL='["http://..."]'
        try:
            import ast
            val = ast.literal_eval(text)
            if isinstance(val, (list, tuple)):
                return [str(x).strip() for x in val if str(x).strip()]
        except Exception:
            pass
        return [line.strip() for line in text.splitlines() if line.strip()]
    return str(raw).strip()


def env_value(key: str, default=None, vtype: str | None = None):
    ensure_loaded()
    raw = _raw_env_value(key)
    # `.env.example` 和 WebUI 里常见 `KEY=` / `KEY=""` 这种空配置。
    # 空值表示“未配置，使用 config/*.py 里的默认值”，否则 bool 默认 True
    # 会被空字符串误覆盖成 False，str/list 默认值也会被误清空。
    if raw is None:
        return default
    if str(raw).strip() == "":
        if vtype == "list_str_multiline" and key in EXPLICIT_EMPTY_LIST_ENV_KEYS:
            return []
        return default
    try:
        return _coerce_env_value(raw, default, vtype)
    except Exception:
        return default


def env_bool(key: str, default: bool = False) -> bool:
    return bool(env_value(key, default, "bool"))


def env_int(key: str, default: int = 0) -> int:
    return int(env_value(key, default, "int"))


def env_float(key: str, default: float = 0.0) -> float:
    return float(env_value(key, default, "float"))


def env_list(key: str, default: list[str] | None = None) -> list[str]:
    return list(env_value(key, default or [], "list_str_multiline"))


def apply_env_overrides(namespace: dict, schema: dict[str, str] | None = None) -> None:
    """用 .env/环境变量覆盖模块 globals() 中的配置常量。

    schema: {KEY: type}，type 支持 bool/int/float/str/list_str_multiline。
    没传 schema 时，会对 namespace 里已有的大写常量按默认值类型推断。
    """
    ensure_loaded()
    keys = schema.keys() if schema else [k for k in namespace if k.isupper()]
    for key in keys:
        if _raw_env_value(key) is None:
            continue
        default = namespace.get(key)
        vtype = schema.get(key) if schema else None
        namespace[key] = env_value(key, default, vtype)
