# -*- coding: utf-8 -*-
"""NexusVault Codex 凭证导入客户端。

本模块只处理单份 CPA 兼容 Codex OAuth 凭证。批量上传由独立服务限流并发
调用，复用连接并保留逐份结果，不在日志或响应中暴露 token。
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

import requests


DEFAULT_IMPORT_URL = "https://nvtokens.com/api/inventory/cards/import"
_ALLOWED_HOST = "nvtokens.com"
_ALLOWED_PATH = "/api/inventory/cards/import"
_MAX_TOKEN_LENGTH = 256 * 1024
_MAX_REQUEST_BYTES = 768 * 1024


class NexusVaultError(RuntimeError):
    """可安全返回给前端的 NexusVault 入库错误。"""

    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def validate_import_url(url: str) -> str:
    """只允许 NexusVault 官方 HTTPS 导入端点，防止凭证被发往错误地址。"""
    target = str(url or "").strip()
    try:
        parsed = urlparse(target)
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        raise NexusVaultError("NexusVault API 地址必须是官方 HTTPS 导入端点") from None
    if (
        parsed.scheme.lower() != "https"
        or hostname != _ALLOWED_HOST
        or port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path.rstrip("/") != _ALLOWED_PATH
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise NexusVaultError("NexusVault API 地址必须是官方 HTTPS 导入端点")
    return target


def build_import_payload(credential: dict[str, Any]) -> dict[str, dict[str, str]]:
    """把本地 CPA 兼容凭证转换为 NexusVault 单账号导入格式。"""
    if not isinstance(credential, dict):
        raise NexusVaultError("Codex 凭证根节点必须是 JSON 对象")

    access_token = credential.get("access_token")
    refresh_token = credential.get("refresh_token")
    email = credential.get("email")
    if not isinstance(access_token, str) or not access_token.strip():
        raise NexusVaultError("Codex 凭证缺少 access_token")
    if not isinstance(refresh_token, str) or not refresh_token.strip():
        raise NexusVaultError("Codex 凭证缺少 refresh_token")
    if not isinstance(email, str) or not email.strip() or "@" not in email:
        raise NexusVaultError("Codex 凭证缺少有效 email")
    if len(access_token) > _MAX_TOKEN_LENGTH or len(refresh_token) > _MAX_TOKEN_LENGTH:
        raise NexusVaultError("Codex token 长度超过安全限制")
    if len(email) > 320 or any(ch in email for ch in "\r\n"):
        raise NexusVaultError("Codex 凭证 email 非法")

    payload = {
        "data": {
            "access_token": access_token.strip(),
            "refresh_token": refresh_token.strip(),
            "email": email.strip(),
            "type": "codex",
        }
    }
    encoded_size = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    if encoded_size > _MAX_REQUEST_BYTES:
        raise NexusVaultError("Codex 凭证请求体超过安全限制")
    return payload


def import_codex_credential(
    credential: dict[str, Any],
    *,
    api_key: str,
    api_url: str = DEFAULT_IMPORT_URL,
    timeout: float = 30,
    http: Any | None = None,
) -> dict[str, Any]:
    """上传一份 Codex 凭证；返回值不包含任何 OAuth token 或 API Key。"""
    key = str(api_key or "").strip()
    if not key:
        raise NexusVaultError("NexusVault API Key 未配置")
    url = validate_import_url(api_url)
    payload = build_import_payload(credential)
    try:
        timeout_value = max(1.0, min(float(timeout or 30), 120.0))
    except (TypeError, ValueError):
        timeout_value = 30.0

    sender = http or requests
    try:
        response = sender.post(
            url,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "gpt-register-console/nexusvault",
                "x-api-key": key,
            },
            json=payload,
            timeout=timeout_value,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise NexusVaultError(f"NexusVault 请求失败: {type(exc).__name__}") from None
    except Exception as exc:
        # 测试注入的 HTTP 客户端不一定抛 requests.RequestException；同样只返回类型。
        raise NexusVaultError(f"NexusVault 请求失败: {type(exc).__name__}") from None

    status = int(getattr(response, "status_code", 0) or 0)
    if status < 200 or status >= 300:
        if 300 <= status < 400:
            raise NexusVaultError(f"NexusVault 拒绝重定向: HTTP {status}", status_code=status)
        raise NexusVaultError(f"NexusVault 入库失败: HTTP {status}", status_code=status)

    return {
        "ok": True,
        "uploaded": True,
        "status_code": status,
        "email": payload["data"]["email"],
    }
