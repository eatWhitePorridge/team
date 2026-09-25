"""Bounded NexusVault uploads, independent of registration/supplement pools."""
from __future__ import annotations

import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import perf_counter

import requests

from core import db, nexusvault_client

logger = logging.getLogger(__name__)
UPLOAD_WORKERS = 5
# Threads start only on submit; all callers share the same network limit.
_EXECUTOR = ThreadPoolExecutor(max_workers=UPLOAD_WORKERS, thread_name_prefix="nexusvault-upload")
_HTTP_CONTEXT = threading.local()
_INFLIGHT_LOCK = threading.Lock()
_INFLIGHT: set[tuple[str, str]] = set()


def _http_session() -> requests.Session:
    """One keep-alive session per worker, never shared across threads."""
    session = getattr(_HTTP_CONTEXT, "session", None)
    if session is None:
        session = requests.Session()
        _HTTP_CONTEXT.session = session
    return session


def _upload_one(filename: str, *, api_key: str, api_url: str, timeout: float) -> dict:
    started = perf_counter()
    try:
        content, real_filename = db.read_codex_credential(filename)
        credential = json.loads(content)
        loaded = perf_counter()
        http = _http_session()
        try:
            result = nexusvault_client.import_codex_credential(
                credential, api_key=api_key, api_url=api_url, timeout=timeout, http=http,
            )
        finally:
            # Reuse TLS connections, not cookie/auth state from another API key.
            http.cookies.clear()
    except nexusvault_client.NexusVaultError as exc:
        return {"failed": {"filename": filename, "error": str(exc)[:240], "status_code": exc.status_code}}
    except ValueError as exc:
        return {"failed": {"filename": filename, "error": str(exc)[:240]}}
    except Exception as exc:
        return {"failed": {"filename": filename, "error": f"入库异常: {type(exc).__name__}"}}

    uploaded_at = perf_counter()
    uploaded = {
        "filename": real_filename, "email": result.get("email"),
        "status_code": result.get("status_code"), "export_marked": True,
    }
    warning = None
    try:
        state = db.mark_codex_exported(real_filename)
        uploaded.update(
            exported_count=state.get("exported_count", 0), exported_at=state.get("exported_at"),
        )
    except Exception as exc:
        # Remote POST already succeeded. Do not call it a failed upload and
        # encourage resubmitting the same credential when only the local save failed.
        uploaded["export_marked"] = False
        warning = {
            "filename": real_filename,
            "error": f"已入库，但本地已导出标记保存失败（{type(exc).__name__}）；请勿重复上传",
        }
        logger.warning("[NexusVault] 入库成功但导出标记保存失败: error=%s", type(exc).__name__)
    logger.debug(
        "[NexusVault] 单份耗时: read=%.3fs upload=%.3fs mark=%.3fs",
        loaded - started, uploaded_at - loaded, perf_counter() - uploaded_at,
    )
    return {"uploaded": uploaded, "warning": warning}


def _run_reserved(target: tuple[str, str], stop: threading.Event, **kwargs) -> dict:
    try:
        if stop.is_set():
            return {"failed": {"filename": target[1], "error": "尚未发送：本批遇到鉴权失败或限流，请检查后再提交"}}
        result = _upload_one(target[1], **kwargs)
        if (result.get("failed") or {}).get("status_code") in {401, 403, 429}:
            stop.set()
        return result
    finally:
        with _INFLIGHT_LOCK:
            _INFLIGHT.discard(target)


def upload_codex_files(filenames: list, *, api_key: str, api_url: str, timeout: float = 30) -> dict:
    """Upload selected files with partial results, no automatic POST retries."""
    key = str(api_key or "").strip()
    if not key:
        raise nexusvault_client.NexusVaultError("NexusVault API Key 未配置")
    url = nexusvault_client.validate_import_url(api_url)
    started = perf_counter()
    names = list(dict.fromkeys(str(value or "").strip() for value in filenames))
    names = [name for name in names if name]
    results = {}
    pending = {}
    stop = threading.Event()
    directory = str(db._CODEX_DIR.resolve(strict=False))
    for filename in names:
        target = (directory, filename)
        with _INFLIGHT_LOCK:
            if target in _INFLIGHT:
                results[filename] = {"failed": {"filename": filename, "error": "此凭证正在入库，请等待原请求完成"}}
                continue
            _INFLIGHT.add(target)
        try:
            future = _EXECUTOR.submit(_run_reserved, target, stop, api_key=key, api_url=url, timeout=timeout)
            pending[future] = filename
        except Exception as exc:
            with _INFLIGHT_LOCK:
                _INFLIGHT.discard(target)
            results[filename] = {"failed": {"filename": filename, "error": f"入库队列提交失败: {type(exc).__name__}"}}

    for future in as_completed(pending):
        filename = pending[future]
        try:
            results[filename] = future.result()
        except Exception as exc:
            results[filename] = {"failed": {"filename": filename, "error": f"入库异常: {type(exc).__name__}"}}
    # Completion order must not scramble the selected-file/result association.
    uploaded = [results[name]["uploaded"] for name in names if results[name].get("uploaded")]
    failed = [results[name]["failed"] for name in names if results[name].get("failed")]
    warnings = [results[name]["warning"] for name in names if results[name].get("warning")]
    logger.info(
        "[NexusVault] Codex 入库完成: requested=%s uploaded=%s failed=%s warnings=%s workers=%s elapsed=%.3fs",
        len(names), len(uploaded), len(failed), len(warnings), UPLOAD_WORKERS, perf_counter() - started,
    )
    return {
        "ok": not failed, "partial": bool(uploaded and failed),
        "uploaded": uploaded, "uploaded_count": len(uploaded),
        "failed": failed, "failed_count": len(failed), "warnings": warnings,
    }
