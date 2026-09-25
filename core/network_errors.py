"""Classify transport failures without inspecting sensitive exception text."""
from curl_cffi import CurlECode, CurlError
from curl_cffi.requests import exceptions as curl_errors
from requests import exceptions as request_errors


def is_retryable_network_error(exc: Exception) -> bool:
    supplied_retryable = getattr(exc, "retryable", None)
    if supplied_retryable is not None:
        return bool(supplied_retryable)

    # Generic libcurl exceptions need a code to distinguish transport failures
    # from invalid configuration, certificate verification, or HTTP rejection.
    if isinstance(exc, CurlError) and exc.code:
        return exc.code in {
            CurlECode.COULDNT_RESOLVE_PROXY,
            CurlECode.COULDNT_RESOLVE_HOST,
            CurlECode.COULDNT_CONNECT,
            CurlECode.WEIRD_SERVER_REPLY,
            CurlECode.HTTP2,
            CurlECode.PARTIAL_FILE,
            CurlECode.OPERATION_TIMEDOUT,
            CurlECode.SSL_CONNECT_ERROR,
            CurlECode.GOT_NOTHING,
            CurlECode.SEND_ERROR,
            CurlECode.RECV_ERROR,
            CurlECode.HTTP2_STREAM,
            CurlECode.HTTP3,
            CurlECode.QUIC_CONNECT_ERROR,
            CurlECode.PROXY,
        }
    return isinstance(exc, (
        TimeoutError,
        ConnectionError,
        curl_errors.Timeout,
        curl_errors.ConnectionError,
        curl_errors.ProxyError,
        request_errors.Timeout,
        request_errors.ConnectionError,
    ))
