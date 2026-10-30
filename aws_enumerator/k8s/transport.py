"""HTTP transport to a Kubernetes API server (collectors-cli.md §5.16, F-120).

:class:`ApiClientTransport` sends every request through ``kubernetes.client.ApiClient.call_api`` with

* an explicit ``_request_timeout=(connect, read)`` (default ``(5, 60)``; 3 s connect for endpoints that are
  private or CIDR-restricted), so an unreachable endpoint never stalls the run for the OS TCP timeout;
* ``_preload_content=False``: the raw JSON body is parsed here, never deserialised into model objects;
* the bearer token refreshed before each request (``refresh``), the per-cluster :class:`RateGate`, and the
  user agent set once on the client.

Every failure becomes a :class:`K8sRequestError` with a stable ``code`` (``Unauthorized``, ``Forbidden``,
``NotFound``, ``Gone``, ``TooManyRequests``, ``HTTP500``, ``ConnectTimeoutError``, ``SSLError``,
``TokenRefreshFailed`` ...).
Response bodies and exception messages are never kept: they can echo request data, and the error
strings end up in reports.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple

__all__ = [
    "ApiClientTransport", "JSON_ACCEPT", "K8sRequestError", "METADATA_ONLY_ACCEPT", "PRIVATE_CONNECT_TIMEOUT",
    "RateGate", "classify_exception",
]

log = logging.getLogger("aws_enumerator.k8s")

JSON_ACCEPT = "application/json"
#: Metadata-only lists: the API server returns ``PartialObjectMetadataList`` (no ``data``), F-009.
METADATA_ONLY_ACCEPT = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1"
#: Connect timeout for endpoints that are private or restricted to CIDRs (F-120).
PRIVATE_CONNECT_TIMEOUT = 3.0

_HTTP_CODES = {400: "BadRequest", 401: "Unauthorized", 403: "Forbidden", 404: "NotFound", 405: "MethodNotAllowed",
               409: "Conflict", 410: "Gone", 422: "Invalid", 429: "TooManyRequests"}
#: urllib3 / socket failures that mean "no HTTP response" (the endpoint is not reachable from here).
_UNREACHABLE = frozenset({
    "ConnectTimeoutError", "NewConnectionError", "MaxRetryError", "ProtocolError", "ConnectionError",
    "ConnectionRefusedError", "ConnectionResetError", "NameResolutionError", "TimeoutError", "timeout",
    "gaierror", "ProxyError", "LocationParseError",
})


class K8sRequestError(Exception):
    """One failed request. ``status`` is the HTTP status (``None`` when no response was received).

    ``kind`` is ``http`` (the server answered), ``unreachable`` (no connection), ``timeout`` (connected,
    then no answer in time), ``tls`` (certificate/TLS failure) or ``error`` (anything else).
    """

    def __init__(self, code: str, *, status: Optional[int] = None, kind: str = "http"):
        super().__init__(code if status is None else f"{code} (HTTP {status})")
        self.code = code
        self.status = status
        self.kind = kind

    @property
    def denied(self) -> bool:
        return self.status in (401, 403)


def _innermost(exc: BaseException) -> BaseException:
    """urllib3's ``MaxRetryError.reason`` holds the underlying error."""
    reason = getattr(exc, "reason", None)
    if type(exc).__name__ == "MaxRetryError" and isinstance(reason, BaseException):
        return reason
    return exc


def classify_exception(exc: BaseException) -> K8sRequestError:
    """Map a client/urllib3/socket exception to a :class:`K8sRequestError` (no message text kept)."""
    if isinstance(exc, K8sRequestError):
        return exc
    status = getattr(exc, "status", None)
    if isinstance(status, int) and not isinstance(status, bool):
        if status == 0:  # the client's own wrapper for TLS errors and "no response"
            reason = str(getattr(exc, "reason", "") or "")
            if reason.startswith("SSLError"):
                return K8sRequestError("SSLError", kind="tls")
            return K8sRequestError("ConnectionError", kind="unreachable")
        return K8sRequestError(_HTTP_CODES.get(status, f"HTTP{status}"), status=status, kind="http")
    inner = _innermost(exc)
    name = type(inner).__name__
    if name in ("SSLError", "SSLCertVerificationError", "CertificateError"):
        return K8sRequestError("SSLError", kind="tls")
    if name in ("ReadTimeoutError", "ReadTimeout"):
        return K8sRequestError("ReadTimeoutError", kind="timeout")
    if name in _UNREACHABLE or isinstance(inner, (ConnectionError, TimeoutError)):
        return K8sRequestError(name, kind="unreachable")
    if isinstance(inner, OSError):
        return K8sRequestError(name, kind="unreachable")
    return K8sRequestError(name, kind="error")


class RateGate:
    """A token bucket (``rate`` requests per second, ``burst`` tokens) for one cluster.

    ``acquire`` sleeps in slices of at most 0.5 s and calls ``check_stop`` between slices, so a stopping
    run is not held up by the limiter.
    """

    def __init__(self, rate: float, burst: int, *, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep, check_stop: Optional[Callable[[], None]] = None):
        if rate <= 0 or burst < 1:
            raise ValueError("rate must be > 0 and burst >= 1")
        self.rate = float(rate)
        self.burst = int(burst)
        self._clock = clock
        self._sleep = sleep
        self._check_stop = check_stop
        self._tokens = float(burst)
        self._stamp = clock()
        self._lock = threading.Lock()

    def _take(self) -> float:
        """Take a token if one is free (returns 0), else the seconds until one is."""
        with self._lock:
            now = self._clock()
            self._tokens = min(self.burst, self._tokens + (now - self._stamp) * self.rate)
            self._stamp = now
            if self._tokens >= 1:
                self._tokens -= 1
                return 0.0
            return (1 - self._tokens) / self.rate

    def acquire(self) -> None:
        while True:
            wait = self._take()
            if wait <= 0:
                return
            if self._check_stop is not None:
                self._check_stop()
            self._sleep(min(wait, 0.5))


class ApiClientTransport:
    """``request(method, path, query, headers, body) -> parsed JSON`` over a kubernetes ``ApiClient``."""

    def __init__(self, api_client: Any, *, timeout: Tuple[float, float],
                 refresh: Optional[Callable[[], None]] = None, gate: Optional[RateGate] = None,
                 user_agent: Optional[str] = None):
        self.api_client = api_client
        self.timeout = (float(timeout[0]), float(timeout[1]))
        self._refresh = refresh
        self._gate = gate
        if user_agent:
            # default_headers win over per-request headers in ApiClient.__call_api, so set it here.
            api_client.set_default_header("User-Agent", user_agent)

    def request(self, method: str, path: str, *, query: Sequence[Tuple[str, Any]] = (),
                headers: Optional[Mapping[str, str]] = None, body: Any = None) -> Dict[str, Any]:
        if self._refresh is not None:
            try:
                self._refresh()
            except Exception as exc:  # re-signing the EKS token (botocore credential errors ...)
                log.debug("token refresh before %s %s failed: %s", method.upper(), path, type(exc).__name__)
                raise K8sRequestError("TokenRefreshFailed", kind="error") from None
        if self._gate is not None:
            self._gate.acquire()
        header_params = {"Accept": JSON_ACCEPT}
        if body is not None:
            header_params["Content-Type"] = "application/json"
        header_params.update(headers or {})
        try:
            response = self.api_client.call_api(
                path, method.upper(), path_params={}, query_params=list(query), header_params=header_params,
                body=body, auth_settings=["BearerToken"], _preload_content=False, _return_http_data_only=True,
                _request_timeout=self.timeout)
        except Exception as exc:  # the client raises ApiException, urllib3 and socket errors
            err = classify_exception(exc)
            log.debug("%s %s failed: %s", method.upper(), path, err.code)
            raise err from None
        return _parse(response)


def _parse(response: Any) -> Dict[str, Any]:
    raw = getattr(response, "data", response)
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("utf-8", errors="replace")
    try:
        doc = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        raise K8sRequestError("InvalidJSON", kind="error") from None
    if not isinstance(doc, dict):
        raise K8sRequestError("InvalidJSON", kind="error")
    return doc
