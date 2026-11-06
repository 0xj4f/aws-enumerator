"""Coverage contract: what a collector could and could not read (docs/contracts/coverage-schema.md).

* :func:`classify` maps an exception from an AWS call to ``(status, code, fatal)``.
  It separates "not configured" error codes (``NoSuchBucketPolicy`` ...) from denials,
  and flags credential failures (``ExpiredToken`` ...) as fatal (F-058, F-059, F-102).
* :class:`CallResult` is what ``ctx.call`` / ``ctx.paginate`` return.
* :class:`CircuitBreaker` stops fan-out calls after N consecutive denials of one API,
  and stops an API after M final throttles (F-125 noise).
* :class:`Coverage` records every call of one module in one run unit, derives the module
  status (ok / partial / denied / failed / skipped / interrupted / not_run) and renders
  ``_coverage.json`` (schema ``aws_enumerator/schemas/coverage-1.schema.json``).

API strings are ``"<botocore service name>:<OperationName>"``, e.g. ``"s3:GetBucketPolicy"``,
``"elbv2:DescribeLoadBalancers"``. They name API operations, not IAM actions; mapping
operations to IAM actions is the permissions generator's job.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from aws_enumerator.util.fsio import iso_z, utc_now

__all__ = [
    "CALL_STATUSES", "MODULE_STATUSES", "SCHEMA_VERSION", "DEFAULT_DENY_BREAKER", "DEFAULT_THROTTLE_BREAKER",
    "DEFAULT_ITEM_ERRORS_CAP", "NOT_CONFIGURED", "DENIED_CODES", "THROTTLE_CODES", "UNAVAILABLE_CODES",
    "FATAL_CODES", "CallResult", "CircuitBreaker", "Coverage", "RunAborted", "RunInterrupted",
    "classify", "error_code_of", "is_not_configured", "worst_status",
]

SCHEMA_VERSION = 1

#: Status of one API call (or of one aggregated row in ``_coverage.json``).
CALL_STATUSES: Tuple[str, ...] = ("ok", "denied", "error", "throttled", "skipped")
#: Status of one module in one run unit, in increasing order of severity for ``worst_status``.
MODULE_STATUSES: Tuple[str, ...] = ("ok", "skipped", "not_run", "partial", "denied", "failed", "interrupted")

DEFAULT_DENY_BREAKER = 3
DEFAULT_THROTTLE_BREAKER = 5
DEFAULT_ITEM_ERRORS_CAP = 500

CIRCUIT_OPEN_DENIED = "CircuitOpen:AccessDenied"
CIRCUIT_OPEN_THROTTLED = "CircuitOpen:Throttling"

_log = logging.getLogger("aws_enumerator.coverage")


# ── run-level control-flow exceptions ────────────────────────────────────────
class RunInterrupted(BaseException):
    """Raised by ``ctx.check_stop()`` once the run's stop event is set (SIGINT/SIGTERM).

    A ``BaseException`` so that ``except Exception`` in collectors and in ``ctx.section``
    cannot swallow it; the unit unwinds, writes partial data and coverage, and stops.
    """


class RunAborted(BaseException):
    """A fatal condition (expired or invalid credentials): the whole run must stop and exit 1."""

    def __init__(self, message: str, *, api: Optional[str] = None, code: Optional[str] = None):
        super().__init__(message)
        self.api = api
        self.code = code


# ── classification tables ────────────────────────────────────────────────────
#: "This resource simply has no such configuration" error codes, per API. A call that
#: fails with one of these is recorded as ``ok`` with ``not_configured: true``; the
#: collector writes the absent value (``PolicyStatus: "absent"``), never a denial.
#: ``"<service>:*"`` applies to every operation of the service. Collector-specific codes
#: are declared on ``CollectorSpec.not_configured`` and merged by ``ctx.call``.
NOT_CONFIGURED: Dict[str, frozenset] = {
    "s3:GetBucketPolicy": frozenset({"NoSuchBucketPolicy"}),
    "s3:GetBucketPolicyStatus": frozenset({"NoSuchBucketPolicy"}),
    "s3:GetPublicAccessBlock": frozenset({"NoSuchPublicAccessBlockConfiguration"}),
    "s3:GetBucketEncryption": frozenset({"ServerSideEncryptionConfigurationNotFoundError"}),
    "s3:GetBucketTagging": frozenset({"NoSuchTagSet"}),
    "s3:GetBucketCors": frozenset({"NoSuchCORSConfiguration"}),
    "s3:GetBucketWebsite": frozenset({"NoSuchWebsiteConfiguration"}),
    "s3:GetBucketReplication": frozenset({"ReplicationConfigurationNotFoundError"}),
    "s3:GetBucketOwnershipControls": frozenset({"OwnershipControlsNotFoundError"}),
    "s3:GetBucketLifecycleConfiguration": frozenset({"NoSuchLifecycleConfiguration"}),
    "s3control:GetPublicAccessBlock": frozenset({"NoSuchPublicAccessBlockConfiguration"}),
    "iam:GetAccountPasswordPolicy": frozenset({"NoSuchEntity"}),
    "iam:GetLoginProfile": frozenset({"NoSuchEntity"}),
    "lambda:GetPolicy": frozenset({"ResourceNotFoundException"}),
    "lambda:GetFunctionUrlConfig": frozenset({"ResourceNotFoundException"}),
    "lambda:GetLayerVersionPolicy": frozenset({"ResourceNotFoundException"}),
    "ecr:GetRepositoryPolicy": frozenset({"RepositoryPolicyNotFoundException"}),
    "ecr:GetRegistryPolicy": frozenset({"RegistryPolicyNotFoundException"}),
    "dynamodb:GetResourcePolicy": frozenset({"PolicyNotFoundException"}),
    "cloudtrail:GetInsightSelectors": frozenset({"InsightNotEnabledException"}),
    "organizations:*": frozenset({"AWSOrganizationsNotInUseException"}),
    "securityhub:DescribeHub": frozenset({"InvalidAccessException"}),
    "securityhub:GetEnabledStandards": frozenset({"InvalidAccessException"}),
    "eks:ListAccessEntries": frozenset({"InvalidRequestException"}),
    "wafv2:GetLoggingConfiguration": frozenset({"WAFNonexistentItemException"}),
}

#: Exact denial codes (plus every code starting with ``AccessDenied`` / ``AuthorizationError``).
DENIED_CODES = frozenset({
    "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnauthorizedAccess",
    "UnauthorizedException", "AuthorizationError", "AuthorizationErrorException", "Forbidden",
    "ForbiddenException", "NotAuthorized", "NotAuthorizedException", "AllAccessDisabled",
})
_DENIED_PREFIXES = ("AccessDenied", "AuthorizationError", "Unauthorized")

#: Final throttling codes (botocore's retries are already exhausted when we see them).
THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "ThrottledException", "TooManyRequestsException",
    "RequestLimitExceeded", "SlowDown", "PriorRequestNotComplete", "ProvisionedThroughputExceededException",
    "RequestThrottled", "RequestThrottledException", "BandwidthLimitExceeded", "EC2ThrottledException",
})

#: The service/feature is not available to this account or region: ``skipped`` (unavailable).
UNAVAILABLE_CODES = frozenset({
    "OptInRequired", "SubscriptionRequiredException", "UnknownEndpoint", "UnknownService",
})

#: Credential failures: the run aborts (exit 1). Ambiguous codes are not listed here.
FATAL_CODES = frozenset({
    "ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId", "UnrecognizedClientException",
    "RequestExpired", "InvalidAccessKeyId", "SignatureDoesNotMatch", "AuthFailure",
    "TokenRetrievalError", "NoCredentialsError", "PartialCredentialsError", "CredentialRetrievalError",
    "UnauthorizedSSOTokenError", "SSOTokenLoadError", "InvalidToken",
})
#: Codes that are fatal only for some services (elsewhere they are ordinary errors).
_FATAL_ONLY_FOR = {"InvalidToken": frozenset({"s3", "s3control", "sts"})}

#: botocore exception class names -> (status, code) for non-ClientError failures.
_BOTOCORE_CLASS_MAP = {
    "UnknownEndpointError": ("skipped", "UnknownEndpoint"),
    "UnknownServiceError": ("skipped", "UnknownService"),
    "UnknownRegionError": ("skipped", "UnknownRegion"),
}


def _service_of(api: str) -> str:
    return api.split(":", 1)[0] if api else ""


def is_not_configured(api: str, code: Optional[str],
                      extra: Optional[Mapping[str, Iterable[str]]] = None) -> bool:
    """True when ``code`` means "not configured" for ``api`` (global table plus ``extra``)."""
    if not code:
        return False
    svc_wild = f"{_service_of(api)}:*"
    for table in (NOT_CONFIGURED, extra or {}):
        for key in (api, svc_wild):
            codes = table.get(key)
            if codes and code in codes:
                return True
    return False


def error_code_of(exc: BaseException) -> Optional[str]:
    """``Error.Code`` of a botocore ``ClientError``-like exception, else ``None``."""
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        err = response.get("Error") or {}
        if isinstance(err, Mapping):
            code = err.get("QueryErrorCode") or err.get("Code")
            if code:
                return str(code)
    return None


def _http_status_of(exc: BaseException) -> Optional[int]:
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        meta = response.get("ResponseMetadata") or {}
        status = meta.get("HTTPStatusCode") if isinstance(meta, Mapping) else None
        if isinstance(status, int):
            return status
    return None


def _is_botocore_error(exc: BaseException) -> bool:
    from botocore.exceptions import BotoCoreError  # a hard dependency; imported on first use

    return isinstance(exc, BotoCoreError)


def classify(exc: BaseException, api: str,
             not_configured: Optional[Mapping[str, Iterable[str]]] = None) -> Tuple[str, Optional[str], bool]:
    """Classify the failure of one AWS call.

    Returns ``(status, code, fatal)``:

    =========================================================  ==============================
    input                                                      result
    =========================================================  ==============================
    code in ``NOT_CONFIGURED[api]`` (or ``not_configured``)    ``("ok", code, False)``
    credential failure (``FATAL_CODES``)                       ``("error", code, True)``
    ``AccessDenied*``, ``Unauthorized*``, HTTP 403 ...          ``("denied", code, False)``
    ``Throttling*``, ``SlowDown``, HTTP 429 ...                 ``("throttled", code, False)``
    ``OptInRequired``, unknown endpoint ...                     ``("skipped", code, False)``
    any other ``ClientError`` / ``BotoCoreError`` / Exception  ``("error", code, False)``
    =========================================================  ==============================

    ``("ok", code, False)`` with a non-null ``code`` therefore means "not configured".
    For a ``BotoCoreError`` (and any other non-AWS exception) ``code`` is the class name,
    e.g. ``"EndpointConnectionError"`` or ``"ParamValidationError"``.
    """
    code = error_code_of(exc)
    service = _service_of(api)
    if code is not None:
        if is_not_configured(api, code, not_configured):
            return "ok", code, False
        if code in FATAL_CODES and (code not in _FATAL_ONLY_FOR or service in _FATAL_ONLY_FOR[code]):
            return "error", code, True
        if code in DENIED_CODES or code.startswith(_DENIED_PREFIXES):
            return "denied", code, False
        if code in THROTTLE_CODES or code.startswith("Throttl"):
            return "throttled", code, False
        if code in UNAVAILABLE_CODES:
            return "skipped", code, False
        http = _http_status_of(exc)
        if http == 403:
            return "denied", code, False
        if http == 429:
            return "throttled", code, False
        return "error", code, False
    name = type(exc).__name__
    if name in FATAL_CODES:
        return "error", name, True
    if name in _BOTOCORE_CLASS_MAP:
        status, mapped = _BOTOCORE_CLASS_MAP[name]
        return status, mapped, False
    if _is_botocore_error(exc):
        return "error", name, False
    return "error", name, False


# ── call results ─────────────────────────────────────────────────────────────
@dataclass
class CallResult:
    """The outcome of ``ctx.call`` / ``ctx.paginate`` (never raises for AWS errors).

    * ``value``: the parsed response without ``ResponseMetadata`` (``call``), or the list of
      result items (``paginate``; a dict of lists when several result keys were requested).
      ``paginate`` always returns a list/dict, possibly partial, so writers keep stable
      shapes; ``call`` returns ``None`` when the call did not succeed.
    * ``status``: one of :data:`CALL_STATUSES`.
    * ``not_configured``: the call "failed" with a code from :data:`NOT_CONFIGURED`.
    """

    api: str
    status: str = "ok"
    value: Any = None
    error_code: Optional[str] = None
    not_configured: bool = False
    pages: int = 0
    items: Optional[int] = None
    item: Optional[str] = None
    primary: bool = False
    optional: bool = False
    message: Optional[str] = None
    exception: Optional[BaseException] = field(default=None, repr=False, compare=False)

    @property
    def ok(self) -> bool:
        """The call succeeded (``not_configured`` counts as success)."""
        return self.status == "ok"

    @property
    def has_data(self) -> bool:
        """Succeeded and returned a configuration (not ``not_configured``)."""
        return self.status == "ok" and not self.not_configured

    @property
    def failed(self) -> bool:
        return self.status in ("denied", "error", "throttled")

    def get(self, key: str, default: Any = None) -> Any:
        """``value.get(key, default)`` when ``value`` is a mapping, else ``default``."""
        return self.value.get(key, default) if isinstance(self.value, Mapping) else default

    def policy_status(self) -> str:
        """``PolicyStatus`` for a resource-policy read: present|absent|denied|error|skipped."""
        if self.status == "ok":
            if self.not_configured or self.value in (None, "", {}, []):
                return "absent"
            return "present"
        if self.status == "denied":
            return "denied"
        if self.status == "skipped":
            return "skipped"
        return "error"

    def collection_error(self) -> Optional[Dict[str, Any]]:
        """A ``CollectionErrors`` entry ``{api, status, error_code}``, or ``None`` when ok."""
        if self.status == "ok":
            return None
        return {"api": self.api, "status": self.status, "error_code": self.error_code}


# ── circuit breaker ──────────────────────────────────────────────────────────
class CircuitBreaker:
    """Per (module, unit) breaker, keyed by API.

    * **deny breaker:** after ``deny_threshold`` *consecutive* ``denied`` results of
      fan-out calls (calls made with ``item=``) for one API, the API is open: the
      remaining items are not called and are recorded as ``skipped`` with
      ``CircuitOpen:AccessDenied``. Any non-denied result resets the streak. 0 disables.
    * **throttle breaker:** after ``throttle_threshold`` final ``throttled`` results for one
      API (any calls, not necessarily consecutive) the API is open with
      ``CircuitOpen:Throttling``. 0 disables.
    """

    def __init__(self, deny_threshold: int = DEFAULT_DENY_BREAKER,
                 throttle_threshold: int = DEFAULT_THROTTLE_BREAKER):
        if deny_threshold < 0 or throttle_threshold < 0:
            raise ValueError("breaker thresholds must be >= 0")
        self.deny_threshold = int(deny_threshold)
        self.throttle_threshold = int(throttle_threshold)
        self._deny_streak: Dict[str, int] = {}
        self._throttles: Dict[str, int] = {}
        self._open: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._lock = threading.Lock()

    def open_reason(self, api: str) -> Optional[str]:
        """``CircuitOpen:...`` when ``api`` is open, else ``None``."""
        with self._lock:
            info = self._open.get(api)
            return info["reason"] if info else None

    def note_skipped(self, api: str) -> None:
        with self._lock:
            if api in self._open:
                self._open[api]["skipped"] += 1

    def record(self, api: str, status: str, *, fanout: bool) -> Optional[str]:
        """Feed one result; returns the reason when this result opened the breaker."""
        with self._lock:
            if api in self._open:
                return None
            if status == "denied" and fanout:
                streak = self._deny_streak.get(api, 0) + 1
                self._deny_streak[api] = streak
                if self.deny_threshold and streak >= self.deny_threshold:
                    self._open[api] = {"api": api, "kind": "deny", "reason": CIRCUIT_OPEN_DENIED,
                                       "opened_after": streak, "skipped": 0}
                    return CIRCUIT_OPEN_DENIED
            elif fanout:
                self._deny_streak[api] = 0
            if status == "throttled":
                count = self._throttles.get(api, 0) + 1
                self._throttles[api] = count
                if self.throttle_threshold and count >= self.throttle_threshold:
                    self._open[api] = {"api": api, "kind": "throttle", "reason": CIRCUIT_OPEN_THROTTLED,
                                       "opened_after": count, "skipped": 0}
                    return CIRCUIT_OPEN_THROTTLED
            return None

    def opened(self) -> List[Dict[str, Any]]:
        """``[{api, kind, reason, opened_after, skipped}]`` in opening order."""
        with self._lock:
            return [dict(v) for v in self._open.values()]


# ── coverage of one module in one unit ───────────────────────────────────────
_SEVERITY = {s: i for i, s in enumerate(MODULE_STATUSES)}


def worst_status(statuses: Iterable[str]) -> str:
    """The most severe module status (``ok`` < skipped < not_run < partial < denied < failed < interrupted)."""
    worst = "ok"
    for s in statuses:
        if _SEVERITY.get(s, 0) > _SEVERITY[worst]:
            worst = s
    return worst


def _short_message(exc: BaseException, limit: int = 200) -> Optional[str]:
    """A short message for non-AWS exceptions. AWS error messages are never recorded: they
    carry the caller ARN, which ``--redact-identity`` must be able to keep out of the report."""
    if error_code_of(exc) is not None:
        return None
    text = str(exc).replace("\n", " ").strip()
    return text[:limit] if text else None


class Coverage:
    """Everything one module did in one run unit (``region`` is ``"global"`` or a region).

    Thread-safe, but meant to be owned by one unit thread. Render with :meth:`to_json`.
    """

    def __init__(self, module: str, region: str, services: Sequence[str] = (), *,
                 deny_breaker: int = DEFAULT_DENY_BREAKER, throttle_breaker: int = DEFAULT_THROTTLE_BREAKER,
                 item_errors_cap: int = DEFAULT_ITEM_ERRORS_CAP, protocol: str = "ctx",
                 logger: Optional[logging.Logger] = None, clock=time.monotonic):
        self.module = module
        self.region = region
        self.services = tuple(services)
        self.protocol = protocol
        self.breaker = CircuitBreaker(deny_breaker, throttle_breaker)
        self.item_errors_cap = int(item_errors_cap)
        self.log = logger or _log
        self._clock = clock
        self._lock = threading.RLock()
        self._rows: "OrderedDict[Tuple[Any, ...], Dict[str, Any]]" = OrderedDict()
        self._sections: List[Dict[str, Any]] = []
        self._item_errors: List[Dict[str, Any]] = []
        self._item_errors_total = 0
        self._primary_denied = False
        self._degraded_reasons: List[str] = []
        self._error: Optional[Dict[str, Any]] = None
        self._forced: Optional[Tuple[str, Optional[str]]] = None  # (status, reason) for skipped/not_run
        self._interrupted = False
        self._throttle_events = 0
        self.started_at: Optional[str] = None
        self.ended_at: Optional[str] = None
        self._t0: Optional[float] = None
        self.duration_seconds: Optional[float] = None

    # lifecycle ---------------------------------------------------------------
    @classmethod
    def not_run(cls, module: str, region: str, reason: str, services: Sequence[str] = ()) -> "Coverage":
        cov = cls(module, region, services)
        cov._forced = ("not_run", reason)
        return cov

    def start(self) -> "Coverage":
        with self._lock:
            if self._t0 is None:
                self._t0 = self._clock()
                self.started_at = iso_z(utc_now())
        return self

    def finish(self) -> "Coverage":
        with self._lock:
            if self._t0 is not None and self.duration_seconds is None:
                self.duration_seconds = round(max(0.0, self._clock() - self._t0), 3)
                self.ended_at = iso_z(utc_now())
        return self

    def mark_skipped(self, reason: str) -> None:
        """The whole module was skipped (unavailable in the partition, dependency missing, flag)."""
        with self._lock:
            self._forced = ("skipped", reason)

    def mark_failed(self, exc: BaseException) -> None:
        """An unhandled exception escaped the module outside any section."""
        with self._lock:
            self._error = {"type": type(exc).__name__, "code": error_code_of(exc), "message": _short_message(exc)}

    def mark_interrupted(self) -> None:
        with self._lock:
            self._interrupted = True

    # recording ---------------------------------------------------------------
    def record(self, result: CallResult) -> CallResult:
        """Record one call result (``ctx.call`` / ``ctx.paginate`` do this)."""
        status = result.status
        if status not in CALL_STATUSES:
            raise ValueError(f"unknown call status {status!r}")
        circuit = bool(result.error_code and result.error_code.startswith("CircuitOpen:"))
        with self._lock:
            key = (result.api, status, result.error_code, bool(result.not_configured),
                   bool(result.primary), bool(result.optional))
            row = self._rows.get(key)
            if row is None:
                row = {"api": result.api, "status": status, "count": 0, "items": None, "pages": 0,
                       "error_code": result.error_code, "not_configured": bool(result.not_configured),
                       "primary": bool(result.primary), "optional": bool(result.optional)}
                self._rows[key] = row
            row["count"] += 1
            row["pages"] += int(result.pages or 0)
            if result.items is not None:
                row["items"] = (row["items"] or 0) + int(result.items)
            if status == "throttled":
                self._throttle_events += 1
            if not result.optional:
                if status == "denied" and result.primary:
                    self._primary_denied = True
                if status in ("denied", "error", "throttled") or (status == "skipped" and circuit):
                    self._degraded_reasons.append(f"{result.api} {status}")
            if result.item is not None and status != "ok":
                self._add_item_error(result.item, result.api, status, result.error_code)
        if result.item is not None or status == "throttled":
            opened = self.breaker.record(result.api, status, fanout=result.item is not None)
            if opened:
                self.log.warning("%s/%s: circuit breaker opened for %s (%s); remaining calls are skipped",
                                 self.module, self.region, result.api, opened)
        return result

    def circuit_skip(self, api: str, *, item: Optional[str] = None, primary: bool = False,
                     optional: bool = False) -> Optional[CallResult]:
        """If ``api`` is open, record a skipped call and return it; else ``None``."""
        reason = self.breaker.open_reason(api)
        if reason is None:
            return None
        self.breaker.note_skipped(api)
        return self.record(CallResult(api=api, status="skipped", error_code=reason, item=item,
                                      primary=primary, optional=optional))

    def skip(self, api: str, reason: str, *, item: Optional[str] = None) -> CallResult:
        """Record a call deliberately not made (a flag, a mode, a cap). Never degrades the status."""
        return self.record(CallResult(api=api, status="skipped", error_code=reason, item=item, optional=True))

    def item_error(self, resource: str, api: str, status: str, error_code: Optional[str] = None) -> None:
        """Record a per-item problem that did not come from a single wrapped call."""
        if status not in CALL_STATUSES or status == "ok":
            raise ValueError(f"item_error status must be a failure status, got {status!r}")
        with self._lock:
            self._add_item_error(resource, api, status, error_code)
            if status in ("denied", "error", "throttled"):
                self._degraded_reasons.append(f"{api} {status} ({resource})")

    def _add_item_error(self, resource: str, api: str, status: str, error_code: Optional[str]) -> None:
        self._item_errors_total += 1
        if len(self._item_errors) < self.item_errors_cap:
            self._item_errors.append({"resource": str(resource), "api": api, "status": status,
                                      "error_code": error_code})

    def section_started(self, name: str) -> Dict[str, Any]:
        with self._lock:
            entry = {"name": name, "status": "ok", "error_type": None, "error_code": None, "message": None}
            self._sections.append(entry)
            return entry

    def section_error(self, entry: Dict[str, Any], exc: BaseException) -> None:
        """A section raised: it is recorded, the module becomes ``partial``, collection goes on."""
        with self._lock:
            entry.update(status="error", error_type=type(exc).__name__, error_code=error_code_of(exc),
                         message=_short_message(exc))
            self._degraded_reasons.append(f"section {entry['name']} raised {type(exc).__name__}")

    def section_interrupted(self, entry: Dict[str, Any]) -> None:
        with self._lock:
            entry["status"] = "interrupted"

    # derived -----------------------------------------------------------------
    @property
    def status(self) -> str:
        """``not_run``/``skipped`` (forced) > ``interrupted`` > ``failed`` > ``denied`` > ``partial`` > ``ok``."""
        with self._lock:
            if self._forced is not None:
                return self._forced[0]
            if self._interrupted:
                return "interrupted"
            if self._error is not None:
                return "failed"
            if self._primary_denied:
                return "denied"
            if self._degraded_reasons:
                return "partial"
            return "ok"

    @property
    def status_reason(self) -> Optional[str]:
        with self._lock:
            if self._forced is not None:
                return self._forced[1]
            if self._interrupted:
                return "run interrupted"
            if self._error is not None:
                return f"unhandled {self._error['type']}"
            if self._primary_denied:
                denied = sorted({r["api"] for r in self._rows.values() if r["primary"] and r["status"] == "denied"})
                return "primary call denied: " + ", ".join(denied)
            if self._degraded_reasons:
                first = self._degraded_reasons[0]
                more = len(self._degraded_reasons) - 1
                return first + (f" (+{more} more)" if more else "")
            return None

    @property
    def throttle_events(self) -> int:
        return self._throttle_events

    def summary(self) -> Dict[str, int]:
        """Counts for the manifest: ``{calls, ok, denied, error, throttled, skipped, not_configured, item_errors}``."""
        with self._lock:
            out = {"calls": 0, "ok": 0, "denied": 0, "error": 0, "throttled": 0, "skipped": 0,
                   "not_configured": 0, "item_errors": self._item_errors_total}
            for row in self._rows.values():
                out["calls"] += row["count"]
                out[row["status"]] += row["count"]
                if row["not_configured"]:
                    out["not_configured"] += row["count"]
            return out

    def denied_apis(self) -> List[str]:
        with self._lock:
            return sorted({r["api"] for r in self._rows.values() if r["status"] == "denied"})

    def calls(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = [dict(r) for r in self._rows.values()]
        return sorted(rows, key=lambda r: (r["api"], r["status"], r["error_code"] or "", r["not_configured"],
                                           r["primary"], r["optional"]))

    def to_json(self) -> Dict[str, Any]:
        """The ``_coverage.json`` document (schema ``coverage-1.schema.json``)."""
        with self._lock:
            item_errors = sorted((dict(e) for e in self._item_errors),
                                 key=lambda e: (e["api"], e["resource"], e["status"], e["error_code"] or ""))
            doc = {
                "schema_version": SCHEMA_VERSION,
                "module": self.module,
                "region": self.region,
                "services": list(self.services),
                "protocol": self.protocol,
                "status": self.status,
                "status_reason": self.status_reason,
                "started_at": self.started_at,
                "ended_at": self.ended_at,
                "duration_seconds": self.duration_seconds,
                "summary": self.summary(),
                "calls": self.calls(),
                "sections": [dict(s) for s in self._sections],
                "breakers": self.breaker.opened(),
                "item_errors": item_errors,
                "item_errors_truncated": self._item_errors_total > len(self._item_errors),
                "error": dict(self._error) if self._error else None,
            }
        return doc
