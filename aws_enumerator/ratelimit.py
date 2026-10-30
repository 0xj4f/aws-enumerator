"""Client-side request budget: token buckets per (service, region) with AIMD (F-154, F-127).

botocore's adaptive retry mode only starts limiting after the first throttle, and only per client. This
module adds one shared budget per ``(service, region)`` for the whole run, so concurrent units and every client of
a service draw from the same bucket:

* :class:`TokenBucket` is a thread-safe token bucket (rate, burst) with an injectable clock and sleep;
  :meth:`TokenBucket.acquire` waits in slices of at most 0.5 s and gives up with :class:`RunInterrupted`
  when the run's stop event is set. A slice the clock did not see pass (an injected sleep that does not advance
  an injected clock, or advances it by less than its resolution) is credited to the bucket, so ``acquire``
  always terminates after at most ``1 / (rate * 0.5 s)`` + 1 slices.
* :class:`RateLimiter` keys buckets by ``(service, region)``; global control-plane services (IAM, Route 53,
  Organizations, CloudFront, STS) use the partition's global region as their key, so their budget is
  account-wide. On a throttle the rate halves (floor 0.2 rps); after each 10 s without a throttle it rises
  by 10 % up to the configured rate (AIMD).
* :meth:`RateLimiter.install` registers botocore event handlers on a session's event emitter: one token per
  API call (``before-parameter-build``, which also fires for every page), and throttle observation on
  ``needs-retry`` (every attempt) and ``after-call`` (the final answer), counted once per attempt.

Defaults (requests per second / burst) follow collectors-cli.md §4. ``--max-rps N`` caps every bucket at
``min(default, N)``; ``--rate-limit svc=rps`` overrides one service (and may go higher); ``--no-rate-limit``
disables the limiter.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Tuple

from aws_enumerator.coverage import THROTTLE_CODES, RunInterrupted

__all__ = [
    "DEFAULT_RATES", "GLOBAL_SERVICES", "RateLimitConfig", "RateLimiter", "TokenBucket", "parse_rate_overrides",
]

log = logging.getLogger(__name__)

#: (rate rps, burst) per boto3 service name; ``default`` for everything else.
DEFAULT_RATES: Dict[str, Tuple[float, float]] = {
    "default": (5.0, 5.0),
    "apigateway": (2.0, 4.0), "apigatewayv2": (2.0, 4.0),
    "lambda": (3.0, 3.0),
    "route53": (2.0, 2.0),
    "organizations": (2.0, 2.0),
    "iam": (4.0, 4.0),
    "ec2": (8.0, 8.0), "kms": (8.0, 8.0), "s3": (8.0, 8.0),
    "ecs": (5.0, 5.0),
    "ssm": (3.0, 3.0), "cognito-idp": (3.0, 3.0), "cognito-identity": (3.0, 3.0), "wafv2": (3.0, 3.0),
    "cloudtrail": (3.0, 3.0), "eks": (3.0, 3.0), "sagemaker": (3.0, 3.0),
}
#: Services whose control plane is global: one bucket per partition, keyed by the global region.
GLOBAL_SERVICES = frozenset({"iam", "route53", "organizations", "cloudfront", "sts"})
#: botocore ``service_id`` (hyphenised) -> boto3 service name, for services whose names differ.
_SERVICE_ID_TO_NAME = {
    "api-gateway": "apigateway", "apigatewayv2": "apigatewayv2", "route-53": "route53",
    "cognito-identity-provider": "cognito-idp", "cognito-identity": "cognito-identity",
    "elastic-load-balancing": "elb", "elastic-load-balancing-v2": "elbv2", "secrets-manager": "secretsmanager",
    "cloudformation": "cloudformation", "codebuild": "codebuild", "dynamodb": "dynamodb",
}
_FLOOR_RPS = 0.2
#: A token shortfall below this is rounding noise, not a reason to sleep (keeps ``acquire`` finite).
_EPSILON_TOKENS = 1e-9
_INCREASE_EVERY = 10.0
_INCREASE_FACTOR = 1.1
_MAX_SLICE = 0.5
_UID = "aws-enumerator-ratelimit"
_CTX_SEEN = "aws_enumerator_throttle_counted"


@dataclass
class RateLimitConfig:
    """Effective limiter settings (``manifest.run.options.rate_limit``)."""

    enabled: bool = True
    max_rps: Optional[float] = None
    overrides: Mapping[str, float] = field(default_factory=dict)

    def rate_for(self, service: str) -> Tuple[float, float]:
        rate, burst = DEFAULT_RATES.get(service, DEFAULT_RATES["default"])
        if service in self.overrides:
            rate = float(self.overrides[service])
            return rate, max(1.0, rate)
        if self.max_rps is not None:
            rate = min(rate, float(self.max_rps))
            burst = max(1.0, min(burst, rate))
        return rate, burst

    def to_manifest(self) -> Dict[str, Any]:
        return {"enabled": self.enabled, "default_rps": DEFAULT_RATES["default"][0] if self.enabled else None,
                "max_rps": self.max_rps, "overrides": {k: float(v) for k, v in sorted(self.overrides.items())}}


def parse_rate_overrides(values: Iterable[str]) -> Dict[str, float]:
    """``["lambda=1", "iam=2.5"]`` -> ``{"lambda": 1.0, "iam": 2.5}`` (ValueError on bad input)."""
    out: Dict[str, float] = {}
    for raw in values:
        service, sep, rps = str(raw).partition("=")
        service = service.strip().lower()
        if not sep or not service:
            raise ValueError(f"--rate-limit expects SERVICE=RPS, got {raw!r}")
        try:
            value = float(rps)
        except ValueError:
            raise ValueError(f"--rate-limit {raw!r}: RPS must be a number") from None
        if not value > 0:
            raise ValueError(f"--rate-limit {raw!r}: RPS must be greater than 0")
        out[service] = value
    return out


class TokenBucket:
    """A thread-safe token bucket with AIMD rate adjustment."""

    def __init__(self, rate: float, burst: float, *, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        if rate <= 0 or burst <= 0:
            raise ValueError("rate and burst must be positive")
        self.configured_rate = float(rate)
        self.rate = float(rate)
        self.burst = float(burst)
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._tokens = float(burst)
        now = clock()
        self._last_refill = now
        self._last_increase = now
        self.throttles = 0
        self.waited_seconds = 0.0

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self._last_refill)
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
        self._last_refill = now
        # Additive increase: _last_increase is reset by every throttle and every increase, so this fires
        # after each quiet 10 s window.
        if self.rate < self.configured_rate and now - self._last_increase >= _INCREASE_EVERY:
            self.rate = min(self.configured_rate, self.rate * _INCREASE_FACTOR)
            self._last_increase = now

    def _try_take(self) -> float:
        """Take a token and return 0, or return the seconds to wait for the next one."""
        with self._lock:
            now = self._clock()
            self._refill(now)
            if self._tokens >= 1.0 - _EPSILON_TOKENS:
                self._tokens -= 1.0
                return 0.0
            return (1.0 - self._tokens) / self.rate

    def _credit(self, seconds: float) -> None:
        """Refill for ``seconds`` of a sleep the clock did not record."""
        with self._lock:
            self._tokens = min(self.burst, self._tokens + seconds * self.rate)

    def acquire(self, stop_event: Optional[threading.Event] = None) -> float:
        """Block until a token is available; return the seconds waited."""
        waited = 0.0
        while True:
            if stop_event is not None and stop_event.is_set():
                raise RunInterrupted("run is stopping")
            wait = self._try_take()
            if wait <= 0:
                if waited:
                    with self._lock:
                        self.waited_seconds += waited
                return waited
            step = min(wait, _MAX_SLICE)
            before = self._clock()
            self._sleep(step)
            shortfall = step - max(0.0, self._clock() - before)
            if shortfall > 0:
                self._credit(shortfall)
            waited += step

    def on_throttle(self) -> None:
        """Multiplicative decrease: halve the rate (floor 0.2 rps)."""
        with self._lock:
            now = self._clock()
            self.rate = max(_FLOOR_RPS, self.rate / 2.0)
            self._tokens = min(self._tokens, 1.0)
            self._last_increase = now
            self.throttles += 1


def _service_name(model: Any, event_name: str) -> str:
    try:
        return model.service_model.service_name
    except AttributeError:
        service_id = event_name.split(".")[1] if "." in event_name else "unknown"
        return _SERVICE_ID_TO_NAME.get(service_id, service_id)


def _error_code(parsed: Any) -> Optional[str]:
    if isinstance(parsed, Mapping):
        err = parsed.get("Error")
        if isinstance(err, Mapping):
            code = err.get("Code")
            return str(code) if code else None
    return None


def _is_throttle(code: Optional[str], status: Optional[int]) -> bool:
    return bool(code and (code in THROTTLE_CODES or code.startswith("Throttl"))) or status == 429


class RateLimiter:
    """Shared buckets keyed by ``(service, region)`` for one run."""

    def __init__(self, config: RateLimitConfig, *, global_region: str = "us-east-1",
                 stop_event: Optional[threading.Event] = None, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.config = config
        self.global_region = global_region
        self.stop_event = stop_event
        self._clock = clock
        self._sleep = sleep
        self._buckets: Dict[Tuple[str, str], TokenBucket] = {}
        self._lock = threading.Lock()

    def key(self, service: str, region: Optional[str]) -> Tuple[str, str]:
        if service in GLOBAL_SERVICES or not region:
            return service, self.global_region
        return service, region

    def bucket(self, service: str, region: Optional[str]) -> TokenBucket:
        key = self.key(service, region)
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                rate, burst = self.config.rate_for(service)
                bucket = TokenBucket(rate, burst, clock=self._clock, sleep=self._sleep)
                self._buckets[key] = bucket
            return bucket

    def acquire(self, service: str, region: Optional[str]) -> float:
        if not self.config.enabled:
            return 0.0
        waited = self.bucket(service, region).acquire(self.stop_event)
        if waited:
            log.debug("rate limiter: waited %.2fs for %s@%s", waited, service, region or self.global_region)
        return waited

    def on_throttle(self, service: str, region: Optional[str]) -> None:
        if not self.config.enabled:
            return
        bucket = self.bucket(service, region)
        bucket.on_throttle()
        log.debug("rate limiter: throttle on %s@%s, rate now %.2f rps", service, region or self.global_region,
                  bucket.rate)

    def stats(self) -> Dict[str, Dict[str, float]]:
        """``{"service@region": {rate, configured_rate, throttles, waited_seconds}}`` (sorted keys)."""
        with self._lock:
            items = sorted(self._buckets.items())
        return {f"{svc}@{region}": {"rate": round(b.rate, 3), "configured_rate": b.configured_rate,
                                    "throttles": b.throttles, "waited_seconds": round(b.waited_seconds, 3)}
                for (svc, region), b in items}

    # ── botocore wiring ─────────────────────────────────────────────────────
    def install(self, events: Any) -> None:
        """Register the handlers on a botocore event emitter (a session's, before clients are created)."""
        events.register("before-parameter-build", self._before_call, unique_id=f"{_UID}-bpb")
        events.register("needs-retry", self._needs_retry, unique_id=f"{_UID}-nr")
        events.register("after-call", self._after_call, unique_id=f"{_UID}-ac")

    def _before_call(self, model: Any = None, context: Any = None, event_name: str = "", **_: Any) -> None:
        region = context.get("client_region") if isinstance(context, Mapping) else None
        self.acquire(_service_name(model, event_name), region)

    def _count(self, context: Any, service: str, region: Optional[str]) -> None:
        if isinstance(context, dict):
            context[_CTX_SEEN] = context.get(_CTX_SEEN, 0) + 1
        self.on_throttle(service, region)

    def _needs_retry(self, response: Any = None, operation: Any = None, request_dict: Any = None,
                     event_name: str = "", **_: Any) -> None:
        if not response or not isinstance(response, tuple) or len(response) < 2:
            return None
        http, parsed = response[0], response[1]
        status = getattr(http, "status_code", None)
        if _is_throttle(_error_code(parsed), status):
            context = request_dict.get("context") if isinstance(request_dict, Mapping) else None
            region = context.get("client_region") if isinstance(context, Mapping) else None
            self._count(context, _service_name(operation, event_name), region)
        return None

    def _after_call(self, http_response: Any = None, parsed: Any = None, model: Any = None, context: Any = None,
                    event_name: str = "", **_: Any) -> None:
        if isinstance(context, Mapping) and context.get(_CTX_SEEN):
            return
        status = getattr(http_response, "status_code", None)
        if _is_throttle(_error_code(parsed), status):
            region = context.get("client_region") if isinstance(context, Mapping) else None
            self._count(context, _service_name(model, event_name), region)
