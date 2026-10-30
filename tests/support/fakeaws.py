"""Routed, order-independent fake AWS for boto3 (no network, no moto).

``FakeAWS(world)`` attaches to a ``boto3.Session`` through the same botocore
events :class:`botocore.stub.Stubber` uses, but routes each request by
``(service, operation, params, region)`` instead of a FIFO queue, so it is
order-independent and thread-safe:

* ``before-parameter-build``: the request params are validated against the
  operation's input shape with :func:`botocore.validate.validate_parameters`
  (so bugs such as F-047, ``GetInsightSelectors(Name=...)``, surface exactly as
  botocore would raise them) and stashed in the request context;
* ``before-call``: injected errors are applied, then the world handler for
  ``(service, operation)`` builds the parsed response, which is validated
  against the output shape, paginated (tokens are opaque strings), and returned
  as ``(AWSResponse, parsed)`` so botocore never builds an HTTP request;
* ``before-send``: a hard failure. Any request that would reach the network
  raises :class:`NetworkAccessAttempt` (a ``BaseException``, so product code's
  ``except Exception`` cannot swallow it) and is recorded.

Every call is recorded as a :class:`Call` (service, operation, region, params,
calling module, outcome) for read-only / permission-coverage tests.

Harness failures (unknown operation, invalid world response, network access)
derive from :class:`FakeAWSHarnessError`, a ``BaseException``: a world that is
missing an answer must fail the test, not be mistaken for an AWS error that a
collector swallows.

The fake never imports production code. Attach it with :meth:`FakeAWS.session`
(a ``boto3.Session`` subclass whose instances attach themselves, so
``session.__class__(...)`` rebuilds such as ``waf.py``'s stay covered),
:meth:`FakeAWS.attach` for an existing session, or :meth:`FakeAWS.install` to
patch ``boto3.Session`` for the duration of a test.

Notes on fidelity:

* botocore's retry layer lives below ``before-call``; an injected throttle is
  therefore raised immediately (no retries, no sleeps).
* IAM policy documents should be served URL-encoded (``World.iam_doc``), as
  real IAM does, so botocore's ``json_decode_policies`` handler runs.
* Error responses carry ``Error.Code`` / ``Error.Message`` and an HTTP status;
  botocore maps the code to the modelled exception class, exactly as it would
  for a real response.
"""

from __future__ import annotations

import copy
import itertools
import json
import sys
import threading
import urllib.parse
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

import boto3
import boto3.session
import botocore.exceptions
import botocore.session
from botocore.awsrequest import AWSResponse
from botocore.exceptions import BotoCoreError, ParamValidationError
from botocore.validate import ParamValidator, ValidationErrors, validate_parameters

__all__ = [
    "AWSError", "Call", "ErrorRule", "FakeAWS", "FakeAWSHarnessError", "NetworkAccessAttempt",
    "Request", "UnhandledOperation", "World", "WorldResponseInvalid", "READ_ONLY_OPERATIONS",
    "READ_ONLY_PREFIXES", "default_skip_modules",
]

#: Operation-name prefixes considered read-only (List*/Get*/Describe*/BatchGet*...).
READ_ONLY_PREFIXES: Tuple[str, ...] = ("List", "Get", "Describe", "BatchGet", "Lookup", "Search")
#: ``service:Operation`` names outside those prefixes that the tool may still call because they change
#: nothing an operator would see: generating the IAM credential report (collectors-cli.md §5.1). Keep tiny.
READ_ONLY_OPERATIONS = frozenset({"iam:GenerateCredentialReport"})

RESPONSE_METADATA_REQUEST_ID = "FAKEAWS-REQUEST-ID"

#: botocore validation error types not enforced on *responses* (request-side constraints).
_IGNORED_OUTPUT_ERRORS = frozenset({"invalid length", "invalid range"})

#: Services whose access-denied error code is ``AccessDenied`` (query/rest-xml APIs).
_DENY_CODE_ACCESS_DENIED = frozenset({
    "iam", "s3", "sts", "cloudfront", "route53", "rds", "sns", "elb", "elbv2",
    "cloudformation", "sqs", "autoscaling",
})
_THROTTLE_CODE_QUERY = frozenset({
    "iam", "sts", "cloudfront", "route53", "rds", "sns", "elb", "elbv2", "cloudformation",
    "autoscaling",
})


# ── Harness errors (BaseException: never swallowed by product code) ──────────
class FakeAWSHarnessError(BaseException):
    """Base for failures of the test harness itself."""


class NetworkAccessAttempt(FakeAWSHarnessError):
    """A request reached botocore's ``before-send``: it would have hit the network."""


class UnhandledOperation(FakeAWSHarnessError):
    """The world has no handler for an operation the code under test called."""


class WorldResponseInvalid(FakeAWSHarnessError):
    """A world handler returned a response that does not match the output shape."""


# ── World-facing API ─────────────────────────────────────────────────────────
class AWSError(Exception):
    """Raised by a world handler to answer with an AWS error response."""

    def __init__(self, code: str, message: Optional[str] = None, status: int = 400):
        super().__init__(code, message)
        self.code = code
        self.message = message if message is not None else f"{code} (fakeaws)"
        self.status = status


@dataclass
class Request:
    """What a world handler sees."""

    service: str           # botocore service name, e.g. "iam", "cognito-idp", "elbv2"
    operation: str         # API operation name, e.g. "ListUsers"
    region: Optional[str]  # client region
    params: Dict[str, Any]  # validated request params (a private copy)
    world: "World"

    def error(self, code: str, message: Optional[str] = None, status: int = 400) -> AWSError:
        return AWSError(code, message, status)

    def deny(self, resource: Optional[str] = None) -> AWSError:
        return self.world.deny_error(self.service, self.operation, resource)


Handler = Callable[[Request], Mapping[str, Any]]


@dataclass
class ErrorRule:
    """An injected failure for matching requests.

    ``kind`` is ``"deny"`` (service-appropriate AccessDenied code), ``"throttle"``,
    ``"error"`` (explicit ``code``/``status``) or ``"raise"`` (``exception`` is a
    zero-argument factory returning a :class:`BotoCoreError` (or other) instance
    to raise from the client call).
    ``match`` is a subset of request params that must be equal; ``operation`` may be
    ``"*"`` for every operation of the service; ``region`` ``None`` matches all.
    """

    service: str
    operation: str
    kind: str
    match: Optional[Dict[str, Any]] = None
    region: Optional[str] = None
    code: Optional[str] = None
    message: Optional[str] = None
    status: Optional[int] = None
    exception: Optional[Callable[[], BaseException]] = None
    note: str = ""

    def matches(self, service: str, operation: str, region: Optional[str], params: Mapping[str, Any]) -> bool:
        if self.service != service:
            return False
        if self.operation not in ("*", operation):
            return False
        if self.region is not None and self.region != region:
            return False
        for k, v in (self.match or {}).items():
            if params.get(k, _MISSING) != v:
                return False
        return True


_MISSING = object()


@dataclass
class PaginationSpec:
    input_token: str
    output_token: str
    result_key: str
    more_results: Optional[str] = None
    limit_key: Optional[str] = None


class World:
    """A synthetic AWS account: handlers per (service, operation) plus injections.

    Handlers return the *full* parsed response (no pagination tokens); when
    ``page_sizes[(service, op)]`` is set, :class:`FakeAWS` slices the result key
    using botocore's paginator model (or ``pagination[(service, op)]`` for
    operations botocore has no paginator for) and issues opaque tokens.
    """

    def __init__(self, name: str, account_id: str, *, partition: str = "aws",
                 caller_arn: Optional[str] = None, regions: Sequence[str] = ()):
        self.name = name
        self.account_id = account_id
        self.partition = partition
        self.caller_arn = caller_arn or f"arn:{partition}:iam::{account_id}:user/demo-caller"
        self.regions = list(regions)
        self.handlers: Dict[Tuple[str, str], Handler] = {}
        self.errors: List[ErrorRule] = []
        self.page_sizes: Dict[Tuple[str, str], int] = {}
        self.pagination: Dict[Tuple[str, str], PaginationSpec] = {}
        self.meta: Dict[str, Any] = {}

    # registration -----------------------------------------------------------
    def op(self, service: str, *operations: str) -> Callable[[Handler], Handler]:
        def deco(fn: Handler) -> Handler:
            for operation in operations:
                self.handlers[(service, operation)] = fn
            return fn
        return deco

    def static(self, service: str, operation: str, response: Mapping[str, Any]) -> None:
        frozen = copy.deepcopy(dict(response))
        self.handlers[(service, operation)] = lambda req: frozen

    # injections -------------------------------------------------------------
    def deny(self, service: str, operation: str, match: Optional[Dict[str, Any]] = None,
             region: Optional[str] = None, message: Optional[str] = None, note: str = "") -> ErrorRule:
        return self._add(ErrorRule(service, operation, "deny", match, region, message=message, note=note))

    def throttle(self, service: str, operation: str, match: Optional[Dict[str, Any]] = None,
                 region: Optional[str] = None, note: str = "") -> ErrorRule:
        return self._add(ErrorRule(service, operation, "throttle", match, region, note=note))

    def fail(self, service: str, operation: str, code: str, message: Optional[str] = None,
             status: int = 400, match: Optional[Dict[str, Any]] = None, region: Optional[str] = None,
             note: str = "") -> ErrorRule:
        return self._add(ErrorRule(service, operation, "error", match, region, code=code,
                                   message=message, status=status, note=note))

    def raise_exc(self, service: str, operation: str, exception: Callable[[], BaseException],
                  match: Optional[Dict[str, Any]] = None, region: Optional[str] = None,
                  note: str = "") -> ErrorRule:
        return self._add(ErrorRule(service, operation, "raise", match, region, exception=exception, note=note))

    def _add(self, rule: ErrorRule) -> ErrorRule:
        self.errors.append(rule)
        return rule

    def clear_errors(self, service: Optional[str] = None) -> None:
        self.errors = [r for r in self.errors if service is not None and r.service != service]

    # helpers for handlers ---------------------------------------------------
    def deny_code(self, service: str) -> str:
        if service == "ec2":
            return "UnauthorizedOperation"
        if service in _DENY_CODE_ACCESS_DENIED:
            return "AccessDenied"
        return "AccessDeniedException"

    def deny_error(self, service: str, operation: str, resource: Optional[str] = None,
                   message: Optional[str] = None, action_prefix: Optional[str] = None) -> AWSError:
        prefix = action_prefix or service
        msg = message or (f"User: {self.caller_arn} is not authorized to perform: {prefix}:{operation}"
                          + (f" on resource: {resource}" if resource else "")
                          + " (fakeaws)")
        return AWSError(self.deny_code(service), msg, 403)

    def throttle_error(self, service: str) -> AWSError:
        if service == "ec2":
            return AWSError("RequestLimitExceeded", "Request limit exceeded. (fakeaws)", 503)
        if service in _THROTTLE_CODE_QUERY:
            return AWSError("Throttling", "Rate exceeded (fakeaws)", 400)
        return AWSError("ThrottlingException", "Rate exceeded (fakeaws)", 400)

    @staticmethod
    def iam_doc(document: Mapping[str, Any]) -> str:
        """URL-encode a policy document the way IAM serves it."""
        return urllib.parse.quote(json.dumps(document, separators=(",", ":")))

    @staticmethod
    def json_doc(document: Mapping[str, Any]) -> str:
        """A JSON-string policy document (S3, KMS, Lambda, SNS, SQS ... serve these)."""
        return json.dumps(document, separators=(",", ":"))

    def copy(self) -> "World":
        """An independent copy: handlers shared, injections/pagination copied."""
        other = World.__new__(World)
        other.__dict__.update(self.__dict__)
        other.handlers = dict(self.handlers)
        other.errors = list(self.errors)
        other.page_sizes = dict(self.page_sizes)
        other.pagination = dict(self.pagination)
        other.meta = copy.deepcopy(self.meta)
        other.regions = list(self.regions)
        return other


# ── Recording ────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Call:
    seq: int
    service: str
    operation: str
    region: Optional[str]
    params: Dict[str, Any]
    module: str          # label of the calling module (see FakeAWS(labeler=...))
    caller: str          # full dotted name of the calling module
    outcome: str         # "ok" | error code | "ParamValidationError" | "raise:<Exc>" | "unhandled"
    thread: str
    access_key_id: Optional[str] = None  # credentials the client signed with (fake test keys only)

    @property
    def op(self) -> str:
        return f"{self.service}:{self.operation}"

    @property
    def read_only(self) -> bool:
        return self.operation.startswith(READ_ONLY_PREFIXES) or self.op in READ_ONLY_OPERATIONS


_SKIP_MODULE_PREFIXES = ("botocore", "boto3", "s3transfer", "urllib3", "dateutil", "jmespath")


def _default_labeler(module_name: str) -> str:
    return module_name.rsplit(".", 1)[-1] if module_name else "<unknown>"


_PAGINATOR_SESSION_LOCK = threading.Lock()
_PAGINATOR_SESSION: Dict[str, Any] = {}


def _paginator_config(service: str, operation: str) -> Optional[Dict[str, Any]]:
    with _PAGINATOR_SESSION_LOCK:
        sess = _PAGINATOR_SESSION.get("s")
        if sess is None:
            sess = botocore.session.get_session()
            _PAGINATOR_SESSION["s"] = sess
        key = ("cfg", service, operation)
        if key in _PAGINATOR_SESSION:
            return _PAGINATOR_SESSION[key]
        try:
            cfg = dict(sess.get_paginator_model(service).get_paginator(operation))
        except Exception:  # no paginator model / no paginator for this op
            cfg = None
        _PAGINATOR_SESSION[key] = cfg
        return cfg


def _get_path(obj: Any, dotted: str) -> Any:
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return _MISSING
        cur = cur[part]
    return cur


def _set_path(obj: Dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = obj
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


def _del_path(obj: Dict[str, Any], dotted: str) -> None:
    parts = dotted.split(".")
    cur = obj
    for part in parts[:-1]:
        if not isinstance(cur, dict) or part not in cur:
            return
        cur = cur[part]
    if isinstance(cur, dict):
        cur.pop(parts[-1], None)


def _safe_copy(obj: Any) -> Any:
    try:
        return copy.deepcopy(obj)
    except Exception:
        return copy.copy(obj)


class FakeAWS:
    """Attachable, routed fake for every client created from a session.

    :param world: the :class:`World` to serve.
    :param strict: unknown operations raise :class:`UnhandledOperation` (default).
        With ``strict=False`` they answer ``FakeAWSUnhandledOperation`` (HTTP 501).
    :param validate_output: validate handler responses against the output shape.
    :param labeler: maps the calling module's dotted name to a stable label
        (default: last dotted component, e.g. ``aws_enumerator.collectors.iam`` -> ``iam``).
    :param skip_modules: dotted module names of *call wrappers* whose frames are skipped when the
        calling module is determined (an entry also covers its submodules). ``None`` (default)
        means :func:`default_skip_modules`: the collector context (``ctx.call`` / ``ctx.paginate``
        in ``collectors/base.py``) and ``coverage.py``, so a migrated ``collect(ctx)`` collector's
        calls are labelled with the collector module (``iam``, ``s3`` ...) instead of ``base``
        (request contracts-runtime-2). Pass ``()`` to label the innermost non-library frame.
    """

    def __init__(self, world: World, *, strict: bool = True, validate_output: bool = True,
                 labeler: Optional[Callable[[str], str]] = None,
                 skip_modules: Optional[Sequence[str]] = None):
        self.world = world
        self.strict = strict
        self.validate_output = validate_output
        self.labeler = labeler or _default_labeler
        self.skip_modules: Tuple[str, ...] = tuple(default_skip_modules() if skip_modules is None
                                                   else skip_modules)
        self.calls: List[Call] = []
        self.network_attempts: List[str] = []
        self.harness_errors: List[str] = []
        self._lock = threading.Lock()
        self._seq = itertools.count()
        self._uid = f"fakeaws-{id(self):x}"
        self._session_class: Optional[type] = None

    # ── attaching ───────────────────────────────────────────────────────────
    def attach(self, session: Any) -> Any:
        """Register the handlers on a ``boto3.Session`` (or botocore session)."""
        events = session.events if hasattr(session, "events") else session.get_component("event_emitter")
        events.register("before-parameter-build", self._on_before_parameter_build,
                        unique_id=f"{self._uid}-bpb")
        events.register("before-call", self._on_before_call, unique_id=f"{self._uid}-bc")
        events.register("before-send", self._on_before_send, unique_id=f"{self._uid}-bs")
        return session

    @property
    def session_class(self) -> type:
        """A ``boto3.Session`` subclass whose instances attach to this fake on creation."""
        if self._session_class is None:
            fake = self
            base = _genuine_session_class()

            class FakeAWSSession(base):  # type: ignore[misc, valid-type]
                _fakeaws = fake

                def __init__(self, *args: Any, **kwargs: Any) -> None:
                    super().__init__(*args, **kwargs)
                    fake.attach(self)

            FakeAWSSession.__name__ = "Session"
            FakeAWSSession.__qualname__ = "Session"
            self._session_class = FakeAWSSession
        return self._session_class

    def session(self, region_name: Optional[str] = None, **kwargs: Any) -> boto3.session.Session:
        """A real ``boto3.Session`` (subclass) with this fake attached."""
        return self.session_class(region_name=region_name, **kwargs)

    def session_factory(self, **kwargs: Any) -> Callable[[str], boto3.session.Session]:
        """A drop-in for ``get_boto3_session(region)``."""
        return lambda region: self.session(region_name=region, **kwargs)

    def install(self, monkeypatch: Any) -> "FakeAWS":
        """Make every ``boto3.Session(...)`` / ``boto3.client(...)`` in this test use the fake."""
        monkeypatch.setattr(boto3, "Session", self.session_class)
        monkeypatch.setattr(boto3.session, "Session", self.session_class)
        monkeypatch.setattr(boto3, "DEFAULT_SESSION", None)
        return self

    # ── botocore event handlers ─────────────────────────────────────────────
    def _on_before_parameter_build(self, params: Dict[str, Any], model: Any, context: Dict[str, Any],
                                   **_: Any) -> None:
        if context is None:
            return
        shape = model.input_shape
        if shape is not None:
            try:
                validate_parameters(params, shape)
            except ParamValidationError:
                self._record(model, context, _safe_copy(params), "ParamValidationError")
                raise
        context["fakeaws_params"] = _safe_copy(params)

    def _on_before_call(self, model: Any, params: Any, context: Dict[str, Any], request_signer: Any = None,
                        **_: Any):
        if context is not None:
            context["fakeaws_access_key_id"] = _access_key_id(request_signer)
        service = model.service_model.service_name
        operation = model.name
        region = context.get("client_region") if context else None
        api_params = (context or {}).get("fakeaws_params", {})
        world = self.world

        for rule in world.errors:
            if rule.matches(service, operation, region, api_params):
                if rule.kind == "raise":
                    exc = rule.exception() if rule.exception else BotoCoreError()
                    self._record(model, context, api_params, f"raise:{type(exc).__name__}")
                    raise exc
                if rule.kind == "deny":
                    err = world.deny_error(service, operation, _resource_hint(api_params),
                                           message=rule.message,
                                           action_prefix=model.service_model.signing_name)
                elif rule.kind == "throttle":
                    err = world.throttle_error(service)
                else:
                    err = AWSError(rule.code or "InternalFailure", rule.message, rule.status or 400)
                return self._error_response(model, context, api_params, err)

        handler = world.handlers.get((service, operation))
        if handler is None:
            self._record(model, context, api_params, "unhandled")
            if self.strict:
                msg = (f"world {world.name!r} has no handler for {service}:{operation} "
                       f"(region={region}, params={_short(api_params)})")
                self.harness_errors.append(msg)
                raise UnhandledOperation(msg)
            return self._error_response(model, context, api_params,
                                        AWSError("FakeAWSUnhandledOperation", f"{service}:{operation}", 501))

        req = Request(service, operation, region, _safe_copy(api_params), world)
        try:
            response = handler(req)
        except AWSError as err:
            return self._error_response(model, context, api_params, err)
        response = copy.deepcopy(dict(response or {}))
        response.pop("ResponseMetadata", None)
        response = self._paginate(service, operation, api_params, response)
        if self.validate_output:
            self._validate_output(model, service, operation, response)
        response["ResponseMetadata"] = {
            "RequestId": RESPONSE_METADATA_REQUEST_ID,
            "HTTPStatusCode": 200,
            "HTTPHeaders": {},
            "RetryAttempts": 0,
        }
        self._record(model, context, api_params, "ok")
        return AWSResponse(None, 200, {}, None), response

    def _on_before_send(self, request: Any = None, **kwargs: Any):
        url = getattr(request, "url", "?")
        msg = f"fakeaws: request would reach the network: {getattr(request, 'method', '?')} {url}"
        with self._lock:
            self.network_attempts.append(msg)
        raise NetworkAccessAttempt(msg)

    # ── internals ───────────────────────────────────────────────────────────
    def _error_response(self, model: Any, context: Dict[str, Any], api_params: Mapping[str, Any],
                        err: AWSError):
        self._record(model, context, dict(api_params), err.code)
        parsed = {
            "Error": {"Code": err.code, "Message": err.message},
            "ResponseMetadata": {
                "RequestId": RESPONSE_METADATA_REQUEST_ID,
                "HTTPStatusCode": err.status,
                "HTTPHeaders": {},
                "RetryAttempts": 0,
            },
        }
        return AWSResponse(None, err.status, {}, None), parsed

    def _paginate(self, service: str, operation: str, params: Mapping[str, Any],
                  response: Dict[str, Any]) -> Dict[str, Any]:
        size = self.world.page_sizes.get((service, operation))
        spec = self.world.pagination.get((service, operation))
        if spec is None:
            cfg = _paginator_config(service, operation)
            if cfg is None:
                return response
            if not all(isinstance(cfg.get(k), str) for k in ("input_token", "output_token", "result_key")):
                return response  # multi-token / multi-result paginators are served whole
            spec = PaginationSpec(cfg["input_token"], cfg["output_token"], cfg["result_key"],
                                  cfg.get("more_results"), cfg.get("limit_key"))
        limit = params.get(spec.limit_key) if spec.limit_key else None
        if size is None and not isinstance(limit, int):
            return response
        items = _get_path(response, spec.result_key)
        if items is _MISSING or not isinstance(items, list):
            return response
        page = min(x for x in (size, limit if isinstance(limit, int) and limit > 0 else None) if x)
        start = _decode_token(params.get(spec.input_token), operation)
        chunk = items[start:start + page]
        _set_path(response, spec.result_key, chunk)
        more = start + page < len(items)
        if more:
            _set_path(response, spec.output_token, _encode_token(operation, start + page))
        else:
            _del_path(response, spec.output_token)
        if spec.more_results:
            _set_path(response, spec.more_results, more)
        return response

    def _validate_output(self, model: Any, service: str, operation: str, response: Dict[str, Any]) -> None:
        """Structure/type check of a world response (like Stubber), minus min-length/min-value checks.

        Real services return e.g. ``{"projects": []}`` although the shared shape says
        ``min: 1``; those constraints describe requests, so they are not enforced here.
        """
        shape = model.output_shape
        report = ""
        if shape is not None:
            errors = ParamValidator().validate(response, shape)
            kept = [e for e in getattr(errors, "_errors", []) if e[0] not in _IGNORED_OUTPUT_ERRORS]
            if kept:
                filtered = ValidationErrors()
                filtered._errors = kept
                report = filtered.generate_report()
        elif response:
            report = "operation has no output shape but the world returned data"
        if report:
            msg = f"world {self.world.name!r} returned an invalid {service}:{operation} response: {report}"
            self.harness_errors.append(msg)
            raise WorldResponseInvalid(msg)

    def _record(self, model: Any, context: Optional[Dict[str, Any]], params: Mapping[str, Any],
                outcome: str) -> None:
        caller = _calling_module(self.skip_modules)
        call_params = dict(params) if isinstance(params, Mapping) else {}
        with self._lock:
            self.calls.append(Call(
                seq=next(self._seq),
                service=model.service_model.service_name,
                operation=model.name,
                region=(context or {}).get("client_region"),
                params=call_params,
                module=self.labeler(caller),
                caller=caller,
                outcome=outcome,
                thread=threading.current_thread().name,
                access_key_id=(context or {}).get("fakeaws_access_key_id"),
            ))

    # ── queries ─────────────────────────────────────────────────────────────
    def calls_for(self, service: Optional[str] = None, operation: Optional[str] = None,
                  module: Optional[str] = None, region: Optional[str] = None,
                  outcome: Optional[str] = None) -> List[Call]:
        with self._lock:
            calls = list(self.calls)
        return [c for c in calls
                if (service is None or c.service == service)
                and (operation is None or c.operation == operation)
                and (module is None or c.module == module)
                and (region is None or c.region == region)
                and (outcome is None or c.outcome == outcome)]

    def operations(self) -> List[str]:
        """Sorted unique ``service:Operation`` strings that were called."""
        return sorted({c.op for c in self.calls_for()})

    def non_read_only_calls(self) -> List[Call]:
        return [c for c in self.calls_for() if not c.read_only]

    def summary(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        """``{module: {"service:Operation": {calls, regions, outcomes, param_keys}}}`` (JSON-ready)."""
        out: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
        acc: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for c in self.calls_for():
            key = (c.module, c.op)
            entry = acc.setdefault(key, {"calls": 0, "regions": set(), "outcomes": Counter(), "param_keys": set()})
            entry["calls"] += 1
            entry["regions"].add(c.region or "<none>")
            entry["outcomes"][c.outcome] += 1
            entry["param_keys"].update(c.params.keys())
        for (module, op), e in sorted(acc.items()):
            out[module][op] = {
                "calls": e["calls"],
                "regions": sorted(e["regions"]),
                "outcomes": dict(sorted(e["outcomes"].items())),
                "param_keys": sorted(e["param_keys"]),
            }
        return {m: dict(sorted(v.items())) for m, v in sorted(out.items())}

    def assert_clean(self) -> None:
        """Raise AssertionError if any network attempt or harness error was recorded."""
        problems = list(self.network_attempts) + list(self.harness_errors)
        if problems:
            raise AssertionError("fakeaws problems:\n  " + "\n  ".join(problems))


_GENUINE_SESSION = boto3.session.Session


def _access_key_id(request_signer: Any) -> Optional[str]:
    """Access key id of the credentials a client signs with (None when unsigned/unknown)."""
    creds = getattr(request_signer, "_credentials", None)
    if creds is None:
        return None
    try:
        return creds.get_frozen_credentials().access_key
    except Exception:
        return getattr(creds, "access_key", None)


def _genuine_session_class() -> type:
    """The real ``boto3.session.Session`` even if another FakeAWS patched the module attribute."""
    base = _GENUINE_SESSION
    while getattr(base, "_fakeaws", None) is not None:
        base = base.__mro__[1]
    return base


def default_skip_modules() -> Tuple[str, ...]:
    """Call-wrapper modules skipped when labelling calls: the collector context and coverage.

    Read lazily from ``tests.support.targets`` (test code; the fake itself never imports production
    code), so the rename-proof module names live in one place.
    """
    from tests.support import targets  # local import: targets is test-only and import-cheap

    return (targets.COLLECTOR_BASE_MODULE, targets.COVERAGE_MODULE)


def _is_skipped(name: str, skip: Sequence[str]) -> bool:
    for entry in skip:
        if name == entry or name.startswith(entry + "."):
            return True
    return False


def _calling_module(skip: Sequence[str] = ()) -> str:
    """Dotted name of the innermost frame that issued the AWS call.

    Library frames (botocore, boto3 ...), this module and the ``skip`` wrapper modules are passed over.
    """
    f = sys._getframe(1)
    while f is not None:
        name = f.f_globals.get("__name__", "") or ""
        if name == __name__ or name.startswith(_SKIP_MODULE_PREFIXES) or _is_skipped(name, skip):
            f = f.f_back
            continue
        return name
    return "<unknown>"


def _encode_token(operation: str, offset: int) -> str:
    return f"fakeaws-{operation}-{offset}"


def _decode_token(token: Any, operation: str) -> int:
    if not token:
        return 0
    prefix = f"fakeaws-{operation}-"
    if isinstance(token, str) and token.startswith(prefix):
        try:
            return int(token[len(prefix):])
        except ValueError:
            pass
    raise UnhandledOperation(f"unknown pagination token {token!r} for {operation}")


_RESOURCE_PARAM_HINTS = (
    "Bucket", "UserName", "RoleName", "GroupName", "PolicyArn", "SecretId", "FunctionName", "KeyId",
    "name", "clusterName", "TopicArn", "QueueUrl", "repositoryName", "TableName", "ResourceArn",
    "DBSnapshotIdentifier", "SnapshotId", "IdentityPoolId", "HostedZoneId", "TargetGroupArn",
    "LoadBalancerArn", "restApiId", "ApiId", "Id", "Name", "WebACLArn", "taskDefinition",
    "NotebookInstanceName", "TrailName",
)


def _resource_hint(params: Mapping[str, Any]) -> Optional[str]:
    for key in _RESOURCE_PARAM_HINTS:
        value = params.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _short(params: Mapping[str, Any], limit: int = 200) -> str:
    text = json.dumps(params, default=str, sort_keys=True)
    return text if len(text) <= limit else text[:limit] + "..."


def botocore_error(name: str, **kwargs: Any) -> Callable[[], BaseException]:
    """Factory for a botocore exception by class name, e.g. ``botocore_error("EndpointConnectionError",
    endpoint_url="https://ec2.eu-west-1.amazonaws.com/")``."""
    cls = getattr(botocore.exceptions, name)
    return lambda: cls(**kwargs)


def load_world(spec: Union[str, World, Callable[[], World]]) -> World:
    """Accept a world object, a factory, or a dotted ``module:factory`` string."""
    if isinstance(spec, World):
        return spec
    if callable(spec):
        return spec()
    module_name, _, attr = spec.partition(":")
    import importlib
    module = importlib.import_module(module_name)
    return getattr(module, attr or "build_world")()


def iter_ops(calls: Iterable[Call]) -> List[str]:
    return sorted({c.op for c in calls})
