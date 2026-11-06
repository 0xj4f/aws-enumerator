"""Collector runtime: ``CollectContext``, ``ModuleOutput`` and the module runner
(contract: docs/contracts/collector-context.md).

Every collector is ``def collect(ctx) -> dict | None`` and makes every AWS call through
``ctx.call`` / ``ctx.paginate`` inside ``ctx.section(...)`` blocks, writing files with
``ctx.out.write``. Coverage is recorded as a side effect and written to
``<module dir>/_coverage.json`` by :func:`run_collector` (``protocol: "ctx"``).

The Wave 0/1 legacy adapter for the d13c215 ``collect(session, path)`` modules is gone (0.3.0, F-084/F-166):
a module whose ``collect`` does not take exactly ``ctx`` fails with a ``TypeError`` recorded in its coverage.
"""

from __future__ import annotations

import contextlib
import fnmatch
import importlib
import inspect
import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

from aws_enumerator.coverage import (
    DEFAULT_DENY_BREAKER,
    DEFAULT_THROTTLE_BREAKER,
    CallResult,
    Coverage,
    RunAborted,
    RunInterrupted,
    classify,
    error_code_of,
)
from aws_enumerator.registry import CollectorSpec, global_region_for
from aws_enumerator.util import fsio

__all__ = [
    "COVERAGE_FILE", "AwsProvider", "CollectContext", "ModuleOutput", "ModuleResult", "RunInfo", "RunAborted",
    "RunInterrupted", "SessionAwsProvider", "ShapeError", "is_ctx_protocol", "resolve_collect", "run_collector",
]

COVERAGE_FILE = "_coverage.json"
_MAX_PAGES = 10_000
_DEFAULT = object()


class ShapeError(ValueError):
    """``ModuleOutput.write`` refused data: wrong declared shape, or an error dict in place of data."""


# ── AWS access ───────────────────────────────────────────────────────────────
class AwsProvider:
    """What a context needs from the run's AWS layer (the runtime's ``AwsContext`` implements it).

    ``client(service, region)``: a cached botocore client from the run's single credential set
    (thread-safe after creation). Collectors never build sessions themselves (F-060, F-167).
    """

    def client(self, service: str, region: str) -> Any:  # pragma: no cover - protocol
        raise NotImplementedError


class SessionAwsProvider(AwsProvider):
    """Minimal provider over a ``session_factory(region) -> boto3.Session`` (tests and fixtures).

    Sessions are cached per region (:meth:`session`) and clients per (service, region); creation is locked.
    """

    def __init__(self, session_factory: Callable[[str], Any], *, client_config: Any = None):
        self._factory = session_factory
        self._config = client_config
        self._sessions: Dict[str, Any] = {}
        self._clients: Dict[Tuple[str, str], Any] = {}
        self._lock = threading.Lock()

    def session(self, region: str) -> Any:
        with self._lock:
            sess = self._sessions.get(region)
            if sess is None:
                sess = self._factory(region)
                self._sessions[region] = sess
            return sess

    def client(self, service: str, region: str) -> Any:
        sess = self.session(region)
        with self._lock:
            key = (service, region)
            cli = self._clients.get(key)
            if cli is None:
                kwargs = {"region_name": region}
                if self._config is not None:
                    kwargs["config"] = self._config
                cli = sess.client(service, **kwargs)
                self._clients[key] = cli
            return cli


@dataclass
class RunInfo:
    """Run-wide state shared by every context of one run.

    ``options`` holds parsed CLI options by name (``deny_breaker``, ``throttle_breaker``,
    collector tuning flags ...). Contexts read them with ``ctx.option(name, default)``.
    """

    run_id: str
    aws: AwsProvider
    options: Mapping[str, Any] = field(default_factory=dict)
    stop_event: threading.Event = field(default_factory=threading.Event)
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("aws_enumerator"))
    run_root: Optional[Path] = None

    @property
    def deny_breaker(self) -> int:
        return int(self.options.get("deny_breaker", DEFAULT_DENY_BREAKER))

    @property
    def throttle_breaker(self) -> int:
        return int(self.options.get("throttle_breaker", DEFAULT_THROTTLE_BREAKER))


# ── output ───────────────────────────────────────────────────────────────────
_ERROR_STUB_KEYS = frozenset({"Error", "error", "Scope", "Status", "name", "Name", "Id"})


def _is_error_stub(obj: Any) -> bool:
    if not isinstance(obj, Mapping) or not obj:
        return False
    keys = set(obj)
    has_err = any(isinstance(obj.get(k), str) for k in ("Error", "error"))
    return has_err and keys <= _ERROR_STUB_KEYS


class ModuleOutput:
    """Writer for one module directory (``<unit dir>/<spec.output_dir>``).

    * ``write(name, data)``: atomic ``0600`` JSON via :mod:`aws_enumerator.util.fsio`;
      ``name`` is relative (``"buckets.json"``, ``"policies/demo-bucket.json"``).
    * Stable shapes: a dict that is only an error marker (``{"Error": "..."}``) is refused
      at the top level and as a list item or map value; when ``SPEC.outputs`` declares a
      file as ``list``/``dict`` the data must have that type. Failures live in coverage.
    * Names whose first segment starts with ``_`` are reserved (``_coverage.json``).
    """

    def __init__(self, root: Union[str, Path], spec: Optional[CollectorSpec] = None):
        self.root = Path(root)
        self.spec = spec
        self.files: List[str] = []
        self._lock = threading.Lock()

    def ensure(self) -> Path:
        return fsio.ensure_dir(self.root)

    def path_for(self, name: str) -> Path:
        return fsio.safe_join(self.root, name)

    def _declared_kind(self, name: str) -> Optional[str]:
        if self.spec is None:
            return None
        for pattern, kind in self.spec.outputs:
            if name == pattern or fnmatch.fnmatchcase(name, pattern):
                return kind
        return None

    def write(self, name: str, data: Any, *, kind: Optional[str] = None) -> Path:
        parts = fsio.validate_relpath(name)
        if parts[0].startswith("_"):
            raise ShapeError(f"{name!r}: names starting with '_' are reserved for the runtime")
        expected = kind or self._declared_kind(name)
        if expected == "list" and not isinstance(data, list):
            raise ShapeError(f"{name!r} must be a list, got {type(data).__name__}")
        if expected == "dict" and not isinstance(data, dict):
            raise ShapeError(f"{name!r} must be an object, got {type(data).__name__}")
        if _is_error_stub(data):
            raise ShapeError(f"{name!r}: refusing to write an error object in place of data; record it in coverage")
        children = data if isinstance(data, list) else (list(data.values()) if isinstance(data, dict) else [])
        if any(_is_error_stub(c) for c in children):
            raise ShapeError(f"{name!r}: an item is an error object; use CollectionErrors / coverage instead")
        path = fsio.safe_join(self.root, name)
        fsio.ensure_dir(self.root)
        fsio.atomic_write_json(path, data)
        with self._lock:
            self.files.append(name)
        return path

    def write_item(self, subdir: str, key: str, data: Any, *, hint: Optional[str] = None) -> str:
        """Write one item to ``<subdir>/<slug(hint)>-<sha256(key)[:12]>.json`` (F-114); returns the name."""
        name = f"{subdir}/{fsio.hashed_filename(key, hint)}"
        self.write(name, data)
        return name

    def finalize(self, cov: Coverage) -> Path:
        """Write ``_coverage.json`` (always; the module directory is created if needed)."""
        fsio.ensure_dir(self.root)
        return fsio.atomic_write_json(self.root / COVERAGE_FILE, cov.to_json())


# ── context ──────────────────────────────────────────────────────────────────
_TOKEN_PAIRS: Tuple[Tuple[str, str], ...] = (
    ("NextToken", "NextToken"), ("nextToken", "nextToken"), ("NextMarker", "NextMarker"),
    ("Marker", "NextMarker"), ("Marker", "Marker"), ("ContinuationToken", "NextContinuationToken"),
    ("PaginationToken", "PaginationToken"), ("NextPageToken", "NextPageToken"), ("position", "position"),
)
_LIMIT_KEYS: Tuple[str, ...] = ("MaxResults", "maxResults", "Limit", "limit", "MaxItems", "PageSize",
                                "MaxRecords", "maxItems")


def _dig(obj: Any, dotted: str) -> Any:
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, Mapping):
            return None
        cur = cur.get(part)
    return cur


def _op_names(client: Any, op: str) -> Tuple[str, str, str]:
    """``(method_name, OperationName, "service:OperationName")`` for ``op`` in either spelling."""
    meta = client.meta
    if op[:1].isupper():
        operation = op
        from botocore import xform_name
        method = xform_name(op)
    else:
        method = op
        operation = meta.method_to_api_mapping.get(op)
        if operation is None:
            raise AttributeError(f"{meta.service_model.service_name} client has no operation {op!r}")
    return method, operation, f"{meta.service_model.service_name}:{operation}"


def _short(exc: BaseException) -> Optional[str]:
    if error_code_of(exc) is not None:
        return None
    text = str(exc).replace("\n", " ").strip()
    return text[:200] or None


class CollectContext:
    """Everything one collector needs for one run unit.

    :param spec: the module's ``CollectorSpec``.
    :param region: ``"global"`` for the global unit, else the region name.
    :param client_region: region for clients (the partition's global region for ``"global"``).
    :param account_id: target account (12 digits).
    :param partition: ``aws`` / ``aws-us-gov`` / ``aws-cn`` / ...
    :param run: :class:`RunInfo` (run id, options, stop event, AWS provider).
    :param out: :class:`ModuleOutput` for ``<unit dir>/<spec.output_dir>``.
    :param cov: :class:`~aws_enumerator.coverage.Coverage` for this module and unit.
    :param deps: return values of modules this one depends on, in memory (``deps["eks"]``).
    """

    def __init__(self, spec: CollectorSpec, region: str, client_region: str, account_id: str, partition: str,
                 run: RunInfo, out: ModuleOutput, cov: Coverage, deps: Optional[Mapping[str, Any]] = None):
        self.spec = spec
        self.region = region
        self.client_region = client_region
        self.account_id = account_id
        self.partition = partition
        self.run = run
        self.out = out
        self.cov = cov
        self.deps: Mapping[str, Any] = dict(deps or {})
        base = logging.getLogger(f"aws_enumerator.collect.{spec.name}")
        self.log = logging.LoggerAdapter(base, {"collector": spec.name, "region": region})
        self._not_configured = spec.not_configured_map()

    @classmethod
    def create(cls, spec: CollectorSpec, *, region: str, account_id: str, partition: str, run: RunInfo,
               unit_dir: Union[str, Path], client_region: Optional[str] = None,
               deps: Optional[Mapping[str, Any]] = None) -> "CollectContext":
        """Build a context with a fresh :class:`Coverage` and :class:`ModuleOutput` for ``unit_dir``."""
        if client_region is None:
            client_region = global_region_for(partition) if region == "global" else region
        cov = Coverage(spec.name, region, spec.services, deny_breaker=run.deny_breaker,
                       throttle_breaker=run.throttle_breaker,
                       logger=logging.getLogger(f"aws_enumerator.collect.{spec.name}"))
        out = ModuleOutput(Path(unit_dir) / spec.output_dir, spec)
        return cls(spec, region, client_region, account_id, partition, run, out, cov, deps)

    # basics ------------------------------------------------------------------
    @property
    def is_global(self) -> bool:
        return self.region == "global"

    @property
    def unit_dir(self) -> Path:
        return self.out.root.parent

    def option(self, name: str, default: Any = None) -> Any:
        return self.run.options.get(name, default)

    def client(self, service: str, region: Optional[str] = None) -> Any:
        """A client from the run's single credential set (never a rebuilt session; F-060, F-167)."""
        return self.run.aws.client(service, region or self.client_region)

    def arn(self, service: str, resource: str, region: Any = _DEFAULT, account: Any = _DEFAULT) -> str:
        """Partition-aware ARN (F-119): ``arn:{partition}:{service}:{region}:{account}:{resource}``.

        ``region`` defaults to ``""`` in the global unit, else ``ctx.region``; ``account``
        defaults to ``ctx.account_id``. Pass ``""`` explicitly to leave a field empty
        (``ctx.arn("s3", bucket, region="", account="")``).
        """
        if region is _DEFAULT:
            region = "" if self.is_global else self.region
        if account is _DEFAULT:
            account = self.account_id
        return f"arn:{self.partition}:{service}:{region or ''}:{account or ''}:{resource}"

    def check_stop(self) -> None:
        """Raise :class:`RunInterrupted` once the run's stop event is set."""
        if self.run.stop_event.is_set():
            raise RunInterrupted(f"{self.spec.name}/{self.region}: stop requested")

    @contextlib.contextmanager
    def section(self, name: str) -> Iterator[None]:
        """Isolate one phase: an ``Exception`` is recorded in coverage (module becomes
        ``partial``) and swallowed so later sections still run (F-053, F-103). Data written
        before the failure stays. ``RunInterrupted``/``RunAborted`` propagate."""
        entry = self.cov.section_started(name)
        try:
            yield
        except RunInterrupted:
            self.cov.section_interrupted(entry)
            raise
        except Exception as exc:
            self.cov.section_error(entry, exc)
            self.log.warning("section %r failed: %s%s", name, type(exc).__name__,
                             f" ({error_code_of(exc)})" if error_code_of(exc) else "",
                             exc_info=self.log.isEnabledFor(logging.DEBUG))

    # calls -------------------------------------------------------------------
    def _failure(self, api: str, exc: Exception, *, item: Optional[str], primary: bool, optional: bool,
                 value: Any = None, pages: int = 0, items: Optional[int] = None) -> CallResult:
        status, code, fatal = classify(exc, api, self._not_configured)
        result = CallResult(api=api, status=status, value=value, error_code=code, not_configured=status == "ok",
                            pages=pages, items=items, item=item, primary=primary, optional=optional,
                            message=_short(exc), exception=exc)
        self.cov.record(result)
        if fatal:
            self.log.error("%s failed with %s: credentials expired or invalid; aborting the run", api, code)
            raise RunAborted(f"{api}: {code}: credentials expired or invalid", api=api, code=code) from exc
        if status == "ok":
            self.log.debug("%s: not configured (%s)%s", api, code, f" for {item}" if item else "")
        elif item is not None or optional:
            self.log.debug("%s %s (%s)%s", api, status, code, f" for {item}" if item else "")
        else:
            self.log.warning("%s %s (%s)", api, status, code)
        return result

    def call(self, client: Any, op: str, *, item: Optional[str] = None, primary: bool = False,
             optional: bool = False, **params: Any) -> CallResult:
        """One API call. Never raises for AWS/botocore errors: returns a :class:`CallResult`.

        ``op`` is the method (``"get_bucket_policy"``) or operation (``"GetBucketPolicy"``) name.
        ``item`` marks a fan-out call for one resource (deny breaker, ``item_errors``);
        ``primary`` marks the call whose denial means the module is ``denied``;
        ``optional`` calls never degrade the module status.
        """
        self.check_stop()
        method, _operation, api = _op_names(client, op)
        skipped = self.cov.circuit_skip(api, item=item, primary=primary, optional=optional)
        if skipped is not None:
            return skipped
        try:
            response = getattr(client, method)(**params)
        except Exception as exc:
            return self._failure(api, exc, item=item, primary=primary, optional=optional)
        if isinstance(response, dict):
            response.pop("ResponseMetadata", None)
        return self.cov.record(CallResult(api=api, status="ok", value=response, pages=1, item=item,
                                          primary=primary, optional=optional))

    def _pages(self, client: Any, method: str, operation: str, page_size: Optional[int],
               params: Mapping[str, Any]) -> Iterator[Mapping[str, Any]]:
        if client.can_paginate(method):
            paginator = client.get_paginator(method)
            kwargs = dict(params)
            cfg = getattr(paginator, "_pagination_cfg", None) or {}
            if page_size and cfg.get("limit_key"):
                kwargs["PaginationConfig"] = {"PageSize": page_size}
            yield from paginator.paginate(**kwargs)
            return
        op_model = client.meta.service_model.operation_model(operation)
        in_members = op_model.input_shape.members if op_model.input_shape is not None else {}
        out_members = op_model.output_shape.members if op_model.output_shape is not None else {}
        pair = next(((i, o) for i, o in _TOKEN_PAIRS if i in in_members and o in out_members), None)
        limit_key = next((k for k in _LIMIT_KEYS if k in in_members), None)
        request = dict(params)
        if page_size and limit_key and limit_key not in request:
            request[limit_key] = page_size
        seen = set()
        for _ in range(_MAX_PAGES):
            page = getattr(client, method)(**request)
            yield page
            if pair is None:
                return
            if page.get("IsTruncated") is False or page.get("Truncated") is False:
                return
            token = page.get(pair[1])
            if not token:
                return
            marker = token if isinstance(token, (str, int)) else repr(token)
            if marker in seen:
                return
            seen.add(marker)
            request[pair[0]] = token

    def paginate(self, client: Any, op: str, result_key: Union[str, Sequence[str]], *,
                 page_size: Optional[int] = None, item: Optional[str] = None, primary: bool = False,
                 optional: bool = False, **params: Any) -> CallResult:
        """All pages of ``op``. Uses the botocore paginator when one exists, else a token loop
        detected from the operation model (``NextToken``, ``NextMarker``, ``Marker`` ...).

        ``result_key`` is a (dotted) key such as ``"Buckets"`` or ``"DistributionList.Items"``;
        with several keys the value is ``{key: [...]}``. The value is always a list (or dict of
        lists), holding whatever was collected before a failure; check ``.status``.
        """
        self.check_stop()
        method, operation, api = _op_names(client, op)
        keys = (result_key,) if isinstance(result_key, str) else tuple(result_key)
        collected: Dict[str, List[Any]] = {k: [] for k in keys}

        def value() -> Any:
            return collected[keys[0]] if len(keys) == 1 else collected

        def count() -> int:
            return sum(len(v) for v in collected.values())

        skipped = self.cov.circuit_skip(api, item=item, primary=primary, optional=optional)
        if skipped is not None:
            skipped.value, skipped.items = value(), 0
            return skipped
        pages = 0
        try:
            for page in self._pages(client, method, operation, page_size, params):
                pages += 1
                for k in keys:
                    got = _dig(page, k)
                    if isinstance(got, list):
                        collected[k].extend(got)
                    elif got is not None:
                        collected[k].append(got)
                self.check_stop()
        except Exception as exc:
            return self._failure(api, exc, item=item, primary=primary, optional=optional, value=value(),
                                 pages=pages, items=count())
        return self.cov.record(CallResult(api=api, status="ok", value=value(), pages=pages, items=count(),
                                          item=item, primary=primary, optional=optional))


# ── dispatch ─────────────────────────────────────────────────────────────────
def is_ctx_protocol(fn: Callable[..., Any]) -> bool:
    """True for ``def collect(ctx)`` (one required positional parameter named ``ctx``)."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return False
    positional = [p for p in sig.parameters.values()
                  if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)]
    required = [p for p in positional if p.default is inspect.Parameter.empty]
    return bool(positional) and positional[0].name == "ctx" and len(required) == 1


def resolve_collect(spec: CollectorSpec) -> Callable[..., Any]:
    """The module's ``collect`` function, looked up at call time (tests may monkeypatch it).

    Use specs from :func:`aws_enumerator.registry.get_registry` (the registry fills ``module``;
    a module-level ``SPEC`` read directly leaves it empty).
    """
    if not spec.module:
        raise ValueError(f"spec {spec.name!r} has no module; take it from registry.get_registry()")
    module = importlib.import_module(spec.module)
    return module.collect


# ── module runner ────────────────────────────────────────────────────────────
@dataclass
class ModuleResult:
    """What the runner records for one module in one unit (one ``manifest.modules[]`` entry).

    ``control`` holds a :class:`RunInterrupted` / :class:`RunAborted` caught while running the
    module; the runner records the result first and then calls :meth:`reraise`.
    """

    name: str
    scope: str
    region: str
    status: str
    status_reason: Optional[str] = None
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    error: Optional[Dict[str, Any]] = None
    coverage: Optional[Dict[str, int]] = None
    denied_apis: List[str] = field(default_factory=list)
    throttle_events: int = 0
    dir: Optional[str] = None
    protocol: Optional[str] = None
    resumed: bool = False
    value: Any = field(default=None, repr=False)
    control: Optional[BaseException] = field(default=None, repr=False)

    @classmethod
    def skipped(cls, spec: CollectorSpec, region: str, reason: str, *, status: str = "skipped") -> "ModuleResult":
        """A module that was not run (``skipped`` by selection/partition, or ``not_run``)."""
        if status not in ("skipped", "not_run"):
            raise ValueError("status must be 'skipped' or 'not_run'")
        return cls(name=spec.name, scope=spec.scope, region=region, status=status, status_reason=reason)

    def manifest_entry(self) -> Dict[str, Any]:
        return {
            "name": self.name, "scope": self.scope, "region": self.region, "status": self.status,
            "status_reason": self.status_reason, "started_at": self.started_at, "ended_at": self.ended_at,
            "duration_seconds": self.duration_seconds, "error": self.error, "coverage": self.coverage,
            "throttle_events": self.throttle_events, "resumed": self.resumed, "dir": self.dir,
        }

    def reraise(self) -> None:
        if self.control is not None:
            raise self.control


def run_collector(ctx: CollectContext, *, collect_fn: Optional[Callable[..., Any]] = None) -> ModuleResult:
    """Run one module in one unit and always write its ``_coverage.json``.

    Calls the module's ``collect(ctx)``; a ``collect`` with any other signature is a ``TypeError``
    (status ``failed``): the d13c215 ``collect(session, path)`` protocol is no longer supported.
    Unhandled ``Exception`` -> status ``failed``; :class:`RunInterrupted` -> ``interrupted``;
    :class:`RunAborted` -> ``failed`` (both returned in ``result.control``). Other
    ``BaseException`` s (``KeyboardInterrupt``, test-harness errors) propagate after the
    coverage file is written.
    """
    spec, cov = ctx.spec, ctx.cov
    if spec.planned:
        cov.mark_skipped("not implemented in this version")
        return _result(ctx, None, None)
    cov.start()
    value: Any = None
    control: Optional[BaseException] = None
    try:
        fn = collect_fn or resolve_collect(spec)
        if not is_ctx_protocol(fn):
            raise TypeError(f"{spec.name}: collect() must take exactly one parameter named 'ctx' "
                            f"(collector-context.md §2)")
        cov.protocol = "ctx"
        value = fn(ctx)
    except RunInterrupted as exc:
        cov.mark_interrupted()
        control = exc
        ctx.log.warning("interrupted")
    except RunAborted as exc:
        cov.mark_failed(exc)
        control = exc
    except Exception as exc:
        cov.mark_failed(exc)
        ctx.log.error("module failed: %s%s", type(exc).__name__,
                      f" ({error_code_of(exc)})" if error_code_of(exc) else "",
                      exc_info=ctx.log.isEnabledFor(logging.DEBUG))
    finally:
        cov.finish()
        try:
            ctx.out.finalize(cov)
        except OSError as exc:
            ctx.log.error("cannot write %s: %s", COVERAGE_FILE, exc)
    return _result(ctx, value, control)


def _result(ctx: CollectContext, value: Any, control: Optional[BaseException]) -> ModuleResult:
    cov = ctx.cov
    rel: Optional[str]
    if cov.status in ("skipped", "not_run"):
        rel = None
    elif ctx.run.run_root is not None:
        try:
            rel = ctx.out.root.resolve().relative_to(Path(ctx.run.run_root).resolve()).as_posix()
        except ValueError:
            rel = f"{ctx.region}/{ctx.spec.output_dir}"
    else:
        rel = f"{ctx.region}/{ctx.spec.output_dir}"
    doc_error = cov.to_json()["error"]
    return ModuleResult(
        name=ctx.spec.name, scope=ctx.spec.scope, region=ctx.region, status=cov.status,
        status_reason=cov.status_reason, started_at=cov.started_at, ended_at=cov.ended_at,
        duration_seconds=cov.duration_seconds, error=doc_error, coverage=cov.summary(),
        denied_apis=cov.denied_apis(), throttle_events=cov.throttle_events, dir=rel, protocol=cov.protocol,
        value=value, control=control,
    )
