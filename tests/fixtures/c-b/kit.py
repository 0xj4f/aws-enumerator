"""Shared helpers for the C-B collector tests (``tests/python/collectors/test_<collector>*.py``).

The directory name has a hyphen (ownership.md §1 rule 3), so test modules import this file with
``importlib.import_module("tests.fixtures.c-b.kit")``.

Every helper runs one registry module through ``collectors.base.run_collector`` against the routed
fake AWS (``tests/support/fakeaws.py``) and the ``acme`` world, **strict** by default: an operation the
world does not model aborts the test, so a collector can never call an API the tests did not see.

Contract checks (dashboard-docs-tests.md §C6, collector-context.md §8):

* :func:`assert_contract` - ``_coverage.json`` validates against ``coverage-1.schema.json``, no data
  file holds an ``{"Error": ...}`` object (coverage-schema.md §1), declared output shapes hold;
* :func:`assert_declared_and_read_only` - every recorded operation is read-only and maps to an IAM
  action in ``SPEC.actions`` / ``optional_actions`` / ``resource_scoped`` (F-151);
* :func:`assert_each_api_denied_is_survivable` - each API the happy run used, denied in turn, never
  crashes the module, is recorded as denied (or breaker-skipped) and keeps stable shapes (F-059, F-103);
* :func:`assert_no_canaries` - secret canaries planted in ``acme`` never reach a file.
"""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

import jsonschema

from tests.fixtures.regressions import support as S
from tests.fixtures.worlds import acme
from tests.support import targets
from tests.support.fakeaws import READ_ONLY_OPERATIONS, READ_ONLY_PREFIXES, FakeAWS, World

W1, W2, G = "eu-west-1", "eu-west-2", acme.GLOBAL_REGION
#: A region acme does not model: every regional handler answers with empty data.
EMPTY_REGION = "us-west-2"
ACCT = acme.ACCOUNT_ID
EXT = acme.EXTERNAL_ACCOUNT_ID

_SCHEMA = json.loads((targets.schema_path("coverage-1.schema.json")).read_text())
COVERAGE_VALIDATOR = jsonschema.Draft202012Validator(_SCHEMA)
_ERROR_STUB_KEYS = frozenset({"Error", "error", "Scope", "Status", "name", "Name", "Id"})

#: boto3 service name -> IAM service prefix where they differ (collectors-cli.md §6).
_IAM_PREFIX = {"elbv2": "elasticloadbalancing", "elb": "elasticloadbalancing"}


def registry() -> Any:
    return targets.registry_module().get_registry()


def spec(name: str) -> Any:
    return registry().get(name)


def world() -> World:
    """A fresh acme world (handlers + acme's injections)."""
    return acme.build_world()


def clean_world(*services: str) -> World:
    """acme without the injected errors of ``services`` (all services when none is given)."""
    w = acme.build_world()
    if services:
        for svc in services:
            w.clear_errors(svc)
    else:
        w.errors = []
    return w


def run(name: str, tmp_path: Path, w: Optional[World] = None, *, region: str = W2,
        options: Optional[Mapping[str, Any]] = None, strict: bool = True,
        fake: Optional[FakeAWS] = None) -> Any:
    """Run registry module ``name`` once (``S.ModuleRun``: ``result``, ``fake``, ``out``, ``unit_dir``)."""
    return S.run_module(name, w if w is not None else world(), Path(tmp_path), region=region,
                        options=options, strict=strict, fake=fake)


# ── reading the output ───────────────────────────────────────────────────────
def data_files(r: Any) -> Dict[str, Any]:
    """``{relative path: parsed JSON}`` for every data file (``_coverage.json`` excluded)."""
    out = {}
    for path in S.files_under(r.out):
        rel = path.relative_to(r.out).as_posix()
        if rel != "_coverage.json":
            out[rel] = json.loads(path.read_text(encoding="utf-8"))
    return out


def walk(obj: Any) -> Iterator[Any]:
    yield obj
    if isinstance(obj, Mapping):
        for v in obj.values():
            yield from walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v)


def coverage(r: Any) -> Dict[str, Any]:
    return r.coverage()


def calls(r: Any, api: str) -> List[Dict[str, Any]]:
    """The ``_coverage.json`` rows of one api (``"sqs:GetQueueAttributes"``)."""
    return [row for row in coverage(r).get("calls", []) if row["api"] == api]


def operations(r: Any) -> List[Tuple[str, str]]:
    """Sorted unique ``(service, Operation)`` pairs the module sent to the fake."""
    return sorted({(c.service, c.operation) for c in r.fake.calls_for()})


def by(items: Iterable[Mapping[str, Any]], key: str) -> Dict[Any, Mapping[str, Any]]:
    return {i.get(key): i for i in items if isinstance(i, Mapping)}


# ── contract assertions ──────────────────────────────────────────────────────
def iam_action(service: str, operation: str) -> str:
    """The IAM action that authorises ``service:operation`` (collectors-cli.md §6 mapping)."""
    if service in ("apigateway", "apigatewayv2"):
        return "apigateway:GET"
    return f"{_IAM_PREFIX.get(service, service)}:{operation}"


def is_error_stub(obj: Any) -> bool:
    if not isinstance(obj, Mapping) or not obj:
        return False
    return any(isinstance(obj.get(k), str) for k in ("Error", "error")) and set(obj) <= _ERROR_STUB_KEYS


def assert_contract(r: Any, *, statuses: Sequence[str] = ("ok",)) -> Dict[str, Any]:
    """Status, schema-valid coverage, no error objects anywhere, declared shapes. Returns the coverage."""
    doc = coverage(r)
    assert r.result.status in statuses, (r.result.status, r.result.status_reason, r.result.error)
    errors = sorted(COVERAGE_VALIDATOR.iter_errors(doc), key=lambda e: list(e.path))
    assert not errors, [f"{list(e.path)}: {e.message}" for e in errors]
    assert doc["protocol"] == "ctx", doc["protocol"]
    files = data_files(r)
    for rel, data in files.items():
        stubs = [o for o in walk(data) if is_error_stub(o)]
        assert not stubs, (rel, stubs[:3])
        if isinstance(data, Mapping):
            assert "Error" not in data, rel
    for pattern, kind in spec(r.result.name).outputs:
        for rel, data in files.items():
            if rel == pattern or fnmatch.fnmatchcase(rel, pattern):
                assert isinstance(data, list if kind == "list" else dict), (rel, kind)
    return doc


def declared_actions(name: str) -> set:
    s = spec(name)
    return set(s.actions) | set(s.optional_actions) | {a for a, _ in s.resource_scoped}


def assert_declared_and_read_only(r: Any) -> None:
    """F-151: every operation is read-only and covered by the module's declared IAM actions."""
    declared = declared_actions(r.result.name)
    for service, operation in operations(r):
        assert operation.startswith(READ_ONLY_PREFIXES) or f"{service}:{operation}" in READ_ONLY_OPERATIONS, \
            f"{service}:{operation} is not read-only"
        assert iam_action(service, operation) in declared, \
            f"{service}:{operation} -> {iam_action(service, operation)} not in SPEC actions {sorted(declared)}"


def assert_no_canaries(r: Any, *names: str) -> None:
    """None of acme's ``CANARIES[name]`` (all canaries when no name is given) is in any output file."""
    wanted = names or tuple(acme.CANARIES)
    for name in wanted:
        hits = S.grep_tree(acme.CANARIES[name], r.out)
        assert hits == [], (name, hits)
    hits = S.grep_tree(acme.CANARY, r.out)
    assert names or hits == [], hits


def assert_each_api_denied_is_survivable(name: str, tmp_path: Path, *, region: str = W2,
                                         base: Callable[[], World] = world,
                                         options: Optional[Mapping[str, Any]] = None) -> List[str]:
    """Deny every API of the happy run in turn: no crash, recorded, stable shapes. Returns the APIs."""
    happy = run(name, tmp_path / "happy", base(), region=region, options=options)
    apis = [f"{s}:{o}" for s, o in operations(happy)]
    assert apis, "the happy run made no call"
    for n, (service, operation) in enumerate(operations(happy)):
        w = base()
        w.deny(service, operation)
        r = run(name, tmp_path / f"deny{n}", w, region=region, options=options)
        doc = assert_contract(r, statuses=("ok", "partial", "denied"))
        api = f"{service}:{operation}"
        rows = [row for row in doc["calls"] if row["api"] == api]
        assert any(row["status"] in ("denied", "skipped") for row in rows), (api, rows)
        for rel in S.files_under(r.out):
            json.loads(rel.read_text(encoding="utf-8"))
    return apis


def collection_errors(item: Mapping[str, Any]) -> List[Tuple[str, str]]:
    return [(e["api"], e["status"]) for e in item.get("CollectionErrors") or []]


def sorted_by(items: Sequence[Mapping[str, Any]], key: str) -> bool:
    values = [i.get(key) for i in items]
    return values == sorted(values, key=lambda v: (v is None, str(v)))
