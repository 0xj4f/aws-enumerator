"""Helpers shared by ``tests/python/regressions/test_*.py`` (stream regressions-py).

The regression tests describe the CORRECT behaviour for verified findings and are marked
``xfail(strict=True)`` until the stream that owns the fix lands it. They reach production code only
through :mod:`tests.support.targets` (package name, legacy engine, collectors, CLI) and the frozen
contracts in ``docs/contracts/``.

Entry points, in order of preference:

* **Analysis of a legacy-layout tree** (:func:`analyze_tree`): ``engine.analyze_report(<dir>)`` once it
  exists (engine-api.md §3.2, legacy-single / legacy-all), otherwise the legacy ``analyze()`` the
  baseline ships. Both write ``<dir>/analysis/`` with the per-domain legacy files, so symptom tests
  read the same files before and after the engine rewrite.
* **graph.json** (:func:`analyze_graph`, :func:`analyze_run_graph`): the contract API
  (``analyze_report`` / ``analyze_run``). Tests that need it say "requires <API>" in their xfail reason.
* **Collectors** (:func:`run_module`): ``collectors.base.run_collector`` with a ``CollectContext``
  (collector-context.md §5); it runs old-style ``collect(session, path)`` modules through the legacy
  adapter and new ``collect(ctx)`` modules directly, so the same test survives the migration.
* **CLI** (:func:`run_cli`): ``tests.python.collectors.legacy_harness.run_legacy_main`` with
  ``$AWS_ENUMERATOR_OUTPUT`` pointing into ``tmp_path``; finders look in both the legacy
  ``./reports/<date>/`` tree and the v2 output root, so assertions are layout-agnostic.

Rules every helper follows: placeholder accounts only (123456789012, 111122223333, 999999999999),
``demo-*`` names, no network, nothing outside ``tmp_path``.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import io
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

from tests.support import ref_paths, targets
from tests.support import report_builder as rb

ACCT = rb.ACCT_MAIN            # 123456789012
ACCT_EXT = rb.ACCT_EXT         # 999999999999
REGION = "eu-west-2"
OTHER_REGION = "eu-west-1"
RUN_ID = "20261015T101500Z-a1b2c3"
SOURCE_DATE_EPOCH = "1767225600"  # 2026-01-01T00:00:00Z


# ── production modules (through targets) ─────────────────────────────────────
def package_module(name: str) -> ModuleType:
    """``<package>.<name>`` (the package name comes from targets.py)."""
    return importlib.import_module(f"{targets.PACKAGE_NAME}.{name}")


def engine_package() -> ModuleType:
    return package_module("engine")


def engine_api(name: str) -> Callable[..., Any]:
    """A public engine entry point (engine-api.md §1). ``AttributeError`` until it exists."""
    return getattr(engine_package(), name)


def collector_base() -> ModuleType:
    return package_module("collectors.base")


def registry_module() -> ModuleType:
    return package_module("registry")


def schema_path(name: str) -> Path:
    """Runtime schemas live in ``<package>/schemas``, engine schemas in ``<package>/engine/schema``."""
    runtime = targets.PACKAGE_DIR / "schemas" / name
    return runtime if runtime.exists() else ref_paths.engine_schema_dir() / name


# ── generic matching ─────────────────────────────────────────────────────────
def refers(value: Any, name: str) -> bool:
    """True when ``value`` names ``name`` exactly or as its last ``/`` or ``:`` segment.

    Tolerates both the legacy renderings (``i-0abc``, ``bucket:demo``, ``lambda:arn:...:function:fn``)
    and ARN node ids (``arn:aws:ec2:...:instance/i-0abc``).
    """
    if not isinstance(value, str) or not name:
        return False
    return value == name or value.endswith("/" + name) or value.endswith(":" + name)


def walk_strings(obj: Any) -> Iterator[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, Mapping):
        for k, v in obj.items():
            yield str(k)
            yield from walk_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from walk_strings(v)


def files_under(*roots: Path) -> List[Path]:
    out: List[Path] = []
    for root in roots:
        root = Path(root)
        if root.is_dir():
            out.extend(p for p in sorted(root.rglob("*")) if p.is_file())
    return out


def grep_tree(needle: str, *roots: Path) -> List[str]:
    """Files under ``roots`` whose bytes contain ``needle`` (relative-ish paths for messages)."""
    hits = []
    raw = needle.encode("utf-8")
    for p in files_under(*roots):
        try:
            if raw in p.read_bytes():
                hits.append(str(p))
        except OSError:
            continue
    return hits


def load_json(path: Path, default: Any = None) -> Any:
    path = Path(path)
    if not path.is_file():
        return default
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ── scenario trees with contract-valid resource ids ──────────────────────────
_RESOURCE_ID = re.compile(r"\b(i|sg|subnet|vpc|snap|ami)-([0-9a-z]{6,})\b")


def _hex_id(match: "re.Match[str]") -> str:
    prefix, suffix = match.group(1), match.group(2)
    if re.fullmatch(r"[0-9a-f]+", suffix):
        return match.group(0)
    return f"{prefix}-{hashlib.sha1(match.group(0).encode()).hexdigest()[:17]}"


def build_scenario(name: str, root: Path) -> Path:
    """Build report_builder scenario ``name`` into ``root`` with EC2-family ids made hexadecimal.

    Some scenarios use readable ids such as ``i-0a1b2c3dweb00001``; node-ids.md requires the AWS form
    (``i-[0-9a-f]+``), so a v2 engine may refuse them. The rewrite is deterministic and consistent across
    files; already-valid ids are untouched (request regressions-py-1 asks for the fix at the source).
    """
    rb.build(name, Path(root))
    for path in sorted(Path(root).rglob("*.json")):
        text = path.read_text(encoding="utf-8")
        fixed = _RESOURCE_ID.sub(_hex_id, text)
        if fixed != text:
            path.write_text(fixed, encoding="utf-8")
    return Path(root)


# ── analysis of legacy-layout trees ──────────────────────────────────────────
TRUST_FILE = "trust_relationships.json"


@dataclass
class Analysis:
    """The ``analysis/`` directory one analysis run wrote (legacy file names)."""

    dir: Path
    result: Any = None

    def load(self, name: str, default: Any = None) -> Any:
        return load_json(self.dir / name, default)

    def findings(self) -> List[Dict[str, Any]]:
        doc = self.load("findings.json", {}) or {}
        return list(doc.get("findings", [])) if isinstance(doc, Mapping) else []

    def summary(self) -> Dict[str, Any]:
        return self.load("summary.json", {}) or {}

    def relationship_files(self) -> List[str]:
        if not self.dir.is_dir():
            return []
        return sorted(p.name for p in self.dir.iterdir()
                      if p.name.endswith("_relationships.json") and p.name != TRUST_FILE)

    def edges(self, *names: str) -> List[Dict[str, Any]]:
        """Edges of the named ``<domain>_relationships.json`` files (all of them when none is named)."""
        files = [n if n.endswith(".json") else f"{n}_relationships.json" for n in names] or self.relationship_files()
        out: List[Dict[str, Any]] = []
        for name in files:
            doc = self.load(name, {}) or {}
            if isinstance(doc, Mapping):
                out.extend(e for e in doc.get("edges", []) if isinstance(e, Mapping))
        return out

    def trust(self) -> List[Dict[str, Any]]:
        doc = self.load(TRUST_FILE, []) or []
        if isinstance(doc, Mapping):
            doc = doc.get("relationships") or doc.get("edges") or []
        return [t for t in doc if isinstance(t, Mapping)]

    def graph(self) -> Dict[str, Any]:
        with open(self.dir / "graph.json", encoding="utf-8") as fh:
            return json.load(fh)


def analyze_tree(report_dir: Path) -> Analysis:
    """Analyse a legacy-layout tree through the product's current entry point.

    ``report_dir`` is a single-region directory (it holds ``iam/``) or the account directory of an old
    ``--all`` tree (it holds ``global/``). With ``engine.analyze_report`` (engine-api.md §3.2) the whole
    directory is analysed; with the baseline ``analyze()`` the single-region directory or ``global/``.
    Console output is discarded.
    """
    report_dir = Path(report_dir)
    analyze_report = getattr(engine_package(), "analyze_report", None)
    with contextlib.redirect_stdout(io.StringIO()):
        if analyze_report is not None:
            result = analyze_report(str(report_dir))
            out = getattr(result, "analysis_dir", None) or (report_dir / "analysis")
            return Analysis(Path(out), result)
        target = report_dir / "global" if (report_dir / "global").is_dir() else report_dir
        targets.engine_analyze()(str(target))
        return Analysis(target / "analysis", None)


def analyze_graph(report_dir: Path) -> Dict[str, Any]:
    """``analyze_report(<legacy dir>)`` and its ``graph.json`` (requires the contract API)."""
    report_dir = Path(report_dir)
    analyze_report = engine_api("analyze_report")
    with contextlib.redirect_stdout(io.StringIO()):
        result = analyze_report(str(report_dir))
    out = Path(getattr(result, "analysis_dir", None) or report_dir / "analysis")
    return load_json(out / "graph.json")


def analyze_run_graph(run_root: Path, regions: Sequence[str], **kw: Any) -> Tuple[Any, Dict[str, Any]]:
    """``analyze_run(run_root, regions=...)`` (engine-api.md §3.1) and its graph.json."""
    analyze_run = engine_api("analyze_run")
    with contextlib.redirect_stdout(io.StringIO()):
        result = analyze_run(str(run_root), regions=list(regions), **kw)
    out = Path(getattr(result, "analysis_dir", None) or Path(run_root) / "analysis")
    return result, load_json(out / "graph.json")


class _ReversedScandir:
    """``os.scandir`` stand-in: same entries, reverse order, usable as an iterator and a context manager."""

    def __init__(self, entries: List[Any]):
        self._it = iter(list(reversed(entries)))

    def __iter__(self) -> "_ReversedScandir":
        return self

    def __next__(self) -> Any:
        return next(self._it)

    def __enter__(self) -> "_ReversedScandir":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        self._it = iter(())


def with_listdir_reversed(fn: Callable[[], Any]) -> Any:
    """Run ``fn`` while directory listings come back in reverse order (F-162).

    Patches ``os.listdir`` and ``os.scandir`` (``os.walk`` and ``glob`` use the latter) and, on Python 3.10,
    ``pathlib._NormalAccessor`` (which bound the originals at import time, so ``Path.iterdir`` is covered too).
    """
    import pathlib

    real_listdir, real_scandir = os.listdir, os.scandir

    def reversed_listdir(path: Any = ".") -> List[str]:
        return list(reversed(real_listdir(path)))

    def reversed_scandir(path: Any = ".") -> _ReversedScandir:
        with real_scandir(path) as it:
            return _ReversedScandir(list(it))

    accessor = getattr(pathlib, "_NormalAccessor", None)
    saved = {name: accessor.__dict__[name] for name in ("listdir", "scandir")
             if accessor is not None and name in accessor.__dict__}
    os.listdir, os.scandir = reversed_listdir, reversed_scandir
    for name, impl in (("listdir", reversed_listdir), ("scandir", reversed_scandir)):
        if name in saved:
            setattr(accessor, name, staticmethod(impl))
    try:
        return fn()
    finally:
        os.listdir, os.scandir = real_listdir, real_scandir
        for name, original in saved.items():
            setattr(accessor, name, original)


# ── findings and edges (legacy files) ────────────────────────────────────────
def finding_ids(f: Mapping[str, Any]) -> set:
    ids = {f.get("id")}
    ids.update(f.get("legacy_ids") or [])
    return {i for i in ids if i}


def finding_subjects(f: Mapping[str, Any]) -> List[str]:
    out = [f.get(k) for k in ("node_id", "entity_arn", "entity", "resource")]
    return [s for s in out if isinstance(s, str)]


def findings_for(findings: Iterable[Mapping[str, Any]], fid: Optional[str] = None,
                 subject: Optional[str] = None) -> List[Mapping[str, Any]]:
    """Findings whose id (or legacy id) is ``fid`` and whose subject names ``subject``."""
    out = []
    for f in findings:
        if fid is not None and fid not in finding_ids(f):
            continue
        if subject is not None and not any(refers(s, subject) or s == subject for s in finding_subjects(f)):
            continue
        out.append(f)
    return out


def edges_from(edges: Iterable[Mapping[str, Any]], source: str, target_name: Optional[str] = None,
               types: Optional[Iterable[str]] = None) -> List[Mapping[str, Any]]:
    types = set(types) if types else None
    return [e for e in edges if refers(e.get("source"), source) or e.get("source") == source
            if (target_name is None or refers(e.get("target"), target_name))
            and (types is None or e.get("type") in types)]


def edges_linking(edges: Iterable[Mapping[str, Any]], a: str, b: str,
                  types: Optional[Iterable[str]] = None) -> List[Mapping[str, Any]]:
    """Edges between ``a`` and ``b`` in either direction (legacy grant edges point resource -> grantee)."""
    types = set(types) if types else None
    out = []
    for e in edges:
        s, t = e.get("source"), e.get("target")
        if types is not None and e.get("type") not in types:
            continue
        if (refers(s, a) and refers(t, b)) or (refers(s, b) and refers(t, a)):
            out.append(e)
    return out


def mentions(analysis: Analysis, name: str) -> List[str]:
    """Where ``name`` appears in any analysis output file (for no-bleed assertions)."""
    return [str(p.name) for p in files_under(analysis.dir) if name.encode() in p.read_bytes()]


# ── graph.json ───────────────────────────────────────────────────────────────
def nodes_by_id(graph: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {n["id"]: n for n in graph.get("nodes", []) if isinstance(n, Mapping) and "id" in n}


def graph_edges(graph: Mapping[str, Any], *, edge_type: Optional[str] = None, source: Optional[str] = None,
                target: Optional[str] = None) -> List[Dict[str, Any]]:
    return [e for e in graph.get("edges", [])
            if (edge_type is None or e.get("type") == edge_type) and (source is None or e.get("source") == source)
            and (target is None or e.get("target") == target)]


def graph_findings(graph: Mapping[str, Any], fid: str) -> List[Dict[str, Any]]:
    return [f for f in graph.get("findings", []) if fid in finding_ids(f)]


def path(graph: Mapping[str, Any], source: str, target: str):
    """Directed shortest path over traversable edges (the normative reference, graph-json.md §11)."""
    return ref_paths.shortest_path(graph, source, target)


def graph_problems(graph: Mapping[str, Any]) -> List[str]:
    """Schema errors plus ``validate_graph`` problem codes (graph-json.md §12)."""
    import jsonschema

    problems: List[str] = []
    schema = load_json(ref_paths.engine_schema_dir() / "graph-1.0.schema.json")
    for err in jsonschema.Draft202012Validator(schema).iter_errors(graph):
        problems.append(f"schema: {err.message[:160]}")
    validate = ref_paths.engine_module("graph").validate_graph
    for p in validate(graph):
        problems.append(str(getattr(p, "code", p)))
    return problems


def iam_arn(kind: str, name: str, account: str = ACCT, path: str = "/") -> str:
    return f"arn:aws:iam::{account}:{kind}{path}{name}"


# ── v2 run trees (report-layout.md §1, manifest.md §5) ───────────────────────
class V2Run:
    """A synthetic v2 run root ``<root>/<account>/<run_id>/`` with legacy-shaped module files.

    Module data uses the report_builder record shapes (the engine reads old and new shapes,
    engine.md §0); only the layout and ``manifest.json`` are v2.
    """

    def __init__(self, root: Path, *, account: str = ACCT, run_id: str = RUN_ID,
                 regions: Sequence[str] = (REGION,), partition: str = "aws"):
        self.account = account
        self.run_id = run_id
        self.regions = list(regions)
        self.partition = partition
        self.path = Path(root) / account / run_id

    def scope(self, name: str) -> rb.Scope:
        s = rb.Scope(self.path.parent.parent, self.account, name)
        s.path = self.path / name
        return s

    def manifest(self) -> Dict[str, Any]:
        return {
            "schema_version": "2.0",
            "tool": {"name": "aws-enumerator", "version": "0.3.0", "git_sha": None, "python": "3.10.11",
                     "boto3": "1.37.34", "botocore": "1.37.34", "kubernetes": None},
            "run": {"run_id": self.run_id, "kind": "collect", "status": "complete",
                    "started_at": "2026-10-15T10:15:00Z", "ended_at": "2026-10-15T10:17:00Z",
                    "duration_seconds": 120.0, "exit_code": 0,
                    "argv": ["collect", "--regions", ",".join(self.regions), "--no-k8s"],
                    "options": {"regions_requested": list(self.regions), "modules": ["iam"],
                                "skipped_modules": [], "k8s": False, "k8s_secrets": False, "concurrency": 3,
                                "rate_limit": {"enabled": True, "default_rps": 5, "max_rps": None,
                                               "overrides": {}},
                                "max_tier": 2, "deny_breaker": 3, "redact_identity": False},
                    "resumes": [], "global_source": None},
            "target": {"account_id": self.account, "partition": self.partition, "home_region": self.regions[0],
                       "global_region": "us-east-1", "regions": sorted(self.regions), "region_source": "explicit",
                       "regions_skipped": []},
            "operator": {"caller_arn": f"arn:aws:sts::{self.account}:assumed-role/demo-operator/demo-session",
                         "caller_user_id": "AROAEXAMPLEDEMOOPER01:demo-session", "caller_arn_sha256": "0" * 64,
                         "principal_arn": f"arn:aws:iam::{self.account}:role/demo-operator",
                         "principal_type": "assumed-role", "redacted": False},
            "classification": "CONFIDENTIAL: pre-computed attack map of the target account; see HANDLING.txt",
            "preflight": None,
            "modules": [],
            "analysis": {"status": "not_run", "engine": "v2", "started_at": None, "duration_seconds": None,
                         "error": None, "dir": "analysis", "graph_schema_version": None},
            "coverage_summary": {"modules_by_status": {}, "denied_apis": [], "partial_modules": [],
                                 "failed_modules": [], "throttled_calls": 0, "item_errors": 0},
            "files": [],
        }

    def write_manifest(self) -> Path:
        self.path.mkdir(parents=True, exist_ok=True)
        rb.dump_json(self.path / "manifest.json", self.manifest())
        return self.path / "manifest.json"


# ── collectors through run_collector ─────────────────────────────────────────
@dataclass
class ModuleRun:
    result: Any
    fake: Any
    out: Path
    unit_dir: Path

    def load(self, rel: str, default: Any = None) -> Any:
        return load_json(self.out / rel, default)

    def coverage(self) -> Dict[str, Any]:
        return self.load("_coverage.json", {}) or {}

    def files(self) -> List[str]:
        return sorted(p.relative_to(self.out).as_posix() for p in files_under(self.out))


def run_module(name: str, world: Any, tmp_path: Path, *, region: str = REGION, account: str = "111122223333",
               options: Optional[Mapping[str, Any]] = None, deps: Optional[Mapping[str, Any]] = None,
               fake: Any = None, strict: bool = False) -> ModuleRun:
    """Run registry module ``name`` against ``world`` (collector-context.md §8).

    ``strict=False`` by default: an operation the world does not model answers a 501 error instead of
    aborting the test, so a migrated collector that makes extra calls still produces the data the
    regression test inspects.
    """
    from tests.support.fakeaws import FakeAWS

    base = collector_base()
    spec = registry_module().get_registry().get(name)
    fake = fake or FakeAWS(world, strict=strict)
    run = base.RunInfo(run_id=RUN_ID, aws=base.SessionAwsProvider(fake.session_factory()),
                       options=dict(options or {}), run_root=Path(tmp_path))
    unit = "global" if spec.scope == "global" else region
    unit_dir = Path(tmp_path) / unit
    ctx = base.CollectContext.create(spec, region=unit, account_id=account, partition="aws", run=run,
                                     unit_dir=unit_dir, deps=dict(deps or {}))
    result = base.run_collector(ctx)
    return ModuleRun(result, fake, Path(ctx.out.root), unit_dir)


# ── the CLI (legacy invocation or subcommands) ───────────────────────────────
@dataclass
class CliRun:
    legacy: Any                      # tests.python.collectors.legacy_harness.LegacyRun (or None)
    exit_code: Any
    output_root: Path
    workdir: Path
    interrupted: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)

    def roots(self) -> List[Path]:
        return [self.workdir / "reports", self.output_root]

    def manifests(self) -> List[Path]:
        return [p for p in files_under(*self.roots()) if p.name == "manifest.json"]

    def manifest_docs(self) -> List[Dict[str, Any]]:
        return [load_json(p) for p in self.manifests()]

    def run_manifest(self) -> Optional[Dict[str, Any]]:
        """The top-level manifest of the run (v2 run root, or the legacy account/region dir)."""
        docs = [(p, load_json(p)) for p in self.manifests()]
        v2 = [d for _, d in docs if isinstance(d, Mapping) and d.get("schema_version", "").startswith("2")]
        if v2:
            return v2[0]
        return docs[0][1] if docs else None

    def analysis_dirs(self) -> List[Path]:
        dirs = set()
        for p in files_under(*self.roots()):
            if p.parent.name == "analysis" and (p.name == "graph.json" or p.name.endswith("_relationships.json")):
                dirs.add(p.parent)
        return sorted(dirs)

    def grep(self, needle: str) -> List[str]:
        return grep_tree(needle, *self.roots())


def run_cli(argv: Sequence[str], tmp_path: Path, monkeypatch: Any, **kw: Any) -> CliRun:
    """Run the console entry point with ``argv`` against the acme fake world.

    ``$AWS_ENUMERATOR_OUTPUT`` points at ``<tmp_path>/out`` so a v2 runner writes there (cli.md §7);
    the baseline writes ``<workdir>/reports/<date>/``. Both are searched by the ``CliRun`` finders.
    """
    from tests.python.collectors.legacy_harness import run_legacy_main

    out = Path(tmp_path) / "out"
    out.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("AWS_ENUMERATOR_OUTPUT", str(out))
    workdir_name = kw.pop("workdir_name", "run")
    legacy = run_legacy_main(list(argv), Path(tmp_path), monkeypatch, workdir_name=workdir_name, **kw)
    return CliRun(legacy, legacy.exit_code, out, Path(tmp_path) / workdir_name)


def edge_counts(analysis_dir: Path) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for p in sorted(Path(analysis_dir).glob("*_relationships.json")):
        if p.name == TRUST_FILE:
            continue
        doc = load_json(p, {}) or {}
        out[p.name[: -len("_relationships.json")]] = len(doc.get("edges", [])) if isinstance(doc, Mapping) else 0
    return out


def capture_main(argv: Sequence[str], monkeypatch: Any) -> Tuple[Any, str, str]:
    """Run ``main()`` with ``sys.argv = ["aws-enumerator", *argv]``; return (exit code, stdout, stderr)."""
    import sys

    monkeypatch.setattr(sys, "argv", ["aws-enumerator", *argv])
    out, err = io.StringIO(), io.StringIO()
    code: Any = None
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rv = targets.main_entry()()
            code = 0 if rv is None else rv
        except SystemExit as exc:
            code = 0 if exc.code is None else exc.code
    return code, out.getvalue(), err.getvalue()
