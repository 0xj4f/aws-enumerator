"""The analysis pipeline (engine-api.md §3, §5; engine.md §1).

``analyze_run`` / ``analyze_report`` build an :class:`~aws_enumerator.engine.context.AnalysisContext` from an
**explicit** region list (F-010, F-025, F-063), then run the registered analyzers phase by phase:

1. CONTEXT  — the context (layout, regions, account, partition, operator, clock);
2. LOAD     — one isolated loader per domain (``io/loaders``);
3-8.        — every :class:`~aws_enumerator.engine.model.AnalyzerSpec` of :data:`ANALYZER_MODULES`, in phase
              order, then module order, then tuple order;
9. WRITE    — ``graph.json`` (validated), ``findings.json``, ``summary.json``, ``diff.json``, the legacy outputs
              and exports, staged in ``analysis.tmp/`` and swapped into ``analysis/`` (report-layout.md §1.1).

**Registration** (engine-api.md §5). Every module in :data:`ANALYZER_MODULES` exports ``ANALYZERS``. A module that
exports none yields one ``not_implemented`` status; one that cannot be imported yields one ``error`` status (the
analysis is then ``partial``). There is no fallback to the d13c215 analyzers any more (DECISIONS.md D-53).

**Isolation** (F-002). Each spec runs in its own ``try``: an exception becomes an ``error`` status with its type
and a one-line message, the spec's partial graph output is rolled back, and every other analyzer still runs and
writes. ``AnalysisResult.status`` is ``ok`` / ``partial`` / ``error`` (F-061).
"""

from __future__ import annotations

import importlib
import logging
import os
import shutil
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from aws_enumerator._version import __version__
from aws_enumerator.engine.context import (
    ANALYSIS_DIR, ORIG_DIR, PREV_DIR, AnalysisContext, add_standard_gaps, build_report_context,
    build_run_context, detect_layout, provenance,
)
from aws_enumerator.engine.graph import GRAPH_SCHEMA_VERSION
from aws_enumerator.engine.graph.builder import CatalogError, GraphBuilder, RunInfo
from aws_enumerator.engine.io.loaders import LOADER_MODULES
from aws_enumerator.engine.model import (
    AnalysisOptions, AnalysisResult, AnalysisUsageError, AnalyzerSkipped, AnalyzerSpec, AnalyzerStatus, Phase,
)

log = logging.getLogger(__name__)

#: ``graph.generator.engine_version``: the generation of the traversability table and analyzer set (graph-json.md
#: §3). 1.1.0: the Wave 3 edge types (cross-account sharing, ``VPC_CONNECTED``) and the network analyzer (D-52).
ENGINE_SCHEMA_VERSION = "1.1.0"

#: Every planned analyzer module, in registration order (engine-api.md §5, §7). Missing ones are fine.
ANALYZER_MODULES: Tuple[str, ...] = (
    "aws_enumerator.engine.iam.principals",       # PRINCIPALS: principal models + evaluator (E-policy)
    "aws_enumerator.engine.iam",                  # PRINCIPALS/IDENTITY: permission map, IAM graph, admin
    "aws_enumerator.engine.iam.trust",            # IDENTITY: TRUST-* findings, trust_relationships.json
    "aws_enumerator.engine.iam.assume",           # IDENTITY: CAN_ASSUME / web identity / SAML edges
    "aws_enumerator.engine.iam.hygiene",          # IDENTITY: IAM hygiene (E-compute, Wave 2)
    "aws_enumerator.engine.analyzers.s3",         # RESOURCES (E-net)
    "aws_enumerator.engine.analyzers.ec2",
    "aws_enumerator.engine.analyzers.edge_services",
    "aws_enumerator.engine.analyzers.posture",
    "aws_enumerator.engine.analyzers.network",    # RESOURCES: VPC connectivity context (I1, Wave 3, F-105)
    "aws_enumerator.engine.analyzers.k8s",        # RESOURCES (E-k8s)
    "aws_enumerator.engine.analyzers.kms",        # RESOURCES (E-data)
    "aws_enumerator.engine.analyzers.secrets",
    "aws_enumerator.engine.analyzers.data_stores",
    "aws_enumerator.engine.analyzers.lambda_",    # RESOURCES (E-compute)
    "aws_enumerator.engine.analyzers.compute",
    "aws_enumerator.engine.analyzers.messaging",
    "aws_enumerator.engine.analyzers.cognito",
    "aws_enumerator.engine.analyzers.coverage_gaps",
    "aws_enumerator.engine.rules.runner",         # RULES (E-rules)
    "aws_enumerator.engine.rules.severity",       # RULES/CLOSURE (E-rules)
    "aws_enumerator.engine.graph.closure",        # CLOSURE (E-rules)
    "aws_enumerator.engine.rules.subsume",        # POSTPROCESS (E-rules)
)

#: Phase recorded for a ``not_implemented`` module (its planned phase).
PLANNED_PHASES: Mapping[str, Phase] = {
    "aws_enumerator.engine.iam.principals": Phase.PRINCIPALS,
    "aws_enumerator.engine.iam.hygiene": Phase.IDENTITY,
    "aws_enumerator.engine.rules.runner": Phase.RULES,
    "aws_enumerator.engine.rules.severity": Phase.RULES,
    "aws_enumerator.engine.graph.closure": Phase.CLOSURE,
    "aws_enumerator.engine.rules.subsume": Phase.POSTPROCESS,
}


# ── registry ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Registered:
    """A spec with its position (module index, tuple index) and origin (always ``native``)."""

    spec: AnalyzerSpec
    module_index: int
    index: int
    origin: str = "native"

    @property
    def order(self) -> Tuple[int, int, int]:
        return (int(self.spec.phase), self.module_index, self.index)


def _short_name(module: str) -> str:
    return module.rsplit(".", 1)[-1].rstrip("_") or module


def collect_specs(modules: Sequence[str] = ANALYZER_MODULES) -> Tuple[List[Registered], List[AnalyzerStatus]]:
    """Every registered spec (sorted for execution) and the statuses of modules that registered none.

    A module without ``ANALYZERS`` is ``not_implemented``; a module that cannot be imported is ``error`` (an engine
    defect, never silently skipped: the analysis becomes ``partial``).
    """
    specs: List[Registered] = []
    missing: List[AnalyzerStatus] = []
    for mi, name in enumerate(modules):
        phase = PLANNED_PHASES.get(name, Phase.RESOURCES)
        try:
            declared = getattr(importlib.import_module(name), "ANALYZERS", None)
        except Exception as exc:  # noqa: BLE001 - a broken module is reported, never fatal
            log.error("analyzer module %s cannot be imported: %s: %s", name, type(exc).__name__, _message(exc))
            missing.append(AnalyzerStatus(_short_name(name), phase, "error", None, type(exc).__name__,
                                          _message(exc)))
            continue
        if declared:
            specs.extend(Registered(s, mi, ti) for ti, s in enumerate(declared))
        else:
            missing.append(AnalyzerStatus(_short_name(name), phase, "not_implemented"))
    return sorted(specs, key=lambda r: r.order), missing


# ── execution ────────────────────────────────────────────────────────────────

_UNAVAILABLE = frozenset({"not-collected", "skipped"})


def inputs_missing(ctx: AnalysisContext, inputs: Sequence[str]) -> Tuple[str, ...]:
    """The input facets (``service.facet`` or a module directory name) with no collected unit."""
    units = ["global"] + list(ctx.regions)
    out = []
    for facet in inputs:
        module = facet.split(".", 1)[0]
        if all(ctx.coverage.module_status(module, u) in _UNAVAILABLE for u in units):
            out.append(facet)
    return tuple(out)


def _message(exc: BaseException) -> str:
    text = " ".join(str(exc).split())
    return text[:200]


def run_spec(spec: AnalyzerSpec, ctx: AnalysisContext, builder: GraphBuilder,
             done: Mapping[str, str]) -> AnalyzerStatus:
    """Run one analyzer in isolation (F-002); never raises except for ``strict_catalog`` violations."""
    unmet = tuple(r for r in spec.requires if done.get(r) != "ok")
    if unmet:
        return AnalyzerStatus(spec.name, spec.phase, "skipped", inputs_missing=unmet)
    absent = inputs_missing(ctx, spec.inputs)
    if spec.inputs and len(absent) == len(spec.inputs):
        return AnalyzerStatus(spec.name, spec.phase, "skipped", inputs_missing=absent)
    mark = builder.mark()
    builder.origin = spec.name
    started = time.monotonic()
    status, err_type, err_msg, missing = "ok", None, None, ()
    try:
        spec.run(ctx, builder)
    except AnalyzerSkipped as exc:
        status, missing = "skipped", exc.inputs_missing
    except NotImplementedError as exc:
        status, err_msg = "not_implemented", _message(exc)
    except CatalogError:
        if ctx.options.strict_catalog:
            raise
        status, err_type, err_msg = "error", "CatalogError", "unknown finding id or edge type"
    except Exception as exc:  # noqa: BLE001 - per-analyzer isolation is the point (F-002)
        log.warning("analyzer %s failed: %s: %s", spec.name, type(exc).__name__, _message(exc))
        log.debug("analyzer %s traceback", spec.name, exc_info=True)
        status, err_type, err_msg = "error", type(exc).__name__, _message(exc)
    finally:
        builder.origin = None
    if status != "ok":
        builder.rollback(mark)
    duration = None if ctx.reproducible else round(time.monotonic() - started, 3)
    return AnalyzerStatus(spec.name, spec.phase, status, duration, err_type,
                          err_msg if err_type else None, tuple(missing))


def run_loaders(ctx: AnalysisContext) -> List[AnalyzerStatus]:
    """Phase LOAD: every domain loader, isolated; ``ctx.data[domain]`` is set for those that succeed."""
    out = []
    for domain, module in LOADER_MODULES.items():
        started = time.monotonic()
        name = f"load:{domain}"
        try:
            result = importlib.import_module(module).load(ctx)
        except Exception as exc:  # noqa: BLE001 - one unreadable domain must not stop the analysis
            log.warning("loader %s failed: %s", domain, type(exc).__name__)
            out.append(AnalyzerStatus(name, Phase.LOAD, "error", None if ctx.reproducible else 0.0,
                                      type(exc).__name__, _message(exc)))
            continue
        ctx.data[domain] = result.data
        ctx.shared.setdefault("load_status", {})[domain] = result.status
        _record_load_gaps(ctx, domain, result.gaps)
        duration = None if ctx.reproducible else round(time.monotonic() - started, 3)
        status = "skipped" if result.status == "missing" else "ok"
        out.append(AnalyzerStatus(name, Phase.LOAD, status, duration,
                                  inputs_missing=(domain,) if status == "skipped" else ()))
    return out


def _record_load_gaps(ctx: AnalysisContext, domain: str, gaps: Mapping[str, str]) -> None:
    designed = {k: v for k, v in gaps.items() if ":" in k and "/" not in k and k == k.lower()}
    for code, detail in sorted(designed.items()):
        ctx.add_gap(code, detail)
    files = sorted(k for k in gaps if k not in designed)
    if files:
        ctx.add_gap("input:files-unreadable", "Data files that hold a collector error marker or are not "
                    "readable; their resources are unknown, not absent: " + ", ".join(files[:20]), len(files))


def run_phases(ctx: AnalysisContext, builder: GraphBuilder, specs: Sequence[Registered]) -> List[AnalyzerStatus]:
    """Phases PRINCIPALS … POSTPROCESS (the specs are already in execution order).

    A failing analyzer is isolated (``error``, its partial output rolled back); analyzers that ``require`` it are
    ``skipped``; every other analyzer still runs (F-002).
    """
    done: Dict[str, str] = {}
    out = []
    for reg in specs:
        st = run_spec(reg.spec, ctx, builder, done)
        done[reg.spec.name] = st.status
        out.append(st)
    return out


# ── POSTPROCESS (finding lifecycle) ──────────────────────────────────────────

def postprocess(ctx: AnalysisContext, builder: GraphBuilder, prepared: Mapping[str, Any]) -> List[AnalyzerStatus]:
    """Suppression, then baseline comparison (both E-core, F-143)."""
    from aws_enumerator.engine.findings.lifecycle import apply_baseline, apply_suppressions

    def suppress(c: AnalysisContext, b: GraphBuilder) -> None:
        if not prepared.get("suppressions"):
            raise AnalyzerSkipped(reason="no --suppress file")
        c.shared["suppression_counts"] = apply_suppressions(
            b, prepared["suppressions"], account=c.account_id, generated_at=c.generated_at)

    def baseline(c: AnalysisContext, b: GraphBuilder) -> None:
        if prepared.get("baseline") is None:
            raise AnalyzerSkipped(reason="no --baseline")
        c.shared["diff"] = apply_baseline(b, prepared["baseline"], ref=prepared["baseline_ref"],
                                          baseline_path=prepared.get("baseline_path"),
                                          coverage_status=c.coverage.status())

    out = []
    for spec in (AnalyzerSpec("suppression", Phase.POSTPROCESS, suppress),
                 AnalyzerSpec("baseline", Phase.POSTPROCESS, baseline)):
        out.append(run_spec(spec, ctx, builder, {}))
    return out


# ── WRITE ────────────────────────────────────────────────────────────────────

def _generator(ctx: AnalysisContext) -> Dict[str, Any]:
    from aws_enumerator.engine.findings.catalog import rules_version

    tool = (ctx.manifest or {}).get("tool") if isinstance((ctx.manifest or {}).get("tool"), Mapping) else {}
    sha = tool.get("git_sha") if isinstance(tool.get("git_sha"), str) else None
    if sha is not None and not (7 <= len(sha) <= 40 and all(c in "0123456789abcdef" for c in sha)):
        sha = None
    return {"tool": "aws-enumerator", "version": __version__, "engine_version": ENGINE_SCHEMA_VERSION,
            "rules_version": rules_version(), "git_sha": sha}


def build_graph(ctx: AnalysisContext, builder: GraphBuilder, statuses: Sequence[AnalyzerStatus]) -> Dict[str, Any]:
    run = RunInfo(ctx.run_id, ctx.account_id, ctx.partition, ctx.mode, ctx.regions, ctx.generated_at,
                  ctx.manifest_sha256)
    return builder.finalize(run, generator=_generator(ctx), coverage=ctx.coverage.graph_block(),
                            evaluation_gaps=ctx.evaluation_gaps(), analyzer_status=[s.to_json() for s in statuses],
                            operator=ctx.operator)


@dataclass
class Outputs:
    """The staged files (name → bytes) and what the result reports."""

    files: Dict[str, bytes] = field(default_factory=dict)
    graph: Dict[str, Any] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)
    legacy_edge_counts: Dict[str, int] = field(default_factory=dict)


def _file_status(specs: Sequence[Registered], statuses: Sequence[AnalyzerStatus]) -> Dict[str, str]:
    by_name = {s.name: s.status for s in statuses}
    out: Dict[str, str] = {}
    for reg in specs:
        for name in reg.spec.legacy_files:
            out[name] = by_name.get(reg.spec.name, "not_implemented")
    return out


def _file_findings(specs: Sequence[Registered], builder: GraphBuilder) -> Dict[str, List[str]]:
    origins = builder.finding_origins()
    out: Dict[str, List[str]] = {}
    for reg in specs:
        fps = [fp for fp, origin in origins.items() if origin == reg.spec.name]
        for name in reg.spec.legacy_files:
            out.setdefault(name, []).extend(fps)
    return out


def render_outputs(ctx: AnalysisContext, builder: GraphBuilder, specs: Sequence[Registered],
                   statuses: Sequence[AnalyzerStatus], result_status: str) -> Outputs:
    """Render every file of graph-json.md §1 (validating ``graph.json``)."""
    from aws_enumerator.engine.writers import EXPORT_FORMATS, export
    from aws_enumerator.engine.writers import findings as fw
    from aws_enumerator.engine.writers import graph_json, legacy, summary

    out = Outputs()
    out.graph = build_graph(ctx, builder, statuses)
    out.files["graph.json"] = graph_json.checked(out.graph)
    out.files["findings.json"] = fw.render(fw.findings_document(out.graph))
    docs = legacy.legacy_documents(ctx.legacy_outputs(), out.graph, file_status=_file_status(specs, statuses),
                                   file_findings=_file_findings(specs, builder))
    out.legacy_edge_counts = legacy.domain_edge_counts(docs)
    out.summary = summary.summary_document(out.graph, status=result_status, ignored_dirs=ctx.ignored_dirs,
                                           legacy_edge_counts=out.legacy_edge_counts)
    out.files["summary.json"] = summary.render(out.summary)
    if ctx.shared.get("diff") is not None:
        out.files["diff.json"] = fw.render(ctx.shared["diff"])
    if ctx.options.legacy_outputs:
        out.files.update({name: legacy.render(doc) for name, doc in docs.items()})
    if ctx.is_legacy:
        out.files["_provenance.json"] = fw.render(provenance(
            ctx, tool_version=__version__, git_sha=None, input_files=int(ctx.shared.get("input_files", 0))))
    for fmt in ctx.options.exports:
        try:
            out.files[f"exports/{EXPORT_FORMATS[fmt][1]}"] = export(out.graph, fmt)
        except NotImplementedError as exc:
            log.warning("export %s skipped: %s", fmt, exc)
    return out


def stage(ctx: AnalysisContext, files: Mapping[str, bytes]) -> List[str]:
    """Write ``files`` into ``analysis.tmp/`` (0600 files, 0700 directories); returns the relative paths."""
    from aws_enumerator.util.fsio import atomic_write_bytes, ensure_dir

    ensure_dir(ctx.tmp_dir)
    for rel in sorted(files):
        atomic_write_bytes(ctx.tmp_dir / rel, files[rel])
    return sorted(files)


def swap_in(ctx: AnalysisContext) -> Path:
    """``analysis/`` → ``analysis.prev/``, ``analysis.tmp/`` → ``analysis/``, delete ``analysis.prev/``.

    For an old single-region report, an ``analysis/`` written by the d13c215 engine (no ``_provenance.json``) is
    kept once as ``analysis.orig/`` (report-layout.md §8).
    """
    final, prev, orig = ctx.run_root / ANALYSIS_DIR, ctx.run_root / PREV_DIR, ctx.run_root / ORIG_DIR
    if prev.exists():
        shutil.rmtree(prev)
    if final.is_dir():
        keep_orig = ctx.mode == "legacy-single" and not (final / "_provenance.json").exists() and not orig.exists()
        os.rename(final, orig if keep_orig else prev)
    os.rename(ctx.tmp_dir, final)
    if prev.exists():
        shutil.rmtree(prev)
    return final


def _discard_tmp(ctx: AnalysisContext) -> None:
    if ctx.tmp_dir.exists():
        shutil.rmtree(ctx.tmp_dir, ignore_errors=True)


# ── the driver ───────────────────────────────────────────────────────────────

def _catalog(ctx: AnalysisContext) -> Any:
    from aws_enumerator.engine.findings.catalog import build_catalog, build_catalog_lenient

    try:
        return build_catalog(ANALYZER_MODULES)
    except ValueError as exc:
        if ctx.options.strict_catalog:
            raise
        catalog, skipped = build_catalog_lenient(ANALYZER_MODULES)
        log.error("finding catalogue conflict (%s); the first declaration of %s is used", exc, ", ".join(skipped))
        ctx.add_gap("catalog:conflict", f"The finding catalogue could not be merged ({_message(exc)}); the first "
                    f"declaration of each duplicated id is used.", len(skipped))
        return catalog


def result_status(statuses: Sequence[AnalyzerStatus]) -> str:
    return "partial" if any(s.status == "error" for s in statuses) else "ok"


def _error_result(ctx: AnalysisContext, statuses: Sequence[AnalyzerStatus], exc: BaseException) -> AnalysisResult:
    log.error("analysis failed, nothing written: %s: %s", type(exc).__name__, _message(exc))
    failed = list(statuses) + [AnalyzerStatus("write", Phase.WRITE, "error", None, type(exc).__name__,
                                              _message(exc))]
    previous = ctx.run_root / ANALYSIS_DIR
    return AnalysisResult("error", tuple(failed), (), None,
                          str(previous) if previous.is_dir() else None, {}, None)


def execute(ctx: AnalysisContext, prepared: Mapping[str, Any]) -> AnalysisResult:
    """Run every phase on ``ctx`` and write ``analysis/`` (engine-api.md §3.1 behaviour)."""
    from aws_enumerator.engine import console

    _discard_tmp(ctx)
    builder = GraphBuilder(ctx.account_id, ctx.partition, catalog=_catalog(ctx), strict=ctx.options.strict_catalog)
    add_standard_gaps(ctx)
    specs, missing = collect_specs()
    statuses: List[AnalyzerStatus] = run_loaders(ctx)
    if any(s.name == "load:iam" and s.status == "error" for s in statuses):
        _discard_tmp(ctx)
        return _error_result(ctx, statuses, RuntimeError("the IAM data could not be read"))
    try:
        statuses += run_phases(ctx, builder, specs)
        statuses += missing
        statuses += postprocess(ctx, builder, prepared)
        status = result_status(statuses)
        statuses.append(AnalyzerStatus("write", Phase.WRITE, "ok", None if ctx.reproducible else 0.0))
        statuses = sorted(statuses, key=lambda s: int(s.phase))
        out = render_outputs(ctx, builder, specs, statuses, status)
        written = stage(ctx, out.files)
        final = swap_in(ctx)
    except (AnalysisUsageError, CatalogError):
        _discard_tmp(ctx)
        raise
    except Exception as exc:  # noqa: BLE001 - nothing usable: keep the previous analysis/ (D-18)
        log.debug("analysis write failed", exc_info=True)
        _discard_tmp(ctx)
        return _error_result(ctx, statuses, exc)
    console.report(out.summary, out.graph["findings"], out.legacy_edge_counts)
    counts = dict(builder.counts())
    return AnalysisResult(status, tuple(statuses), tuple(written), str(final / "graph.json"), str(final), counts,
                          GRAPH_SCHEMA_VERSION)


def _options(options: Optional[AnalysisOptions]) -> AnalysisOptions:
    options = options or AnalysisOptions()
    exports = tuple(options.exports or ())
    from aws_enumerator.engine.writers import EXPORT_FORMATS

    unknown = [f for f in exports if f not in EXPORT_FORMATS]
    if unknown:
        raise AnalysisUsageError(f"unknown export formats {unknown}; expected {sorted(EXPORT_FORMATS)}")
    return replace(options, exports=exports)


def _prepare(options: AnalysisOptions) -> Dict[str, Any]:
    from aws_enumerator.engine.findings.lifecycle import load_options

    return load_options(options.baseline, options.suppress)


def analyze_run(run_root: "str | os.PathLike[str]", *, regions: Sequence[str], account_id: Optional[str] = None,
                partition: Optional[str] = None, manifest: Optional[Mapping[str, Any]] = None,
                options: Optional[AnalysisOptions] = None) -> AnalysisResult:
    """Analyse a v2 run root over the **explicit** ``regions`` (engine-api.md §3.1)."""
    options = _options(options)
    prepared = _prepare(options)
    ctx = build_run_context(Path(run_root), regions=regions, account_id=account_id, partition=partition,
                            manifest=manifest, options=options)
    return execute(ctx, prepared)


def analyze_report(report_dir: "str | os.PathLike[str]", options: Optional[AnalysisOptions] = None) -> AnalysisResult:
    """``aws-enumerator analyze <dir>``: a v2 run, an old ``--all`` account directory or an old region directory."""
    report_dir = Path(report_dir)
    if not report_dir.is_dir():
        raise FileNotFoundError(f"{report_dir} is not a directory")
    options = _options(options)
    if detect_layout(report_dir) == "run":
        from aws_enumerator.engine.context import read_manifest_bytes

        manifest = read_manifest_bytes(report_dir / "manifest.json") or {}
        target = manifest.get("target") if isinstance(manifest.get("target"), Mapping) else {}
        return analyze_run(report_dir, regions=list(target.get("regions") or ()), manifest=manifest,
                           options=options)
    prepared = _prepare(options)
    ctx = build_report_context(report_dir, options)
    ctx.shared["input_files"] = _count_inputs(ctx)
    return execute(ctx, prepared)


def _count_inputs(ctx: AnalysisContext) -> int:
    roots = [ctx.global_dir] + [p for p in ctx.region_dirs.values() if p != ctx.global_dir]
    total = 0
    for root in roots:
        for _dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if not d.startswith(ANALYSIS_DIR))
            total += sum(1 for f in filenames if f.endswith(".json") and f != "manifest.json")
    return total


__all__ = [
    "ANALYZER_MODULES", "ENGINE_SCHEMA_VERSION", "PLANNED_PHASES", "Registered", "analyze_report", "analyze_run",
    "collect_specs", "execute", "inputs_missing", "render_outputs", "result_status", "run_loaders", "run_phases",
    "run_spec", "stage", "swap_in",
]
