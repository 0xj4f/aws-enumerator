"""The one place the CLI calls the analysis engine (engine-api.md §3; report-layout.md §1.3).

Analysis runs **once, after every unit of a run has finished** (F-010), over the explicit region list of the
manifest; the engine never discovers regions by scanning directories (F-025, F-063).

* :func:`analyze_run_root` calls ``aws_enumerator.engine.analyze_run`` for a v2 run root;
* :func:`analyze_report_dir` calls ``aws_enumerator.engine.analyze_report`` for ``aws-enumerator analyze <dir>``
  (a v2 run root or an old report layout: the engine's loaders read the old shapes).

The engine writes ``analysis.tmp/`` -> ``analysis/`` itself and returns an ``AnalysisResult``; its status maps to
``manifest.analysis.status`` as ``ok -> ok``, ``partial -> partial``, ``error -> failed`` (D-16). Writing
``manifest.json`` and the digests is the caller's job (D-17). The d13c215 ``engine.analyze(<dir>)`` fallback
(the "interim adapter" of Wave 1) is gone: 0.3.0 always runs the v2 engine.

The entry points are looked up on the engine package at call time, so tests can spy on them
(``tests/support/targets.main_patch_points``).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from aws_enumerator import output

__all__ = ["AnalysisOutcome", "AnalysisUsage", "analyze_report_dir", "analyze_run_root", "validate_analysis_inputs"]

log = logging.getLogger("aws_enumerator.engine")

ENGINE_NAME = "v2"
_STATUS_MAP = {"ok": "ok", "partial": "partial", "error": "failed"}


class AnalysisUsage(ValueError):
    """The engine refused its input (bad baseline/suppression file, in-progress run): exit 64."""


@dataclass
class AnalysisOutcome:
    """What ``manifest.analysis`` records about one analysis."""

    status: str
    engine: Optional[str]
    started_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    error: Optional[str] = None
    graph_schema_version: Optional[str] = None
    analysis_dir: Optional[Path] = None

    def manifest_fields(self) -> Dict[str, Any]:
        return {"status": self.status, "engine": self.engine, "started_at": self.started_at,
                "duration_seconds": self.duration_seconds, "error": self.error, "dir": "analysis",
                "graph_schema_version": self.graph_schema_version}


def _engine() -> Any:
    from aws_enumerator import engine  # imported on first use (the engine is large); looked up at call time

    return engine


def _options(**fields: Any) -> Any:
    """The engine's ``AnalysisOptions`` with the given (non-``None``) fields."""
    from aws_enumerator.engine.model import AnalysisOptions

    return AnalysisOptions(**{k: v for k, v in fields.items() if v is not None})


def _usage_error_type() -> type:
    from aws_enumerator.engine.model import AnalysisUsageError

    return AnalysisUsageError


def _one_line(exc: BaseException) -> str:
    text = str(exc).splitlines()[0] if str(exc) else ""
    return f"{type(exc).__name__}: {text}"[:300] if text else type(exc).__name__


def _from_result(result: Any, started: str, t0: float) -> AnalysisOutcome:
    status = _STATUS_MAP.get(str(getattr(result, "status", "error")), "failed")
    analysis_dir = getattr(result, "analysis_dir", None)
    return AnalysisOutcome(status=status, engine=ENGINE_NAME, started_at=started,
                           duration_seconds=round(time.monotonic() - t0, 3),
                           error=None if status != "failed" else "the engine wrote no usable analysis",
                           graph_schema_version=getattr(result, "graph_schema_version", None),
                           analysis_dir=Path(analysis_dir) if analysis_dir else None)


def _failed(exc: Exception, started: str, t0: float, engine: Optional[str]) -> AnalysisOutcome:
    """An engine exception: a usage error re-raised as :class:`AnalysisUsage`, anything else recorded."""
    if isinstance(exc, _usage_error_type()):
        raise AnalysisUsage(str(exc)) from None
    log.error("analysis failed: %s", _one_line(exc), exc_info=log.isEnabledFor(logging.DEBUG))
    return AnalysisOutcome(status="failed", engine=engine, started_at=started,
                           duration_seconds=round(time.monotonic() - t0, 3), error=_one_line(exc))


def validate_analysis_inputs(*, baseline: Optional[str] = None, suppress: Optional[str] = None) -> None:
    """Check ``--baseline`` / ``--suppress`` before any collection (cli.md §3.1: invalid -> exit 64).

    Uses the engine's own loaders (finding-identity.md §4-§5), so the check is the one the analysis applies
    later; raises :class:`AnalysisUsage`.
    """
    from aws_enumerator.engine.findings.baseline import load_baseline
    from aws_enumerator.engine.findings.suppress import load_suppressions

    for value, loader in ((suppress, load_suppressions), (baseline, load_baseline)):
        if not value:
            continue
        try:
            loader(str(Path(value).expanduser()))
        except Exception as exc:  # noqa: BLE001 - every failure of a user-supplied file is a usage error
            if isinstance(exc, _usage_error_type()):
                raise AnalysisUsage(str(exc)) from None
            raise AnalysisUsage(f"{value}: {_one_line(exc)}") from None


def analyze_run_root(run_root: Path, *, regions: Sequence[str], manifest: Optional[Mapping[str, Any]],
                     baseline: Optional[str] = None, suppress: Optional[str] = None,
                     redact_identity: bool = False, force: bool = True,
                     legacy_outputs: bool = True) -> AnalysisOutcome:
    """Analyse a v2 run root once, after collection; never raises for engine failures (usage errors: 64).

    ``legacy_outputs=False`` (``--no-legacy-outputs``) maps to ``AnalysisOptions.legacy_outputs``.
    """
    started, t0 = output.iso(), time.monotonic()
    target = (manifest or {}).get("target", {})
    try:
        opts = _options(baseline=baseline, suppress=suppress, redact_identity=redact_identity, force=force,
                        legacy_outputs=legacy_outputs)
        result = _engine().analyze_run(str(run_root), regions=list(regions), account_id=target.get("account_id"),
                                       partition=target.get("partition"), manifest=manifest, options=opts)
    except Exception as exc:  # noqa: BLE001 - the engine's failure is recorded, never fatal to the run
        return _failed(exc, started, t0, ENGINE_NAME)
    return _from_result(result, started, t0)


def analyze_report_dir(report_dir: Path, *, baseline: Optional[str] = None, suppress: Optional[str] = None,
                       redact_identity: bool = False, force: bool = False,
                       legacy_outputs: bool = True) -> AnalysisOutcome:
    """``aws-enumerator analyze <dir>`` for an old report layout (v2 runs go through :func:`analyze_run_root`)."""
    started, t0 = output.iso(), time.monotonic()
    try:
        opts = _options(baseline=baseline, suppress=suppress, redact_identity=redact_identity, force=force,
                        legacy_outputs=legacy_outputs)
        result = _engine().analyze_report(str(report_dir), options=opts)
    except Exception as exc:  # noqa: BLE001
        return _failed(exc, started, t0, None)
    return _from_result(result, started, t0)
