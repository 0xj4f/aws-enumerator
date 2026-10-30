"""Finding counts for ``summary.json`` and the console (finding-identity.md §6, F-074).

d13c215 counted LOW findings only inside ``total_findings`` (no ``low_count``) and the CLI printed
CRITICAL/HIGH/MEDIUM only, so LOW and INFO findings disappeared from every breakdown. Every severity now has
a count, ``by_severity`` always lists all five levels, and severity counts include **open** findings only,
so they sum to ``total_findings``. ``_generate_summary`` keeps its d13c215 name and legacy keys.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

from aws_enumerator.engine.model import SEVERITIES


def _is_open(f: Mapping[str, Any]) -> bool:
    return f.get("status", "open") == "open"


def severity_counts(findings: Iterable[Mapping[str, Any]]) -> Dict[str, int]:
    """Open findings per severity, all five levels present."""
    counts = Counter(str(f.get("severity", "")).upper() for f in findings if _is_open(f))
    return {s: counts.get(s, 0) for s in SEVERITIES}


def _generate_summary(findings):
    """Legacy summary keys plus ``low_count`` / ``info_count``; open findings only (F-074)."""
    findings = [f for f in findings if _is_open(f)]
    by_sev = severity_counts(findings)
    categories = Counter(str(f.get("category") or "uncategorised") for f in findings)
    unique = {(f.get("id"), f.get("node_id") or f.get("entity")) for f in findings}
    return {
        "total_findings": len(findings),
        "unique_findings": len(unique),
        "by_severity": by_sev,
        "by_category": dict(sorted(categories.items())),
        "critical_count": by_sev["CRITICAL"],
        "high_count": by_sev["HIGH"],
        "medium_count": by_sev["MEDIUM"],
        "low_count": by_sev["LOW"],
        "info_count": by_sev["INFO"],
    }


def build_summary(findings: Sequence[Mapping[str, Any]], *, run: Mapping[str, Any],
                  analyzer_status: Sequence[Mapping[str, Any]], evaluation_gaps: Sequence[Mapping[str, Any]],
                  counts: Mapping[str, int], status: str, ignored_dirs: Sequence[str] = (),
                  coverage: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """The ``summary.json`` document: legacy keys plus lifecycle counts and run context."""
    out = _generate_summary(findings)
    subsumed = {fid for f in findings for fid in (f.get("subsumes") or ())}
    out.update({
        "suppressed_count": sum(1 for f in findings if f.get("status") == "suppressed"),
        "subsumed_count": len(subsumed),
        "unattached_count": 0,
        "status": status,
        "graph": {"nodes": counts.get("nodes", 0), "edges": counts.get("edges", 0)},
        "run": {k: run.get(k) for k in ("run_id", "account_id", "partition", "mode", "regions", "generated_at")},
        "ignored_dirs": sorted(ignored_dirs),
        "analyzer_status": [dict(s) for s in analyzer_status],
        "evaluation_gaps": [dict(g) for g in evaluation_gaps],
    })
    if coverage is not None:
        out["coverage_status"] = coverage.get("status")
    return out


__all__ = ["build_summary", "severity_counts"]
