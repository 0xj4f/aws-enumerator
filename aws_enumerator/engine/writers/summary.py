"""``summary.json`` (finding-identity.md §6; F-074, F-061).

The d13c215 keys (``total_findings``, ``by_severity``, ``critical_count`` …) stay; ``by_severity`` always has
all five levels, ``low_count`` / ``info_count`` exist, and severity counts include **open** findings only, so
they sum to ``total_findings``. Added: suppressed / subsumed / unattached counts, the analysis status, the
per-analyzer status, the evaluation gaps, the run context, ``ignored_dirs`` (directories under the run root that
are not in the explicit region list, F-010/F-025/F-063) and the legacy edge counts per domain.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Mapping, Sequence

from aws_enumerator.engine.findings.summary import build_summary


def summary_document(graph: Mapping[str, Any], *, status: str, ignored_dirs: Sequence[str] = (),
                     legacy_edge_counts: Mapping[str, int] = None) -> Dict[str, Any]:
    """Build ``summary.json`` from a rendered ``graph.json``."""
    counts = {"nodes": len(graph["nodes"]), "edges": len(graph["edges"])}
    doc = build_summary(graph["findings"], run=graph["run"], analyzer_status=graph["analyzer_status"],
                        evaluation_gaps=graph["evaluation_gaps"], counts=counts, status=status,
                        ignored_dirs=ignored_dirs, coverage=graph["coverage"])
    doc["schema_version"] = "1.0.0"
    doc["operator"] = dict(graph["run"]["operator"])
    doc["edges_by_type"] = _count(e["type"] for e in graph["edges"])
    doc["legacy_edge_counts"] = dict(sorted((legacy_edge_counts or {}).items()))
    return doc


def _count(values: Any) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items()))


def render(doc: Mapping[str, Any]) -> bytes:
    return (json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


__all__ = ["render", "summary_document"]
