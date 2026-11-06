"""Baseline comparison (``--baseline <run dir | findings.json>`` → ``analysis/diff.json``, F-143).

finding-identity.md §4:

1. findings are matched by ``fingerprint`` only (suppressed ones take part like open ones);
2. in the baseline but not now → ``resolved``, **unless** the inputs that produced it are incomplete now
   (denied, error, skipped …): then ``unknown`` with the reason, because a missing permission must never
   look like a fix;
3. now but not in the baseline → ``new``; in both → ``unchanged`` or ``severity_changed``;
4. every current finding gets ``baseline_state``;
5. a baseline of another schema major, or a pre-1.0 bare ``{"findings": [...]}``, is refused;
6. every list is sorted by (``id``, ``node_id``, ``fingerprint``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from aws_enumerator.engine.graph import DIFF_SCHEMA_VERSION
from aws_enumerator.engine.model import AnalysisUsageError

REANALYSE_HINT = "re-run `aws-enumerator analyze` on the old report first"

#: ``unknown_reason(finding) -> str | None``: why a finding missing now cannot count as resolved.
UnknownReason = Callable[[Mapping[str, Any]], Optional[str]]


def baseline_file(ref: "str | Path") -> Path:
    """The ``findings.json`` a ``--baseline`` argument names (a file, a run root or an analysed dir)."""
    p = Path(ref)
    if p.is_file():
        return p
    for candidate in (p / "analysis" / "findings.json", p / "findings.json"):
        if candidate.is_file():
            return candidate
    raise AnalysisUsageError(f"baseline {ref}: no findings.json found")


def load_baseline(ref: "str | Path") -> Dict[str, Any]:
    """Read and check a baseline ``findings.json``; raises :class:`AnalysisUsageError` when unusable."""
    path = baseline_file(ref)
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        raise AnalysisUsageError(f"baseline {path} is not readable JSON: {exc}") from None
    if not isinstance(doc, Mapping) or not isinstance(doc.get("findings"), list):
        raise AnalysisUsageError(f"baseline {path} is not a findings.json document")
    version = doc.get("schema_version")
    if not isinstance(version, str):
        raise AnalysisUsageError(f"baseline {path} predates findings.json 1.0; {REANALYSE_HINT}")
    if version.split(".", 1)[0] != "1":
        raise AnalysisUsageError(f"baseline {path} has schema_version {version}; {REANALYSE_HINT}")
    if any(not isinstance(f, Mapping) or not f.get("fingerprint") for f in doc["findings"]):
        raise AnalysisUsageError(f"baseline {path} has findings without fingerprints; {REANALYSE_HINT}")
    return dict(doc)


def _entry(f: Mapping[str, Any]) -> Dict[str, Any]:
    return {"fingerprint": f["fingerprint"], "id": f["id"], "node_id": f["node_id"], "severity": f["severity"]}


def _key(e: Mapping[str, Any]) -> tuple:
    return (str(e.get("id")), str(e.get("node_id")), str(e.get("fingerprint")))


def diff(current: Sequence[Dict[str, Any]], baseline: Mapping[str, Any], *, ref: str,
         unknown_reason: Optional[UnknownReason] = None) -> Dict[str, Any]:
    """Compare finding records; sets ``baseline_state`` on ``current`` in place; returns ``diff.json``."""
    old = {f["fingerprint"]: f for f in baseline.get("findings", [])}
    now = {f["fingerprint"]: f for f in current}
    out: Dict[str, List[Dict[str, Any]]] = {k: [] for k in ("new", "resolved", "unchanged", "severity_changed",
                                                            "unknown")}
    for fp, f in now.items():
        prev = old.get(fp)
        if prev is None:
            f["baseline_state"] = "new"
            out["new"].append(_entry(f))
        elif prev.get("severity") != f.get("severity"):
            f["baseline_state"] = "severity_changed"
            out["severity_changed"].append({"fingerprint": fp, "id": f["id"], "node_id": f["node_id"],
                                            "from": prev["severity"], "to": f["severity"]})
        else:
            f["baseline_state"] = "unchanged"
            out["unchanged"].append(_entry(f))
    for fp, prev in old.items():
        if fp in now:
            continue
        reason = unknown_reason(prev) if unknown_reason else None
        if reason:
            out["unknown"].append(dict(_entry(prev), reason=reason))
        else:
            out["resolved"].append(_entry(prev))
    for key in out:
        out[key].sort(key=_key)
    return {
        "schema_version": DIFF_SCHEMA_VERSION,
        "baseline": {"ref": ref, "schema_version": str(baseline.get("schema_version")),
                     "run_id": baseline.get("run_id"), "generated_at": baseline.get("generated_at")},
        "counts": {k: len(v) for k, v in out.items()},
        **out,
    }


__all__ = ["baseline_file", "diff", "load_baseline"]
