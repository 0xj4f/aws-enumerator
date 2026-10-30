"""Finding lifecycle in the POSTPROCESS phase: suppression and baseline comparison (F-143).

* :func:`apply_suppressions` marks matching findings ``status: "suppressed"`` (they stay in every output and
  are excluded from severity counts and ``max_severity``) and turns each expired entry into an INFO
  ``SUPPRESSION-EXPIRED-001`` at the account anchor (finding-identity.md §5);
* :func:`apply_baseline` compares fingerprints with a previous ``findings.json``, sets ``baseline_state`` on
  every current finding and returns the ``diff.json`` document (finding-identity.md §4). A finding that
  disappeared while its inputs became incomplete is ``unknown``, never ``resolved``: a missing permission must
  not look like a fix.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from aws_enumerator.engine.findings import baseline as _baseline
from aws_enumerator.engine.findings import suppress as _suppress
from aws_enumerator.engine.graph import ids

log = logging.getLogger(__name__)

_INCOMPLETE = frozenset({"partial", "denied", "error", "throttled", "skipped", "not-collected"})


def ensure_account_anchor(builder: Any, account: str) -> str:
    """The account anchor node ``aws-enumerator:account/<acct>`` (created on first use) for account-wide findings."""
    node_id = ids.account_anchor_id(account)
    if not builder.has_node(node_id):
        builder.add_node(node_id, "account", f"Account {account}", coverage_status="not-applicable")
    return node_id


def run_date(generated_at: str) -> _dt.date:
    """The UTC date of ``run.generated_at`` (expiry is judged against it, never the wall clock)."""
    return _dt.datetime.fromisoformat(generated_at.replace("Z", "+00:00")).astimezone(_dt.timezone.utc).date()


def _entry_label(e: _suppress.Suppression) -> str:
    return f"fingerprint {e.fingerprint}" if e.fingerprint else f"{e.rule_id} on {e.node_id_glob}"


def apply_suppressions(builder: Any, entries: Sequence[_suppress.Suppression], *, account: str,
                       generated_at: str, catalog: Any = None) -> Dict[str, int]:
    """Mark suppressed findings and report expired entries; returns counts."""
    active, expired = _suppress.split_expired(entries, run_date(generated_at))
    suppressed = 0
    for f in builder.findings():
        aliases = [f.id] + list(f.legacy_ids)
        hit = _suppress.match(active, fingerprint=f.fingerprint, ids=aliases, node_id=f.node_id)
        if hit is not None:
            f.status = "suppressed"
            f.suppression = hit.to_json()
            suppressed += 1
    anchor = ensure_account_anchor(builder, account) if expired else None
    for e in expired:
        builder.add_finding(
            "SUPPRESSION-EXPIRED-001", anchor, severity="INFO", discriminator=e.key,
            title=f"Suppression entry expired on {e.expires.isoformat()}",
            description=f"The suppression for {_entry_label(e)} expired on {e.expires.isoformat()} and was ignored.",
            evidence={"match": e.match, "expires": e.expires.isoformat(), "owner": e.owner, "reason": e.reason})
    return {"suppressed": suppressed, "expired": len(expired)}


def _baseline_coverage(path: Optional[Path]) -> Optional[str]:
    """``coverage.status`` of the baseline's ``graph.json`` next to its ``findings.json`` (when there is one)."""
    if path is None:
        return None
    graph = path.parent / "graph.json"
    try:
        with open(graph, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    cov = doc.get("coverage") if isinstance(doc, Mapping) else None
    return cov.get("status") if isinstance(cov, Mapping) else None


def unknown_reason_factory(builder: Any, *, coverage_status: str, baseline_coverage: Optional[str]) -> Any:
    """``unknown_reason(previous_finding)`` for :func:`baseline.diff` (rule 2 of finding-identity.md §4)."""
    def reason(prev: Mapping[str, Any]) -> Optional[str]:
        node = builder.node(str(prev.get("node_id")))
        if node is not None and node.coverage_status in _INCOMPLETE:
            return f"node coverage is {node.coverage_status} now"
        if node is None and coverage_status != "complete" and baseline_coverage == "complete":
            return f"run coverage is {coverage_status} now (it was complete in the baseline)"
        return None
    return reason


def apply_baseline(builder: Any, baseline_doc: Mapping[str, Any], *, ref: str, baseline_path: Optional[Path],
                   coverage_status: str) -> Dict[str, Any]:
    """Set ``baseline_state`` on the current findings and return ``diff.json``."""
    current: List[Dict[str, Any]] = [f.to_json() for f in builder.findings()]
    reason = unknown_reason_factory(builder, coverage_status=coverage_status,
                                    baseline_coverage=_baseline_coverage(baseline_path))
    diff = _baseline.diff(current, baseline_doc, ref=ref, unknown_reason=reason)
    states = {rec["fingerprint"]: rec.get("baseline_state") for rec in current}
    for f in builder.findings():
        f.baseline_state = states.get(f.fingerprint)
    return diff


def load_options(baseline: Optional[str], suppress: Optional[str]) -> Dict[str, Any]:
    """Read and validate ``--baseline`` / ``--suppress`` **before** any work (usage errors, exit 64)."""
    out: Dict[str, Any] = {"suppressions": [], "baseline": None, "baseline_path": None, "baseline_ref": None}
    if suppress:
        out["suppressions"] = _suppress.load_suppressions(suppress)
    if baseline:
        out["baseline_path"] = _baseline.baseline_file(baseline)
        out["baseline"] = _baseline.load_baseline(baseline)
        out["baseline_ref"] = str(baseline)
    return out


__all__ = ["apply_baseline", "apply_suppressions", "ensure_account_anchor", "load_options", "run_date",
           "unknown_reason_factory"]
