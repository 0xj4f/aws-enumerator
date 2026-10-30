"""Collection gaps as findings and node coverage (E-compute; engine.md §6.7, F-058, F-059, F-053, F-111).

d13c215 could not tell "denied" from "empty": a denied ``GetBucketPolicy`` looked exactly like a bucket without a
policy, so a public bucket read as private. The v2 collectors record every call in ``_coverage.json``
(coverage-schema.md §5); this module turns those records into what a reader sees:

* **COLLECTION-GAP-001** (INFO, catalogue core id): one finding per (failing API, unit) -- an API whose calls
  ended ``denied`` / ``error`` / ``throttled``, or were skipped by an open circuit breaker -- anchored at the
  region anchor (``aws-enumerator:region/<acct>/<region>``) or, for the global unit, the account anchor. The
  fingerprint discriminator is ``<facet>/<region>`` (finding-identity.md §2) with the API as the facet, so a
  re-run keeps the identity. The evidence names the module, the error codes, the number of calls and the
  affected resources; ``related_node_ids`` lists those that are graph nodes. A failed section (an exception
  inside the collector) is the facet ``section:<module>/<name>``; a module that failed without any recorded
  call is the facet ``module:<module>``. Deliberate skips (flags, caps) and "not configured" answers are not
  gaps.
* **Node coverage** (graph-json.md §7.2): every resource named in ``item_errors`` that is a graph node gets
  ``coverage.status = partial`` and the gap ``<api>:<status>`` -- its exposure is *unknown*, never "not public".

Legacy reports (no ``_coverage.json``) produce no COLLECTION-GAP finding: they already carry the report-level gap
``coverage-not-recorded`` and every node is ``legacy-unknown``.

The module also holds the per-item coverage helpers the other E-compute analyzers share
(:func:`item_coverage`, :func:`register_policy`).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.io.coverage import COVERAGE_FILE
from aws_enumerator.engine.io.fs import ls_sorted, read_json
from aws_enumerator.engine.model import AnalyzerSkipped, AnalyzerSpec, Phase

log = logging.getLogger(__name__)

FINDING_ID = "COLLECTION-GAP-001"
#: Call statuses that leave data unknown (``ok`` with a code is "not configured", never a gap).
GAP_STATUSES = frozenset({"denied", "error", "throttled"})
#: Skips caused by an open breaker are gaps; explicit skips (flags, caps, partitions) are not.
BREAKER_PREFIX = "CircuitOpen"
#: ``PolicyStatus`` values that mean "the policy could not be read" (coverage-schema.md §1).
UNKNOWN_POLICY = frozenset({"denied", "error", "skipped"})
_MAX_RESOURCES = 25
_SKIP_DIRS = frozenset({"analysis", "analysis.tmp", "analysis.prev", "analysis.orig"})


# ── per-item coverage (shared by the E-compute analyzers) ────────────────────

def item_coverage(record: Mapping[str, Any], *, legacy: bool = False,
                  policy_api: Optional[str] = None) -> Tuple[Optional[str], List[str]]:
    """``(node coverage status, gap codes)`` of one collected item (coverage-schema.md §1).

    ``CollectionErrors`` entries and a ``PolicyStatus`` of denied / error / skipped make the node ``partial``
    with the gaps ``<api>:<status>``; a legacy record is ``legacy-unknown``; otherwise ``(None, [])`` (the
    builder's default, ``complete``).
    """
    gaps = set()
    for err in record.get("CollectionErrors") or ():
        if isinstance(err, Mapping) and err.get("api"):
            gaps.add(f"{err['api']}:{err.get('status') or 'error'}")
    status = record.get("PolicyStatus")
    if policy_api and status in UNKNOWN_POLICY:
        gaps.add(f"{policy_api}:{status}")
    if gaps:
        return "partial", sorted(gaps)
    return ("legacy-unknown", []) if legacy else (None, [])


def policy_state(policy: Any, status: Any) -> str:
    """``present`` / ``absent`` / ``unknown`` of a collected resource policy.

    ``PolicyStatus`` decides when it is recorded; a legacy record (no status) is ``present`` with a document and
    ``unknown`` without one, because d13c215 wrote the same ``null`` for "no policy" and "could not read it"
    (F-059). A document that is not JSON (``{"_raw": ...}``) is unreadable, hence ``unknown``.
    """
    readable = isinstance(policy, Mapping) and "_raw" not in policy and bool(policy)
    if status == "present":
        return "present" if readable else "unknown"
    if status == "absent":
        return "absent"
    if status in UNKNOWN_POLICY:
        return "unknown"
    return "present" if readable else "unknown"


def register_policy(evaluator: Any, resource_arn: str, policy: Any, status: Any, *, owner: Optional[str],
                    layer: str = "resource") -> str:
    """Register a collected resource policy in the evaluator's index (requests/e-policy-1.md item 2).

    Returns the :func:`policy_state`. ``unknown`` marks the resource so a cross-account decision on it is
    conditional (``resource-policy-unknown``) instead of "not shared".
    """
    state = policy_state(policy, status)
    index = getattr(evaluator, "resources", None)
    if index is None:
        return state
    if state == "present":
        index.add(resource_arn, dict(policy), layer=layer, owner=owner)
    elif state == "absent":
        index.mark_absent(resource_arn, layer=layer)
        if owner:
            index.set_owner(resource_arn, owner)
    else:
        index.mark_unknown(resource_arn, layer=layer)
        if owner:
            index.set_owner(resource_arn, owner)
    return state


def is_legacy(ctx: Any) -> bool:
    """True for an old report (no ``_coverage.json``): node coverage is ``legacy-unknown``."""
    return getattr(getattr(ctx, "coverage", None), "source", "legacy-unknown") == "legacy-unknown"


# ── COLLECTION-GAP-001 ───────────────────────────────────────────────────────

@dataclass
class Gap:
    """One failing facet of one unit, accumulated over the module's call rows and item errors."""

    module: str
    unit: str
    facet: str
    statuses: Dict[str, int] = field(default_factory=dict)
    codes: set = field(default_factory=set)
    optional: bool = True
    resources: set = field(default_factory=set)

    def add_rows(self, status: str, count: int, code: Optional[str], optional: bool) -> None:
        self.statuses[status] = self.statuses.get(status, 0) + max(int(count or 1), 1)
        if code:
            self.codes.add(str(code))
        self.optional = self.optional and optional

    @property
    def status(self) -> str:
        for s in ("denied", "throttled", "error", "skipped"):
            if s in self.statuses:
                return s
        return "error"


def _is_gap_row(row: Mapping[str, Any]) -> bool:
    if row.get("not_configured"):
        return False
    status = str(row.get("status"))
    if status in GAP_STATUSES:
        return True
    return status == "skipped" and str(row.get("error_code") or "").startswith(BREAKER_PREFIX)


def _module_gaps(module: str, unit: str, doc: Mapping[str, Any]) -> Dict[str, Gap]:
    gaps: Dict[str, Gap] = {}
    for row in doc.get("calls") or ():
        if isinstance(row, Mapping) and row.get("api") and _is_gap_row(row):
            api = str(row["api"])
            gaps.setdefault(api, Gap(module, unit, api)).add_rows(
                str(row.get("status")), row.get("count") or 1, row.get("error_code"), bool(row.get("optional")))
    for err in doc.get("item_errors") or ():
        if isinstance(err, Mapping) and err.get("api") in gaps and err.get("resource"):
            gaps[str(err["api"])].resources.add(str(err["resource"]))
    for sec in doc.get("sections") or ():
        if isinstance(sec, Mapping) and sec.get("status") == "error":
            facet = f"section:{module}/{sec.get('name')}"
            gaps.setdefault(facet, Gap(module, unit, facet)).add_rows(
                "error", 1, sec.get("error_code") or sec.get("error_type"), False)
    if not gaps and str(doc.get("status")) in ("failed", "denied"):
        err = doc.get("error") if isinstance(doc.get("error"), Mapping) else {}
        facet = f"module:{module}"
        gaps[facet] = Gap(module, unit, facet)
        gaps[facet].add_rows("error" if doc.get("status") == "failed" else "denied", 1, err.get("code"), False)
    return gaps


def collect_gaps(units: Mapping[str, Path]) -> List[Gap]:
    """Every gap of every module directory of the analysed units (sorted, deterministic)."""
    out: List[Gap] = []
    for unit in sorted(units):
        base = Path(units[unit])
        for name in ls_sorted(base):
            if name in _SKIP_DIRS or not (base / name).is_dir():
                continue
            res = read_json(base / name / COVERAGE_FILE)
            if not res.ok or not isinstance(res.data, Mapping):
                continue
            module = str(res.data.get("module") or name)
            gaps = _module_gaps(module, unit, res.data)
            out.extend(gaps[k] for k in sorted(gaps))
    return out


def _units(ctx: Any) -> Dict[str, Path]:
    units: Dict[str, Path] = {"global": Path(ctx.global_dir)}
    for region, path in sorted(ctx.region_dirs.items()):
        if Path(path) != Path(ctx.global_dir):
            units[region] = Path(path)
    return units


def _node_for_resource(builder: Any, resource: str) -> Optional[str]:
    if builder.has_node(resource):
        return resource
    if ":lambda:" in resource and ":function:" in resource:
        try:
            base = ids.lambda_unqualified(resource)[0]
        except ValueError:
            return None
        return base if builder.has_node(base) else None
    return None


def _anchor(ctx: Any, unit: str) -> str:
    if unit == "global":
        return ids.account_anchor_id(ctx.account_id)
    return ids.region_anchor_id(ctx.account_id, unit)


def emit_gap(ctx: Any, builder: Any, gap: Gap) -> str:
    """One COLLECTION-GAP-001 finding (module docstring)."""
    region = None if gap.unit == "global" else gap.unit
    resources = sorted(gap.resources)
    related = sorted({n for n in (_node_for_resource(builder, r) for r in resources) if n})
    where = "the global services" if region is None else region
    calls = sum(gap.statuses.values())
    status = gap.status
    title = f"Collection gap: {gap.facet} {status} in {where}"
    description = (f"{calls} call(s) of {gap.facet} ({gap.module}) ended {status} in {where}"
                   + (f" ({', '.join(sorted(gap.codes))})" if gap.codes else "")
                   + ". The data these calls provide is unknown: resources that depend on it may be exposed or "
                     "shared even though no finding says so (unknown, not absent).")
    evidence = {"module": gap.module, "facet": gap.facet, "status": status, "calls": calls,
                "statuses": dict(sorted(gap.statuses.items())), "error_codes": sorted(gap.codes),
                "optional_call": gap.optional, "affected_resources": resources[:_MAX_RESOURCES],
                "affected_resource_count": len(resources)}
    return builder.add_finding(FINDING_ID, _anchor(ctx, gap.unit), severity="INFO", title=title,
                               description=description, evidence=evidence,
                               discriminator=f"{gap.facet}/{gap.unit}", region=region,
                               related_node_ids=related, gaps=[f"{gap.facet}:{status}"])


def annotate_nodes(builder: Any, gaps: Iterable[Gap]) -> int:
    """Node coverage ``partial`` + ``<api>:<status>`` for every failing item that is a node (F-059)."""
    count = 0
    for gap in gaps:
        for resource in sorted(gap.resources):
            node_id = _node_for_resource(builder, resource)
            node = builder.node(node_id) if node_id else None
            if node is None:
                continue
            builder.add_node(node_id, node.type, node.label, coverage_status="partial",
                             coverage_gaps=[f"{gap.facet}:{gap.status}"])
            count += 1
    return count


def run_coverage_gaps(ctx: Any, builder: Any) -> None:
    """Analyzer ``coverage-gaps`` (phase POSTPROCESS, after every node exists)."""
    if is_legacy(ctx):
        raise AnalyzerSkipped("coverage", reason="the report predates _coverage.json (coverage-not-recorded)")
    gaps = collect_gaps(_units(ctx))
    for gap in gaps:
        emit_gap(ctx, builder, gap)
    annotated = annotate_nodes(builder, gaps)
    log.debug("coverage-gaps: %d gaps, %d nodes annotated", len(gaps), annotated)


ANALYZERS: Tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec("coverage-gaps", Phase.POSTPROCESS, run_coverage_gaps),
)

#: COLLECTION-GAP-001 is a core catalogue id (findings/catalog.py); this module declares no new one.
FINDINGS: Tuple[Any, ...] = ()

__all__ = [
    "ANALYZERS", "FINDINGS", "FINDING_ID", "Gap", "annotate_nodes", "collect_gaps", "emit_gap", "is_legacy",
    "item_coverage", "policy_state", "register_policy", "run_coverage_gaps",
]
