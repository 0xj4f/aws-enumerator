"""Severity policy for rule findings (engine.md §3.3, F-068), including the closure-aware pass.

``severity = adjust(base, decision strength)`` where the base comes from the rule class and the targets:

* self-escalation (the principal modifies its own permissions, its own group or a policy attached to it):
  CRITICAL (Put*Policy and Attach*Policy alike: attaching ``AdministratorAccess`` is as direct as writing an
  inline admin policy, and Attach*Policy rules probe ``iam:PolicyARN`` with that ARN);
* modifying **another** principal's permissions or a policy held only by others: HIGH; the closure pass below
  raises it to CRITICAL when the principal can also act as the modified principal (the derived CAN_ESCALATE,
  engine.md §4.6), because then it is a complete path to the account administrator;
* every derived class (credential takeover, group membership, PassRole, existing resources) takes the
  **target tier**: CRITICAL when a target is admin-equivalent, HIGH when a target holds crown-jewel access
  (all secrets, all parameters, all keys, full S3, full Lambda or EC2) that the caller lacks, MEDIUM otherwise;
  a probe target (any principal of the kind, including ones not collected) is HIGH; a probe for a resource type
  no collector lists is MEDIUM (and conditional, so LOW);
* **closure-aware tiers**: after the closure (``graph/closure.py``), a target that reaches the account-admin node
  over traversable edges is tiered ``admin`` (definite reach) or at least ``high`` (conditional reach), so a
  PassRole to a role that can itself assume an admin role is CRITICAL, not MEDIUM;
* a PassRole rule whose chain is complete but has no qualifying role is INFO ("no passable role currently
  trusts <service>", F-012);
* a conditional decision is lowered by its strength: WEAK −1 level, STRONG −2 levels, never below INFO; the
  unadjusted value is kept in ``base_severity``.

The functions above the pipeline section are pure; :data:`ANALYZERS` registers the closure-aware pass in phase
POSTPROCESS (after CLOSURE, before ``rules/subsume.py``).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from aws_enumerator.engine.model import SEVERITIES, SEVERITY_RANK, Strength

log = logging.getLogger(__name__)

#: Target tiers, most privileged first.
TIERS = ("admin", "high", "medium")
TIER_SEVERITY = {"admin": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "probe": "HIGH", "uncollected": "MEDIUM"}
#: ``finding.targets[].tier`` (a severity) for every target tier, ``self`` included.
TARGET_TIER_SEVERITY = dict(TIER_SEVERITY, self="CRITICAL")
STRENGTH_STEPS = {Strength.NONE: 0, Strength.WEAK: 1, Strength.STRONG: 2}
#: Rule classes whose targets are principals whose permissions are modified (closure: CAN_ESCALATE).
MODIFY_CLASSES = frozenset({"policy-modification", "principal-modification"})
#: Rule classes whose severity is the tier of what is gained (closure: reach of the gained node).
DERIVED_CLASSES = frozenset({"principal-access", "group-membership", "new-passrole", "existing-passrole",
                             "existing-resource"})


def lower(severity: str, levels: int) -> str:
    """``severity`` lowered by ``levels`` (floor INFO)."""
    idx = min(SEVERITY_RANK[severity.upper()] + max(levels, 0), len(SEVERITIES) - 1)
    return SEVERITIES[idx]


def adjust(base: str, strength: Strength, *, conditional: bool) -> str:
    """Apply the conditional-decision downgrade (engine.md §3.3)."""
    return lower(base, STRENGTH_STEPS[strength]) if conditional else base.upper()


def highest(severities: Iterable[str]) -> Optional[str]:
    """The most severe of ``severities`` (``None`` for none)."""
    values = [s.upper() for s in severities]
    return min(values, key=lambda s: SEVERITY_RANK[s]) if values else None


def tier_severity(tiers: Iterable[str]) -> str:
    """Severity of the best target tier (``admin`` > ``high``/``probe`` > ``medium``)."""
    sevs = [TIER_SEVERITY.get(t, "MEDIUM") for t in tiers]
    return highest(sevs) or "MEDIUM"


def base_severity(rule_class: str, fixed: str, *, self_target: bool, tiers: Iterable[str],
                  no_candidate: bool = False) -> str:
    """Base severity of one rule hit before the conditional downgrade."""
    if no_candidate:
        return "INFO"
    tiers = list(tiers)
    if rule_class in MODIFY_CLASSES:
        return "CRITICAL" if self_target else "HIGH"
    if fixed != "derived":
        return fixed
    return tier_severity(tiers)


def closure_tier(reach: Optional[str]) -> Optional[str]:
    """The tier a target gets from its reach of the account-admin node (``None``: no change)."""
    return {"definite": "admin", "conditional": "high"}.get(reach or "")


# ── the closure-aware pass (phase POSTPROCESS) ───────────────────────────────

def _strength_of(finding: Any) -> Strength:
    value = (finding.evidence or {}).get("condition_strength")
    try:
        return Strength(value) if value else Strength.WEAK
    except ValueError:
        return Strength.WEAK


def _derived_upgrade(finding: Any, closure: Any) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    """The best closure tier over the targets of a derived-class finding, and the targets it upgrades."""
    details = (finding.evidence or {}).get("targets_detail") or []
    best: Optional[str] = None
    upgraded = []
    for d in details:
        if d.get("probe"):
            continue
        gained = d.get("role") or d.get("node_id")
        tier = closure_tier(closure.reach_of(gained))
        if tier is None or SEVERITY_RANK[TIER_SEVERITY[tier]] >= SEVERITY_RANK[str(d.get("tier", "MEDIUM"))]:
            continue
        upgraded.append({"node_id": d.get("node_id"), "gained": gained, "tier": TIER_SEVERITY[tier],
                         "reach": closure.reach_of(gained)})
        best = tier if best is None or TIERS.index(tier) < TIERS.index(best) else best
    return best, upgraded


def _modify_upgrade(finding: Any, closure: Any) -> Tuple[Optional[str], List[Dict[str, Any]]]:
    """``admin`` when the closure derived an escalation from this rule's modification edges."""
    escs = [e for e in getattr(closure, "escalations", ())
            if e.source == finding.node_id and finding.id in e.rule_ids]
    if not escs:
        return None, []
    tier = "admin" if any(e.confidence == "definite" for e in escs) else "high"
    return tier, [{"node_id": e.target, "chain": list(e.chain), "confidence": e.confidence,
                   "tier": TIER_SEVERITY[tier]} for e in escs]


def rescore_finding(finding: Any, rule_class: str, closure: Any) -> bool:
    """Raise one rule finding's severity from the closure; ``True`` when it changed."""
    if rule_class in MODIFY_CLASSES:
        tier, upgraded = _modify_upgrade(finding, closure)
    elif rule_class in DERIVED_CLASSES:
        tier, upgraded = _derived_upgrade(finding, closure)
    else:
        return False
    if tier is None:
        return False
    new_base = highest([finding.base_severity or finding.severity, TIER_SEVERITY[tier]]) or finding.severity
    conditional = finding.confidence == "conditional"
    new_sev = adjust(new_base, _strength_of(finding), conditional=conditional) if conditional else new_base
    if new_base == finding.base_severity and new_sev == finding.severity:
        return False
    finding.evidence["closure"] = {"previous_severity": finding.severity, "targets": upgraded}
    finding.base_severity, finding.severity = new_base, new_sev
    raised = {u.get("node_id"): u["tier"] for u in upgraded if u.get("node_id")}
    finding.targets = [dict(t, tier=raised.get(t.get("node_id"), t.get("tier"))) for t in finding.targets]
    return True


def rescore(builder: Any, closure: Any, rule_classes: Mapping[str, str], *, origin: str = "rules") -> int:
    """Closure-aware severity for every finding the native rules analyzer emitted; returns the change count."""
    changed = 0
    for f in builder.findings():
        if builder.finding_origin(f.fingerprint) != origin or (f.evidence or {}).get("no_candidate"):
            continue
        rule_class = rule_classes.get(f.id)
        if rule_class and rescore_finding(f, rule_class, closure):
            changed += 1
    return changed


def _run(ctx: Any, builder: Any) -> None:
    """Phase POSTPROCESS: raise rule findings whose targets reach the account admin (engine.md §3.3)."""
    from aws_enumerator.engine.model import AnalyzerSkipped
    from aws_enumerator.engine.rules.catalogue import load_catalogue

    closure = ctx.shared.get("closure")
    if closure is None:
        raise AnalyzerSkipped("closure", reason="the closure did not run")
    classes = {r.id: r.rule_class for r in load_catalogue().privesc}
    changed = rescore(builder, closure, classes)
    ctx.shared["severity.rescored"] = changed
    log.debug("closure-aware severity raised %d rule findings", changed)


def _analyzers() -> Tuple[Any, ...]:
    from aws_enumerator.engine.model import AnalyzerSpec, Phase

    return (AnalyzerSpec("severity", Phase.POSTPROCESS, _run, inputs=("iam.authorization_details",),
                         requires=("rules", "closure")),)


ANALYZERS = _analyzers()

__all__ = [
    "ANALYZERS", "DERIVED_CLASSES", "MODIFY_CLASSES", "TARGET_TIER_SEVERITY", "TIERS", "TIER_SEVERITY", "adjust",
    "base_severity", "closure_tier", "highest", "lower", "rescore", "rescore_finding", "tier_severity",
]
