"""Sinks for rule results: the graph builder (graph.json) and the d13c215 ``findings.json`` records.

* :func:`emit_to_builder` writes one finding per :class:`~aws_enumerator.engine.rules.runner.RuleHit` and the
  hit's edges (CAN_PASS_ROLE_TO, CAN_TAKEOVER, CAN_MODIFY_PERMISSIONS_OF, CAN_ESCALATE, CAN_UPDATE_CODE,
  CAN_HIJACK, CAN_EXEC, CAN_CONNECT, CAN_MODIFY_USERDATA; engine.md §4.4), creating a missing endpoint node only
  when its id has the shape node-ids.md prescribes for its type;
* ``finding.targets`` has exactly the contract shape ``[{node_id, tier, decision}]`` with ``tier`` a severity
  (graph-json.md §9, ``requests/e-core-1.md`` item 2); the facts the contract record has no key for (ARN, the
  qualitative tier, probe flag, the role a resource runs as, PassRole trust facts) are kept in
  ``evidence.targets_detail``, so nothing is lost;
* :func:`emit_admin_edges` adds ``IS_ADMIN_EQUIVALENT`` for administrator-equivalent principals that the
  identity analyzer did not cover (groups, and principals with full IAM control plus a definite self-escalation,
  engine.md §3.4 / §4.5), so the closure and every path search see one admin target;
* :func:`legacy_finding` renders the d13c215 record (plus the new evidence keys) for ``legacy_rules``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional

from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.model import Decision, EvalResult, PrincipalModel
from aws_enumerator.engine.rules.severity import TARGET_TIER_SEVERITY

if TYPE_CHECKING:  # pragma: no cover
    from aws_enumerator.engine.rules.runner import RuleEdge, RuleHit, RulesResult

#: Node types a rule edge may point at besides principals (traversability-table.md targets of rule edges).
RESOURCE_NODE_TYPES = frozenset({"lambda", "gluedevendpoint", "gluejob", "codebuild", "cfnstack", "stackset",
                                 "sagemaker", "sagemakerdomain", "ecsservice", "ecstask", "instance",
                                 "launchtemplate"})
_PRINCIPAL_TYPES = ("user", "role", "group")


def targets_json(hit: "RuleHit") -> List[Dict[str, Any]]:
    """``finding.targets`` in the contract shape: concrete targets only, ``tier`` as a severity."""
    out: List[Dict[str, Any]] = []
    for tr in hit.targets:
        if not tr.target.node_id:
            continue
        out.append({"node_id": tr.target.node_id, "tier": TARGET_TIER_SEVERITY.get(tr.tier, "MEDIUM"),
                    "decision": tr.outcome.decision.value})
    return out


def targets_detail(hit: "RuleHit") -> List[Dict[str, Any]]:
    """Every target with the facts the contract record omits (``evidence.targets_detail``)."""
    out = []
    for tr in hit.targets:
        entry: Dict[str, Any] = {"node_id": tr.target.node_id, "arn": tr.target.arn,
                                 "tier": TARGET_TIER_SEVERITY.get(tr.tier, "MEDIUM"), "tier_class": tr.tier,
                                 "decision": tr.outcome.decision.value}
        if tr.target.probe:
            entry["probe"] = True
        if tr.target.gained_role and tr.target.gained_role != tr.target.node_id:
            entry["role"] = tr.target.gained_role
        for k, v in tr.target.meta:
            entry[k] = v
        out.append(entry)
    return out


def finding_evidence(hit: "RuleHit") -> Dict[str, Any]:
    """``evidence`` of a rule finding (engine.md §3.5)."""
    ev: Dict[str, Any] = {"decision": hit.decision.value, "steps": [dict(s) for s in hit.steps]}
    if hit.decision is Decision.CONDITIONAL:
        ev["condition_strength"] = hit.strength.value
    if hit.no_candidate:
        ev["no_candidate"] = True
        if hit.legacy.get("services"):
            ev["services"] = list(hit.legacy["services"])
    if hit.targets:
        ev["targets_detail"] = targets_detail(hit)
    if hit.rule_class:
        ev["rule_class"] = hit.rule_class
    return ev


def via_group(hit: "RuleHit") -> Optional[str]:
    """The group **every** granting statement came through (``None`` when any grant is the principal's own)."""
    groups = {g.get("via_group") for step in hit.steps for g in step.get("granted", ())
              if step.get("decision") in ("allow", "conditional")}
    return groups.pop() if len(groups) == 1 and None not in groups else None


def emit_to_builder(result: "RulesResult", builder: Any, *, rule_version: Optional[str] = None) -> None:
    """Write rule findings and edges into a :class:`~aws_enumerator.engine.graph.builder.GraphBuilder`."""
    for hit in result.hits:
        ensure_principal_node(builder, hit.principal)
        builder.add_finding(
            hit.rule_id, hit.principal.id, severity=hit.severity, title=hit.title, description=hit.description,
            remediation=hit.remediation, evidence=finding_evidence(hit), confidence=hit.confidence,
            base_severity=hit.base_severity, matched_actions=list(hit.matched_actions),
            targets=targets_json(hit), gaps=sorted(hit.gaps), via_group=via_group(hit),
            rule_version=rule_version,
            related_node_ids=sorted({t.target.node_id for t in hit.targets if t.target.node_id}
                                    | {t.target.gained_role for t in hit.targets if t.target.gained_role}))
        for edge in hit.edges:
            if ensure_edge_target(builder, edge, hit):
                builder.add_edge(edge.source, edge.edge_type, edge.target,
                                 result=EvalResult(edge.decision, strength=edge.strength), evidence=edge.evidence)


def principal_kind(principal_id: str) -> str:
    for kind in ("group", "role"):
        if f":{kind}/" in principal_id:
            return kind
    return "user"


def ensure_principal_node(builder: Any, model: PrincipalModel) -> None:
    builder.add_node(model.id, principal_kind(model.id), model.id.rsplit("/", 1)[-1])


def ensure_edge_target(builder: Any, edge: "RuleEdge", hit: "RuleHit") -> bool:
    """Make sure the edge's target node exists; ``False`` when it cannot be created with a valid id."""
    if builder.has_node(edge.target):
        return True
    if edge.target.startswith("aws-enumerator:account-admin/"):
        builder.add_node(edge.target, "account_admin", "Account administrator")
        return True
    kind = next((tr.target.kind for tr in hit.targets if tr.target.node_id == edge.target), None)
    if kind is None:
        kind = next((k for k in _PRINCIPAL_TYPES if f":{k}/" in edge.target), None)
    if kind not in RESOURCE_NODE_TYPES and kind not in _PRINCIPAL_TYPES:
        return False
    if not ids.node_id_matches(kind, edge.target):
        return False
    builder.add_node(edge.target, kind, edge.target.rsplit("/", 1)[-1].rsplit(":", 1)[-1])
    return True


def emit_admin_edges(builder: Any, admins: Mapping[str, Mapping[str, Any]], account: Optional[str]) -> int:
    """``P -IS_ADMIN_EQUIVALENT-> account-admin`` for every admin principal that has none yet; returns the count."""
    if not account:
        return 0
    admin_node = ids.account_admin_id(account)
    added = 0
    for pid in sorted(admins):
        if not builder.has_node(pid) or builder.has_edge(pid, "IS_ADMIN_EQUIVALENT", admin_node):
            continue
        basis = admins[pid]
        builder.add_edge(pid, "IS_ADMIN_EQUIVALENT", admin_node, confidence="definite",
                         evidence={"basis": basis.get("basis"), "derived_by": "rules",
                                   "rule_ids": sorted(basis.get("rule_ids") or ())})
        added += 1
    return added


def legacy_finding(hit: "RuleHit", *, entity_kind: str, entity_name: str, entity_arn: str) -> Dict[str, Any]:
    """The d13c215 ``findings.json`` dict for one hit (plus the new evidence fields)."""
    first = (hit.steps[0].get("granted") or [{}])[0] if hit.steps else {}
    resources = first.get("resources") or ([f"NOT {r}" for r in first.get("not_resources", [])])
    source = first.get("policy_name") or first.get("policy_arn") or "unknown"
    out: Dict[str, Any] = {
        "id": hit.rule_id, "severity": hit.severity,
        "category": "privilege_escalation" if hit.kind == "privesc" else "dangerous_permission",
        "title": hit.title, "entity": f"{entity_kind}/{entity_name}", "entity_arn": entity_arn,
        "description": (f"{entity_kind.title()} '{entity_name}' has {hit.title.split(':', 1)[0]} privilege "
                        f"escalation path. {hit.description}." if hit.kind == "privesc"
                        else f"{entity_kind.title()} '{entity_name}' has {hit.title}."),
        "matched_actions": list(hit.matched_actions),
        "source_policy": source, "source_type": _legacy_source_type(first.get("source_type")),
        "resource": list(resources),
        "remediation": hit.remediation,
        "base_severity": hit.base_severity, "confidence": hit.confidence,
    }
    if hit.targets:
        out["targets"] = targets_detail(hit)
    if hit.no_candidate:
        out["no_candidate"] = True
    group = via_group(hit)
    if group:
        out["via_group"] = group
    if hit.gaps:
        out["gaps"] = sorted(hit.gaps)
    out["evidence"] = finding_evidence(hit)
    return out


def _legacy_source_type(value: Optional[str]) -> str:
    if value in ("aws_managed", "managed"):
        return "managed"
    return value or "unknown"


__all__ = [
    "RESOURCE_NODE_TYPES", "emit_admin_edges", "emit_to_builder", "ensure_edge_target", "ensure_principal_node",
    "finding_evidence", "legacy_finding", "principal_kind", "targets_detail", "targets_json", "via_group",
]
