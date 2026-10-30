"""Identity analysis: the IAM part of the graph (engine.md §1.1 ``iam/``, §4; engine-api.md §5).

This package module registers the E-core identity analyzers (engine-api.md §5 ``ANALYZERS``):

* ``permission-map`` (phase PRINCIPALS): the d13c215-shaped permission map, built from the IAM loader's data with
  managed policies resolved **by ARN** (F-013); it is written as the legacy output ``permission_map.json`` with
  policy names restored (plus ``attached_policy_arns``).
* ``iam-graph`` (PRINCIPALS): user, role, group and managed-policy nodes (ARN ids exactly as collected, F-039)
  with ``props.attached_policies_status`` / ``attached_policies_error`` (F-006), entry points (users with
  credentials, or unknown credentials), coverage gaps such as ``iam:inline-unknown`` (F-053/F-111), and the
  MEMBER_OF (user → group), HAS_POLICY and HAS_BOUNDARY edges that d13c215 derived in the dashboard (F-007).
* ``admin-equivalence`` (IDENTITY): IS_ADMIN_EQUIVALENT edges into the account-admin node and
  ``props.high_value`` on admin-equivalent principals, by the policy evaluator when available and otherwise by
  the AdministratorAccess **ARN** (never by policy name) or an unconditioned ``Allow *:*`` statement.

The evaluator itself is built by ``iam/principals.py`` (analyzer ``principals``, engine-api.md §4).
"""

from __future__ import annotations

import copy
import logging
from typing import Any, Dict, List, Mapping, Optional, Tuple

from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.model import AnalyzerSkipped, AnalyzerSpec, Capability, Phase

log = logging.getLogger(__name__)

ADMIN_POLICY_SUFFIX = ":iam::aws:policy/AdministratorAccess"
#: Coverage-facet status of an entity whose attachments were readable.
_GAP_STATUS = {"denied": "partial", "error": "partial", "throttled": "partial", "not-collected": "partial"}


def iam_data(ctx: Any) -> Any:
    """The IAM loader's data, or :class:`AnalyzerSkipped` when IAM was not collected."""
    data = (ctx.data or {}).get("iam")
    if data is None or getattr(data, "layout", "missing") == "missing":
        raise AnalyzerSkipped("iam.authorization_details", reason="IAM data was not collected")
    return data


# ── permission map (legacy view, F-013) ──────────────────────────────────────

def run_permission_map(ctx: Any, builder: Any) -> None:
    from aws_enumerator.engine.iam.principals import _build_permission_map
    from aws_enumerator.engine.io.loaders.iam import legacy_permission_inputs, restore_policy_names

    iam = iam_data(ctx)
    pmap = _build_permission_map(*legacy_permission_inputs(iam))
    ctx.shared["permission_map"] = pmap
    ctx.shared["policy_names"] = {arn: p.name for arn, p in iam.policies.items()}
    ctx.set_legacy_output("permission_map.json", restore_policy_names(copy.deepcopy(pmap), iam))


def permission_map(ctx: Any) -> Dict[str, Any]:
    """The legacy permission map built by ``permission-map`` (empty tables when it did not run)."""
    return ctx.shared.get("permission_map") or {"users": {}, "roles": {}, "groups": {}}


# ── IAM nodes and structural edges ───────────────────────────────────────────

def _coverage_status(base: str, ent: Any) -> str:
    from aws_enumerator.engine.io.coverage import worst

    statuses = [base]
    if ent.attached_status != "complete":
        statuses.append(_GAP_STATUS.get(ent.attached_status, "partial"))
    if ent.gaps or ent.inline_status != "complete":
        statuses.append("partial")
    return worst(statuses)


def _entity_gaps(ent: Any) -> List[str]:
    gaps = set(ent.gaps)
    if ent.attached_status != "complete":
        gaps.add(f"iam:attached-policies:{ent.attached_status}")
    if ent.inline_status not in ("complete", "partial"):
        gaps.add("iam:inline-unknown")
    return sorted(gaps)


def _entity_props(ent: Any) -> Dict[str, Any]:
    props: Dict[str, Any] = {
        "path": ent.path,
        "attached_policies_status": ent.attached_status,
        "attached_policies_error": ent.attached_error,
    }
    if ent.kind == "user" and ent.has_credentials is not False and ent.record:
        props["entry_point"] = True
        props["credentials"] = "unknown" if ent.has_credentials is None else "present"
    if ent.kind == "role" and ent.path.startswith("/aws-service-role/"):
        props["service_linked"] = True
    if not ent.record:
        props["placeholder"] = True
    if ent.boundary_arn:
        props["permissions_boundary"] = ent.boundary_arn
    return props


def _add_policy_nodes(builder: Any, iam: Any) -> None:
    for arn in sorted(iam.policies):
        pol = iam.policies[arn]
        builder.add_node(arn, "policy", pol.name, props={
            "aws_managed": pol.aws_managed, "default_version": pol.default_version,
            "versions_collected": len(pol.versions), "document_status": pol.document_status})


def _ensure_policy(builder: Any, arn: str) -> Optional[str]:
    if builder.has_node(arn):
        return arn
    if not ids.node_id_matches("policy", arn):
        return None
    builder.add_node(arn, "policy", arn.rsplit("/", 1)[-1], props={"placeholder": True},
                     coverage_status="not-collected")
    return arn


def _add_entity_nodes(ctx: Any, builder: Any, iam: Any) -> None:
    base = ctx.coverage.module_status("iam", "global")
    for ent in iam.entities():
        if not ids.node_id_matches(ent.kind, ent.arn):
            log.warning("skipping IAM %s with an unusable ARN", ent.kind)
            continue
        builder.add_node(ent.arn, ent.kind, ent.name, props=_entity_props(ent), tags=ent.tags,
                         coverage_status="not-collected" if not ent.record else _coverage_status(base, ent),
                         coverage_gaps=_entity_gaps(ent))


def _add_structural_edges(builder: Any, iam: Any) -> None:
    for user in iam.entities("user"):
        for garn in user.groups:
            if builder.has_node(garn) and builder.has_node(user.arn):
                builder.add_edge(user.arn, "MEMBER_OF", garn, holds=user.boundary_arn is None,
                                 evidence={"reduced_by": "permissions-boundary"} if user.boundary_arn else None)
    for ent in iam.entities():
        if not builder.has_node(ent.arn):
            continue
        for parn in ent.attached:
            if _ensure_policy(builder, parn):
                builder.add_edge(ent.arn, "HAS_POLICY", parn)
        if ent.boundary_arn and ent.kind in ("user", "role") and _ensure_policy(builder, ent.boundary_arn):
            builder.add_edge(ent.arn, "HAS_BOUNDARY", ent.boundary_arn)


def _add_identity_providers(builder: Any, iam: Any) -> None:
    """IdP nodes for the account's OIDC and SAML providers (GAAD layout, F-110)."""
    from aws_enumerator.engine.graph.builder import idp_provider

    for kind in ("oidc", "saml"):
        for rec in iam.identity_providers.get(kind) or ():
            arn = rec.get("Arn") if isinstance(rec, Mapping) else None
            if not isinstance(arn, str) or not ids.node_id_matches("idp", arn):
                continue
            label = str(rec.get("Url") or arn.rsplit("/", 1)[-1])
            props: Dict[str, Any] = {"provider": idp_provider(arn)}
            if kind == "oidc" and isinstance(rec.get("ClientIDList"), list):
                props["client_ids"] = sorted(str(c) for c in rec["ClientIDList"])
            builder.add_node(arn, "idp", label, props=props)


def _policy_collisions(builder: Any, iam: Any) -> None:
    """IAM-POLICY-COLLISION-001: a customer policy shares its name with another managed policy (F-013)."""
    for name, arns in sorted(iam.name_collisions.items()):
        for arn in arns:
            if ":iam::aws:policy/" in arn or not builder.has_node(arn):
                continue
            builder.add_finding(
                "IAM-POLICY-COLLISION-001", arn, severity="INFO", discriminator=name,
                title=f"Customer policy shares the name {name!r} with another managed policy",
                description="Policies are keyed by ARN, so the analysis is not affected; reviews and tools that "
                            "match policies by name can be misled.",
                evidence={"policy_arns": list(arns)}, related_node_ids=[a for a in arns if a != arn])


def run_iam_graph(ctx: Any, builder: Any) -> None:
    iam = iam_data(ctx)
    _add_policy_nodes(builder, iam)
    _policy_collisions(builder, iam)
    _add_identity_providers(builder, iam)
    _add_entity_nodes(ctx, builder, iam)
    _add_structural_edges(builder, iam)
    if iam.layout == "legacy":
        ctx.add_gap("iam:legacy-layout", "IAM was collected per entity (d13c215 layout): no policy versions, "
                    "identity providers or credential report; permissions boundaries may be missing.")


# ── admin equivalence ────────────────────────────────────────────────────────

def entity_documents(iam: Any, ent: Any) -> List[Tuple[str, Any]]:
    """``(source, document)`` of the entity's own identity policies (attached default versions, inline)."""
    out: List[Tuple[str, Any]] = []
    for arn in ent.attached:
        pol = iam.policies.get(arn)
        if pol is not None and pol.document is not None:
            out.append((arn, pol.document))
    out.extend((f"inline:{name}", doc) for name, doc in sorted(ent.inline.items()))
    return out


def identity_statements(iam: Any, ent: Any, *, groups: bool = False, partition: str = "aws") -> List[Any]:
    """The parsed statements of ``ent``'s own identity policies (plus its groups' with ``groups``), for the
    statement-level fallbacks used when the evaluator is unavailable (parsing lives in ``engine/policy``, R-13)."""
    from aws_enumerator.engine.policy.parse import parse_policy

    owners = [(ent, None)]
    if groups:
        owners += [(iam.groups[g], g) for g in ent.groups if g in iam.groups]
    out: List[Any] = []
    for owner, via in owners:
        for src, doc in entity_documents(iam, owner):
            arn = src if src.startswith("arn:") else None
            out.extend(parse_policy(doc, layer="identity", source_type="managed" if arn else "inline",
                                    policy_arn=arn, policy_name=None if arn else src, via_group=via,
                                    partition=partition).statements)
    return out


def unmodelled_restrictions(iam: Any, ent: Any) -> List[str]:
    """Reasons a statement-level match may not be a definite grant without the evaluator."""
    reasons = []
    if ent.boundary_arn:
        reasons.append("permissions-boundary")
    if any(s.effect == "Deny" for s in identity_statements(iam, ent)):
        reasons.append("deny-statement")
    if ent.gaps or ent.attached_status != "complete":
        reasons.append("incomplete-policies")
    return reasons


def _star_sources(iam: Any, ent: Any) -> List[str]:
    from aws_enumerator.engine.policy.apply import allows_everything

    return sorted({s.source.policy_arn or s.source.policy_name or "unknown"
                   for s in identity_statements(iam, ent) if allows_everything(s)})


def _fallback_admin(iam: Any, ent: Any) -> Optional[Dict[str, Any]]:
    by_arn = sorted(a for a in ent.attached if a.endswith(ADMIN_POLICY_SUFFIX))
    stars = _star_sources(iam, ent)
    if not by_arn and not stars:
        return None
    restrictions = unmodelled_restrictions(iam, ent)
    return {"confidence": "conditional" if restrictions else "definite", "strength": "weak",
            "evidence": {"basis": "policy-arn" if by_arn else "allow-star-statement", "policies": by_arn or stars,
                         "gaps": ["evaluator-unavailable"] + restrictions if restrictions else []}}


def _evaluator_admin(ctx: Any, ent: Any) -> Optional[Dict[str, Any]]:
    result = ctx.evaluator.evaluate_capability(ent.arn, Capability(resource_template="*", action_glob="*"))
    if not result.decision.grants:
        return {"denied": True}
    return {"result": result, "evidence": {"basis": "evaluator"}}


def admin_decision(ctx: Any, iam: Any, ent: Any) -> Optional[Dict[str, Any]]:
    """How ``ent`` is admin-equivalent (``None``: it is not). The evaluator decides when it is available."""
    if ctx.evaluator is not None and ent.kind in ("user", "role"):
        try:
            decision = _evaluator_admin(ctx, ent)
            return None if decision.get("denied") else decision
        except Exception as exc:  # noqa: BLE001 - an evaluator defect must not lose the identity analysis
            log.warning("evaluator failed for an admin probe (%s); using the statement fallback",
                        type(exc).__name__)
            ctx.add_gap("evaluator-error", "The policy evaluator failed for some decisions; statement-level "
                        "fallbacks were used.", 1)
    return _fallback_admin(iam, ent)


def run_admin_equivalence(ctx: Any, builder: Any) -> None:
    iam = iam_data(ctx)
    admin = ids.account_admin_id(ctx.account_id)
    for ent in iam.entities():
        if not builder.has_node(ent.arn) or not ent.record:
            continue
        decision = admin_decision(ctx, iam, ent)
        if decision is None:
            continue
        result = decision.get("result")
        conf = "conditional" if result is not None and result.confidence == "conditional" else \
            decision.get("confidence", "definite")
        builder.add_edge(ent.arn, "IS_ADMIN_EQUIVALENT", admin, result=result,
                         confidence=None if result is not None else conf,
                         strength=None if result is not None else decision.get("strength"),
                         evidence={k: v for k, v in decision["evidence"].items() if v})
        if conf == "definite":
            builder.set_node_props(ent.arn, high_value=True, high_value_reason="admin-equivalent")


ANALYZERS: Tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec("permission-map", Phase.PRINCIPALS, run_permission_map, inputs=("iam.authorization_details",),
                 legacy_files=("permission_map.json",)),
    AnalyzerSpec("iam-graph", Phase.PRINCIPALS, run_iam_graph, inputs=("iam.authorization_details",)),
    AnalyzerSpec("admin-equivalence", Phase.IDENTITY, run_admin_equivalence, inputs=("iam.authorization_details",),
                 requires=("iam-graph",)),
)

__all__ = [
    "ANALYZERS", "admin_decision", "entity_documents", "iam_data", "identity_statements", "permission_map",
    "run_admin_equivalence", "run_iam_graph", "run_permission_map", "unmodelled_restrictions",
]
