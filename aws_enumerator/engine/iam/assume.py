"""Role assumption as edges (engine.md §4.2-§4.3; F-036, F-020, F-039, F-072).

d13c215 drew CAN_ASSUME in the dashboard only when a trust principal was **exactly** an enumerated user or
role ARN: same-account ``:root`` trusts, cross-account trusts and federated trusts produced no edge, and
``CAN_ASSUME_CROSS`` was unreachable (F-036). Here every classified trust grant (``iam/trust.py``) becomes an
edge in the attack direction:

=====================================  =======================================================================
trusted principal                      edge
=====================================  =======================================================================
same-account user/role ARN             ``P -CAN_ASSUME-> R`` (a placeholder node when P was not collected)
same-account ``:root`` / bare id       ``P -CAN_ASSUME-> R`` for every local user/role P whose identity
                                       policies allow ``sts:AssumeRole`` on R (the evaluator decides)
foreign account / principal            ``external -CAN_ASSUME-> R``, conditional, ``external-identity-unknown``
``*``                                  ``anonymous -CAN_ASSUME-> R``, graded by condition strength (F-021)
service                                ``svc -SERVICE_CAN_ASSUME-> R`` (info)
OIDC / web identity provider           ``idp -CAN_ASSUME_WEB_IDENTITY-> R`` (``props.admits``); a GitHub trust
                                       admitting any repository also gets ``anonymous -> R`` (F-020)
SAML provider                          ``idp -CAN_ASSUME_SAML-> R``
=====================================  =======================================================================

A trust ``Deny`` that removes the principal suppresses the edge; a conditional one makes it conditional (F-073).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.iam import iam_data, identity_statements, unmodelled_restrictions
from aws_enumerator.engine.iam.trust import TrustGrant, trust_model
from aws_enumerator.engine.model import AnalyzerSpec, Phase

log = logging.getLogger(__name__)

_ASSUME_SOURCES = frozenset({"user", "role", "external_account", "external_principal", "anonymous"})
_STRENGTHS = ("none", "weak", "strong")


def _stronger(a: str, b: str) -> str:
    return a if _STRENGTHS.index(a) >= _STRENGTHS.index(b) else b


def _trust_evidence(g: TrustGrant, **extra: Any) -> Dict[str, Any]:
    ev: Dict[str, Any] = {"trust_statement": g.statement_index, "actions": list(g.actions)}
    if g.denied == "conditional":
        ev["trust_deny"] = "conditional"
    ev.update({k: v for k, v in extra.items() if v})
    return ev


def _trust_confidence(g: TrustGrant) -> Tuple[str, str]:
    """(confidence, strength) of what the trust policy alone allows."""
    if g.strength != "none":
        return "conditional", g.strength
    if g.denied == "conditional":
        return "conditional", "weak"
    return "definite", "none"


# ── same-account principals ──────────────────────────────────────────────────

def _evaluate(ctx: Any, caller: str, role_arn: str) -> Optional[Any]:
    """The evaluator's ``can_assume`` decision, or ``None`` when it is unavailable or failed."""
    if ctx.evaluator is None:
        return None
    try:
        return ctx.evaluator.can_assume(caller, role_arn)
    except Exception as exc:  # noqa: BLE001 - fall back to the trust/statement view, never lose the edge
        log.warning("evaluator failed for an AssumeRole decision (%s)", type(exc).__name__)
        ctx.add_gap("evaluator-error", "The policy evaluator failed for some decisions; statement-level "
                    "fallbacks were used.", 1)
        return None


def _explicit(ctx: Any, builder: Any, g: TrustGrant) -> None:
    ref = builder.ensure_principal(g.principal, principal_type="AWS")
    if ref.node_id is None or builder.node(ref.node_id).type not in _ASSUME_SOURCES:
        return
    if ref.node_id == g.role_arn:
        return
    result = _evaluate(ctx, ref.node_id, g.role_arn)
    if result is not None:
        if result.decision.grants:
            builder.add_edge(ref.node_id, "CAN_ASSUME", g.role_arn, result=result,
                             evidence=_trust_evidence(g, basis="evaluator", trust="explicit-principal"))
        return
    conf, stren = _trust_confidence(g)
    builder.add_edge(ref.node_id, "CAN_ASSUME", g.role_arn, confidence=conf, strength=stren,
                     evidence=_trust_evidence(g, basis="trust-policy", trust="explicit-principal"))


def _statement_allows_assume(ctx: Any, iam: Any, ent: Any, role_arn: str) -> List[str]:
    """Sources of the Allow statements (own and group policies) naming ``sts:AssumeRole`` on ``role_arn``: the
    statement-level view, used only when the evaluator is unavailable (``policy.apply.allow_sources``, R-13)."""
    from aws_enumerator.engine.model import RequestContext
    from aws_enumerator.engine.policy.apply import allow_sources
    from aws_enumerator.engine.policy.parse import request_principal

    request = RequestContext(request_principal(ent.arn, partition=ctx.partition), {})
    return allow_sources(identity_statements(iam, ent, groups=True, partition=ctx.partition), "sts:AssumeRole",
                         role_arn, request)


def _root_delegation(ctx: Any, builder: Any, g: TrustGrant) -> None:
    iam = iam_data(ctx)
    for ent in iam.entities("user") + iam.entities("role"):
        if ent.arn == g.role_arn or not builder.has_node(ent.arn) or not ent.record:
            continue
        result = _evaluate(ctx, ent.arn, g.role_arn)
        if result is not None:
            if result.decision.grants:
                builder.add_edge(ent.arn, "CAN_ASSUME", g.role_arn, result=result,
                                 evidence=_trust_evidence(g, basis="evaluator", trust="account-root"))
            continue
        sources = _statement_allows_assume(ctx, iam, ent, g.role_arn)
        if not sources:
            continue
        conf, stren = _trust_confidence(g)
        gaps = unmodelled_restrictions(iam, ent)
        if gaps:
            conf, stren = "conditional", _stronger(stren, "weak")
        builder.add_edge(ent.arn, "CAN_ASSUME", g.role_arn, confidence=conf, strength=stren,
                         evidence=_trust_evidence(g, basis="identity-statement", trust="account-root",
                                                  identity_sources=sources,
                                                  gaps=["evaluator-unavailable"] + gaps if gaps else None))


# ── other principals ─────────────────────────────────────────────────────────

def _wildcard(builder: Any, g: TrustGrant) -> None:
    conf, stren = _trust_confidence(g)
    builder.add_edge(ids.ANONYMOUS_ID, "CAN_ASSUME", g.role_arn, confidence=conf, strength=stren,
                     evidence=_trust_evidence(g, trust="wildcard"), props={"auth": "any-aws-account"})


def _cross_account(builder: Any, g: TrustGrant) -> None:
    ref = builder.ensure_principal(g.principal, principal_type="AWS")
    if ref.node_id is None or builder.node(ref.node_id).type not in _ASSUME_SOURCES:
        return
    _conf, stren = _trust_confidence(g)
    builder.add_edge(ref.node_id, "CAN_ASSUME", g.role_arn, confidence="conditional", strength=stren,
                     evidence=_trust_evidence(g, trust=g.category, guard=g.guard, gaps=["external-identity-unknown"]),
                     props={"cross_account": True})


def _service(builder: Any, g: TrustGrant) -> None:
    ref = builder.ensure_principal(g.principal, principal_type="Service")
    if ref.node_id is not None:
        builder.add_edge(ref.node_id, "SERVICE_CAN_ASSUME", g.role_arn, evidence=_trust_evidence(g))


_ADMITS_CONFIDENCE = {"any": ("definite", "none"), "pattern": ("conditional", "weak"),
                      "specific": ("conditional", "strong")}


def _federated(builder: Any, g: TrustGrant) -> None:
    ref = builder.ensure_principal(g.principal, principal_type="Federated")
    if ref.node_id is None:
        return
    if g.provider == "saml":
        conf, stren = _trust_confidence(g)
        builder.add_edge(ref.node_id, "CAN_ASSUME_SAML", g.role_arn, confidence=conf, strength=stren,
                         evidence=_trust_evidence(g, provider="saml"))
        return
    admits = g.admits or "any"
    conf, stren = _ADMITS_CONFIDENCE[admits]
    if g.denied == "conditional":
        conf, stren = "conditional", _stronger(stren, "weak")
    builder.add_edge(ref.node_id, "CAN_ASSUME_WEB_IDENTITY", g.role_arn, confidence=conf, strength=stren,
                     evidence=_trust_evidence(g, provider=g.provider), props={"admits": admits})
    if g.provider == "github" and admits == "any":
        builder.add_edge(ids.ANONYMOUS_ID, "CAN_ASSUME_WEB_IDENTITY", g.role_arn, confidence=conf, strength=stren,
                         evidence=_trust_evidence(g, provider="github"),
                         props={"admits": "any", "technique": "github-oidc-any-repository"})


def emit_assume_edges(ctx: Any, builder: Any) -> int:
    """Add every assume edge of the trust model; returns the number of grants considered."""
    model = trust_model(ctx, builder)
    count = 0
    for g in model.grants:
        if g.denied == "yes" or not builder.has_node(g.role_arn):
            continue
        handler = {
            "wildcard": lambda grant: _wildcard(builder, grant),
            "same-account-principal": lambda grant: _explicit(ctx, builder, grant),
            "same-account-root": lambda grant: _root_delegation(ctx, builder, grant),
            "cross-account-root": lambda grant: _cross_account(builder, grant),
            "cross-account-principal": lambda grant: _cross_account(builder, grant),
            "service": lambda grant: _service(builder, grant),
            "federated": lambda grant: _federated(builder, grant),
        }.get(g.category)
        if handler is not None:
            handler(g)
            count += 1
    return count


def run_assume(ctx: Any, builder: Any) -> None:
    """Analyzer ``assume`` (phase IDENTITY)."""
    iam_data(ctx)
    emit_assume_edges(ctx, builder)


ANALYZERS: Tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec("assume", Phase.IDENTITY, run_assume, inputs=("iam.roles",), requires=("iam-graph",)),
)

__all__ = ["ANALYZERS", "emit_assume_edges", "run_assume"]
