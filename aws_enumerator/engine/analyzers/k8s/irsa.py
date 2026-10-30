"""IRSA and EKS Pod Identity (E-k8s): service account → IAM role bridges, verified against the role (F-034, F-085,
F-050).

**IRSA** (``IRSA_BRIDGE`` sa → role, traversable only when ``trust-verified``). A pod gets a web-identity token
whose ``sub`` is ``system:serviceaccount:<ns>:<sa>`` and whose ``aud`` is ``sts.amazonaws.com`` (or the SA's
``eks.amazonaws.com/audience``), signed by the cluster's OIDC issuer. Whether that token may assume a role is the
role's **trust policy**, evaluated by the policy evaluator (``can_assume(provider, role, protocol="WebIdentity",
claims={<issuer>:sub, <issuer>:aud})``): Federated principal of *this* cluster's provider, the ``sub`` / ``aud``
conditions, trust Deny statements, everything else the evaluator honours (F-014). The annotation alone proves
nothing (F-034): a stale or planted annotation keeps an edge for context but it is not traversable, and
K8S-IRSA-002 (LOW) says so. The role is looked up by its **exact ARN** (F-085): a role of the same name in
another account is never the local one; a role in another account cannot be evaluated (K8S-IRSA-003, INFO).

Roles whose trust names the cluster's provider are also evaluated for **every other service account** of the
cluster (wildcard ``sub`` such as ``system:serviceaccount:*:*``, or a ``sub`` naming a service account that is
not annotated). Such an account holds no ``sts.amazonaws.com`` token unless its pods project one, so the edge is
conditional (strong): the attacker must first mint a token (TokenRequest, or a pod with a projected token).

**Pod Identity** (``POD_IDENTITY`` sa → role, same rule): an association names the role; it works only when the
role trusts ``pods.eks.amazonaws.com`` for ``sts:AssumeRole`` and ``sts:TagSession``, evaluated with the request
context the Pod Identity agent sends (``aws:SourceAccount``, ``aws:SourceArn`` = the cluster, the
``eks-cluster-*`` / ``kubernetes-*`` session tags).

**K8S-IRSA-ADMIN** (CRITICAL): a service account that holds a token for a verified bridge to an admin-equivalent
role (the ``IS_ADMIN_EQUIVALENT`` decision of the identity analysis, by exact ARN).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Set, Tuple

from aws_enumerator.engine.analyzers.k8s.cluster import oidc_issuer, role_node
from aws_enumerator.engine.analyzers.k8s.util import (
    AUDIENCE_ANNOTATION, DEFAULT_AUDIENCE, IRSA_ANNOTATION, POD_IDENTITY_AUDIENCE, ClusterView, annotation,
    cluster_views, mapping, projected_token_audiences, service_account_of, text,
)
from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.policy.parse import iter_statements

log = logging.getLogger("aws_enumerator.engine.analyzers.k8s")

POD_IDENTITY_SERVICE = "pods.eks.amazonaws.com"
UNKNOWN_TRUST_GAPS = frozenset({"trust:unknown"})


# ── verdicts ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Verdict:
    """Does the role admit the service account? ``holds`` is ``None`` when it could not be evaluated."""

    holds: Optional[bool]
    result: Any = None                     # the granting EvalResult when ``holds``
    reason: str = ""
    gaps: Tuple[str, ...] = ()

    @property
    def label(self) -> Any:
        return "unknown" if self.holds is None else self.holds


def _verdict(results: List[Any]) -> Verdict:
    """Combine the evaluator results of the actions a mechanism needs (every one must grant)."""
    gaps = tuple(sorted({g for r in results for g in r.gaps}))
    if all(r.decision.grants for r in results):
        weakest = next((r for r in results if r.decision.value == "conditional"), results[0])
        return Verdict(True, weakest, "the role's trust policy admits the service account", gaps)
    if UNKNOWN_TRUST_GAPS & set(gaps):
        return Verdict(None, None, "the role's trust policy was not collected", gaps)
    denied = [r for r in results if not r.decision.grants]
    return Verdict(False, None, f"trust policy: {denied[0].decision.value}"
                   + (f" ({denied[0].reason})" if denied[0].reason else ""), gaps)


def _guarded(ctx: Any, calls: List[Callable[[Any], Any]]) -> Verdict:
    """Run evaluator calls; an unavailable or failing evaluator makes the trust unknown, never a crash."""
    if ctx.evaluator is None:
        return Verdict(None, None, "the policy evaluator is unavailable", ("evaluator-unavailable",))
    try:
        return _verdict([call(ctx.evaluator) for call in calls])
    except Exception as exc:  # noqa: BLE001 - an evaluator defect must not lose the Kubernetes analysis
        log.warning("policy evaluator failed on a Kubernetes trust decision: %s", type(exc).__name__)
        ctx.add_gap("evaluator-error", "The policy evaluator failed for some decisions; they are reported as "
                    "unknown.", 1)
        return Verdict(None, None, "the policy evaluator failed", ("evaluator-error",))


def verify_irsa(ctx: Any, provider: str, host: str, role_arn: str, sa: Tuple[str, str],
                audience: Optional[str]) -> Verdict:
    """The evaluator's web-identity decision for ``sa`` on ``role_arn`` (module docstring)."""
    claims = {f"{host}:sub": f"system:serviceaccount:{sa[0]}:{sa[1]}"}
    if audience:
        claims[f"{host}:aud"] = audience
    return _guarded(ctx, [lambda ev: ev.can_assume(provider, role_arn, protocol="WebIdentity", claims=claims)])


def pod_identity_context(view: ClusterView, sa: Tuple[str, str]) -> Dict[str, str]:
    """The request context the EKS Pod Identity agent's AssumeRole carries (pod name and uid stay unknown)."""
    return {"aws:SourceAccount": view.account, "aws:SourceArn": view.arn,
            "aws:RequestTag/eks-cluster-arn": view.arn, "aws:RequestTag/eks-cluster-name": view.data.name,
            "aws:RequestTag/kubernetes-namespace": sa[0], "aws:RequestTag/kubernetes-service-account": sa[1]}


def verify_pod_identity(ctx: Any, view: ClusterView, role_arn: str, sa: Tuple[str, str]) -> Verdict:
    """``sts:AssumeRole`` and ``sts:TagSession`` by ``pods.eks.amazonaws.com`` on ``role_arn``."""
    context = pod_identity_context(view, sa)
    caller = f"svc:{POD_IDENTITY_SERVICE}"
    return _guarded(ctx, [lambda ev: ev.can_assume(caller, role_arn, claims=context),
                          lambda ev: ev.evaluate(caller, "sts:TagSession", role_arn, context=context)])


# ── inputs ───────────────────────────────────────────────────────────────────

def issuer_host(view: ClusterView) -> Optional[str]:
    """The cluster's OIDC issuer without its scheme (the prefix of the ``sub`` / ``aud`` condition keys)."""
    issuer = oidc_issuer(view.data.record)
    if not issuer:
        return None
    host = issuer.split("://", 1)[-1].rstrip("/")
    return host or None


def provider_arn(view: ClusterView, host: str) -> Optional[str]:
    parts = ids.parse_arn(view.arn)
    return f"arn:{parts.partition}:iam::{parts.account}:oidc-provider/{host}" if parts else None


def federated_roles(ctx: Any, provider: str) -> List[str]:
    """Collected roles whose trust policy names ``provider`` as a Federated principal (evaluated afterwards)."""
    iam = (ctx.data or {}).get("iam")
    wanted = provider.lower()
    out = []
    for arn, role in sorted(getattr(iam, "roles", {}).items()):
        for _i, stmt in iter_statements(role.trust_policy):
            principal = mapping(stmt.get("Principal")).get("Federated")
            values = principal if isinstance(principal, list) else [principal]
            if any(isinstance(v, str) and v.lower() == wanted for v in values):
                out.append(arn)
                break
    return out


def token_audiences(view: ClusterView) -> Dict[Tuple[str, str], Set[str]]:
    """Web-identity token audiences the pods of each service account already hold (projected volumes)."""
    out: Dict[Tuple[str, str], Set[str]] = {}
    for wl in view.workloads:
        for pod in wl.pods:
            auds = projected_token_audiences(pod) - {""}
            if auds:
                out.setdefault((wl.namespace, service_account_of(pod)), set()).update(auds)
    return out


@dataclass
class IrsaState:
    """Per-cluster inputs shared by the IRSA emitters."""

    view: ClusterView
    host: str
    provider: str
    audiences: Dict[Tuple[str, str], Set[str]]
    admins: Mapping[str, str]
    done: Set[Tuple[Tuple[str, str], str]] = field(default_factory=set)


def local_role(builder: Any, view: ClusterView, role_arn: str) -> Optional[str]:
    """The ``role`` node of ``role_arn`` when it is a role of the cluster's account (exact ARN, F-085);
    ``None`` for another account's role (it cannot be evaluated, and no orphan node is created)."""
    parts = ids.parse_arn(role_arn)
    if parts is None or parts.account != view.account or not parts.resource.startswith("role/"):
        return None
    return role_node(builder, role_arn)


def admin_roles(builder: Any) -> Dict[str, str]:
    """Role node id → confidence of its ``IS_ADMIN_EQUIVALENT`` edge (exact ARNs, F-085)."""
    return {e.source: e.confidence for e in builder.edges("IS_ADMIN_EQUIVALENT")}


# ── emission ─────────────────────────────────────────────────────────────────

def _bridge(builder: Any, etype: str, sa_id: str, role_id: str, verdict: Verdict, evidence: Mapping[str, Any],
            *, token_step: bool = False) -> None:
    ev = dict(evidence, trust_verified=verdict.label, trust_reason=verdict.reason)
    if verdict.gaps:
        ev["trust_gaps"] = list(verdict.gaps)
    if verdict.holds and not token_step:
        builder.add_edge(sa_id, etype, role_id, result=verdict.result, holds=True, evidence=ev)
    elif verdict.holds:
        ev["trust_decision"] = verdict.result.decision.value
        builder.add_edge(sa_id, etype, role_id, confidence="conditional", strength="strong", holds=True,
                         evidence=ev)
    else:
        builder.add_edge(sa_id, etype, role_id, holds=False, evidence=ev)


def _finding(builder: Any, view: ClusterView, sa: Tuple[str, str], fid: str, severity: str, title: str,
             description: str, role_arn: str, evidence: Mapping[str, Any], confidence: str = "definite") -> str:
    sa_id = view.sa_id(*sa)
    return builder.add_finding(
        fid, sa_id, severity=severity, title=f"{title} ({sa[0]}/{sa[1]}, cluster {view.data.name})",
        description=description, evidence=dict(evidence, role_arn=role_arn), discriminator=role_arn,
        confidence=confidence, related_node_ids=[role_arn] if builder.has_node(role_arn) else [],
        region=view.region, entity=f"sa/{view.data.name}/{sa[0]}/{sa[1]}", entity_arn=sa_id, resource=[sa_id],
        source_type="k8s_service_account", source_policy=evidence.get("mechanism", "irsa"))


def _admin(builder: Any, st: IrsaState, sa: Tuple[str, str], role_id: str, verdict: Verdict,
           mechanism: str) -> Optional[str]:
    level = st.admins.get(role_id)
    if not verdict.holds or level is None:
        return None
    conditional = level == "conditional" or getattr(verdict.result, "confidence", "definite") == "conditional"
    how = "IRSA" if mechanism == "irsa" else "EKS Pod Identity"
    return _finding(builder, st.view, sa, "K8S-IRSA-ADMIN", "CRITICAL",
                    f"Service account can assume an admin IAM role through {how}",
                    f"Every pod running as service account {sa[0]}/{sa[1]} can assume {role_id}, which is "
                    "administrator-equivalent in AWS: compromising one such pod compromises the account.",
                    role_id, {"mechanism": mechanism, "admin_confidence": level},
                    "conditional" if conditional else "definite")


def _not_admitted(builder: Any, st: IrsaState, sa: Tuple[str, str], role_arn: str, verdict: Verdict,
                  mechanism: str) -> str:
    if verdict.holds is None:
        return _finding(builder, st.view, sa, "K8S-IRSA-003", "INFO",
                        "Service account names an IAM role whose trust could not be evaluated",
                        f"The {mechanism} configuration of {sa[0]}/{sa[1]} names {role_arn}, but {verdict.reason}: "
                        "whether the service account can use the role is unknown.",
                        role_arn, {"mechanism": mechanism, "trust_verified": "unknown", "gaps": list(verdict.gaps)})
    return _finding(builder, st.view, sa, "K8S-IRSA-002", "LOW",
                    "Service account names an IAM role whose trust does not admit it",
                    f"The {mechanism} configuration of {sa[0]}/{sa[1]} names {role_arn}, but the role's trust "
                    f"policy does not admit it ({verdict.reason}). The pods get no AWS credentials from it; the "
                    "configuration is stale or was planted, and is not an attack path.",
                    role_arn, {"mechanism": mechanism, "trust_verified": False})


def annotated_bridges(ctx: Any, builder: Any, st: IrsaState) -> int:
    """``IRSA_BRIDGE`` for every service account with an ``eks.amazonaws.com/role-arn`` annotation."""
    count = 0
    for key, rec in sorted(st.view.service_accounts.items()):
        role_arn = annotation(rec, IRSA_ANNOTATION)
        sa_id = st.view.sa_id(*key)
        if role_arn is None or sa_id is None:
            continue
        audience = annotation(rec, AUDIENCE_ANNOTATION) or DEFAULT_AUDIENCE
        role_id = local_role(builder, st.view, role_arn)
        if role_id is None:                            # another account (or not a role ARN): cannot evaluate
            _not_admitted(builder, st, key, role_arn, Verdict(None, None, "the role is in another account or the "
                                                              "ARN is not a role", ("trust:unknown",)), "irsa")
            continue
        verdict = verify_irsa(ctx, st.provider, st.host, role_id, key, audience)
        _bridge(builder, "IRSA_BRIDGE", sa_id, role_id, verdict,
                {"mechanism": "irsa", "source": "annotation", "token": "irsa-webhook", "audience": audience,
                 "oidc_provider": st.provider, "technique": "irsa"})
        st.done.add((key, role_id))
        if verdict.holds:
            _admin(builder, st, key, role_id, verdict, "irsa")
        else:
            _not_admitted(builder, st, key, role_id, verdict, "irsa")
        count += 1
    return count


def trusted_bridges(ctx: Any, builder: Any, st: IrsaState) -> int:
    """``IRSA_BRIDGE`` from every other service account that a provider-trusting role admits."""
    if ctx.evaluator is None:
        return 0
    count = 0
    for role_arn in federated_roles(ctx, st.provider):
        role_id = local_role(builder, st.view, role_arn)
        if role_id is None:
            continue
        for key in sorted(st.view.sa_keys):
            sa_id = st.view.sa_id(*key)
            if sa_id is None or (key, role_id) in st.done or not builder.has_node(sa_id):
                continue
            held = st.audiences.get(key, set()) - {POD_IDENTITY_AUDIENCE}
            audience = DEFAULT_AUDIENCE if not held or DEFAULT_AUDIENCE in held else sorted(held)[0]
            verdict = verify_irsa(ctx, st.provider, st.host, role_id, key, audience)
            if not verdict.holds:
                continue
            _bridge(builder, "IRSA_BRIDGE", sa_id, role_id, verdict,
                    {"mechanism": "irsa", "source": "trust-policy", "audience": audience,
                     "token": "projected" if held else "token-request-needed", "oidc_provider": st.provider,
                     "technique": "irsa"}, token_step=not held)
            st.done.add((key, role_id))
            if held:
                _admin(builder, st, key, role_id, verdict, "irsa")
            count += 1
    return count


def pod_identity_bridges(ctx: Any, builder: Any, st: IrsaState) -> int:
    """``POD_IDENTITY`` for every EKS Pod Identity association of the cluster."""
    count = 0
    for assoc in st.view.data.eks_items("pod_identity_associations"):
        ns, name, role_arn = text(assoc.get("namespace")), text(assoc.get("serviceAccount")), text(assoc.get("roleArn"))
        sa_id = st.view.sa_id(ns, name) if ns and name else None
        if role_arn is None or sa_id is None or not builder.has_node(sa_id):
            continue
        key = (str(ns), str(name))
        role_id = local_role(builder, st.view, role_arn)
        if role_id is None:
            _not_admitted(builder, st, key, role_arn, Verdict(None, None, "the role is in another account or the "
                                                              "ARN is not a role", ("trust:unknown",)),
                          "pod-identity")
            continue
        verdict = verify_pod_identity(ctx, st.view, role_id, key)
        _bridge(builder, "POD_IDENTITY", sa_id, role_id, verdict,
                {"mechanism": "pod-identity", "association": text(assoc.get("associationArn")),
                 "target_role_arn": text(assoc.get("targetRoleArn")), "technique": "pod-identity"})
        if verdict.holds:
            _admin(builder, st, key, role_id, verdict, "pod-identity")
        else:
            _not_admitted(builder, st, key, role_id, verdict, "pod-identity")
        count += 1
    return count


def run_irsa(ctx: Any, builder: Any) -> int:
    """IRSA and Pod Identity bridges for every cluster; returns the number of bridges emitted."""
    admins = admin_roles(builder)
    count = 0
    for view in cluster_views(ctx):
        host = issuer_host(view)
        provider = provider_arn(view, host) if host else None
        st = IrsaState(view, host or "", provider or "", token_audiences(view), admins)
        if provider is not None:
            count += annotated_bridges(ctx, builder, st) + trusted_bridges(ctx, builder, st)
        else:
            _no_issuer(builder, st)
        count += pod_identity_bridges(ctx, builder, st)
    return count


def _no_issuer(builder: Any, st: IrsaState) -> None:
    """Annotated service accounts of a cluster whose OIDC issuer is unknown: K8S-IRSA-003, no edge."""
    for key, rec in sorted(st.view.service_accounts.items()):
        role_arn = annotation(rec, IRSA_ANNOTATION)
        if role_arn is not None and st.view.sa_id(*key):
            _not_admitted(builder, st, key, local_role(builder, st.view, role_arn) or role_arn,
                          Verdict(None, None, "the cluster's OIDC issuer was not collected", ("eks:oidc-unknown",)),
                          "irsa")


__all__ = [
    "POD_IDENTITY_SERVICE", "IrsaState", "Verdict", "admin_roles", "annotated_bridges", "federated_roles",
    "issuer_host", "local_role", "pod_identity_bridges", "pod_identity_context", "provider_arn", "run_irsa",
    "token_audiences", "trusted_bridges", "verify_irsa", "verify_pod_identity",
]
