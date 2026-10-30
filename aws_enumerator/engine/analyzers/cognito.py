"""Cognito: identity pools as bridges from the internet to IAM roles (E-compute; F-032, F-048, F-037).

An identity pool hands out credentials for IAM roles. Who can get which role depends on the pool configuration,
which the d13c215 analyzer ignored: it linked every configured unauthenticated role at weight 0 even when guest
access was off (F-032) and never read role mappings, the classic flow or the login providers (F-048). This module
reads the Cognito records of the edge-services loader (``ctx.data["edge_services"]["cognito"]``, both layouts) and
emits, per traversability-table.md §5.16:

* ``COGNITO_PUBLIC_IDENTITY`` anonymous → pool when anyone can obtain an identity: guest access
  (``AllowUnauth``) or a **public authenticated path** (a linked user pool with self sign-up, or a public social
  login provider such as Google, Facebook, Amazon or Apple);
* ``POOL_UNAUTH_ROLE`` pool → role **only when** ``AllowUnauth`` is true (conditional when it could not be read);
  with guest access off the role is dormant: no edge, ``COGNITO-UNAUTH-002`` (INFO) instead of the HIGH
  ``COGNITO-UNAUTH-001``;
* ``POOL_AUTH_ROLE`` / ``POOL_MAPPED_ROLE`` pool → role for the authenticated role, every role of a rules-based
  mapping, the roles a token-based mapping can pick and, with the classic (basic) flow, every role whose trust
  policy admits the pool. They are traversable only when the authenticated path is public (rule
  ``pool-auth-public``); an unknown auth path is not traversable and says so in ``evidence.gaps``.

Every pool → role edge is checked against the role's trust policy through the evaluator (``can_assume`` with the
``cognito-identity.amazonaws.com:aud`` / ``:amr`` claims of that pool): a role whose trust does not admit the pool
cannot be handed out, so no edge; a role whose trust was not collected gives a conditional edge with a gap.

Findings: ``COGNITO-UNAUTH-001`` (guest access to a role), ``COGNITO-UNAUTH-002`` (dormant unauthenticated role),
``COGNITO-AUTH-PUBLIC-001`` (the authenticated role is effectively public), ``COGNITO-CLASSIC-001`` (classic flow
enabled), ``COGNITO-TOKEN-MAP-001`` (the identity provider's token picks the role).

Null = unknown (c-b-1, F-059): ``AllowUnauth``, ``RoleMappings``, the provider lists and ``SelfSignupEnabled`` of
``null`` are unknown, recorded as node coverage gaps and conditional edges, never read as "off".
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from aws_enumerator.engine.analyzers.compute import unit_records
from aws_enumerator.engine.analyzers.coverage_gaps import is_legacy, item_coverage
from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.model import AnalyzerSkipped, AnalyzerSpec, Decision, EvalResult, Phase, Strength

log = logging.getLogger(__name__)

COGNITO_IDP = "cognito-identity.amazonaws.com"
AUD_KEY = f"{COGNITO_IDP}:aud"
AMR_KEY = f"{COGNITO_IDP}:amr"
#: Login providers anyone on the internet can sign in with (an account there is free and self-service).
SOCIAL_PROVIDERS = frozenset({"accounts.google.com", "graph.facebook.com", "www.amazon.com", "appleid.apple.com",
                              "api.twitter.com"})
_UNKNOWN = EvalResult(Decision.CONDITIONAL, reason="no_allow", strength=Strength.WEAK)


@dataclass
class Pool:
    """One identity pool node and what decides who can get its roles."""

    node_id: str
    pool_id: str
    region: str
    record: Mapping[str, Any]
    auth_public: Optional[bool] = False
    auth_reasons: List[str] = field(default_factory=list)
    gaps: Set[str] = field(default_factory=set)

    @property
    def name(self) -> str:
        return str(self.record.get("Name") or self.pool_id)

    @property
    def allow_unauth(self) -> Optional[bool]:
        value = self.record.get("AllowUnauth")
        return value if isinstance(value, bool) else None


# ── records ──────────────────────────────────────────────────────────────────

def _records(ctx: Any) -> List[Tuple[str, Mapping[str, Any]]]:
    edge = (ctx.data or {}).get("edge_services")
    if not isinstance(edge, Mapping) or "cognito" not in edge:
        raise AnalyzerSkipped("cognito", reason="no Cognito data was loaded")
    return [(u, r) for u, r in unit_records(edge, "cognito") if u != "global"]


def _pool_node_id(ctx: Any, unit: str, rec: Mapping[str, Any]) -> Optional[str]:
    arn = rec.get("Arn")
    if isinstance(arn, str) and ids.node_id_matches("cognito", arn):
        return arn
    pool_id = rec.get("Id")
    if not isinstance(pool_id, str) or not pool_id:
        return None
    region = pool_id.split(":", 1)[0] if ":" in pool_id else unit
    try:
        return ids.node_id_for("cognito", region=region, account=ctx.account_id, partition=ctx.partition,
                               pool_id=pool_id)
    except ValueError:
        return None


def _user_pool_node_id(ctx: Any, unit: str, rec: Mapping[str, Any]) -> Optional[str]:
    arn = rec.get("Arn")
    if isinstance(arn, str) and ids.node_id_matches("cognitouserpool", arn):
        return arn
    pool_id = rec.get("Id")
    node_id = f"arn:{ctx.partition}:cognito-idp:{unit}:{ctx.account_id}:userpool/{pool_id}"
    return node_id if isinstance(pool_id, str) and ids.node_id_matches("cognitouserpool", node_id) else None


def load_pools(ctx: Any) -> Tuple[List[Pool], Dict[str, Mapping[str, Any]]]:
    """``(identity pools, user pool records by user pool id)`` of the analysed regions."""
    pools: Dict[str, Pool] = {}
    user_pools: Dict[str, Mapping[str, Any]] = {}
    for unit, rec in _records(ctx):
        if rec.get("Kind") == "user_pool" and isinstance(rec.get("Id"), str):
            user_pools[str(rec["Id"])] = dict(rec, _unit=unit)
        elif rec.get("Kind") == "identity_pool":
            node_id = _pool_node_id(ctx, unit, rec)
            if node_id is None:
                ctx.add_gap("cognito:unrecognised-id", "Some identity pools have no usable id and are not in the "
                            "graph.", 1)
                continue
            region = node_id.split(":")[3]
            pools.setdefault(node_id, Pool(node_id, node_id.split("identitypool/", 1)[1], region, rec))
    return [pools[k] for k in sorted(pools)], user_pools


def _linked_user_pools(pool: Pool) -> Optional[List[str]]:
    """User pool ids behind ``CognitoIdentityProviders`` (``None`` when the list is unknown)."""
    providers = pool.record.get("CognitoIdentityProviders")
    if providers is None:
        return None if "CognitoIdentityProviders" in pool.record else []
    out = []
    for p in providers if isinstance(providers, list) else ():
        name = p.get("ProviderName") if isinstance(p, Mapping) else None
        if isinstance(name, str) and "/" in name:
            out.append(name.rsplit("/", 1)[1])
    return sorted(set(out))


def classify_auth(pool: Pool, user_pools: Mapping[str, Mapping[str, Any]]) -> None:
    """Is the authenticated path public? ``True`` / ``False`` / ``None`` (unknown) with reasons and gaps."""
    rec = pool.record
    reasons: List[str] = []
    unknown: Set[str] = set()
    logins = rec.get("SupportedLoginProviders")
    if isinstance(logins, Mapping):
        reasons += [f"public login provider {p}" for p in sorted(logins) if str(p).lower() in SOCIAL_PROVIDERS]
    elif logins is None and "SupportedLoginProviders" in rec:
        unknown.add("cognito-identity:DescribeIdentityPool:login-providers-unknown")
    linked = _linked_user_pools(pool)
    if linked is None:
        unknown.add("cognito-identity:DescribeIdentityPool:user-pools-unknown")
    for up_id in linked or ():
        up = user_pools.get(up_id)
        signup = up.get("SelfSignupEnabled") if up is not None else None
        if signup is True:
            reasons.append(f"user pool {up_id} allows self sign-up")
        elif signup is None:
            unknown.add(f"cognito-idp:DescribeUserPool:self-signup-unknown@{up_id}")
    if rec.get("OpenIdConnectProviderARNs"):
        unknown.add("cognito-identity:oidc-provider-sign-up-unknown")
    pool.auth_reasons = reasons
    pool.auth_public = True if reasons else (None if unknown else False)
    if pool.auth_public is None:
        pool.gaps |= unknown


# ── roles and trust ──────────────────────────────────────────────────────────

def _role_node(builder: Any, value: Any) -> Optional[str]:
    if not isinstance(value, str) or ":role/" not in value:
        return None
    ref = builder.ensure_principal(value, principal_type="AWS")
    if ref.node_id is None or builder.node(ref.node_id).type != "role":
        return None
    return ref.node_id


def _known_roles(ctx: Any) -> Set[str]:
    iam = (ctx.data or {}).get("iam")
    return set(getattr(iam, "roles", None) or {})


def trust_result(ctx: Any, role_arn: str, pool: Pool, amr: str) -> Optional[EvalResult]:
    """May identities of ``pool`` (``amr`` authenticated / unauthenticated) assume ``role_arn``?

    ``None`` when the trust policy denies it; a conditional result with the gap ``iam:trust-unknown`` when the role
    (or the evaluator) is not available.
    """
    evaluator = getattr(ctx, "evaluator", None)
    if evaluator is None or role_arn not in _known_roles(ctx):
        return EvalResult(Decision.CONDITIONAL, reason="no_allow", strength=Strength.WEAK,
                          gaps=frozenset({"iam:trust-unknown"}))
    result = evaluator.can_assume(COGNITO_IDP, role_arn, protocol="WebIdentity",
                                  claims={AUD_KEY: pool.pool_id, AMR_KEY: amr})
    return result if result.decision.grants else None


def trusting_roles(ctx: Any) -> List[str]:
    """Roles whose trust policy names the Cognito federated principal (classic flow / token mapping candidates)."""
    pset = ctx.shared.get("iam.principal_set")
    trust = getattr(pset, "trust", None) or {}
    out = []
    for arn in sorted(trust):
        doc = trust[arn]
        for stmt in getattr(doc, "statements", ()):
            if stmt.effect == "Allow" and any(COGNITO_IDP in (p.raw or "").lower() for p in stmt.principals or ()):
                out.append(arn)
                break
    return out


def _mapping_roles(pool: Pool) -> Tuple[Dict[str, List[str]], List[str]]:
    """``({role ARN: [providers]}`` of rules-based mappings, ``[providers]`` with token-based mappings)."""
    rules: Dict[str, List[str]] = {}
    token: List[str] = []
    mappings = pool.record.get("RoleMappings")
    for provider, mapping in sorted(mappings.items()) if isinstance(mappings, Mapping) else ():
        if not isinstance(mapping, Mapping):
            continue
        if str(mapping.get("Type")).lower() == "token":
            token.append(str(provider))
        config = mapping.get("RulesConfiguration") if isinstance(mapping.get("RulesConfiguration"), Mapping) else {}
        for rule in config.get("Rules") or ():
            if isinstance(rule, Mapping) and isinstance(rule.get("RoleARN"), str):
                rules.setdefault(rule["RoleARN"], []).append(str(provider))
    return rules, token


# ── edges and findings ───────────────────────────────────────────────────────

@dataclass
class PoolEdges:
    """What one pool contributes: the roles reached per edge type (for findings and props)."""

    unauth: List[str] = field(default_factory=list)
    auth: List[str] = field(default_factory=list)
    mapped: List[str] = field(default_factory=list)
    untrusted: List[str] = field(default_factory=list)


def _emit(ctx: Any, builder: Any, pool: Pool, etype: str, role_arn: Any, amr: str, technique: str,
          out: PoolEdges, extra: Optional[Mapping[str, Any]] = None, configured: bool = True) -> Optional[str]:
    """One pool → role edge when the role's trust admits the pool's identities (``configured``: the pool names
    the role, so a refusing trust policy is worth reporting in ``props.roles_not_trusting_pool``)."""
    role = _role_node(builder, role_arn)
    if role is None:
        return None
    result = trust_result(ctx, role, pool, amr)
    if result is None:
        if configured:
            out.untrusted.append(role)
        return None
    evidence: Dict[str, Any] = {"technique": technique, "pool_id": pool.pool_id}
    evidence.update(extra or {})
    holds = None
    if etype in ("POOL_AUTH_ROLE", "POOL_MAPPED_ROLE"):
        holds = pool.auth_public is True
        evidence["auth_public"] = "unknown" if pool.auth_public is None else pool.auth_public
        if pool.auth_public is None:
            evidence["gaps"] = sorted(pool.gaps)
    if etype == "POOL_UNAUTH_ROLE" and pool.allow_unauth is None:
        result = _UNKNOWN if result.decision is Decision.ALLOW else result
        evidence["gaps"] = sorted(set(result.gaps) | {"cognito-identity:DescribeIdentityPool:allow-unauth-unknown"})
    builder.add_edge(pool.node_id, etype, role, result=result, holds=holds, evidence=evidence)
    return role


def pool_edges(ctx: Any, builder: Any, pool: Pool, trusting: Iterable[str]) -> PoolEdges:
    """Every pool → role edge of one identity pool (module docstring)."""
    out = PoolEdges()
    rec = pool.record
    if rec.get("UnauthRole") and pool.allow_unauth is not False:
        role = _emit(ctx, builder, pool, "POOL_UNAUTH_ROLE", rec["UnauthRole"], "unauthenticated", "guest-access",
                     out)
        out.unauth += [role] if role else []
    if rec.get("AuthRole"):
        role = _emit(ctx, builder, pool, "POOL_AUTH_ROLE", rec["AuthRole"], "authenticated", "authenticated-role",
                     out)
        out.auth += [role] if role else []
    rules, token = _mapping_roles(pool)
    for role_arn, providers in sorted(rules.items()):
        role = _emit(ctx, builder, pool, "POOL_MAPPED_ROLE", role_arn, "authenticated", "rules-mapping", out,
                     {"providers": sorted(set(providers))})
        out.mapped += [role] if role else []
    candidates = sorted(set(trusting)) if (token or rec.get("AllowClassicFlow") is True) else []
    for role_arn in candidates:
        technique = "classic-flow" if rec.get("AllowClassicFlow") is True else "token-mapping"
        role = _emit(ctx, builder, pool, "POOL_MAPPED_ROLE", role_arn, "authenticated", technique, out,
                     configured=False)
        out.mapped += [role] if role else []
        if rec.get("AllowClassicFlow") is True and pool.allow_unauth is not False:
            role = _emit(ctx, builder, pool, "POOL_UNAUTH_ROLE", role_arn, "unauthenticated", "classic-flow", out,
                         configured=False)
            out.unauth += [role] if role else []
    return out


def public_identity_edge(builder: Any, pool: Pool) -> None:
    """``COGNITO_PUBLIC_IDENTITY`` when guest access is on (or unknown) or the authenticated path is public."""
    if pool.allow_unauth is True or pool.auth_public is True:
        reasons = (["guest access (AllowUnauthenticatedIdentities)"] if pool.allow_unauth else []) + pool.auth_reasons
        builder.add_edge(ids.ANONYMOUS_ID, "COGNITO_PUBLIC_IDENTITY", pool.node_id,
                         evidence={"technique": "public-identity", "reasons": reasons})
    elif pool.allow_unauth is None and pool.record.get("UnauthRole"):
        builder.add_edge(ids.ANONYMOUS_ID, "COGNITO_PUBLIC_IDENTITY", pool.node_id, confidence="conditional",
                         strength="weak", evidence={"technique": "public-identity",
                                                    "gaps": ["cognito-identity:DescribeIdentityPool:"
                                                             "allow-unauth-unknown"]})


def pool_findings(builder: Any, pool: Pool, reached: PoolEdges) -> None:
    rec = pool.record
    common = {"region": pool.region}
    if reached.unauth and pool.allow_unauth is True:
        builder.add_finding(
            "COGNITO-UNAUTH-001", pool.node_id, severity="HIGH",
            title=f"Cognito identity pool '{pool.name}' grants an unauthenticated role",
            description="Guest access is enabled: anyone on the internet can obtain credentials for "
                        + ", ".join(sorted(set(reached.unauth))) + ".",
            evidence={"roles": sorted(set(reached.unauth)), "allow_unauth": True},
            related_node_ids=sorted(set(reached.unauth)), **common)
    elif rec.get("UnauthRole") and pool.allow_unauth is None:
        builder.add_finding(
            "COGNITO-UNAUTH-001", pool.node_id, severity="MEDIUM", base_severity="HIGH", confidence="conditional",
            title=f"Cognito identity pool '{pool.name}' maps an unauthenticated role (guest access unverified)",
            description="The pool maps an unauthenticated role, but whether guest access is enabled could not be "
                        "read: anyone on the internet may be able to obtain its credentials.",
            evidence={"role": rec.get("UnauthRole"), "allow_unauth": "unknown"},
            gaps=["cognito-identity:DescribeIdentityPool:allow-unauth-unknown"], **common)
    elif rec.get("UnauthRole") and pool.allow_unauth is False:
        builder.add_finding(
            "COGNITO-UNAUTH-002", pool.node_id, severity="INFO",
            title=f"Cognito identity pool '{pool.name}' has a dormant unauthenticated role",
            description="An unauthenticated role is mapped but guest access is disabled, so no credentials are "
                        "issued for it today; enabling guest access would expose the role.",
            evidence={"role": rec.get("UnauthRole"), "allow_unauth": False}, **common)
    _auth_findings(builder, pool, reached, common)


def _auth_findings(builder: Any, pool: Pool, reached: PoolEdges, common: Mapping[str, Any]) -> None:
    rec = pool.record
    roles = sorted(set(reached.auth + reached.mapped))
    if pool.auth_public is True and roles:
        builder.add_finding(
            "COGNITO-AUTH-PUBLIC-001", pool.node_id, severity="HIGH",
            title=f"Cognito identity pool '{pool.name}': the authenticated role is effectively public",
            description="Anyone can become an authenticated identity (" + "; ".join(pool.auth_reasons)
                        + ") and then obtain credentials for " + ", ".join(roles) + ".",
            evidence={"reasons": pool.auth_reasons, "roles": roles}, related_node_ids=roles, **common)
    if rec.get("AllowClassicFlow") is True:
        reachable = sorted(set(reached.mapped + reached.unauth))
        builder.add_finding(
            "COGNITO-CLASSIC-001", pool.node_id, severity="MEDIUM" if reachable else "LOW", base_severity="MEDIUM",
            title=f"Cognito identity pool '{pool.name}' allows the classic (basic) authentication flow",
            description="With the classic flow an identity can call AssumeRoleWithWebIdentity on any role whose "
                        "trust policy admits this pool, bypassing the configured roles and mappings.",
            evidence={"roles_trusting_pool": reachable}, related_node_ids=reachable, **common)
    _rules, token = _mapping_roles(pool)
    if token:
        builder.add_finding(
            "COGNITO-TOKEN-MAP-001", pool.node_id, severity="LOW",
            title=f"Cognito identity pool '{pool.name}' lets the identity provider's token choose the role",
            description="Token-based role mapping uses the cognito:preferred_role / cognito:roles claims of the "
                        "token: whoever controls group membership in the provider controls which role is issued.",
            evidence={"providers": token}, **common)


def _pool_props(pool: Pool, reached: PoolEdges) -> Dict[str, Any]:
    rec = pool.record
    logins = rec.get("SupportedLoginProviders")
    props: Dict[str, Any] = {
        "pool_id": pool.pool_id, "allow_unauth": pool.allow_unauth, "allow_classic_flow": rec.get("AllowClassicFlow"),
        "auth_public": "unknown" if pool.auth_public is None else pool.auth_public,
        "login_providers": sorted(logins) if isinstance(logins, Mapping) else None,
        "user_pools": _linked_user_pools(pool) or None,
        "developer_provider": bool(rec.get("DeveloperProviderName")) or None,
        "roles_not_trusting_pool": sorted(set(reached.untrusted)) or None}
    return {k: v for k, v in props.items() if v is not None}


def user_pool_nodes(ctx: Any, builder: Any, user_pools: Mapping[str, Mapping[str, Any]]) -> None:
    legacy = is_legacy(ctx)
    for up_id in sorted(user_pools):
        rec = user_pools[up_id]
        node_id = _user_pool_node_id(ctx, str(rec.get("_unit")), rec)
        if node_id is None:
            continue
        status, gaps = item_coverage(rec, legacy=legacy)
        clients = rec.get("Clients")
        props = {"self_signup_enabled": rec.get("SelfSignupEnabled"), "mfa_configuration": rec.get("MfaConfiguration"),
                 "client_count": len(clients) if isinstance(clients, list) else None}
        builder.add_node(node_id, "cognitouserpool", str(rec.get("Name") or up_id), region=str(rec.get("_unit")),
                         props={k: v for k, v in props.items() if v is not None}, coverage_status=status,
                         coverage_gaps=gaps)


# ── the analyzer ─────────────────────────────────────────────────────────────

def analyze_cognito(ctx: Any, builder: Any) -> None:
    """Analyzer ``cognito`` (phase RESOURCES)."""
    pools, user_pools = load_pools(ctx)
    user_pool_nodes(ctx, builder, user_pools)
    trusting = trusting_roles(ctx)
    legacy = is_legacy(ctx)
    for pool in pools:
        classify_auth(pool, user_pools)
        status, gaps = item_coverage(pool.record, legacy=legacy)
        if pool.allow_unauth is None and "AllowUnauth" in pool.record:
            gaps = sorted(set(gaps) | {"cognito-identity:DescribeIdentityPool:allow-unauth-unknown"})
            status = "partial"
        builder.add_node(pool.node_id, "cognito", pool.name, region=pool.region, coverage_status=status,
                         coverage_gaps=sorted(set(gaps) | pool.gaps))
        reached = pool_edges(ctx, builder, pool, trusting)
        public_identity_edge(builder, pool)
        builder.set_node_props(pool.node_id, **_pool_props(pool, reached))
        pool_findings(builder, pool, reached)
    log.debug("cognito: %d identity pools, %d user pools", len(pools), len(user_pools))


def _run(ctx: Any, builder: Any) -> None:
    analyze_cognito(ctx, builder)       # looked up at call time (tests may patch the module attribute)


def _findings() -> Tuple[Any, ...]:
    from aws_enumerator.engine.findings.catalog import A_COGNITO, CatalogEntry

    entry = CatalogEntry
    return (
        entry("COGNITO-UNAUTH-001", "HIGH", "cognito_unauth", "Identity pool grants an unauthenticated role",
              "Remove the unauthenticated role or tightly scope it; set AllowUnauthenticatedIdentities=false if "
              "anonymous access isn't required.", A_COGNITO),
        entry("COGNITO-UNAUTH-002", "INFO", "cognito_unauth", "Identity pool has a dormant unauthenticated role",
              "Remove the unauthenticated role mapping, or scope the role as if guest access were enabled.",
              A_COGNITO),
        entry("COGNITO-AUTH-PUBLIC-001", "HIGH", "cognito_auth_public",
              "The authenticated role of an identity pool is effectively public",
              "Disable self sign-up on the linked user pool (or require admin approval), remove public social "
              "providers, or use rules-based role mapping that gives sign-ups an unprivileged role.", A_COGNITO),
        entry("COGNITO-CLASSIC-001", "MEDIUM", "cognito_classic_flow", "Identity pool allows the classic flow",
              "Set AllowClassicFlow=false and make every role trust policy require the pool id (aud) and the "
              "expected amr.", A_COGNITO),
        entry("COGNITO-TOKEN-MAP-001", "LOW", "cognito_role_mapping",
              "The identity provider's token chooses the identity pool role",
              "Prefer rules-based mappings, or restrict who can change group membership in the provider.",
              A_COGNITO),
    )


#: Finding ids this module emits (findings/catalog.py merges them, DECISIONS.md D-33).
FINDINGS: Tuple[Any, ...] = _findings()

ANALYZERS: Tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec("cognito", Phase.RESOURCES, _run, inputs=("cognito",)),
)

__all__ = ["ANALYZERS", "FINDINGS", "Pool", "analyze_cognito", "classify_auth", "load_pools", "pool_edges",
           "trust_result", "trusting_roles"]
