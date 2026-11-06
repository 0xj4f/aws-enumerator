"""Role trust-policy analysis (engine.md §4.2-§4.3; F-020, F-021, F-072, F-073, F-002).

Every statement of every role's trust policy is read through ``policy.parse.iter_statements`` (a
single-object ``Statement`` is one statement, F-002) and classified into :class:`TrustGrant` records:

* who is trusted, resolved by **exact ARN** (``graph.ids.resolve_principal``): the anonymous wildcard, a
  same-account principal, the same account's root (delegation to identity policies), a foreign account or
  principal (a bare 12-digit id is that account's root, F-072), a service, a federated identity provider;
* how strongly the statement's conditions restrict it (``policy.conditions.classify_strength``, F-021);
* which guard protects a cross-account trust (``sts:ExternalId``, ``aws:PrincipalOrgID`` …, F-073);
* for federated providers, which subjects the conditions admit (``any`` / ``pattern`` / ``specific``, F-020);
* whether a ``Deny`` statement of the same policy removes the grant (definitely or conditionally, F-073), and how
  hard it is for the trusted caller to escape it (F-031, :class:`DenyGuard`).

``Allow`` + ``NotPrincipal`` trusts every AWS principal except the listed ones: it is a ``wildcard`` grant with
``not_principals`` set ("public-except", F-031).

**Deny guards (F-031).** Each ``Deny`` statement is applied to the grant's caller with the shared statement logic
(``policy.apply.apply_statement``: Principal / NotPrincipal, Action / NotAction, conditions with the shared
attacker model), for the assume action of the grant's protocol. The caller of a ``*`` grant is an arbitrary AWS
principal (``policy.resource_policy.ANY_AWS``), so ``Deny Principal * … StringNotEquals aws:PrincipalOrgID``
applies to it conditionally, and the escape strength of that Deny is the shared condition-strength classifier's
(``conditions.gate_strength`` with ``effect="Deny"``): ``strong`` for an organisation, account, VPC endpoint or
principal-ARN guard. A ``Deny NotPrincipal`` applies to an arbitrary caller unless it is one of the listed
principals, a ``strong`` escape too. A Deny that applies definitely removes the grant (``denied="yes"``). A
conditional one makes the grant conditional; only a ``strong`` guard also lowers the grant's ``strength`` (to
``strong``, so TRUST-001 becomes INFO like an Allow-side organisation condition, and the assume edge is graded
``strong``). A weak or unclassified guard keeps the grade of the Allow statement. ``allow_strength`` keeps the
Allow statement's own classification; ``deny_guards`` records every applicable Deny (``evidence.denied_by``).

The records feed two analyzers: ``trust`` (this module: the TRUST-* findings and ``trust_relationships.json``)
and ``assume`` (``iam/assume.py``: the CAN_ASSUME / web-identity / SAML / service edges). Both read the model
through :func:`trust_model`, computed once per analysis.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from aws_enumerator.engine.findings.catalog import A_EXTERNAL, CatalogEntry
from aws_enumerator.engine.findings.fingerprint import normalised_principal
from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.model import AnalyzerSpec, Phase

log = logging.getLogger(__name__)


# ── finding catalogue (D-33: ids owned by this module) ───────────────────────

_TRUST002_FIX = {
    "none": "Verify the cross-account trust is intended; restrict it to specific role ARNs and require "
            "sts:ExternalId (third parties) or aws:PrincipalOrgID (your organisation).",
    "external-id": "The trust requires sts:ExternalId; keep the value secret per customer and restrict the "
                   "principal to the vendor's specific role ARN.",
    "org": "The trust is limited to your organisation (aws:PrincipalOrgID / OrgPaths); confirm the "
           "organisation boundary is intended.",
    "other": "Review the trust conditions; prefer sts:ExternalId or aws:PrincipalOrgID guards.",
}

FINDINGS: Tuple[CatalogEntry, ...] = (
    CatalogEntry("TRUST-001", "CRITICAL", "trust_policy", "Role trusts any AWS principal (Principal: *)",
                 "Restrict Principal to specific accounts or role ARNs; conditions on Principal: * are only as "
                 "strong as their weakest key.", A_EXTERNAL),
    CatalogEntry("TRUST-002", "HIGH", "trust_policy", "Role trusts another AWS account",
                 _TRUST002_FIX["none"], A_EXTERNAL, discriminator="trusted-principal",
                 remediation_variants=dict(_TRUST002_FIX)),
    CatalogEntry("TRUST-OIDC-001", "CRITICAL", "trust_policy",
                 "Role trusts a web identity provider with weak subject or audience conditions",
                 "Require the provider's audience (<host>:aud) and an exact subject (<host>:sub), e.g. "
                 "repo:<org>/<repo>:ref:refs/heads/main for GitHub or system:serviceaccount:<ns>:<sa> for EKS.",
                 A_EXTERNAL, discriminator="principal"),
    CatalogEntry("TRUST-SAML-001", "INFO", "trust_policy", "Role is assumable through SAML federation",
                 "Confirm the SAML provider and its attribute mapping only admit intended users.", A_EXTERNAL,
                 discriminator="principal"),
)

#: Categories of a trusted principal (:attr:`TrustGrant.category`).
CATEGORIES: Tuple[str, ...] = (
    "wildcard", "same-account-principal", "same-account-root", "cross-account-root", "cross-account-principal",
    "service", "federated", "stale", "unsupported",
)

_ASSUME_ACTION = re.compile(r"^sts:(assumerole|assumerolewithwebidentity|assumerolewithsaml|\*|tagsession|"
                            r"setsourceidentity|setcontext)$|^\*$", re.IGNORECASE)
_ORG_KEYS = ("aws:principalorgid", "aws:principalorgpaths", "aws:sourceorgid", "aws:sourceorgpaths")
_EXTERNAL_ID = "sts:externalid"
_MFA_KEYS = ("aws:multifactorauthpresent", "aws:multifactorauthage")


#: Escape strength from which a conditional Deny guard lowers a grant's grade (F-031, module docstring).
CREDITED_GUARD_STRENGTH = "strong"


@dataclass(frozen=True)
class DenyGuard:
    """A Deny statement of the same trust policy that applies to a grant's caller (F-031, F-073)."""

    statement_index: int
    sid: Optional[str]
    applies: str                                   # yes (definitely) | conditional
    strength: str                                  # how hard the caller escapes it: none | weak | strong
    conditions: Optional[Mapping[str, Any]] = None
    not_principals: Tuple[Tuple[str, str], ...] = ()   # (type, value) of a ``Deny NotPrincipal`` statement

    @property
    def credited(self) -> bool:
        """True when the guard is strong enough to lower the grant's grade."""
        return self.applies == "conditional" and self.strength == CREDITED_GUARD_STRENGTH

    def to_json(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"statement_index": self.statement_index, "sid": self.sid, "effect": "Deny",
                               "applies": self.applies, "escape_strength": self.strength,
                               "conditions": _condition_list(self.conditions), "lowers_severity": self.credited}
        if self.not_principals:
            out["not_principals"] = _pairs_json(self.not_principals)
        return out


@dataclass(frozen=True)
class TrustGrant:
    """One (statement, principal) pair of a role's trust policy, classified."""

    role_arn: str
    role_name: str
    principal_type: str                  # AWS | Service | Federated | CanonicalUser
    principal: str                       # raw value as written ("*" for an Allow + NotPrincipal statement)
    node_id: Optional[str]               # resolved node (None: see ``reason``)
    node_type: Optional[str]
    reason: str                          # graph.ids.resolve_principal reason
    category: str                        # one of CATEGORIES
    account: Optional[str]               # the principal's account when it has one
    statement_index: int
    sid: Optional[str]
    actions: Tuple[str, ...]
    conditions: Optional[Mapping[str, Any]]
    strength: str                        # none | weak | strong: Allow conditions and credited Deny guards (F-021)
    guard: str                           # none | external-id | org | mfa | other (F-073)
    provider: Optional[str] = None       # federated: github, eks, cognito, saml, google, ... generic
    admits: Optional[str] = None         # federated: any | pattern | specific (F-020)
    denied: str = "no"                   # no | yes | conditional (a Deny statement of the same policy)
    allow_strength: str = "none"         # the Allow statement's own conditions only (F-021)
    deny_guards: Tuple[DenyGuard, ...] = ()               # the Deny statements that apply (F-031)
    not_principals: Tuple[Tuple[str, str], ...] = ()      # Allow + NotPrincipal: everyone except these (F-031)

    @property
    def cross_account(self) -> bool:
        return self.category in ("cross-account-root", "cross-account-principal")

    @property
    def public_except(self) -> bool:
        """An ``Allow`` + ``NotPrincipal`` grant: every AWS principal except :attr:`not_principals`."""
        return bool(self.not_principals)

    @property
    def credited_guards(self) -> Tuple[DenyGuard, ...]:
        return tuple(d for d in self.deny_guards if d.credited)

    def legacy_entry(self) -> Dict[str, Any]:
        """``trust_relationships.json`` row: the d13c215 keys plus the classification."""
        row = {
            "role_name": self.role_name, "role_arn": self.role_arn, "trusted_principal": self.principal,
            "principal_type": self.principal_type, "conditions": dict(self.conditions) if self.conditions else None,
            "is_cross_account": self.cross_account, "is_wildcard": self.category == "wildcard",
            "normalised_principal": self.node_id, "category": self.category, "account": self.account,
            "condition_strength": self.allow_strength, "guard": self.guard, "provider": self.provider,
            "admits": self.admits, "actions": list(self.actions), "statement_index": self.statement_index,
            "sid": self.sid, "denied": self.denied,
        }
        if self.not_principals:
            row["not_principals"] = _pairs_json(self.not_principals)
        if self.deny_guards:
            row["denied_by"] = [d.to_json() for d in self.deny_guards]
            row["effective_strength"] = self.strength
        return row


@dataclass
class TrustModel:
    """All classified trust grants of the analysed account, plus per-role gaps."""

    grants: List[TrustGrant] = field(default_factory=list)
    unreadable_roles: List[str] = field(default_factory=list)

    def for_role(self, role_arn: str) -> List[TrustGrant]:
        return [g for g in self.grants if g.role_arn == role_arn]


# ── classification helpers ───────────────────────────────────────────────────

def _strength(conditions: Optional[Mapping[str, Any]], effect: str) -> str:
    """Condition strength through E-policy's shared classifier (F-021); a local fallback if it is absent."""
    if not conditions:
        return "none"
    try:
        from aws_enumerator.engine.policy.conditions import classify_strength

        return classify_strength(conditions, effect).value
    except Exception as exc:  # noqa: BLE001 - classifier unavailable or failing: degrade, never crash
        log.debug("classify_strength unavailable (%s); using the local guard heuristic", type(exc).__name__)
        keys = _condition_keys(conditions)
        if any(k in keys for k in _ORG_KEYS) or any(k.endswith(":sub") or k.endswith(":aud") for k in keys):
            return "strong"
        return "weak"


def _condition_keys(conditions: Optional[Mapping[str, Any]]) -> Dict[str, List[str]]:
    """Lower-case condition key → every value it is compared with (any operator)."""
    out: Dict[str, List[str]] = {}
    for _op, block in (conditions or {}).items():
        if not isinstance(block, Mapping):
            continue
        for key, values in block.items():
            vals = values if isinstance(values, list) else [values]
            out.setdefault(str(key).lower(), []).extend(str(v) for v in vals)
    return out


def guard_of(conditions: Optional[Mapping[str, Any]]) -> str:
    """The strongest cross-account guard among the conditions (F-073)."""
    keys = _condition_keys(conditions)
    if any(k in keys for k in _ORG_KEYS):
        return "org"
    if _EXTERNAL_ID in keys:
        return "external-id"
    if any(k in keys for k in _MFA_KEYS):
        return "mfa"
    return "other" if keys else "none"


def _provider_host(node_id: Optional[str], raw: str) -> str:
    value = node_id or raw
    if value.startswith(ids.SYNTHETIC_PREFIX + "idp/"):
        return value[len(ids.SYNTHETIC_PREFIX + "idp/"):].lower()
    if ":oidc-provider/" in value:
        return value.split(":oidc-provider/", 1)[1].lower()
    return raw.lower()


def provider_of(node_id: Optional[str], raw: str) -> str:
    """``props.provider`` of a federated principal (graph-json.md §7.1)."""
    from aws_enumerator.engine.graph.builder import idp_provider

    return idp_provider(node_id or raw)


def _subject_admits(values: Sequence[str]) -> str:
    """``any`` / ``pattern`` / ``specific`` for the subject values a condition admits."""
    if not values:
        return "any"
    kinds = []
    for v in values:
        stripped = v.strip()
        if stripped in ("*", "") or stripped.startswith("*"):
            kinds.append("any")
        elif "*" in stripped or "?" in stripped:
            kinds.append("pattern")
        else:
            kinds.append("specific")
    for k in ("any", "pattern", "specific"):
        if k in kinds:
            return k
    return "specific"  # pragma: no cover


def _github_admits(values: Sequence[str]) -> str:
    """GitHub ``sub``: ``repo:*`` (or missing) admits any repository; ``repo:org/*`` a pattern."""
    if not values:
        return "any"
    out = "specific"
    for v in values:
        s = v.strip()
        if s in ("*", "repo:*") or s.startswith("*") or s.startswith("repo:*"):
            return "any"
        if "*" in s or "?" in s:
            out = "pattern"
    return out


def _eks_admits(values: Sequence[str]) -> str:
    if not values:
        return "any"
    for v in values:
        s = v.strip()
        if s in ("*", "system:serviceaccount:*", "system:serviceaccount:*:*") or s.startswith("*"):
            return "any"
    return _subject_admits(values)


def federated_admits(provider: str, host: str, conditions: Optional[Mapping[str, Any]]) -> Tuple[str, List[str]]:
    """``(admits, problems)`` for a web-identity trust (F-020). ``problems`` name missing / wildcard claims."""
    keys = _condition_keys(conditions)
    host = host.lower()                     # condition keys are case-insensitive (compared lower-case)
    sub = keys.get(f"{host}:sub", [])
    aud = keys.get(f"{host}:aud", [])
    problems: List[str] = []
    if provider == "github":
        admits = _github_admits(sub)
        if not sub:
            problems.append(f"{host}:sub missing")
    elif provider == "eks":
        admits = _eks_admits(sub)
        if not sub:
            problems.append(f"{host}:sub missing")
    elif provider == "cognito":
        admits = "specific" if aud and _subject_admits(aud) == "specific" else ("pattern" if aud else "any")
        if not aud:
            problems.append(f"{host}:aud missing")
        amr = [v.lower() for v in keys.get(f"{host}:amr", [])]
        if "unauthenticated" in amr:
            problems.append(f"{host}:amr admits unauthenticated identities")
    else:
        admits = _subject_admits(sub or aud)
        if not (sub or aud):
            problems.append(f"{host}:sub and {host}:aud missing")
    return admits, problems


def _category(ref: ids.PrincipalRef) -> str:
    if ref.reason == "wildcard":
        return "wildcard"
    if ref.kind == "service":
        return "service"
    if ref.reason in ("well-known-web-idp", "exact", "provider-not-collected") and ref.node_type == "idp":
        return "federated"
    if ref.reason == "same-account-root-delegation":
        return "same-account-root"
    if ref.reason == "foreign-account":
        return "cross-account-root"
    if ref.external:
        return "cross-account-principal"
    if ref.reason == "stale-principal":
        return "stale"
    if ref.node_id is not None:
        return "same-account-principal"
    return "unsupported"


def _principal_pairs(stmt: Mapping[str, Any], element: str = "Principal") -> List[Tuple[str, str]]:
    """``(type, value)`` pairs of a ``Principal`` (or ``NotPrincipal``) element as written."""
    principal = stmt.get(element)
    if isinstance(principal, str):
        return [("AWS", principal)]
    out: List[Tuple[str, str]] = []
    if isinstance(principal, Mapping):
        for ptype, values in sorted(principal.items()):
            vals = values if isinstance(values, list) else [values]
            out.extend((str(ptype), str(v)) for v in vals if isinstance(v, str))
    return out


def _pairs_json(pairs: Sequence[Tuple[str, str]]) -> List[Dict[str, str]]:
    return [{"type": t, "value": v} for t, v in pairs]


def _actions(stmt: Mapping[str, Any]) -> Tuple[str, ...]:
    raw = stmt.get("Action")
    vals = [raw] if isinstance(raw, str) else (raw if isinstance(raw, list) else [])
    return tuple(sorted({str(v) for v in vals if isinstance(v, str)}))


def _is_assume_statement(stmt: Mapping[str, Any]) -> bool:
    """True when the statement can concern role assumption (``NotAction`` statements count, conservatively)."""
    if "NotAction" in stmt:
        return True
    return any(_ASSUME_ACTION.match(a) for a in _actions(stmt))


@dataclass(frozen=True)
class _Deny:
    """A parsed Deny statement of a trust policy plus what its evidence shows (as written)."""

    stmt: Any                                      # model.Statement
    conditions: Optional[Mapping[str, Any]]
    not_principals: Tuple[Tuple[str, str], ...]


def _denies(doc: Any, statements: Sequence[Tuple[int, Mapping[str, Any]]], role: Any, ctx: Any) -> List[_Deny]:
    """Every Deny statement, parsed by ``policy.parse`` (the shared statement model, R-13)."""
    from aws_enumerator.engine.policy.parse import parse_policy

    raw = dict(statements)
    parsed = parse_policy(doc, layer="trust", source_type="resource", policy_arn=role.arn,
                          policy_name="AssumeRolePolicyDocument", partition=ctx.partition)
    out = []
    for stmt in parsed.statements:
        if stmt.effect != "Deny":
            continue
        written = raw.get(stmt.source.statement_index, {})
        cond = written.get("Condition") if isinstance(written.get("Condition"), Mapping) else None
        excepted = tuple(_principal_pairs(written, "NotPrincipal")) if stmt.principals is None else ()
        out.append(_Deny(stmt, cond, excepted))
    return out


#: The credential-issuing action a grant's caller sends, by protocol (the evaluator's ``ASSUME_ACTIONS``).
_PROTOCOL_ACTION = {"AWS": "sts:assumerole", "Service": "sts:assumerole", "CanonicalUser": "sts:assumerole",
                    "SAML": "sts:assumerolewithsaml", "WebIdentity": "sts:assumerolewithwebidentity"}
_IDENTITY_KEYS = ("aws:principalarn", "aws:principalaccount", "aws:username", "aws:userid", "aws:principaltype",
                  "aws:principalorgid", "aws:principalorgpaths")


def _caller(ptype: str, raw: str, category: str, provider: Optional[str], ctx: Any) -> Tuple[Any, str]:
    """(requester principal, assume action) of a grant: a ``*`` grant's caller is an arbitrary AWS principal."""
    from aws_enumerator.engine.policy.parse import parse_principal
    from aws_enumerator.engine.policy.resource_policy import ANY_AWS

    if category == "wildcard":
        return ANY_AWS, _PROTOCOL_ACTION["AWS"]
    protocol = ptype
    if ptype == "Federated":
        protocol = "SAML" if provider == "saml" else "WebIdentity"
    return parse_principal(ptype, raw, partition=ctx.partition), _PROTOCOL_ACTION.get(protocol, "sts:assumerole")


def _request_context(caller: Any) -> Any:
    """Identity keys known for the caller from the trust policy alone (a subset of the evaluator's: the rest is
    unknown, so a Deny over them stays conditional)."""
    from aws_enumerator.engine.model import ABSENT, Known, RequestContext
    from aws_enumerator.engine.policy.conditions import ContextKeys

    if caller.kind == "service":
        keys: Dict[str, Any] = {k: ABSENT for k in _IDENTITY_KEYS}
        keys.update({"aws:principalisawsservice": Known(("true",)),
                     "aws:principalservicename": Known((caller.name or caller.raw,))})
    else:
        keys = {"aws:principalisawsservice": Known(("false",))}
        if caller.kind in ("aws_root", "aws_user", "aws_role") and caller.account:
            keys["aws:principalaccount"] = Known((caller.account,))
        if caller.kind in ("aws_user", "aws_role") and caller.arn:
            keys["aws:principalarn"] = Known((caller.arn,))
    return RequestContext(principal=caller, keys=ContextKeys(keys))


def _deny_guards(denies: Sequence[_Deny], caller: Any, action: str, role_arn: str) -> Tuple[DenyGuard, ...]:
    """The Deny statements that apply to ``caller`` assuming ``role_arn``, with their escape strength (F-031)."""
    from aws_enumerator.engine.model import Tri
    from aws_enumerator.engine.policy.apply import apply_statement

    if not denies:
        return ()
    rc = _request_context(caller)
    out: List[DenyGuard] = []
    for d in denies:
        r = apply_statement(d.stmt, action, role_arn, rc, check_principal=True)
        if r.outcome is Tri.FALSE:
            continue
        applies, strength = ("yes", "none") if r.outcome is Tri.TRUE else ("conditional", r.gate.value)
        if caller.kind == "wildcard" and any(v != "*" for _t, v in d.not_principals):
            # "Deny everyone except the listed principals": an arbitrary caller escapes only by being one of them
            applies = "conditional"
            strength = CREDITED_GUARD_STRENGTH if r.outcome is Tri.TRUE else r.gate.value
        out.append(DenyGuard(d.stmt.source.statement_index, d.stmt.source.sid, applies, strength, d.conditions,
                             d.not_principals))
    return tuple(out)


def _role_grants(role: Any, doc: Any, ctx: Any, lookup: ids.PrincipalLookup) -> List[TrustGrant]:
    from aws_enumerator.engine.policy.parse import iter_statements

    statements = list(iter_statements(doc))
    denies = _denies(doc, statements, role, ctx)
    out: List[TrustGrant] = []
    for idx, stmt in statements:
        if stmt.get("Effect") != "Allow" or not _is_assume_statement(stmt):
            continue
        conditions = stmt.get("Condition") if isinstance(stmt.get("Condition"), Mapping) else None
        if "Principal" not in stmt and "NotPrincipal" in stmt:
            # Allow + NotPrincipal: every AWS principal except the listed ones ("public-except", F-031)
            excepted = tuple(_principal_pairs(stmt, "NotPrincipal"))
            out.append(_grant(role, idx, stmt, "AWS", "*", conditions, denies, ctx, lookup, excepted))
            continue
        for ptype, raw in _principal_pairs(stmt):
            out.append(_grant(role, idx, stmt, ptype, raw, conditions, denies, ctx, lookup))
    return out


def _account_of(raw: str) -> Optional[str]:
    bare = raw.strip()
    if re.fullmatch(r"\d{12}", bare):
        return bare
    parts = ids.parse_arn(bare)
    return parts.account if parts else None


def _grant(role: Any, idx: int, stmt: Mapping[str, Any], ptype: str, raw: str,
           conditions: Optional[Mapping[str, Any]], denies: Sequence[_Deny], ctx: Any,
           lookup: ids.PrincipalLookup, not_principals: Tuple[Tuple[str, str], ...] = ()) -> TrustGrant:
    ref = ids.resolve_principal(raw, lookup, ctx.account_id, principal_type=ptype, partition=ctx.partition)
    category = _category(ref)
    account = None
    if category in ("cross-account-root", "cross-account-principal", "same-account-principal", "same-account-root"):
        account = _account_of(raw)
    provider = admits = None
    if category == "federated":
        provider = provider_of(ref.node_id, raw)
        admits = None if provider == "saml" else federated_admits(provider, _provider_host(ref.node_id, raw),
                                                                  conditions)[0]
    caller, action = _caller(ptype, raw, category, provider, ctx)
    guards = _deny_guards(denies, caller, action, role.arn)
    allow_strength, guard = _strength(conditions, "Allow"), guard_of(conditions)
    strength, denied = allow_strength, "no"
    if any(d.applies == "yes" for d in guards):
        denied = "yes"
    elif guards:
        denied = "conditional"
        credited = [d for d in guards if d.credited]
        if credited:
            strength = CREDITED_GUARD_STRENGTH
            if guard not in ("org", "external-id") and any(guard_of(d.conditions) == "org" for d in credited):
                guard = "org"
    return TrustGrant(
        role_arn=role.arn, role_name=role.name, principal_type=ptype, principal=raw, node_id=ref.node_id,
        node_type=ref.node_type, reason=ref.reason, category=category, account=account, statement_index=idx,
        sid=stmt.get("Sid") if isinstance(stmt.get("Sid"), str) else None, actions=_actions(stmt),
        conditions=conditions, strength=strength, guard=guard, provider=provider, admits=admits, denied=denied,
        allow_strength=allow_strength, deny_guards=guards, not_principals=not_principals)


def build_trust_model(ctx: Any, lookup: Optional[ids.PrincipalLookup] = None) -> TrustModel:
    """Classify every role's trust policy (the IAM data is ``ctx.data["iam"]``)."""
    iam = (getattr(ctx, "data", None) or {}).get("iam")
    model = TrustModel()
    if iam is None:
        return model
    lookup = lookup or ids.PrincipalLookup({e.arn: e.kind for e in iam.entities()})
    for role in iam.entities("role"):
        doc = role.trust_policy
        if not isinstance(doc, Mapping):
            model.unreadable_roles.append(role.arn)
            continue
        model.grants.extend(_role_grants(role, doc, ctx, lookup))
    return model


def trust_model(ctx: Any, builder: Any = None) -> TrustModel:
    """The analysis' :class:`TrustModel`, computed once and shared by ``trust`` and ``assume``."""
    cached = ctx.shared.get("trust_model")
    if cached is None:
        lookup = builder.lookup() if builder is not None else None
        cached = ctx.shared["trust_model"] = build_trust_model(ctx, lookup)
    return cached


# ── findings ─────────────────────────────────────────────────────────────────

_TRUST001_SEVERITY = {"none": "CRITICAL", "weak": "HIGH", "strong": "INFO"}
_TRUST002_SEVERITY = {"external-id": "LOW", "org": "INFO"}
_OIDC_SEVERITY = {("github", "any"): "CRITICAL", ("github", "pattern"): "MEDIUM", ("github", "specific"): "INFO",
                  ("eks", "any"): "HIGH", ("eks", "pattern"): "MEDIUM", ("eks", "specific"): "INFO"}


def _legacy_fields(g: TrustGrant) -> Dict[str, Any]:
    return {"entity": f"role/{g.role_name}", "entity_arn": g.role_arn,
            "source_policy": "AssumeRolePolicyDocument", "source_type": "trust_policy", "resource": [g.role_arn]}


def _guard_evidence(g: TrustGrant) -> Dict[str, Any]:
    """Evidence keys for Deny guards and NotPrincipal (only present when the grant has them, F-031)."""
    ev: Dict[str, Any] = {}
    if g.public_except:
        ev.update(principal_scope="public-except", not_principals=_pairs_json(g.not_principals))
    if g.deny_guards:
        ev.update(denied_by=[d.to_json() for d in g.deny_guards], effective_strength=g.strength)
    if g.credited_guards:
        ev["mitigated_by"] = [f"trust-deny:statement-{d.statement_index}" for d in g.credited_guards]
    return ev


def _guard_text(g: TrustGrant) -> str:
    if not g.deny_guards:
        return ""
    stmts = ", ".join(str(d.statement_index) for d in g.deny_guards)
    if g.credited_guards:
        return (f" A Deny statement (statement {stmts}) removes every caller that does not satisfy its conditions "
                f"(a strong guard), so only callers inside that boundary can assume it.")
    best = max(g.deny_guards, key=lambda d: ("none", "weak", "strong").index(d.strength))
    return (f" A Deny statement (statement {stmts}) restricts it only conditionally ({best.strength} guard: an "
            "outside caller can escape it).")


def _trust001(builder: Any, g: TrustGrant) -> None:
    severity = _TRUST001_SEVERITY[g.strength]
    who = "any AWS principal (Principal: *)"
    if g.public_except:
        who = f"any AWS principal except {len(g.not_principals)} listed (NotPrincipal)"
    allows = "Principal '*'" if not g.public_except else (
        "every AWS principal except " + ", ".join(v for _t, v in g.not_principals) + " (NotPrincipal)")
    base = ("without conditions: any AWS account can assume it." if g.allow_strength == "none" else
            f"guarded only by {g.allow_strength} conditions.")
    if g.public_except and g.allow_strength == "none":
        base = "without conditions: any other AWS account can assume it."
    if g.credited_guards and g.allow_strength == "none":
        base = "without conditions of its own."
    builder.add_finding(
        "TRUST-001", g.role_arn, severity=severity, base_severity="CRITICAL",
        confidence="definite" if g.strength == "none" and g.denied == "no" else "conditional",
        title=f"Role '{g.role_name}' trusts {who}" + (" behind a Deny guard" if g.credited_guards else ""),
        description=f"The trust policy of '{g.role_name}' allows {allows} {base}{_guard_text(g)}",
        evidence={"statement_index": g.statement_index, "condition_strength": g.allow_strength,
                  "conditions": _condition_list(g.conditions), "denied": g.denied, **_guard_evidence(g)},
        matched_actions=list(g.actions), related_node_ids=[ids.ANONYMOUS_ID], **_legacy_fields(g))


def _trust002(builder: Any, g: TrustGrant, catalog: Any) -> None:
    whole_account = g.category == "cross-account-root"
    severity = _TRUST002_SEVERITY.get(g.guard) or ("HIGH" if whole_account else "MEDIUM")
    entry = catalog.get("TRUST-002") if catalog is not None else None
    variant = g.guard if g.guard in _TRUST002_FIX else "other"
    builder.add_finding(
        "TRUST-002", g.role_arn, severity=severity, base_severity="HIGH" if whole_account else "MEDIUM",
        confidence="conditional" if g.denied == "conditional" else "definite",
        title=f"Role '{g.role_name}' trusts {'account' if whole_account else 'principal'} "
              f"{g.account or g.principal}",
        description=(f"The trust policy of '{g.role_name}' allows '{g.principal}' from account {g.account}; "
                     f"guard: {g.guard}.{_guard_text(g)}"),
        remediation=entry.remediation_for(variant) if entry else _TRUST002_FIX[variant],
        discriminator=normalised_principal(g.principal),
        evidence={"statement_index": g.statement_index, "guard": g.guard, "condition_strength": g.allow_strength,
                  "conditions": _condition_list(g.conditions), "denied": g.denied, **_guard_evidence(g)},
        matched_actions=list(g.actions), related_node_ids=[g.node_id] if g.node_id else [],
        **_legacy_fields(g))


def _federated(builder: Any, g: TrustGrant) -> None:
    if g.provider == "saml":
        builder.add_finding(
            "TRUST-SAML-001", g.role_arn, severity="INFO", discriminator=g.node_id or g.principal,
            title=f"Role '{g.role_name}' is assumable through SAML provider {g.principal}",
            description="Users of the SAML identity provider can assume the role (AssumeRoleWithSAML).",
            confidence="conditional" if g.denied == "conditional" else "definite",
            evidence={"statement_index": g.statement_index, "conditions": _condition_list(g.conditions),
                      **_guard_evidence(g)},
            matched_actions=list(g.actions), related_node_ids=[g.node_id] if g.node_id else [],
            **_legacy_fields(g))
        return
    host = _provider_host(g.node_id, g.principal)
    admits, problems = federated_admits(g.provider or "generic", host, g.conditions)
    severity = _OIDC_SEVERITY.get((g.provider or "", admits))
    if severity is None:
        severity = "HIGH" if problems else ("MEDIUM" if admits != "specific" else "INFO")
    builder.add_finding(
        "TRUST-OIDC-001", g.role_arn, severity=severity, base_severity="CRITICAL" if g.provider == "github" else
        "HIGH", confidence="definite" if admits == "any" and g.denied == "no" else "conditional",
        discriminator=g.node_id or g.principal,
        title=f"Role '{g.role_name}' trusts {g.provider} identities ({admits} subjects)",
        description=(f"Web identity provider {g.principal} can assume '{g.role_name}'"
                     + (f"; {', '.join(problems)}." if problems else ".")),
        evidence={"statement_index": g.statement_index, "provider": g.provider, "admits": admits,
                  "problems": problems, "conditions": _condition_list(g.conditions), **_guard_evidence(g)},
        matched_actions=list(g.actions), related_node_ids=[g.node_id] if g.node_id else [],
        **_legacy_fields(g))


def _stale(builder: Any, g: TrustGrant) -> None:
    builder.add_finding(
        "IAM-STALE-PRINCIPAL-001", g.role_arn, severity="INFO", discriminator=g.principal,
        title=f"Trust policy of '{g.role_name}' names a deleted principal",
        description=f"The trust policy names the unique id {g.principal}: the principal was deleted.",
        evidence={"statement_index": g.statement_index}, **_legacy_fields(g))


def _condition_list(conditions: Optional[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for op, block in sorted((conditions or {}).items()):
        if isinstance(block, Mapping):
            for key, values in sorted(block.items()):
                vals = values if isinstance(values, list) else [values]
                out.append({"operator": str(op), "key": str(key), "values": sorted(str(v) for v in vals)})
    return out


def emit_findings(model: TrustModel, builder: Any, catalog: Any = None) -> int:
    """Add the TRUST-* findings of ``model`` to ``builder``; returns how many grants produced one."""
    count = 0
    for g in model.grants:
        if g.denied == "yes":
            continue
        if g.category == "wildcard":
            _trust001(builder, g)
        elif g.cross_account and g.principal_type == "AWS":
            _trust002(builder, g, catalog)
        elif g.category == "federated":
            _federated(builder, g)
        elif g.category == "stale":
            _stale(builder, g)
        else:
            continue
        count += 1
    return count


def legacy_relationships(model: TrustModel) -> List[Dict[str, Any]]:
    """``trust_relationships.json``: one row per trusted principal of an Allow statement."""
    rows = [g.legacy_entry() for g in model.grants]
    return sorted(rows, key=lambda r: (r["role_arn"], r["statement_index"], r["principal_type"],
                                       r["trusted_principal"]))


def run_trust(ctx: Any, builder: Any) -> None:
    """Analyzer ``trust`` (phase IDENTITY): TRUST-* findings and ``trust_relationships.json``."""
    model = trust_model(ctx, builder)
    emit_findings(model, builder, getattr(builder, "catalog", None))
    ctx.set_legacy_output("trust_relationships.json", legacy_relationships(model))


ANALYZERS: Tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec("trust", Phase.IDENTITY, run_trust, inputs=("iam.roles",), requires=("iam-graph",),
                 legacy_files=("trust_relationships.json",)),
)


def grants_by_category(model: TrustModel, categories: Iterable[str]) -> List[TrustGrant]:
    wanted = set(categories)
    return [g for g in model.grants if g.category in wanted]


__all__ = [
    "ANALYZERS", "CATEGORIES", "CREDITED_GUARD_STRENGTH", "DenyGuard", "FINDINGS", "TrustGrant", "TrustModel",
    "build_trust_model", "emit_findings", "federated_admits", "guard_of", "legacy_relationships", "provider_of",
    "run_trust", "trust_model",
]
