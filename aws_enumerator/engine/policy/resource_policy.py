"""Resource-based policies: the index the evaluator reads and the one shared grant walker (F-031).

* :class:`ResourcePolicyIndex` — resource ARN → policy per layer (``resource`` for bucket/queue/secret/function
  policies, ``trust`` for role trust policies, ``key_policy`` for KMS keys), KMS grants, AWS-managed keys and
  bucket owners. A resource the index has never heard of is ``unknown`` for services that support
  resource-based policies and ``absent`` for those that do not.
* :func:`policy_grants` — every principal a resource policy grants, with the decision **for that principal**:
  the statement's own conditions, every Deny in the same policy that can apply to that principal (a
  ``Deny … StringNotEquals aws:PrincipalOrgID`` guard blocks anonymous callers definitely and outsiders
  conditionally), ``NotPrincipal`` (Allow + NotPrincipal = public except the listed principals) and the
  shared condition-strength classifier. This replaces the five copy-pasted walkers of d13c215 (one per
  service) — ``Evaluator.resource_policy_grants`` is its public entry point. Switching
  ``analyzers/data_stores.py`` to it is E-data's Wave 2 task (DECISIONS.md D-39).

For a ``*`` principal two grants are returned: one for an **anonymous** (unsigned) caller and one for **any
authenticated AWS principal** (``Principal.kind`` ``anonymous`` / ``wildcard``), because identity condition
keys are absent for the first and unknown for the second (AWS "Condition operators": missing keys).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from aws_enumerator.engine.model import (
    Decision, Grant, PolicyDoc, Principal, RequestContext, Statement, Strength, Tri,
)
from aws_enumerator.engine.policy.apply import Gate, action_covers, action_overlaps, apply_statement, g_and
from aws_enumerator.engine.policy.arn import bucket_arn, parse_arn, unqualified_lambda_arn
from aws_enumerator.engine.policy.parse import parse_policy

#: Services whose resources can carry a resource-based policy (AWS "AWS services that work with IAM").
RESOURCE_POLICY_SERVICES = frozenset({
    "s3", "sqs", "sns", "secretsmanager", "lambda", "ecr", "kms", "glacier", "es", "aoss", "backup", "events",
    "logs", "codeartifact", "iam", "sts", "dynamodb", "apigateway", "execute-api", "elasticfilesystem",
    "serverlessrepo", "mediastore", "ram", "cognito-idp", "kinesis", "ssm-incidents", "signer"})

ANONYMOUS = Principal("anonymous", "*", None, None, None, None)
ANY_AWS = Principal("wildcard", "*", None, None, None, None)


@dataclass(frozen=True)
class KmsGrant:
    """One KMS grant: ``grantee`` (principal ARN) may call ``operations`` on the key."""

    grantee: str
    operations: Tuple[str, ...]
    grant_id: Optional[str] = None


class ResourcePolicyIndex:
    """Resource-based policies by resource ARN and layer (see module docstring)."""

    def __init__(self, *, default_owner: Optional[str] = None, partition: str = "aws"):
        self.default_owner = default_owner
        self.partition = partition
        self._policies: Dict[Tuple[str, str], PolicyDoc] = {}
        self._absent: Set[Tuple[str, str]] = set()
        self._unknown: Set[Tuple[str, str]] = set()
        self._owners: Dict[str, str] = {}
        self._grants: Dict[str, List[KmsGrant]] = {}
        self._aws_managed_keys: Set[str] = set()

    # ── building ─────────────────────────────────────────────────────────────
    def add(self, resource_arn: str, policy: object, *, layer: str = "resource", owner: Optional[str] = None,
            policy_name: Optional[str] = None) -> PolicyDoc:
        """Register a policy (a :class:`PolicyDoc` or a raw document) for ``resource_arn``."""
        doc = policy if isinstance(policy, PolicyDoc) else parse_policy(
            policy, layer=layer if layer in ("trust", "key_policy") else "resource", source_type="resource",
            policy_arn=resource_arn, policy_name=policy_name or layer, partition=self.partition)
        self._policies[(layer, resource_arn)] = doc
        if owner:
            self._owners[resource_arn] = owner
        return doc

    def mark_absent(self, resource_arn: str, *, layer: str = "resource") -> None:
        """The resource was collected and has no policy of this layer."""
        self._absent.add((layer, resource_arn))

    def mark_unknown(self, resource_arn: str, *, layer: str = "resource") -> None:
        """Collection of this resource's policy failed (denied, error)."""
        self._unknown.add((layer, resource_arn))

    def set_owner(self, resource_arn: str, account: str) -> None:
        self._owners[resource_arn] = account

    def add_kms_grant(self, key_arn: str, grantee: str, operations: Iterable[str],
                      grant_id: Optional[str] = None) -> None:
        self._grants.setdefault(key_arn, []).append(
            KmsGrant(grantee, tuple(sorted({o.lower() for o in operations})), grant_id))

    def set_aws_managed_key(self, key_arn: str) -> None:
        self._aws_managed_keys.add(key_arn)

    # ── queries ──────────────────────────────────────────────────────────────
    def _candidates(self, resource_arn: str) -> Tuple[str, ...]:
        out = [resource_arn]
        b = bucket_arn(resource_arn)
        if b and b != resource_arn:
            out.append(b)
        u = unqualified_lambda_arn(resource_arn)
        if u != resource_arn:
            out.append(u)
        return tuple(out)

    def policy_for(self, resource_arn: str, layer: str = "resource") -> Optional[PolicyDoc]:
        for arn in self._candidates(resource_arn):
            doc = self._policies.get((layer, arn))
            if doc is not None:
                return doc
        return None

    def status(self, resource_arn: str, layer: str = "resource") -> str:
        """``present`` | ``absent`` | ``unknown`` for this resource and layer."""
        for arn in self._candidates(resource_arn):
            if (layer, arn) in self._policies:
                return "present"
            if (layer, arn) in self._unknown:
                return "unknown"
            if (layer, arn) in self._absent:
                return "absent"
        if layer != "resource":
            return "unknown"
        arn = parse_arn(resource_arn)
        if arn is None or arn.service.lower() not in RESOURCE_POLICY_SERVICES:
            return "absent"
        return "unknown"

    def owner_of(self, resource_arn: str) -> Optional[str]:
        for arn in self._candidates(resource_arn):
            if arn in self._owners:
                return self._owners[arn]
        return None

    def kms_grants(self, key_arn: str) -> Tuple[KmsGrant, ...]:
        return tuple(self._grants.get(key_arn, ()))

    def is_aws_managed_key(self, key_arn: str) -> bool:
        return key_arn in self._aws_managed_keys

    def resources(self, layer: str = "resource") -> Tuple[str, ...]:
        return tuple(sorted(arn for (lay, arn) in self._policies if lay == layer))


# ── Grants ───────────────────────────────────────────────────────────────────

def _resource_forms(resource_arn: str) -> Tuple[str, ...]:
    """The resource itself plus its children (objects of a bucket, qualifiers of a function)."""
    return (resource_arn, f"{resource_arn}/*", f"{resource_arn}:*")


def _statement_actions(stmt: Statement) -> Tuple[str, ...]:
    if stmt.actions is not None:
        return stmt.actions
    return ("*",)


def _allow_forms(stmt: Statement, resource_arn: str, rc: RequestContext, now: Optional[float],
                 actions: Sequence[str]) -> Tuple[Gate, Tuple[str, ...]]:
    """Truth of an Allow for this principal over the resource or its children, and the forms it applies to."""
    best = Gate(Tri.FALSE)
    forms: List[str] = []

    def test(s: Statement) -> bool:
        return any(action_overlaps(s, a) for a in actions)

    for form in _resource_forms(resource_arn):
        r = apply_statement(stmt, "", form, rc, now=now, check_principal=True, resource_mode="overlap",
                            action_test=test)
        if r.outcome is Tri.FALSE:
            continue
        forms.append(form)
        if r.outcome is Tri.TRUE:
            best = Gate(Tri.TRUE)
        elif best.t is Tri.FALSE:
            best = Gate(Tri.MAYBE, r.gate)
    return best, tuple(forms)


def _deny_effect(stmt: Statement, forms: Sequence[str], rc: RequestContext, now: Optional[float],
                 actions: Sequence[str]) -> Tuple[Gate, bool]:
    """(gate, overlaps) of a Deny against one grant.

    The gate is non-FALSE only when the Deny removes the **whole** grant: it covers every granted action on every
    resource form the grant applies to. A Deny that only overlaps the grant (one action, one prefix) is reported
    through ``overlaps`` and recorded in ``Grant.deny_offsets``, never as a DENY of the grant.
    """
    gates: List[Gate] = []
    overlaps = False
    for form in forms:
        full = apply_statement(stmt, "", form, rc, now=now, check_principal=True, resource_mode="covers",
                               action_test=lambda s: all(action_covers(s, a) for a in actions))
        gates.append(Gate(full.outcome, full.gate))
        if not overlaps:
            part = apply_statement(stmt, "", form, rc, now=now, check_principal=True, resource_mode="overlap",
                                   action_test=lambda s: any(action_overlaps(s, a) for a in actions))
            overlaps = part.outcome is not Tri.FALSE
    if not gates or any(g.t is Tri.FALSE for g in gates):
        return Gate(Tri.FALSE), overlaps
    return g_and(*gates), True


def _grant_requesters(stmt: Statement) -> List[Tuple[Principal, bool]]:
    """(requester principal, has_notprincipal) pairs an Allow statement grants."""
    if stmt.principals is None and stmt.not_principals is not None:
        return [(ANONYMOUS, True), (ANY_AWS, True)]
    out: List[Tuple[Principal, bool]] = []
    for p in stmt.principals or ():
        if p.kind == "wildcard":
            out.extend([(ANONYMOUS, False), (ANY_AWS, False)])
        elif p.kind not in ("unique_id", "canonical_user"):
            out.append((p, False))
    return out


def policy_grants(policy: PolicyDoc, resource_arn: str, rc_for: Callable[[Principal], RequestContext], *,
                  now: Optional[float] = None) -> List[Grant]:
    """Every (Allow statement, principal) grant of ``policy`` with the decision for that principal."""
    denies = [s for s in policy.statements if s.effect == "Deny"]
    grants: List[Grant] = []
    for stmt in policy.statements:
        if stmt.effect != "Allow":
            continue
        actions = _statement_actions(stmt)
        for principal, has_not in _grant_requesters(stmt):
            rc = rc_for(principal)
            allow, forms = _allow_forms(stmt, resource_arn, rc, now, actions)
            if allow.t is Tri.FALSE:
                continue
            deny_gates, offsets = [], []
            for d in denies:
                g, overlaps = _deny_effect(d, forms, rc, now, actions)
                if g.t is not Tri.FALSE:
                    deny_gates.append(g)
                if overlaps:
                    offsets.append(d.source.statement_index)
            decision, strength = _decide(allow, deny_gates)
            grants.append(Grant(principal=principal, actions=tuple(actions), decision=decision, strength=strength,
                                has_notprincipal=has_not, deny_offsets=tuple(offsets), source=stmt.source))
    grants.sort(key=lambda g: (g.source.statement_index if g.source else 0, g.principal.kind, g.principal.raw))
    return grants


def _decide(allow: Gate, deny_gates: Sequence[Gate]) -> Tuple[Decision, Strength]:
    if any(g.t is Tri.TRUE for g in deny_gates):
        return Decision.DENY, Strength.NONE
    # To be granted, the allow must hold and every MAYBE deny must be escaped.
    escapes = [Gate(Tri.MAYBE, g.gate) for g in deny_gates if g.t is Tri.MAYBE]
    total = g_and(allow, *escapes)
    if total.t is Tri.TRUE:
        return Decision.ALLOW, Strength.NONE
    return Decision.CONDITIONAL, total.gate


#: Global condition keys that tie a service principal's request to the resource, account or organisation it acts
#: for (AWS IAM User Guide, "The confused deputy problem" and "AWS global condition context keys").
SOURCE_CONTEXT_KEYS: FrozenSet[str] = frozenset({
    "aws:sourcearn", "aws:sourceaccount", "aws:sourceorgid", "aws:sourceorgpaths"})


def _source_keys(stmt: Statement) -> Tuple[str, ...]:
    return tuple(sorted({c.key for c in stmt.conditions if c.key in SOURCE_CONTEXT_KEYS}))


def _deny_guards(deny: Statement, grant: Grant) -> bool:
    """A Deny that names a source key and can apply to the grant's service principal and actions."""
    if not _source_keys(deny):
        return False
    if deny.principals is not None:
        if not any(p.kind == "wildcard" or (p.kind == "service" and p.raw.lower() == grant.principal.raw.lower())
                   for p in deny.principals):
            return False
    elif deny.not_principals is not None:
        if any(p.kind == "service" and p.raw.lower() == grant.principal.raw.lower() for p in deny.not_principals):
            return False
    return any(action_overlaps(deny, a) for a in grant.actions)


def unguarded_service_grants(policy: PolicyDoc, grants: Iterable[Grant]) -> List[Grant]:
    """The grants of ``policy`` to AWS service principals that no source condition restricts (F-033).

    A service principal (``s3.amazonaws.com``, ``sns.amazonaws.com``, ``events.amazonaws.com`` …) acts for every
    AWS customer. A resource-policy Allow for it without ``aws:SourceArn`` / ``aws:SourceAccount`` /
    ``aws:SourceOrgID`` / ``aws:SourceOrgPaths`` lets that service act on the resource on behalf of resources in
    **any** account (an attacker's bucket notification, topic or rule). The grant counts as guarded when its own
    statement carries one of those keys (any operator), or when a Deny of the same policy that can apply to the
    service and the granted actions does (``Deny … StringNotEquals aws:SourceAccount``). Only granting decisions
    (``allow`` / ``conditional``) are returned, in the walker's order.
    """
    by_index = {s.source.statement_index: s for s in policy.statements}
    denies = [s for s in policy.statements if s.effect == "Deny"]
    out: List[Grant] = []
    for g in grants:
        if g.principal.kind != "service" or not g.decision.grants:
            continue
        stmt = by_index.get(g.source.statement_index) if g.source is not None else None
        if stmt is not None and _source_keys(stmt):
            continue
        if any(_deny_guards(d, g) for d in denies):
            continue
        out.append(g)
    return out


def strongest_public(grants: Iterable[Grant]) -> Optional[Grant]:
    """The most permissive public grant (anonymous first, then any AWS principal), or ``None``."""
    public = [g for g in grants if g.principal.kind in ("anonymous", "wildcard") and g.decision.grants]
    if not public:
        return None
    return sorted(public, key=lambda g: (-g.decision.rank, g.strength.rank,
                                         0 if g.principal.kind == "anonymous" else 1))[0]


def grants_by_principal(grants: Iterable[Grant]) -> Mapping[str, List[Grant]]:
    out: Dict[str, List[Grant]] = {}
    for g in grants:
        out.setdefault(g.principal.arn or g.principal.raw, []).append(g)
    return out


__all__ = ["ANONYMOUS", "ANY_AWS", "KmsGrant", "RESOURCE_POLICY_SERVICES", "ResourcePolicyIndex", "SOURCE_CONTEXT_KEYS",
           "policy_grants", "strongest_public", "grants_by_principal", "unguarded_service_grants", "Strength"]
