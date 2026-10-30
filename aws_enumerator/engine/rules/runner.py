"""Rule execution (engine.md §3.1-§3.5; F-011, F-012, F-015, F-016, F-017, F-019, F-069, F-071, F-113).

Every rule is evaluated **through the evaluator**, per principal and per target, never against a flat action
set:

* **targets** (``target.select``): ``self_or_principal`` (the principal itself plus other users/roles/groups),
  ``principal`` (others only: credential and trust takeover; self-scoped grants such as
  ``user/${aws:username}`` therefore never fire, F-017), ``group_membership``, ``attached_customer_policy``,
  ``passable_service_role`` (roles R ≠ P that P may pass to the service, whose trust admits the service and that
  are more privileged than P, F-012) and ``existing`` (collected resources that run as a role: functions, dev
  endpoints, build projects, stacks, StackSets, notebooks, Studio profiles, ECS Exec services, instances and
  launch templates; :mod:`.inventory`). When a principal/policy selector finds no concrete target, a **probe**
  target stands for "any principal (or policy) of that kind, including ones not collected": it matches
  unrestricted grants (``*``, ``user/*``) and never a scoped one;
* **target filters**: ``login_profile`` (``present`` / ``absent``) and ``access_keys`` (``below_limit`` /
  ``at_limit``: CreateAccessKey fails on a user that already has two keys unless one is deleted first);
  ``trusted_services`` (any of several service principals) and ``trust_protocol`` (``WebIdentity`` for Cognito
  identity pools) for passable roles;
* **chain completeness** (F-069): every ``all`` child and at least one ``any`` child must be ALLOW or
  CONDITIONAL; the chain's decision is its weakest step;
* **context probes** (F-015): ``iam:PassedToService`` and ``iam:PolicyARN`` are set by the step, so a PassRole
  grant scoped to another service does not satisfy the rule;
* **provenance** (F-071): ``evidence.steps`` lists, per rule action, the decision and the statements that
  granted it (wildcard-resource statements first) plus the denies considered; ``matched_actions`` is the union of
  the rule actions on the path that fired, including the ``any`` alternative;
* **DANGER rules** (F-019) are capability probes (:meth:`Evaluator.evaluate_capability`) over resource templates;
* **administrator equivalence** (engine.md §3.4): a principal whose identity allows ``*`` on ``*`` (ALLOW), or
  that holds full IAM control (DANGER-002, ALLOW) and can definitely modify its own permissions, is
  administrator-equivalent (:attr:`RulesResult.admins`); the pipeline adds ``IS_ADMIN_EQUIVALENT`` edges for the
  ones the identity analyzer does not cover and ``rules/subsume.py`` reports them once as ADMIN-001 (F-018).

Outputs are pure data (:class:`RuleHit`, :class:`RuleEdge`); :mod:`.emit` writes them to the graph builder or to
the d13c215 record shape. :data:`ANALYZERS` registers the pipeline entry point (engine-api.md §5).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple

from aws_enumerator.engine.model import (
    SEVERITY_RANK, Capability, Decision, EvalResult, PolicySource, Principal, PrincipalModel, Statement, Strength,
)
from aws_enumerator.engine.rules import severity as sev
from aws_enumerator.engine.rules.catalogue import (
    DangerRule, Group, Leaf, PrivescRule, RuleCatalogue, Step, load_catalogue,
)
from aws_enumerator.engine.rules.emit import (
    emit_admin_edges, emit_to_builder, finding_evidence, legacy_finding, targets_detail, targets_json,
)
from aws_enumerator.engine.rules.inventory import (
    EXISTING_TYPES, PROBE_NAME, ExistingResource, access_key_counts, expand,
)
from aws_enumerator.engine.rules.inventory import existing_from_data as _inventory_from_data

log = logging.getLogger(__name__)

_GRANTS = (Decision.ALLOW, Decision.CONDITIONAL)
_NOT_ALLOWED = EvalResult(Decision.NOT_ALLOWED, reason="no_allow")
ADMIN_CAPABILITY = "ADMIN"
#: Capabilities that make a principal's access "crown jewels" (engine.md §3.3 target tier HIGH).
CROWN_JEWELS = frozenset({"DANGER-001", "DANGER-002", "DANGER-003", "DANGER-004", "DANGER-007", "DANGER-008",
                          "DANGER-009", "DANGER-010"})
#: Rule classes whose self-targeted hit is an escalation of the principal's own permissions.
MODIFY_CLASSES = frozenset({"policy-modification", "principal-modification"})
ACCESS_KEY_LIMIT = 2


# ── inputs ───────────────────────────────────────────────────────────────────

@dataclass
class RulesContext:
    """What the runner needs: the evaluator, the principal set and the existing-resource inventory.

    ``access_keys`` maps user ARNs to their access-key count (``None`` unknown); ``probe_uncollected`` makes
    existing-resource rules over resource types no collector lists run against a probe target (conditional,
    low severity) instead of not at all.
    """

    evaluator: Any
    principals: Any                                     # iam.principals.PrincipalSet
    existing: Mapping[str, Sequence[ExistingResource]] = field(default_factory=dict)
    catalogue: Optional[RuleCatalogue] = None
    access_keys: Mapping[str, Optional[int]] = field(default_factory=dict)
    probe_uncollected: bool = False

    @property
    def account(self) -> Optional[str]:
        return self.principals.account_id

    @property
    def partition(self) -> str:
        return self.principals.partition


# ── outputs ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Target:
    """A candidate the rule's ``$target`` steps are evaluated against."""

    arn: str
    kind: str                       # user | role | group | policy | a resource node type
    node_id: Optional[str]
    is_self: bool = False
    probe: bool = False
    holders: Tuple[str, ...] = ()   # policy targets: principals the policy is attached to
    gained_role: Optional[str] = None   # passable roles / existing resources: the role whose rights are gained
    meta: Tuple[Tuple[str, Any], ...] = ()
    uncollected: bool = False       # a probe for a resource type no collector lists


@dataclass(frozen=True)
class StepOutcome:
    """Decision of a step tree for one (principal, target)."""

    decision: Decision
    strength: Strength = Strength.NONE
    matched: Tuple[str, ...] = ()
    evidence: Tuple[Mapping[str, Any], ...] = ()
    gaps: FrozenSet[str] = frozenset()

    @property
    def grants(self) -> bool:
        return self.decision in _GRANTS


@dataclass(frozen=True)
class TargetResult:
    target: Target
    outcome: StepOutcome
    tier: str                       # admin | high | medium | probe | self | uncollected


@dataclass(frozen=True)
class RuleEdge:
    source: str
    edge_type: str
    target: str
    decision: Decision
    strength: Strength
    evidence: Mapping[str, Any]


@dataclass
class RuleHit:
    """One rule that fires for one principal."""

    rule_id: str
    kind: str                       # privesc | dangerous
    principal: PrincipalModel
    decision: Decision
    strength: Strength
    severity: str
    base_severity: str
    title: str
    description: str
    remediation: str
    matched_actions: Tuple[str, ...]
    steps: Tuple[Mapping[str, Any], ...]
    targets: List[TargetResult] = field(default_factory=list)
    edges: List[RuleEdge] = field(default_factory=list)
    gaps: FrozenSet[str] = frozenset()
    no_candidate: bool = False
    legacy: Dict[str, Any] = field(default_factory=dict)
    rule_class: str = ""

    @property
    def confidence(self) -> str:
        return "conditional" if self.decision is Decision.CONDITIONAL else "definite"


@dataclass
class RulesResult:
    hits: List[RuleHit] = field(default_factory=list)
    gaps: Dict[str, str] = field(default_factory=dict)
    #: Administrator-equivalent principals: id → ``{"basis": ..., "rule_ids": [...]}`` (engine.md §3.4).
    admins: Dict[str, Dict[str, Any]] = field(default_factory=dict)


# ── privilege oracle (target tiers, "more privileged") ───────────────────────

class PrivilegeOracle:
    """Capability sets and tiers of principals, memoised (engine.md §3.3)."""

    def __init__(self, rctx: RulesContext, catalogue: RuleCatalogue):
        self.rctx = rctx
        self.probes: Tuple[Tuple[str, Capability], ...] = tuple(
            (d.id, d.probe(partition=rctx.partition, account=rctx.account or "*")) for d in catalogue.dangerous)
        self._caps: Dict[str, FrozenSet[str]] = {}

    def capabilities(self, principal_id: str) -> FrozenSet[str]:
        """DANGER ids (and ``ADMIN``) the principal holds (ALLOW or CONDITIONAL)."""
        hit = self._caps.get(principal_id)
        if hit is not None:
            return hit
        model = self.rctx.principals.models.get(principal_id)
        out = set()
        if model is not None:
            ev = self.rctx.evaluator
            for rid, cap in self.probes:
                if ev.evaluate_capability(model, cap).decision in _GRANTS:
                    out.add(rid)
            admin = ev.evaluate_capability(model, Capability("*", action_glob="*"))
            if admin.decision is Decision.ALLOW:
                out.add(ADMIN_CAPABILITY)
        self._caps[principal_id] = frozenset(out)
        return self._caps[principal_id]

    def is_admin(self, principal_id: str) -> bool:
        caps = self.capabilities(principal_id)
        return ADMIN_CAPABILITY in caps

    def tier(self, target_id: Optional[str], caller_id: str) -> str:
        """``admin`` / ``high`` (crown jewels the caller lacks) / ``medium``."""
        if target_id is None:
            return "probe"
        if self.is_admin(target_id):
            return "admin"
        gained = (self.capabilities(target_id) & CROWN_JEWELS) - self.capabilities(caller_id)
        return "high" if gained else "medium"

    def more_privileged(self, target_id: str, caller_id: str) -> bool:
        """``False`` only when every dangerous capability of the target is already the caller's."""
        target_caps = self.capabilities(target_id)
        if not target_caps:
            return not self.is_admin(caller_id)
        return not target_caps <= self.capabilities(caller_id)


# ── target selection ─────────────────────────────────────────────────────────

def _probe_arn(kind: str, rctx: RulesContext) -> str:
    return f"arn:{rctx.partition}:iam::{rctx.account or '000000000000'}:{kind}/{PROBE_NAME}"


def _template_for(rule: PrivescRule, rctx: RulesContext) -> str:
    sel = rule.target
    if sel["select"] in ("self_or_principal", "principal"):
        res = f"{sel['kind']}/*"
    elif sel["select"] == "group_membership":
        res = "group/*"
    elif sel["select"] == "attached_customer_policy":
        res = "policy/*"
    elif sel["select"] == "passable_service_role":
        res = "role/*"
    else:
        return expand(EXISTING_TYPES[sel["resource_type"]].template, partition=rctx.partition, account=rctx.account)
    return f"arn:{rctx.partition}:iam::{rctx.account or '*'}:{res}"


def _principal_targets(rule: PrivescRule, p: PrincipalModel, rctx: RulesContext) -> List[Target]:
    sel = rule.target
    kind = sel["kind"]
    include_self = sel["select"] == "self_or_principal"
    out: List[Target] = []
    for q in rctx.principals.of_kind(kind):
        is_self = q.id == p.id or (kind == "group" and q.id in p.groups)
        if is_self and not include_self:
            continue
        if kind == "role" and not include_self and q.is_service_linked:
            continue          # UpdateAssumeRolePolicy is refused on service-linked roles
        if not _login_profile_ok(sel.get("login_profile"), rctx.principals.login_profiles.get(q.id)):
            continue
        if not _access_keys_ok(sel.get("access_keys"), rctx.access_keys.get(q.id)):
            continue
        if sel.get("boundary") == "present" and q.boundary is None:
            continue          # removing or replacing a boundary gains nothing on a principal without one
        out.append(Target(q.id, kind, q.id, is_self=is_self))
    return out


def _login_profile_ok(want: Optional[str], has: Optional[bool]) -> bool:
    if want is None or has is None:
        return True
    return has if want == "present" else not has


def _access_keys_ok(want: Optional[str], count: Optional[int]) -> bool:
    """``below_limit``: a new key can be created; ``at_limit``: one must be deleted first (unknown: both)."""
    if want is None or count is None:
        return True
    return count < ACCESS_KEY_LIMIT if want == "below_limit" else count >= ACCESS_KEY_LIMIT


def _group_targets(p: PrincipalModel, rctx: RulesContext) -> List[Target]:
    return [Target(g.id, "group", g.id) for g in rctx.principals.of_kind("group") if g.id not in p.groups]


def _policy_targets(p: PrincipalModel, rctx: RulesContext) -> List[Target]:
    mine = {p.id, *p.groups}
    out = []
    for parn in sorted(rctx.principals.policy_holders):
        holders = tuple(sorted(set(rctx.principals.policy_holders[parn])))
        out.append(Target(parn, "policy", None, is_self=bool(mine & set(holders)), holders=holders))
    return out


def _trust_result(rule: PrivescRule, role_id: str, rctx: RulesContext) -> EvalResult:
    """Best decision of the role's trust for the rule's service principals (or federated principal)."""
    sel = rule.target
    ev = rctx.evaluator
    if sel.get("trust_protocol") == "WebIdentity":
        return ev.can_assume(sel["trusted_principal"], role_id, protocol="WebIdentity")
    best = _NOT_ALLOWED
    for service in sel.get("trusted_services") or (sel["service_principal"],):
        result = ev.can_assume(f"svc:{service}", role_id)
        if result.decision.rank > best.decision.rank:
            best = result
        if best.decision is Decision.ALLOW:
            break
    return best


#: Creating an instance profile for a role that has none (needed to hand a role to EC2 instances).
_PROFILE_STEPS = Group("all", (Leaf("iam:createinstanceprofile", "arn:{partition}:iam::{account}:instance-profile/*"),
                               Leaf("iam:addroletoinstanceprofile",
                                    "arn:{partition}:iam::{account}:instance-profile/*")))


def _profile_meta(rule: PrivescRule, p: PrincipalModel, role_id: str, rctx: RulesContext,
                  cache: Dict[str, bool]) -> Optional[List[Tuple[str, Any]]]:
    """Instance-profile facts of a candidate role; ``None`` when the role cannot reach an instance.

    Rules whose role is handed over as an instance profile (``target.instance_profile: required``: RunInstances,
    Spot, Auto Scaling, EMR, Image Builder, profile association) need the role to be in a profile, or the
    principal to be able to create one (e-policy handoff: PRIVESC-015 did not require it). Unknown profiles keep
    the role.
    """
    profiles = rctx.principals.instance_profile_roles
    service = rule.target["service_principal"]
    if profiles is None or (rule.target.get("instance_profile") != "required" and service != "ec2.amazonaws.com"):
        return []
    if role_id in profiles:
        return [("in_instance_profile", True)]
    if rule.target.get("instance_profile") != "required":
        return [("in_instance_profile", False)]
    if "creatable" not in cache:
        cache["creatable"] = StepEvaluator(rctx, p).run(_PROFILE_STEPS, None, "*").grants
    return [("in_instance_profile", False), ("instance_profile", "creatable")] if cache["creatable"] else None


def _passable_targets(rule: PrivescRule, p: PrincipalModel, rctx: RulesContext,
                      oracle: PrivilegeOracle) -> List[Target]:
    out = []
    cache: Dict[str, bool] = {}
    for r in rctx.principals.of_kind("role"):
        if r.id == p.id or r.is_service_linked:
            continue
        trust = _trust_result(rule, r.id, rctx)
        if trust.decision not in _GRANTS or not oracle.more_privileged(r.id, p.id):
            continue
        profile = _profile_meta(rule, p, r.id, rctx, cache)
        if profile is None:
            continue
        meta = [("trust_decision", trust.decision.value)] + profile
        out.append(Target(r.id, "role", r.id, gained_role=r.id, meta=tuple(meta)))
    return out


def _existing_targets(rule: PrivescRule, p: PrincipalModel, rctx: RulesContext) -> List[Target]:
    rtype = EXISTING_TYPES[rule.target["resource_type"]]
    if not rtype.collected:
        if not rctx.probe_uncollected:
            return []
        arn = rtype.probe_arn(partition=rctx.partition, account=rctx.account)
        return [Target(arn, rtype.node_type or "resource", None, probe=True, uncollected=True,
                       meta=(("resource_type", rtype.name),))]
    out = []
    for res in sorted(rctx.existing.get(rtype.name, ()), key=lambda r: r.arn):
        if not res.role_arn or res.role_arn == p.id:
            continue
        node_id = res.arn if rtype.node_type else None
        out.append(Target(res.arn, rtype.node_type or "resource", node_id, gained_role=res.role_arn,
                          meta=(("resource_type", rtype.name),)))
    return out


def select_targets(rule: PrivescRule, p: PrincipalModel, rctx: RulesContext, oracle: PrivilegeOracle) -> List[Target]:
    """Concrete targets of ``rule`` for ``p`` (a probe target when a principal/policy selector finds none)."""
    sel = rule.selector
    if sel in ("self_or_principal", "principal"):
        found = _principal_targets(rule, p, rctx)
        probe_kind = rule.target["kind"]
    elif sel == "group_membership":
        found, probe_kind = _group_targets(p, rctx), "group"
    elif sel == "attached_customer_policy":
        found, probe_kind = _policy_targets(p, rctx), "policy"
    elif sel == "passable_service_role":
        return _passable_targets(rule, p, rctx, oracle)
    else:
        return _existing_targets(rule, p, rctx)
    if not found and rule.target.get("probe", True):
        found = [Target(_probe_arn(probe_kind, rctx), probe_kind, None, probe=True)]
    return found


# ── step evaluation ──────────────────────────────────────────────────────────

class _StatementLookup:
    """PolicySource → Statement for evidence (identity and boundary statements of one principal)."""

    def __init__(self, model: PrincipalModel):
        self._map: Dict[PolicySource, Statement] = {}
        for stmt in model.identity:
            self._map.setdefault(stmt.source, stmt)
        if isinstance(model.boundary, tuple):
            for stmt in model.boundary:
                self._map.setdefault(stmt.source, stmt)

    def get(self, src: PolicySource) -> Optional[Statement]:
        return self._map.get(src)


def statement_evidence(src: PolicySource, stmt: Optional[Statement]) -> Dict[str, Any]:
    """One granting statement in the provenance shape of engine.md §3.5."""
    out: Dict[str, Any] = {k: v for k, v in src.to_json().items() if v is not None}
    if stmt is not None:
        if stmt.resources is not None:
            out["resources"] = list(stmt.resources)
        if stmt.not_resources is not None:
            out["not_resources"] = list(stmt.not_resources)
        if stmt.actions is not None:
            out["actions"] = list(stmt.actions)
        if stmt.not_actions is not None:
            out["not_actions"] = list(stmt.not_actions)
        if stmt.conditions:
            out["conditions"] = [{"operator": (c.qualifier + ":" if c.qualifier else "") + c.operator
                                  + ("IfExists" if c.if_exists else ""), "key": c.key, "values": list(c.values)}
                                 for c in stmt.conditions]
    return out


def _wildcard_first(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(entries, key=lambda e: (0 if "*" in (e.get("resources") or ()) else 1))


class StepEvaluator:
    """Evaluates rule step trees for one principal (memoised through the evaluator)."""

    def __init__(self, rctx: RulesContext, model: PrincipalModel):
        self.rctx = rctx
        self.model = model
        self.lookup = _StatementLookup(model)

    def run(self, step: Step, target_arn: Optional[str], template: str) -> StepOutcome:
        if isinstance(step, Leaf):
            return self._leaf(step, target_arn, template)
        outs = [self.run(c, target_arn, template) for c in step.children]
        return _all(outs) if step.op == "all" else _any(outs)

    def _leaf(self, leaf: Leaf, target_arn: Optional[str], template: str) -> StepOutcome:
        rctx = self.rctx
        context = {k: expand(v, partition=rctx.partition, account=rctx.account) for k, v in leaf.context}
        ev = rctx.evaluator
        if leaf.uses_target:
            resource = target_arn or template
            concrete = target_arn is not None
        else:
            resource = expand(leaf.resource, partition=rctx.partition, account=rctx.account)
            concrete = leaf.mode == "target"
        if concrete:
            result = ev.evaluate(self.model, leaf.action, resource, context=context or None)
        else:
            result = ev.evaluate_any(self.model, leaf.action, resource, context=context or None)
        granted = _wildcard_first([statement_evidence(s, self.lookup.get(s)) for s in result.allow_refs
                                   if s.layer == "identity"])
        evidence = {"rule_action": leaf.action, "resource": resource, "decision": result.decision.value,
                    "granted": granted,
                    "denies_considered": [statement_evidence(s, self.lookup.get(s)) for s in result.deny_refs]}
        if context:
            evidence["context"] = dict(sorted(context.items()))
        strength = result.strength if result.decision is Decision.CONDITIONAL else Strength.NONE
        return StepOutcome(result.decision, strength, (leaf.action,), (evidence,), frozenset(result.gaps))


def _all(outs: Sequence[StepOutcome]) -> StepOutcome:
    failing = [o for o in outs if not o.grants]
    gaps = frozenset().union(*(o.gaps for o in outs))
    if failing:
        worst = min(failing, key=lambda o: o.decision.rank)
        return StepOutcome(worst.decision, Strength.NONE, (), tuple(e for o in outs for e in o.evidence), gaps)
    conditional = [o for o in outs if o.decision is Decision.CONDITIONAL]
    decision = Decision.CONDITIONAL if conditional else Decision.ALLOW
    strength = Strength.strongest(o.strength for o in conditional)
    matched = tuple(sorted({a for o in outs for a in o.matched}))
    return StepOutcome(decision, strength, matched, tuple(e for o in outs for e in o.evidence), gaps)


def _any(outs: Sequence[StepOutcome]) -> StepOutcome:
    best = max(outs, key=lambda o: (o.decision.rank, -o.strength.rank))
    if not best.grants:
        return StepOutcome(best.decision, Strength.NONE, (), tuple(e for o in outs for e in o.evidence),
                           frozenset().union(*(o.gaps for o in outs)))
    return best


# ── one rule for one principal ───────────────────────────────────────────────

def _tier_for(t: Target, p: PrincipalModel, oracle: PrivilegeOracle) -> str:
    if t.is_self:
        return "self"
    if t.uncollected:
        return "uncollected"
    if t.probe:
        return "probe"
    if t.kind == "policy":
        tiers = [oracle.tier(h, p.id) for h in t.holders] or ["medium"]
        return min(tiers, key=_TIER_ORDER.__getitem__)
    return oracle.tier(t.gained_role or t.node_id, p.id)


_TIER_ORDER = {"self": 0, "admin": 1, "high": 2, "probe": 2, "medium": 3, "uncollected": 4}


def _target_severity(rule: PrivescRule, tr: TargetResult) -> Tuple[str, str]:
    base = sev.base_severity(rule.rule_class, rule.base_severity, self_target=tr.tier == "self",
                             tiers=[tr.tier if tr.tier != "self" else "admin"])
    conditional = tr.outcome.decision is Decision.CONDITIONAL
    return base, sev.adjust(base, tr.outcome.strength, conditional=conditional)


def _versions_gap(rule: PrivescRule, t: Target, rctx: RulesContext, oracle: PrivilegeOracle
                  ) -> Tuple[Optional[bool], Optional[str]]:
    """PRIVESC-002 (F-110): does a non-default version grant more than the default? ``None`` = unknown."""
    if rule.target.get("versions") != "more_permissive_non_default" or t.kind != "policy" or t.probe:
        return True, None
    versions = rctx.principals.policy_versions.get(t.arn)
    if versions is None:
        return None, "iam:versions-not-collected"
    default = [v for v in versions.values() if v.is_default_version]
    others = [v for v in versions.values() if not v.is_default_version]
    if not others:
        return False, None
    base_caps = _doc_caps(default[0].statements if default else (), rctx, oracle)
    return any(_doc_caps(v.statements, rctx, oracle) - base_caps for v in others), None


def _doc_caps(statements: Sequence[Statement], rctx: RulesContext, oracle: PrivilegeOracle) -> FrozenSet[str]:
    from aws_enumerator.engine.iam.principals import build_action_index
    from aws_enumerator.engine.policy.evaluator import Evaluator
    model = PrincipalModel(id="aws-enumerator:policy-version", principal=_DOC_PRINCIPAL,
                           identity=tuple(statements), boundary=None, groups=(), tags={}, scp_chain=(),
                           is_service_linked=False, action_index=build_action_index(tuple(statements)),
                           gaps=frozenset())
    ev = Evaluator(None, {}, account_id=rctx.account, partition=rctx.partition)
    out = {rid for rid, cap in oracle.probes if ev.evaluate_capability(model, cap).decision in _GRANTS}
    if ev.evaluate_capability(model, Capability("*", action_glob="*")).decision is Decision.ALLOW:
        out.add(ADMIN_CAPABILITY)
    return frozenset(out)


#: Stand-in requester for evaluating one policy version on its own (PRIVESC-002).
_DOC_PRINCIPAL = Principal("aws_user", "aws-enumerator:policy-version", None, None, None, None)


def _qualify(rule: PrivescRule, t: Target, outcome: StepOutcome, rctx: RulesContext,
             oracle: PrivilegeOracle) -> Optional[StepOutcome]:
    """Target-specific downgrades: unknown policy versions (PRIVESC-002) and uncollected resource types."""
    more, gap = _versions_gap(rule, t, rctx, oracle)
    if more is False:
        return None
    gaps = set(outcome.gaps)
    if more is None:
        gaps.add(str(gap))
    if t.uncollected:
        gaps.add(f"{dict(t.meta).get('resource_type', 'resource')}:not-collected")
    if rule.target.get("condition_gap") and not t.probe:
        gaps.add(str(rule.target["condition_gap"]))
    if gaps == set(outcome.gaps):
        return outcome
    return StepOutcome(Decision.CONDITIONAL, Strength.strongest((outcome.strength, Strength.WEAK)),
                       outcome.matched, outcome.evidence, frozenset(gaps))


def run_privesc_rule(rule: PrivescRule, p: PrincipalModel, rctx: RulesContext,
                     oracle: PrivilegeOracle) -> Optional[RuleHit]:
    """Evaluate one privesc rule for one principal (``None`` when it does not fire)."""
    steps = StepEvaluator(rctx, p)
    template = _template_for(rule, rctx)
    existential = steps.run(rule.steps, None, template)
    if not existential.grants:
        return None
    results: List[TargetResult] = []
    gaps = set(existential.gaps)
    for t in select_targets(rule, p, rctx, oracle):
        # an uncollected resource type: "some resource of the type" is the existential question
        outcome = existential if t.uncollected else steps.run(rule.steps, t.arn, template)
        if not outcome.grants:
            continue
        qualified = _qualify(rule, t, outcome, rctx, oracle)
        if qualified is None:
            continue
        results.append(TargetResult(t, qualified, _tier_for(t, p, oracle)))
        gaps |= qualified.gaps
    if not results and rule.selector != "passable_service_role":
        return None
    return _build_hit(rule, p, rctx, existential, results, frozenset(gaps))


def _rank_target(rule: PrivescRule, tr: TargetResult) -> Tuple[int, int, int, str]:
    _, adjusted = _target_severity(rule, tr)
    return (SEVERITY_RANK[adjusted], -tr.outcome.decision.rank, tr.outcome.strength.rank, tr.target.arn)


def _no_candidate_hit(rule: PrivescRule, p: PrincipalModel, existential: StepOutcome,
                      gaps: FrozenSet[str]) -> RuleHit:
    sel = rule.target
    services = list(sel.get("trusted_services") or ()) or [sel.get("trusted_principal") or sel["service_principal"]]
    who = ", ".join(services)
    return RuleHit(
        rule.id, "privesc", p, existential.decision, existential.strength, "INFO", "INFO",
        f"{rule.name}: no passable role currently trusts {who}",
        f"{rule.description}, but no role that this principal may pass currently trusts {who} and is more "
        f"privileged than the principal.", rule.remediation, existential.matched, existential.evidence,
        gaps=gaps, no_candidate=True, legacy={"services": services}, rule_class=rule.rule_class)


def _build_hit(rule: PrivescRule, p: PrincipalModel, rctx: RulesContext, existential: StepOutcome,
               results: List[TargetResult], gaps: FrozenSet[str]) -> RuleHit:
    results = sorted(results, key=lambda tr: _rank_target(rule, tr))
    if not results:
        return _no_candidate_hit(rule, p, existential, gaps)
    best = results[0]
    base, adjusted = _target_severity(rule, best)
    decision = Decision.ALLOW if any(tr.outcome.decision is Decision.ALLOW for tr in results) \
        else Decision.CONDITIONAL
    strength = Strength.NONE if decision is Decision.ALLOW else min(
        (tr.outcome.strength for tr in results), key=lambda s: s.rank)
    hit = RuleHit(rule.id, "privesc", p, decision, strength, adjusted, base, f"{rule.name}: {rule.description}",
                  rule.description, rule.remediation, best.outcome.matched, best.outcome.evidence,
                  targets=results, gaps=gaps, rule_class=rule.rule_class)
    hit.edges = _edges_for(rule, p, rctx, results)
    return hit


def _edges_for(rule: PrivescRule, p: PrincipalModel, rctx: RulesContext,
               results: Sequence[TargetResult]) -> List[RuleEdge]:
    from aws_enumerator.engine.graph.ids import account_admin_id
    admin = account_admin_id(rctx.account) if rctx.account else None
    edges: List[RuleEdge] = []
    for tr in results:
        t, o = tr.target, tr.outcome
        ev: Dict[str, Any] = {"rule_ids": [rule.id], "matched_actions": list(o.matched)}
        if rule.emits.get("via"):
            ev["via"] = [rule.emits["via"]]
        for edge_type, dest in _edge_dests(rule, p, t, admin):
            if dest and dest != p.id:
                edges.append(RuleEdge(p.id, edge_type, dest, o.decision, o.strength, ev))
    return edges


def _edge_dests(rule: PrivescRule, p: PrincipalModel, t: Target, admin: Optional[str]) -> List[Tuple[str, str]]:
    if t.probe:
        return []
    self_edge, other_edge = rule.emits.get("self"), rule.emits.get("other")
    if t.kind == "policy":
        mine = {p.id, *p.groups}
        out = [(self_edge, admin)] if self_edge and mine & set(t.holders) else []
        return out + [(other_edge, h) for h in t.holders if h not in mine and other_edge]
    if t.is_self:
        return [(self_edge, admin)] if self_edge else []
    return [(other_edge, t.node_id)] if other_edge and t.node_id else []


def run_danger_rule(rule: DangerRule, p: PrincipalModel, rctx: RulesContext) -> Optional[RuleHit]:
    """Evaluate one capability rule for one principal (``None`` when it does not fire)."""
    cap = rule.probe(partition=rctx.partition, account=rctx.account or "*")
    result = rctx.evaluator.evaluate_capability(p, cap)
    if result.decision not in _GRANTS:
        return None
    lookup = _StatementLookup(p)
    granted = _wildcard_first([statement_evidence(s, lookup.get(s)) for s in result.allow_refs
                               if s.layer == "identity"])
    globs = (cap.action_glob,) if cap.action_glob else cap.actions_any
    step = {"rule_action": " | ".join(globs), "resource": cap.resource_template, "decision": result.decision.value,
            "granted": granted,
            "denies_considered": [statement_evidence(s, lookup.get(s)) for s in result.deny_refs]}
    conditional = result.decision is Decision.CONDITIONAL
    adjusted = sev.adjust(rule.base_severity, result.strength, conditional=conditional)
    return RuleHit(rule.id, "dangerous", p, result.decision, result.strength if conditional else Strength.NONE,
                   adjusted, rule.base_severity, rule.title, rule.description, rule.remediation,
                   tuple(g.lower() for g in globs), (step,), gaps=frozenset(result.gaps))


# ── administrator equivalence (engine.md §3.4) ───────────────────────────────

def _self_escalation_rules(hits: Iterable[RuleHit]) -> Dict[str, List[str]]:
    """Principal → privesc rule ids that definitely let it modify its own permissions."""
    out: Dict[str, List[str]] = {}
    for h in hits:
        if h.kind != "privesc" or h.rule_class not in MODIFY_CLASSES:
            continue
        if any(tr.tier == "self" and tr.outcome.decision is Decision.ALLOW for tr in h.targets):
            out.setdefault(h.principal.id, []).append(h.rule_id)
    return out


def admin_principals(hits: Sequence[RuleHit], oracle: PrivilegeOracle,
                     principals: Iterable[PrincipalModel]) -> Dict[str, Dict[str, Any]]:
    """Administrator-equivalent principals and why (``allow-star`` or ``iam-self-escalation``)."""
    selfesc = _self_escalation_rules(hits)
    full_iam = {h.principal.id for h in hits if h.rule_id == "DANGER-002" and h.decision is Decision.ALLOW}
    out: Dict[str, Dict[str, Any]] = {}
    for p in principals:
        if oracle.is_admin(p.id):
            out[p.id] = {"basis": "allow-star", "rule_ids": ["DANGER-001"]}
        elif p.id in full_iam and p.id in selfesc:
            out[p.id] = {"basis": "iam-self-escalation", "rule_ids": sorted(["DANGER-002", *selfesc[p.id]])}
    return out


# ── the whole catalogue ──────────────────────────────────────────────────────

def _run_catalogue(rctx: RulesContext, kinds: Iterable[str], *, privesc: bool, dangerous: bool,
                   principal_filter: Optional[Callable[[PrincipalModel], bool]]) -> RulesResult:
    cat = rctx.catalogue or load_catalogue()
    oracle = PrivilegeOracle(rctx, cat)
    out = RulesResult()
    seen: List[PrincipalModel] = []
    for kind in kinds:
        for p in rctx.principals.of_kind(kind):
            if principal_filter is not None and not principal_filter(p):
                continue
            seen.append(p)
            if privesc:
                out.hits.extend(h for h in (run_privesc_rule(r, p, rctx, oracle) for r in cat.privesc) if h)
            if dangerous:
                out.hits.extend(h for h in (run_danger_rule(d, p, rctx) for d in cat.dangerous) if h)
    out.admins = admin_principals(out.hits, oracle, seen)
    for gap in sorted(getattr(rctx.evaluator, "report_gaps", lambda: ())()):
        out.gaps[gap] = "reported by the evaluator while running the rules"
    return out


def run_rules(evaluator: Any, principals: Any, *, existing: Optional[Mapping[str, Sequence[ExistingResource]]] = None,
              catalogue: Optional[RuleCatalogue] = None, kinds: Iterable[str] = ("user", "role", "group"),
              privesc: bool = True, dangerous: bool = True,
              principal_filter: Optional[Callable[[PrincipalModel], bool]] = None,
              access_keys: Optional[Mapping[str, Optional[int]]] = None,
              probe_uncollected: bool = False) -> RulesResult:
    """Run every rule for every principal of ``kinds`` (deterministic order: principal id, rule id)."""
    cat = catalogue or load_catalogue()
    rctx = RulesContext(evaluator, principals, existing or {}, cat, access_keys or {}, probe_uncollected)
    return _run_catalogue(rctx, kinds, privesc=privesc, dangerous=dangerous, principal_filter=principal_filter)


# ── pipeline registration (engine-api.md §5) ─────────────────────────────────

def existing_from_data(data: Mapping[str, Any], *, partition: str = "aws", account: Optional[str] = None,
                       iam: Any = None) -> Dict[str, List[ExistingResource]]:
    """Existing-resource inventory from the loader outputs (``ctx.data``; :mod:`.inventory`)."""
    return _inventory_from_data(data, partition=partition, account=account, iam=iam)


def _run(ctx: Any, builder: Any) -> None:
    """Phase RULES: run the catalogue for every principal and write findings, edges and admin edges."""
    pset = ctx.shared.get("iam.principal_set") if hasattr(ctx, "shared") else None
    if pset is None or ctx.evaluator is None:
        from aws_enumerator.engine.model import AnalyzerSkipped
        raise AnalyzerSkipped("principals", reason="rules need the principal set and the evaluator")
    data = getattr(ctx, "data", {}) or {}
    iam = data.get("iam")
    result = run_rules(ctx.evaluator, pset,
                       existing=existing_from_data(data, partition=ctx.partition, account=ctx.account_id, iam=iam),
                       access_keys=access_key_counts(iam), probe_uncollected=True)
    emit_to_builder(result, builder, rule_version=load_catalogue().version)
    emit_admin_edges(builder, result.admins, ctx.account_id)
    ctx.shared["rules.admins"] = dict(result.admins)
    for code, detail in sorted(result.gaps.items()):
        ctx.add_gap(code, detail)


def _analyzers() -> Tuple[Any, ...]:
    from aws_enumerator.engine.model import AnalyzerSpec, Phase
    return (AnalyzerSpec("rules", Phase.RULES, _run, inputs=("iam.authorization_details",),
                         requires=("principals",)),)


ANALYZERS = _analyzers()


__all__ = [
    "ANALYZERS", "ExistingResource", "PROBE_NAME", "PrivilegeOracle", "RuleEdge", "RuleHit", "RulesContext",
    "RulesResult", "StepEvaluator", "StepOutcome", "Target", "TargetResult", "admin_principals", "emit_to_builder",
    "existing_from_data", "finding_evidence", "legacy_finding", "run_danger_rule", "run_privesc_rule",
    "run_rules", "select_targets", "statement_evidence", "targets_detail", "targets_json",
]
