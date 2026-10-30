"""Data stores: ECR, DynamoDB, RDS and API Gateway (was "newsurface"; F-164), plus the evaluator-backed helpers
the three E-data analyzers share (``kms``, ``secrets``, ``data_stores``).

Every decision comes from the policy evaluator (engine-api.md §4; F-001, F-014, F-015, F-031):

* **who can use a resource**: the candidates are the principals whose identity policies may cover the service
  (the action index), the same-account principals a resource policy names, and (for an ``*`` grant) every
  principal. Each is evaluated per action through ``ctx.evaluator``, so Deny, NotAction/NotResource,
  conditions, permissions boundaries, SCPs/RCPs and the resource policy itself (a same-account grant folds into
  the effective-access edge) decide. Edges are emitted in the attack direction (grantee → resource) with
  ``result=``, so confidence, condition strength and provenance come from the decision. A user whose access
  comes only from a group it is a traversable member of reaches the resource through ``MEMBER_OF`` and the
  group's edge (no duplicate user edge);
* **exposure**: the shared walker ``Evaluator.resource_policy_grants`` (F-031; it replaces the private
  ``_resource_policy_grants`` copy, DECISIONS.md D-39) lists who a resource policy names. Public grants start at
  the anonymous node (F-037) and are graded by condition strength: a ``SecureTransport`` condition does not make a
  policy private, a ``PrincipalOrgID`` guard or a ``Deny … unless PrincipalOrgID`` does (no public edge, the node
  records ``public_grant: "restricted"``). Foreign accounts and principals get ``*_GRANTS_CROSS_ACCOUNT`` edges
  from their exact-ARN nodes (F-039);
* **unknown is not absent**: a policy or attribute that could not be read (``null``, ``PolicyStatus``
  ``denied``/``error``, ``CollectionErrors``) is registered with the evaluator as unknown, shown in the node's
  coverage and never reported as "not public" (F-058, F-059, ``requests/c-b-1.md``).

This module adds: RDS sharing (``RDS_SHARED_PUBLIC`` / ``RDS_SHARED_CROSS_ACCOUNT``, ``RDS-XACCT-001``, Aurora
cluster snapshots; F-056), API Gateway routes (``INVOKES`` to the **unqualified** function, qualifiers and stages
as edge properties, stage-variable targets listed in ``props.unresolved_targets``; F-082, F-099),
``APIGW-AUTH-001`` only for Lambda routes whose effective authorisation is ``NONE``, graded for PRIVATE endpoints
and resource policies, and ``PUBLIC_INBOUND`` from the anonymous node (F-044), the ECR registry policy and
cross-account replication (F-116), and the KMS keys of RDS resolved through the shared resolver (F-027).

The legacy ``newsurface_relationships.json`` is rendered from these edges by the legacy writer (one release). The
d13c215 entry points and the ``_resource_policy_grants`` alias were removed in Wave 3 (DECISIONS.md D-39, D-53).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union

from aws_enumerator.engine.findings.catalog import A_EXPOSURE, CatalogEntry
from aws_enumerator.engine.graph import edge_types as ET
from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.io.coverage import worst
from aws_enumerator.engine.io.loaders.data_stores import Api, ApiRoute, PolicyResource, RdsResource
from aws_enumerator.engine.io.loaders.kms import UNREADABLE, ItemErrors, KmsResolver
from aws_enumerator.engine.model import (
    AnalyzerSpec, Decision, EvalResult, Grant, Phase, PolicyDoc, Principal, PrincipalModel, Strength,
)
from aws_enumerator.engine.policy.glob import glob_overlap
from aws_enumerator.engine.policy.parse import iter_statements, parse_policy
from aws_enumerator.engine.policy.resource_policy import ANY_AWS

log = logging.getLogger(__name__)

# ── action classes ───────────────────────────────────────────────────────────
#: Item reads, including PartiQL selects and exports (a read of the whole table).
DDB_READ_ACTIONS = ["dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan",
                    "dynamodb:PartiQLSelect", "dynamodb:ExportTableToPointInTime"]
DDB_WRITE_ACTIONS = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem",
                     "dynamodb:PartiQLInsert", "dynamodb:PartiQLUpdate", "dynamodb:PartiQLDelete"]
ECR_PULL_ACTIONS = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
ECR_PUSH_ACTIONS = ["ecr:PutImage", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload"]
ECR_ADMIN_ACTIONS = ["ecr:SetRepositoryPolicy", "ecr:DeleteRepositoryPolicy", "ecr:DeleteRepository"]
#: Registry-policy actions that let another account write into this registry (F-116).
ECR_REGISTRY_ACTIONS = ["ecr:ReplicateImage", "ecr:CreateRepository", "ecr:BatchImportUpstreamImage"]

#: Finding ids this module owns (engine-api.md §5, DECISIONS.md D-33).
FINDINGS: Tuple[CatalogEntry, ...] = (
    CatalogEntry("ECR-PUB-001", "HIGH", "ecr_public", "Repository policy grants everyone",
                 "Scope the Principal or add Condition constraints (e.g. aws:PrincipalOrgID).", A_EXPOSURE),
    CatalogEntry("ECR-XACCT-001", "MEDIUM", "ecr_cross_account", "Repository policy grants another account",
                 "Verify cross-account pull/push access is intended.", A_EXPOSURE),
    CatalogEntry("ECR-REGISTRY-001", "HIGH", "ecr_registry", "Registry policy lets another account write images",
                 "Remove registry-policy grants (ReplicateImage, CreateRepository) to accounts that should not "
                 "write into this registry.", A_EXPOSURE),
    CatalogEntry("ECR-REPLICATION-001", "LOW", "ecr_registry", "Images replicate to another account",
                 "Verify that cross-account replication destinations are intended and trusted.", A_EXPOSURE),
    CatalogEntry("DDB-PUB-001", "HIGH", "dynamodb_public", "Table resource policy grants everyone",
                 "Scope the Principal or add Condition constraints (e.g. aws:PrincipalOrgID).", A_EXPOSURE),
    CatalogEntry("DDB-XACCT-001", "MEDIUM", "dynamodb_cross_account", "Table resource policy grants another account",
                 "Verify cross-account access is intended.", A_EXPOSURE),
    CatalogEntry("RDS-PUB-001", "HIGH", "rds_public", "RDS database is publicly accessible",
                 "Set PubliclyAccessible=false and place the database in private subnets.", A_EXPOSURE),
    CatalogEntry("RDS-SNAP-001", "HIGH", "rds_public_snapshot", "RDS snapshot is shared publicly",
                 "Remove public sharing from the snapshot immediately.", A_EXPOSURE),
    CatalogEntry("RDS-XACCT-001", "MEDIUM", "rds_cross_account", "RDS snapshot is shared with another account",
                 "Verify the snapshot sharing is intended; remove accounts that should not restore it.", A_EXPOSURE,
                 discriminator="target-account"),
    CatalogEntry("RDS-ENC-001", "MEDIUM", "rds_unencrypted", "RDS storage is not encrypted",
                 "Recreate the database (or restore an encrypted copy of a snapshot) with storage encryption.",
                 A_EXPOSURE),
    CatalogEntry("APIGW-AUTH-001", "MEDIUM", "apigw_public", "API has Lambda routes without authentication",
                 "Attach an authorizer (IAM, Cognito, JWT or Lambda) to the listed routes, or confirm that "
                 "unauthenticated access is intended.", A_EXPOSURE),
)


# ═══════════════════════════════════════════════════════════════════════════
# Shared helpers (kms, secrets, data_stores)
# ═══════════════════════════════════════════════════════════════════════════

PrincipalArg = Union[str, PrincipalModel, Principal]
ContextFor = Callable[[Optional[str]], Optional[Mapping[str, Any]]]
_PUBLIC_KINDS = frozenset({"anonymous", "wildcard"})
_NAMED_KINDS = frozenset({"aws_user", "aws_role", "aws_assumed_role"})
_EXTERNAL_KINDS = frozenset({"aws_root", "aws_user", "aws_role", "aws_assumed_role", "aws_federated_user"})
_STANDBY_KEY = "e-data.evaluator"


def _standby_evaluator(ctx: Any) -> Any:
    """One evaluator without principal models, shared by the E-data analyzers when phase PRINCIPALS produced none.

    It still decides resource-policy exposure; identity-based access edges are then not emitted and the gap
    ``evaluator:unavailable`` says so. ``ctx.evaluator`` itself is never replaced.
    """
    from aws_enumerator.engine.policy.evaluator import Evaluator
    from aws_enumerator.engine.policy.resource_policy import ResourcePolicyIndex

    shared = ctx.shared if isinstance(getattr(ctx, "shared", None), dict) else {}
    cached = shared.get(_STANDBY_KEY)
    if cached is not None:
        return cached
    evaluator = Evaluator(ctx, {}, ResourcePolicyIndex(default_owner=ctx.account_id, partition=ctx.partition), None)
    shared[_STANDBY_KEY] = evaluator
    ctx.add_gap("evaluator:unavailable", "The policy evaluator of the PRINCIPALS phase was not available (IAM data "
                "missing or its analyzer failed): resource policies were evaluated, identity-based access edges to "
                "KMS keys, secrets, parameters and tables were not.")
    return evaluator


class DomainEvaluator:
    """``ctx.evaluator`` plus the principal models it knows (engine-api.md §4, §6.1)."""

    def __init__(self, ctx: Any):
        self.ctx = ctx
        self.account: str = ctx.account_id
        self.partition: str = ctx.partition
        evaluator = getattr(ctx, "evaluator", None)
        self.identity = evaluator is not None
        self.evaluator = evaluator if evaluator is not None else _standby_evaluator(ctx)
        models = (getattr(ctx, "principals", None) or {}) if self.identity else {}
        self.models: Tuple[PrincipalModel, ...] = tuple(
            models[k] for k in sorted(models) if isinstance(models[k], PrincipalModel))
        self._by_id = {m.id: m for m in self.models}

    @property
    def resources(self) -> Any:
        return self.evaluator.resources

    def model(self, node_id: str) -> Optional[PrincipalModel]:
        return self._by_id.get(node_id)

    def register(self, arn: str, policy: Optional[Mapping[str, Any]], status: str, *, layer: str = "resource",
                 owner: Optional[str] = None) -> Optional[PolicyDoc]:
        """Register a resource policy (or its absence / unknown state) with the evaluator; returns the parsed doc."""
        if status == "present" and isinstance(policy, Mapping):
            return self.resources.add(arn, dict(policy), layer=layer, owner=owner or self.account)
        if status in UNREADABLE or status == "skipped":
            self.resources.mark_unknown(arn, layer=layer)
        else:
            self.resources.mark_absent(arn, layer=layer)
        if owner:
            self.resources.set_owner(arn, owner)
        return None

    def grants(self, doc: Optional[PolicyDoc], arn: str) -> List[Grant]:
        """Who ``doc`` grants on ``arn`` (the shared walker, F-031); ``[]`` without a policy."""
        if doc is None:
            return []
        return list(self.evaluator.resource_policy_grants(doc, arn))

    def best(self, principal: PrincipalArg, actions: Sequence[str], resource: str, *,
             context: Optional[Mapping[str, Any]] = None) -> Tuple[Optional[str], EvalResult, Tuple[str, ...]]:
        """(best action, its result, every action that is allowed or conditional) over ``actions``."""
        best_action: Optional[str] = None
        best_result = EvalResult(Decision.NOT_ALLOWED, reason="no_allow")
        granted: List[str] = []
        for action in actions:
            r = self.evaluator.evaluate(principal, action, resource, context=context)
            if r.decision.grants:
                granted.append(action)
            if best_action is None or better(r, best_result):
                best_action, best_result = action, r
        return best_action, best_result, tuple(granted)

    @staticmethod
    def capable(model: PrincipalModel, services: Iterable[str]) -> bool:
        """The principal's identity statements may cover one of ``services`` (action index, O(1) per service)."""
        index = model.action_index
        return any(index.may_cover(s) for s in services)


def better(a: EvalResult, b: EvalResult) -> bool:
    """``a`` decides more permissively than ``b`` (rank, then the weaker unresolved gate)."""
    if a.decision.rank != b.decision.rank:
        return a.decision.rank > b.decision.rank
    return a.strength.rank < b.strength.rank


def worse_of(results: Sequence[EvalResult]) -> EvalResult:
    """The least permissive of ``results`` (all of them are needed: a chain of actions)."""
    worst_result = results[0]
    for r in results[1:]:
        if better(worst_result, r):
            worst_result = r
    return worst_result


def legacy_evidence(edge_type: str, source_type: Optional[str]) -> Dict[str, Any]:
    """``evidence.legacy`` (graph-json.md §8.1): how the legacy relationship file renders this edge."""
    et = ET.EDGE_TYPES.get(edge_type)
    if et is None or et.legacy_name is None:
        return {}
    return {"legacy": {"type": et.legacy_name, "file": et.legacy_file_for(source_type) or "",
                       "direction": "reversed" if et.legacy_reversed else "forward"}}


def add_edge(builder: Any, source: str, edge_type: str, target: str, *,
             evidence: Optional[Mapping[str, Any]] = None, **kw: Any) -> str:
    """``builder.add_edge`` with ``evidence.legacy`` filled in and ``None`` evidence values dropped (every E-data
    edge goes through here)."""
    node = builder.node(source)
    ev: Dict[str, Any] = legacy_evidence(edge_type, node.type if node is not None else None)
    ev.update({k: v for k, v in (evidence or {}).items() if v is not None})
    return builder.add_edge(source, edge_type, target, evidence=ev, **kw)


def kind_of(node_id: str) -> Optional[str]:
    for kind in ("user", "role", "group"):
        if f":{kind}/" in node_id:
            return kind
    return None


@dataclass(frozen=True)
class Candidate:
    """A principal that may have access to a resource, and why it was considered."""

    node_id: str
    principal: PrincipalArg
    account: Optional[str]
    reason: str          # "named" (resource policy names it) | "identity" (its policies cover the service) | "wildcard"

    @property
    def kind(self) -> Optional[str]:
        return kind_of(self.node_id)


def candidates(dev: DomainEvaluator, builder: Any, services: Sequence[str], grants: Sequence[Grant]
               ) -> List[Candidate]:
    """Principals worth evaluating for a resource (module docstring); groups first, then by node id."""
    out: Dict[str, Candidate] = {}
    for g in grants:
        p = g.principal
        if p.kind not in _NAMED_KINDS or p.account != dev.account or not g.decision.grants:
            continue
        ref = builder.ensure_principal(p.arn or p.raw, principal_type="AWS")
        if ref.node_id is None or kind_of(ref.node_id) is None:
            continue
        model = dev.model(ref.node_id)
        out[ref.node_id] = Candidate(ref.node_id, model if model is not None else ref.node_id, dev.account, "named")
    wildcard = any(g.principal.kind in _PUBLIC_KINDS and g.decision.grants for g in grants)
    for model in dev.models:
        if model.id in out:
            continue
        if dev.capable(model, services):
            out[model.id] = Candidate(model.id, model, model.principal.account, "identity")
        elif wildcard:
            out[model.id] = Candidate(model.id, model, model.principal.account, "wildcard")
    return [out[k] for k in sorted(out, key=lambda k: (0 if kind_of(k) == "group" else 1, k))]


@dataclass(frozen=True)
class AccessClass:
    """An edge type and the actions that give it (any one of them suffices)."""

    edge_type: str
    actions: Tuple[str, ...]


@dataclass(frozen=True)
class ClassResult:
    """The decision behind one access edge: the best of the class's actions and every action granted."""

    edge_type: str
    result: EvalResult
    actions: Tuple[str, ...]


#: ``resolve(candidate, action) -> EvalResult``: one request of a candidate against the resource at hand.
Resolve = Callable[[Candidate, str], EvalResult]


def class_results(cand: Candidate, classes: Sequence[AccessClass], resolve: Resolve, *,
                  dominance: Optional[Mapping[str, Iterable[str]]] = None) -> Dict[str, ClassResult]:
    """``{edge type: ClassResult}`` for the classes the candidate is granted (allowed or conditional).

    A class stops at its first definite (ALLOW) action: nothing can decide better, so ``actions`` lists the
    granted actions up to that one. A class that a definite result of an earlier class makes redundant
    (``dominance``) is not evaluated at all.
    """
    out: Dict[str, ClassResult] = {}
    for cls in classes:
        if dominance and any(cls.edge_type in implied and d in out and out[d].result.decision is Decision.ALLOW
                             for d, implied in dominance.items()):
            continue
        best: Optional[EvalResult] = None
        granted: List[str] = []
        for action in cls.actions:
            r = resolve(cand, action)
            if not r.decision.grants:
                continue
            granted.append(action)
            if best is None or better(r, best):
                best = r
            if r.decision is Decision.ALLOW:
                break
        if best is not None:
            out[cls.edge_type] = ClassResult(cls.edge_type, best, tuple(granted))
    return out


def keep_for(cand: Candidate, result: EvalResult, public_allows: bool) -> bool:
    """A principal considered only because of an ``*`` grant gets its own edge only when that grant is definite
    for it and the resource is not already open to everyone (the anonymous edge says that once)."""
    if cand.reason != "wildcard":
        return True
    return result.decision is Decision.ALLOW and not public_allows


def _confidence_rank(conf: str) -> int:
    return 1 if conf == "definite" else 0


class AccessEmitter:
    """Principal → resource access edges of one domain (module docstring).

    ``dominance`` maps an edge type to the types it makes redundant: an implied edge is not emitted when the
    implying edge is at least as definite (one edge per fact, F-022).
    """

    def __init__(self, dev: DomainEvaluator, builder: Any, services: Sequence[str],
                 classes: Sequence[AccessClass], *, dominance: Optional[Mapping[str, Iterable[str]]] = None):
        self.dev, self.builder = dev, builder
        self.services = tuple(services)
        self.classes = tuple(classes)
        self.dominance = {k: frozenset(v) for k, v in (dominance or {}).items()}
        self.member_of = self._memberships(builder)
        self._group_edges: Dict[Tuple[str, str], Dict[str, str]] = {}

    @staticmethod
    def _memberships(builder: Any) -> Dict[str, Set[str]]:
        out: Dict[str, Set[str]] = {}
        for e in builder.edges("MEMBER_OF"):
            if e.traversable:
                out.setdefault(e.source, set()).add(e.target)
        return out

    def candidates(self, grants: Sequence[Grant]) -> List[Candidate]:
        if not self.dev.identity:
            return []
        return candidates(self.dev, self.builder, self.services, grants)

    def _kept(self, results: Mapping[str, ClassResult]) -> List[ClassResult]:
        kept = []
        for et in sorted(results):
            res = results[et]
            implied_by = [d for d, implied in self.dominance.items() if et in implied and d in results]
            if any(_confidence_rank(results[d].result.confidence) >= _confidence_rank(res.result.confidence)
                   for d in implied_by):
                continue
            kept.append(res)
        return kept

    def _explained_by_group(self, user: str, target: str, edge_type: str, result: EvalResult) -> bool:
        """The user's identity grant comes only from traversable groups that already have this edge.

        Only identity-layer provenance counts: a resource policy that delegates to the account (a KMS key policy's
        root statement) does not name the user, and a user the resource policy names is never skipped (its
        candidate reason is ``named``, see :meth:`emit`).
        """
        groups = self.member_of.get(user)
        refs = [r for r in result.allow_refs if r.layer == "identity"]
        if not groups or not refs or any(r.via_group is None for r in refs):
            return False
        via = {r.via_group for r in refs}
        if not via <= groups:
            return False
        rank = _confidence_rank(result.confidence)
        for g in sorted(via):
            conf = self._group_edges.get((g, target), {}).get(edge_type)
            if conf is not None and _confidence_rank(conf) >= rank:
                return True
        return False

    def emit(self, node_id: str, cands: Sequence[Candidate], resolve: Resolve, *, public_allows: bool = False,
             rename: Optional[Callable[[Candidate, ClassResult], str]] = None,
             evidence: Optional[Mapping[str, Any]] = None) -> int:
        """Emit the kept class edges ``candidate → node_id``; returns the number of edges added."""
        count = 0
        for cand in cands:
            if not self.builder.has_node(cand.node_id):
                continue
            for res in self._kept(class_results(cand, self.classes, resolve, dominance=self.dominance)):
                if not keep_for(cand, res.result, public_allows):
                    continue
                etype = rename(cand, res) if rename is not None else res.edge_type
                if cand.kind == "user" and cand.reason == "identity" and \
                        self._explained_by_group(cand.node_id, node_id, etype, res.result):
                    continue
                ev: Dict[str, Any] = {"actions": sorted(set(res.actions)), "basis": cand.reason}
                ev.update({k: v for k, v in (evidence or {}).items() if v not in (None, [], {}, "")})
                add_edge(self.builder, cand.node_id, etype, node_id, result=res.result, evidence=ev)
                if cand.kind == "group":
                    self._group_edges.setdefault((cand.node_id, node_id), {})[etype] = res.result.confidence
                count += 1
        return count


def type_template(resource_arn: str) -> Optional[str]:
    """The ARN template of every resource of the same type, region and account (``…:secret:*``,
    ``…:parameter/*``, ``…:table/*``), or ``None`` for an ARN without a typed resource part."""
    from aws_enumerator.engine.policy.arn import parse_arn

    p = parse_arn(resource_arn)
    if p is None:
        return None
    cuts = [i for i in (p.resource.find("/"), p.resource.find(":")) if i >= 0]
    if not cuts:
        return None
    return f"arn:{p.partition}:{p.service}:{p.region}:{p.account}:{p.resource[:min(cuts) + 1]}*"


def identity_only_shortcut(dev: DomainEvaluator, cand: Candidate, action: str, resource: str
                           ) -> Optional[EvalResult]:
    """A decision that makes the per-resource evaluation unnecessary, or ``None``.

    For a same-account principal considered only for its identity policies, on a resource without a resource
    policy, the evaluator can only allow through the identity layer: when no identity statement can reach **any**
    resource of the type (``Evaluator.evaluate_any`` on the type template is not a grant), the per-resource answer
    is the same. Memoised per (principal, action, template) by the evaluator; this is what keeps hundreds of
    principals × thousands of resources fast (engine.md §2.6).
    """
    if cand.reason != "identity" or not isinstance(cand.principal, PrincipalModel) \
            or cand.account != dev.account or dev.resources.policy_for(resource) is not None:
        return None
    template = type_template(resource)
    if template is None:
        return None
    pre = dev.evaluator.evaluate_any(cand.principal, action, template)
    return None if pre.decision.grants else pre


def plain_resolver(dev: DomainEvaluator, resource: str, *, context_for: Optional[ContextFor] = None,
                   key_policy: bool = False) -> Resolve:
    """``resolve(candidate, action)``: one ``Evaluator.evaluate`` on ``resource`` (memoised by the evaluator).

    ``key_policy``: the resource is a KMS key (key policy and grants decide first, no identity-only shortcut).
    """

    def resolve(cand: Candidate, action: str) -> EvalResult:
        if not key_policy:
            short = identity_only_shortcut(dev, cand, action, resource)
            if short is not None:
                return short
        context = context_for(cand.account) if context_for is not None else None
        return dev.evaluator.evaluate(cand.principal, action, resource, context=context)

    return resolve


# ── exposure (public and cross-account grants) ───────────────────────────────

@dataclass(frozen=True)
class ExposureSpec:
    """How one resource type renders resource-policy exposure."""

    public_edge: str
    xacct_edge: str
    public_finding: str
    xacct_finding: str
    actions: Tuple[str, ...]          # the actions that matter for this resource type
    label: str                        # "Secret", "KMS key" …
    entity: str                       # legacy entity prefix ("secret", "kms" …)
    source_policy: str                # legacy source_policy ("ResourcePolicy", "KeyPolicy")
    source_type: str                  # legacy source_type
    context_for: Optional[ContextFor] = None
    #: An unsigned (anonymous) caller can use the service (execute-api); otherwise "public" means any AWS principal.
    anonymous: bool = False


@dataclass
class ExposureResult:
    public: Optional[EvalResult] = None
    public_allows: bool = False
    external: Dict[str, EvalResult] = field(default_factory=dict)


def public_grade(result: Optional[EvalResult]) -> Optional[Tuple[str, str]]:
    """(severity, confidence) of a public grant, ``None`` when a strong gate keeps it private (F-031)."""
    if result is None or not result.decision.grants:
        return None
    if result.decision is Decision.ALLOW:
        return "HIGH", "definite"
    if result.strength is Strength.NONE:
        return "HIGH", "conditional"
    if result.strength is Strength.WEAK:
        return "MEDIUM", "conditional"
    return None


def external_grade(result: EvalResult) -> Tuple[str, str]:
    """(severity, confidence) of a cross-account grant (the foreign identity side is always unknown)."""
    if result.strength is Strength.STRONG:
        return "LOW", "conditional"
    if result.strength is Strength.WEAK:
        return "MEDIUM", "conditional"
    return "MEDIUM", "definite"


def _public(dev: DomainEvaluator, resource_arn: str, spec: ExposureSpec
            ) -> Tuple[Optional[EvalResult], Tuple[str, ...], str]:
    """Best public decision: any authenticated AWS principal, or an unsigned caller where the service allows it."""
    context = spec.context_for(None) if spec.context_for else None
    _w, wild, wild_granted = dev.best(ANY_AWS, spec.actions, resource_arn, context=context)
    if spec.anonymous:
        _a, anon, anon_granted = dev.best(ids.ANONYMOUS_ID, spec.actions, resource_arn, context=context)
        if anon.decision.grants and not better(wild, anon):
            return anon, anon_granted, "none"
    if wild.decision.grants:
        return wild, wild_granted, "any-aws-account"
    return None, (), ""


def legacy_fields(spec: ExposureSpec, name: str, arn: str) -> Dict[str, Any]:
    return {"entity": f"{spec.entity}/{name}", "entity_arn": arn, "source_policy": spec.source_policy,
            "source_type": spec.source_type, "resource": [arn]}


def _emit_public(dev: DomainEvaluator, builder: Any, node_id: str, arn: str, spec: ExposureSpec, name: str,
                 region: Optional[str], out: ExposureResult) -> None:
    result, granted, auth = _public(dev, arn, spec)
    if result is None:
        return
    grade = public_grade(result)
    if grade is None:
        builder.set_node_props(node_id, public_grant="restricted")
        return
    out.public, out.public_allows = result, result.decision is Decision.ALLOW
    builder.set_node_props(node_id, public_grant="conditional" if grade[1] == "conditional" else "open")
    add_edge(builder, ids.ANONYMOUS_ID, spec.public_edge, node_id, result=result,
             evidence={"actions": sorted(granted)}, props={"auth": auth})
    severity, confidence = grade
    builder.add_finding(
        spec.public_finding, node_id, severity=severity, base_severity="HIGH", confidence=confidence,
        title=f"{spec.label} '{name}' is accessible to everyone through its resource policy",
        description=f"The {spec.label.lower()}'s resource policy grants {', '.join(sorted(granted))} to "
                    f"{'anonymous callers' if auth == 'none' else 'any AWS principal'}"
                    f"{'' if confidence == 'definite' else ' under conditions an outsider may satisfy'}.",
        evidence={"decision": result.decision.value, "condition_strength": result.strength.value,
                  "statements": [s.to_json() for s in result.allow_refs], "auth": auth},
        region=region, matched_actions=list(granted), **legacy_fields(spec, name, arn))


def external_edges(dev: DomainEvaluator, builder: Any, node_id: str, arn: str, edge_type: str,
                   actions: Sequence[str], grants: Sequence[Grant], *, context_for: Optional[ContextFor] = None
                   ) -> Dict[str, Tuple[str, Tuple[str, ...], EvalResult]]:
    """``external -edge_type-> node`` for every foreign grantee of a resource policy (F-039).

    Each foreign account or principal the policy names is evaluated for ``actions`` on ``arn`` (its own identity
    side is unknown, so the decision comes from the resource policy); returns
    ``{external node: (account, granted actions, decision)}``.
    """
    seen: Dict[str, Tuple[str, Tuple[str, ...], EvalResult]] = {}
    for g in grants:
        p = g.principal
        if p.kind not in _EXTERNAL_KINDS or not p.account or p.account == dev.account or not g.decision.grants:
            continue
        ref = builder.ensure_principal(p.arn or p.raw, principal_type="AWS")
        if ref.node_id is None or ref.node_id in seen or ref.node_type not in ("external_account",
                                                                               "external_principal"):
            continue
        context = context_for(p.account) if context_for else None
        _action, result, granted = dev.best(p.arn or p.raw, actions, arn, context=context)
        if not result.decision.grants:
            continue
        add_edge(builder, ref.node_id, edge_type, node_id, result=result,
                 evidence={"actions": sorted(granted)}, props={"cross_account": True})
        seen[ref.node_id] = (p.account, tuple(granted), result)
    return seen


def _emit_external(dev: DomainEvaluator, builder: Any, node_id: str, arn: str, spec: ExposureSpec,
                   grants: Sequence[Grant], out: ExposureResult) -> Dict[str, Tuple[str, Tuple[str, ...]]]:
    """Cross-account edges of an exposure spec; returns ``{external node: (account, granted actions)}``."""
    found = external_edges(dev, builder, node_id, arn, spec.xacct_edge, spec.actions, grants,
                           context_for=spec.context_for)
    out.external.update({node: result for node, (_acct, _granted, result) in found.items()})
    return {node: (acct, granted) for node, (acct, granted, _result) in found.items()}


def emit_exposure(dev: DomainEvaluator, builder: Any, node_id: str, arn: str, grants: Sequence[Grant],
                  spec: ExposureSpec, *, name: str, region: Optional[str]) -> ExposureResult:
    """Public and cross-account edges and findings of one resource policy (F-031, F-037, F-039)."""
    out = ExposureResult()
    if any(g.principal.kind in _PUBLIC_KINDS and g.decision.grants for g in grants):
        _emit_public(dev, builder, node_id, arn, spec, name, region, out)
    seen = _emit_external(dev, builder, node_id, arn, spec, grants, out)
    if not seen:
        return out
    least_gated = max(out.external.values(), key=lambda r: (r.decision.rank, -r.strength.rank))
    severity, confidence = external_grade(least_gated)
    accounts = sorted({acct for acct, _g in seen.values()})
    actions = sorted({a for _acct, granted in seen.values() for a in granted})
    builder.add_finding(
        spec.xacct_finding, node_id, severity=severity, base_severity="MEDIUM", confidence=confidence,
        title=f"{spec.label} '{name}' is shared with {', '.join(accounts)}",
        description=f"The {spec.label.lower()}'s resource policy grants {', '.join(actions)} to principals of "
                    f"account(s) {', '.join(accounts)}, independently of this account's IAM policies.",
        evidence={"accounts": accounts, "principals": sorted(seen)}, region=region, matched_actions=actions,
        related_node_ids=sorted(seen), **legacy_fields(spec, name, arn))
    return out


# ── nodes and coverage ───────────────────────────────────────────────────────

def node_coverage(ctx: Any, module: str, region: Optional[str], errors: ItemErrors, *, legacy: bool = False,
                  extra: Iterable[str] = ()) -> Tuple[str, List[str]]:
    """Node coverage (graph-json.md §7.2): ``partial`` with gap codes when an input of the item is unknown."""
    gaps = sorted(set(errors.gaps) | set(extra))
    base = "complete"
    coverage = getattr(ctx, "coverage", None)
    if legacy or (coverage is not None and coverage.source == "legacy-unknown"):
        base = "legacy-unknown"
    elif region and coverage is not None:
        status = coverage.module_status(module, region)
        base = status if status in ("legacy-unknown", "denied", "error") else "complete"
    return worst([base, "partial"] if gaps else [base]), gaps


def policy_gaps(ctx: Any, service: str, api: str, region: Optional[str], arn: str, status: str) -> List[str]:
    """Gap codes (and a coverage-facet record) for a resource policy that could not be read."""
    if status not in UNREADABLE:
        return []
    if region and getattr(ctx, "coverage", None) is not None:
        ctx.coverage.facet(service, api, region, item=arn)
    return [f"{api}:{status}"]


def add_resource_node(builder: Any, node_type: str, arn: str, label: str, *, region: Optional[str], account: str,
                      props: Optional[Mapping[str, Any]] = None, coverage: Tuple[str, Sequence[str]] = ("complete", ())
                      ) -> str:
    """Create (or upgrade a placeholder into) the collected resource's node, with its coverage.

    The collecting domain is authoritative for its resource nodes: a node another analyzer created first from a
    reference (an encryption key, an integration target) takes this label; a placeholder's ``not-collected``
    coverage is replaced by the builder's placeholder upgrade (``requests/e-data-1.md`` §1).
    """
    clean = {k: v for k, v in (props or {}).items() if v is not None}
    existing = builder.node(arn) is not None
    builder.add_node(arn, node_type, label or arn, account=account, region=region, props=clean,
                     coverage_status=coverage[0], coverage_gaps=coverage[1])
    if existing and label:
        builder.node(arn).label = label
    return arn


def kms_target(builder: Any, resolver: KmsResolver, ref: Optional[str], *, region: Optional[str], account: str,
               default_alias: Optional[str] = None) -> Optional[str]:
    """The ``kms`` node a resource's key reference names (a placeholder when not collected, F-027)."""
    kref = resolver.resolve(ref, region=region, account=account, default_alias=default_alias)
    if kref is None or not ids.node_id_matches("kms", kref.node_id):
        return None
    if builder.has_node(kref.node_id):
        return kref.node_id
    props: Dict[str, Any] = {"placeholder": True}
    if not kref.resolved:
        props["unresolved_alias"] = True
        if resolver.aliases_unknown(region):
            props["aliases_unknown"] = True
    label = kref.node_id.split(":", 5)[-1]
    builder.add_node(kref.node_id, "kms", label, props=props, coverage_status="not-collected")
    return kref.node_id


def encryption_edge(builder: Any, resolver: KmsResolver, source: str, edge_type: str, ref: Optional[str], *,
                    region: Optional[str], account: str, default_alias: Optional[str] = None) -> Optional[str]:
    """``source -edge_type-> key`` with the reference resolved to the key node (F-027); returns the key node."""
    key_node = kms_target(builder, resolver, ref, region=region, account=account, default_alias=default_alias)
    if key_node is None:
        return None
    evidence = {"kms_key_id": ref} if ref else {"kms_key_id": None, "default_alias": default_alias}
    add_edge(builder, source, edge_type, key_node, evidence={k: v for k, v in evidence.items() if v is not None})
    return key_node


# ═══════════════════════════════════════════════════════════════════════════
# ECR and DynamoDB
# ═══════════════════════════════════════════════════════════════════════════

ECR_EXPOSURE = ExposureSpec("ECR_GRANTS_PUBLIC", "ECR_GRANTS_CROSS_ACCOUNT", "ECR-PUB-001", "ECR-XACCT-001",
                            tuple(ECR_PULL_ACTIONS + ECR_PUSH_ACTIONS + ECR_ADMIN_ACTIONS), "ECR repository", "ecr",
                            "ResourcePolicy", "ecr_resource_policy")
DDB_EXPOSURE = ExposureSpec("DDB_GRANTS_PUBLIC", "DDB_GRANTS_CROSS_ACCOUNT", "DDB-PUB-001", "DDB-XACCT-001",
                            tuple(DDB_READ_ACTIONS + DDB_WRITE_ACTIONS), "DynamoDB table", "dynamodb",
                            "ResourcePolicy", "dynamodb_resource_policy")
DDB_CLASSES = (AccessClass("CAN_READ_TABLE", tuple(DDB_READ_ACTIONS)),
               AccessClass("CAN_WRITE_TABLE", tuple(DDB_WRITE_ACTIONS)))
_POLICY_API = {"ecr": ("ecr", "ecr:GetRepositoryPolicy"), "dynamodb": ("dynamodb", "dynamodb:GetResourcePolicy")}


def _policy_resource(dev: DomainEvaluator, builder: Any, item: PolicyResource,
                     tables: Optional[AccessEmitter]) -> None:
    ctx = dev.ctx
    service, api = _POLICY_API[item.kind]
    extra = policy_gaps(ctx, service, api, item.region, item.arn, item.policy_status)
    props = dict(item.props)
    props["policy_status"] = item.policy_status
    add_resource_node(builder, item.kind, item.arn, item.name, region=item.region, account=item.account,
                      props=props, coverage=node_coverage(ctx, service, item.region, item.errors, legacy=item.legacy,
                                                          extra=extra))
    doc = dev.register(item.arn, item.policy, item.policy_status, owner=item.account)
    grants = dev.grants(doc, item.arn)
    spec = ECR_EXPOSURE if item.kind == "ecr" else DDB_EXPOSURE
    exposure = emit_exposure(dev, builder, item.arn, item.arn, grants, spec, name=item.name, region=item.region)
    if doc is not None:
        _service_deputies(builder, item, doc, grants, spec.label)
    if tables is not None and item.kind == "dynamodb":
        tables.emit(item.arn, tables.candidates(grants), plain_resolver(dev, item.arn),
                    public_allows=exposure.public_allows)


def _service_deputies(builder: Any, item: PolicyResource, doc: PolicyDoc, grants: Sequence[Grant], label: str) -> int:
    """SVC-DEPUTY-001: the repository / table policy grants an AWS service principal (``lambda``, ``codebuild`` …)
    with no ``aws:SourceArn`` / ``aws:SourceAccount`` / ``aws:SourceOrgID`` condition (F-033)."""
    from aws_enumerator.engine.analyzers.compute import add_deputy_findings
    from aws_enumerator.engine.policy.resource_policy import unguarded_service_grants

    deputies = unguarded_service_grants(doc, grants)
    return add_deputy_findings(builder, item.arn, deputies, what=label, name=item.name, region=item.region) \
        if deputies else 0


def _registry_grants(dev: DomainEvaluator, doc: Optional[PolicyDoc], registry_arn: str
                     ) -> Tuple[bool, Dict[str, List[str]]]:
    """(public, {foreign account: actions}) of the registry policy's write grants."""
    accounts: Dict[str, List[str]] = {}
    public = False
    for g in dev.grants(doc, registry_arn):
        acts = sorted(a for a in g.actions if any(glob_overlap(a, x.lower()) for x in ECR_REGISTRY_ACTIONS))
        if not acts or not g.decision.grants:
            continue
        if g.principal.kind in _PUBLIC_KINDS:
            public = True
        elif g.principal.account and g.principal.account != dev.account:
            accounts.setdefault(g.principal.account, []).extend(acts)
    return public, accounts


def _registry(dev: DomainEvaluator, builder: Any, reg: Any) -> None:
    """ECR registry policy (another account may write into this registry) and replication out (F-116)."""
    ctx = dev.ctx
    anchor = ids.region_anchor_id(ctx.account_id, reg.region)
    registry_arn = f"arn:{ctx.partition}:ecr:{reg.region}:{reg.registry_id}:repository/*"
    if reg.policy_status in UNREADABLE:
        ctx.add_gap("ecr:registry-policy-unknown", "The ECR registry policy could not be read: whether other "
                    "accounts may replicate or create repositories in this registry is unknown.", 1)
    doc = None
    if reg.policy_status == "present" and isinstance(reg.policy, Mapping):
        doc = parse_policy(dict(reg.policy), layer="resource", source_type="resource", policy_arn=registry_arn,
                           policy_name="registry-policy", partition=ctx.partition)
    public, accounts = _registry_grants(dev, doc, registry_arn)
    legacy_kw = {"entity": f"ecr-registry/{reg.region}", "entity_arn": registry_arn}
    if public or accounts:
        names = sorted(accounts)
        builder.add_finding(
            "ECR-REGISTRY-001", anchor, severity="HIGH" if public else "MEDIUM", base_severity="HIGH",
            title=f"ECR registry in {reg.region} lets {'everyone' if public else ', '.join(names)} write images",
            description="The registry permission policy grants replication or repository creation to principals "
                        "outside this account, so they can place images in this registry.",
            evidence={"accounts": names, "public": public,
                      "actions": sorted({a for acts in accounts.values() for a in acts})},
            region=reg.region, **legacy_kw)
    if reg.replication_accounts:
        builder.add_finding(
            "ECR-REPLICATION-001", anchor, severity="LOW",
            title=f"ECR images in {reg.region} replicate to {', '.join(reg.replication_accounts)}",
            description="Registry replication rules copy images to registries of other accounts.",
            evidence={"accounts": list(reg.replication_accounts)}, region=reg.region, **legacy_kw)


# ═══════════════════════════════════════════════════════════════════════════
# RDS (F-056, F-027)
# ═══════════════════════════════════════════════════════════════════════════

def _rds_unknown(item: RdsResource) -> List[str]:
    gaps = []
    if item.is_snapshot:
        if item.public_snapshot is None:
            gaps.append("rds:snapshot-public-unknown")
        if item.shared_accounts is None:
            gaps.append("rds:snapshot-sharing-unknown")
    else:
        if item.public is None:
            gaps.append("rds:publicly-accessible-unknown")
        if item.encrypted is None:
            gaps.append("rds:storage-encrypted-unknown")
    return gaps


def _rds_node(dev: DomainEvaluator, builder: Any, item: RdsResource) -> str:
    props = {"kind": item.kind, "engine": item.engine, "publicly_accessible": item.public,
             "storage_encrypted": item.encrypted, "public_snapshot": item.public_snapshot,
             "shared_accounts": list(item.shared_accounts) if item.shared_accounts is not None else None}
    gaps = [] if item.legacy else _rds_unknown(item)
    return add_resource_node(builder, "rdssnapshot" if item.is_snapshot else "rds", item.arn, item.name,
                             region=item.region, account=item.account, props=props,
                             coverage=node_coverage(dev.ctx, "rds", item.region, item.errors, legacy=item.legacy,
                                                    extra=gaps))


def _rds_database(builder: Any, item: RdsResource, legacy_kw: Mapping[str, Any]) -> None:
    standalone = item.kind == "instance" or not item.members   # cluster members are flagged as instances
    if item.public and standalone:
        builder.add_finding(
            "RDS-PUB-001", item.arn, severity="HIGH", region=item.region,
            title=f"RDS {item.kind} '{item.name}' is publicly accessible",
            description="PubliclyAccessible is true: the endpoint resolves to a public address and is reachable "
                        "from the internet wherever its security groups allow it.",
            evidence={"kind": item.kind}, source_policy="DBConfig", **legacy_kw)
        add_edge(builder, ids.ANONYMOUS_ID, "PUBLIC_INBOUND", item.arn, confidence="conditional", strength="weak",
                 evidence={"basis": "publicly-accessible", "gaps": ["security-groups-not-evaluated"]})
    if item.encrypted is False and standalone:
        builder.add_finding(
            "RDS-ENC-001", item.arn, severity="MEDIUM", region=item.region,
            title=f"RDS {item.kind} '{item.name}' storage is not encrypted",
            description="StorageEncrypted is false: data at rest and its snapshots are not protected by KMS.",
            evidence={"kind": item.kind}, source_policy="DBConfig", **legacy_kw)


def _snapshot_key(resolver: KmsResolver, item: RdsResource) -> Any:
    """The collected KMS key of an encrypted snapshot, or ``None`` (not encrypted, unresolved, not collected)."""
    if not item.kms_key_id:
        return None
    kref = resolver.resolve(item.kms_key_id, region=item.region, account=item.account)
    return resolver.inventory.key(kref.node_id) if kref is not None else None


def _rds_snapshot(dev: DomainEvaluator, builder: Any, item: RdsResource, resolver: KmsResolver,
                  legacy_kw: Mapping[str, Any]) -> None:
    kind_label = item.kind.replace("_", " ")
    if item.public_snapshot:
        add_edge(builder, ids.ANONYMOUS_ID, "RDS_SHARED_PUBLIC", item.arn, evidence={"attribute": "restore"},
                 props={"auth": "any-aws-account"})
        builder.add_finding(
            "RDS-SNAP-001", item.arn, severity="HIGH", region=item.region,
            title=f"RDS {kind_label} '{item.name}' is shared publicly",
            description="The snapshot's restore attribute includes 'all': any AWS account can restore it and read "
                        "the data.", evidence={"attribute": "restore"}, source_policy="SnapshotAttributes",
            **legacy_kw)
    key = _snapshot_key(resolver, item)
    unusable = key is not None and key.aws_managed
    for account in item.shared_accounts or ():
        if account == dev.account or not ids._ACCT_RE.match(account):
            continue
        ref = builder.ensure_principal(account, principal_type="AWS")
        if ref.node_id is None or ref.node_type != "external_account":
            continue
        evidence: Dict[str, Any] = {"attribute": "restore", "encrypted": item.encrypted}
        if item.encrypted:
            # restoring an encrypted snapshot also needs the key: shared customer keys are not evaluated here
            evidence["gaps"] = ["kms-key-access-unknown"]
        add_edge(builder, ref.node_id, "RDS_SHARED_CROSS_ACCOUNT", item.arn,
                 confidence="conditional" if item.encrypted else None,
                 strength="weak" if item.encrypted else None,
                 evidence={k: v for k, v in evidence.items() if v is not None}, props={"cross_account": True})
        builder.add_finding(
            "RDS-XACCT-001", item.arn, severity="LOW" if unusable else "MEDIUM", base_severity="MEDIUM",
            discriminator=account, region=item.region, related_node_ids=[ref.node_id],
            title=f"RDS {kind_label} '{item.name}' is shared with account {account}",
            description=f"The snapshot's restore attribute lists account {account}, which can restore it"
                        + (" (the AWS-managed key it is encrypted with cannot be used by another account, so the "
                           "share cannot be restored as is)." if unusable else "."),
            evidence={"account": account, "encrypted": item.encrypted}, source_policy="SnapshotAttributes",
            **legacy_kw)


def _rds(dev: DomainEvaluator, builder: Any, item: RdsResource, resolver: KmsResolver) -> None:
    _rds_node(dev, builder, item)
    legacy_kw = {"entity": f"rds/{item.name}", "entity_arn": item.arn, "source_type": "rds_config",
                 "resource": [item.arn]}
    if item.is_snapshot:
        _rds_snapshot(dev, builder, item, resolver, legacy_kw)
    else:
        _rds_database(builder, item, legacy_kw)
    if item.kms_key_id:
        encryption_edge(builder, resolver, item.arn, "RDS_ENCRYPTED_BY", item.kms_key_id, region=item.region,
                        account=item.account)


# ═══════════════════════════════════════════════════════════════════════════
# API Gateway (F-044, F-082, F-099)
# ═══════════════════════════════════════════════════════════════════════════

def _lambda_node(builder: Any, arn: str, collected: Iterable[str]) -> Optional[str]:
    try:
        node_id = ids.lambda_unqualified(arn)[0]
    except ValueError:
        return None
    if not ids.node_id_matches("lambda", node_id):
        return None
    if not builder.has_node(node_id):
        is_collected = node_id in set(collected)
        builder.add_node(node_id, "lambda", node_id.rsplit(":", 1)[-1],
                         props=None if is_collected else {"placeholder": True},
                         coverage_status=None if is_collected else "not-collected")
    return node_id


def _route_json(r: ApiRoute) -> Dict[str, Any]:
    return {k: v for k, v in {"route": r.key, "path": r.path, "function": r.lambda_arn, "qualifier": r.qualifier,
                              "stage": r.stage, "authorization": r.effective_auth}.items() if v is not None}


def _unresolved_json(r: ApiRoute) -> Dict[str, Any]:
    return {k: v for k, v in _route_json(r).items() if k in ("route", "path", "stage")}


def _invokes(builder: Any, api: Api, collected: Iterable[str]) -> List[Dict[str, Any]]:
    """``INVOKES`` api → unqualified function (qualifiers/stages as props); returns the unresolved targets."""
    by_fn: Dict[str, List[ApiRoute]] = {}
    unresolved = []
    routes = api.routes if api.routes is not None else api.targets
    for r in routes:
        if r.unresolved:
            unresolved.append(_unresolved_json(r))
        elif r.lambda_arn:
            by_fn.setdefault(r.lambda_arn, []).append(r)
    if api.routes is not None:
        unresolved.extend(_unresolved_json(r) for r in api.targets if r.unresolved and r.key is None)
    for fn_arn in sorted(by_fn):
        fn_node = _lambda_node(builder, fn_arn, collected)
        if fn_node is None:
            continue
        rs = by_fn[fn_arn]
        props = {"qualifiers": sorted({r.qualifier for r in rs if r.qualifier}),
                 "stages": sorted({r.stage for r in rs if r.stage})}
        add_edge(builder, api.arn, "INVOKES", fn_node, props={k: v for k, v in props.items() if v},
                 evidence={"routes": [_route_json(r) for r in rs if r.key is not None]})
    uniq = {tuple(sorted(d.items())): d for d in unresolved}
    return [uniq[k] for k in sorted(uniq)]


def _execute_api_doc(api: Api, partition: str) -> Optional[Mapping[str, Any]]:
    """The REST API resource policy with ``execute-api:/…`` shorthand resources expanded to ARNs."""
    if not isinstance(api.resource_policy, Mapping):
        return None
    base = f"arn:{partition}:execute-api:{api.region}:{api.account}:{api.api_id}"

    def expand(value: Any) -> Any:
        if isinstance(value, str) and value.startswith("execute-api:/"):
            return base + value[len("execute-api:"):]
        if isinstance(value, list):
            return [expand(v) for v in value]
        return value

    statements = []
    for _idx, stmt in iter_statements(api.resource_policy):
        stmt = dict(stmt)
        for key in ("Resource", "NotResource"):
            if key in stmt:
                stmt[key] = expand(stmt[key])
        statements.append(stmt)
    return {"Version": "2012-10-17", "Statement": statements}


def _api_reach(dev: DomainEvaluator, api: Api) -> Tuple[Optional[EvalResult], str]:
    """(public decision for an unsigned caller, reachability: ``internet``, ``vpc`` or ``restricted``).

    Without a resource policy a REGIONAL/EDGE endpoint is reachable from the internet; with one, the anonymous
    grant decides like any public grant (a strong gate such as an ``aws:SourceIp`` range or ``aws:SourceVpce``
    keeps it ``restricted``, F-031).
    """
    if api.private:
        return None, "vpc"
    doc = _execute_api_doc(api, dev.partition)
    if doc is None:
        return EvalResult(Decision.ALLOW), "internet"
    arn = f"arn:{dev.partition}:execute-api:{api.region}:{api.account}:{api.api_id}"
    parsed = parse_policy(doc, layer="resource", source_type="resource", policy_arn=api.arn,
                          policy_name="resource-policy", partition=dev.partition)
    public = [g for g in dev.grants(parsed, arn) if g.principal.kind == "anonymous" and g.decision.grants]
    if not public:
        return None, "restricted"
    best = max(public, key=lambda g: (g.decision.rank, -g.strength.rank))
    result = EvalResult(best.decision, strength=best.strength,
                        allow_refs=(best.source,) if best.source is not None else ())
    if public_grade(result) is None:
        return None, "restricted"
    return result, "internet"


def _auth_finding(builder: Any, api: Api, unauth: Sequence[ApiRoute], reach: str, public: Optional[EvalResult]
                  ) -> None:
    severity, notes = "MEDIUM", []
    if reach == "vpc":
        severity, notes = "LOW", ["PRIVATE endpoint: only callers inside the VPC (through an interface endpoint) "
                                  "can reach it"]
    elif reach == "restricted":
        severity, notes = "LOW", ["the resource policy restricts who may invoke the API"]
    if api.execute_api_disabled:
        notes.append("the default execute-api endpoint is disabled (custom domains may still route to it)")
    routes = [_route_json(r) for r in unauth]
    builder.add_finding(
        "APIGW-AUTH-001", api.arn, severity=severity, base_severity="MEDIUM", region=api.region,
        confidence="definite" if public is None or public.decision is Decision.ALLOW else "conditional",
        title=f"API '{api.name}' has {len(routes)} Lambda route(s) without authentication",
        description="These methods/routes have no effective authorisation (NONE): anyone who can reach the "
                    "endpoint can invoke the Lambda function" + (f" ({'; '.join(notes)})." if notes else "."),
        evidence={"routes": routes, "reach": reach, "endpoint_types": list(api.endpoint_types or ())},
        entity=f"apigw/{api.name}", entity_arn=api.arn, source_policy="APIConfig", source_type="apigw_config",
        resource=[api.arn])


def _legacy_auth_finding(builder: Any, api: Api) -> None:
    """d13c215 reports: only ``HasAuthorizer`` is known, so a route-level verdict is impossible (F-044)."""
    builder.add_finding(
        "APIGW-AUTH-001", api.arn, severity="MEDIUM", region=api.region, confidence="conditional",
        title=f"API '{api.name}' has Lambda integrations and no authorizer object",
        description="This report predates per-method authorisation data: the API has Lambda integrations and no "
                    "authorizer object, so its routes may be unauthenticated (AWS_IAM methods need no authorizer "
                    "object; re-collect to decide per route).",
        evidence={"basis": "legacy-has-authorizer", "functions": sorted({r.lambda_arn for r in api.targets
                                                                          if r.lambda_arn})},
        gaps=["apigateway:per-method-authorization-unknown"], entity=f"apigw/{api.name}", entity_arn=api.arn,
        source_policy="APIConfig", source_type="apigw_config", resource=[api.arn])


def _api(dev: DomainEvaluator, builder: Any, api: Api, collected: Iterable[str]) -> None:
    unknown = [] if api.routes is not None else ["apigateway:per-method-authorization-unknown"]
    add_resource_node(builder, "apigw", api.arn, api.name, region=api.region, account=api.account, props={
        "protocol": api.protocol, "api_id": api.api_id, "endpoint_types": list(api.endpoint_types or ()) or None,
        "execute_api_disabled": api.execute_api_disabled, "has_resource_policy": api.resource_policy is not None},
        coverage=node_coverage(dev.ctx, "apigateway", api.region, api.errors, legacy=api.legacy, extra=unknown))
    unresolved = _invokes(builder, api, collected)
    if unresolved:
        builder.set_node_props(api.arn, unresolved_targets=unresolved)
    public, reach = _api_reach(dev, api)
    unauth = list(api.unauthenticated or ())
    if unauth:
        _auth_finding(builder, api, unauth, reach, public)
    elif api.legacy and api.has_authorizer is False and any(r.lambda_arn for r in api.targets):
        _legacy_auth_finding(builder, api)
    if reach == "vpc" or public is None:
        return
    add_edge(builder, ids.ANONYMOUS_ID, "PUBLIC_INBOUND", api.arn, result=public,
             evidence={"basis": "api-endpoint", "reach": reach,
                       "unauthenticated_routes": len(unauth)},
             props={"auth": "none"} if unauth else None)


# ═══════════════════════════════════════════════════════════════════════════
# The analyzer
# ═══════════════════════════════════════════════════════════════════════════

def run_data_stores(ctx: Any, builder: Any) -> None:
    """Analyzer ``data_stores`` (phase RESOURCES): ECR, DynamoDB, RDS and API Gateway."""
    from aws_enumerator.engine.io.loaders.data_stores import data_stores_inventory
    from aws_enumerator.engine.io.loaders.kms import kms_resolver

    inv = data_stores_inventory(ctx)
    dev = DomainEvaluator(ctx)
    resolver = kms_resolver(ctx)
    tables = AccessEmitter(dev, builder, ("dynamodb",), DDB_CLASSES) if inv.dynamodb else None
    for item in inv.ecr + inv.dynamodb:
        _policy_resource(dev, builder, item, tables)
    for reg in inv.registries:
        _registry(dev, builder, reg)
    for rds in inv.rds:
        _rds(dev, builder, rds, resolver)
    for api in inv.apis:
        _api(dev, builder, api, inv.lambda_functions)
    _report_gaps(ctx, inv)


def _report_gaps(ctx: Any, inv: Any) -> None:
    unknown_policies = sum(1 for r in inv.ecr + inv.dynamodb if r.policy_status in UNREADABLE)
    if unknown_policies:
        ctx.add_gap("data-stores:resource-policy-unknown", "ECR repository or DynamoDB table policies that could "
                    "not be read: their public or cross-account exposure is unknown, not absent.", unknown_policies)
    unknown_sharing = sum(1 for r in inv.rds if r.is_snapshot and not r.legacy and
                          (r.public_snapshot is None or r.shared_accounts is None))
    if unknown_sharing:
        ctx.add_gap("rds:snapshot-sharing-unknown", "RDS snapshots whose restore attribute could not be read: "
                    "their public or cross-account sharing is unknown, not absent.", unknown_sharing)
    legacy_apis = sum(1 for a in inv.apis if a.routes is None)
    if legacy_apis:
        ctx.add_gap("apigateway:per-method-authorization-unknown", "APIs without per-method/route authorisation "
                    "data (old report or a failed call): unauthenticated routes cannot be listed.", legacy_apis)


ANALYZERS: Tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec("data_stores", Phase.RESOURCES, run_data_stores, inputs=("ecr", "rds", "apigateway", "dynamodb"),
                 legacy_files=("newsurface_relationships.json",)),
)


__all__ = [
    "ANALYZERS", "AccessClass", "AccessEmitter", "Candidate", "ClassResult", "DDB_READ_ACTIONS", "DDB_WRITE_ACTIONS",
    "DomainEvaluator", "ExposureResult", "ExposureSpec", "FINDINGS", "add_resource_node",
    "better", "candidates", "class_results", "emit_exposure", "encryption_edge", "external_edges", "external_grade",
    "keep_for",
    "kind_of", "kms_target", "legacy_fields", "node_coverage", "plain_resolver", "policy_gaps",
    "public_grade", "run_data_stores", "worse_of",
]
