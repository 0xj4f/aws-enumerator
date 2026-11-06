"""Compute to role: ECS, CloudFormation (stacks, StackSets), Glue, CodeBuild, SageMaker (E-compute).

Every decision comes from the policy evaluator (``ctx.evaluator``; F-001 NotAction/NotResource, F-014 Deny,
boundaries, SCP/RCP, F-015 conditions), never from the d13c215 ``stmt['actions']`` walkers. Edges follow the
traversability table (traversability-table.md §5.4; engine.md §6.3):

* ``USES_ROLE`` (control bridge) compute → the role its **code** runs as: the ECS task role (never the execution
  role, which is ``EXECUTION_ROLE``, info), a stack's service role, a StackSet's administration role, a Glue job
  or endpoint role, a CodeBuild service role, a SageMaker notebook / user-profile / domain role (F-004, F-113).
* Control over **existing** compute, per action (F-004):

  ======================  ======================================================  ====================
  resource                complete chain                                          edge
  ======================  ======================================================  ====================
  ECS task family         ``ecs:RunTask`` / ``StartTask`` + ``iam:PassRole`` of     ``CAN_HIJACK``
                          its task and execution roles (``iam:PassedToService``
                          ``ecs-tasks``)
  ECS service             ``ecs:ExecuteCommand`` on the cluster and its tasks,     ``CAN_EXEC``
                          when ECS Exec is enabled (F-113)
  CloudFormation stack    ``UpdateStack`` or ``CreateChangeSet`` +                 ``CAN_HIJACK``
                          ``ExecuteChangeSet`` (the stack keeps its role)
  StackSet                ``UpdateStackSet`` + ``iam:PassRole`` of the admin role  ``CAN_HIJACK``
  Glue job                ``UpdateJob`` + ``StartJobRun`` or ``CreateTrigger`` +    ``CAN_HIJACK``
                          ``iam:PassRole`` of the job role (UpdateJob re-passes it)
  Glue dev endpoint       ``UpdateDevEndpoint`` (add an SSH key)                   ``CAN_HIJACK``
  CodeBuild project       ``StartBuild`` / ``StartBuildBatch`` (buildspec          ``CAN_HIJACK``
                          override)
  SageMaker notebook      ``CreatePresignedNotebookInstanceUrl``                   ``CAN_EXEC``
                          lifecycle config + update + stop + start                 ``CAN_HIJACK``
  SageMaker user profile  ``CreatePresignedDomainUrl`` (IAM-auth domains; an SSO   ``CAN_EXEC``
                          domain has no presigned URL)
  SageMaker domain        ``CreateUserProfile`` + ``CreatePresignedDomainUrl`` (the ``CAN_HIJACK``
                          new profile runs as the domain default role)
  ======================  ======================================================  ====================

  Any other modifying action of the resource without a complete chain is ``CAN_MODIFY`` (info, never a path).
  ``Create*`` actions make **new** resources: they are PassRole escalations (``CAN_PASS_ROLE_TO`` from the rules,
  plus the Glue interactive-session and SageMaker training/processing-job surfaces here, F-113), never an edge
  into an existing resource.
* **ECS nodes per role set (F-049).** One ``ecstask`` node per (region, family, task role, execution role) with
  the revisions as ``props.revisions``; the id is the family ARN, plus ``?roles=<sha8>`` when a family has several
  role sets (node-ids.md §2). d13c215 reports (one record per revision, task and execution roles mixed in
  ``Roles``) are grouped the same way; their execution role is recognised by the AWS-managed
  ``AmazonECSTaskExecutionRolePolicy`` or the default ``ecsTaskExecutionRole`` name, else the role is kept as a
  conditional ``USES_ROLE`` with the gap ``ecs:role-kind-unknown``.
* **Glue ARNs (F-051).** Real ARNs come from the loader (synthesised for bare names in old reports); there is no
  bare-name branch any more, so ARN-scoped grants match and same-named jobs of two regions stay two nodes.
* **CodeBuild webhooks (F-113)**: ``CODEBUILD-WEBHOOK-001`` for a webhook-triggered project (MEDIUM when pull
  requests from anyone trigger builds, LOW for push-only or actor-filtered webhooks).
* **Null = unknown (c-b-1).** ``Roles: null`` or a failed describe makes the node ``partial`` with a gap, never
  "no role".

Performance (F-030): principals are pre-filtered by the action index (``may_cover(service)``) and, once per
resource type, by an existential evaluation on the type's ARN template; only the survivors are evaluated per
resource (memoised by the evaluator).

This module also holds the **shared evaluator helpers** the other E-compute analyzers use (``lambda_``,
``messaging``, ``cognito``): :class:`AccessScanner`, :func:`policy_grant_edges`, :func:`combine`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Set, Tuple

from aws_enumerator.engine.analyzers.coverage_gaps import is_legacy, item_coverage
from aws_enumerator.engine.graph import edge_types as ET
from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.model import (
    AnalyzerSkipped, AnalyzerSpec, Decision, EvalResult, Grant, Phase, PolicySource, PrincipalModel, Strength,
)

log = logging.getLogger(__name__)

PRINCIPAL_KINDS: Tuple[str, ...] = ("user", "role")
_NO = EvalResult(Decision.NOT_ALLOWED, reason="no_allow")


# ══ shared evaluator helpers (lambda_, messaging, cognito use them too) ═════

def unit_records(domain: Any, key: str) -> Iterator[Tuple[str, Mapping[str, Any]]]:
    """``(unit, record)`` for every record of ``domain[key][unit]`` (loader data), sorted by unit."""
    data = getattr(domain, "data", domain)
    table = data.get(key) if isinstance(data, Mapping) else None
    if not isinstance(table, Mapping):
        return
    for unit in sorted(table):
        for rec in table[unit] if isinstance(table[unit], list) else ():
            if isinstance(rec, Mapping):
                yield unit, rec


def evaluator_of(ctx: Any) -> Any:
    """``ctx.evaluator``, or a resource-policy-only evaluator when the PRINCIPALS phase produced none.

    Without IAM data the identity edges are skipped, but resource policies (public / cross-account grants) are
    still evaluated; the gap ``evaluator-unavailable`` says so.
    """
    if getattr(ctx, "evaluator", None) is not None:
        return ctx.evaluator
    cached = ctx.shared.get("e-compute.resource-evaluator")
    if cached is None:
        from aws_enumerator.engine.policy.evaluator import Evaluator

        ctx.add_gap("evaluator-unavailable", "No policy evaluator was built (IAM data missing or the principals "
                    "analyzer failed): identity-policy edges of Lambda, compute and messaging are not computed.")
        cached = ctx.shared["e-compute.resource-evaluator"] = Evaluator(ctx, {})
    return cached


def principal_models(ctx: Any, kinds: Sequence[str] = PRINCIPAL_KINDS) -> List[PrincipalModel]:
    """The local principals to evaluate (users carry their group-inherited statements), sorted by ARN."""
    if getattr(ctx, "evaluator", None) is None:
        return []
    pset = ctx.shared.get("iam.principal_set")
    if pset is not None and hasattr(pset, "of_kind"):
        return [m for kind in kinds for m in pset.of_kind(kind)]
    markers = tuple(f":{k}/" for k in kinds)
    models = getattr(ctx, "principals", {}) or {}
    return [models[a] for a in sorted(models) if any(m in a for m in markers)]


def ensure_principal_node(builder: Any, model: PrincipalModel) -> str:
    """The principal's node (normally created by ``iam-graph``; created here when that analyzer did not run)."""
    if not builder.has_node(model.id):
        kind = "role" if ":role/" in model.id else ("group" if ":group/" in model.id else "user")
        builder.add_node(model.id, kind, model.id.rsplit("/", 1)[-1])
    return model.id


def combine(results: Sequence[EvalResult]) -> EvalResult:
    """Conjunction of decisions (every step of a chain must hold): NOT_ALLOWED when one does not grant."""
    if not results:
        return _NO
    if any(not r.decision.grants for r in results):
        return _NO
    conditional = [r for r in results if r.decision is Decision.CONDITIONAL]
    refs: List[PolicySource] = []
    notes: list = []
    gaps: Set[str] = set()
    for r in results:
        refs.extend(x for x in r.allow_refs if x not in refs)
        notes.extend(n for n in r.condition_notes if n not in notes)
        gaps |= set(r.gaps)
    if not conditional:
        return EvalResult(Decision.ALLOW, allow_refs=tuple(refs), gaps=frozenset(gaps))
    return EvalResult(Decision.CONDITIONAL, reason=conditional[0].reason, allow_refs=tuple(refs),
                      condition_notes=tuple(notes), strength=Strength.strongest(r.strength for r in conditional),
                      gaps=frozenset(gaps))


def better(a: EvalResult, b: EvalResult) -> bool:
    """``a`` is a stronger grant than ``b`` (ALLOW > CONDITIONAL, then the weaker unresolved gate)."""
    if a.decision.rank != b.decision.rank:
        return a.decision.rank > b.decision.rank
    return a.strength.rank < b.strength.rank


def evaluator_error(ctx: Any, exc: BaseException, what: str) -> None:
    log.warning("evaluator failed for %s (%s)", what, type(exc).__name__)
    ctx.add_gap("evaluator-error", "The policy evaluator failed for some decisions; those edges are missing.", 1)


@dataclass(frozen=True)
class AccessClass:
    """One identity-policy capability on a resource: the edge type and the actions that grant it."""

    edge_type: str
    actions: Tuple[str, ...]
    qualified: bool = False        # also try the target's qualified ARNs (Lambda aliases and versions)


@dataclass(frozen=True)
class AccessTier:
    """Classes evaluated together; ``first_only`` emits only the strongest class that holds."""

    classes: Tuple[AccessClass, ...]
    first_only: bool = True


@dataclass(frozen=True)
class AccessTarget:
    """A resource node and the ARNs a request may name (the unqualified ARN first)."""

    node_id: str
    arn: str
    qualified: Tuple[str, ...] = ()


class AccessScanner:
    """Identity-policy edges of the local principals to one resource type (F-001, F-014, F-015, F-030).

    ``tiers`` are evaluated in order and the scan of a (principal, resource) pair stops at the first tier that
    emitted an edge. ``forced`` principals (named by a resource policy) skip the pre-filter: a same-account grant
    in the resource policy alone gives them access.
    """

    def __init__(self, ctx: Any, builder: Any, *, service: str, template: str, tiers: Sequence[AccessTier],
                 forced: Iterable[str] = ()):
        self.ctx, self.builder, self.service, self.template = ctx, builder, service, template
        self.tiers = tuple(tiers)
        self.forced = frozenset(forced)
        self.evaluator = getattr(ctx, "evaluator", None)

    def _possible(self, model: PrincipalModel) -> Tuple[AccessTier, ...]:
        """The tiers / classes this principal can hold on *some* resource of the type (hoisted, F-030)."""
        if model.id in self.forced:
            return self.tiers
        if not model.action_index.may_cover(self.service):
            return ()
        out = []
        for tier in self.tiers:
            classes = tuple(c for c in tier.classes if any(
                self.evaluator.evaluate_any(model, a, self.template).decision.grants for a in c.actions))
            if classes:
                out.append(AccessTier(classes, tier.first_only))
        return tuple(out)

    def candidates(self) -> List[Tuple[PrincipalModel, Tuple[AccessTier, ...]]]:
        out = []
        for model in principal_models(self.ctx):
            try:
                tiers = self._possible(model)
            except Exception as exc:  # noqa: BLE001 - one principal's failure must not cost the domain
                evaluator_error(self.ctx, exc, model.id)
                continue
            if tiers:
                out.append((model, tiers))
        return out

    def scan(self, targets: Sequence[AccessTarget]) -> int:
        """Emit the edges; returns the number of (principal, resource) pairs that got one."""
        if self.evaluator is None or not targets:
            return 0
        count = 0
        for model, tiers in self.candidates():
            ensure_principal_node(self.builder, model)
            for target in targets:
                try:
                    count += self._pair(model, tiers, target)
                except Exception as exc:  # noqa: BLE001 - isolate evaluator failures per pair
                    evaluator_error(self.ctx, exc, f"{model.id} -> {target.node_id}")
        return count

    def _best(self, model: PrincipalModel, cls: AccessClass, target: AccessTarget) -> Tuple[str, str, EvalResult]:
        arns = (target.arn,) + (target.qualified if cls.qualified else ())
        best: Tuple[str, str, EvalResult] = (cls.actions[0], target.arn, _NO)
        for arn in arns:
            action, result = self.evaluator.best(model, cls.actions, arn)
            if action is not None and better(result, best[2]):
                best = (action, arn, result)
        return best

    def _pair(self, model: PrincipalModel, tiers: Sequence[AccessTier], target: AccessTarget) -> int:
        for tier in tiers:
            emitted = False
            for cls in tier.classes:
                action, arn, result = self._best(model, cls, target)
                if not result.decision.grants:
                    continue
                evidence: Dict[str, Any] = {"actions": [action]}
                if arn != target.arn:
                    evidence["qualifiers"] = [arn[len(target.arn) + 1:]]
                self.builder.add_edge(model.id, cls.edge_type, target.node_id, result=result, evidence=evidence)
                emitted = True
                if tier.first_only:
                    break
            if emitted:
                return 1
        return 0


@dataclass(frozen=True)
class GrantEdge:
    """One resource-policy grant resolved to a graph node: ``kind`` is public / cross-account / local / service."""

    kind: str
    node_id: str
    grant: Grant


def policy_grant_edges(ctx: Any, builder: Any, policy: Any, resource_arn: str, *,
                       context: Optional[Mapping[str, Any]] = None) -> List[GrantEdge]:
    """Every principal a resource policy grants on ``resource_arn``, with the decision for it (F-031, F-037).

    ``*`` principals become the anonymous node (one entry per grant; callers keep the strongest); a foreign
    account or principal becomes an external node (F-039); a same-account root is delegation to identity
    policies and gives no grant edge; a stale unique id gives none either.
    """
    from aws_enumerator.engine.policy.parse import parse_policy

    evaluator = evaluator_of(ctx)
    doc = parse_policy(policy, layer="resource", source_type="resource", policy_arn=resource_arn,
                       policy_name="resource-policy", partition=ctx.partition)
    out: List[GrantEdge] = []
    for g in evaluator.resource_policy_grants(doc, resource_arn, context=context):
        if not g.decision.grants:
            continue
        kind, node_id = _grant_node(builder, g)
        if node_id is not None:
            out.append(GrantEdge(kind, node_id, g))
    return out


def _grant_node(builder: Any, g: Grant) -> Tuple[str, Optional[str]]:
    p = g.principal
    if p.kind in ("anonymous", "wildcard"):
        return "public", ids.ANONYMOUS_ID
    if p.kind == "service":
        ref = builder.ensure_principal(p.raw, principal_type="Service")
        return "service", ref.node_id
    if not p.kind.startswith("aws_"):
        return "skip", None
    ref = builder.ensure_principal(p.arn or p.raw, principal_type="AWS")
    if ref.node_id is None:
        return "skip", None
    ntype = builder.node(ref.node_id).type
    return ("cross-account" if ntype in ET.EXTERNAL else "local"), ref.node_id


def grant_result(g: Grant) -> EvalResult:
    """The edge decision of a grant (``result=`` of ``GraphBuilder.add_edge``)."""
    return EvalResult(g.decision, reason="resource-policy", allow_refs=(g.source,) if g.source else (),
                      strength=g.strength if g.decision is Decision.CONDITIONAL else Strength.NONE)


def strongest(grants: Iterable[GrantEdge]) -> Dict[Tuple[str, str], GrantEdge]:
    """The strongest grant per (kind, node)."""
    out: Dict[Tuple[str, str], GrantEdge] = {}
    for ge in grants:
        key = (ge.kind, ge.node_id)
        if key not in out or better(grant_result(ge.grant), grant_result(out[key].grant)):
            out[key] = ge
    return out


def exposure_severity(g: Grant, *, high: str = "HIGH", medium: str = "MEDIUM") -> Optional[Tuple[str, str]]:
    """``(severity, confidence)`` of a public / cross-account grant finding; ``None`` when strongly gated.

    ALLOW is definite at ``high``; a conditional grant whose gates do not restrict outsiders (strength none) is
    ``high`` conditional; a weakly gated one ``medium`` conditional; a strongly gated one (e.g. ``aws:SourceArn``
    of the account's own resource) gives no finding.
    """
    if g.decision is Decision.ALLOW:
        return high, "definite"
    if g.strength is Strength.NONE:
        return high, "conditional"
    if g.strength is Strength.WEAK:
        return medium, "conditional"
    return None


DEPUTY_ID = "SVC-DEPUTY-001"
#: How each guard key is written in policies (the finding names them).
_SOURCE_KEYS_DISPLAY = ("aws:SourceArn", "aws:SourceAccount", "aws:SourceOrgID", "aws:SourceOrgPaths")


def deputy_grants(ctx: Any, policy: Any, resource_arn: str) -> List[Grant]:
    """Grants of a resource policy (raw document or :class:`PolicyDoc`) to AWS service principals that carry no
    ``aws:SourceArn`` / ``aws:SourceAccount`` / ``aws:SourceOrgID`` restriction (SVC-DEPUTY-001, F-033)."""
    from aws_enumerator.engine.model import PolicyDoc
    from aws_enumerator.engine.policy.parse import parse_policy
    from aws_enumerator.engine.policy.resource_policy import unguarded_service_grants

    doc = policy if isinstance(policy, PolicyDoc) else parse_policy(
        policy, layer="resource", source_type="resource", policy_arn=resource_arn, policy_name="resource-policy",
        partition=ctx.partition)
    return unguarded_service_grants(doc, evaluator_of(ctx).resource_policy_grants(doc, resource_arn))


def add_deputy_findings(builder: Any, node_id: str, grants: Iterable[Grant], *, what: str, name: str,
                        region: Optional[str] = None, qualifiers: Iterable[str] = ()) -> int:
    """One SVC-DEPUTY-001 per (resource, service principal) for :func:`deputy_grants` results; returns the count.

    ``what`` names the policy ("Lambda function", "SQS queue" …) and ``name`` the resource in the title.
    """
    by_service: Dict[str, List[Grant]] = {}
    for g in grants:
        by_service.setdefault(g.principal.raw.lower(), []).append(g)
    for service, gs in sorted(by_service.items()):
        actions = sorted({a for g in gs for a in g.actions})
        definite = any(g.decision is Decision.ALLOW for g in gs)
        statements = []
        for g in gs:
            if g.source is not None and g.source.to_json() not in statements:
                statements.append(g.source.to_json())
        builder.add_finding(
            DEPUTY_ID, node_id, severity="LOW", discriminator=service,
            confidence="definite" if definite else "conditional",
            title=f"{what} '{name}' lets {service} act on it for any account",
            description=(f"The resource policy grants the AWS service principal {service} "
                         f"{', '.join(actions)} with no {' / '.join(_SOURCE_KEYS_DISPLAY[:3])} condition, so the "
                         "service can perform these actions on behalf of resources in any AWS account, not only "
                         "this account's own."),
            evidence={"service": service, "actions": actions, "statements": statements,
                      "missing_conditions": list(_SOURCE_KEYS_DISPLAY),
                      "qualifiers": sorted(set(qualifiers))},
            matched_actions=actions, region=region,
            related_node_ids=[ids.service_principal_id(service)])
    return len(by_service)


def role_lookup(ctx: Any) -> Dict[str, str]:
    """Role name → ARN of the collected roles (Glue and old reports name roles without an ARN)."""
    iam = (ctx.data or {}).get("iam")
    roles = getattr(iam, "roles", None) or {}
    return {e.name: arn for arn, e in sorted(roles.items())}


def resolve_role(ctx: Any, builder: Any, value: Any, lookup: Mapping[str, str]) -> Optional[str]:
    """Role node id for a role ARN or bare name (exact ARN resolution, placeholder when not collected)."""
    if not isinstance(value, str) or not value:
        return None
    arn = value if value.startswith("arn:") else lookup.get(value) or \
        f"arn:{ctx.partition}:iam::{ctx.account_id}:role/{value}"
    ref = builder.ensure_principal(arn, principal_type="AWS")
    if ref.node_id is None or builder.node(ref.node_id).type not in ("role", "external_principal"):
        return None
    return ref.node_id


# ══ compute surfaces ═══════════════════════════════════════════════════════

@dataclass(frozen=True)
class Step:
    """One required action; ``resource`` formats the ARN it is evaluated on (``None``: the resource itself)."""

    action: str
    resource: Optional[str] = None


@dataclass(frozen=True)
class Chain:
    """A complete existing-resource chain; ``passrole`` also requires ``iam:PassRole`` of the resource's roles."""

    steps: Tuple[Step, ...]
    technique: str
    passrole: bool = False
    needs_role: bool = False       # meaningful only when the resource runs as a role (stacks)


def _chain(technique: str, *actions: str, passrole: bool = False, needs_role: bool = False,
           resource: Optional[str] = None) -> Chain:
    return Chain(tuple(Step(a, resource) for a in actions), technique, passrole, needs_role)


@dataclass(frozen=True)
class Surface:
    """What controls one compute type (module docstring table); ``key`` is the node type or a sub-kind key."""

    key: str
    service: str
    service_principal: str
    template: str                                  # ARN template of the type (pre-filter, F-030)
    hijack: Tuple[Chain, ...] = ()
    exec_: Tuple[Chain, ...] = ()
    modify: Tuple[str, ...] = ()


#: Surface key of a SageMaker Studio user profile (node type ``sagemakerdomain``, ``Kind: user_profile``).
SM_PROFILE = "sagemakerdomain:user_profile"
_LIFECYCLE = "arn:{p}:sagemaker:{region}:{account}:notebook-instance-lifecycle-config/*"
_PROFILES = "arn:{p}:sagemaker:{region}:{account}:user-profile/{domain_id}/*"

SURFACES: Mapping[str, Surface] = {s.key: s for s in (
    Surface("ecstask", "ecs", "ecs-tasks.amazonaws.com", "arn:{p}:ecs:*:*:task-definition/*",
            hijack=(_chain("run-task-with-overrides", "ecs:RunTask", passrole=True),
                    _chain("start-task-with-overrides", "ecs:StartTask", passrole=True)),
            modify=("ecs:RunTask", "ecs:StartTask", "ecs:RegisterTaskDefinition", "ecs:DeregisterTaskDefinition")),
    Surface("ecsservice", "ecs", "ecs-tasks.amazonaws.com", "arn:{p}:ecs:*:*:service/*",
            modify=("ecs:UpdateService", "ecs:DeleteService", "ecs:ExecuteCommand")),
    Surface("cfnstack", "cloudformation", "cloudformation.amazonaws.com", "arn:{p}:cloudformation:*:*:stack/*",
            hijack=(_chain("update-stack-with-its-role", "cloudformation:UpdateStack", needs_role=True),
                    _chain("change-set-with-its-role", "cloudformation:CreateChangeSet",
                           "cloudformation:ExecuteChangeSet", needs_role=True)),
            modify=("cloudformation:UpdateStack", "cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet",
                    "cloudformation:DeleteStack", "cloudformation:SetStackPolicy")),
    Surface("stackset", "cloudformation", "cloudformation.amazonaws.com", "arn:{p}:cloudformation:*:*:stackset/*",
            hijack=(_chain("update-stack-set", "cloudformation:UpdateStackSet", passrole=True, needs_role=True),),
            modify=("cloudformation:UpdateStackSet", "cloudformation:CreateStackInstances",
                    "cloudformation:UpdateStackInstances", "cloudformation:DeleteStackSet")),
    Surface("gluejob", "glue", "glue.amazonaws.com", "arn:{p}:glue:*:*:job/*",
            hijack=(_chain("update-job-and-run", "glue:UpdateJob", "glue:StartJobRun", passrole=True),
                    _chain("update-job-and-trigger", "glue:UpdateJob", "glue:CreateTrigger", passrole=True)),
            modify=("glue:UpdateJob", "glue:StartJobRun", "glue:CreateTrigger", "glue:DeleteJob",
                    "glue:BatchStopJobRun")),
    Surface("gluedevendpoint", "glue", "glue.amazonaws.com", "arn:{p}:glue:*:*:devEndpoint/*",
            hijack=(_chain("add-ssh-key", "glue:UpdateDevEndpoint"),),
            modify=("glue:UpdateDevEndpoint", "glue:DeleteDevEndpoint")),
    Surface("codebuild", "codebuild", "codebuild.amazonaws.com", "arn:{p}:codebuild:*:*:project/*",
            hijack=(_chain("start-build-with-buildspec-override", "codebuild:StartBuild"),
                    _chain("start-build-batch-with-buildspec-override", "codebuild:StartBuildBatch")),
            modify=("codebuild:UpdateProject", "codebuild:StartBuild", "codebuild:StartBuildBatch",
                    "codebuild:DeleteProject", "codebuild:CreateWebhook", "codebuild:UpdateWebhook")),
    Surface("sagemaker", "sagemaker", "sagemaker.amazonaws.com", "arn:{p}:sagemaker:*:*:notebook-instance/*",
            hijack=(Chain((Step("sagemaker:CreateNotebookInstanceLifecycleConfig", _LIFECYCLE),
                           Step("sagemaker:UpdateNotebookInstance"), Step("sagemaker:StopNotebookInstance"),
                           Step("sagemaker:StartNotebookInstance")), "lifecycle-config"),),
            exec_=(_chain("presigned-notebook-url", "sagemaker:CreatePresignedNotebookInstanceUrl"),),
            modify=("sagemaker:UpdateNotebookInstance", "sagemaker:StopNotebookInstance",
                    "sagemaker:StartNotebookInstance", "sagemaker:DeleteNotebookInstance",
                    "sagemaker:CreatePresignedNotebookInstanceUrl")),
    Surface("sagemakerdomain", "sagemaker", "sagemaker.amazonaws.com", "arn:{p}:sagemaker:*:*:*/*",
            hijack=(Chain((Step("sagemaker:CreateUserProfile", _PROFILES),
                           Step("sagemaker:CreatePresignedDomainUrl", _PROFILES)), "new-user-profile-default-role"),),
            modify=("sagemaker:UpdateDomain", "sagemaker:DeleteDomain")),
    Surface(SM_PROFILE, "sagemaker", "sagemaker.amazonaws.com", "arn:{p}:sagemaker:*:*:user-profile/*",
            exec_=(_chain("presigned-domain-url", "sagemaker:CreatePresignedDomainUrl"),),
            modify=("sagemaker:UpdateUserProfile", "sagemaker:DeleteUserProfile")),
)}

#: PassRole escalations to **new** compute that no rule of the d13c215 catalogue covered (F-113):
#: (service, service principal, technique, actions on ``*``-scoped templates).
PASSROLE_CREATE: Tuple[Tuple[str, str, str, Tuple[Tuple[str, str], ...]], ...] = (
    ("glue", "glue.amazonaws.com", "glue-interactive-session",
     (("glue:CreateSession", "arn:{p}:glue:*:*:session/*"), ("glue:RunStatement", "arn:{p}:glue:*:*:session/*"))),
    ("sagemaker", "sagemaker.amazonaws.com", "sagemaker-training-job",
     (("sagemaker:CreateTrainingJob", "arn:{p}:sagemaker:*:*:training-job/*"),)),
    ("sagemaker", "sagemaker.amazonaws.com", "sagemaker-processing-job",
     (("sagemaker:CreateProcessingJob", "arn:{p}:sagemaker:*:*:processing-job/*"),)),
)


@dataclass
class ComputeNode:
    """One compute resource as a graph node: id, type, region, role bindings and the record it came from."""

    node_id: str
    node_type: str
    region: str
    arn: str
    record: Mapping[str, Any]
    uses: Tuple[str, ...] = ()             # role node ids its code runs as (USES_ROLE)
    execution: Tuple[str, ...] = ()        # ECS execution roles (EXECUTION_ROLE)
    uses_confidence: str = "definite"
    roles_known: bool = True
    props: Dict[str, Any] = field(default_factory=dict)
    gaps: Set[str] = field(default_factory=set)
    format_args: Dict[str, str] = field(default_factory=dict)
    surface: str = ""                      # SURFACES key when it differs from the node type
    enterable: bool = True                 # False: no interactive entry (SageMaker domain in SSO auth mode)

    @property
    def surface_key(self) -> str:
        return self.surface or self.node_type


def _fmt(template: str, node: ComputeNode, ctx: Any) -> str:
    args = {"p": ctx.partition, "region": node.region, "account": ctx.account_id}
    args.update(node.format_args)
    return template.format(**args)


# ── compute nodes from the loader data ───────────────────────────────────────

_EXEC_POLICY = ":iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"


def _region_account(arn: Any, unit: str, ctx: Any) -> Tuple[str, str]:
    p = ids.parse_arn(arn) if isinstance(arn, str) else None
    region = p.region if p is not None and p.region else unit
    account = p.account if p is not None and p.account else ctx.account_id
    return region, account


def _looks_like_execution_role(ctx: Any, role_arn: str) -> bool:
    """d13c215 ECS records mix task and execution roles: recognise the execution role by its managed policy."""
    iam = (ctx.data or {}).get("iam")
    ent = (getattr(iam, "roles", None) or {}).get(role_arn)
    if ent is not None and any(a.endswith(_EXEC_POLICY) for a in getattr(ent, "attached", ()) or ()):
        return True
    return role_arn.rsplit("/", 1)[-1].lower() == "ecstaskexecutionrole"


@dataclass
class _EcsGroup:
    unit: str
    region: str
    family: str
    task: Tuple[str, ...]
    execution: Tuple[str, ...]
    confidence: str = "definite"
    roles_known: bool = True
    revisions: Set[int] = field(default_factory=set)
    newest: Tuple[int, str] = (-1, "")
    truncated: bool = False
    records: List[Mapping[str, Any]] = field(default_factory=list)
    gaps: Set[str] = field(default_factory=set)


def _ecs_roles(ctx: Any, rec: Mapping[str, Any]) -> Tuple[Tuple[str, ...], Tuple[str, ...], str, bool, Set[str]]:
    """(task roles, execution roles, confidence, roles known, gaps) of one ECS record (v2 or d13c215)."""
    if any(k in rec for k in ("TaskRole", "ExecutionRole", "Revisions")):
        task = tuple(r for r in [rec.get("TaskRole")] if isinstance(r, str) and r)
        execution = tuple(r for r in [rec.get("ExecutionRole")] if isinstance(r, str) and r)
        known = not (rec.get("Roles") is None and not task and not execution and rec.get("CollectionErrors"))
        return task, execution, "definite", known, (set() if known else {"ecs:roles-unknown"})
    roles = rec.get("Roles")
    if roles is None:
        return (), (), "definite", False, {"ecs:roles-unknown"}
    roles = sorted({r for r in roles if isinstance(r, str) and r})
    execution = tuple(r for r in roles if _looks_like_execution_role(ctx, r))
    task = tuple(r for r in roles if r not in execution)
    if len(roles) <= 1 and not execution or len(task) > 1:
        return task, execution, "conditional", True, {"ecs:role-kind-unknown"}
    return task, execution, "definite", True, set()


def _revision(rec: Mapping[str, Any]) -> Tuple[Optional[str], Optional[int]]:
    arn = rec.get("Arn")
    if not isinstance(arn, str) or ":task-definition/" not in arn:
        return None, None
    body = arn.split(":task-definition/", 1)[1]
    family, _, rev = body.partition(":")
    return family, int(rev) if rev.isdigit() else None


def _ecs_groups(ctx: Any) -> List[_EcsGroup]:
    groups: Dict[Tuple[str, str, Tuple[str, ...], Tuple[str, ...]], _EcsGroup] = {}
    for unit, rec in unit_records((ctx.data or {}).get("compute"), "ecs"):
        arn_family, rev = _revision(rec)
        family = str(rec.get("Family") or arn_family or rec.get("Name") or "")
        if not family or unit == "global":
            continue
        task, execution, conf, known, gaps = _ecs_roles(ctx, rec)
        region, _account = _region_account(rec.get("Arn"), unit, ctx)
        g = groups.setdefault((region, family, task, execution),
                              _EcsGroup(unit, region, family, task, execution, conf, known))
        g.records.append(rec)
        g.gaps |= gaps
        g.roles_known = g.roles_known and known
        if conf == "conditional":
            g.confidence = "conditional"
        revs = [r for r in rec.get("Revisions") or () if isinstance(r, int)] or ([rev] if rev is not None else [])
        g.revisions.update(revs)
        g.truncated = g.truncated or bool(rec.get("RevisionsTruncated"))
        top = max(revs) if revs else -1
        if top >= g.newest[0] and isinstance(rec.get("Arn"), str):
            g.newest = (top, rec["Arn"])
    return [groups[k] for k in sorted(groups)]


def _ecs_nodes(ctx: Any, builder: Any, lookup: Mapping[str, str]) -> List[ComputeNode]:
    groups = _ecs_groups(ctx)
    per_family: Dict[Tuple[str, str], int] = {}
    for g in groups:
        per_family[(g.region, g.family)] = per_family.get((g.region, g.family), 0) + 1
    out = []
    for g in groups:
        roles = g.task + g.execution
        suffix = ids.role_set_suffix(roles) if per_family[(g.region, g.family)] > 1 else ""
        node_id = f"arn:{ctx.partition}:ecs:{g.region}:{ctx.account_id}:task-definition/{g.family}{suffix}"
        if not ids.node_id_matches("ecstask", node_id):
            ctx.add_gap("compute:unrecognised-id", "Some compute resources have identifiers outside the node-id "
                        "scheme and are not in the graph.", 1)
            continue
        node = ComputeNode(node_id, "ecstask", g.region, g.newest[1] or node_id, g.records[-1],
                           uses=_resolve_all(ctx, builder, g.task, lookup),
                           execution=_resolve_all(ctx, builder, g.execution, lookup),
                           uses_confidence=g.confidence, roles_known=g.roles_known, gaps=set(g.gaps))
        node.props = {"family": g.family, "revisions": sorted(g.revisions), "revisions_truncated": g.truncated,
                      "newest_revision_arn": g.newest[1] or None, "task_role": g.task[0] if g.task else None,
                      "execution_role": g.execution[0] if g.execution else None}
        node.record = _merged_errors(g.records)
        out.append(node)
    return out


def _merged_errors(records: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    errors = [e for r in records for e in r.get("CollectionErrors") or () if isinstance(e, Mapping)]
    return {"CollectionErrors": errors} if errors else {}


def _resolve_all(ctx: Any, builder: Any, roles: Iterable[Any], lookup: Mapping[str, str]) -> Tuple[str, ...]:
    out = []
    for r in roles:
        node_id = resolve_role(ctx, builder, r, lookup)
        if node_id and node_id not in out:
            out.append(node_id)
    return tuple(out)


def _service_nodes(ctx: Any, builder: Any, tasks: Sequence[ComputeNode]) -> List[ComputeNode]:
    by_revision: Dict[str, ComputeNode] = {}
    for t in tasks:
        family = str(t.props.get("family"))
        for rev in t.props.get("revisions") or ():
            by_revision[f"{t.region}/{family}:{rev}"] = t
    out = []
    for unit, rec in unit_records((ctx.data or {}).get("compute"), "ecs_services"):
        arn = rec.get("ServiceArn")
        if not isinstance(arn, str) or not ids.node_id_matches("ecsservice", arn):
            continue
        region, _ = _region_account(arn, unit, ctx)
        family, rev = _revision({"Arn": rec.get("TaskDefinition")})
        task = by_revision.get(f"{region}/{family}:{rev}")
        node = ComputeNode(arn, "ecsservice", region, arn, rec, uses=task.uses if task else (),
                           execution=task.execution if task else (), roles_known=task is not None,
                           uses_confidence=task.uses_confidence if task else "definite")
        if task is None:
            node.gaps.add("ecs:task-definition-not-collected")
        node.props = {"cluster_arn": rec.get("ClusterArn"), "task_definition": rec.get("TaskDefinition"),
                      "enable_execute_command": rec.get("EnableExecuteCommand"),
                      "launch_type": rec.get("LaunchType"), "assign_public_ip": rec.get("AssignPublicIp")}
        out.append(node)
    return out


#: (loader key, record ``Type`` values that key may hold).
_GENERIC_KEYS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("cloudformation", ("cfnstack", "stackset")), ("glue", ("gluejob", "gluedevendpoint")),
    ("codebuild", ("codebuild",)), ("sagemaker", ("sagemaker", "sagemakerdomain")),
)


def _generic_props(ntype: str, rec: Mapping[str, Any]) -> Dict[str, Any]:
    if ntype == "stackset":
        return {"permission_model": rec.get("PermissionModel"), "execution_role_name": rec.get("ExecutionRoleName")}
    if ntype == "cfnstack":
        return {"stack_status": rec.get("StackStatus")}
    if ntype == "codebuild":
        source = rec.get("Source") if isinstance(rec.get("Source"), Mapping) else {}
        return {"project_visibility": rec.get("ProjectVisibility"), "source_type": source.get("Type"),
                "webhook": isinstance(rec.get("Webhook"), Mapping)}
    if ntype == "sagemakerdomain":
        return {"kind": rec.get("Kind"), "domain_id": rec.get("DomainId"), "auth_mode": rec.get("AuthMode"),
                "inherits_domain_role": rec.get("InheritsDomainRole")}
    if ntype == "sagemaker":
        return {"direct_internet_access": rec.get("DirectInternetAccess"), "root_access": rec.get("RootAccess")}
    if ntype in ("gluejob", "gluedevendpoint"):
        return {"arn_synthesised": True} if rec.get("ArnSynthesised") else {}
    return {}


def _domain_auth_modes(ctx: Any) -> Dict[Tuple[str, str], Any]:
    """``(region, domain id) -> AuthMode`` of the collected SageMaker Studio domains."""
    out: Dict[Tuple[str, str], Any] = {}
    for unit, rec in unit_records((ctx.data or {}).get("compute"), "sagemaker"):
        if rec.get("Type") == "sagemakerdomain" and rec.get("Kind") == "domain" and rec.get("DomainId"):
            region, _ = _region_account(rec.get("Arn"), unit, ctx)
            out[(region, str(rec["DomainId"]))] = rec.get("AuthMode")
    return out


def _sagemaker_domain(node: ComputeNode, auth_modes: Mapping[Tuple[str, str], Any]) -> None:
    """Domain / user-profile specifics: the profile surface, the domain id and SSO auth mode (no presigned URL)."""
    rec = node.record
    domain_id = str(rec.get("DomainId") or node.arn.split("/")[1])
    node.format_args["domain_id"] = domain_id
    if rec.get("Kind") == "user_profile" or ":user-profile/" in node.arn:
        node.surface = SM_PROFILE
    mode = rec.get("AuthMode") if rec.get("Kind") == "domain" else auth_modes.get((node.region, domain_id))
    if str(mode or "").upper() == "SSO":
        node.enterable = False             # CreatePresignedDomainUrl works only for IAM-auth domains
        node.props["auth_mode"] = "SSO"


def _generic_nodes(ctx: Any, builder: Any, lookup: Mapping[str, str]) -> List[ComputeNode]:
    out = []
    auth_modes = _domain_auth_modes(ctx)
    for key, types in _GENERIC_KEYS:
        for unit, rec in unit_records((ctx.data or {}).get("compute"), key):
            ntype, arn = str(rec.get("Type") or ""), rec.get("Arn")
            if ntype not in types or not isinstance(arn, str) or not ids.node_id_matches(ntype, arn):
                if rec.get("Arn"):
                    ctx.add_gap("compute:unrecognised-id", "Some compute resources have identifiers outside the "
                                "node-id scheme and are not in the graph.", 1)
                continue
            region, _ = _region_account(arn, unit, ctx)
            roles = rec.get("Roles")
            node = ComputeNode(arn, ntype, region, arn, rec, uses=_resolve_all(ctx, builder, roles or (), lookup),
                               roles_known=roles is not None, props=_generic_props(ntype, rec))
            if roles is None:
                node.gaps.add(f"{key}:roles-unknown")
            if ntype == "sagemakerdomain":
                _sagemaker_domain(node, auth_modes)
            out.append(node)
    return out


def compute_nodes(ctx: Any, builder: Any) -> List[ComputeNode]:
    """Every compute node of the analysed regions, created in the graph with its role edges."""
    lookup = role_lookup(ctx)
    tasks = _ecs_nodes(ctx, builder, lookup)
    nodes = tasks + _service_nodes(ctx, builder, tasks) + _generic_nodes(ctx, builder, lookup)
    legacy = is_legacy(ctx)
    for n in nodes:
        status, gaps = item_coverage(n.record, legacy=legacy)
        if n.gaps:
            status = "partial" if status in (None, "complete") else status
        props = {k: v for k, v in n.props.items() if v is not None}
        label = str(n.record.get("Name") or n.props.get("family") or n.node_id.rsplit("/", 1)[-1])
        builder.add_node(n.node_id, n.node_type, label, region=n.region, props=props, coverage_status=status,
                         coverage_gaps=sorted(set(gaps) | n.gaps))
        _role_edges(builder, n)
    return nodes


def _role_edges(builder: Any, n: ComputeNode) -> None:
    for role in n.uses:
        conf = n.uses_confidence
        builder.add_edge(n.node_id, "USES_ROLE", role, confidence=conf, strength="weak" if conf == "conditional"
                         else None, evidence={"gaps": sorted(n.gaps)} if conf == "conditional" else None)
    if n.node_type in ("ecstask", "ecsservice"):
        for role in n.execution:
            if role not in n.uses:
                builder.add_edge(n.node_id, "EXECUTION_ROLE", role, evidence={"technique": "ecs-agent-only"})


# ── control over existing compute (F-004, F-113) ─────────────────────────────

class ComputeControl:
    """``CAN_HIJACK`` / ``CAN_EXEC`` / ``CAN_MODIFY`` edges from the local principals (module docstring table)."""

    def __init__(self, ctx: Any, builder: Any):
        self.ctx, self.builder = ctx, builder
        self.evaluator = getattr(ctx, "evaluator", None)

    def _step(self, model: PrincipalModel, step: Step, node: ComputeNode) -> EvalResult:
        if step.resource is None:
            return self.evaluator.evaluate(model, step.action, node.arn)
        resource = _fmt(step.resource, node, self.ctx)
        if "*" in resource:
            return self.evaluator.evaluate_any(model, step.action, resource)
        return self.evaluator.evaluate(model, step.action, resource)

    def _passrole(self, model: PrincipalModel, node: ComputeNode, surface: Surface) -> EvalResult:
        """``iam:PassRole`` of every role the run needs (ECS: the task **and** execution roles)."""
        roles = [r for r in node.uses + node.execution if ":role/" in r]
        if not roles:
            return _NO
        ctx = {"iam:PassedToService": surface.service_principal}
        return combine([self.evaluator.evaluate(model, "iam:PassRole", r, context=ctx) for r in roles])

    def chain(self, model: PrincipalModel, chain: Chain, node: ComputeNode, surface: Surface) -> EvalResult:
        if chain.needs_role and not node.uses:
            return _NO
        results = []
        for step in chain.steps:
            r = self._step(model, step, node)
            if not r.decision.grants:
                return _NO
            results.append(r)
        if chain.passrole:
            results.append(self._passrole(model, node, surface))
        return combine(results)

    def _best_chain(self, model: PrincipalModel, chains: Sequence[Chain], node: ComputeNode,
                    surface: Surface) -> Tuple[Optional[Chain], EvalResult]:
        best: Tuple[Optional[Chain], EvalResult] = (None, _NO)
        for c in chains:
            r = self.chain(model, c, node, surface)
            if r.decision.grants and better(r, best[1]):
                best = (c, r)
        return best

    def _emit(self, model: PrincipalModel, etype: str, node: ComputeNode, chain: Chain, result: EvalResult) -> None:
        actions = [s.action for s in chain.steps] + (["iam:PassRole"] if chain.passrole else [])
        evidence: Dict[str, Any] = {"technique": chain.technique, "actions": actions}
        if chain.passrole:
            evidence["passrole_roles"] = sorted({r for r in node.uses + node.execution if ":role/" in r})
        self.builder.add_edge(model.id, etype, node.node_id, result=result, evidence=evidence)

    def node_edges(self, model: PrincipalModel, node: ComputeNode, surface: Surface) -> None:
        emitted = False
        for etype, chains in (("CAN_HIJACK", surface.hijack), ("CAN_EXEC", surface.exec_)):
            if not node.enterable and surface.service == "sagemaker" and node.node_type == "sagemakerdomain":
                break
            chain, result = self._best_chain(model, chains, node, surface)
            if chain is not None:
                self._emit(model, etype, node, chain, result)
                emitted = True
        if node.node_type == "ecsservice":
            emitted = self._ecs_exec(model, node) or emitted
        if emitted or not surface.modify:
            return
        action, result = self.evaluator.best(model, surface.modify, node.arn)
        if action is not None and result.decision.grants:
            self.builder.add_edge(model.id, "CAN_MODIFY", node.node_id, result=result,
                                  evidence={"actions": [action], "technique": "incomplete-chain"})

    def _ecs_exec(self, model: PrincipalModel, node: ComputeNode) -> bool:
        """``ecs:ExecuteCommand`` into a service with ECS Exec enabled (unknown: conditional, F-113)."""
        enabled = node.record.get("EnableExecuteCommand")
        cluster = node.record.get("ClusterArn")
        if enabled is False or not isinstance(cluster, str) or ":cluster/" not in cluster:
            return False
        name = cluster.split(":cluster/", 1)[1]
        tasks = f"arn:{self.ctx.partition}:ecs:{node.region}:{self.ctx.account_id}:task/{name}/*"
        parts = [self.evaluator.evaluate(model, "ecs:ExecuteCommand", cluster),
                 self.evaluator.evaluate_any(model, "ecs:ExecuteCommand", tasks)]
        if enabled is None:
            parts.append(EvalResult(Decision.CONDITIONAL, reason="ecs-exec-unknown", strength=Strength.WEAK,
                                    gaps=frozenset({"ecs:enable-execute-command-unknown"})))
        result = combine(parts)
        if not result.decision.grants:
            return False
        self.builder.add_edge(model.id, "CAN_EXEC", node.node_id, result=result,
                              evidence={"technique": "ecs-exec", "actions": ["ecs:ExecuteCommand"]})
        return True

    def _may_act(self, model: PrincipalModel, surface: Surface) -> bool:
        """Pre-filter (F-030): can the principal do any action of the surface on *some* resource of the type?"""
        if not model.action_index.may_cover(surface.service):
            return False
        template = surface.template.format(p=self.ctx.partition)
        actions = {s.action for c in surface.hijack + surface.exec_ for s in c.steps} | set(surface.modify)
        return any(self.evaluator.evaluate_any(model, a, template).decision.grants for a in sorted(actions))

    def run(self, nodes: Sequence[ComputeNode]) -> int:
        if self.evaluator is None:
            return 0
        by_type: Dict[str, List[ComputeNode]] = {}
        for n in nodes:
            by_type.setdefault(n.surface_key, []).append(n)
        pairs = 0
        for model in principal_models(self.ctx):
            for ntype in sorted(by_type):
                surface = SURFACES[ntype]
                try:
                    if not self._may_act(model, surface):
                        continue
                    ensure_principal_node(self.builder, model)
                    for node in by_type[ntype]:
                        self.node_edges(model, node, surface)
                        pairs += 1
                except Exception as exc:  # noqa: BLE001 - isolate one principal's evaluator failure
                    evaluator_error(self.ctx, exc, f"{model.id} on {ntype}")
        return pairs


def passrole_create_edges(ctx: Any, builder: Any) -> int:
    """``CAN_PASS_ROLE_TO`` for the new-compute PassRole surfaces of :data:`PASSROLE_CREATE` (F-113)."""
    evaluator = getattr(ctx, "evaluator", None)
    pset = ctx.shared.get("iam.principal_set")
    if evaluator is None or pset is None:
        return 0
    roles = [m.id for m in pset.of_kind("role")]
    count = 0
    for service, principal, technique, steps in PASSROLE_CREATE:
        passable = [r for r in roles if evaluator.can_assume(f"svc:{principal}", r).decision.grants]
        if not passable:
            continue
        for model in principal_models(ctx):
            if not (model.action_index.may_cover(service) and model.action_index.may_cover("iam")):
                continue
            create = combine([evaluator.evaluate_any(model, a, t.format(p=ctx.partition)) for a, t in steps])
            if not create.decision.grants:
                continue
            for role in passable:
                if role == model.id:
                    continue
                result = combine([create, evaluator.evaluate(model, "iam:PassRole", role,
                                                             context={"iam:PassedToService": principal})])
                if result.decision.grants:
                    ensure_principal_node(builder, model)
                    builder.add_edge(model.id, "CAN_PASS_ROLE_TO", role, result=result, evidence={
                        "technique": technique, "via": [service],
                        "actions": [a for a, _ in steps] + ["iam:PassRole"]})
                    count += 1
    return count


# ── CodeBuild webhooks (poisoned pipeline, F-113) ────────────────────────────

_PR_EVENTS = ("PULL_REQUEST_CREATED", "PULL_REQUEST_UPDATED", "PULL_REQUEST_REOPENED")


def webhook_exposure(webhook: Mapping[str, Any]) -> Tuple[str, List[str]]:
    """``(severity, reasons)``: MEDIUM when a pull request from anyone triggers a build, else LOW."""
    groups = webhook.get("FilterGroups") or []
    if not groups:
        return "MEDIUM", ["no filter groups: every event of the repository (pull requests included) builds"]
    reasons = []
    for group in groups:
        filters = [f for f in group or () if isinstance(f, Mapping)]
        events = " ".join(str(f.get("pattern") or "") for f in filters if str(f.get("type")).upper() == "EVENT")
        actor = any(str(f.get("type")).upper() == "ACTOR_ACCOUNT_ID" and not f.get("excludeMatchedPattern")
                    for f in filters)
        if any(e in events for e in _PR_EVENTS) and not actor:
            reasons.append("pull-request events without an ACTOR_ACCOUNT_ID filter")
    if reasons:
        return "MEDIUM", sorted(set(reasons))
    return "LOW", ["builds run on pushes (or actor-filtered events) to the source repository"]


def codebuild_webhook_findings(builder: Any, nodes: Sequence[ComputeNode]) -> int:
    count = 0
    for n in nodes:
        webhook = n.record.get("Webhook") if n.node_type == "codebuild" else None
        if not isinstance(webhook, Mapping):
            continue
        severity, reasons = webhook_exposure(webhook)
        source = n.record.get("Source") if isinstance(n.record.get("Source"), Mapping) else {}
        name = str(n.record.get("Name") or n.node_id)
        builder.add_finding(
            "CODEBUILD-WEBHOOK-001", n.node_id, severity=severity,
            title=f"CodeBuild project '{name}' builds on repository webhooks",
            description=("Commits or pull requests to the project's source repository trigger builds that run "
                         "as the project's service role: whoever can push (or open a pull request) can run code "
                         "with that role (poisoned pipeline). " + "; ".join(reasons) + "."),
            evidence={"source_type": source.get("Type"), "build_type": webhook.get("BuildType"),
                      "reasons": reasons, "project_visibility": n.record.get("ProjectVisibility")},
            related_node_ids=list(n.uses), region=n.region)
        count += 1
    return count


# ── the analyzer ─────────────────────────────────────────────────────────────

def analyze_compute(ctx: Any, builder: Any) -> None:
    """Analyzer ``compute`` (phase RESOURCES): nodes, role bridges, control edges, findings."""
    if (ctx.data or {}).get("compute") is None:
        raise AnalyzerSkipped("compute", reason="no compute data was loaded")
    nodes = compute_nodes(ctx, builder)
    pairs = ComputeControl(ctx, builder).run(nodes)
    created = passrole_create_edges(ctx, builder)
    hooks = codebuild_webhook_findings(builder, nodes)
    log.debug("compute: %d nodes, %d evaluated pairs, %d passrole edges, %d webhooks", len(nodes), pairs,
              created, hooks)


def _run(ctx: Any, builder: Any) -> None:
    analyze_compute(ctx, builder)       # looked up at call time (tests may patch the module attribute)


#: Finding ids this module emits (findings/catalog.py merges them, DECISIONS.md D-33).
def _findings() -> Tuple[Any, ...]:
    from aws_enumerator.engine.findings.catalog import A_EXPOSURE, A_PRIVESC, CatalogEntry

    return (CatalogEntry(
        "CODEBUILD-WEBHOOK-001", "MEDIUM", "compute_pipeline", "CodeBuild project builds on repository webhooks",
        "Restrict webhook filter groups (ACTOR_ACCOUNT_ID, branch filters, no pull requests from forks), give the "
        "service role least privilege and require approval for builds of untrusted contributions.", A_PRIVESC),
        # emitted by the lambda, messaging and s3 analyzers through add_deputy_findings (one declaration, D-33)
        CatalogEntry(
            DEPUTY_ID, "LOW", "service_principal_scope",
            "Resource policy grants an AWS service without a source condition",
            "Add an aws:SourceArn (the resource the service acts for) or aws:SourceAccount / aws:SourceOrgID "
            "condition to the statement that grants the service principal, so that the service can use the "
            "grant only on behalf of your own resources.", A_EXPOSURE, discriminator="service",
            description="A resource policy (Lambda permission, SQS queue, SNS topic or S3 bucket policy) grants an "
                        "AWS service principal access with no aws:SourceArn, aws:SourceAccount or aws:SourceOrgID "
                        "condition, so the service may act on the resource for any AWS account's resources."),)


FINDINGS: Tuple[Any, ...] = _findings()

ANALYZERS: Tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec("compute", Phase.RESOURCES, _run, inputs=("ecs", "cloudformation", "glue", "codebuild", "sagemaker"),
                 legacy_files=("compute_relationships.json",)),
)
