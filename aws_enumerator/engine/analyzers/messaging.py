"""Messaging: SNS topics and SQS queues -- who can use them, who they are shared with, where they deliver (E-compute).

Every decision comes from the policy evaluator (``ctx.evaluator``; F-001 NotAction/NotResource, F-014 Deny,
boundaries, SCP/RCP, F-015 conditions), never from the d13c215 ``stmt['actions']`` walkers. Topic and queue
policies are registered in the evaluator's resource index first, so a same-account grant in a queue policy also
counts for the identity decisions (same-account union), and parsed with ``iter_statements`` (a single-object
``Statement`` is one statement, F-002).

Edges (traversability-table.md §5.11, §5.14, §5.15):

* identity policies, per (principal, resource): ``CAN_ADMIN_MSG`` (``Set{Topic,Queue}Attributes`` /
  ``AddPermission``: can rewrite the policy, so it implies the rest) else ``CAN_RECEIVE``
  (``sns:Subscribe`` / ``sqs:ReceiveMessage``) and ``CAN_SEND`` (``sns:Publish`` / ``sqs:SendMessage``);
* resource policies: ``MSG_GRANTS_PUBLIC`` (anonymous) and ``MSG_GRANTS_CROSS_ACCOUNT`` (external account or
  principal), normalised grantee → resource, with ``MSG-PUB-001`` / ``MSG-XACCT-001`` graded by the grant's
  condition strength (a ``*`` principal gated by ``aws:SourceArn`` of the account's own resource is the normal
  way services publish and gives no finding); a grant to an AWS service principal with no ``aws:SourceArn`` /
  ``aws:SourceAccount`` / ``aws:SourceOrgID`` condition is ``SVC-DEPUTY-001`` (LOW, F-033);
* ``SUBSCRIBES`` topic → SQS queue / Lambda function (unqualified) for ``sqs`` / ``lambda`` subscriptions; other
  endpoints (HTTP, e-mail, Firehose …) are listed in ``props.subscriptions_other`` (F-116);
* ``MSG_ENCRYPTED_BY`` topic / queue → KMS key (``KmsMasterKeyId`` resolved to the key, F-027, F-116); SSE-SQS
  (``SqsManagedSseEnabled``) has no customer key and gives ``props.sse = "sqs-managed"``.

**Null = unknown (c-b-1, F-059).** A ``PolicyStatus`` of denied / error / skipped (or a d13c215 record without a
policy) means the policy could not be read: the node is ``partial`` with ``props.exposure_unknown`` and the
evaluator treats the resource policy as unknown (cross-account decisions become conditional) -- never "not
public". ``Subscriptions: null`` and ``KmsMasterKeyId: null`` with ``CollectionErrors`` are unknown as well.

Performance (F-030): principals are pre-filtered by the action index (``may_cover(service)``) and, once per
resource type, by an existential evaluation on the type's ARN template (:class:`AccessScanner`); only the survivors
are evaluated per resource (memoised by the evaluator). 200 roles × 1,000 queues runs in well under two seconds.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from aws_enumerator.engine.analyzers.compute import (
    AccessClass, AccessScanner, AccessTarget, AccessTier, GrantEdge, add_deputy_findings, deputy_grants, evaluator_of,
    exposure_severity, grant_result, policy_grant_edges, strongest, unit_records,
)
from aws_enumerator.engine.analyzers.coverage_gaps import is_legacy, item_coverage, register_policy
from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.model import AnalyzerSkipped, AnalyzerSpec, Phase

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Service:
    """One messaging service: node type, the API that reads its policy, ARN template and capability tiers."""

    name: str
    attributes_api: str
    template: str
    admin: Tuple[str, ...]
    receive: Tuple[str, ...]
    send: Tuple[str, ...]
    aws_managed_alias: str

    def tiers(self) -> Tuple[AccessTier, ...]:
        return (AccessTier((AccessClass("CAN_ADMIN_MSG", self.admin),), first_only=True),
                AccessTier((AccessClass("CAN_RECEIVE", self.receive), AccessClass("CAN_SEND", self.send)),
                           first_only=False))


SERVICES: Mapping[str, Service] = {s.name: s for s in (
    Service("sns", "sns:GetTopicAttributes", "arn:{p}:sns:*:*:*",
            admin=("sns:SetTopicAttributes", "sns:AddPermission"), receive=("sns:Subscribe",),
            send=("sns:Publish",), aws_managed_alias="alias/aws/sns"),
    Service("sqs", "sqs:GetQueueAttributes", "arn:{p}:sqs:*:*:*",
            admin=("sqs:SetQueueAttributes", "sqs:AddPermission"), receive=("sqs:ReceiveMessage",),
            send=("sqs:SendMessage",), aws_managed_alias="alias/aws/sqs"),
)}
_GRANT_EDGE = {"public": "MSG_GRANTS_PUBLIC", "cross-account": "MSG_GRANTS_CROSS_ACCOUNT"}


@dataclass
class Resource:
    """One topic or queue node with its collected record and policy read state."""

    service: Service
    node_id: str
    region: str
    record: Mapping[str, Any]
    state: str = "unknown"
    gaps: Set[str] = field(default_factory=set)

    @property
    def name(self) -> str:
        return str(self.record.get("Name") or self.node_id.rsplit(":", 1)[-1])


# ── resources ────────────────────────────────────────────────────────────────

def load_resources(ctx: Any) -> List[Resource]:
    """Topics and queues of the analysed regions (records without a usable ARN are a counted gap)."""
    data = (ctx.data or {}).get("messaging")
    out: Dict[str, Resource] = {}
    unusable = 0
    for key in sorted(SERVICES):
        for unit, rec in unit_records(data, key):
            arn = rec.get("Arn")
            if unit == "global" or not isinstance(arn, str) or not ids.node_id_matches(key, arn):
                unusable += 1
                continue
            out.setdefault(arn, Resource(SERVICES[key], arn, arn.split(":")[3], rec))
    if unusable:
        ctx.add_gap("messaging:unrecognised-id", "Some SNS/SQS records have no usable ARN and are not in the "
                    "graph.", unusable)
    return [out[k] for k in sorted(out)]


def _sse(res: Resource) -> Optional[str]:
    rec = res.record
    if rec.get("KmsMasterKeyId"):
        return "kms"
    if rec.get("SqsManagedSseEnabled") is True:
        return "sqs-managed"
    if "KmsMasterKeyId" in rec and rec.get("CollectionErrors"):
        return None                                     # attributes unreadable: unknown, not "unencrypted"
    if "KmsMasterKeyId" in rec or rec.get("SqsManagedSseEnabled") is False:
        return "none"
    return None


def _props(res: Resource) -> Dict[str, Any]:
    subs = res.record.get("Subscriptions")
    props: Dict[str, Any] = {"policy_status": res.state, "sse": _sse(res),
                             "kms_master_key_id": res.record.get("KmsMasterKeyId")}
    if isinstance(subs, list):
        props["subscription_count"] = len(subs)
    if res.state == "unknown":
        props["exposure_unknown"] = True
    return {k: v for k, v in props.items() if v is not None}


def add_resource_nodes(ctx: Any, builder: Any, resources: Sequence[Resource]) -> None:
    """Register each policy with the evaluator, then create the node with its read state (F-059)."""
    evaluator = evaluator_of(ctx)
    legacy = is_legacy(ctx)
    for res in resources:
        rec = res.record
        res.state = register_policy(evaluator, res.node_id, rec.get("Policy"), rec.get("PolicyStatus"),
                                    owner=ctx.account_id)
        status, gaps = item_coverage(rec, legacy=legacy, policy_api=res.service.attributes_api)
        res.gaps = set(gaps)
        if res.state == "unknown" and not legacy:
            res.gaps.add(f"{res.service.attributes_api}:policy-unknown")
            status = "partial"
        if res.service.name == "sns" and "Subscriptions" in rec and rec.get("Subscriptions") is None:
            res.gaps.add("sns:ListSubscriptionsByTopic:unknown")
            status = "partial"
        builder.add_node(res.node_id, res.service.name, res.name, region=res.region, props=_props(res),
                         coverage_status=status, coverage_gaps=sorted(res.gaps))


# ── resource-policy grants (F-031, F-037, F-039) ─────────────────────────────

def grant_edges(ctx: Any, builder: Any, res: Resource) -> Set[str]:
    """``MSG_GRANTS_*`` edges and findings of one resource; returns the same-account grantees (forced)."""
    policy = res.record.get("Policy")
    if res.state != "present" or not isinstance(policy, Mapping):
        return set()
    local: Set[str] = set()
    gated = False
    for (kind, node_id), ge in sorted(strongest(policy_grant_edges(ctx, builder, policy, res.node_id)).items()):
        if kind == "local":
            local.add(node_id)
            continue
        if kind not in _GRANT_EDGE:
            continue
        graded = exposure_severity(ge.grant) if kind == "public" else \
            exposure_severity(ge.grant, high="MEDIUM", medium="LOW")
        if kind == "public" and graded is None:
            gated = True
            continue
        builder.add_edge(node_id, _GRANT_EDGE[kind], res.node_id, result=grant_result(ge.grant),
                         evidence={"actions": sorted(ge.grant.actions), "technique": "resource-policy"},
                         props={"cross_account": True} if kind == "cross-account" else None)
        if graded is not None:
            _grant_finding(builder, res, kind, node_id, ge, graded)
    if gated:
        builder.set_node_props(res.node_id, public_grant_gated=True)
    return local


def deputy_findings(ctx: Any, builder: Any, res: Resource) -> int:
    """SVC-DEPUTY-001: the topic / queue policy lets an AWS service principal (``sns``, ``events``, ``s3`` …) use
    it with no ``aws:SourceArn`` / ``aws:SourceAccount`` condition (F-033)."""
    policy = res.record.get("Policy")
    if res.state != "present" or not isinstance(policy, Mapping):
        return 0
    grants = deputy_grants(ctx, policy, res.node_id)
    what = "SNS topic" if res.service.name == "sns" else "SQS queue"
    return add_deputy_findings(builder, res.node_id, grants, what=what, name=res.name, region=res.region) \
        if grants else 0


def _grant_finding(builder: Any, res: Resource, kind: str, node_id: str, ge: GrantEdge,
                   graded: Tuple[str, str]) -> None:
    severity, confidence = graded
    label = res.service.name.upper()
    actions = sorted(ge.grant.actions)
    if kind == "public":
        builder.add_finding(
            "MSG-PUB-001", res.node_id, severity=severity, base_severity="HIGH", confidence=confidence,
            title=f"{label} '{res.name}' grants access to everyone",
            description=(f"The {label} policy lets any principal perform {', '.join(actions)}"
                         + (" under conditions an outsider may satisfy." if confidence == "conditional" else ".")),
            evidence={"actions": actions, "decision": ge.grant.decision.value,
                      "condition_strength": ge.grant.strength.value},
            matched_actions=actions, region=res.region, related_node_ids=[ids.ANONYMOUS_ID])
        return
    account = builder.node(node_id).account
    builder.add_finding(
        "MSG-XACCT-001", res.node_id, severity=severity, base_severity="MEDIUM", confidence=confidence,
        title=f"{label} '{res.name}' grants access to account {account}",
        description=(f"The {label} policy lets {ge.grant.principal.raw} (account {account}) perform "
                     f"{', '.join(actions)}."),
        evidence={"actions": actions, "grantee": node_id, "decision": ge.grant.decision.value},
        discriminator=str(account or node_id), matched_actions=actions, region=res.region, related_node_ids=[node_id])


# ── identity-policy edges (F-001, F-014, F-015, F-030) ──────────────────────

def access_edges(ctx: Any, builder: Any, resources: Sequence[Resource], forced: Mapping[str, Set[str]]) -> int:
    """``CAN_ADMIN_MSG`` / ``CAN_RECEIVE`` / ``CAN_SEND`` of the local principals, one scan per service.

    ``forced``: per service, the local principals a topic / queue policy of that service names (they skip the
    pre-filter, because the same-account grant alone may give them access).
    """
    pairs = 0
    for name, service in sorted(SERVICES.items()):
        targets = [AccessTarget(r.node_id, r.node_id) for r in resources if r.service.name == name]
        if not targets:
            continue
        scanner = AccessScanner(ctx, builder, service=name, template=service.template.format(p=ctx.partition),
                                tiers=service.tiers(), forced=forced.get(name, ()))
        pairs += scanner.scan(targets)
    return pairs


# ── data flow and encryption (F-116) ─────────────────────────────────────────

def _subscription_target(builder: Any, endpoint: str, protocol: str) -> Optional[Tuple[str, Optional[str]]]:
    """(node id, qualifier) of an SQS / Lambda subscription endpoint, creating a placeholder node if needed."""
    if protocol == "sqs" and ids.node_id_matches("sqs", endpoint):
        node_id, ntype, qualifier = endpoint, "sqs", None
    elif protocol == "lambda":
        try:
            node_id, qualifier = ids.lambda_unqualified(endpoint)
        except ValueError:
            return None
        ntype = "lambda"
        if not ids.node_id_matches("lambda", node_id):
            return None
    else:
        return None
    if not builder.has_node(node_id):
        p = ids.parse_arn(node_id)
        builder.add_node(node_id, ntype, node_id.rsplit(":", 1)[-1], region=p.region if p else None,
                         props={"placeholder": True}, coverage_status="not-collected")
    return node_id, qualifier


def subscription_edges(builder: Any, res: Resource) -> int:
    """``SUBSCRIBES`` topic → queue / function; other endpoints become ``props.subscriptions_other``."""
    subs = res.record.get("Subscriptions") if res.service.name == "sns" else None
    if not isinstance(subs, list):
        return 0
    other: Set[str] = set()
    count = 0
    for sub in subs:
        if not isinstance(sub, Mapping):
            continue
        protocol, endpoint = str(sub.get("Protocol") or "").lower(), sub.get("Endpoint")
        hit = _subscription_target(builder, endpoint, protocol) if isinstance(endpoint, str) else None
        if hit is None or hit[0] == res.node_id:
            other.add(f"{protocol}:{endpoint}" if endpoint else protocol)
            continue
        evidence: Dict[str, Any] = {"technique": "topic-subscription", "protocol": protocol}
        if hit[1]:
            evidence["qualifiers"] = [hit[1]]
        if sub.get("Owner") and str(sub.get("Owner")) != builder.account_id:
            evidence["subscription_owner"] = str(sub.get("Owner"))
        builder.add_edge(res.node_id, "SUBSCRIBES", hit[0], evidence=evidence)
        count += 1
    if other:
        builder.set_node_props(res.node_id, subscriptions_other=sorted(other))
    return count


def encryption_edge(ctx: Any, builder: Any, res: Resource) -> bool:
    """``MSG_ENCRYPTED_BY`` to the resolved key (an unresolvable alias is a placeholder key node, F-027)."""
    ref = res.record.get("KmsMasterKeyId")
    if not isinstance(ref, str) or not ref:
        return False
    from aws_enumerator.engine.io.loaders.kms import kms_resolver

    kref = kms_resolver(ctx).resolve(ref, region=res.region)
    if kref is None or not ids.node_id_matches("kms", kref.node_id):
        return False
    if not builder.has_node(kref.node_id):
        props: Dict[str, Any] = {"placeholder": True}
        if not kref.resolved:
            props["unresolved_alias"] = True
        if kref.node_id.endswith(f":{res.service.aws_managed_alias}"):
            props["aws_managed"] = True
        builder.add_node(kref.node_id, "kms", kref.node_id.split(":", 5)[-1], region=res.region, props=props)
    builder.add_edge(res.node_id, "MSG_ENCRYPTED_BY", kref.node_id,
                     evidence={"kms_reference": ref, "resolution": kref.kind})
    return True


# ── the analyzer ─────────────────────────────────────────────────────────────

def analyze_messaging(ctx: Any, builder: Any) -> None:
    """Analyzer ``messaging`` (phase RESOURCES): nodes, grants, access edges, subscriptions, encryption."""
    if (ctx.data or {}).get("messaging") is None:
        raise AnalyzerSkipped("messaging", reason="no SNS/SQS data was loaded")
    resources = load_resources(ctx)
    add_resource_nodes(ctx, builder, resources)
    forced: Dict[str, Set[str]] = {}
    flows = encrypted = 0
    for res in resources:
        forced.setdefault(res.service.name, set()).update(grant_edges(ctx, builder, res))
        deputy_findings(ctx, builder, res)
        flows += subscription_edges(builder, res)
        encrypted += encryption_edge(ctx, builder, res)
    pairs = access_edges(ctx, builder, resources, forced)
    log.debug("messaging: %d resources, %d principal/resource pairs with edges, %d subscriptions, %d encrypted",
              len(resources), pairs, flows, encrypted)


def _run(ctx: Any, builder: Any) -> None:
    analyze_messaging(ctx, builder)       # looked up at call time (tests may patch the module attribute)


def _findings() -> Tuple[Any, ...]:
    from aws_enumerator.engine.findings.catalog import A_EXPOSURE, CatalogEntry

    return (
        CatalogEntry("MSG-PUB-001", "HIGH", "messaging_public", "Topic or queue policy grants everyone",
                     "Scope the Principal or add a Condition (e.g. aws:SourceArn/SourceAccount).", A_EXPOSURE),
        CatalogEntry("MSG-XACCT-001", "MEDIUM", "messaging_cross_account",
                     "Topic or queue policy grants another account", "Verify cross-account access is intended.",
                     A_EXPOSURE, discriminator="target-account"),
    )


#: Finding ids this module emits (findings/catalog.py merges them, DECISIONS.md D-33).
FINDINGS: Tuple[Any, ...] = _findings()

ANALYZERS: Tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec("messaging", Phase.RESOURCES, _run, inputs=("sns", "sqs"),
                 legacy_files=("messaging_relationships.json",)),
)
