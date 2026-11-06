"""Lambda: functions, their roles, who controls / exposes / invokes them, public URLs and policies (E-compute).

Decisions come from the policy evaluator (F-001 NotAction/NotResource, F-014 Deny/boundaries/SCP, F-015
conditions); resource policies go through ``Evaluator.resource_policy_grants`` (F-031) after being registered in
the evaluator's index, so a same-account grant in a function policy also counts for identity decisions.

Edges (traversability-table.md §5.9, engine.md §6.3; F-004):

* ``USES_ROLE`` function → execution role (control bridge).
* Identity policies, per (principal, function), strongest first: ``CAN_UPDATE_CODE``
  (``lambda:UpdateFunctionCode``) or ``CAN_MODIFY_CONFIG`` (``lambda:UpdateFunctionConfiguration`` only) are
  **control**; otherwise ``CAN_EXPOSE`` (``AddPermission``, ``Create/UpdateFunctionUrlConfig``,
  ``PublishVersion``, ``Create/UpdateAlias``: info) and ``CAN_INVOKE`` (access, never traversable: invoking a
  function never gives its role). Requests on alias / version ARNs count for the qualifier-aware classes.
* Function policies (the function's own and every alias's, F-055): ``LAMBDA_GRANTS_PUBLIC`` (anonymous),
  ``LAMBDA_GRANTS_CROSS_ACCOUNT`` (external account / principal) and ``LAMBDA_GRANTS_INVOKE`` (same-account
  principal or service), all normalised grantee → function and non-traversable (entering compute is never
  control). Grants on an alias are attached to the **unqualified** function node with the qualifier in
  ``evidence.qualifiers``; there is no alias node (node-ids.md: ``props.qualifiers``).
* ``HAS_SG`` function → security group (VPC functions), ``TRIGGERS`` SQS queue / DynamoDB table → function
  (event source mappings, F-116), ``LAYER_GRANTS_PUBLIC`` anonymous → layer version (F-116).

Findings:

* ``LAMBDA-URL-001`` (HIGH): a function URL with ``AuthType NONE`` **and** a policy (of the URL's qualifier)
  that lets an unauthenticated caller invoke it (``lambda:InvokeFunctionUrl`` / ``lambda:InvokeFunction`` with
  ``lambda:FunctionUrlAuthType = NONE``, F-080). When that policy could not be read the exposure is unknown:
  MEDIUM, conditional, never "not public" (F-059). ``LAMBDA-URL-002`` (INFO) when the policy is known and does
  not authorise anonymous callers (the URL answers 403).
* ``SVC-DEPUTY-001`` (LOW, declared in ``compute.py``): a function policy lets an AWS service principal invoke
  the function with no ``aws:SourceArn`` / ``aws:SourceAccount`` / ``aws:SourceOrgID`` condition (F-033).
* ``LAMBDA-PUB-001`` / ``LAMBDA-XACCT-001``: a function policy grants everyone / another account (graded by the
  grant's condition strength). A public grant that only serves the function URL (``InvokeFunctionUrl`` under
  ``lambda:FunctionUrlAuthType``) is reported by the URL findings instead, never twice.
* ``LAMBDA-LAYER-PUB-001``: a layer version policy lets anyone use the layer; ``LAMBDA-LAYER-XACCT-001`` (LOW) and
  ``LAYER_GRANTS_CROSS_ACCOUNT`` from the foreign grantee: it lets another account use it (F-116, D-52).

Null = unknown (request c-b-1): ``FunctionUrls`` / ``Aliases`` / ``PolicyStatus`` of ``null`` mean "not read",
recorded as node coverage gaps, never as "no URL" or "no policy".
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from aws_enumerator.engine.analyzers.compute import (
    AccessClass, AccessScanner, AccessTarget, AccessTier, GrantEdge, add_deputy_findings, better, deputy_grants,
    evaluator_of, exposure_severity, grant_result, policy_grant_edges, resolve_role, role_lookup, strongest,
    unit_records,
)
from aws_enumerator.engine.analyzers.coverage_gaps import is_legacy, item_coverage, register_policy
from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.model import AnalyzerSkipped, AnalyzerSpec, Decision, Phase
from aws_enumerator.engine.policy.glob import action_matches

log = logging.getLogger(__name__)

GET_POLICY = "lambda:GetPolicy"
URL_AUTH_KEY = "lambda:FunctionUrlAuthType"
URL_CONTEXT = {URL_AUTH_KEY: "NONE"}
URL_ACTIONS = ("lambda:InvokeFunctionUrl", "lambda:InvokeFunction")
LAYER_ACTION = "lambda:GetLayerVersion"
FUNCTION_TEMPLATE = "arn:{p}:lambda:*:*:function:*"

TIERS: Tuple[AccessTier, ...] = (
    AccessTier((AccessClass("CAN_UPDATE_CODE", ("lambda:UpdateFunctionCode",)),
                AccessClass("CAN_MODIFY_CONFIG", ("lambda:UpdateFunctionConfiguration",))), first_only=True),
    AccessTier((AccessClass("CAN_EXPOSE", ("lambda:AddPermission", "lambda:CreateFunctionUrlConfig",
                                           "lambda:UpdateFunctionUrlConfig", "lambda:PublishVersion",
                                           "lambda:CreateAlias", "lambda:UpdateAlias"), qualified=True),
                AccessClass("CAN_INVOKE", ("lambda:InvokeFunction", "lambda:InvokeFunctionUrl", "lambda:InvokeAsync"),
                            qualified=True)), first_only=False),
)
_GRANT_EDGE = {"public": "LAMBDA_GRANTS_PUBLIC", "cross-account": "LAMBDA_GRANTS_CROSS_ACCOUNT",
               "local": "LAMBDA_GRANTS_INVOKE", "service": "LAMBDA_GRANTS_INVOKE"}


@dataclass
class Function:
    """One function (unqualified node) with its qualifiers, policies and their read states."""

    node_id: str
    region: str
    name: str
    record: Mapping[str, Any]
    policies: Dict[Optional[str], Any] = field(default_factory=dict)       # qualifier -> document
    states: Dict[Optional[str], str] = field(default_factory=dict)         # qualifier -> present|absent|unknown
    qualifiers: Tuple[str, ...] = ()

    def arn(self, qualifier: Optional[str] = None) -> str:
        return f"{self.node_id}:{qualifier}" if qualifier else self.node_id


# ── functions and policies ───────────────────────────────────────────────────

def _qualifier_states(rec: Mapping[str, Any]) -> Dict[str, Any]:
    """``PolicyStatus`` per alias / version (v2 records); ``None`` values = unknown."""
    out: Dict[str, Any] = {}
    for key, name_key in (("Aliases", "Name"), ("Versions", "Version")):
        for item in rec.get(key) or ():
            if isinstance(item, Mapping) and item.get(name_key) is not None:
                out[str(item[name_key])] = item.get("PolicyStatus")
    return out


def load_functions(ctx: Any) -> Dict[str, Function]:
    """Functions of the analysed regions keyed by unqualified ARN, with their policies keyed by qualifier."""
    lam = (ctx.data or {}).get("lambda")
    out: Dict[str, Function] = {}
    for unit, rec in unit_records(lam, "functions"):
        try:
            node_id = ids.lambda_unqualified(str(rec.get("FunctionArn")))[0]
        except ValueError:
            continue
        if unit == "global" or not ids.node_id_matches("lambda", node_id) or node_id in out:
            continue
        name = str(rec.get("FunctionName") or node_id.rsplit(":", 1)[-1])
        out[node_id] = Function(node_id, node_id.split(":")[3], name, rec,
                                qualifiers=tuple(sorted(_qualifier_states(rec))))
    for _unit, pol in unit_records(lam, "policies"):
        fn = out.get(str(pol.get("FunctionArn")))
        if fn is not None and pol.get("Qualifier") not in fn.policies:
            fn.policies[pol.get("Qualifier")] = pol.get("ResourcePolicy")
    return out


def register_policies(ctx: Any, fn: Function) -> None:
    """Register every policy of the function in the evaluator's index and record its read state (F-059).

    A qualifier collected without a policy is marked absent under its **qualified** ARN, so the index never
    falls back to the unqualified function's policy for it (an alias has a policy of its own).
    """
    evaluator = evaluator_of(ctx)
    states = _qualifier_states(fn.record)
    base_status = fn.record.get("PolicyStatus")
    fn.states[None] = register_policy(evaluator, fn.node_id, fn.policies.get(None), base_status, owner=ctx.account_id)
    for q in sorted(set(states) | {q for q in fn.policies if q}):
        status = states.get(q) if q in states else ("present" if fn.policies.get(q) else None)
        fn.states[q] = register_policy(evaluator, fn.arn(q), fn.policies.get(q), status, owner=ctx.account_id)


def _urls(rec: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    """URL configs of both layouts as ``{Qualifier, FunctionUrl, AuthType}`` (``[]`` when unknown)."""
    urls = rec.get("FunctionUrls")
    if isinstance(urls, list):
        return [u for u in urls if isinstance(u, Mapping)]
    single = rec.get("FunctionUrl")
    if isinstance(single, Mapping):
        return [{"Qualifier": None, "FunctionUrl": single.get("Url"), "AuthType": single.get("AuthType")}]
    return []


def _node_props(fn: Function) -> Dict[str, Any]:
    rec = fn.record
    urls = [{"qualifier": u.get("Qualifier"), "auth_type": u.get("AuthType")} for u in _urls(rec)]
    vpc = rec.get("VpcConfig") if isinstance(rec.get("VpcConfig"), Mapping) else {}
    props: Dict[str, Any] = {"runtime": rec.get("Runtime"), "qualifiers": list(fn.qualifiers),
                             "function_urls": urls, "layers": sorted(x for x in rec.get("Layers") or () if x),
                             "vpc_id": vpc.get("VpcId"), "policy_status": fn.states.get(None)}
    if "FunctionUrls" in rec and rec.get("FunctionUrls") is None:
        props["function_urls_unknown"] = True
    if "Aliases" in rec and rec.get("Aliases") is None:
        props["aliases_unknown"] = True
    return {k: v for k, v in props.items() if v not in (None, [])}


def _coverage(ctx: Any, fn: Function) -> Tuple[Optional[str], List[str]]:
    status, gaps = item_coverage(fn.record, legacy=is_legacy(ctx), policy_api=GET_POLICY)
    extra = set()
    if "FunctionUrls" in fn.record and fn.record.get("FunctionUrls") is None:
        extra.add("lambda:ListFunctionUrlConfigs:unknown")
    if "Aliases" in fn.record and fn.record.get("Aliases") is None:
        extra.add("lambda:ListAliases:unknown")
    extra |= {f"{GET_POLICY}:unknown@{q}" for q, s in fn.states.items() if q and s == "unknown"}
    if extra:
        return "partial", sorted(set(gaps) | extra)
    return status, gaps


def add_function_nodes(ctx: Any, builder: Any, functions: Mapping[str, Function]) -> None:
    """One node per unqualified function, its execution role bridge and its security groups."""
    lookup = role_lookup(ctx)
    for fn in functions.values():
        status, gaps = _coverage(ctx, fn)
        builder.add_node(fn.node_id, "lambda", fn.name, region=fn.region, props=_node_props(fn),
                         coverage_status=status, coverage_gaps=gaps)
        role = resolve_role(ctx, builder, fn.record.get("Role"), lookup)
        if role:
            builder.add_edge(fn.node_id, "USES_ROLE", role, evidence={"technique": "execution-role"})
        _security_groups(ctx, builder, fn)


def _security_groups(ctx: Any, builder: Any, fn: Function) -> None:
    vpc = fn.record.get("VpcConfig") if isinstance(fn.record.get("VpcConfig"), Mapping) else {}
    for sg in sorted({s for s in vpc.get("SecurityGroupIds") or () if isinstance(s, str)}):
        try:
            sg_id = ids.node_id_for("sg", partition=ctx.partition, region=fn.region, account=ctx.account_id, id=sg)
        except ValueError:
            continue
        if not builder.has_node(sg_id):
            builder.add_node(sg_id, "sg", sg, region=fn.region, props={"placeholder": True})
        builder.add_edge(fn.node_id, "HAS_SG", sg_id)


# ── identity-policy edges (F-001, F-004, F-014, F-015, F-030) ───────────────

def access_edges(ctx: Any, builder: Any, functions: Mapping[str, Function],
                 forced: Set[str]) -> int:
    """``CAN_UPDATE_CODE`` / ``CAN_MODIFY_CONFIG`` / ``CAN_EXPOSE`` / ``CAN_INVOKE`` of the local principals."""
    targets = [AccessTarget(fn.node_id, fn.node_id, tuple(fn.arn(q) for q in fn.qualifiers))
               for fn in functions.values()]
    scanner = AccessScanner(ctx, builder, service="lambda", template=FUNCTION_TEMPLATE.format(p=ctx.partition),
                            tiers=TIERS, forced=forced)
    return scanner.scan(targets)


# ── resource-policy grants ───────────────────────────────────────────────────

def _url_auth_types(fn: Function, qualifier: Optional[str]) -> Set[str]:
    """``AuthType`` values of the function URLs of one qualifier (``None`` = the unqualified function)."""
    out = set()
    for url in _urls(fn.record):
        q = url.get("Qualifier") if isinstance(url.get("Qualifier"), str) and url.get("Qualifier") else None
        if q == qualifier:
            out.add(str(url.get("AuthType") or "").upper())
    return out


def _url_only(ge: GrantEdge, fn: Function, qualifier: Optional[str]) -> bool:
    """A public grant that only serves the function URL and is reported by :func:`url_findings` (or is dormant).

    ``lambda:InvokeFunctionUrl`` alone is meaningful only through a URL: with a NONE-auth URL the URL findings
    report it (never twice), without any URL it is dormant. With an AWS_IAM URL it stays a public grant (any
    authenticated AWS principal may call the URL).
    """
    acts = {a.lower() for a in ge.grant.actions}
    if not acts or not all(action_matches(a, "lambda:InvokeFunctionUrl") and "*" not in a for a in acts):
        return False
    auth = _url_auth_types(fn, qualifier)
    return "NONE" in auth or not auth


def _grants(ctx: Any, builder: Any, fn: Function) -> Dict[Tuple[str, str], Tuple[GrantEdge, Set[str], Set[str]]]:
    """Strongest grant per (kind, node) over the function's policies, with qualifiers and actions seen."""
    acc: Dict[Tuple[str, str], Tuple[GrantEdge, Set[str], Set[str]]] = {}
    for q in sorted(fn.policies, key=lambda x: (x is not None, x or "")):
        doc = fn.policies[q]
        if fn.states.get(q) != "present" or not isinstance(doc, Mapping):
            continue
        found = strongest(policy_grant_edges(ctx, builder, doc, fn.arn(q)))
        for key, ge in sorted(found.items()):
            if ge.kind == "public" and _url_only(ge, fn, q):
                continue                         # reported by url_findings, or dormant (F-080)
            prev = acc.get(key)
            qualifiers = (prev[1] if prev else set()) | ({q} if q else set())
            actions = (prev[2] if prev else set()) | set(ge.grant.actions)
            best = ge if prev is None or better(grant_result(ge.grant), grant_result(prev[0].grant)) else prev[0]
            acc[key] = (best, qualifiers, actions)
    return acc


def grant_edges(ctx: Any, builder: Any, fn: Function) -> Set[str]:
    """``LAMBDA_GRANTS_*`` edges and ``LAMBDA-PUB-001`` / ``LAMBDA-XACCT-001``; returns the local grantees."""
    gated, local = False, set()
    for (kind, node_id), (ge, qualifiers, actions) in sorted(_grants(ctx, builder, fn).items()):
        if kind == "public" and exposure_severity(ge.grant) is None:
            gated = True
            continue
        evidence = {"actions": sorted(actions), "qualifiers": sorted(qualifiers), "technique": "function-policy"}
        builder.add_edge(node_id, _GRANT_EDGE[kind], fn.node_id, result=grant_result(ge.grant), evidence=evidence,
                         props={"cross_account": True} if kind == "cross-account" else None)
        if kind == "public":
            _public_finding(builder, fn, ge, actions, qualifiers)
        elif kind == "cross-account":
            _cross_account_finding(builder, fn, ge, node_id, actions, qualifiers)
        elif kind == "local":
            local.add(node_id)
    if gated:
        builder.set_node_props(fn.node_id, public_grant_gated=True)
    return local


def deputy_findings(ctx: Any, builder: Any, fn: Function) -> int:
    """SVC-DEPUTY-001: the function's policies (own and per qualifier) let an AWS service invoke it with no
    ``aws:SourceArn`` / ``aws:SourceAccount`` condition (``lambda add-permission`` without ``--source-arn`` /
    ``--source-account``; F-033)."""
    grants, qualifiers = [], set()
    for q in sorted(fn.policies, key=lambda x: (x is not None, x or "")):
        doc = fn.policies[q]
        if fn.states.get(q) != "present" or not isinstance(doc, Mapping):
            continue
        found = deputy_grants(ctx, doc, fn.arn(q))
        grants.extend(found)
        if found and q:
            qualifiers.add(q)
    return add_deputy_findings(builder, fn.node_id, grants, what="Lambda function", name=fn.name, region=fn.region,
                               qualifiers=qualifiers) if grants else 0


def _public_finding(builder: Any, fn: Function, ge: GrantEdge, actions: Set[str], qualifiers: Set[str]) -> None:
    severity, confidence = exposure_severity(ge.grant) or ("HIGH", "conditional")
    where = f" (qualifiers: {', '.join(sorted(qualifiers))})" if qualifiers else ""
    builder.add_finding(
        "LAMBDA-PUB-001", fn.node_id, severity=severity, base_severity="HIGH", confidence=confidence,
        title=f"Lambda '{fn.name}' grants public access via its resource policy",
        description=(f"A policy of the function{where} lets any caller perform {', '.join(sorted(actions))}"
                     + (" under conditions an outsider may satisfy." if confidence == "conditional" else ".")),
        evidence={"actions": sorted(actions), "qualifiers": sorted(qualifiers), "decision": ge.grant.decision.value,
                  "condition_strength": ge.grant.strength.value},
        matched_actions=sorted(actions), region=fn.region, related_node_ids=[ids.ANONYMOUS_ID])


def _cross_account_finding(builder: Any, fn: Function, ge: GrantEdge, node_id: str, actions: Set[str],
                           qualifiers: Set[str]) -> None:
    graded = exposure_severity(ge.grant, high="MEDIUM", medium="LOW")
    if graded is None:
        return
    severity, confidence = graded
    account = builder.node(node_id).account
    builder.add_finding(
        "LAMBDA-XACCT-001", fn.node_id, severity=severity, base_severity="MEDIUM", confidence=confidence,
        title=f"Lambda '{fn.name}' grants access to account {account}",
        description=(f"A policy of the function lets {ge.grant.principal.raw} (account {account}) perform "
                     f"{', '.join(sorted(actions))}."),
        evidence={"actions": sorted(actions), "qualifiers": sorted(qualifiers), "grantee": node_id,
                  "decision": ge.grant.decision.value},
        discriminator=str(account or node_id), matched_actions=sorted(actions), region=fn.region,
        related_node_ids=[node_id])


# ── function URLs (F-080, F-055) ─────────────────────────────────────────────

def _url_grant(ctx: Any, builder: Any, fn: Function, qualifier: Optional[str]) -> Optional[GrantEdge]:
    """The strongest anonymous grant of InvokeFunctionUrl / InvokeFunction in the qualifier's own policy."""
    doc = fn.policies.get(qualifier)
    if not isinstance(doc, Mapping):
        return None
    best: Optional[GrantEdge] = None
    for ge in policy_grant_edges(ctx, builder, doc, fn.arn(qualifier), context=URL_CONTEXT):
        if ge.kind != "public" or ge.grant.principal.kind not in ("anonymous", "wildcard"):
            continue
        if not any(action_matches(a, u) for a in ge.grant.actions for u in URL_ACTIONS):
            continue
        if best is None or better(grant_result(ge.grant), grant_result(best.grant)):
            best = ge
    return best


def url_findings(ctx: Any, builder: Any, fn: Function) -> None:
    for url in _urls(fn.record):
        if str(url.get("AuthType") or "").upper() != "NONE":
            continue
        q = url.get("Qualifier") if isinstance(url.get("Qualifier"), str) and url.get("Qualifier") else None
        state = fn.states.get(q, "unknown")
        if state == "present":
            ge = _url_grant(ctx, builder, fn, q)
            if ge is None or exposure_severity(ge.grant) is None:
                _url_not_public(builder, fn, q, url)
            else:
                _url_public(builder, fn, q, url, ge)
        elif state == "absent":
            _url_not_public(builder, fn, q, url)
        else:
            _url_unknown(builder, fn, q, url)


def _url_evidence(q: Optional[str], url: Mapping[str, Any], **extra: Any) -> Dict[str, Any]:
    ev = {"qualifier": q, "url": url.get("FunctionUrl"), "auth_type": "NONE"}
    ev.update(extra)
    return {k: v for k, v in ev.items() if v is not None}


def _where(q: Optional[str]) -> str:
    return f" on alias/version '{q}'" if q else ""


def _url_public(builder: Any, fn: Function, q: Optional[str], url: Mapping[str, Any], ge: GrantEdge) -> None:
    severity, confidence = exposure_severity(ge.grant) or ("MEDIUM", "conditional")
    builder.add_edge(ids.ANONYMOUS_ID, "LAMBDA_GRANTS_PUBLIC", fn.node_id, result=grant_result(ge.grant),
                     evidence={"technique": "function-url", "qualifiers": [q] if q else [],
                               "actions": sorted(ge.grant.actions)})
    builder.add_finding(
        "LAMBDA-URL-001", fn.node_id, severity=severity, base_severity="HIGH", confidence=confidence,
        title=f"Lambda '{fn.name}' has a public function URL{_where(q)} (AuthType NONE)",
        description="The function URL needs no authentication and the function policy lets unauthenticated "
                    "callers invoke it: anyone on the internet can run the function.",
        evidence=_url_evidence(q, url, policy="public", decision=ge.grant.decision.value),
        discriminator=q or "", matched_actions=["lambda:InvokeFunctionUrl"], region=fn.region,
        related_node_ids=[ids.ANONYMOUS_ID])


def _url_not_public(builder: Any, fn: Function, q: Optional[str], url: Mapping[str, Any]) -> None:
    builder.add_finding(
        "LAMBDA-URL-002", fn.node_id, severity="INFO",
        title=f"Lambda '{fn.name}' has a function URL{_where(q)} with AuthType NONE that is not publicly authorised",
        description="The URL needs no authentication, but no policy of that qualifier lets unauthenticated callers "
                    "invoke the function, so requests are refused (403). Adding such a permission would make it "
                    "public.", evidence=_url_evidence(q, url, policy="no-public-grant"), discriminator=q or "",
        region=fn.region)


def _url_unknown(builder: Any, fn: Function, q: Optional[str], url: Mapping[str, Any]) -> None:
    builder.add_finding(
        "LAMBDA-URL-001", fn.node_id, severity="MEDIUM", base_severity="HIGH", confidence="conditional",
        title=f"Lambda '{fn.name}' has a function URL{_where(q)} with AuthType NONE (exposure unknown)",
        description="The URL needs no authentication and the function policy of that qualifier could not be read, "
                    "so whether unauthenticated callers may invoke it is unknown (not 'private').",
        evidence=_url_evidence(q, url, policy="unknown"), gaps=[f"{GET_POLICY}:unknown"], discriminator=q or "",
        matched_actions=["lambda:InvokeFunctionUrl"], region=fn.region)


# ── layers and event source mappings (F-116) ─────────────────────────────────

def _layer_versions(ctx: Any) -> List[Tuple[str, Mapping[str, Any], Mapping[str, Any]]]:
    """``(region, layer record, version record)`` of every collected layer version."""
    out = []
    for unit, layer in unit_records((ctx.data or {}).get("lambda"), "layers"):
        for version in layer.get("Versions") or ():
            if isinstance(version, Mapping) and isinstance(version.get("LayerVersionArn"), str):
                out.append((unit, layer, version))
    return out


def layer_edges(ctx: Any, builder: Any) -> int:
    """Layer version nodes and their policy grants (F-116): ``LAYER_GRANTS_PUBLIC`` + ``LAMBDA-LAYER-PUB-001`` for a
    public layer version, ``LAYER_GRANTS_CROSS_ACCOUNT`` + ``LAMBDA-LAYER-XACCT-001`` for one shared with other
    accounts. Returns the number of public layer versions."""
    evaluator = evaluator_of(ctx)
    count = 0
    for unit, layer, version in _layer_versions(ctx):
        arn = str(version["LayerVersionArn"])
        if not ids.node_id_matches("lambdalayer", arn):
            continue
        status, gaps = item_coverage(version, legacy=is_legacy(ctx), policy_api="lambda:GetLayerVersionPolicy")
        name = f"{layer.get('LayerName') or arn.split(':')[6]}:{version.get('Version')}"
        builder.add_node(arn, "lambdalayer", name, region=unit, coverage_status=status, coverage_gaps=gaps,
                         props={"layer_name": layer.get("LayerName"), "version": version.get("Version")})
        state = register_policy(evaluator, arn, version.get("Policy"), version.get("PolicyStatus"),
                                owner=ctx.account_id)
        if state != "present":
            continue
        grants = strongest(policy_grant_edges(ctx, builder, version["Policy"], arn))
        count += _public_layer(builder, grants.get(("public", ids.ANONYMOUS_ID)), arn, name, unit)
        _shared_layer(builder, [g for (kind, _n), g in sorted(grants.items()) if kind == "cross-account"], arn, name,
                      unit)
    return count


def _public_layer(builder: Any, best: Optional[GrantEdge], arn: str, name: str, unit: str) -> int:
    graded = exposure_severity(best.grant, high="MEDIUM", medium="LOW") if best else None
    if best is None or graded is None:
        return 0
    builder.add_edge(ids.ANONYMOUS_ID, "LAYER_GRANTS_PUBLIC", arn, result=grant_result(best.grant),
                     evidence={"actions": sorted(best.grant.actions), "technique": "layer-version-policy"})
    builder.add_finding(
        "LAMBDA-LAYER-PUB-001", arn, severity=graded[0], base_severity="MEDIUM", confidence=graded[1],
        title=f"Lambda layer version '{name}' is public",
        description="The layer version policy lets any AWS account read the layer (lambda:GetLayerVersion): "
                    "its code and any configuration or credentials packaged in it are exposed.",
        evidence={"actions": sorted(best.grant.actions), "decision": best.grant.decision.value},
        matched_actions=sorted(best.grant.actions), region=unit, related_node_ids=[ids.ANONYMOUS_ID])
    return 1


def _shared_layer(builder: Any, shares: List[GrantEdge], arn: str, name: str, unit: str) -> None:
    """``external -LAYER_GRANTS_CROSS_ACCOUNT-> layer version`` per foreign grantee, one finding per account."""
    for ge in shares:
        # a named foreign account is a grant even behind a strong gate (the gate is about who in that account):
        # LOW, conditional unless the policy allows it outright
        confidence = "definite" if ge.grant.decision is Decision.ALLOW else "conditional"
        builder.add_edge(ge.node_id, "LAYER_GRANTS_CROSS_ACCOUNT", arn, result=grant_result(ge.grant),
                         evidence={"actions": sorted(ge.grant.actions), "technique": "layer-version-policy"},
                         props={"cross_account": True})
        account = ge.grant.principal.account or ""
        builder.add_finding(
            "LAMBDA-LAYER-XACCT-001", arn, severity="LOW", confidence=confidence, discriminator=account,
            title=f"Lambda layer version '{name}' is shared with account {account}",
            description=f"The layer version policy lets principals of account {account} read the layer "
                        "(lambda:GetLayerVersion): its code and anything packaged in it.",
            evidence={"actions": sorted(ge.grant.actions), "account": account,
                      "decision": ge.grant.decision.value},
            matched_actions=sorted(ge.grant.actions), region=unit, related_node_ids=[ge.node_id])


def _event_source_node(ctx: Any, builder: Any, arn: str) -> Optional[str]:
    """The SQS queue / DynamoDB table node of an event source ARN (a stream maps to its table)."""
    p = ids.parse_arn(arn)
    if p is None:
        return None
    if p.service == "sqs" and ids.node_id_matches("sqs", arn):
        node_id, ntype, label = arn, "sqs", p.resource
    elif p.service == "dynamodb" and p.resource.startswith("table/"):
        table = p.resource.split("/")[1]
        node_id, ntype, label = f"arn:{p.partition}:dynamodb:{p.region}:{p.account}:table/{table}", "dynamodb", table
        if not ids.node_id_matches("dynamodb", node_id):
            return None
    else:
        return None
    if not builder.has_node(node_id):
        builder.add_node(node_id, ntype, label, region=p.region, props={"placeholder": True})
    return node_id


def trigger_edges(ctx: Any, builder: Any, functions: Mapping[str, Function]) -> int:
    """``TRIGGERS`` event source → function for SQS and DynamoDB mappings; other sources stay as props."""
    count = 0
    unmapped: Dict[str, List[str]] = {}
    for _unit, esm in unit_records((ctx.data or {}).get("lambda"), "event_source_mappings"):
        source, target = esm.get("EventSourceArn"), esm.get("FunctionArn")
        try:
            fn_id, qualifier = ids.lambda_unqualified(str(target))
        except ValueError:
            continue
        if fn_id not in functions or not isinstance(source, str):
            continue
        src = _event_source_node(ctx, builder, source)
        if src is None:
            unmapped.setdefault(fn_id, []).append(source)
            continue
        evidence = {"technique": "event-source-mapping", "state": esm.get("State")}
        if qualifier:
            evidence["qualifiers"] = [qualifier]
        builder.add_edge(src, "TRIGGERS", fn_id, evidence={k: v for k, v in evidence.items() if v is not None})
        count += 1
    for fn_id, sources in sorted(unmapped.items()):
        builder.set_node_props(fn_id, event_sources_other=sorted(set(sources)))
    return count


# ── the analyzer ─────────────────────────────────────────────────────────────

def analyze_lambda(ctx: Any, builder: Any) -> None:
    """Analyzer ``lambda`` (phase RESOURCES): nodes, role bridges, grants, access edges, findings."""
    if (ctx.data or {}).get("lambda") is None:
        raise AnalyzerSkipped("lambda", reason="no Lambda data was loaded")
    functions = load_functions(ctx)
    for fn in functions.values():
        register_policies(ctx, fn)
    add_function_nodes(ctx, builder, functions)
    forced: Set[str] = set()
    for fn in functions.values():
        forced |= grant_edges(ctx, builder, fn)
        url_findings(ctx, builder, fn)
        deputy_findings(ctx, builder, fn)
    pairs = access_edges(ctx, builder, functions, forced)
    layers = layer_edges(ctx, builder)
    triggers = trigger_edges(ctx, builder, functions)
    log.debug("lambda: %d functions, %d principal/function pairs with edges, %d public layers, %d triggers",
              len(functions), pairs, layers, triggers)


def _run(ctx: Any, builder: Any) -> None:
    analyze_lambda(ctx, builder)       # looked up at call time (tests may patch the module attribute)


def _findings() -> Tuple[Any, ...]:
    from aws_enumerator.engine.findings.catalog import A_EXPOSURE, CatalogEntry

    return (
        CatalogEntry("LAMBDA-URL-001", "HIGH", "lambda_public", "Function URL without authentication",
                     "Set the function URL AuthType to AWS_IAM, or remove the public InvokeFunctionUrl permission "
                     "and the URL if it is not needed.", A_EXPOSURE, discriminator="qualifier"),
        CatalogEntry("LAMBDA-URL-002", "INFO", "lambda_public",
                     "Function URL without authentication, not publicly authorised",
                     "Set AuthType to AWS_IAM so that adding a public permission later cannot expose the function.",
                     A_EXPOSURE, discriminator="qualifier"),
        CatalogEntry("LAMBDA-PUB-001", "HIGH", "lambda_public", "Function policy grants everyone",
                     "Scope the Principal, or add a SourceArn/SourceAccount Condition.", A_EXPOSURE),
        CatalogEntry("LAMBDA-XACCT-001", "MEDIUM", "lambda_cross_account", "Function policy grants another account",
                     "Verify cross-account invoke access is intended.", A_EXPOSURE, discriminator="target-account"),
        CatalogEntry("LAMBDA-LAYER-PUB-001", "MEDIUM", "lambda_public", "Lambda layer version is public",
                     "Remove the public statement from the layer version policy (RemoveLayerVersionPermission) "
                     "or restrict it to an organisation (aws:PrincipalOrgID).", A_EXPOSURE),
        CatalogEntry("LAMBDA-LAYER-XACCT-001", "LOW", "lambda_cross_account",
                     "Lambda layer version is shared with another account",
                     "Verify the layer is meant to be shared with that account; remove the statement "
                     "(RemoveLayerVersionPermission) otherwise.", A_EXPOSURE, discriminator="target-account"),
    )


#: Finding ids this module emits (findings/catalog.py merges them, DECISIONS.md D-33).
FINDINGS: Tuple[Any, ...] = _findings()

ANALYZERS: Tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec("lambda", Phase.RESOURCES, _run, inputs=("lambda",), legacy_files=("lambda_relationships.json",)),
)
