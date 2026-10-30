"""AWS WAFv2, REGIONAL scope (regional). The CLOUDFRONT scope is the ``waf_cloudfront`` module, which
reuses :func:`collect_scope` from here with the run's own credentials (F-060).

Every list call follows ``NextMarker`` (wafv2 has no botocore paginators; F-107) and every per-item call
is isolated. Web ACL associations are looked up for **every** REGIONAL resource type, each type isolated
(F-118): ``APPLICATION_LOAD_BALANCER`` needs only ``wafv2:ListResourcesForWebACL``; the other types also
need the resource service's permission (``apigateway:GET``, ``cognito-idp:ListResourcesForWebACL``,
``appsync:ListResourcesForWebACL``, ``apprunner:ListAssociatedServicesForWebAcl``,
``ec2:GetVerifiedAccessInstanceWebAcl``; AMPLIFY: see the AWS WAF permission reference), so their
failures are expected: they are
recorded as optional calls, the type is not asked again for the remaining ACLs, and the ACL lists it in
``UncheckedResourceTypes``.

Output (``<region>/waf/``; ``global/waf_cloudfront/`` has the same files):

``web_acls.json``
    list, sorted by ``ARN``::

        {Id, Name, ARN, Scope, Description, DefaultAction, Rules, VisibilityConfig, Capacity,
         ManagedByFirewallManager, LabelNamespace, AssociatedResources: [{ResourceType, Arn}] | null,
         UncheckedResourceTypes: [str], CollectionErrors?}

    ``Rules`` ... ``LabelNamespace`` are ``null`` when ``GetWebACL`` failed. ``AssociatedResources`` is
    ``null`` when no association lookup succeeded; otherwise it lists what the successful lookups found
    and ``UncheckedResourceTypes`` names the types whose lookup failed or was skipped.

``rule_groups.json``
    list, sorted by ``ARN``: ``{Id, Name, ARN, Scope, Description, Capacity, Rules, VisibilityConfig,
    LabelNamespace, CollectionErrors?}`` (detail fields ``null`` when ``GetRuleGroup`` failed).

``ip_sets.json``
    list, sorted by ``ARN``: ``{Id, Name, ARN, Scope, Description, IPAddressVersion, Addresses,
    CollectionErrors?}``.

``logging_configs.json``
    list, sorted by ``ResourceArn``: each ``LoggingConfiguration`` as AWS returns it.

``_coverage.json``
    every call (docs/contracts/coverage-schema.md).
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

from aws_enumerator.collectors._common import add_error
from aws_enumerator.collectors.base import CollectContext
from aws_enumerator.registry import CollectorSpec

WAF_ACTIONS: Tuple[str, ...] = (
    "wafv2:ListWebACLs", "wafv2:GetWebACL", "wafv2:ListResourcesForWebACL", "wafv2:ListRuleGroups",
    "wafv2:GetRuleGroup", "wafv2:ListIPSets", "wafv2:GetIPSet", "wafv2:ListLoggingConfigurations",
)
WAF_OUTPUTS: Tuple[Tuple[str, str], ...] = (
    ("web_acls.json", "list"), ("rule_groups.json", "list"), ("ip_sets.json", "list"),
    ("logging_configs.json", "list"),
)

SPEC = CollectorSpec(
    name="waf", scope="regional", output_dir="waf", services=("wafv2",),
    tier=1, cost="low", noise="low", default=True, groups=("@edge",),
    actions=WAF_ACTIONS,
    optional_actions=("apigateway:GET", "cognito-idp:ListResourcesForWebACL", "appsync:ListResourcesForWebACL",
                      "apprunner:ListAssociatedServicesForWebAcl", "ec2:GetVerifiedAccessInstanceWebAcl"),
    probe=("wafv2", "ListWebACLs", (("Scope", "REGIONAL"), ("Limit", 1))),
    outputs=WAF_OUTPUTS,
    description="WAFv2 web ACLs (with associations of every resource type), rule groups, IP sets, logging; "
                "REGIONAL scope",
)

#: Every ``ResourceType`` ListResourcesForWebACL accepts (botocore enum). CLOUDFRONT is not one of them.
REGIONAL_RESOURCE_TYPES: Tuple[str, ...] = (
    "APPLICATION_LOAD_BALANCER", "API_GATEWAY", "APPSYNC", "COGNITO_USER_POOL", "APP_RUNNER_SERVICE",
    "VERIFIED_ACCESS_INSTANCE", "AMPLIFY",
)
#: The type that needs nothing beyond wafv2:ListResourcesForWebACL; its failures degrade the module.
_BASE_RESOURCE_TYPE = "APPLICATION_LOAD_BALANCER"
_PAGE = 100

#: ``associations(ctx, acl_arn) -> (resources | None, unchecked types, collection errors)``
Associations = Callable[[CollectContext, str], Tuple[Optional[List[Dict[str, Any]]], List[str], List[Dict]]]

_ACL_DETAIL_KEYS = ("DefaultAction", "Rules", "VisibilityConfig", "Capacity", "ManagedByFirewallManager",
                    "LabelNamespace")
_RULE_GROUP_DETAIL_KEYS = ("Capacity", "Rules", "VisibilityConfig", "LabelNamespace")
_IP_SET_DETAIL_KEYS = ("IPAddressVersion", "Addresses")


def collect(ctx: CollectContext) -> None:
    """REGIONAL-scope WAF in this region."""
    collect_scope(ctx, "REGIONAL", RegionalAssociations(ctx.client("wafv2")))


def collect_scope(ctx: CollectContext, scope: str, associations: Associations) -> None:
    """Collect one WAF scope into ``ctx.out`` (web ACLs, rule groups, IP sets, logging configurations).

    The wafv2 client is ``ctx.client("wafv2")``: the run's single credential set, in the unit's client
    region (the partition's global region for the CLOUDFRONT scope).
    """
    client = ctx.client("wafv2")
    acls: List[Dict[str, Any]] = []
    with ctx.section("web_acls"):
        acls = _web_acls(ctx, client, scope, associations)
    ctx.out.write("web_acls.json", acls)

    groups: List[Dict[str, Any]] = []
    with ctx.section("rule_groups"):
        groups = _detailed(ctx, client, scope, ("list_rule_groups", "RuleGroups"), ("get_rule_group", "RuleGroup"),
                           _RULE_GROUP_DETAIL_KEYS)
    ctx.out.write("rule_groups.json", groups)

    ip_sets: List[Dict[str, Any]] = []
    with ctx.section("ip_sets"):
        ip_sets = _detailed(ctx, client, scope, ("list_ip_sets", "IPSets"), ("get_ip_set", "IPSet"),
                            _IP_SET_DETAIL_KEYS)
    ctx.out.write("ip_sets.json", ip_sets)

    logging_configs: List[Dict[str, Any]] = []
    with ctx.section("logging_configs"):
        result = ctx.paginate(client, "list_logging_configurations", "LoggingConfigurations", page_size=_PAGE,
                              Scope=scope)
        logging_configs = sorted((dict(c) for c in result.value if isinstance(c, dict)),
                                 key=lambda c: str(c.get("ResourceArn")))
    ctx.out.write("logging_configs.json", logging_configs)


def _summaries(ctx: CollectContext, client: Any, op: str, key: str, scope: str, *, primary: bool = False):
    listed = ctx.paginate(client, op, key, page_size=_PAGE, primary=primary, Scope=scope)
    return sorted((s for s in listed.value if isinstance(s, dict) and s.get("ARN")), key=lambda s: str(s["ARN"]))


def _base_record(summary: Dict[str, Any], scope: str) -> Dict[str, Any]:
    return {"Id": summary.get("Id"), "Name": summary.get("Name"), "ARN": summary.get("ARN"), "Scope": scope,
            "Description": summary.get("Description")}


def _web_acls(ctx: CollectContext, client: Any, scope: str, associations: Associations) -> List[Dict[str, Any]]:
    out = []
    for summary in _summaries(ctx, client, "list_web_acls", "WebACLs", scope, primary=True):
        record = _base_record(summary, scope)
        record.update({key: None for key in _ACL_DETAIL_KEYS})
        detail = ctx.call(client, "get_web_acl", item=summary["ARN"], Name=summary.get("Name"),
                          Scope=scope, Id=summary.get("Id"))
        if detail.has_data:
            acl = detail.get("WebACL") or {}
            record["Description"] = acl.get("Description", record["Description"])
            record.update({key: acl.get(key) for key in _ACL_DETAIL_KEYS})
        add_error(record, detail)
        resources, unchecked, errors = associations(ctx, summary["ARN"])
        record["AssociatedResources"] = resources
        record["UncheckedResourceTypes"] = unchecked
        for error in errors:
            if error not in record.get("CollectionErrors", []):
                record.setdefault("CollectionErrors", []).append(error)
        out.append(record)
    return out


def _detailed(ctx: CollectContext, client: Any, scope: str, listing: Tuple[str, str], getter: Tuple[str, str],
              detail_keys: Tuple[str, ...]) -> List[Dict[str, Any]]:
    out = []
    for summary in _summaries(ctx, client, listing[0], listing[1], scope):
        record = _base_record(summary, scope)
        record.update({key: None for key in detail_keys})
        detail = ctx.call(client, getter[0], item=summary["ARN"], Name=summary.get("Name"), Scope=scope,
                          Id=summary.get("Id"))
        if detail.has_data:
            item = detail.get(getter[1]) or {}
            record["Description"] = item.get("Description", record["Description"])
            record.update({key: item.get(key) for key in detail_keys})
            if isinstance(record.get("Addresses"), list):
                record["Addresses"] = sorted(record["Addresses"])
        add_error(record, detail)
        out.append(record)
    return out


class RegionalAssociations:
    """ListResourcesForWebACL for every REGIONAL resource type, one type isolated from another.

    ``APPLICATION_LOAD_BALANCER`` lookups are ordinary fan-out calls (``item=``, deny breaker). The
    other types need extra service permissions, so their calls are ``optional`` and made without
    ``item`` (an expected denial of one type must not open the API's deny breaker for the others);
    after a type fails once it is skipped for the remaining ACLs (recorded as a deliberate skip).
    """

    def __init__(self, client: Any, resource_types: Tuple[str, ...] = REGIONAL_RESOURCE_TYPES):
        self.client = client
        self.resource_types = resource_types
        self.failed: Dict[str, str] = {}

    def __call__(self, ctx: CollectContext, acl_arn: str):
        resources: List[Dict[str, Any]] = []
        unchecked: List[str] = []
        errors: List[Dict[str, Any]] = []
        succeeded = False
        for rtype in self.resource_types:
            if rtype in self.failed:
                ctx.cov.skip("wafv2:ListResourcesForWebACL", f"Skipped:{rtype} lookups failed ({self.failed[rtype]})")
                unchecked.append(rtype)
                continue
            base = rtype == _BASE_RESOURCE_TYPE
            result = ctx.call(self.client, "list_resources_for_web_acl", item=acl_arn if base else None,
                              optional=not base, WebACLArn=acl_arn, ResourceType=rtype)
            if result.ok:
                succeeded = True
                resources.extend({"ResourceType": rtype, "Arn": arn}
                                 for arn in result.get("ResourceArns") or [] if isinstance(arn, str))
                continue
            unchecked.append(rtype)
            if base:
                error = result.collection_error()
                if error is not None:
                    errors.append(error)
            elif result.status != "skipped":
                self.failed[rtype] = result.error_code or result.status
        resources.sort(key=lambda r: (r["ResourceType"], r["Arn"]))
        return (resources if succeeded else None), unchecked, errors
