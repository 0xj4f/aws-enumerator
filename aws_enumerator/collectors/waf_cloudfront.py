"""AWS WAFv2, CLOUDFRONT scope (global unit; split from ``waf.py``).

The wafv2 client comes from ``ctx.client("wafv2")``: the run's single credential set, in the
partition's global region (us-east-1 in ``aws``). The old module rebuilt a session from
``profile_name`` here, which failed with environment credentials or silently switched identity (F-060).

Associations use ``cloudfront:ListDistributionsByWebACLId(WebACLId=<web ACL ARN>)``:
``ListResourcesForWebACL`` does not accept ``CLOUDFRONT`` as a resource type (F-118).

Output (``global/waf_cloudfront/``): the same four files as the ``waf`` module (see
:mod:`aws_enumerator.collectors.waf`), with ``Scope: "CLOUDFRONT"`` and associations
``[{ResourceType: "CLOUDFRONT", Arn: <distribution ARN>}]``:

``web_acls.json``, ``rule_groups.json``, ``ip_sets.json``, ``logging_configs.json`` (lists) and
``_coverage.json``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_enumerator.collectors.base import CollectContext
from aws_enumerator.collectors.waf import WAF_ACTIONS, WAF_OUTPUTS, collect_scope
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="waf_cloudfront", scope="global", output_dir="waf_cloudfront", services=("cloudfront", "wafv2"),
    tier=1, cost="low", noise="low", default=True, groups=("@edge",),
    actions=WAF_ACTIONS + ("cloudfront:ListDistributionsByWebACLId",),
    probe=("wafv2", "ListWebACLs", (("Scope", "CLOUDFRONT"), ("Limit", 1))),
    outputs=WAF_OUTPUTS,
    description="WAFv2 web ACLs, rule groups, IP sets and logging in CLOUDFRONT scope, with the distributions "
                "each web ACL protects",
)

_MAX_PAGES = 1000


def collect(ctx: CollectContext) -> None:
    """CLOUDFRONT-scope WAF, with the run's credentials in the global region."""
    collect_scope(ctx, "CLOUDFRONT", CloudFrontAssociations(ctx.client("cloudfront")))


class CloudFrontAssociations:
    """Distributions protected by a web ACL (``ListDistributionsByWebACLId``, ``Marker`` loop)."""

    def __init__(self, client: Any):
        self.client = client

    def __call__(self, ctx: CollectContext, acl_arn: str):
        resources: List[Dict[str, Any]] = []
        marker: Optional[str] = None
        for _ in range(_MAX_PAGES):
            params = {"WebACLId": acl_arn, "MaxItems": "100"}
            if marker:
                params["Marker"] = marker
            result = ctx.call(self.client, "list_distributions_by_web_acl_id", item=acl_arn, **params)
            if not result.ok:
                error = result.collection_error()
                return None, ["CLOUDFRONT"], ([error] if error else [])
            page = result.get("DistributionList") or {}
            resources.extend({"ResourceType": "CLOUDFRONT", "Arn": d["ARN"]}
                             for d in page.get("Items") or [] if isinstance(d, dict) and d.get("ARN"))
            next_marker = page.get("NextMarker")
            if not page.get("IsTruncated") or not next_marker or next_marker == marker:
                break
            marker = next_marker
        return sorted(resources, key=lambda r: r["Arn"]), [], []
