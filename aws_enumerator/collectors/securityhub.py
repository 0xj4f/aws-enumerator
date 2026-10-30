"""AWS Security Hub enablement and enabled standards (regional; F-046). Findings are never read.

Output (``<region>/securityhub/``):

``hub.json``
    object::

        {Enabled: bool | null, HubArn, SubscribedAt, AutoEnableControls, ControlFindingGenerator,
         Standards: [{StandardsArn, StandardsSubscriptionArn, StandardsStatus, StandardsStatusReason}] | null}

    ``Enabled`` is ``false`` when ``DescribeHub`` answers ``InvalidAccessException`` (the account is not
    subscribed: "not configured", coverage-schema.md §2.1) and ``null`` when the call was denied or failed.
    ``Standards`` is ``[]`` for a disabled hub and ``null`` when it could not be read completely.

``_coverage.json``
    every call (docs/contracts/coverage-schema.md).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_enumerator.collectors.base import CollectContext
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="securityhub", scope="regional", output_dir="securityhub", services=("securityhub",),
    tier=1, cost="low", noise="low", default=True, groups=("@posture",),
    actions=("securityhub:DescribeHub", "securityhub:GetEnabledStandards"),
    probe=("securityhub", "DescribeHub", ()),
    outputs=(("hub.json", "dict"),),
    description="Security Hub enablement and enabled standards (never findings)",
)

_HUB_KEYS = ("HubArn", "SubscribedAt", "AutoEnableControls", "ControlFindingGenerator")


def collect(ctx: CollectContext) -> None:
    """Describe the hub, then its enabled standards when it is enabled."""
    client = ctx.client("securityhub")
    hub: Dict[str, Any] = {"Enabled": None}
    hub.update({key: None for key in _HUB_KEYS})
    hub["Standards"] = None
    with ctx.section("hub"):
        result = ctx.call(client, "describe_hub", primary=True)
        if result.has_data:
            hub["Enabled"] = True
            for key in _HUB_KEYS:
                hub[key] = result.get(key)
        elif result.ok:  # InvalidAccessException: not subscribed
            hub["Enabled"] = False
            hub["Standards"] = []
    if hub["Enabled"]:
        with ctx.section("standards"):
            hub["Standards"] = _standards(ctx, client)
    ctx.out.write("hub.json", hub)


def _standards(ctx: CollectContext, client: Any) -> Optional[List[Dict[str, Any]]]:
    result = ctx.paginate(client, "get_enabled_standards", "StandardsSubscriptions", page_size=100)
    if not result.ok:
        return None
    if result.not_configured:
        return []
    out = [{"StandardsArn": s.get("StandardsArn"), "StandardsSubscriptionArn": s.get("StandardsSubscriptionArn"),
            "StandardsStatus": s.get("StandardsStatus"), "StandardsStatusReason": s.get("StandardsStatusReason")}
           for s in result.value if isinstance(s, dict)]
    return sorted(out, key=lambda s: (str(s["StandardsArn"]), str(s["StandardsSubscriptionArn"])))
