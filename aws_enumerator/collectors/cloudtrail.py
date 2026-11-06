"""CloudTrail trails, their logging status and event selectors, and CloudTrail Lake event data stores
(regional).

``DescribeTrails`` is called with its default ``includeShadowTrails=True`` (F-045, F-167): multi-region
trails homed in another region and organization trails of the management account are listed too, and
marked ``IsShadow`` (homed in another region, or owned by another account: ``OwnerAccountId``, the
account in the trail ARN). For each trail homed in **this** region, every detail call uses the trail ARN
and is isolated per call (F-047): ``GetTrailStatus(Name=<ARN>)``, ``GetEventSelectors(TrailName=<ARN>)``
and, only when the trail has insight selectors, ``GetInsightSelectors(TrailName=<ARN>)``
(``InsightNotEnabledException`` = not configured). For another account's organization trail these calls
are ``optional`` (a member account may be refused them; the refusal is still recorded per trail).
Trails homed in another region are detailed in their home region, so their detail fields stay ``null``
here and no call is made for them (F-167).

Output (``<region>/cloudtrail/``):

``trails.json``
    list, sorted by ``TrailARN``::

        {Name, TrailARN, HomeRegion, IsShadow, IsMultiRegionTrail, IsOrganizationTrail,
         IncludeGlobalServiceEvents, S3BucketName, S3KeyPrefix, SnsTopicARN, KmsKeyId,
         LogFileValidationEnabled, CloudWatchLogsLogGroupArn, CloudWatchLogsRoleArn,
         HasCustomEventSelectors, HasInsightSelectors, OwnerAccountId,
         Status: {IsLogging, LatestDeliveryTime, StartLoggingTime, StopLoggingTime, ...} | null,
         EventSelectors: [...] | null, AdvancedEventSelectors: [...] | null, InsightSelectors: [...] | null,
         CollectionErrors?}

    ``null`` = not read (shadow trail, or the call failed; ``CollectionErrors`` then says which).
    ``[]`` = read and empty.

``event_data_stores.json``
    list, sorted by ``EventDataStoreArn``: each ``ListEventDataStores`` record.

``_coverage.json``
    every call (docs/contracts/coverage-schema.md).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_enumerator.collectors._common import add_error
from aws_enumerator.collectors.base import CollectContext
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="cloudtrail", scope="regional", output_dir="cloudtrail", services=("cloudtrail",),
    tier=1, cost="low", noise="low", default=True, groups=("@posture",),
    actions=("cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:GetEventSelectors",
             "cloudtrail:GetInsightSelectors", "cloudtrail:ListEventDataStores"),
    probe=("cloudtrail", "DescribeTrails", ()),
    outputs=(("trails.json", "list"), ("event_data_stores.json", "list")),
    description="CloudTrail trails (shadow trails included), logging status, event and insight selectors, "
                "event data stores",
)

_TRAIL_KEYS = ("Name", "TrailARN", "HomeRegion", "IsMultiRegionTrail", "IsOrganizationTrail",
               "IncludeGlobalServiceEvents", "S3BucketName", "S3KeyPrefix", "SnsTopicARN", "KmsKeyId",
               "LogFileValidationEnabled", "CloudWatchLogsLogGroupArn", "CloudWatchLogsRoleArn",
               "HasCustomEventSelectors", "HasInsightSelectors")


def collect(ctx: CollectContext) -> None:
    """Trails (with per-call isolated details), then event data stores."""
    client = ctx.client("cloudtrail")
    trails: List[Dict[str, Any]] = []
    with ctx.section("trails"):
        listed = ctx.call(client, "describe_trails", primary=True)
        raw = [t for t in listed.get("trailList") or [] if isinstance(t, dict)]
        for trail in sorted(raw, key=lambda t: str(t.get("TrailARN") or t.get("Name"))):
            trails.append(_trail(ctx, client, trail))
    ctx.out.write("trails.json", trails)

    stores: List[Dict[str, Any]] = []
    with ctx.section("event_data_stores"):
        result = ctx.paginate(client, "list_event_data_stores", "EventDataStores", page_size=1000)
        stores = sorted((dict(s) for s in result.value if isinstance(s, dict)),
                        key=lambda s: str(s.get("EventDataStoreArn")))
    ctx.out.write("event_data_stores.json", stores)


def _arn_account(arn: Any) -> Optional[str]:
    """The account field of an ARN (``arn:<p>:cloudtrail:<region>:<account>:trail/<name>``)."""
    parts = arn.split(":", 5) if isinstance(arn, str) else []
    if len(parts) != 6 or not parts[4]:
        return None
    return parts[4]


def _trail(ctx: CollectContext, client: Any, trail: Dict[str, Any]) -> Dict[str, Any]:
    record: Dict[str, Any] = {key: trail.get(key) for key in _TRAIL_KEYS}
    arn = trail.get("TrailARN")
    home_elsewhere = bool(trail.get("HomeRegion")) and trail.get("HomeRegion") != ctx.region
    owner = _arn_account(arn)
    foreign = owner is not None and owner != ctx.account_id  # an organization trail seen from a member
    record["IsShadow"] = home_elsewhere or foreign
    record["OwnerAccountId"] = owner
    record.update(Status=None, EventSelectors=None, AdvancedEventSelectors=None, InsightSelectors=None)
    if home_elsewhere or not arn:
        return record  # detailed once, in its home region (F-167)
    # Every detail call names the trail by ARN (required for organization trails) and is isolated (F-047).
    # A member account may be refused the management account's trail details: expected, so optional.
    status = ctx.call(client, "get_trail_status", item=arn, optional=foreign, Name=arn)
    if status.has_data:
        record["Status"] = dict(status.value)
    add_error(record, status)

    selectors = ctx.call(client, "get_event_selectors", item=arn, optional=foreign, TrailName=arn)
    if selectors.ok:
        record["EventSelectors"] = list(selectors.get("EventSelectors") or [])
        record["AdvancedEventSelectors"] = list(selectors.get("AdvancedEventSelectors") or [])
    add_error(record, selectors)

    if not trail.get("HasInsightSelectors"):
        record["InsightSelectors"] = []
    else:
        insights = ctx.call(client, "get_insight_selectors", item=arn, optional=foreign, TrailName=arn)
        if insights.ok:  # InsightNotEnabledException is "not configured": []
            record["InsightSelectors"] = list(insights.get("InsightSelectors") or [])
        add_error(record, insights)
    return record
