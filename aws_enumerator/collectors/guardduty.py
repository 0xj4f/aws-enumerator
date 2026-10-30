"""Amazon GuardDuty detectors and their protection plans (regional; F-046). Findings are never read.

Output (``<region>/guardduty/``):

``detectors.json``
    list, sorted by ``DetectorId``; ``[]`` when GuardDuty is not enabled in the region::

        {DetectorId, Arn, Status, ServiceRole, FindingPublishingFrequency, CreatedAt, UpdatedAt,
         Features: [{Name, Status, AdditionalConfiguration: [{Name, Status}]}] | null,
         DataSources: {...} | null, CollectionErrors?}

    A detector whose ``GetDetector`` call fails keeps ``DetectorId`` / ``Arn``; every other field is
    ``null`` (unknown) and ``CollectionErrors`` says why.

``_coverage.json``
    every call (docs/contracts/coverage-schema.md).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_enumerator.collectors.base import CollectContext
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="guardduty", scope="regional", output_dir="guardduty", services=("guardduty",),
    tier=1, cost="low", noise="low", default=True, groups=("@posture",),
    actions=("guardduty:ListDetectors", "guardduty:GetDetector"),
    probe=("guardduty", "ListDetectors", (("MaxResults", 1),)),
    outputs=(("detectors.json", "list"),),
    description="GuardDuty detectors, status and protection plans (never findings)",
)

_DETAIL_KEYS = ("Status", "ServiceRole", "FindingPublishingFrequency", "CreatedAt", "UpdatedAt")


def collect(ctx: CollectContext) -> None:
    """List the region's detectors and describe each one."""
    client = ctx.client("guardduty")
    detectors: List[Dict[str, Any]] = []
    with ctx.section("detectors"):
        listed = ctx.paginate(client, "list_detectors", "DetectorIds", page_size=50, primary=True)
        for detector_id in sorted({d for d in listed.value if isinstance(d, str)}):
            detectors.append(_detector(ctx, client, detector_id))
    ctx.out.write("detectors.json", detectors)


def _detector(ctx: CollectContext, client: Any, detector_id: str) -> Dict[str, Any]:
    arn = ctx.arn("guardduty", f"detector/{detector_id}")
    record: Dict[str, Any] = {"DetectorId": detector_id, "Arn": arn}
    record.update({key: None for key in _DETAIL_KEYS})
    record.update(Features=None, DataSources=None)
    result = ctx.call(client, "get_detector", item=arn, DetectorId=detector_id)
    if result.has_data:
        for key in _DETAIL_KEYS:
            record[key] = result.get(key)
        record["Features"] = _features(result.get("Features"))
        record["DataSources"] = result.get("DataSources")
    error = result.collection_error()
    if error is not None:
        record["CollectionErrors"] = [error]
    return record


def _features(features: Any) -> Optional[List[Dict[str, Any]]]:
    if not isinstance(features, list):
        return None
    out = []
    for feature in features:
        if not isinstance(feature, dict):
            continue
        extra = [{"Name": c.get("Name"), "Status": c.get("Status")}
                 for c in feature.get("AdditionalConfiguration") or [] if isinstance(c, dict)]
        out.append({"Name": feature.get("Name"), "Status": feature.get("Status"),
                    "AdditionalConfiguration": sorted(extra, key=lambda c: str(c["Name"]))})
    return sorted(out, key=lambda f: str(f["Name"]))
