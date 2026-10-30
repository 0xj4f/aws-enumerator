"""AWS Config recorders, their recording status and delivery channels (regional; F-046).

Registry name ``config`` (this file is ``config_service.py``; ``--modules config_service`` is an alias).
Configuration items and compliance results are never read.

Output (``<region>/config/``):

``recorders.json``
    list, sorted by ``name``: each ``ConfigurationRecorder`` as AWS returns it (``name``, ``roleARN``,
    ``recordingGroup``, ``recordingMode`` ...) plus ``status``::

        status: {recording, lastStatus, lastStartTime, lastStopTime, lastStatusChangeTime, lastErrorCode,
                 lastErrorMessage} | null

    ``status`` is ``null`` when ``DescribeConfigurationRecorderStatus`` failed or has no entry for the
    recorder. ``[]`` when Config is not set up in the region.

``delivery_channels.json``
    list, sorted by ``name``: each ``DeliveryChannel`` as AWS returns it (``s3BucketName``,
    ``s3KeyPrefix``, ``s3KmsKeyArn``, ``snsTopicARN``, ``configSnapshotDeliveryProperties``).

``_coverage.json``
    every call (docs/contracts/coverage-schema.md).
"""

from __future__ import annotations

from typing import Any, Dict, List

from aws_enumerator.collectors.base import CollectContext
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="config", scope="regional", output_dir="config", services=("config",),
    tier=1, cost="low", noise="low", default=True, groups=("@posture",),
    actions=("config:DescribeConfigurationRecorders", "config:DescribeConfigurationRecorderStatus",
             "config:DescribeDeliveryChannels"),
    probe=("config", "DescribeConfigurationRecorders", ()),
    outputs=(("recorders.json", "list"), ("delivery_channels.json", "list")),
    description="AWS Config recorders, recording status and delivery channels",
)

_STATUS_KEYS = ("recording", "lastStatus", "lastStartTime", "lastStopTime", "lastStatusChangeTime",
                "lastErrorCode", "lastErrorMessage")


def collect(ctx: CollectContext) -> None:
    """Recorders (with their status) and delivery channels."""
    client = ctx.client("config")
    recorders: List[Dict[str, Any]] = []
    with ctx.section("recorders"):
        listed = ctx.call(client, "describe_configuration_recorders", primary=True)
        recorders = [dict(r) for r in listed.get("ConfigurationRecorders") or [] if isinstance(r, dict)]
        if recorders:  # no recorder, no status to ask for
            _attach_status(ctx, client, recorders)
    recorders.sort(key=lambda r: str(r.get("name")))
    for recorder in recorders:
        recorder.setdefault("status", None)
    ctx.out.write("recorders.json", recorders)

    channels: List[Dict[str, Any]] = []
    with ctx.section("delivery_channels"):
        result = ctx.call(client, "describe_delivery_channels")
        channels = [dict(c) for c in result.get("DeliveryChannels") or [] if isinstance(c, dict)]
    ctx.out.write("delivery_channels.json", sorted(channels, key=lambda c: str(c.get("name"))))


def _attach_status(ctx: CollectContext, client: Any, recorders: List[Dict[str, Any]]) -> None:
    result = ctx.call(client, "describe_configuration_recorder_status")
    statuses: Dict[str, Dict[str, Any]] = {}
    for status in result.get("ConfigurationRecordersStatus") or []:
        if isinstance(status, dict) and status.get("name"):
            statuses[status["name"]] = {key: status.get(key) for key in _STATUS_KEYS}
    for recorder in recorders:
        recorder["status"] = statuses.get(recorder.get("name")) if result.has_data else None
