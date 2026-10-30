"""VPC flow log configuration (regional). Flow log records themselves are never read.

Output (``<region>/flowlogs/``):

``flowlogs.json``
    list, sorted by ``FlowLogId``: each ``FlowLog`` as ``DescribeFlowLogs`` returns it (``FlowLogId``,
    ``ResourceId``, ``TrafficType``, ``LogDestinationType``, ``LogDestination``, ``LogGroupName``,
    ``DeliverLogsPermissionArn``, ``DeliverLogsStatus``, ``FlowLogStatus``, ``MaxAggregationInterval``,
    ``LogFormat``, ``CreationTime``, ``Tags`` ...). Always a list: a denied or failed listing writes
    what was read before the failure (usually ``[]``) and the failure is in ``_coverage.json``.

``_coverage.json``
    every call (docs/contracts/coverage-schema.md).
"""

from __future__ import annotations

from typing import Any, Dict, List

from aws_enumerator.collectors.base import CollectContext
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="flowlogs", scope="regional", output_dir="flowlogs", services=("ec2",),
    tier=1, cost="low", noise="low", default=True, groups=("@network", "@posture"),
    actions=("ec2:DescribeFlowLogs",),
    probe=("ec2", "DescribeFlowLogs", (("MaxResults", 5),)),
    outputs=(("flowlogs.json", "list"),),
    description="VPC flow log configuration",
)


def collect(ctx: CollectContext) -> None:
    """Every flow log of the region (all pages)."""
    ec2 = ctx.client("ec2")
    flow_logs: List[Dict[str, Any]] = []
    with ctx.section("flow_logs"):
        result = ctx.paginate(ec2, "describe_flow_logs", "FlowLogs", page_size=1000, primary=True)
        flow_logs = [dict(f) for f in result.value if isinstance(f, dict)]
    ctx.out.write("flowlogs.json", sorted(flow_logs, key=lambda f: str(f.get("FlowLogId"))))
