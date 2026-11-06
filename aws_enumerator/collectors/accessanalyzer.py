"""IAM Access Analyzer analyzers (regional; F-046). Analyzer findings are never read.

boto3 service ``accessanalyzer``; IAM action prefix ``access-analyzer``. ``--modules access_analyzer``
is an alias.

Output (``<region>/accessanalyzer/``):

``analyzers.json``
    list, sorted by ``arn``; ``[]`` when no analyzer exists in the region::

        {arn, name, type, status, statusReason, createdAt, lastResourceAnalyzed, lastResourceAnalyzedAt,
         configuration}

    ``type`` is ``ACCOUNT`` / ``ORGANIZATION`` (external access) or ``*_UNUSED_ACCESS``. Missing
    optional fields are ``null``. Tags are not kept.

``_coverage.json``
    every call (docs/contracts/coverage-schema.md).
"""

from __future__ import annotations

from typing import Any, Dict, List

from aws_enumerator.collectors.base import CollectContext
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="accessanalyzer", scope="regional", output_dir="accessanalyzer", services=("accessanalyzer",),
    tier=1, cost="low", noise="low", default=True, groups=("@posture",),
    actions=("access-analyzer:ListAnalyzers",),
    probe=("accessanalyzer", "ListAnalyzers", (("maxResults", 1),)),
    outputs=(("analyzers.json", "list"),),
    description="IAM Access Analyzer analyzers (external and unused access; never findings)",
)

_KEYS = ("arn", "name", "type", "status", "statusReason", "createdAt", "lastResourceAnalyzed",
         "lastResourceAnalyzedAt", "configuration")


def collect(ctx: CollectContext) -> None:
    """List every analyzer of the region (all types)."""
    client = ctx.client("accessanalyzer")
    analyzers: List[Dict[str, Any]] = []
    with ctx.section("analyzers"):
        listed = ctx.paginate(client, "list_analyzers", "analyzers", page_size=100, primary=True)
        analyzers = [{key: a.get(key) for key in _KEYS} for a in listed.value if isinstance(a, dict)]
    ctx.out.write("analyzers.json", sorted(analyzers, key=lambda a: str(a["arn"])))
