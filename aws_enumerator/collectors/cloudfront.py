"""CloudFront distributions (global; F-101).

Records are built from the ``ListDistributions`` summaries (all pages). ``GetDistributionConfig`` is
called per distribution only for ``Logging`` and ``DefaultRootObject``, isolated per item. Origin custom
header **values are never stored**: ``CustomHeaders.Items[].HeaderValue`` becomes ``"<redacted>"`` (the
header name is kept). Origin-verification secrets let an attacker bypass CloudFront/WAF, so they must
not end up in a report.

Output (``global/cloudfront/``):

``distributions.json``
    list, sorted by ``Id``::

        {Id, ARN, DomainName, Status, Enabled, Staging, Comment, LastModifiedTime, Aliases, Origins,
         OriginGroups, DefaultCacheBehavior, CacheBehaviors, CustomErrorResponses, ViewerCertificate,
         Restrictions, WebACLId, HttpVersion, IsIPV6Enabled, PriceClass, Logging: {...} | null,
         DefaultRootObject: str | null, CollectionErrors?}

    The nested structures keep the AWS shapes (``{Quantity, Items}``). ``Logging`` /
    ``DefaultRootObject`` are ``null`` when ``GetDistributionConfig`` failed (``CollectionErrors``).

``_coverage.json``
    every call (docs/contracts/coverage-schema.md).
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List

from aws_enumerator.collectors.base import CollectContext
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="cloudfront", scope="global", output_dir="cloudfront", services=("cloudfront",),
    tier=1, cost="low", noise="low", default=True, groups=("@edge",),
    actions=("cloudfront:ListDistributions", "cloudfront:GetDistributionConfig"),
    probe=("cloudfront", "ListDistributions", (("MaxItems", "1"),)),
    outputs=(("distributions.json", "list"),),
    description="CloudFront distributions: aliases, origins (header values redacted), behaviours, TLS, WAF",
)

REDACTED = "<redacted>"
_SUMMARY_KEYS = ("Id", "ARN", "DomainName", "Status", "Enabled", "Staging", "Comment", "LastModifiedTime",
                 "Aliases", "Origins", "OriginGroups", "DefaultCacheBehavior", "CacheBehaviors",
                 "CustomErrorResponses", "ViewerCertificate", "Restrictions", "WebACLId", "HttpVersion",
                 "IsIPV6Enabled", "PriceClass")


def collect(ctx: CollectContext) -> None:
    """Every distribution (all pages), each enriched with its logging configuration."""
    client = ctx.client("cloudfront")
    distributions: List[Dict[str, Any]] = []
    with ctx.section("distributions"):
        listed = ctx.paginate(client, "list_distributions", "DistributionList.Items", primary=True)
        summaries = sorted((d for d in listed.value if isinstance(d, dict) and d.get("Id")),
                           key=lambda d: str(d["Id"]))
        for summary in summaries:
            distributions.append(_distribution(ctx, client, summary))
    ctx.out.write("distributions.json", distributions)


def redact_origins(origins: Any) -> Any:
    """A copy of an ``Origins`` structure with every custom header value replaced by ``"<redacted>"``."""
    origins = copy.deepcopy(origins)
    items = origins.get("Items") if isinstance(origins, dict) else None
    for origin in items or []:
        headers = origin.get("CustomHeaders") if isinstance(origin, dict) else None
        for header in (headers or {}).get("Items") or []:
            if isinstance(header, dict) and "HeaderValue" in header:
                header["HeaderValue"] = REDACTED
    return origins


def _distribution(ctx: CollectContext, client: Any, summary: Dict[str, Any]) -> Dict[str, Any]:
    record: Dict[str, Any] = {key: summary.get(key) for key in _SUMMARY_KEYS}
    record["Origins"] = redact_origins(summary.get("Origins"))
    record.update(Logging=None, DefaultRootObject=None)
    arn = summary.get("ARN") or ctx.arn("cloudfront", f"distribution/{summary['Id']}", region="")
    result = ctx.call(client, "get_distribution_config", item=arn, Id=summary["Id"])
    if result.has_data:
        config = result.get("DistributionConfig") or {}
        record["Logging"] = config.get("Logging")
        record["DefaultRootObject"] = config.get("DefaultRootObject")
    error = result.collection_error()
    if error is not None:
        record["CollectionErrors"] = [error]
    return record
