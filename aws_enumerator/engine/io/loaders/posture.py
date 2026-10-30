"""Defensive-posture loader: CloudTrail trails, VPC flow logs, WAF web ACLs (regional and CloudFront scope),
CloudFront distributions, GuardDuty, AWS Config, Security Hub and IAM Access Analyzer (E-net, Wave 2; F-045,
F-046, F-047).

Reads only the explicit units of the analysis context (the global unit and ``ctx.region_dirs``), never sibling
directories (F-010, F-025, F-063). Tables are ``data[key][unit] = [records]`` with ``data["_status"]`` (see
:mod:`aws_enumerator.engine.io.loaders.ec2`): a listing that was denied or failed is *unknown*, so the posture
analyzer never reports "not enabled" from data it could not read.

The VPC list (``vpc/vpcs.json``, flow-log coverage is per VPC) and the API Gateway list
(``apigateway/resources.json``, stage web ACLs) are read here too.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from aws_enumerator.engine.io.loaders import LoadResult
from aws_enumerator.engine.io.loaders.ec2 import TableSpec, read_tables

TABLES: Tuple[TableSpec, ...] = (
    TableSpec("distributions", "cloudfront/distributions.json", "cloudfront:ListDistributions", scope="global"),
    TableSpec("web_acls_cloudfront", "waf_cloudfront/web_acls.json", "wafv2:ListWebACLs", scope="global"),
    TableSpec("trails", "cloudtrail/trails.json", "cloudtrail:DescribeTrails"),
    TableSpec("flow_logs", "flowlogs/flowlogs.json", "ec2:DescribeFlowLogs"),
    TableSpec("vpcs", "vpc/vpcs.json", "ec2:DescribeVpcs"),
    TableSpec("web_acls", "waf/web_acls.json", "wafv2:ListWebACLs"),
    TableSpec("guardduty", "guardduty/detectors.json", "guardduty:ListDetectors"),
    TableSpec("config", "config/recorders.json", "config:DescribeConfigurationRecorders"),
    TableSpec("securityhub", "securityhub/hub.json", "securityhub:DescribeHub", kind="dict"),
    TableSpec("access_analyzers", "accessanalyzer/analyzers.json", "accessanalyzer:ListAnalyzers"),
    TableSpec("apis", "apigateway/resources.json", "apigateway:GetRestApis"),
)

#: The stub's file map (kept for callers that read it).
GLOBAL_FILES: Dict[str, str] = {t.key: t.path for t in TABLES if t.scope == "global"}
REGIONAL_FILES: Dict[str, str] = {t.key: t.path for t in TABLES if t.scope == "regional"}


def load(ctx: Any) -> LoadResult:
    """Pipeline entry point: ``ctx.data["posture"]`` (module docstring)."""
    return read_tables(ctx, TABLES)


__all__ = ["GLOBAL_FILES", "REGIONAL_FILES", "TABLES", "load"]
