"""Edge-service loader: EBS snapshots and snapshot settings, load balancers, Route 53 zones (global) and Cognito
pools (E-net, Wave 2).

Reads only the explicit units of the analysis context (the global unit and ``ctx.region_dirs``), never sibling
directories (F-010, F-025, F-063), in both layouts (d13c215 ``*/resources.json`` and the Wave 1 shapes, whose
``null`` fields mean *unknown*: ``SharedAccounts``, ``Public``, ``Targets``, ``Listeners``, ``Records``,
``TakeoverCandidates`` …; ``requests/c-b-1.md``). Tables are ``data[key][unit] = [records]`` with
``data["_status"]`` (see :mod:`aws_enumerator.engine.io.loaders.ec2`).

``cognito`` stays in this domain's data: E-compute's ``analyzers/cognito.py`` reads ``ctx.data["edge_services"]
["cognito"]``.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from aws_enumerator.engine.io.loaders import LoadResult
from aws_enumerator.engine.io.loaders.ec2 import TableSpec, read_tables

TABLES: Tuple[TableSpec, ...] = (
    TableSpec("route53", "route53/resources.json", "route53:ListHostedZones", scope="global"),
    TableSpec("cognito", "cognito/resources.json", "cognito-identity:ListIdentityPools"),
    TableSpec("ebs", "ebs/resources.json", "ec2:DescribeSnapshots"),
    TableSpec("ebs_settings", "ebs/account_settings.json", "ec2:GetSnapshotBlockPublicAccessState", kind="dict"),
    TableSpec("elb", "elb/resources.json", "elbv2:DescribeLoadBalancers"),
)

#: The stub's file map (kept for callers that read it).
GLOBAL_FILES: Dict[str, str] = {"route53": "route53/resources.json"}
REGIONAL_FILES: Dict[str, str] = {t.key: t.path for t in TABLES if t.scope == "regional"}


def load(ctx: Any) -> LoadResult:
    """Pipeline entry point: ``ctx.data["edge_services"]`` (module docstring)."""
    return read_tables(ctx, TABLES)


__all__ = ["GLOBAL_FILES", "REGIONAL_FILES", "TABLES", "load"]
