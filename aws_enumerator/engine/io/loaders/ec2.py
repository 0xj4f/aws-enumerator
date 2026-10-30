"""EC2 network-exposure loader: instances, Elastic IPs, launch templates, AMIs, security groups, VPC routing,
NACLs, prefix lists and SSM managed instances (E-net, Wave 2).

Reads only the explicit units of the analysis context (``ctx.region_dirs``), never sibling directories (F-010,
F-025, F-063), in both collector layouts: the d13c215 files (``ec2/instances.json``, ``sg/``, ``vpc/``) and the
Wave 1 ones, which add ``ec2/{elastic_ips,launch_templates,images,account_settings}.json``,
``vpc/{nacls,managed_prefix_lists}.json`` and ``ssm/managed_instances.json``; the network context analyzer
(``analyzers/network.py``) reads ``vpc/{vpc_peering_connections,transit_gateway_attachments,vpn_gateways,
vpn_connections}.json`` from the same data.

The data shape is ``data[key][unit] = [records]`` tables, plus ``data["_status"][key][unit]``: whether that table is
``complete``, ``partial``, ``missing`` (not collected), or ``denied`` / ``throttled`` / ``error``. Analyzers use the
status to tell "no route tables" from "route tables unknown": an unknown table never reads as empty (F-058,
F-059). A JSON object file (``account_settings.json``) is a one-element table.

:func:`read_tables` is shared by the other E-net loaders (``s3``, ``edge_services``, ``posture``).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from aws_enumerator.engine.io.fs import read_json, stub_status
from aws_enumerator.engine.io.loaders import LoadResult

#: Table statuses meaning "the collected list can be trusted as the full set".
KNOWN = frozenset({"complete"})
#: Table statuses meaning "some records were read, the set may be incomplete".
PARTIAL = frozenset({"partial"})
STATUS_KEY = "_status"


@dataclass(frozen=True)
class TableSpec:
    """One collector file read into ``data[key][unit]``.

    ``api`` is the coverage api (``<botocore service>:<Operation>``) that fills the file, used to tell a list that
    was read completely from one whose listing was denied (an empty list is then *unknown*, not empty).
    """

    key: str
    path: str
    api: str
    scope: str = "regional"      # "regional" | "global"
    kind: str = "list"           # "list" | "dict" (a dict file becomes a one-element table)


def _units(ctx: Any, scope: str) -> List[Tuple[str, Path]]:
    if scope == "global":
        return [("global", Path(ctx.global_dir))]
    return [(unit, Path(path)) for unit, path in sorted((ctx.region_dirs or {}).items())]


def _coverage_status(ctx: Any, spec: TableSpec, unit: str) -> str:
    """Facet status of the api behind ``spec`` (``complete`` when the run recorded no coverage)."""
    ledger = getattr(ctx, "coverage", None)
    if ledger is None:
        return "complete"
    facet = ledger.facet(spec.path.split("/", 1)[0], spec.api, unit)
    if facet in ("complete", "legacy-unknown", "not-collected", "skipped", "not-applicable"):
        # a readable file without a coverage record (synthetic runs, legacy layouts) is taken as read
        return "complete"
    return facet


def _read_one(ctx: Any, spec: TableSpec, unit: str, base: Path) -> Tuple[List[Any], str, Optional[str]]:
    """``(records, status, error_code)`` of one file in one unit."""
    res = read_json(base / spec.path)
    if res.status == "missing":
        return [], "missing", None
    if res.status == "error-stub":
        return [], stub_status(res.error_code), res.error_code
    if res.status != "ok":
        return [], "error", None
    if spec.kind == "dict":
        if not isinstance(res.data, Mapping):
            return [], "error", None
        return [dict(res.data)], _coverage_status(ctx, spec, unit), None
    if not isinstance(res.data, list):
        return [], "error", None
    records = [dict(r) for r in res.data if isinstance(r, Mapping)]
    return records, _coverage_status(ctx, spec, unit), None


def read_tables(ctx: Any, specs: Iterable[TableSpec]) -> LoadResult:
    """Read every table of ``specs`` over the context's explicit units (module docstring)."""
    data: Dict[str, Any] = {}
    status: Dict[str, Dict[str, str]] = {}
    gaps: Dict[str, str] = {}
    seen = 0
    for spec in specs:
        data[spec.key] = {}
        status[spec.key] = {}
        for unit, base in _units(ctx, spec.scope):
            records, st, code = _read_one(ctx, spec, unit, base)
            data[spec.key][unit] = records
            status[spec.key][unit] = st
            if st != "missing":
                seen += 1
            if st not in ("complete", "missing", "partial"):
                gaps[f"{spec.path}:{st}"] = f"{unit}/{spec.path} could not be read ({code or st})"
    data[STATUS_KEY] = status
    if seen == 0:
        overall = "missing"
    else:
        overall = "partial" if gaps or any(s == "partial" for t in status.values() for s in t.values()) else "ok"
    return LoadResult(data, overall, gaps, files=seen)


def table(data: Optional[Mapping[str, Any]], key: str, unit: str) -> List[Dict[str, Any]]:
    """The records of ``key`` in ``unit`` (``[]`` when absent)."""
    if not isinstance(data, Mapping):
        return []
    units = data.get(key)
    rows = units.get(unit) if isinstance(units, Mapping) else None
    return [r for r in rows or () if isinstance(r, Mapping)]


def table_status(data: Optional[Mapping[str, Any]], key: str, unit: str) -> str:
    """Status of ``key`` in ``unit`` (``missing`` when the loader did not run or the table is unknown)."""
    if not isinstance(data, Mapping):
        return "missing"
    status = data.get(STATUS_KEY)
    if not isinstance(status, Mapping):
        # a loader that predates the status table (E-core's stub shape): data present = taken as read
        return "complete" if table(data, key, unit) else "missing"
    per_key = status.get(key)
    return str(per_key.get(unit, "missing")) if isinstance(per_key, Mapping) else "missing"


def units_of(data: Optional[Mapping[str, Any]], key: str) -> List[str]:
    """Units (``global`` / regions) that have a ``key`` table, sorted."""
    if not isinstance(data, Mapping) or not isinstance(data.get(key), Mapping):
        return []
    return sorted(data[key])


def document(data: Optional[Mapping[str, Any]], key: str, unit: str) -> Optional[Dict[str, Any]]:
    """The object of a ``dict`` table (``None`` when not read)."""
    rows = table(data, key, unit)
    return dict(rows[0]) if rows else None


# ── the EC2 loader ───────────────────────────────────────────────────────────

TABLES: Tuple[TableSpec, ...] = (
    TableSpec("instances", "ec2/instances.json", "ec2:DescribeInstances"),
    TableSpec("elastic_ips", "ec2/elastic_ips.json", "ec2:DescribeAddresses"),
    TableSpec("launch_templates", "ec2/launch_templates.json", "ec2:DescribeLaunchTemplates"),
    TableSpec("images", "ec2/images.json", "ec2:DescribeImages"),
    TableSpec("account_settings", "ec2/account_settings.json", "ec2:GetImageBlockPublicAccessState", kind="dict"),
    TableSpec("security_groups", "sg/security_groups.json", "ec2:DescribeSecurityGroups"),
    TableSpec("route_tables", "vpc/route_tables.json", "ec2:DescribeRouteTables"),
    TableSpec("internet_gateways", "vpc/internet_gateways.json", "ec2:DescribeInternetGateways"),
    TableSpec("subnets", "vpc/subnets.json", "ec2:DescribeSubnets"),
    TableSpec("vpcs", "vpc/vpcs.json", "ec2:DescribeVpcs"),
    TableSpec("nacls", "vpc/nacls.json", "ec2:DescribeNetworkAcls"),
    TableSpec("prefix_lists", "vpc/managed_prefix_lists.json", "ec2:DescribeManagedPrefixLists"),
    TableSpec("vpc_peerings", "vpc/vpc_peering_connections.json", "ec2:DescribeVpcPeeringConnections"),
    TableSpec("tgw_attachments", "vpc/transit_gateway_attachments.json", "ec2:DescribeTransitGatewayAttachments"),
    TableSpec("vpn_gateways", "vpc/vpn_gateways.json", "ec2:DescribeVpnGateways"),
    TableSpec("vpn_connections", "vpc/vpn_connections.json", "ec2:DescribeVpnConnections"),
    TableSpec("managed_instances", "ssm/managed_instances.json", "ssm:DescribeInstanceInformation"),
)

#: The stub's file map (kept for callers that read it).
GLOBAL_FILES: Dict[str, str] = {}
REGIONAL_FILES: Dict[str, str] = {t.key: t.path for t in TABLES if t.scope == "regional"}


def load(ctx: Any) -> LoadResult:
    """Pipeline entry point: ``ctx.data["ec2"]`` (module docstring)."""
    return read_tables(ctx, TABLES)


__all__ = [
    "GLOBAL_FILES", "KNOWN", "PARTIAL", "REGIONAL_FILES", "STATUS_KEY", "TABLES", "TableSpec", "document", "load",
    "read_tables", "table", "table_status", "units_of",
]
