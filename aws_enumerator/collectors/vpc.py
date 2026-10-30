"""VPC network topology (regional): VPCs, subnets, routing, gateways, NACLs, endpoints, peering, transit
gateways, VPN, Network Firewall and customer-managed prefix lists.

Every listing is paginated (F-117) and isolated in its own section, so one denied call never empties
another file. Files are always lists; a failed listing writes what was read before the failure and the
failure is in ``_coverage.json`` (F-058).

Output (``<region>/vpc/``), each a list of the AWS records sorted by their id:

=================================== ====================================================================
``vpcs.json``                       ``DescribeVpcs`` (``VpcId``)
``subnets.json``                    ``DescribeSubnets`` (``SubnetId``)
``route_tables.json``               ``DescribeRouteTables`` (``RouteTableId``)
``internet_gateways.json``          ``DescribeInternetGateways`` (``InternetGatewayId``)
``nat_gateways.json``               ``DescribeNatGateways`` (``NatGatewayId``)
``nacls.json``                      ``DescribeNetworkAcls`` (``NetworkAclId``)
``vpc_endpoints.json``              ``DescribeVpcEndpoints`` (``VpcEndpointId``; includes ``PolicyDocument``)
``dhcp_options.json``               ``DescribeDhcpOptions`` (``DhcpOptionsId``)
``vpc_peering_connections.json``    ``DescribeVpcPeeringConnections`` (``VpcPeeringConnectionId``)
``transit_gateways.json``           ``DescribeTransitGateways`` (``TransitGatewayId``)
``transit_gateway_attachments.json`` ``DescribeTransitGatewayAttachments`` (``TransitGatewayAttachmentId``)
``vpn_gateways.json``               ``DescribeVpnGateways`` (``VpnGatewayId``)
``vpn_connections.json``            ``DescribeVpnConnections`` (``VpnConnectionId``) **with every
                                    ``CustomerGatewayConfiguration`` and ``PreSharedKey`` removed** (they
                                    hold the tunnel pre-shared keys, F-105)
``network_firewalls.json``          ``network-firewall:ListFirewalls`` ``{FirewallName, FirewallArn}``;
                                    ``[]`` where the service does not exist in the region
``managed_prefix_lists.json``       ``DescribeManagedPrefixLists`` (``PrefixListId``) plus
                                    ``Entries: [{Cidr, Description}] | null``: the entries of
                                    customer-owned lists (``GetManagedPrefixListEntries``, F-076);
                                    ``null`` for AWS-owned lists (not read) and when the read failed
                                    (with ``CollectionErrors``)
``_coverage.json``                  every call (docs/contracts/coverage-schema.md)
=================================== ====================================================================
"""

from __future__ import annotations

import functools
import threading
from typing import Any, Dict, List, Optional, Tuple

from aws_enumerator.collectors.base import CollectContext
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="vpc", scope="regional", output_dir="vpc", services=("ec2", "network-firewall"),
    tier=1, cost="low", noise="low", default=True, groups=("@network",),
    actions=(
        "ec2:DescribeVpcs", "ec2:DescribeSubnets", "ec2:DescribeRouteTables", "ec2:DescribeInternetGateways",
        "ec2:DescribeNatGateways", "ec2:DescribeNetworkAcls", "ec2:DescribeVpcEndpoints", "ec2:DescribeDhcpOptions",
        "ec2:DescribeVpcPeeringConnections", "ec2:DescribeTransitGateways", "ec2:DescribeTransitGatewayAttachments",
        "ec2:DescribeVpnGateways", "ec2:DescribeVpnConnections", "ec2:DescribeManagedPrefixLists",
        "ec2:GetManagedPrefixListEntries", "network-firewall:ListFirewalls",
    ),
    probe=("ec2", "DescribeVpcs", (("MaxResults", 5),)),
    outputs=(
        ("vpcs.json", "list"), ("subnets.json", "list"), ("route_tables.json", "list"),
        ("internet_gateways.json", "list"), ("nat_gateways.json", "list"), ("nacls.json", "list"),
        ("vpc_endpoints.json", "list"), ("dhcp_options.json", "list"), ("vpc_peering_connections.json", "list"),
        ("transit_gateways.json", "list"), ("transit_gateway_attachments.json", "list"),
        ("vpn_gateways.json", "list"), ("vpn_connections.json", "list"), ("network_firewalls.json", "list"),
        ("managed_prefix_lists.json", "list"),
    ),
    description="VPCs, subnets, routing, gateways, NACLs, endpoints, peering, transit gateways, VPN, firewalls",
)

#: (file, ec2 operation, result key, id key, page size or None, primary)
_LISTINGS: Tuple[Tuple[str, str, str, str, Optional[int], bool], ...] = (
    ("vpcs.json", "describe_vpcs", "Vpcs", "VpcId", 1000, True),
    ("subnets.json", "describe_subnets", "Subnets", "SubnetId", 1000, False),
    ("route_tables.json", "describe_route_tables", "RouteTables", "RouteTableId", 100, False),
    ("internet_gateways.json", "describe_internet_gateways", "InternetGateways", "InternetGatewayId", 1000, False),
    ("nat_gateways.json", "describe_nat_gateways", "NatGateways", "NatGatewayId", 1000, False),
    ("nacls.json", "describe_network_acls", "NetworkAcls", "NetworkAclId", 1000, False),
    ("vpc_endpoints.json", "describe_vpc_endpoints", "VpcEndpoints", "VpcEndpointId", 1000, False),
    ("dhcp_options.json", "describe_dhcp_options", "DhcpOptions", "DhcpOptionsId", 1000, False),
    ("vpc_peering_connections.json", "describe_vpc_peering_connections", "VpcPeeringConnections",
     "VpcPeeringConnectionId", 1000, False),
    ("transit_gateways.json", "describe_transit_gateways", "TransitGateways", "TransitGatewayId", 1000, False),
    ("transit_gateway_attachments.json", "describe_transit_gateway_attachments", "TransitGatewayAttachments",
     "TransitGatewayAttachmentId", 1000, False),
    ("vpn_gateways.json", "describe_vpn_gateways", "VpnGateways", "VpnGatewayId", None, False),
    ("vpn_connections.json", "describe_vpn_connections", "VpnConnections", "VpnConnectionId", None, False),
)

#: Keys that carry VPN tunnel secrets; removed at any depth from vpn_connections.json.
_VPN_SECRET_KEYS = frozenset({"CustomerGatewayConfiguration", "PreSharedKey"})
_AWS_OWNER = "AWS"


def collect(ctx: CollectContext) -> None:
    """Every listing in its own section, then firewalls and prefix lists."""
    ec2 = ctx.client("ec2")
    for filename, op, key, id_key, page_size, primary in _LISTINGS:
        items: List[Dict[str, Any]] = []
        with ctx.section(filename[:-5]):
            result = ctx.paginate(ec2, op, key, page_size=page_size, primary=primary)
            items = [dict(i) for i in result.value if isinstance(i, dict)]
        if filename == "vpn_connections.json":
            items = [_strip_keys(i, _VPN_SECRET_KEYS) for i in items]
        ctx.out.write(filename, sorted(items, key=lambda i, k=id_key: str(i.get(k))))

    firewalls: List[Dict[str, Any]] = []
    with ctx.section("network_firewalls"):
        firewalls = _firewalls(ctx)
    ctx.out.write("network_firewalls.json", firewalls)

    prefix_lists: List[Dict[str, Any]] = []
    with ctx.section("managed_prefix_lists"):
        prefix_lists = _prefix_lists(ctx, ec2)
    ctx.out.write("managed_prefix_lists.json", prefix_lists)


def _strip_keys(obj: Any, keys: frozenset) -> Any:
    """A copy of ``obj`` without the mapping keys in ``keys``, at any depth."""
    if isinstance(obj, dict):
        return {k: _strip_keys(v, keys) for k, v in obj.items() if k not in keys}
    if isinstance(obj, list):
        return [_strip_keys(v, keys) for v in obj]
    return obj


def _firewalls(ctx: CollectContext) -> List[Dict[str, Any]]:
    api = "network-firewall:ListFirewalls"
    if not _service_in_region("network-firewall", ctx.region, ctx.partition):
        ctx.cov.skip(api, f"network-firewall is not available in {ctx.region}")
        return []
    client = ctx.client("network-firewall")
    result = ctx.paginate(client, "list_firewalls", "Firewalls", page_size=100)
    out = [{"FirewallName": f.get("FirewallName"), "FirewallArn": f.get("FirewallArn")}
           for f in result.value if isinstance(f, dict)]
    return sorted(out, key=lambda f: str(f["FirewallArn"]))


def _prefix_lists(ctx: CollectContext, ec2: Any) -> List[Dict[str, Any]]:
    listed = ctx.paginate(ec2, "describe_managed_prefix_lists", "PrefixLists", page_size=100)
    out = []
    for prefix_list in sorted((p for p in listed.value if isinstance(p, dict)),
                              key=lambda p: str(p.get("PrefixListId"))):
        record = dict(prefix_list)
        record["Entries"] = None
        if prefix_list.get("OwnerId") != _AWS_OWNER and prefix_list.get("PrefixListId"):
            arn = prefix_list.get("PrefixListArn") or ctx.arn("ec2", f"prefix-list/{prefix_list['PrefixListId']}")
            entries = ctx.paginate(ec2, "get_managed_prefix_list_entries", "Entries", page_size=100, item=arn,
                                   PrefixListId=prefix_list["PrefixListId"])
            if entries.ok:
                record["Entries"] = sorted(({"Cidr": e.get("Cidr"), "Description": e.get("Description")}
                                            for e in entries.value if isinstance(e, dict)),
                                           key=lambda e: str(e["Cidr"]))
            else:
                record["CollectionErrors"] = [entries.collection_error()]
        out.append(record)
    return out


_BOTOCORE_LOCK = threading.Lock()


@functools.lru_cache(maxsize=None)
def _regions_of(service: str, partition: str) -> frozenset:
    import botocore.session  # local: only needed for this offline endpoint lookup

    with _BOTOCORE_LOCK:
        try:
            session = botocore.session.get_session()
            return frozenset(session.get_available_regions(service, partition_name=partition))
        except Exception:  # unknown partition / no endpoint data: treat as unknown
            return frozenset()


def _service_in_region(service: str, region: str, partition: str) -> bool:
    """False only when botocore's bundled endpoint data knows the region (for EC2) but not ``service``
    there; a region botocore does not know yet is assumed to have the service."""
    known = _regions_of("ec2", partition)
    return region not in known or region in _regions_of(service, partition)
