"""Security groups and the network interfaces that use them (regional).

Calls: one paginated ``DescribeSecurityGroups`` and **one** paginated ``DescribeNetworkInterfaces`` for
the whole region, grouped by ``Groups[].GroupId`` (F-109, F-167: no per-group ENI lookup).

Output (``<region>/sg/``):

``security_groups.json``
    list, sorted by ``GroupId``::

        {GroupId, GroupName, Description, VpcId, OwnerId, Tags: [{Key, Value}],
         InboundRules: [IpPermission], OutboundRules: [IpPermission],
         AssociatedResources: [{NetworkInterfaceId, PrivateIpAddress, PublicIp, Description, InterfaceType,
                                InstanceId, Attachment}] | null}

    ``InboundRules`` / ``OutboundRules`` are the raw ``IpPermissions`` / ``IpPermissionsEgress`` (CIDRs,
    IPv6 ranges, prefix-list ids, group pairs). ``AssociatedResources`` is ``null`` when the network
    interfaces could not be listed (unknown, not "unused"); entries are sorted by ``NetworkInterfaceId``.

``_coverage.json``
    every call (docs/contracts/coverage-schema.md).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_enumerator.collectors.base import CollectContext
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="sg", scope="regional", output_dir="sg", services=("ec2",),
    tier=1, cost="low", noise="low", default=True, groups=("@network",),
    actions=("ec2:DescribeSecurityGroups", "ec2:DescribeNetworkInterfaces"),
    probe=("ec2", "DescribeSecurityGroups", (("MaxResults", 5),)),
    outputs=(("security_groups.json", "list"),),
    description="Security groups and the network interfaces that use them",
)

EniIndex = Dict[str, List[Dict[str, Any]]]


def collect(ctx: CollectContext) -> None:
    """Security groups plus one region-wide network-interface listing."""
    ec2 = ctx.client("ec2")
    groups: List[Dict[str, Any]] = []
    with ctx.section("security_groups"):
        listed = ctx.paginate(ec2, "describe_security_groups", "SecurityGroups", page_size=1000, primary=True)
        groups = [g for g in listed.value if isinstance(g, dict) and g.get("GroupId")]
    index: Optional[EniIndex] = None
    if groups:  # nothing to map when there is no group (or the listing failed)
        with ctx.section("network_interfaces"):
            index = _eni_index(ctx, ec2)
    records = [_record(group, index) for group in groups]
    ctx.out.write("security_groups.json", sorted(records, key=lambda g: str(g["GroupId"])))


def _eni_index(ctx: CollectContext, ec2: Any) -> Optional[EniIndex]:
    result = ctx.paginate(ec2, "describe_network_interfaces", "NetworkInterfaces", page_size=1000)
    if not result.ok:
        return None
    index: EniIndex = {}
    for eni in result.value:
        if not isinstance(eni, dict):
            continue
        entry = _eni_entry(eni)
        for group_id in sorted({g.get("GroupId") for g in eni.get("Groups") or [] if isinstance(g, dict)} - {None}):
            index.setdefault(group_id, []).append(entry)
    return index


def _eni_entry(eni: Dict[str, Any]) -> Dict[str, Any]:
    attachment = eni.get("Attachment") if isinstance(eni.get("Attachment"), dict) else None
    association = eni.get("Association") if isinstance(eni.get("Association"), dict) else {}
    return {
        "NetworkInterfaceId": eni.get("NetworkInterfaceId"),
        "PrivateIpAddress": eni.get("PrivateIpAddress"),
        "PublicIp": association.get("PublicIp"),
        "Description": eni.get("Description"),
        "InterfaceType": eni.get("InterfaceType"),
        "InstanceId": (attachment or {}).get("InstanceId"),
        "Attachment": attachment,
    }


def _record(group: Dict[str, Any], index: Optional[EniIndex]) -> Dict[str, Any]:
    associated = None
    if index is not None:
        associated = sorted(index.get(group["GroupId"], []), key=lambda e: str(e["NetworkInterfaceId"]))
    return {
        "GroupId": group["GroupId"],
        "GroupName": group.get("GroupName"),
        "Description": group.get("Description"),
        "VpcId": group.get("VpcId"),
        "OwnerId": group.get("OwnerId"),
        "Tags": list(group.get("Tags") or []),
        "InboundRules": list(group.get("IpPermissions") or []),
        "OutboundRules": list(group.get("IpPermissionsEgress") or []),
        "AssociatedResources": associated,
    }
