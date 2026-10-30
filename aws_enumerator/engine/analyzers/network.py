"""Network context: VPC connectivity through peering and transit gateways, VPN reach (F-105; DECISIONS.md D-52).

The VPC collector lists peering connections, transit-gateway attachments, VPN gateways and VPN connections
(``vpc/*.json``). This analyzer turns them into **context**, never into attack steps:

* ``vpc -VPC_CONNECTED-> vpc`` (structural, not traversable) for two VPCs that can route traffic to each other:
  an ``active`` VPC peering connection, or attachments (``available`` / ``modifying``) to the same transit gateway
  or to transit gateways joined by an active transit-gateway peering. One edge per pair, stored from the smaller
  node id; ``evidence.via`` lists every link as ``peering:<pcx id>`` / ``transit-gateway:<tgw id>``. Transit-gateway
  route tables are not evaluated (``evidence.route_tables_evaluated = false``): two attachments of one gateway
  may still be isolated by its route tables.
* VPC props ``transit_gateways`` (the gateways the VPC is attached to) and ``vpn_connections`` (the ``available``
  site-to-site VPN connections that reach it through its virtual private gateway or one of its transit gateways):
  the on-premises side has no node type, so VPN reach is a property of the VPC.

A VPC of another account or region that is not in the analysed data becomes a placeholder VPC node of its owner
account (peering accepter / requester). A listing that could not be read completely is a report gap
(``network:connectivity-unknown``), never "no connectivity" (F-059).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from aws_enumerator.engine.analyzers.posture import vpc_node
from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.io.loaders.ec2 import table, table_status, units_of
from aws_enumerator.engine.model import AnalyzerSkipped, AnalyzerSpec, Phase

log = logging.getLogger(__name__)

#: Transit-gateway attachment states in which traffic can flow.
ACTIVE_ATTACHMENT = frozenset({"available", "modifying"})
#: Tables whose incomplete listing makes the connectivity picture unknown.
CONNECTIVITY_TABLES: Tuple[str, ...] = ("vpc_peerings", "tgw_attachments", "vpn_gateways", "vpn_connections")
_TGW_PEERING_TYPES = frozenset({"peering", "tgw-peering"})


@dataclass
class Links:
    """What the analyzer collected before emitting: VPC pairs with their links, gateways and VPNs per VPC."""

    pairs: Dict[Tuple[str, str], Set[Tuple[str, str]]] = field(default_factory=dict)
    tgw_vpcs: Dict[str, Set[str]] = field(default_factory=dict)      # tgw id -> vpc node ids
    tgw_parent: Dict[str, str] = field(default_factory=dict)         # union-find over peered gateways
    vgw_vpcs: Dict[str, Set[str]] = field(default_factory=dict)      # vgw id -> vpc node ids
    vpns: Dict[str, Set[str]] = field(default_factory=dict)          # vpc node id -> vpn connection ids

    def link(self, a: str, b: str, kind: str, link_id: str) -> None:
        if a == b:
            return
        key = (a, b) if a < b else (b, a)
        self.pairs.setdefault(key, set()).add((kind, link_id))

    def root(self, tgw: str) -> str:
        parent = self.tgw_parent.setdefault(tgw, tgw)
        if parent != tgw:
            parent = self.tgw_parent[tgw] = self.root(parent)
        return parent

    def join(self, a: str, b: str) -> None:
        ra, rb = self.root(a), self.root(b)
        if ra != rb:
            self.tgw_parent[max(ra, rb)] = min(ra, rb)


class Network:
    """One analysis: the EC2 loader's tables, the VPC records by id, the builder."""

    def __init__(self, ctx: Any, builder: Any):
        self.ctx = ctx
        self.builder = builder
        self.data = (ctx.data or {}).get("ec2")
        self.links = Links()
        self._records: Dict[Tuple[str, str], Mapping[str, Any]] = {}
        for region in units_of(self.data, "vpcs"):
            for rec in table(self.data, "vpcs", region):
                if rec.get("VpcId"):
                    self._records[(region, str(rec["VpcId"]))] = rec

    def vpc(self, region: str, vpc_id: str, owner: Optional[str] = None) -> Optional[str]:
        """The VPC node (collected record, else a placeholder of its owner account)."""
        rec = self._records.get((region, vpc_id))
        if rec is not None and (owner in (None, self.ctx.account_id)):
            return vpc_node(self.ctx, self.builder, region, rec)
        account = owner or self.ctx.account_id
        try:
            node = ids.node_id_for("vpc", partition=self.ctx.partition, region=region, account=account, id=vpc_id)
        except ValueError:
            return None
        self.builder.add_node(node, "vpc", vpc_id, region=region, account=account,
                              props={"placeholder": True}, coverage_status="not-collected")
        return node


def _active(rec: Mapping[str, Any], key: str, states: Iterable[str]) -> bool:
    value = rec.get(key)
    if isinstance(value, Mapping):
        value = value.get("Code")
    return str(value or "").lower() in states


def peerings(net: Network, region: str) -> None:
    """``VPC_CONNECTED`` for every active peering connection listed in ``region``."""
    for pcx in table(net.data, "vpc_peerings", region):
        if not _active(pcx, "Status", ("active",)):
            continue
        ends = []
        for side in ("RequesterVpcInfo", "AccepterVpcInfo"):
            info = pcx.get(side) if isinstance(pcx.get(side), Mapping) else {}
            vid, owner = str(info.get("VpcId") or ""), str(info.get("OwnerId") or "") or None
            node = net.vpc(str(info.get("Region") or region), vid, owner) if vid else None
            if node is not None:
                ends.append(node)
        if len(ends) == 2:
            net.links.link(ends[0], ends[1], "peering", str(pcx.get("VpcPeeringConnectionId") or ""))


def attachments(net: Network, region: str) -> None:
    """Transit-gateway attachments of ``region``: VPC members, VPN attachments and gateway peerings."""
    for att in table(net.data, "tgw_attachments", region):
        if not _active(att, "State", ACTIVE_ATTACHMENT):
            continue
        tgw, rtype = str(att.get("TransitGatewayId") or ""), str(att.get("ResourceType") or "").lower()
        rid = str(att.get("ResourceId") or "")
        if not tgw or not rid:
            continue
        net.links.root(tgw)
        if rtype == "vpc":
            node = net.vpc(region, rid, str(att.get("ResourceOwnerId") or "") or None)
            if node is not None:
                net.links.tgw_vpcs.setdefault(tgw, set()).add(node)
        elif rtype in _TGW_PEERING_TYPES and rid.startswith("tgw-"):
            net.links.join(tgw, rid)


def vpn_gateways(net: Network, region: str) -> None:
    for vgw in table(net.data, "vpn_gateways", region):
        gid = str(vgw.get("VpnGatewayId") or "")
        for att in vgw.get("VpcAttachments") or ():
            if isinstance(att, Mapping) and str(att.get("State") or "").lower() == "attached" and att.get("VpcId"):
                node = net.vpc(region, str(att["VpcId"]))
                if gid and node is not None:
                    net.links.vgw_vpcs.setdefault(gid, set()).add(node)


def _gateway_groups(links: Links) -> Dict[str, Set[str]]:
    """VPC nodes per group of peered transit gateways (key: the group's smallest gateway id)."""
    groups: Dict[str, Set[str]] = {}
    for tgw in sorted(links.tgw_vpcs):
        groups.setdefault(links.root(tgw), set()).update(links.tgw_vpcs[tgw])
    return groups


def transit_links(links: Links) -> None:
    """``VPC_CONNECTED`` for every pair of VPCs attached to one transit gateway (or to peered gateways)."""
    for root, members in sorted(_gateway_groups(links).items()):
        gateways = sorted(t for t in links.tgw_vpcs if links.root(t) == root)
        ordered = sorted(members)
        for i, a in enumerate(ordered):
            for b in ordered[i + 1:]:
                for tgw in gateways:
                    if a in links.tgw_vpcs[tgw] or b in links.tgw_vpcs[tgw]:
                        links.link(a, b, "transit-gateway", tgw)


def vpn_connections(net: Network, region: str) -> None:
    """VPN connections reaching a VPC through its virtual private gateway or one of its transit gateways."""
    groups = _gateway_groups(net.links)
    for vpn in table(net.data, "vpn_connections", region):
        if str(vpn.get("State") or "").lower() != "available" or not vpn.get("VpnConnectionId"):
            continue
        vid = str(vpn["VpnConnectionId"])
        reached: Set[str] = set(net.links.vgw_vpcs.get(str(vpn.get("VpnGatewayId") or ""), ()))
        tgw = str(vpn.get("TransitGatewayId") or "")
        if tgw:
            reached |= groups.get(net.links.root(tgw), set())
        for node in reached:
            net.links.vpns.setdefault(node, set()).add(vid)


def emit(net: Network) -> int:
    """The ``VPC_CONNECTED`` edges and the VPC props; returns the number of edges."""
    for (a, b), via in sorted(net.links.pairs.items()):
        net.builder.add_edge(a, "VPC_CONNECTED", b, evidence={
            "via": [f"{kind}:{link_id}" for kind, link_id in sorted(via)], "route_tables_evaluated": False})
    gateways: Dict[str, Set[str]] = {}
    for tgw, members in net.links.tgw_vpcs.items():
        for node in members:
            gateways.setdefault(node, set()).add(tgw)
    for node in sorted(set(gateways) | set(net.links.vpns)):
        props: Dict[str, List[str]] = {}
        if node in gateways:
            props["transit_gateways"] = sorted(gateways[node])
        if node in net.links.vpns:
            props["vpn_connections"] = sorted(net.links.vpns[node])
        net.builder.set_node_props(node, **props)
    return len(net.links.pairs)


def _unknown_listings(net: Network, regions: Iterable[str]) -> List[str]:
    return sorted(f"{region}/{key}" for region in regions for key in CONNECTIVITY_TABLES
                  if table_status(net.data, key, region) not in ("complete", "missing"))


def run_network(ctx: Any, builder: Any) -> None:
    """Phase RESOURCES: VPC connectivity and VPN reach of the analysed regions (module docstring)."""
    net = Network(ctx, builder)
    regions = sorted({r for key in CONNECTIVITY_TABLES for r in units_of(net.data, key)})
    if not any(table_status(net.data, key, r) != "missing" for r in regions for key in CONNECTIVITY_TABLES):
        raise AnalyzerSkipped("vpc", reason="no peering, transit-gateway or VPN data was collected")
    for region in regions:
        peerings(net, region)
        attachments(net, region)
        vpn_gateways(net, region)
    transit_links(net.links)
    for region in regions:
        vpn_connections(net, region)
    edges = emit(net)
    unknown = _unknown_listings(net, regions)
    if unknown:
        ctx.add_gap("network:connectivity-unknown", "Peering, transit-gateway or VPN listings that were not read "
                    "completely; VPC connectivity there is unknown, not absent: " + ", ".join(unknown[:20]),
                    len(unknown))
    log.debug("network: %d VPC links, %d VPCs with VPN reach", edges, len(net.links.vpns))


ANALYZERS: Tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec("network", Phase.RESOURCES, run_network, inputs=("vpc",)),
)

__all__ = ["ACTIVE_ATTACHMENT", "ANALYZERS", "CONNECTIVITY_TABLES", "Links", "Network", "run_network"]
