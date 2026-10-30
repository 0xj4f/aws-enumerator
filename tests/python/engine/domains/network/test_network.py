"""Network context (analyzers/network.py; F-105, DECISIONS.md D-52): VPC connectivity through peering and transit
gateways, and VPN reach, as non-traversable ``VPC_CONNECTED`` edges and VPC props."""

from __future__ import annotations

import importlib

import pytest

K = importlib.import_module("tests.fixtures.e-net.kit")
rb = K.rb
W2, W1 = K.REGION, K.OTHER                     # eu-west-2, eu-west-1


def _vpc_id(region: str, vid: str, account: str = K.ACCT) -> str:
    return f"arn:aws:ec2:{region}:{account}:vpc/{vid}"


def _vpc(vid: str) -> dict:
    return {"VpcId": vid, "CidrBlock": "10.0.0.0/16", "IsDefault": False}


def _att(tgw: str, rtype: str, rid: str, state: str = "available", aid: str = "tgw-attach-0a1b2c3d4e5f60001"):
    return {"TransitGatewayAttachmentId": aid, "TransitGatewayId": tgw, "ResourceType": rtype, "ResourceId": rid,
            "ResourceOwnerId": K.ACCT, "State": state}


def _world(tmp_path, *, tgw_calls=None):
    run = K.Run(tmp_path, regions=(W1, W2))
    run.write_json(W2, "vpc/vpcs.json", [_vpc("vpc-0aaa"), _vpc("vpc-0bbb"), _vpc("vpc-0ccc")])
    run.write_json(W2, "vpc/vpc_peering_connections.json", [
        {"VpcPeeringConnectionId": "pcx-0a1b2c3d4e5f60001", "Status": {"Code": "active"},
         "RequesterVpcInfo": {"VpcId": "vpc-0aaa", "OwnerId": K.ACCT, "Region": W2},
         "AccepterVpcInfo": {"VpcId": "vpc-0fff", "OwnerId": K.FOREIGN, "Region": W1}},
        {"VpcPeeringConnectionId": "pcx-0a1b2c3d4e5f60002", "Status": {"Code": "deleted"},
         "RequesterVpcInfo": {"VpcId": "vpc-0bbb", "OwnerId": K.ACCT, "Region": W2},
         "AccepterVpcInfo": {"VpcId": "vpc-0ccc", "OwnerId": K.ACCT, "Region": W2}}])
    run.write_json(W2, "vpc/transit_gateway_attachments.json", [
        _att("tgw-0aaa", "vpc", "vpc-0aaa", aid="tgw-attach-01"),
        _att("tgw-0aaa", "vpc", "vpc-0bbb", aid="tgw-attach-02"),
        _att("tgw-0aaa", "vpc", "vpc-0ccc", state="deleted", aid="tgw-attach-03"),
        _att("tgw-0aaa", "vpn", "vpn-0aaa", aid="tgw-attach-04"),
        _att("tgw-0aaa", "peering", "tgw-0ddd", aid="tgw-attach-05")], calls=tgw_calls)
    run.write_json(W2, "vpc/vpn_gateways.json", [
        {"VpnGatewayId": "vgw-0ccc", "State": "available",
         "VpcAttachments": [{"VpcId": "vpc-0ccc", "State": "attached"}]}])
    run.write_json(W2, "vpc/vpn_connections.json", [
        {"VpnConnectionId": "vpn-0aaa", "State": "available", "TransitGatewayId": "tgw-0aaa"},
        {"VpnConnectionId": "vpn-0ccc", "State": "available", "VpnGatewayId": "vgw-0ccc"},
        {"VpnConnectionId": "vpn-0dead", "State": "deleted", "VpnGatewayId": "vgw-0ccc"}])
    run.write_json(W1, "vpc/vpcs.json", [_vpc("vpc-0ddd")])
    run.write_json(W1, "vpc/transit_gateway_attachments.json",
                   [_att("tgw-0ddd", "vpc", "vpc-0ddd", aid="tgw-attach-06")])
    run.finish()
    return run.analyze()


@pytest.mark.finding("F-105")
def test_vpc_connectivity_through_peering_and_transit_gateways(tmp_path):
    res = _world(tmp_path)
    g = res.graph
    assert K.problems(g) == [] and K.statuses(res.result)["network"] == "ok"
    a, b, c, d = (_vpc_id(W2, "vpc-0aaa"), _vpc_id(W2, "vpc-0bbb"), _vpc_id(W2, "vpc-0ccc"), _vpc_id(W1, "vpc-0ddd"))
    foreign = _vpc_id(W1, "vpc-0fff", K.FOREIGN)
    links = {(e["source"], e["target"]): e for e in K.edges(g, "VPC_CONNECTED")}
    assert set(links) == {tuple(sorted(p)) for p in ((a, b), (a, d), (b, d), (a, foreign))}
    assert all(e["traversable"] is False and e["traversal"] == "structural" for e in links.values())
    assert links[tuple(sorted((a, foreign)))]["evidence"]["via"] == ["peering:pcx-0a1b2c3d4e5f60001"]
    assert links[tuple(sorted((a, b)))]["evidence"]["via"] == ["transit-gateway:tgw-0aaa"]
    assert links[tuple(sorted((a, d)))]["evidence"]["route_tables_evaluated"] is False
    nodes = K.nodes_by_id(g)
    assert nodes[foreign]["account"] == K.FOREIGN and nodes[foreign]["props"]["placeholder"] is True
    assert nodes[a]["props"]["transit_gateways"] == ["tgw-0aaa"] and nodes[d]["props"]["transit_gateways"] == [
        "tgw-0ddd"]
    assert nodes[a]["props"]["vpn_connections"] == ["vpn-0aaa"] == nodes[d]["props"]["vpn_connections"]
    assert nodes[c]["props"]["vpn_connections"] == ["vpn-0ccc"]                      # through its VGW only
    assert not [e for e in K.edges(g, "VPC_CONNECTED") if c in (e["source"], e["target"])]   # deleted links
    assert not [e for e in g["edges"] if e["source"] in (a, b, c, d) and e["traversable"]]


@pytest.mark.finding("F-105", "F-059")
def test_an_unread_attachment_listing_is_a_gap_not_no_connectivity(tmp_path):
    res = _world(tmp_path, tgw_calls=[{"api": "ec2:DescribeTransitGatewayAttachments", "status": "denied",
                                       "primary": False}])
    gaps = {x["code"]: x for x in res.graph["evaluation_gaps"]}
    assert gaps["network:connectivity-unknown"]["count"] >= 1
    assert K.problems(res.graph) == []
