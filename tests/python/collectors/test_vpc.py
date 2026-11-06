"""VPC collector (collectors-cli.md §5.3): every listing paginated and isolated, transit gateways, VPN (pre-shared
keys stripped), Network Firewall, customer-managed prefix lists with their entries."""

from __future__ import annotations

import importlib
import json

import pytest

from tests.fixtures.worlds import acme
from tests.support.fakeaws import botocore_error

KIT = importlib.import_module("tests.fixtures.c-a.kit")
pytestmark = pytest.mark.collectors

W1, W2 = KIT.W1, KIT.W2
LISTINGS = {
    "vpcs.json": ("DescribeVpcs", "Vpcs", "VpcId"),
    "subnets.json": ("DescribeSubnets", "Subnets", "SubnetId"),
    "route_tables.json": ("DescribeRouteTables", "RouteTables", "RouteTableId"),
    "internet_gateways.json": ("DescribeInternetGateways", "InternetGateways", "InternetGatewayId"),
    "nat_gateways.json": ("DescribeNatGateways", "NatGateways", "NatGatewayId"),
    "nacls.json": ("DescribeNetworkAcls", "NetworkAcls", "NetworkAclId"),
    "vpc_endpoints.json": ("DescribeVpcEndpoints", "VpcEndpoints", "VpcEndpointId"),
    "dhcp_options.json": ("DescribeDhcpOptions", "DhcpOptions", "DhcpOptionsId"),
    "vpc_peering_connections.json": ("DescribeVpcPeeringConnections", "VpcPeeringConnections",
                                     "VpcPeeringConnectionId"),
}


@pytest.mark.finding("F-117")
@pytest.mark.parametrize("filename", sorted(LISTINGS))
def test_every_listing_follows_next_token(filename, tmp_path):
    op, key, id_key = LISTINGS[filename]
    w = KIT.clean_world()
    w.page_sizes[("ec2", op)] = 1
    r = KIT.run("vpc", tmp_path, w)
    expected = sorted(item[id_key] for item in acme.REGIONAL[W2]["ec2"][key])
    assert [item[id_key] for item in r.load(filename)] == expected
    assert len(KIT.sent(r, "ec2", op)) == max(1, len(expected))


@pytest.mark.finding("F-058")
def test_one_failed_listing_does_not_empty_the_others(tmp_path):
    r = KIT.run("vpc", tmp_path, KIT.world(), region=W1)   # acme: NAT gateways time out, peering denied
    doc = KIT.assert_contract(r, statuses=("partial",))
    assert r.load("nat_gateways.json") == [] and r.load("vpc_peering_connections.json") == []
    assert [v["VpcId"] for v in r.load("vpcs.json")] == [v["VpcId"] for v in acme.REGIONAL[W1]["ec2"]["Vpcs"]]
    assert len(r.load("subnets.json")) == 1
    statuses = {(row["api"], row["status"], row["error_code"]) for row in doc["calls"]}
    assert ("ec2:DescribeNatGateways", "error", "EndpointConnectionError") in statuses
    assert ("ec2:DescribeVpcPeeringConnections", "denied", "UnauthorizedOperation") in statuses


@pytest.mark.finding("F-058")
def test_a_denied_vpc_listing_makes_the_module_denied(tmp_path):
    w = KIT.clean_world()
    w.deny("ec2", "DescribeVpcs")
    r = KIT.run("vpc", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("vpcs.json") == [] and len(r.load("subnets.json")) == 2


@pytest.mark.finding("F-105")
def test_transit_gateways_vpn_and_firewalls_are_collected(tmp_path):
    r = KIT.run("vpc", tmp_path, KIT.world())
    KIT.assert_contract(r)
    assert [t["TransitGatewayId"] for t in r.load("transit_gateways.json")] == ["tgw-0dec0000000000002"]
    attachments = r.load("transit_gateway_attachments.json")
    assert [a["ResourceOwnerId"] for a in attachments] == [KIT.ACCT, KIT.EXT]
    assert [g["VpnGatewayId"] for g in r.load("vpn_gateways.json")] == ["vgw-0dec0000000000002"]
    assert r.load("network_firewalls.json") == [
        {"FirewallName": "demo-egress-fw",
         "FirewallArn": f"arn:aws:network-firewall:{W2}:{KIT.ACCT}:firewall/demo-egress-fw"}]


@pytest.mark.finding("F-105")
def test_vpn_pre_shared_keys_never_reach_the_report(tmp_path):
    r = KIT.run("vpc", tmp_path, KIT.world())
    KIT.assert_no_canaries(r)
    (vpn,) = r.load("vpn_connections.json")
    text = json.dumps(vpn)
    assert "CustomerGatewayConfiguration" not in text and "PreSharedKey" not in text
    assert vpn["Options"]["TunnelOptions"] == [{"OutsideIpAddress": "198.51.100.30"}]
    assert vpn["Routes"][0]["DestinationCidrBlock"] == "192.168.0.0/16"


@pytest.mark.finding("F-076")
def test_customer_prefix_lists_carry_their_entries_and_aws_lists_are_not_read(tmp_path):
    r = KIT.run("vpc", tmp_path, KIT.world())
    lists = KIT.by(r.load("managed_prefix_lists.json"), "PrefixListId")
    office = lists["pl-0dec00ff1ce000002"]
    assert office["Entries"] == [{"Cidr": "0.0.0.0/0", "Description": "demo: far too broad (F-076)"},
                                 {"Cidr": "198.51.100.0/24", "Description": "demo office"}]
    assert lists["pl-7ca54a1e"]["Entries"] is None                          # AWS-owned: not read
    assert [p["PrefixListId"] for p in KIT.sent(r, "ec2", "GetManagedPrefixListEntries")] == ["pl-0dec00ff1ce000002"]
    w = KIT.clean_world()
    w.deny("ec2", "GetManagedPrefixListEntries")
    r = KIT.run("vpc", tmp_path / "denied", w)
    office = KIT.by(r.load("managed_prefix_lists.json"), "PrefixListId")["pl-0dec00ff1ce000002"]
    assert office["Entries"] is None
    assert KIT.collection_errors(office) == [("ec2:GetManagedPrefixListEntries", "denied")]
    assert r.result.status == "partial"


def test_network_firewall_is_skipped_where_the_service_does_not_exist(tmp_path, monkeypatch):
    vpc = KIT.module("vpc")
    monkeypatch.setattr(vpc, "_service_in_region", lambda service, region, partition: False)
    r = KIT.run("vpc", tmp_path, KIT.clean_world())
    KIT.assert_contract(r)
    assert r.load("network_firewalls.json") == []
    assert KIT.sent(r, "network-firewall", "ListFirewalls") == []
    assert [(row["status"], row["optional"]) for row in KIT.calls(r, "network-firewall:ListFirewalls")] == [
        ("skipped", True)]


def test_a_transport_error_mid_module_keeps_the_data_already_read(tmp_path):
    w = KIT.clean_world()
    w.raise_exc("ec2", "DescribeTransitGateways",
                botocore_error("ConnectTimeoutError", endpoint_url="https://ec2.eu-west-2.amazonaws.com/"))
    r = KIT.run("vpc", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    assert r.load("transit_gateways.json") == []
    assert len(r.load("vpcs.json")) == 1 and len(r.load("vpn_connections.json")) == 1
