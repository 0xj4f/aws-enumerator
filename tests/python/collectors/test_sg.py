"""Security-group collector (collectors-cli.md §5.3): paginated groups, ONE region-wide network-interface
listing grouped by group id (no per-group calls), unknown associations are ``null``."""

from __future__ import annotations

import importlib

import pytest

from tests.fixtures.worlds import acme

KIT = importlib.import_module("tests.fixtures.c-a.kit")
WORLDS = importlib.import_module("tests.fixtures.c-a.worlds")
pytestmark = pytest.mark.collectors

W1, W2 = KIT.W1, KIT.W2
WEB, APP, DEFAULT = (g["GroupId"] for g in acme.REGIONAL[W2]["ec2"]["SecurityGroups"])


def groups(r):
    return KIT.by(r.load("security_groups.json"), "GroupId")


@pytest.mark.finding("F-167", "F-109", "F-117")
def test_three_groups_and_four_interfaces_over_two_pages_in_one_plus_two_calls(tmp_path):
    r = KIT.run("sg", tmp_path, WORLDS.extra_eni(page_size=2))
    KIT.assert_contract(r)
    assert len(KIT.sent(r, "ec2", "DescribeSecurityGroups")) == 1
    eni_calls = KIT.sent(r, "ec2", "DescribeNetworkInterfaces")
    assert len(eni_calls) == 2 and all("Filters" not in p for p in eni_calls)     # never one call per group
    g = groups(r)
    assert sorted(g) == sorted([WEB, APP, DEFAULT])
    assert [e["NetworkInterfaceId"] for e in g[WEB]["AssociatedResources"]] == [
        "eni-0dec0a1b0000002", "eni-0dec0eeb0000002"]
    assert [e["NetworkInterfaceId"] for e in g[APP]["AssociatedResources"]] == [
        "eni-0dec0abb0000002", WORLDS.EXTRA_ENI_ID]
    assert [e["NetworkInterfaceId"] for e in g[DEFAULT]["AssociatedResources"]] == [WORLDS.EXTRA_ENI_ID]
    shared = g[DEFAULT]["AssociatedResources"][0]
    assert (shared["InstanceId"], shared["PublicIp"], shared["InterfaceType"]) == (
        "i-0dec0abb000000002", "203.0.113.40", "interface")


@pytest.mark.finding("F-117")
def test_security_groups_follow_next_token(tmp_path):
    w = KIT.world()
    w.page_sizes[("ec2", "DescribeSecurityGroups")] = 1
    r = KIT.run("sg", tmp_path, w)
    assert len(KIT.sent(r, "ec2", "DescribeSecurityGroups")) == 3
    assert list(groups(r)) == sorted([WEB, APP, DEFAULT])


def test_rules_and_metadata_are_kept(tmp_path):
    r = KIT.run("sg", tmp_path, KIT.world())
    web = groups(r)[WEB]
    raw = acme.REGIONAL[W2]["ec2"]["SecurityGroups"][0]
    assert web["InboundRules"] == raw["IpPermissions"]
    assert web["OutboundRules"] == raw.get("IpPermissionsEgress", [])
    assert (web["GroupName"], web["VpcId"]) == (raw["GroupName"], raw["VpcId"])
    assert set(web) == {"GroupId", "GroupName", "Description", "VpcId", "OwnerId", "Tags", "InboundRules",
                        "OutboundRules", "AssociatedResources"}


@pytest.mark.finding("F-058")
def test_unlisted_interfaces_make_associations_unknown_not_empty(tmp_path):
    r = KIT.run("sg", tmp_path, KIT.world(), region=W1)        # acme denies DescribeNetworkInterfaces in W1
    KIT.assert_contract(r, statuses=("partial",))
    (only,) = r.load("security_groups.json")
    assert only["AssociatedResources"] is None
    assert [(row["status"], row["error_code"]) for row in KIT.calls(r, "ec2:DescribeNetworkInterfaces")] == [
        ("denied", "UnauthorizedOperation")]


def test_no_interface_listing_without_groups(tmp_path):
    r = KIT.run("sg", tmp_path, KIT.world(), region=KIT.EMPTY_REGION)
    assert r.load("security_groups.json") == []
    assert KIT.sent(r, "ec2", "DescribeNetworkInterfaces") == []
