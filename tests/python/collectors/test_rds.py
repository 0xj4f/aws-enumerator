"""RDS collector (collectors-cli.md §5.11): cross-account shares, Aurora cluster snapshots, null on failure."""

from __future__ import annotations

import importlib

import pytest

from tests.support import targets

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

W2, ACCT, EXT = KIT.W2, KIT.ACCT, KIT.EXT
RDS = f"arn:aws:rds:{W2}:{ACCT}:"


def by_kind(r):
    out = {}
    for item in r.load("resources.json"):
        out.setdefault(item["Kind"], {})[item["Name"]] = item
    return out


@pytest.mark.finding("F-056", "F-059")
def test_snapshots_record_public_and_cross_account_sharing(tmp_path):
    r = KIT.run("rds", tmp_path)
    KIT.assert_contract(r, statuses=("partial",))           # acme denies one snapshot's attributes
    items = r.load("resources.json")
    assert [i["Kind"] for i in items] == ["instance"] * 2 + ["cluster"] + ["snapshot"] * 3 + ["cluster_snapshot"] * 2
    kinds = by_kind(r)
    snaps = kinds["snapshot"]
    assert set(snaps) == {"demo-db-snap-denied", "demo-db-snap-public", "demo-db-snap-shared"}   # manual only
    public = snaps["demo-db-snap-public"]
    assert public["PublicSnapshot"] is True and public["SharedAccounts"] == []
    assert snaps["demo-db-snap-shared"]["PublicSnapshot"] is False
    assert snaps["demo-db-snap-shared"]["SharedAccounts"] == [EXT]                          # F-056
    denied = snaps["demo-db-snap-denied"]
    assert denied["PublicSnapshot"] is None and denied["SharedAccounts"] is None              # never False (F-059)
    assert KIT.collection_errors(denied) == [("rds:DescribeDBSnapshotAttributes", "denied")]
    assert denied["Arn"] == f"{RDS}snapshot:demo-db-snap-denied"


@pytest.mark.finding("F-056")
def test_aurora_clusters_and_cluster_snapshots_are_collected(tmp_path):
    kinds = by_kind(KIT.run("rds", tmp_path))
    cluster = kinds["cluster"]["demo-aurora"]
    assert cluster["Arn"] == f"{RDS}cluster:demo-aurora" and cluster["Members"] == ["demo-db-private"]
    assert cluster["Encrypted"] is True and cluster["IAMAuth"] is True and cluster["Public"] is False
    csnaps = kinds["cluster_snapshot"]
    assert set(csnaps) == {"demo-aurora-snap-shared", "demo-aurora-snap-public"}
    assert csnaps["demo-aurora-snap-shared"]["SharedAccounts"] == [EXT]
    assert csnaps["demo-aurora-snap-shared"]["PublicSnapshot"] is False
    assert csnaps["demo-aurora-snap-public"]["PublicSnapshot"] is True
    assert csnaps["demo-aurora-snap-public"]["Arn"] == f"{RDS}cluster-snapshot:demo-aurora-snap-public"
    instance = kinds["instance"]["demo-db-private"]
    assert instance["DBClusterIdentifier"] is None and instance["Engine"] == "aurora-postgresql"


@pytest.mark.finding("F-059")
def test_a_denied_cluster_snapshot_attribute_is_null(tmp_path):
    w = KIT.clean_world("rds")
    w.deny("rds", "DescribeDBClusterSnapshotAttributes")
    r = KIT.run("rds", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    for snap in by_kind(r)["cluster_snapshot"].values():
        assert snap["PublicSnapshot"] is None and snap["SharedAccounts"] is None


@pytest.mark.parametrize("values, expected", [
    ([{"AttributeName": "restore", "AttributeValues": ["all", EXT, "123456789012"]}], (True, ["123456789012", EXT])),
    ([{"AttributeName": "restore", "AttributeValues": []}], (False, [])),
    ([], (False, [])),
])
def test_restore_sharing(values, expected):
    mod = targets.collector_module("rds")
    assert mod.restore_sharing(values) == expected


@pytest.mark.finding("F-103", "F-061")
def test_everything_denied_in_a_region_is_denied_with_an_empty_list(tmp_path):
    r = KIT.run("rds", tmp_path, region=KIT.W1)               # acme denies the instance and snapshot listings
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("resources.json") == []


@pytest.mark.finding("F-103")
def test_a_denied_section_keeps_the_others(tmp_path):
    w = KIT.world()
    w.deny("rds", "DescribeDBClusters")
    r = KIT.run("rds", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    assert "cluster" not in by_kind(r) and len(by_kind(r)["cluster_snapshot"]) == 2


def test_empty_region_is_ok(tmp_path):
    r = KIT.run("rds", tmp_path, region=KIT.EMPTY_REGION)
    KIT.assert_contract(r)
    assert r.load("resources.json") == []


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    assert KIT.assert_each_api_denied_is_survivable("rds", tmp_path) == [
        "rds:DescribeDBClusterSnapshotAttributes", "rds:DescribeDBClusterSnapshots", "rds:DescribeDBClusters",
        "rds:DescribeDBInstances", "rds:DescribeDBSnapshotAttributes", "rds:DescribeDBSnapshots"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    r = KIT.run("rds", tmp_path)
    KIT.assert_declared_and_read_only(r)
    for op in ("DescribeDBSnapshots", "DescribeDBClusterSnapshots"):
        assert {c.params.get("SnapshotType") for c in r.fake.calls_for(service="rds", operation=op)} == {"manual"}
