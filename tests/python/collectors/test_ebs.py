"""EBS collector (collectors-cli.md §5.13): public set in one listing, capped share checks, null not false, BPA."""

from __future__ import annotations

import importlib

import pytest

from tests.support import targets

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

W2, ACCT, EXT = KIT.W2, KIT.ACCT, KIT.EXT
PUBLIC, SHARED, PRIVATE = "snap-0dec0b0b11c000021", "snap-0dec054aaed000022", "snap-0dec0ba1ba7e00023"


def snapshot_world(count=5000, public_every=1000, shared_every=7):
    """``count`` self-owned snapshots (newest = highest number); some public, some shared with EXT."""
    w = KIT.world()
    snaps = []
    for n in range(count):
        perms = [{"Group": "all"}] if n % public_every == 0 else ([{"UserId": EXT}] if n % shared_every == 0 else [])
        snaps.append({"SnapshotId": f"snap-{n:017x}", "VolumeId": f"vol-{n:017x}", "State": "completed",
                      "StartTime": f"2024-01-{1 + n // 1440:02d}T{(n // 60) % 24:02d}:{n % 60:02d}:00Z",
                      "OwnerId": ACCT, "Progress": "100%", "VolumeSize": 8, "Encrypted": False, "perms": perms})
    by_id = {s["SnapshotId"]: s for s in snaps}

    @w.op("ec2", "DescribeSnapshots")
    def describe(req):
        wanted = set(req.params.get("RestorableByUserIds") or [])
        chosen = [s for s in snaps if not wanted or any(p.get("Group") in wanted for p in s["perms"])]
        return {"Snapshots": [{k: v for k, v in s.items() if k != "perms"} for s in chosen]}

    @w.op("ec2", "DescribeSnapshotAttribute")
    def attribute(req):
        return {"SnapshotId": req.params["SnapshotId"],
                "CreateVolumePermissions": by_id[req.params["SnapshotId"]]["perms"]}

    return w, snaps


@pytest.mark.finding("F-104", "F-059", "F-080")
def test_public_shared_and_unknown_snapshots(tmp_path):
    r = KIT.run("ebs", tmp_path)
    KIT.assert_contract(r, statuses=("partial",))           # acme denies the private snapshot's attribute
    snaps = KIT.by(r.load("resources.json"), "Id")
    assert list(snaps) == sorted([PUBLIC, SHARED, PRIVATE])
    assert snaps[PUBLIC]["Public"] is True and snaps[PUBLIC]["SharedAccounts"] == []
    assert snaps[PUBLIC]["Arn"] == f"arn:aws:ec2:{W2}::snapshot/{PUBLIC}"
    assert snaps[SHARED]["Public"] is False and snaps[SHARED]["SharedAccounts"] == [EXT]
    private = snaps[PRIVATE]
    assert private["Public"] is False                        # known from the RestorableByUserIds=[all] listing
    assert private["SharedAccounts"] is None and private["SharingChecked"] is False   # unknown, never []
    assert KIT.collection_errors(private) == [("ec2:DescribeSnapshotAttribute", "denied")]
    assert r.load("account_settings.json") == {"SnapshotBlockPublicAccessState": "unblocked",
                                               "EbsEncryptionByDefault": False}
    lists = r.fake.calls_for(service="ec2", operation="DescribeSnapshots")
    assert [c.params.get("RestorableByUserIds") for c in lists] == [None, ["all"]]
    assert all(c.params["OwnerIds"] == ["self"] for c in lists)


@pytest.mark.finding("F-104", "F-147")
def test_five_thousand_snapshots_with_a_cap_of_one_hundred(tmp_path):
    w, snaps = snapshot_world()
    r = KIT.run("ebs", tmp_path, w, options={"ebs_share_check": "cap:100"})
    KIT.assert_contract(r)                                   # budget skips never degrade the module
    assert sum(row["count"] for row in KIT.calls(r, "ec2:DescribeSnapshots")) == 2      # two logical listings
    attr_calls = r.fake.calls_for(service="ec2", operation="DescribeSnapshotAttribute")
    assert len(attr_calls) == 100
    items = r.load("resources.json")
    assert len(items) == 5000
    newest = sorted(snaps, key=lambda s: (s["StartTime"], s["SnapshotId"]), reverse=True)[:100]
    assert {c.params["SnapshotId"] for c in attr_calls} == {s["SnapshotId"] for s in newest}
    checked = [i for i in items if i["SharingChecked"]]
    unchecked = [i for i in items if not i["SharingChecked"]]
    assert len(checked) == 100 and all(i["SharedAccounts"] is None for i in unchecked)
    assert sum(1 for i in items if i["Public"]) == 5              # every public one, without attribute calls
    skipped = [row for row in KIT.calls(r, "ec2:DescribeSnapshotAttribute") if row["status"] == "skipped"]
    assert skipped and skipped[0]["count"] == 4900 and skipped[0]["error_code"] == "ShareCheckBudget"


@pytest.mark.finding("F-104")
@pytest.mark.parametrize("value, calls", [("none", 0), ("all", 3), ("cap:2", 2), (None, 3)])
def test_share_check_budget(tmp_path, value, calls):
    options = {} if value is None else {"ebs_share_check": value}
    r = KIT.run("ebs", tmp_path, KIT.clean_world("ec2"), options=options)
    assert len(r.fake.calls_for(service="ec2", operation="DescribeSnapshotAttribute")) == calls


def test_share_check_budget_parsing():
    mod = targets.collector_module("ebs")
    assert mod.share_check_budget("all") is None and mod.share_check_budget("none") == 0
    assert mod.share_check_budget("CAP:250") == 250 and mod.share_check_budget(None) == 1000
    with pytest.raises(ValueError):
        mod.share_check_budget("cap:-1")


@pytest.mark.finding("F-104", "F-059")
def test_without_the_public_listing_public_is_unknown_unless_checked(tmp_path):
    w = KIT.world()
    w.deny("ec2", "DescribeSnapshots", {"RestorableByUserIds": ["all"]})
    r = KIT.run("ebs", tmp_path, w)
    snaps = KIT.by(r.load("resources.json"), "Id")
    assert snaps[PUBLIC]["Public"] is True and snaps[SHARED]["Public"] is False      # from the attribute check
    assert snaps[PRIVATE]["Public"] is None                                          # neither call answered


@pytest.mark.finding("F-080")
def test_snapshot_block_public_access_is_recorded(tmp_path, monkeypatch):
    from tests.fixtures.worlds import acme
    monkeypatch.setitem(acme.REGIONAL[W2]["ec2"], "SnapshotBlockPublicAccessState", "block-all-sharing")
    r = KIT.run("ebs", tmp_path)
    assert r.load("account_settings.json")["SnapshotBlockPublicAccessState"] == "block-all-sharing"
    w = KIT.world()
    w.deny("ec2", "GetSnapshotBlockPublicAccessState")
    r2 = KIT.run("ebs", tmp_path / "denied", w)
    settings = r2.load("account_settings.json")
    assert settings["SnapshotBlockPublicAccessState"] is None and settings["EbsEncryptionByDefault"] is False
    assert KIT.collection_errors(settings) == [("ec2:GetSnapshotBlockPublicAccessState", "denied")]


@pytest.mark.finding("F-103", "F-061")
def test_listing_denied_is_denied_and_settings_still_read(tmp_path):
    r = KIT.run("ebs", tmp_path, region=KIT.W1)              # acme denies DescribeSnapshots in eu-west-1
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("resources.json") == [] and "SnapshotBlockPublicAccessState" in r.load("account_settings.json")


def test_empty_region_is_ok(tmp_path):
    r = KIT.run("ebs", tmp_path, region=KIT.EMPTY_REGION)
    KIT.assert_contract(r)
    assert r.load("resources.json") == []


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    assert KIT.assert_each_api_denied_is_survivable("ebs", tmp_path) == [
        "ec2:DescribeSnapshotAttribute", "ec2:DescribeSnapshots", "ec2:GetEbsEncryptionByDefault",
        "ec2:GetSnapshotBlockPublicAccessState"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    KIT.assert_declared_and_read_only(KIT.run("ebs", tmp_path))
