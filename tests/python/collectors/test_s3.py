"""S3 collector (collectors-cli.md §5.2): denied vs not configured, region normalisation, pagination, account
Block Public Access, policy status, sub-resource modes, per-bucket region clients."""

from __future__ import annotations

import importlib

import pytest

from tests.fixtures.worlds import acme
from tests.support.fakeaws import Request

KIT = importlib.import_module("tests.fixtures.c-a.kit")
pytestmark = pytest.mark.collectors

BASIC_OPS = {"GetBucketPolicy", "GetBucketPolicyStatus", "GetBucketAcl", "GetPublicAccessBlock",
             "GetBucketEncryption", "GetBucketNotificationConfiguration", "GetBucketOwnershipControls"}
FULL_ONLY_OPS = {"GetBucketVersioning", "GetBucketTagging", "GetBucketLogging", "GetBucketCors",
                 "GetBucketWebsite", "GetBucketReplication"}


def buckets(r):
    return KIT.by(r.load("buckets.json"), "Name")


@pytest.mark.finding("F-058")
def test_denied_and_not_configured_are_different_states(tmp_path):
    r = KIT.run("s3", tmp_path, KIT.world())
    KIT.assert_contract(r, statuses=("partial",))
    b = buckets(r)
    assert set(b) == {x["Name"] for x in acme.S3_BUCKETS}
    assert b["demo-data-bucket"]["SubResources"]["policy"] == "present"
    assert b["demo-logs-bucket"]["SubResources"]["policy"] == "absent"            # NoSuchBucketPolicy
    assert b["demo-legacy-eu-bucket"]["SubResources"]["policy"] == "denied"       # acme denies it
    assert b["demo-public-site"]["SubResources"]["public_access_block"] == "absent"
    for name, rec in b.items():
        assert rec["PolicyStatus"] == rec["SubResources"]["policy"], name
        assert rec["Arn"] == f"arn:aws:s3:::{name}"
    denied = b["demo-denied-bucket"]
    assert {v for k, v in denied["SubResources"].items() if k in
            ("policy", "acl", "public_access_block", "encryption", "notifications", "ownership_controls")} == {"denied"}
    assert len(KIT.collection_errors(denied)) == 7
    assert "CollectionErrors" not in b["demo-data-bucket"] and "CollectionErrors" not in b["demo-logs-bucket"]
    assert KIT.collection_errors(b["demo-legacy-eu-bucket"]) == [("s3:GetBucketPolicy", "denied"),
                                                                 ("s3:GetBucketAcl", "denied")]
    files = r.files()
    assert "policies/demo-data-bucket.json" in files and "policies/demo-logs-bucket.json" not in files
    assert r.load("policies/demo-data-bucket.json")["Statement"][1]["Sid"] == "DenyInsecure"
    assert r.load("acls/demo-logs-bucket.json")["Grants"][1]["Permission"] == "WRITE"
    assert r.load("public_access_block/demo-data-bucket.json")["RestrictPublicBuckets"] is True
    assert r.load("ownership_controls/demo-data-bucket.json") == {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}
    assert r.load("notifications/demo-data-bucket.json")["QueueConfigurations"][0]["Id"] == "demo-to-queue"
    no_policy = [row for row in KIT.calls(r, "s3:GetBucketPolicy") if row["not_configured"]]
    assert [(row["status"], row["error_code"]) for row in no_policy] == [("ok", "NoSuchBucketPolicy")]


@pytest.mark.finding("F-023", "F-105")
def test_policy_status_is_aws_verdict_and_only_asked_when_a_policy_exists(tmp_path):
    r = KIT.run("s3", tmp_path, KIT.world())
    b = buckets(r)
    assert b["demo-public-site"]["PolicyIsPublic"] is True
    assert b["demo-legacy-eu-bucket"]["PolicyIsPublic"] is True                   # status readable, policy not
    assert b["demo-data-bucket"]["PolicyIsPublic"] is False
    assert b["demo-logs-bucket"]["PolicyIsPublic"] is False                       # no policy: not public by one
    assert b["demo-denied-bucket"]["PolicyIsPublic"] is None                      # unknown
    asked = {p["Bucket"] for p in KIT.sent(r, "s3", "GetBucketPolicyStatus")}
    assert "demo-logs-bucket" not in asked and {"demo-public-site", "demo-data-bucket"} <= asked
    assert r.load("policy_status/demo-public-site.json") == {"IsPublic": True}


@pytest.mark.finding("F-138")
def test_region_comes_from_the_listing_and_legacy_constraints_are_normalised(tmp_path):
    r = KIT.run("s3", tmp_path / "listing", KIT.clean_world())
    assert KIT.sent(r, "s3", "GetBucketLocation") == []                           # BucketRegion is in ListBuckets
    w = KIT.clean_world()
    listing = w.handlers[("s3", "ListBuckets")]

    def without_region(req: Request):
        resp = listing(req)
        return dict(resp, Buckets=[{k: v for k, v in b.items() if k != "BucketRegion"} for b in resp["Buckets"]])

    w.handlers[("s3", "ListBuckets")] = without_region
    r = KIT.run("s3", tmp_path / "location", w)
    regions = {n: rec["Region"] for n, rec in buckets(r).items()}
    assert regions == {"demo-data-bucket": "eu-west-2", "demo-denied-bucket": "eu-west-2",
                       "demo-legacy-eu-bucket": "eu-west-1", "demo-logs-bucket": "us-east-1",
                       "demo-public-site": "eu-west-1"}
    assert len(KIT.sent(r, "s3", "GetBucketLocation")) == len(acme.S3_BUCKETS)
    s3 = KIT.module("s3")
    assert [s3.normalise_region(v) for v in ("EU", "", None, "ap-south-2")] == \
        ["eu-west-1", "us-east-1", "us-east-1", "ap-south-2"]


@pytest.mark.finding("F-107")
def test_list_buckets_follows_every_page(tmp_path):
    w = KIT.clean_world()
    w.page_sizes[("s3", "ListBuckets")] = 2
    r = KIT.run("s3", tmp_path, w)
    pages = KIT.sent(r, "s3", "ListBuckets")
    assert len(pages) == 3 and all(p.get("MaxBuckets") == 1000 for p in pages)
    assert [bool(p.get("ContinuationToken")) for p in pages] == [False, True, True]
    assert sorted(buckets(r)) == sorted(b["Name"] for b in acme.S3_BUCKETS)
    assert KIT.is_sorted_by(r.load("buckets.json"), "Name")


@pytest.mark.finding("F-023")
def test_account_public_access_block_configured_absent_and_denied(tmp_path):
    r = KIT.run("s3", tmp_path / "set", KIT.clean_world())
    assert r.load("account_public_access_block.json") == {"Configured": True, **acme.S3_ACCOUNT_PAB}
    assert KIT.sent(r, "s3control", "GetPublicAccessBlock") == [{"AccountId": KIT.ACCT}]
    w = KIT.clean_world()
    w.fail("s3control", "GetPublicAccessBlock", "NoSuchPublicAccessBlockConfiguration", status=404)
    r = KIT.run("s3", tmp_path / "absent", w)
    assert r.load("account_public_access_block.json") == {
        "Configured": False, "BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False}
    assert r.result.status == "ok"
    w = KIT.clean_world()
    w.deny("s3control", "GetPublicAccessBlock")
    r = KIT.run("s3", tmp_path / "denied", w)
    assert set(r.load("account_public_access_block.json").values()) == {None}
    assert r.result.status == "partial"


@pytest.mark.finding("F-109")
def test_basic_mode_makes_at_most_seven_calls_per_bucket(tmp_path):
    r = KIT.run("s3", tmp_path, KIT.clean_world())
    per_bucket = {}
    for c in r.fake.calls_for(service="s3"):
        if "Bucket" in c.params:
            per_bucket.setdefault(c.params["Bucket"], []).append(c.operation)
    for name, ops in per_bucket.items():
        assert len(ops) <= 7, (name, ops)
        assert set(ops) <= BASIC_OPS, (name, ops)
    assert len(per_bucket["demo-data-bucket"]) == 7
    skipped = {row["api"] for row in KIT.coverage(r)["calls"] if row["status"] == "skipped"}
    assert {"s3:GetBucketVersioning", "s3:GetBucketReplication"} <= skipped
    statuses = buckets(r)["demo-data-bucket"]["SubResources"]
    assert {statuses[k] for k in ("versioning", "tagging", "logging", "cors", "website", "replication")} == {"skipped"}


@pytest.mark.finding("F-105")
def test_full_mode_adds_versioning_tags_logging_cors_website_and_replication(tmp_path):
    r = KIT.run("s3", tmp_path, KIT.clean_world(), options={"s3_subresources": "full"})
    KIT.assert_contract(r)
    ops = {c.operation for c in r.fake.calls_for(service="s3")}
    assert FULL_ONLY_OPS <= ops
    assert r.load("website/demo-public-site.json")["IndexDocument"] == {"Suffix": "index.html"}
    assert r.load("replication/demo-data-bucket.json")["Rules"][0]["Destination"]["Account"] == KIT.EXT
    assert r.load("tagging/demo-data-bucket.json") == [{"Key": "env", "Value": "demo"},
                                                        {"Key": "owner", "Value": "demo-team"}]
    assert r.load("cors/demo-public-site.json")[0]["AllowedOrigins"] == ["*"]
    assert r.load("logging/demo-data-bucket.json") == {"TargetBucket": "demo-logs-bucket", "TargetPrefix": "data/"}
    b = buckets(r)
    assert b["demo-data-bucket"]["SubResources"]["website"] == "absent"
    assert b["demo-public-site"]["SubResources"]["website"] == "present"
    assert b["demo-logs-bucket"]["SubResources"]["logging"] == "absent"


def test_each_bucket_is_read_with_a_client_in_its_region(tmp_path):
    r = KIT.run("s3", tmp_path, KIT.clean_world())
    regions = {}
    for c in r.fake.calls_for(service="s3", operation="GetBucketAcl"):
        regions[c.params["Bucket"]] = c.region
    assert regions == {"demo-data-bucket": "eu-west-2", "demo-denied-bucket": "eu-west-2",
                       "demo-legacy-eu-bucket": "eu-west-1", "demo-logs-bucket": "us-east-1",
                       "demo-public-site": "eu-west-1"}


def test_unknown_subresource_mode_falls_back_to_basic(tmp_path):
    r = KIT.run("s3", tmp_path, KIT.clean_world(), options={"s3_subresources": "everything"})
    assert not {c.operation for c in r.fake.calls_for(service="s3")} & FULL_ONLY_OPS
