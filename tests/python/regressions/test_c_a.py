"""Regression tests owned by stream C-A (iam, s3, ec2, vpc, sg, flowlogs, cloudtrail, cloudfront, waf, posture).

Written xfail-first (see test_e_policy.py); C-A flipped them in Wave 1. Each test runs one registry module through
``collectors.base.run_collector`` against the synthetic ``acme`` world (account 111122223333,
tests/fixtures/worlds/acme.py), so it runs today's old-style collector through the legacy adapter and the
migrated ``collect(ctx)`` module after Wave 1 without changes. ``FakeAWS(strict=False)``: calls the world
does not model answer a 501 error instead of aborting, so extra calls a migrated module makes do not hide
the behaviour under test (the C-A stream may still need to teach acme new operations, e.g. GAAD).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fixtures.regressions import support as S
from tests.fixtures.worlds import acme

pytestmark = pytest.mark.collectors

W1, W2, GLOBAL = "eu-west-1", "eu-west-2", "us-east-1"


def world():
    return acme.build_world()


def per_entity_iam_world():
    """GAAD denied, so a migrated IAM collector takes its per-entity fallback (collectors-cli.md §5.1)."""
    w = world()
    w.deny("iam", "GetAccountAuthorizationDetails")
    return w


def policy_document_arns(out: Path):
    arns = set()
    for p in sorted((out / "policy_documents").rglob("*.json")) if (out / "policy_documents").is_dir() else []:
        doc = json.loads(p.read_text())
        if isinstance(doc, dict) and doc.get("PolicyArn"):
            arns.add(doc["PolicyArn"])
    return arns


def write_default_profile(tmp_path, monkeypatch):
    """A ``[default]`` profile on disk so the legacy WAF CLOUDFRONT session rebuild (F-060) succeeds and the
    WAF association logic itself is exercised."""
    d = tmp_path / "aws-config"
    d.mkdir()
    (d / "config").write_text("[default]\nregion = us-east-1\n", encoding="utf-8")
    (d / "credentials").write_text("[default]\naws_access_key_id = AKIAEXAMPLEDEFAULT01\n"
                                   "aws_secret_access_key = example-default-secret-key-not-real-00000\n",
                                   encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(d / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(d / "credentials"))


# ── F-013 (collector side): one document per policy ARN ──────────────────────
@pytest.mark.finding("F-013")
def test_f013_customer_and_aws_policy_with_the_same_name_keep_two_documents(tmp_path, monkeypatch):
    monkeypatch.setitem(acme.CUSTOMER_POLICIES, "ReadOnlyAccess", {
        "id": "ANPAEXAMPLEROCOLLIDE1", "default": "v118", "attachments": 0,
        "versions": {"v118": acme._doc(acme._allow("*", "*"))}})
    run = S.run_module("iam", per_entity_iam_world(), tmp_path)
    arns = policy_document_arns(run.out)
    assert {"arn:aws:iam::aws:policy/ReadOnlyAccess",
            f"arn:aws:iam::{acme.ACCOUNT_ID}:policy/ReadOnlyAccess"} <= arns, sorted(arns)


# ── F-045 / F-047: CloudTrail ────────────────────────────────────────────────
@pytest.mark.finding("F-045")
def test_f045_multi_region_trail_is_visible_outside_its_home_region(tmp_path):
    run = S.run_module("cloudtrail", world(), tmp_path, region=W1)
    trails = run.load("trails.json", [])
    assert isinstance(trails, list)
    assert [t for t in trails if t.get("HomeRegion") == W2 and t.get("IsMultiRegionTrail")], trails
    sent = [c.params for c in run.fake.calls_for(service="cloudtrail", operation="DescribeTrails")]
    assert sent and all(p.get("includeShadowTrails", True) is not False for p in sent), sent


@pytest.mark.finding("F-047")
def test_f047_trail_status_survives_and_insight_selectors_use_trail_name(tmp_path):
    run = S.run_module("cloudtrail", world(), tmp_path, region=W2)
    trails = [t for t in run.load("trails.json", []) if t.get("HomeRegion") == W2]
    assert trails
    for t in trails:
        assert "Error" not in t, t
        assert (t.get("Status") or {}).get("IsLogging") is True, t
    calls = run.fake.calls_for(service="cloudtrail")
    assert [c for c in calls if c.outcome == "ParamValidationError"] == []
    assert all("TrailName" in c.params for c in calls if c.operation == "GetInsightSelectors")


# ── F-053 / F-111: IAM collection phases are isolated ────────────────────────
@pytest.mark.finding("F-053")
def test_f053_denied_list_users_does_not_abort_the_rest_of_iam(tmp_path):
    w = per_entity_iam_world()
    w.deny("iam", "ListUsers")
    run = S.run_module("iam", w, tmp_path)
    files = run.files()
    for name in ("roles.json", "policies.json", "instance_profiles.json"):
        assert name in files, (name, files)
    assert {r.get("RoleName") for r in run.load("roles.json", [])} >= {"demo-admin-role", "demo-app-role"}
    assert policy_document_arns(run.out), "policy documents must still be collected"
    assert any(f.startswith("inline_policies/roles/") for f in files), files
    assert run.result.status == "partial"


@pytest.mark.finding("F-111")
def test_f111_denied_inline_policy_listing_is_recorded_per_entity(tmp_path):
    w = per_entity_iam_world()
    w.deny("iam", "ListRolePolicies", {"RoleName": "demo-app-role"})
    run = S.run_module("iam", w, tmp_path)
    errors = [e for e in run.coverage().get("item_errors", [])
              if e.get("api") == "iam:ListRolePolicies" and "demo-app-role" in str(e.get("resource"))]
    assert errors, run.coverage().get("item_errors")
    assert errors[0].get("status") == "denied"
    assert "inline_policies/roles/demo-irsa-role.json" in run.files()          # other roles still collected


# ── F-058: denied is not "not configured" ────────────────────────────────────
@pytest.mark.finding("F-058")
def test_f058_denied_bucket_policy_is_distinguishable_from_no_policy(tmp_path):
    run = S.run_module("s3", world(), tmp_path)
    buckets = {b.get("Name"): b for b in run.load("buckets.json", []) if isinstance(b, dict)}

    def policy_status(name):
        b = buckets.get(name, {})
        return b.get("PolicyStatus") or (b.get("SubResources") or {}).get("policy")

    assert policy_status("demo-data-bucket") == "present"
    assert policy_status("demo-logs-bucket") == "absent"            # NoSuchBucketPolicy
    assert policy_status("demo-legacy-eu-bucket") == "denied"       # acme denies GetBucketPolicy here


@pytest.mark.finding("F-058")
def test_f058_denied_describe_instances_makes_the_module_denied(tmp_path):
    w = world()
    w.deny("ec2", "DescribeInstances", region=W2)
    run = S.run_module("ec2", w, tmp_path, region=W2)
    assert run.load("instances.json") == []                        # stable shape
    assert run.result.status == "denied", run.result.status


# ── F-060: WAF CLOUDFRONT scope keeps the run's credentials ──────────────────
@pytest.mark.finding("F-060")
def test_f060_waf_cloudfront_uses_the_same_credentials_without_a_profile(tmp_path):
    run = S.run_module("waf_cloudfront", world(), tmp_path)
    assert run.result.status in ("ok", "partial"), (run.result.status, run.result.error)
    assert [a.get("Name") for a in run.load("web_acls.json", [])] == ["demo-cf-acl"]
    keys = {c.access_key_id for c in run.fake.calls_for(service="wafv2") if c.access_key_id}
    assert keys == {"testing"}, keys                                 # the run's (fake) env credentials only


# ── F-106 (collector side): HttpEndpoint is kept ─────────────────────────────
@pytest.mark.finding("F-106")
def test_f106_instance_metadata_options_keep_http_endpoint(tmp_path):
    run = S.run_module("ec2", world(), tmp_path, region=W1)        # the eu-west-1 instance has IMDS disabled
    instances = run.load("instances.json", [])
    assert instances
    assert [(i.get("MetadataOptions") or {}).get("HttpEndpoint") for i in instances] == ["disabled"]


# ── F-107 / F-117: every list call is paginated ──────────────────────────────
@pytest.mark.finding("F-107")
def test_f107_list_buckets_follows_pagination(tmp_path):
    w = world()
    w.page_sizes[("s3", "ListBuckets")] = 2
    run = S.run_module("s3", w, tmp_path)
    names = {b.get("Name") for b in run.load("buckets.json", []) if isinstance(b, dict)}
    assert names == {b["Name"] for b in acme.S3_BUCKETS}, names


@pytest.mark.finding("F-107")
def test_f107_inline_policy_listing_follows_pagination(tmp_path):
    w = per_entity_iam_world()
    w.errors = [r for r in w.errors if (r.service, r.operation) != ("iam", "GetRolePolicy")]
    w.page_sizes[("iam", "ListRolePolicies")] = 1                  # demo-lambda-role has two inline policies
    run = S.run_module("iam", w, tmp_path)
    doc = run.load("inline_policies/roles/demo-lambda-role.json", {}) or {}
    assert set(doc.get("InlinePolicies", {})) == {"demo-lambda-inline", "demo-lambda-logs"}, doc


@pytest.mark.finding("F-117")
@pytest.mark.parametrize("module, op, rel, key", [
    ("ec2", "DescribeInstances", "instances.json", "InstanceId"),
    ("vpc", "DescribeSubnets", "subnets.json", "SubnetId"),
    ("sg", "DescribeSecurityGroups", "security_groups.json", "GroupId"),
])
def test_f117_ec2_vpc_sg_describe_calls_follow_next_token(tmp_path, module, op, rel, key):
    data_key = {"DescribeInstances": "Reservations", "DescribeSubnets": "Subnets",
                "DescribeSecurityGroups": "SecurityGroups"}[op]
    items = acme.REGIONAL[W2]["ec2"][data_key]
    if data_key == "Reservations":
        items = [i for r in items for i in r["Instances"]]
    expected = {item[key] for item in items}
    assert len(expected) >= 2, "the world must hold more than one page"
    w = world()
    w.page_sizes[("ec2", op)] = 1
    run = S.run_module(module, w, tmp_path, region=W2)
    got = {item.get(key) for item in run.load(rel, []) if isinstance(item, dict)}
    assert got == expected


# ── F-118: WAF associations ──────────────────────────────────────────────────
@pytest.mark.finding("F-118")
def test_f118_cloudfront_acl_associations_do_not_use_an_invalid_resource_type(tmp_path, monkeypatch):
    write_default_profile(tmp_path, monkeypatch)
    run = S.run_module("waf_cloudfront", world(), tmp_path)
    acls = run.load("web_acls.json", [])
    assert [a.get("Name") for a in acls] == ["demo-cf-acl"], acls
    assert all("Error" not in a for a in acls), acls
    bad = [c.params for c in run.fake.calls_for(service="wafv2", operation="ListResourcesForWebACL")
           if c.params.get("ResourceType") == "CLOUDFRONT"]
    assert bad == []


@pytest.mark.finding("F-118")
def test_f118_regional_acl_associations_cover_every_resource_type(tmp_path):
    run = S.run_module("waf", world(), tmp_path, region=W2)
    types = {c.params.get("ResourceType") for c in run.fake.calls_for(service="wafv2",
                                                                     operation="ListResourcesForWebACL")}
    assert {"APPLICATION_LOAD_BALANCER", "API_GATEWAY", "COGNITO_USER_POOL"} <= types, types


# ── F-138 (collector side): legacy S3 region constraint ──────────────────────
@pytest.mark.finding("F-138")
def test_f138_eu_location_constraint_is_normalised(tmp_path):
    run = S.run_module("s3", world(), tmp_path)
    regions = {b.get("Name"): b.get("Region") for b in run.load("buckets.json", []) if isinstance(b, dict)}
    assert regions.get("demo-legacy-eu-bucket") == "eu-west-1", regions
    assert regions.get("demo-logs-bucket") == "us-east-1", regions        # empty constraint
