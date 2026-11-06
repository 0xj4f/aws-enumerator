"""WAF collectors (collectors-cli.md §5.5): ``waf`` (REGIONAL, every region) and ``waf_cloudfront`` (CLOUDFRONT
scope, global unit, the run's own credentials): NextMarker loops, associations of every resource type,
CloudFront associations through ListDistributionsByWebACLId, failures recorded per item."""

from __future__ import annotations

import importlib
import inspect
import re

import pytest

from tests.fixtures.worlds import acme

KIT = importlib.import_module("tests.fixtures.c-a.kit")
WORLDS = importlib.import_module("tests.fixtures.c-a.worlds")
pytestmark = pytest.mark.collectors

W1, W2 = KIT.W1, KIT.W2
TYPES = ["APPLICATION_LOAD_BALANCER", "API_GATEWAY", "APPSYNC", "COGNITO_USER_POOL", "APP_RUNNER_SERVICE",
         "VERIFIED_ACCESS_INSTANCE", "AMPLIFY"]
ACLS = {a["Name"]: a for a in acme.REGIONAL[W2]["waf"]["web_acls"]}
API_ACL, REGIONAL_ACL = ACLS["demo-api-acl"]["ARN"], ACLS["demo-regional-acl"]["ARN"]


def acls(r):
    return KIT.by(r.load("web_acls.json"), "Name")


# ── REGIONAL ─────────────────────────────────────────────────────────────────
@pytest.mark.finding("F-118")
def test_regional_associations_cover_every_resource_type(tmp_path):
    r = KIT.run("waf", tmp_path, KIT.world())
    KIT.assert_contract(r)
    sent = KIT.sent(r, "wafv2", "ListResourcesForWebACL")
    for arn in (API_ACL, REGIONAL_ACL):
        assert [p["ResourceType"] for p in sent if p["WebACLArn"] == arn] == TYPES
    assert "CLOUDFRONT" not in {p["ResourceType"] for p in sent}
    a = acls(r)
    assert a["demo-api-acl"]["AssociatedResources"] == [
        {"ResourceType": "API_GATEWAY", "Arn": "arn:aws:apigateway:eu-west-2::/restapis/demorest01/stages/prod"},
        {"ResourceType": "COGNITO_USER_POOL",
         "Arn": f"arn:aws:cognito-idp:{W2}:{KIT.ACCT}:userpool/eu-west-2_DemoPool1"}]
    assert [x["ResourceType"] for x in a["demo-regional-acl"]["AssociatedResources"]] == ["APPLICATION_LOAD_BALANCER"]
    assert a["demo-api-acl"]["UncheckedResourceTypes"] == []
    assert a["demo-api-acl"]["Scope"] == "REGIONAL" and a["demo-api-acl"]["Capacity"] == 700
    assert a["demo-api-acl"]["Rules"] == ACLS["demo-api-acl"]["Rules"]


@pytest.mark.finding("F-118")
def test_a_type_that_needs_another_service_permission_fails_once_and_is_skipped_after(tmp_path):
    w = KIT.world()
    w.deny("wafv2", "ListResourcesForWebACL", {"ResourceType": "APPSYNC"})
    r = KIT.run("waf", tmp_path, w)
    KIT.assert_contract(r, statuses=("ok",))            # expected denial of an optional type
    appsync = [p for p in KIT.sent(r, "wafv2", "ListResourcesForWebACL") if p["ResourceType"] == "APPSYNC"]
    assert len(appsync) == 1                            # not asked again for the second ACL
    for acl in acls(r).values():
        assert acl["UncheckedResourceTypes"] == ["APPSYNC"]
        assert acl["AssociatedResources"] is not None
    rows = {(row["status"], row["optional"]) for row in KIT.calls(r, "wafv2:ListResourcesForWebACL")}
    assert ("denied", True) in rows and ("skipped", True) in rows


@pytest.mark.finding("F-118", "F-058")
def test_a_denied_alb_lookup_is_an_item_error_and_all_denied_is_unknown(tmp_path):
    w = KIT.world()
    w.deny("wafv2", "ListResourcesForWebACL", {"ResourceType": "APPLICATION_LOAD_BALANCER"})
    r = KIT.run("waf", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    regional = acls(r)["demo-regional-acl"]
    assert regional["UncheckedResourceTypes"] == ["APPLICATION_LOAD_BALANCER"]
    assert regional["AssociatedResources"] == []                    # other types were read and found nothing
    assert KIT.collection_errors(regional) == [("wafv2:ListResourcesForWebACL", "denied")]
    assert {e["resource"] for e in KIT.item_errors(r)} == {API_ACL, REGIONAL_ACL}
    w = KIT.world()
    w.deny("wafv2", "ListResourcesForWebACL")
    r = KIT.run("waf", tmp_path / "all", w)
    for acl in acls(r).values():
        assert acl["AssociatedResources"] is None and acl["UncheckedResourceTypes"] == TYPES


@pytest.mark.finding("F-107")
def test_every_wafv2_listing_follows_next_marker(tmp_path):
    r = KIT.run("waf", tmp_path, WORLDS.waf_paged())
    KIT.assert_contract(r)
    for op, filename, key in (("ListWebACLs", "web_acls.json", "Name"), ("ListRuleGroups", "rule_groups.json", "Name"),
                              ("ListIPSets", "ip_sets.json", "Name"),
                              ("ListLoggingConfigurations", "logging_configs.json", "ResourceArn")):
        pages = KIT.sent(r, "wafv2", op)
        assert len(pages) == 2, op
        assert [bool(p.get("NextMarker")) for p in pages] == [False, True], op
        assert all(p["Limit"] == 100 and p["Scope"] == "REGIONAL" for p in pages), op
        assert len(r.load(filename)) == 2, filename
        assert KIT.is_sorted_by(r.load(filename), "ARN" if key == "Name" else key), filename
    ips = KIT.by(r.load("ip_sets.json"), "Name")
    assert ips["demo-partner-ips"]["Addresses"] == ["192.0.2.0/24", "198.51.100.0/24"]


@pytest.mark.finding("F-058")
def test_a_denied_rule_group_listing_keeps_the_web_acls(tmp_path):
    r = KIT.run("waf", tmp_path, KIT.world(), region=W1)   # acme denies ListRuleGroups in eu-west-1
    KIT.assert_contract(r, statuses=("partial",))
    assert r.load("rule_groups.json") == []
    assert [a["Name"] for a in r.load("web_acls.json")] == ["demo-west-acl"]


def test_a_denied_web_acl_detail_keeps_the_record_with_unknown_rules(tmp_path):
    w = KIT.world()
    w.deny("wafv2", "GetWebACL", {"Name": "demo-api-acl"})
    r = KIT.run("waf", tmp_path, w)
    api = acls(r)["demo-api-acl"]
    assert (api["Rules"], api["DefaultAction"], api["Capacity"]) == (None, None, None)
    assert api["Description"] == "demo-api-acl (acme)"                  # from the listing
    assert KIT.collection_errors(api) == [("wafv2:GetWebACL", "denied")]
    assert len(api["AssociatedResources"]) == 2


# ── CLOUDFRONT ───────────────────────────────────────────────────────────────
@pytest.mark.finding("F-060")
def test_cloudfront_scope_uses_the_runs_credentials_in_the_global_region(tmp_path):
    r = KIT.run("waf_cloudfront", tmp_path, KIT.world())
    KIT.assert_contract(r)
    calls = r.fake.calls_for(service="wafv2")
    assert calls and {c.region for c in calls} == {"us-east-1"}
    assert {c.params["Scope"] for c in calls if "Scope" in c.params} == {"CLOUDFRONT"}
    assert {c.access_key_id for c in calls + r.fake.calls_for(service="cloudfront")} == {"testing"}
    (acl,) = r.load("web_acls.json")
    assert (acl["Name"], acl["Scope"]) == ("demo-cf-acl", "CLOUDFRONT")
    assert [s["Name"] for s in r.load("ip_sets.json")] == ["demo-cf-allowlist"]


@pytest.mark.finding("F-060")
def test_no_collector_rebuilds_a_session_from_a_profile():
    for name in ("waf", "waf_cloudfront"):
        source = inspect.getsource(KIT.module(name))
        assert not re.search(r"profile_name\s*=|Session\(|__class__\(", source), name


@pytest.mark.finding("F-118")
def test_cloudfront_associations_come_from_list_distributions_by_web_acl_id(tmp_path):
    r = KIT.run("waf_cloudfront", tmp_path, KIT.world())
    assert KIT.sent(r, "wafv2", "ListResourcesForWebACL") == []
    assert KIT.sent(r, "cloudfront", "ListDistributionsByWebACLId") == [{"WebACLId": acme.CF_ACL_ARN,
                                                                          "MaxItems": "100"}]
    (acl,) = r.load("web_acls.json")
    assert acl["AssociatedResources"] == [
        {"ResourceType": "CLOUDFRONT", "Arn": f"arn:aws:cloudfront::{KIT.ACCT}:distribution/E1DEMOEXAMPLE01"}]
    assert acl["UncheckedResourceTypes"] == []


@pytest.mark.finding("F-118")
def test_a_denied_distribution_lookup_leaves_the_associations_unknown(tmp_path):
    w = KIT.world()
    w.deny("cloudfront", "ListDistributionsByWebACLId")
    r = KIT.run("waf_cloudfront", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    (acl,) = r.load("web_acls.json")
    assert acl["AssociatedResources"] is None and acl["UncheckedResourceTypes"] == ["CLOUDFRONT"]
    assert KIT.collection_errors(acl) == [("cloudfront:ListDistributionsByWebACLId", "denied")]
    assert acl["Rules"] is not None


@pytest.mark.finding("F-060")
def test_a_cloudfront_scope_failure_leaves_the_regional_module_untouched(tmp_path):
    w = KIT.world()
    w.deny("wafv2", "ListWebACLs", region="us-east-1")
    cf = KIT.run("waf_cloudfront", tmp_path / "cf", w)
    KIT.assert_contract(cf, statuses=("denied",))
    assert cf.load("web_acls.json") == []
    regional = KIT.run("waf", tmp_path / "regional", w)
    KIT.assert_contract(regional, statuses=("ok",))
    assert sorted(acls(regional)) == ["demo-api-acl", "demo-regional-acl"]
    assert {c.params["Scope"] for c in regional.fake.calls_for(service="wafv2") if "Scope" in c.params} == \
        {"REGIONAL"}
