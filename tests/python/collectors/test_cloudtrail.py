"""CloudTrail collector (collectors-cli.md §5.4): shadow trails listed, details by ARN with one call each,
event selectors, insight selectors, organization trails of another account, CloudTrail Lake stores."""

from __future__ import annotations

import importlib

import pytest

from tests.fixtures.worlds import acme

KIT = importlib.import_module("tests.fixtures.c-a.kit")
WORLDS = importlib.import_module("tests.fixtures.c-a.worlds")
pytestmark = pytest.mark.collectors

W1, W2 = KIT.W1, KIT.W2
TRAIL = acme.REGIONAL[W2]["cloudtrail"]["trails"][0]
ARN = TRAIL["TrailARN"]


def trails(r):
    return KIT.by(r.load("trails.json"), "TrailARN")


@pytest.mark.finding("F-047", "F-046")
def test_home_region_trail_details_use_the_arn_and_each_call_stands_alone(tmp_path):
    r = KIT.run("cloudtrail", tmp_path, KIT.world())
    KIT.assert_contract(r)
    assert KIT.sent(r, "cloudtrail", "GetTrailStatus") == [{"Name": ARN}]
    assert KIT.sent(r, "cloudtrail", "GetEventSelectors") == [{"TrailName": ARN}]
    assert KIT.sent(r, "cloudtrail", "GetInsightSelectors") == [{"TrailName": ARN}]
    assert [c for c in r.fake.calls_for(service="cloudtrail") if c.outcome == "ParamValidationError"] == []
    t = trails(r)[ARN]
    assert (t["IsShadow"], t["OwnerAccountId"]) == (False, KIT.ACCT)
    assert t["Status"]["IsLogging"] is True
    assert t["EventSelectors"] == [{"ReadWriteType": "All", "IncludeManagementEvents": True, "DataResources": []}]
    assert t["AdvancedEventSelectors"] == []
    assert t["InsightSelectors"] == [{"InsightType": "ApiCallRateInsight"}]
    assert t["KmsKeyId"] == TRAIL["KmsKeyId"] and t["LogFileValidationEnabled"] is True


@pytest.mark.finding("F-045", "F-167")
def test_shadow_trails_are_listed_but_not_detailed_outside_their_home_region(tmp_path):
    r = KIT.run("cloudtrail", tmp_path, KIT.world(), region=W1)
    KIT.assert_contract(r)
    assert all("includeShadowTrails" not in p for p in KIT.sent(r, "cloudtrail", "DescribeTrails"))
    t = trails(r)[ARN]
    assert (t["IsShadow"], t["HomeRegion"], t["IsMultiRegionTrail"]) == (True, W2, True)
    assert (t["Status"], t["EventSelectors"], t["InsightSelectors"]) == (None, None, None)
    for op in ("GetTrailStatus", "GetEventSelectors", "GetInsightSelectors"):
        assert KIT.sent(r, "cloudtrail", op) == [], op


@pytest.mark.finding("F-047")
def test_a_denied_status_keeps_the_event_selectors(tmp_path):
    w = KIT.world()
    w.deny("cloudtrail", "GetTrailStatus")
    r = KIT.run("cloudtrail", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    t = trails(r)[ARN]
    assert t["Status"] is None
    assert t["EventSelectors"][0]["ReadWriteType"] == "All"
    assert KIT.collection_errors(t) == [("cloudtrail:GetTrailStatus", "denied")]
    assert KIT.item_errors(r) == [{"resource": ARN, "api": "cloudtrail:GetTrailStatus", "status": "denied",
                                   "error_code": "AccessDeniedException"}]


@pytest.mark.finding("F-047")
def test_insight_not_enabled_is_an_empty_list_and_no_selectors_means_no_call(tmp_path):
    w = KIT.world()
    w.fail("cloudtrail", "GetInsightSelectors", "InsightNotEnabledException")
    r = KIT.run("cloudtrail", tmp_path, w)
    KIT.assert_contract(r)
    t = trails(r)[ARN]
    assert t["InsightSelectors"] == [] and t["Status"]["IsLogging"] is True
    assert "CollectionErrors" not in t
    w = KIT.world()
    describe = w.handlers[("cloudtrail", "DescribeTrails")]
    w.handlers[("cloudtrail", "DescribeTrails")] = lambda req: {
        "trailList": [dict(t, HasInsightSelectors=False) for t in describe(req)["trailList"]]}
    r = KIT.run("cloudtrail", tmp_path / "none", w)
    assert KIT.sent(r, "cloudtrail", "GetInsightSelectors") == []
    assert trails(r)[ARN]["InsightSelectors"] == []


@pytest.mark.finding("F-045")
def test_another_accounts_organization_trail_is_recorded_without_degrading(tmp_path):
    r = KIT.run("cloudtrail", tmp_path, WORLDS.org_trail())
    KIT.assert_contract(r, statuses=("ok",))
    org = trails(r)[WORLDS.ORG_TRAIL_ARN]
    assert (org["IsShadow"], org["OwnerAccountId"], org["IsOrganizationTrail"]) == (True, WORLDS.MGMT_ACCOUNT, True)
    assert org["Status"] is None and org["EventSelectors"] is None
    assert KIT.collection_errors(org) == [("cloudtrail:GetTrailStatus", "denied"),
                                          ("cloudtrail:GetEventSelectors", "denied")]
    assert KIT.sent(r, "cloudtrail", "GetTrailStatus") == [{"Name": ARN}, {"Name": WORLDS.ORG_TRAIL_ARN}]
    rows = [row for row in KIT.calls(r, "cloudtrail:GetTrailStatus") if row["status"] == "denied"]
    assert [row["optional"] for row in rows] == [True]
    assert {e["resource"] for e in KIT.item_errors(r)} == {WORLDS.ORG_TRAIL_ARN}


@pytest.mark.finding("F-046")
def test_event_data_stores_are_collected(tmp_path):
    r = KIT.run("cloudtrail", tmp_path, KIT.world())
    (store,) = r.load("event_data_stores.json")
    assert store["Name"] == "demo-lake" and store["MultiRegionEnabled"] is True
    assert store["CreatedTimestamp"] == "2024-01-02T10:00:00Z"
    r = KIT.run("cloudtrail", tmp_path / "w1", KIT.world(), region=W1)
    assert r.load("event_data_stores.json") == []


@pytest.mark.finding("F-058")
def test_denied_describe_trails_makes_the_module_denied(tmp_path):
    w = KIT.world()
    w.deny("cloudtrail", "DescribeTrails")
    r = KIT.run("cloudtrail", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("trails.json") == [] and len(r.load("event_data_stores.json")) == 1
