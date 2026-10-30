"""GuardDuty collector (collectors-cli.md §5.15, F-046): detectors, status and protection plans; never findings."""

from __future__ import annotations

import importlib

import pytest

from tests.fixtures.worlds import acme
from tests.support.fakeaws import Request

KIT = importlib.import_module("tests.fixtures.c-a.kit")
pytestmark = pytest.mark.collectors

W1, W2 = KIT.W1, KIT.W2
DETECTOR = acme.REGIONAL[W2]["guardduty"]["detectors"][0]["DetectorId"]
SECOND = "dec0dec0dec0dec0dec0dec0dec0dec9"


@pytest.mark.finding("F-046")
def test_detectors_are_described_with_their_protection_plans(tmp_path):
    r = KIT.run("guardduty", tmp_path, KIT.world())
    KIT.assert_contract(r)
    (d,) = r.load("detectors.json")
    assert d["DetectorId"] == DETECTOR
    assert d["Arn"] == f"arn:aws:guardduty:{W2}:{KIT.ACCT}:detector/{DETECTOR}"
    assert (d["Status"], d["FindingPublishingFrequency"]) == ("ENABLED", "SIX_HOURS")
    assert d["ServiceRole"].endswith(":role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty")
    assert d["Features"] == [
        {"Name": "EKS_AUDIT_LOGS", "Status": "DISABLED", "AdditionalConfiguration": []},
        {"Name": "RUNTIME_MONITORING", "Status": "DISABLED", "AdditionalConfiguration": []},
        {"Name": "S3_DATA_EVENTS", "Status": "ENABLED", "AdditionalConfiguration": []}]
    assert {c.operation for c in r.fake.calls_for(service="guardduty")} == {"ListDetectors", "GetDetector"}


@pytest.mark.finding("F-046")
def test_a_region_without_guardduty_is_an_empty_list(tmp_path):
    r = KIT.run("guardduty", tmp_path, KIT.world(), region=W1)
    KIT.assert_contract(r)
    assert r.load("detectors.json") == []
    assert KIT.sent(r, "guardduty", "GetDetector") == []


@pytest.mark.finding("F-046", "F-058")
def test_an_unreadable_detector_is_kept_with_unknown_fields(tmp_path):
    w = KIT.world()
    w.deny("guardduty", "GetDetector")
    r = KIT.run("guardduty", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    (d,) = r.load("detectors.json")
    assert d["DetectorId"] == DETECTOR
    assert (d["Status"], d["Features"], d["DataSources"]) == (None, None, None)
    assert KIT.collection_errors(d) == [("guardduty:GetDetector", "denied")]


@pytest.mark.finding("F-046", "F-107")
def test_detector_listing_follows_next_token(tmp_path):
    w = KIT.world()
    listing, getter = w.handlers[("guardduty", "ListDetectors")], w.handlers[("guardduty", "GetDetector")]

    def list_detectors(req: Request):
        resp = listing(req)
        return {"DetectorIds": resp["DetectorIds"] + ([SECOND] if req.region == W2 else [])}

    def get_detector(req: Request):
        if req.params["DetectorId"] == SECOND:
            return {"Status": "DISABLED", "ServiceRole": "", "CreatedAt": "2024-01-03T10:00:00.000Z"}
        return getter(req)

    w.handlers[("guardduty", "ListDetectors")] = list_detectors
    w.handlers[("guardduty", "GetDetector")] = get_detector
    w.page_sizes[("guardduty", "ListDetectors")] = 1
    r = KIT.run("guardduty", tmp_path, w)
    assert len(KIT.sent(r, "guardduty", "ListDetectors")) == 2
    detectors = r.load("detectors.json")
    assert [d["DetectorId"] for d in detectors] == sorted([DETECTOR, SECOND])
    assert KIT.by(detectors, "DetectorId")[SECOND]["Features"] is None      # not returned: unknown
