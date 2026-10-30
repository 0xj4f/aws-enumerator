"""Security Hub collector (collectors-cli.md §5.15, F-046): hub enablement and enabled standards; never findings."""

from __future__ import annotations

import importlib

import pytest

from tests.fixtures.worlds import acme

KIT = importlib.import_module("tests.fixtures.c-a.kit")
pytestmark = pytest.mark.collectors

W1, W2 = KIT.W1, KIT.W2


@pytest.mark.finding("F-046")
def test_an_enabled_hub_lists_its_standards(tmp_path):
    r = KIT.run("securityhub", tmp_path, KIT.world())
    KIT.assert_contract(r)
    hub = r.load("hub.json")
    assert hub["Enabled"] is True
    assert hub["HubArn"] == acme.REGIONAL[W2]["securityhub"]["hub"]["HubArn"]
    assert hub["AutoEnableControls"] is True and hub["ControlFindingGenerator"] is None
    (std,) = hub["Standards"]
    assert std["StandardsStatus"] == "READY"
    assert std["StandardsArn"].endswith("standards/aws-foundational-security-best-practices/v/1.0.0")
    assert set(std) == {"StandardsArn", "StandardsSubscriptionArn", "StandardsStatus", "StandardsStatusReason"}


@pytest.mark.finding("F-046")
def test_not_subscribed_is_disabled_not_an_error(tmp_path):
    r = KIT.run("securityhub", tmp_path, KIT.world(), region=W1)   # InvalidAccessException
    KIT.assert_contract(r, statuses=("ok",))
    hub = r.load("hub.json")
    assert (hub["Enabled"], hub["Standards"], hub["HubArn"]) == (False, [], None)
    assert KIT.sent(r, "securityhub", "GetEnabledStandards") == []
    assert [(row["status"], row["not_configured"]) for row in KIT.calls(r, "securityhub:DescribeHub")] == [
        ("ok", True)]


@pytest.mark.finding("F-046", "F-058")
def test_denied_hub_is_unknown_and_the_module_denied(tmp_path):
    w = KIT.world()
    w.deny("securityhub", "DescribeHub")
    r = KIT.run("securityhub", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    hub = r.load("hub.json")
    assert (hub["Enabled"], hub["Standards"]) == (None, None)


@pytest.mark.finding("F-046", "F-058")
def test_unreadable_standards_are_unknown(tmp_path):
    w = KIT.world()
    w.deny("securityhub", "GetEnabledStandards")
    r = KIT.run("securityhub", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    hub = r.load("hub.json")
    assert (hub["Enabled"], hub["Standards"]) == (True, None)
