"""AWS Config collector (registry name ``config``, file ``config_service.py``; collectors-cli.md §5.15, F-046):
recorders with their recording status, delivery channels."""

from __future__ import annotations

import importlib

import pytest

KIT = importlib.import_module("tests.fixtures.c-a.kit")
pytestmark = pytest.mark.collectors

W1, W2 = KIT.W1, KIT.W2


@pytest.mark.finding("F-046")
def test_recorders_carry_their_status_and_channels_are_listed(tmp_path):
    r = KIT.run("config", tmp_path, KIT.world())
    KIT.assert_contract(r)
    (rec,) = r.load("recorders.json")
    assert rec["name"] == "default" and rec["recordingGroup"]["allSupported"] is True
    assert rec["status"] == {"recording": True, "lastStatus": "SUCCESS", "lastStartTime": "2024-01-01T10:00:00Z",
                             "lastStopTime": None, "lastStatusChangeTime": "2024-01-15T10:00:00Z",
                             "lastErrorCode": None, "lastErrorMessage": None}
    assert r.load("delivery_channels.json") == [{"name": "default", "s3BucketName": "demo-logs-bucket",
                                                  "s3KeyPrefix": "config"}]


@pytest.mark.finding("F-046")
def test_a_region_without_config_writes_empty_lists_and_skips_the_status_call(tmp_path):
    r = KIT.run("config", tmp_path, KIT.world(), region=W1)
    KIT.assert_contract(r)
    assert r.load("recorders.json") == [] and r.load("delivery_channels.json") == []
    assert KIT.sent(r, "config", "DescribeConfigurationRecorderStatus") == []


@pytest.mark.finding("F-046", "F-058")
def test_unreadable_status_is_null_and_partial(tmp_path):
    w = KIT.world()
    w.deny("config", "DescribeConfigurationRecorderStatus")
    r = KIT.run("config", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    (rec,) = r.load("recorders.json")
    assert rec["status"] is None


@pytest.mark.finding("F-046", "F-058")
def test_denied_recorders_keep_the_channels(tmp_path):
    w = KIT.world()
    w.deny("config", "DescribeConfigurationRecorders")
    r = KIT.run("config", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("recorders.json") == [] and len(r.load("delivery_channels.json")) == 1


def test_registry_name_and_aliases(tmp_path):
    spec = KIT.spec("config")
    assert (spec.name, spec.output_dir, spec.module.rsplit(".", 1)[-1]) == ("config", "config", "config_service")
    assert KIT.registry().get("config_service").name == "config"
