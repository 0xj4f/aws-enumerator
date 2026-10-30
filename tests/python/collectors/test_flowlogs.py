"""Flow-logs collector (collectors-cli.md §5.3): paginated, failures recorded, the file is always a list."""

from __future__ import annotations

import importlib

import pytest

from tests.fixtures.worlds import acme

KIT = importlib.import_module("tests.fixtures.c-a.kit")
pytestmark = pytest.mark.collectors

W1, W2 = KIT.W1, KIT.W2


@pytest.mark.finding("F-107", "F-117")
def test_every_page_of_flow_logs_is_collected_and_sorted(tmp_path):
    r = KIT.run("flowlogs", tmp_path, KIT.world())          # acme serves one flow log per page
    KIT.assert_contract(r)
    expected = sorted(f["FlowLogId"] for f in acme.REGIONAL[W2]["ec2"]["FlowLogs"])
    assert [f["FlowLogId"] for f in r.load("flowlogs.json")] == expected
    assert len(KIT.sent(r, "ec2", "DescribeFlowLogs")) == len(expected) == 2
    first = acme.REGIONAL[W2]["ec2"]["FlowLogs"][0]
    got = KIT.by(r.load("flowlogs.json"), "FlowLogId")[first["FlowLogId"]]
    assert got["ResourceId"] == first["ResourceId"]


@pytest.mark.finding("F-058")
def test_a_read_timeout_is_recorded_and_the_file_is_still_written(tmp_path):
    r = KIT.run("flowlogs", tmp_path, KIT.world(), region=W1)   # acme: ReadTimeoutError in eu-west-1
    KIT.assert_contract(r, statuses=("partial",))
    assert r.load("flowlogs.json") == []
    assert [(row["status"], row["error_code"], row["primary"]) for row in KIT.calls(r, "ec2:DescribeFlowLogs")] == [
        ("error", "ReadTimeoutError", True)]


@pytest.mark.finding("F-058")
def test_denied_flow_logs_make_the_module_denied(tmp_path):
    w = KIT.world()
    w.deny("ec2", "DescribeFlowLogs")
    r = KIT.run("flowlogs", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("flowlogs.json") == []
