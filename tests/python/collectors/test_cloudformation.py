"""CloudFormation collector (collectors-cli.md §5.10): stacks and StackSets, never parameters or outputs."""

from __future__ import annotations

import importlib

import pytest

from tests.fixtures.worlds import acme

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

W2, ACCT = KIT.W2, KIT.ACCT
CFN_ROLE = acme.role_arn("demo-cfn-role")
STACKSET_ID = "demo-baseline:dec0dec0-0000-4000-8000-0000000000c5"


@pytest.mark.finding("F-113")
def test_stacks_and_stack_sets_with_their_roles(tmp_path):
    r = KIT.run("cloudformation", tmp_path)
    KIT.assert_contract(r)
    items = r.load("resources.json")
    assert [(i["Type"], i["Arn"]) for i in items] == sorted((i["Type"], i["Arn"]) for i in items)
    stacks = KIT.by([i for i in items if i["Type"] == "cfnstack"], "Name")
    assert stacks["demo-app-stack"]["Roles"] == [CFN_ROLE] and stacks["demo-network-stack"]["Roles"] == []
    assert stacks["demo-app-stack"]["Arn"].startswith(f"arn:aws:cloudformation:{W2}:{ACCT}:stack/demo-app-stack/")
    sets = [i for i in items if i["Type"] == "stackset"]
    assert sets == [{"Type": "stackset", "Arn": f"arn:aws:cloudformation:{W2}:{ACCT}:stackset/{STACKSET_ID}",
                     "Name": "demo-baseline", "StackSetId": STACKSET_ID, "Roles": [CFN_ROLE],
                     "AdministrationRoleARN": CFN_ROLE, "ExecutionRoleName": "demo-stackset-execution",
                     "PermissionModel": "SELF_MANAGED", "Status": "ACTIVE"}]


@pytest.mark.finding("F-112")
def test_parameters_and_outputs_are_never_written(tmp_path):
    r = KIT.run("cloudformation", tmp_path)
    KIT.assert_no_canaries(r, "cfn_parameter", "cfn_output", "cfn_stackset_parameter")
    assert all(set(i) & {"Parameters", "Outputs", "Description"} == set() for i in r.load("resources.json"))


@pytest.mark.finding("F-102", "F-059")
def test_a_denied_stack_set_describe_keeps_the_stack_set(tmp_path):
    w = KIT.world()
    w.deny("cloudformation", "DescribeStackSet")
    r = KIT.run("cloudformation", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    ss = [i for i in r.load("resources.json") if i["Type"] == "stackset"][0]
    assert ss["Arn"] == f"arn:aws:cloudformation:{W2}:{ACCT}:stackset/{STACKSET_ID}"   # from the summary id
    assert ss["Roles"] is None and ss["PermissionModel"] == "SELF_MANAGED"
    assert KIT.collection_errors(ss) == [("cloudformation:DescribeStackSet", "denied")]


@pytest.mark.finding("F-103", "F-061")
def test_stack_listing_denied_is_denied_and_stack_sets_still_run(tmp_path):
    w = KIT.world()
    w.deny("cloudformation", "DescribeStacks")
    r = KIT.run("cloudformation", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert [i["Type"] for i in r.load("resources.json")] == ["stackset"]


def test_empty_region_is_ok(tmp_path):
    r = KIT.run("cloudformation", tmp_path, region=KIT.EMPTY_REGION)
    KIT.assert_contract(r)
    assert r.load("resources.json") == []


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    assert KIT.assert_each_api_denied_is_survivable("cloudformation", tmp_path) == [
        "cloudformation:DescribeStackSet", "cloudformation:DescribeStacks", "cloudformation:ListStackSets"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    r = KIT.run("cloudformation", tmp_path)
    KIT.assert_declared_and_read_only(r)
    assert [c.params.get("Status") for c in r.fake.calls_for(service="cloudformation", operation="ListStackSets")] == [
        "ACTIVE"]
