"""SSM collector (collectors-cli.md §5.7): parameter projection, parameter policies, documents, instances."""

from __future__ import annotations

import copy
import importlib

import pytest

from tests.fixtures.worlds import acme
from tests.support.fakeaws import botocore_error

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

W2, ACCT, EXT = KIT.W2, KIT.ACCT, KIT.EXT
ADVANCED = f"arn:aws:ssm:{W2}:{ACCT}:parameter/demo/shared/advanced"


@pytest.fixture
def advanced_parameter(monkeypatch):
    """acme plus an Advanced-tier parameter of the account shared through a resource policy."""
    ssm = copy.deepcopy(acme.REGIONAL[W2]["ssm"])
    ssm["parameters"].append({"Name": "/demo/shared/advanced", "ARN": ADVANCED, "Type": "String",
                              "LastModifiedDate": acme.ts(6), "LastModifiedUser": f"arn:aws:iam::{ACCT}:user/demo-ci",
                              "Version": 1, "Tier": "Advanced", "Policies": [], "DataType": "text"})
    ssm["parameter_policies"][ADVANCED] = {"Version": "2012-10-17", "Statement": [{
        "Sid": "ShareOut", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{EXT}:root"},
        "Action": "ssm:GetParameter", "Resource": ADVANCED}]}
    monkeypatch.setitem(acme.REGIONAL[W2], "ssm", ssm)
    return ADVANCED


@pytest.mark.finding("F-112")
def test_parameters_are_projected_without_operator_identity_or_free_text(tmp_path):
    r = KIT.run("ssm", tmp_path)
    KIT.assert_contract(r)
    params = r.load("parameters.json")
    assert [p["Name"] for p in params] == ["/demo/app/endpoint", "/demo/app/hosts", "/demo/db/password"]
    for p in params:
        assert set(p) == {"Name", "ARN", "Type", "KeyId", "Tier", "DataType", "Version", "LastModifiedDate",
                          "PolicyStatus"}
        assert p["PolicyStatus"] == "absent"                 # Standard tier: no policy possible, no call
    assert not r.fake.calls_for(service="ssm", operation="GetResourcePolicies")
    KIT.assert_no_canaries(r, "ssm_description")
    assert KIT.S.grep_tree("demo-alice", r.out) == []        # LastModifiedUser
    assert KIT.S.grep_tree("10.20.1.10", r.out) == [] and KIT.S.grep_tree("compute.internal", r.out) == []


@pytest.mark.finding("F-112")
def test_keep_sensitive_metadata_keeps_last_modified_user_and_description(tmp_path):
    r = KIT.run("ssm", tmp_path, options={"keep_sensitive_metadata": True})
    endpoint = KIT.by(r.load("parameters.json"), "Name")["/demo/app/endpoint"]
    assert endpoint["LastModifiedUser"].endswith(":user/demo-alice")
    assert acme.CANARIES["ssm_description"] in endpoint["Description"]


@pytest.mark.finding("F-116", "F-114")
def test_an_advanced_parameter_policy_is_written_to_a_hashed_file(tmp_path, advanced_parameter):
    r = KIT.run("ssm", tmp_path)
    KIT.assert_contract(r)
    item = KIT.by(r.load("parameters.json"), "ARN")[advanced_parameter]
    assert item["PolicyStatus"] == "present"
    files = KIT.S.files_under(r.out / "parameter_policies")
    assert len(files) == 1 and files[0].name.endswith(".json") and "/" not in files[0].name
    doc = KIT.S.load_json(files[0])
    assert doc["ParameterArn"] == advanced_parameter
    assert doc["Policies"][0]["Policy"]["Statement"][0]["Sid"] == "ShareOut"
    assert [c.params["ResourceArn"] for c in r.fake.calls_for(service="ssm", operation="GetResourcePolicies")] == [
        advanced_parameter]


@pytest.mark.finding("F-059", "F-102")
def test_a_denied_parameter_policy_is_marked_and_the_parameter_kept(tmp_path, advanced_parameter):
    w = KIT.world()
    w.deny("ssm", "GetResourcePolicies")
    r = KIT.run("ssm", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    item = KIT.by(r.load("parameters.json"), "ARN")[advanced_parameter]
    assert item["PolicyStatus"] == "denied"
    assert KIT.collection_errors(item) == [("ssm:GetResourcePolicies", "denied")]


@pytest.mark.finding("F-116")
def test_parameters_shared_with_the_account_are_listed_separately(tmp_path):
    r = KIT.run("ssm", tmp_path)
    shared = r.load("parameters_shared_with_account.json")
    assert [p["ARN"] for p in shared] == [f"arn:aws:ssm:{W2}:{EXT}:parameter/shared/demo-config"]
    assert "PolicyStatus" not in shared[0]
    assert [c.params.get("Shared") for c in r.fake.calls_for(service="ssm", operation="DescribeParameters")] == [
        None, None, True]                                      # two pages of own parameters, then shared


@pytest.mark.finding("F-116")
def test_public_and_shared_documents(tmp_path):
    r = KIT.run("ssm", tmp_path)
    docs = KIT.by(r.load("documents.json"), "Name")
    assert set(docs) == {"demo-run-shell", "demo-patch-baseline", "demo-private-doc"}     # Owner=Self only
    assert docs["demo-run-shell"]["Public"] is True and docs["demo-run-shell"]["SharedAccounts"] == []
    assert docs["demo-patch-baseline"]["Public"] is False and docs["demo-patch-baseline"]["SharedAccounts"] == [EXT]
    assert docs["demo-private-doc"]["Public"] is False and docs["demo-private-doc"]["SharedAccounts"] == []
    assert docs["demo-run-shell"]["Arn"] == f"arn:aws:ssm:{W2}:{ACCT}:document/demo-run-shell"


@pytest.mark.finding("F-059", "F-104")
def test_a_denied_document_permission_is_null_not_false(tmp_path):
    w = KIT.world()
    w.deny("ssm", "DescribeDocumentPermission", {"Name": "demo-run-shell"})
    r = KIT.run("ssm", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    doc = KIT.by(r.load("documents.json"), "Name")["demo-run-shell"]
    assert doc["Public"] is None and doc["SharedAccounts"] is None
    assert KIT.collection_errors(doc) == [("ssm:DescribeDocumentPermission", "denied")]


def test_managed_instances_keep_identity_and_role_only(tmp_path):
    r = KIT.run("ssm", tmp_path)
    instances = r.load("managed_instances.json")
    assert [i["InstanceId"] for i in instances] == sorted(i["InstanceId"] for i in instances) and instances
    assert all("IPAddress" not in i and "ComputerName" not in i for i in instances)


@pytest.mark.finding("F-103")
def test_a_failing_section_keeps_the_other_files(tmp_path):
    w = KIT.world()
    w.raise_exc("ssm", "ListDocuments",
                botocore_error("EndpointConnectionError", endpoint_url="https://ssm.eu-west-2.amazonaws.com/"))
    r = KIT.run("ssm", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    assert r.load("documents.json") == []
    assert len(r.load("parameters.json")) == 3 and r.load("managed_instances.json")


@pytest.mark.finding("F-103", "F-061")
def test_parameter_listing_denied_is_denied_and_the_rest_still_runs(tmp_path):
    w = KIT.world()
    w.deny("ssm", "DescribeParameters")
    r = KIT.run("ssm", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("parameters.json") == [] and r.load("parameters_shared_with_account.json") == []
    assert len(r.load("documents.json")) == 3


def test_empty_region_is_ok(tmp_path):
    r = KIT.run("ssm", tmp_path, region=KIT.EMPTY_REGION)
    KIT.assert_contract(r)
    assert all(r.load(name) == [] for name in ("parameters.json", "documents.json", "managed_instances.json"))


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path, advanced_parameter):
    assert KIT.assert_each_api_denied_is_survivable("ssm", tmp_path) == [
        "ssm:DescribeDocumentPermission", "ssm:DescribeInstanceInformation", "ssm:DescribeParameters",
        "ssm:GetResourcePolicies", "ssm:ListDocuments"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path, advanced_parameter):
    r = KIT.run("ssm", tmp_path)
    KIT.assert_declared_and_read_only(r)
    ops = {o for _s, o in KIT.operations(r)}
    assert not ops & {"GetParameter", "GetParameters", "GetParametersByPath", "GetDocument"}
