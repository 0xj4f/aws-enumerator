"""Organizations collector (collectors-cli.md §5.15, registry.md §4.2): membership, OU path, SCPs/RCPs, --scp-file."""

from __future__ import annotations

import importlib
import json

import pytest

from tests.fixtures.worlds import acme
from tests.support import targets
from tests.support.fakeaws import botocore_error

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

ACCT, EXT = KIT.ACCT, KIT.EXT
ROOT, OU = acme.ORG_ROOT_ID, acme.ORG_OU_ID
SCP, RCP = "SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY"


def org_module():
    return targets.collector_module("organizations")


def run(tmp_path, w=None, **kw):
    return KIT.run("organizations", tmp_path, w, region="global", **kw)


def files(r):
    return r.load("organization.json"), r.load("ou_path.json"), r.load("policies.json")


@pytest.mark.finding("F-126")
def test_member_account_gets_membership_path_and_control_policies(tmp_path):
    r = run(tmp_path)
    KIT.assert_contract(r)
    org, path, policies = files(r)
    assert org["InOrganization"] is True and org["Id"] == acme.ORG_ID
    assert org["ManagementAccountId"] == EXT and org["IsManagementAccount"] is False
    assert org["PolicyCollection"] == {SCP: "complete", RCP: "complete"}
    assert path["Complete"] is True and path["Source"] == "api"
    assert [lvl["Id"] for lvl in path["Path"]] == [ROOT, OU, ACCT]
    assert [lvl["Type"] for lvl in path["Path"]] == ["ROOT", "ORGANIZATIONAL_UNIT", "ACCOUNT"]
    assert path["Path"][1]["Name"] == "demo-workloads"
    by_id = KIT.by(policies, "PolicyId")
    assert set(by_id) == {"p-FullAWSAccess", "p-demo0deny01", "p-demo0region", "p-RCPFullAWSAccess"}
    assert by_id["p-FullAWSAccess"]["Targets"] == sorted([ACCT, OU, ROOT])
    assert by_id["p-demo0deny01"]["Targets"] == [OU]
    assert by_id["p-demo0region"]["Targets"] == [ACCT]
    assert by_id["p-RCPFullAWSAccess"]["Type"] == RCP and by_id["p-RCPFullAWSAccess"]["Targets"] == [ROOT]
    assert by_id["p-demo0region"]["Content"]["Statement"][0]["Effect"] == "Deny"   # parsed, not a string
    assert all(p["Source"] == "api" and "CollectionErrors" not in p for p in policies)
    assert [(p["Type"], p["PolicyId"]) for p in policies] == sorted((p["Type"], p["PolicyId"]) for p in policies)


@pytest.mark.finding("F-112", "F-126")
def test_management_account_email_is_never_stored(tmp_path):
    r = run(tmp_path)
    assert KIT.S.grep_tree(acme.ORGANIZATION["MasterAccountEmail"], r.out) == []
    assert KIT.S.grep_tree("@example.com", r.out) == []


@pytest.mark.finding("F-126")
def test_engine_org_loader_reads_the_chain(tmp_path):
    """The output is what E-core's org loader (engine/io/loaders/org.py) expects: a full SCP chain, no gap."""
    r = run(tmp_path)
    loader = targets.engine_module("io.loaders.org")
    data, status = loader.load_org(r.unit_dir)
    assert status == "ok" and data.in_organization is True and data.is_management_account is False
    assert data.path == (ROOT, OU, ACCT)
    chain = data.chain(SCP)
    assert [sorted(p.id for p in level) for level in chain] == [
        ["p-FullAWSAccess"], ["p-FullAWSAccess", "p-demo0deny01"], ["p-FullAWSAccess", "p-demo0region"]]
    assert data.gaps() == {}


@pytest.mark.finding("F-126", "F-059")
def test_not_in_an_organization_is_ok_and_complete(tmp_path):
    w = KIT.world()
    w.fail("organizations", "DescribeOrganization", "AWSOrganizationsNotInUseException",
           "Your account is not a member of an organization.")
    r = run(tmp_path, w)
    doc = KIT.assert_contract(r)
    org, path, policies = files(r)
    assert org["InOrganization"] is False and org["IsManagementAccount"] is False
    assert org["PolicyCollection"] == {SCP: "not_applicable", RCP: "not_applicable"}
    assert path == {"AccountId": ACCT, "Complete": True, "Source": "api", "Path": []}
    assert policies == []
    assert KIT.operations(r) == [("organizations", "DescribeOrganization")]
    assert doc["calls"][0]["not_configured"] is True


@pytest.mark.finding("F-126", "F-059")
def test_member_account_denied_the_walk_stays_ok_and_marks_policies_unknown(tmp_path):
    w = KIT.world()
    w.deny("organizations", "ListParents")
    r = run(tmp_path, w)
    KIT.assert_contract(r)                                   # optional calls never degrade the module
    org, path, policies = files(r)
    assert org["InOrganization"] is True
    assert org["PolicyCollection"] == {SCP: "not_collected", RCP: "not_collected"}
    assert path["Complete"] is False and path["Path"] == [] and path["Source"] is None
    assert policies == []
    assert ("organizations", "ListPoliciesForTarget") not in KIT.operations(r)
    assert [c["status"] for c in KIT.calls(r, "organizations:ListParents")] == ["denied"]
    loader = targets.engine_module("io.loaders.org")
    data, _status = loader.load_org(r.unit_dir)
    assert set(data.gaps()) == {"org:scp-unknown", "org:rcp-unknown"}


@pytest.mark.finding("F-126", "F-102", "F-059")
def test_an_unreadable_policy_is_kept_and_the_set_is_partial(tmp_path):
    w = KIT.world()
    w.deny("organizations", "DescribePolicy", {"PolicyId": "p-demo0region"})
    r = run(tmp_path, w)
    KIT.assert_contract(r)
    org, _path, policies = files(r)
    assert org["PolicyCollection"] == {SCP: "partial", RCP: "complete"}
    region = KIT.by(policies, "PolicyId")["p-demo0region"]
    assert region["Content"] is None and region["Targets"] == [ACCT]
    assert KIT.collection_errors(region) == [("organizations:DescribePolicy", "denied")]


@pytest.mark.finding("F-126", "F-103")
def test_a_botocore_error_while_listing_keeps_the_rest(tmp_path):
    w = KIT.world()
    w.raise_exc("organizations", "ListPoliciesForTarget",
                botocore_error("EndpointConnectionError", endpoint_url="https://organizations.us-east-1.amazonaws.com/"),
                match={"TargetId": OU})
    r = run(tmp_path, w)
    KIT.assert_contract(r)
    org, path, policies = files(r)
    assert path["Complete"] is True
    assert org["PolicyCollection"] == {SCP: "partial", RCP: "partial"}
    assert "p-demo0deny01" not in KIT.by(policies, "PolicyId")           # only attached to the OU
    assert KIT.by(policies, "PolicyId")["p-FullAWSAccess"]["Targets"] == sorted([ACCT, ROOT])


@pytest.mark.finding("F-126")
def test_describe_organization_denied_is_denied_with_stable_files(tmp_path):
    w = KIT.world()
    w.deny("organizations", "DescribeOrganization")
    w.deny("organizations", "ListParents")
    r = run(tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    org, path, policies = files(r)
    assert org["InOrganization"] is None and org["IsManagementAccount"] is None
    assert KIT.collection_errors(org) == [("organizations:DescribeOrganization", "denied")]
    assert path["Path"] == [] and policies == []


# ── --scp-file ───────────────────────────────────────────────────────────────
def _export(**extra):
    doc = {"OuPath": [ROOT, OU, ACCT], "Policies": [
        {"PolicyId": "p-FullAWSAccess", "Name": "FullAWSAccess", "Type": SCP, "AwsManaged": True,
         "Targets": [ROOT, OU, ACCT], "Content": json.dumps(acme.ORG_POLICIES["p-FullAWSAccess"]["content"])},
        {"Policy": {"PolicySummary": {"Id": "p-demo0region", "Name": "demo-region-lock", "Type": SCP,
                                      "AwsManaged": False},
                    "Content": json.dumps(acme.ORG_POLICIES["p-demo0region"]["content"])},
         "Targets": [{"TargetId": ACCT}]},
    ]}
    doc.update(extra)
    return doc


@pytest.mark.finding("F-126")
def test_scp_file_fills_in_for_a_member_account_that_cannot_read_organizations(tmp_path):
    scp = tmp_path / "scps.json"
    scp.write_text(json.dumps(_export()))
    w = KIT.world()
    w.deny("organizations", "ListParents")
    r = run(tmp_path / "run", w, options={"scp_file": str(scp)})
    KIT.assert_contract(r)
    org, path, policies = files(r)
    assert org["PolicyCollection"] == {SCP: "imported", RCP: "imported"}
    assert path["Complete"] is True and path["Source"] == "import"
    assert [lvl["Id"] for lvl in path["Path"]] == [ROOT, OU, ACCT]
    assert [(p["PolicyId"], p["Source"], p["Targets"]) for p in policies] == [
        ("p-FullAWSAccess", "import", sorted([ACCT, OU, ROOT])), ("p-demo0region", "import", [ACCT])]
    assert policies[1]["Content"]["Statement"][0]["Effect"] == "Deny"


@pytest.mark.finding("F-126")
def test_scp_file_is_ignored_when_the_api_answered_completely(tmp_path, caplog):
    scp = tmp_path / "scps.json"
    scp.write_text(json.dumps(_export()))
    r = run(tmp_path / "run", options={"scp_file": str(scp)})
    _org, _path, policies = files(r)
    assert {p["Source"] for p in policies} == {"api"} and len(policies) == 4
    assert "--scp-file ignored" in caplog.text


@pytest.mark.finding("F-126", "F-103")
def test_an_invalid_scp_file_is_rejected_whole_and_named_without_its_directory(tmp_path):
    scp = tmp_path / "private-dir" / "bad.json"
    scp.parent.mkdir()
    scp.write_text(json.dumps({"Policies": [{"PolicyId": "p-x", "Type": SCP, "Content": "{}"}]}))
    w = KIT.world()
    w.deny("organizations", "ListParents")
    r = run(tmp_path / "run", w, options={"scp_file": str(scp)})
    doc = KIT.assert_contract(r, statuses=("partial",))
    section = [s for s in doc["sections"] if s["name"] == "scp_import"][0]
    assert section["status"] == "error" and section["error_type"] == "ScpImportError"
    assert "private-dir" not in json.dumps(doc) and "Targets" in section["message"]
    _org, _path, policies = files(r)
    assert policies == []


@pytest.mark.parametrize("data, needle", [
    ({"Policies": []}, "no policies"),
    ({"OuPath": [ROOT, "999999999999"], "Policies": [{}]}, "must end with the target account"),
    ([{"PolicyId": "p-1", "Type": "TAG_POLICY", "Targets": [ACCT], "Content": {"Statement": []}}], "Type"),
    ([{"PolicyId": "p-1", "Type": SCP, "Targets": [ACCT], "Content": "not json"}], "policy document"),
    ([{"PolicyId": "p-1", "Type": SCP, "Targets": [ACCT], "Content": {"Statement": []}}] * 2, "duplicate"),
    ("text", "expected an object"),
])
def test_scp_import_validation(data, needle):
    mod = org_module()
    with pytest.raises(mod.ScpImportError, match=needle):
        mod.parse_scp_import(data, ACCT)


def test_scp_import_accepts_this_modules_own_policies_file(tmp_path):
    """A policies.json written by a management-account run can be fed to a member-account run."""
    own = files(run(tmp_path))[2]
    policies, path = org_module().parse_scp_import(own, ACCT)
    assert path is None and [p["PolicyId"] for p in policies] == [p["PolicyId"] for p in own]
    assert all(p["Source"] == "import" for p in policies)


def test_a_too_large_scp_file_is_refused(tmp_path, monkeypatch):
    mod = org_module()
    monkeypatch.setattr(mod, "MAX_IMPORT_BYTES", 10)
    scp = tmp_path / "big.json"
    scp.write_text(json.dumps(_export()))
    with pytest.raises(mod.ScpImportError, match="larger than"):
        mod.load_scp_file(scp, ACCT)
    with pytest.raises(mod.ScpImportError, match="cannot be read"):
        mod.load_scp_file(tmp_path / "missing.json", ACCT)


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    apis = KIT.assert_each_api_denied_is_survivable("organizations", tmp_path, region="global")
    assert apis == ["organizations:DescribeOrganization", "organizations:DescribeOrganizationalUnit",
                    "organizations:DescribePolicy", "organizations:ListParents",
                    "organizations:ListPoliciesForTarget"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    r = run(tmp_path)
    KIT.assert_declared_and_read_only(r)
    spec = KIT.spec("organizations")
    assert not spec.planned and spec.scope == "global" and spec.groups == ("@identity", "@posture")
    assert spec.actions == ("organizations:DescribeOrganization",)
    assert spec.probe == ("organizations", "DescribeOrganization", ())
