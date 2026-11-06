"""Organizations loader: per-type ``PolicyCollection``, ``AvailablePolicyTypes`` and ``ou_path.Complete``
(requests ``c-b-2`` and ``e-policy-2``, F-126)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest

SCP, RCP = "SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY"
ROOT, OU = "r-ab12", "ou-ab12-cd34ef56"


def _write(base, organization: Dict[str, Any], ou_path: Any, policies: List[Dict[str, Any]]) -> None:
    d = base / "organizations"
    d.mkdir(parents=True, exist_ok=True)
    (d / "organization.json").write_text(json.dumps(organization))
    (d / "ou_path.json").write_text(json.dumps(ou_path))
    (d / "policies.json").write_text(json.dumps(policies))


def _org(acct: str, *, collection: Optional[Dict[str, str]] = None, available: Any = "both",
         in_org: Any = True) -> Dict[str, Any]:
    if available == "both":
        available = [{"Type": SCP, "Status": "ENABLED"}, {"Type": RCP, "Status": "ENABLED"}]
    doc = {"AccountId": acct, "InOrganization": in_org, "Id": "o-ab12cd34ef", "ManagementAccountId": "999999999999",
           "IsManagementAccount": False, "AvailablePolicyTypes": available}
    if collection is not None:
        doc["PolicyCollection"] = collection
    return doc


def _path(acct: str, complete: bool = True) -> Dict[str, Any]:
    levels = [{"Id": ROOT, "Type": "ROOT"}, {"Id": OU, "Type": "ORGANIZATIONAL_UNIT"},
              {"Id": acct, "Type": "ACCOUNT"}]
    if complete:
        return {"AccountId": acct, "Complete": True, "Source": "api", "Path": levels}
    return {"AccountId": acct, "Complete": False, "Source": None, "Path": [], "PartialPath": levels[::-1][:2]}


def _policies(acct: str) -> List[Dict[str, Any]]:
    allow = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    deny = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]}
    return [
        {"PolicyId": "p-FullAWSAccess", "Name": "FullAWSAccess", "Type": SCP, "Targets": [ROOT, OU, acct],
         "Content": allow},
        {"PolicyId": "p-demo0deny01", "Name": "demo-deny", "Type": SCP, "Targets": [OU], "Content": deny},
        {"PolicyId": "p-RCPFullAWSAccess", "Name": "RCPFullAWSAccess", "Type": RCP, "Targets": [ROOT, OU, acct],
         "Content": allow},
    ]


@pytest.mark.finding("F-126")
def test_complete_and_imported_sets_are_collected_and_partial_ones_are_unknown(h, tmp_path):
    org = h.engine("io.loaders.org")
    _write(tmp_path, _org(h.ACCT, collection={SCP: "complete", RCP: "partial"}), _path(h.ACCT), _policies(h.ACCT))
    data, status = org.load_org(tmp_path)
    assert status == "ok" and data.policies_collected is True
    assert data.collected_types == (SCP,) and data.policy_collection == {SCP: "complete", RCP: "partial"}
    assert [p.id for p in data.policies] == ["p-FullAWSAccess", "p-demo0deny01"]
    assert [p.id for p in data.uncollected_policies] == ["p-RCPFullAWSAccess"]     # lower bound, kept apart
    assert data.chain(SCP) is not None and data.chain(RCP) is None
    gaps = data.gaps()
    assert set(gaps) == {"org:rcp-unknown"} and "partially collected" in gaps["org:rcp-unknown"]

    _write(tmp_path, _org(h.ACCT, collection={SCP: "imported", RCP: "imported"}), _path(h.ACCT), _policies(h.ACCT))
    data, _ = org.load_org(tmp_path)
    assert data.collected_types == (SCP, RCP) and data.gaps() == {}
    assert len(data.chain(RCP)) == 3


@pytest.mark.finding("F-126")
@pytest.mark.parametrize("state", ["partial", "not_collected"])
def test_an_incomplete_scp_set_never_reaches_the_evaluator(h, tmp_path, state):
    """A partial SCP set would deny everything a missing Allow does not cover: it must be unknown instead."""
    org = h.engine("io.loaders.org")
    policy_org = h.engine("policy.org")
    _write(tmp_path, _org(h.ACCT, collection={SCP: state, RCP: "complete"}), _path(h.ACCT), _policies(h.ACCT))
    data, _ = org.load_org(tmp_path)
    assert data.policies_collected is True and data.collected_types == (RCP,)
    assert set(data.gaps()) == {"org:scp-unknown"}
    model = policy_org.OrgModel.from_org_data(data, account_id=h.ACCT)
    assert model.scp_chain(h.ACCT) is None                  # unknown, never "nothing allowed"
    assert model.rcp_chain(h.ACCT) is not None


@pytest.mark.finding("F-126")
def test_both_types_incomplete_means_no_policy_is_evaluated(h, tmp_path):
    org = h.engine("io.loaders.org")
    _write(tmp_path, _org(h.ACCT, collection={SCP: "partial", RCP: "partial"}), _path(h.ACCT), _policies(h.ACCT))
    data, _ = org.load_org(tmp_path)
    assert data.policies_collected is False and data.policies == [] and len(data.uncollected_policies) == 3
    assert set(data.gaps()) == {"org:scp-unknown", "org:rcp-unknown"}
    model = h.engine("policy.org").OrgModel.from_org_data(data, account_id=h.ACCT)
    assert model.scp_chain(h.ACCT) is None and model.rcp_chain(h.ACCT) is None


@pytest.mark.finding("F-126")
def test_available_policy_types_is_kept_and_a_disabled_type_is_not_a_gap(h, tmp_path):
    org = h.engine("io.loaders.org")
    available = [{"Type": SCP, "Status": "ENABLED"}]
    _write(tmp_path, _org(h.ACCT, collection={SCP: "complete", RCP: "complete"}, available=available),
           _path(h.ACCT), [p for p in _policies(h.ACCT) if p["Type"] == SCP])
    data, _ = org.load_org(tmp_path)
    assert data.available_policy_types == available
    assert data.type_enabled(SCP) is True and data.type_enabled(RCP) is False
    assert data.gaps() == {}                                  # RCPs are disabled: none can apply
    model = h.engine("policy.org").OrgModel.from_org_data(data, account_id=h.ACCT)
    assert model.rcp_chain(h.ACCT) == () and model.scp_chain(h.ACCT) is not None

    _write(tmp_path, _org(h.ACCT, collection={SCP: "complete", RCP: "not_collected"}, available=None),
           _path(h.ACCT), [p for p in _policies(h.ACCT) if p["Type"] == SCP])
    data, _ = org.load_org(tmp_path)
    assert data.available_policy_types is None and data.type_enabled(RCP) is None
    assert set(data.gaps()) == {"org:rcp-unknown"}           # unknown list disables nothing


@pytest.mark.finding("F-126")
def test_an_incomplete_ou_path_is_unknown_even_with_a_partial_path(h, tmp_path):
    org = h.engine("io.loaders.org")
    _write(tmp_path, _org(h.ACCT, collection={SCP: "not_collected", RCP: "not_collected"}),
           _path(h.ACCT, complete=False), [])
    data, _ = org.load_org(tmp_path)
    assert data.path_complete is False and data.path == ()
    assert data.chain(SCP) is None and data.chain(RCP) is None
    gaps = data.gaps()
    assert set(gaps) == {"org:scp-unknown", "org:rcp-unknown"} and "OU path unknown" in gaps["org:scp-unknown"]
    model = h.engine("policy.org").OrgModel.from_org_data(data, account_id=h.ACCT)
    assert model.scp_chain(h.ACCT) is None

    _write(tmp_path, _org(h.ACCT, collection={SCP: "complete", RCP: "complete"}), _path(h.ACCT), _policies(h.ACCT))
    data, _ = org.load_org(tmp_path)
    assert data.path_complete is True and data.path == (ROOT, OU, h.ACCT)


@pytest.mark.finding("F-126")
def test_not_in_an_organization_and_old_reports(h, tmp_path):
    org = h.engine("io.loaders.org")
    _write(tmp_path, _org(h.ACCT, collection={SCP: "not_applicable", RCP: "not_applicable"}, in_org=False,
                          available=None),
           {"AccountId": h.ACCT, "Complete": True, "Source": "api", "Path": []}, [])
    data, _ = org.load_org(tmp_path)
    assert data.in_organization is False and data.collected_types == () and data.gaps() == {}
    # A report written before PolicyCollection existed: a readable policies.json counts for both types.
    old = _org(h.ACCT)
    old.pop("AvailablePolicyTypes")
    _write(tmp_path, old, [ROOT, OU, h.ACCT], _policies(h.ACCT))
    data, _ = org.load_org(tmp_path)
    assert data.policy_collection is None and data.path_complete is None
    assert data.collected_types == (SCP, RCP) and data.gaps() == {} and len(data.chain(SCP)) == 3


@pytest.mark.finding("F-126")
def test_the_pipeline_reports_only_the_unknown_type(h, tmp_path):
    """End to end through ``analyze_run``: a partial RCP set is a report-level gap, the SCPs are evaluated."""
    run = h.Run(tmp_path)
    run.iam.user("demo-user", attached=[run.iam.managed("demo-admin", h.rb.doc(h.rb.allow("*")), customer=True)])
    run.write()
    _write(run.scope("global").path, _org(h.ACCT, collection={SCP: "complete", RCP: "partial"}), _path(h.ACCT),
           _policies(h.ACCT))
    out = run.analyze()
    codes = {g["code"] for g in out.graph["evaluation_gaps"]}
    assert "org:rcp-unknown" in codes and "org:scp-unknown" not in codes
