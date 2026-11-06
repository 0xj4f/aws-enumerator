"""Organizations model: SCP / RCP chains and their evaluation (F-126; engine.md §2.4 steps 2-3)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from aws_enumerator.engine.model import Decision
from aws_enumerator.engine.policy.org import OrgModel

pytestmark = pytest.mark.finding("F-126")

ACCT = "111122223333"
FULL = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
DENY_IAM = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"},
                                                   {"Effect": "Deny", "Action": "iam:*", "Resource": "*"}]}
PATH = {"AccountId": ACCT, "Complete": True, "Path": [{"Id": "r-ex12", "Type": "ROOT"},
                                                      {"Id": "ou-ex12-11111111", "Type": "ORGANIZATIONAL_UNIT"},
                                                      {"Id": ACCT, "Type": "ACCOUNT"}]}
ORG = {"InOrganization": True, "Id": "o-exampleorgid", "ManagementAccountId": "000000000000",
       "IsManagementAccount": False,
       "AvailablePolicyTypes": [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}]}


def _policies(ou_doc=FULL):
    return [{"PolicyId": "p-full", "Name": "FullAWSAccess", "Type": "SERVICE_CONTROL_POLICY",
             "Targets": ["r-ex12", ACCT], "Content": FULL},
            {"PolicyId": "p-ou", "Name": "ou-guard", "Type": "SERVICE_CONTROL_POLICY", "Targets": ["ou-ex12-11111111"],
             "Content": ou_doc}]


def test_chain_per_level_root_to_account():
    org = OrgModel.from_documents(ORG, PATH, _policies(DENY_IAM), account_id=ACCT)
    chain = org.scp_chain(ACCT)
    assert chain is not None and len(chain) == 3
    assert org.org_path == "o-exampleorgid/r-ex12/ou-ex12-11111111/"
    assert org.rcp_chain(ACCT) == ()                    # RCPs not enabled: no RCP applies


def test_unknown_cases():
    assert OrgModel.from_documents(None, None, None, account_id=ACCT).scp_chain(ACCT) is None
    assert OrgModel.from_documents(ORG, PATH, None, account_id=ACCT).scp_chain(ACCT) is None
    no_account_level = [p for p in _policies() if p["PolicyId"] != "p-full"]
    assert OrgModel.from_documents(ORG, PATH, no_account_level, account_id=ACCT).scp_chain(ACCT) is None
    incomplete = dict(PATH, Complete=False)
    assert OrgModel.from_documents(ORG, incomplete, _policies(), account_id=ACCT).scp_chain(ACCT) is None
    untargeted = [{"PolicyId": "p-x", "Type": "SERVICE_CONTROL_POLICY", "Content": FULL}]
    assert OrgModel.from_documents(ORG, PATH, untargeted, account_id=ACCT).scp_chain(ACCT) is None


def test_not_in_org_and_management_account_have_no_scps():
    assert OrgModel.from_documents({"InOrganization": False}, None, None, account_id=ACCT).scp_chain(ACCT) == ()
    mgmt = dict(ORG, IsManagementAccount=True)
    assert OrgModel.from_documents(mgmt, PATH, _policies(DENY_IAM), account_id=ACCT).scp_chain(ACCT) == ()


def test_from_org_data_adapter_reads_the_loader_object():
    data = SimpleNamespace(in_organization=True, org_id="o-exampleorgid", management_account="000000000000",
                           is_management_account=False, path=("r-ex12", "ou-ex12-11111111", ACCT),
                           policies_collected=True, available_policy_types=ORG["AvailablePolicyTypes"],
                           policies=[SimpleNamespace(id=p["PolicyId"], arn=None, name=p["Name"], type=p["Type"],
                                                     targets=tuple(p["Targets"]), document=p["Content"])
                                     for p in _policies(DENY_IAM)])
    org = OrgModel.from_org_data(data, account_id=ACCT)
    assert len(org.scp_chain(ACCT)) == 3
    assert OrgModel.from_org_data(SimpleNamespace(in_organization=None, org_id=None), account_id=ACCT) \
        .scp_chain(ACCT) is None
    not_collected = SimpleNamespace(in_organization=True, org_id="o-x", path=("r-ex12", ACCT), policies_collected=False)
    assert OrgModel.from_org_data(not_collected, account_id=ACCT).scp_chain(ACCT) is None


def test_scp_deny_reaches_the_evaluator(kit):
    role = kit.role("dev", [{"Effect": "Allow", "Action": "*", "Resource": "*"}])
    kit.org = OrgModel.from_documents(ORG, PATH, _policies(DENY_IAM), account_id=kit.account)
    ev = kit.evaluator()
    assert ev.evaluate(role, "iam:CreateUser", "*").decision is Decision.DENY
    assert ev.evaluate(role, "s3:GetObject", "arn:aws:s3:::b/k").decision is Decision.ALLOW
    assert "org:scp-unknown" not in ev.report_gaps()


def test_unknown_org_is_a_report_gap_not_a_downgrade(kit):
    role = kit.role("dev", [{"Effect": "Allow", "Action": "*", "Resource": "*"}])
    ev = kit.evaluator()
    assert ev.evaluate(role, "iam:CreateUser", "*").decision is Decision.ALLOW
    assert "org:scp-unknown" in ev.report_gaps()


def test_principal_org_keys_come_from_the_org_model(kit):
    role = kit.role("dev", [{"Effect": "Allow", "Action": "s3:*", "Resource": "*",
                             "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}}}])
    kit.org = OrgModel.from_documents(ORG, PATH, _policies(), account_id=kit.account)
    assert kit.evaluator().evaluate(role, "s3:GetObject", "arn:aws:s3:::b/k").decision is Decision.ALLOW
    kit.org = OrgModel.from_documents({"InOrganization": False}, None, None, account_id=kit.account)
    assert kit.evaluator().evaluate(role, "s3:GetObject", "arn:aws:s3:::b/k").decision is Decision.NOT_ALLOWED
