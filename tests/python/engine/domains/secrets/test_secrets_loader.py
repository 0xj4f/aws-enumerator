"""Secrets Manager / SSM loader (F-059, F-079, F-114, F-116)."""

from __future__ import annotations

import importlib

import pytest

K = importlib.import_module("tests.fixtures.e-data.kit")


def _inventory(data, secret_files=None, param_files=None):
    loader = K.engine("io.loaders.secrets")
    return loader.build_inventory(data, secret_files or {}, param_files or {}, account=K.ACCT, partition="aws")


@pytest.mark.finding("F-114")
def test_secret_policies_are_keyed_by_the_arn_inside_each_file():
    a, b = K.v2_secret("demo/db", policy_status="present"), K.v2_secret("demo_db", policy_status="present")
    files = {K.REGION: [K.secret_policy_file(b, {"Statement": [{"Sid": "b"}]}),
                        K.secret_policy_file(a, {"Statement": [{"Sid": "a"}]}),
                        {"SecretName": "orphan", "ResourcePolicy": {"Statement": []}}]}
    inv = _inventory({"secrets": {K.REGION: [a, b]}}, files)
    sids = {s.name: s.policy["Statement"][0]["Sid"] for s in inv.secrets}
    assert sids == {"demo/db": "a", "demo_db": "b"}


@pytest.mark.finding("F-059", "F-116")
def test_secret_status_fields():
    deleted = K.v2_secret("demo/old", deleted=True)
    denied = K.mark(K.v2_secret("demo/denied", policy_status="denied"), K.denied("secretsmanager:GetResourcePolicy"))
    unreadable = K.v2_secret("demo/raw", policy_status="present")
    inv = _inventory({"secrets": {K.REGION: [deleted, denied, unreadable]}},
                     {K.REGION: [K.secret_policy_file(unreadable, {"_raw": "not json"})]})
    by = {s.name: s for s in inv.secrets}
    assert by["demo/old"].pending_deletion and by["demo/old"].policy_status == "skipped"
    assert by["demo/denied"].policy_status == "denied"
    assert by["demo/denied"].errors.gaps == ("secretsmanager:GetResourcePolicy:denied",)
    assert by["demo/raw"].policy_status == "error" and by["demo/raw"].policy is None


@pytest.mark.finding("F-079")
def test_parameters_use_their_collected_arn_and_legacy_records_get_one():
    v2 = K.v2_param("/demo/a")
    legacy = {"Name": "/demo/b", "Type": "String"}                          # very old record without ARN
    inv = _inventory({"parameters": {K.REGION: [v2, legacy]}})
    assert [p.arn for p in inv.parameters] == [v2["ARN"], f"arn:aws:ssm:{K.REGION}:{K.ACCT}:parameter/demo/b"]
    assert [p.legacy for p in inv.parameters] == [False, True]


@pytest.mark.finding("F-116", "F-059")
def test_parameter_policies_merge_and_unreadable_ones_are_errors():
    ok = K.v2_param("/demo/ok", tier="Advanced", policy_status="present")
    bad = K.v2_param("/demo/bad", tier="Advanced", policy_status="present")
    files = {K.REGION: [K.param_policy_file(ok, {"Statement": [{"Sid": "one"}]}, {"Statement": {"Sid": "two"}}),
                        K.param_policy_file(bad, {"Statement": [{"Sid": "x"}]}, {"_raw": "broken"})]}
    inv = _inventory({"parameters": {K.REGION: [ok, bad]}}, param_files=files)
    by = {p.name: p for p in inv.parameters}
    assert [s["Sid"] for s in by["/demo/ok"].policy["Statement"]] == ["one", "two"]
    assert by["/demo/ok"].policy_status == "present"
    assert by["/demo/bad"].policy_status == "error" and by["/demo/bad"].policy is None


@pytest.mark.finding("F-116", "F-059")
def test_documents_and_inbound_parameters():
    docs = [K.v2_document("demo-a", public=True, shared=["all", K.FOREIGN]),
            K.v2_document("demo-b", public=None, shared=None)]
    inbound = {"Name": "/partner/x", "ARN": f"arn:aws:ssm:{K.REGION}:{K.FOREIGN}:parameter/partner/x",
               "Type": "SecureString", "KeyId": None, "Tier": "Advanced"}
    inv = _inventory({"documents": {K.REGION: docs}, "shared_parameters": {K.REGION: [inbound]}})
    by = {d.name: d for d in inv.documents}
    assert by["demo-a"].public is True and by["demo-a"].shared_accounts == (K.FOREIGN, "all")
    assert by["demo-b"].public is None and by["demo-b"].shared_accounts is None
    (p,) = inv.shared_parameters
    assert p.inbound and p.account == K.FOREIGN and p.policy_status == "skipped"
