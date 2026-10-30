"""KMS collector (collectors-cli.md §5.9): keys kept on describe failure, policy status, null grants."""

from __future__ import annotations

import importlib

import pytest

from tests.support.fakeaws import botocore_error

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

W2, ACCT = KIT.W2, KIT.ACCT
A1, A2, A3, A4 = (f"1111aaaa-0000-4000-8000-0000000000a{i}" for i in range(1, 5))


def arn(key_id, region=W2):
    return f"arn:aws:kms:{region}:{ACCT}:key/{key_id}"


@pytest.mark.finding("F-102", "F-059")
def test_keys_are_kept_with_markers_when_calls_are_denied(tmp_path):
    r = KIT.run("kms", tmp_path)
    KIT.assert_contract(r, statuses=("partial",))
    keys = r.load("keys.json")
    assert [k["Arn"] for k in keys] == sorted(arn(k) for k in (A1, A2, A3, A4))
    by_id = KIT.by(keys, "KeyId")
    a1 = by_id[A1]
    assert a1["KeyManager"] == "CUSTOMER" and a1["PolicyStatus"] == "present" and "CollectionErrors" not in a1
    assert a1["Aliases"] == ["alias/demo-key", "alias/demo-key-secondary"]
    assert a1["KeySpec"] == "SYMMETRIC_DEFAULT" and a1["KeyUsage"] == "ENCRYPT_DECRYPT" and a1["MultiRegion"] is False
    grant = a1["Grants"][0]
    assert grant["GranteePrincipal"].endswith(":role/demo-lambda-role")
    assert set(grant) == {"GrantId", "Name", "GranteePrincipal", "RetiringPrincipal", "Operations", "Constraints",
                          "IssuingAccount"}
    a2 = by_id[A2]
    assert a2["KeyManager"] == "AWS" and a2["PolicyStatus"] == "skipped" and a2["Grants"] == []
    a3 = by_id[A3]                                            # DescribeKey denied: kept (F-102)
    assert a3["Arn"] == arn(A3) and a3["KeyManager"] is None and a3["KeyState"] is None
    assert KIT.collection_errors(a3) == [("kms:DescribeKey", "denied")]
    assert a3["PolicyStatus"] == "present"                    # the policy is still attempted
    a4 = by_id[A4]
    assert a4["PolicyStatus"] == "denied" and a4["Grants"] is None    # unknown is null, never [] (F-059)
    assert KIT.collection_errors(a4) == [("kms:GetKeyPolicy", "denied"), ("kms:ListGrants", "denied")]
    policy = r.load(f"key_policies/{A1}.json")
    assert policy["Arn"] == arn(A1) and policy["Policy"]["Statement"][1]["Sid"] == "AppDecrypt"
    assert not (r.out / "key_policies" / f"{A2}.json").exists() and not (r.out / "key_policies" / f"{A4}.json").exists()
    assert len(r.fake.calls_for(service="kms", operation="ListKeys")) == 2       # 3 per page


@pytest.mark.finding("F-059")
def test_unreadable_aliases_are_null_for_every_key(tmp_path):
    r = KIT.run("kms", tmp_path, region=KIT.W1)               # acme denies ListAliases in eu-west-1
    KIT.assert_contract(r, statuses=("partial",))
    keys = r.load("keys.json")
    assert [k["Aliases"] for k in keys] == [None]
    assert keys[0]["PolicyStatus"] == "present"


@pytest.mark.finding("F-103", "F-102")
def test_a_botocore_error_on_describe_keeps_the_key(tmp_path):
    w = KIT.clean_world("kms")
    w.raise_exc("kms", "DescribeKey", botocore_error("ReadTimeoutError", endpoint_url="https://kms.eu-west-2.amazonaws.com/"),
                match={"KeyId": A1})
    r = KIT.run("kms", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    a1 = KIT.by(r.load("keys.json"), "KeyId")[A1]
    assert a1["Arn"] == arn(A1) and a1["Grants"] and a1["PolicyStatus"] == "present"
    assert a1["CollectionErrors"] == [{"api": "kms:DescribeKey", "status": "error", "error_code": "ReadTimeoutError"}]


@pytest.mark.finding("F-103", "F-061")
def test_listing_denied_is_denied_with_an_empty_list(tmp_path):
    w = KIT.world()
    w.deny("kms", "ListKeys")
    r = KIT.run("kms", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("keys.json") == []


def test_empty_region_is_ok(tmp_path):
    r = KIT.run("kms", tmp_path, region=KIT.EMPTY_REGION)
    KIT.assert_contract(r)
    assert r.load("keys.json") == []


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    assert KIT.assert_each_api_denied_is_survivable("kms", tmp_path) == [
        "kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListAliases", "kms:ListGrants", "kms:ListKeys"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    r = KIT.run("kms", tmp_path)
    KIT.assert_declared_and_read_only(r)
    assert not {o for _s, o in KIT.operations(r)} & {"Decrypt", "GenerateDataKey", "GetPublicKey"}
