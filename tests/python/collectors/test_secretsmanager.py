"""Secrets Manager collector (collectors-cli.md §5.7): projection, policy status, hashed policy files."""

from __future__ import annotations

import importlib
import re

import pytest

from tests.fixtures.worlds import acme
from tests.support import targets
from tests.support.fakeaws import botocore_error

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

W2, ACCT = KIT.W2, KIT.ACCT
SM = f"arn:aws:secretsmanager:{W2}:{ACCT}:secret:"
DB, DB_UNDERSCORE, API_KEY = f"{SM}demo/db-creds-AbCdEf", f"{SM}demo_db-creds-GhIjKl", f"{SM}demo/api-key-MnOpQr"
DENIED, RETIRED = f"{SM}demo/denied-StUvWx", f"{SM}demo/retired-token-XyZaBc"


def policy_files(r):
    """``{SecretArn: (path, data)}`` of the written policy files."""
    out = {}
    for path in KIT.S.files_under(r.out / "resource_policies"):
        data = KIT.S.load_json(path)
        out[data["SecretArn"]] = (path, data)
    return out


@pytest.mark.finding("F-059", "F-116", "F-112")
def test_every_secret_is_listed_with_its_policy_status_and_no_free_text(tmp_path):
    r = KIT.run("secretsmanager", tmp_path)
    KIT.assert_contract(r, statuses=("partial",))           # acme denies one GetResourcePolicy
    secrets = r.load("secrets.json")
    assert [s["ARN"] for s in secrets] == sorted([DB, DB_UNDERSCORE, API_KEY, DENIED, RETIRED])
    status = {s["ARN"]: s["PolicyStatus"] for s in secrets}
    assert status == {DB: "present", DB_UNDERSCORE: "present", API_KEY: "absent", DENIED: "denied",
                      RETIRED: "skipped"}
    by_arn = KIT.by(secrets, "ARN")
    assert KIT.collection_errors(by_arn[DENIED]) == [("secretsmanager:GetResourcePolicy", "denied")]
    assert by_arn[RETIRED]["DeletedDate"]                   # planned deletion is listed (F-116)
    assert by_arn[DB]["RotationLambdaARN"].endswith(":function:demo-rotator")
    for s in secrets:
        assert "Description" not in s and "Tags" not in s   # F-112: free text only with the opt-in
    KIT.assert_no_canaries(r, "secrets_description")
    lists = r.fake.calls_for(service="secretsmanager", operation="ListSecrets")
    assert all(c.params.get("IncludePlannedDeletion") is True for c in lists) and len(lists) == 3   # 2 per page
    policy_calls = r.fake.calls_for(service="secretsmanager", operation="GetResourcePolicy")
    assert RETIRED not in {c.params["SecretId"] for c in policy_calls} and len(policy_calls) == 4


@pytest.mark.finding("F-112")
def test_keep_sensitive_metadata_keeps_description_and_tags(tmp_path):
    r = KIT.run("secretsmanager", tmp_path, options={"keep_sensitive_metadata": True})
    db = KIT.by(r.load("secrets.json"), "ARN")[DB]
    assert acme.CANARIES["secrets_description"] in db["Description"]
    assert db["Tags"] == [{"Key": "env", "Value": "demo"}]


@pytest.mark.finding("F-114")
def test_policy_files_are_keyed_by_arn_so_colliding_names_both_survive(tmp_path):
    r = KIT.run("secretsmanager", tmp_path)
    files = policy_files(r)
    assert set(files) == {DB, DB_UNDERSCORE}
    for path, data in files.values():
        assert re.fullmatch(r"[a-z0-9._-]{1,48}-[0-9a-f]{12}\.json", path.name), path.name
        assert data["SecretName"] in ("demo/db-creds", "demo_db-creds")
        assert data["ResourcePolicy"]["Statement"]
    assert files[DB_UNDERSCORE][1]["ResourcePolicy"]["Statement"][0]["Principal"] == "*"


@pytest.mark.finding("F-114", "F-103")
def test_one_unwritable_policy_file_does_not_cost_the_others(tmp_path, monkeypatch):
    base = targets.collector_base_module()
    original = base.ModuleOutput.write_item

    def failing(self, subdir, key, data, *, hint=None):
        if key == DB:
            raise OSError(63, "File name too long")
        return original(self, subdir, key, data, hint=hint)

    monkeypatch.setattr(base.ModuleOutput, "write_item", failing)
    r = KIT.run("secretsmanager", tmp_path)
    KIT.assert_contract(r, statuses=("partial",))
    assert set(policy_files(r)) == {DB_UNDERSCORE}
    db = KIT.by(r.load("secrets.json"), "ARN")[DB]
    assert db["PolicyStatus"] == "error"
    assert db["CollectionErrors"] == [{"api": "secretsmanager:GetResourcePolicy", "status": "error",
                                       "error_code": "OSError"}]


@pytest.mark.finding("F-103")
def test_a_botocore_error_on_one_policy_keeps_the_rest(tmp_path):
    w = KIT.clean_world("secretsmanager")
    w.raise_exc("secretsmanager", "GetResourcePolicy",
                botocore_error("ReadTimeoutError", endpoint_url="https://secretsmanager.eu-west-2.amazonaws.com/"),
                match={"SecretId": DB})
    r = KIT.run("secretsmanager", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    status = {s["ARN"]: s["PolicyStatus"] for s in r.load("secrets.json")}
    assert status[DB] == "error" and status[DB_UNDERSCORE] == "present" and status[DENIED] == "absent"
    assert set(policy_files(r)) == {DB_UNDERSCORE}


@pytest.mark.finding("F-103", "F-061")
def test_listing_denied_is_denied_with_an_empty_list(tmp_path):
    r = KIT.run("secretsmanager", tmp_path, region=KIT.W1)       # acme denies ListSecrets in eu-west-1
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("secrets.json") == []


def test_empty_region_is_ok(tmp_path):
    r = KIT.run("secretsmanager", tmp_path, region=KIT.EMPTY_REGION)
    KIT.assert_contract(r)
    assert r.load("secrets.json") == []


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    assert KIT.assert_each_api_denied_is_survivable("secretsmanager", tmp_path) == [
        "secretsmanager:GetResourcePolicy", "secretsmanager:ListSecrets"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    r = KIT.run("secretsmanager", tmp_path)
    KIT.assert_declared_and_read_only(r)
    assert not r.fake.calls_for(service="secretsmanager", operation="GetSecretValue")
