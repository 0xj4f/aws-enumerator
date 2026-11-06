"""ECR collector (collectors-cli.md §5.11): repository and registry policies, replication, policy status."""

from __future__ import annotations

import importlib

import pytest

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

W2, ACCT, EXT = KIT.W2, KIT.ACCT, KIT.EXT
REPO = f"arn:aws:ecr:{W2}:{ACCT}:repository/"


@pytest.mark.finding("F-059", "F-102")
def test_repositories_with_policy_status_and_a_throttled_read(tmp_path):
    r = KIT.run("ecr", tmp_path)
    KIT.assert_contract(r, statuses=("partial",))           # acme throttles GetRepositoryPolicy on demo-base
    repos = KIT.by(r.load("resources.json"), "Arn")
    assert list(repos) == [f"{REPO}demo-api", f"{REPO}demo-base"]
    api = repos[f"{REPO}demo-api"]
    assert api["PolicyStatus"] == "present" and api["Policy"]["Statement"][0]["Sid"] == "XAccountPull"
    assert api["EncryptionType"] == "AES256" and api["ScanOnPush"] is False and api["ImageTagMutability"] == "MUTABLE"
    base = repos[f"{REPO}demo-base"]
    assert base["Policy"] is None and base["PolicyStatus"] == "error"   # throttled is not "no policy" (F-059)
    assert KIT.collection_errors(base) == [("ecr:GetRepositoryPolicy", "throttled")]


@pytest.mark.finding("F-059")
def test_no_repository_policy_is_absent_not_an_error(tmp_path):
    r = KIT.run("ecr", tmp_path, KIT.clean_world("ecr"))
    KIT.assert_contract(r)
    base = KIT.by(r.load("resources.json"), "Name")["demo-base"]
    assert base["PolicyStatus"] == "absent" and "CollectionErrors" not in base
    rows = KIT.calls(r, "ecr:GetRepositoryPolicy")
    assert {(row["status"], row["not_configured"]) for row in rows} == {("ok", True), ("ok", False)}


@pytest.mark.finding("F-116")
def test_registry_policy_and_replication(tmp_path):
    r = KIT.run("ecr", tmp_path)
    policy = r.load("registry_policy.json")
    assert policy["RegistryId"] == ACCT and policy["PolicyStatus"] == "present"
    assert policy["Policy"]["Statement"][0]["Principal"] == {"AWS": f"arn:aws:iam::{EXT}:root"}
    assert r.load("registry.json") == {"RegistryId": ACCT, "ReplicationRules": [
        {"Destinations": [{"Region": "eu-west-1", "RegistryId": EXT}], "RepositoryFilters": []}]}


@pytest.mark.finding("F-116", "F-059")
def test_registry_policy_absent_and_denied(tmp_path):
    r = KIT.run("ecr", tmp_path, region=KIT.W1)
    KIT.assert_contract(r)
    assert r.load("registry_policy.json") == {"RegistryId": ACCT, "Policy": None, "PolicyStatus": "absent"}
    assert r.load("registry.json") == {"RegistryId": ACCT, "ReplicationRules": []}
    w = KIT.world()
    w.deny("ecr", "GetRegistryPolicy")
    w.deny("ecr", "DescribeRegistry")
    r2 = KIT.run("ecr", tmp_path / "denied", w)
    assert r2.load("registry_policy.json")["PolicyStatus"] == "denied"
    assert r2.load("registry.json")["ReplicationRules"] is None
    assert KIT.collection_errors(r2.load("registry.json")) == [("ecr:DescribeRegistry", "denied")]


@pytest.mark.finding("F-103", "F-061")
def test_listing_denied_is_denied_and_the_registry_still_read(tmp_path):
    w = KIT.world()
    w.deny("ecr", "DescribeRepositories")
    r = KIT.run("ecr", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("resources.json") == [] and r.load("registry_policy.json")["PolicyStatus"] == "present"


def test_empty_region_is_ok(tmp_path):
    r = KIT.run("ecr", tmp_path, region=KIT.EMPTY_REGION)
    KIT.assert_contract(r)
    assert r.load("resources.json") == []


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    assert KIT.assert_each_api_denied_is_survivable("ecr", tmp_path) == [
        "ecr:DescribeRegistry", "ecr:DescribeRepositories", "ecr:GetRegistryPolicy", "ecr:GetRepositoryPolicy"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    r = KIT.run("ecr", tmp_path)
    KIT.assert_declared_and_read_only(r)
    assert not {o for _s, o in KIT.operations(r)} & {"BatchGetImage", "GetDownloadUrlForLayer", "GetAuthorizationToken"}
