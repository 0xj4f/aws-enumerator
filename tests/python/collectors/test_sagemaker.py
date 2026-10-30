"""SageMaker collector (collectors-cli.md §5.10): notebooks, Studio domains and user profiles with their roles."""

from __future__ import annotations

import importlib

import pytest

from tests.fixtures.worlds import acme

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

W2, ACCT = KIT.W2, KIT.ACCT
SM = f"arn:aws:sagemaker:{W2}:{ACCT}:"
DOMAIN = "d-0dec0a1b2c3d4"
SM_ROLE, APP_ROLE = acme.role_arn("demo-sagemaker-role"), acme.role_arn("demo-app-role")


@pytest.mark.finding("F-113")
def test_notebooks_domains_and_user_profiles_with_their_roles(tmp_path):
    r = KIT.run("sagemaker", tmp_path)
    KIT.assert_contract(r)
    items = r.load("resources.json")
    assert [(i["Type"], i["Arn"]) for i in items] == sorted((i["Type"], i["Arn"]) for i in items)
    by_arn = KIT.by(items, "Arn")
    notebook = by_arn[f"{SM}notebook-instance/demo-notebook"]
    assert notebook["Kind"] == "notebook" and notebook["Roles"] == [SM_ROLE]
    assert notebook["DirectInternetAccess"] == "Enabled" and notebook["RootAccess"] == "Enabled"
    domain = by_arn[f"{SM}domain/{DOMAIN}"]
    assert domain["Kind"] == "domain" and domain["DefaultUserRole"] == domain["DefaultSpaceRole"] == SM_ROLE
    assert domain["Roles"] == [SM_ROLE] and domain["AppNetworkAccessType"] == "PublicInternetOnly"
    analyst = by_arn[f"{SM}user-profile/{DOMAIN}/demo-analyst"]
    assert analyst["Roles"] == [APP_ROLE] and analyst["InheritsDomainRole"] is False
    default = by_arn[f"{SM}user-profile/{DOMAIN}/demo-default-user"]
    assert default["ExecutionRole"] is None and default["InheritsDomainRole"] is True
    assert default["Roles"] == [SM_ROLE]                     # inherits the domain's default role


@pytest.mark.finding("F-102", "F-059")
def test_unreadable_items_are_kept_with_null_roles(tmp_path):
    w = KIT.world()
    w.deny("sagemaker", "DescribeNotebookInstance")
    w.deny("sagemaker", "DescribeDomain")
    r = KIT.run("sagemaker", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    by_arn = KIT.by(r.load("resources.json"), "Arn")
    notebook = by_arn[f"{SM}notebook-instance/demo-notebook"]
    assert notebook["Roles"] is None and KIT.collection_errors(notebook) == [
        ("sagemaker:DescribeNotebookInstance", "denied")]
    assert by_arn[f"{SM}domain/{DOMAIN}"]["Roles"] is None
    default = by_arn[f"{SM}user-profile/{DOMAIN}/demo-default-user"]
    assert default["Roles"] is None                          # the domain default is unknown, so is its role
    assert by_arn[f"{SM}user-profile/{DOMAIN}/demo-analyst"]["Roles"] == [APP_ROLE]


@pytest.mark.finding("F-147")
def test_no_domain_means_no_user_profile_listing(tmp_path):
    r = KIT.run("sagemaker", tmp_path, region=KIT.EMPTY_REGION)
    KIT.assert_contract(r)
    assert r.load("resources.json") == []
    assert ("sagemaker", "ListUserProfiles") not in KIT.operations(r)


@pytest.mark.finding("F-103", "F-061")
def test_notebook_listing_denied_is_denied_and_studio_still_runs(tmp_path):
    r = KIT.run("sagemaker", tmp_path, region=KIT.W1)         # acme denies ListNotebookInstances in eu-west-1
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("resources.json") == []
    w = KIT.world()
    w.deny("sagemaker", "ListNotebookInstances")
    r2 = KIT.run("sagemaker", tmp_path / "w2", w)
    assert {i["Kind"] for i in r2.load("resources.json")} == {"domain", "user_profile"}


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    assert KIT.assert_each_api_denied_is_survivable("sagemaker", tmp_path) == [
        "sagemaker:DescribeDomain", "sagemaker:DescribeNotebookInstance", "sagemaker:DescribeUserProfile",
        "sagemaker:ListDomains", "sagemaker:ListNotebookInstances", "sagemaker:ListUserProfiles"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    r = KIT.run("sagemaker", tmp_path)
    KIT.assert_declared_and_read_only(r)
    assert not {o for _s, o in KIT.operations(r)} & {"CreatePresignedDomainUrl", "CreatePresignedNotebookInstanceUrl"}
