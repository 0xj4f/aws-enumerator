"""CodeBuild collector (collectors-cli.md §5.10): batch bisection, secret-free projection, source credentials."""

from __future__ import annotations

import importlib

import pytest

from tests.fixtures.worlds import acme
from tests.support import targets
from tests.support.fakeaws import AWSError

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

W2, ACCT = KIT.W2, KIT.ACCT
PROJECT = f"arn:aws:codebuild:{W2}:{ACCT}:project/"
BUILD_ROLE = acme.role_arn("demo-build-role")


def module():
    return targets.collector_module("codebuild")


def many_projects_world(count=150, denied="demo-p077"):
    """``count`` projects; any BatchGetProjects that includes ``denied`` is refused as a whole (like IAM)."""
    w = KIT.world()
    names = [f"demo-p{i:03d}" for i in range(count)]

    @w.op("codebuild", "ListProjects")
    def list_projects(req):
        return {"projects": list(names)}

    @w.op("codebuild", "BatchGetProjects")
    def batch_get(req):
        if denied in req.params["names"]:
            raise req.deny(f"{PROJECT}{denied}")
        return {"projects": [{"name": n, "arn": f"{PROJECT}{n}", "serviceRole": BUILD_ROLE,
                              "source": {"type": "NO_SOURCE"}} for n in req.params["names"]]}

    return w


@pytest.mark.finding("F-112", "F-113")
def test_projects_keep_roles_source_and_variable_names_but_no_secrets(tmp_path):
    r = KIT.run("codebuild", tmp_path)
    KIT.assert_contract(r)
    projects = KIT.by(r.load("resources.json"), "Name")
    build = projects["demo-build"]
    assert build["Arn"] == f"{PROJECT}demo-build" and build["Roles"] == [BUILD_ROLE]
    assert build["Source"]["Location"] == "https://git.example.com/demo/app.git"     # userinfo stripped
    assert build["Source"]["Type"] == "GITHUB"
    assert build["EnvironmentVariables"] == [{"Name": "NPM_TOKEN", "Type": "PLAINTEXT"},
                                             {"Name": "DB_PASSWORD", "Type": "PARAMETER_STORE"}]
    assert build["Environment"]["PrivilegedMode"] is False and build["Webhook"] is None
    KIT.assert_no_canaries(r, "codebuild_env", "codebuild_source_url")
    assert KIT.S.grep_tree("demo-user", r.out) == []
    assert r.load("source_credentials.json") == [{"Arn": f"arn:aws:codebuild:{W2}:{ACCT}:token/github",
                                                  "ServerType": "GITHUB", "AuthType": "PERSONAL_ACCESS_TOKEN"}]


@pytest.mark.finding("F-113", "F-112")
def test_webhook_secret_payload_url_and_buildspec_are_dropped(tmp_path):
    project = {"name": "demo-hooked", "arn": f"{PROJECT}demo-hooked", "serviceRole": BUILD_ROLE,
               "source": {"type": "GITHUB", "location": "https://demo-token123@git.example.com/demo/app.git",
                          "buildspec": "phases: {build: {commands: [echo CANARY-SECRET-VALUE-buildspec]}}",
                          "auth": {"type": "OAUTH", "resource": "CANARY-SECRET-VALUE-auth-resource"}},
               "webhook": {"url": "https://api.github.com/repos/demo/app/hooks/1", "secret": "CANARY-SECRET-VALUE-hook",
                           "payloadUrl": "https://codebuild.eu-west-2.amazonaws.com/webhooks?t=CANARY-SECRET-VALUE-p",
                           "buildType": "BUILD", "filterGroups": [[{"type": "EVENT", "pattern": "PUSH"}]]}}
    item = module().project_item(project)
    assert item["Webhook"] == {"Url": "https://api.github.com/repos/demo/app/hooks/1", "BuildType": "BUILD",
                               "FilterGroups": [[{"type": "EVENT", "pattern": "PUSH"}]], "ManualCreation": None,
                               "LastModifiedSecret": None}
    assert item["Source"] == {"Type": "GITHUB", "Location": "https://git.example.com/demo/app.git", "AuthType": "OAUTH",
                              "ReportBuildStatus": None, "SourceIdentifier": None}
    assert acme.CANARY not in repr(item) and "demo-token123" not in repr(item)


@pytest.mark.parametrize("location, expected", [
    ("https://user:pass@host.example.com/r.git", "https://host.example.com/r.git"),
    ("https://token@host.example.com:8443/r.git?x=1", "https://host.example.com:8443/r.git?x=1"),
    ("https://host.example.com/r.git", "https://host.example.com/r.git"),
    ("demo-bucket/source.zip", "demo-bucket/source.zip"),
    (None, None),
])
def test_strip_userinfo(location, expected):
    assert module().strip_userinfo(location) == expected


@pytest.mark.finding("F-102")
def test_a_failing_batch_is_bisected_and_only_the_bad_project_is_lost(tmp_path):
    r = KIT.run("codebuild", tmp_path, many_projects_world())
    KIT.assert_contract(r, statuses=("partial",))
    projects = r.load("resources.json")
    assert len(projects) == 150 and KIT.sorted_by(projects, "Arn")
    bad = [p for p in projects if p.get("CollectionErrors")]
    assert [p["Name"] for p in bad] == ["demo-p077"]
    assert bad[0]["Arn"] == f"{PROJECT}demo-p077" and bad[0]["Roles"] is None
    assert KIT.collection_errors(bad[0]) == [("codebuild:BatchGetProjects", "denied")]
    assert all(p["Roles"] == [BUILD_ROLE] for p in projects if p is not bad[0])
    calls = r.fake.calls_for(service="codebuild", operation="BatchGetProjects")
    assert max(len(c.params["names"]) for c in calls) == 100
    assert len(calls) <= 2 + 2 * 7                           # two batches + one bisection path (log2 100 ~ 7)
    assert KIT.coverage(r)["item_errors"] == [{"resource": f"{PROJECT}demo-p077", "api": "codebuild:BatchGetProjects",
                                               "status": "denied", "error_code": "AccessDeniedException"}]


@pytest.mark.finding("F-103")
def test_source_credentials_denied_keeps_the_projects(tmp_path):
    w = KIT.world()
    w.deny("codebuild", "ListSourceCredentials")
    r = KIT.run("codebuild", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    assert len(r.load("resources.json")) == 2 and r.load("source_credentials.json") == []


@pytest.mark.finding("F-103", "F-061")
def test_project_listing_denied_is_denied(tmp_path):
    w = KIT.world()
    w.deny("codebuild", "ListProjects")
    r = KIT.run("codebuild", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("resources.json") == []


def test_projects_that_vanish_between_list_and_describe_are_not_invented(tmp_path):
    w = KIT.world()

    @w.op("codebuild", "ListProjects")
    def list_projects(req):
        return {"projects": ["demo-build", "demo-gone"]}

    r = KIT.run("codebuild", tmp_path, w)
    assert [p["Name"] for p in r.load("resources.json")] == ["demo-build"]


def test_unexpected_batch_errors_are_errors(tmp_path):
    w = KIT.world()

    @w.op("codebuild", "BatchGetProjects")
    def boom(req):
        raise AWSError("InvalidInputException", "bad", 400)

    r = KIT.run("codebuild", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    assert {p["CollectionErrors"][0]["status"] for p in r.load("resources.json")} == {"error"}


def test_empty_region_is_ok(tmp_path):
    r = KIT.run("codebuild", tmp_path, region=KIT.EMPTY_REGION)
    KIT.assert_contract(r)
    assert r.load("resources.json") == [] and r.load("source_credentials.json") == []


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    assert KIT.assert_each_api_denied_is_survivable("codebuild", tmp_path) == [
        "codebuild:BatchGetProjects", "codebuild:ListProjects", "codebuild:ListSourceCredentials"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    r = KIT.run("codebuild", tmp_path)
    KIT.assert_declared_and_read_only(r)
    assert KIT.spec("codebuild").tier == 2
