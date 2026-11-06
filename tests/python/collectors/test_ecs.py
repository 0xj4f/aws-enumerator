"""ECS collector (collectors-cli.md §5.10): role-set grouping, capped revisions, services, task vs execution role."""

from __future__ import annotations

import copy
import importlib

import pytest

from tests.fixtures.worlds import acme

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

W2, ACCT = KIT.W2, KIT.ACCT
TD = f"arn:aws:ecs:{W2}:{ACCT}:task-definition/"
TASK_ROLE, EXEC_ROLE = acme.role_arn("demo-ecs-task-role"), acme.role_arn("demo-ecs-exec-role")


@pytest.fixture
def many_revisions(monkeypatch):
    """800 ACTIVE revisions of demo-ci with one role set, then revisions 801-802 with a second one."""
    ecs = copy.deepcopy(acme.REGIONAL[W2]["ecs"])
    tds = [{"family": "demo-ci", "revision": n, "taskRoleArn": TASK_ROLE, "executionRoleArn": EXEC_ROLE, "env": []}
           for n in range(1, 801)]
    tds += [{"family": "demo-ci", "revision": n, "taskRoleArn": acme.role_arn("demo-ci-admin"),
             "executionRoleArn": EXEC_ROLE, "env": []} for n in (801, 802)]
    ecs["task_definitions"] = tds
    monkeypatch.setitem(acme.REGIONAL[W2], "ecs", ecs)
    w = KIT.world()
    w.page_sizes[("ecs", "ListTaskDefinitions")] = 100
    return w


@pytest.mark.finding("F-049", "F-004", "F-102")
def test_revisions_are_grouped_by_role_set_and_unreadable_ones_kept(tmp_path):
    r = KIT.run("ecs", tmp_path)
    KIT.assert_contract(r, statuses=("partial",))           # acme denies DescribeTaskDefinition demo-batch:1
    items = r.load("resources.json")
    assert [(i["Family"], i["Arn"]) for i in items] == sorted((i["Family"], i["Arn"]) for i in items)
    api = [i for i in items if i["Family"] == "demo-api"]
    assert len(api) == 1 and api[0]["Arn"] == f"{TD}demo-api:2" and api[0]["Revisions"] == [2, 1]
    assert api[0]["TaskRole"] == api[0]["ExecutionRole"] == TASK_ROLE and api[0]["Roles"] == [TASK_ROLE]
    assert api[0]["RevisionsTruncated"] is False and api[0]["Type"] == "ecstask"
    batch = [i for i in items if i["Family"] == "demo-batch"]
    assert len(batch) == 1 and batch[0]["Arn"] == f"{TD}demo-batch:1"
    assert batch[0]["Roles"] is None and batch[0]["TaskRole"] is None            # unknown, not "no role"
    assert KIT.collection_errors(batch[0]) == [("ecs:DescribeTaskDefinition", "denied")]
    KIT.assert_no_canaries(r, "ecs_env")
    assert all("containerDefinitions" not in i for i in items)


@pytest.mark.finding("F-004")
def test_the_execution_role_is_recorded_but_not_a_role_the_code_runs_as(tmp_path, monkeypatch):
    ecs = copy.deepcopy(acme.REGIONAL[W2]["ecs"])
    for td in ecs["task_definitions"]:
        if td["family"] == "demo-api":
            td["executionRoleArn"] = EXEC_ROLE
    monkeypatch.setitem(acme.REGIONAL[W2], "ecs", ecs)
    r = KIT.run("ecs", tmp_path)
    api = [i for i in r.load("resources.json") if i["Family"] == "demo-api"][0]
    assert api["TaskRole"] == TASK_ROLE and api["ExecutionRole"] == EXEC_ROLE
    assert api["Roles"] == [TASK_ROLE]


@pytest.mark.finding("F-049", "F-147")
def test_eight_hundred_revisions_cost_five_describes_and_one_item(tmp_path, many_revisions):
    r = KIT.run("ecs", tmp_path, many_revisions)
    KIT.assert_contract(r)
    items = r.load("resources.json")
    assert len(r.fake.calls_for(service="ecs", operation="DescribeTaskDefinition")) == 5
    assert len(items) == 2                                   # the newest five hold both role sets
    newest = [i for i in items if i["TaskRole"] == acme.role_arn("demo-ci-admin")][0]
    older = [i for i in items if i["TaskRole"] == TASK_ROLE][0]
    assert newest["Revisions"] == [802, 801] and newest["Arn"] == f"{TD}demo-ci:802"
    assert older["Revisions"] == [800, 799, 798] and older["Arn"] == f"{TD}demo-ci:800"
    assert newest["RevisionsTruncated"] is True and older["RevisionsTruncated"] is True
    lists = r.fake.calls_for(service="ecs", operation="ListTaskDefinitions")
    assert all(c.params["sort"] == "DESC" and c.params["familyPrefix"] == "demo-ci" for c in lists)
    assert len(lists) == 1                                   # one page of five, no more


@pytest.mark.finding("F-049")
def test_one_role_set_gives_one_item(tmp_path, many_revisions):
    r = KIT.run("ecs", tmp_path, many_revisions, options={"ecs_max_revisions": 3})
    items = r.load("resources.json")
    assert len(items) == 2 and len(r.fake.calls_for(service="ecs", operation="DescribeTaskDefinition")) == 3
    r1 = KIT.run("ecs", tmp_path / "one", many_revisions, options={"ecs_max_revisions": 1})
    assert [i["Revisions"] for i in r1.load("resources.json")] == [[802]]


@pytest.mark.finding("F-049")
def test_max_revisions_zero_describes_every_revision(tmp_path, many_revisions):
    r = KIT.run("ecs", tmp_path, many_revisions, options={"ecs_max_revisions": 0})
    items = r.load("resources.json")
    assert len(r.fake.calls_for(service="ecs", operation="DescribeTaskDefinition")) == 802
    assert sorted(len(i["Revisions"]) for i in items) == [2, 800]
    assert all(i["RevisionsTruncated"] is False for i in items)


@pytest.mark.finding("F-113")
def test_services_record_ecs_exec_and_networking(tmp_path):
    r = KIT.run("ecs", tmp_path)
    assert r.load("services.json") == [{
        "ClusterArn": f"arn:aws:ecs:{W2}:{ACCT}:cluster/demo-ecs",
        "ServiceArn": f"arn:aws:ecs:{W2}:{ACCT}:service/demo-ecs/demo-api-svc", "Name": "demo-api-svc",
        "TaskDefinition": f"{TD}demo-api:2", "EnableExecuteCommand": True, "LaunchType": "FARGATE",
        "AssignPublicIp": "ENABLED", "Subnets": ["subnet-0dec0b0b0000002"], "SecurityGroups": ["sg-0dec0eeb000000002"]}]


@pytest.mark.finding("F-102", "F-059")
def test_a_denied_describe_services_keeps_the_services(tmp_path):
    w = KIT.world()
    w.deny("ecs", "DescribeServices")
    r = KIT.run("ecs", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    svc = r.load("services.json")
    assert len(svc) == 1 and svc[0]["Name"] == "demo-api-svc" and svc[0]["EnableExecuteCommand"] is None
    assert KIT.collection_errors(svc[0]) == [("ecs:DescribeServices", "denied")]


@pytest.mark.finding("F-103", "F-061")
def test_family_listing_denied_is_denied_and_services_still_run(tmp_path):
    w = KIT.world()
    w.deny("ecs", "ListTaskDefinitionFamilies")
    r = KIT.run("ecs", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("resources.json") == [] and len(r.load("services.json")) == 1


@pytest.mark.finding("F-102")
def test_a_denied_revision_listing_keeps_the_family(tmp_path):
    w = KIT.world()
    w.deny("ecs", "ListTaskDefinitions", {"familyPrefix": "demo-api"})
    r = KIT.run("ecs", tmp_path, w)
    api = [i for i in r.load("resources.json") if i["Family"] == "demo-api"]
    assert len(api) == 1 and api[0]["Arn"] == f"{TD}demo-api" and api[0]["Roles"] is None
    assert KIT.collection_errors(api[0]) == [("ecs:ListTaskDefinitions", "denied")]


def test_empty_region_is_ok(tmp_path):
    r = KIT.run("ecs", tmp_path, region=KIT.EMPTY_REGION)
    KIT.assert_contract(r)
    assert r.load("resources.json") == [] and r.load("services.json") == []


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    assert KIT.assert_each_api_denied_is_survivable("ecs", tmp_path) == [
        "ecs:DescribeServices", "ecs:DescribeTaskDefinition", "ecs:ListClusters", "ecs:ListServices",
        "ecs:ListTaskDefinitionFamilies", "ecs:ListTaskDefinitions"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    r = KIT.run("ecs", tmp_path)
    KIT.assert_declared_and_read_only(r)
    assert KIT.spec("ecs").tier == 2
