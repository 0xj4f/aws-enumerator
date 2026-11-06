"""Glue collector (collectors-cli.md §5.10): real partition-aware ARNs, roles, never job arguments."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from tests.fixtures.regressions import support as S
from tests.fixtures.worlds import acme
from tests.support import targets
from tests.support.fakeaws import FakeAWS

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

W1, W2, ACCT = KIT.W1, KIT.W2, KIT.ACCT
GLUE_ROLE = acme.role_arn("demo-glue-role")


@pytest.mark.finding("F-051")
def test_jobs_and_dev_endpoints_have_real_arns_and_roles(tmp_path):
    r = KIT.run("glue", tmp_path)
    KIT.assert_contract(r)
    assert r.load("resources.json") == [
        {"Type": "gluejob", "Kind": "dev_endpoint", "Arn": f"arn:aws:glue:{W2}:{ACCT}:devEndpoint/demo-dev-endpoint",
         "Name": "demo-dev-endpoint", "Roles": [GLUE_ROLE], "Status": "READY",
         "PublicAddress": "ec2-203-0-113-30.eu-west-2.compute.amazonaws.com"},
        {"Type": "gluejob", "Kind": "job", "Arn": f"arn:aws:glue:{W2}:{ACCT}:job/demo-etl-job", "Name": "demo-etl-job",
         "Roles": [GLUE_ROLE], "Command": "glueetl"},
    ]


@pytest.mark.finding("F-112")
def test_job_arguments_are_never_written(tmp_path):
    KIT.assert_no_canaries(KIT.run("glue", tmp_path), "glue_args")


@pytest.mark.finding("F-051")
def test_same_named_jobs_in_two_regions_have_distinct_arns(tmp_path, monkeypatch):
    jobs = [{"Name": "demo-etl-job", "Role": GLUE_ROLE, "DefaultArguments": {}}]
    monkeypatch.setitem(acme.REGIONAL[W1]["glue"], "jobs", jobs)
    arns = set()
    for region in (W1, W2):
        r = KIT.run("glue", tmp_path / region, region=region)
        arns |= {i["Arn"] for i in r.load("resources.json") if i["Kind"] == "job"}
    assert arns == {f"arn:aws:glue:{W1}:{ACCT}:job/demo-etl-job", f"arn:aws:glue:{W2}:{ACCT}:job/demo-etl-job"}


@pytest.mark.finding("F-051")
def test_arns_follow_the_partition(tmp_path):
    w = KIT.world()

    @w.op("glue", "GetJobs")
    def get_jobs(req):
        return {"Jobs": [{"Name": "demo-gov-job", "Role": GLUE_ROLE, "Command": {"Name": "pythonshell"}}]}

    base = targets.collector_base_module()
    fake = FakeAWS(w, strict=True)
    run = base.RunInfo(run_id="20261015T101500Z-a1b2c3", aws=base.SessionAwsProvider(fake.session_factory()),
                       run_root=Path(tmp_path))
    ctx = base.CollectContext.create(KIT.spec("glue"), region="us-gov-west-1", account_id=ACCT,
                                     partition="aws-us-gov", run=run, unit_dir=Path(tmp_path) / "us-gov-west-1")
    result = base.run_collector(ctx)
    assert result.status == "ok", result.status_reason
    items = S.load_json(ctx.out.root / "resources.json")
    assert [i["Arn"] for i in items] == [f"arn:aws-us-gov:glue:us-gov-west-1:{ACCT}:job/demo-gov-job"]


@pytest.mark.finding("F-103")
def test_dev_endpoints_denied_keeps_the_jobs(tmp_path):
    r = KIT.run("glue", tmp_path, region=W1)                 # acme denies GetDevEndpoints in eu-west-1
    KIT.assert_contract(r, statuses=("partial",))
    assert [i["Name"] for i in r.load("resources.json")] == ["demo-west-job"]


@pytest.mark.finding("F-103", "F-061")
def test_job_listing_denied_is_denied(tmp_path):
    w = KIT.world()
    w.deny("glue", "GetJobs")
    r = KIT.run("glue", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert [i["Kind"] for i in r.load("resources.json")] == ["dev_endpoint"]


def test_empty_region_is_ok(tmp_path):
    r = KIT.run("glue", tmp_path, region=KIT.EMPTY_REGION)
    KIT.assert_contract(r)
    assert r.load("resources.json") == []


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    assert KIT.assert_each_api_denied_is_survivable("glue", tmp_path) == ["glue:GetDevEndpoints", "glue:GetJobs"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    KIT.assert_declared_and_read_only(KIT.run("glue", tmp_path))
