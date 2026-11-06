"""DynamoDB collector (collectors-cli.md §5.11): deterministic ARNs (no DescribeTable), policy status."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from tests.fixtures.regressions import support as S
from tests.support import targets
from tests.support.fakeaws import FakeAWS

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

W2, ACCT, EXT = KIT.W2, KIT.ACCT, KIT.EXT
TABLE = f"arn:aws:dynamodb:{W2}:{ACCT}:table/"


@pytest.mark.finding("F-100", "F-102", "F-059")
def test_every_table_is_listed_without_describe_table(tmp_path):
    r = KIT.run("dynamodb", tmp_path)
    KIT.assert_contract(r)
    tables = KIT.by(r.load("resources.json"), "Arn")
    assert list(tables) == [f"{TABLE}demo-denied-table", f"{TABLE}demo-orders", f"{TABLE}demo-sessions"]
    assert tables[f"{TABLE}demo-orders"]["PolicyStatus"] == "present"
    assert tables[f"{TABLE}demo-orders"]["Policy"]["Statement"][0]["Principal"] == {"AWS": f"arn:aws:iam::{EXT}:root"}
    assert tables[f"{TABLE}demo-sessions"]["PolicyStatus"] == "absent"
    assert ("dynamodb", "DescribeTable") not in KIT.operations(r)          # F-100: the ARN is deterministic
    assert len(r.fake.calls_for(service="dynamodb", operation="ListTables")) == 2      # 2 per page


@pytest.mark.finding("F-059", "F-102")
def test_a_denied_policy_read_keeps_the_table(tmp_path):
    w = KIT.world()
    w.deny("dynamodb", "GetResourcePolicy", {"ResourceArn": f"{TABLE}demo-orders"})
    r = KIT.run("dynamodb", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    orders = KIT.by(r.load("resources.json"), "Name")["demo-orders"]
    assert orders["Policy"] is None and orders["PolicyStatus"] == "denied"
    assert KIT.collection_errors(orders) == [("dynamodb:GetResourcePolicy", "denied")]


@pytest.mark.finding("F-100")
def test_table_arns_follow_the_partition(tmp_path):
    base = targets.collector_base_module()
    w = KIT.world()

    @w.op("dynamodb", "ListTables")
    def list_tables(req):
        return {"TableNames": ["demo-cn-table"]}

    fake = FakeAWS(w, strict=True)
    run = base.RunInfo(run_id="20261015T101500Z-a1b2c3", aws=base.SessionAwsProvider(fake.session_factory()),
                       run_root=Path(tmp_path))
    ctx = base.CollectContext.create(KIT.spec("dynamodb"), region="cn-north-1", account_id=ACCT, partition="aws-cn",
                                     run=run, unit_dir=Path(tmp_path) / "cn-north-1")
    base.run_collector(ctx)
    items = S.load_json(ctx.out.root / "resources.json")
    assert [i["Arn"] for i in items] == [f"arn:aws-cn:dynamodb:cn-north-1:{ACCT}:table/demo-cn-table"]
    assert [c.params["ResourceArn"] for c in fake.calls_for(operation="GetResourcePolicy")] == [items[0]["Arn"]]


@pytest.mark.finding("F-103", "F-061")
def test_listing_denied_is_denied_with_an_empty_list(tmp_path):
    w = KIT.world()
    w.deny("dynamodb", "ListTables")
    r = KIT.run("dynamodb", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("resources.json") == []


def test_empty_region_is_ok(tmp_path):
    r = KIT.run("dynamodb", tmp_path, region=KIT.W1)
    KIT.assert_contract(r)
    assert r.load("resources.json") == []


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    assert KIT.assert_each_api_denied_is_survivable("dynamodb", tmp_path) == [
        "dynamodb:GetResourcePolicy", "dynamodb:ListTables"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    r = KIT.run("dynamodb", tmp_path)
    KIT.assert_declared_and_read_only(r)
    assert not {o for _s, o in KIT.operations(r)} & {"Scan", "Query", "GetItem", "DescribeTable"}
