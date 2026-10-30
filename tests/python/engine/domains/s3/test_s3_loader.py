"""E-net loaders (engine/io/loaders/{s3,ec2,edge_services,posture}.py): both collector layouts, explicit units only,
table statuses that tell "empty" from "unknown" (F-010, F-025, F-058, F-059, F-138, F-162)."""

from __future__ import annotations

import importlib
import os
from types import SimpleNamespace

import pytest

K = importlib.import_module("tests.fixtures.e-net.kit")
rb = K.rb


def _ctx(run):
    ctx_mod = K.engine("context")
    options = K.engine("model").AnalysisOptions()
    return ctx_mod.build_run_context(run.path, regions=list(run.v2.regions), options=options)


def _legacy_ctx(tree):
    return K.engine("context").build_report_context(tree.path)


def _load(name, ctx):
    return K.engine(f"io.loaders.{name}").load(ctx)


@pytest.mark.finding("F-138", "F-058")
def test_s3_loader_reads_subresource_statuses_and_normalises_regions(tmp_path):
    run = K.Run(tmp_path)
    recs = [K.v2_bucket(run, "demo-a", policy=K.public_policy("demo-a"), policy_is_public=True),
            K.v2_bucket(run, "demo-b", statuses_={"policy": "denied", "acl": "error"}),
            K.v2_bucket(run, "demo-c", region="EU")]
    recs[2]["Region"] = "EU"
    run.write_json("global", "s3/buckets.json", recs)
    run.write_json("global", "s3/account_public_access_block.json", K.account_pab(None), module="s3")
    run.finish()
    res = _load("s3", _ctx(run))
    loader = K.engine("io.loaders.s3")
    by = {b.name: b for b in loader.buckets(res.data)}
    assert by["demo-a"].status["policy"] == "present" and by["demo-a"].content["policy"]["Statement"]
    assert by["demo-a"].policy_is_public is True
    assert by["demo-b"].status["policy"] == "denied" and "policy" not in by["demo-b"].content
    assert by["demo-b"].status["acl"] == "error" and by["demo-b"].policy_is_public is None
    assert by["demo-c"].region == "eu-west-1"
    # a sub-resource reported present whose file is missing is an error, never "not configured"
    (run.path / "global" / "s3" / "policies" / "demo-a.json").unlink()
    by = {b.name: b for b in loader.buckets(_load("s3", _ctx(run)).data)}
    assert by["demo-a"].status["policy"] == "error"


@pytest.mark.finding("F-059")
def test_legacy_s3_layout_missing_files_are_not_configured_and_error_stubs_are_denied(tmp_path):
    t = K.Tree(tmp_path)
    t.write()
    x = rb.s3_bucket(t.scope, "demo-x")
    x["Region"] = ""                                        # GetBucketLocation's empty constraint
    t.scope.write("s3/buckets.json", [x, rb.s3_bucket(t.scope, "demo-y")])
    t.scope.write("s3/acls/demo-y.json", {"Error": "An error occurred (AccessDenied) when calling GetBucketAcl"})
    loader = K.engine("io.loaders.s3")
    by = {b.name: b for b in loader.buckets(_load("s3", _legacy_ctx(t)).data)}
    assert by["demo-x"].layout == "legacy" and by["demo-x"].status["policy"] == "absent"
    assert by["demo-x"].region == "us-east-1"
    assert by["demo-y"].status["acl"] == "denied"


@pytest.mark.finding("F-058", "F-025")
def test_ec2_loader_statuses_tell_denied_from_empty_and_read_only_explicit_regions(tmp_path):
    run = K.Run(tmp_path, regions=(K.OTHER, K.REGION))
    run.write_json(K.REGION, "ec2/instances.json", [rb.ec2_instance("i-0a1b2c3d4e5f6c001", account=K.ACCT,
                                                                    region=K.REGION)])
    run.write_json(K.OTHER, "ec2/instances.json", [])
    run.write_json(K.OTHER, "vpc/route_tables.json", [], calls=[
        {"api": "ec2:DescribeRouteTables", "status": "denied", "primary": False}])
    stray = run.path / "us-east-1" / "ec2"
    stray.mkdir(parents=True)
    (stray / "instances.json").write_text("[{\"InstanceId\": \"i-0a1b2c3d4e5f6ffff\"}]", encoding="utf-8")
    run.finish()
    res = _load("ec2", _ctx(run))
    t = K.engine("io.loaders.ec2")
    assert t.table_status(res.data, "instances", K.REGION) == "complete"
    assert t.table_status(res.data, "instances", K.OTHER) == "complete" and t.table(res.data, "instances",
                                                                                    K.OTHER) == []
    assert t.table_status(res.data, "route_tables", K.OTHER) == "denied"
    assert t.units_of(res.data, "instances") == sorted([K.OTHER, K.REGION])          # never the stray region
    assert t.table_status(res.data, "nacls", K.REGION) == "missing"


@pytest.mark.finding("F-162")
def test_loaders_are_independent_of_directory_listing_order(tmp_path, monkeypatch):
    t = K.Tree(tmp_path)
    t.write()
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, f"demo-{i}") for i in range(5)])
    first = [b.name for b in K.engine("io.loaders.s3").buckets(_load("s3", _legacy_ctx(t)).data)]
    real = os.listdir
    monkeypatch.setattr(os, "listdir", lambda p=".": list(reversed(real(p))))
    second = [b.name for b in K.engine("io.loaders.s3").buckets(_load("s3", _legacy_ctx(t)).data)]
    assert first == second == sorted(first)


def test_edge_and_posture_loaders_keep_null_fields_and_read_dict_files(tmp_path):
    run = K.Run(tmp_path)
    run.write_json(K.REGION, "ebs/resources.json", [{"Id": "snap-0a1b2c3d4e5f60001", "Public": None,
                                                     "SharedAccounts": None}])
    run.write_json(K.REGION, "ebs/account_settings.json", {"SnapshotBlockPublicAccessState": "block-all-sharing"},
                   module="ebs")
    run.write_json(K.REGION, "securityhub/hub.json", {"Enabled": False})
    run.finish()
    ctx = _ctx(run)
    t = K.engine("io.loaders.ec2")
    edge = _load("edge_services", ctx).data
    assert t.table(edge, "ebs", K.REGION)[0]["SharedAccounts"] is None
    assert t.document(edge, "ebs_settings", K.REGION) == {"SnapshotBlockPublicAccessState": "block-all-sharing"}
    posture = _load("posture", ctx).data
    assert t.document(posture, "securityhub", K.REGION) == {"Enabled": False}
    assert t.table_status(posture, "trails", K.REGION) == "missing"


def test_table_helpers_tolerate_foreign_shapes():
    t = K.engine("io.loaders.ec2")
    assert t.table(None, "x", "u") == [] and t.table_status(None, "x", "u") == "missing"
    stub = {"instances": {"eu-west-2": [{"InstanceId": "i-1"}]}}                 # a loader without _status
    assert t.table_status(stub, "instances", "eu-west-2") == "complete"
    assert t.document(SimpleNamespace(), "x", "u") is None
