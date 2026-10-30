"""Context, file-system helpers, coverage ledger and the organisation loader."""

from __future__ import annotations

import json
import os

import pytest

from tests.fixtures.regressions import support as S


def _ctx_v2(h, tmp_path, regions=("eu-west-2",), **manifest_changes):
    run = h.Run(tmp_path, regions=list(regions))
    run.iam.role("demo-app-role", {"Version": "2012-10-17", "Statement": []})
    run.write(manifest=run.manifest(**manifest_changes))
    return run, h.engine("context").build_run_context(run.path, regions=list(regions))


@pytest.mark.finding("F-171")
def test_context_clock_is_utc_and_reproducible(h, tmp_path, monkeypatch):
    context = h.engine("context")
    monkeypatch.setenv("SOURCE_DATE_EPOCH", h.EPOCH)
    _run, ctx = _ctx_v2(h, tmp_path)
    assert ctx.generated_at == "2026-01-01T00:00:00Z" and ctx.reproducible
    assert ctx.reference_time.tzinfo is not None
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "not-a-number")
    _run, ctx = _ctx_v2(h, tmp_path / "b")
    assert not ctx.reproducible and ctx.generated_at.endswith("Z")
    assert context.iso_utc(ctx.reference_time).endswith("Z")


@pytest.mark.finding("F-146")
def test_context_takes_the_operator_from_the_manifest_and_honours_redaction(h, tmp_path):
    run, ctx = _ctx_v2(h, tmp_path)
    assert ctx.operator.caller_arn.endswith(":assumed-role/demo-operator/demo-session")
    assert not ctx.operator.redacted
    opts = h.engine("model").AnalysisOptions(redact_identity=True)
    ctx = h.engine("context").build_run_context(run.path, regions=[h.REGION], options=opts)
    assert ctx.operator.redacted and ctx.operator.principal_arn.endswith(":role/demo-operator")


@pytest.mark.finding("F-146")
def test_run_operator_in_graph_maps_the_session_to_its_role(h, tmp_path):
    run = h.Run(tmp_path)
    run.iam.role("demo-operator", {"Version": "2012-10-17", "Statement": []})
    run.write()
    g = run.analyze().graph
    assert g["run"]["operator"]["resolution"] == "assumed-role"
    assert g["run"]["operator"]["node_id"] == h.iam_arn("role", "demo-operator")
    assert h.iam_arn("role", "demo-operator") in g["meta"]["default_sources"]
    redacted = run.analyze(redact_identity=True).graph["run"]["operator"]
    assert redacted["redacted"] is True and redacted["arn"] == h.iam_arn("role", "demo-operator")


def test_legacy_manifest_caller_is_the_operator(h, tmp_path):
    t = h.Tree(tmp_path)
    t.iam.user("demo-operator")
    t.write()
    h.rb.write_manifest(t.path, account=h.ACCT, mode="single_region", region=h.REGION,
                        caller=h.iam_arn("user", "demo-operator"))
    op = t.analyze().graph["run"]["operator"]
    assert op["resolution"] == "exact" and op["node_id"] == h.iam_arn("user", "demo-operator")


@pytest.mark.finding("F-162")
def test_ls_sorted_and_error_stub_reads(h, tmp_path):
    fs = h.engine("io.fs")
    for name in ("b.json", "a.json", "c.json"):
        (tmp_path / name).write_text("[]")
    assert fs.ls_sorted(tmp_path) == ["a.json", "b.json", "c.json"]
    assert fs.ls_sorted(tmp_path / "missing") == []
    (tmp_path / "stub.json").write_text(json.dumps({"Error": "An error occurred (AccessDenied) when calling X"}))
    items, res = fs.read_list(tmp_path / "stub.json")
    assert items == [] and res.status == "error-stub" and res.error_code == "AccessDenied"
    assert fs.stub_status(res.error_code) == "denied" and fs.stub_status("ThrottlingException") == "throttled"
    (tmp_path / "bad.json").write_text("{not json")
    assert fs.read_json(tmp_path / "bad.json").status == "invalid"
    assert fs.read_json(tmp_path / "nope.json").status == "missing"


@pytest.mark.finding("F-162")
def test_loaders_never_depend_on_listing_order(h, tmp_path):
    loader = h.engine("io.loaders.iam")
    S.build_scenario("poweruser_notaction", tmp_path)
    path = tmp_path / S.ACCT / S.REGION
    a = loader.load_iam(path)
    b = S.with_listdir_reversed(lambda: loader.load_iam(path))
    assert [e.arn for e in a.entities()] == [e.arn for e in b.entities()]
    assert {k: v.versions for k, v in a.policies.items()} == {k: v.versions for k, v in b.policies.items()}


def test_coverage_ledger_reads_coverage_files_and_the_manifest_modules(h, tmp_path):
    ledger_mod = h.engine("io.coverage")
    g = tmp_path / "global" / "s3"
    g.mkdir(parents=True)
    (g / "_coverage.json").write_text(json.dumps({
        "schema_version": 1, "module": "s3", "region": "global", "status": "partial",
        "calls": [{"api": "s3:GetBucketPolicy", "status": "denied", "count": 2},
                  {"api": "s3:ListBuckets", "status": "ok", "count": 1}],
        "item_errors": [{"resource": "arn:aws:s3:::demo-a", "api": "s3:GetBucketPolicy", "status": "denied"}]}))
    manifest = {"modules": [{"name": "s3", "region": "global", "status": "partial", "status_reason": "denied",
                             "error": None}]}
    ledger = ledger_mod.CoverageLedger.from_dirs({"global": tmp_path / "global"}, legacy=False, manifest=manifest)
    assert ledger.facet("s3", "s3.bucket_policy", "global") == "denied"
    assert ledger.facet("s3", "s3.buckets", "global") == "complete"
    assert ledger.facet("s3", "s3.bucket_policy", "global", item="arn:aws:s3:::demo-a") == "denied"
    assert ledger.module_status("lambda", "eu-west-2") == "not-collected"
    block = ledger.graph_block()
    assert block["source"] == "ledger" and block["status"] == "partial"
    assert block["modules"] == [{"module": "s3", "region": "global", "status": "partial", "error_code": None,
                                 "detail": "denied"}]
    legacy = ledger_mod.CoverageLedger.from_dirs({"global": tmp_path / "global"}, legacy=True)
    assert legacy.graph_block()["status"] == "unknown"


def test_legacy_reports_disclose_coverage_not_recorded(h, tree):
    tree.iam.role("demo-app-role", {"Version": "2012-10-17", "Statement": []})
    tree.write()
    g = tree.analyze().graph
    codes = {x["code"] for x in g["evaluation_gaps"]}
    assert {"coverage-not-recorded", "iam:legacy-layout", "external-identity", "runtime-conditions",
            "session-policies"} <= codes
    assert g["coverage"]["source"] == "legacy-unknown" and g["coverage"]["status"] == "unknown"
    assert all(m["status"] == "legacy-unknown" for m in g["coverage"]["modules"])


def test_org_loader_keeps_unknown_as_unknown(h, tmp_path):
    org = h.engine("io.loaders.org")
    data, status = org.load_org(tmp_path)
    assert status == "missing" and data.in_organization is None
    assert set(data.gaps()) == {"org:scp-unknown", "org:rcp-unknown"}
    base = tmp_path / "organizations"
    base.mkdir()
    (base / "organization.json").write_text(json.dumps({"InOrganization": True, "Id": "o-abc",
                                                        "ManagementAccountId": h.FOREIGN}))
    (base / "ou_path.json").write_text(json.dumps([{"Id": "r-abcd"}, {"Id": h.ACCT}]))
    (base / "policies.json").write_text(json.dumps([{"PolicyId": "p-1", "Name": "deny-all",
                                                     "Type": "SERVICE_CONTROL_POLICY", "Targets": ["r-abcd"],
                                                     "Content": json.dumps({"Statement": []})}]))
    data, status = org.load_org(tmp_path)
    assert status == "ok" and data.gaps() == {} and len(data.chain() or ()) == 2
    assert data.raw["organization"]["Id"] == "o-abc"


def test_detect_layout(h, tmp_path):
    context = h.engine("context")
    (tmp_path / "acct" / "global").mkdir(parents=True)
    assert context.detect_layout(tmp_path / "acct") == "legacy-all"
    (tmp_path / "region" / "iam").mkdir(parents=True)
    assert context.detect_layout(tmp_path / "region") == "legacy-single"
    (tmp_path / "run").mkdir()
    (tmp_path / "run" / "manifest.json").write_text(json.dumps({"schema_version": "2.1"}))
    assert context.detect_layout(tmp_path / "run") == "run"
    assert context.manifest_major({"schema_version": "2.0"}) == 2
    assert context.is_known_region("us-gov-west-1") and context.is_known_region("cn-north-1")
    assert not context.is_known_region("global")
    assert os.path.isdir(tmp_path / "acct")
