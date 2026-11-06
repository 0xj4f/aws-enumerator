"""E-core pipeline: entry points, explicit regions, isolation, status, staged writes, determinism."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fixtures.regressions import support as S

EC2_TRUST = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}

GRAPH_FILES = {"graph.json", "findings.json", "summary.json"}


def _instance(h, iid, region, profile=None):
    return h.rb.ec2_instance(iid, account=h.ACCT, region=region, profile=profile)


# ── public API surface ───────────────────────────────────────────────────────

def test_engine_package_exports_the_contract_api(h):
    eng = h.engine()
    for name in ("analyze_run", "analyze_report", "ENGINE_SCHEMA_VERSION", "AnalysisOptions", "AnalysisResult"):
        assert hasattr(eng, name), name
    assert not hasattr(eng, "analyze")          # the d13c215 entry point was removed in Wave 3 (D-53)


@pytest.mark.finding("F-084")
def test_registry_lists_every_planned_module_and_reports_missing_ones(h):
    pipeline = h.engine("pipeline")
    planned = set(pipeline.ANALYZER_MODULES)
    for module in ("aws_enumerator.engine.analyzers.s3", "aws_enumerator.engine.analyzers.cognito",
                   "aws_enumerator.engine.analyzers.coverage_gaps", "aws_enumerator.engine.iam.hygiene",
                   "aws_enumerator.engine.graph.closure", "aws_enumerator.engine.rules.runner"):
        assert module in planned
    specs, missing = pipeline.collect_specs()
    names = [r.spec.name for r in specs]
    assert len(names) == len(set(names)), "analyzer names are unique"
    assert {"permission-map", "iam-graph", "trust", "assume"} <= set(names)
    orders = [r.order for r in specs]
    assert orders == sorted(orders)
    assert missing == [] and {r.origin for r in specs} == {"native"}
    # a module that cannot be imported yields exactly one error status (an engine defect), never an exception;
    # a module without ANALYZERS is not_implemented
    specs2, missing2 = pipeline.collect_specs(("aws_enumerator.engine.analyzers.does_not_exist",
                                               "aws_enumerator.engine.graph.ids"))
    assert specs2 == [] and [m.status for m in missing2] == ["error", "not_implemented"]
    assert missing2[0].error_type == "ModuleNotFoundError"


# ── explicit regions (F-010, F-025, F-063) ───────────────────────────────────

@pytest.mark.finding("F-025", "F-063")
def test_v2_run_reads_only_the_explicit_regions_and_reports_the_rest(h, tmp_path):
    run = h.Run(tmp_path, regions=[h.REGION])
    run.iam.role("demo-app-role", EC2_TRUST)
    prof = run.iam.instance_profile("demo-app-profile", ["demo-app-role"])
    run.write()
    run.scope(h.REGION).write("ec2/instances.json", [_instance(h, "i-0a1b2c3d4e5f60aaa", h.REGION, prof)])
    stray = run.scope(h.OTHER)  # an earlier run's or a .stale copy's region: not in the manifest
    h.rb.write_empty_regional(stray)
    stray.write("ec2/instances.json", [_instance(h, "i-0a1b2c3d4e5f60bbb", h.OTHER, prof)])
    out = run.analyze()
    assert out.result.status == "ok"
    ids = set(h.nodes_by_id(out.graph))
    assert f"arn:aws:ec2:{h.REGION}:{h.ACCT}:instance/i-0a1b2c3d4e5f60aaa" in ids
    assert not [n for n in ids if "i-0a1b2c3d4e5f60bbb" in n]
    assert out.graph["run"]["regions"] == [h.REGION] and out.graph["run"]["mode"] == "run"
    summary = h.load(out.dir / "summary.json")
    assert summary["ignored_dirs"] == [h.OTHER]
    # nothing but analysis/ was written, and no transient directory survives
    assert sorted(p.name for p in run.path.iterdir()) == sorted(["analysis", "global", "manifest.json", h.OTHER,
                                                                 h.REGION])


@pytest.mark.finding("F-025")
def test_empty_region_does_not_import_a_neighbours_instances(h, tmp_path):
    run = h.Run(tmp_path, regions=[h.REGION, h.OTHER])
    run.iam.role("demo-app-role", EC2_TRUST)
    prof = run.iam.instance_profile("demo-app-profile", ["demo-app-role"])
    run.write()
    run.scope(h.OTHER).write("ec2/instances.json", [_instance(h, "i-0a1b2c3d4e5f60ccc", h.OTHER, prof)])
    out = run.analyze()
    inst = [n for n in out.graph["nodes"] if n["type"] == "instance"]
    assert [n["region"] for n in inst] == [h.OTHER]   # attributed to its own region only
    role = h.iam_arn("role", "demo-app-role")
    assert h.edges(out.graph, "INSTANCE_ROLE", target=role)


@pytest.mark.finding("F-010")
def test_legacy_all_layout_uses_the_region_directories_as_the_region_list(h, tmp_path):
    acct = tmp_path / "20261015" / h.ACCT
    g = h.rb.Scope(tmp_path / "20261015", h.ACCT, "global")
    iam = h.rb.Iam(h.ACCT)
    iam.role("demo-app-role", EC2_TRUST)
    prof = iam.instance_profile("demo-app-profile", ["demo-app-role"])
    iam.write(g)
    for region in (h.REGION, h.OTHER):
        r = h.rb.Scope(tmp_path / "20261015", h.ACCT, region)
        h.rb.write_empty_regional(r)
        r.write("ec2/instances.json", [_instance(h, f"i-0a1b2c3d4e5f6{region[-1]}00a", region, prof)])
    (acct / "not-a-region").mkdir()
    out = h.engine().analyze_report(str(acct))
    graph = h.load(Path(out.graph_path))
    assert graph["run"]["mode"] == "legacy-all"
    assert graph["run"]["regions"] == sorted([h.REGION, h.OTHER])
    assert graph["run"]["run_id"] == "legacy-20261015"
    assert len(h.edges(graph, "INSTANCE_ROLE")) == 2
    prov = h.load(acct / "analysis" / "_provenance.json")
    assert prov["source_layout"] == "legacy-all" and prov["regions"] == graph["run"]["regions"]
    assert prov["input_files"] > 0
    assert h.load(acct / "analysis" / "summary.json")["ignored_dirs"] == ["not-a-region"]


@pytest.mark.finding("F-010")
def test_legacy_single_directory_keeps_the_old_analysis_once_as_analysis_orig(h, tree):
    tree.iam.role("demo-app-role", EC2_TRUST)
    path = tree.write()
    (path / "analysis").mkdir()
    (path / "analysis" / "findings.json").write_text('{"findings": []}')
    out = tree.analyze()
    assert out.result.status == "ok"
    assert (path / "analysis.orig" / "findings.json").is_file()
    assert (path / "analysis" / "_provenance.json").is_file()
    assert out.graph["run"]["mode"] == "legacy-single" and out.graph["run"]["regions"] == [h.REGION]
    # a second analysis replaces analysis/ and never touches analysis.orig/
    tree.analyze()
    assert (path / "analysis.orig" / "findings.json").read_text() == '{"findings": []}'
    assert not (path / "analysis.tmp").exists() and not (path / "analysis.prev").exists()


def test_legacy_single_directory_with_an_unknown_region_name_has_no_region(h, tmp_path):
    t = h.Tree(tmp_path, region="demo-unknown-dir")
    t.iam.role("demo-app-role", EC2_TRUST)
    t.write()
    out = t.analyze()
    assert out.graph["run"]["regions"] == []
    assert "legacy:region-unknown" in {g["code"] for g in out.graph["evaluation_gaps"]}


def test_usage_errors(h, tmp_path):
    usage = h.engine("model").AnalysisUsageError
    (tmp_path / "empty").mkdir()
    with pytest.raises(usage):
        h.engine().analyze_report(str(tmp_path / "empty"))
    with pytest.raises(FileNotFoundError):
        h.engine().analyze_run(str(tmp_path / "missing"), regions=[h.REGION])
    run = h.Run(tmp_path / "r")
    manifest = run.manifest()
    manifest["run"] = dict(manifest["run"], status="in_progress")
    run.write(manifest=manifest)
    with pytest.raises(usage):
        run.analyze()
    assert run.analyze(force=True).result.status == "ok"
    with pytest.raises(usage):
        h.engine().analyze_run(str(run.path), regions="eu-west-2")


# ── isolation and status (F-002, F-061) ──────────────────────────────────────

@pytest.mark.finding("F-002", "F-061")
def test_a_failing_analyzer_is_isolated_and_the_result_is_partial(h, tree, monkeypatch):
    tree.iam.role("demo-app-role", EC2_TRUST)
    tree.iam.user("demo-dev", access_keys=1)
    tree.write()
    from aws_enumerator.engine.analyzers import lambda_ as lam

    def boom(*_a, **_k):
        raise RuntimeError("demo failure\nwith a second line")

    monkeypatch.setattr(lam, "analyze_lambda", boom)
    out = tree.analyze()
    assert out.result.status == "partial"
    by_name = {s.name: s for s in out.result.analyzer_status}
    assert by_name["lambda"].status == "error" and by_name["lambda"].error_type == "RuntimeError"
    assert by_name["lambda"].error_message == "demo failure with a second line"
    assert by_name["iam-graph"].status == "ok" and by_name["trust"].status == "ok"
    for name in GRAPH_FILES | {"permission_map.json", "s3_relationships.json", "lambda_relationships.json"}:
        assert (out.dir / name).is_file(), name
    assert h.load(out.dir / "lambda_relationships.json")["status"] == "error"
    assert h.graph_problems(out.graph) == []
    status = {s["name"]: s for s in out.graph["analyzer_status"]}
    assert status["lambda"]["error"] == {"type": "RuntimeError", "message": "demo failure with a second line"}
    assert h.load(out.dir / "summary.json")["status"] == "partial"


@pytest.mark.finding("F-002")
def test_single_object_statements_never_crash_the_analysis(h, tree):
    single = {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Principal": {"AWS": "*"},
                                                     "Action": "sts:AssumeRole"}}
    tree.iam.role("demo-open-role", single)
    tree.iam.user("demo-dev", inline={"p": {"Version": "2012-10-17",
                                            "Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}}})
    tree.write()
    out = tree.analyze()
    assert out.result.status in ("ok", "partial")
    role = h.iam_arn("role", "demo-open-role")
    assert h.findings(out.graph, "TRUST-001", role)
    assert h.edges(out.graph, "CAN_ASSUME", "aws-enumerator:anonymous", role)


@pytest.mark.finding("F-061")
def test_result_reports_outputs_counts_and_schema_version(h, tree):
    tree.iam.role("demo-app-role", EC2_TRUST)
    tree.write()
    out = tree.analyze()
    r = out.result
    assert r.status == "ok" and r.graph_schema_version == "1.0.0"
    assert Path(r.graph_path) == out.dir / "graph.json"
    assert set(r.outputs) >= GRAPH_FILES | {"_provenance.json", "permission_map.json", "trust_relationships.json"}
    assert r.counts["nodes"] == len(out.graph["nodes"]) and r.counts["edges"] == len(out.graph["edges"])
    assert set(r.counts) >= {"critical", "high", "medium", "low", "info"}
    phases = [s.phase for s in r.analyzer_status]
    assert phases == sorted(phases)


@pytest.mark.finding("F-061")
def test_an_unwritable_graph_is_an_error_and_keeps_the_previous_analysis(h, tree, monkeypatch):
    tree.iam.role("demo-app-role", EC2_TRUST)
    tree.write()
    first = tree.analyze()
    before = (first.dir / "graph.json").read_bytes()
    from aws_enumerator.engine.writers import graph_json

    def invalid(doc):
        raise graph_json.GraphInvalid(["demo:problem"])

    monkeypatch.setattr(graph_json, "checked", invalid)
    result = h.engine().analyze_report(str(tree.path))
    assert result.status == "error" and result.graph_path is None
    assert result.analyzer_status[-1].name == "write" and result.analyzer_status[-1].status == "error"
    assert (first.dir / "graph.json").read_bytes() == before
    assert not (tree.path / "analysis.tmp").exists()


# ── staged writes and permissions ────────────────────────────────────────────

def test_outputs_are_private_and_exactly_the_contract_file_set(h, tree):
    tree.iam.role("demo-app-role", EC2_TRUST)
    tree.write()
    out = tree.analyze()
    legacy = h.engine("writers.legacy").LEGACY_OUTPUTS
    assert sorted(p.name for p in out.dir.iterdir()) == sorted(GRAPH_FILES | set(legacy) | {"_provenance.json"})
    assert oct(out.dir.stat().st_mode & 0o777) == "0o700"
    assert {oct(p.stat().st_mode & 0o777) for p in out.dir.iterdir()} == {"0o600"}
    out2 = tree.analyze(legacy_outputs=False)
    assert sorted(p.name for p in out2.dir.iterdir()) == sorted(GRAPH_FILES | {"_provenance.json"})


@pytest.mark.finding("F-171")
def test_generated_at_is_utc_and_honours_source_date_epoch(h, tree, monkeypatch):
    tree.iam.role("demo-app-role", EC2_TRUST)
    tree.write()
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    live = tree.analyze().graph["run"]["generated_at"]
    assert live.endswith("Z") and len(live) == 20
    monkeypatch.setenv("SOURCE_DATE_EPOCH", h.EPOCH)
    assert tree.analyze().graph["run"]["generated_at"] == "2026-01-01T00:00:00Z"
    assert tree.analyze(source_date_epoch=86400).graph["run"]["generated_at"] == "1970-01-02T00:00:00Z"
    findings_doc = h.load(tree.path / "analysis" / "findings.json")
    assert findings_doc["generated_at"] == "1970-01-02T00:00:00Z"


@pytest.mark.finding("F-162")
def test_two_analyses_are_byte_identical_whatever_the_listing_order(h, tmp_path, fixed_clock):
    S.build_scenario("data_services", tmp_path / "a")
    S.build_scenario("data_services", tmp_path / "b")
    a = h.engine().analyze_report(str(tmp_path / "a" / S.ACCT / S.REGION))
    b = S.with_listdir_reversed(lambda: h.engine().analyze_report(str(tmp_path / "b" / S.ACCT / S.REGION)))
    files_a = {p.name: p.read_bytes() for p in Path(a.analysis_dir).iterdir()}
    files_b = {p.name: p.read_bytes() for p in Path(b.analysis_dir).iterdir()}
    assert files_a.keys() == files_b.keys()
    differing = sorted(n for n in files_a if files_a[n] != files_b[n] and n != "_provenance.json")
    assert differing == []
    graph = json.loads(files_a["graph.json"])
    assert graph["findings"], "an empty analysis proves nothing"
    assert all(s.get("duration_seconds") is None for s in graph["analyzer_status"])


@pytest.mark.finding("F-162")
def test_graph_json_is_canonical_compact_json(h, tree, fixed_clock):
    tree.iam.role("demo-app-role", EC2_TRUST)
    tree.write()
    out = tree.analyze()
    raw = (out.dir / "graph.json").read_text(encoding="utf-8")
    doc = json.loads(raw)
    assert raw == json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert h.engine("graph").validate_graph(doc, strict_order=True) == []


def test_analysis_result_is_returned_for_a_v2_report_through_analyze_report(h, run):
    run.iam.role("demo-app-role", EC2_TRUST)
    run.write()
    result = h.engine().analyze_report(str(run.path))
    assert result.status == "ok"
    graph = h.load(Path(result.graph_path))
    assert graph["run"]["mode"] == "run" and graph["coverage"]["source"] == "ledger"
    assert graph["run"]["source_manifest_sha256"] and not (run.path / "analysis" / "_provenance.json").exists()


@pytest.mark.finding("F-025", "F-063")
def test_loaders_read_only_the_explicit_units_of_a_run(h, run, monkeypatch):
    """The loaders open files under ``global`` and the manifest's regions only (no sibling scan, no view)."""
    run.iam.role("demo-app-role", EC2_TRUST)
    run.write()
    stray = run.path / "eu-north-1" / "s3"
    stray.mkdir(parents=True)
    (stray / "buckets.json").write_text("[]", encoding="utf-8")
    fs = h.engine("io.fs")
    opened = set()
    real = fs.read_json

    def spy(path):
        opened.add(Path(path).resolve().relative_to(run.path.resolve()).parts[0])
        return real(path)

    monkeypatch.setattr(fs, "read_json", spy)
    for module in h.engine("io.loaders").LOADER_MODULES.values():
        mod = __import__(module, fromlist=["read_json"])
        if getattr(mod, "read_json", None) is real:
            monkeypatch.setattr(mod, "read_json", spy)
    run.analyze()
    assert opened and opened <= {"global", h.REGION}
    assert not (run.path / "analysis" / ".legacy-view").exists()
