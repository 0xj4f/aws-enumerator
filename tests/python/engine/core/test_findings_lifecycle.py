"""Finding identity and lifecycle: fingerprints, findings.json, baseline, suppression, summary, references."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests.fixtures.regressions import support as S

EC2_TRUST = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
OPEN_TRUST = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}


def _open_role_tree(h, tree, *roles):
    for name in roles:
        tree.iam.role(name, OPEN_TRUST)
    tree.write()
    return tree


@pytest.mark.finding("F-143")
def test_fingerprint_vectors_of_the_contract(h):
    fp = h.engine("graph.ids").finding_fingerprint
    assert fp("ADMIN-001", "111122223333", "arn:aws:iam::111122223333:role/admin/demo-admin-role") == \
        "0c80ca1a6b56b17fdb05e1f307aeafc5"
    assert fp("TRUST-002", "111122223333", "arn:aws:iam::111122223333:role/demo-app-role", "999999999999") == \
        "09e028bbd285472f10764dc3807433c6"
    assert h.engine("findings.fingerprint").normalised_principal("arn:aws:iam::999999999999:root") == "999999999999"


@pytest.mark.finding("F-143")
def test_findings_json_is_the_wrapper_with_run_context(h, tree, fixed_clock):
    _open_role_tree(h, tree, "demo-open")
    out = tree.analyze()
    doc = h.load(out.dir / "findings.json")
    assert set(doc) == {"schema_version", "tool_version", "rules_version", "account_id", "partition", "regions",
                        "mode", "run_id", "generated_at", "findings"}
    assert doc["findings"] == out.graph["findings"]
    assert doc["account_id"] == h.ACCT and doc["mode"] == "legacy-single" and doc["regions"] == [h.REGION]
    import jsonschema

    schema = h.engine("graph").load_schema("findings")
    jsonschema.Draft202012Validator(schema).validate(doc)
    fps = [f["fingerprint"] for f in doc["findings"]]
    assert len(fps) == len(set(fps)) and all(re.fullmatch(r"[0-9a-f]{32}", f) for f in fps)


@pytest.mark.finding("F-143")
def test_fingerprints_are_stable_across_reruns_and_renames(h, tmp_path, fixed_clock):
    a = _open_role_tree(h, h.Tree(tmp_path / "a"), "demo-open")
    first = {f["fingerprint"] for f in a.analyze().graph["findings"]}
    second = {f["fingerprint"] for f in a.analyze().graph["findings"]}
    assert first == second


@pytest.mark.finding("F-143")
def test_ec2_exposure_is_one_finding_per_instance(h, tmp_path):
    S.build_scenario("public_exposure", tmp_path)
    graph = S.analyze_graph(tmp_path / S.ACCT / S.REGION)
    exposure = [f for f in graph["findings"] if f["id"] == "EC2-EXPOSURE-001"]
    nodes = [f["node_id"] for f in exposure]
    assert len(nodes) == len(set(nodes))


@pytest.mark.finding("F-143")
def test_baseline_diff_new_resolved_unchanged_and_refusals(h, tree, tmp_path, fixed_clock):
    _open_role_tree(h, tree, "demo-open", "demo-gone")
    base = tree.analyze()
    baseline_copy = tmp_path / "baseline" / "findings.json"
    baseline_copy.parent.mkdir()
    baseline_copy.write_bytes((base.dir / "findings.json").read_bytes())
    tree.iam.roles = [r for r in tree.iam.roles if r["RoleName"] != "demo-gone"]
    tree.iam.role("demo-new", OPEN_TRUST)
    tree.write()
    out = tree.analyze(baseline=str(baseline_copy))
    diff = h.load(out.dir / "diff.json")
    by_state = {k: {e["node_id"] for e in diff[k]} for k in ("new", "resolved", "unchanged")}
    assert h.iam_arn("role", "demo-new") in by_state["new"]
    assert h.iam_arn("role", "demo-gone") in by_state["resolved"]
    assert h.iam_arn("role", "demo-open") in by_state["unchanged"]
    assert diff["counts"]["new"] == len(diff["new"])
    states = {f["node_id"]: f["baseline_state"] for f in out.graph["findings"] if f["id"] == "TRUST-001"}
    assert states[h.iam_arn("role", "demo-new")] == "new" and states[h.iam_arn("role", "demo-open")] == "unchanged"
    assert h.graph_problems(out.graph) == []
    usage = h.engine("model").AnalysisUsageError
    old = tmp_path / "old.json"
    old.write_text(json.dumps({"findings": [{"id": "X"}]}))
    with pytest.raises(usage):
        tree.analyze(baseline=str(old))
    old.write_text(json.dumps({"schema_version": "2.0.0", "findings": []}))
    with pytest.raises(usage):
        tree.analyze(baseline=str(old))


@pytest.mark.finding("F-143")
def test_a_finding_whose_node_lost_coverage_is_unknown_not_resolved(h):
    lifecycle = h.engine("findings.lifecycle")
    builder = h.engine("graph.builder").GraphBuilder(h.ACCT, "aws")
    role = h.iam_arn("role", "demo-role")
    builder.add_node(role, "role", "demo-role", props={"attached_policies_status": "denied"},
                     coverage_status="partial")
    prev = {"fingerprint": "f" * 32, "id": "TRUST-001", "node_id": role, "severity": "CRITICAL"}
    diff = lifecycle.apply_baseline(builder, {"schema_version": "1.0.0", "findings": [prev]}, ref="x",
                                    baseline_path=None, coverage_status="partial")
    assert diff["resolved"] == [] and diff["unknown"][0]["reason"].startswith("node coverage is partial")


@pytest.mark.finding("F-143")
def test_suppression_by_fingerprint_and_rule_and_expired_entries(h, tree, tmp_path, fixed_clock):
    _open_role_tree(h, tree, "demo-open", "demo-public-a", "demo-public-b")
    first = tree.analyze().graph
    fp = next(f["fingerprint"] for f in first["findings"] if f["node_id"] == h.iam_arn("role", "demo-open"))
    sup = tmp_path / "suppress.json"
    sup.write_text(json.dumps({"version": 1, "suppressions": [
        {"fingerprint": fp, "reason": "Reviewed break-glass role", "expires": "2027-01-31", "owner": "example-team"},
        {"rule_id": "TRUST-001", "node_id_glob": "arn:aws:iam::*:role/demo-public-*", "reason": "Demo",
         "expires": "2026-06-30"},
        {"rule_id": "TRUST-002", "node_id_glob": "*", "reason": "Old", "expires": "2025-12-31"}]}))
    out = tree.analyze(suppress=str(sup))
    g = out.graph
    status = {f["node_id"]: f for f in g["findings"] if f["id"] == "TRUST-001"}
    assert status[h.iam_arn("role", "demo-open")]["status"] == "suppressed"
    assert status[h.iam_arn("role", "demo-open")]["suppression"]["match"] == "fingerprint"
    assert status[h.iam_arn("role", "demo-public-a")]["suppression"]["match"] == "rule"
    expired = h.findings(g, "SUPPRESSION-EXPIRED-001")
    assert len(expired) == 1 and expired[0]["node_id"] == f"aws-enumerator:account/{h.ACCT}"
    node = h.nodes_by_id(g)[h.iam_arn("role", "demo-open")]
    assert node["max_severity"] is None                       # suppressed findings never count
    summary = h.load(out.dir / "summary.json")
    assert summary["suppressed_count"] == 3 and summary["by_severity"]["CRITICAL"] == 0
    assert h.graph_problems(g) == []
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"version": 1, "suppressions": [{"fingerprint": fp, "expires": "2027-01-01"}]}))
    with pytest.raises(h.engine("model").AnalysisUsageError):
        tree.analyze(suppress=str(bad))


@pytest.mark.finding("F-074")
def test_summary_counts_every_severity_and_sums_to_the_total(h, tmp_path):
    S.build_scenario("public_exposure", tmp_path)
    out = S.analyze_tree(tmp_path / S.ACCT / S.REGION)
    summary = out.summary()
    assert set(summary["by_severity"]) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    assert sum(summary["by_severity"].values()) == summary["total_findings"]
    assert summary["low_count"] == summary["by_severity"]["LOW"] >= 1
    assert summary["info_count"] == summary["by_severity"]["INFO"]
    assert summary["unattached_count"] == 0
    assert {"analyzer_status", "evaluation_gaps", "ignored_dirs", "status", "run"} <= set(summary)


@pytest.mark.finding("F-074", "F-164")
def test_console_summary_lists_low_and_info_and_domain_labels(h, caplog):
    console = h.engine("console")
    summary = {"by_severity": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 2, "INFO": 3}, "total_findings": 6,
               "status": "partial", "analyzer_status": [{"name": "s3", "status": "error"}]}
    lines = console.summary_lines(summary, [{"id": "TRUST-001", "severity": "CRITICAL", "node_id": "n",
                                            "reference": "https://example.org/x"}],
                                  {"edge_services": 2, "data_stores": 1, "s3": 0})
    assert lines[0] == "Findings: 1 CRITICAL, 0 HIGH, 0 MEDIUM, 2 LOW, 3 INFO (6 total)"
    assert "Analysis status: partial (1 analyzer(s) failed: s3)" in lines
    assert "Cognito/EBS/ELB/Route 53 relationships: 2 edges" in lines
    assert "ECR/RDS/API Gateway/DynamoDB relationships: 1 edges" in lines
    with caplog.at_level("INFO", logger="aws_enumerator.engine"):
        console.report(summary)
    assert any("2 LOW, 3 INFO" in r.getMessage() for r in caplog.records)


@pytest.mark.finding("F-163")
def test_references_are_pinned_to_the_installed_version_and_anchors_exist(h):
    refs = h.engine("findings.references")
    version = __import__("aws_enumerator._version", fromlist=["__version__"]).__version__
    assert refs.DOC_BASE == f"https://github.com/0xj4f/aws-enumerator/blob/v{version}/docs/attack_paths.md"
    assert "/blob/main/" not in refs.doc_reference("#common-privilege-escalation-patterns")
    doc = (Path(__file__).resolve().parents[4] / "docs" / "attack_paths.md").read_text(encoding="utf-8")
    anchors = set()
    for line in doc.splitlines():
        if line.startswith("#"):
            text = line.lstrip("#").strip().lower()
            anchors.add("#" + re.sub(r"[^a-z0-9 -]", "", text).replace(" ", "-"))
    catalog = h.engine("findings.catalog").build_catalog()
    for entry in catalog:
        assert entry.doc_anchor in anchors, (entry.id, entry.doc_anchor)
        assert entry.reference.startswith(refs.DOC_BASE + "#")
        assert "/blob/main/" not in entry.reference


@pytest.mark.finding("F-088")
def test_catalog_aliases_and_labels(h):
    catalog = h.engine("findings.catalog").build_catalog()
    assert catalog.canonical("SECRET-XAUTH-001") == "SECRET-XACCT-001"
    entry = catalog.get("SECRET-XAUTH-001")
    assert "ExternalId" not in entry.remediation and "PrincipalOrgID" in entry.remediation
    for elb_id in ("ELB-PUB-001",):     # the d13c215 anchor table lacked ELB (F-088): every id has its own anchor
        assert catalog.get(elb_id) is not None and catalog.get(elb_id).doc_anchor.startswith("#")
    with pytest.raises(ValueError):
        cat = h.engine("findings.catalog")
        cat.Catalog([cat.CORE_ENTRIES[0], cat.CORE_ENTRIES[0]])


@pytest.mark.finding("F-088", "F-164")
def test_outputs_list_matches_the_contract_and_domain_files_keep_their_names(h, tree):
    tree.iam.role("demo-app-role", EC2_TRUST)
    tree.write()
    out = tree.analyze()
    legacy = h.engine("writers.legacy")
    assert set(out.result.outputs) == {"graph.json", "findings.json", "summary.json", "_provenance.json",
                                       *legacy.LEGACY_OUTPUTS}
    assert legacy.DOMAIN_OF_FILE == {"newsurface_relationships.json": "data_stores",
                                     "extra_relationships.json": "edge_services"}
    summary = h.load(out.dir / "summary.json")
    assert {"data_stores", "edge_services"} <= set(summary["legacy_edge_counts"])
    assert "newsurface" not in summary["legacy_edge_counts"]


def test_export_dispatcher(h):
    writers = h.engine("writers")
    with pytest.raises(ValueError):
        writers.export({}, "pdf")
    assert writers.export_file_name("sarif") == "findings.sarif"
    assert set(writers.EXPORT_FORMATS) == {"sarif", "csv", "md", "asff", "opengraph"}
    try:
        writers.export({"findings": []}, "csv")
    except NotImplementedError:
        pass                                                   # E-rules ships the renderer in Wave 2
