"""End to end on a fake account: CLI -> run root -> zip -> dashboard core, plus exports, verify and old layouts.

One ``aws-enumerator collect --regions eu-west-1,eu-west-2 --zip --output <tmp>`` runs against the synthetic
``acme`` world through the routed fake AWS (``tests/python/collectors/legacy_harness.py`` patch points; no
network, no real AWS). Then, on that one run:

* the exit code matches the manifest (0 complete, 2 partial; acme denies some calls on purpose, so 2);
* ``manifest.json`` validates against ``manifest-2.0.schema.json``; ``analysis/graph.json`` against
  ``graph-1.0.schema.json`` and ``validate_graph(strict_order=True)``;
* ``node tests/js/helpers/load-zip-cli.js <zip>`` loads the zip through ``loader.js`` + ``graph-core.js`` exactly
  as the dashboard does: digest verified, no structural problem, the same node / edge / finding counts;
* ``aws-enumerator export --format sarif|csv|md|asff|opengraph`` each write a well-formed document;
* ``aws-enumerator verify`` passes for the run root and the zip;
* ``aws-enumerator analyze`` re-analyses a copy of each old (v0.2) report layout of ``tests/fixtures/scenarios``.

Findings: F-010 (analysis once, after collection), F-061 (exit codes), F-145 (zip loads in the dashboard core),
F-165 (exports), F-168 (digests and verify), F-063 (run-unique layout under ``--output``).
"""

from __future__ import annotations

import csv
import io
import json
import os
import pwd
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

import jsonschema
import pytest

from tests.fixtures.worlds import acme
from tests.python.collectors.legacy_harness import LegacyRun, run_legacy_main
from tests.python.orchestration import r_harness as R
from tests.support import targets

REGIONS = ("eu-west-1", "eu-west-2")
LOAD_ZIP_CLI = targets.REPO_ROOT / "tests" / "js" / "helpers" / "load-zip-cli.js"
SOURCE_DATE_EPOCH = "1767225600"   # 2026-01-01T00:00:00Z: reproducible analysis clock
NODE = shutil.which("node")
CSV_COLUMNS = ["severity", "id", "title", "node_id", "node_label", "node_type", "account", "region", "confidence",
               "category", "status", "fingerprint", "reference"]
EXPORT_FILES = {"sarif": "findings.sarif", "csv": "findings.csv", "md": "findings.md",
                "asff": "findings.asff.json", "opengraph": "opengraph.json"}


class E2E:
    """The one collect run every test of this module reads."""

    def __init__(self, run: LegacyRun, output: Path, decoy: Path):
        self.run, self.output, self.decoy = run, output, decoy
        lines = run.stdout_lines()
        assert len(lines) == 1, run.out
        self.run_root = Path(lines[0])

    @property
    def manifest(self) -> Dict[str, Any]:
        return R.load(self.run_root / "manifest.json")

    @property
    def graph(self) -> Dict[str, Any]:
        return R.load(self.run_root / "analysis" / "graph.json")

    @property
    def zip_path(self) -> Path:
        return self.run_root.parent / f"{self.run_root.name}.zip"

    def open_findings(self) -> List[Dict[str, Any]]:
        return [f for f in self.graph["findings"] if f.get("status") != "suppressed"]


@pytest.fixture(scope="module")
def e2e(tmp_path_factory) -> E2E:
    tmp = tmp_path_factory.mktemp("e2e")
    output, decoy = tmp / "out", tmp / "decoy"
    mp = pytest.MonkeyPatch()
    try:
        mp.setenv("AWS_ENUMERATOR_OUTPUT", str(decoy))       # --output must win over the environment
        run = run_legacy_main(["collect", "--regions", ",".join(REGIONS), "--zip", "--output", str(output)], tmp, mp,
                              source_date_epoch=SOURCE_DATE_EPOCH)
    finally:
        mp.undo()
    return E2E(run, output, decoy)


def _graph_problems(doc: Dict[str, Any]) -> List[str]:
    schema = json.loads(targets.engine_schema_path("graph-1.0.schema.json").read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    found = [f"schema:{'/'.join(map(str, e.absolute_path))}: {e.message[:160]}" for e in validator.iter_errors(doc)]
    validate = targets.engine_module("graph").validate_graph
    found.extend(f"{p.code}:{p.path}: {p.message}" for p in validate(doc, strict_order=True))
    return found


# ── collect ──────────────────────────────────────────────────────────────────
@pytest.mark.finding("F-061", "F-063", "F-010")
def test_collect_exit_code_layout_and_one_analysis(e2e):
    run, manifest = e2e.run, e2e.manifest
    status = manifest["run"]["status"]
    assert status in ("complete", "partial")
    assert run.exit_code == {"complete": 0, "partial": 2}[status] == manifest["run"]["exit_code"], run.err[-2000:]
    assert status == "partial"                               # acme denies some calls on purpose
    assert any(m["status"] in ("denied", "partial") for m in manifest["modules"])
    assert e2e.run_root.parent == e2e.output / acme.ACCOUNT_ID and e2e.run_root.is_dir()
    assert not e2e.decoy.exists() or not any(e2e.decoy.iterdir())
    assert sorted(manifest["target"]["regions"]) == list(REGIONS)
    assert len(run.analyze_calls) == 1 and run.analyze_calls[0].regions == list(REGIONS)
    assert set(run.analyze_calls[0].regional_dirs_present) == set(REGIONS)  # every unit existed (F-010)
    for entry in ("manifest.json", "HANDLING.txt", "SHA256SUMS", "run.log", "global", "analysis", *REGIONS):
        assert (e2e.run_root / entry).exists(), entry
    assert e2e.zip_path.is_file()


@pytest.mark.finding("F-168")
def test_manifest_validates_against_schema_2_0(e2e):
    manifest = e2e.manifest
    assert manifest["schema_version"].startswith("2.")
    assert R.validate_manifest(manifest) == []
    assert manifest["analysis"]["status"] in ("ok", "partial")
    assert manifest["analysis"]["engine"] == "v2" and manifest["analysis"]["graph_schema_version"] == "1.0.0"
    assert "analysis/graph.json" in {f["path"] for f in manifest["files"]}


def test_graph_json_validates_against_schema_1_0(e2e):
    graph = e2e.graph
    assert graph["schema_version"] == "1.0.0" and graph["run"]["mode"] == "run"
    assert graph["run"]["account_id"] == acme.ACCOUNT_ID and sorted(graph["run"]["regions"]) == list(REGIONS)
    assert _graph_problems(graph) == []
    assert graph["nodes"] and graph["edges"] and graph["findings"]


# ── the dashboard core reads the zip ─────────────────────────────────────────
@pytest.mark.finding("F-145", "F-168")
@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_the_zip_loads_through_the_dashboard_loader_and_graph_core(e2e):
    # version managers' shims (asdf, nvm) look up the user's real home, which the test guard redirects
    env = dict(os.environ, HOME=pwd.getpwuid(os.getuid()).pw_dir)
    proc = subprocess.run([NODE, str(LOAD_ZIP_CLI), str(e2e.zip_path)], capture_output=True, text=True, timeout=120,
                          cwd=targets.REPO_ROOT, env=env)
    assert proc.returncode == 0, proc.stderr + proc.stdout
    loaded = json.loads(proc.stdout)
    graph = e2e.graph
    assert loaded["root"] == f"{e2e.run_root.name}/" and loaded["kind"] == "ok"
    assert loaded["integrity"] == "verified"                  # digest of graph.json against manifest.files
    assert loaded["structural"] == 0, loaded["problems"]
    assert (loaded["nodes"], loaded["edges"], loaded["findings"] + loaded["unattached"]) == (
        len(graph["nodes"]), len(graph["edges"]), len(graph["findings"]))
    assert loaded["unattached"] == 0                           # every finding is attached to a node (F-005)
    assert (loaded["run_id"], loaded["account_id"], loaded["schema_version"]) == (
        graph["run"]["run_id"], acme.ACCOUNT_ID, "1.0.0")


# ── exports ──────────────────────────────────────────────────────────────────
def _export(e2e: E2E, fmt: str, monkeypatch) -> bytes:
    code, out, err = R.invoke(["export", str(e2e.run_root), "--format", fmt], monkeypatch)
    dest = e2e.run_root / "analysis" / "exports" / EXPORT_FILES[fmt]
    assert (code, out.strip()) == (0, str(dest)), err
    assert R.mode(dest) == 0o600
    return dest.read_bytes()


@pytest.mark.finding("F-165")
def test_export_sarif(e2e, monkeypatch):
    doc = json.loads(_export(e2e, "sarif", monkeypatch))
    assert doc["version"] == "2.1.0" and "sarif-2.1.0" in doc["$schema"]
    (run,) = doc["runs"]
    assert run["tool"]["driver"]["name"] == "aws-enumerator"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert len(run["results"]) == len(e2e.open_findings())
    for result in run["results"]:
        assert result["ruleId"] in rule_ids and result["level"] in ("error", "warning", "note")
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "analysis/graph.json"


@pytest.mark.finding("F-165")
def test_export_csv(e2e, monkeypatch):
    text = _export(e2e, "csv", monkeypatch).decode("utf-8")
    assert not text.startswith("﻿") and text.endswith("\r\n")
    rows = list(csv.reader(io.StringIO(text, newline="")))
    assert rows[0] == CSV_COLUMNS
    assert len(rows) - 1 == len(e2e.open_findings())
    assert all(line.startswith('"') for line in text.split("\r\n") if line)   # every field quoted
    assert {r[6] for r in rows[1:]} == {acme.ACCOUNT_ID}


@pytest.mark.finding("F-165")
def test_export_markdown(e2e, monkeypatch):
    text = _export(e2e, "md", monkeypatch).decode("utf-8")
    run = e2e.graph["run"]
    assert text.startswith(f"# aws-enumerator findings: {acme.ACCOUNT_ID} ({run['run_id']})\n")
    assert "| Severity | Count |" in text and text.endswith("\n") and not text.endswith("\n\n")
    table = [line for line in text.splitlines() if line.startswith("| ") and not line.startswith("| Severity |")
             and line.count("|") >= 7]
    assert len(table) == len(e2e.open_findings())
    assert "<script" not in text.lower()


@pytest.mark.finding("F-165")
def test_export_asff(e2e, monkeypatch):
    doc = json.loads(_export(e2e, "asff", monkeypatch))
    findings = doc["Findings"]
    assert len(findings) == len(e2e.open_findings())
    labels = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}
    for item in findings:
        assert item["SchemaVersion"] == "2018-10-08" and item["AwsAccountId"] == acme.ACCOUNT_ID
        assert item["Severity"]["Label"] in labels and item["Id"].startswith(f"aws-enumerator/{acme.ACCOUNT_ID}/")
        assert item["Resources"] and item["RecordState"] == "ACTIVE"


@pytest.mark.finding("F-165", "F-141")
def test_export_opengraph(e2e, monkeypatch):
    doc = json.loads(_export(e2e, "opengraph", monkeypatch))
    assert doc["metadata"]["source_kind"] == "AWSEnumerator"
    nodes, edges = doc["graph"]["nodes"], doc["graph"]["edges"]
    ids = {n["id"] for n in nodes}
    assert ids == {n["id"] for n in e2e.graph["nodes"]}
    assert all("AWSEnumerator" in n["kinds"] for n in nodes)
    assert edges and all(e["properties"]["traversable"] is True for e in edges)   # traversable only by default
    assert all(e["start"]["value"] in ids and e["end"]["value"] in ids for e in edges)


# ── verify ───────────────────────────────────────────────────────────────────
@pytest.mark.finding("F-168")
def test_verify_the_run_root_and_the_zip(e2e, monkeypatch):
    for target in (e2e.run_root, e2e.zip_path):
        code, out, err = R.invoke(["verify", str(target)], monkeypatch)
        assert code == 0 and out.startswith("OK "), (target.name, out, err)


# ── old report layouts are still analysable ──────────────────────────────────
@pytest.mark.finding("F-010")
@pytest.mark.parametrize("scenario, rel, mode", [
    ("all_mode", "111122223333", "legacy-all"),
    ("single_region_minimal", "111122223333/eu-west-2", "legacy-single"),
    ("cross_account", "123456789012/eu-west-2", "legacy-single"),
])
def test_analyze_an_old_layout(tmp_path, monkeypatch, scenario, rel, mode):
    """``analyze_report`` + the loaders' old-shape handling on a copy of a frozen v0.2 scenario tree."""
    tree = tmp_path / scenario
    shutil.copytree(targets.scenario_fixtures_dir() / scenario / "tree", tree)
    report = tree / rel
    code, out, err = R.invoke(["analyze", str(report)], monkeypatch)
    assert code in (0, 2), err
    analysis = Path(out.strip())
    assert analysis == report / "analysis" and (analysis / "graph.json").is_file(), (out, err)
    graph = R.load(analysis / "graph.json")
    assert graph["run"]["mode"] == mode and graph["coverage"]["source"] == "legacy-unknown"
    assert _graph_problems(graph) == []
    assert (analysis / "_provenance.json").is_file()
    status = {s["name"]: s["status"] for s in graph["analyzer_status"]}
    assert "error" not in status.values(), status
