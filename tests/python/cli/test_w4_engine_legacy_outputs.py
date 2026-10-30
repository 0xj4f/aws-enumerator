"""The d13c215 legacy outputs of ``analysis/`` (F-022, Wave 4): compact JSON, and ``--no-legacy-outputs``.

* The twelve legacy files (``permission_map.json``, ``trust_relationships.json``, the ten ``*_relationships.json``)
  stay on by default for one release (DECISIONS.md D-22) but are written compact (``separators=(",", ":")``, keys
  sorted): their bytes are exactly ``writers.legacy.render`` of their content, and the per-domain edge records
  are the graph's edges (the same edge ids, and ``render_from_graph`` output where no analyzer stored its own).
* ``--no-legacy-outputs`` on ``analyze`` and ``collect`` (``cli.py`` -> ``commands.py`` / ``runner.py`` ->
  ``engine_adapter._options(legacy_outputs=False)``) leaves all twelve out; graph.json, findings.json and
  summary.json are still written, and a v2 run's manifest digests stay consistent (``verify``).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tests.python.orchestration import r_harness as R
from tests.support import report_builder as rb
from tests.support import targets

pytestmark = pytest.mark.finding("F-022")

W2 = "eu-west-2"
SCENARIO = "data_services"
CORE_FILES = {"graph.json", "findings.json", "summary.json"}
#: Domain files their analyzer renders itself (``ctx.set_legacy_output``, analyzers/s3.py ``store_legacy_file``).
STORED = ("s3_relationships.json", "ec2_relationships.json")


def _legacy():
    return targets.engine_module("writers.legacy")


def _report(tmp_path: Path) -> Path:
    """The old single-region layout of the ``data_services`` scenario (its ``analyze`` root)."""
    report_dir = rb.materialize(SCENARIO, tmp_path / "tree")[0]
    return report_dir.parent if rb.get(SCENARIO).layout == "all_mode" else report_dir


def _analysis_files(root: Path) -> set:
    return {p.name for p in (root / "analysis").iterdir() if p.is_file()}


def test_legacy_files_are_compact_and_carry_the_graph_edges(tmp_path, monkeypatch):
    root = _report(tmp_path)
    code, out, err = R.invoke(["analyze", str(root)], monkeypatch)
    assert code == 0, err[-2000:]
    analysis = root / "analysis"
    legacy = _legacy()
    assert set(legacy.LEGACY_OUTPUTS) <= _analysis_files(root)
    graph = json.loads((analysis / "graph.json").read_text(encoding="utf-8"))
    nodes = {n["id"]: n for n in graph["nodes"]}
    et = targets.engine_module("graph.edge_types").EDGE_TYPES
    for name in legacy.LEGACY_OUTPUTS:
        raw = (analysis / name).read_bytes()
        doc = json.loads(raw)
        # compact and canonical: the bytes are the writer's rendering of the parsed content, on one line
        assert raw == legacy.render(doc), name
        assert raw == (json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                       + "\n").encode("utf-8"), name
        assert raw.count(b"\n") == 1, name
        if name not in legacy.DOMAIN_FILES:
            continue
        # parse-equality with the graph: the file's edge records are the graph edges rendered into it
        expected = {e["id"] for e in graph["edges"] if e["type"] in et
                    and et[e["type"]].legacy_file_for(nodes[e["source"]]["type"]) == name}
        got = {r["edge_id"] for r in doc["edges"]}
        if name in STORED:
            # rendered by their analyzer (d13c215 record fields) from the edges that analyzer emitted
            assert got <= expected, name
        else:
            assert doc["edges"] == legacy.render_from_graph(graph, name)["edges"], name
            assert got == expected, name
    pretty = json.dumps(json.loads((analysis / "permission_map.json").read_bytes()), sort_keys=True, indent=2)
    assert len((analysis / "permission_map.json").read_bytes()) < len(pretty)


def test_analyze_with_no_legacy_outputs_writes_none_of_them(tmp_path, monkeypatch):
    root = _report(tmp_path)
    code, out, err = R.invoke(["analyze", str(root), "--no-legacy-outputs"], monkeypatch)
    assert code == 0, err[-2000:]
    assert out.strip() == str(root / "analysis")
    files = _analysis_files(root)
    assert CORE_FILES <= files
    assert not [f for f in files if f.endswith("_relationships.json")]
    assert not set(_legacy().LEGACY_OUTPUTS) & files
    # the per-domain counts are still reported (from the graph), only the files are not written
    summary = json.loads((root / "analysis" / "summary.json").read_text(encoding="utf-8"))
    assert summary["legacy_edge_counts"]["s3"] > 0


@pytest.fixture(scope="module")
def collected(tmp_path_factory):
    """One small acme collection with the real engine and ``--no-legacy-outputs``."""
    mp = pytest.MonkeyPatch()
    tmp = tmp_path_factory.mktemp("w4-legacy-off")
    try:
        run = R.collect(["collect", "--region", W2, "--modules", "iam,vpc,sg", "--no-legacy-outputs"], tmp, mp)
        assert run.exit_code in (0, 2), run.err[-2000:]
        return run.run_root
    finally:
        mp.undo()


def test_collect_with_no_legacy_outputs_reaches_the_engine(collected, tmp_path, monkeypatch):
    root = tmp_path / collected.parent.name / collected.name
    shutil.copytree(collected, root)
    files = _analysis_files(root)
    assert CORE_FILES <= files
    assert not set(_legacy().LEGACY_OUTPUTS) & files
    manifest = R.load(root / "manifest.json")
    assert manifest["analysis"]["status"] in ("ok", "partial")
    listed = {f["path"] for f in manifest["files"]}
    assert "analysis/graph.json" in listed and not [p for p in listed if p.endswith("_relationships.json")]
    code, out, err = R.invoke(["verify", str(root)], monkeypatch)
    assert code == 0 and out.startswith("OK "), err[-2000:]
    # re-analysing without the flag brings the legacy files back (the default is unchanged)
    code, _out, err = R.invoke(["analyze", str(root)], monkeypatch)
    assert code in (0, 2), err[-2000:]
    assert set(_legacy().LEGACY_OUTPUTS) <= _analysis_files(root)


def test_the_flag_exists_on_collect_and_analyze_only():
    parser = targets.main_module().build_parser()
    for argv, attr in ((["analyze", "x", "--no-legacy-outputs"], True), (["analyze", "x"], False),
                       (["collect", "--region", W2, "--no-legacy-outputs"], True)):
        assert parser.parse_args(argv).no_legacy_outputs is attr
    with pytest.raises(SystemExit):
        parser.parse_args(["export", "x", "--format", "csv", "--no-legacy-outputs"])
