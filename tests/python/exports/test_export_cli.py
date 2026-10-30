"""The export writers end to end: the dispatcher, ``aws-enumerator export`` and ``AnalysisOptions.exports``
(engine-api.md §6.3, cli.md §3.3, exports.md §1; F-141, F-165)."""

from __future__ import annotations

import csv
import importlib
import io
import json
import stat

import pytest

from aws_enumerator.engine import writers
from aws_enumerator.engine.model import AnalysisOptions
from tests.python.orchestration import r_harness as R

W = importlib.import_module("tests.fixtures.e-rules.worlds")
FILES = {"sarif": "findings.sarif", "csv": "findings.csv", "md": "findings.md", "asff": "findings.asff.json",
         "opengraph": "opengraph.json"}


def _world(tmp_path):
    w = W.World(tmp_path / "tree")
    w.admin_role("demo-fn-admin", W.trusts_service("lambda.amazonaws.com"))
    w.user("demo-dev", W.allow(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]))
    w.user("demo-keys", W.allow("iam:CreateAccessKey", "*"))
    return w


@pytest.mark.finding("F-141", "F-165")
def test_dispatcher_renders_every_format(example):
    assert set(writers.EXPORT_FORMATS) == set(FILES)
    for fmt, name in FILES.items():
        data = writers.export(example, fmt)
        assert isinstance(data, bytes) and data and writers.export_file_name(fmt) == name
        if fmt in ("sarif", "asff", "opengraph"):
            json.loads(data)
    with pytest.raises(ValueError):
        writers.export(example, "pdf")


@pytest.mark.finding("F-141", "F-165")
@pytest.mark.parametrize("fmt", sorted(FILES))
def test_cli_export_writes_the_default_file(tmp_path, monkeypatch, fmt):
    out = _world(tmp_path).analyze()
    report = out.dir.parent
    code, stdout, stderr = R.invoke(["export", str(report), "--format", fmt], monkeypatch)
    assert code == 0, stderr[-2000:]
    dest = report / "analysis" / "exports" / FILES[fmt]
    assert stdout.strip() == str(dest)
    assert dest.read_bytes() == writers.export(out.graph, fmt)
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600


@pytest.mark.finding("F-165")
def test_cli_export_filters_and_stdout(tmp_path, monkeypatch, capsysbinary):
    out = _world(tmp_path).analyze()
    report = out.dir.parent
    target = tmp_path / "high.csv"
    code, _o, err = R.invoke(["export", str(report), "--format", "csv", "--min-severity", "high",
                              "--output", str(target)], monkeypatch)
    assert code == 0, err
    rows = list(csv.reader(io.StringIO(target.read_text(encoding="utf-8"), newline="")))[1:]
    assert rows and {r[0] for r in rows} <= {"CRITICAL", "HIGH"}
    assert target.read_bytes() == writers.export(out.graph, "csv", min_severity="high")


@pytest.mark.finding("F-165")
def test_cli_export_refuses_a_legacy_report_without_graph_json(tmp_path, monkeypatch):
    report = _world(tmp_path).build()
    code, _o, err = R.invoke(["export", str(report), "--format", "sarif"], monkeypatch)
    assert code == 64 and "aws-enumerator analyze" in err


@pytest.mark.finding("F-141", "F-165")
def test_analysis_options_exports_write_into_analysis_exports(tmp_path):
    w = _world(tmp_path)
    report = w.build()
    from aws_enumerator.engine import analyze_report

    result = analyze_report(str(report), AnalysisOptions(exports=tuple(sorted(FILES))))
    assert result.status == "ok"
    graph = json.loads((report / "analysis" / "graph.json").read_text(encoding="utf-8"))
    for fmt, name in FILES.items():
        path = report / "analysis" / "exports" / name
        assert path.read_bytes() == writers.export(graph, fmt), fmt
