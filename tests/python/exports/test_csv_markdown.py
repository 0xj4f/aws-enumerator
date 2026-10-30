"""Findings CSV and Markdown exports (exports.md §1, §3, §4; F-165), including byte parity with the dashboard's
``AEExports.findingsCsv`` / ``findingsMarkdown`` (dashboard-core-api.md §4; D-12, D-24, D-25, D-50)."""

from __future__ import annotations

import copy
import csv
import io

import pytest

from aws_enumerator.engine import writers
from aws_enumerator.engine.writers import csv as csv_writer
from aws_enumerator.engine.writers import markdown as md_writer

pytestmark = pytest.mark.finding("F-165")

HEADER = ("severity,id,title,node_id,node_label,node_type,account,region,confidence,category,status,fingerprint,"
          "reference")


def _rows(data: bytes):
    return list(csv.reader(io.StringIO(data.decode("utf-8"), newline="")))


# ── CSV ──────────────────────────────────────────────────────────────────────

def test_csv_dialect_header_and_quoting(example):
    data = writers.export(example, "csv")
    text = data.decode("utf-8")
    assert not text.startswith("﻿") and text.endswith("\r\n") and "\n" not in text.replace("\r\n", "")
    first = text.split("\r\n", 1)[0]
    assert first == ",".join(f'"{c}"' for c in HEADER.split(","))
    rows = _rows(data)
    assert rows[0] == HEADER.split(",")
    open_findings = [f for f in example["findings"] if f["status"] != "suppressed"]
    assert len(rows) - 1 == len(open_findings)
    for line in text.split("\r\n")[1:-1]:
        assert line.startswith('"') and line.endswith('"')


def test_csv_neutralises_formulas_and_keeps_newlines():
    graph = {"schema_version": "1.0.0", "run": {"account_id": "111122223333"}, "generator": {}, "nodes": [],
             "findings": [{"id": "X-001", "severity": "HIGH", "node_id": "n", "fingerprint": "f1", "status": "open",
                           "title": "=cmd|' /C calc'!A0", "category": "+SUM(A1)", "reference": "@x",
                           "confidence": "-1", "region": None, "account": "\tTAB"},
                          {"id": "X-002", "severity": "low", "node_id": "n", "fingerprint": "f2", "status": "open",
                           "title": 'say "hi"\nline2\rcr', "region": "eu-west-2"}]}
    rows = _rows(writers.export(graph, "csv"))
    first, second = rows[1], rows[2]
    assert first[2] == "'=cmd|' /C calc'!A0" and first[9] == "'+SUM(A1)" and first[12] == "'@x"
    assert first[8] == "'-1" and first[6] == "'\tTAB" and first[7] == ""          # region null -> empty cell
    assert second[2] == 'say "hi"\nline2\rcr' and second[6] == "111122223333"   # account falls back to the run's
    assert second[0] == "low"                                                   # stored severity copied as-is


def test_csv_filters_and_order(example):
    rows = _rows(writers.export(example, "csv", min_severity="HIGH"))[1:]
    assert rows and all(r[0].upper() in ("CRITICAL", "HIGH") for r in rows)
    everything = _rows(writers.export(example, "csv", include_suppressed=True))[1:]
    assert any(r[10] == "suppressed" for r in everything)
    ranks = [csv_writer.severity_rank(r[0]) for r in everything]
    assert ranks == sorted(ranks)
    keys = [(csv_writer.severity_rank(r[0]), r[1], r[3], r[11]) for r in everything]
    assert keys == sorted(keys)
    with pytest.raises(ValueError):
        writers.export(example, "csv", min_severity="severe")


def test_csv_lists_and_cells():
    assert csv_writer.cell_text(["a", 1, True, None, ["x", "y"]]) == 'a;1;true;;["x","y"]'
    assert csv_writer.cell_text({"k": "v"}) == '{"k":"v"}' and csv_writer.cell_text(None) == ""
    assert csv_writer.cell_text(2.0) == "2" and csv_writer.cell_text(0.5) == "0.5"
    assert csv_writer.csv_cell("=1") == "\"'=1\"" and csv_writer.csv_cell('a"b') == '"a""b"'


# ── Markdown ─────────────────────────────────────────────────────────────────

def test_markdown_layout(example):
    text = writers.export(example, "md").decode("utf-8")
    lines = text.split("\n")
    assert lines[0] == "# aws-enumerator findings: 111122223333 (20260101T000000Z-a1b2c3)"
    assert lines[2].startswith("Generated 2026-01-01T00:00:00Z by aws-enumerator 0.3.0. Regions: eu-west-2. ")
    assert lines[2].endswith("CONFIDENTIAL: see HANDLING.txt.")
    assert lines[4:11] == ["| Severity | Count |", "|---|---|", lines[6], lines[7], lines[8], lines[9], lines[10]]
    assert [ln.split(" | ")[0] for ln in lines[6:11]] == ["| Critical", "| High", "| Medium", "| Low", "| Info"]
    assert "| Severity | ID | Title | Resource | Type | Region |" in lines
    assert text.endswith("|\n") and not text.endswith("\n\n")
    for ln in lines:
        if ln.startswith("| ") and "ADMIN-001" in ln:
            assert ln.endswith("| role | global |")


def test_markdown_escapes_every_report_string(hostile):
    text = writers.export(hostile, "md").decode("utf-8")
    assert "<" not in text and ">" not in text                  # no raw HTML from report data
    assert "&lt;img src=x onerror=window.__aeXssCanary=1&gt;" in text
    table = [ln for ln in text.split("\n") if ln.startswith("| ") and "|---" not in ln]
    widths = {ln.replace("\\|", "").count("|") for ln in table if "Count" not in ln and ln.count("|") > 3}
    assert widths == {7}                                         # one row, six cells, whatever the strings hold
    assert md_writer.md_escape("a|b`c[d]e\\f\r\ng<h>&") == "a\\|b\\`c\\[d\\]e\\\\f  g&lt;h&gt;&amp;"


def test_markdown_fallbacks_and_no_findings():
    """D-50: the pinned fallbacks of exports.js."""
    text = writers.export({"schema_version": "1.0.0", "run": {}, "generator": {}, "nodes": [], "findings": []},
                          "md").decode("utf-8")
    assert text == ("# aws-enumerator findings: unknown account (unknown run)\n\n"
                    "Generated at an unknown time by aws-enumerator unknown version. Regions: none. "
                    "CONFIDENTIAL: see HANDLING.txt.\n\n| Severity | Count |\n|---|---|\n| Critical | 0 |\n"
                    "| High | 0 |\n| Medium | 0 |\n| Low | 0 |\n| Info | 0 |\n\nNo findings.\n")


# ── parity with the dashboard (exports.md §3, §4) ────────────────────────────

@pytest.mark.parametrize("name", ["example", "hostile", "analysed"])
def test_python_and_dashboard_exports_are_byte_identical(name, request, js_exports):
    graph = request.getfixturevalue(name)
    js = js_exports(graph)
    unfiltered = dict(graph, findings=[dict(f, status="open") for f in graph["findings"]])
    js_all = js_exports(unfiltered)
    assert writers.export(unfiltered, "csv").decode("utf-8") == js_all["csv"]
    assert writers.export(unfiltered, "md").decode("utf-8") == js_all["md"]
    # The dashboard exports what it is given; the CLI drops suppressed findings unless asked (exports.md §1).
    assert writers.export(graph, "csv", include_suppressed=True).decode("utf-8") == js["csv"]


def test_exports_are_deterministic(analysed):
    shuffled = copy.deepcopy(analysed)
    shuffled["findings"] = list(reversed(shuffled["findings"]))
    shuffled["nodes"] = list(reversed(shuffled["nodes"]))
    for fmt in writers.EXPORT_FORMATS:
        assert writers.export(analysed, fmt) == writers.export(shuffled, fmt), fmt
