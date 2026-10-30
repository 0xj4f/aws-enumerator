"""The analysis reference time is the report's recorded start, never the wall clock (F-162, F-171).

``IAM-KEY-AGE-001`` once carried ``evidence.reference_time`` = the wall clock (the manifest end time was not set yet
when the runner analysed), so two analyses of the same run differed and the collectors-v0 determinism goldens failed.
``ctx.reference_time`` is now ``SOURCE_DATE_EPOCH``, else the manifest ``run.started_at`` (then ``ended_at``), else
an old report's ``run_metadata.timestamp_start`` or ``YYYYMMDD`` date directory; the wall clock stands in only when
the report records no time, disclosed as ``clock:reference-time-unknown``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

OLD_KEY = "2024-06-01 00:00:00+00:00"


def _stale_key_user(iam) -> str:
    arn = iam.user("demo-keys", access_keys=1)
    iam.users[-1]["AccessKeys"][0]["CreateDate"] = OLD_KEY
    return arn


def _without_generated_at(path: Path) -> str:
    """The graph without its run clock (``generated_at``, analyzer durations): what must be byte-identical."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["run"].pop("generated_at", None)
    for status in doc["analyzer_status"]:
        status.pop("duration_seconds", None)
    return json.dumps(doc, sort_keys=True)


@pytest.mark.finding("F-162", "F-171")
def test_a_run_is_aged_against_its_recorded_start_and_reanalyses_are_identical(h, run, monkeypatch):
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    user = _stale_key_user(run.iam)
    run.write()
    first = run.analyze()
    started = run.manifest()["run"]["started_at"]
    [finding] = h.findings(first.graph, "IAM-KEY-AGE-001", user)
    assert finding["evidence"]["reference_time"] == started            # not the wall clock
    graph_one = _without_generated_at(first.dir / "graph.json")
    findings_one = (first.dir / "findings.json").read_text(encoding="utf-8")
    second = run.analyze()
    assert _without_generated_at(second.dir / "graph.json") == graph_one
    assert json.loads((second.dir / "findings.json").read_text(encoding="utf-8"))["findings"] == \
        json.loads(findings_one)["findings"]
    assert "clock:reference-time-unknown" not in {g["code"] for g in second.graph["evaluation_gaps"]}


@pytest.mark.finding("F-171")
def test_an_old_report_uses_its_recorded_start(h, tree, monkeypatch):
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    user = _stale_key_user(tree.iam)
    tree.write()
    out = tree.analyze()
    [finding] = h.findings(out.graph, "IAM-KEY-AGE-001", user)
    assert finding["evidence"]["reference_time"] == "2026-01-01T00:00:00Z"   # run_metadata.timestamp_start


@pytest.mark.finding("F-171")
def test_source_date_epoch_wins_and_an_unrecorded_time_is_a_gap(h, tree, monkeypatch, fixed_clock):
    user = _stale_key_user(tree.iam)
    tree.write()
    manifest = tree.path / "manifest.json"
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    doc["run_metadata"].pop("timestamp_start")
    doc["run_metadata"].pop("timestamp_end")
    manifest.write_text(json.dumps(doc), encoding="utf-8")
    fixed = tree.analyze()
    assert h.findings(fixed.graph, "IAM-KEY-AGE-001", user)[0]["evidence"]["reference_time"] == \
        "2026-01-01T00:00:00Z"
    assert "clock:reference-time-unknown" not in {g["code"] for g in fixed.graph["evaluation_gaps"]}
    monkeypatch.delenv("SOURCE_DATE_EPOCH")
    loose = tree.analyze()
    assert "clock:reference-time-unknown" in {g["code"] for g in loose.graph["evaluation_gaps"]}
