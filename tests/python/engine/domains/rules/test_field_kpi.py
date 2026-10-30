"""Subsumption KPI (engine.md §3.4; F-018): on a field-shaped account the administrator-equivalent principals hold
less than 20 % of the findings (the review measured 86-96 % on real accounts before subsumption)."""

from __future__ import annotations

import importlib

import pytest

W = importlib.import_module("tests.fixtures.e-rules.worlds")
FIELD = importlib.import_module("tests.fixtures.e-rules.field")


def _without_subsumption(monkeypatch):
    from aws_enumerator.engine import pipeline

    real = pipeline.collect_specs

    def collect(modules=pipeline.ANALYZER_MODULES):
        specs, missing = real(modules)
        return [r for r in specs if r.spec.name != "subsume"], missing

    monkeypatch.setattr(pipeline, "collect_specs", collect)


@pytest.fixture(scope="module")
def field(tmp_path_factory):
    w, admins = FIELD.build(tmp_path_factory.mktemp("field"))
    return w.analyze(), admins


@pytest.mark.finding("F-018")
def test_admin_share_is_below_20_percent(field):
    out, admins = field
    share = W.admin_share(out.graph, admins)
    assert share < 0.20, f"admin share {share:.1%} of {len(out.graph['findings'])} findings"
    assert W.graph_problems(out.graph) == []


@pytest.mark.finding("F-018")
def test_each_admin_is_reported_once(field):
    out, admins = field
    admin_findings = out.findings("ADMIN-001")
    anchors = sorted(f["node_id"] for f in admin_findings)
    members = sorted(m for f in admin_findings for m in f.get("affected_members") or ())
    assert sorted(anchors + members) == sorted(admins)
    for a in anchors:
        assert [i for i in out.ids_at(a) if i.startswith(("PRIVESC-", "DANGER-"))] == []


@pytest.mark.finding("F-018")
def test_without_subsumption_admins_dominate(tmp_path, monkeypatch):
    """The same world without the subsumption pass reproduces the F-018 shape (most findings on admins)."""
    _without_subsumption(monkeypatch)
    w, admins = FIELD.build(tmp_path)
    out = w.analyze()
    assert not out.findings("ADMIN-001")
    assert W.admin_share(out.graph, admins) > 0.5
