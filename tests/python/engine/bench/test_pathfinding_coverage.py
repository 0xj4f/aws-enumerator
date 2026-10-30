"""pathfinding.cloud coverage benchmark (engine.md §3.6; F-011).

The d13c215 rules fired on 40 of the 92 paths of the pinned dataset (55 counting resource edges). The gate is
at least 60/92 (PLAN.md), the target 80/92; ``coverage.json`` records the achieved figure, per path how it is
covered (finding and/or directed path to the account admin) and the negative-twin precision. This test recomputes
everything (about 300 offline analyses, ~30 s) and fails on a gate miss, a precision drop, or a path that the
committed ``coverage.json`` lists as covered but no longer is.
"""

from __future__ import annotations

import importlib
import json

import pytest

from tests.python.engine.bench import import_pathfinding as PF
from tests.python.engine.bench import pathfinding_harness as H

W = importlib.import_module("tests.fixtures.e-rules.worlds")

pytest.importorskip("yaml")

GATE = 60
TARGET = 80
MIN_TWIN_PRECISION = 0.95


@pytest.fixture(scope="module")
def coverage():
    return H.run()


@pytest.fixture(scope="module")
def recorded():
    return json.loads(H.COVERAGE_FILE.read_text(encoding="utf-8"))


@pytest.mark.finding("F-011")
def test_gate_at_least_60_of_92_paths(coverage):
    assert coverage["total"] == PF.EXPECTED_PATHS
    assert coverage["covered_count"] >= GATE, coverage["not_covered"]


@pytest.mark.finding("F-011")
def test_recorded_coverage_reaches_the_target_and_does_not_regress(coverage, recorded):
    assert recorded["covered_count"] >= TARGET, f"recorded {recorded['covered_count']}/92 < {TARGET}"
    lost = sorted(set(recorded["covered"]) - set(coverage["covered"]))
    assert not lost, f"paths recorded as covered are no longer covered: {lost}"
    assert recorded["dataset"]["commit"] == PF.read_pin()["commit"]


@pytest.mark.finding("F-011", "F-069", "F-012")
def test_negative_twins_do_not_fire(coverage):
    twins = coverage["twins"]
    assert twins["evaluated"] >= 150
    assert twins["precision"] >= MIN_TWIN_PRECISION, [
        (pid, removed, t["by"]) for pid, e in coverage["paths"].items() for removed, t in e["twins"].items()
        if t.get("fired") and not t.get("justified")]


@pytest.mark.finding("F-011")
def test_every_category_is_covered(coverage):
    by_cat = {k: tuple(int(x) for x in v.split("/")) for k, v in coverage["by_category"].items()}
    assert by_cat["self-escalation"] == (8, 8) and by_cat["principal-access"] == (14, 14)
    assert by_cat["new-passrole"][0] >= 45 and by_cat["existing-passrole"][0] >= 13


@pytest.mark.finding("F-011")
def test_every_covered_path_is_a_directed_path_or_a_critical_rule(coverage):
    for pid in coverage["covered"]:
        by = coverage["paths"][pid]["by"]
        assert any(b.startswith(("finding:", "path:")) for b in by), pid


@pytest.mark.finding("F-011")
def test_uncollected_resource_types_give_a_low_conditional_finding(tmp_path):
    """Step Functions state machines are not collected: the hijack rule reports what it cannot verify."""
    w = W.World(tmp_path)
    p = w.user("demo-sfn-operator", W.allow(["states:UpdateStateMachine", "states:StartExecution"], "*"))
    out = w.analyze()
    f = out.finding("PRIVESC-063", p)
    assert (f["severity"], f["confidence"]) == ("LOW", "conditional")
    assert "sfn_state_machine:not-collected" in f["gaps"] and "targets" not in f
    assert out.path(p) is None


@pytest.mark.finding("F-011")
def test_every_imported_rule_references_a_vendored_path():
    paths = {p.id for p in PF.load_paths()}
    cmap = PF.coverage_map(PF.load_paths(), PF.catalogue_rules())
    for rule_id, refs in cmap["by_rule"].items():
        assert set(refs) <= paths, (rule_id, sorted(set(refs) - paths))
    imported = [r for r in PF.catalogue_rules() if r.get("imported")]
    assert len(imported) >= 35 and all(r["references"].get("pathfinding_cloud") for r in imported)
    # sts-001 (sts:AssumeRole on a role that trusts the caller) is an identity edge (CAN_ASSUME), not a rule
    assert {pid for pid, rules in cmap["by_path"].items() if not rules} == {"sts-001"}
