"""MITRE ATT&CK tags (aws_enumerator/engine/attack.py, DECISIONS.md D-58).

The tables are internally consistent and name only real edge types and finding ids; the SARIF export carries the
tags. With ``AE_ATTACK_STIX`` pointing at MITRE's ``enterprise-attack-<version>.json``, the pinned names and
tactics are also checked against it (scripts/attack_catalog.py does the same by hand).
"""

from __future__ import annotations

import json
import os
import re
import runpy
from pathlib import Path

import pytest

from aws_enumerator.engine import attack, writers
from aws_enumerator.engine.findings.catalog import build_catalog
from aws_enumerator.engine.graph.edge_types import EDGE_TYPES
from tests.support import targets

TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
TACTIC_ID = re.compile(r"^TA\d{4}$")


def test_every_tag_names_a_real_edge_type_or_finding_id():
    assert set(attack.EDGE_TECHNIQUES) <= set(EDGE_TYPES)
    assert set(attack.FINDING_TECHNIQUES) <= set(build_catalog().ids())


def test_the_technique_table_holds_exactly_the_techniques_the_mappings_use():
    used = {t for ts in (*attack.EDGE_TECHNIQUES.values(), *attack.FINDING_TECHNIQUES.values()) for t in ts}
    assert used == set(attack.TECHNIQUES)
    shortnames = [t.shortname for t in attack.TACTICS]
    assert len(set(shortnames)) == len(shortnames) == 15
    assert all(TACTIC_ID.match(t.id) for t in attack.TACTICS)
    for tid, tech in attack.TECHNIQUES.items():
        assert TECHNIQUE_ID.match(tid), tid
        assert tech.tactics and set(tech.tactics) <= set(shortnames), tid
        assert list(tech.tactics) == sorted(tech.tactics, key=shortnames.index), f"{tid}: tactics not in matrix order"
        if "." in tid:
            assert ": " in tech.name, f"{tid}: a sub-technique is named 'Parent: Sub'"


def test_only_attacker_actions_are_tagged():
    """Structural edges (membership, attachment, placement, encryption) are never tagged; data flow neither."""
    for name in attack.EDGE_TECHNIQUES:
        t = EDGE_TYPES[name]
        assert t.traversal != "structural" and t.category != "flow", name


def test_tactics_follow_the_matrix_order():
    assert [t.id for t in attack.tactics_of(["T1530", "T1078.004", "T1548.005"])] == \
        ["TA0001", "TA0003", "TA0004", "TA0005", "TA0009"]
    assert attack.tactics_of(["T9999"]) == ()


def test_sarif_tags_name_techniques_then_tactics():
    assert attack.sarif_tags("PRIVESC-015") == ["external/mitre-attack/T1548.005", "external/mitre-attack/TA0004"]
    assert attack.sarif_tags("CLOUDTRAIL-001") == ["external/mitre-attack/T1685.002", "external/mitre-attack/TA0112"]
    assert attack.sarif_tags("COLLECTION-GAP-001") == []


def test_the_sarif_export_tags_each_rule_with_its_techniques():
    graph = json.loads((targets.graph_fixtures_dir() / "example.json").read_text("utf-8"))
    sarif = json.loads(writers.export(graph, "sarif").decode("utf-8"))
    rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rules, "the example graph has findings"
    for fid, rule in rules.items():
        tags = rule["properties"]["tags"]
        assert tags[:2] == ["security", "aws"]
        assert [t for t in tags if t.startswith("external/mitre-attack/")] == attack.sarif_tags(fid), fid
    assert any(attack.sarif_tags(fid) for fid in rules), "no rule of the example graph is tagged"


STIX = os.environ.get("AE_ATTACK_STIX", "")


@pytest.mark.skipif(not (STIX and Path(STIX).is_file()), reason="set AE_ATTACK_STIX to enterprise-attack-<v>.json")
def test_the_pinned_tables_match_mitre_stix():
    script = runpy.run_path(str(targets.REPO_ROOT / "scripts" / "attack_catalog.py"))
    assert script["check"](script["Stix"](Path(STIX))) == []
