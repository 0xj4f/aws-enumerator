"""The rule catalogue as data (engine.md §3.1-§3.2; F-019, F-069): schema, invariants, loader checks."""

from __future__ import annotations

import copy
import json

import jsonschema
import pytest

from aws_enumerator.engine import rules
from aws_enumerator.engine.rules import catalogue as cat

PASSROLE_RULES = {f"PRIVESC-{n:03d}" for n in range(14, 21)}


def _docs():
    return cat.read_document("privesc.json"), cat.read_document("dangerous.json")


def test_data_files_validate_against_the_schema():
    schema = json.loads(cat.SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    for doc in _docs():
        assert list(validator.iter_errors(doc)) == []


@pytest.mark.finding("F-011")
def test_catalogue_loads_every_legacy_rule_and_the_split_ones():
    """The 23 Wave 1 rules keep their ids; the pathfinding.cloud import continues the numbering without gaps
    (request e-rules-1; rules_version 2.1.0)."""
    c = cat.load_catalogue()
    ids = [r.id for r in c.privesc]
    assert ids[:23] == [f"PRIVESC-{n:03d}" for n in range(1, 24)]
    assert ids == [f"PRIVESC-{n:03d}" for n in range(1, len(ids) + 1)]      # contiguous, no gaps
    assert [d.id for d in c.dangerous] == [f"DANGER-{n:03d}" for n in range(1, 11)]
    assert c.version == "2.1.0" and c.get("DANGER-009").capability["actions_any"] == [
        "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]


@pytest.mark.finding("F-015", "F-069")
def test_every_passrole_rule_probes_passed_to_service_and_has_a_run_step():
    c = cat.load_catalogue()
    assert PASSROLE_RULES <= {r.id for r in c.privesc if r.rule_class == "new-passrole"}
    for rule in c.privesc:
        leaves = list(cat.iter_leaves(rule.steps))
        passrole = [leaf for leaf in leaves if leaf.action == "iam:passrole"]
        if rule.rule_class == "new-passrole":
            assert rule.selector == "passable_service_role" and len(passrole) == 1
            assert dict(passrole[0].context)["iam:PassedToService"] == rule.target["service_principal"]
            assert len(leaves) >= 2, rule.id            # PassRole alone never completes a chain
        else:
            assert not passrole, rule.id


@pytest.mark.finding("F-069")
def test_existing_resource_actions_are_passrole_free_rules():
    c = cat.load_catalogue()
    by_action = {leaf.action: r.id for r in c.privesc for leaf in cat.iter_leaves(r.steps)
                 if r.rule_class == "existing-resource"}
    assert by_action == {"lambda:updatefunctioncode": "PRIVESC-021", "glue:updatedevendpoint": "PRIVESC-022",
                         "codebuild:startbuild": "PRIVESC-023", "codebuild:startbuildbatch": "PRIVESC-023"}
    ecs = c.get("PRIVESC-017")
    ecs_actions = {leaf.action for leaf in cat.iter_leaves(ecs.steps)}
    assert {"ecs:createservice", "ecs:updateservice"} <= ecs_actions


@pytest.mark.finding("F-019")
def test_danger_templates_cover_service_scoped_wildcards():
    c = cat.load_catalogue()
    probes = {d.id: d.probe(partition="aws-us-gov", account="111122223333") for d in c.dangerous}
    assert probes["DANGER-006"].resource_template == "arn:aws-us-gov:iam::111122223333:role/*"
    assert probes["DANGER-002"].resource_template == "arn:aws-us-gov:iam::111122223333:*"
    assert probes["DANGER-001"].resource_template == "*"
    assert all(p.mode == "covers" for p in probes.values())


def test_catalog_entries_feed_the_finding_catalogue():
    entries = {e["id"]: e for e in rules.catalog_entries()}
    loaded = cat.load_catalogue()
    assert len(entries) == len(loaded.privesc) + len(loaded.dangerous)        # 67 + 10 after the import
    assert entries["PRIVESC-014"]["severity"] == "CRITICAL" and entries["PRIVESC-014"]["category"] == \
        "privilege_escalation"
    assert entries["DANGER-006"]["severity"] == "MEDIUM" and entries["DANGER-006"]["category"] == \
        "dangerous_permission"


def test_notice_is_shipped_with_an_attribution_section():
    text = (cat.DATA_DIR / "NOTICE").read_text(encoding="utf-8")
    assert "pathfinding.cloud" in text and "Apache License 2.0" in text


@pytest.mark.parametrize("mutate,message", [
    (lambda p, d: p["rules"][0].update(id="BAD-1"), "bad privesc rule id"),
    (lambda p, d: p["rules"][0]["target"].update(select="nope"), "unknown target selector"),
    (lambda p, d: p["rules"][0].update(steps={"all": []}), "non-empty list"),
    (lambda p, d: p["rules"][0].update(steps={"action": "not an action"}), "bad step action"),
    (lambda p, d: p["rules"][1].update(id=p["rules"][0]["id"]), "declared twice"),
    (lambda p, d: d.update(rules_version="9.9.9"), "different rules_version"),
    (lambda p, d: d["rules"][0]["capability"].pop("action_glob"), "exactly one of"),
    (lambda p, d: p["rules"][0].update(base_severity="SEVERE"), "bad severity"),
    (lambda p, d: p["rules"][13]["target"].pop("service_principal"), "needs service_principal"),
])
def test_loader_rejects_malformed_data(mutate, message):
    privesc, danger = copy.deepcopy(_docs())
    mutate(privesc, danger)
    with pytest.raises(cat.RuleDataError, match=message):
        cat.build_catalogue(privesc, danger)
