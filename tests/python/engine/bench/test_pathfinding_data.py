"""The vendored pathfinding.cloud dataset (engine.md §3.6; F-011): pinned, licensed, complete, unmodified."""

from __future__ import annotations

import pytest

from tests.python.engine.bench import import_pathfinding as PF

pytest.importorskip("yaml")


@pytest.mark.finding("F-011")
def test_dataset_is_pinned_and_unmodified():
    pin = PF.read_pin()
    assert pin["repository"] == "https://github.com/DataDog/pathfinding.cloud"
    assert pin["commit"].startswith("ecc3d09") and len(pin["commit"]) == 40
    assert len(pin["archive_sha256"]) == 64
    assert PF.verify_pin() == []


@pytest.mark.finding("F-011")
def test_dataset_licence_is_apache_2_and_the_notice_is_kept():
    license_text = (PF.DATA_DIR / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in license_text and "Version 2.0, January 2004" in license_text
    assert "Datadog" in (PF.DATA_DIR / "NOTICE").read_text(encoding="utf-8")


@pytest.mark.finding("F-011")
def test_all_92_paths_parse_with_permissions_and_a_category():
    paths = PF.load_paths()
    assert len(paths) == PF.EXPECTED_PATHS and len({p.id for p in paths}) == PF.EXPECTED_PATHS
    assert {p.category for p in paths} == {"self-escalation", "principal-access", "new-passrole", "existing-passrole"}
    for p in paths:
        assert p.required and all(":" in a for a in p.required), p.id
    passrole = [p for p in paths if p.category == "new-passrole" and p.uses_passrole]
    assert all(p.trusted_services for p in passrole if p.id != "cloudformation-004"), [
        p.id for p in passrole if not p.trusted_services]


@pytest.mark.finding("F-011")
def test_skeletons_and_the_coverage_map():
    paths = {p.id: p for p in PF.load_paths()}
    sk = PF.skeleton_rule(paths["lambda-001"], "PRIVESC-999")
    assert sk["imported"] is True and sk["references"]["pathfinding_cloud"] == ["lambda-001"]
    assert sk["target"] == {"select": "passable_service_role", "service_principal": "lambda.amazonaws.com"}
    assert [leaf["action"] for leaf in sk["steps"]["all"]][0] == "iam:PassRole"
    cmap = PF.coverage_map(list(paths.values()), PF.catalogue_rules())
    assert "PRIVESC-014" in cmap["by_path"]["lambda-001"] and "lambda-001" in cmap["by_rule"]["PRIVESC-014"]


def test_the_vendored_data_holds_only_placeholder_account_ids():
    import re

    placeholders = {"123456789012", "111122223333", "999999999999", "000000000000"}
    for f in sorted((PF.DATA_DIR / "paths").rglob("*.yaml")):
        found = set(re.findall(r"(?<!\d)\d{12}(?!\d)", f.read_text(encoding="utf-8")))
        assert found <= placeholders, (f.name, sorted(found - placeholders))
