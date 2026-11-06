"""The finding catalogue and its documentation agree (DOC2, Wave 3b; F-135, F-088, F-163).

The anchor checks use ``scripts/gen_docs.py``'s re-implementation of GitHub's heading slugs, which is itself
pinned here against hand-computed GitHub anchors.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
DOCS = REPO / "docs"


def _gen_docs():
    name = "aws_enumerator_gen_docs"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / "gen_docs.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


@pytest.fixture(scope="module")
def gen():
    return _gen_docs()


@pytest.fixture(scope="module")
def catalog():
    from aws_enumerator.engine.findings.catalog import build_catalog

    return build_catalog()


# GitHub anchors of real headings (github-slugger: lower-case; keep letters, marks, numbers, "_", " " and "-";
# spaces become "-"; repeats get "-1", "-2" ...).
SLUG_VECTORS = [
    ("Scenario 1 — You compromised an EC2 instance", "scenario-1--you-compromised-an-ec2-instance"),
    ("Scenario 6 — You're external (no foothold yet)", "scenario-6--youre-external-no-foothold-yet"),
    ("Resource-Exposure & External-Access Findings", "resource-exposure--external-access-findings"),
    ("High-Value Targets to Hunt", "high-value-targets-to-hunt"),
    ("Edge Type Reference (Translating Graph → Action)", "edge-type-reference-translating-graph--action"),
    ("`MEMBER_OF`", "member_of"),
    ("CAN_ASSUME_WEB_IDENTITY", "can_assume_web_identity"),
    ("PRIVESC-014", "privesc-014"),
    ("K8S-DEFAULT-SA", "k8s-default-sa"),
    ("What's new? (v0.3.0)", "whats-new-v030"),
    ("aws-enumerator collect", "aws-enumerator-collect"),
    ("Role assumption (`trust`)", "role-assumption-trust"),
    ("Café **Ünïcode**", "café-ünïcode"),
]


@pytest.mark.finding("F-135")
@pytest.mark.parametrize(("heading", "anchor"), SLUG_VECTORS)
def test_github_slug_algorithm(gen, heading, anchor):
    assert gen.github_slug(gen.heading_text(heading)) == anchor


@pytest.mark.finding("F-135")
def test_repeated_headings_get_numbered_anchors_and_fences_are_skipped(gen):
    text = "# A\n\n## Step 1\n\n```\n# not a heading\n```\n\n## Step 1\n\n### Step 1\n"
    assert [h.anchor for h in gen.headings(text)] == ["a", "step-1", "step-1-1", "step-1-2"]
    assert gen.section_lines(text, "#step-1-1") == ["## Step 1", "", "### Step 1"]


@pytest.mark.finding("F-135", "F-163")
def test_every_catalogue_reference_is_version_pinned_and_built_from_its_anchor(catalog):
    from aws_enumerator._version import __version__
    from aws_enumerator.engine.findings.references import DOC_BASE, REPOSITORY_URL, doc_reference

    assert DOC_BASE == f"{REPOSITORY_URL}/blob/v{__version__}/docs/attack_paths.md"
    for entry in catalog:
        assert entry.doc_anchor.startswith("#"), entry.id
        assert entry.reference == doc_reference(entry.doc_anchor) == DOC_BASE + entry.doc_anchor
        assert "/blob/main/" not in entry.reference


@pytest.mark.finding("F-135", "F-088")
def test_the_reference_index_lists_exactly_the_catalogue(catalog, gen):
    text = (DOCS / "reference" / "findings.md").read_text(encoding="utf-8")
    documented = {h.text for h in gen.headings(text) if h.level == 2} - {"Index"}
    assert documented == set(catalog.ids())
    for entry in catalog:
        section = "\n".join(gen.section_lines(text, "#" + gen.github_slug(entry.id)))
        assert entry.severity in section and entry.category in section, entry.id
        assert f"attack_paths.md{entry.doc_anchor}" in section, entry.id
        for alias in entry.legacy_ids:
            assert alias in section, (entry.id, alias)


@pytest.mark.finding("F-135")
def test_every_rule_of_the_rule_data_is_documented(gen):
    from aws_enumerator.engine.rules.catalogue import read_document

    reference = (DOCS / "reference" / "findings.md").read_text(encoding="utf-8")
    guide = (DOCS / "attack_paths.md").read_text(encoding="utf-8")
    ref_anchors = {h.anchor for h in gen.headings(reference)}
    guide_anchors = {h.anchor for h in gen.headings(guide)}
    for name in ("privesc.json", "dangerous.json"):
        for rule in read_document(name)["rules"]:
            slug = gen.github_slug(rule["id"])
            assert slug in ref_anchors and slug in guide_anchors, rule["id"]
            for alias in rule.get("legacy_ids") or ():
                assert alias in reference, (rule["id"], alias)


@pytest.mark.finding("F-135")
def test_severity_documented_as_a_maximum_holds_on_every_golden_finding(catalog):
    """The guide says a finding's catalogue severity is the highest it is emitted with."""
    from aws_enumerator.engine.model import SEVERITY_RANK

    graphs = sorted((REPO / "tests" / "golden" / "v1").glob("*/graph.json"))
    assert graphs, "the v1 goldens are missing"
    seen = 0
    for path in graphs:
        for finding in json.loads(path.read_text(encoding="utf-8"))["findings"]:
            entry = catalog.get(finding["id"])
            assert entry is not None, (path.parent.name, finding["id"])
            assert SEVERITY_RANK[finding["severity"]] >= SEVERITY_RANK[entry.severity], (path.parent.name,
                                                                                         finding["id"])
            seen += 1
    assert seen > 100
