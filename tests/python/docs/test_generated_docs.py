"""The generated reference documentation is current and complete (DOC2, Wave 3b).

``scripts/gen_docs.py`` writes ``docs/reference/**``, ``docs/permissions.md`` and the marker blocks of
``docs/attack_paths.md`` from the code; these tests fail when a committed file drifts from the code
(F-135, F-070, F-088, F-151, F-161, F-163).
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
DOCS = REPO / "docs"
REFERENCE = DOCS / "reference"


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
def outputs(gen):
    return gen.outputs()


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ── drift ─────────────────────────────────────────────────────────────────────

@pytest.mark.finding("F-135", "F-151")
def test_generated_files_have_no_diff(gen, outputs):
    stale = [str(p.relative_to(REPO)) for p in gen.stale(outputs)]
    assert not stale, f"out of date, run .venv/bin/python scripts/gen_docs.py: {stale}"
    assert set(outputs) >= {REFERENCE / n for n in ("findings.md", "edges.md", "node-types.md", "cli.md",
                                                    "iam-policy.json", "k8s-clusterrole.yaml")}
    assert gen.check_only() == []


@pytest.mark.finding("F-135")
def test_gen_docs_check_command_exits_zero():
    proc = subprocess.run([sys.executable, "-I", "-B", str(REPO / "scripts" / "gen_docs.py"), "--check"],
                          cwd=REPO, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr


@pytest.mark.finding("F-135")
def test_marker_blocks_are_owned_by_the_generator(gen):
    text = _read(DOCS / "attack_paths.md")
    blocks = gen.attack_path_blocks()
    for name in blocks:
        assert text.count(f"<!-- BEGIN GENERATED:{name} ") == 1, name
        assert text.count(f"<!-- END GENERATED:{name} -->") == 1, name
    with pytest.raises(SystemExit):
        gen.apply_blocks(text.replace("<!-- END GENERATED:weights -->", ""), blocks)
    with pytest.raises(SystemExit):
        gen.apply_blocks("no blocks here\n", blocks)


# ── edge and node types ───────────────────────────────────────────────────────

@pytest.mark.finding("F-135", "F-070")
def test_every_edge_type_has_its_doc_anchor_heading(gen):
    from aws_enumerator.engine.graph import edge_types as ET

    hs = {h.anchor: h for h in gen.headings(_read(REFERENCE / "edges.md"))}
    for name, et in ET.EDGE_TYPES.items():
        anchor = ET.edge_type_entry(name)["doc_anchor"].lstrip("#")
        assert anchor in hs, name
        assert hs[anchor].text == name and hs[anchor].level == 3, name
        section = "\n".join(gen.section_lines(_read(REFERENCE / "edges.md"), "#" + anchor))
        assert f"`{et.traversal}`" in section and f"**Base weight:** {gen._num(et.base_weight)}" in section, name


@pytest.mark.finding("F-135", "F-070", "F-088")
def test_every_edge_type_is_in_the_field_guide_and_no_dead_type_is(gen):
    from aws_enumerator.engine.graph import edge_types as ET

    guide = _read(DOCS / "attack_paths.md")
    for name in ET.EDGE_TYPES:
        assert f"[`{name}`](reference/edges.md#{name.lower()})" in guide, name
    # KMS_GRANTS_DECRYPT is emitted since F-029 and documented; INTERNET_FACING was never an edge (F-070)
    assert "KMS_GRANTS_DECRYPT" in ET.EDGE_TYPES
    assert "INTERNET_FACING" not in ET.EDGE_TYPES


@pytest.mark.finding("F-135")
def test_rule_data_emits_only_documented_edge_types():
    from aws_enumerator.engine.graph import edge_types as ET
    from aws_enumerator.engine.rules.catalogue import read_document

    edges = _read(REFERENCE / "edges.md")
    for rule in read_document("privesc.json")["rules"]:
        for key, value in (rule.get("emits") or {}).items():
            if key == "via":
                continue
            assert value in ET.EDGE_TYPES, (rule["id"], value)
            assert f"\n### {value}\n" in edges, (rule["id"], value)


@pytest.mark.finding("F-135")
def test_every_finding_id_and_edge_type_of_the_goldens_is_documented(gen):
    findings = _read(REFERENCE / "findings.md")
    edges = _read(REFERENCE / "edges.md")
    ids, types = set(), set()
    for path in sorted((REPO / "tests" / "golden" / "v1").glob("*/graph.json")):
        doc = json.loads(_read(path))
        ids |= {f["id"] for f in doc["findings"]}
        types |= {e["type"] for e in doc["edges"]}
    assert ids and types
    for fid in sorted(ids):
        assert f"\n## {fid}\n" in findings, fid
    for etype in sorted(types):
        assert f"\n### {etype}\n" in edges, etype


@pytest.mark.finding("F-135")
def test_node_types_reference_lists_every_type():
    from aws_enumerator.engine.graph import edge_types as ET

    text = _read(REFERENCE / "node-types.md")
    for name in ET.NODE_TYPES:
        assert f"| `{name}` |" in text, name


# ── CLI ───────────────────────────────────────────────────────────────────────

def test_cli_reference_lists_every_subcommand_and_option(gen):
    import argparse

    from aws_enumerator.cli import SUBCOMMANDS, build_parser

    text = _read(REFERENCE / "cli.md")
    anchors = {h.anchor for h in gen.headings(text)}
    parser = build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    assert tuple(sub.choices) == SUBCOMMANDS
    for name, sp in sub.choices.items():
        assert f"aws-enumerator-{name}" in anchors, name
        for action in sp._actions:
            for flag in action.option_strings:
                if flag in ("-h", "--help", "--version"):
                    continue
                assert f"`{flag}`" in text, (name, flag)


# ── permissions (F-151, F-161) ────────────────────────────────────────────────

def _cli_stdout(argv):
    """``aws-enumerator <argv>`` in process: its stdout (the command result only, cli.md §5)."""
    import contextlib
    import io

    from aws_enumerator.cli import main

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    assert code == 0, err.getvalue()
    return out.getvalue()


@pytest.mark.finding("F-151", "F-161")
def test_iam_policy_file_is_the_permissions_command_output():
    assert _read(REFERENCE / "iam-policy.json") == _cli_stdout(["permissions", "-q"])
    policy = json.loads(_read(REFERENCE / "iam-policy.json"))
    assert policy["Version"] == "2012-10-17"
    assert all(st["Effect"] == "Allow" for st in policy["Statement"])


@pytest.mark.finding("F-161")
def test_k8s_rbac_file_is_the_permissions_command_output():
    text = _read(REFERENCE / "k8s-clusterrole.yaml")
    assert text == _cli_stdout(["permissions", "-q", "--format", "k8s"])
    assert "kind: ClusterRole" in text and '"secrets"' not in text


@pytest.mark.finding("F-151", "F-161")
def test_permissions_page_covers_every_module_action_and_the_security_audit_delta(gen):
    from aws_enumerator import permissions as P
    from aws_enumerator import registry

    page = _read(DOCS / "permissions.md")
    specs = list(registry.get_registry())
    policy = json.loads(_read(REFERENCE / "iam-policy.json"))
    allowed = {a for st in policy["Statement"] for a in st["Action"]}
    for spec in specs:
        assert f"| `{spec.name}` |" in page, spec.name
        for action in P.module_actions(spec)[0]:
            assert f"`{action}`" in page, (spec.name, action)
            assert action in allowed, (spec.name, action)
    for action in gen.SECURITY_AUDIT_MISSING:
        assert action in allowed, action
        assert f"| `{action}` |" in page, action
    assert "SecurityAudit" in page and "version 94" in page
    for action in P.GUARDRAIL_DENY:
        assert f"`{action}`" in page, action
    assert "appear in CloudTrail" in page


# ── references (F-163) ────────────────────────────────────────────────────────

@pytest.mark.finding("F-163")
def test_reference_url_format_is_documented_as_the_engine_builds_it():
    from aws_enumerator._version import __version__
    from aws_enumerator.engine.findings.references import DOC_PATH, REPOSITORY_URL, doc_reference

    guide = _read(DOCS / "attack_paths.md")
    reference = _read(REFERENCE / "findings.md")
    example = doc_reference("#common-privilege-escalation-patterns")
    assert example == f"{REPOSITORY_URL}/blob/v{__version__}/{DOC_PATH}#common-privilege-escalation-patterns"
    assert f"`{example}`" in guide
    assert f"`{REPOSITORY_URL}/blob/v<version>/{DOC_PATH}#<anchor>`" in reference
    for path in [DOCS / "attack_paths.md", DOCS / "permissions.md", *sorted(REFERENCE.glob("*.md"))]:
        assert "/blob/main/" not in _read(path), path.name
