"""The committed merged run of ``tests/fixtures/dashboard-merge/`` (graph.json 1.1; F-126, dashboard half).

The folder is an ``aws-enumerator merge`` output of two synthetic runs (README there gives the recipe). It is
checked for what the dashboard tests rely on: it is a valid graph 1.1 merge document, the manifest digests and
``SHA256SUMS`` match the bytes, and it names placeholder accounts only. It is deliberately **not** compared with
the current engine's output: only a schema change makes it stale.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict

import pytest
from jsonschema import Draft202012Validator

from tests.support import targets

FIXTURE = targets.FIXTURES_DIR / "dashboard-merge"
RUNS = sorted(p for p in (FIXTURE / "merged").iterdir() if p.is_dir())
PLACEHOLDER_ACCOUNTS = {"123456789012", "111122223333", "999999999999", "000000000000"}
ACCOUNT_LIKE = re.compile(r"(?<![0-9A-Za-z])[0-9]{12}(?![0-9A-Za-z])")


def _json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def run_root() -> Path:
    assert len(RUNS) == 1, f"expected one merged run under {FIXTURE / 'merged'}, found {RUNS}"
    return RUNS[0]


@pytest.mark.finding("F-126")
def test_the_merged_graph_is_a_valid_graph_1_1_merge_document(run_root):
    doc = _json(run_root / "analysis" / "graph.json")
    schema = _json(targets.ENGINE_SCHEMA_DIR / "graph-1.1.schema.json")
    errors = sorted(Draft202012Validator(schema).iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))
    assert not errors, [f"{'/'.join(map(str, e.absolute_path))}: {e.message[:200]}" for e in errors[:10]]
    assert doc["schema_version"].startswith("1.1.") and doc["run"]["mode"] == "merge"
    assert doc["run"]["run_id"] == run_root.name
    assert doc["run"]["operator"]["node_id"] is None and doc["run"]["operator"]["resolution"] == "unavailable"
    sources = doc["run"]["sources"]
    assert sorted(s["account_id"] for s in sources) == ["111122223333", "123456789012"]
    # what the dashboard tests look at: per-account modules (one not ok), findings of both accounts
    accounts = {m["account"] for m in doc["coverage"]["modules"]}
    assert accounts == {s["account_id"] for s in sources}
    assert [m["module"] for m in doc["coverage"]["modules"] if m["status"] != "ok"] == ["sns"]
    assert {f["node_id"].split(":")[4] for f in doc["findings"] if f["node_id"].startswith("arn:aws:iam::")} == accounts


@pytest.mark.finding("F-126")
def test_the_manifest_and_sha256sums_match_the_committed_bytes(run_root):
    manifest = _json(run_root / "manifest.json")
    assert manifest["run"]["run_id"] == run_root.name and manifest["run"]["kind"] == "merge"
    listed = {f["path"]: f for f in manifest["files"]}
    assert "analysis/graph.json" in listed, "the dashboard verifies graph.json against this entry (F-168)"
    for rel, entry in listed.items():
        data = (run_root / rel).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["sha256"] and len(data) == entry["bytes"], rel
    sums = {}
    for line in (run_root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, _, rel = line.partition("  ")
        sums[rel] = digest
    assert set(sums) == {"HANDLING.txt", "analysis/graph.json", "manifest.json"}
    for rel, digest in sums.items():
        assert hashlib.sha256((run_root / rel).read_bytes()).hexdigest() == digest, rel


@pytest.mark.finding("F-126")
def test_the_fixture_names_placeholder_accounts_only():
    files = sorted(p for p in FIXTURE.rglob("*") if p.is_file())
    assert len(files) == 5, [str(p.relative_to(FIXTURE)) for p in files]   # README + the four run files
    for path in files:
        text = path.read_text(encoding="utf-8")
        found = set(ACCOUNT_LIKE.findall(text))
        assert found <= PLACEHOLDER_ACCOUNTS, (path.name, sorted(found - PLACEHOLDER_ACCOUNTS))
        assert "/Users/" not in text and "/home/" not in text and "/private/" not in text, path.name
        for email in re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", text):
            assert email.split("@")[1].startswith("example."), (path.name, email)
