"""Unit tests for tests/support/canonical.py (golden canonicalisation)."""

from __future__ import annotations

import json

from tests.support import canonical


def test_edges_sorted_by_source_target_type():
    data = {"edges": [
        {"source": "b", "target": "x", "type": "T2"},
        {"source": "a", "target": "y", "type": "T1"},
        {"source": "a", "target": "x", "type": "T9"},
        {"source": "a", "target": "x", "type": "T1"},
    ]}
    out = canonical.canonicalize(data)["edges"]
    assert [(e["source"], e["target"], e["type"]) for e in out] == [
        ("a", "x", "T1"), ("a", "x", "T9"), ("a", "y", "T1"), ("b", "x", "T2")]


def test_findings_sorted_by_id_then_entity():
    data = {"findings": [{"id": "B-1", "entity": "role/a"}, {"id": "A-2", "entity": "user/z"},
                         {"id": "A-2", "entity": "role/b"}]}
    out = canonical.canonicalize(data)["findings"]
    assert [(f["id"], f["entity"]) for f in out] == [("A-2", "role/b"), ("A-2", "user/z"), ("B-1", "role/a")]


def test_scalar_lists_sorted_and_set_order_irrelevant():
    a = {"matched_actions": ["s3:PutObject", "s3:GetObject", "*"]}
    b = {"matched_actions": ["*", "s3:GetObject", "s3:PutObject"]}
    assert canonical.dumps(a) == canonical.dumps(b)


def test_mixed_scalar_types_do_not_raise():
    assert canonical.canonicalize([3, "3", None, True, 1.5]) is not None


def test_timestamps_stripped_and_paths_replaced(tmp_path):
    root = str(tmp_path)
    data = {"run_metadata": {"timestamp_start": "2026-10-15T10:00:00", "duration_seconds": 12.5,
                             "path": f"{root}/111122223333/global"}}
    out = canonical.canonicalize(data, path_roots=[root])
    assert out["run_metadata"]["timestamp_start"] == canonical.STRIPPED
    assert out["run_metadata"]["duration_seconds"] == canonical.STRIPPED
    assert out["run_metadata"]["path"] == "<ROOT>/111122223333/global"


def test_dumps_is_sorted_ascii_with_newline():
    text = canonical.dumps({"b": 1, "a": "‮"})
    assert text.endswith("\n")
    assert text.index('"a"') < text.index('"b"')
    assert "\\u202e" in text and json.loads(text) == {"a": "‮", "b": 1}


def test_check_or_update_roundtrip(tmp_path):
    golden = tmp_path / "golden" / "demo"
    actual = {"analysis/x.json": canonical.dumps({"k": [2, 1]}), "outcome.json": canonical.dumps({"raised": None})}
    assert "does not exist" in canonical.check_or_update(golden, actual, update=False)
    assert canonical.check_or_update(golden, actual, update=True) is None
    assert canonical.check_or_update(golden, actual, update=False) is None
    changed = dict(actual, **{"analysis/x.json": canonical.dumps({"k": [3]})})
    message = canonical.check_or_update(golden, changed, update=False)
    assert message and "analysis/x.json" in message and "--update-golden" in message
    fewer = {"outcome.json": actual["outcome.json"]}
    assert "not produced" in canonical.check_or_update(golden, fewer, update=False)
    canonical.check_or_update(golden, fewer, update=True)
    assert not (golden / "analysis").exists()  # stale files and empty dirs removed


def test_canonical_tree_reads_nested_json(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "x.json").write_text('{"z": [2, 1]}', encoding="utf-8")
    (tmp_path / "skip.txt").write_text("nope", encoding="utf-8")
    assert canonical.canonical_tree(tmp_path) == {"a/x.json": canonical.dumps({"z": [1, 2]})}
