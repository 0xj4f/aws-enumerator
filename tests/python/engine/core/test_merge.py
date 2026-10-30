"""``engine/merge.py`` and the graph 1.1 validator (graph-json.md §4.2, §12; engine-api.md §3.5; D-42 to D-45).

Two synthetic v2 runs (``tests/fixtures/e-core/merge_runs.py``, built with ``report_builder.V2Run`` and analysed by
the real engine) are merged and checked against ``graph-1.1.schema.json`` and ``validate_graph(strict_order=True)``.
"""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import shutil
import stat

import pytest
from jsonschema import Draft202012Validator

from tests.support import targets

MR = importlib.import_module("tests.fixtures.e-core.merge_runs")
GRAPH = targets.engine_module("graph")
WRITER = targets.engine_module("writers.graph_json")
MODEL = targets.engine_module("model")
pytestmark = pytest.mark.finding("F-126")

A, B, C = MR.ACCT_A, MR.ACCT_B, MR.ACCT_C
READER = MR.role_arn(B, "demo-reader")
OPERATOR = MR.role_arn(B, "demo-operator")
TS = "2026-01-02T00:00:00Z"


@pytest.fixture(scope="module")
def pair(tmp_path_factory):
    old = os.environ.get("SOURCE_DATE_EPOCH")
    os.environ["SOURCE_DATE_EPOCH"] = MR.EPOCH
    try:
        yield MR.two_accounts(tmp_path_factory.mktemp("merge"))
    finally:
        if old is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = old


@pytest.fixture(scope="module")
def merged(pair):
    m = targets.merge_module()
    return m.merge_graphs(m.plan_merge([pair.b, pair.a]), run_id="demo-merge-1", generated_at=TS)


def _schema_errors(doc, name="graph-1.1"):
    return [e.message for e in Draft202012Validator(GRAPH.load_schema(name)).iter_errors(doc)]


def _codes(doc):
    return [p.code for p in GRAPH.validate_graph(doc, strict_order=True)]


def _nodes(doc):
    return {n["id"]: n for n in doc["nodes"]}


# ── the merged document ──────────────────────────────────────────────────────
def test_two_accounts_merge_into_a_valid_1_1_document(pair, merged):
    assert merged["schema_version"] == GRAPH.GRAPH_MERGE_SCHEMA_VERSION == "1.1.0"
    assert _schema_errors(merged) == [] and _codes(merged) == []
    assert WRITER.problems(merged) == []                       # the writer validates with the schema of 1.1
    run = merged["run"]
    assert run["mode"] == "merge" and run["account_id"] == B == run["sources"][0]["account_id"]
    assert [(s["account_id"], s["run_id"]) for s in run["sources"]] == [(B, MR.RUN_B), (A, MR.RUN_A)]
    assert run["regions"] == ["eu-west-1", "eu-west-2"] and run["generated_at"] == TS
    assert run["source_manifest_sha256"] is None
    assert run["operator"] == {"arn": None, "node_id": None, "resolution": "unavailable", "redacted": False}
    by_account = {s["account_id"]: s for s in run["sources"]}
    graph_a = (pair.a / "analysis" / "graph.json").read_bytes()
    assert by_account[A]["graph_sha256"] == hashlib.sha256(graph_a).hexdigest()
    assert by_account[A]["generator"] == json.loads(graph_a)["generator"]
    assert by_account[B]["operator"]["node_id"] == OPERATOR
    assert merged["generator"]["tool"] == "aws-enumerator"


def test_an_external_principal_resolves_to_the_collecting_accounts_role(pair, merged):
    a = MR.load_graph(pair.a)
    assert _nodes(a)[READER]["type"] == "external_principal"
    node = _nodes(merged)[READER]
    assert node["type"] == "role" and node["account"] == B and not node["props"].get("external")
    [edge] = [e for e in merged["edges"] if e["type"] == "KMS_GRANTS_CROSS_ACCOUNT"]
    assert (edge["source"], edge["target"]) == (READER, MR.key_arn(A))
    assert edge in [e for e in a["edges"] if e["type"] == "KMS_GRANTS_CROSS_ACCOUNT"]   # never re-evaluated
    # The endpoint relaxation is a merge-mode reading only (graph-json.md §12.2).
    as_run = copy.deepcopy(merged)
    as_run["run"]["mode"] = "run"
    assert "edge-source-type" in _codes(as_run)


def test_every_account_admin_is_a_target_and_every_source_operator_a_source(merged):
    meta = merged["meta"]
    assert {f"aws-enumerator:account-admin/{a}" for a in (A, B)} <= set(meta["default_targets"])
    assert OPERATOR in meta["default_sources"] and "aws-enumerator:anonymous" in meta["default_sources"]
    broken = copy.deepcopy(merged)
    broken["meta"]["default_sources"] = ["aws-enumerator:anonymous"]
    assert "meta-sources-mismatch" in _codes(broken)


def test_findings_are_unioned_with_their_account_and_reattached(pair, merged):
    sources = [MR.load_graph(pair.a), MR.load_graph(pair.b)]
    fingerprints = {f["fingerprint"] for g in sources for f in g["findings"]}
    assert {f["fingerprint"] for f in merged["findings"]} == fingerprints
    assert all(f["account"] in (A, B) for f in merged["findings"])
    nodes = _nodes(merged)
    for f in merged["findings"]:
        assert f["fingerprint"] in nodes[f["node_id"]]["findings"]
    assert merged["findings"] == sorted(merged["findings"], key=GRAPH.finding_sort_key)


def test_coverage_gaps_and_analyzer_status_are_kept_per_account(merged):
    cov = merged["coverage"]
    assert cov["source"] == "ledger" and cov["status"] == "partial"           # B's sns module is partial
    assert {(m["module"], m["account"], m["status"]) for m in cov["modules"]} >= {
        ("iam", A, "ok"), ("iam", B, "ok"), ("kms", A, "ok"), ("sns", B, "partial")}
    accounts = [m["account"] for m in cov["modules"]]
    assert accounts == [B] * accounts.count(B) + [A] * accounts.count(A)   # concatenated in source order
    gaps = {g["code"]: g for g in merged["evaluation_gaps"]}
    assert gaps["external-identity"]["accounts"] == sorted([A, B])
    assert [g["code"] for g in merged["evaluation_gaps"]] == sorted(gaps)
    statuses = merged["analyzer_status"]
    assert {s["account"] for s in statuses} == {A, B}
    order = [s["account"] for s in statuses]
    assert order == [B] * order.count(B) + [A] * order.count(A)


def test_the_merge_is_deterministic_whatever_the_argument_order(pair):
    m = targets.merge_module()
    one = m.merge_graphs(m.plan_merge([pair.a, pair.b]), run_id="demo-merge-1", generated_at=TS)
    two = m.merge_graphs(m.plan_merge([pair.b, pair.a]), run_id="demo-merge-1", generated_at=TS)
    assert WRITER.render(one) == WRITER.render(two)


def test_write_merged_writes_only_graph_json_privately(merged, tmp_path):
    m = targets.merge_module()
    root = tmp_path / "merged" / "demo-merge-1"
    root.mkdir(parents=True)
    path = m.write_merged(merged, root)
    assert path == root / "analysis" / "graph.json" and json.loads(path.read_text()) == merged
    assert sorted(p.name for p in root.iterdir()) == ["analysis"]
    assert sorted(p.name for p in (root / "analysis").iterdir()) == ["graph.json"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE((root / "analysis").stat().st_mode) == 0o700
    with pytest.raises(FileExistsError):
        m.write_merged(merged, root)


# ── plan_merge: usage errors (64) and invalid sources (1) ───────────────────
def _copy_run(src, dest):
    shutil.copytree(src, dest)
    return dest


def test_usage_errors(pair, merged, tmp_path):
    m = targets.merge_module()
    usage = MODEL.AnalysisUsageError
    with pytest.raises(usage, match="at least two"):
        m.plan_merge([pair.a])
    empty = tmp_path / "not-analysed"
    empty.mkdir()
    with pytest.raises(usage, match="no analysis/graph.json"):
        m.plan_merge([pair.a, empty])
    with pytest.raises(usage, match="more than one run"):
        m.plan_merge([pair.a, _copy_run(pair.a, tmp_path / "again")])
    nested = tmp_path / "nested"
    (nested / "analysis").mkdir(parents=True)
    MR.write_graph(nested, merged)
    with pytest.raises(usage, match="itself a merged graph"):
        m.plan_merge([pair.a, nested])
    other = _copy_run(pair.b, tmp_path / "cn")
    doc = MR.load_graph(other)
    doc["run"]["partition"] = "aws-cn"
    MR.write_graph(other, doc)
    with pytest.raises(usage, match="different partitions"):
        m.plan_merge([pair.a, other])


@pytest.mark.parametrize("change, match", [
    ("unparsable", "cannot be read or parsed"),
    ("major-2", "is not 1.x"),
    ("minor-2", "newer than this build knows"),
    ("dangling-edge", "is invalid"),
    ("merge-in-1.0", "is invalid"),
])
def test_invalid_sources_raise_merge_invalid(pair, tmp_path, change, match):
    m = targets.merge_module()
    bad = _copy_run(pair.b, tmp_path / "bad")
    doc = MR.load_graph(bad)
    if change == "unparsable":
        MR.write_graph(bad, None, raw=b"{not json")
    else:
        if change == "major-2":
            doc["schema_version"] = "2.0.0"
        elif change == "minor-2":
            doc["schema_version"] = "1.2.0"
        elif change == "dangling-edge":
            doc["edges"][0]["target"] = "arn:aws:iam::111122223333:role/demo-missing"
        elif change == "merge-in-1.0":
            doc["run"]["sources"] = []                     # a 1.0 document may not carry run.sources
        MR.write_graph(bad, doc)
    with pytest.raises(m.MergeInvalid, match=match):
        m.plan_merge([pair.a, bad])


def test_a_merged_document_that_fails_validation_is_refused(pair, monkeypatch):
    m = targets.merge_module()
    sources = m.plan_merge([pair.a, pair.b])
    monkeypatch.setattr(m, "_meta", lambda nodes, records: {"default_sources": [], "default_targets": []})
    with pytest.raises(m.MergeInvalid, match="merged graph is invalid") as err:
        m.merge_graphs(sources, run_id="demo-merge-1", generated_at=TS)
    assert any("meta-targets-mismatch" in p for p in err.value.problems)


# ── the 1.1 validator ────────────────────────────────────────────────────────
def test_merge_sources_rule(merged):
    def codes_after(mutate):
        doc = copy.deepcopy(merged)
        mutate(doc)
        return _codes(doc)

    assert "merge-sources" in codes_after(lambda d: d["run"]["sources"].reverse())
    assert "merge-sources" in codes_after(lambda d: d["run"].update(account_id=A))
    assert "merge-sources" in codes_after(lambda d: d["run"]["sources"][1].update(partition="aws-cn"))
    assert "merge-sources" in codes_after(lambda d: d["run"]["sources"][1].update(account_id=B))
    assert "merge-sources" in codes_after(lambda d: d["run"].update(sources=d["run"]["sources"][:1]))


def test_every_source_account_admin_node_is_required(merged):
    doc = copy.deepcopy(merged)
    admin = f"aws-enumerator:account-admin/{A}"
    doc["nodes"] = [n for n in doc["nodes"] if n["id"] != admin]
    doc["edges"] = [e for e in doc["edges"] if admin not in (e["source"], e["target"])]
    doc["meta"]["default_targets"].remove(admin)
    assert "synthetic-node-missing" in _codes(doc)


def test_schema_is_chosen_by_minor():
    assert GRAPH.graph_schema_name("1.0.0") == "graph" and GRAPH.graph_schema_name("1.1.0") == "graph-1.1"
    assert GRAPH.graph_schema_name("1.2.0") is None                         # newer minor: validate_graph only
    assert GRAPH.graph_schema_name("2.0.0") == "graph" and GRAPH.graph_schema_name(None) == "graph"
    assert GRAPH.GRAPH_SCHEMA_VERSION == "1.0.0"                            # analyses keep writing 1.0
    schema = GRAPH.load_schema("graph-1.1")
    Draft202012Validator.check_schema(schema)
    assert schema["$id"] == "urn:aws-enumerator:schema:graph:1.1"


def test_a_merge_labelled_1_0_fails_the_1_0_schema(merged):
    doc = copy.deepcopy(merged)
    doc["schema_version"] = "1.0.0"
    assert _schema_errors(doc, "graph") != []
    assert WRITER.problems(doc) != []


@pytest.mark.parametrize("name", ["minimal.json", "example.json", "hostile.json"])
def test_every_1_0_fixture_is_a_valid_1_1_document(name):
    doc = json.loads((targets.graph_fixtures_dir() / name).read_text(encoding="utf-8"))
    assert _schema_errors(doc, "graph-1.1") == [] and GRAPH.validate_graph(doc, strict_order=True) == []
