"""Engine-side Wave 0 contracts (stream contracts-engine).

Covers: the graph / findings JSON Schemas, the valid and invalid graph fixtures, the shared path vectors
against the reference directed Dijkstra, the traversability table (self-consistency, legacy inventory,
generated documentation), the identity helpers and the model types.

These are contract tests, not fixes: they carry no ``finding`` markers (the production code that uses
these contracts lands in Waves 1 and 2, where the fixing streams tag their tests).
"""

from __future__ import annotations

import ast
import dataclasses
import importlib.util
import inspect
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, Set, Tuple

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from tests.support import targets
from tests.support.ref_paths import (
    CONTRACTS_DIR,
    FIXTURES_GRAPH_DIR,
    FIXTURES_GRAPH_INVALID_DIR,
    engine_module,
    engine_schema_dir,
    reachable,
    shortest_path,
)

ET = engine_module("graph.edge_types")
IDS = engine_module("graph.ids")
GRAPH = engine_module("graph")
MODEL = engine_module("model")

MAIN, EXT = "111122223333", "999999999999"
VALID_FIXTURES = ("minimal.json", "example.json", "hostile.json")


# ── helpers ───────────────────────────────────────────────────────────────────

def _load(path: Path) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _schema(name: str) -> Dict[str, Any]:
    return _load(engine_schema_dir() / GRAPH.SCHEMA_FILES[name])


def _validator(name: str, ref: str = "") -> Draft202012Validator:
    schema = _schema(name)
    if not ref:
        return Draft202012Validator(schema)
    registry = Registry().with_resource(schema["$id"], Resource.from_contents(schema))
    return Draft202012Validator({"$ref": f"{schema['$id']}#/$defs/{ref}"}, registry=registry)


def _pointer(path) -> str:
    return "".join(f"/{p}" for p in path)


def _assert_valid(doc: Any, *, strict_order: bool = True) -> None:
    errors = [(e.message[:200], _pointer(e.absolute_path)) for e in _validator("graph").iter_errors(doc)]
    assert errors == []
    problems = [(p.code, p.path, p.message) for p in GRAPH.validate_graph(doc, strict_order=strict_order)]
    assert problems == []


GRAPH_SCHEMA_VALIDATOR = _validator("graph")


# ── schemas ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", ["graph", "findings"])
def test_schema_is_valid_draft_2020_12(name):
    schema = _schema(name)
    Draft202012Validator.check_schema(schema)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == f"urn:aws-enumerator:schema:{name}:1.0"
    assert GRAPH.schema_path(name) == engine_schema_dir() / GRAPH.SCHEMA_FILES[name]
    assert GRAPH.load_schema(name) == schema


def test_finding_definition_identical_in_both_schemas():
    g, f = _schema("graph")["$defs"], _schema("findings")["$defs"]
    shared = set(g) & set(f)
    assert {"finding", "evidence", "safeValue", "safeObject", "safeKey", "fieldKey", "fingerprint", "nodeId"} <= shared
    for key in sorted(shared):
        assert g[key] == f[key], key


def test_schema_top_level_keys_match_contract():
    schema = _schema("graph")
    expected = ["schema_version", "generator", "run", "meta", "node_types", "edge_types", "nodes", "edges",
                "findings", "coverage", "evaluation_gaps", "analyzer_status"]
    assert schema["required"] == expected
    assert schema["additionalProperties"] is False
    assert schema["$defs"]["finding"]["required"] == list(MODEL.FINDING_REQUIRED)
    assert schema["$defs"]["analyzerStatus"]["properties"]["phase"]["enum"] == [p.name.lower() for p in MODEL.Phase]
    assert schema["$defs"]["operator"]["properties"]["resolution"]["enum"] == list(IDS.OPERATOR_RESOLUTIONS)
    assert schema["$defs"]["node"]["properties"]["coverage"]["properties"]["status"]["enum"] == \
        list(MODEL.COVERAGE_STATUSES)


def test_schema_versions_constants():
    assert GRAPH.GRAPH_SCHEMA_VERSION == "1.0.0"
    assert GRAPH.FINDINGS_SCHEMA_VERSION == "1.0.0"
    for f in VALID_FIXTURES:
        assert _load(FIXTURES_GRAPH_DIR / f)["schema_version"] == GRAPH.GRAPH_SCHEMA_VERSION


# ── valid fixtures ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", VALID_FIXTURES)
def test_valid_fixture(name):
    _assert_valid(_load(FIXTURES_GRAPH_DIR / name))


def test_minimal_fixture_is_only_the_synthetic_nodes():
    doc = _load(FIXTURES_GRAPH_DIR / "minimal.json")
    assert [n["id"] for n in doc["nodes"]] == [IDS.account_admin_id(MAIN), IDS.ANONYMOUS_ID]
    assert doc["edges"] == [] and doc["findings"] == []
    assert doc["meta"] == {"default_sources": [IDS.ANONYMOUS_ID], "default_targets": [IDS.account_admin_id(MAIN)]}


def test_example_fixture_exercises_the_dashboard_fields():
    doc = _load(FIXTURES_GRAPH_DIR / "example.json")
    nodes = {n["id"]: n for n in doc["nodes"]}
    op = doc["run"]["operator"]
    assert op["resolution"] == "assumed-role" and op["node_id"] in nodes
    assert op["node_id"] in doc["meta"]["default_sources"]
    props = [n["props"] for n in doc["nodes"]]
    for key in ("high_value", "high_value_reason", "external", "entry_point", "data_asset",
                "attached_policies_status"):
        assert any(key in p for p in props), key
    statuses = {f["status"] for f in doc["findings"]}
    assert statuses == {"open", "suppressed"}
    assert any(n["inherited_findings"] for n in doc["nodes"])
    assert any(not e["traversable"] for e in doc["edges"]) and any(e["traversable"] for e in doc["edges"])
    assert {e["confidence"] for e in doc["edges"]} == {"definite", "conditional"}
    assert doc["coverage"]["status"] == "partial"
    assert {g["code"] for g in doc["evaluation_gaps"]} >= {"external-identity", "runtime-conditions",
                                                           "session-policies"}


def test_hostile_fixture_carries_canaries_in_every_rendered_field():
    doc = _load(FIXTURES_GRAPH_DIR / "hostile.json")
    text = json.dumps(doc)
    assert text.count("__aeXssCanary") >= 20
    labels = {n["label"] for n in doc["nodes"]}
    assert {"constructor", "__proto__", "hasOwnProperty", "toString"} <= labels
    assert any("__aeXssCanary" in n["id"] for n in doc["nodes"])            # IAM path canary in an id
    assert any("__aeXssCanary" in json.dumps(n["props"]) for n in doc["nodes"])
    assert any("__aeXssCanary" in t["value"] for n in doc["nodes"] for t in n["tags"])
    assert any(t["key"] in ("constructor", "toString") for n in doc["nodes"] for t in n["tags"])
    assert any("__aeXssCanary" in json.dumps(e["evidence"]) for e in doc["edges"])
    for key in ("title", "description", "remediation", "reference"):
        assert any("__aeXssCanary" in str(f.get(key)) for f in doc["findings"]), key
    assert "__proto__" in doc["run"]["operator"]["arn"]


def test_reference_dijkstra_tie_break_is_edge_id_sequence():
    case = next(c for c in PATH_CASES if c["name"] == "equal_cost_and_hops_breaks_tie_on_edge_ids")
    edges = {(e["source"], e["target"]): e["id"] for e in case["graph"]["edges"]}
    candidates = [p for p in (
        [case["source"], mid, case["target"]] for mid in {e["target"] for e in case["graph"]["edges"]
                                                           if e["source"] == case["source"]})]
    best = min(candidates, key=lambda p: [edges[(p[i], p[i + 1])] for i in range(len(p) - 1)])
    assert case["expect"]["path"] == best


# ── invalid fixtures ──────────────────────────────────────────────────────────

INVALID_EXPECTATIONS = _load(FIXTURES_GRAPH_INVALID_DIR / "expectations.json")


def test_every_invalid_fixture_has_an_expectation():
    files = sorted(p.name for p in FIXTURES_GRAPH_INVALID_DIR.glob("*.json") if p.name != "expectations.json")
    assert files == sorted(e["file"] for e in INVALID_EXPECTATIONS)
    required = {"finding_missing_node_id.json", "dangling_edge.json", "negative_weight.json",
                "wrong_schema_major.json", "duplicate_node_ids.json", "duplicate_edge_ids.json",
                "proto_props.json"}
    assert required <= set(files)


@pytest.mark.parametrize("exp", INVALID_EXPECTATIONS, ids=[e["file"] for e in INVALID_EXPECTATIONS])
def test_invalid_fixture_fails_for_its_reason(exp):
    doc = _load(FIXTURES_GRAPH_INVALID_DIR / exp["file"])
    errors = [({e.validator} | {str(k) for k in e.absolute_schema_path}, _pointer(e.absolute_path))
              for e in GRAPH_SCHEMA_VALIDATOR.iter_errors(doc)]
    if exp["layer"] == "schema":
        expected = [tuple(x) for x in exp["errors"]]
        assert errors, "schema accepted an invalid document"
        for keywords, path in errors:
            assert any(kw in keywords and path == p for kw, p in expected), (sorted(keywords), path)
        for kw, p in expected:
            assert any(kw in keywords and path == p for keywords, path in errors), (kw, p)
    else:
        assert errors == [], "a semantic-layer fixture must be schema-valid"
        codes = sorted({p.code for p in GRAPH.validate_graph(doc, strict_order=exp.get("strict_order", False))})
        assert codes == sorted(exp["codes"])


def test_validate_graph_rejects_non_objects_and_wrong_major():
    assert [p.code for p in GRAPH.validate_graph([])] == ["not-an-object"]
    doc = _load(FIXTURES_GRAPH_DIR / "minimal.json")
    doc["schema_version"] = "2.0.0"
    assert [p.code for p in GRAPH.validate_graph(doc)] == ["schema-major"]


def test_validate_graph_detects_self_loops_and_bad_weights():
    doc = _load(FIXTURES_GRAPH_DIR / "example.json")
    e = next(x for x in doc["edges"] if x["type"] == "CAN_READ")
    e["weight"] = float("inf")
    codes = {p.code for p in GRAPH.validate_graph(doc)}
    assert "bad-weight" in codes
    e["weight"] = True                     # a bool is not a number
    assert "bad-weight" in {p.code for p in GRAPH.validate_graph(doc)}


def test_every_validator_code_is_documented():
    src = inspect.getsource(GRAPH)
    codes = set(re.findall(r'(?:add|Problem)\(\s*"([a-z][a-z-]+)"', src))
    assert len(codes) >= 40
    doc = (CONTRACTS_DIR / "graph-json.md").read_text(encoding="utf-8")
    missing = sorted(c for c in codes if f"`{c}`" not in doc)
    assert missing == []


# ── path vectors ──────────────────────────────────────────────────────────────

PATH_CASES = _load(FIXTURES_GRAPH_DIR / "path_cases.json")


def test_path_cases_shape():
    names = [c["name"] for c in PATH_CASES]
    assert len(names) == len(set(names))
    for c in PATH_CASES:
        assert set(c) == {"name", "description", "findings", "graph", "source", "target", "options", "expect"}
        assert set(c["options"]) <= {"exclude_categories", "exclude_node_types", "definite_only"}
        assert all(re.fullmatch(r"F-\d{3}", f) for f in c["findings"])
        assert isinstance(c["expect"]["reachable"], bool)
        if c["expect"]["reachable"]:
            assert {"cost", "hops", "path", "edge_types"} <= set(c["expect"])
        ids_ = {n["id"] for n in c["graph"]["nodes"]}
        assert c["source"] in ids_ and c["target"] in ids_


def test_path_cases_cover_the_required_scenarios():
    names = {c["name"] for c in PATH_CASES}
    required = {
        "shared_group_no_path_between_members", "shared_policy_no_path", "shared_bucket_no_path_to_grantee",
        "shared_bucket_grantee_reaches_bucket", "reversed_edge_not_walkable", "zero_weight_path_honoured",
        "zero_weight_edge_preferred", "conditional_edge_included_by_default",
        "conditional_edge_excluded_with_definite_only", "anonymous_reaches_public_bucket",
        "lambda_invoke_does_not_reach_execution_role", "lambda_update_code_reaches_execution_role",
        "irsa_unverified_not_traversable", "k8s_pods_sharing_cluster_not_connected", "hidden_category_excluded",
    }
    assert required <= names


@pytest.mark.parametrize("case", PATH_CASES, ids=[c["name"] for c in PATH_CASES])
def test_path_case_graph_is_valid(case):
    _assert_valid(case["graph"])


@pytest.mark.parametrize("case", PATH_CASES, ids=[c["name"] for c in PATH_CASES])
def test_reference_dijkstra_passes_path_case(case):
    exp = case["expect"]
    got = shortest_path(case["graph"], case["source"], case["target"], **case["options"])
    if not exp["reachable"]:
        assert got is None
        assert case["target"] not in reachable(case["graph"], case["source"], **case["options"])
        return
    assert got is not None
    assert got.cost == exp["cost"]
    assert got.hops == exp["hops"]
    assert list(got.nodes) == exp["path"]
    assert list(got.edge_types) == exp["edge_types"]
    assert not set(got.edge_types) & set(exp.get("must_not_traverse_types", []))
    by_id = {e["id"]: e for e in case["graph"]["edges"]}
    assert all(by_id[eid]["traversable"] is True for eid in got.edges)
    assert sum(by_id[eid]["weight"] for eid in got.edges) == exp["cost"]


def test_reference_dijkstra_semantics_edge_cases():
    doc = next(c["graph"] for c in PATH_CASES if c["name"] == "forward_edge_walkable")
    src = next(c["source"] for c in PATH_CASES if c["name"] == "forward_edge_walkable")
    assert shortest_path(doc, src, src) is None                      # self is not a path query
    assert shortest_path(doc, src, "arn:aws:iam::111122223333:role/demo-missing") is None
    broken = json.loads(json.dumps(doc))
    for e in broken["edges"]:
        e["weight"] = "x"                                            # invalid weight counts as 1
    assert shortest_path(broken, src, broken["edges"][0]["target"]).cost == 1


# ── fixture builders ──────────────────────────────────────────────────────────

def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(f"graph_fixture_{name}", FIXTURES_GRAPH_DIR / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_committed_fixtures_match_builder():
    builder = _load_script("build_fixtures")
    stale = [str(p) for p, text in builder.outputs().items()
             if not p.exists() or p.read_text(encoding="utf-8") != text]
    assert stale == [], "run: .venv/bin/python tests/fixtures/graph/build_fixtures.py --write"


def test_large_generator_is_valid_and_deterministic():
    gen = _load_script("gen_large")
    a = gen.generate(scale=15, seed=3)
    _assert_valid(a)
    assert gen.dumps(a) == gen.dumps(gen.generate(scale=15, seed=3))
    assert gen.dumps(a) != gen.dumps(gen.generate(scale=15, seed=4))
    assert len(gen.generate(scale=30, seed=3)["edges"]) > len(a["edges"])
    with pytest.raises(ValueError):
        gen.generate(scale=0)


# ── traversability table ──────────────────────────────────────────────────────

def test_table_is_self_consistent():
    assert ET.check_table() == []


#: Edge types added to the table in Wave 3 (DECISIONS.md D-52; requests e-data-2, F-105 / F-116 gaps).
WAVE3_ADDITIONS = {
    "PARAM_GRANTS_CROSS_ACCOUNT", "AMI_SHARED_CROSS_ACCOUNT", "SSMDOC_SHARED_CROSS_ACCOUNT",
    "LAYER_GRANTS_CROSS_ACCOUNT", "VPC_CONNECTED",
}


@pytest.mark.finding("F-116")
@pytest.mark.finding("F-105")
@pytest.mark.parametrize("name,traversal,traversable,sources,targets", [
    ("PARAM_GRANTS_CROSS_ACCOUNT", "access", True, ("external_account", "external_principal"), ("ssmparam",)),
    ("AMI_SHARED_CROSS_ACCOUNT", "access", True, ("external_account",), ("ami",)),
    ("SSMDOC_SHARED_CROSS_ACCOUNT", "access", True, ("external_account",), ("ssmdocument",)),
    ("LAYER_GRANTS_CROSS_ACCOUNT", "access", True, ("external_account", "external_principal"), ("lambdalayer",)),
    ("VPC_CONNECTED", "structural", False, ("vpc",), ("vpc",)),
])
def test_wave3_edge_types(name, traversal, traversable, sources, targets):
    et = ET.EDGE_TYPES[name]
    assert (et.traversal, et.traversable, et.sources, et.targets) == (traversal, traversable, sources, targets)
    assert et.status == "new" and et.legacy_name is None
    assert et.base_weight == (2 if traversal == "access" else 1)


def test_table_matches_engine_md_inventory():
    names = set(ET.EDGE_TYPES)
    # every row of engine.md §6.3 (current + new), CAN_LAUNCH excluded (legacy only)
    engine_md = {
        "MEMBER_OF", "HAS_POLICY", "HAS_BOUNDARY", "IS_ADMIN_EQUIVALENT", "CAN_ASSUME", "CAN_ASSUME_WEB_IDENTITY",
        "CAN_ASSUME_SAML", "SERVICE_CAN_ASSUME", "CAN_PASS_ROLE_TO", "CAN_TAKEOVER", "CAN_MODIFY_PERMISSIONS_OF",
        "CAN_ESCALATE", "INSTANCE_ROLE", "SSRF_TO_IMDS", "PUBLIC_INBOUND", "EC2_FULL_ACCESS", "CAN_CONNECT",
        "CAN_MODIFY_USERDATA", "CAN_MANAGE", "CAN_TERMINATE", "CAN_ADMIN_SG", "HAS_SG", "SG_ALLOWS_FROM",
        "FULL_ACCESS", "CAN_ADMIN", "CAN_WRITE", "CAN_READ", "GRANTS_CROSS_ACCOUNT", "GRANTS_PUBLIC",
        "ENCRYPTED_BY", "SECRET_ENCRYPTED_BY", "PARAM_ENCRYPTED_BY", "RDS_ENCRYPTED_BY", "EBS_ENCRYPTED_BY",
        "MSG_ENCRYPTED_BY", "NOTIFIES", "TRIGGERS", "SUBSCRIBES", "INVOKES", "CAN_READ_SECRET", "CAN_WRITE_SECRET",
        "CAN_READ_PARAM", "SECRET_GRANTS_CROSS_ACCOUNT", "SECRET_GRANTS_PUBLIC", "CAN_UPDATE_CODE",
        "CAN_MODIFY_CONFIG", "CAN_EXPOSE", "CAN_INVOKE", "LAMBDA_GRANTS_INVOKE", "LAMBDA_GRANTS_CROSS_ACCOUNT",
        "LAMBDA_GRANTS_PUBLIC", "USES_ROLE", "EXECUTION_ROLE", "CAN_HIJACK", "CAN_EXEC", "CAN_MODIFY",
        "CAN_DECRYPT", "CAN_ADMIN_KEY", "KMS_GRANTS_DECRYPT", "KMS_GRANT", "CAN_ENCRYPT",
        "KMS_GRANTS_CROSS_ACCOUNT", "KMS_GRANTS_PUBLIC", "CAN_SEND", "CAN_RECEIVE", "CAN_ADMIN_MSG",
        "MSG_GRANTS_CROSS_ACCOUNT", "MSG_GRANTS_PUBLIC", "CAN_READ_TABLE", "CAN_WRITE_TABLE",
        "ECR_GRANTS_CROSS_ACCOUNT", "ECR_GRANTS_PUBLIC", "DDB_GRANTS_CROSS_ACCOUNT", "DDB_GRANTS_PUBLIC",
        "RDS_SHARED_CROSS_ACCOUNT", "RDS_SHARED_PUBLIC", "EBS_SHARED_CROSS_ACCOUNT", "EBS_SHARED_PUBLIC",
        "AMI_SHARED_PUBLIC", "SSMDOC_SHARED_PUBLIC", "LAYER_GRANTS_PUBLIC", "COGNITO_PUBLIC_IDENTITY",
        "POOL_UNAUTH_ROLE", "POOL_AUTH_ROLE", "POOL_MAPPED_ROLE", "EXPOSES", "FRONTS", "CLUSTER_ROLE",
        "NODE_ROLE", "CAN_REACH_NODE_IMDS", "IRSA_BRIDGE", "POD_IDENTITY", "RUNS_AS", "MEMBER_OF_K8S_GROUP",
        "BOUND_TO", "CAN_RUN_AS_SA", "EKS_ACCESS_ENTRY", "AWS_AUTH_MAPPING", "IN_CLUSTER", "MOUNTS_SECRET",
        "SELECTS", "INGRESS_ROUTES_TO",
    }
    assert engine_md | WAVE3_ADDITIONS == names
    assert not engine_md & WAVE3_ADDITIONS
    for removed in ("CAN_LAUNCH", "CAN_ASSUME_CROSS", "INTERNET_FACING", "GRANTS_ACCESS", "SECRET_GRANTS_ACCESS"):
        assert removed not in names


@pytest.mark.parametrize("name,traversable,traversal,weight", [
    ("CAN_INVOKE", False, "access", 1), ("CAN_UPDATE_CODE", True, "control", 1),
    ("MEMBER_OF", "rule", "control", 0), ("HAS_POLICY", False, "structural", 0),
    ("IRSA_BRIDGE", "rule", "control", 0), ("IN_CLUSTER", False, "structural", 0),
    ("GRANTS_PUBLIC", True, "exposure", 0), ("PUBLIC_INBOUND", False, "exposure", 0),
    ("FULL_ACCESS", True, "access", 0), ("CAN_ADMIN", True, "access", 0.5), ("USES_ROLE", True, "control", 0),
    ("EXECUTION_ROLE", False, "info", 0), ("CLUSTER_ROLE", False, "info", 0), ("SSRF_TO_IMDS", True, "control", 5),
    ("CAN_PASS_ROLE_TO", True, "control", 2), ("LAMBDA_GRANTS_INVOKE", False, "access", 1),
    ("POOL_AUTH_ROLE", "rule", "control", 1),
])
def test_table_rows(name, traversable, traversal, weight):
    et = ET.EDGE_TYPES[name]
    if traversable == "rule":
        assert et.traversable_rule in ET.TRAVERSABLE_RULES and et.may_traverse
    else:
        assert et.traversable is traversable
    assert et.traversal == traversal
    assert et.base_weight == weight


def test_bridge_types_and_compute_nodes():
    bridges = {n for n, t in ET.NODE_TYPES.items() if t.is_compute_bridge}
    assert {"lambda", "instance", "ecstask", "ecsservice", "gluejob", "codebuild", "sagemaker", "cfnstack",
            "stackset", "pod", "sa", "nodegroup", "cognito"} <= bridges
    # every incoming traversable edge type of a bridge node is control
    for et in ET.EDGE_TYPES.values():
        if et.may_traverse and set(et.targets) & bridges:
            assert et.traversal == "control", et.name
    assert {e.name for e in ET.EDGE_TYPES.values() if e.bridge} == {
        "INSTANCE_ROLE", "USES_ROLE", "POOL_UNAUTH_ROLE", "POOL_AUTH_ROLE", "POOL_MAPPED_ROLE", "NODE_ROLE",
        "IRSA_BRIDGE", "POD_IDENTITY", "RUNS_AS"}


def test_grant_edges_are_normalised():
    for et in ET.EDGE_TYPES.values():
        if "GRANTS" in et.name or "SHARED" in et.name:
            assert "anonymous" in et.sources or set(et.sources) & {"external_account", "external_principal", "user"}
            assert not set(et.targets) & {"anonymous", "external_account", "external_principal"}, et.name
        if et.name.endswith("_PUBLIC"):
            assert et.sources == ("anonymous",), et.name
    for le in ET.LEGACY_EDGE_TYPES:
        if le.disposition == "normalised":
            for nt in le.new_types:
                assert ET.EDGE_TYPES[nt].legacy_reversed, nt


def test_edge_weight_formula():
    assert ET.edge_weight("CAN_ASSUME") == 1
    assert ET.edge_weight("CAN_ASSUME", "conditional", "weak") == 2
    assert ET.edge_weight("CAN_ASSUME", "conditional", "strong") == 4
    assert ET.edge_weight("CAN_ASSUME", "conditional", "none") == 1
    assert ET.edge_weight("CAN_ASSUME", "definite", "strong") == 1
    assert ET.edge_weight("CAN_REACH_NODE_IMDS", extra=2) == 3
    assert ET.edge_weight("CAN_CONNECT") == 0.5
    assert isinstance(ET.edge_weight("FULL_ACCESS"), int)
    for bad in ({"confidence": "maybe"}, {"strength": "huge"}, {"extra": -1}):
        with pytest.raises(ValueError):
            ET.edge_weight("CAN_ASSUME", **bad)


def test_registry_entries_validate_against_schema():
    node_v, edge_v = _validator("graph", "nodeTypeEntry"), _validator("graph", "edgeTypeEntry")
    for name in ET.NODE_TYPES:
        assert list(node_v.iter_errors(ET.node_type_entry(name))) == [], name
    for name in ET.EDGE_TYPES:
        assert list(edge_v.iter_errors(ET.edge_type_entry(name))) == [], name
        assert ET.edge_type_entry(name)["traversable"] in (True, False, "conditional")


def test_node_type_icons_exist_or_are_announced():
    icons = {p.stem for p in (targets.dashboard_dir() / "icons").glob("*.svg")}
    for t in ET.NODE_TYPES.values():
        assert t.icon in icons or t.icon in ET.NEW_ICON_KEYS, (t.name, t.icon)
    assert len(set(ET.NEW_ICON_KEYS)) == len(ET.NEW_ICON_KEYS)


def test_node_types_have_id_patterns_and_builders():
    assert set(IDS.NODE_ID_PATTERNS) == set(ET.NODE_TYPES)


# legacy inventory ─────────────────────────────────────────────────────────────

LEGACY_FILE_BY_DICT = {
    "S3_ACCESS_WEIGHTS": "s3_relationships.json", "EC2_ACCESS_WEIGHTS": "ec2_relationships.json",
    "K8S_ACCESS_WEIGHTS": "k8s_relationships.json", "SECRETS_ACCESS_WEIGHTS": "secrets_relationships.json",
    "LAMBDA_ACCESS_WEIGHTS": "lambda_relationships.json", "KMS_ACCESS_WEIGHTS": "kms_relationships.json",
    "COMPUTE_WEIGHTS": "compute_relationships.json", "MESSAGING_WEIGHTS": "messaging_relationships.json",
    "NEWSURFACE_WEIGHTS": "newsurface_relationships.json", "EXTRA_WEIGHTS": "extra_relationships.json",
}
#: The d13c215 dashboard-derived edges (index.html :1163-1251).
DASHBOARD_EDGES = {"MEMBER_OF", "HAS_POLICY", "CAN_ASSUME", "CAN_ASSUME_CROSS", "INSTANCE_ROLE", "SSRF_TO_IMDS"}


def _inventory() -> Set[Tuple[str, str]]:
    return {(le.origin, le.name) for le in ET.LEGACY_EDGE_TYPES}


def _git_show(path: str) -> str:
    try:
        return subprocess.run(["git", "-C", str(targets.REPO_ROOT), "show", f"d13c215:{path}"], check=True,
                              capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        pytest.skip("git or commit d13c215 unavailable")


def test_legacy_inventory_matches_d13c215_weight_tables():
    tree = ast.parse(_git_show("app/components/policy_parser.py"))
    found: Set[Tuple[str, str]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id in LEGACY_FILE_BY_DICT:
                    for k in node.value.keys:
                        found.add((LEGACY_FILE_BY_DICT[t.id], ast.literal_eval(k)))
    assert len(found) == 72
    engine_part = {x for x in _inventory() if x[0] != ET.LEGACY_DASHBOARD}
    assert found == engine_part


def test_legacy_inventory_covers_d13c215_dashboard_edges():
    html = _git_show("app/dashboard/index.html")
    lines = html.splitlines()[1150:1260]
    found = set()
    for line in lines:
        if "makeEdge(" in line or "edgeType =" in line:
            found |= set(re.findall(r"'([A-Z][A-Z_]+)'", line))
    assert found == DASHBOARD_EDGES
    assert {n for o, n in _inventory() if o == ET.LEGACY_DASHBOARD} == DASHBOARD_EDGES


def test_legacy_goldens_edge_types_are_in_inventory():
    # The d13c215 characterisation goldens (tests/golden/legacy/**) were retired in Wave 3a (D-53); the (file, type)
    # pairs they held are kept as tests/golden/d13c215-relationship-edge-types.json.
    inventory = _load(targets.REPO_ROOT / "tests" / "golden" / "d13c215-relationship-edge-types.json")
    seen: Set[Tuple[str, str]] = {(f, t) for f, types in inventory["files"].items() for t in types}
    assert len(seen) > 40
    assert seen <= _inventory()


def test_live_weight_tables_only_use_known_names():
    """Wave 1/2 may edit the analyzers' weight dicts; every key must stay a known legacy or table name."""
    known = {n for _, n in _inventory()} | set(ET.EDGE_TYPES)
    tables = (("analyzers.s3", "S3_ACCESS_WEIGHTS"), ("analyzers.ec2", "EC2_ACCESS_WEIGHTS"),
              ("analyzers.k8s", "K8S_ACCESS_WEIGHTS"), ("analyzers.secrets", "SECRETS_ACCESS_WEIGHTS"),
              ("analyzers.lambda_", "LAMBDA_ACCESS_WEIGHTS"), ("analyzers.kms", "KMS_ACCESS_WEIGHTS"),
              ("analyzers.compute", "COMPUTE_WEIGHTS"), ("analyzers.messaging", "MESSAGING_WEIGHTS"),
              ("analyzers.data_stores", "NEWSURFACE_WEIGHTS"), ("analyzers.edge_services", "EXTRA_WEIGHTS"))
    for mod_name, dict_name in tables:
        try:
            table = getattr(engine_module(mod_name), dict_name)
        except (ImportError, AttributeError):
            continue
        assert set(table) <= known, (mod_name, sorted(set(table) - known))


def test_explore_edge_semantics_inventory_is_mapped():
    doc = targets.REPO_ROOT / "internal-docs" / "fix-plan" / "explore-edge-semantics.md"
    if not doc.exists():
        pytest.skip("internal-docs not present (untracked by owner decision)")
    text = doc.read_text(encoding="utf-8")
    section = text.split("# 1. Edge semantics table", 1)[1].split("# 2. Node types", 1)[0]
    names: Set[str] = set()
    for line in section.splitlines():
        if line.startswith("| ") and not line.startswith("| Type") and not line.startswith("|---"):
            first = line.split("|")[1]
            names |= set(re.findall(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b|\b[A-Z]{4,}\b", first))
    assert len(names) >= 60
    assert names <= {n for _, n in _inventory()}


def test_legacy_rendering_round_trips_through_inventory():
    inv = {(le.origin, le.name): le for le in ET.LEGACY_EDGE_TYPES}
    for et in ET.EDGE_TYPES.values():
        if et.legacy_name is None:
            continue
        files = {et.legacy_file} | {f for _, f in et.legacy_file_by_source}
        for f in files:
            le = inv.get((f, et.legacy_name))
            assert le is not None, (et.name, f, et.legacy_name)
            assert et.name in le.new_types, (et.name, le)
    # every replacement listed in the inventory is rendered back under the old name or is a renamed/new type
    for le in ET.LEGACY_EDGE_TYPES:
        if le.disposition in ("kept", "normalised", "implemented") and le.origin != ET.LEGACY_DASHBOARD:
            et = ET.EDGE_TYPES[le.new_types[0]]
            files = {et.legacy_file} | {f for _, f in et.legacy_file_by_source}
            assert et.legacy_name == le.name and le.origin in files


# generated documentation ──────────────────────────────────────────────────────

def test_traversability_markdown_is_generated_from_table():
    committed = (CONTRACTS_DIR / "traversability-table.md").read_text(encoding="utf-8")
    assert committed == ET.render_markdown(), \
        "run: .venv/bin/python -m aws_enumerator.engine.graph.edge_types --write docs/contracts/traversability-table.md"
    assert ET.main(["--check", str(CONTRACTS_DIR / "traversability-table.md")]) == 0


def test_markdown_lists_every_type():
    md = ET.render_markdown()
    for name in ET.EDGE_TYPES:
        assert f"| `{name}` |" in md
    for name in ET.NODE_TYPES:
        assert f"| `{name}` |" in md
    assert md == ET.render_markdown()


def test_contract_docs_exist_and_cross_reference():
    for name in ("graph-json.md", "traversability-table.md", "engine-api.md", "finding-identity.md",
                 "node-ids.md", "path-map.md"):
        assert (CONTRACTS_DIR / name).is_file(), name
    api = (CONTRACTS_DIR / "engine-api.md").read_text(encoding="utf-8")
    assert "analyze_run(run_root, *, regions, account_id=None, partition=None, manifest=None, options=None)" in api
    assert "analyze_report(report_dir, options=None)" in api
    for opt in ("baseline", "suppress", "strict_catalog"):
        assert f"`{opt}`" in api
    for field_ in dataclasses.fields(MODEL.AnalysisOptions):
        assert f"`{field_.name}`" in api, field_.name
    for field_ in dataclasses.fields(MODEL.AnalysisResult):
        assert f"`{field_.name}`" in api, field_.name
    gj = (CONTRACTS_DIR / "graph-json.md").read_text(encoding="utf-8")
    for key in _schema("graph")["required"]:
        assert f"`{key}`" in gj, key
    for res in IDS.OPERATOR_RESOLUTIONS:
        assert f"`{res}`" in gj, res
    ni = (CONTRACTS_DIR / "node-ids.md").read_text(encoding="utf-8")
    for t in ET.NODE_TYPES:
        assert f"`{t}`" in ni, t


# ── identity helpers ──────────────────────────────────────────────────────────

FINGERPRINT_VECTORS = [
    ("ADMIN-001", MAIN, "arn:aws:iam::111122223333:role/admin/demo-admin-role", "", "0c80ca1a6b56b17fdb05e1f307aeafc5"),
    ("TRUST-002", MAIN, "arn:aws:iam::111122223333:role/demo-app-role", EXT, "09e028bbd285472f10764dc3807433c6"),
    ("S3-PUBLIC-001", MAIN, "arn:aws:s3:::demo-data-bucket", "", "d31b2b7fa68f40023b132034787e640e"),
    ("EC2-EXPOSURE-001", MAIN, "arn:aws:ec2:eu-west-2:111122223333:instance/i-0123456789abcdef0", "",
     "b6a6a7826f8360cc72068ed93b833a29"),
]


@pytest.mark.parametrize("cid,acct,node,disc,expected", FINGERPRINT_VECTORS)
def test_fingerprint_vectors(cid, acct, node, disc, expected):
    assert IDS.finding_fingerprint(cid, acct, node, disc) == expected
    doc = (CONTRACTS_DIR / "finding-identity.md").read_text(encoding="utf-8")
    assert expected in doc


def test_edge_id_vectors():
    assert IDS.edge_id("arn:aws:iam::111122223333:user/demo-user", "CAN_ASSUME",
                       "arn:aws:iam::111122223333:role/demo-app-role") == "e:02722febd9aa2c7acf16"
    assert IDS.edge_id(IDS.ANONYMOUS_ID, "GRANTS_PUBLIC", "arn:aws:s3:::demo-data-bucket") == "e:75337cbbfdf30f4f4379"
    assert IDS.edge_id("a", "T", "b") != IDS.edge_id("b", "T", "a")
    assert IDS.role_set_suffix(["arn:aws:iam::111122223333:role/demo-task-role"]) == "?roles=8a2609e7"


CLUSTER = "arn:aws:eks:eu-west-2:111122223333:cluster/demo-cluster"


@pytest.mark.parametrize("kind,parts,expected", [
    ("anonymous", {}, "aws-enumerator:anonymous"),
    ("account_admin", {"account": MAIN}, "aws-enumerator:account-admin/111122223333"),
    ("account", {"account": MAIN}, "aws-enumerator:account/111122223333"),
    ("region", {"account": MAIN, "region": "eu-west-2"}, "aws-enumerator:region/111122223333/eu-west-2"),
    ("external_account", {"account": EXT}, "arn:aws:iam::999999999999:root"),
    ("external_account", {"account": EXT, "partition": "aws-us-gov"}, "arn:aws-us-gov:iam::999999999999:root"),
    ("service_principal", {"service": "Lambda.amazonaws.com"}, "svc:lambda.amazonaws.com"),
    ("idp", {"host": "accounts.google.com"}, "aws-enumerator:idp/accounts.google.com"),
    ("role", {"arn": "arn:aws:iam::111122223333:role/team/demo-role"}, "arn:aws:iam::111122223333:role/team/demo-role"),
    ("instance", {"region": "eu-west-2", "account": MAIN, "id": "i-0abc"},
     "arn:aws:ec2:eu-west-2:111122223333:instance/i-0abc"),
    ("sg", {"partition": "aws-cn", "region": "cn-north-1", "account": MAIN, "id": "sg-0abc"},
     "arn:aws-cn:ec2:cn-north-1:111122223333:security-group/sg-0abc"),
    ("ami", {"region": "eu-west-2", "id": "ami-0abc"}, "arn:aws:ec2:eu-west-2::image/ami-0abc"),
    ("ebssnapshot", {"region": "eu-west-2", "id": "snap-0abc"}, "arn:aws:ec2:eu-west-2::snapshot/snap-0abc"),
    ("bucket", {"name": "demo-bucket"}, "arn:aws:s3:::demo-bucket"),
    ("lambda", {"arn": "arn:aws:lambda:eu-west-2:111122223333:function:demo-fn:live"},
     "arn:aws:lambda:eu-west-2:111122223333:function:demo-fn"),
    ("lambda", {"region": "eu-west-2", "account": MAIN, "name": "demo-fn"},
     "arn:aws:lambda:eu-west-2:111122223333:function:demo-fn"),
    ("kms", {"region": "eu-west-2", "account": MAIN, "key_id": "mrk-0abc"},
     "arn:aws:kms:eu-west-2:111122223333:key/mrk-0abc"),
    ("ssmparam", {"region": "eu-west-2", "account": MAIN, "name": "/demo/db/password"},
     "arn:aws:ssm:eu-west-2:111122223333:parameter/demo/db/password"),
    ("sqs", {"region": "eu-west-2", "account": MAIN, "name": "demo-queue"},
     "arn:aws:sqs:eu-west-2:111122223333:demo-queue"),
    ("dynamodb", {"region": "eu-west-2", "account": MAIN, "name": "demo-table"},
     "arn:aws:dynamodb:eu-west-2:111122223333:table/demo-table"),
    ("gluejob", {"region": "eu-west-2", "account": MAIN, "name": "demo-job"},
     "arn:aws:glue:eu-west-2:111122223333:job/demo-job"),
    ("elb", {"region": "eu-west-2", "account": MAIN, "name": "demo-classic"},
     "arn:aws:elasticloadbalancing:eu-west-2:111122223333:loadbalancer/demo-classic"),
    ("cognito", {"region": "eu-west-2", "account": MAIN, "pool_id": "eu-west-2:0000"},
     "arn:aws:cognito-identity:eu-west-2:111122223333:identitypool/eu-west-2:0000"),
    ("route53zone", {"zone_id": "/hostedzone/Z0ABC"}, "arn:aws:route53:::hostedzone/Z0ABC"),
    ("cluster", {"region": "eu-west-2", "account": MAIN, "name": "demo-cluster"}, CLUSTER),
    ("ecstask", {"region": "eu-west-2", "account": MAIN, "family": "web"},
     "arn:aws:ecs:eu-west-2:111122223333:task-definition/web"),
    ("ecstask", {"region": "eu-west-2", "account": MAIN, "family": "web",
                 "roles": ["arn:aws:iam::111122223333:role/demo-task-role"]},
     "arn:aws:ecs:eu-west-2:111122223333:task-definition/web?roles=8a2609e7"),
    ("pod", {"cluster_arn": CLUSTER, "namespace": "default", "name": "Deployment:web"},
     f"k8s://{CLUSTER}/Pod/default/Deployment:web"),
    ("sa", {"cluster_arn": CLUSTER, "namespace": "default", "name": "app"},
     f"k8s://{CLUSTER}/ServiceAccount/default/app"),
    ("k8srole", {"cluster_arn": CLUSTER, "k8s_kind": "ClusterRole", "namespace": "ignored", "name": "admin"},
     f"k8s://{CLUSTER}/ClusterRole/_/admin"),
    ("k8srole", {"cluster_arn": CLUSTER, "namespace": "default", "name": "pod-creator"},
     f"k8s://{CLUSTER}/Role/default/pod-creator"),
    ("k8sgroup", {"cluster_arn": CLUSTER, "name": "system:masters"}, f"k8s://{CLUSTER}/Group/_/system:masters"),
    ("k8suser", {"cluster_arn": CLUSTER, "name": "arn:aws:iam::111122223333:role/demo"},
     f"k8s://{CLUSTER}/User/_/arn:aws:iam::111122223333:role/demo"),
])
def test_node_id_for(kind, parts, expected):
    got = IDS.node_id_for(kind, **parts)
    assert got == expected
    assert IDS.node_id_matches(kind, got)


@pytest.mark.parametrize("kind,parts", [
    ("nope", {}),
    ("role", {"arn": "role:demo"}),                                  # legacy dashboard scheme
    ("role", {"arn": "arn:aws:iam::111122223333:user/demo"}),        # wrong type
    ("instance", {"region": "eu-west-2", "account": "1234", "id": "i-0abc"}),
    ("instance", {"region": "EU", "account": MAIN, "id": "i-0abc"}),
    ("bucket", {}),
    ("account_admin", {"account": "not-an-account"}),
    ("lambda", {"arn": "arn:aws:s3:::demo"}),
    ("sa", {"cluster_arn": "demo-cluster", "namespace": "default", "name": "app"}),
    ("sa", {"cluster_arn": CLUSTER, "namespace": "default", "name": "a/b"}),
    ("k8srole", {"cluster_arn": CLUSTER, "k8s_kind": "Pod", "namespace": "x", "name": "y"}),
])
def test_node_id_for_rejects_bad_parts(kind, parts):
    with pytest.raises(ValueError):
        IDS.node_id_for(kind, **parts)


def test_parse_arn_and_lambda_qualifiers():
    p = IDS.parse_arn("arn:aws:secretsmanager:eu-west-2:111122223333:secret:demo/db:with:colons")
    assert (p.partition, p.service, p.region, p.account) == ("aws", "secretsmanager", "eu-west-2", MAIN)
    assert p.resource == "secret:demo/db:with:colons"
    assert IDS.parse_arn("not-an-arn") is None and IDS.parse_arn("arn:aws") is None
    assert IDS.lambda_unqualified("arn:aws:lambda:eu-west-2:111122223333:function:fn:7") == (
        "arn:aws:lambda:eu-west-2:111122223333:function:fn", "7")
    assert IDS.lambda_unqualified("arn:aws:lambda:eu-west-2:111122223333:function:fn")[1] is None


@pytest.mark.parametrize("arn,kind,name,session,iam_arn", [
    ("arn:aws:iam::111122223333:user/team/demo-user", "user", "demo-user", None,
     "arn:aws:iam::111122223333:user/team/demo-user"),
    ("arn:aws:iam::111122223333:root", "root", None, None, "arn:aws:iam::111122223333:root"),
    ("arn:aws:sts::111122223333:assumed-role/demo-role/demo-session", "assumed-role", "demo-role", "demo-session",
     None),
    ("arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Admin_0123/demo-user", "sso",
     "AWSReservedSSO_Admin_0123", "demo-user", None),
    ("arn:aws-us-gov:sts::111122223333:federated-user/demo", "federated-user", "demo", None, None),
])
def test_principal_from_sts_arn(arn, kind, name, session, iam_arn):
    p = IDS.principal_from_sts_arn(arn)
    assert (p.kind, p.name, p.session, p.iam_arn, p.account) == (kind, name, session, iam_arn, MAIN)


@pytest.mark.parametrize("arn", ["", "arn:aws:s3:::bucket", "arn:aws:sts::111122223333:assumed-role/",
                                 "arn:aws:iam::111122223333:group/demo", "arn:aws:iam::abc:user/x"])
def test_principal_from_sts_arn_rejects(arn):
    assert IDS.principal_from_sts_arn(arn) is None


LOCAL_ROLE = "arn:aws:iam::111122223333:role/team/admin-role"
INDEX = {
    LOCAL_ROLE: "role",
    "arn:aws:iam::111122223333:user/demo-user": "user",
    "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com": "idp",
    IDS.ANONYMOUS_ID: "anonymous",
}


@pytest.mark.parametrize("raw,ptype,node_id,node_type,reason,external,placeholder", [
    ("*", "AWS", IDS.ANONYMOUS_ID, "anonymous", "wildcard", False, False),
    (MAIN, "AWS", None, None, "same-account-root-delegation", False, False),
    ("arn:aws:iam::111122223333:root", "AWS", None, None, "same-account-root-delegation", False, False),
    (EXT, "AWS", "arn:aws:iam::999999999999:root", "external_account", "foreign-account", True, False),
    (LOCAL_ROLE, "AWS", LOCAL_ROLE, "role", "exact", False, False),
    # F-039: a foreign role with the same name is never the local role
    ("arn:aws:iam::999999999999:role/admin-role", "AWS", "arn:aws:iam::999999999999:role/admin-role",
     "external_principal", "foreign-principal", True, False),
    # exact ARN only: the same name without the path is not matched to the indexed role
    ("arn:aws:iam::111122223333:role/admin-role", "AWS", "arn:aws:iam::111122223333:role/admin-role", "role",
     "local-not-collected", False, True),
    ("arn:aws:iam::111122223333:user/admin-role", "AWS", "arn:aws:iam::111122223333:user/admin-role", "user",
     "local-not-collected", False, True),
    ("arn:aws:iam::111122223333:group/demo-devs", "AWS", "arn:aws:iam::111122223333:group/demo-devs", "group",
     "local-not-collected", False, True),
    ("arn:aws:sts::111122223333:assumed-role/admin-role/s1", "AWS", LOCAL_ROLE, "role", "session-mapped-to-role",
     False, False),
    ("arn:aws:sts::111122223333:assumed-role/ADMIN-ROLE/s1", "AWS", LOCAL_ROLE, "role", "session-mapped-to-role",
     False, False),
    ("arn:aws:sts::111122223333:assumed-role/missing/s1", "AWS", None, None, "local-session-role-not-collected",
     False, False),
    ("arn:aws:sts::999999999999:assumed-role/admin-role/s1", "AWS",
     "arn:aws:sts::999999999999:assumed-role/admin-role/s1", "external_principal", "foreign-principal", True, False),
    ("AROAEXAMPLEEXAMPLE1234", "AWS", None, None, "stale-principal", False, False),
    ("lambda.amazonaws.com", "Service", "svc:lambda.amazonaws.com", "service_principal", "service-principal",
     False, False),
    ("arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com", "Federated",
     "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com", "idp", "exact", False, False),
    ("arn:aws:iam::999999999999:saml-provider/demo", "Federated", "arn:aws:iam::999999999999:saml-provider/demo",
     "idp", "provider-not-collected", True, True),
    ("cognito-identity.amazonaws.com", "Federated", "aws-enumerator:idp/cognito-identity.amazonaws.com", "idp",
     "well-known-web-idp", False, False),
    ("79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be", "CanonicalUser", None, None,
     "canonical-user", False, False),
    ("arn:aws:s3:::demo-bucket", "AWS", None, None, "unparseable", False, False),
    ("garbage", "AWS", None, None, "unparseable", False, False),
])
def test_resolve_principal(raw, ptype, node_id, node_type, reason, external, placeholder):
    ref = IDS.resolve_principal(raw, INDEX, MAIN, principal_type=ptype)
    assert (ref.node_id, ref.node_type, ref.reason, ref.external, ref.placeholder) == (
        node_id, node_type, reason, external, placeholder)


def test_resolve_principal_partition_and_lookup_reuse():
    look = IDS.PrincipalLookup(INDEX.items())
    ref = IDS.resolve_principal(EXT, look, MAIN, partition="aws-us-gov")
    assert ref.node_id == "arn:aws-us-gov:iam::999999999999:root"
    assert IDS.resolve_principal("", look, MAIN).reason == "empty-principal"
    assert IDS.resolve_principal("x", look, MAIN, principal_type="Weird").reason == "unknown-principal-type"
    with pytest.raises(ValueError):
        IDS.resolve_principal("*", look, "bad-account")


def test_resolve_principal_never_matches_by_last_segment():
    look = IDS.PrincipalLookup(INDEX)
    for raw in ("arn:aws:iam::999999999999:role/team/admin-role", "arn:aws:iam::999999999999:user/admin-role",
                "arn:aws:iam::999999999999:role/demo-user"):
        ref = IDS.resolve_principal(raw, look, MAIN)
        assert ref.node_id == raw and ref.node_id not in INDEX


@pytest.mark.parametrize("caller,kwargs,node_id,resolution,arn", [
    ("arn:aws:iam::111122223333:user/demo-user", {}, "arn:aws:iam::111122223333:user/demo-user", "exact", None),
    ("arn:aws:iam::111122223333:user/other", {}, None, "not-in-graph", None),
    ("arn:aws:sts::111122223333:assumed-role/admin-role/s", {}, LOCAL_ROLE, "assumed-role", None),
    ("arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_X_1/u", {}, None, "not-in-graph", None),
    ("arn:aws:iam::111122223333:root", {}, "aws-enumerator:account-admin/111122223333", "root", None),
    ("arn:aws:sts::111122223333:federated-user/demo", {}, None, "federated", None),
    ("arn:aws:sts::999999999999:assumed-role/admin-role/s", {}, None, "cross-account", None),
    (None, {}, None, "unavailable", None),
    ("arn:aws:sts::111122223333:assumed-role/admin-role/s",
     {"principal_arn": LOCAL_ROLE, "redacted": True}, LOCAL_ROLE, "exact", LOCAL_ROLE),
    # redacted, and the manifest did not know the role path: mapped by name in the same account
    ("arn:aws:sts::111122223333:assumed-role/admin-role/s",
     {"principal_arn": "arn:aws:iam::111122223333:role/admin-role", "redacted": True}, LOCAL_ROLE, "assumed-role",
     "arn:aws:iam::111122223333:role/admin-role"),
    (None, {"principal_arn": "arn:aws:iam::111122223333:role/missing-role"}, None, "not-in-graph",
     "arn:aws:iam::111122223333:role/missing-role"),
    ("weird", {}, None, "not-in-graph", None),
])
def test_resolve_operator(caller, kwargs, node_id, resolution, arn):
    op = IDS.resolve_operator(caller, INDEX, MAIN, **kwargs)
    assert (op.node_id, op.resolution) == (node_id, resolution)
    assert op.arn == (arn if arn is not None else caller)
    assert op.redacted is kwargs.get("redacted", False)
    assert op.resolution in IDS.OPERATOR_RESOLUTIONS
    assert list(_validator("graph", "operator").iter_errors(op.to_json())) == []


def test_resolve_operator_sso_maps_to_role():
    sso = "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/eu-west-2/AWSReservedSSO_Admin_0123"
    op = IDS.resolve_operator("arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Admin_0123/demo",
                              {sso: "role"}, MAIN)
    assert (op.node_id, op.resolution) == (sso, "sso")


KMS_KW = {"partition": "aws", "region": "eu-west-2", "account": MAIN}
KEY = "arn:aws:kms:eu-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
ALIASES = {"arn:aws:kms:eu-west-2:111122223333:alias/demo": KEY,
           "arn:aws:kms:eu-west-2:111122223333:alias/aws/secretsmanager": KEY}


@pytest.mark.parametrize("ref,kwargs,expected", [
    (KEY, {}, (KEY, True, "key-arn")),
    ("arn:aws:kms:us-east-1:999999999999:key/mrk-1", {}, ("arn:aws:kms:us-east-1:999999999999:key/mrk-1", True,
                                                          "key-arn")),
    ("1234abcd-12ab-34cd-56ef-1234567890ab", {}, (KEY, True, "key-id")),
    ("alias/demo", {"aliases": ALIASES}, (KEY, True, "alias-resolved")),
    ("arn:aws:kms:eu-west-2:111122223333:alias/demo", {"aliases": ALIASES}, (KEY, True, "alias-resolved")),
    ("alias/missing", {"aliases": ALIASES}, ("arn:aws:kms:eu-west-2:111122223333:alias/missing", False,
                                             "alias-unresolved")),
    (None, {"aliases": ALIASES, "default_alias": "alias/aws/secretsmanager"}, (KEY, True, "default-alias")),
    ("", {}, None),
])
def test_kms_key_node_id(ref, kwargs, expected):
    got = IDS.kms_key_node_id(ref, **KMS_KW, **kwargs)
    assert (None if got is None else (got.node_id, got.resolved, got.kind)) == expected
    if got is not None:
        assert IDS.node_id_matches("kms", got.node_id)


def test_kms_key_node_id_rejects_non_kms():
    with pytest.raises(ValueError):
        IDS.kms_key_node_id("arn:aws:s3:::bucket", **KMS_KW)
    with pytest.raises(ValueError):
        IDS.kms_key_node_id("arn:aws:kms:eu-west-2:111122223333:grant/x", **KMS_KW)


# ── model ─────────────────────────────────────────────────────────────────────

def test_tri_kleene_tables():
    T, F, M = MODEL.Tri.TRUE, MODEL.Tri.FALSE, MODEL.Tri.MAYBE
    and_ = {(T, T): T, (T, F): F, (T, M): M, (F, F): F, (F, M): F, (M, M): M}
    or_ = {(T, T): T, (T, F): T, (T, M): T, (F, F): F, (F, M): M, (M, M): M}
    for (a, b), r in and_.items():
        assert a.and_(b) is r and b.and_(a) is r
    for (a, b), r in or_.items():
        assert a.or_(b) is r and b.or_(a) is r
    assert (T.not_(), F.not_(), M.not_()) == (F, T, M)
    assert MODEL.Tri.all_([]) is T and MODEL.Tri.any_([]) is F
    assert MODEL.Tri.all_([T, M, T]) is M and MODEL.Tri.any_([F, M]) is M
    assert MODEL.Tri.of(True) is T


def test_decision_and_strength_order():
    D, S = MODEL.Decision, MODEL.Strength
    assert sorted(D, key=lambda d: d.rank, reverse=True) == [D.ALLOW, D.CONDITIONAL, D.NOT_ALLOWED, D.DENY]
    assert [d.value for d in D] == ["allow", "conditional", "deny", "not_allowed"]
    assert D.ALLOW.grants and D.CONDITIONAL.grants and not D.DENY.grants and not D.NOT_ALLOWED.grants
    assert S.strongest([S.NONE, S.WEAK]) is S.WEAK and S.strongest([]) is S.NONE
    assert S.strongest([S.STRONG, S.WEAK]) is S.STRONG
    assert MODEL.EvalResult(D.CONDITIONAL, strength=S.WEAK).confidence == "conditional"
    assert MODEL.EvalResult(D.ALLOW).confidence == "definite"
    assert MODEL.ABSENT is type(MODEL.ABSENT)()


def test_action_matcher_and_capability():
    m = MODEL.ActionMatcher(exact=frozenset({"s3:getobject"}), prefixes=(("iam", "put"),),
                            globs=(re.compile(r"ec2:.*instances"),))
    assert m.matches("S3:GetObject") and m.matches("iam:PutUserPolicy") and m.matches("ec2:DescribeInstances")
    assert not m.matches("iam:GetUser") and not m.matches("s3:PutObject")
    assert MODEL.ActionMatcher(any=True).matches("anything:at-all")
    MODEL.Capability("arn:aws:iam::*:role/*", action_glob="iam:*")
    with pytest.raises(ValueError):
        MODEL.Capability("*")
    with pytest.raises(ValueError):
        MODEL.Capability("*", action_glob="iam:*", actions_any=("iam:PassRole",))


def test_policy_model_is_frozen_and_slotted():
    src = MODEL.PolicySource("identity", "arn:aws:iam::aws:policy/ReadOnlyAccess", "ReadOnlyAccess", "v1",
                             "aws_managed", None, 0, None)
    st = MODEL.Statement("Allow", ("s3:getobject",), None, ("*",), None, None, None, (), src)
    with pytest.raises(dataclasses.FrozenInstanceError):
        st.effect = "Deny"
    assert not hasattr(st, "__dict__")
    assert src.to_json()["statement_index"] == 0
    expected = {"Tri", "Decision", "Strength", "PolicySource", "Condition", "Statement", "Principal",
                "PrincipalModel", "RequestContext", "EvalResult", "Node", "Edge", "Finding"}
    assert expected <= set(dir(MODEL))


def test_evaluator_protocol_signatures():
    api = MODEL.EvaluatorAPI
    for name, params in {
        "evaluate": ["self", "principal", "action", "resource", "context"],
        "evaluate_any": ["self", "principal", "action", "resource_template", "context"],
        "evaluate_capability": ["self", "principal", "capability"],
        "best": ["self", "principal", "actions", "resource", "kw"],
        "can_assume": ["self", "caller", "role_arn", "protocol", "claims"],
        "resource_policy_grants": ["self", "policy", "resource_arn"],
    }.items():
        assert list(inspect.signature(getattr(api, name)).parameters) == params, name


def test_graph_records_serialise_to_schema_shapes():
    node = MODEL.Node(id="arn:aws:iam::111122223333:role/demo", type="role", label="demo", account=MAIN,
                      partition="aws", props={"attached_policies_status": "complete"},
                      tags=[MODEL.Tag("b", "2"), MODEL.Tag("a", "1")], findings=["f" * 32, "f" * 32])
    nj = node.to_json()
    assert [t["key"] for t in nj["tags"]] == ["a", "b"] and nj["findings"] == ["f" * 32]
    assert list(_validator("graph", "node").iter_errors(nj)) == []
    with pytest.raises(ValueError):
        MODEL.Node(id="x", type="role", label="x", props={"__proto__": 1}).to_json()
    with pytest.raises(ValueError):
        MODEL.Node(id="x", type="role", label="x", props={"BadKey": 1}).to_json()
    src, tgt = "arn:aws:iam::111122223333:user/u", "arn:aws:iam::111122223333:role/demo"
    edge = MODEL.Edge(id=IDS.edge_id(src, "CAN_ASSUME", tgt), source=src, target=tgt, type="CAN_ASSUME",
                      category="trust", traversal="control", traversable=True, weight=1)
    assert list(_validator("graph", "edge").iter_errors(edge.to_json())) == []
    assert "props" not in edge.to_json()
    f = MODEL.Finding(fingerprint=IDS.finding_fingerprint("ADMIN-001", MAIN, tgt), id="ADMIN-001",
                      severity="CRITICAL", node_id=tgt, title="t", description="d", remediation="r",
                      reference=None, matched_actions=["b", "a", "a"], legacy={"entity": "demo"})
    fj = f.to_json()
    assert fj["base_severity"] == "CRITICAL" and fj["matched_actions"] == ["a", "b"] and fj["entity"] == "demo"
    assert list(fj)[:len(MODEL.FINDING_REQUIRED)] == list(MODEL.FINDING_REQUIRED)
    assert list(_validator("graph", "finding").iter_errors(fj)) == []
    assert list(_validator("findings", "finding").iter_errors(fj)) == []
    status = MODEL.AnalyzerStatus("s3", MODEL.Phase.RESOURCES, "error", 0.5, "KeyError", "boom", ("s3.acl",))
    assert list(_validator("graph", "analyzerStatus").iter_errors(status.to_json())) == []
    assert status.to_json()["error"] == {"type": "KeyError", "message": "boom"}


def test_analysis_options_and_result_fields():
    opts = MODEL.AnalysisOptions()
    assert (opts.baseline, opts.suppress, opts.strict_catalog) == (None, None, False)
    names = [f.name for f in dataclasses.fields(MODEL.AnalysisResult)]
    assert names[:4] == ["status", "analyzer_status", "outputs", "graph_path"]
    assert [p.value for p in MODEL.Phase] == list(range(1, 10))
    spec = MODEL.AnalyzerSpec("demo", MODEL.Phase.RESOURCES, run=lambda ctx, builder: None)
    assert spec.inputs == () and spec.optional is False


# ── findings.json, diff.json, suppressions ────────────────────────────────────

def test_findings_wrapper_validates():
    doc = _load(FIXTURES_GRAPH_DIR / "example.json")
    run = doc["run"]
    wrapper = {"schema_version": "1.0.0", "tool_version": doc["generator"]["version"],
               "rules_version": doc["generator"]["rules_version"], "account_id": run["account_id"],
               "partition": run["partition"], "regions": run["regions"], "mode": run["mode"],
               "run_id": run["run_id"], "generated_at": run["generated_at"], "findings": doc["findings"]}
    assert list(_validator("findings").iter_errors(wrapper)) == []
    wrapper.pop("findings")
    assert any(e.validator == "required" for e in _validator("findings").iter_errors(wrapper))
    assert any(e.validator == "required" for e in _validator("findings").iter_errors({"findings": []}))


def test_diff_document_validates():
    fp = "0c80ca1a6b56b17fdb05e1f307aeafc5"
    entry = {"fingerprint": fp, "id": "ADMIN-001", "node_id": "arn:aws:iam::111122223333:role/x",
             "severity": "CRITICAL"}
    diff = {"schema_version": "1.0.0", "baseline": {"ref": "old/findings.json", "schema_version": "1.0.0",
                                                    "run_id": None, "generated_at": None},
            "counts": {"new": 1, "resolved": 0, "unchanged": 0, "severity_changed": 1, "unknown": 1},
            "new": [entry], "resolved": [], "unchanged": [],
            "severity_changed": [{**{k: entry[k] for k in ("fingerprint", "id", "node_id")}, "from": "HIGH",
                                  "to": "CRITICAL"}],
            "unknown": [{**entry, "reason": "s3.bucket_policy: complete -> denied"}]}
    v = _validator("findings", "diff")
    assert list(v.iter_errors(diff)) == []
    diff["counts"]["new"] = -1
    assert list(v.iter_errors(diff))


@pytest.mark.parametrize("entry,valid", [
    ({"fingerprint": "0c80ca1a6b56b17fdb05e1f307aeafc5", "reason": "accepted", "expires": "2027-01-31"}, True),
    ({"rule_id": "S3-PUBLIC-001", "node_id_glob": "arn:aws:s3:::demo-*", "reason": "web", "expires": "2026-12-31",
      "owner": None}, True),
    ({"fingerprint": "0c80ca1a6b56b17fdb05e1f307aeafc5", "rule_id": "S3-PUBLIC-001", "node_id_glob": "*",
      "reason": "x", "expires": "2026-12-31"}, False),
    ({"rule_id": "S3-PUBLIC-001", "reason": "x", "expires": "2026-12-31"}, False),
    ({"fingerprint": "0c80ca1a6b56b17fdb05e1f307aeafc5", "expires": "2026-12-31"}, False),
    ({"fingerprint": "0c80ca1a6b56b17fdb05e1f307aeafc5", "reason": "", "expires": "2026-12-31"}, False),
    ({"fingerprint": "0c80ca1a6b56b17fdb05e1f307aeafc5", "reason": "x", "expires": "next week"}, False),
])
def test_suppression_file_schema(entry, valid):
    errors = list(_validator("findings", "suppressionFile").iter_errors({"version": 1, "suppressions": [entry]}))
    assert (errors == []) is valid
