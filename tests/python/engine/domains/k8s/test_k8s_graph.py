"""The ``k8s`` analyzer end to end: valid ``graph.json``, the legacy ``k8s_relationships.json``, determinism,
hostile input, the standby fallback, the acme fake world, and the module structure (F-084).
"""

from __future__ import annotations

import ast
import importlib
import json
import shutil
from pathlib import Path

import pytest

from tests.fixtures.regressions import support as S
from tests.support import targets

W = importlib.import_module("tests.fixtures.e-k8s.k8s_world")
K8S_DIR = targets.package_dir() / "engine" / "analyzers" / "k8s"
LEGACY_K8S_NAMES = {"CLUSTER_ROLE", "NODE_ROLE", "IRSA_BRIDGE", "IN_CLUSTER", "RUNS_AS", "MOUNTS_SECRET", "BOUND_TO",
                    "SELECTS", "EXPOSES"}


@pytest.mark.finding("F-005", "F-007", "F-025")
def test_the_eks_irsa_scenario_is_a_valid_directed_graph(tmp_path):
    S.build_scenario("eks_irsa", tmp_path)
    g = S.analyze_graph(tmp_path / S.ACCT / S.REGION)
    assert S.graph_problems(g) == [] and W.status(g) == "ok"
    nodes = W.nodes_by_id(g)
    for f in g["findings"]:
        if f["id"].startswith(("K8S-", "EKS-")):
            assert f["node_id"] in nodes and f["fingerprint"] in nodes[f["node_id"]]["findings"]
    cluster = f"arn:aws:eks:{S.REGION}:{S.ACCT}:cluster/demo-eks"
    assert nodes[cluster]["coverage"]["status"] == "complete"
    legacy = json.loads((tmp_path / S.ACCT / S.REGION / "analysis" / "k8s_relationships.json").read_text())
    assert "status" not in legacy and legacy["edges"] and legacy["findings"]
    assert {e["type"] for e in legacy["edges"]} <= LEGACY_K8S_NAMES
    assert "EXPOSES" in {e["type"] for e in legacy["edges"]}           # INGRESS_ROUTES_TO keeps its old name
    assert {f["id"] for f in legacy["findings"]} >= {"K8S-IRSA-ADMIN", "K8S-PRIV-001", "K8S-RBAC-001"}
    # the d13c215 layout keeps env values and Secret manifests on disk: none of it reaches the analysis
    for name in ("graph.json", "findings.json", "k8s_relationships.json"):
        text = (tmp_path / S.ACCT / S.REGION / "analysis" / name).read_text(encoding="utf-8")
        assert "AE-ENV-CANARY" not in text and "QUUtU0VDUkVULUNBTkFSWQ" not in text, name


@pytest.mark.finding("F-162")
def test_two_analyses_of_the_same_report_are_byte_identical(tmp_path):
    S.build_scenario("eks_irsa", tmp_path / "a")
    shutil.copytree(tmp_path / "a", tmp_path / "b")
    opts = targets.engine_module("model").AnalysisOptions(source_date_epoch=1767225600)
    outs = []
    for side in ("a", "b"):
        res = targets.engine_module().analyze_report(str(tmp_path / side / S.ACCT / S.REGION), opts)
        outs.append({name: (Path(res.analysis_dir) / name).read_bytes()
                     for name in ("graph.json", "findings.json", "k8s_relationships.json")})
    assert outs[0] == outs[1]


@pytest.mark.finding("F-002", "F-008")
def test_hostile_names_are_counted_never_guessed_or_crashing(report):
    c = report.cluster()
    xss = "<img src=x onerror=alert(1)>"
    c.pod("apps", "bad/name")                                       # cannot form an id
    c.pod("apps", xss, sa=xss)
    c.sa("apps", "slash/sa")
    c.binding(None, "weird", "ClusterRole", "cluster-admin",
              [W.subject("Group", "oidc:org/team"), W.subject("User", ""), W.subject("Bogus", "x")])
    c.service("apps", xss, svc_type="LoadBalancer", selector={"app": xss})
    out = report.analyze()
    g = out.graph
    assert W.problems(g) == [] and W.status(g) == "ok"
    assert c.id("Pod", "apps", xss) in W.nodes_by_id(g)              # stored raw; the dashboard escapes it
    assert W.nodes_by_id(g)[c.id("Group", None, "oidc:org/team")]["type"] == "k8sgroup"
    gaps = {x["code"]: x for x in g["evaluation_gaps"]}
    assert gaps["k8s:objects-unrepresentable"]["count"] >= 2


@pytest.mark.finding("F-002")
def test_a_failing_k8s_analyzer_is_isolated_and_rolled_back(tmp_path, monkeypatch):
    """One spec for the domain: a failure rolls the whole domain back; the rest of the analysis is kept (the
    d13c215 standby fallback is gone, D-53)."""
    pkg = targets.engine_module("analyzers.k8s")

    def boom(ctx, builder):
        raise RuntimeError("synthetic analyzer failure")

    monkeypatch.setattr(pkg, "run_workloads", boom)
    S.build_scenario("eks_irsa", tmp_path)
    g = S.analyze_graph(tmp_path / S.ACCT / S.REGION)
    statuses = {s["name"]: s["status"] for s in g["analyzer_status"]}
    assert statuses["k8s"] == "error" and "k8s:fallback" not in statuses
    assert S.graph_problems(g) == []
    assert not [n for n in g["nodes"] if n["type"] in ("pod", "cluster", "sa")]     # rolled back, never half
    assert [n for n in g["nodes"] if n["type"] == "role"] and statuses["trust"] == "ok"


@pytest.mark.finding("F-050", "F-034", "F-033", "F-025")
def test_the_acme_world_collected_and_analysed(tmp_path, monkeypatch):
    R = importlib.import_module("tests.python.orchestration.r_harness")
    run = R.collect(["collect", "--regions", "eu-west-1,eu-west-2"], tmp_path, monkeypatch)
    g = json.loads((run.run_root / "analysis" / "graph.json").read_text(encoding="utf-8"))
    assert W.status(g) == "ok" and W.problems(g) == []
    acct = g["run"]["account_id"]
    east = f"arn:aws:eks:eu-west-2:{acct}:cluster/demo-cluster"
    west = f"arn:aws:eks:eu-west-1:{acct}:cluster/demo-west-cluster"
    nodes = W.nodes_by_id(g)
    assert {east, west} <= set(nodes)
    sa = f"k8s://{east}/ServiceAccount/demo-apps/demo-api"
    irsa = W.edge(g, "IRSA_BRIDGE", sa, f"arn:aws:iam::{acct}:role/demo-irsa-role")
    assert irsa is not None and irsa["traversable"] is True               # its trust admits demo-apps/demo-api
    node_sa = f"k8s://{east}/ServiceAccount/kube-system/aws-node"
    stale = W.edge(g, "IRSA_BRIDGE", node_sa, f"arn:aws:iam::{acct}:role/demo-eks-node-role")
    assert stale is not None and stale["traversable"] is False            # an EC2 role: annotation only
    admin = f"arn:aws:iam::{acct}:role/demo-admin-role"
    for c in (east, west):
        target = f"k8s://{c}/ClusterRole/_/AccessPolicy:AmazonEKSClusterAdminPolicy"
        assert W.edge(g, "EKS_ACCESS_ENTRY", admin, target) is not None
    assert W.path(g, admin, f"arn:aws:iam::{acct}:role/demo-irsa-role") is not None
    assert W.edges(g, "POD_IDENTITY")                                      # demo-apps/demo-worker association
    text = (run.run_root / "analysis" / "graph.json").read_text(encoding="utf-8")
    assert "CANARY" not in text


# ── structure (F-084) ────────────────────────────────────────────────────────

def _modules():
    return sorted(K8S_DIR.glob("*.py"))


@pytest.mark.finding("F-084")
@pytest.mark.parametrize("path", _modules(), ids=lambda p: p.name)
def test_k8s_modules_are_small_functions_without_print_or_raw_action_loops(path):
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            assert node.end_lineno - node.lineno + 1 <= 120, (path.name, node.name)
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
            assert name not in ("print", "listdir", "scandir"), (path.name, node.lineno, name)
    assert "['actions']" not in text and '["actions"]' not in text


@pytest.mark.finding("F-084", "F-137")
def test_the_456_line_function_is_gone():
    init = (K8S_DIR / "__init__.py").read_text(encoding="utf-8")
    assert "def _analyze_k8s_relationships" not in init and not (K8S_DIR / "legacy.py").exists()
    assert targets.engine_module("analyzers.k8s").ANALYZERS[0].name == "k8s"
    for name in ("_analyze_k8s_relationships", "K8S_ACCESS_WEIGHTS", "_safe_get"):
        assert not hasattr(targets.engine_module("analyzers.k8s"), name), name
