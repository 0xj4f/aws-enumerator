"""Regression tests owned by stream E-k8s (Kubernetes analyzers and the k8s loader).

xfail-first (see test_e_policy.py). Kubernetes node ids follow node-ids.md:
``k8s://<cluster ARN>/<Kind>/<namespace>/<name>``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fixtures.regressions import support as S
from tests.support import report_builder as rb

ACCT, R, R1 = S.ACCT, S.REGION, S.OTHER_REGION
CLUSTER = f"arn:aws:eks:{R}:{ACCT}:cluster/demo-eks"


def pod(namespace: str, name: str) -> str:
    return f"k8s://{CLUSTER}/Pod/{namespace}/{name}"


# ── F-025 (K8s loader): no sibling-region bleed ──────────────────────────────
def build_sibling_clusters(root: Path) -> None:
    """eu-west-1 has an EKS cluster with a pod; eu-west-2 (same account, same day) has none."""
    for region, with_cluster in ((R1, True), (R, False)):
        s = rb.Scope(root, ACCT, region)
        iam = rb.Iam(ACCT)
        iam.role("demo-eks-cluster-role", rb.trust({"Service": "eks.amazonaws.com"}))
        iam.write(s)
        rb.write_empty_regional(s)
        if with_cluster:
            c = rb.eks_cluster("demo-west1-eks", account=ACCT, region=region,
                               role_arn=iam.arn("role", "demo-eks-cluster-role"))
            s.write("eks/clusters.json", [c])
            k = "k8s/demo-west1-eks"
            s.write(f"{k}/cluster_info.json",
                    {"name": "demo-west1-eks", "endpoint": c["endpoint"], "auth_status": "ok"})
            s.write(f"{k}/pods.json", [rb.k8s_pod("demo-west1-pod", "default", sa="default", privileged=True)])
            for f in ("namespaces", "service_accounts", "roles", "cluster_roles", "role_bindings",
                      "cluster_role_bindings", "secrets", "services", "ingresses"):
                s.write(f"{k}/{f}.json", [])
        rb.write_manifest(s.path, account=ACCT, mode="single_region", region=region)


@pytest.mark.finding("F-025", "F-063")
def test_f025_region_without_clusters_does_not_import_a_sibling_cluster(tmp_path):
    build_sibling_clusters(tmp_path)
    own = S.analyze_tree(tmp_path / ACCT / R1)          # positive control
    assert S.mentions(own, "demo-west1-eks")
    empty = S.analyze_tree(tmp_path / ACCT / R)
    assert S.mentions(empty, "demo-west1-eks") == []
    assert S.mentions(empty, "demo-west1-pod") == []


# ── F-007 (K8s part): pods sharing a cluster are not connected ───────────────
@pytest.mark.finding("F-007")
def test_f007_workloads_sharing_a_cluster_do_not_reach_each_others_roles(tmp_path):
    S.build_scenario("eks_irsa", tmp_path)
    graph = S.analyze_graph(tmp_path / ACCT / R)
    admin_irsa = S.iam_arn("role", "demo-irsa-admin")
    reader_irsa = S.iam_arn("role", "demo-irsa-reader")
    real = S.path(graph, pod("payments", "payments-api-0"), admin_irsa)   # pod -> RUNS_AS -> sa -> IRSA_BRIDGE
    assert real is not None and real.edge_types[-1] == "IRSA_BRIDGE", real
    assert S.path(graph, pod("web", "web-frontend-0"), admin_irsa) is None
    assert S.path(graph, reader_irsa, admin_irsa) is None
    assert all(e["traversable"] is False for e in S.graph_edges(graph, edge_type="IN_CLUSTER"))
