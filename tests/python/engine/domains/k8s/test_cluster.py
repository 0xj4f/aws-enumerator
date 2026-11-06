"""EKS clusters (``analyzers/k8s/cluster.py``): endpoint exposure, enumeration status, the collecting identity's own
rules, and the control-plane / node roles.

F-033: EKS-ENDPOINT-001 for a public endpoint open to the internet; K8S-AUTH-001 (INFO) when the Kubernetes API of a
cluster was not enumerated, so an unreadable cluster never looks like an empty one. F-152: SelfSubjectRulesReview
results (K8S-CALLER-001) and namespaced fallbacks as partial coverage. F-007: CLUSTER_ROLE and IN_CLUSTER are not
attack steps.
"""

from __future__ import annotations

import importlib

import pytest

W = importlib.import_module("tests.fixtures.e-k8s.k8s_world")


@pytest.mark.finding("F-033")
@pytest.mark.parametrize("public, cidrs, expected", [
    (True, ["0.0.0.0/0"], "definite"),
    (True, ["198.51.100.0/24", "::/0"], "definite"),
    (True, ["203.0.113.0/24"], None),
    (False, None, None),
    (True, None, "conditional"),                  # publicAccessCidrs not collected: unknown, not safe
])
def test_public_endpoint_open_to_the_internet(report, public, cidrs, expected):
    c = report.cluster(public=public, cidrs=cidrs)
    g = report.analyze().graph
    assert W.problems(g) == []
    found = W.findings(g, "EKS-ENDPOINT-001", c.arn)
    inbound = W.edges(g, "PUBLIC_INBOUND", target=c.arn)
    if expected is None:
        assert found == [] and inbound == []
        return
    [f] = found
    assert f["severity"] == "MEDIUM" and f["confidence"] == expected
    [e] = inbound
    assert e["source"] == "aws-enumerator:anonymous" and e["traversable"] is False   # the API still authenticates
    assert W.nodes_by_id(g)[c.arn]["props"]["endpoint_public_access"] is True


@pytest.mark.finding("F-033")
@pytest.mark.parametrize("auth_status, coverage", [
    ("failed", "error"), ("unreachable", "error"), ("forbidden", "denied"), ("dependency_missing", "skipped")])
def test_a_cluster_that_was_not_enumerated_says_so(v2report, auth_status, coverage):
    c = v2report.cluster(auth_status=auth_status)
    c.pod("apps", "never-read")
    g = v2report.analyze().graph
    assert W.problems(g) == []
    [f] = W.findings(g, "K8S-AUTH-001", c.arn)
    assert f["severity"] == "INFO" and f["evidence"]["auth_status"] == auth_status
    node = W.nodes_by_id(g)[c.arn]
    assert node["coverage"]["status"] == coverage and f"k8s:api:{coverage}" in node["coverage"]["gaps"]
    assert [n for n in g["nodes"] if n["type"] == "pod"] == []


@pytest.mark.finding("F-033", "F-062")
def test_no_k8s_leaves_every_cluster_unknown(v2report):
    v2report.k8s_module_status = "skipped"
    c = v2report.cluster(auth_status=None)                         # --no-k8s: no k8s directory at all
    g = v2report.analyze().graph
    [f] = W.findings(g, "K8S-AUTH-001", c.arn)
    assert f["evidence"]["coverage_status"] == "skipped"
    assert W.nodes_by_id(g)[c.arn]["coverage"]["status"] == "skipped"


@pytest.mark.finding("F-152")
def test_the_collecting_identitys_rules_are_reported(v2report):
    c = v2report.cluster()
    c.self_rules = [
        {"namespace": "apps", "resource_rules": [{"verbs": ["create"], "api_groups": [""], "resources": ["pods"]},
                                                 {"verbs": ["get", "list"], "api_groups": [""],
                                                  "resources": ["secrets"]}],
         "non_resource_rules": [], "incomplete": False, "evaluation_error": None},
        {"namespace": "default", "resource_rules": [{"verbs": ["get"], "api_groups": [""], "resources": ["pods"]}],
         "non_resource_rules": [], "incomplete": True, "evaluation_error": None},
    ]
    g = v2report.analyze().graph
    [f] = W.findings(g, "K8S-CALLER-001", c.arn)
    assert f["severity"] == "INFO"
    notable = {(n["namespace"], n["permission"]) for n in f["evidence"]["notable"]}
    assert ("apps", "create pods (run as any service account of the namespace)") in notable
    assert ("apps", "list secrets (reads every value)") in notable
    assert f["evidence"]["incomplete_namespaces"] == ["default"]


@pytest.mark.finding("F-152", "F-059")
def test_a_namespaced_fallback_listing_is_partial_coverage(v2report):
    c = v2report.cluster()
    c.pod("apps", "api")
    c.resource_status["pods"] = {"status": "partial", "scope": "namespaced", "error_code": "Forbidden",
                                 "items": 1, "namespaces": ["apps"]}
    g = v2report.analyze().graph
    node = W.nodes_by_id(g)[c.arn]
    assert node["coverage"]["status"] == "partial" and "k8s:pods:partial" in node["coverage"]["gaps"]
    assert c.id("Pod", "apps", "api") in W.nodes_by_id(g)            # what was read is still analysed


@pytest.mark.finding("F-007", "F-033")
def test_the_control_plane_role_and_placement_are_not_attack_steps(report):
    c = report.cluster()
    c.pod("apps", "api")
    g = report.analyze().graph
    cluster_role = W.iam_arn("role", "demo-eks-cluster-role")
    [cr] = W.edges(g, "CLUSTER_ROLE", source=c.arn)
    assert cr["target"] == cluster_role and cr["traversable"] is False
    [placement] = W.edges(g, "IN_CLUSTER", source=c.id("Pod", "apps", "api"))
    assert placement["target"] == c.arn and placement["traversable"] is False
    assert W.path(g, c.id("Pod", "apps", "api"), cluster_role) is None
