"""Kubernetes RBAC (``analyzers/k8s/rbac.py``): every subject kind, group membership, ``CAN_RUN_AS_SA`` with the
Kubernetes rule semantics, and the noise rules.

F-035: Group and User subjects (``system:authenticated``, ``system:anonymous`` …) bound to admin roles,
``CAN_RUN_AS_SA``. F-086: built-in roles never raise K8S-RBAC-002. F-007: a RoleBinding to a ClusterRole is
namespaced and never a cluster-wide path.
"""

from __future__ import annotations

import importlib

import pytest

W = importlib.import_module("tests.fixtures.e-k8s.k8s_world")
ADMIN_RULES = [W.rule(["*"], ["*"], ["*"])]


def _rbac():
    return importlib.import_module("tests.support.targets").engine_module("analyzers.k8s.rbac")


@pytest.mark.finding("F-035")
def test_group_and_user_subjects_are_bound_and_broad_ones_flagged(report):
    c = report.cluster()
    c.role(None, "cluster-admin", ADMIN_RULES)
    c.role("apps", "ns-all", [W.rule(["*"], ["*"])])
    c.binding(None, "everyone", "ClusterRole", "cluster-admin",
              [W.subject("Group", "system:authenticated"), W.subject("User", "system:anonymous"),
               W.subject("User", "demo-admin@example.com")])
    c.binding("apps", "apps-sas", "Role", "ns-all", [W.subject("Group", "system:serviceaccounts:apps")])
    c.sa("apps", "api")
    g = report.analyze().graph
    assert W.problems(g) == []
    admin = c.id("ClusterRole", None, "cluster-admin")
    for kind, name in (("Group", "system:authenticated"), ("User", "system:anonymous"),
                       ("User", "demo-admin@example.com")):
        assert W.edge(g, "BOUND_TO", c.id(kind, None, name), admin)["traversable"] is True
    sev = {f["node_id"].rsplit("/", 1)[-1]: f["severity"] for f in W.findings(g, "K8S-RBAC-003")}
    assert sev == {"system:authenticated": "CRITICAL", "system:anonymous": "CRITICAL",
                   "system:serviceaccounts:apps": "HIGH"}          # a namespaced grant is HIGH
    # memberships that make those bindings reach real identities
    sa = c.id("ServiceAccount", "apps", "api")
    groups = {e["target"].rsplit("/", 1)[-1] for e in W.edges(g, "MEMBER_OF_K8S_GROUP", source=sa)}
    assert groups == {"system:authenticated", "system:serviceaccounts:apps"}
    anon = W.edge(g, "MEMBER_OF_K8S_GROUP", c.id("User", None, "system:anonymous"),
                  c.id("Group", None, "system:authenticated"))
    assert anon is None                                            # anonymous is not authenticated
    assert W.findings(g, "K8S-RBAC-001") == []                     # no service account is bound directly


@pytest.mark.finding("F-035")
def test_can_run_as_sa_follows_the_kubernetes_rule_semantics(report):
    c = report.cluster()
    for ns, name in (("apps", "svc-a"), ("apps", "svc-b"), ("other", "svc-c")):
        c.sa(ns, name)
    rules = {
        "pod-creator": [W.rule(["create"], ["pods"])],
        "token-minter": [W.rule(["create"], ["serviceaccounts/token"], names=["svc-a"])],
        "impersonator": [W.rule(["impersonate"], ["serviceaccounts"])],
        "deploy-patcher": [W.rule(["patch"], ["deployments"], ["apps"])],
        "reader": [W.rule(["get", "list", "watch"], ["pods", "secrets"])],
        "wrong-group": [W.rule(["create"], ["deployments"], ["extensions-demo"])],
    }
    for name, r in rules.items():
        c.role("apps", name, r)
        c.binding("apps", f"bind-{name}", "Role", name, [W.subject("User", f"demo-{name}")])
    g = report.analyze().graph
    targets = {name: {e["target"].rsplit("/", 1)[-1] for e in
                      W.edges(g, "CAN_RUN_AS_SA", source=c.id("Role", "apps", name))} for name in rules}
    assert targets == {"pod-creator": {"svc-a", "svc-b"},
                       "token-minter": {"svc-a"}, "impersonator": {"svc-a", "svc-b"},
                       "deploy-patcher": {"svc-a", "svc-b"}, "reader": set(), "wrong-group": set()}
    e = W.edge(g, "CAN_RUN_AS_SA", c.id("Role", "apps", "pod-creator"), c.id("ServiceAccount", "apps", "svc-a"))
    assert e["traversable"] is True and e["evidence"]["via"] == ["create pods"]


@pytest.mark.finding("F-007", "F-035")
def test_a_rolebinding_to_a_cluster_role_is_namespaced(report):
    c = report.cluster()
    irsa = report.iam.role("demo-system-irsa", c.irsa_trust("kube-system", "controller"),
                           attached=["AdministratorAccess"])
    c.sa("kube-system", "controller", role_arn=irsa)
    c.sa("apps", "api")
    c.pod("apps", "api", sa="api")
    c.role(None, "cluster-admin", ADMIN_RULES)
    c.binding("apps", "api-admin", "ClusterRole", "cluster-admin", [W.subject("ServiceAccount", "api", "apps")])
    g = report.analyze().graph
    instance = c.id("Role", "apps", "ClusterRole:cluster-admin")
    assert W.edge(g, "BOUND_TO", c.id("ServiceAccount", "apps", "api"), instance) is not None
    assert W.edges(g, "BOUND_TO", target=c.id("ClusterRole", None, "cluster-admin")) == []
    assert {e["target"] for e in W.edges(g, "CAN_RUN_AS_SA", source=instance)} == {
        c.id("ServiceAccount", "apps", "api")}
    assert W.path(g, c.id("Pod", "apps", "api"), irsa) is None     # admin of apps is not admin of kube-system
    [f] = W.findings(g, "K8S-RBAC-001")
    assert f["severity"] == "HIGH" and f["evidence"]["scope"] == "apps"
    assert W.nodes_by_id(g)[instance]["props"]["role_kind"] == "BoundClusterRole"


@pytest.mark.finding("F-035")
def test_a_cluster_wide_admin_binding_reaches_every_service_account(report):
    c = report.cluster()
    irsa = report.iam.role("demo-system-irsa", c.irsa_trust("kube-system", "controller"),
                           attached=["AdministratorAccess"])
    c.sa("kube-system", "controller", role_arn=irsa)
    c.sa("ci", "deployer")
    c.pod("ci", "runner", sa="deployer")
    c.role(None, "cluster-admin", ADMIN_RULES)
    c.binding(None, "ci-admin", "ClusterRole", "cluster-admin", [W.subject("ServiceAccount", "deployer", "ci")])
    g = report.analyze().graph
    p = W.path(g, c.id("Pod", "ci", "runner"), irsa)
    assert p is not None and tuple(p.edge_types) == ("RUNS_AS", "BOUND_TO", "CAN_RUN_AS_SA", "IRSA_BRIDGE")
    [f] = W.findings(g, "K8S-RBAC-001")
    assert f["severity"] == "CRITICAL" and f["node_id"] == c.id("ServiceAccount", "ci", "deployer")


@pytest.mark.finding("F-086")
def test_built_in_roles_are_not_wildcard_findings(report):
    c = report.cluster()
    c.role(None, "cluster-admin", ADMIN_RULES)
    c.role(None, "system:controller:demo", ADMIN_RULES)
    c.role(None, "eks:addon-manager", ADMIN_RULES)
    c.role(None, "demo-defaults", ADMIN_RULES, labels={"kubernetes.io/bootstrapping": "rbac-defaults"})
    c.role(None, "demo-wildcard", ADMIN_RULES)
    c.role("apps", "demo-ns-wildcard", [W.rule(["*"], ["*"])])
    g = report.analyze().graph
    flagged = {f["node_id"] for f in W.findings(g, "K8S-RBAC-002")}
    assert flagged == {c.id("ClusterRole", None, "demo-wildcard"), c.id("Role", "apps", "demo-ns-wildcard")}


@pytest.mark.finding("F-035")
@pytest.mark.parametrize("rule, verb, group, resource, name, expected", [
    ({"verbs": ["*"], "api_groups": ["*"], "resources": ["*"]}, "create", "", "pods", "", True),
    ({"verbs": ["create"], "api_groups": [""], "resources": ["pods/exec"]}, "create", "", "pods", "", False),
    ({"verbs": ["create"], "api_groups": [""], "resources": ["*/token"]}, "create", "", "serviceaccounts/token", "",
     True),
    ({"verbs": ["create"], "api_groups": [""], "resources": ["serviceaccounts/token"], "resource_names": ["a"]},
     "create", "", "serviceaccounts/token", "b", False),
    ({"verbs": ["create"], "api_groups": ["apps"], "resources": ["deployments"]}, "create", "", "deployments", "",
     False),
])
def test_rule_matching_is_kubernetes_rbac(rule, verb, group, resource, name, expected):
    assert _rbac().rule_allows(rule, verb, group, resource, name) is expected
