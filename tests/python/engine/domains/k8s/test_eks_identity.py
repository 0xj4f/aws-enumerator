"""IAM → Kubernetes identity mapping (``analyzers/k8s/eks_identity.py``, F-050, F-033): EKS access entries with their
access policies, and the ``aws-auth`` ConfigMap (data only), matched the way the AWS IAM authenticator matches."""

from __future__ import annotations

import importlib
import json

import pytest

W = importlib.import_module("tests.fixtures.e-k8s.k8s_world")


def _yaml(value):
    return json.dumps(value)            # JSON is YAML: the collector's parser reads it


def _irsa_admin(rep, c, ns="apps", sa="api-sa"):
    role = rep.iam.role("demo-irsa-admin", c.irsa_trust(ns, sa), attached=["AdministratorAccess"])
    c.sa(ns, sa, role_arn=role)
    c.sa("default", "default")
    return role


@pytest.mark.finding("F-050", "F-033")
def test_access_entries_map_principals_to_groups_and_access_policies(v2report):
    rep = v2report
    c = rep.cluster()
    irsa = _irsa_admin(rep, c)
    admin = rep.iam.role("demo-platform-admin", W.rb.trust({"Service": "ec2.amazonaws.com"}))
    dev = rep.iam.role("demo-developer", W.rb.trust({"Service": "ec2.amazonaws.com"}))
    viewer = rep.iam.user("demo-viewer")
    c.access_entry(admin, groups=["demo-platform"], policies=[(W.ADMIN_POLICY, None)])
    c.access_entry(dev, policies=[(W.EDIT_POLICY, ["apps"])])
    c.access_entry(viewer, policies=[(W.VIEW_POLICY, None)])
    g = rep.analyze().graph
    assert W.problems(g) == [] and W.status(g) == "ok"

    cluster_admin = c.id("ClusterRole", None, "AccessPolicy:AmazonEKSClusterAdminPolicy")
    edit_apps = c.id("Role", "apps", "AccessPolicy:AmazonEKSEditPolicy")
    view = c.id("ClusterRole", None, "AccessPolicy:AmazonEKSViewPolicy")
    e = W.edge(g, "EKS_ACCESS_ENTRY", admin, cluster_admin)
    assert e["traversable"] is True and e["evidence"]["access_scope"] == "cluster"
    assert W.edge(g, "EKS_ACCESS_ENTRY", admin, c.id("Group", None, "demo-platform")) is not None
    assert W.edge(g, "EKS_ACCESS_ENTRY", dev, edit_apps) is not None
    assert W.edge(g, "EKS_ACCESS_ENTRY", viewer, view) is not None
    nodes = W.nodes_by_id(g)
    assert nodes[cluster_admin]["props"]["rules_source"] == "eks-access-policy"

    # the cluster-wide admin policy runs as every service account, the namespaced edit policy only in "apps"
    admin_targets = {x["target"] for x in W.edges(g, "CAN_RUN_AS_SA", source=cluster_admin)}
    assert c.id("ServiceAccount", "default", "default") in admin_targets
    edit_targets = {x["target"] for x in W.edges(g, "CAN_RUN_AS_SA", source=edit_apps)}
    assert edit_targets == {c.id("ServiceAccount", "apps", "api-sa")}
    assert W.edges(g, "CAN_RUN_AS_SA", source=view) == []

    # IAM principal -> cluster admin -> service account -> IRSA admin role: the F-050 lateral path
    p = W.path(g, admin, irsa)
    assert p is not None and tuple(p.edge_types) == ("EKS_ACCESS_ENTRY", "CAN_RUN_AS_SA", "IRSA_BRIDGE"), p
    assert W.path(g, viewer, irsa) is None
    [f] = W.findings(g, "EKS-ADMIN-001")
    assert f["node_id"] == c.arn and f["severity"] == "INFO" and f["evidence"]["principal"] == admin


@pytest.mark.finding("F-050")
def test_aws_auth_matches_roles_without_their_path_and_users_exactly(v2report):
    rep = v2report
    c = rep.cluster()
    node = rep.iam.role("demo-eks-nodes", W.rb.trust({"Service": "ec2.amazonaws.com"}), path="/eks/")
    masters = rep.iam.role("demo-break-glass", W.rb.trust({"Service": "ec2.amazonaws.com"}))
    rep.iam.role("demo-team-admin", W.rb.trust({"Service": "ec2.amazonaws.com"}), path="/team/")
    alice = rep.iam.user("demo-alice")
    c.binding("apps", "alice-edit", "ClusterRole", "edit", [W.subject("User", "alice")])
    c.aws_auth = {
        "mapRoles": _yaml([
            {"rolearn": W.iam_arn("role", "demo-eks-nodes"), "username": "system:node:{{EC2PrivateDNSName}}",
             "groups": ["system:bootstrappers", "system:nodes"]},
            {"rolearn": masters, "username": "break-glass", "groups": ["system:masters"]},
            {"rolearn": W.iam_arn("role", "demo-team-admin", path_="/team/"), "username": "team",
             "groups": ["system:masters"]},
        ]),
        "mapUsers": _yaml([{"userarn": alice, "username": "alice", "groups": ["demo-readers"]}]),
        "mapAccounts": _yaml([W.FOREIGN, W.ACCT]),
        "other": "not read",
    }
    g = rep.analyze().graph
    assert W.problems(g) == []
    # the role path is dropped by the authenticator: the path-less entry maps the /eks/ role
    e = W.edge(g, "AWS_AUTH_MAPPING", node, c.id("Group", None, "system:nodes"))
    assert e is not None and "role-name-in-account" in e["evidence"]["match"]
    # an entry written with a path never matches at run time
    team = W.iam_arn("role", "demo-team-admin", path_="/team/")
    assert W.edges(g, "AWS_AUTH_MAPPING", source=team) == []
    assert W.nodes_by_id(g)[c.arn]["props"]["aws_auth_ineffective_mappings"] == 1
    # system:masters is cluster-admin whatever the bindings say
    sm = c.id("Group", None, "system:masters")
    assert W.edge(g, "AWS_AUTH_MAPPING", masters, sm) is not None
    assert W.edge(g, "BOUND_TO", sm, c.id("ClusterRole", None, "cluster-admin")) is not None
    assert [f["evidence"]["principal"] for f in W.findings(g, "EKS-ADMIN-001")] == [masters]
    # a mapped user reaches the RBAC user a binding names
    assert W.edge(g, "AWS_AUTH_MAPPING", alice, c.id("User", None, "alice")) is not None
    sev = {f["evidence"]["account"]: f["severity"] for f in W.findings(g, "EKS-AUTH-MAP-001")}
    assert sev == {W.FOREIGN: "MEDIUM", W.ACCT: "LOW"}


@pytest.mark.finding("F-050")
@pytest.mark.parametrize("mode, entry_edge, map_edge", [
    ("API", True, False), ("CONFIG_MAP", False, True), ("API_AND_CONFIG_MAP", True, True), (None, True, True)])
def test_the_authentication_mode_decides_which_mappings_count(v2report, mode, entry_edge, map_edge):
    rep = v2report
    c = rep.cluster(mode=mode)
    via_entry = rep.iam.role("demo-entry", W.rb.trust({"Service": "ec2.amazonaws.com"}))
    via_map = rep.iam.role("demo-mapped", W.rb.trust({"Service": "ec2.amazonaws.com"}))
    c.access_entry(via_entry, groups=["system:masters"])
    c.aws_auth = {"mapRoles": _yaml([{"rolearn": via_map, "username": "m", "groups": ["system:masters"]}])}
    g = rep.analyze().graph
    sm = c.id("Group", None, "system:masters")
    assert (W.edge(g, "EKS_ACCESS_ENTRY", via_entry, sm) is not None) is entry_edge
    assert (W.edge(g, "AWS_AUTH_MAPPING", via_map, sm) is not None) is map_edge


@pytest.mark.finding("F-050", "F-035")
def test_mapped_principals_are_in_system_authenticated(v2report):
    rep = v2report
    c = rep.cluster()
    _irsa_admin(rep, c)
    mapped = rep.iam.role("demo-mapped", W.rb.trust({"Service": "ec2.amazonaws.com"}))
    c.access_entry(mapped)                                              # no group, no policy
    c.binding(None, "everyone-admin", "ClusterRole", "cluster-admin", [W.subject("Group", "system:authenticated")])
    g = rep.analyze().graph
    group = c.id("Group", None, "system:authenticated")
    e = W.edge(g, "EKS_ACCESS_ENTRY", mapped, group)
    assert e is not None and e["evidence"]["implicit"] is True
    [rbac3] = W.findings(g, "K8S-RBAC-003")
    assert rbac3["node_id"] == group and rbac3["severity"] == "CRITICAL"
    # every service account is authenticated too
    sa = c.id("ServiceAccount", "apps", "api-sa")
    assert W.edge(g, "MEMBER_OF_K8S_GROUP", sa, group) is not None
    assert W.path(g, mapped, W.iam_arn("role", "demo-irsa-admin")) is not None
