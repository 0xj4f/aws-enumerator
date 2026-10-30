"""IAM loader (legacy and GAAD layouts) and the IAM part of the graph (iam/__init__.py)."""

from __future__ import annotations

import pytest

EC2_TRUST = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
ADMIN = "aws-enumerator:account-admin/123456789012"


def _populate(h, iam):
    iam.managed("demo-shared", [h.rb.allow("s3:ListAllMyBuckets", "*")], customer=True, version="v2")
    iam.policy_version("demo-shared", "v1", [h.rb.allow("*", "*")])
    iam.policy_version("demo-shared", "v2", [h.rb.allow("s3:ListAllMyBuckets", "*")], default=True)
    iam.group("demo-devs", inline={"g": [h.rb.allow("ec2:DescribeInstances", "*")]}, attached=["ReadOnlyAccess"])
    iam.user("demo-dev", groups=["demo-devs"], attached=["demo-shared"], access_keys=1)
    iam.user("demo-quiet")
    iam.role("demo-app-role", EC2_TRUST, inline={"p": [h.rb.allow("s3:GetObject", "*")]})
    iam.role("demo-admin-role", EC2_TRUST, attached=["AdministratorAccess"])
    iam.oidc_provider("token.actions.githubusercontent.com")


@pytest.mark.finding("F-109", "F-110")
def test_gaad_and_legacy_layouts_load_the_same_model_and_gaad_keeps_every_version(h, tmp_path):
    loader = h.engine("io.loaders.iam")
    legacy, gaad = h.Tree(tmp_path / "a"), h.Tree(tmp_path / "b")
    for t in (legacy, gaad):
        _populate(h, t.iam)
    legacy.write("legacy")
    gaad.write("gaad")
    a, b = loader.load_iam(legacy.path), loader.load_iam(gaad.path)
    assert (a.layout, b.layout) == ("legacy", "gaad")
    for kind in ("user", "role", "group"):
        ea, eb = {e.arn: e for e in a.entities(kind)}, {e.arn: e for e in b.entities(kind)}
        assert ea.keys() == eb.keys()
        for arn in ea:
            assert ea[arn].attached == eb[arn].attached and ea[arn].inline == eb[arn].inline, arn
            assert ea[arn].groups == eb[arn].groups
    shared = f"arn:aws:iam::{h.ACCT}:policy/demo-shared"
    assert a.policies[shared].document == b.policies[shared].document
    assert sorted(b.policies[shared].versions) == ["v1", "v2"] and b.policies[shared].default_version == "v2"
    assert sorted(a.policies[shared].versions) == ["v2"]                   # legacy: default version only
    assert "iam:legacy-layout" in a.gaps and "iam:legacy-layout" not in b.gaps
    assert [p["Arn"] for p in b.identity_providers["oidc"]] == [
        f"arn:aws:iam::{h.ACCT}:oidc-provider/token.actions.githubusercontent.com"]


@pytest.mark.finding("F-110")
def test_gaad_identity_providers_become_idp_nodes(h, tree):
    _populate(h, tree.iam)
    tree.write("gaad")
    g = tree.analyze().graph
    idp = h.nodes_by_id(g)[f"arn:aws:iam::{h.ACCT}:oidc-provider/token.actions.githubusercontent.com"]
    assert idp["type"] == "idp" and idp["props"]["provider"] == "github"
    assert "iam:legacy-layout" not in {x["code"] for x in g["evaluation_gaps"]}
    assert h.graph_problems(g) == []


@pytest.mark.finding("F-013")
def test_policies_are_keyed_by_arn_and_a_name_collision_is_reported(h, tree):
    customer = tree.iam.managed("ReadOnlyAccess", [h.rb.allow("*", "*")], customer=True, version="v1")
    aws = tree.iam.managed("ReadOnlyAccess", h.rb.AWS_MANAGED_DOCS["ReadOnlyAccess"], version="v118")
    tree.iam.role("demo-backdoor", EC2_TRUST, attached=[customer])
    tree.iam.role("demo-auditor", EC2_TRUST, attached=[aws])
    tree.write()
    out = tree.analyze()
    g = out.graph
    backdoor, auditor = h.iam_arn("role", "demo-backdoor"), h.iam_arn("role", "demo-auditor")
    assert h.edges(g, "HAS_POLICY", backdoor, customer["PolicyArn"])
    assert h.edges(g, "HAS_POLICY", auditor, aws["PolicyArn"])
    assert h.edges(g, "IS_ADMIN_EQUIVALENT", backdoor, ADMIN)
    assert not h.edges(g, "IS_ADMIN_EQUIVALENT", auditor, ADMIN)
    [coll] = h.findings(g, "IAM-POLICY-COLLISION-001")
    assert coll["node_id"] == customer["PolicyArn"] and coll["severity"] == "INFO"
    pmap = h.load(out.dir / "permission_map.json")
    assert pmap["roles"]["demo-backdoor"]["attached_policies"] == ["ReadOnlyAccess"]
    assert pmap["roles"]["demo-backdoor"]["attached_policy_arns"] == [customer["PolicyArn"]]


@pytest.mark.finding("F-006")
def test_error_attachment_maps_become_attached_policies_status(h, tree):
    tree.iam.role("demo-denied", EC2_TRUST)
    tree.iam.role("demo-readable", EC2_TRUST, attached=["ReadOnlyAccess"])
    tree.iam.user("demo-user")
    tree.iam.override("role_attached_policies.json", {
        "demo-denied": {"Error": "An error occurred (AccessDenied) when calling ListAttachedRolePolicies"},
        "demo-readable": [{"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}]})
    tree.iam.override("user_attached_policies.json", {"Error": "An error occurred (Throttling) when calling X"})
    tree.write()
    g = tree.analyze().graph
    nodes = h.nodes_by_id(g)
    denied = nodes[h.iam_arn("role", "demo-denied")]
    assert denied["props"]["attached_policies_status"] == "denied"
    assert denied["props"]["attached_policies_error"] == "AccessDenied"
    assert denied["coverage"]["status"] == "partial" and "iam:attached-policies:denied" in denied["coverage"]["gaps"]
    assert nodes[h.iam_arn("role", "demo-readable")]["props"]["attached_policies_status"] == "complete"
    user = nodes[h.iam_arn("user", "demo-user")]
    assert user["props"]["attached_policies_status"] == "throttled"
    assert all("attached_policies_status" in n["props"] for n in g["nodes"] if n["type"] in ("user", "role", "group"))


@pytest.mark.finding("F-053", "F-111")
def test_unreadable_inline_policies_are_a_gap_never_an_empty_list(h, tree):
    tree.iam.role("demo-role", EC2_TRUST, inline={"ok": [h.rb.allow("s3:GetObject", "*")]})
    tree.iam.user("demo-user")
    tree.write()
    stub = tree.path / "iam" / "inline_policies" / "users" / "demo-user.json"
    stub.parent.mkdir(parents=True, exist_ok=True)
    stub.write_text('{"Error": "An error occurred (AccessDenied) when calling ListUserPolicies"}')
    g = tree.analyze().graph
    user = h.nodes_by_id(g)[h.iam_arn("user", "demo-user")]
    assert user["coverage"]["status"] == "partial" and "iam:inline-unknown" in user["coverage"]["gaps"]
    role = h.nodes_by_id(g)[h.iam_arn("role", "demo-role")]
    assert "iam:inline-unknown" not in role["coverage"]["gaps"]


@pytest.mark.finding("F-007")
def test_iam_structure_edges_point_from_the_principal_and_policies_are_not_walked(h, tree):
    _populate(h, tree.iam)
    tree.write()
    g = tree.analyze().graph
    dev, devs = h.iam_arn("user", "demo-dev"), h.iam_arn("group", "demo-devs")
    [member] = h.edges(g, "MEMBER_OF", dev, devs)
    assert member["traversable"] is True and member["weight"] == 0
    assert not h.edges(g, "MEMBER_OF", devs, dev)
    assert all(not e["traversable"] for e in h.edges(g, "HAS_POLICY"))
    traverse = h.engine("graph.traverse")
    assert traverse.shortest_path(g, dev, h.iam_arn("user", "demo-quiet")) is None
    admin_role = h.iam_arn("role", "demo-admin-role")
    assert h.nodes_by_id(g)[admin_role]["props"]["high_value_reason"] == "admin-equivalent"
    assert admin_role in g["meta"]["default_targets"]


def test_users_with_credentials_are_entry_points(h, tree):
    _populate(h, tree.iam)
    tree.write()
    g = tree.analyze().graph
    nodes = h.nodes_by_id(g)
    assert nodes[h.iam_arn("user", "demo-dev")]["props"]["entry_point"] is True
    assert "entry_point" not in nodes[h.iam_arn("user", "demo-quiet")]["props"]
    assert h.iam_arn("user", "demo-dev") in g["meta"]["default_sources"]


def test_admin_equivalence_is_decided_by_arn_never_by_name(h, tree):
    real = tree.iam.managed("AdministratorAccess", h.rb.AWS_MANAGED_DOCS["AdministratorAccess"], version="v1")
    fake = tree.iam.managed("AdministratorAccess", [h.rb.allow("s3:ListAllMyBuckets", "*")], customer=True,
                            version="v7")
    tree.iam.role("demo-fake-admin", EC2_TRUST, attached=[fake])
    tree.iam.role("demo-real-admin", EC2_TRUST, attached=[real])
    tree.write()
    g = tree.analyze().graph
    assert not h.edges(g, "IS_ADMIN_EQUIVALENT", h.iam_arn("role", "demo-fake-admin"))
    assert h.edges(g, "IS_ADMIN_EQUIVALENT", h.iam_arn("role", "demo-real-admin"), ADMIN)


def test_iam_loader_reads_error_stub_lists_as_gaps(h, tmp_path):
    loader = h.engine("io.loaders.iam")
    t = h.Tree(tmp_path)
    t.iam.role("demo-role", EC2_TRUST)
    t.iam.override("users.json", {"Error": "An error occurred (AccessDenied) when calling ListUsers"})
    t.write()
    data = loader.load_iam(t.path)
    assert data.users == {} and any(k.startswith("iam:users-") for k in data.gaps)
    assert list(data.roles) == [h.iam_arn("role", "demo-role")]


@pytest.mark.finding("F-036", "F-002")
def test_a_failing_evaluator_degrades_to_statement_level_decisions(h, tree, monkeypatch):
    """When the evaluator raises, root-delegated CAN_ASSUME and admin equivalence come from the parsed statements
    (``policy.apply.allow_sources`` / ``allows_everything``: no raw statement walking outside engine/policy, R-13),
    conditional when a Deny or boundary is not modelled, and the gap ``evaluator-error`` says so."""
    evaluator = h.engine("policy.evaluator").Evaluator

    def broken(*_args, **_kwargs):
        raise RuntimeError("demo evaluator failure")

    monkeypatch.setattr(evaluator, "can_assume", broken)
    monkeypatch.setattr(evaluator, "evaluate_capability", broken)
    target = h.iam_arn("role", "demo-target")
    tree.iam.role("demo-target", h.rb.trust({"AWS": f"arn:aws:iam::{h.ACCT}:root"}))
    tree.iam.group("demo-ops", inline={"g": [h.rb.allow("sts:AssumeRole", target)]})
    tree.iam.user("demo-via-group", groups=["demo-ops"])
    tree.iam.user("demo-denied", inline={"a": [h.rb.allow("sts:*", "*")], "d": [h.rb.deny("iam:*")]})
    tree.iam.user("demo-star", inline={"p": [h.rb.allow("*", "*")]})
    tree.write()
    g = tree.analyze().graph
    assert h.graph_problems(g) == []
    [via_group] = h.edges(g, "CAN_ASSUME", h.iam_arn("user", "demo-via-group"), target)
    assert via_group["evidence"]["basis"] == "identity-statement" and via_group["evidence"]["identity_sources"]
    [denied] = h.edges(g, "CAN_ASSUME", h.iam_arn("user", "demo-denied"), target)
    assert denied["confidence"] == "conditional" and "deny-statement" in denied["evidence"]["gaps"]
    [admin] = h.edges(g, "IS_ADMIN_EQUIVALENT", h.iam_arn("user", "demo-star"), ADMIN)
    assert admin["evidence"]["basis"] == "allow-star-statement"
    assert "evaluator-error" in {x["code"] for x in g["evaluation_gaps"]}
