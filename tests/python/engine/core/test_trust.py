"""Trust analysis and assume edges (iam/trust.py, iam/assume.py; engine.md §4.2-§4.3)."""

from __future__ import annotations

import pytest

ANON = "aws-enumerator:anonymous"
GITHUB = "token.actions.githubusercontent.com"
EKS = "oidc.eks.eu-west-2.amazonaws.com/id/0123456789ABCDEF0123456789ABCDEF"


def _trust(principal, action="sts:AssumeRole", cond=None, single=False):
    stmt = {"Effect": "Allow", "Principal": principal, "Action": action}
    if cond:
        stmt["Condition"] = cond
    return {"Version": "2012-10-17", "Statement": stmt if single else [stmt]}


def _web(provider_arn, cond=None):
    return _trust({"Federated": provider_arn}, "sts:AssumeRoleWithWebIdentity", cond)


def _role(h, name):
    return h.iam_arn("role", name)


def _severity(graph, fid, node):
    return sorted(f["severity"] for f in graph["findings"] if f["id"] == fid and f["node_id"] == node)


@pytest.fixture
def trust_graph(h, tree):
    """One role per trust shape."""
    gh = f"arn:aws:iam::{h.ACCT}:oidc-provider/{GITHUB}"
    eks = f"arn:aws:iam::{h.ACCT}:oidc-provider/{EKS}"
    saml = f"arn:aws:iam::{h.ACCT}:saml-provider/demo-idp"
    i = tree.iam
    ops = i.user("demo-ops", access_keys=1)
    i.user("demo-caller", inline={"p": [h.rb.allow("sts:AssumeRole", _role(h, "demo-root-trusting"))]},
           access_keys=1)
    i.user("demo-bystander", inline={"p": [h.rb.allow("s3:ListAllMyBuckets", "*")]}, access_keys=1)
    i.role("demo-explicit", _trust({"AWS": ops}))
    i.role("demo-root-trusting", _trust({"AWS": f"arn:aws:iam::{h.ACCT}:root"}))
    i.role("demo-open", _trust({"AWS": "*"}))
    i.role("demo-open-weak", _trust({"AWS": "*"}, cond={"StringEquals": {"aws:PrincipalTag/team": "x"}}))
    i.role("demo-open-org", _trust({"AWS": "*"}, cond={"StringEquals": {"aws:PrincipalOrgID": "o-abcdef1234"}}))
    i.role("demo-xacct-bare", _trust({"AWS": h.FOREIGN}))
    i.role("demo-xacct-role", _trust({"AWS": f"arn:aws:iam::{h.FOREIGN}:role/demo-vendor"}))
    i.role("demo-xacct-extid", _trust({"AWS": h.FOREIGN}, cond={"StringEquals": {"sts:ExternalId": "demo-x"}}))
    i.role("demo-xacct-org", _trust({"AWS": h.FOREIGN}, cond={"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}))
    i.role("demo-xacct-denied", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": h.FOREIGN}, "Action": "sts:AssumeRole"},
        {"Effect": "Deny", "Principal": {"AWS": h.FOREIGN}, "Action": "sts:AssumeRole"}]})
    i.role("demo-gh-any", _web(gh, {"StringEquals": {f"{GITHUB}:aud": "sts.amazonaws.com"}}))
    i.role("demo-gh-org", _web(gh, {"StringLike": {f"{GITHUB}:sub": "repo:demo-org/*"}}))
    i.role("demo-gh-exact", _web(gh, {"StringEquals": {f"{GITHUB}:sub": "repo:demo-org/app:ref:refs/heads/main",
                                                       f"{GITHUB}:aud": "sts.amazonaws.com"}}))
    i.role("demo-eks-wild", _web(eks, {"StringLike": {f"{EKS}:sub": "system:serviceaccount:*:*"}}))
    i.role("demo-cognito", _trust({"Federated": "cognito-identity.amazonaws.com"},
                                  "sts:AssumeRoleWithWebIdentity"))
    i.role("demo-saml", _trust({"Federated": saml}, "sts:AssumeRoleWithSAML"))
    i.role("demo-svc", _trust({"Service": "lambda.amazonaws.com"}))
    i.role("demo-stale", _trust({"AWS": "AROAEXAMPLEDELETED001"}))
    i.oidc_provider(GITHUB)
    tree.write()
    out = tree.analyze()
    assert h.graph_problems(out.graph) == []
    return out


@pytest.mark.finding("F-036")
def test_explicit_and_root_delegated_principals_get_can_assume(h, trust_graph):
    g = trust_graph.graph
    ops, caller = h.iam_arn("user", "demo-ops"), h.iam_arn("user", "demo-caller")
    assert h.edges(g, "CAN_ASSUME", ops, _role(h, "demo-explicit"))
    # same-account :root trust delegates to identity policies: only the caller allowed to AssumeRole gets an edge
    root_edges = h.edges(g, "CAN_ASSUME", target=_role(h, "demo-root-trusting"))
    assert [e["source"] for e in root_edges] == [caller]
    assert not h.edges(g, "CAN_ASSUME", h.iam_arn("user", "demo-bystander"))


@pytest.mark.finding("F-036", "F-072")
def test_cross_account_trusts_are_edges_from_external_nodes(h, trust_graph):
    g = trust_graph.graph
    nodes = h.nodes_by_id(g)
    ext_root = f"arn:aws:iam::{h.FOREIGN}:root"
    assert nodes[ext_root]["type"] == "external_account" and nodes[ext_root]["props"]["external"] is True
    [edge] = h.edges(g, "CAN_ASSUME", ext_root, _role(h, "demo-xacct-bare"))
    assert edge["confidence"] == "conditional" and edge["props"]["cross_account"] is True
    assert "external-identity-unknown" in edge["evidence"]["gaps"]
    vendor = f"arn:aws:iam::{h.FOREIGN}:role/demo-vendor"
    assert nodes[vendor]["type"] == "external_principal"
    assert h.edges(g, "CAN_ASSUME", vendor, _role(h, "demo-xacct-role"))
    # an explicit Deny of the same principal removes the trust (F-073)
    assert not h.edges(g, "CAN_ASSUME", target=_role(h, "demo-xacct-denied"))


@pytest.mark.finding("F-073", "F-072")
def test_trust002_is_graded_by_guard_with_the_real_actions(h, trust_graph):
    g = trust_graph.graph
    assert _severity(g, "TRUST-002", _role(h, "demo-xacct-bare")) == ["HIGH"]       # whole account, no guard
    assert _severity(g, "TRUST-002", _role(h, "demo-xacct-role")) == ["MEDIUM"]     # one principal, no guard
    assert _severity(g, "TRUST-002", _role(h, "demo-xacct-extid")) == ["LOW"]       # sts:ExternalId
    assert _severity(g, "TRUST-002", _role(h, "demo-xacct-org")) == ["INFO"]        # aws:PrincipalOrgID
    assert _severity(g, "TRUST-002", _role(h, "demo-xacct-denied")) == []           # explicit Deny
    [f] = [f for f in g["findings"] if f["id"] == "TRUST-002" and f["node_id"] == _role(h, "demo-xacct-extid")]
    assert f["matched_actions"] == ["sts:AssumeRole"] and f["evidence"]["guard"] == "external-id"
    assert "ExternalId" in f["remediation"] and "secret" in f["remediation"]
    fp = h.engine("graph.ids").finding_fingerprint("TRUST-002", h.ACCT, _role(h, "demo-xacct-bare"), h.FOREIGN)
    assert fp in {x["fingerprint"] for x in g["findings"]}


@pytest.mark.finding("F-021")
def test_wildcard_trust_is_graded_by_condition_strength(h, trust_graph):
    g = trust_graph.graph
    assert _severity(g, "TRUST-001", _role(h, "demo-open")) == ["CRITICAL"]
    assert _severity(g, "TRUST-001", _role(h, "demo-open-weak")) == ["HIGH"]
    assert _severity(g, "TRUST-001", _role(h, "demo-open-org")) == ["INFO"]
    [open_edge] = h.edges(g, "CAN_ASSUME", ANON, _role(h, "demo-open"))
    [weak] = h.edges(g, "CAN_ASSUME", ANON, _role(h, "demo-open-weak"))
    [strong] = h.edges(g, "CAN_ASSUME", ANON, _role(h, "demo-open-org"))
    assert open_edge["confidence"] == "definite" and open_edge["weight"] == 1
    assert weak["evidence"]["condition_strength"] == "weak" and weak["weight"] == 2
    assert strong["evidence"]["condition_strength"] == "strong" and strong["weight"] == 4


@pytest.mark.finding("F-020")
def test_federated_trusts_are_classified_with_edges(h, trust_graph):
    g = trust_graph.graph
    gh = f"arn:aws:iam::{h.ACCT}:oidc-provider/{GITHUB}"
    nodes = h.nodes_by_id(g)
    assert nodes[gh]["type"] == "idp" and nodes[gh]["props"]["provider"] == "github"
    assert _severity(g, "TRUST-OIDC-001", _role(h, "demo-gh-any")) == ["CRITICAL"]
    assert _severity(g, "TRUST-OIDC-001", _role(h, "demo-gh-org")) == ["MEDIUM"]
    assert _severity(g, "TRUST-OIDC-001", _role(h, "demo-gh-exact")) == ["INFO"]
    assert _severity(g, "TRUST-OIDC-001", _role(h, "demo-eks-wild")) == ["HIGH"]
    assert _severity(g, "TRUST-OIDC-001", _role(h, "demo-cognito")) == ["HIGH"]
    assert _severity(g, "TRUST-SAML-001", _role(h, "demo-saml")) == ["INFO"]
    [any_edge] = h.edges(g, "CAN_ASSUME_WEB_IDENTITY", gh, _role(h, "demo-gh-any"))
    assert any_edge["props"]["admits"] == "any" and any_edge["confidence"] == "definite"
    assert h.edges(g, "CAN_ASSUME_WEB_IDENTITY", gh, _role(h, "demo-gh-exact"))[0]["props"]["admits"] == "specific"
    # anyone can mint a GitHub OIDC token for any repository: an internet entry point
    assert h.edges(g, "CAN_ASSUME_WEB_IDENTITY", ANON, _role(h, "demo-gh-any"))
    assert not h.edges(g, "CAN_ASSUME_WEB_IDENTITY", ANON, _role(h, "demo-gh-exact"))
    assert h.edges(g, "CAN_ASSUME_WEB_IDENTITY", "aws-enumerator:idp/cognito-identity.amazonaws.com",
                   _role(h, "demo-cognito"))
    assert h.edges(g, "CAN_ASSUME_SAML", f"arn:aws:iam::{h.ACCT}:saml-provider/demo-idp", _role(h, "demo-saml"))


def test_service_and_stale_principals(h, trust_graph):
    g = trust_graph.graph
    assert h.edges(g, "SERVICE_CAN_ASSUME", "svc:lambda.amazonaws.com", _role(h, "demo-svc"))
    assert _severity(g, "IAM-STALE-PRINCIPAL-001", _role(h, "demo-stale")) == ["INFO"]
    assert not h.edges(g, target=_role(h, "demo-stale"))


@pytest.mark.finding("F-002", "F-020")
def test_trust_relationships_json_keeps_old_keys_and_adds_the_classification(h, trust_graph):
    rows = h.load(trust_graph.dir / "trust_relationships.json")
    by_role = {(r["role_name"], r["trusted_principal"]): r for r in rows}
    row = by_role[("demo-xacct-extid", h.FOREIGN)]
    for key in ("role_name", "role_arn", "trusted_principal", "principal_type", "conditions", "is_cross_account",
                "is_wildcard"):
        assert key in row
    assert row["is_cross_account"] is True and row["guard"] == "external-id"
    assert row["normalised_principal"] == f"arn:aws:iam::{h.FOREIGN}:root"
    assert by_role[("demo-gh-org", f"arn:aws:iam::{h.ACCT}:oidc-provider/{GITHUB}")]["admits"] == "pattern"


@pytest.mark.finding("F-002")
def test_single_object_trust_statement_is_one_statement(h, tree):
    tree.iam.role("demo-fn-role", _trust({"Service": "lambda.amazonaws.com"}, single=True))
    tree.write()
    out = tree.analyze()
    rows = h.load(out.dir / "trust_relationships.json")
    assert [(r["role_name"], r["trusted_principal"]) for r in rows] == [("demo-fn-role", "lambda.amazonaws.com")]
    assert h.edges(out.graph, "SERVICE_CAN_ASSUME", "svc:lambda.amazonaws.com", _role(h, "demo-fn-role"))


@pytest.mark.finding("F-036")
def test_bare_same_account_id_is_root_delegation_not_cross_account(h, tree):
    tree.iam.user("demo-caller", inline={"p": [h.rb.allow("sts:AssumeRole", "*")]}, access_keys=1)
    tree.iam.role("demo-target", _trust({"AWS": h.ACCT}))
    tree.write()
    g = tree.analyze().graph
    assert not h.findings(g, "TRUST-002")
    assert h.edges(g, "CAN_ASSUME", h.iam_arn("user", "demo-caller"), _role(h, "demo-target"))


def test_trust_model_unit_classification(h):
    trust = h.engine("iam.trust")
    assert trust.guard_of({"StringEquals": {"sts:ExternalId": "x"}}) == "external-id"
    assert trust.guard_of({"StringEquals": {"aws:PrincipalOrgID": "o-x"}}) == "org"
    assert trust.guard_of({"Bool": {"aws:MultiFactorAuthPresent": "true"}}) == "mfa"
    assert trust.guard_of(None) == "none"
    admits, problems = trust.federated_admits("github", GITHUB, None)
    assert admits == "any" and problems == [f"{GITHUB}:sub missing"]
    assert trust.federated_admits("github", GITHUB, {"StringLike": {f"{GITHUB}:sub": "repo:*"}})[0] == "any"
    assert trust.federated_admits("eks", EKS, {"StringEquals": {f"{EKS}:sub": "system:serviceaccount:ns:sa"}})[0] \
        == "specific"
    _, problems = trust.federated_admits("cognito", "cognito-identity.amazonaws.com", {"ForAnyValue:StringLike": {
        "cognito-identity.amazonaws.com:amr": "unauthenticated"}})
    assert any("aud missing" in p for p in problems) and any("unauthenticated" in p for p in problems)
