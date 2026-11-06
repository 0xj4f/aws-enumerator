"""IRSA and EKS Pod Identity bridges (``analyzers/k8s/irsa.py``): verified against the role's trust policy.

F-034: the annotation alone is never a path; the role's OIDC trust must admit the service account (provider of
*this* cluster, ``sub`` and ``aud``), and a wildcard ``sub`` reaches every matching service account.
F-085: the annotated role is looked up by its exact ARN. F-050: Pod Identity associations. F-014 (K8s part):
an explicit Deny in the trust policy is honoured.
"""

from __future__ import annotations

import importlib

import pytest

W = importlib.import_module("tests.fixtures.e-k8s.k8s_world")


def _ev(edge):
    return edge["evidence"]


@pytest.mark.finding("F-034")
def test_annotation_is_a_path_only_when_the_trust_admits_the_service_account(report):
    c = report.cluster()
    ok = report.iam.role("demo-irsa-ok", c.irsa_trust("payments", "api-sa"), attached=["AdministratorAccess"])
    other = report.iam.role("demo-irsa-other", c.irsa_trust("other", "other-sa"), attached=["AdministratorAccess"])
    ec2 = report.iam.role("demo-irsa-ec2", W.rb.trust({"Service": "ec2.amazonaws.com"}),
                          attached=["AdministratorAccess"])
    for sa, role in (("api-sa", ok), ("stale-sa", other), ("ec2-sa", ec2)):
        c.sa("payments", sa, role_arn=role)
        c.pod("payments", f"{sa}-pod", sa=sa)
    g = report.analyze().graph
    assert W.problems(g) == [] and W.status(g) == "ok"

    good = W.edge(g, "IRSA_BRIDGE", c.id("ServiceAccount", "payments", "api-sa"), ok)
    assert good["traversable"] is True and _ev(good)["trust_verified"] is True
    assert _ev(good)["traversable_rule"] == {"rule": "trust-verified", "holds": True}
    for sa, role in (("stale-sa", other), ("ec2-sa", ec2)):
        e = W.edge(g, "IRSA_BRIDGE", c.id("ServiceAccount", "payments", sa), role)
        assert e is not None and e["traversable"] is False, e            # kept for context, never a step
        assert _ev(e)["trust_verified"] is False
        assert W.path(g, c.id("Pod", "payments", f"{sa}-pod"), role) is None
    assert W.path(g, c.id("Pod", "payments", "api-sa-pod"), ok) is not None

    admin = W.findings(g, "K8S-IRSA-ADMIN")
    assert [f["node_id"] for f in admin] == [c.id("ServiceAccount", "payments", "api-sa")]
    assert admin[0]["severity"] == "CRITICAL" and admin[0]["confidence"] == "definite"
    stale = {f["node_id"] for f in W.findings(g, "K8S-IRSA-002")}
    assert stale == {c.id("ServiceAccount", "payments", s) for s in ("stale-sa", "ec2-sa")}
    assert all(f["severity"] == "LOW" for f in W.findings(g, "K8S-IRSA-002"))


@pytest.mark.finding("F-034")
def test_wildcard_sub_gives_an_edge_from_every_matching_service_account(report):
    c = report.cluster()
    wild = report.iam.role("demo-irsa-wild", c.irsa_trust("*", "*", operator="StringLike"))
    web = report.iam.role("demo-irsa-web", c.irsa_trust("web", "*", operator="StringLike"))
    c.sa("default", "default")
    c.sa("web", "web-sa")
    c.sa("web", "batch-sa")
    c.pod("web", "web-0", sa="web-sa", volumes=[W.token_volume("sts.amazonaws.com")])
    g = report.analyze().graph
    assert W.problems(g) == []
    wild_sources = {e["source"] for e in W.edges(g, "IRSA_BRIDGE", target=wild)}
    assert wild_sources == {c.id("ServiceAccount", ns, n) for ns, n in
                            (("default", "default"), ("web", "web-sa"), ("web", "batch-sa"))}
    web_sources = {e["source"] for e in W.edges(g, "IRSA_BRIDGE", target=web)}
    assert web_sources == {c.id("ServiceAccount", "web", n) for n in ("web-sa", "batch-sa")}

    held = W.edge(g, "IRSA_BRIDGE", c.id("ServiceAccount", "web", "web-sa"), wild)
    minted = W.edge(g, "IRSA_BRIDGE", c.id("ServiceAccount", "web", "batch-sa"), wild)
    assert held["confidence"] == "definite" and _ev(held)["token"] == "projected"
    # no pod holds an sts token for batch-sa: an extra step (TokenRequest / a new pod) is needed
    assert minted["traversable"] is True and minted["confidence"] == "conditional"
    assert _ev(minted)["token"] == "token-request-needed" and minted["weight"] > held["weight"]
    assert W.findings(g, "K8S-IRSA-ADMIN") == []                   # neither role is admin


@pytest.mark.finding("F-034")
def test_audience_and_issuer_of_another_cluster_are_not_admitted(report):
    a = report.cluster("demo-eks")
    b = report.cluster("demo-eks-b")
    aud = report.iam.role("demo-irsa-aud", a.irsa_trust("apps", "custom-aud"))
    foreign_issuer = report.iam.role("demo-irsa-b", b.irsa_trust("apps", "moved"))   # trusts cluster b only
    a.sa("apps", "custom-aud", role_arn=aud, audience="example-audience")
    a.sa("apps", "moved", role_arn=foreign_issuer)
    b.sa("apps", "moved", role_arn=foreign_issuer)
    g = report.analyze().graph
    assert W.edge(g, "IRSA_BRIDGE", a.id("ServiceAccount", "apps", "custom-aud"), aud)["traversable"] is False
    assert W.edge(g, "IRSA_BRIDGE", a.id("ServiceAccount", "apps", "moved"), foreign_issuer)["traversable"] is False
    assert W.edge(g, "IRSA_BRIDGE", b.id("ServiceAccount", "apps", "moved"), foreign_issuer)["traversable"] is True


@pytest.mark.finding("F-034", "F-014")
def test_an_explicit_deny_in_the_trust_policy_is_honoured(report):
    c = report.cluster()
    trust = c.irsa_trust("apps", "*", operator="StringLike")
    trust["Statement"].append({"Effect": "Deny", "Principal": {"Federated": c.provider_arn},
                               "Action": "sts:AssumeRoleWithWebIdentity",
                               "Condition": {"StringEquals": {f"{c.issuer_host}:sub":
                                                              "system:serviceaccount:apps:untrusted"}}})
    role = report.iam.role("demo-irsa-deny", trust, attached=["AdministratorAccess"])
    c.sa("apps", "trusted", role_arn=role)
    c.sa("apps", "untrusted", role_arn=role)
    g = report.analyze().graph
    assert W.edge(g, "IRSA_BRIDGE", c.id("ServiceAccount", "apps", "trusted"), role)["traversable"] is True
    denied = W.edge(g, "IRSA_BRIDGE", c.id("ServiceAccount", "apps", "untrusted"), role)
    assert denied["traversable"] is False and "deny" in _ev(denied)["trust_reason"]
    assert {f["node_id"] for f in W.findings(g, "K8S-IRSA-ADMIN")} == {c.id("ServiceAccount", "apps", "trusted")}


@pytest.mark.finding("F-085")
def test_a_same_named_role_in_another_account_is_never_the_local_admin(report):
    c = report.cluster()
    local = report.iam.role("demo-app-admin", c.irsa_trust("apps", "local-sa"), attached=["AdministratorAccess"])
    foreign = W.iam_arn("role", "demo-app-admin", W.FOREIGN)
    c.sa("apps", "ext", role_arn=foreign)
    g = report.analyze().graph
    sa = c.id("ServiceAccount", "apps", "ext")
    assert W.edges(g, "IRSA_BRIDGE", source=sa, target=local) == []
    assert W.findings(g, "K8S-IRSA-ADMIN") == []
    [unknown] = W.findings(g, "K8S-IRSA-003", sa)
    assert unknown["severity"] == "INFO" and unknown["evidence"]["role_arn"] == foreign
    assert foreign not in W.nodes_by_id(g)                      # no orphan node for the other account's role
    assert W.nodes_by_id(g)[sa]["props"]["irsa_role_arn"] == foreign


@pytest.mark.finding("F-085")
def test_role_with_a_path_is_matched_by_its_exact_arn(report):
    c = report.cluster()
    pathed = report.iam.role("demo-path-role", c.irsa_trust("apps", "svc"), path="/team/",
                             attached=["AdministratorAccess"])
    report.iam.role("demo-other-path-role", c.irsa_trust("apps", "svc"), path="/other/")
    c.sa("apps", "svc", role_arn=pathed)
    g = report.analyze().graph
    assert pathed == W.iam_arn("role", "demo-path-role", path_="/team/")
    e = W.edge(g, "IRSA_BRIDGE", c.id("ServiceAccount", "apps", "svc"), pathed)
    assert e["traversable"] is True and _ev(e)["source"] == "annotation"
    [admin] = W.findings(g, "K8S-IRSA-ADMIN")
    assert admin["evidence"]["role_arn"] == pathed


@pytest.mark.finding("F-034")
def test_a_role_that_was_not_collected_is_unknown_not_admitted(report):
    c = report.cluster()
    missing = W.iam_arn("role", "demo-not-collected")
    c.sa("apps", "svc", role_arn=missing)
    g = report.analyze().graph
    e = W.edge(g, "IRSA_BRIDGE", c.id("ServiceAccount", "apps", "svc"), missing)
    assert e["traversable"] is False and _ev(e)["trust_verified"] == "unknown"
    assert W.nodes_by_id(g)[missing]["props"].get("placeholder") is True
    assert [f["severity"] for f in W.findings(g, "K8S-IRSA-003")] == ["INFO"]


@pytest.mark.finding("F-050")
def test_pod_identity_associations_are_verified_against_the_role(v2report):
    c = v2report.cluster()
    pods_trust = W.rb.trust({"Service": "pods.eks.amazonaws.com"}, ["sts:AssumeRole", "sts:TagSession"])
    good = v2report.iam.role("demo-podid", pods_trust, attached=["AdministratorAccess"])
    no_tag = v2report.iam.role("demo-podid-notag", W.rb.trust({"Service": "pods.eks.amazonaws.com"}))
    scoped = v2report.iam.role("demo-podid-scoped", W.rb.trust(
        {"Service": "pods.eks.amazonaws.com"}, ["sts:AssumeRole", "sts:TagSession"],
        {"ArnEquals": {"aws:SourceArn": "arn:aws:eks:eu-west-2:123456789012:cluster/demo-other"}}))
    for sa, role in (("good", good), ("notag", no_tag), ("scoped", scoped)):
        c.sa("apps", sa)
        c.pod_identity_association("apps", sa, role)
    c.pod_identity_association("apps", "missing-role", None)
    g = v2report.analyze().graph
    assert W.problems(g) == [] and W.status(g) == "ok"
    e = W.edge(g, "POD_IDENTITY", c.id("ServiceAccount", "apps", "good"), good)
    assert e["traversable"] is True and _ev(e)["mechanism"] == "pod-identity" and _ev(e)["association"]
    for sa, role in (("notag", no_tag), ("scoped", scoped)):
        assert W.edge(g, "POD_IDENTITY", c.id("ServiceAccount", "apps", sa), role)["traversable"] is False
    assert {f["node_id"] for f in W.findings(g, "K8S-IRSA-ADMIN")} == {c.id("ServiceAccount", "apps", "good")}
    assert {f["node_id"] for f in W.findings(g, "K8S-IRSA-002")} == {
        c.id("ServiceAccount", "apps", s) for s in ("notag", "scoped")}


@pytest.mark.finding("F-034", "F-002")
def test_a_failing_evaluator_makes_the_trust_unknown_not_a_crash(report, monkeypatch):
    from tests.support import targets

    def boom(self, *args, **kwargs):
        raise RuntimeError("synthetic evaluator failure")

    monkeypatch.setattr(targets.engine_module("policy.evaluator").Evaluator, "can_assume", boom)
    c = report.cluster()
    role = report.iam.role("demo-irsa", c.irsa_trust("apps", "svc"), attached=["AdministratorAccess"])
    c.sa("apps", "svc", role_arn=role)
    g = report.analyze().graph
    assert W.status(g) == "ok" and W.problems(g) == []
    e = W.edge(g, "IRSA_BRIDGE", c.id("ServiceAccount", "apps", "svc"), role)
    assert e["traversable"] is False and _ev(e)["trust_verified"] == "unknown"
    assert W.findings(g, "K8S-IRSA-ADMIN") == [] and len(W.findings(g, "K8S-IRSA-003")) == 1
    assert "evaluator-error" in {x["code"] for x in g["evaluation_gaps"]}


@pytest.mark.finding("F-014", "F-034")
def test_an_admin_policy_cancelled_by_an_explicit_deny_is_not_an_admin_role(report):
    c = report.cluster()
    capped = report.iam.role("demo-irsa-capped", c.irsa_trust("apps", "svc"), attached=["AdministratorAccess"],
                             inline={"deny-all": [W.rb.deny("*", "*")]})
    c.sa("apps", "svc", role_arn=capped)
    g = report.analyze().graph
    assert W.edge(g, "IRSA_BRIDGE", c.id("ServiceAccount", "apps", "svc"), capped)["traversable"] is True
    assert W.findings(g, "K8S-IRSA-ADMIN") == []          # d13c215 matched AdministratorAccess and ignored the Deny
