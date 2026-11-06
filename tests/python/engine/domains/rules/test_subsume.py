"""Subsumption and group dedup (engine.md §3.4; F-018) through the whole pipeline (``analyze_report``)."""

from __future__ import annotations

import importlib

import pytest

W = importlib.import_module("tests.fixtures.e-rules.worlds")
allow, deny = W.allow, W.deny

LAMBDA_CHAIN = allow(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"])


@pytest.mark.finding("F-018")
def test_admin_role_gets_one_admin_finding_instead_of_thirty(tmp_path):
    """T10: one role with Allow * on * gave 20 PRIVESC + 10 DANGER rows in d13c215; now one ADMIN-001."""
    w = W.World(tmp_path)
    admin = w.role("demo-admin", allow("*", "*"))
    out = w.analyze()
    assert out.ids_at(admin) == ["ADMIN-001"]
    f = out.finding("ADMIN-001", admin)
    assert f["severity"] == "CRITICAL" and f["confidence"] == "definite"
    assert {"DANGER-001", "DANGER-002", "PRIVESC-005", "PRIVESC-008"} <= set(f["subsumes"])
    assert f["evidence"]["basis"] == "allow-star" and f["evidence"]["subsumed_count"] >= 10
    assert out.edges("IS_ADMIN_EQUIVALENT", source=admin, target=W.ADMIN_NODE)
    assert out.summary()["subsumed_count"] == len(set(f["subsumes"]))
    assert W.graph_problems(out.graph) == []


@pytest.mark.finding("F-018")
def test_no_passable_role_notes_of_an_admin_collapse_into_admin_001(tmp_path):
    """An admin holds every PassRole chain; with no service-trusting role d13c215-era output had one INFO
    "no passable role" note per PassRole rule. They are part of ADMIN-001 now."""
    w = W.World(tmp_path)
    admin = w.user("demo-admin-user", attached=[W.ADMIN_POLICY])
    out = w.analyze()
    assert out.ids_at(admin) == ["ADMIN-001"]
    subsumes = set(out.finding("ADMIN-001", admin)["subsumes"])
    assert {"PRIVESC-014", "PRIVESC-015", "PRIVESC-020"} <= subsumes   # the INFO notes are subsumed too
    assert not [f for f in out.graph["findings"] if f["severity"] == "INFO" and f["node_id"] == admin]


@pytest.mark.finding("F-018")
def test_admin_group_reports_once_with_its_members(tmp_path):
    """T11: an admin group with 2 members gave 70 findings; now one group ADMIN-001 with both members."""
    w = W.World(tmp_path)
    group = w.group("demo-admins", attached=[W.ADMIN_POLICY])
    u1 = w.user("demo-ops-1", groups=["demo-admins"])
    u2 = w.user("demo-ops-2", groups=["demo-admins"])
    out = w.analyze()
    (f,) = out.findings("ADMIN-001")
    assert f["node_id"] == group and f["affected_members"] == sorted([u1, u2])
    assert out.ids_at(u1) == [] and out.ids_at(u2) == []
    for member in (u1, u2):
        assert f["fingerprint"] in out.node(member)["inherited_findings"]
    assert out.edges("IS_ADMIN_EQUIVALENT", source=group)
    assert W.graph_problems(out.graph) == []


@pytest.mark.finding("F-018")
def test_member_with_its_own_grant_keeps_its_own_finding(tmp_path):
    """A member whose result differs from the group's (a member-only grant) keeps its own row."""
    w = W.World(tmp_path)
    group = w.group("demo-keys", allow("iam:CreateAccessKey", W.arn("user", "demo-svc")))
    same = w.user("demo-same", groups=["demo-keys"])
    own = w.user("demo-own", allow("iam:CreateAccessKey", "*"), groups=["demo-keys"])
    w.user("demo-svc", attached=[W.ADMIN_POLICY])
    out = w.analyze()
    gf = out.finding("PRIVESC-009", group)
    assert gf["affected_members"] == [same]
    assert out.findings("PRIVESC-009", same) == []
    own_f = out.finding("PRIVESC-009", own)
    assert "via_group" not in own_f


@pytest.mark.finding("F-018")
def test_member_boundary_changes_the_result_so_the_member_finding_differs(tmp_path):
    """A member whose boundary caps the group grant gets no copy of the group finding and is not listed."""
    w = W.World(tmp_path)
    w.iam.managed("demo-ro-boundary", W.policy(allow("s3:GetObject")), customer=True)
    boundary = {"PermissionsBoundaryType": "Policy",
                "PermissionsBoundaryArn": f"arn:aws:iam::{W.ACCT}:policy/demo-ro-boundary"}
    group = w.group("demo-devs", allow("iam:CreateAccessKey", "*"))
    plain = w.user("demo-dev-plain", groups=["demo-devs"])
    capped = w.user("demo-dev-capped", groups=["demo-devs"], boundary=boundary)
    w.user("demo-target", attached=[W.ADMIN_POLICY])
    out = w.analyze()
    gf = out.finding("PRIVESC-009", group)
    assert plain in gf["affected_members"] and capped not in gf["affected_members"]
    assert out.findings("PRIVESC-009", capped) == []


@pytest.mark.finding("F-018")
def test_full_iam_control_plus_self_escalation_is_admin_equivalent(tmp_path):
    """iam:* on the account (DANGER-002) with a definite self-escalation is ADMIN-001 (basis iam-self-escalation)."""
    w = W.World(tmp_path)
    iam_admin = w.role("demo-iam-admin", allow("iam:*", "*"))
    out = w.analyze()
    f = out.finding("ADMIN-001", iam_admin)
    assert f["evidence"]["basis"] == "iam-self-escalation"
    assert "DANGER-002" in f["subsumes"] and out.ids_at(iam_admin) == ["ADMIN-001"]
    assert out.edges("IS_ADMIN_EQUIVALENT", source=iam_admin)


@pytest.mark.finding("F-018")
def test_conditional_full_iam_control_subsumes_the_iam_rows(tmp_path):
    """Not admin (MFA-conditioned iam:*): DANGER-002 stays and absorbs PRIVESC-001..013 of the same strength."""
    w = W.World(tmp_path)
    mfa = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    p = w.user("demo-iam-mfa", allow("iam:*", "*", mfa))
    out = w.analyze()
    ids = out.ids_at(p)
    assert "ADMIN-001" not in ids and "DANGER-002" in ids
    assert not [i for i in ids if i.startswith("PRIVESC-0") and int(i[-3:]) <= 13]
    d2 = out.finding("DANGER-002", p)
    assert {"PRIVESC-003", "PRIVESC-006", "PRIVESC-009"} <= set(d2["subsumes"])


@pytest.mark.finding("F-018", "F-012")
def test_no_candidate_notes_of_one_principal_collapse_into_one(tmp_path):
    """A non-admin with several complete PassRole chains and no passable role gets one INFO note, not one per rule."""
    w = W.World(tmp_path)
    p = w.user("demo-deployer", allow(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction",
                                       "ec2:RunInstances", "cloudformation:CreateStack"], "*"))
    out = w.analyze()
    notes = [f for f in out.findings(node=p) if f["evidence"].get("no_candidate")]
    assert len(notes) == 1
    (note,) = notes
    assert note["severity"] == "INFO" and note["id"] == "PRIVESC-014"
    assert {"PRIVESC-015", "PRIVESC-016"} <= set(note["subsumes"])
    assert {"lambda.amazonaws.com", "ec2.amazonaws.com", "cloudformation.amazonaws.com"} <= set(
        note["evidence"]["services"])


@pytest.mark.finding("F-018")
def test_non_admin_findings_keep_their_detail(tmp_path):
    """Subsumption touches admins only: a single-path principal keeps its PRIVESC finding."""
    w = W.World(tmp_path)
    w.admin_role("demo-fn-admin", W.trusts_service("lambda.amazonaws.com"))
    dev = w.user("demo-dev", LAMBDA_CHAIN)
    out = w.analyze()
    f = out.finding("PRIVESC-014", dev)
    assert f["severity"] == "CRITICAL" and "subsumes" not in f
