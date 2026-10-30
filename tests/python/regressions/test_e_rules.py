"""Regression tests owned by stream E-rules (rule catalogue and runner, subsumption, severity, closure).

xfail-first (see test_e_policy.py). The dangerous-permission (DANGER-*) detection moves to
``rules/runner.py`` (E-policy in Wave 1, E-rules from Wave 2, engine-api.md §7); these tests pin the
rule outcomes that F-001 hides today.
"""

from __future__ import annotations

import importlib
import json

import pytest

from tests.fixtures.regressions import support as S

ACCT, R = S.ACCT, S.REGION

#: Capabilities the PowerUserAccess shape grants (engine.md §5, F-001 regression test).
POWERUSER_DANGER = {"DANGER-003", "DANGER-004", "DANGER-007", "DANGER-008", "DANGER-009", "DANGER-010"}


@pytest.fixture
def poweruser(tmp_path):
    S.build_scenario("poweruser_notaction", tmp_path)
    return S.analyze_tree(tmp_path / ACCT / R)


def _ids_for(findings, subject):
    return {i for f in S.findings_for(findings, subject=subject) for i in S.finding_ids(f)}


@pytest.mark.finding("F-001")
def test_f001_poweruser_notaction_fires_the_capabilities_it_grants(poweruser):
    role = S.iam_arn("role", "demo-poweruser")
    ids = _ids_for(poweruser.findings(), role)
    assert POWERUSER_DANGER <= ids, f"missing {sorted(POWERUSER_DANGER - ids)}; got {sorted(ids)}"
    # NotAction iam:* excludes IAM: no full-IAM-control or unrestricted-PassRole finding.
    assert not ({"DANGER-001", "DANGER-002", "DANGER-006", "ADMIN-001"} & ids), sorted(ids)


@pytest.mark.finding("F-001")
def test_f001_poweruser_group_member_gets_the_findings(poweruser):
    user = S.iam_arn("user", "demo-notaction-user")
    group = S.iam_arn("group", "demo-power-group")
    ids = _ids_for(poweruser.findings(), user) | _ids_for(poweruser.findings(), group)
    for f in poweruser.findings():  # group findings may list the member in affected_members
        if user in (f.get("affected_members") or []):
            ids |= S.finding_ids(f)
    assert POWERUSER_DANGER <= ids, f"missing {sorted(POWERUSER_DANGER - ids)}"


@pytest.mark.finding("F-001")
def test_f001_action_star_notresource_is_flagged_as_full_iam_control(poweruser):
    role = S.iam_arn("role", "demo-star-notresource")
    ids = _ids_for(poweruser.findings(), role)
    assert {"ADMIN-001", "DANGER-001", "DANGER-002"} & ids, sorted(ids)


# ── Wave 2 (E-rules): the review's repros, now fixed ─────────────────────────
W = importlib.import_module("tests.fixtures.e-rules.worlds")
PR = "iam:PassRole"


def _ec2_admin_instance(w):
    w.admin_role("demo-ec2-admin", W.trusts_service("ec2.amazonaws.com"))
    profile = w.iam.instance_profile("demo-profile", ["demo-ec2-admin"])
    w.write("ec2/instances.json", [W.rb.ec2_instance("i-0a1b2c3d4e5f60001", account=W.ACCT, region=W.REGION,
                                                     profile=profile)])


def _fn_admin(w):
    admin = w.admin_role("demo-fn-admin", W.trusts_service("lambda.amazonaws.com"))
    w.write("lambda/functions.json", [W.lambda_function("demo-fn", admin)])


#: F-011 evidence: each technique alone gave privesc [] in d13c215 (synthetic run of the review).
F011_TECHNIQUES = {
    "lambda:UpdateFunctionCode": (["lambda:UpdateFunctionCode"], _fn_admin, "PRIVESC-021"),
    "ssm:SendCommand": (["ssm:SendCommand"], _ec2_admin_instance, "PRIVESC-050"),
    "PassRole+ec2:RequestSpotInstances": ([PR, "ec2:RequestSpotInstances"], _ec2_admin_instance, "PRIVESC-026"),
    "PassRole+ec2:AssociateIamInstanceProfile": ([PR, "ec2:AssociateIamInstanceProfile", "ssm:SendCommand"],
                                                 _ec2_admin_instance, "PRIVESC-064"),
    "PassRole+autoscaling LC/ASG": ([PR, "autoscaling:CreateLaunchConfiguration",
                                     "autoscaling:CreateAutoScalingGroup"], _ec2_admin_instance, "PRIVESC-065"),
    "PassRole+sagemaker:CreateTrainingJob": (
        [PR, "sagemaker:CreateTrainingJob"],
        lambda w: w.admin_role("demo-sm-admin", W.trusts_service("sagemaker.amazonaws.com")), "PRIVESC-040"),
    "PassRole+states": ([PR, "states:CreateStateMachine", "states:StartExecution"],
                        lambda w: w.admin_role("demo-sfn-admin", W.trusts_service("states.amazonaws.com")),
                        "PRIVESC-043"),
    "PassRole+ssm automation": ([PR, "ssm:CreateDocument", "ssm:StartAutomationExecution"],
                                lambda w: w.admin_role("demo-ssm-admin", W.trusts_service("ssm.amazonaws.com")),
                                "PRIVESC-042"),
}


@pytest.mark.finding("F-011")
@pytest.mark.parametrize("technique", sorted(F011_TECHNIQUES))
def test_f011_missing_techniques_now_fire(tmp_path, technique):
    actions, setup, rule_id = F011_TECHNIQUES[technique]
    w = W.World(tmp_path)
    setup(w)
    p = w.user("demo-attacker", W.allow(actions))
    out = w.analyze()
    assert out.finding(rule_id, p)["severity"] == "CRITICAL"
    assert out.path(p) is not None, out.ids_at(p)


@pytest.mark.finding("F-012")
def test_f012_passrole_without_a_service_trusting_role_is_info(tmp_path):
    w = W.World(tmp_path)
    w.admin_role("demo-admin", W.trusts_account())
    p = w.user("demo-x", W.allow([PR, "ec2:RunInstances"]))
    out = w.analyze()
    f = out.finding("PRIVESC-015", p)
    assert (f["severity"], f["evidence"].get("no_candidate")) == ("INFO", True)
    assert out.path(p) is None


@pytest.mark.finding("F-016")
def test_f016_privesc_is_a_traversable_hop(tmp_path):
    w = W.World(tmp_path)
    admin = w.admin_role("demo-fn-admin", W.trusts_service("lambda.amazonaws.com"))
    p = w.user("demo-x", W.allow([PR, "lambda:CreateFunction", "lambda:InvokeFunction"]))
    out = w.analyze()
    p_path = out.path(p)
    assert p_path is not None and p_path.nodes[1] == admin and p_path.edge_types[0] == "CAN_PASS_ROLE_TO"


@pytest.mark.finding("F-017")
def test_f017_scoped_passrole_and_self_service_are_not_critical(tmp_path):
    w = W.World(tmp_path)
    low = w.role("example-readonly-instance-role", W.allow("s3:ListBucket"),
                 trust=W.trusts_service("ec2.amazonaws.com"))
    w.admin_role("demo-ec2-admin", W.trusts_service("ec2.amazonaws.com"))
    w.iam.instance_profile("example-readonly-profile", ["example-readonly-instance-role"])
    w.iam.instance_profile("demo-admin-profile", ["demo-ec2-admin"])
    scoped = w.user("demo-scoped", W.allow(PR, low), W.allow("ec2:RunInstances"))
    selfsvc = w.user("demo-self", W.allow(["iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile"],
                                          f"arn:aws:iam::{W.ACCT}:user/${{aws:username}}"))
    out = w.analyze()
    assert out.finding("PRIVESC-015", scoped)["severity"] == "MEDIUM"
    assert not [i for i in out.ids_at(selfsvc) if i.startswith("PRIVESC")]


@pytest.mark.finding("F-018")
def test_f018_action_star_principal_has_one_finding_not_thirty(tmp_path):
    w = W.World(tmp_path)
    star = w.role("demo-star", W.allow("*", "*"))
    w.group("demo-admins", W.allow("*", "*"))
    u1, u2 = (w.user(f"demo-u{i}", groups=["demo-admins"]) for i in (1, 2))
    out = w.analyze()
    assert out.ids_at(star) == ["ADMIN-001"]
    rule_rows = [f for f in out.graph["findings"] if f["id"].startswith(("PRIVESC-", "DANGER-", "ADMIN-"))]
    assert len(rule_rows) == 2                         # d13c215: 30 + 70
    group_f = out.finding("ADMIN-001", W.arn("group", "demo-admins"))
    assert group_f["affected_members"] == sorted([u1, u2])


@pytest.mark.finding("F-068")
def test_f068_attach_policy_is_as_severe_as_put_policy_and_groups_follow_the_group(tmp_path):
    w = W.World(tmp_path)
    attach = w.role("demo-attach", W.allow("iam:AttachRolePolicy", W.arn("role", "demo-attach")))
    put = w.role("demo-put", W.allow("iam:PutRolePolicy", W.arn("role", "demo-put")))
    w.group("demo-admins", attached=[W.ADMIN_POLICY])
    joiner = w.user("demo-join", W.allow("iam:AddUserToGroup", W.arn("group", "demo-admins")))
    out = w.analyze()
    assert out.finding("PRIVESC-008", attach)["severity"] == out.finding("PRIVESC-005", put)["severity"] == "CRITICAL"
    assert out.finding("PRIVESC-012", joiner)["severity"] == "CRITICAL"


@pytest.mark.finding("F-069")
def test_f069_register_task_definition_alone_is_not_a_chain(tmp_path):
    w = W.World(tmp_path)
    w.admin_role("demo-task-admin", W.trusts_service("ecs-tasks.amazonaws.com"))
    only_register = w.user("demo-a", W.allow([PR, "ecs:RegisterTaskDefinition"]))
    create_service = w.user("demo-b", W.allow([PR, "ecs:RegisterTaskDefinition", "ecs:CreateService"]))
    out = w.analyze()
    assert out.findings("PRIVESC-017", only_register) == []
    assert out.finding("PRIVESC-017", create_service)["severity"] == "CRITICAL"


@pytest.mark.finding("F-071")
def test_f071_provenance_names_the_any_alternative_and_the_wildcard_statement(tmp_path):
    w = W.World(tmp_path)
    w.admin_role("demo-fn-admin", W.trusts_service("lambda.amazonaws.com"))
    p = w.user("demo-x", W.allow(PR, W.arn("role", "limited"), sid="Narrow"), W.allow(PR, "*", sid="Wide"),
               W.allow("lambda:UpdateFunctionCode", sid="Q"),
               W.allow(["lambda:CreateFunction", "lambda:CreateEventSourceMapping"], sid="Fn"))
    out = w.analyze()
    f = out.finding("PRIVESC-014", p)
    assert "lambda:createeventsourcemapping" in f["matched_actions"]
    step = next(s for s in f["evidence"]["steps"] if s["rule_action"] == "iam:passrole")
    assert step["granted"][0]["sid"] == "Wide"


@pytest.mark.finding("F-141", "F-165")
def test_f141_f165_exports_exist_for_every_format(tmp_path):
    from aws_enumerator.engine import writers

    w = W.World(tmp_path)
    w.admin_role("demo-fn-admin", W.trusts_service("lambda.amazonaws.com"))
    w.user("demo-x", W.allow([PR, "lambda:CreateFunction", "lambda:InvokeFunction"]))
    graph = w.analyze().graph
    for fmt in ("sarif", "csv", "md", "asff", "opengraph"):
        assert writers.export(graph, fmt), fmt
    og = json.loads(writers.export(graph, "opengraph"))
    assert {n["id"] for n in og["graph"]["nodes"]} == {n["id"] for n in graph["nodes"]}
