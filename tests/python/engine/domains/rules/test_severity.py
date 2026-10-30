"""The severity policy through the pipeline (engine.md §3.3; F-068).

d13c215 rated Put*Policy CRITICAL but Attach*Policy HIGH, AddUserToGroup a fixed MEDIUM, and PassRole rules by
service (Lambda/EC2/CFN CRITICAL, ECS/Glue/CodeBuild/SageMaker HIGH). Now the class and the target decide.
"""

from __future__ import annotations

import importlib

import pytest

from aws_enumerator.engine.model import Strength
from aws_enumerator.engine.rules import severity as sev

W = importlib.import_module("tests.fixtures.e-rules.worlds")
allow = W.allow

SELF_MODIFY = [
    ("role", "iam:PutRolePolicy", "PRIVESC-005"),
    ("role", "iam:AttachRolePolicy", "PRIVESC-008"),
    ("user", "iam:PutUserPolicy", "PRIVESC-003"),
    ("user", "iam:AttachUserPolicy", "PRIVESC-006"),
]


@pytest.mark.finding("F-068")
@pytest.mark.parametrize("kind,action,rule_id", SELF_MODIFY)
def test_put_and_attach_on_self_are_both_critical(tmp_path, kind, action, rule_id):
    w = W.World(tmp_path)
    me = W.arn(kind, "demo-self")
    if kind == "role":
        w.role("demo-self", allow(action, me))
    else:
        w.user("demo-self", allow(action, me))
    out = w.analyze()
    f = out.finding(rule_id, me)
    assert f["severity"] == "CRITICAL" and f["base_severity"] == "CRITICAL"
    assert out.edges("CAN_ESCALATE", source=me, target=W.ADMIN_NODE)


@pytest.mark.finding("F-068")
@pytest.mark.parametrize("action,rule_id", [("iam:PutRolePolicy", "PRIVESC-005"),
                                            ("iam:AttachRolePolicy", "PRIVESC-008")])
def test_modifying_a_role_one_cannot_use_is_high_for_put_and_attach_alike(tmp_path, action, rule_id):
    w = W.World(tmp_path)
    other = w.role("demo-other", allow("s3:ListBucket"))
    me = w.user("demo-me", allow(action, other))
    out = w.analyze()
    assert out.finding(rule_id, me)["severity"] == "HIGH"


@pytest.mark.finding("F-068")
def test_add_user_to_group_follows_the_group(tmp_path):
    w = W.World(tmp_path)
    w.group("demo-admins", attached=[W.ADMIN_POLICY])
    w.group("demo-readers", allow("s3:GetObject"))
    to_admins = w.user("demo-a", allow("iam:AddUserToGroup", W.arn("group", "demo-admins")))
    to_readers = w.user("demo-b", allow("iam:AddUserToGroup", W.arn("group", "demo-readers")))
    out = w.analyze()
    assert out.finding("PRIVESC-012", to_admins)["severity"] == "CRITICAL"
    assert out.finding("PRIVESC-012", to_readers)["severity"] == "MEDIUM"
    assert out.path_types(to_admins) == ["CAN_TAKEOVER", "IS_ADMIN_EQUIVALENT"]


PASSROLE = [
    ("PRIVESC-014", "lambda.amazonaws.com", ["lambda:CreateFunction", "lambda:InvokeFunction"]),
    ("PRIVESC-015", "ec2.amazonaws.com", ["ec2:RunInstances"]),
    ("PRIVESC-016", "cloudformation.amazonaws.com", ["cloudformation:CreateStack"]),
    ("PRIVESC-017", "ecs-tasks.amazonaws.com", ["ecs:RunTask"]),
    ("PRIVESC-018", "glue.amazonaws.com", ["glue:CreateDevEndpoint"]),
    ("PRIVESC-019", "codebuild.amazonaws.com", ["codebuild:CreateProject", "codebuild:StartBuild"]),
    ("PRIVESC-020", "sagemaker.amazonaws.com",
     ["sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl"]),
]


@pytest.mark.finding("F-068", "F-012")
@pytest.mark.parametrize("rule_id,service,actions", PASSROLE)
def test_passrole_severity_comes_from_the_target_not_the_service(tmp_path, rule_id, service, actions):
    w = W.World(tmp_path)
    w.admin_role("demo-svc-admin", W.trusts_service(service))
    w.role("demo-svc-low", allow("logs:CreateLogStream"), trust=W.trusts_service(service))
    if service == "ec2.amazonaws.com":                           # EC2 receives roles as instance profiles
        w.iam.instance_profile("demo-admin-profile", ["demo-svc-admin"])
        w.iam.instance_profile("demo-low-profile", ["demo-svc-low"])
    to_admin = w.user("demo-wide", allow(["iam:PassRole"] + actions))
    to_low = w.user("demo-narrow", allow("iam:PassRole", W.arn("role", "demo-svc-low")), allow(actions))
    out = w.analyze()
    assert out.finding(rule_id, to_admin)["severity"] == "CRITICAL"
    assert out.finding(rule_id, to_low)["severity"] == "MEDIUM"


@pytest.mark.finding("F-068", "F-015")
def test_conditional_decisions_are_lowered_by_strength(tmp_path):
    w = W.World(tmp_path)
    w.admin_role("demo-fn-admin", W.trusts_service("lambda.amazonaws.com"))
    mfa = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    dev = w.user("demo-dev", allow(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "*", mfa))
    out = w.analyze()
    f = out.finding("PRIVESC-014", dev)
    assert (f["base_severity"], f["severity"], f["confidence"]) == ("CRITICAL", "HIGH", "conditional")


@pytest.mark.finding("F-068")
@pytest.mark.parametrize("tier,reach,expected", [
    ("medium", "definite", "admin"), ("medium", "conditional", "high"), ("medium", None, None)])
def test_closure_tier_table(tier, reach, expected):
    assert sev.closure_tier(reach) == expected


@pytest.mark.finding("F-068")
def test_target_tier_severities():
    assert sev.TARGET_TIER_SEVERITY == {"admin": "CRITICAL", "self": "CRITICAL", "high": "HIGH", "probe": "HIGH",
                                        "medium": "MEDIUM", "uncollected": "MEDIUM"}
    assert sev.adjust("MEDIUM", Strength.WEAK, conditional=True) == "LOW"
