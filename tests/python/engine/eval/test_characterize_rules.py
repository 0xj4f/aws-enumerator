"""The rule engine's technique matrix through the permission-map entry points (``_detect_privesc_paths`` /
``_detect_dangerous_permissions``) and the native pipeline: correct-behaviour assertions, each tied to a finding.

Sources: internal-docs/repro/off_technique_matrix.py (44 single-technique roles), dev_golden_demo.py (6-case
``_action_matches`` table), def_remediation_loop.py (3 BEFORE/AFTER pairs) and po_microbench.py (10 labelled roles;
the d13c215 engine scored precision 0.50 / recall 0.80, the evaluator-backed rules score 1.0 / 1.0).

These rows started in Wave 0 as a characterisation of d13c215's output. Wave 3a turned every row into an assertion of
the intended behaviour (:data:`ROW_FINDINGS` names the finding each row proves; ledger:
tests/golden/CHANGES.d/{e-policy,e-rules}.md):

* a technique whose complete action chain is granted on ``*`` fires its rule with a probe target (F-017) or, for a
  PassRole chain, as the INFO "no passable role" note because no role trusts the service (F-012);
* an incomplete chain never fires (F-069), a resource-scoped grant is judged on its scope (F-017, F-019);
* an existing-resource technique (``lambda:UpdateFunctionCode`` alone, ``ssm:SendCommand`` alone, ...) claims nothing
  while no resource is collected ("nothing collected, nothing claimed"), and fires through the pipeline once the
  resource is collected (:func:`test_existing_resource_rows_fire_when_the_resource_is_collected`, F-011, F-113);
* the fidelity probes cover NotAction (F-001), explicit Deny (F-014), conditions (F-015), ``${aws:username}``
  self-scope (F-017) and ARN-wildcard / concrete-action DANGER rules (F-019).

The microbench (:func:`test_microbench_precision_and_recall`) runs ``engine.analyze_report`` on the committed
``microbench`` scenario tree (the d13c215 ``analyze()`` it used before is gone, DECISIONS.md D-53).
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from tests.support import report_builder as rb
from tests.support import targets
from tests.support.permmap import (action_matches, allow, danger_ids, deny, permission_map_for,
                                   privesc_findings, privesc_ids)

ACCT = "123456789012"
ALL_PRIVESC = [f"PRIVESC-{n:03d}" for n in range(1, 21)]
ALL_DANGER = [f"DANGER-{n:03d}" for n in range(1, 11)]
PR = "iam:PassRole"

# name: (statements, expected privesc ids, expected danger ids)
TECHNIQUES = {
    "CreatePolicyVersion": ([allow("iam:CreatePolicyVersion")], ["PRIVESC-001"], []),
    "SetDefaultPolicyVersion": ([allow("iam:SetDefaultPolicyVersion")], ["PRIVESC-002"], []),
    "PutRolePolicy (self)": ([allow("iam:PutRolePolicy")], ["PRIVESC-005"], []),
    "AttachRolePolicy": ([allow("iam:AttachRolePolicy")], ["PRIVESC-008"], []),
    "CreateAccessKey (other user)": ([allow("iam:CreateAccessKey")], ["PRIVESC-009"], []),
    "UpdateLoginProfile": ([allow("iam:UpdateLoginProfile")], ["PRIVESC-011"], []),
    "AddUserToGroup": ([allow("iam:AddUserToGroup")], ["PRIVESC-012"], []),
    "UpdateAssumeRolePolicy": ([allow("iam:UpdateAssumeRolePolicy")], ["PRIVESC-013"], []),
    "Put/DeleteRolePermissionsBoundary": (
        [allow(["iam:DeleteRolePermissionsBoundary", "iam:PutRolePermissionsBoundary"])], [], []),
    "sts:AssumeRole on *": ([allow("sts:AssumeRole")], [], ["DANGER-005"]),
    "sts:AssumeRole on one role ARN": (
        [allow("sts:AssumeRole", f"arn:aws:iam::{ACCT}:role/example-admin")], [], []),
    "PassRole+lambda:CreateFunction+Invoke": (
        [allow([PR, "lambda:CreateFunction", "lambda:InvokeFunction"])], ["PRIVESC-014"], ["DANGER-006"]),
    "lambda:UpdateFunctionCode alone": ([allow("lambda:UpdateFunctionCode")], [], []),
    "lambda:UpdateFunctionConfiguration alone": ([allow("lambda:UpdateFunctionConfiguration")], [], []),
    "PassRole+ec2:RunInstances": ([allow([PR, "ec2:RunInstances"])], ["PRIVESC-015"], ["DANGER-006"]),
    "PassRole+ec2:AssociateIamInstanceProfile": (
        [allow([PR, "ec2:AssociateIamInstanceProfile"])], [], ["DANGER-006"]),
    "ec2:CreateLaunchTemplateVersion+ModifyLaunchTemplate": (
        [allow(["ec2:CreateLaunchTemplateVersion", "ec2:ModifyLaunchTemplate"])], [], []),
    "PassRole+autoscaling LC/ASG": (
        [allow([PR, "autoscaling:CreateLaunchConfiguration", "autoscaling:CreateAutoScalingGroup"])],
        ["PRIVESC-065"], ["DANGER-006"]),
    "PassRole+ec2:RequestSpotInstances": ([allow([PR, "ec2:RequestSpotInstances"])], ["PRIVESC-026"], ["DANGER-006"]),
    "ssm:SendCommand alone": ([allow("ssm:SendCommand")], [], []),
    "ssm:StartSession alone": ([allow("ssm:StartSession")], [], []),
    "PassRole+cloudformation:CreateStack": (
        [allow([PR, "cloudformation:CreateStack"])], ["PRIVESC-016"], ["DANGER-006"]),
    "cloudformation:UpdateStack alone": ([allow("cloudformation:UpdateStack")], [], []),
    "PassRole+ecs:RunTask": (
        [allow([PR, "ecs:RunTask", "ecs:RegisterTaskDefinition"])], ["PRIVESC-017"], ["DANGER-006"]),
    "PassRole+ecs:RegisterTaskDefinition only": (
        [allow([PR, "ecs:RegisterTaskDefinition"])], [], ["DANGER-006"]),          # F-069: no run step
    "ecs:ExecuteCommand alone": ([allow("ecs:ExecuteCommand")], [], []),
    "PassRole+glue:CreateDevEndpoint": ([allow([PR, "glue:CreateDevEndpoint"])], ["PRIVESC-018"], ["DANGER-006"]),
    "glue:UpdateDevEndpoint alone": ([allow("glue:UpdateDevEndpoint")], [], []),
    "PassRole+codebuild:CreateProject+StartBuild": (
        [allow([PR, "codebuild:CreateProject", "codebuild:StartBuild"])], ["PRIVESC-019"], ["DANGER-006"]),
    "codebuild:StartBuild alone": ([allow("codebuild:StartBuild")], [], []),
    "PassRole+sagemaker:CreateNotebookInstance": (
        [allow([PR, "sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl"])],
        ["PRIVESC-020"], ["DANGER-006"]),
    "sagemaker:CreatePresignedNotebookInstanceUrl alone": (
        [allow("sagemaker:CreatePresignedNotebookInstanceUrl")], [], []),
    "PassRole+sagemaker:CreateTrainingJob": ([allow([PR, "sagemaker:CreateTrainingJob"])], ["PRIVESC-040"],
                                             ["DANGER-006"]),
    "PassRole+datapipeline": (
        [allow([PR, "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition",
                "datapipeline:ActivatePipeline"])], ["PRIVESC-031"], ["DANGER-006"]),
    "PassRole+ssm:StartAutomationExecution": (
        [allow([PR, "ssm:StartAutomationExecution"])], [], ["DANGER-006"]),
    "PassRole+states:CreateStateMachine+StartExecution": (
        [allow([PR, "states:CreateStateMachine", "states:StartExecution"])], ["PRIVESC-043"], ["DANGER-006"]),
    "PassRole+cognito SetIdentityPoolRoles": (
        [allow([PR, "cognito-identity:SetIdentityPoolRoles"])], ["PRIVESC-030"], ["DANGER-006"]),
    # fidelity probes
    "PowerUser shape (NotAction iam:*)": (                                   # F-001
        [{"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"], "Resource": "*"}], [],
        ["DANGER-003", "DANGER-004", "DANGER-005", "DANGER-007", "DANGER-008", "DANGER-009", "DANGER-010"]),
    "Admin + explicit Deny iam:*": (                                        # F-014: Deny honoured
        [allow("*"), deny("iam:*")], [],
        ["DANGER-003", "DANGER-004", "DANGER-005", "DANGER-007", "DANGER-008", "DANGER-009", "DANGER-010"]),
    "PassRole PassedToService=ec2 + lambda:CreateFunction": (               # F-015 (and F-069: no invoke)
        [allow(PR, "*", {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}),
         allow("lambda:CreateFunction")], [], ["DANGER-006"]),
    "PassRole on one low-priv role + ec2:RunInstances": (
        [allow(PR, f"arn:aws:iam::{ACCT}:role/example-lowpriv"), allow("ec2:RunInstances")], ["PRIVESC-015"], []),
    "Self-service keys (${aws:username})": (                                 # F-017: self-scoped
        [allow(["iam:CreateAccessKey", "iam:UpdateLoginProfile"], f"arn:aws:iam::{ACCT}:user/${{aws:username}}")],
        [], []),
    "GetSecretValue on secret ARN wildcard": (                               # F-019
        [allow("secretsmanager:GetSecretValue", "arn:aws:secretsmanager:*:*:secret:*")], [], ["DANGER-008"]),
    "ssm:GetParameters on *": ([allow(["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"])],
                               [], ["DANGER-009"]),                            # F-019
}


#: Every row -> the finding(s) whose fix the row proves (see the module docstring for the classes of rows).
ROW_FINDINGS = {
    # IAM principal-modification techniques granted on "*": fire against a probe target of the kind (F-017).
    "CreatePolicyVersion": ("F-017",),
    "SetDefaultPolicyVersion": ("F-017",),
    "PutRolePolicy (self)": ("F-017",),
    "AttachRolePolicy": ("F-017",),
    "CreateAccessKey (other user)": ("F-017",),
    "UpdateLoginProfile": ("F-017",),
    "AddUserToGroup": ("F-017",),
    "UpdateAssumeRolePolicy": ("F-017",),
    # PRIVESC-066/067 (catalogue import) need a boundary to remove: no boundary, no finding.
    "Put/DeleteRolePermissionsBoundary": ("F-011",),
    "sts:AssumeRole on *": ("F-019",),
    "sts:AssumeRole on one role ARN": ("F-017", "F-019"),
    # complete PassRole chains with no role that trusts the service: the INFO "no passable role" note (F-012).
    "PassRole+lambda:CreateFunction+Invoke": ("F-012", "F-069"),
    "PassRole+ec2:RunInstances": ("F-012",),
    "PassRole+cloudformation:CreateStack": ("F-012",),
    "PassRole+ecs:RunTask": ("F-012", "F-069"),
    "PassRole+glue:CreateDevEndpoint": ("F-012",),
    "PassRole+codebuild:CreateProject+StartBuild": ("F-012", "F-069"),
    "PassRole+sagemaker:CreateNotebookInstance": ("F-012", "F-069"),
    # incomplete chains (F-069): no run step / no instance command step / no CreateDocument.
    "PassRole+ecs:RegisterTaskDefinition only": ("F-069",),
    "PassRole+ec2:AssociateIamInstanceProfile": ("F-069",),
    "PassRole+ssm:StartAutomationExecution": ("F-069",),
    # existing-resource techniques with no collected resource (F-017; they fire when collected, see below).
    "lambda:UpdateFunctionCode alone": ("F-017",),
    "lambda:UpdateFunctionConfiguration alone": ("F-017",),
    "ec2:CreateLaunchTemplateVersion+ModifyLaunchTemplate": ("F-017",),
    "ssm:SendCommand alone": ("F-017",),
    "ssm:StartSession alone": ("F-017",),
    "cloudformation:UpdateStack alone": ("F-017",),
    "ecs:ExecuteCommand alone": ("F-017",),
    "glue:UpdateDevEndpoint alone": ("F-017",),
    "codebuild:StartBuild alone": ("F-017",),
    "sagemaker:CreatePresignedNotebookInstanceUrl alone": ("F-017",),
    # techniques imported from pathfinding.cloud or added for F-011 / F-113 (INFO notes here, F-012).
    "PassRole+autoscaling LC/ASG": ("F-011",),
    "PassRole+ec2:RequestSpotInstances": ("F-011",),
    "PassRole+sagemaker:CreateTrainingJob": ("F-011", "F-113"),
    "PassRole+datapipeline": ("F-011",),
    "PassRole+states:CreateStateMachine+StartExecution": ("F-011",),
    "PassRole+cognito SetIdentityPoolRoles": ("F-011",),
    # fidelity probes
    "PowerUser shape (NotAction iam:*)": ("F-001",),
    "Admin + explicit Deny iam:*": ("F-014",),
    "PassRole PassedToService=ec2 + lambda:CreateFunction": ("F-015", "F-069"),
    "PassRole on one low-priv role + ec2:RunInstances": ("F-012", "F-017"),
    "Self-service keys (${aws:username})": ("F-017",),
    "GetSecretValue on secret ARN wildcard": ("F-019",),
    "ssm:GetParameters on *": ("F-019",),
}


def _technique_params():
    for name in TECHNIQUES:
        yield pytest.param(name, marks=[pytest.mark.finding(*ROW_FINDINGS[name])], id=name)


def test_technique_table_has_44_rows_and_every_row_names_its_finding():
    assert len(TECHNIQUES) == 44
    assert sorted(ROW_FINDINGS) == sorted(TECHNIQUES)


@pytest.mark.parametrize("name", _technique_params())
def test_technique_matrix(name):
    statements, privesc, danger = TECHNIQUES[name]
    assert privesc_ids(statements, "role", name="example-role") == privesc
    assert danger_ids(statements, "role", name="example-role") == danger


@pytest.mark.finding("F-017")
def test_self_service_keys_as_the_user_itself_are_not_escalation():
    """The AWS self-service policy on a user (the principal it was written for) gives no takeover finding."""
    stmts = [allow(["iam:CreateAccessKey", "iam:UpdateLoginProfile"], f"arn:aws:iam::{ACCT}:user/${{aws:username}}")]
    assert privesc_ids(stmts, "user", name="example-user") == []
    assert privesc_ids([allow(["iam:CreateAccessKey", "iam:UpdateLoginProfile"])], "user",
                       name="example-user") == ["PRIVESC-009", "PRIVESC-011"]


@pytest.mark.finding("F-012")
def test_passrole_rows_without_a_passable_role_are_info():
    """With no role that trusts the service, a complete PassRole chain is reported as INFO only (F-012)."""
    pm = permission_map_for([allow([PR, "ec2:RunInstances"])], "role", name="example-role")
    (finding,) = privesc_findings(pm)
    assert (finding["id"], finding["severity"], finding.get("no_candidate")) == ("PRIVESC-015", "INFO", True)


# (pattern, action, expected) — dev_golden_demo.py: IAM action globs are case-insensitive, ``?`` matches one
# character, and a service prefix never matches a longer one (``ec2:*`` is not ``ec2messages:*``).
ACTION_MATCHES = [
    ("s3:*", "s3:GetObject", True),
    ("S3:get*", "s3:GetObject", True),
    ("*", "iam:PassRole", True),
    ("iam:Pass?ole", "iam:PassRole", True),
    ("s3:Get*", "s3:PutObject", False),
    ("ec2:*", "ec2messages:SendReply", False),
]


@pytest.mark.finding("F-142")
@pytest.mark.parametrize("pattern,action,expected", ACTION_MATCHES)
def test_action_matches(pattern, action, expected):
    assert action_matches(pattern, action) is expected


# def_remediation_loop.py: applying the tool's own remediation text does not clear the finding (F-017 shape)
A0 = rb.ACCT_ZERO
REMEDIATION_PAIRS = {
    "PRIVESC-015": ([allow([PR, "ec2:RunInstances"])],
                    [allow(PR, f"arn:aws:iam::{A0}:role/app-readonly"), allow("ec2:RunInstances")]),
    "PRIVESC-009": ([allow("iam:CreateAccessKey")],
                    [allow("iam:CreateAccessKey", f"arn:aws:iam::{A0}:user/${{aws:username}}")]),
    "PRIVESC-001": ([allow("iam:CreatePolicyVersion")],
                    [allow("iam:CreatePolicyVersion", f"arn:aws:iam::{A0}:policy/app-only")]),
}


@pytest.mark.finding("F-017", "F-012")
@pytest.mark.parametrize("finding_id", list(REMEDIATION_PAIRS))
def test_remediation_loop_clears(finding_id):
    """Applying the tool's own remediation text clears the finding (d13c215 kept reporting it, F-017).

    PRIVESC-015's scoped AFTER policy still has a complete chain over a role that does not exist, so it stays
    as an INFO "no passable role" note (F-012), never as an escalation finding.
    """
    before, after = REMEDIATION_PAIRS[finding_id]
    assert privesc_ids(before, "user", name="u", account=A0) == [finding_id]
    after_findings = privesc_findings(permission_map_for(after, "user", name="u", account=A0))
    assert [f for f in after_findings if f["severity"] != "INFO"] == []


@pytest.mark.finding("F-071")
def test_group_statements_reach_member_users_with_their_provenance():
    """Group statements propagate to member users (``via_group`` names the group); privesc is reported on the user."""
    pm = permission_map_for([allow("iam:CreatePolicyVersion")], "group", name="example")
    member = pm["users"]["example-member"]
    assert [s.get("via_group") for s in member["effective_statements"]] == ["example"]
    assert [(f["id"], f["entity"]) for f in privesc_findings(pm)] == [("PRIVESC-001", "user/example-member")]


# po_microbench.py: case -> flagged? (d13c215 flagged c06-c09 and missed c02: P 0.50 / R 0.80)
MICROBENCH_EXPECTED = {
    "c01-admin": True,
    "c02-poweruser-notaction": True,       # F-001: NotAction grants are seen
    "c03-putrolepolicy": True,
    "c04-attachuserpolicy": True,
    "c05-iam-notresource": True,
    "c06-quarantined": False,              # F-014: explicit Deny honoured
    "c07-passrole-scoped": False,          # F-012/F-017: PassRole scope and targets checked
    "c08-self-service-keys": False,        # F-017: ${aws:username} self-scope
    "c09-boundary-capped": False,          # F-052: boundary (document not collected) downgrades
    "c10-readonly": False,
}


def _microbench_flags(tmp_path):
    """Case -> "has a CRITICAL/HIGH privilege-escalation or dangerous-permission finding" (native analysis)."""
    report_dir = rb.materialize("microbench", tmp_path / "tree")[0]
    result = targets.engine_module().analyze_report(str(report_dir))
    assert result.status == "ok"
    findings = json.loads((Path(result.analysis_dir) / "findings.json").read_text(encoding="utf-8"))["findings"]
    per = defaultdict(list)
    for f in findings:
        per[str(f.get("node_id", "")).rsplit("/", 1)[-1]].append(f)
    return {name: any(f["severity"] in ("CRITICAL", "HIGH")
                      and f["category"] in ("privilege_escalation", "dangerous_permission") for f in per.get(name, []))
            for name in rb.MICROBENCH_CASES}


@pytest.mark.finding("F-001", "F-012", "F-014", "F-017", "F-052")
def test_microbench_precision_and_recall(tmp_path):
    flags = _microbench_flags(tmp_path)
    assert flags == MICROBENCH_EXPECTED
    truth = {n: c["positive"] for n, c in rb.MICROBENCH_CASES.items()}
    tp = sum(1 for n in truth if truth[n] and flags[n])
    fp = sum(1 for n in truth if not truth[n] and flags[n])
    fn = sum(1 for n in truth if truth[n] and not flags[n])
    precision, recall = tp / (tp + fp), tp / (tp + fn)
    assert (round(precision, 2), round(recall, 2)) == (1.0, 1.0)


# Existing-resource rows through the pipeline: the same single techniques fire once the resource is collected.
EXISTING_ROWS = {
    # row name: (pathfinding.cloud world, rule id, expected severity)
    "lambda:UpdateFunctionCode alone": ("lambda-003", "PRIVESC-021", "CRITICAL"),
    "ssm:SendCommand alone": ("ssm-002", "PRIVESC-050", "CRITICAL"),
    "ssm:StartSession alone": ("ssm-001", "PRIVESC-050", "CRITICAL"),
    "cloudformation:UpdateStack alone": ("cloudformation-002", "PRIVESC-029", "CRITICAL"),
    "glue:UpdateDevEndpoint alone": ("glue-002", "PRIVESC-022", "CRITICAL"),
    "codebuild:StartBuild alone": ("codebuild-002", "PRIVESC-023", "CRITICAL"),
    "sagemaker:CreatePresignedNotebookInstanceUrl alone": ("sagemaker-004", "PRIVESC-054", "CRITICAL"),
}
# (launch templates and ECS Exec services need the Wave 2 loaders' tables; their inventory is unit-tested in
# tests/python/engine/domains/rules/test_inventory.py)


@pytest.mark.finding("F-011", "F-069", "F-113")
@pytest.mark.parametrize("row", sorted(EXISTING_ROWS))
def test_existing_resource_rows_fire_when_the_resource_is_collected(tmp_path, row):
    from tests.python.engine.bench import import_pathfinding as PF
    from tests.python.engine.bench import pathfinding_harness as H

    path_id, rule_id, severity = EXISTING_ROWS[row]
    statements, privesc, _ = TECHNIQUES[row]
    assert privesc == []                       # a permission map has no collected resources
    actions = [a for s in statements for a in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])]
    path = PF.PathDef(path_id, row, "existing-passrole", (), tuple(actions), (), row, "")
    world, attacker = H.build_world(tmp_path, path, actions)
    out = world.analyze()
    (finding,) = out.findings(rule_id, attacker)
    assert finding["severity"] == severity and finding["targets"][0]["tier"] == "CRITICAL"
