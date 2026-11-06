"""Rules for the compute take-over surfaces of F-113 (engine side) and the boundary manipulation of F-011.

SageMaker training / processing jobs and Glue interactive sessions are PassRole rules (no collector needed);
SageMaker Studio user profiles, CloudFormation stacks and StackSets are collected resources whose role is taken
over; permissions boundaries are modelled by the evaluator, so removing one is an escalation.
"""

from __future__ import annotations

import importlib

import pytest

W = importlib.import_module("tests.fixtures.e-rules.worlds")
rb = W.rb
allow = W.allow


@pytest.mark.finding("F-113", "F-011")
@pytest.mark.parametrize("rule_id,actions,service", [
    ("PRIVESC-040", ["iam:PassRole", "sagemaker:CreateTrainingJob"], "sagemaker.amazonaws.com"),
    ("PRIVESC-040", ["iam:PassRole", "sagemaker:CreateProcessingJob"], "sagemaker.amazonaws.com"),
    ("PRIVESC-036", ["iam:PassRole", "glue:CreateSession", "glue:RunStatement"], "glue.amazonaws.com"),
    ("PRIVESC-027", ["iam:PassRole", "cloudformation:CreateStackSet", "cloudformation:CreateStackInstances"],
     "cloudformation.amazonaws.com"),
])
def test_passrole_into_new_jobs_sessions_and_stacksets(tmp_path, rule_id, actions, service):
    w = W.World(tmp_path)
    admin = w.admin_role("demo-admin", W.trusts_service(service))
    dev = w.user("demo-dev", allow(actions))
    out = w.analyze()
    f = out.finding(rule_id, dev)
    assert f["severity"] == "CRITICAL" and f["targets"][0]["node_id"] == admin
    assert out.edges("CAN_PASS_ROLE_TO", source=dev, target=admin)


@pytest.mark.finding("F-113")
def test_studio_presigned_domain_url_takes_over_the_profile_role(tmp_path):
    w = W.World(tmp_path)
    admin = w.admin_role("demo-studio-admin", W.trusts_service("sagemaker.amazonaws.com"))
    profile = f"arn:aws:sagemaker:{W.REGION}:{W.ACCT}:user-profile/d-0a1b2c3d4e5f/demo-ann"
    w.write("sagemaker/resources.json", [rb.compute_resource("sagemakerdomain", profile, "demo-ann", [admin],
                                                             Kind="user_profile")])
    dev = w.user("demo-dev", allow("sagemaker:CreatePresignedDomainUrl", profile))
    out = w.analyze()
    f = out.finding("PRIVESC-056", dev)
    assert f["severity"] == "CRITICAL" and f["evidence"]["targets_detail"][0]["role"] == admin
    assert out.edges("CAN_EXEC", source=dev, target=profile)


@pytest.mark.finding("F-113", "F-011")
def test_existing_stack_change_set_runs_as_the_stack_role(tmp_path):
    w = W.World(tmp_path)
    admin = w.admin_role("demo-cfn-admin", W.trusts_service("cloudformation.amazonaws.com"))
    stack = f"arn:aws:cloudformation:{W.REGION}:{W.ACCT}:stack/demo-stack/0a1b2c3d-0000-4000-8000-000000000001"
    w.write("cloudformation/resources.json", [rb.compute_resource("cfnstack", stack, "demo-stack", [admin])])
    dev = w.user("demo-dev", allow(["cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet"], stack))
    half = w.user("demo-half", allow("cloudformation:CreateChangeSet", stack))
    out = w.analyze()
    assert out.finding("PRIVESC-029", dev)["severity"] == "CRITICAL"
    assert out.edges("CAN_HIJACK", source=dev, target=stack)
    assert out.findings("PRIVESC-029", half) == []                          # chain completeness (F-069)


@pytest.mark.finding("F-011", "F-052")
def test_removing_ones_own_boundary_is_an_escalation(tmp_path):
    """A boundary caps the boundary-removal call too; one that does not protect itself can be removed."""
    w = W.World(tmp_path)
    w.customer_policy("demo-cap", allow(["s3:GetObject", "iam:DeleteRolePermissionsBoundary"]))
    w.customer_policy("demo-tight", allow("s3:GetObject"))
    boundary = {"PermissionsBoundaryType": "Policy",
                "PermissionsBoundaryArn": f"arn:aws:iam::{W.ACCT}:policy/demo-cap"}
    capped = w.role("demo-capped", allow("*"), allow("iam:DeleteRolePermissionsBoundary", W.arn("role", "demo-capped")),
                    extra={"PermissionsBoundary": boundary})
    tight = w.role("demo-tight-role", allow("*"),
                   extra={"PermissionsBoundary": dict(boundary, PermissionsBoundaryArn=boundary[
                       "PermissionsBoundaryArn"].replace("demo-cap", "demo-tight"))})
    free = w.role("demo-free", allow("s3:ListBucket"),
                  allow("iam:DeleteRolePermissionsBoundary", W.arn("role", "demo-free")))
    out = w.analyze()
    assert out.finding("PRIVESC-067", capped)["severity"] == "CRITICAL"
    assert out.edges("CAN_ESCALATE", source=capped, target=W.ADMIN_NODE)
    assert out.findings("PRIVESC-067", tight) == []                         # its boundary blocks the call
    assert out.findings("PRIVESC-067", free) == []                          # no boundary: nothing to gain
