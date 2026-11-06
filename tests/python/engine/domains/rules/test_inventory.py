"""Existing-resource inventory (rules/inventory.py; F-011, F-069, F-113): every collected type, both layouts."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from aws_enumerator.engine.rules import inventory as I

ACCT, REGION = "123456789012", "eu-west-2"
ADMIN = f"arn:aws:iam::{ACCT}:role/demo-admin"
PROFILE = f"arn:aws:iam::{ACCT}:instance-profile/demo-profile"


def _arn(service, resource):
    return f"arn:aws:{service}:{REGION}:{ACCT}:{resource}"


def _iam():
    return SimpleNamespace(instance_profiles=[{"Arn": PROFILE, "Roles": [{"Arn": ADMIN}]}],
                           users={"u": SimpleNamespace(arn=f"arn:aws:iam::{ACCT}:user/u",
                                                       record={"AccessKeys": [{}, {}]}),
                                  "v": SimpleNamespace(arn=f"arn:aws:iam::{ACCT}:user/v",
                                                       record={"AccessKeys": None})})


def _data():
    unit = lambda *records: {REGION: list(records)}  # noqa: E731
    return {
        "lambda": {"functions": unit({"FunctionArn": _arn("lambda", "function:fn:7"), "Role": ADMIN,
                                      "FunctionName": "fn"},
                                     {"FunctionArn": _arn("lambda", "function:no-role"), "Role": None})},
        "compute": {
            "glue": unit({"Type": "gluejob", "Kind": "dev_endpoint", "Arn": _arn("glue", "devEndpoint/e"),
                          "Roles": [ADMIN]},
                         {"Type": "gluejob", "Kind": "job", "Arn": _arn("glue", "job/j"), "Roles": [ADMIN]}),
            "codebuild": unit({"Type": "codebuild", "Arn": _arn("codebuild", "project/p"), "Roles": [ADMIN]}),
            "cloudformation": unit(
                {"Type": "cfnstack", "Arn": _arn("cloudformation", "stack/s/1"), "Roles": [ADMIN]},
                {"Type": "stackset", "Arn": _arn("cloudformation", "stackset/ss:1"), "Roles": None}),
            "sagemaker": unit(
                {"Type": "sagemaker", "Kind": "notebook", "Arn": _arn("sagemaker", "notebook-instance/nb"),
                 "Roles": [ADMIN]},
                {"Type": "sagemakerdomain", "Kind": "user_profile", "Arn": _arn("sagemaker", "user-profile/d-1/ann"),
                 "Roles": [ADMIN]},
                {"Type": "sagemakerdomain", "Kind": "domain", "Arn": _arn("sagemaker", "domain/d-1"),
                 "Roles": [ADMIN]}),
            "ecs": unit({"Type": "ecstask", "Arn": _arn("ecs", "task-definition/web:3"), "Family": "web",
                         "TaskRole": ADMIN, "Roles": [ADMIN]}),
            "ecs_services": unit({"ServiceArn": _arn("ecs", "service/c/web"), "Name": "web",
                                  "TaskDefinition": _arn("ecs", "task-definition/web:3"), "EnableExecuteCommand": True},
                                 {"ServiceArn": _arn("ecs", "service/c/api"), "Name": "api",
                                  "TaskDefinition": _arn("ecs", "task-definition/web:3"),
                                  "EnableExecuteCommand": None}),
        },
        "ec2": {
            "instances": unit({"InstanceId": "i-0a1b2c3d4e5f60001", "State": "running",
                               "IamInstanceProfile": {"Arn": PROFILE}},
                              {"InstanceId": "i-0a1b2c3d4e5f60002", "State": "terminated",
                               "IamInstanceProfile": {"Arn": PROFILE}},
                              {"InstanceId": "i-0a1b2c3d4e5f60003", "State": "running", "IamInstanceProfile": {}}),
            "launch_templates": unit({"LaunchTemplateId": "lt-0a1b2c3d4e5f60001", "LaunchTemplateName": "lt",
                                      "Arn": _arn("ec2", "launch-template/lt-0a1b2c3d4e5f60001"),
                                      "Versions": [{"VersionNumber": 2,
                                                    "IamInstanceProfile": {"Name": "demo-profile"}}]},
                                     {"LaunchTemplateId": "lt-0a1b2c3d4e5f60002", "Arn": _arn(
                                         "ec2", "launch-template/lt-0a1b2c3d4e5f60002"), "Versions": None}),
            "_status": {"instances": {REGION: "complete"}},
        },
    }


@pytest.mark.finding("F-011", "F-113")
def test_every_collected_type_is_read_and_unknown_roles_are_skipped():
    inv = I.existing_from_data(_data(), partition="aws", account=ACCT, iam=_iam())
    arns = {k: [r.arn for r in v] for k, v in inv.items()}
    assert arns["lambda_function"] == [_arn("lambda", "function:fn"), _arn("lambda", "function:no-role")]
    assert [r.role_arn for r in inv["lambda_function"]] == [ADMIN, None]
    assert arns["glue_dev_endpoint"] == [_arn("glue", "devEndpoint/e")]
    assert arns["codebuild_project"] == [_arn("codebuild", "project/p")]
    assert arns["cfn_stack"] == [_arn("cloudformation", "stack/s/1")]
    assert inv["cfn_stack_set"][0].role_arn is None                  # null = unknown, never guessed
    assert arns["sagemaker_notebook"] == [_arn("sagemaker", "notebook-instance/nb")]
    assert arns["sagemaker_user_profile"] == [_arn("sagemaker", "user-profile/d-1/ann")]
    assert [(r.arn, r.role_arn) for r in inv["ecs_exec_service"]] == [(_arn("ecs", "service/c/web"), ADMIN)]
    assert [(r.arn, r.role_arn) for r in inv["ec2_instance"]] == [
        (_arn("ec2", "instance/i-0a1b2c3d4e5f60001"), ADMIN)]
    assert [(r.arn, r.role_arn) for r in inv["ec2_launch_template"]] == [
        (_arn("ec2", "launch-template/lt-0a1b2c3d4e5f60001"), ADMIN)]


def test_missing_domains_give_empty_lists():
    inv = I.existing_from_data({})
    assert set(inv) == {t.name for t in I.EXISTING_TYPES.values() if t.collected}
    assert all(v == [] for v in inv.values())


@pytest.mark.finding("F-011")
def test_access_key_counts_and_unknowns():
    counts = I.access_key_counts(_iam())
    assert counts == {f"arn:aws:iam::{ACCT}:user/u": 2, f"arn:aws:iam::{ACCT}:user/v": None}


def test_types_and_probe_arns():
    sfn = I.EXISTING_TYPES["sfn_state_machine"]
    assert not sfn.collected and sfn.node_type is None
    assert sfn.probe_arn(partition="aws-us-gov", account=ACCT) == \
        f"arn:aws-us-gov:states:*:{ACCT}:stateMachine:{I.PROBE_NAME}"
    for t in I.EXISTING_TYPES.values():
        assert "{partition}" in t.template and t.label
