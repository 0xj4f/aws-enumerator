"""Regression tests owned by stream E-data (KMS, Secrets Manager / SSM and data-store analyzers).

xfail-first (see test_e_policy.py).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fixtures.regressions import support as S
from tests.support import report_builder as rb

ACCT, R, ACCT_EXT = S.ACCT, S.REGION, S.ACCT_EXT
EC2_TRUST = rb.trust({"Service": "ec2.amazonaws.com"})


def _tree(root: Path, region: str = R):
    return rb.Scope(root, ACCT, region), rb.Iam(ACCT)


def _finish(s):
    rb.write_manifest(s.path, account=ACCT, mode="single_region", region=s.name)
    return s.path


# ── F-026: metadata-only actions are not reads ───────────────────────────────
@pytest.mark.finding("F-026")
def test_f026_metadata_actions_do_not_read_secrets_or_parameters(tmp_path):
    s, iam = _tree(tmp_path)
    iam.role("demo-describer", EC2_TRUST, inline={"p": [rb.allow(
        ["secretsmanager:DescribeSecret", "secretsmanager:ListSecretVersionIds", "ssm:DescribeParameters"], "*")]})
    iam.role("demo-describe-wild", EC2_TRUST, inline={"p": [rb.allow(
        ["secretsmanager:Describe*", "secretsmanager:List*", "ssm:Describe*"], "*")]})
    iam.role("demo-getter", EC2_TRUST, inline={"p": [rb.allow(
        ["secretsmanager:GetSecretValue", "ssm:GetParameter"], "*")]})
    iam.write(s)
    sec = rb.secret("demo/app", account=ACCT, region=R)
    param = rb.ssm_parameter("/demo/app/password", account=ACCT, region=R)
    s.write("secretsmanager/secrets.json", [sec])
    s.write("ssm/parameters.json", [param])
    edges = S.analyze_tree(_finish(s)).edges("secrets")

    def reads(role):
        out = set()
        if S.edges_from(edges, S.iam_arn("role", role), sec["ARN"], types=["CAN_READ_SECRET"]):
            out.add("secret")
        if S.edges_from(edges, S.iam_arn("role", role), param["ARN"], types=["CAN_READ_PARAM"]):
            out.add("param")
        return out

    assert reads("demo-getter") == {"secret", "param"}            # positive control
    assert reads("demo-describer") == set()
    assert reads("demo-describe-wild") == set()


# ── F-029: key-policy grants to same-account principals ──────────────────────
@pytest.mark.finding("F-029")
def test_f029_key_policy_grants_to_same_account_roles_create_edges(tmp_path):
    s, iam = _tree(tmp_path)
    for name in ("demo-key-user", "demo-key-admin", "demo-bystander"):
        iam.role(name, EC2_TRUST)
    iam.write(s)
    key = rb.kms_key("7b8c9d0e-aaaa-4bbb-8ccc-1f2a3b4c5d6e", account=ACCT, region=R)
    s.write("kms/keys.json", [key])
    s.write(f"kms/key_policies/{key['KeyId']}.json", rb.kms_policy_file(key, rb.resource_policy(
        rb.grant({"AWS": f"arn:aws:iam::{ACCT}:root"}, "kms:*", sid="Enable IAM User Permissions"),
        rb.grant({"AWS": iam.arn("role", "demo-key-user")}, ["kms:Decrypt", "kms:DescribeKey"]),
        rb.grant({"AWS": iam.arn("role", "demo-key-admin")}, ["kms:PutKeyPolicy", "kms:ScheduleKeyDeletion"]))))
    edges = S.analyze_tree(_finish(s)).edges("kms")
    assert S.edges_linking(edges, S.iam_arn("role", "demo-key-user"), key["Arn"],
                           types={"KMS_GRANTS_DECRYPT", "CAN_DECRYPT"})
    assert S.edges_linking(edges, S.iam_arn("role", "demo-key-admin"), key["Arn"], types={"CAN_ADMIN_KEY"})
    # the root "Enable IAM User Permissions" statement delegates to IAM; it grants nobody directly
    assert S.edges_linking(edges, S.iam_arn("role", "demo-bystander"), key["Arn"]) == []


# ── F-081: multi-Region key replicas keep their own key policies ─────────────
MRK = "mrk-0a1b2c3d4e5f60718293a4b5c6d7e8f9"


@pytest.mark.finding("F-081")
def test_f081_mrk_replicas_are_evaluated_against_their_own_policies(tmp_path):
    g = rb.Scope(tmp_path, ACCT, "global")
    rb.Iam(ACCT).write(g)
    g.write("s3/buckets.json", [])
    arns = {}
    policies = {"us-east-1": rb.resource_policy(rb.grant("*", "kms:Decrypt")),
                "eu-west-1": rb.resource_policy(rb.grant({"AWS": f"arn:aws:iam::{ACCT_EXT}:root"}, "kms:Decrypt"))}
    for region, policy in policies.items():
        r = rb.Scope(tmp_path, ACCT, region)
        rb.write_empty_regional(r, skip={"kms"})
        key = rb.kms_key(MRK, account=ACCT, region=region)
        arns[region] = key["Arn"]
        r.write("kms/keys.json", [key])
        r.write(f"kms/key_policies/{MRK}.json", rb.kms_policy_file(key, policy))
    rb.write_manifest(tmp_path / ACCT, account=ACCT, mode="all_regions", region=None, regions=sorted(policies))
    findings = S.analyze_tree(tmp_path / ACCT).findings()

    def subjects(fid):
        return {region for region, arn in arns.items() if S.findings_for(findings, fid, arn)}

    assert subjects("KMS-PUB-001") == {"us-east-1"}
    assert subjects("KMS-XACCT-001") == {"eu-west-1"}


# ── F-082: API Gateway targets join the unqualified Lambda node ──────────────
@pytest.mark.finding("F-082")
def test_f082_invokes_targets_are_unqualified_lambda_arns(tmp_path):
    s, iam = _tree(tmp_path)
    iam.role("demo-fn-role", rb.trust({"Service": "lambda.amazonaws.com"}))
    iam.write(s)
    fn = rb.lambda_function("demo-api-fn", account=ACCT, region=R, role=iam.arn("role", "demo-fn-role"))
    s.write("lambda/functions.json", [fn])
    s.write("apigateway/resources.json", [
        {"Type": "apigw", "Arn": f"arn:aws:apigateway:{R}::/apis/a1b2c3d4e5", "Name": "demo-alias-api",
         "Protocol": "HTTP", "LambdaTargets": [fn["FunctionArn"] + ":live"], "HasAuthorizer": True},
        {"Type": "apigw", "Arn": f"arn:aws:apigateway:{R}::/restapis/f6a7b8c9d0", "Name": "demo-stagevar-api",
         "Protocol": "REST", "LambdaTargets": [f"arn:aws:lambda:{R}:{ACCT}:function:${{stageVariables.fn}}"],
         "HasAuthorizer": True},
    ])
    invokes = [e for e in S.analyze_tree(_finish(s)).edges() if e.get("type") == "INVOKES"]
    assert [e for e in invokes if S.refers(e.get("target"), fn["FunctionArn"])], invokes
    assert [e.get("target") for e in invokes if str(e.get("target")).endswith(":live")] == []
    assert [e.get("target") for e in invokes if "${" in str(e.get("target"))] == []
