"""Least-privilege permissions generator and its coverage of what the collectors really call (F-151, F-161)."""

from __future__ import annotations

import json

import pytest

from tests.fixtures.worlds import acme
from tests.python.orchestration import r_harness as R
from tests.support import targets

P = targets.runtime_module("permissions")
IA = targets.runtime_module("iam_actions")


def _policy(monkeypatch, *flags):
    code, out, err = R.invoke(["permissions", *flags], monkeypatch)
    assert code == 0, err
    return json.loads(out)


def _statement(policy, sid):
    return next((s for s in policy["Statement"] if s["Sid"] == sid), None)


@pytest.mark.finding("F-151", "F-161")
def test_policy_statements_tiers_and_scoping(monkeypatch):
    policy = _policy(monkeypatch)
    assert policy["Version"] == "2012-10-17"
    tier1 = _statement(policy, "AwsEnumeratorTier1")
    assert tier1["Resource"] == "*"
    assert {"iam:GetAccountAuthorizationDetails", "iam:ListRoles"} & set(tier1["Action"])
    assert "ec2:DescribeRegions" in tier1["Action"]                # the runner's own --all discovery
    assert all(a == a.strip() and ":" in a and "*" not in a for s in policy["Statement"] for a in s["Action"])
    api = _statement(policy, "AwsEnumeratorApiGatewayRead")
    assert api["Action"] == ["apigateway:GET"] and all(r.startswith("arn:aws:apigateway:") for r in api["Resource"])
    assert "apigateway:GET" not in tier1["Action"]            # never on Resource "*" (would read API key values)
    tier2 = _statement(policy, "AwsEnumeratorTier2SecretBearingConfig")
    assert tier2 and any(a.startswith("lambda:") for a in tier2["Action"])
    assert _statement(policy, "AwsEnumeratorOptional") is None
    assert _statement(policy, "AwsEnumeratorDenyDataPlane") is None


@pytest.mark.finding("F-151")
def test_policy_flags(monkeypatch):
    tier1_only = _policy(monkeypatch, "--max-tier", "1")
    assert _statement(tier1_only, "AwsEnumeratorTier2SecretBearingConfig") is None
    guarded = _policy(monkeypatch, "--guardrail", "--include-optional")
    deny = _statement(guarded, "AwsEnumeratorDenyDataPlane")
    assert deny["Effect"] == "Deny" and {"s3:GetObject", "secretsmanager:GetSecretValue", "kms:Decrypt"} <= set(
        deny["Action"])
    assert _statement(guarded, "AwsEnumeratorOptional") is not None
    gov = _policy(monkeypatch, "--partition", "aws-us-gov", "--modules", "apigateway")
    assert all(r.startswith("arn:aws-us-gov:apigateway:") for r in _statement(gov, "AwsEnumeratorApiGatewayRead")[
        "Resource"])
    only = _policy(monkeypatch, "--modules", "sns")
    assert {a.split(":")[0] for s in only["Statement"] for a in s["Action"]} <= {"sns", "ec2"}


@pytest.mark.finding("F-151")
def test_unknown_partition_or_module_is_a_usage_error(monkeypatch):
    for argv in (["permissions", "--partition", "aws-mars"], ["permissions", "--modules", "lamda"]):
        code, out, _err = R.invoke(argv, monkeypatch)
        assert (code, out) == (64, "")


@pytest.mark.finding("F-161", "F-062")
def test_kubernetes_rbac_lists_secrets_only_with_k8s_secrets(monkeypatch):
    code, out, _err = R.invoke(["permissions", "--format", "k8s"], monkeypatch)
    assert code == 0 and "kind: ClusterRole" in out and "aws-enumerator-readers" in out
    assert '"secrets"' not in out and 'resourceNames: ["aws-auth"]' in out
    code, out, _err = R.invoke(["permissions", "--format", "k8s", "--k8s-secrets"], monkeypatch)
    assert '"secrets"' in out and "read every Secret value" in out


def test_markdown_page(monkeypatch):
    code, out, _err = R.invoke(["permissions", "--format", "markdown"], monkeypatch)
    assert code == 0 and out.startswith("# Permissions") and "## IAM policy" in out and "| `iam` |" in out


@pytest.mark.parametrize("api, action", [
    ("s3:ListBuckets", "s3:ListAllMyBuckets"),
    ("elbv2:DescribeLoadBalancers", "elasticloadbalancing:DescribeLoadBalancers"),
    ("apigatewayv2:GetApis", "apigateway:GET"), ("s3:GetBucketCors", "s3:GetBucketCORS"),
    ("sts:GetCallerIdentity", None), ("cognito-idp:ListUserPools", "cognito-idp:ListUserPools"),
])
def test_operation_to_action_mapping(api, action):
    assert IA.iam_action_for(api) == action


def _allowed(policy, action):
    return any(s["Effect"] == "Allow" and action in s["Action"] for s in policy["Statement"])


@pytest.mark.finding("F-151", "F-161")
def test_generated_policy_covers_every_call_of_a_full_run(tmp_path, monkeypatch):
    """Every (service, operation) the collectors and the runner issue in an acme --all run maps to an allowed
    action of ``permissions --include-optional`` (the CI-equivalent check of collectors-cli.md §6)."""
    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--all", "--k8s-secrets"], tmp_path, monkeypatch, patch_region_discovery=False)
    assert run.exit_code in (0, 2), run.err[-3000:]
    policy = _policy(monkeypatch, "--include-optional", "--k8s-secrets")
    missing = {}
    for call in run.fake.calls_for():
        action = IA.iam_action_for(call.op)
        if action and not _allowed(policy, action):
            missing.setdefault(action, set()).add(call.module)
    assert missing == {}, {a: sorted(m) for a, m in sorted(missing.items())}
    assert run.fake.non_read_only_calls() == [] or {c.op for c in run.fake.non_read_only_calls()} <= {
        "iam:GenerateCredentialReport"}
    assert acme.ACCOUNT_ID not in json.dumps(policy)


@pytest.mark.finding("F-161")
def test_preflight_probe_for_every_default_module(monkeypatch):
    registry = targets.registry_module().get_registry()
    for spec in registry.implemented():
        assert P.probe_for(spec) is not None, spec.name
