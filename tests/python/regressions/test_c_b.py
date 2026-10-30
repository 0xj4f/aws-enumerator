"""Regression tests owned by stream C-B (the remaining 19 collectors plus organizations).

xfail-first (see test_e_policy.py; collector conventions in test_c_a.py). F-166 is already fixed by the
Wave 0b rename and is a plain passing test.
"""

from __future__ import annotations

import builtins
import inspect
import json

import pytest

from tests.fixtures.regressions import support as S
from tests.fixtures.worlds import acme
from tests.support import targets
from tests.support.fakeaws import World

pytestmark = pytest.mark.collectors

W1, W2 = "eu-west-1", "eu-west-2"
ACCT = acme.ACCOUNT_ID


# ── F-004 (collector side): ECS task role vs execution role ──────────────────
@pytest.mark.finding("F-004")
def test_f004_ecs_task_definitions_record_task_and_execution_roles_separately(tmp_path, monkeypatch):
    exec_role = acme.role_arn("demo-ecs-exec-role")
    for td in acme.REGIONAL[W2]["ecs"]["task_definitions"]:
        if td["family"] == "demo-api":
            monkeypatch.setitem(td, "executionRoleArn", exec_role)
    run = S.run_module("ecs", acme.build_world(), tmp_path, region=W2)
    items = [i for i in run.load("resources.json", []) if isinstance(i, dict) and "demo-api" in str(i.get("Arn"))]
    assert items, run.load("resources.json")
    for item in items:
        assert item.get("TaskRole") == acme.role_arn("demo-ecs-task-role"), item
        assert item.get("ExecutionRole") == exec_role, item


# ── F-051 (collector side): real ARNs ────────────────────────────────────────
@pytest.mark.finding("F-051")
def test_f051_glue_resources_have_real_arns(tmp_path):
    run = S.run_module("glue", acme.build_world(), tmp_path, region=W2)
    arns = {i.get("Arn") for i in run.load("resources.json", []) if isinstance(i, dict)}
    assert f"arn:aws:glue:{W2}:{ACCT}:job/demo-etl-job" in arns, arns
    assert f"arn:aws:glue:{W2}:{ACCT}:devEndpoint/demo-dev-endpoint" in arns, arns


@pytest.mark.finding("F-051")
def test_f051_classic_load_balancers_have_real_arns(tmp_path):
    run = S.run_module("elb", acme.build_world(), tmp_path, region=W2)
    arns = {i.get("Name"): i.get("Arn") for i in run.load("resources.json", []) if isinstance(i, dict)}
    assert arns.get("demo-classic-elb") == f"arn:aws:elasticloadbalancing:{W2}:{ACCT}:loadbalancer/demo-classic-elb"


# ── F-055 (collector side): alias-qualified URLs and policies ────────────────
ALIAS_URL = "https://demo-west-live.lambda-url.eu-west-1.on.aws/"


def lambda_alias_world() -> World:
    """acme plus a 'live' alias on eu-west-1's demo-west-fn with a NONE-auth URL and a public policy."""
    w = acme.build_world()
    fn_arn = acme.lambda_arn(W1, "demo-west-fn")
    original_policy = w.handlers[("lambda", "GetPolicy")]
    original_url = w.handlers[("lambda", "GetFunctionUrlConfig")]
    url_config = {"FunctionUrl": ALIAS_URL, "FunctionArn": f"{fn_arn}:live", "AuthType": "NONE",
                  "CreationTime": "2024-01-15T10:00:00.000Z", "LastModifiedTime": "2024-01-15T10:00:00.000Z",
                  "InvokeMode": "BUFFERED"}

    def is_alias(req):
        return req.region == W1 and req.params.get("Qualifier") == "live" and str(
            req.params.get("FunctionName", "")).endswith("demo-west-fn")

    @w.op("lambda", "ListFunctionUrlConfigs")
    def list_url_configs(req):
        return {"FunctionUrlConfigs": [url_config] if req.region == W1 else []}

    @w.op("lambda", "ListAliases")
    def list_aliases(req):
        if req.region == W1 and str(req.params.get("FunctionName", "")).endswith("demo-west-fn"):
            return {"Aliases": [{"AliasArn": f"{fn_arn}:live", "Name": "live", "FunctionVersion": "3"}]}
        return {"Aliases": []}

    @w.op("lambda", "GetFunctionUrlConfig")
    def get_url(req):
        return dict(url_config) if is_alias(req) else original_url(req)

    @w.op("lambda", "GetPolicy")
    def get_policy(req):
        if is_alias(req):
            doc = {"Version": "2012-10-17", "Statement": [{
                "Sid": "PublicUrl", "Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunctionUrl",
                "Resource": f"{fn_arn}:live", "Condition": {"StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}}}]}
            return {"Policy": World.json_doc(doc), "RevisionId": "00000000-rev0-4000-8000-0000000000e9"}
        return original_policy(req)

    return w


@pytest.mark.finding("F-055")
def test_f055_alias_function_url_and_policy_are_collected(tmp_path):
    run = S.run_module("lambda", lambda_alias_world(), tmp_path, region=W1)
    functions = run.load("functions.json", [])
    assert ALIAS_URL in json.dumps(functions), functions
    policies = [S.load_json(p) for p in S.files_under(run.out / "resource_policies")]
    alias = [p for p in policies if isinstance(p, dict) and (p.get("Qualifier") == "live"
                                                             or str(p.get("FunctionArn", "")).endswith(":live"))]
    assert alias, policies
    doc = alias[0].get("ResourcePolicy")
    doc = json.loads(doc) if isinstance(doc, str) else doc
    assert any(st.get("Principal") in ("*", {"AWS": "*"}) for st in doc["Statement"]), doc


# ── F-114: Secrets Manager policy files never collide or abort ───────────────
@pytest.mark.finding("F-114")
def test_f114_every_secret_keeps_its_policy(tmp_path, monkeypatch):
    long_name = "demo/" + "x" * 251                            # 256 characters, the API maximum
    long_secret = {"ARN": f"arn:aws:secretsmanager:{W2}:{ACCT}:secret:{long_name}-MnOpQr", "Name": long_name,
                   "RotationEnabled": False, "LastChangedDate": acme.ts(8), "CreatedDate": acme.ts(2),
                   "policy": acme._doc({"Sid": "CrossAccount", "Effect": "Allow",
                                        "Principal": {"AWS": f"arn:aws:iam::{acme.EXTERNAL_ACCOUNT_ID}:root"},
                                        "Action": "secretsmanager:GetSecretValue", "Resource": "*"})}
    secrets = acme.REGIONAL[W2]["secretsmanager"]
    monkeypatch.setitem(secrets, "secrets", [long_secret] + list(secrets["secrets"]))
    run = S.run_module("secretsmanager", acme.build_world(), tmp_path, region=W2)
    assert run.result.status != "failed", run.result.error
    stored = {(S.load_json(p) or {}).get("SecretArn") for p in S.files_under(run.out / "resource_policies")}
    expected = {long_secret["ARN"], f"arn:aws:secretsmanager:{W2}:{ACCT}:secret:demo/db-creds-AbCdEf",
                f"arn:aws:secretsmanager:{W2}:{ACCT}:secret:demo_db-creds-GhIjKl"}
    assert expected <= stored, sorted(str(s) for s in stored)


# ── F-115: SQS ListQueues asks for pages ─────────────────────────────────────
@pytest.mark.finding("F-115")
def test_f115_list_queues_sends_max_results(tmp_path):
    run = S.run_module("sqs", acme.build_world(), tmp_path, region=W2)
    calls = run.fake.calls_for(service="sqs", operation="ListQueues")
    assert calls
    assert all(c.params.get("MaxResults") == 1000 for c in calls), [c.params for c in calls]


# ── F-166 (already fixed by the rename): no collector shadows a builtin ──────
@pytest.mark.finding("F-166")
@pytest.mark.parametrize("name", targets.collector_names())
def test_f166_collector_entry_point_does_not_shadow_enumerate(name):
    module = targets.collector_module(name)
    assert getattr(module, "enumerate", builtins.enumerate) is builtins.enumerate
    assert callable(getattr(module, "collect", None))
    assert "def enumerate(" not in inspect.getsource(module)
