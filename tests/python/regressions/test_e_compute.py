"""Regression tests owned by stream E-compute (Lambda, compute, messaging, Cognito analyzers, IAM hygiene).

xfail-first (see test_e_policy.py). F-004 is about which edges may be walked; the legacy files render
CAN_EXPOSE as CAN_MODIFY_CONFIG and EXECUTION_ROLE as USES_ROLE (edge_types.py ``legacy_name``), so its
tests read ``graph.json`` (contract API).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fixtures.regressions import support as S
from tests.support import report_builder as rb

ACCT, R, R1 = S.ACCT, S.REGION, S.OTHER_REGION
GRAPH_API = "requires engine.analyze_report() writing analysis/graph.json"


def _tree(root: Path, region: str = R):
    return rb.Scope(root, ACCT, region), rb.Iam(ACCT)


def _finish(s):
    rb.write_manifest(s.path, account=ACCT, mode="single_region", region=s.name)
    return s.path


# ── F-004: use/expose is not control ─────────────────────────────────────────
def build_lambda_tree(root: Path) -> Path:
    s, iam = _tree(root)
    iam.role("demo-fn-role", rb.trust({"Service": "lambda.amazonaws.com"}), attached=["AdministratorAccess"])
    fn_arn = f"arn:aws:lambda:{R}:{ACCT}:function:demo-fn"
    iam.user("demo-invoker", inline={"p": [rb.allow("lambda:InvokeFunction", fn_arn)]})
    iam.user("demo-exposer", inline={"p": [rb.allow(["lambda:AddPermission", "lambda:CreateFunctionUrlConfig",
                                                      "lambda:UpdateFunctionUrlConfig", "lambda:PublishVersion",
                                                      "lambda:UpdateAlias"], fn_arn)]})
    iam.user("demo-updater", inline={"p": [rb.allow("lambda:UpdateFunctionCode", fn_arn)]})
    iam.write(s)
    fn = rb.lambda_function("demo-fn", account=ACCT, region=R, role=iam.arn("role", "demo-fn-role"))
    s.write("lambda/functions.json", [fn])
    s.write("lambda/resource_policies/demo-fn.json", rb.lambda_policy_file(fn, rb.resource_policy(
        rb.grant("*", "lambda:InvokeFunction", fn_arn))))
    return _finish(s)


@pytest.mark.finding("F-004")
def test_f004_invoking_or_exposing_a_function_does_not_reach_its_role(tmp_path):
    graph = S.analyze_graph(build_lambda_tree(tmp_path))
    role = S.iam_arn("role", "demo-fn-role")
    fn = f"arn:aws:lambda:{R}:{ACCT}:function:demo-fn"
    updater = S.path(graph, S.iam_arn("user", "demo-updater"), role)             # positive control
    assert updater is not None and updater.edge_types == ("CAN_UPDATE_CODE", "USES_ROLE"), updater
    assert S.path(graph, S.iam_arn("user", "demo-invoker"), role) is None
    assert S.path(graph, S.iam_arn("user", "demo-exposer"), role) is None
    assert S.path(graph, "aws-enumerator:anonymous", role) is None
    exposer_types = {e["type"] for e in S.graph_edges(graph, source=S.iam_arn("user", "demo-exposer"), target=fn)}
    assert exposer_types == {"CAN_EXPOSE"}, exposer_types


def build_compute_tree(root: Path) -> Path:
    s, iam = _tree(root)
    iam.role("demo-task-role", rb.trust({"Service": "ecs-tasks.amazonaws.com"}), attached=["AdministratorAccess"])
    iam.role("demo-task-exec-role", rb.trust({"Service": "ecs-tasks.amazonaws.com"}), attached=["AdministratorAccess"])
    iam.role("demo-build-role", rb.trust({"Service": "codebuild.amazonaws.com"}), attached=["AdministratorAccess"])
    project = f"arn:aws:codebuild:{R}:{ACCT}:project/demo-build"
    iam.user("demo-ecs-dev", inline={"p": [rb.allow(["ecs:RegisterTaskDefinition", "ecs:RunTask"], "*")]})
    iam.user("demo-cb-dev", inline={"p": [rb.allow("codebuild:StartBuild", project)]})
    iam.write(s)
    task, execution = iam.arn("role", "demo-task-role"), iam.arn("role", "demo-task-exec-role")
    s.write("ecs/resources.json", [rb.compute_resource(
        "ecstask", f"arn:aws:ecs:{R}:{ACCT}:task-definition/demo-app:3", "demo-app", [task, execution],
        Family="demo-app", TaskRole=task, ExecutionRole=execution)])
    s.write("codebuild/resources.json", [rb.compute_resource("codebuild", project, "demo-build",
                                                             [iam.arn("role", "demo-build-role")])])
    return _finish(s)


@pytest.mark.finding("F-004")
def test_f004_passrole_less_compute_actions_and_ecs_execution_role_are_not_paths(tmp_path):
    graph = S.analyze_graph(build_compute_tree(tmp_path))
    task_role, exec_role = S.iam_arn("role", "demo-task-role"), S.iam_arn("role", "demo-task-exec-role")
    cb = S.path(graph, S.iam_arn("user", "demo-cb-dev"), S.iam_arn("role", "demo-build-role"))
    assert cb is not None                                    # StartBuild hijacks an existing project's role
    assert S.path(graph, S.iam_arn("user", "demo-ecs-dev"), task_role) is None
    assert S.path(graph, S.iam_arn("user", "demo-ecs-dev"), exec_role) is None
    tasks = [n["id"] for n in graph["nodes"] if n["type"] == "ecstask"]
    assert tasks, "the ECS task definition must be a node"
    for t in tasks:
        assert [e for e in S.graph_edges(graph, source=t, target=task_role) if e["traversable"]], t
        assert not [e for e in S.graph_edges(graph, source=t, target=exec_role) if e["traversable"]], t
        assert {e["type"] for e in S.graph_edges(graph, source=t, target=exec_role)} <= {"EXECUTION_ROLE"}


# ── F-032: Cognito guest access gate ─────────────────────────────────────────
@pytest.mark.finding("F-032")
def test_f032_unauth_role_matters_only_when_guest_access_is_enabled(tmp_path):
    s, iam = _tree(tmp_path)
    web_identity = rb.trust({"Federated": "cognito-identity.amazonaws.com"}, "sts:AssumeRoleWithWebIdentity")
    iam.role("demo-unauth-off", web_identity)
    iam.role("demo-unauth-on", web_identity)
    iam.write(s)
    off_id, on_id = (f"{R}:0a1b2c3d-aaaa-4bbb-8ccc-00000000000{n}" for n in (1, 2))
    s.write("cognito/resources.json", [
        {"Type": "cognito", "Kind": "identity_pool", "Id": off_id, "Name": "demo_guest_off", "AuthRole": None,
         "UnauthRole": iam.arn("role", "demo-unauth-off"), "AllowUnauth": False},
        {"Type": "cognito", "Kind": "identity_pool", "Id": on_id, "Name": "demo_guest_on", "AuthRole": None,
         "UnauthRole": iam.arn("role", "demo-unauth-on"), "AllowUnauth": True},
    ])
    analysis = S.analyze_tree(_finish(s))
    findings = analysis.findings()

    def flagged(pool_id, name):
        return bool(S.findings_for(findings, "COGNITO-UNAUTH-001", pool_id)
                    or S.findings_for(findings, "COGNITO-UNAUTH-001", name))

    assert flagged(on_id, "demo_guest_on")                                   # positive control
    assert not flagged(off_id, "demo_guest_off")
    edges = [e for e in analysis.edges() if e.get("type") == "POOL_UNAUTH_ROLE"]
    assert S.edges_linking(edges, on_id, S.iam_arn("role", "demo-unauth-on"))
    assert S.edges_linking(edges, off_id, S.iam_arn("role", "demo-unauth-off")) == []


# ── F-051 (engine side): Glue jobs get real ARNs ─────────────────────────────
@pytest.mark.finding("F-051")
def test_f051_arn_scoped_glue_grant_reaches_a_bare_name_job(tmp_path):
    s, iam = _tree(tmp_path)
    iam.role("demo-glue-role", rb.trust({"Service": "glue.amazonaws.com"}))
    iam.user("demo-etl-dev", inline={"p": [rb.allow(["glue:UpdateJob", "glue:StartJobRun"],
                                                     f"arn:aws:glue:{R}:{ACCT}:job/*")]})
    iam.write(s)
    s.write("glue/resources.json", [rb.compute_resource("gluejob", "demo-etl-job", "demo-etl-job",
                                                        [iam.arn("role", "demo-glue-role")])])
    edges = S.analyze_tree(_finish(s)).edges("compute")
    assert S.edges_from(edges, S.iam_arn("user", "demo-etl-dev"), "demo-etl-job", types=["CAN_MODIFY"])


@pytest.mark.finding("F-051")
def test_f051_same_named_glue_jobs_in_two_regions_stay_separate(tmp_path):
    g = rb.Scope(tmp_path, ACCT, "global")
    iam = rb.Iam(ACCT)
    for name in ("demo-glue-role-a", "demo-glue-role-b"):
        iam.role(name, rb.trust({"Service": "glue.amazonaws.com"}))
    iam.write(g)
    g.write("s3/buckets.json", [])
    for region, role in ((R1, "demo-glue-role-a"), (R, "demo-glue-role-b")):
        r = rb.Scope(tmp_path, ACCT, region)
        rb.write_empty_regional(r, skip={"glue"})
        r.write("glue/resources.json", [rb.compute_resource("gluejob", "demo-etl-job", "demo-etl-job",
                                                            [iam.arn("role", role)])])
    rb.write_manifest(tmp_path / ACCT, account=ACCT, mode="all_regions", region=None, regions=[R1, R])
    edges = [e for e in S.analyze_tree(tmp_path / ACCT).edges("compute") if e.get("type") == "USES_ROLE"]
    sources = {name: {e.get("source") for e in edges if S.refers(e.get("target"), S.iam_arn("role", name))}
               for name in ("demo-glue-role-a", "demo-glue-role-b")}
    assert all(len(v) == 1 for v in sources.values()), sources
    assert sources["demo-glue-role-a"] != sources["demo-glue-role-b"], sources


# ── F-055 (engine side): alias-qualified URLs and policies ───────────────────
@pytest.mark.finding("F-055")
def test_f055_alias_function_url_is_attached_to_the_base_function(tmp_path):
    s, iam = _tree(tmp_path)
    iam.role("demo-fn-role", rb.trust({"Service": "lambda.amazonaws.com"}))
    iam.write(s)
    fn = rb.lambda_function("demo-alias-fn", account=ACCT, region=R, role=iam.arn("role", "demo-fn-role"))
    fn["FunctionUrl"] = None                                   # no URL on the unqualified function
    fn["FunctionUrls"] = [{"Qualifier": "live", "FunctionUrl": "https://demo-alias.lambda-url.eu-west-2.on.aws/",
                           "AuthType": "NONE", "InvokeMode": "BUFFERED", "CorsAllowOrigins": []}]
    s.write("lambda/functions.json", [fn])
    s.write("lambda/resource_policies/demo-alias-fn-live.json", {
        "FunctionArn": fn["FunctionArn"], "FunctionName": fn["FunctionName"], "Qualifier": "live",
        "ResourcePolicy": rb.resource_policy(rb.grant("*", "lambda:InvokeFunctionUrl", fn["FunctionArn"] + ":live",
                                                      {"StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}}))})
    findings = S.analyze_tree(_finish(s)).findings()
    url = S.findings_for(findings, "LAMBDA-URL-001", fn["FunctionArn"]) or S.findings_for(
        findings, "LAMBDA-URL-001", "demo-alias-fn")
    assert url, sorted({i for f in findings for i in S.finding_ids(f)})
    assert not S.findings_for(findings, subject=fn["FunctionArn"] + ":live")   # never a separate alias node
