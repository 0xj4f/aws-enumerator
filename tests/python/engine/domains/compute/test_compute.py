"""Compute analyzer (analyzers/compute.py, loader io/loaders/compute.py): ECS, CloudFormation, Glue, CodeBuild,
SageMaker on the policy evaluator.

Covers F-004 (per-action table: CAN_HIJACK / CAN_EXEC only for complete chains, PassRole where AWS needs it,
CAN_MODIFY info otherwise, ECS EXECUTION_ROLE), F-049 (one ECS node per family and role set), F-051 (real Glue
ARNs, no bare-name branch), F-113 (SageMaker Studio, ECS Exec, CodeBuild webhooks, StackSets, Glue sessions and
SageMaker jobs), F-001/F-014 (evaluator decisions) and request c-b-1 (``Roles: null`` = unknown).
"""

from __future__ import annotations

import importlib

import pytest

K = importlib.import_module("tests.fixtures.e-compute.kit")
rb = K.rb
R, A = K.REGION, K.ACCT


def _role(t, name, service, admin=True):
    t.iam.role(name, rb.trust({"Service": f"{service}.amazonaws.com"}),
               attached=["AdministratorAccess"] if admin else [])
    return K.iam_arn("role", name)


def _ecs(family, task, execution, revisions=(3,), region=R):
    newest = max(revisions)
    return rb.compute_resource("ecstask", f"arn:aws:ecs:{region}:{A}:task-definition/{family}:{newest}", family,
                               [task] if task else [], Family=family, TaskRole=task, ExecutionRole=execution,
                               Revisions=list(revisions), RevisionsTruncated=False)


# ── F-004: ECS ───────────────────────────────────────────────────────────────

@pytest.mark.finding("F-004")
def test_run_task_needs_passrole_of_the_task_and_execution_roles(tmp_path):
    t = K.LegacyTree(tmp_path)
    task, execution = _role(t, "demo-task-role", "ecs-tasks"), _role(t, "demo-exec-role", "ecs-tasks")
    ecs_ctx = {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}}
    t.iam.user("demo-runner", inline={"p": [rb.allow("ecs:RunTask", "*"),
                                            rb.allow("iam:PassRole", [task, execution], ecs_ctx)]})
    t.iam.user("demo-half", inline={"p": [rb.allow("ecs:RunTask", "*"), rb.allow("iam:PassRole", task)]})
    t.iam.user("demo-no-pass", inline={"p": [rb.allow(["ecs:RegisterTaskDefinition", "ecs:RunTask"], "*")]})
    t.iam.user("demo-wrong-svc", inline={"p": [rb.allow("ecs:RunTask", "*"), rb.allow(
        "iam:PassRole", "*", {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}})]})
    t.put("ecs/resources.json", [_ecs("demo-app", task, execution)])
    g = t.analyze().graph
    assert K.problems(g) == []
    node = f"arn:aws:ecs:{R}:{A}:task-definition/demo-app"
    hijack = K.only(K.edges(g, "CAN_HIJACK", K.iam_arn("user", "demo-runner"), node))
    assert hijack["evidence"]["passrole_roles"] == sorted([task, execution])
    assert K.path(g, K.iam_arn("user", "demo-runner"), task) is not None
    for name in ("demo-half", "demo-no-pass", "demo-wrong-svc"):
        user = K.iam_arn("user", name)
        assert K.edge_types(g, user, node) == {"CAN_MODIFY"}, name
        assert K.only(K.edges(g, "CAN_MODIFY", user, node))["traversable"] is False
    exec_edge = K.only(K.edges(g, "EXECUTION_ROLE", node, execution))
    assert exec_edge["traversable"] is False
    assert not K.edges(g, "USES_ROLE", node, execution)


@pytest.mark.finding("F-004", "F-049")
def test_d13c215_ecs_records_split_the_execution_role(tmp_path):
    """Old reports put the task and execution roles in ``Roles``; the managed execution policy tells them apart."""
    t = K.LegacyTree(tmp_path)
    task = _role(t, "demo-task-role", "ecs-tasks")
    t.iam.role("ecsTaskExecutionRole", rb.trust({"Service": "ecs-tasks.amazonaws.com"}))
    execution = K.iam_arn("role", "ecsTaskExecutionRole")
    legacy = [rb.compute_resource("ecstask", f"arn:aws:ecs:{R}:{A}:task-definition/demo-app:{n}", "demo-app",
                                  [task, execution]) for n in (1, 2, 3)]
    t.put("ecs/resources.json", legacy)
    g = t.analyze().graph
    node = K.only(n for n in K.nodes(g).values() if n["type"] == "ecstask")
    assert node["id"] == f"arn:aws:ecs:{R}:{A}:task-definition/demo-app"
    assert node["props"]["revisions"] == [1, 2, 3]
    assert K.edges(g, "USES_ROLE", node["id"], task) and K.edges(g, "EXECUTION_ROLE", node["id"], execution)


# ── F-049: one node per (family, role set) ───────────────────────────────────

@pytest.mark.finding("F-049")
def test_one_node_per_family_and_role_set_with_revisions_as_props(tmp_path):
    t = K.LegacyTree(tmp_path)
    a, b = _role(t, "demo-role-a", "ecs-tasks"), _role(t, "demo-role-b", "ecs-tasks")
    t.iam.user("demo-ops", inline={"p": [rb.allow(["ecs:*", "iam:PassRole"], "*")]})
    t.put("ecs/resources.json", [_ecs("demo-web", a, None, revisions=(1, 2, 3, 4, 5)),
                                 _ecs("demo-web", b, None, revisions=(6,)),
                                 _ecs("demo-batch", a, None, revisions=(9,))])
    g = t.analyze().graph
    tasks = {n["id"]: n for n in K.nodes(g).values() if n["type"] == "ecstask"}
    assert len(tasks) == 3
    web = sorted(i for i in tasks if "/demo-web" in i)
    assert len(web) == 2 and all("?roles=" in i for i in web)                  # two role sets: hashed suffix
    assert f"arn:aws:ecs:{R}:{A}:task-definition/demo-batch" in tasks         # one role set: no suffix
    assert sorted(tasks[i]["props"]["revisions"] for i in web) == [[1, 2, 3, 4, 5], [6]]
    ops = K.iam_arn("user", "demo-ops")
    assert len(K.edges(g, "CAN_HIJACK", source=ops)) == 3                      # one edge per node, not per revision


# ── F-004 / F-113: the other compute surfaces ────────────────────────────────

@pytest.mark.finding("F-004", "F-113")
def test_existing_resource_chains_per_action(tmp_path):
    t = K.LegacyTree(tmp_path)
    build, glue, stack, nb = (_role(t, "demo-build-role", "codebuild"), _role(t, "demo-glue-role", "glue"),
                              _role(t, "demo-stack-role", "cloudformation"), _role(t, "demo-nb-role", "sagemaker"))
    project, job = f"arn:aws:codebuild:{R}:{A}:project/demo-build", f"arn:aws:glue:{R}:{A}:job/demo-etl"
    endpoint = f"arn:aws:glue:{R}:{A}:devEndpoint/demo-dev"
    cfn, notebook = f"arn:aws:cloudformation:{R}:{A}:stack/demo-stack/1a2b", \
        f"arn:aws:sagemaker:{R}:{A}:notebook-instance/demo-nb"
    t.iam.user("demo-builder", inline={"p": [rb.allow("codebuild:StartBuild", project)]})
    t.iam.user("demo-glue", inline={"p": [rb.allow(["glue:UpdateJob", "glue:StartJobRun", "iam:PassRole"], "*")]})
    t.iam.user("demo-glue-no-pass", inline={"p": [rb.allow(["glue:UpdateJob", "glue:StartJobRun"], "*")]})
    t.iam.user("demo-ssh", inline={"p": [rb.allow("glue:UpdateDevEndpoint", endpoint)]})
    t.iam.user("demo-cfn", inline={"p": [rb.allow("cloudformation:UpdateStack", cfn)]})
    t.iam.user("demo-cfn-delete", inline={"p": [rb.allow("cloudformation:DeleteStack", cfn)]})
    t.iam.user("demo-nb", inline={"p": [rb.allow("sagemaker:CreatePresignedNotebookInstanceUrl", notebook)]})
    t.iam.user("demo-creator", inline={"p": [rb.allow(["codebuild:CreateProject", "glue:CreateJob",
                                                       "cloudformation:CreateStack"], "*")]})
    t.put("codebuild/resources.json", [rb.compute_resource("codebuild", project, "demo-build", [build])])
    t.put("glue/resources.json", [rb.compute_resource("gluejob", job, "demo-etl", [glue], Kind="job"),
                                  rb.compute_resource("gluejob", endpoint, "demo-dev", [glue], Kind="dev_endpoint")])
    t.put("cloudformation/resources.json", [rb.compute_resource("cfnstack", cfn, "demo-stack", [stack])])
    t.put("sagemaker/resources.json", [rb.compute_resource("sagemaker", notebook, "demo-nb", [nb], Kind="notebook")])
    g = t.analyze().graph
    assert K.problems(g) == []
    u = {n: K.iam_arn("user", n) for n in ("demo-builder", "demo-glue", "demo-glue-no-pass", "demo-ssh", "demo-cfn",
                                            "demo-cfn-delete", "demo-nb", "demo-creator")}
    assert K.edge_types(g, u["demo-builder"], project) == {"CAN_HIJACK"}            # buildspec override
    assert K.edge_types(g, u["demo-glue"], job) == {"CAN_HIJACK"}
    assert K.edge_types(g, u["demo-glue-no-pass"], job) == {"CAN_MODIFY"}           # UpdateJob re-passes the role
    assert K.edge_types(g, u["demo-ssh"], endpoint) == {"CAN_HIJACK"}
    assert K.nodes(g)[endpoint]["type"] == "gluedevendpoint"
    assert K.edge_types(g, u["demo-cfn"], cfn) == {"CAN_HIJACK"}                    # the stack keeps its role
    assert K.edge_types(g, u["demo-cfn-delete"], cfn) == {"CAN_MODIFY"}
    assert K.edge_types(g, u["demo-nb"], notebook) == {"CAN_EXEC"}
    for res in (project, job, cfn):                                                 # Create* is never an edge
        assert not K.edges(g, source=u["demo-creator"], target=res)
    for user, role in ((u["demo-builder"], build), (u["demo-glue"], glue), (u["demo-cfn"], stack),
                       (u["demo-nb"], nb), (u["demo-ssh"], glue)):
        assert K.path(g, user, role) is not None, user
    for user in (u["demo-glue-no-pass"], u["demo-cfn-delete"], u["demo-creator"]):
        assert K.path(g, user, glue) is None and K.path(g, user, stack) is None


@pytest.mark.finding("F-113")
def test_sagemaker_studio_profiles_domains_and_sso(tmp_path, monkeypatch):
    """compute.py alone (the rules runner's own PRIVESC-056 edges are E-rules', see requests/e-compute-3.md)."""
    K.without_analyzer_modules(monkeypatch, ".rules.runner")
    t = K.LegacyTree(tmp_path)
    prof_role = _role(t, "demo-profile-role", "sagemaker", admin=False)
    dom_role = _role(t, "demo-domain-role", "sagemaker", admin=False)
    sso_role = _role(t, "demo-sso-role", "sagemaker", admin=False)
    domain, sso = f"arn:aws:sagemaker:{R}:{A}:domain/d-aaaa1111", f"arn:aws:sagemaker:{R}:{A}:domain/d-bbbb2222"
    profile = f"arn:aws:sagemaker:{R}:{A}:user-profile/d-aaaa1111/demo-alice"
    sso_profile = f"arn:aws:sagemaker:{R}:{A}:user-profile/d-bbbb2222/demo-bob"
    t.iam.user("demo-presign", inline={"p": [rb.allow("sagemaker:CreatePresignedDomainUrl", "*")]})
    t.iam.user("demo-onboard", inline={"p": [rb.allow(["sagemaker:CreateUserProfile",
                                                       "sagemaker:CreatePresignedDomainUrl"],
                                                      f"arn:aws:sagemaker:{R}:{A}:user-profile/d-aaaa1111/*")]})
    t.put("sagemaker/resources.json", [
        rb.compute_resource("sagemakerdomain", domain, "demo-domain", [dom_role], Kind="domain", DomainId="d-aaaa1111",
                            AuthMode="IAM", DefaultUserRole=dom_role),
        rb.compute_resource("sagemakerdomain", sso, "demo-sso", [sso_role], Kind="domain", DomainId="d-bbbb2222",
                            AuthMode="SSO"),
        rb.compute_resource("sagemakerdomain", profile, "demo-alice", [prof_role], Kind="user_profile",
                            DomainId="d-aaaa1111", ExecutionRole=prof_role, InheritsDomainRole=False),
        rb.compute_resource("sagemakerdomain", sso_profile, "demo-bob", [sso_role], Kind="user_profile",
                            DomainId="d-bbbb2222", InheritsDomainRole=True)])
    g = t.analyze().graph
    assert K.problems(g) == []
    presign, onboard = K.iam_arn("user", "demo-presign"), K.iam_arn("user", "demo-onboard")
    assert K.edge_types(g, presign, profile) == {"CAN_EXEC"}
    assert K.path(g, presign, prof_role) is not None
    assert not K.edges(g, "CAN_EXEC", presign, sso_profile)                       # SSO domains: no presigned URL
    assert K.path(g, presign, sso_role) is None
    assert K.edge_types(g, onboard, domain) == {"CAN_HIJACK"}                     # new profile, default role
    assert K.path(g, onboard, dom_role) is not None
    assert K.nodes(g)[sso]["props"]["auth_mode"] == "SSO"


@pytest.mark.finding("F-113", "F-004")
def test_rules_never_enter_a_profile_of_an_sso_domain(tmp_path):
    """With the rules runner too (request e-compute-3): PRIVESC-056 skips profiles of SSO-auth Studio domains, so the
    compute analyzer and the rules agree that a presigned domain URL cannot enter them."""
    t = K.LegacyTree(tmp_path)
    prof_role = _role(t, "demo-profile-role", "sagemaker", admin=False)
    sso_role = _role(t, "demo-sso-role", "sagemaker", admin=False)
    sso = f"arn:aws:sagemaker:{R}:{A}:domain/d-bbbb2222"
    profile = f"arn:aws:sagemaker:{R}:{A}:user-profile/d-aaaa1111/demo-alice"
    sso_profile = f"arn:aws:sagemaker:{R}:{A}:user-profile/d-bbbb2222/demo-bob"
    t.iam.user("demo-presign", inline={"p": [rb.allow("sagemaker:CreatePresignedDomainUrl", "*")]})
    t.put("sagemaker/resources.json", [
        rb.compute_resource("sagemakerdomain", f"arn:aws:sagemaker:{R}:{A}:domain/d-aaaa1111", "demo-domain",
                            [prof_role], Kind="domain", DomainId="d-aaaa1111", AuthMode="IAM"),
        rb.compute_resource("sagemakerdomain", sso, "demo-sso", [sso_role], Kind="domain", DomainId="d-bbbb2222",
                            AuthMode="SSO"),
        rb.compute_resource("sagemakerdomain", profile, "demo-alice", [prof_role], Kind="user_profile",
                            DomainId="d-aaaa1111", ExecutionRole=prof_role, InheritsDomainRole=False),
        rb.compute_resource("sagemakerdomain", sso_profile, "demo-bob", [sso_role], Kind="user_profile",
                            DomainId="d-bbbb2222", InheritsDomainRole=True)])
    g = t.analyze().graph
    assert K.problems(g) == []
    presign = K.iam_arn("user", "demo-presign")
    assert not K.edges(g, "CAN_EXEC", presign, sso_profile)
    assert K.path(g, presign, sso_role) is None
    assert K.edges(g, "CAN_EXEC", presign, profile)                     # the IAM-auth domain's profile still is


@pytest.mark.finding("F-113")
def test_ecs_exec_into_services_and_unknown_exec_flag(tmp_path):
    t = K.LegacyTree(tmp_path)
    task = _role(t, "demo-task-role", "ecs-tasks")
    cluster = f"arn:aws:ecs:{R}:{A}:cluster/demo-cluster"
    t.iam.user("demo-shell", inline={"p": [rb.allow("ecs:ExecuteCommand", "*")]})
    t.put("ecs/resources.json", [_ecs("demo-app", task, None, revisions=(4,))])
    services = []
    for name, flag in (("demo-on", True), ("demo-off", False), ("demo-unknown", None)):
        services.append({"ClusterArn": cluster, "ServiceArn": f"arn:aws:ecs:{R}:{A}:service/demo-cluster/{name}",
                         "Name": name, "TaskDefinition": f"arn:aws:ecs:{R}:{A}:task-definition/demo-app:4",
                         "EnableExecuteCommand": flag, "LaunchType": "FARGATE"})
    t.put("ecs/services.json", services)
    g = t.analyze().graph
    assert K.problems(g) == []
    shell = K.iam_arn("user", "demo-shell")
    svc = {n: f"arn:aws:ecs:{R}:{A}:service/demo-cluster/{n}" for n in ("demo-on", "demo-off", "demo-unknown")}
    on = K.only(K.edges(g, "CAN_EXEC", shell, svc["demo-on"]))
    assert on["confidence"] == "definite" and K.path(g, shell, task) is not None
    assert K.edge_types(g, shell, svc["demo-off"]) == {"CAN_MODIFY"}
    unknown = K.only(K.edges(g, "CAN_EXEC", shell, svc["demo-unknown"]))
    assert unknown["confidence"] == "conditional"
    assert "ecs:enable-execute-command-unknown" in unknown["evidence"]["gaps"]
    assert K.edges(g, "USES_ROLE", svc["demo-on"], task)


@pytest.mark.finding("F-113")
def test_stacksets_need_passrole_and_new_compute_passrole_surfaces(tmp_path):
    t = K.LegacyTree(tmp_path)
    admin_role = _role(t, "demo-stackset-admin", "cloudformation")
    glue_role, sm_role = _role(t, "demo-glue-svc", "glue"), _role(t, "demo-sm-svc", "sagemaker")
    stackset = f"arn:aws:cloudformation:{R}:{A}:stackset/demo-set:1234"
    t.iam.user("demo-set-pass", inline={"p": [rb.allow(["cloudformation:UpdateStackSet", "iam:PassRole"], "*")]})
    t.iam.user("demo-set", inline={"p": [rb.allow("cloudformation:UpdateStackSet", "*")]})
    t.iam.user("demo-session", inline={"p": [rb.allow(["glue:CreateSession", "glue:RunStatement"], "*"),
                                             rb.allow("iam:PassRole", glue_role)]})
    t.iam.user("demo-trainer", inline={"p": [rb.allow("sagemaker:CreateTrainingJob", "*"),
                                             rb.allow("iam:PassRole", sm_role)]})
    t.put("cloudformation/resources.json", [rb.compute_resource(
        "stackset", stackset, "demo-set", [admin_role], AdministrationRoleARN=admin_role,
        ExecutionRoleName="AWSCloudFormationStackSetExecutionRole", PermissionModel="SELF_MANAGED")])
    g = t.analyze().graph
    assert K.problems(g) == []
    assert K.edge_types(g, K.iam_arn("user", "demo-set-pass"), stackset) == {"CAN_HIJACK"}
    assert K.edge_types(g, K.iam_arn("user", "demo-set"), stackset) == {"CAN_MODIFY"}
    session = K.only(K.edges(g, "CAN_PASS_ROLE_TO", K.iam_arn("user", "demo-session"), glue_role))
    assert "glue-interactive-session" in str(session["evidence"])
    assert K.edges(g, "CAN_PASS_ROLE_TO", K.iam_arn("user", "demo-trainer"), sm_role)


@pytest.mark.finding("F-113")
def test_codebuild_webhook_findings(tmp_path):
    t = K.LegacyTree(tmp_path)
    role = _role(t, "demo-build-role", "codebuild")
    pr_hook = {"Url": "https://example.invalid", "BuildType": "BUILD", "FilterGroups": [
        [{"type": "EVENT", "pattern": "PULL_REQUEST_CREATED,PULL_REQUEST_UPDATED"}]]}
    actor_hook = {"BuildType": "BUILD", "FilterGroups": [
        [{"type": "EVENT", "pattern": "PULL_REQUEST_CREATED"}, {"type": "ACTOR_ACCOUNT_ID", "pattern": "12345"}]]}
    projects = []
    for name, hook in (("demo-pr", pr_hook), ("demo-actor", actor_hook), ("demo-none", None)):
        projects.append(rb.compute_resource("codebuild", f"arn:aws:codebuild:{R}:{A}:project/{name}", name, [role],
                                            Webhook=hook, Source={"Type": "GITHUB"}))
    t.put("codebuild/resources.json", projects)
    g = t.analyze().graph
    hooks = {f["node_id"].rsplit("/", 1)[1]: f for f in K.findings(g, "CODEBUILD-WEBHOOK-001")}
    assert set(hooks) == {"demo-pr", "demo-actor"}
    assert hooks["demo-pr"]["severity"] == "MEDIUM" and hooks["demo-actor"]["severity"] == "LOW"
    assert role in hooks["demo-pr"]["related_node_ids"]


# ── F-051: Glue ARNs ─────────────────────────────────────────────────────────

@pytest.mark.finding("F-051")
def test_bare_glue_names_get_real_partition_aware_arns():
    loader = K.engine("io.loaders.compute")
    job = loader.normalise_glue({"Type": "gluejob", "Arn": "demo-etl", "Name": "demo-etl"},
                                partition="aws-us-gov", region="us-gov-west-1", account=A)
    assert job["Arn"] == f"arn:aws-us-gov:glue:us-gov-west-1:{A}:job/demo-etl" and job["ArnSynthesised"] is True
    dev = loader.normalise_glue({"Type": "gluejob", "Kind": "dev_endpoint", "Arn": "demo-dev", "Name": "demo-dev"},
                                partition="aws", region=R, account=A)
    assert dev["Arn"] == f"arn:aws:glue:{R}:{A}:devEndpoint/demo-dev" and dev["Type"] == "gluedevendpoint"
    real = loader.normalise_glue({"Type": "gluejob", "Arn": f"arn:aws:glue:{R}:{A}:job/x", "Name": "x"},
                                 partition="aws", region=R, account=A)
    assert "ArnSynthesised" not in real


@pytest.mark.finding("F-051")
def test_arn_scoped_glue_grant_matches_a_d13c215_bare_name_job(tmp_path):
    t = K.LegacyTree(tmp_path)
    role = _role(t, "demo-glue-role", "glue")
    t.iam.user("demo-etl", inline={"p": [rb.allow(["glue:UpdateJob", "glue:StartJobRun", "iam:PassRole"],
                                                  [f"arn:aws:glue:{R}:{A}:job/*", role])]})
    t.put("glue/resources.json", [rb.compute_resource("gluejob", "demo-job", "demo-job", [role])])
    g = t.analyze().graph
    job = f"arn:aws:glue:{R}:{A}:job/demo-job"
    assert K.nodes(g)[job]["props"]["arn_synthesised"] is True
    assert K.edge_types(g, K.iam_arn("user", "demo-etl"), job) == {"CAN_HIJACK"}


# ── c-b-1: null = unknown ────────────────────────────────────────────────────

@pytest.mark.finding("F-059")
def test_unknown_roles_are_a_coverage_gap_not_no_role(tmp_path):
    t = K.LegacyTree(tmp_path)
    t.iam.user("demo-builder", inline={"p": [rb.allow("codebuild:StartBuild", "*")]})
    project = f"arn:aws:codebuild:{R}:{A}:project/demo-unknown"
    rec = rb.mark_item(rb.compute_resource("codebuild", project, "demo-unknown", []),
                       rb.collection_error("codebuild:BatchGetProjects", "error"), unknown=["Roles"])
    ecs = rb.mark_item(_ecs("demo-app", None, None), rb.collection_error("ecs:DescribeTaskDefinition"),
                       unknown=["Roles", "TaskRole", "ExecutionRole"])
    stackset = rb.mark_item(rb.compute_resource("stackset", f"arn:aws:cloudformation:{R}:{A}:stackset/demo:1",
                                                "demo", []), rb.collection_error("cloudformation:DescribeStackSet"),
                            unknown=["Roles"])
    t.put("codebuild/resources.json", [rec])
    t.put("ecs/resources.json", [ecs])
    t.put("cloudformation/resources.json", [stackset])
    g = t.analyze().graph
    assert K.problems(g) == []
    node = K.nodes(g)[project]
    assert node["coverage"]["status"] == "partial"
    assert {"codebuild:roles-unknown", "codebuild:BatchGetProjects:error"} <= set(node["coverage"]["gaps"])
    assert not K.edges(g, "USES_ROLE", project)
    task = K.nodes(g)[f"arn:aws:ecs:{R}:{A}:task-definition/demo-app"]
    assert task["coverage"]["status"] == "partial" and "ecs:roles-unknown" in task["coverage"]["gaps"]
