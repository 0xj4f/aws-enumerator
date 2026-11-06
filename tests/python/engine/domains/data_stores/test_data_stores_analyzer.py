"""Data-stores analyzer (E-data): ECR, DynamoDB, RDS and API Gateway."""

from __future__ import annotations

import importlib
import inspect

import pytest

K = importlib.import_module("tests.fixtures.e-data.kit")
rb = K.rb
ROLE = K.iam_arn
FN = f"arn:aws:lambda:{K.REGION}:{K.ACCT}:function:demo-api-fn"


def _run(tmp_path, files, *, setup=None, iam=True, regions=(K.REGION,)):
    """A v2 run with ``files`` = {(unit, rel): data}; ``iam=False`` collects no IAM data (no evaluator)."""
    run = K.Run(tmp_path, regions=regions)
    if setup is not None:
        setup(run.iam)
    for (unit, rel), data in files.items():
        run.write_json(unit, rel, data)
    if iam:
        run.finish()
    else:
        run.v2.finalize()
    res = run.analyze()
    assert K.problems(res.graph) == []
    assert K.statuses(res.result).get("data_stores") == "ok"
    return res


def _ddb(name, policy=None, **kw):
    return K.v2_policy_resource("dynamodb", name, policy=policy, **kw)


def _ecr(name, policy=None, **kw):
    return K.v2_policy_resource("ecr", name, policy=policy, **kw)


# ── F-031: one shared resource-policy walker (D-39) ──────────────────────────

@pytest.mark.finding("F-031", "F-037")
def test_table_policies_are_graded_by_what_an_outsider_can_satisfy(tmp_path):
    q = "dynamodb:Query"
    org = {"StringEquals": {"aws:PrincipalOrgID": "o-a1b2c3"}}
    partner = f"arn:aws:iam::{K.FOREIGN}:root"
    cases = {
        "a-tls": rb.resource_policy(rb.grant("*", q, cond={"Bool": {"aws:SecureTransport": "true"}})),
        "b-org": rb.resource_policy(rb.grant("*", q, cond=org)),
        "c-guard": rb.resource_policy(rb.grant("*", q), {"Effect": "Deny", "Principal": "*", "Action": "*",
                                                         "Resource": "*",
                                                         "Condition": {"StringNotEquals": {"aws:PrincipalOrgID":
                                                                                           "o-a1b2c3"}}}),
        "d-notprincipal": rb.resource_policy({"Effect": "Allow", "NotPrincipal": {"AWS": partner}, "Action": q,
                                              "Resource": "*"}),
        "e-partner": rb.resource_policy(rb.grant({"AWS": partner}, q)),
        "f-sourcearn": rb.resource_policy(rb.grant("*", q, cond={"ArnLike": {"aws:SourceArn": "*"}})),
        "g-ip": rb.resource_policy(rb.grant("*", q, cond={"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}})),
    }
    tables = [_ddb(f"demo-{k}", v) for k, v in cases.items()]
    res = _run(tmp_path, {(K.REGION, "dynamodb/resources.json"): tables})
    arn = {k: t["Arn"] for k, t in zip(cases, tables, strict=True)}
    public = {k for k in cases if K.findings(res.graph, "DDB-PUB-001", arn[k])}
    assert public == {"a-tls", "d-notprincipal", "f-sourcearn"}
    assert {k for k in cases if K.edges(res.graph, "DDB_GRANTS_PUBLIC", K.ANON, arn[k])} == public
    assert K.nodes_by_id(res.graph)[arn["b-org"]]["props"]["public_grant"] == "restricted"
    assert K.findings(res.graph, "DDB-XACCT-001", arn["e-partner"])
    assert K.edges(res.graph, "DDB_GRANTS_CROSS_ACCOUNT", partner, arn["e-partner"])


@pytest.mark.finding("F-031")
def test_the_private_walker_and_its_legacy_alias_are_gone(tmp_path):
    ds = K.engine("analyzers.data_stores")
    source = inspect.getsource(ds)
    assert "_extract_principals" not in source and "stmt.get('Effect')" not in source
    assert not hasattr(ds, "_resource_policy_grants")             # the D-39 alias was removed in Wave 3 (D-53)
    guarded = rb.resource_policy(rb.grant("*", "ecr:BatchGetImage"), {
        "Effect": "Deny", "Principal": "*", "Action": "*", "Resource": "*",
        "Condition": {"StringNotEquals": {"aws:PrincipalOrgID": "o-a1b2c3"}}})
    single = {"Statement": {"Effect": "Allow", "Principal": "*", "Action": "ecr:BatchGetImage", "Resource": "*"}}
    repos = [_ecr("demo-guarded", guarded), _ecr("demo-open", single)]
    res = _run(tmp_path, {(K.REGION, "ecr/resources.json"): repos})
    flagged = sorted(f["node_id"].rsplit("/", 1)[-1] for f in K.findings(res.graph, "ECR-PUB-001"))
    assert flagged == ["demo-open"]          # d13c215 reported the org-guarded policy HIGH public (case C)
    assert K.edges(res.graph, "ECR_GRANTS_PUBLIC", K.ANON, repos[1]["Arn"])


# ── DynamoDB access (F-001, F-014) ───────────────────────────────────────────

@pytest.mark.finding("F-001", "F-014")
def test_table_access_edges_come_from_the_evaluator(tmp_path):
    table = _ddb("demo-orders", rb.resource_policy(rb.grant({"AWS": ROLE("role", "demo-named")}, "dynamodb:GetItem")))

    def setup(iam):
        iam.role("demo-partiql", K.EC2_TRUST, inline={"p": [rb.allow("dynamodb:PartiQLSelect", table["Arn"])]})
        iam.role("demo-writer", K.EC2_TRUST, inline={"p": [rb.allow("dynamodb:PutItem", "*")]})
        iam.role("demo-denied", K.EC2_TRUST, inline={"p": [rb.allow("dynamodb:*", "*"),
                                                             rb.deny("dynamodb:*", table["Arn"])]})
        iam.role("demo-describe", K.EC2_TRUST, inline={"p": [rb.allow("dynamodb:DescribeTable", "*")]})
        iam.role("demo-named", K.EC2_TRUST)

    res = _run(tmp_path, {(K.REGION, "dynamodb/resources.json"): [table]}, setup=setup)
    arn = table["Arn"]
    assert K.types_between(res.graph, ROLE("role", "demo-partiql"), arn) == ["CAN_READ_TABLE"]
    assert K.types_between(res.graph, ROLE("role", "demo-writer"), arn) == ["CAN_WRITE_TABLE"]
    assert K.types_between(res.graph, ROLE("role", "demo-denied"), arn) == []
    assert K.types_between(res.graph, ROLE("role", "demo-describe"), arn) == []
    assert K.types_between(res.graph, ROLE("role", "demo-named"), arn) == ["CAN_READ_TABLE"]   # resource policy


# ── ECR (F-116) ──────────────────────────────────────────────────────────────

@pytest.mark.finding("F-116", "F-059")
def test_ecr_repositories_and_the_registry_policy(tmp_path):
    partner = f"arn:aws:iam::{K.FOREIGN}:root"
    repos = [_ecr("demo-public", rb.resource_policy(rb.grant("*", ["ecr:BatchGetImage",
                                                                   "ecr:GetDownloadUrlForLayer"]))),
             _ecr("demo-partner", rb.resource_policy(rb.grant({"AWS": partner}, "ecr:BatchGetImage"))),
             _ecr("demo-hidden", policy_status="denied")]
    registry_policy = {"RegistryId": K.ACCT, "PolicyStatus": "present", "Policy": rb.resource_policy(
        rb.grant({"AWS": partner}, ["ecr:ReplicateImage", "ecr:CreateRepository"],
                 f"arn:aws:ecr:{K.REGION}:{K.ACCT}:repository/*"))}
    registry = {"RegistryId": K.ACCT, "ReplicationRules": [
        {"Destinations": [{"Region": K.OTHER, "RegistryId": K.FOREIGN}, {"Region": K.OTHER, "RegistryId": K.ACCT}],
         "RepositoryFilters": []}]}
    res = _run(tmp_path, {(K.REGION, "ecr/resources.json"): repos, (K.REGION, "ecr/registry_policy.json"):
                          registry_policy, (K.REGION, "ecr/registry.json"): registry})
    arn = {r["Name"]: r["Arn"] for r in repos}
    assert K.findings(res.graph, "ECR-PUB-001", arn["demo-public"])
    assert K.edges(res.graph, "ECR_GRANTS_PUBLIC", K.ANON, arn["demo-public"])
    assert K.findings(res.graph, "ECR-XACCT-001", arn["demo-partner"])
    hidden = K.nodes_by_id(res.graph)[arn["demo-hidden"]]
    assert hidden["coverage"]["status"] == "partial" and hidden["props"]["policy_status"] == "denied"
    assert K.gaps(res.graph)["data-stores:resource-policy-unknown"]["count"] == 1
    anchor = f"aws-enumerator:region/{K.ACCT}/{K.REGION}"
    reg = K.findings(res.graph, "ECR-REGISTRY-001", anchor)
    assert reg and reg[0]["evidence"]["accounts"] == [K.FOREIGN] and reg[0]["severity"] == "MEDIUM"
    rep = K.findings(res.graph, "ECR-REPLICATION-001", anchor)
    assert rep and rep[0]["evidence"]["accounts"] == [K.FOREIGN]


@pytest.mark.finding("F-059")
def test_an_unreadable_registry_policy_is_a_gap(tmp_path):
    res = _run(tmp_path, {(K.REGION, "ecr/resources.json"): [],
                          (K.REGION, "ecr/registry_policy.json"): K.mark(
                              {"RegistryId": K.ACCT, "Policy": None}, K.denied("ecr:GetRegistryPolicy"),
                              policy_status="denied")})
    assert "ecr:registry-policy-unknown" in K.gaps(res.graph)
    assert K.findings(res.graph, "ECR-REGISTRY-001") == []


# ── RDS (F-056, F-027) ───────────────────────────────────────────────────────

@pytest.mark.finding("F-056")
def test_snapshot_sharing_public_and_cross_account(tmp_path):
    aws_key = K.v2_key(K.AWS_KEY_ID, manager="AWS", aliases=["alias/aws/rds"], policy_status="skipped")
    snaps = [K.rds_snapshot("demo-shared", shared=[K.FOREIGN, rb.ACCT_ALT]),
             K.rds_snapshot("demo-aurora", kind="cluster_snapshot", public=True),
             K.rds_snapshot("demo-managed-key", shared=[K.FOREIGN], encrypted=True,
                            kms_key=K.key_arn(K.AWS_KEY_ID)),
             K.rds_snapshot("demo-unknown", public=None, shared=None)]
    res = _run(tmp_path, {(K.REGION, "rds/resources.json"): snaps, (K.REGION, "kms/keys.json"): [aws_key]})
    arn = {s["Name"]: s["Arn"] for s in snaps}
    xacct = K.findings(res.graph, "RDS-XACCT-001", arn["demo-shared"])
    assert sorted(f["evidence"]["account"] for f in xacct) == sorted([K.FOREIGN, rb.ACCT_ALT])
    assert len({f["fingerprint"] for f in xacct}) == 2                     # discriminator: the target account
    for acct in (K.FOREIGN, rb.ACCT_ALT):
        edge = K.edges(res.graph, "RDS_SHARED_CROSS_ACCOUNT", f"arn:aws:iam::{acct}:root", arn["demo-shared"])
        assert edge and edge[0]["confidence"] == "definite" and edge[0]["traversable"]
    assert K.edges(res.graph, "RDS_SHARED_PUBLIC", K.ANON, arn["demo-aurora"])
    assert K.findings(res.graph, "RDS-SNAP-001", arn["demo-aurora"])
    managed = K.findings(res.graph, "RDS-XACCT-001", arn["demo-managed-key"])
    assert [f["severity"] for f in managed] == ["LOW"]                     # AWS-managed key: cannot be shared
    assert K.edges(res.graph, "RDS_ENCRYPTED_BY", arn["demo-managed-key"], K.key_arn(K.AWS_KEY_ID))
    unknown = K.nodes_by_id(res.graph)[arn["demo-unknown"]]
    assert unknown["coverage"]["status"] == "partial"
    assert {"rds:snapshot-public-unknown", "rds:snapshot-sharing-unknown"} <= set(unknown["coverage"]["gaps"])
    assert K.gaps(res.graph)["rds:snapshot-sharing-unknown"]["count"] == 1
    assert K.findings(res.graph, "RDS-SNAP-001", arn["demo-unknown"]) == []


@pytest.mark.finding("F-056", "F-059")
def test_databases_public_and_unencrypted(tmp_path):
    dbs = [K.rds_database("demo-public", public=True, encrypted=False),
           K.rds_database("demo-member", public=True, cluster="demo-cluster"),
           K.rds_database("demo-cluster", kind="cluster", public=True, members=["demo-member"]),
           K.rds_database("demo-serverless", kind="cluster", public=False, encrypted=False),
           K.rds_database("demo-unknown", public=None, encrypted=None)]
    res = _run(tmp_path, {(K.REGION, "rds/resources.json"): dbs})
    arn = {d["Name"]: d["Arn"] for d in dbs}
    pub = {n for n in arn if K.findings(res.graph, "RDS-PUB-001", arn[n])}
    assert pub == {"demo-public", "demo-member"}                           # the cluster is not flagged twice
    inbound = K.edges(res.graph, "PUBLIC_INBOUND", K.ANON, arn["demo-public"])
    assert inbound and inbound[0]["confidence"] == "conditional" and inbound[0]["traversable"] is False
    enc = {n for n in arn if K.findings(res.graph, "RDS-ENC-001", arn[n])}
    assert enc == {"demo-public", "demo-serverless"}
    assert K.nodes_by_id(res.graph)[arn["demo-unknown"]]["coverage"]["status"] == "partial"


# ── API Gateway (F-044, F-082, F-099) ────────────────────────────────────────

def _fn(name="demo-api-fn"):
    return K.rb.lambda_function(name, account=K.ACCT, region=K.REGION, role=ROLE("role", "demo-fn-role"))


@pytest.mark.finding("F-044")
def test_apigw_auth_001_only_for_lambda_routes_without_authentication(tmp_path):
    fn_b = FN.replace("demo-api-fn", "demo-admin-fn")
    apis = [K.v2_api("a1b2c3d4e5", name="demo-mixed", integrations=[
                K.integration("GET", "/health", FN), K.integration("POST", "/admin", fn_b, auth="AWS_IAM")]),
            K.v2_api("b2c3d4e5f6", name="demo-iam", integrations=[K.integration("GET", "/x", FN, auth="AWS_IAM")]),
            K.v2_api("c3d4e5f6a7", name="demo-private", endpoint_types=["PRIVATE"],
                     integrations=[K.integration("GET", "/x", FN)]),
            K.v2_api("d4e5f6a7b8", name="demo-restricted", resource_policy=rb.resource_policy(rb.grant(
                "*", "execute-api:Invoke", "execute-api:/*",
                cond={"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}})),
                     integrations=[K.integration("GET", "/x", FN)])]
    res = _run(tmp_path, {(K.REGION, "apigateway/resources.json"): apis,
                          (K.REGION, "lambda/functions.json"): [_fn()]})
    arn = {a["Name"]: a["Arn"] for a in apis}
    mixed = K.findings(res.graph, "APIGW-AUTH-001", arn["demo-mixed"])
    assert len(mixed) == 1 and mixed[0]["severity"] == "MEDIUM"
    assert [r["path"] for r in mixed[0]["evidence"]["routes"]] == ["/health"]
    assert K.findings(res.graph, "APIGW-AUTH-001", arn["demo-iam"]) == []
    assert [f["severity"] for f in K.findings(res.graph, "APIGW-AUTH-001", arn["demo-private"])] == ["LOW"]
    assert [f["severity"] for f in K.findings(res.graph, "APIGW-AUTH-001", arn["demo-restricted"])] == ["LOW"]
    inbound = {a: K.edges(res.graph, "PUBLIC_INBOUND", K.ANON, arn[a]) for a in arn}
    assert inbound["demo-mixed"][0]["props"]["auth"] == "none"
    assert inbound["demo-iam"] and "props" not in inbound["demo-iam"][0]
    assert inbound["demo-private"] == [] and inbound["demo-restricted"] == []


@pytest.mark.finding("F-044")
def test_legacy_reports_without_per_method_data(tmp_path):
    tree = K.Tree(tmp_path)
    tree.write_json("apigateway/resources.json", [
        {"Type": "apigw", "Arn": f"arn:aws:apigateway:{K.REGION}::/restapis/e5f6a7b8c9", "Name": "demo-noauth",
         "Protocol": "REST", "LambdaTargets": [FN], "HasAuthorizer": False},
        {"Type": "apigw", "Arn": f"arn:aws:apigateway:{K.REGION}::/restapis/f6a7b8c9d0", "Name": "demo-auth",
         "Protocol": "REST", "LambdaTargets": [FN], "HasAuthorizer": True}])
    tree.write(skip={"apigateway"})
    res = tree.analyze()
    assert K.problems(res.graph) == []
    flagged = K.findings(res.graph, "APIGW-AUTH-001")
    assert [f["node_id"].rsplit("/", 1)[-1] for f in flagged] == ["e5f6a7b8c9"]
    assert flagged[0]["confidence"] == "conditional"
    assert "apigateway:per-method-authorization-unknown" in flagged[0]["gaps"]
    assert K.gaps(res.graph)["apigateway:per-method-authorization-unknown"]["count"] == 2


@pytest.mark.finding("F-082", "F-099")
def test_invokes_targets_are_unqualified_with_qualifiers_and_unresolved_targets_as_props(tmp_path):
    other = FN.replace("demo-api-fn", "demo-uncollected")
    api = K.v2_api("a7b8c9d0e1", integrations=[
        K.integration("GET", "/live", FN, qualifier="live", stage="prod"),
        K.integration("GET", "/beta", FN, qualifier="7", stage="beta"),
        K.integration("GET", "/other", other, auth="AWS_IAM"),
        K.integration("GET", "/var", None, stage="prod", unresolved=True)])
    res = _run(tmp_path, {(K.REGION, "apigateway/resources.json"): [api],
                          (K.REGION, "lambda/functions.json"): [_fn()]})
    edge = K.edges(res.graph, "INVOKES", api["Arn"], FN)
    assert edge and edge[0]["props"] == {"qualifiers": ["7", "live"], "stages": ["beta", "prod"]}
    assert not [e for e in K.edges(res.graph, "INVOKES") if ":live" in e["target"] or "${" in e["target"]]
    placeholder = K.nodes_by_id(res.graph)[other]
    assert placeholder["props"].get("placeholder") is True and placeholder["coverage"]["status"] == "not-collected"
    node = K.nodes_by_id(res.graph)[api["Arn"]]
    assert node["props"]["unresolved_targets"] == [{"path": "/var", "route": "GET", "stage": "prod"}]


@pytest.mark.finding("F-059", "F-044")
def test_unknown_integrations_are_a_gap_not_a_clean_api(tmp_path):
    api = K.v2_api("b8c9d0e1f2", integrations=None)
    res = _run(tmp_path, {(K.REGION, "apigateway/resources.json"): [api]})
    node = K.nodes_by_id(res.graph)[api["Arn"]]
    assert node["coverage"]["status"] == "partial"
    assert "apigateway:per-method-authorization-unknown" in node["coverage"]["gaps"]
    assert K.findings(res.graph, "APIGW-AUTH-001") == []


# ── no evaluator, null safety, legacy entry points ───────────────────────────

@pytest.mark.finding("F-061", "F-031")
def test_without_iam_data_exposure_is_still_evaluated(tmp_path):
    table = _ddb("demo-open", rb.resource_policy(rb.grant("*", "dynamodb:Query")))
    res = _run(tmp_path, {(K.REGION, "dynamodb/resources.json"): [table]}, iam=False)
    assert "evaluator:unavailable" in K.gaps(res.graph)
    assert K.findings(res.graph, "DDB-PUB-001", table["Arn"])


@pytest.mark.finding("F-059", "F-002")
def test_every_nullable_field_null_at_once_is_survivable(tmp_path):
    """requests/c-b-1.md: the E-data analyzers read every ``|null`` field of the C-B collectors as unknown."""
    key = K.v2_key(aliases=None, grants=None, policy_status="error")
    for f in ("KeyManager", "KeyState", "MultiRegion", "KeyUsage"):
        key[f] = None
    api = K.v2_api("c9d0e1f2a3", integrations=None, endpoint_types=None)
    api.update({"Authorizers": None, "HasAuthorizer": None, "Stages": None})
    snap = K.rds_snapshot("demo-null", public=None, shared=None, encrypted=None)
    db = K.rds_database("demo-null-db", public=None, encrypted=None)
    db["Members"] = None
    files = {(K.REGION, "kms/keys.json"): [key], (K.REGION, "apigateway/resources.json"): [api],
             (K.REGION, "rds/resources.json"): [snap, db],
             (K.REGION, "ecr/resources.json"): [_ecr("demo-null", policy_status="error")],
             (K.REGION, "ecr/registry.json"): {"RegistryId": K.ACCT, "ReplicationRules": None},
             (K.REGION, "dynamodb/resources.json"): [_ddb("demo-null", policy_status="denied")],
             (K.REGION, "secretsmanager/secrets.json"): [K.v2_secret("demo/null", policy_status="error")],
             (K.REGION, "ssm/parameters.json"): [dict(K.v2_param("/demo/null"), Type=None, PolicyStatus=None)],
             (K.REGION, "ssm/documents.json"): [K.v2_document("demo-null", public=None, shared=None)]}
    res = _run(tmp_path, files)
    st = K.statuses(res.result)
    assert (st["kms"], st["secrets"], st["data_stores"]) == ("ok", "ok", "ok")
    assert "legacy:unknown-lists-as-empty" not in K.gaps(res.graph)      # native: no sanitised view needed


@pytest.mark.finding("F-082")
def test_an_old_report_layout_renders_unqualified_targets_in_graph_and_legacy_file(tmp_path):
    """Old (d13c215) report layouts stay analysable (``analyze <dir>``): the native analyzer, not a d13c215 entry
    point, writes ``newsurface_relationships.json`` from the graph."""
    tree = K.Tree(tmp_path)
    tree.iam.role("demo-fn-role", K.LAMBDA_TRUST)
    tree.write_json("apigateway/resources.json", [
        {"Type": "apigw", "Arn": f"arn:aws:apigateway:{K.REGION}::/apis/a1b2c3d4e5", "Name": "demo-alias-api",
         "Protocol": "HTTP", "LambdaTargets": [FN + ":live"], "HasAuthorizer": True}])
    tree.write(skip={"apigateway"})
    res = tree.analyze()
    assert K.statuses(res.result)["data_stores"] == "ok" and K.problems(res.graph) == []
    assert K.edges(res.graph, "INVOKES", f"arn:aws:apigateway:{K.REGION}::/apis/a1b2c3d4e5", FN)
    legacy = K.load(res.dir / "newsurface_relationships.json")
    assert [(e["type"], e["target"]) for e in legacy["edges"]] == [("INVOKES", f"lambda:{FN}")]


@pytest.mark.finding("F-162")
def test_the_e_data_graph_is_deterministic(tmp_path):
    def build(root):
        run = K.Run(root)
        run.iam.role("demo-reader", K.EC2_TRUST, inline={"p": [rb.allow(["kms:Decrypt", "dynamodb:Query",
                                                                         "secretsmanager:GetSecretValue"], "*")]})
        run.write_json(K.REGION, "kms/keys.json", [K.v2_key(K.KEY_ID_2), K.v2_key()])
        for kid in (K.KEY_ID, K.KEY_ID_2):
            rec = K.v2_key(kid)
            run.write_json(K.REGION, f"kms/key_policies/{kid}.json",
                           K.key_policy_file(rec, rb.resource_policy(K.root_delegation())))
        run.write_json(K.REGION, "dynamodb/resources.json", [_ddb("demo-b"), _ddb("demo-a")])
        run.write_json(K.REGION, "secretsmanager/secrets.json", [K.v2_secret("demo/b"), K.v2_secret("demo/a")])
        run.finish()
        res = run.analyze(source_date_epoch=1767225600)                  # 2026-01-01T00:00:00Z
        return (res.dir / "graph.json").read_bytes()

    assert build(tmp_path / "one") == build(tmp_path / "two")


@pytest.mark.finding("F-027", "F-059")
def test_a_collected_resource_replaces_the_placeholder_another_analyzer_created():
    ds = K.engine("analyzers.data_stores")
    builder = K.engine("graph.builder").GraphBuilder(K.ACCT, "aws")
    key = K.key_arn()
    builder.add_node(key, "kms", "key/" + K.KEY_ID, props={"placeholder": True}, coverage_status="not-collected")
    ds.add_resource_node(builder, "kms", key, "alias/demo-app", region=K.REGION, account=K.ACCT,
                         props={"key_manager": "CUSTOMER"}, coverage=("partial", ["kms:ListGrants:denied"]))
    node = builder.node(key)
    assert (node.label, node.coverage_status, node.coverage_gaps) == ("alias/demo-app", "partial",
                                                                      ["kms:ListGrants:denied"])
    assert "placeholder" not in node.props and node.props["key_manager"] == "CUSTOMER"
