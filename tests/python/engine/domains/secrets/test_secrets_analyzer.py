"""Secrets Manager / SSM analyzer (E-data): reads, writes, matching, encryption, exposure, documents."""

from __future__ import annotations

import importlib

import pytest

K = importlib.import_module("tests.fixtures.e-data.kit")
rb = K.rb
ROLE = K.iam_arn


def _run(tmp_path, *, setup=None, secrets=(), secret_policies=(), params=(), param_policies=(), keys=(),
         documents=None, shared=None, regions=(K.REGION,), partition="aws", unit=K.REGION):
    run = K.Run(tmp_path, regions=regions, partition=partition)
    if setup is not None:
        setup(run.iam)
    run.write_json(unit, "secretsmanager/secrets.json", list(secrets))
    for i, (secret, policy) in enumerate(secret_policies):
        run.write_json(unit, f"secretsmanager/resource_policies/demo-{i:02d}.json", K.secret_policy_file(secret,
                                                                                                         policy))
    run.write_json(unit, "ssm/parameters.json", list(params))
    for i, (param, *policies) in enumerate(param_policies):
        run.write_json(unit, f"ssm/parameter_policies/demo-{i:02d}.json", K.param_policy_file(param, *policies))
    if documents is not None:
        run.write_json(unit, "ssm/documents.json", list(documents))
    if shared is not None:
        run.write_json(unit, "ssm/parameters_shared_with_account.json", list(shared))
    if keys:
        run.write_json(unit, "kms/keys.json", list(keys))
    run.finish()
    res = run.analyze()
    assert K.problems(res.graph) == []
    assert K.statuses(res.result).get("secrets") == "ok"
    return res


def _types(res, source, target):
    return K.types_between(res.graph, source, target)


# ── F-026: reading means GetSecretValue / SSM Get* ───────────────────────────

@pytest.mark.finding("F-026")
def test_metadata_actions_give_no_read_edge(tmp_path):
    sec = K.v2_secret("demo/app")
    param = K.v2_param("/demo/app/db_password", ptype="SecureString")

    def setup(iam):
        iam.role("demo-auditor", K.EC2_TRUST, inline={"p": [rb.allow(
            ["secretsmanager:Describe*", "secretsmanager:List*", "secretsmanager:GetResourcePolicy",
             "ssm:Describe*", "ssm:List*"], "*")]})
        iam.role("demo-batch-only", K.EC2_TRUST, inline={"p": [rb.allow("secretsmanager:BatchGetSecretValue", "*")]})
        iam.role("demo-reader", K.EC2_TRUST, inline={"p": [rb.allow(
            ["secretsmanager:GetSecretValue", "ssm:GetParameter"], "*")]})
        iam.role("demo-writer", K.EC2_TRUST, inline={"p": [rb.allow("secretsmanager:PutSecretValue", "*")]})

    res = _run(tmp_path, setup=setup, secrets=[sec], params=[param])
    for role in ("demo-auditor", "demo-batch-only"):
        assert _types(res, ROLE("role", role), sec["ARN"]) == []
        assert _types(res, ROLE("role", role), param["ARN"]) == []
    assert _types(res, ROLE("role", "demo-reader"), sec["ARN"]) == ["CAN_READ_SECRET"]
    assert _types(res, ROLE("role", "demo-reader"), param["ARN"]) == ["CAN_READ_PARAM"]
    assert _types(res, ROLE("role", "demo-writer"), sec["ARN"]) == ["CAN_WRITE_SECRET"]


# ── F-079: matching on the collected ARN ─────────────────────────────────────

@pytest.mark.finding("F-079")
def test_get_parameters_by_path_on_an_ancestor_grants_the_parameters_below(tmp_path):
    deep = K.v2_param("/prod/db/password", ptype="SecureString")
    other = K.v2_param("/staging/db/password", ptype="SecureString")
    prefix = f"arn:aws:ssm:{K.REGION}:{K.ACCT}:parameter"

    def setup(iam):
        iam.role("demo-path", K.EC2_TRUST, inline={"p": [rb.allow("ssm:GetParametersByPath", f"{prefix}/prod")]})
        iam.role("demo-get-on-path", K.EC2_TRUST, inline={"p": [rb.allow("ssm:GetParameter", f"{prefix}/prod")]})
        iam.role("demo-star", K.EC2_TRUST, inline={"p": [rb.allow("ssm:GetParameter", f"{prefix}/prod/*")]})

    res = _run(tmp_path, setup=setup, params=[deep, other])
    edge = K.edges(res.graph, "CAN_READ_PARAM", ROLE("role", "demo-path"), deep["ARN"])
    assert edge and edge[0]["evidence"]["actions"] == ["ssm:GetParametersByPath"]
    assert _types(res, ROLE("role", "demo-path"), other["ARN"]) == []
    assert _types(res, ROLE("role", "demo-get-on-path"), deep["ARN"]) == []   # GetParameter needs the full name
    assert _types(res, ROLE("role", "demo-star"), deep["ARN"]) == ["CAN_READ_PARAM"]


@pytest.mark.finding("F-079")
def test_secret_names_match_case_sensitively_in_one_direction(tmp_path):
    sec = K.v2_secret("prod/db")
    upper = f"arn:aws:secretsmanager:{K.REGION}:{K.ACCT}:secret:PROD/*"
    exact = f"arn:aws:secretsmanager:{K.REGION}:{K.ACCT}:secret:prod/db-??????"

    def setup(iam):
        iam.role("demo-upper", K.EC2_TRUST, inline={"p": [rb.allow("secretsmanager:GetSecretValue", upper)]})
        iam.role("demo-exact", K.EC2_TRUST, inline={"p": [rb.allow("secretsmanager:GetSecretValue", exact)]})
        iam.role("demo-foreign", K.EC2_TRUST, inline={"p": [rb.allow(
            "secretsmanager:GetSecretValue", f"arn:aws:secretsmanager:*:{K.FOREIGN}:secret:*")]})

    res = _run(tmp_path, setup=setup, secrets=[sec])
    assert _types(res, ROLE("role", "demo-upper"), sec["ARN"]) == []
    assert _types(res, ROLE("role", "demo-exact"), sec["ARN"]) == ["CAN_READ_SECRET"]
    assert _types(res, ROLE("role", "demo-foreign"), sec["ARN"]) == []


@pytest.mark.finding("F-079", "F-119")
def test_govcloud_arns_match_scoped_grants(tmp_path):
    region = "us-gov-west-1"
    sec = K.v2_secret("demo/gov", region=region, partition="aws-us-gov")
    param = K.v2_param("/demo/gov/token", region=region, partition="aws-us-gov", ptype="SecureString")

    def setup(iam):
        iam.role("demo-gov", K.EC2_TRUST, inline={"p": [rb.allow(
            ["secretsmanager:GetSecretValue", "ssm:GetParameter"],
            [f"arn:aws-us-gov:secretsmanager:{region}:{K.ACCT}:secret:demo/*",
             f"arn:aws-us-gov:ssm:{region}:{K.ACCT}:parameter/demo/*"])]})

    res = _run(tmp_path, setup=setup, secrets=[sec], params=[param], regions=(region,), partition="aws-us-gov",
               unit=region)
    role = ROLE("role", "demo-gov", partition="aws-us-gov")
    assert _types(res, role, sec["ARN"]) == ["CAN_READ_SECRET"]
    assert _types(res, role, param["ARN"]) == ["CAN_READ_PARAM"]


# ── F-001 / F-014 / F-015 ────────────────────────────────────────────────────

@pytest.mark.finding("F-001", "F-014", "F-015")
def test_deny_notaction_and_conditions_decide_secret_access(tmp_path):
    sec = K.v2_secret("demo/app")

    def setup(iam):
        iam.role("demo-denied", K.EC2_TRUST, inline={"p": [rb.allow("secretsmanager:*", "*"),
                                                             rb.deny("secretsmanager:GetSecretValue", "*")]})
        iam.role("demo-poweruser", K.EC2_TRUST, inline={"p": [{"Effect": "Allow", "NotAction": "iam:*",
                                                                "Resource": "*"}]})
        iam.role("demo-mfa", K.EC2_TRUST, inline={"p": [rb.allow(
            "secretsmanager:GetSecretValue", "*", cond={"Bool": {"aws:MultiFactorAuthPresent": "true"}})]})

    res = _run(tmp_path, setup=setup, secrets=[sec])
    assert _types(res, ROLE("role", "demo-denied"), sec["ARN"]) == ["CAN_WRITE_SECRET"]
    assert _types(res, ROLE("role", "demo-poweruser"), sec["ARN"]) == ["CAN_READ_SECRET", "CAN_WRITE_SECRET"]
    mfa = K.edges(res.graph, "CAN_READ_SECRET", ROLE("role", "demo-mfa"), sec["ARN"])
    assert mfa and mfa[0]["confidence"] == "conditional"


# ── resource policies (F-031, F-037, F-039, F-088, F-114) ────────────────────

@pytest.mark.finding("F-031", "F-037", "F-088")
def test_secret_policy_exposure_is_graded(tmp_path):
    names = ("demo/open", "demo/org", "demo/guard", "demo/notprincipal", "demo/partner", "demo/same")
    sec = {n: K.v2_secret(n, policy_status="present") for n in names}
    partner = ROLE("role", "demo-partner", account=K.FOREIGN)
    read = "secretsmanager:GetSecretValue"
    policies = {
        "demo/open": rb.resource_policy(rb.grant("*", read)),
        "demo/org": rb.resource_policy(rb.grant("*", read, cond={"StringEquals": {"aws:PrincipalOrgID": "o-a1b2c3"}})),
        "demo/guard": rb.resource_policy(rb.grant("*", read), {
            "Effect": "Deny", "Principal": "*", "Action": "*", "Resource": "*",
            "Condition": {"StringNotEquals": {"aws:PrincipalOrgID": "o-a1b2c3"}}}),
        "demo/notprincipal": rb.resource_policy({"Effect": "Allow", "NotPrincipal": {"AWS": partner},
                                                 "Action": read, "Resource": "*"}),
        "demo/partner": rb.resource_policy(rb.grant({"AWS": partner}, read)),
        "demo/same": rb.resource_policy(rb.grant({"AWS": ROLE("role", "demo-app")}, read)),
    }

    def setup(iam):
        iam.role("demo-app", K.EC2_TRUST)

    res = _run(tmp_path, setup=setup, secrets=list(sec.values()),
               secret_policies=[(sec[n], policies[n]) for n in names])
    arn = {n: s["ARN"] for n, s in sec.items()}
    public = {n for n in names if K.findings(res.graph, "SECRET-PUB-001", arn[n])}
    assert public == {"demo/open", "demo/notprincipal"}
    pub_edge = K.edges(res.graph, "SECRET_GRANTS_PUBLIC", K.ANON, arn["demo/open"])
    assert pub_edge and pub_edge[0]["props"]["auth"] == "any-aws-account" and pub_edge[0]["traversable"]
    assert K.edges(res.graph, "SECRET_GRANTS_PUBLIC", K.ANON, arn["demo/org"]) == []
    assert K.edges(res.graph, "SECRET_GRANTS_PUBLIC", K.ANON, arn["demo/guard"]) == []
    xacct = K.findings(res.graph, "SECRET-XACCT-001", arn["demo/partner"])
    assert len(xacct) == 1 and "SECRET-XAUTH-001" in xacct[0]["legacy_ids"]
    assert "ExternalId" not in xacct[0]["remediation"]
    assert K.edges(res.graph, "SECRET_GRANTS_CROSS_ACCOUNT", partner, arn["demo/partner"])
    # a same-account grant folds into the effective-access edge (no SECRET_GRANTS_ACCESS)
    same = K.edges(res.graph, "CAN_READ_SECRET", ROLE("role", "demo-app"), arn["demo/same"])
    assert same and same[0]["evidence"]["basis"] == "named"
    assert {e["type"] for e in res.graph["edges"]}.isdisjoint({"SECRET_GRANTS_ACCESS"})


@pytest.mark.finding("F-114")
def test_secret_policies_are_matched_by_the_arn_inside_the_file(tmp_path):
    slash, underscore = K.v2_secret("demo/db", policy_status="present"), K.v2_secret("demo_db", policy_status="present")
    res = _run(tmp_path, secrets=[slash, underscore], secret_policies=[
        (slash, rb.resource_policy(rb.grant("*", "secretsmanager:GetSecretValue"))),
        (underscore, rb.resource_policy(rb.grant({"AWS": f"arn:aws:iam::{K.ACCT}:root"}, "secretsmanager:*")))])
    assert K.findings(res.graph, "SECRET-PUB-001", slash["ARN"])
    assert not K.findings(res.graph, "SECRET-PUB-001", underscore["ARN"])


@pytest.mark.finding("F-002")
def test_a_single_object_secret_policy_statement_is_read(tmp_path):
    sec = K.v2_secret("demo/single", policy_status="present")
    policy = {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Principal": "*",
                                                     "Action": "secretsmanager:GetSecretValue", "Resource": "*"}}
    res = _run(tmp_path, secrets=[sec], secret_policies=[(sec, policy)])
    assert K.findings(res.graph, "SECRET-PUB-001", sec["ARN"])


@pytest.mark.finding("F-059")
def test_an_unreadable_secret_policy_is_unknown_not_private(tmp_path):
    sec = K.mark(K.v2_secret("demo/hidden", policy_status="denied"), K.denied("secretsmanager:GetResourcePolicy"))
    partner = ROLE("role", "demo-partner", account=K.FOREIGN)
    res = _run(tmp_path, secrets=[sec])
    node = K.nodes_by_id(res.graph)[sec["ARN"]]
    assert node["coverage"]["status"] == "partial"
    assert "secretsmanager:GetResourcePolicy:denied" in node["coverage"]["gaps"]
    assert K.gaps(res.graph)["secrets:resource-policy-unknown"]["count"] == 1
    assert node["props"]["policy_status"] == "denied"
    assert K.findings(res.graph, "SECRET-PUB-001") == []
    assert K.edges(res.graph, source=partner) == []


# ── encryption (F-027) ───────────────────────────────────────────────────────

@pytest.mark.finding("F-027")
def test_encryption_edges_join_the_collected_key_nodes(tmp_path):
    cmk = K.v2_key(K.KEY_ID, aliases=["alias/demo-app"])
    aws_sm = K.v2_key(K.AWS_KEY_ID, manager="AWS", aliases=["alias/aws/secretsmanager"], policy_status="skipped")
    by_alias = K.v2_secret("demo/by-alias", kms_key="alias/demo-app")
    by_id = K.v2_secret("demo/by-id", kms_key=K.KEY_ID)
    default = K.v2_secret("demo/default")
    secure = K.v2_param("/demo/secure", ptype="SecureString", key_id="alias/aws/ssm")
    plain = K.v2_param("/demo/plain", ptype="String")
    res = _run(tmp_path, secrets=[by_alias, by_id, default], params=[secure, plain], keys=[cmk, aws_sm])
    for sec in (by_alias, by_id):
        assert K.edges(res.graph, "SECRET_ENCRYPTED_BY", sec["ARN"], K.key_arn(K.KEY_ID))
    assert K.edges(res.graph, "SECRET_ENCRYPTED_BY", default["ARN"], K.key_arn(K.AWS_KEY_ID))
    # aws/ssm was not collected: a region-qualified placeholder, never a bare alias
    placeholder = f"arn:aws:kms:{K.REGION}:{K.ACCT}:alias/aws/ssm"
    assert K.edges(res.graph, "PARAM_ENCRYPTED_BY", secure["ARN"], placeholder)
    node = K.nodes_by_id(res.graph)[placeholder]
    assert node["props"]["unresolved_alias"] is True and node["coverage"]["status"] == "not-collected"
    assert K.edges(res.graph, "PARAM_ENCRYPTED_BY", plain["ARN"]) == []


# ── F-086: credential-looking plaintext parameters ───────────────────────────

@pytest.mark.finding("F-086")
@pytest.mark.parametrize("name,expected", [
    ("/app/db_password", True), ("/app/DB_PASSWORD", True), ("/svc/api-key", True), ("/svc/apikey", True),
    ("/svc/clientSecret", True), ("/x/token", True), ("/x/private_key", True), ("/x/credentials", True),
    ("/app/credit_limit", False), ("/app/tokenizer/model", False), ("/svc/accredited", False),
    ("/x/max_tokens", False), ("/app/secretary_name", False), ("/app/passwordless_login", False),
])
def test_plaintext_parameter_names_match_whole_tokens(name, expected):
    assert K.engine("analyzers.secrets").looks_sensitive(name) is expected


@pytest.mark.finding("F-086")
def test_param_plain_finding_only_for_plaintext_credential_names(tmp_path):
    flagged = K.v2_param("/app/db_password")
    secure = K.v2_param("/app/api_key", ptype="SecureString")
    benign = K.v2_param("/app/credit_limit")
    res = _run(tmp_path, params=[flagged, secure, benign])
    assert [f["node_id"] for f in K.findings(res.graph, "PARAM-PLAIN-001")] == [flagged["ARN"]]


# ── F-116: pending deletion, documents, shared parameters, parameter policies ──

@pytest.mark.finding("F-116")
def test_a_secret_scheduled_for_deletion_must_be_restored_before_it_is_read(tmp_path):
    sec = K.v2_secret("demo/old", deleted=True)

    def setup(iam):
        iam.role("demo-reader", K.EC2_TRUST, inline={"p": [rb.allow("secretsmanager:GetSecretValue", "*")]})
        iam.role("demo-restorer", K.EC2_TRUST, inline={"p": [rb.allow(
            ["secretsmanager:GetSecretValue", "secretsmanager:RestoreSecret"], "*")]})

    res = _run(tmp_path, setup=setup, secrets=[sec])
    assert _types(res, ROLE("role", "demo-reader"), sec["ARN"]) == []
    edge = K.edges(res.graph, "CAN_READ_SECRET", ROLE("role", "demo-restorer"), sec["ARN"])
    assert edge and edge[0]["evidence"]["requires"] == ["secretsmanager:RestoreSecret"]
    node = K.nodes_by_id(res.graph)[sec["ARN"]]
    assert node["props"]["pending_deletion"] is True and node["props"]["policy_status"] == "skipped"


@pytest.mark.finding("F-116", "F-059")
def test_ssm_document_sharing(tmp_path):
    docs = [K.v2_document("demo-public", public=True), K.v2_document("demo-shared", shared=[K.FOREIGN]),
            K.v2_document("demo-private"), K.v2_document("demo-unknown", public=None, shared=None)]
    res = _run(tmp_path, documents=docs)
    arn = {d["Name"]: d["Arn"] for d in docs}
    assert K.edges(res.graph, "SSMDOC_SHARED_PUBLIC", K.ANON, arn["demo-public"])
    assert [f["severity"] for f in K.findings(res.graph, "SSMDOC-PUB-001")] == ["HIGH"]
    xacct = K.findings(res.graph, "SSMDOC-XACCT-001")
    assert [(f["node_id"], f["evidence"]["accounts"]) for f in xacct] == [(arn["demo-shared"], [K.FOREIGN])]
    foreign = f"arn:aws:iam::{K.FOREIGN}:root"                              # F-116, D-52 (request e-data-2)
    [share] = K.edges(res.graph, "SSMDOC_SHARED_CROSS_ACCOUNT", foreign, arn["demo-shared"])
    assert share["traversable"] is True and xacct[0]["related_node_ids"] == [foreign]
    assert not K.edges(res.graph, "SSMDOC_SHARED_CROSS_ACCOUNT", target=arn["demo-unknown"])
    unknown = K.nodes_by_id(res.graph)[arn["demo-unknown"]]
    assert unknown["coverage"]["status"] == "partial" and "public" not in unknown["props"]
    assert K.gaps(res.graph)["ssm:document-sharing-unknown"]["count"] == 1


@pytest.mark.finding("F-116")
def test_parameters_shared_with_the_account_and_parameter_policies(tmp_path):
    inbound = K.v2_param("/partner/feed-token", account=K.FOREIGN, ptype="SecureString")
    inbound.pop("PolicyStatus")
    advanced = K.v2_param("/demo/shared-config", tier="Advanced", policy_status="present")

    def setup(iam):
        iam.role("demo-reader", K.EC2_TRUST, inline={"p": [rb.allow("ssm:GetParameter", "*")]})

    res = _run(tmp_path, setup=setup, params=[advanced], shared=[inbound], param_policies=[
        (advanced, rb.resource_policy(rb.grant({"AWS": f"arn:aws:iam::{K.FOREIGN}:root"}, "ssm:GetParameter")))])
    node = K.nodes_by_id(res.graph)[inbound["ARN"]]
    assert node["account"] == K.FOREIGN and node["props"]["shared_with_account"] is True
    edge = K.edges(res.graph, "CAN_READ_PARAM", ROLE("role", "demo-reader"), inbound["ARN"])
    assert edge and edge[0]["confidence"] == "conditional"
    [shared] = K.findings(res.graph, "PARAM-XACCT-001", advanced["ARN"])
    assert shared["evidence"]["accounts"] == [K.FOREIGN]
    foreign = f"arn:aws:iam::{K.FOREIGN}:root"                              # F-116, D-52 (request e-data-2)
    [edge] = K.edges(res.graph, "PARAM_GRANTS_CROSS_ACCOUNT", foreign, advanced["ARN"])
    assert edge["traversable"] is True and edge["evidence"]["actions"] == ["ssm:GetParameter"]
    assert shared["related_node_ids"] == [foreign]


# ── structure ────────────────────────────────────────────────────────────────

@pytest.mark.finding("F-022")
def test_group_grants_are_one_group_edge_not_one_per_member(tmp_path):
    sec = K.v2_secret("demo/app")

    def setup(iam):
        iam.group("demo-readers", inline={"p": [rb.allow("secretsmanager:GetSecretValue", "*")]})
        iam.user("demo-member", groups=["demo-readers"])
        iam.user("demo-direct", inline={"p": [rb.allow("secretsmanager:GetSecretValue", "*")]})

    res = _run(tmp_path, setup=setup, secrets=[sec])
    assert _types(res, ROLE("group", "demo-readers"), sec["ARN"]) == ["CAN_READ_SECRET"]
    assert _types(res, ROLE("user", "demo-member"), sec["ARN"]) == []
    assert _types(res, ROLE("user", "demo-direct"), sec["ARN"]) == ["CAN_READ_SECRET"]


@pytest.mark.finding("F-026", "F-114")
def test_an_old_report_layout_is_analysed_natively_and_rendered_into_the_legacy_file(tmp_path):
    """Old (d13c215) layouts stay analysable with ``analyze <dir>``; the d13c215 entry points are gone (D-53)."""
    secrets = K.engine("analyzers.secrets")
    for gone in ("_classify_secret_access", "_classify_param_access", "_load_secrets_data",
                 "_analyze_secrets_relationships", "SECRETS_ACCESS_WEIGHTS"):
        assert not hasattr(secrets, gone), gone
    assert secrets.looks_sensitive("/app/credit_limit") is False
    tree = K.Tree(tmp_path)
    tree.iam.role("demo-reader", K.EC2_TRUST)
    sec = rb.secret("demo/legacy", account=K.ACCT, region=K.REGION)
    tree.write_json("secretsmanager/secrets.json", [sec])
    tree.write_json("secretsmanager/resource_policies/demo_legacy.json",
                    {"SecretArn": sec["ARN"], "SecretName": sec["Name"], "ResourcePolicy": rb.resource_policy(
                        rb.grant("*", "secretsmanager:GetSecretValue"))})
    tree.write(skip={"secretsmanager"})
    res = tree.analyze()
    assert K.statuses(res.result)["secrets"] == "ok" and K.problems(res.graph) == []
    assert K.edges(res.graph, "SECRET_GRANTS_PUBLIC", K.ANON, sec["ARN"])
    legacy = K.load(res.dir / "secrets_relationships.json")
    assert ("SECRET_GRANTS_PUBLIC", f"secret:{sec['ARN']}", "principal:*") in {
        (e["type"], e["source"], e["target"]) for e in legacy["edges"]}
    assert [f["id"] for f in legacy["findings"]] == ["SECRET-PUB-001"]
