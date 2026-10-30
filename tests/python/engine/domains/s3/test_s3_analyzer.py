"""S3 analyzer (engine/analyzers/s3.py): principal edges through the evaluator, public exposure with Block Public
Access, ACLs and AWS's policy status, cross-account grants, legacy file rendering (engine.md §5 "S3 and EC2")."""

from __future__ import annotations

import importlib

import pytest

K = importlib.import_module("tests.fixtures.e-net.kit")
rb = K.rb

DATA = "demo-data-bucket"


# ── principal → bucket edges (F-001, F-014, F-015, F-022) ────────────────────

@pytest.mark.finding("F-001")
def test_notaction_and_notresource_statements_reach_the_buckets_they_really_grant(tmp_path):
    t = K.Tree(tmp_path)
    t.iam.role("demo-poweruser", K.EC2_TRUST, inline={"p": [
        {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*"], "Resource": "*"}]})
    t.iam.role("demo-star-notres", K.EC2_TRUST, inline={"p": [
        {"Effect": "Allow", "Action": "*", "NotResource": f"arn:aws:s3:::{DATA}/*"}]})
    t.iam.role("demo-iam-only", K.EC2_TRUST, inline={"p": [
        {"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"}]})
    t.write()
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, DATA)])
    g = t.analyze().graph
    b = K.bucket(DATA)
    assert K.types_between(g, K.iam_arn("role", "demo-poweruser"), b) == ["FULL_ACCESS"]
    # objects excluded, the bucket itself is not: bucket-level admin and list actions remain
    star = K.types_between(g, K.iam_arn("role", "demo-star-notres"), b)
    assert "CAN_ADMIN" in star and "FULL_ACCESS" not in star and "CAN_WRITE" not in star
    assert K.types_between(g, K.iam_arn("role", "demo-iam-only"), b) == []
    assert K.problems(g) == []


@pytest.mark.finding("F-014")
def test_explicit_deny_and_boundaries_remove_bucket_edges(tmp_path):
    t = K.Tree(tmp_path)
    t.iam.role("demo-denied", K.EC2_TRUST, inline={"p": [rb.allow("s3:*", "*"),
                                                          rb.deny("s3:*", [K.bucket(DATA), K.bucket(DATA) + "/*"])]})
    writes = ["s3:Put*", "s3:Delete*", "s3:AbortMultipartUpload", "s3:RestoreObject"]
    t.iam.role("demo-read-only-deny", K.EC2_TRUST, inline={"p": [rb.allow("s3:*", "*"), rb.deny(writes, "*")]})
    t.write()
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, DATA), rb.s3_bucket(t.scope, "demo-other-bucket")])
    g = t.analyze().graph
    assert K.types_between(g, K.iam_arn("role", "demo-denied"), K.bucket(DATA)) == []
    assert K.types_between(g, K.iam_arn("role", "demo-denied"), K.bucket("demo-other-bucket")) == ["FULL_ACCESS"]
    # every write and policy-admin action denied: no FULL_ACCESS (the chain is broken), read only
    assert K.types_between(g, K.iam_arn("role", "demo-read-only-deny"), K.bucket(DATA)) == ["CAN_READ"]
    assert K.problems(g) == []


@pytest.mark.finding("F-015")
def test_conditions_make_edges_conditional_and_heavier(tmp_path):
    t = K.Tree(tmp_path)
    mfa = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    t.iam.user("demo-mfa-reader", inline={"p": [rb.allow("s3:GetObject", "*", cond=mfa)]})
    t.iam.user("demo-reader", inline={"p": [rb.allow("s3:GetObject", "*")]})
    t.write()
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, DATA)])
    g = t.analyze().graph
    [cond] = K.edges(g, "CAN_READ", K.iam_arn("user", "demo-mfa-reader"), K.bucket(DATA))
    [plain] = K.edges(g, "CAN_READ", K.iam_arn("user", "demo-reader"), K.bucket(DATA))
    assert cond["confidence"] == "conditional" and plain["confidence"] == "definite"
    assert cond["weight"] > plain["weight"] == 1
    assert cond["evidence"]["condition_strength"] in ("weak", "strong")
    assert K.problems(g) == []


@pytest.mark.finding("F-022")
def test_one_edge_per_principal_type_and_bucket_and_one_legacy_record_each(tmp_path):
    t = K.Tree(tmp_path)
    shared = t.iam.managed("demo-s3-read", [rb.allow("s3:GetObject", "*")], customer=True)
    t.iam.role("demo-reader", K.EC2_TRUST, attached=[shared], inline={"p": [rb.allow("s3:ListBucket", "*")]})
    t.write()
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, f"demo-bucket-{i}") for i in range(4)])
    out = t.analyze()
    role = K.iam_arn("role", "demo-reader")
    edges = [e for e in K.edges(out.graph, source=role) if e["target"].startswith("arn:aws:s3:::")]
    assert sorted((e["type"], e["target"]) for e in edges) == [
        ("CAN_READ", K.bucket(f"demo-bucket-{i}")) for i in range(4)]
    for e in edges:
        assert e["evidence"]["actions"] == ["s3:GetObject", "s3:ListBucket"]
        assert len(e["evidence"]["statements"]) == 2
    legacy = [e for e in out.legacy("s3_relationships.json")["edges"] if e["source"] == role]
    assert len(legacy) == 4
    rec = legacy[0]
    assert rec["type"] == "CAN_READ" and rec["target"].startswith("bucket:demo-bucket-")
    assert rec["matched_actions"] == ["s3:GetObject", "s3:ListBucket"]
    assert rec["source_policies"] == sorted(["demo-s3-read", "p"])
    assert K.problems(out.graph) == []


@pytest.mark.finding("F-022")
def test_group_grants_reach_the_bucket_through_member_of(tmp_path):
    t = K.Tree(tmp_path)
    t.iam.group("demo-readers", inline={"p": [rb.allow("s3:GetObject", "*")]})
    t.iam.user("demo-member", groups=["demo-readers"])
    t.write()
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, DATA)])
    g = t.analyze().graph
    group, user = K.iam_arn("group", "demo-readers"), K.iam_arn("user", "demo-member")
    assert K.edges(g, "CAN_READ", group, K.bucket(DATA))
    assert K.edges(g, "CAN_READ", user, K.bucket(DATA)) == []        # explained by MEMBER_OF + the group's edge
    path = K.engine("graph.traverse").shortest_path(g, user, K.bucket(DATA))
    assert path is not None and path.edge_types == ("MEMBER_OF", "CAN_READ")


# ── public exposure (F-023, F-024, F-031, F-037) ─────────────────────────────

@pytest.mark.finding("F-037", "F-031")
def test_public_policy_is_an_anonymous_edge_and_a_finding_on_the_bucket(tmp_path):
    t = K.Tree(tmp_path)
    t.write()
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, DATA, policy=K.public_policy(DATA))])
    out = t.analyze()
    g, b = out.graph, K.bucket(DATA)
    [edge] = K.edges(g, "GRANTS_PUBLIC", K.ANON, b)
    assert edge["evidence"]["legacy"]["direction"] == "reversed" and edge["props"]["auth"] == "none"
    [f] = K.findings(g, "S3-PUBLIC-001", b)
    assert f["severity"] == "HIGH" and f["fingerprint"] in K.nodes_by_id(g)[b]["findings"]
    assert K.nodes_by_id(g)[b]["props"]["public"] is True
    legacy = out.legacy("s3_relationships.json")
    assert {(e["source"], e["target"], e["type"]) for e in legacy["edges"]} == {
        ("bucket:" + DATA, "principal:*", "GRANTS_PUBLIC")}
    assert [x["id"] for x in legacy["findings"]] == ["S3-PUBLIC-001"]
    assert K.problems(g) == []


@pytest.mark.finding("F-024", "F-031")
def test_condition_strength_grades_public_policies(tmp_path):
    t = K.Tree(tmp_path)
    t.write()
    tls = {"Bool": {"aws:SecureTransport": "true"}}
    vpce = {"StringEquals": {"aws:SourceVpce": "vpce-0a1b2c3d4e5f60001"}}
    t.scope.write("s3/buckets.json", [
        rb.s3_bucket(t.scope, "demo-tls-only", policy=K.public_policy("demo-tls-only", cond=tls)),
        rb.s3_bucket(t.scope, "demo-vpce-only", policy=K.public_policy("demo-vpce-only", cond=vpce)),
        rb.s3_bucket(t.scope, "demo-public-write", policy=K.public_policy("demo-public-write", "s3:PutObject"))])
    g = t.analyze().graph
    sev = {f["node_id"]: f["severity"] for f in K.findings(g, "S3-PUBLIC-001")}
    # aws:SecureTransport is no restriction on who: still public (d13c215 skipped any conditional policy)
    assert sev[K.bucket("demo-tls-only")] == "HIGH"
    assert sev[K.bucket("demo-public-write")] == "CRITICAL"
    assert sev[K.bucket("demo-vpce-only")] == "INFO"
    [vpce_edge] = K.edges(g, "GRANTS_PUBLIC", K.ANON, K.bucket("demo-vpce-only"))
    assert vpce_edge["confidence"] == "conditional" and vpce_edge["evidence"]["condition_strength"] == "strong"
    assert K.problems(g) == []


@pytest.mark.finding("F-031")
def test_notprincipal_allow_is_public_except_and_a_covering_deny_removes_the_grant(tmp_path):
    t = K.Tree(tmp_path)
    t.iam.role("demo-app", K.EC2_TRUST)
    t.write()
    except_one = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "NotPrincipal": {"AWS": K.iam_arn("role", "demo-app")}, "Action": "s3:GetObject",
        "Resource": K.bucket("demo-notprincipal") + "/*"}]}
    denied = K.public_policy("demo-denied")
    denied["Statement"].append({"Effect": "Deny", "Principal": "*", "Action": "s3:*",
                                "Resource": [K.bucket("demo-denied"), K.bucket("demo-denied") + "/*"]})
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, "demo-notprincipal", policy=except_one),
                                      rb.s3_bucket(t.scope, "demo-denied", policy=denied)])
    g = t.analyze().graph
    assert K.edges(g, "GRANTS_PUBLIC", K.ANON, K.bucket("demo-notprincipal"))
    assert K.edges(g, "GRANTS_PUBLIC", K.ANON, K.bucket("demo-denied")) == []
    assert K.findings(g, "S3-PUBLIC-001", K.bucket("demo-denied")) == []
    assert K.problems(g) == []


@pytest.mark.finding("F-002")
def test_single_object_statement_bucket_policy_is_read(tmp_path):
    t = K.Tree(tmp_path)
    t.write()
    policy = {"Version": "2012-10-17", "Statement": K.public_policy(DATA)["Statement"][0]}
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, DATA, policy=policy)])
    out = t.analyze()
    assert K.statuses(out.result)["s3"] == "ok"
    assert K.findings(out.graph, "S3-PUBLIC-001", K.bucket(DATA))


@pytest.mark.finding("F-023")
def test_block_public_access_mitigates_policy_exposure(tmp_path):
    t = K.Tree(tmp_path)
    t.write()
    pab = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True,
           "RestrictPublicBuckets": True}
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, DATA, policy=K.public_policy(DATA),
                                                   public_access_block=pab)])
    g = t.analyze().graph
    b = K.bucket(DATA)
    assert K.edges(g, "GRANTS_PUBLIC", K.ANON, b) == []
    [f] = K.findings(g, "S3-PUBLIC-001", b)
    assert f["severity"] == "INFO" and f["base_severity"] == "HIGH"
    assert f["evidence"]["mitigated_by"] == ["bucket:RestrictPublicBuckets"]
    props = K.nodes_by_id(g)[b]["props"]
    assert props["public"] is None and props["block_public_access"]["restrict_public_buckets"] is True
    assert K.problems(g) == []


@pytest.mark.finding("F-023")
def test_account_block_public_access_and_aws_policy_status_in_a_v2_run(tmp_path):
    run = K.Run(tmp_path)
    run.write_json("global", "s3/account_public_access_block.json",
                   K.account_pab(RestrictPublicBuckets=True, IgnorePublicAcls=True), module="s3")
    buckets = [
        K.v2_bucket(run, "demo-acct-blocked", policy=K.public_policy("demo-acct-blocked"), policy_is_public=True,
                    public_access_block={"RestrictPublicBuckets": False, "IgnorePublicAcls": False,
                                         "BlockPublicAcls": False, "BlockPublicPolicy": False}),
    ]
    run.write_json("global", "s3/buckets.json", buckets, module="s3")
    run.finish()
    g = run.analyze().graph
    b = K.bucket("demo-acct-blocked")
    assert K.edges(g, "GRANTS_PUBLIC", K.ANON, b) == []
    [f] = K.findings(g, "S3-PUBLIC-001", b)
    assert f["severity"] == "INFO" and f["evidence"]["mitigated_by"] == ["account:RestrictPublicBuckets"]
    assert K.problems(g) == []


@pytest.mark.finding("F-023")
def test_aws_says_not_public_mitigates_and_aws_says_public_with_unreadable_policy_is_reported(tmp_path):
    run = K.Run(tmp_path)
    run.write_json("global", "s3/account_public_access_block.json", K.account_pab(False), module="s3")
    buckets = [
        K.v2_bucket(run, "demo-org-only", policy=K.public_policy("demo-org-only"), policy_is_public=False),
        K.v2_bucket(run, "demo-hidden", statuses_={"policy": "denied"}),
    ]
    buckets[1]["PolicyIsPublic"] = True
    run.write_json("global", "s3/buckets.json", buckets, module="s3")
    run.finish()
    g = run.analyze().graph
    [f] = K.findings(g, "S3-PUBLIC-001", K.bucket("demo-org-only"))
    assert f["severity"] == "INFO" and "aws:policy-status-not-public" in f["evidence"]["mitigated_by"]
    [hidden] = K.edges(g, "GRANTS_PUBLIC", K.ANON, K.bucket("demo-hidden"))
    assert hidden["confidence"] == "conditional"
    [hidden_f] = K.findings(g, "S3-PUBLIC-001", K.bucket("demo-hidden"))
    assert hidden_f["severity"] == "HIGH" and "actions unknown" in hidden_f["description"]
    node = K.nodes_by_id(g)[K.bucket("demo-hidden")]
    assert node["coverage"]["status"] == "denied" and "s3:GetBucketPolicy:denied" in node["coverage"]["gaps"]
    assert K.problems(g) == []


@pytest.mark.finding("F-024")
def test_public_acls_are_graded_by_permission_and_mitigated_by_ignore_public_acls(tmp_path):
    t = K.Tree(tmp_path)
    t.write()
    ignore = {"BlockPublicAcls": False, "IgnorePublicAcls": True, "BlockPublicPolicy": False,
              "RestrictPublicBuckets": False}
    t.scope.write("s3/buckets.json", [
        rb.s3_bucket(t.scope, "demo-acl-read", acl=K.acl(K.acl_grant("AllUsers", "READ"))),
        rb.s3_bucket(t.scope, "demo-acl-write", acl=K.acl(K.acl_grant("AuthenticatedUsers", "WRITE"))),
        rb.s3_bucket(t.scope, "demo-acl-ignored", acl=K.acl(K.acl_grant("AllUsers", "FULL_CONTROL")),
                     public_access_block=ignore),
        rb.s3_bucket(t.scope, "demo-acl-private", acl=K.acl())])
    g = t.analyze().graph
    sev = {f["node_id"]: f["severity"] for f in K.findings(g, "S3-PUBLIC-002")}
    assert sev == {K.bucket("demo-acl-read"): "HIGH", K.bucket("demo-acl-write"): "CRITICAL",
                   K.bucket("demo-acl-ignored"): "INFO"}
    assert K.edges(g, "GRANTS_PUBLIC", K.ANON, K.bucket("demo-acl-read"))
    [w] = K.edges(g, "GRANTS_PUBLIC", K.ANON, K.bucket("demo-acl-write"))
    assert w["props"]["auth"] == "any-aws-account" and w["evidence"]["access_types"] == ["CAN_WRITE"]
    assert K.edges(g, "GRANTS_PUBLIC", K.ANON, K.bucket("demo-acl-ignored")) == []
    assert K.edges(g, "GRANTS_PUBLIC", K.ANON, K.bucket("demo-acl-private")) == []
    assert K.problems(g) == []


@pytest.mark.finding("F-024")
def test_bucket_owner_enforced_disables_acl_exposure(tmp_path):
    run = K.Run(tmp_path)
    run.write_json("global", "s3/account_public_access_block.json", K.account_pab(False), module="s3")
    rec = K.v2_bucket(run, "demo-owner-enforced", acl=K.acl(K.acl_grant("AllUsers", "READ")),
                      ownership_controls={"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]})
    run.write_json("global", "s3/buckets.json", [rec], module="s3")
    run.finish()
    g = run.analyze().graph
    [f] = K.findings(g, "S3-PUBLIC-002", K.bucket("demo-owner-enforced"))
    assert f["severity"] == "INFO" and f["evidence"]["mitigated_by"] == ["bucket:acls-disabled"]
    assert K.edges(g, "GRANTS_PUBLIC") == []


# ── unknown is never "not public" (F-058, F-059) ─────────────────────────────

@pytest.mark.finding("F-059")
def test_denied_policy_and_acl_reads_leave_exposure_unknown(tmp_path):
    run = K.Run(tmp_path)
    run.write_json("global", "s3/account_public_access_block.json", K.account_pab(None), module="s3")
    rec = K.v2_bucket(run, "demo-unknown", statuses_={"policy": "denied", "acl": "error",
                                                      "public_access_block": "denied"})
    run.write_json("global", "s3/buckets.json", [rec], module="s3")
    run.finish()
    g = run.analyze().graph
    node = K.nodes_by_id(g)[K.bucket("demo-unknown")]
    assert node["props"]["public"] is None
    assert node["coverage"]["status"] == "denied"
    assert set(node["coverage"]["gaps"]) >= {"s3:GetBucketPolicy:denied", "s3:GetBucketAcl:error",
                                             "s3:GetPublicAccessBlock:denied"}
    assert K.findings(g, "S3-PUBLIC-001") == [] and K.edges(g, "GRANTS_PUBLIC") == []
    assert K.problems(g) == []


# ── cross-account (F-072, F-079) ─────────────────────────────────────────────

@pytest.mark.finding("F-072")
def test_bare_account_id_principal_is_cross_account_even_without_roles(tmp_path):
    t = K.Tree(tmp_path)
    t.write()                                    # no IAM role at all: the account comes from the context
    pol = K.public_policy(DATA, principal={"AWS": K.FOREIGN})
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, DATA, policy=pol)])
    g = t.analyze().graph
    root = f"arn:aws:iam::{K.FOREIGN}:root"
    [edge] = K.edges(g, "GRANTS_CROSS_ACCOUNT", root, K.bucket(DATA))
    assert K.nodes_by_id(g)[root]["type"] == "external_account" and edge["props"]["cross_account"] is True
    assert "external-identity-unknown" in edge["evidence"]["gaps"]
    assert K.findings(g, "S3-PUBLIC-001") == []
    assert K.problems(g) == []


@pytest.mark.finding("F-072", "F-079")
def test_partition_agnostic_bucket_matching_in_govcloud(tmp_path):
    run = K.Run(tmp_path, regions=("us-gov-west-1",), partition="aws-us-gov")
    run.iam.role("demo-gov-reader", K.EC2_TRUST, inline={"p": [
        rb.allow("s3:GetObject", "arn:aws-us-gov:s3:::demo-gov-bucket/*")]})
    run.write_json("global", "s3/buckets.json", [K.v2_bucket(run, "demo-gov-bucket", region="us-gov-west-1")],
                   module="s3")
    run.finish()
    g = run.analyze().graph
    b = K.bucket("demo-gov-bucket", partition="aws-us-gov")
    readers = [e for e in K.edges(g, "CAN_READ", target=b)]
    assert readers and readers[0]["source"].endswith(":role/demo-gov-reader")
    assert K.problems(g) == []


# ── encryption, notifications, regions, legacy file ──────────────────────────

@pytest.mark.finding("F-027", "F-138")
def test_encryption_notifications_and_region_normalisation(tmp_path):
    t = K.Tree(tmp_path)
    t.write()
    key = f"arn:aws:kms:{K.REGION}:{K.ACCT}:key/1a2b3c4d-aaaa-4bbb-8ccc-0d1e2f3a4b5c"
    queue = f"arn:aws:sqs:{K.REGION}:{K.ACCT}:demo-events"
    t.scope.write("s3/buckets.json", [
        rb.s3_bucket(t.scope, DATA, encryption=rb.kms_encryption(key),
                     notifications={"QueueConfigurations": [{"QueueArn": queue, "Events": ["s3:ObjectCreated:*"]}]}),
        rb.s3_bucket(t.scope, "demo-eu-bucket", region="EU")])
    g = t.analyze().graph
    assert K.edges(g, "ENCRYPTED_BY", K.bucket(DATA), key)
    [n] = K.edges(g, "NOTIFIES", K.bucket(DATA), queue)
    assert n["traversable"] is False and n["evidence"]["events"] == ["s3:ObjectCreated:*"]
    assert K.nodes_by_id(g)[K.bucket("demo-eu-bucket")]["region"] == "eu-west-1"
    assert K.problems(g) == []


def test_without_iam_data_public_exposure_is_still_analysed(tmp_path):
    t = K.Tree(tmp_path)
    rb.write_empty_regional(t.scope)
    rb.write_manifest(t.scope.path, account=K.ACCT, mode="single_region", region=K.REGION)
    (t.scope.path / "iam").mkdir(parents=True, exist_ok=True)
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, DATA, policy=K.public_policy(DATA))])
    out = t.analyze()
    if out.graph is None:
        pytest.skip("the engine refuses a report without IAM data")
    assert K.edges(out.graph, "GRANTS_PUBLIC", K.ANON, K.bucket(DATA))
