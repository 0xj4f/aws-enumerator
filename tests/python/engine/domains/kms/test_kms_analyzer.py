"""KMS analyzer (E-data): key-policy-first access through the policy evaluator (engine.md §2.4 step 7, §5)."""

from __future__ import annotations

import importlib

import pytest

K = importlib.import_module("tests.fixtures.e-data.kit")
rb = K.rb

KEY = K.key_arn()
ROLE = K.iam_arn


def _run(tmp_path, policy, *, setup=None, key=None, extra_keys=(), files=None, regions=(K.REGION,)):
    """A v2 run with one key (``policy`` is its key policy; ``None`` writes no policy file)."""
    run = K.Run(tmp_path, regions=regions)
    if setup is not None:
        setup(run.iam)
    key = key or K.v2_key()
    run.write_json(K.REGION, "kms/keys.json", [key, *extra_keys])
    if policy is not None:
        run.write_json(K.REGION, f"kms/key_policies/{key['KeyId']}.json", K.key_policy_file(key, policy))
    for (unit, rel), data in (files or {}).items():
        run.write_json(unit, rel, data)
    run.finish()
    res = run.analyze()
    assert K.problems(res.graph) == []
    assert K.statuses(res.result).get("kms") == "ok"
    return res


def _types(res, source, target=KEY):
    return K.types_between(res.graph, source, target)


# ── F-028: key-policy delegation, aliases, GenerateDataKey ───────────────────

@pytest.mark.finding("F-028")
def test_iam_permission_counts_only_when_the_key_policy_delegates_to_the_account(tmp_path):
    def setup(iam):
        iam.role("demo-admin-named", K.EC2_TRUST)
        iam.role("demo-iam-decrypt", K.EC2_TRUST, inline={"p": [rb.allow("kms:Decrypt", "*")]})

    hardened = rb.resource_policy(rb.grant({"AWS": ROLE("role", "demo-admin-named")}, "kms:*"))
    res = _run(tmp_path / "hardened", hardened, setup=setup)
    assert _types(res, ROLE("role", "demo-iam-decrypt")) == []          # K2: IAM alone does nothing
    assert "KMS_GRANTS_DECRYPT" in _types(res, ROLE("role", "demo-admin-named"))

    delegated = rb.resource_policy(K.root_delegation())
    res = _run(tmp_path / "delegated", delegated, setup=setup)
    edge = K.edges(res.graph, "CAN_DECRYPT", ROLE("role", "demo-iam-decrypt"), KEY)
    assert edge and edge[0]["confidence"] == "definite" and edge[0]["traversable"] is True
    assert _types(res, ROLE("role", "demo-admin-named")) == []           # delegation grants nobody directly


@pytest.mark.finding("F-028")
def test_generate_data_key_is_encrypt_only(tmp_path):
    def setup(iam):
        iam.role("demo-writer", K.EC2_TRUST, inline={"p": [rb.allow(
            ["kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:GenerateDataKeyPair"], "*")]})
        iam.role("demo-reader", K.EC2_TRUST, inline={"p": [rb.allow(["kms:Decrypt", "kms:GenerateDataKey"], "*")]})

    res = _run(tmp_path, rb.resource_policy(K.root_delegation()), setup=setup)
    assert _types(res, ROLE("role", "demo-writer")) == ["CAN_ENCRYPT"]
    enc = K.edges(res.graph, "CAN_ENCRYPT", ROLE("role", "demo-writer"), KEY)[0]
    assert enc["traversable"] is False and enc["traversal"] == "info"
    # a principal that can decrypt gets no redundant info edge
    assert _types(res, ROLE("role", "demo-reader")) == ["CAN_DECRYPT"]


@pytest.mark.finding("F-028")
def test_an_alias_arn_in_an_iam_resource_never_grants_the_key(tmp_path):
    alias_arn = f"arn:aws:kms:{K.REGION}:{K.ACCT}:alias/demo-app"

    def setup(iam):
        iam.role("demo-alias-resource", K.EC2_TRUST, inline={"p": [rb.allow("kms:Decrypt", alias_arn)]})
        iam.role("demo-alias-condition", K.EC2_TRUST, inline={"p": [rb.allow(
            "kms:Decrypt", "*", cond={"ForAnyValue:StringEquals": {"kms:ResourceAliases": "alias/demo-app"}})]})
        iam.role("demo-other-alias", K.EC2_TRUST, inline={"p": [rb.allow(
            "kms:Decrypt", "*", cond={"ForAnyValue:StringEquals": {"kms:ResourceAliases": "alias/other"}})]})

    key = K.v2_key(aliases=["alias/demo-app"])
    res = _run(tmp_path, rb.resource_policy(K.root_delegation()), setup=setup, key=key)
    assert _types(res, ROLE("role", "demo-alias-resource")) == []        # K3
    assert _types(res, ROLE("role", "demo-alias-condition")) == ["CAN_DECRYPT"]
    assert _types(res, ROLE("role", "demo-other-alias")) == []


# ── F-029: principals named in the key policy ────────────────────────────────

@pytest.mark.finding("F-029")
def test_key_users_and_admins_named_in_the_key_policy_get_edges(tmp_path):
    def setup(iam):
        for name in ("demo-key-user", "demo-key-admin", "demo-bystander"):
            iam.role(name, K.EC2_TRUST)

    policy = rb.resource_policy(
        K.root_delegation(),
        rb.grant({"AWS": ROLE("role", "demo-key-user")}, ["kms:Decrypt", "kms:DescribeKey"]),
        rb.grant({"AWS": ROLE("role", "demo-key-admin")}, ["kms:PutKeyPolicy", "kms:CreateGrant"]))
    res = _run(tmp_path, policy, setup=setup)
    user = K.edges(res.graph, "KMS_GRANTS_DECRYPT", ROLE("role", "demo-key-user"), KEY)
    assert user and user[0]["confidence"] == "definite" and user[0]["traversable"] is True
    assert user[0]["evidence"]["statements"][0]["layer"] == "key_policy"
    assert _types(res, ROLE("role", "demo-key-admin")) == ["CAN_ADMIN_KEY"]
    assert _types(res, ROLE("role", "demo-bystander")) == []
    legacy = res.legacy("kms_relationships.json")
    rendered = [e for e in legacy["edges"] if e["type"] == "KMS_GRANTS_DECRYPT"]
    assert rendered and rendered[0]["source"] == f"kms:{KEY}"           # d13c215 direction (key -> grantee)


@pytest.mark.finding("F-029")
def test_a_bare_account_id_principal_is_delegation_not_a_grant(tmp_path):
    def setup(iam):
        iam.role("demo-iam-decrypt", K.EC2_TRUST, inline={"p": [rb.allow("kms:Decrypt", "*")]})
        iam.role("demo-bystander", K.EC2_TRUST)

    res = _run(tmp_path, rb.resource_policy(rb.grant({"AWS": K.ACCT}, "kms:*")), setup=setup)
    assert _types(res, ROLE("role", "demo-iam-decrypt")) == ["CAN_DECRYPT"]
    assert _types(res, ROLE("role", "demo-bystander")) == []


# ── F-001 / F-014 / F-015 through the evaluator ──────────────────────────────

@pytest.mark.finding("F-001", "F-014", "F-015")
def test_deny_notaction_and_conditions_decide_key_access(tmp_path):
    def setup(iam):
        iam.role("demo-denied", K.EC2_TRUST, inline={"p": [rb.allow("kms:*", "*"),
                                                             rb.deny(["kms:Decrypt", "kms:ReEncrypt*"], "*")]})
        iam.role("demo-half-denied", K.EC2_TRUST, inline={"p": [rb.allow("kms:*", "*"), rb.deny("kms:Decrypt", "*")]})
        iam.role("demo-poweruser", K.EC2_TRUST, inline={"p": [{"Effect": "Allow", "NotAction": ["iam:*"],
                                                                "Resource": "*"}]})
        iam.role("demo-mfa", K.EC2_TRUST, inline={"p": [rb.allow(
            "kms:Decrypt", "*", cond={"Bool": {"aws:MultiFactorAuthPresent": "true"}})]})

    res = _run(tmp_path, rb.resource_policy(K.root_delegation()), setup=setup)
    assert "CAN_DECRYPT" not in _types(res, ROLE("role", "demo-denied"))
    assert "CAN_ADMIN_KEY" in _types(res, ROLE("role", "demo-denied"))
    # ReEncryptFrom still decrypts (into a key the caller controls): denying Decrypt alone is not enough
    half = K.edges(res.graph, "CAN_DECRYPT", ROLE("role", "demo-half-denied"), KEY)
    assert half and half[0]["evidence"]["actions"] == ["kms:ReEncryptFrom"]
    assert {"CAN_DECRYPT", "CAN_ADMIN_KEY"} <= set(_types(res, ROLE("role", "demo-poweruser")))
    mfa = K.edges(res.graph, "CAN_DECRYPT", ROLE("role", "demo-mfa"), KEY)
    assert mfa and mfa[0]["confidence"] == "conditional"


@pytest.mark.finding("F-002")
def test_a_single_object_key_policy_statement_is_read(tmp_path):
    policy = {"Version": "2012-10-17",
              "Statement": {"Effect": "Allow", "Principal": "*", "Action": "kms:Decrypt", "Resource": "*"}}
    res = _run(tmp_path, policy)
    assert K.findings(res.graph, "KMS-PUB-001", KEY)


# ── grants ───────────────────────────────────────────────────────────────────

@pytest.mark.finding("F-029", "F-039")
def test_decrypt_capable_grants_give_kms_grant_edges(tmp_path):
    ext_role = ROLE("role", "demo-partner", account=K.FOREIGN)
    grants = [K.kms_grant(ROLE("role", "demo-grantee"), ["Decrypt"], "1111aaaa"),
              K.kms_grant(ROLE("role", "demo-constrained"), ["Decrypt"], "2222bbbb",
                          constraints={"EncryptionContextSubset": {"app": "demo"}}),
              K.kms_grant(ROLE("role", "demo-gdk"), ["GenerateDataKey"], "3333cccc"),
              K.kms_grant(ext_role, ["ReEncryptFrom"], "4444dddd"),
              K.kms_grant(f"rds.{K.REGION}.amazonaws.com", ["Decrypt", "Encrypt"], "5555eeee")]

    def setup(iam):
        for name in ("demo-grantee", "demo-constrained", "demo-gdk"):
            iam.role(name, K.EC2_TRUST)

    res = _run(tmp_path, rb.resource_policy(K.root_delegation()), setup=setup, key=K.v2_key(grants=grants))
    grantee = K.edges(res.graph, "KMS_GRANT", ROLE("role", "demo-grantee"), KEY)
    assert grantee and grantee[0]["confidence"] == "definite"
    assert grantee[0]["evidence"]["grant_id"] == "1111aaaa"
    assert K.edges(res.graph, "KMS_GRANT", ROLE("role", "demo-constrained"), KEY)[0]["confidence"] == "conditional"
    assert _types(res, ROLE("role", "demo-gdk")) == []
    ext = K.edges(res.graph, "KMS_GRANT", ext_role, KEY)
    assert ext and ext[0]["props"]["cross_account"] is True
    assert K.nodes_by_id(res.graph)[ext_role]["type"] == "external_principal"
    assert K.edges(res.graph, "KMS_GRANT", f"svc:rds.{K.REGION}.amazonaws.com", KEY)


# ── exposure: public and cross-account key policies (F-031, F-037) ──────────

@pytest.mark.finding("F-031", "F-037")
def test_public_key_policies_are_graded_by_condition_strength(tmp_path):
    keys = {"open": K.KEY_ID, "guarded": K.KEY_ID_2, "tls": "9d0e1f2a-cccc-4ddd-8eee-3b4c5d6e7f80"}
    policies = {
        "open": rb.resource_policy(rb.grant("*", "kms:Decrypt")),
        "guarded": rb.resource_policy(rb.grant("*", ["kms:Decrypt", "kms:Encrypt"],
                                               cond={"StringEquals": {"kms:CallerAccount": K.ACCT,
                                                                      "kms:ViaService": f"s3.{K.REGION}"
                                                                                        ".amazonaws.com"}})),
        "tls": rb.resource_policy(rb.grant("*", "kms:Decrypt", cond={"Bool": {"aws:SecureTransport": "true"}})),
    }
    run = K.Run(tmp_path)
    records = [K.v2_key(k) for k in keys.values()]
    run.write_json(K.REGION, "kms/keys.json", records)
    for label, key_id in keys.items():
        rec = next(r for r in records if r["KeyId"] == key_id)
        run.write_json(K.REGION, f"kms/key_policies/{key_id}.json", K.key_policy_file(rec, policies[label]))
    run.finish()
    res = run.analyze()
    assert K.problems(res.graph) == []
    arn = {label: K.key_arn(k) for label, k in keys.items()}
    open_f = K.findings(res.graph, "KMS-PUB-001", arn["open"])
    assert [(f["severity"], f["confidence"]) for f in open_f] == [("HIGH", "definite")]
    pub = K.edges(res.graph, "KMS_GRANTS_PUBLIC", K.ANON, arn["open"])
    assert pub and pub[0]["props"]["auth"] == "any-aws-account"
    assert K.findings(res.graph, "KMS-PUB-001", arn["guarded"]) == []
    assert K.edges(res.graph, "KMS_GRANTS_PUBLIC", K.ANON, arn["guarded"]) == []
    assert K.nodes_by_id(res.graph)[arn["guarded"]]["props"]["public_grant"] == "restricted"
    # a condition the caller controls (aws:SecureTransport) does not make the policy private (F-031 case A)
    tls = K.findings(res.graph, "KMS-PUB-001", arn["tls"])
    assert [f["severity"] for f in tls] == ["HIGH"]


@pytest.mark.finding("F-031", "F-039")
def test_cross_account_key_policy_grants(tmp_path):
    foreign_root = f"arn:aws:iam::{K.FOREIGN}:root"
    foreign_role = ROLE("role", "demo-partner", account=K.FOREIGN)
    policy = rb.resource_policy(K.root_delegation(), rb.grant({"AWS": foreign_root}, "kms:Decrypt"),
                                rb.grant({"AWS": foreign_role}, ["kms:Decrypt", "kms:Encrypt"]))
    res = _run(tmp_path, policy)
    for node, ntype in ((foreign_root, "external_account"), (foreign_role, "external_principal")):
        edge = K.edges(res.graph, "KMS_GRANTS_CROSS_ACCOUNT", node, KEY)
        assert edge and edge[0]["props"]["cross_account"] is True
        assert K.nodes_by_id(res.graph)[node]["type"] == ntype
    xacct = K.findings(res.graph, "KMS-XACCT-001", KEY)
    assert len(xacct) == 1 and xacct[0]["evidence"]["accounts"] == [K.FOREIGN]
    assert sorted(xacct[0]["related_node_ids"]) == sorted([foreign_root, foreign_role])


# ── F-081: multi-Region replicas ─────────────────────────────────────────────

@pytest.mark.finding("F-081")
def test_multi_region_replicas_are_evaluated_against_their_own_policies(tmp_path):
    mrk = "mrk-0a1b2c3d4e5f60718293a4b5c6d7e8f9"
    run = K.Run(tmp_path, regions=(K.OTHER, K.REGION))
    policies = {K.OTHER: rb.resource_policy(rb.grant("*", "kms:Decrypt")),
                K.REGION: rb.resource_policy(rb.grant({"AWS": f"arn:aws:iam::{K.FOREIGN}:root"}, "kms:Decrypt"))}
    for region, policy in policies.items():
        key = K.v2_key(mrk, region=region, multi_region=True)
        run.write_json(region, "kms/keys.json", [key])
        run.write_json(region, f"kms/key_policies/{mrk}.json", K.key_policy_file(key, policy))
    run.finish()
    res = run.analyze()
    assert K.problems(res.graph) == []
    east, west = K.key_arn(mrk, K.OTHER), K.key_arn(mrk, K.REGION)
    assert K.findings(res.graph, "KMS-PUB-001", east) and not K.findings(res.graph, "KMS-PUB-001", west)
    assert K.findings(res.graph, "KMS-XACCT-001", west) and not K.findings(res.graph, "KMS-XACCT-001", east)
    nodes = K.nodes_by_id(res.graph)
    assert nodes[east]["region"] == K.OTHER and nodes[west]["region"] == K.REGION


# ── unknown is not absent (F-059, requests/c-b-1.md) ─────────────────────────

@pytest.mark.finding("F-059", "F-028")
def test_unknown_grants_aliases_and_policies_are_gaps(tmp_path):
    def setup(iam):
        iam.role("demo-iam-decrypt", K.EC2_TRUST, inline={"p": [rb.allow("kms:Decrypt", "*")]})

    key = K.mark(K.v2_key(aliases=None, grants=None, policy_status="denied"), K.denied("kms:GetKeyPolicy"))
    res = _run(tmp_path, None, setup=setup, key=key)
    node = K.nodes_by_id(res.graph)[KEY]
    assert node["coverage"]["status"] == "partial"
    assert {"kms:GetKeyPolicy:denied", "kms:ListAliases:denied", "kms:ListGrants:denied",
            "kms:ListAliases:unknown", "kms:ListGrants:unknown"} <= set(node["coverage"]["gaps"])
    assert "aliases" not in node["props"] and "grant_count" not in node["props"]     # unknown, not []
    gaps = K.gaps(res.graph)
    assert gaps["kms:key-policy-unknown"]["count"] == 1
    assert {"kms:grants-unknown", "kms:aliases-unknown"} <= set(gaps)
    edge = K.edges(res.graph, "CAN_DECRYPT", ROLE("role", "demo-iam-decrypt"), KEY)
    assert edge and edge[0]["confidence"] == "conditional"
    assert "kms:key-policy-unknown" in edge[0]["evidence"]["gaps"]
    assert K.findings(res.graph, "KMS-PUB-001") == []                    # unknown is not "public"


@pytest.mark.finding("F-028")
def test_aws_managed_key_without_a_policy_is_via_service_only(tmp_path):
    def setup(iam):
        iam.role("demo-iam-decrypt", K.EC2_TRUST, inline={"p": [rb.allow("kms:Decrypt", "*")]})

    key = K.v2_key(K.AWS_KEY_ID, manager="AWS", aliases=["alias/aws/secretsmanager"], policy_status="skipped")
    res = _run(tmp_path, None, setup=setup, key=key)
    arn = K.key_arn(K.AWS_KEY_ID)
    edge = K.edges(res.graph, "CAN_DECRYPT", ROLE("role", "demo-iam-decrypt"), arn)[0]
    assert edge["confidence"] == "conditional" and edge["evidence"]["condition_strength"] == "strong"
    assert any(c["operator"] == "via_service_only" for c in edge["evidence"]["conditions"])
    assert "kms:key-policy-unknown" not in K.gaps(res.graph)
    assert K.nodes_by_id(res.graph)[arn]["props"]["aws_managed"] is True


# ── structure: native registration, groups, legacy entry points ──────────────

@pytest.mark.finding("F-002", "F-084")
def test_kms_runs_natively_without_the_legacy_adapter(tmp_path):
    res = _run(tmp_path, rb.resource_policy(K.root_delegation()))
    names = [s.name for s in res.result.analyzer_status]
    assert "kms" in names and "kms:fallback" not in names
    assert res.legacy("kms_relationships.json") == {"edges": [], "findings": []}


@pytest.mark.finding("F-022")
def test_group_grants_are_one_group_edge_not_one_per_member(tmp_path):
    def setup(iam):
        iam.group("demo-crypto", inline={"p": [rb.allow("kms:Decrypt", "*")]})
        iam.user("demo-member", groups=["demo-crypto"])

    res = _run(tmp_path, rb.resource_policy(K.root_delegation()), setup=setup)
    group, user = ROLE("group", "demo-crypto"), ROLE("user", "demo-member")
    assert _types(res, group) == ["CAN_DECRYPT"]
    assert K.edges(res.graph, "MEMBER_OF", user, group)
    assert _types(res, user) == []


@pytest.mark.finding("F-028", "F-081")
def test_an_old_report_layout_is_analysed_natively_and_rendered_into_the_legacy_file(tmp_path):
    """Old (d13c215) layouts stay analysable with ``analyze <dir>``; the d13c215 entry points are gone (D-53)."""
    kms = K.engine("analyzers.kms")
    for gone in ("_classify_kms_access", "_load_kms_data", "_analyze_kms_relationships", "KMS_ACCESS_WEIGHTS"):
        assert not hasattr(kms, gone), gone
    tree = K.Tree(tmp_path)
    tree.iam.role("demo-key-user", K.EC2_TRUST)
    key = rb.kms_key(K.KEY_ID, account=K.ACCT, region=K.REGION)
    tree.write_json("kms/keys.json", [key])
    tree.write_json(f"kms/key_policies/{K.KEY_ID}.json", rb.kms_policy_file(key, rb.resource_policy(
        rb.grant({"AWS": ROLE("role", "demo-key-user")}, "kms:Decrypt"))))
    tree.write(skip={"kms"})
    res = tree.analyze()
    assert K.statuses(res.result)["kms"] == "ok" and K.problems(res.graph) == []
    assert K.edges(res.graph, "KMS_GRANTS_DECRYPT", ROLE("role", "demo-key-user"), KEY)
    legacy = K.load(res.dir / "kms_relationships.json")
    assert ("KMS_GRANTS_DECRYPT", f"kms:{KEY}", ROLE("role", "demo-key-user")) in {
        (e["type"], e["source"], e["target"]) for e in legacy["edges"]}             # stored key -> grantee
