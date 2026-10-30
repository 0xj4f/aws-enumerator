"""KMS loader and the shared KMS reference resolver (F-027, F-059, F-081)."""

from __future__ import annotations

import importlib

import pytest

K = importlib.import_module("tests.fixtures.e-data.kit")


def loader():
    return K.engine("io.loaders.kms")


# ── policy status (shared by every E-data loader) ────────────────────────────

POLICY = {"Version": "2012-10-17", "Statement": []}


@pytest.mark.finding("F-059")
@pytest.mark.parametrize("record,policy,legacy_missing,expected", [
    ({"PolicyStatus": "present"}, POLICY, "absent", "present"),
    ({"PolicyStatus": "present"}, None, "absent", "unknown"),              # said present, file missing
    ({"PolicyStatus": "present"}, {"_raw": "not json"}, "absent", "error"),  # collected but unreadable
    ({"PolicyStatus": None}, POLICY, "absent", "present"),
    ({"PolicyStatus": None}, None, "absent", "unknown"),
    ({"PolicyStatus": "denied"}, None, "absent", "denied"),
    ({"PolicyStatus": "skipped"}, None, "absent", "skipped"),
    ({"PolicyStatus": "bogus"}, None, "absent", "unknown"),
    ({}, POLICY, "absent", "present"),                                     # d13c215 record with a policy
    ({}, None, "absent", "absent"),                                        # d13c215: no file
    ({}, None, "unknown", "unknown"),                                      # d13c215 customer key, no policy
    ({}, {"_raw": "x"}, "absent", "error"),
])
def test_policy_status_never_reads_unknown_as_absent(record, policy, legacy_missing, expected):
    assert loader().policy_status(record, policy, legacy_missing=legacy_missing) == expected
    assert (loader().usable_policy(policy) is not None) == (isinstance(policy, dict) and "Statement" in policy)


# ── keys, policies, grants ───────────────────────────────────────────────────

def _inventory(keys, policies, *, account=K.ACCT, partition="aws"):
    return loader().build_inventory(keys, policies, account=account, partition=partition)


@pytest.mark.finding("F-081")
def test_key_policies_are_keyed_by_key_arn_so_replicas_stay_apart():
    mrk = "mrk-0a1b2c3d4e5f60718293a4b5c6d7e8f9"
    keys = {r: [K.v2_key(mrk, region=r, multi_region=True)] for r in (K.OTHER, K.REGION)}
    files = {K.OTHER: [{"KeyId": mrk, "Arn": K.key_arn(mrk, K.OTHER), "Policy": {"Statement": [{"Sid": "a"}]}}],
             K.REGION: [{"KeyId": mrk, "Policy": {"Statement": [{"Sid": "b"}]}}]}    # legacy file: no Arn
    inv = _inventory(keys, files)
    assert [k.arn for k in inv.keys] == [K.key_arn(mrk, K.OTHER), K.key_arn(mrk, K.REGION)]
    sids = {k.region: k.policy["Statement"][0]["Sid"] for k in inv.keys}
    assert sids == {K.OTHER: "a", K.REGION: "b"}
    assert all(k.multi_region for k in inv.keys)


@pytest.mark.finding("F-059")
def test_null_grants_and_aliases_are_unknown_not_empty():
    inv = _inventory({K.REGION: [K.v2_key(aliases=None, grants=None, policy_status="denied")]}, {})
    key = inv.keys[0]
    assert key.aliases is None and key.grants is None and key.policy_status == "denied"
    assert K.REGION in inv.alias_unknown
    assert set(key.errors.gaps) == {"kms:ListAliases:denied", "kms:ListGrants:denied"}


@pytest.mark.finding("F-059")
def test_legacy_records_keep_their_d13c215_meaning():
    customer = K.rb.kms_key(K.KEY_ID, account=K.ACCT, region=K.REGION)
    aws = K.rb.kms_key(K.AWS_KEY_ID, account=K.ACCT, region=K.REGION, manager="AWS",
                       aliases=["alias/aws/ssm"])
    inv = _inventory({K.REGION: [customer, aws]}, {})
    by_id = {k.key_id: k for k in inv.keys}
    assert by_id[K.KEY_ID].legacy and by_id[K.KEY_ID].policy_status == "unknown"   # every key has a policy
    assert by_id[K.KEY_ID].grants == ()                                            # listed, none
    assert by_id[K.AWS_KEY_ID].aws_managed and by_id[K.AWS_KEY_ID].policy_status == "skipped"
    assert by_id[K.AWS_KEY_ID].grants is None             # d13c215 never listed the grants of AWS-managed keys


def test_grant_records_are_normalised():
    grants = [K.kms_grant("arn:aws:iam::123456789012:role/demo-b", ["Decrypt"], "bbbb"),
              K.kms_grant("arn:aws:iam::123456789012:role/demo-a", ["Encrypt", "Decrypt"], "aaaa",
                          constraints={"EncryptionContextEquals": {"k": "v"}}),
              {"GrantId": "cccc", "Operations": ["Decrypt"]}]                         # no grantee: dropped
    key = _inventory({K.REGION: [K.v2_key(grants=grants)]}, {}).keys[0]
    assert [(g.grant_id, g.operations, g.constrained) for g in key.grants] == [
        ("aaaa", ("Decrypt", "Encrypt"), True), ("bbbb", ("Decrypt",), False)]


# ── the resolver (F-027) ─────────────────────────────────────────────────────

def _resolver():
    keys = {K.REGION: [K.v2_key(K.KEY_ID, aliases=["alias/demo-app"]),
                       K.v2_key(K.AWS_KEY_ID, manager="AWS", aliases=["alias/aws/secretsmanager"])],
            K.OTHER: [K.v2_key(K.KEY_ID_2, region=K.OTHER, aliases=None)]}
    inv = _inventory(keys, {})
    return loader().KmsResolver(inv, account=K.ACCT, partition="aws")


@pytest.mark.finding("F-027")
@pytest.mark.parametrize("ref,default,expected,resolved", [
    (K.key_arn(K.KEY_ID), None, K.key_arn(K.KEY_ID), True),
    (K.KEY_ID, None, K.key_arn(K.KEY_ID), True),
    ("alias/demo-app", None, K.key_arn(K.KEY_ID), True),
    (f"arn:aws:kms:{K.REGION}:{K.ACCT}:alias/demo-app", None, K.key_arn(K.KEY_ID), True),
    (None, "alias/aws/secretsmanager", K.key_arn(K.AWS_KEY_ID), True),
    ("alias/missing", None, f"arn:aws:kms:{K.REGION}:{K.ACCT}:alias/missing", False),
    (K.key_arn(K.KEY_ID_2, account=K.FOREIGN), None, K.key_arn(K.KEY_ID_2, account=K.FOREIGN), True),
])
def test_references_resolve_to_the_key_node(ref, default, expected, resolved):
    kref = _resolver().resolve(ref, region=K.REGION, account=K.ACCT, default_alias=default)
    assert (kref.node_id, kref.resolved) == (expected, resolved)


@pytest.mark.finding("F-027")
def test_unresolved_aliases_are_region_qualified_placeholders():
    r = _resolver()
    west = r.resolve("alias/aws/ssm", region=K.REGION, account=K.ACCT)
    east = r.resolve("alias/aws/ssm", region=K.OTHER, account=K.ACCT)
    assert west.node_id != east.node_id and not west.resolved and not east.resolved
    assert K.REGION in west.node_id and K.OTHER in east.node_id
    assert r.aliases_unknown(K.OTHER) and not r.aliases_unknown(K.REGION)
    assert r.resolve(None, region=K.REGION, account=K.ACCT) is None
    assert r.resolve("arn:aws:s3:::not-a-key", region=K.REGION, account=K.ACCT) is None


@pytest.mark.finding("F-010", "F-025")
def test_the_loader_reads_only_the_explicit_regions(tmp_path):
    run = K.Run(tmp_path, regions=(K.REGION,))
    run.write_json(K.REGION, "kms/keys.json", [K.v2_key()])
    stray = run.path / K.OTHER / "kms"
    stray.mkdir(parents=True)
    (stray / "keys.json").write_text('[{"KeyId": "x", "Arn": "' + K.key_arn(K.KEY_ID_2, K.OTHER) + '"}]')
    run.finish()
    res = run.analyze()
    kms_nodes = [n["id"] for n in res.graph["nodes"] if n["type"] == "kms"]
    assert kms_nodes == [K.key_arn()]
