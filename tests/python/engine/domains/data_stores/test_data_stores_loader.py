"""Data-stores loader: API Gateway targets (F-099), RDS records (F-056), ECR registry (F-116), null = unknown."""

from __future__ import annotations

import importlib

import pytest

K = importlib.import_module("tests.fixtures.e-data.kit")


def loader():
    return K.engine("io.loaders.data_stores")


@pytest.mark.finding("F-099", "F-082")
@pytest.mark.parametrize("uri,arn,qualifier,unresolved", [
    (f"arn:aws:apigateway:{K.REGION}:lambda:path/2015-03-31/functions/arn:aws:lambda:{K.REGION}:{K.ACCT}:function:"
     "demo-fn/invocations", f"arn:aws:lambda:{K.REGION}:{K.ACCT}:function:demo-fn", None, False),
    (f"arn:aws:lambda:{K.REGION}:{K.ACCT}:function:demo-fn:live",
     f"arn:aws:lambda:{K.REGION}:{K.ACCT}:function:demo-fn", "live", False),
    (f"arn:aws-us-gov:lambda:us-gov-west-1:{K.ACCT}:function:demo-fn:7",
     f"arn:aws-us-gov:lambda:us-gov-west-1:{K.ACCT}:function:demo-fn", "7", False),
    (f"arn:aws-cn:lambda:cn-north-1:{K.ACCT}:function:demo-fn",
     f"arn:aws-cn:lambda:cn-north-1:{K.ACCT}:function:demo-fn", None, False),
    (f"arn:aws:lambda:{K.REGION}:{K.ACCT}:function:${{stageVariables.fn}}", None, None, True),
])
def test_lambda_targets_are_unqualified(uri, arn, qualifier, unresolved):
    route = loader().lambda_target(uri)
    assert (route.lambda_arn, route.qualifier, route.unresolved) == (arn, qualifier, unresolved)


def test_non_lambda_targets_are_ignored():
    assert loader().lambda_target("https://example.invalid/backend") is None
    assert loader().lambda_target(None) is None


@pytest.mark.finding("F-044", "F-099")
def test_v2_api_records_keep_routes_and_unknowns():
    fn = f"arn:aws:lambda:{K.REGION}:{K.ACCT}:function:demo-fn"
    api = K.v2_api("a1b2c3d4e5", integrations=[K.integration("GET", "/x", fn, qualifier="live"),
                                                K.integration("POST", "/y", fn, auth="COGNITO_USER_POOLS"),
                                                K.integration("GET", "/z", None, unresolved=True)])
    unknown = K.v2_api("b2c3d4e5f6", integrations=None, endpoint_types=None)
    inv = loader().build_inventory({"apigw": {K.REGION: [api, unknown]}}, account=K.ACCT)
    by = {a.api_id: a for a in inv.apis}
    known = by["a1b2c3d4e5"]
    assert [(r.key, r.path, r.qualifier, r.effective_auth) for r in known.routes if not r.unresolved] == [
        ("GET", "/x", "live", "NONE"), ("POST", "/y", None, "COGNITO_USER_POOLS")]
    assert [r.path for r in known.unauthenticated] == ["/x"]
    assert not known.legacy and not known.private
    gone = by["b2c3d4e5f6"]
    assert gone.routes is None and gone.unauthenticated is None and gone.endpoint_types is None
    assert gone.errors.gaps == ("apigateway:GetResources:denied",)


@pytest.mark.finding("F-056", "F-059")
def test_rds_records_tell_legacy_from_unknown():
    legacy_snap = {"Type": "rds", "Kind": "snapshot", "Arn": f"arn:aws:rds:{K.REGION}:{K.ACCT}:snapshot:demo-old",
                   "Name": "demo-old", "PublicSnapshot": False, "Encrypted": False, "KmsKeyId": None}
    v2_unknown = K.rds_snapshot("demo-new", public=None, shared=None)
    cluster_snap = K.rds_snapshot("demo-aurora", kind="cluster_snapshot", shared=[K.FOREIGN])
    inv = loader().build_inventory({"rds": {K.REGION: [legacy_snap, v2_unknown, cluster_snap]}}, account=K.ACCT)
    by = {r.name: r for r in inv.rds}
    assert by["demo-old"].legacy and by["demo-old"].shared_accounts is None
    assert not by["demo-new"].legacy and by["demo-new"].public_snapshot is None
    assert by["demo-aurora"].is_snapshot and by["demo-aurora"].shared_accounts == (K.FOREIGN,)


@pytest.mark.finding("F-116", "F-059")
def test_ecr_registry_files_per_region(tmp_path):
    run = K.Run(tmp_path, regions=(K.OTHER, K.REGION))
    run.write_json(K.REGION, "ecr/resources.json", [])
    run.write_json(K.REGION, "ecr/registry.json", {"RegistryId": K.ACCT, "ReplicationRules": [
        {"Destinations": [{"Region": K.OTHER, "RegistryId": K.FOREIGN}]}]})
    run.write_json(K.OTHER, "ecr/registry.json", {"RegistryId": K.ACCT, "ReplicationRules": None})
    run.finish()
    ctx = K.engine("context").build_run_context(run.path, regions=[K.OTHER, K.REGION])
    regs, gaps = loader()._registries(dict(ctx.region_dirs), K.ACCT)
    by = {r.region: r for r in regs}
    assert by[K.REGION].replication_accounts == (K.FOREIGN,)
    assert by[K.OTHER].replication_accounts is None and by[K.OTHER].policy_status == "unknown"
    assert gaps == {}
