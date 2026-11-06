"""Contract and finding tests for the migrated ``eks`` collector (collectors-cli.md §5.14).

Runs ``collect(ctx)`` through ``collectors.base.run_collector`` against the acme world (FakeAWS): every
listing follows pagination (F-107), access entries, associated access policies and Pod Identity
associations are collected (F-050), add-on configuration values never reach the report, failures keep
stable shapes, and the module only calls the IAM actions its spec declares.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict

import jsonschema
import pytest
from botocore.exceptions import EndpointConnectionError

from tests.fixtures.regressions import support as S
from tests.fixtures.worlds import acme
from tests.support import targets
from tests.support.fakeaws import AWSError

pytestmark = pytest.mark.collectors

W1, W2 = "eu-west-1", "eu-west-2"
COVERAGE = jsonschema.Draft202012Validator(json.loads((targets.schema_path("coverage-1.schema.json")).read_text()))
EKS_FILES = ("clusters.json", "nodegroups.json", "fargate_profiles.json", "addons.json", "access_entries.json",
             "pod_identity_associations.json")


def run_eks(tmp_path: Path, *, world=None, region: str = W2) -> S.ModuleRun:
    return S.run_module("eks", world or acme.build_world(), tmp_path, region=region)


def coverage(run: S.ModuleRun) -> Dict[str, Any]:
    doc = S.load_json(run.out / "_coverage.json")
    COVERAGE.validate(doc)
    return doc


def override_cluster(world, **changes: Any) -> None:
    """DescribeCluster answers with ``changes`` applied (acme.py itself stays frozen)."""
    original = world.handlers[("eks", "DescribeCluster")]

    def describe(req):
        out = copy.deepcopy(original(req))
        out["cluster"].update(changes)
        for key, value in changes.items():
            if value is None:
                out["cluster"].pop(key, None)
        return out

    world.handlers[("eks", "DescribeCluster")] = describe


def assert_no_error_objects(root: Path) -> None:
    for path in S.files_under(root):
        if path.name == "_coverage.json":
            continue
        for value in _walk(S.load_json(path)):
            assert not (isinstance(value, dict) and ("Error" in value or "error" in value)), (path, value)


def _walk(obj: Any):
    yield obj
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)


# ── happy path ───────────────────────────────────────────────────────────────
@pytest.mark.finding("F-050")
def test_happy_path_writes_every_file_with_stable_shapes(tmp_path):
    run = run_eks(tmp_path)
    assert run.result.protocol == "ctx"
    assert run.result.status == "partial"  # acme denies DescribeAccessEntry for demo-alice
    for name in EKS_FILES:
        data = run.load(name)
        assert isinstance(data, list if name == "clusters.json" else dict), name
    clusters = run.load("clusters.json")
    assert [c["name"] for c in clusters] == ["demo-cluster"]
    assert clusters[0]["certificateAuthority"]["data"] == acme.EKS_CA_DATA
    assert [n["nodegroupName"] for n in run.load("nodegroups.json")["demo-cluster"]] == ["demo-ng"]
    assert [f["fargateProfileName"] for f in run.load("fargate_profiles.json")["demo-cluster"]] == ["demo-fp"]
    value = run.result.value
    assert [c["name"] for c in value["clusters"]] == ["demo-cluster"]
    assert value["namespaces"] == {"demo-cluster": ["demo-apps"]}  # access-entry scope + Pod Identity
    assert coverage(run)["protocol"] == "ctx"
    assert_no_error_objects(run.out)


@pytest.mark.finding("F-050")
def test_access_entries_carry_their_associated_access_policies(tmp_path):
    entries = {e["principalArn"]: e for e in run_eks(tmp_path).load("access_entries.json")["demo-cluster"]}
    admin = entries[acme.role_arn("demo-admin-role")]
    assert admin["type"] == "STANDARD" and admin["username"] == "demo-admin"
    assert [p["policyArn"] for p in admin["associatedAccessPolicies"]] == [
        "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"]
    assert admin["associatedAccessPolicies"][0]["accessScope"] == {"type": "cluster", "namespaces": []}
    alice = entries[acme.iam_arn("user", "demo-alice")]          # DescribeAccessEntry denied (injection)
    assert alice["CollectionErrors"] == [{"api": "eks:DescribeAccessEntry", "status": "denied",
                                          "error_code": "AccessDeniedException"}]
    assert alice["associatedAccessPolicies"][0]["accessScope"]["namespaces"] == ["demo-apps"]
    assert "CollectionErrors" not in entries[acme.role_arn("demo-eks-node-role")]


@pytest.mark.finding("F-050")
def test_pod_identity_associations_name_their_role(tmp_path):
    assocs = run_eks(tmp_path).load("pod_identity_associations.json")["demo-cluster"]
    assert [(a["namespace"], a["serviceAccount"], a["roleArn"]) for a in assocs] == [
        ("demo-apps", "demo-worker", acme.role_arn("demo-app-role"))]


@pytest.mark.finding("F-050")
def test_config_map_cluster_skips_access_entries_instead_of_denied(tmp_path):
    world = acme.build_world()
    override_cluster(world, accessConfig={"authenticationMode": "CONFIG_MAP"})
    run = run_eks(tmp_path, world=world)
    assert run.load("access_entries.json") == {"demo-cluster": []}
    assert run.fake.calls_for("eks", "ListAccessEntries") == []
    doc = coverage(run)
    rows = [c for c in doc["calls"] if c["api"] == "eks:ListAccessEntries"]
    assert rows == [{"api": "eks:ListAccessEntries", "status": "skipped", "count": 1, "items": None, "pages": 0,
                     "error_code": "AuthenticationMode:CONFIG_MAP", "not_configured": False, "primary": False,
                     "optional": True}]
    assert run.result.status == "ok"  # nothing denied; the skip is deliberate
    assert "eks:ListAccessEntries" not in run.result.denied_apis


def test_unknown_authentication_mode_still_lists_and_treats_invalid_request_as_not_configured(tmp_path):
    world = acme.build_world()
    override_cluster(world, accessConfig=None)

    @world.op("eks", "ListAccessEntries")
    def config_map_only(req):
        raise AWSError("InvalidRequestException", "The cluster's authentication mode must be set to one of "
                                                  "[API, API_AND_CONFIG_MAP] to perform this operation.", 400)

    run = run_eks(tmp_path, world=world)
    assert run.load("access_entries.json") == {"demo-cluster": []}
    row = [c for c in coverage(run)["calls"] if c["api"] == "eks:ListAccessEntries"][0]
    assert row["status"] == "ok" and row["not_configured"] is True


def test_addon_configuration_values_are_never_written(tmp_path):
    run = run_eks(tmp_path)
    addons = {a["addonName"]: a for a in run.load("addons.json")["demo-cluster"]}
    assert addons["demo-observability"]["configurationValuesPresent"] is True
    assert addons["vpc-cni"]["configurationValuesPresent"] is False
    assert all("configurationValues" not in a for a in addons.values())
    assert S.grep_tree(acme.CANARIES["eks_addon_config"], tmp_path) == []


# ── pagination (F-107) ───────────────────────────────────────────────────────
@pytest.mark.finding("F-107")
@pytest.mark.parametrize("operation", ["ListClusters", "ListAddons", "ListAccessEntries"])
def test_every_listing_follows_pagination(tmp_path, operation):
    world = acme.build_world()
    world.page_sizes[("eks", operation)] = 1
    run = run_eks(tmp_path, world=world, region=W1 if operation == "ListClusters" else W2)
    calls = run.fake.calls_for("eks", operation)
    assert len(calls) >= 2, f"{operation} was not paginated"
    if operation == "ListClusters":
        assert [c["name"] for c in run.load("clusters.json")] == ["demo-denied-cluster", "demo-west-cluster"]
    elif operation == "ListAddons":
        assert {a["addonName"] for a in run.load("addons.json")["demo-cluster"]} == {"demo-observability", "vpc-cni"}
    else:
        assert len(run.load("access_entries.json")["demo-cluster"]) == 3


@pytest.mark.finding("F-107")
def test_two_page_nodegroups(tmp_path):
    world = acme.build_world()
    world.page_sizes[("eks", "ListNodegroups")] = 1
    second = {"nodegroupName": "demo-ng-2", "clusterName": "demo-cluster", "status": "ACTIVE",
              "nodeRole": acme.role_arn("demo-eks-node-role")}
    list_ng, describe_ng = world.handlers[("eks", "ListNodegroups")], world.handlers[("eks", "DescribeNodegroup")]

    @world.op("eks", "ListNodegroups")
    def list_nodegroups(req):
        return {"nodegroups": list_ng(req)["nodegroups"] + ["demo-ng-2"]}

    @world.op("eks", "DescribeNodegroup")
    def describe_nodegroup(req):
        return {"nodegroup": second} if req.params["nodegroupName"] == "demo-ng-2" else describe_ng(req)

    run = run_eks(tmp_path, world=world)
    assert len(run.fake.calls_for("eks", "ListNodegroups")) == 2
    assert [n["nodegroupName"] for n in run.load("nodegroups.json")["demo-cluster"]] == ["demo-ng", "demo-ng-2"]


# ── failures keep stable shapes ──────────────────────────────────────────────
def test_list_clusters_denied_makes_the_module_denied_with_empty_files(tmp_path):
    world = acme.build_world()
    world.deny("eks", "ListClusters")
    run = run_eks(tmp_path, world=world)
    assert run.result.status == "denied"
    assert run.load("clusters.json") == [] and run.load("nodegroups.json") == {}
    assert run.result.value == {"clusters": [], "namespaces": {}}
    coverage(run)


@pytest.mark.parametrize("operation", [
    "DescribeCluster", "ListNodegroups", "DescribeNodegroup", "ListFargateProfiles", "DescribeFargateProfile",
    "ListAddons", "DescribeAddon", "ListAccessEntries", "DescribeAccessEntry", "ListAssociatedAccessPolicies",
    "ListPodIdentityAssociations", "DescribePodIdentityAssociation"])
def test_each_denied_call_makes_the_module_partial_and_keeps_shapes(tmp_path, operation):
    world = acme.build_world()
    world.deny("eks", operation)
    run = run_eks(tmp_path, world=world)
    assert run.result.status == "partial"
    assert f"eks:{operation}" in run.result.denied_apis
    for name in EKS_FILES:
        assert isinstance(run.load(name), list if name == "clusters.json" else dict), name
    assert_no_error_objects(run.out)
    item_errors = coverage(run)["item_errors"]
    assert any(e["api"] == f"eks:{operation}" for e in item_errors)


def test_failed_listing_omits_the_cluster_key(tmp_path):
    world = acme.build_world()
    world.deny("eks", "ListNodegroups")
    run = run_eks(tmp_path, world=world)
    assert run.load("nodegroups.json") == {}                       # unknown, not "no node groups"
    assert "demo-cluster" in run.load("fargate_profiles.json")


def test_failed_describe_keeps_a_named_item_with_collection_errors(tmp_path):
    world = acme.build_world()
    world.deny("eks", "DescribeCluster")
    run = run_eks(tmp_path, world=world)
    clusters = run.load("clusters.json")
    assert clusters == [{"name": "demo-cluster", "arn": "arn:aws:eks:eu-west-2:111122223333:cluster/demo-cluster",
                         "CollectionErrors": [{"api": "eks:DescribeCluster", "status": "denied",
                                               "error_code": "AccessDeniedException"}]}]


def test_botocore_error_mid_module_keeps_partial_data(tmp_path):
    world = acme.build_world()
    world.raise_exc("eks", "DescribeNodegroup", lambda: EndpointConnectionError(endpoint_url="https://eks"))
    run = run_eks(tmp_path, world=world)
    assert run.result.status == "partial"
    ng = run.load("nodegroups.json")["demo-cluster"][0]
    assert ng["CollectionErrors"][0]["error_code"] == "EndpointConnectionError"
    assert run.load("addons.json")["demo-cluster"]                 # later phases still ran


def test_region_with_denied_and_unreachable_parts(tmp_path):
    """eu-west-1: demo-denied-cluster's DescribeCluster and demo-west-cluster's ListFargateProfiles are denied."""
    run = run_eks(tmp_path, region=W1)
    clusters = {c["name"]: c for c in run.load("clusters.json")}
    assert "CollectionErrors" in clusters["demo-denied-cluster"] and "endpoint" in clusters["demo-west-cluster"]
    assert "demo-west-cluster" not in run.load("fargate_profiles.json")
    assert run.load("access_entries.json")["demo-west-cluster"][0]["associatedAccessPolicies"][0]["policyArn"] \
        .endswith("AmazonEKSClusterAdminPolicy")


# ── read-only and declared actions ───────────────────────────────────────────
def test_only_declared_read_only_actions_are_called(tmp_path):
    run = run_eks(tmp_path)
    spec = S.registry_module().get_registry().get("eks")
    called = {f"{c.service}:{c.operation}" for c in run.fake.calls_for()}
    assert called and called <= set(spec.actions) | set(spec.optional_actions)
    assert all(c.read_only for c in run.fake.calls_for())
