"""Contract and finding tests for the migrated ``k8s`` collector (collectors-cli.md §5.16).

``eks`` then ``k8s`` run through ``collectors.base.run_collector`` against the acme world (FakeAWS) and the
fake ``kubernetes`` package (tests/support/fake_kubernetes.py), which records every REST request with its
path, query, headers and ``_request_timeout``. The ``kubernetes`` package itself is never contacted.

Covered: no Secret value, ``last-applied-configuration``, ``managedFields`` or env literal anywhere in the
output (F-009, F-054); Secret listing off by default and metadata-only when opted in (F-009, F-150);
pods carry init/ephemeral containers, hostPath, capabilities, env references and the automount flag (F-035);
nodes for the pod -> node -> node group path (F-033); ``aws-auth`` reduced to its identity mappings (F-050);
``--no-k8s`` / ``--k8s-clusters`` / ``--k8s-timeout`` honoured (F-062, F-120); ``limit``/``continue`` paging
and the 410 restart (F-149); rules review and namespaced fallback (F-152); ``dependency_missing`` when the
``kubernetes`` package is absent (F-136); stable shapes and a schema-valid ``_coverage.json``.
"""

from __future__ import annotations

import copy
import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional

import jsonschema
import pytest

from tests.fixtures.regressions import support as S
from tests.fixtures.worlds import acme
from tests.support import targets
from tests.support.fake_kubernetes import METADATA_ONLY_ACCEPT, ApiException, FakeCluster, FakeKubernetes

pytestmark = pytest.mark.collectors

W1, W2 = "eu-west-1", "eu-west-2"
ENDPOINT = acme.EKS_ENDPOINTS["demo-cluster"]
CLUSTER_ARN = "arn:aws:eks:eu-west-2:111122223333:cluster/demo-cluster"
COVERAGE = jsonschema.Draft202012Validator(json.loads(targets.schema_path("coverage-1.schema.json").read_text()))
K8S_CANARIES = ("k8s_secret_last_applied", "k8s_pod_env", "k8s_init_container_env")
LIST_FILES = ("namespaces.json", "pods.json", "service_accounts.json", "roles.json", "cluster_roles.json",
              "role_bindings.json", "cluster_role_bindings.json", "services.json", "ingresses.json", "nodes.json",
              "self_rules.json")
#: Extra canaries the hostile pod below carries.
EXTRA_CANARIES = ("DEMO-CANARY-LAST-APPLIED-POD", "DEMO-CANARY-MANAGED-FIELD", "DEMO-CANARY-ANNOTATION-VALUE",
                  "DEMO-CANARY-COMMAND", "DEMO-CANARY-ARGS", "DEMO-CANARY-EPHEMERAL-ENV", "demo-api-key",
                  "fake-service-account-token")


# ── harness ──────────────────────────────────────────────────────────────────
@dataclass
class K8sRun:
    eks: Optional[S.ModuleRun]
    k8s: S.ModuleRun
    fake: Optional[FakeKubernetes]

    def load(self, name: str, cluster: str = "demo-cluster") -> Any:
        return S.load_json(self.k8s.out / cluster / name)

    def info(self, cluster: str = "demo-cluster") -> Dict[str, Any]:
        return self.load("cluster_info.json", cluster)

    def coverage(self) -> Dict[str, Any]:
        doc = S.load_json(self.k8s.out / "_coverage.json")
        COVERAGE.validate(doc)
        return doc

    def requests(self, cluster: str = "demo-cluster") -> List[Any]:
        assert self.fake is not None
        return [c for c in self.fake.calls_for(cluster=cluster) if c.method == "call_api"]


def run_k8s(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, options: Optional[Mapping[str, Any]] = None,
            clusters: Optional[Dict[str, FakeCluster]] = None, world: Any = None, region: str = W2) -> K8sRun:
    """eks, then k8s with its value. The per-cluster rate gate is off unless ``options`` say otherwise
    (:func:`test_requests_go_through_the_per_cluster_rate_gate` covers it), so tests never sleep."""
    options = {"no_rate_limit": True, **dict(options or {})}
    fake = FakeKubernetes(clusters if clusters is not None else acme.build_k8s_clusters()).install(monkeypatch)
    world = world or acme.build_world()
    eks = S.run_module("eks", world, tmp_path, region=region, options=options)
    k8s = S.run_module("k8s", world, tmp_path, region=region, options=options, deps={"eks": eks.result.value})
    return K8sRun(eks, k8s, fake)


def demo_clusters(**changes: Any) -> Dict[str, FakeCluster]:
    clusters = acme.build_k8s_clusters()
    for key, value in changes.items():
        setattr(clusters[ENDPOINT], key, value)
    return clusters


def walk(obj: Any) -> Iterator[Any]:
    yield obj
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield key
            yield from walk(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from walk(value)


def hostile_pod() -> Dict[str, Any]:
    """A pod with every field the projection must drop or reduce (snake_case, as the fake stores it)."""
    manifest = json.dumps({"kind": "Pod", "spec": {"containers": [{"env": [
        {"name": "X", "value": "DEMO-CANARY-LAST-APPLIED-POD"}]}]}})
    return {
        "api_version": None, "kind": None,
        "metadata": {
            "name": "demo-debug", "namespace": "demo-apps", "labels": {"app": "demo-debug"},
            "annotations": {"kubectl.kubernetes.io/last-applied-configuration": manifest,
                            "demo.example.com/note": "DEMO-CANARY-ANNOTATION-VALUE",
                            "eks.amazonaws.com/role-arn": acme.role_arn("demo-irsa-role")},
            "managed_fields": [{"manager": "kubectl", "operation": "Update",
                                "fields_v1": {"f:metadata": {"DEMO-CANARY-MANAGED-FIELD": {}}}}],
            "owner_references": [{"kind": "Job", "name": "demo-debug-job", "uid": "demo-uid"}],
        },
        "spec": {
            "service_account_name": "demo-api", "automount_service_account_token": False, "host_ipc": True,
            "node_name": "ip-10-20-2-10.eu-west-2.compute.internal",
            "containers": [{
                "name": "app", "image": "public.ecr.aws/demo/app:1",
                "command": ["sh", "-c", "echo DEMO-CANARY-COMMAND"], "args": ["DEMO-CANARY-ARGS"],
                "env_from": [{"secret_ref": {"name": "demo-db-secret"}}, {"config_map_ref": {"name": "demo-config"}}],
                "security_context": {"allow_privilege_escalation": True,
                                     "capabilities": {"add": ["SYS_ADMIN", "NET_ADMIN"], "drop": ["ALL"]}}}],
            "ephemeral_containers": [{
                "name": "debugger", "image": "public.ecr.aws/demo/debug:1", "security_context": {"privileged": True},
                "env": [{"name": "TOKEN", "value": "DEMO-CANARY-EPHEMERAL-ENV"}]}],
            "volumes": [{"name": "docker", "host_path": {"path": "/var/run/docker.sock", "type": "Socket"}}],
        },
        "status": {"phase": "Running", "pod_ip": "10.20.2.99"},
    }


def with_hostile_pod() -> Dict[str, FakeCluster]:
    clusters = acme.build_k8s_clusters()
    clusters[ENDPOINT].pods = clusters[ENDPOINT].pods + [hostile_pod()]
    return clusters


def by_name(items: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {i["metadata"]["name"]: i for i in items}


# ── happy path and stable shapes ─────────────────────────────────────────────
@pytest.mark.finding("F-062")
def test_k8s_runs_by_default_and_writes_every_file(tmp_path, monkeypatch):
    run = run_k8s(tmp_path, monkeypatch)
    assert run.k8s.result.protocol == "ctx" and run.k8s.result.status == "ok"
    info = run.info()
    assert info["auth_status"] == "ok" and info["auth_mode"] == "eks-token"
    assert info["version"] == {"major": "1", "minor": "29", "git_version": "v1.29.4-eks-demo",
                               "platform": "linux/amd64"}
    assert info["self_rules_reviewed"] is True and info["secrets_listed"] is False
    for name in LIST_FILES:
        assert isinstance(run.load(name), list), name
    assert isinstance(run.load("aws_auth.json"), dict)
    assert not (run.k8s.out / "demo-cluster" / "secrets.json").exists()
    assert [n["metadata"]["name"] for n in run.load("namespaces.json")] == ["default", "demo-apps", "kube-system"]
    assert {k: v["items"] for k, v in info["resources"].items() if v["items"] is not None} == {
        "namespaces": 3, "pods": 3, "service_accounts": 4, "roles": 1, "cluster_roles": 2, "role_bindings": 1,
        "cluster_role_bindings": 2, "services": 2, "ingresses": 1, "nodes": 1}
    doc = run.coverage()
    assert doc["protocol"] == "ctx" and doc["item_errors"] == []
    assert {c["api"] for c in doc["calls"]} >= {"k8s:GetVersion", "k8s:ListPods", "k8s:ListNodes",
                                               "k8s:GetConfigMap", "k8s:CreateSelfSubjectRulesReview"}


def test_lists_are_sorted_and_the_output_is_deterministic(tmp_path, monkeypatch):
    first = run_k8s(tmp_path / "a", monkeypatch)
    second = run_k8s(tmp_path / "b", monkeypatch)
    for name in LIST_FILES + ("aws_auth.json", "cluster_info.json"):
        assert (first.k8s.out / "demo-cluster" / name).read_bytes() == \
               (second.k8s.out / "demo-cluster" / name).read_bytes(), name
    pods = first.load("pods.json")
    keys = [(p["metadata"]["namespace"], p["metadata"]["name"]) for p in pods]
    assert keys == sorted(keys)


def test_only_get_requests_except_the_rules_review(tmp_path, monkeypatch):
    run = run_k8s(tmp_path, monkeypatch, options={"k8s_secrets": True})
    methods = {(c.http_method, c.resource) for c in run.requests()}
    assert {m for m, _ in methods} == {"GET", "POST"}
    assert {r for m, r in methods if m == "POST"} == {"selfsubjectrulesreviews"}


@pytest.mark.finding("F-150")
def test_every_request_is_covered_by_the_published_rbac(tmp_path, monkeypatch):
    """The RBAC ``permissions --format k8s`` prints (SPEC.k8s_rbac, + secrets with --k8s-secrets) is enough."""
    from aws_enumerator.k8s import rbac

    spec = S.registry_module().get_registry().get("k8s")
    assert spec.k8s_rbac == rbac.REQUIRED_RULES
    assert all(resource != "secrets" for _g, resource, _v, _n in spec.k8s_rbac)
    for secrets in (False, True):
        run = run_k8s(tmp_path / str(secrets), monkeypatch, options={"k8s_secrets": secrets})
        allowed = {(resource, verb, names) for _g, resource, verbs, names in rbac.rules_for(secrets=secrets)
                   for verb in verbs}
        for call in run.requests():
            if call.resource == "version":
                continue
            plural = call.path.rstrip("/").split("/")[-1]
            if call.http_method == "POST":
                need = ("selfsubjectrulesreviews", "create", ())
            elif plural == "aws-auth":
                need = ("configmaps", "get", ("aws-auth",))
            else:
                need = (plural, "list", ())
            assert need in allowed, (secrets, call.path)


# ── secret values never reach the report (F-009, F-054, F-150) ───────────────
@pytest.mark.finding("F-009", "F-150")
def test_no_secret_request_by_default(tmp_path, monkeypatch):
    run = run_k8s(tmp_path, monkeypatch)
    assert [c for c in run.fake.calls if c.resource == "secrets"] == []
    for name in K8S_CANARIES:
        assert S.grep_tree(acme.CANARIES[name], tmp_path) == [], name


@pytest.mark.finding("F-009", "F-054")
@pytest.mark.parametrize("secrets", [False, True])
def test_canaries_never_reach_any_file(tmp_path, monkeypatch, secrets):
    run_k8s(tmp_path, monkeypatch, options={"k8s_secrets": secrets}, clusters=with_hostile_pod())
    for name in K8S_CANARIES + ("eks_addon_config",):
        assert S.grep_tree(acme.CANARIES[name], tmp_path) == [], name
    for needle in EXTRA_CANARIES + ("last-applied-configuration", "managed_fields", "managedFields"):
        assert S.grep_tree(needle, tmp_path) == [], needle


@pytest.mark.finding("F-009", "F-150")
def test_opt_in_lists_secret_metadata_only_one_type_at_a_time(tmp_path, monkeypatch):
    run = run_k8s(tmp_path, monkeypatch, options={"k8s_secrets": True})
    calls = [c for c in run.requests() if c.resource == "secrets"]
    assert calls and all(c.metadata_only for c in calls)
    assert all(c.headers["Accept"] == METADATA_ONLY_ACCEPT for c in calls)
    selectors = {c.kwargs["query_params"].get("fieldSelector") for c in calls}
    assert "type=Opaque" in selectors and "type=kubernetes.io/service-account-token" in selectors
    assert any(s and s.startswith("type!=Opaque,") for s in selectors)          # the "other" bucket
    secrets = run.load("secrets.json")
    assert [(s["namespace"], s["name"], s["type"]) for s in secrets] == [
        ("demo-apps", "demo-db-secret", "Opaque"),
        ("kube-system", "demo-sa-token", "kubernetes.io/service-account-token")]
    for item in secrets:
        assert set(item) == {"name", "namespace", "type", "labels", "annotations"}
    assert secrets[1]["annotations"] == {"kubernetes.io/service-account.name": "aws-node"}
    assert secrets[0]["annotations"] == {}                                      # last-applied dropped
    assert run.info()["secrets_listed"] is True


def test_secret_of_an_unlisted_type_is_reported_as_other(tmp_path, monkeypatch):
    clusters = acme.build_k8s_clusters()
    clusters[ENDPOINT].secrets = clusters[ENDPOINT].secrets + [
        {"api_version": None, "kind": None, "type": "example.com/custom",
         "metadata": {"name": "demo-custom", "namespace": "default"}, "data": {"k": "ZGVtbw=="}}]
    run = run_k8s(tmp_path, monkeypatch, options={"k8s_secrets": True}, clusters=clusters)
    assert {s["name"]: s["type"] for s in run.load("secrets.json")}["demo-custom"] == "other"


@pytest.mark.finding("F-054", "F-035")
def test_pod_env_values_are_never_written_but_their_presence_and_references_are(tmp_path, monkeypatch):
    run = run_k8s(tmp_path, monkeypatch)
    pods = by_name(run.load("pods.json"))
    api = pods["demo-api-7d9f8c6b5-abcde"]["spec"]["containers"][0]
    assert api["env"] == [
        {"name": "DB_PASSWORD", "value_from": None, "value_present": True},
        {"name": "API_KEY", "value_present": False,
         "value_from": {"secret_key_ref": {"name": "demo-db-secret", "key": "api-key"}}}]
    worker = pods["demo-worker-0"]["spec"]
    assert worker["init_containers"][0]["env"] == [{"name": "BOOTSTRAP_TOKEN", "value_from": None,
                                                    "value_present": True}]
    for pod in pods.values():
        for container in (pod["spec"]["containers"] or []) + (pod["spec"]["init_containers"] or []):
            for env in container["env"] or []:
                assert set(env) == {"name", "value_from", "value_present"}


@pytest.mark.finding("F-035")
def test_pods_carry_the_escape_primitives_the_engine_needs(tmp_path, monkeypatch):
    pods = by_name(run_k8s(tmp_path, monkeypatch, clusters=with_hostile_pod()).load("pods.json"))
    worker = pods["demo-worker-0"]["spec"]
    assert worker["host_network"] is True and worker["host_pid"] is True
    assert worker["init_containers"][0]["name"] == "init"
    assert worker["volumes"] == [{"name": "host-root", "host_path": {"path": "/", "type": "Directory"}}]
    assert worker["containers"][0]["security_context"] == {"privileged": True}
    debug = pods["demo-debug"]
    spec = debug["spec"]
    assert spec["automount_service_account_token"] is False and spec["host_ipc"] is True
    assert spec["ephemeral_containers"][0]["security_context"] == {"privileged": True}
    assert spec["ephemeral_containers"][0]["env"] == [{"name": "TOKEN", "value_from": None, "value_present": True}]
    app = spec["containers"][0]
    assert app["security_context"] == {"allow_privilege_escalation": True,
                                       "capabilities": {"add": ["SYS_ADMIN", "NET_ADMIN"], "drop": ["ALL"]}}
    assert app["env_from"] == [{"prefix": None, "secret_ref": {"name": "demo-db-secret"}},
                               {"prefix": None, "config_map_ref": {"name": "demo-config"}}]
    assert "command" not in app and "args" not in app
    assert spec["volumes"] == [{"name": "docker", "host_path": {"path": "/var/run/docker.sock", "type": "Socket"}}]
    assert debug["metadata"]["owner_references"] == [{"kind": "Job", "name": "demo-debug-job"}]
    assert debug["metadata"]["annotations"] == {"demo.example.com/note": None,
                                                "eks.amazonaws.com/role-arn": acme.role_arn("demo-irsa-role")}
    assert "managed_fields" not in debug["metadata"]
    api = pods["demo-api-7d9f8c6b5-abcde"]
    assert api["metadata"]["annotations"] == {"kubectl.kubernetes.io/restartedAt": None}
    assert api["spec"]["volumes"][0] == {"name": "db-creds", "secret": {"secret_name": "demo-db-secret"}}
    assert api["spec"]["volumes"][1]["projected"] == {"sources": [{"service_account_token": {
        "audience": "sts.amazonaws.com", "expiration_seconds": 86400, "path": "token"}}]}


def test_roles_and_bindings_carry_kind_and_every_subject(tmp_path, monkeypatch):
    run = run_k8s(tmp_path, monkeypatch)
    assert {r["kind"] for r in run.load("roles.json")} == {"Role"}
    assert {r["kind"] for r in run.load("cluster_roles.json")} == {"ClusterRole"}
    crbs = by_name(run.load("cluster_role_bindings.json"))
    assert crbs["cluster-admin"]["subjects"] == [{"kind": "Group", "name": "system:masters", "namespace": None,
                                                  "api_group": "rbac.authorization.k8s.io"}]
    assert crbs["demo-worker-admin"]["role_ref"] == {"api_group": "rbac.authorization.k8s.io",
                                                     "kind": "ClusterRole", "name": "cluster-admin"}
    sas = by_name(run.load("service_accounts.json"))
    assert sas["demo-api"]["metadata"]["annotations"] == {
        "eks.amazonaws.com/role-arn": acme.role_arn("demo-irsa-role")}


# ── nodes and aws-auth (F-033, F-050) ────────────────────────────────────────
@pytest.mark.finding("F-033")
def test_nodes_link_pods_to_instances_and_node_groups(tmp_path, monkeypatch):
    run = run_k8s(tmp_path, monkeypatch)
    nodes = run.load("nodes.json")
    assert len(nodes) == 1
    node = nodes[0]
    assert node["metadata"]["name"] == "ip-10-20-2-10.eu-west-2.compute.internal"
    assert (node["instance_id"], node["nodegroup"], node["zone"]) == ("i-0dec0abb000000002", "demo-ng", "eu-west-2b")
    pod_nodes = {p["spec"]["node_name"] for p in run.load("pods.json")}
    assert node["metadata"]["name"] in pod_nodes


@pytest.mark.finding("F-050")
def test_aws_auth_keeps_only_the_identity_mappings(tmp_path, monkeypatch):
    clusters = acme.build_k8s_clusters()
    clusters[ENDPOINT].config_maps[0]["data"]["mapAccounts"] = "- \"111122223333\"\n- 000000000000\n"
    clusters[ENDPOINT].config_maps[0]["data"]["extra"] = "DEMO-CANARY-AWS-AUTH-EXTRA"
    run = run_k8s(tmp_path, monkeypatch, clusters=clusters)
    doc = run.load("aws_auth.json")
    assert doc == {
        "present": True,
        "map_roles": [
            {"rolearn": acme.role_arn("demo-admin-role"), "username": "demo-admin", "groups": ["system:masters"]},
            {"rolearn": acme.role_arn("demo-eks-node-role"), "username": "system:node:{{EC2PrivateDNSName}}",
             "groups": ["system:bootstrappers", "system:nodes"]}],
        "map_users": [], "map_accounts": ["000000000000", "111122223333"], "parse_errors": []}
    assert S.grep_tree("DEMO-CANARY-AWS-AUTH-EXTRA", tmp_path) == []
    reads = [c for c in run.requests() if c.resource == "config_maps"]
    assert [(c.http_method, c.path) for c in reads] == [
        ("GET", "/api/v1/namespaces/kube-system/configmaps/aws-auth")]


@pytest.mark.finding("F-050")
def test_missing_aws_auth_is_absent_not_denied(tmp_path, monkeypatch):
    run = run_k8s(tmp_path, monkeypatch, clusters=demo_clusters(config_maps=[]))
    assert run.load("aws_auth.json") == {"present": False, "map_roles": [], "map_users": [], "map_accounts": [],
                                         "parse_errors": []}
    assert run.k8s.result.status == "ok"
    row = [c for c in run.coverage()["calls"] if c["api"] == "k8s:GetConfigMap"][0]
    assert row["not_configured"] is True and row["error_code"] == "NotFound"


@pytest.mark.finding("F-050")
def test_denied_aws_auth_is_unknown(tmp_path, monkeypatch):
    run = run_k8s(tmp_path, monkeypatch,
                  clusters=demo_clusters(errors={"config_maps": ApiException(status=403, reason="Forbidden")}))
    assert run.load("aws_auth.json") == {"present": None, "map_roles": None, "map_users": None,
                                         "map_accounts": None, "parse_errors": []}
    assert run.info()["resources"]["aws_auth"]["status"] == "denied"
    assert run.k8s.result.status == "partial"
    assert {"resource": CLUSTER_ARN, "api": "k8s:GetConfigMap", "status": "denied",
            "error_code": "Forbidden"} in run.coverage()["item_errors"]


# ── paging (F-149) and timeouts (F-120) ──────────────────────────────────────
@pytest.mark.finding("F-149")
def test_lists_page_with_limit_and_continue(tmp_path, monkeypatch):
    run = run_k8s(tmp_path, monkeypatch, clusters=demo_clusters(page_size=1))
    pod_calls = [c for c in run.requests() if c.resource == "pods"]
    assert len(pod_calls) == 3
    assert [c.kwargs["query_params"].get("continue") for c in pod_calls] == [None, "fake-continue-1",
                                                                             "fake-continue-2"]
    assert all(int(c.kwargs["query_params"]["limit"]) == 500 for c in pod_calls)
    assert len(run.load("pods.json")) == 3
    row = [c for c in run.coverage()["calls"] if c["api"] == "k8s:ListPods"][0]
    assert (row["status"], row["pages"], row["items"]) == ("ok", 3, 3)


@pytest.mark.finding("F-149")
def test_expired_continue_token_restarts_the_list_once(tmp_path, monkeypatch):
    clusters = demo_clusters(page_size=2, error_once={"pods:continue": ApiException(status=410, reason="Gone")})
    run = run_k8s(tmp_path, monkeypatch, clusters=clusters)
    outcomes = [(c.kwargs["query_params"].get("continue"), c.outcome) for c in run.requests()
                if c.resource == "pods"]
    assert outcomes == [(None, "ok"), ("fake-continue-2", "ApiException:410"), (None, "ok"),
                        ("fake-continue-2", "ok")]
    assert len(run.load("pods.json")) == 3                       # no duplicates from the first attempt
    assert run.info()["resources"]["pods"]["status"] == "ok" and run.k8s.result.status == "ok"


@pytest.mark.finding("F-120")
def test_every_request_has_the_default_timeout(tmp_path, monkeypatch):
    run = run_k8s(tmp_path, monkeypatch, options={"k8s_secrets": True})
    timeouts = {c.kwargs["_request_timeout"] for c in run.requests()}
    assert timeouts == {(5.0, 60.0)}


@pytest.mark.finding("F-120", "F-062")
def test_k8s_timeout_option_is_honoured(tmp_path, monkeypatch):
    run = run_k8s(tmp_path, monkeypatch, options={"k8s_timeout": "2,30"})
    assert {c.kwargs["_request_timeout"] for c in run.requests()} == {(2.0, 30.0)}


@pytest.mark.finding("F-120")
def test_unreachable_endpoint_fails_fast_with_a_hint(tmp_path, monkeypatch):
    urllib3 = pytest.importorskip("urllib3")
    timeout = urllib3.exceptions.ConnectTimeoutError(None, "connect timed out")
    unreachable = urllib3.exceptions.MaxRetryError(None, "/version", reason=timeout)
    clusters = acme.build_k8s_clusters()
    clusters[acme.EKS_ENDPOINTS["demo-west-cluster"]].errors = {"*": unreachable}
    run = run_k8s(tmp_path, monkeypatch, clusters=clusters, region=W1)
    info = run.info("demo-west-cluster")
    assert info["auth_status"] == "unreachable" and info["error_code"] == "ConnectTimeoutError"
    assert "could not be reached" in info["error"] and "publicAccessCidrs" in info["error"]
    calls = run.requests("demo-west-cluster")
    assert [(c.resource, c.kwargs["_request_timeout"]) for c in calls] == [("version", (3.0, 60.0))]
    assert run.k8s.result.status == "partial"
    for name in LIST_FILES:
        assert not (run.k8s.out / "demo-west-cluster" / name).exists()


# ── authentication outcomes ──────────────────────────────────────────────────
def test_unauthorized_cluster_and_cluster_without_endpoint(tmp_path, monkeypatch):
    """eu-west-1: demo-west-cluster answers 401; demo-denied-cluster's DescribeCluster was denied."""
    run = run_k8s(tmp_path, monkeypatch, region=W1)
    west = run.info("demo-west-cluster")
    assert (west["auth_status"], west["error_code"]) == ("failed", "Unauthorized")
    assert "access entry" in west["error"]
    assert west["endpoint_hint"] and west["public_access_cidrs"] == ["198.51.100.0/24"]
    denied = run.info("demo-denied-cluster")
    assert (denied["auth_status"], denied["error_code"]) == ("skipped", "NoEndpoint")
    assert run.requests("demo-denied-cluster") == []
    assert len(run.requests("demo-west-cluster")) == 1           # only the /version probe
    doc = run.coverage()
    assert {e["resource"] for e in doc["item_errors"]} >= {
        "arn:aws:eks:eu-west-1:111122223333:cluster/demo-west-cluster"}


def test_forbidden_everywhere_is_reported_as_forbidden(tmp_path, monkeypatch):
    run = run_k8s(tmp_path, monkeypatch,
                  clusters=demo_clusters(errors={"*": ApiException(status=403, reason="Forbidden")}))
    info = run.info()
    assert info["auth_status"] == "forbidden" and info["self_rules_reviewed"] is False
    for name in LIST_FILES:
        assert run.load(name) == [], name
    assert run.k8s.result.status == "partial"


# ── rules review and namespaced fallback (F-152) ─────────────────────────────
@pytest.mark.finding("F-152")
def test_rules_review_is_saved_per_namespace(tmp_path, monkeypatch):
    run = run_k8s(tmp_path, monkeypatch)
    reviews = run.load("self_rules.json")
    assert [r["namespace"] for r in reviews] == ["default", "demo-apps", "kube-system"]
    demo_apps = reviews[1]
    assert {"verbs": ["get", "list"], "api_groups": [""], "resources": ["secrets"], "resource_names": None} \
        in demo_apps["resource_rules"]
    posts = [c for c in run.requests() if c.http_method == "POST"]
    assert [c.kwargs["body"]["spec"]["namespace"] for c in posts] == ["default", "demo-apps", "kube-system"]


@pytest.mark.finding("F-152", "F-062")
def test_self_review_can_be_disabled(tmp_path, monkeypatch):
    run = run_k8s(tmp_path, monkeypatch, options={"no_k8s_self_review": True})
    assert [c for c in run.requests() if c.http_method == "POST"] == []
    assert run.load("self_rules.json") is None and run.info()["self_rules_reviewed"] is False


@pytest.mark.finding("F-152")
def test_cluster_wide_403_falls_back_to_the_namespaces_the_review_allows(tmp_path, monkeypatch):
    clusters = acme.build_k8s_clusters()
    demo = clusters[ENDPOINT]
    demo.errors = {"pods:cluster": ApiException(status=403, reason="Forbidden")}
    no_pods = copy.deepcopy(demo.self_rules["*"])
    no_pods["resource_rules"][0]["resources"] = ["services", "serviceaccounts", "configmaps", "namespaces", "nodes"]
    demo.self_rules = {"*": no_pods, "demo-apps": demo.self_rules["demo-apps"]}  # pods only in demo-apps
    run = run_k8s(tmp_path, monkeypatch, clusters=clusters)
    pods = run.load("pods.json")
    assert {p["metadata"]["namespace"] for p in pods} == {"demo-apps"} and len(pods) == 2
    assert run.info()["resources"]["pods"] == {"status": "partial", "scope": "namespaced",
                                               "error_code": "Forbidden", "namespaces": ["demo-apps"], "items": 2}
    paths = [c.path for c in run.requests() if c.resource == "pods"]
    assert paths == ["/api/v1/pods", "/api/v1/namespaces/demo-apps/pods"]
    assert run.info()["auth_status"] == "ok" and run.k8s.result.status == "partial"


@pytest.mark.finding("F-152")
def test_secret_listing_falls_back_per_namespace_too(tmp_path, monkeypatch):
    clusters = demo_clusters(errors={"secrets:cluster": ApiException(status=403, reason="Forbidden")})
    run = run_k8s(tmp_path, monkeypatch, options={"k8s_secrets": True}, clusters=clusters)
    secrets = run.load("secrets.json")
    assert [(s["namespace"], s["name"], s["type"]) for s in secrets] == [("demo-apps", "demo-db-secret", "Opaque")]
    assert run.info()["resources"]["secrets"]["namespaces"] == ["demo-apps"]
    assert all(c.metadata_only for c in run.requests() if c.resource == "secrets")


def test_deny_breaker_is_per_cluster(tmp_path, monkeypatch):
    """Three clusters whose pod listing is forbidden everywhere: each cluster still gets asked (own RBAC)."""
    clusters: Dict[str, FakeCluster] = {}
    describe = []
    for n in range(1, 5):
        name, endpoint = f"demo-c{n}", f"https://DEMO{n:028d}.gr7.eu-west-2.eks.amazonaws.com"
        cluster = FakeCluster(name=name, errors={"pods": ApiException(status=403, reason="Forbidden")})
        cluster.namespaces = [{"metadata": {"name": ns}} for ns in ("default", "kube-system", "demo-a", "demo-b")]
        clusters[endpoint] = cluster
        describe.append({"name": name, "arn": f"arn:aws:eks:eu-west-2:111122223333:cluster/{name}",
                         "endpoint": endpoint, "certificateAuthority": {"data": acme.EKS_CA_DATA},
                         "resourcesVpcConfig": {"endpointPublicAccess": True, "publicAccessCidrs": ["0.0.0.0/0"]}})
    fake = FakeKubernetes(clusters).install(monkeypatch)
    k8s = S.run_module("k8s", acme.build_world(), tmp_path, region=W2, options={"no_rate_limit": True},
                       deps={"eks": {"clusters": describe, "namespaces": {}}})
    for n in range(1, 5):
        pod_calls = [c for c in fake.calls_for(cluster=f"demo-c{n}") if c.resource == "pods"]
        # cluster-wide 403 + namespaced 403s; the cluster's breaker opens after 3 denials, the 4th is skipped
        assert len(pod_calls) == 3, n
    doc = S.load_json(k8s.out / "_coverage.json")
    COVERAGE.validate(doc)
    skipped = [c for c in doc["calls"] if c["api"] == "k8s:ListPods" and c["status"] == "skipped"]
    assert skipped and skipped[0]["error_code"] == "CircuitOpen:AccessDenied" and skipped[0]["count"] == 8
    assert k8s.result.status == "partial"


# ── options and enablement (F-062, F-136) ────────────────────────────────────
@pytest.mark.finding("F-062")
@pytest.mark.parametrize("options", [{"k8s": False}, {"no_k8s": True}])
def test_no_k8s_contacts_no_cluster(tmp_path, monkeypatch, options):
    run = run_k8s(tmp_path, monkeypatch, options=options)
    assert run.fake.calls == []
    assert run.k8s.result.status == "skipped" and run.k8s.result.status_reason == "disabled by --no-k8s"
    assert not (run.k8s.out / "demo-cluster").exists()


@pytest.mark.finding("F-062")
def test_k8s_clusters_restricts_the_clusters_contacted(tmp_path, monkeypatch):
    run = run_k8s(tmp_path, monkeypatch, options={"k8s_clusters": "demo-west-cluster"}, region=W1)
    assert run.requests("demo-denied-cluster") == []
    assert run.info("demo-denied-cluster")["error_code"] == "NotSelected"
    assert run.requests("demo-west-cluster")
    run2 = run_k8s(tmp_path / "x", monkeypatch, options={"k8s_clusters": "demo-other"})
    assert run2.fake.calls == [] and run2.info()["auth_status"] == "skipped"
    assert run2.k8s.result.status == "ok"                        # a deliberate skip never degrades


@pytest.mark.finding("F-136")
def test_missing_kubernetes_package_is_dependency_missing_not_failed(tmp_path, monkeypatch, caplog):
    monkeypatch.setitem(sys.modules, "kubernetes", None)
    world = acme.build_world()
    eks = S.run_module("eks", world, tmp_path, region=W2)
    with caplog.at_level(logging.WARNING, logger="aws_enumerator"):
        k8s = S.run_module("k8s", world, tmp_path, region=W2, deps={"eks": eks.result.value})
    run = K8sRun(eks, k8s, None)
    info = run.info()
    assert (info["auth_status"], info["error_code"]) == ("dependency_missing", "DependencyMissing")
    assert k8s.result.status == "skipped" and "kubernetes" in k8s.result.status_reason
    hints = [r for r in caplog.records if "kubernetes" in r.getMessage() and r.levelno == logging.WARNING]
    assert len(hints) == 1
    assert not (k8s.out / "demo-cluster" / "pods.json").exists()
    run.coverage()


@pytest.mark.finding("F-136")
def test_missing_package_keeps_the_skip_reason_of_unselected_clusters(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "kubernetes", None)
    world = acme.build_world()
    eks = S.run_module("eks", world, tmp_path, region=W1)
    k8s = S.run_module("k8s", world, tmp_path, region=W1, options={"k8s_clusters": "demo-west-cluster"},
                       deps={"eks": eks.result.value})
    run = K8sRun(eks, k8s, None)
    assert run.info("demo-west-cluster")["auth_status"] == "dependency_missing"
    assert (run.info("demo-denied-cluster")["auth_status"], run.info("demo-denied-cluster")["error_code"]) == (
        "skipped", "NotSelected")


def test_cluster_directory_is_one_safe_segment():
    from aws_enumerator.collectors.k8s import _cluster_dir
    from aws_enumerator.k8s.auth import ClusterTarget

    arn = "arn:aws:eks:eu-west-2:111122223333:cluster/x"
    assert _cluster_dir(ClusterTarget(name="demo-cluster", arn=arn)) == "demo-cluster"
    for name in ("a/b", "..", "_reserved", "bad name"):
        out = _cluster_dir(ClusterTarget(name=name, arn=arn))
        assert "/" not in out and out not in ("..", name) and not out.startswith("_"), (name, out)


def test_no_eks_value_or_no_clusters(tmp_path, monkeypatch):
    FakeKubernetes({}).install(monkeypatch)
    world = acme.build_world()
    none = S.run_module("k8s", world, tmp_path / "a", region=W2, deps={"eks": None})
    assert none.result.status == "skipped" and "eks" in none.result.status_reason
    empty = S.run_module("k8s", world, tmp_path / "b", region=W2, deps={"eks": {"clusters": [], "namespaces": {}}})
    assert empty.result.status == "ok"
    assert [p.name for p in S.files_under(empty.out)] == ["_coverage.json"]


def test_eks_namespace_hints_widen_the_rules_review(tmp_path, monkeypatch):
    clusters = demo_clusters(errors={"namespaces": ApiException(status=403, reason="Forbidden")})
    run = run_k8s(tmp_path, monkeypatch, clusters=clusters)
    assert run.eks.result.value["namespaces"] == {"demo-cluster": ["demo-apps"]}
    assert [r["namespace"] for r in run.load("self_rules.json")] == ["default", "demo-apps", "kube-system"]


@pytest.mark.finding("F-062")
def test_requests_go_through_the_per_cluster_rate_gate(tmp_path, monkeypatch):
    from aws_enumerator.collectors import k8s as k8s_module

    gates: List[Any] = []

    class RecordingGate(k8s_module.RateGate):
        """The real token bucket on a virtual clock: ``sleep`` advances time instead of waiting."""

        def __init__(self, *args: Any, **kwargs: Any):
            self.now, self.slept, self.acquired = 0.0, 0.0, 0
            super().__init__(*args, clock=lambda: self.now, sleep=self._sleep, **kwargs)
            gates.append(self)

        def _sleep(self, seconds: float) -> None:
            self.now += seconds
            self.slept += seconds

        def acquire(self) -> None:
            self.acquired += 1
            super().acquire()

    monkeypatch.setattr(k8s_module, "RateGate", RecordingGate)
    run = run_k8s(tmp_path, monkeypatch, options={"no_rate_limit": None, "rate_limit": ["k8s=2"]})
    assert len(gates) == 1 and (gates[0].rate, gates[0].burst) == (2.0, 10)
    requests = len(run.requests())
    assert gates[0].acquired == requests > 10
    assert gates[0].slept == pytest.approx((requests - 10) / 2.0)   # burst 10, then 2 requests per second
    run_k8s(tmp_path / "off", monkeypatch, options={"no_rate_limit": True})
    assert len(gates) == 1                                     # --no-rate-limit: no gate at all


def test_requests_carry_the_tool_user_agent(tmp_path, monkeypatch):
    from aws_enumerator.collectors import k8s as k8s_module

    seen: List[Dict[str, str]] = []

    class RecordingTransport(k8s_module.ApiClientTransport):
        def __init__(self, api_client: Any, **kwargs: Any):
            super().__init__(api_client, **kwargs)
            seen.append(dict(api_client.default_headers))

    monkeypatch.setattr(k8s_module, "ApiClientTransport", RecordingTransport)
    run_k8s(tmp_path, monkeypatch)
    assert seen[-1]["User-Agent"].startswith("aws-enumerator/") and seen[-1]["User-Agent"].endswith("/a1b2c3")
    run_k8s(tmp_path / "custom", monkeypatch, options={"ua_app_id": "demo-assessment"})
    assert seen[-1]["User-Agent"] == "demo-assessment"
    run_k8s(tmp_path / "none", monkeypatch, options={"no_ua_tag": True})
    assert "User-Agent" not in seen[-1]


def test_bad_option_value_fails_the_module(tmp_path, monkeypatch):
    run = run_k8s(tmp_path, monkeypatch, options={"k8s_timeout": "soon"})
    assert run.k8s.result.status == "failed" and run.fake.calls == []


def test_no_value_from_a_failed_request_is_kept_in_the_report(tmp_path, monkeypatch):
    """Error responses can echo request data: only stable codes are stored, never bodies or messages."""
    body = json.dumps({"kind": "Status", "message": "DEMO-CANARY-ERROR-BODY"})
    run = run_k8s(tmp_path, monkeypatch, clusters=demo_clusters(
        errors={"services": ApiException(status=500, reason="DEMO-CANARY-REASON", body=body)}))
    assert run.info()["resources"]["services"]["error_code"] == "HTTP500"
    assert S.grep_tree("DEMO-CANARY", tmp_path) == []
    for value in walk(run.coverage()):
        assert not (isinstance(value, str) and "DEMO-CANARY" in value)
