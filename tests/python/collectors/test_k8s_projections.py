"""Projections of raw Kubernetes objects (``aws_enumerator.k8s.projections``; collectors-cli.md §5.16).

* engine-field parity: every field path the legacy K8s analyzer reads (``engine/analyzers/k8s``, the d13c215
  ``_analyze_k8s_relationships``) has the same value in the projection as in the full ``to_dict()`` output the
  baseline collector wrote, for every acme object (the collectors-v0 inputs);
* annotations: keys kept, values ``null`` unless allow-listed, ``last-applied-configuration`` dropped (F-009);
* env literals never copied (F-054); init/ephemeral containers, hostPath, capabilities, env references and
  the automount flag carried (F-035); nodes give instance, zone and node group (F-033);
* ``aws-auth``: only ``mapRoles``/``mapUsers``/``mapAccounts`` (F-050).
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Mapping, Sequence, Tuple

import pytest

from aws_enumerator.collectors import k8s as k8s_collector
from aws_enumerator.k8s import projections as proj
from tests.fixtures.worlds import acme
from tests.support.fake_kubernetes import to_camel

pytestmark = pytest.mark.collectors

ENDPOINT = acme.EKS_ENDPOINTS["demo-cluster"]

#: Paths read by the legacy analyzer (``*`` = every list element), per output file.
ENGINE_PATHS: Dict[str, Sequence[Tuple[str, ...]]] = {
    "namespaces": [("metadata", "name")],
    "pods": [("metadata", "namespace"), ("metadata", "name"), ("metadata", "labels"),
             ("spec", "service_account_name"), ("spec", "service_account"), ("spec", "host_network"),
             ("spec", "host_pid"), ("spec", "containers", "*", "security_context", "privileged"),
             ("spec", "volumes", "*", "secret", "secret_name")],
    "service_accounts": [("metadata", "namespace"), ("metadata", "name"),
                         ("metadata", "annotations", "eks.amazonaws.com/role-arn")],
    "roles": [("metadata", "namespace"), ("metadata", "name"), ("rules", "*", "verbs"), ("rules", "*", "resources")],
    "cluster_roles": [("metadata", "name"), ("rules", "*", "verbs"), ("rules", "*", "resources")],
    "role_bindings": [("metadata", "namespace"), ("metadata", "name"), ("role_ref", "kind"), ("role_ref", "name"),
                      ("subjects", "*", "kind"), ("subjects", "*", "namespace"), ("subjects", "*", "name")],
    "cluster_role_bindings": [("metadata", "name"), ("role_ref", "name"), ("subjects", "*", "kind"),
                              ("subjects", "*", "namespace"), ("subjects", "*", "name")],
    "services": [("metadata", "namespace"), ("metadata", "name"), ("spec", "type"), ("spec", "selector")],
    "ingresses": [("metadata", "namespace"), ("metadata", "name"),
                  ("spec", "rules", "*", "http", "paths", "*", "backend", "service", "name")],
}


def projector(key: str) -> Callable[[Mapping[str, Any]], Dict[str, Any]]:
    """The projection the collector itself uses for ``<key>.json``."""
    table = dict(k8s_collector._LISTS)
    table["namespaces"] = proj.project_namespace
    return table[key]


def values_at(obj: Any, path: Sequence[str]) -> List[Any]:
    """Every value at ``path`` (``*`` fans out over lists); missing / ``None`` values are skipped."""
    if not path:
        return [] if obj is None else [obj]
    head, rest = path[0], path[1:]
    if head == "*":
        return [v for item in (obj or []) for v in values_at(item, rest)]
    if not isinstance(obj, Mapping):
        return []
    return values_at(obj.get(head), rest)


def canonical(values: List[Any]) -> List[str]:
    return sorted(json.dumps(v, sort_keys=True) for v in values)


def ident(item: Mapping[str, Any]) -> Tuple[str, str]:
    meta = item.get("metadata") or {}
    return meta.get("namespace") or "", meta.get("name") or ""


# ── engine-field parity ──────────────────────────────────────────────────────
@pytest.mark.finding("F-054", "F-009")
@pytest.mark.parametrize("key", sorted(ENGINE_PATHS))
def test_every_field_the_engine_reads_survives_the_projection(key):
    legacy = getattr(acme.build_k8s_clusters()[ENDPOINT], key)   # what to_dict() gave the baseline collector
    assert legacy, key
    project = projector(key)
    projected = {ident(p): p for p in (project(to_camel(item)) for item in legacy)}
    assert len(projected) == len(legacy)
    for item in legacy:
        new = projected[ident(item)]
        for path in ENGINE_PATHS[key]:
            assert canonical(values_at(new, path)) == canonical(values_at(item, path)), (key, ident(item), path)


def test_ingress_annotation_keys_survive_for_the_auth_check():
    raw = {"metadata": {"name": "i", "namespace": "n", "annotations": {
        "alb.ingress.kubernetes.io/auth-type": "cognito", "nginx.ingress.kubernetes.io/auth-url": "https://x/secret",
        "nginx.ingress.kubernetes.io/auth-signin": "https://x"}}, "spec": {}}
    annotations = proj.project_ingress(raw)["metadata"]["annotations"]
    assert annotations == {"alb.ingress.kubernetes.io/auth-type": "cognito",
                           "nginx.ingress.kubernetes.io/auth-signin": None,
                           "nginx.ingress.kubernetes.io/auth-url": None}


# ── annotations and dropped fields (F-009) ───────────────────────────────────
@pytest.mark.finding("F-009")
def test_filter_annotations():
    assert proj.filter_annotations(None) is None
    assert proj.filter_annotations({
        "kubectl.kubernetes.io/last-applied-configuration": '{"data": {"password": "x"}}',
        "eks.amazonaws.com/role-arn": "arn:aws:iam::111122223333:role/demo",
        "service.beta.kubernetes.io/aws-load-balancer-scheme": "internet-facing",
        "example.com/token": "secret-looking-value", "eks.amazonaws.com/audience": 7,
    }) == {"eks.amazonaws.com/audience": None, "eks.amazonaws.com/role-arn": "arn:aws:iam::111122223333:role/demo",
           "example.com/token": None, "service.beta.kubernetes.io/aws-load-balancer-scheme": "internet-facing"}


@pytest.mark.finding("F-009")
@pytest.mark.parametrize("fn", [proj.project_pod, proj.project_service_account, proj.project_namespace,
                                proj.project_service, proj.project_ingress, proj.project_node,
                                lambda o: proj.project_role(o, "ClusterRole"),
                                lambda o: proj.project_binding(o, "RoleBinding"),
                                lambda o: proj.project_secret_metadata(o, "Opaque")])
def test_managed_fields_and_last_applied_are_dropped_by_every_projection(fn):
    raw = {"metadata": {"name": "n", "namespace": "ns", "uid": "u", "resourceVersion": "1",
                        "managedFields": [{"manager": "kubectl", "fieldsV1": {"f:data": {}}}],
                        "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{\"data\":1}"}},
           "data": {"password": "cGFzcw=="}, "stringData": {"password": "pass"}}
    blob = json.dumps(fn(raw))
    for needle in ("managed", "last-applied", "cGFzcw==", "\"pass\"", "fieldsV1", "\"data\""):
        assert needle not in blob, needle


# ── pods (F-054, F-035) ──────────────────────────────────────────────────────
@pytest.mark.finding("F-054")
def test_env_entries_keep_name_reference_and_presence_only():
    raw = {"spec": {"containers": [{"name": "c", "env": [
        {"name": "LITERAL", "value": "s3cr3t"}, {"name": "EMPTY", "value": ""}, {"name": "NONE"},
        {"name": "FROM_SECRET", "valueFrom": {"secretKeyRef": {"name": "db", "key": "pw", "optional": True}}},
        {"name": "FROM_CM", "valueFrom": {"configMapKeyRef": {"name": "cfg", "key": "k"}}},
        {"name": "FROM_FIELD", "valueFrom": {"fieldRef": {"fieldPath": "status.podIP", "apiVersion": "v1"}}},
        {"name": "FROM_RES", "valueFrom": {"resourceFieldRef": {"resource": "limits.cpu", "containerName": "c"}}},
    ]}]}}
    env = proj.project_pod(raw)["spec"]["containers"][0]["env"]
    assert env == [
        {"name": "LITERAL", "value_from": None, "value_present": True},
        {"name": "EMPTY", "value_from": None, "value_present": False},
        {"name": "NONE", "value_from": None, "value_present": False},
        {"name": "FROM_SECRET", "value_from": {"secret_key_ref": {"name": "db", "key": "pw", "optional": True}},
         "value_present": False},
        {"name": "FROM_CM", "value_from": {"config_map_key_ref": {"name": "cfg", "key": "k"}}, "value_present": False},
        {"name": "FROM_FIELD", "value_from": {"field_ref": {"field_path": "status.podIP"}}, "value_present": False},
        {"name": "FROM_RES", "value_from": {"resource_field_ref": {"resource": "limits.cpu", "container_name": "c"}},
         "value_present": False},
    ]
    assert "s3cr3t" not in json.dumps(proj.project_pod(raw))


@pytest.mark.finding("F-035")
def test_pod_security_fields():
    raw = {"metadata": {"name": "p", "namespace": "n", "ownerReferences": [{"kind": "DaemonSet", "name": "ds",
                                                                           "uid": "x", "controller": True}]},
           "spec": {"automountServiceAccountToken": True, "hostIPC": True, "hostPID": False, "hostNetwork": True,
                    "shareProcessNamespace": True, "nodeName": "node-1",
                    "securityContext": {"runAsUser": 0, "runAsNonRoot": False, "fsGroup": 2000,
                                        "supplementalGroups": [1, "x"], "sysctls": [{"name": "net.x", "value": "1"}],
                                        "seccompProfile": {"type": "Unconfined"}},
                    "initContainers": [{"name": "init", "image": "i", "securityContext": {
                        "privileged": True, "capabilities": {"add": ["ALL"]}, "procMount": "Unmasked"}}],
                    "ephemeralContainers": [{"name": "eph", "image": "e", "targetContainerName": "app"}],
                    "containers": [{"name": "app", "image": "a", "ports": [{"containerPort": 80, "hostPort": 8080}],
                                    "volumeMounts": [{"name": "root", "mountPath": "/host", "readOnly": False}]}],
                    "volumes": [{"name": "root", "hostPath": {"path": "/", "type": ""}},
                                {"name": "pvc", "persistentVolumeClaim": {"claimName": "data"}},
                                {"name": "proj", "projected": {"sources": [{"secret": {"name": "s"}},
                                                                          {"configMap": {"name": "c"}},
                                                                          {"downwardAPI": {"items": []}}]}},
                                {"name": "nfs", "nfs": {"server": "10.0.0.1", "path": "/x"}}]},
           "status": {"phase": "Pending", "podIP": "10.0.0.9"}}
    pod = proj.project_pod(raw)
    spec = pod["spec"]
    assert (spec["automount_service_account_token"], spec["host_ipc"], spec["host_network"], spec["host_pid"],
            spec["share_process_namespace"], spec["node_name"]) == (True, True, True, False, True, "node-1")
    assert spec["security_context"] == {"run_as_user": 0, "run_as_non_root": False, "fs_group": 2000,
                                        "supplemental_groups": [1], "sysctls": [{"name": "net.x"}],
                                        "seccomp_profile": {"type": "Unconfined"}}
    assert spec["init_containers"][0]["security_context"] == {"privileged": True, "proc_mount": "Unmasked",
                                                              "capabilities": {"add": ["ALL"], "drop": None}}
    assert spec["ephemeral_containers"][0]["name"] == "eph"
    assert spec["containers"][0]["ports"] == [{"container_port": 80, "host_port": 8080}]
    assert spec["containers"][0]["volume_mounts"] == [{"name": "root", "mount_path": "/host", "read_only": False}]
    assert spec["volumes"] == [
        {"name": "root", "host_path": {"path": "/", "type": ""}},
        {"name": "pvc", "persistent_volume_claim": {"claim_name": "data"}},
        {"name": "proj", "projected": {"sources": [{"secret": {"name": "s"}}, {"config_map": {"name": "c"}},
                                                   {"downward_api": {}}]}},
        {"name": "nfs"},
    ]
    assert pod["metadata"]["owner_references"] == [{"kind": "DaemonSet", "name": "ds"}]
    assert pod["status"] == {"phase": "Pending"}


# ── nodes (F-033) ────────────────────────────────────────────────────────────
@pytest.mark.finding("F-033")
@pytest.mark.parametrize("provider_id, labels, expected", [
    ("aws:///eu-west-2b/i-0abc123def4567890", {"eks.amazonaws.com/nodegroup": "demo-ng"},
     ("i-0abc123def4567890", "eu-west-2b", "demo-ng", None)),
    ("aws:///eu-west-2a/0123abcd-fargate/fargate-ip-10-0-1-2.eu-west-2.compute.internal",
     {"eks.amazonaws.com/compute-type": "fargate", "topology.kubernetes.io/zone": "eu-west-2a"},
     (None, "eu-west-2a", None, "fargate")),
    (None, {}, (None, None, None, None)),
    ("kind://docker/demo/demo-control-plane", {}, (None, None, None, None)),
])
def test_node_projection(provider_id, labels, expected):
    raw = {"metadata": {"name": "node", "labels": labels, "annotations": {"node.alpha.kubernetes.io/ttl": "0"}},
           "spec": {"providerID": provider_id, "taints": [{"key": "k", "effect": "NoSchedule", "value": "v"}]},
           "status": {"nodeInfo": {"kubeletVersion": "v1.29.0", "osImage": "Bottlerocket", "machineID": "m"},
                      "addresses": [{"type": "InternalIP", "address": "10.0.0.1"}]}}
    node = proj.project_node(raw)
    assert (node["instance_id"], node["zone"], node["nodegroup"], node["compute_type"]) == expected
    assert node["provider_id"] == provider_id
    assert node["spec"]["taints"] == [{"key": "k", "effect": "NoSchedule"}]
    assert node["status"]["node_info"] == {"kubelet_version": "v1.29.0", "os_image": "Bottlerocket"}
    assert node["metadata"]["annotations"] == {"node.alpha.kubernetes.io/ttl": None}


# ── aws-auth (F-050) ─────────────────────────────────────────────────────────
@pytest.mark.finding("F-050")
def test_aws_auth_parsing():
    cm = {"data": {
        "mapRoles": "- rolearn: arn:aws:iam::111122223333:role/demo-b\n  username: b\n"
                    "- rolearn: arn:aws:iam::111122223333:role/demo-a\n  username: a\n  groups: [system:masters]\n",
        "mapUsers": "- userarn: arn:aws:iam::111122223333:user/demo\n  username: demo\n  groups: [g1, 7]\n",
        "mapAccounts": "- 000000000000\n- '111122223333'\n- 999999999999\n",
        "other": "kept-out",
    }}
    assert proj.parse_aws_auth(cm) == {
        "present": True,
        "map_roles": [{"rolearn": "arn:aws:iam::111122223333:role/demo-a", "username": "a",
                       "groups": ["system:masters"]},
                      {"rolearn": "arn:aws:iam::111122223333:role/demo-b", "username": "b", "groups": []}],
        "map_users": [{"userarn": "arn:aws:iam::111122223333:user/demo", "username": "demo", "groups": ["g1"]}],
        "map_accounts": ["000000000000", "111122223333", "999999999999"],
        "parse_errors": [],
    }


@pytest.mark.finding("F-050")
def test_aws_auth_bad_keys_are_null_and_named_without_content():
    cm = {"data": {"mapRoles": "- rolearn: [unclosed", "mapUsers": "just a string",
                   "mapAccounts": "{a: b}"}}
    doc = proj.parse_aws_auth(cm)
    assert doc == {"present": True, "map_roles": None, "map_users": None, "map_accounts": None,
                   "parse_errors": ["mapRoles", "mapUsers", "mapAccounts"]}
    assert proj.parse_aws_auth({"data": None}) == {"present": True, "map_roles": [], "map_users": [],
                                                   "map_accounts": [], "parse_errors": []}
    assert proj.parse_aws_auth(None)["present"] is False
    assert proj.denied_aws_auth()["map_roles"] is None


# ── other objects ────────────────────────────────────────────────────────────
def test_secret_metadata_projection_has_a_fixed_key_set():
    raw = {"kind": "PartialObjectMetadata", "metadata": {"name": "s", "namespace": "n", "labels": {"a": "b"},
                                                         "annotations": {"x": "y"}, "uid": "u"}}
    assert proj.project_secret_metadata(raw, "kubernetes.io/tls") == {
        "name": "s", "namespace": "n", "type": "kubernetes.io/tls", "labels": {"a": "b"}, "annotations": {"x": None}}


def test_rules_review_and_role_projection():
    review = proj.project_rules_review("demo", {"status": {
        "resourceRules": [{"verbs": ["list"], "apiGroups": [""], "resources": ["pods"]}],
        "nonResourceRules": [{"verbs": ["get"], "nonResourceURLs": ["/version"]}], "incomplete": False}})
    assert review == {"namespace": "demo",
                      "resource_rules": [{"verbs": ["list"], "api_groups": [""], "resources": ["pods"],
                                          "resource_names": None}],
                      "non_resource_rules": [{"verbs": ["get"], "non_resource_ur_ls": ["/version"]}],
                      "incomplete": False, "evaluation_error": None}
    role = proj.project_role({"metadata": {"name": "agg"}, "aggregationRule": {"clusterRoleSelectors": [
        {"matchLabels": {"rbac.example.com/aggregate": "true"}}]}, "rules": None}, "ClusterRole")
    assert role["kind"] == "ClusterRole" and role["rules"] is None
    assert role["aggregation_rule"] == {"cluster_role_selectors": [
        {"match_labels": {"rbac.example.com/aggregate": "true"}, "match_expressions": None}]}
    assert "namespace" not in role["metadata"]


def test_service_and_ingress_projection():
    svc = proj.project_service({"metadata": {"name": "s", "namespace": "n"}, "spec": {
        "type": "LoadBalancer", "selector": {"app": "x"}, "clusterIP": "10.0.0.1", "externalIPs": ["1.2.3.4"],
        "loadBalancerSourceRanges": ["0.0.0.0/0"], "ports": [{"port": 443, "targetPort": "https", "nodePort": 30001}]},
        "status": {"loadBalancer": {"ingress": [{"hostname": "lb.example.com"}]}}})
    assert svc["spec"]["external_i_ps"] == ["1.2.3.4"] and svc["spec"]["load_balancer_source_ranges"] == ["0.0.0.0/0"]
    assert svc["spec"]["ports"] == [{"port": 443, "target_port": "https", "node_port": 30001}]
    assert svc["status"] == {"load_balancer": {"ingress": [{"hostname": "lb.example.com"}]}}
    ing = proj.project_ingress({"metadata": {"name": "i", "namespace": "n"}, "spec": {
        "tls": [{"hosts": ["a.example.com"], "secretName": "tls"}],
        "defaultBackend": {"resource": {"kind": "Bucket"}},
        "rules": [{"host": "a.example.com"}]}})
    assert ing["spec"]["tls"] == [{"hosts": ["a.example.com"], "secret_name": "tls"}]
    assert ing["spec"]["default_backend"] == {"service": None}
    assert ing["spec"]["rules"] == [{"host": "a.example.com", "http": None}]


def test_project_all_sorts_by_namespace_then_name():
    items = [{"metadata": {"name": n, "namespace": ns}} for ns, n in (("b", "a"), ("a", "z"), ("a", "b"))]
    out = proj.project_all(items, proj.project_service_account)
    assert [(i["metadata"]["namespace"], i["metadata"]["name"]) for i in out] == [("a", "b"), ("a", "z"), ("b", "a")]
