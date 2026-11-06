"""Projections of raw Kubernetes API objects into the report shapes (collectors-cli.md §5.16).

Input is the raw API JSON (camelCase, as the API server sends it). Output keeps the **snake_case** keys of
the Python client's ``to_dict()``, so the engine's field paths (``spec.service_account_name``,
``role_ref.kind`` ...) keep working, but only the fields listed here are copied:

* ``managedFields`` and ``kubectl.kubernetes.io/last-applied-configuration`` are dropped everywhere: the
  latter holds the full manifest, Secret ``data``/``stringData`` included (F-009);
* annotation keys are kept (the engine checks ingress auth keys), but their values are ``null`` except for
  :data:`ANNOTATION_VALUE_ALLOWLIST` (IRSA role ARN, load-balancer scheme ...);
* container ``env`` values are **never** written: an entry is ``{name, value_from, value_present}``
  (F-054); ``command``/``args`` are not copied either;
* Secrets are projected from metadata only (``{name, namespace, type, labels, annotations}``);
* the ``aws-auth`` ConfigMap is reduced to ``mapRoles`` / ``mapUsers`` / ``mapAccounts`` (F-050).

Pods carry init and ephemeral containers, hostPath / projected / secret volumes, capabilities, env
``valueFrom`` references, ``envFrom`` and the automount flag (F-035 data). Role kinds are set explicitly.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional

__all__ = [
    "ANNOTATION_VALUE_ALLOWLIST", "DROPPED_ANNOTATIONS", "SECRET_TYPES", "denied_aws_auth", "filter_annotations",
    "parse_aws_auth", "project_all", "project_binding", "project_ingress", "project_namespace", "project_node",
    "project_pod", "project_role", "project_rules_review", "project_secret_metadata", "project_service",
    "project_service_account", "project_version", "sort_key",
]

#: Annotations whose values are kept; every other annotation keeps its key with a ``null`` value.
ANNOTATION_VALUE_ALLOWLIST = frozenset({
    "eks.amazonaws.com/role-arn", "eks.amazonaws.com/audience", "eks.amazonaws.com/sts-regional-endpoints",
    "eks.amazonaws.com/token-expiration",
    "service.beta.kubernetes.io/aws-load-balancer-scheme", "service.beta.kubernetes.io/aws-load-balancer-internal",
    "service.beta.kubernetes.io/aws-load-balancer-type",
    "service.beta.kubernetes.io/aws-load-balancer-nlb-target-type",
    "kubernetes.io/ingress.class",
    "alb.ingress.kubernetes.io/scheme", "alb.ingress.kubernetes.io/target-type",
    "alb.ingress.kubernetes.io/auth-type",
    "nginx.ingress.kubernetes.io/auth-type",
    "kubernetes.io/service-account.name",
})
#: Annotations dropped entirely (key and value).
DROPPED_ANNOTATIONS = frozenset({"kubectl.kubernetes.io/last-applied-configuration"})

#: Secret types listed one by one with ``fieldSelector=type=<T>`` (metadata-only lists carry no type);
#: anything else is reported as ``"other"``.
SECRET_TYPES = (
    "Opaque", "kubernetes.io/service-account-token", "kubernetes.io/dockerconfigjson", "kubernetes.io/dockercfg",
    "kubernetes.io/tls", "kubernetes.io/basic-auth", "kubernetes.io/ssh-auth", "bootstrap.kubernetes.io/token",
    "helm.sh/release.v1",
)

_PROVIDER_ID_RE = re.compile(r"^aws:///(?P<zone>[^/]*)/(?P<rest>.+)$")


# ── helpers ──────────────────────────────────────────────────────────────────
def _map(obj: Any) -> Dict[str, Any]:
    return obj if isinstance(obj, dict) else {}


def _list(obj: Any) -> List[Any]:
    return obj if isinstance(obj, list) else []


def _str_map(obj: Any) -> Optional[Dict[str, str]]:
    """A ``map[string]string`` (labels, selectors); ``None`` when absent."""
    if not isinstance(obj, dict):
        return None
    return {str(k): (v if isinstance(v, str) else str(v)) for k, v in sorted(obj.items())}


def _str_list(obj: Any) -> Optional[List[str]]:
    if not isinstance(obj, list):
        return None
    return [v for v in obj if isinstance(v, str)]


def _pick(obj: Any, fields: Mapping[str, str]) -> Optional[Dict[str, Any]]:
    """``{snake: obj[camel]}`` for scalar fields that are present; ``None`` when ``obj`` is not a mapping."""
    if not isinstance(obj, dict):
        return None
    return {snake: obj[camel] for camel, snake in fields.items()
            if camel in obj and isinstance(obj[camel], (str, int, float, bool))}


def _items(obj: Any, fn: Callable[[Dict[str, Any]], Any]) -> Optional[List[Any]]:
    if not isinstance(obj, list):
        return None
    return [fn(i) for i in obj if isinstance(i, dict)]


def filter_annotations(annotations: Any) -> Optional[Dict[str, Optional[str]]]:
    """Keys kept, values ``null`` unless allow-listed; last-applied-configuration dropped (F-009)."""
    if not isinstance(annotations, dict):
        return None
    out: Dict[str, Optional[str]] = {}
    for key in sorted(annotations):
        if key in DROPPED_ANNOTATIONS:
            continue
        value = annotations[key]
        out[str(key)] = value if key in ANNOTATION_VALUE_ALLOWLIST and isinstance(value, str) else None
    return out


def _metadata(obj: Mapping[str, Any], *, namespaced: bool, owners: bool = False) -> Dict[str, Any]:
    meta = _map(obj.get("metadata"))
    out: Dict[str, Any] = {"name": meta.get("name")}
    if namespaced:
        out["namespace"] = meta.get("namespace")
    out["labels"] = _str_map(meta.get("labels"))
    out["annotations"] = filter_annotations(meta.get("annotations"))
    if owners:
        out["owner_references"] = _items(meta.get("ownerReferences"),
                                         lambda o: {"kind": o.get("kind"), "name": o.get("name")})
    return out


def sort_key(item: Mapping[str, Any]) -> tuple:
    """(namespace, name) of a projected object, for deterministic files."""
    meta = _map(item.get("metadata"))
    return (meta.get("namespace") or item.get("namespace") or "", meta.get("name") or item.get("name") or "")


# ── workloads ────────────────────────────────────────────────────────────────
_CONTAINER_SECURITY = {"privileged": "privileged", "allowPrivilegeEscalation": "allow_privilege_escalation",
                       "runAsUser": "run_as_user", "runAsGroup": "run_as_group", "runAsNonRoot": "run_as_non_root",
                       "readOnlyRootFilesystem": "read_only_root_filesystem", "procMount": "proc_mount"}
_POD_SECURITY = {"runAsUser": "run_as_user", "runAsGroup": "run_as_group", "runAsNonRoot": "run_as_non_root",
                 "fsGroup": "fs_group"}
_SECCOMP = {"type": "type", "localhostProfile": "localhost_profile"}


def _security_context(sc: Any, *, pod: bool) -> Optional[Dict[str, Any]]:
    if not isinstance(sc, dict):
        return None
    out = _pick(sc, _POD_SECURITY if pod else _CONTAINER_SECURITY) or {}
    if "seccompProfile" in sc:
        out["seccomp_profile"] = _pick(sc.get("seccompProfile"), _SECCOMP)
    if pod:
        if "supplementalGroups" in sc:
            out["supplemental_groups"] = [g for g in _list(sc.get("supplementalGroups")) if isinstance(g, int)]
        if "sysctls" in sc:  # names only
            out["sysctls"] = _items(sc.get("sysctls"), lambda s: {"name": s.get("name")})
    elif "capabilities" in sc:
        caps = _map(sc.get("capabilities"))
        out["capabilities"] = {"add": _str_list(caps.get("add")), "drop": _str_list(caps.get("drop"))}
    return out


def _key_ref(ref: Any) -> Optional[Dict[str, Any]]:
    return _pick(ref, {"name": "name", "key": "key", "optional": "optional"})


def _value_from(vf: Any) -> Optional[Dict[str, Any]]:
    """Where an env value comes from (names and keys only, never a value)."""
    if not isinstance(vf, dict):
        return None
    out: Dict[str, Any] = {}
    if "secretKeyRef" in vf:
        out["secret_key_ref"] = _key_ref(vf.get("secretKeyRef"))
    if "configMapKeyRef" in vf:
        out["config_map_key_ref"] = _key_ref(vf.get("configMapKeyRef"))
    if "fieldRef" in vf:
        out["field_ref"] = _pick(vf.get("fieldRef"), {"fieldPath": "field_path"})
    if "resourceFieldRef" in vf:
        out["resource_field_ref"] = _pick(vf.get("resourceFieldRef"),
                                          {"resource": "resource", "containerName": "container_name"})
    return out


def _env(entry: Dict[str, Any]) -> Dict[str, Any]:
    """``{name, value_from, value_present}``: the literal ``value`` is never copied (F-054)."""
    value = entry.get("value")
    return {"name": entry.get("name"), "value_from": _value_from(entry.get("valueFrom")),
            "value_present": isinstance(value, str) and value != ""}


def _env_from(entry: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"prefix": entry.get("prefix") if isinstance(entry.get("prefix"), str) else None}
    if "secretRef" in entry:
        out["secret_ref"] = _pick(entry.get("secretRef"), {"name": "name", "optional": "optional"})
    if "configMapRef" in entry:
        out["config_map_ref"] = _pick(entry.get("configMapRef"), {"name": "name", "optional": "optional"})
    return out


def _container(c: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": c.get("name"),
        "image": c.get("image"),
        "security_context": _security_context(c.get("securityContext"), pod=False),
        "ports": _items(c.get("ports"), lambda p: _pick(p, {
            "name": "name", "containerPort": "container_port", "hostPort": "host_port", "protocol": "protocol",
            "hostIP": "host_ip"})),
        "env": _items(c.get("env"), _env),
        "env_from": _items(c.get("envFrom"), _env_from),
        "volume_mounts": _items(c.get("volumeMounts"), lambda m: _pick(m, {
            "name": "name", "mountPath": "mount_path", "readOnly": "read_only", "subPath": "sub_path"})),
    }


def _projected_source(src: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if "serviceAccountToken" in src:
        out["service_account_token"] = _pick(src.get("serviceAccountToken"), {
            "audience": "audience", "expirationSeconds": "expiration_seconds", "path": "path"})
    if "secret" in src:
        out["secret"] = _pick(src.get("secret"), {"name": "name", "optional": "optional"})
    if "configMap" in src:
        out["config_map"] = _pick(src.get("configMap"), {"name": "name", "optional": "optional"})
    if "downwardAPI" in src:
        out["downward_api"] = {}
    return out


#: Volume sources copied (with the listed fields); any other source only keeps the volume name.
_VOLUME_SOURCES = {
    "secret": ("secret", {"secretName": "secret_name", "optional": "optional"}),
    "hostPath": ("host_path", {"path": "path", "type": "type"}),
    "configMap": ("config_map", {"name": "name", "optional": "optional"}),
    "persistentVolumeClaim": ("persistent_volume_claim", {"claimName": "claim_name", "readOnly": "read_only"}),
    "csi": ("csi", {"driver": "driver", "readOnly": "read_only"}),
    "emptyDir": ("empty_dir", {"medium": "medium"}),
}


def _volume(v: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"name": v.get("name")}
    for camel, (snake, fields) in _VOLUME_SOURCES.items():
        if camel in v:
            out[snake] = _pick(v.get(camel), fields)
    if "projected" in v:
        out["projected"] = {"sources": _items(_map(v.get("projected")).get("sources"), _projected_source)}
    return out


def project_pod(obj: Mapping[str, Any]) -> Dict[str, Any]:
    """A pod with its security-relevant spec; env values, command and args are never copied."""
    spec = _map(obj.get("spec"))
    return {
        "metadata": _metadata(obj, namespaced=True, owners=True),
        "spec": {
            "service_account_name": spec.get("serviceAccountName"),
            "service_account": spec.get("serviceAccount"),
            "automount_service_account_token": spec.get("automountServiceAccountToken"),
            "node_name": spec.get("nodeName"),
            "host_network": spec.get("hostNetwork"),
            "host_pid": spec.get("hostPID"),
            "host_ipc": spec.get("hostIPC"),
            "share_process_namespace": spec.get("shareProcessNamespace"),
            "security_context": _security_context(spec.get("securityContext"), pod=True),
            "volumes": _items(spec.get("volumes"), _volume),
            "containers": _items(spec.get("containers"), _container),
            "init_containers": _items(spec.get("initContainers"), _container),
            "ephemeral_containers": _items(spec.get("ephemeralContainers"), _container),
        },
        "status": {"phase": _map(obj.get("status")).get("phase")},
    }


def project_service_account(obj: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "metadata": _metadata(obj, namespaced=True),
        "automount_service_account_token": obj.get("automountServiceAccountToken"),
        "secrets": _items(obj.get("secrets"), lambda s: {"name": s.get("name")}),
        "image_pull_secrets": _items(obj.get("imagePullSecrets"), lambda s: {"name": s.get("name")}),
    }


def project_namespace(obj: Mapping[str, Any]) -> Dict[str, Any]:
    return {"metadata": _metadata(obj, namespaced=False), "status": {"phase": _map(obj.get("status")).get("phase")}}


# ── RBAC ─────────────────────────────────────────────────────────────────────
def _rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    return {"api_groups": _str_list(rule.get("apiGroups")), "resources": _str_list(rule.get("resources")),
            "verbs": _str_list(rule.get("verbs")), "resource_names": _str_list(rule.get("resourceNames")),
            "non_resource_ur_ls": _str_list(rule.get("nonResourceURLs"))}


def _label_selector(sel: Dict[str, Any]) -> Dict[str, Any]:
    return {"match_labels": _str_map(sel.get("matchLabels")),
            "match_expressions": _items(sel.get("matchExpressions"), lambda e: {
                "key": e.get("key"), "operator": e.get("operator"), "values": _str_list(e.get("values"))})}


def project_role(obj: Mapping[str, Any], kind: str) -> Dict[str, Any]:
    """A Role or ClusterRole; ``kind`` is set explicitly (list items carry none)."""
    out: Dict[str, Any] = {"kind": kind, "metadata": _metadata(obj, namespaced=kind == "Role"),
                           "rules": _items(obj.get("rules"), _rule)}
    if kind == "ClusterRole":
        agg = obj.get("aggregationRule")
        out["aggregation_rule"] = ({"cluster_role_selectors": _items(_map(agg).get("clusterRoleSelectors"),
                                                                      _label_selector)}
                                   if isinstance(agg, dict) else None)
    return out


def project_binding(obj: Mapping[str, Any], kind: str) -> Dict[str, Any]:
    """A RoleBinding or ClusterRoleBinding with every subject kind (ServiceAccount, User, Group)."""
    ref = _map(obj.get("roleRef"))
    return {
        "kind": kind,
        "metadata": _metadata(obj, namespaced=kind == "RoleBinding"),
        "role_ref": {"api_group": ref.get("apiGroup"), "kind": ref.get("kind"), "name": ref.get("name")},
        "subjects": _items(obj.get("subjects"), lambda s: {
            "kind": s.get("kind"), "name": s.get("name"), "namespace": s.get("namespace"),
            "api_group": s.get("apiGroup")}),
    }


def project_rules_review(namespace: str, doc: Mapping[str, Any]) -> Dict[str, Any]:
    """The ``status`` of a SelfSubjectRulesReview for ``namespace``."""
    status = _map(doc.get("status"))
    return {
        "namespace": namespace,
        "resource_rules": _items(status.get("resourceRules"), lambda r: {
            "verbs": _str_list(r.get("verbs")), "api_groups": _str_list(r.get("apiGroups")),
            "resources": _str_list(r.get("resources")), "resource_names": _str_list(r.get("resourceNames"))}) or [],
        "non_resource_rules": _items(status.get("nonResourceRules"), lambda r: {
            "verbs": _str_list(r.get("verbs")), "non_resource_ur_ls": _str_list(r.get("nonResourceURLs"))}) or [],
        "incomplete": status.get("incomplete") if isinstance(status.get("incomplete"), bool) else None,
        "evaluation_error": status.get("evaluationError") or None,
    }


# ── network ──────────────────────────────────────────────────────────────────
def _lb_status(status: Any) -> Dict[str, Any]:
    lb = _map(_map(status).get("loadBalancer"))
    return {"load_balancer": {"ingress": _items(lb.get("ingress"), lambda i: _pick(i, {
        "hostname": "hostname", "ip": "ip"}))}}


def project_service(obj: Mapping[str, Any]) -> Dict[str, Any]:
    spec = _map(obj.get("spec"))
    return {
        "metadata": _metadata(obj, namespaced=True),
        "spec": {
            "type": spec.get("type"),
            "selector": _str_map(spec.get("selector")),
            "cluster_ip": spec.get("clusterIP"),
            "external_i_ps": _str_list(spec.get("externalIPs")),
            "load_balancer_source_ranges": _str_list(spec.get("loadBalancerSourceRanges")),
            "load_balancer_class": spec.get("loadBalancerClass"),
            "external_traffic_policy": spec.get("externalTrafficPolicy"),
            "ports": _items(spec.get("ports"), lambda p: _pick(p, {
                "name": "name", "port": "port", "targetPort": "target_port", "nodePort": "node_port",
                "protocol": "protocol"})),
        },
        "status": _lb_status(obj.get("status")),
    }


def _backend(b: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(b, dict):
        return None
    svc = b.get("service")
    if not isinstance(svc, dict):
        return {"service": None}
    return {"service": {"name": svc.get("name"),
                        "port": _pick(svc.get("port"), {"number": "number", "name": "name"})}}


def _ingress_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    http = rule.get("http")
    paths = _items(_map(http).get("paths"), lambda p: {
        "path": p.get("path"), "path_type": p.get("pathType"), "backend": _backend(p.get("backend"))})
    return {"host": rule.get("host"), "http": {"paths": paths} if isinstance(http, dict) else None}


def project_ingress(obj: Mapping[str, Any]) -> Dict[str, Any]:
    spec = _map(obj.get("spec"))
    return {
        "metadata": _metadata(obj, namespaced=True),
        "spec": {
            "ingress_class_name": spec.get("ingressClassName"),
            "default_backend": _backend(spec.get("defaultBackend")),
            "rules": _items(spec.get("rules"), _ingress_rule),
            "tls": _items(spec.get("tls"), lambda t: {"hosts": _str_list(t.get("hosts")),
                                                       "secret_name": t.get("secretName")}),
        },
        "status": _lb_status(obj.get("status")),
    }


# ── nodes ────────────────────────────────────────────────────────────────────
def _parse_provider_id(provider_id: Any) -> Dict[str, Optional[str]]:
    """``aws:///eu-west-2b/i-0abc`` -> zone and EC2 instance id (Fargate ids are not instances)."""
    out: Dict[str, Optional[str]] = {"zone": None, "instance_id": None}
    m = _PROVIDER_ID_RE.match(provider_id) if isinstance(provider_id, str) else None
    if m:
        out["zone"] = m.group("zone") or None
        last = m.group("rest").rsplit("/", 1)[-1]
        out["instance_id"] = last if re.fullmatch(r"i-[0-9a-f]+", last) else None
    return out


def project_node(obj: Mapping[str, Any]) -> Dict[str, Any]:
    """A node with the fields the pod -> node -> node group path needs (F-033)."""
    meta = _metadata(obj, namespaced=False)
    spec = _map(obj.get("spec"))
    info = _map(obj.get("status")).get("nodeInfo")
    labels = meta.get("labels") or {}
    parsed = _parse_provider_id(spec.get("providerID"))
    return {
        "metadata": meta,
        "spec": {"provider_id": spec.get("providerID"), "unschedulable": spec.get("unschedulable"),
                 "taints": _items(spec.get("taints"), lambda t: {"key": t.get("key"), "effect": t.get("effect")})},
        "status": {"node_info": _pick(info, {"kubeletVersion": "kubelet_version", "osImage": "os_image",
                                             "architecture": "architecture",
                                             "containerRuntimeVersion": "container_runtime_version"})},
        "provider_id": spec.get("providerID"),
        "instance_id": parsed["instance_id"],
        "zone": labels.get("topology.kubernetes.io/zone") or parsed["zone"],
        "nodegroup": labels.get("eks.amazonaws.com/nodegroup"),
        "compute_type": labels.get("eks.amazonaws.com/compute-type"),
        "capacity_type": labels.get("eks.amazonaws.com/capacityType"),
    }


# ── secrets, version, aws-auth ───────────────────────────────────────────────
def project_secret_metadata(obj: Mapping[str, Any], secret_type: str) -> Dict[str, Any]:
    """Secret metadata only (from a ``PartialObjectMetadataList``); never ``data``/``stringData``."""
    meta = _metadata(obj, namespaced=True)
    return {"name": meta["name"], "namespace": meta["namespace"], "type": secret_type, "labels": meta["labels"],
            "annotations": meta["annotations"]}


def project_version(doc: Mapping[str, Any]) -> Dict[str, Any]:
    return {"major": doc.get("major"), "minor": doc.get("minor"), "git_version": doc.get("gitVersion"),
            "platform": doc.get("platform")}


_AWS_AUTH_KEYS = (("mapRoles", "map_roles", "rolearn"), ("mapUsers", "map_users", "userarn"))


def _mapping_entries(raw: Any, arn_key: str) -> List[Dict[str, Any]]:
    if not isinstance(raw, list):
        raise ValueError("not a list")
    out = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError("entry is not a mapping")
        groups = entry.get("groups")
        out.append({arn_key: entry.get(arn_key) if isinstance(entry.get(arn_key), str) else None,
                    "username": entry.get("username") if isinstance(entry.get("username"), str) else None,
                    "groups": [g for g in groups if isinstance(g, str)] if isinstance(groups, list) else []})
    return sorted(out, key=lambda e: (e[arn_key] or "", e["username"] or ""))


def _account_id(value: Any) -> str:
    """An unquoted account id is parsed by YAML as an int (losing leading zeros): restore the 12 digits."""
    if isinstance(value, int) and 0 <= value < 10 ** 12:
        return f"{value:012d}"
    return str(value)


def _yaml_load(text: str) -> Any:
    import yaml  # PyYAML ships with the kubernetes package

    return yaml.safe_load(text)


def parse_aws_auth(configmap: Optional[Mapping[str, Any]], *,
                   loader: Callable[[str], Any] = _yaml_load) -> Dict[str, Any]:
    """``kube-system/aws-auth`` reduced to its three identity mappings; every other key is dropped.

    ``configmap`` ``None`` means "not present" (404). Entries keep only ``rolearn``/``userarn``,
    ``username`` and ``groups``; ``mapAccounts`` is a list of account ids. A key that cannot be parsed is
    ``null`` and named in ``parse_errors`` (never its content).
    """
    if configmap is None:
        return {"present": False, "map_roles": [], "map_users": [], "map_accounts": [], "parse_errors": []}
    data = _map(configmap.get("data"))
    out: Dict[str, Any] = {"present": True, "parse_errors": []}
    for camel, snake, arn_key in _AWS_AUTH_KEYS:
        try:
            out[snake] = _mapping_entries(loader(data[camel]) or [], arn_key) if camel in data else []
        except Exception:  # YAML errors, wrong shapes, missing PyYAML: report the key, keep going
            out[snake] = None
            out["parse_errors"].append(camel)
    try:
        accounts = (loader(data["mapAccounts"]) or []) if "mapAccounts" in data else []
        if not isinstance(accounts, list):
            raise ValueError("not a list")
        out["map_accounts"] = sorted(_account_id(a) for a in accounts if isinstance(a, (str, int))
                                     and not isinstance(a, bool))
    except Exception:
        out["map_accounts"] = None
        out["parse_errors"].append("mapAccounts")
    return {k: out[k] for k in ("present", "map_roles", "map_users", "map_accounts", "parse_errors")}


def denied_aws_auth() -> Dict[str, Any]:
    """``aws_auth.json`` when the ConfigMap could not be read: unknown is ``null``."""
    return {"present": None, "map_roles": None, "map_users": None, "map_accounts": None, "parse_errors": []}


def project_all(items: Iterable[Mapping[str, Any]], fn: Callable[[Mapping[str, Any]], Dict[str, Any]],
                ) -> List[Dict[str, Any]]:
    """Project and sort by (namespace, name)."""
    return sorted((fn(i) for i in items), key=sort_key)
