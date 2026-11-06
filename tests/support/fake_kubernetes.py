"""A fake ``kubernetes`` package injected through ``sys.modules`` (no cluster, no network).

It provides the surface the baseline collector uses (``kubernetes.client.Configuration``, ``ApiClient``,
``CoreV1Api``, ``RbacAuthorizationV1Api``, ``NetworkingV1Api``, ``VersionApi`` and
``kubernetes.client.rest.ApiException``) plus what the migrated collector (collectors-cli.md §5.16) needs:

* typed list calls with ``limit``/``_continue`` paging, ``field_selector`` / ``label_selector`` filtering and
  ``_preload_content=False`` (raw JSON response), including the namespaced variants
  (``list_namespaced_*``) used by the namespaced fallback after a cluster-wide 403 (F-152);
* ``read_namespaced_config_map`` (``kube-system/aws-auth``, F-050) and ``list_node`` (F-033);
* ``AuthorizationV1Api.create_self_subject_rules_review`` with the ``V1SelfSubjectRulesReview`` /
  ``V1SelfSubjectRulesReviewSpec`` model constructors;
* ``config.load_kube_config(config_file, context, client_configuration)`` reading a real kubeconfig file
  (server, bearer token, CA path) and ``config.load_incluster_config`` driven by :attr:`FakeKubernetes.in_cluster`
  (``--k8s-auth kubeconfig`` / ``in-cluster``, F-152);
* :attr:`FakeCluster.errors` may hold any exception, for example a urllib3 ``MaxRetryError`` wrapping a
  ``ConnectTimeoutError`` for an unreachable endpoint (F-120); its outcome is the class name;
* ``ApiClient.call_api(resource_path, method, ...)``, the transport the design plans: REST paths are routed
  to the same cluster data and answered with raw, camelCase JSON (``_preload_content=False`` gives an
  urllib3-like response with ``.data``/``.status``/``.headers``). ``Accept:
  application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1`` returns metadata-only lists, as the
  real API server does (F-009: ``--k8s-secrets`` lists Secret metadata only; annotations are still
  returned, so a collector must drop ``last-applied-configuration`` itself).

Clusters are looked up by the ``Configuration.host`` the code sets (the EKS endpoint). Each cluster is a
:class:`FakeCluster` holding plain snake_case dicts, the shape ``V1Pod.to_dict()`` produces; typed calls
return :class:`Model` objects that support both attribute access (``secret.metadata.name``) and
``to_dict()``.

Every API call is recorded as a :class:`K8sCall` (cluster, api, method, resource, kwargs, outcome; plus the
HTTP method and path for ``call_api``) so tests can assert which resources were read, with which timeout
(``kwargs["_request_timeout"]``, F-120) and which ``Accept`` header (``kwargs["header_params"]``).

Errors (:attr:`FakeCluster.errors`, and one-shot :attr:`FakeCluster.error_once`) are looked up, first match
wins, as ``"<resource>:continue"`` (a request carrying a continue token, e.g. 410 Gone for F-149),
``"<resource>:<namespace>"`` or ``"<resource>:cluster"`` (a cluster-wide list), ``"<resource>"`` and ``"*"``.

Usage::

    k8s = FakeKubernetes({endpoint: FakeCluster(...)})
    k8s.install(monkeypatch)          # sys.modules['kubernetes'] = fake package
"""

from __future__ import annotations

import copy
import datetime as _dt
import json
import os
import re
import sys
import threading
import types
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import parse_qsl

__all__ = ["ApiException", "DEFAULT_SELF_RULES", "FakeCluster", "FakeHTTPResponse", "FakeKubernetes", "K8sCall",
           "MAP_FIELDS", "METADATA_ONLY_ACCEPT", "Model", "to_camel", "to_snake"]


class ApiException(Exception):
    """Mirror of ``kubernetes.client.exceptions.ApiException`` (str() format included)."""

    def __init__(self, status: int = 0, reason: Optional[str] = None, body: Optional[str] = None,
                 headers: Optional[Mapping[str, str]] = None, http_resp: Any = None):
        super().__init__(status, reason)
        self.status = status
        self.reason = reason
        self.body = body
        self.headers = dict(headers or {})

    def __str__(self) -> str:
        msg = f"({self.status})\nReason: {self.reason}\n"
        if self.headers:
            msg += f"HTTP response headers: {self.headers}\n"
        if self.body:
            msg += f"HTTP response body: {self.body}\n"
        return msg


class Model:
    """Attribute + ``to_dict()`` view over a snake_case dict (like generated k8s models)."""

    __slots__ = ("_data",)

    def __init__(self, data: Mapping[str, Any]):
        object.__setattr__(self, "_data", copy.deepcopy(dict(data)))

    def to_dict(self) -> Dict[str, Any]:
        return copy.deepcopy(self._data)

    def __getattr__(self, name: str) -> Any:
        data = object.__getattribute__(self, "_data")
        if name not in data:
            return None  # generated models expose every attribute, unset ones are None
        value = data[name]
        if name in MAP_FIELDS:
            return copy.deepcopy(value)  # dict(str, str) attributes are plain dicts in the real client
        return _wrap(value)

    def __repr__(self) -> str:
        return f"Model({self._data!r})"


#: Attributes that are typed ``dict(str, str)`` (plain dicts) in the generated client,
#: as opposed to nested model objects.
MAP_FIELDS = frozenset({
    "labels", "annotations", "data", "string_data", "binary_data", "selector", "node_selector",
    "match_labels", "capacity", "allocatable", "limits", "requests", "volume_attributes",
})

#: The Accept header of a metadata-only list (collectors-cli.md §5.16, F-009).
METADATA_ONLY_ACCEPT = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1"

#: What a read-only auditor without Secret access gets from SelfSubjectRulesReview (any namespace).
DEFAULT_SELF_RULES: Dict[str, Any] = {
    "resource_rules": [
        {"verbs": ["get", "list", "watch"], "api_groups": [""],
         "resources": ["pods", "services", "serviceaccounts", "configmaps", "namespaces", "nodes"],
         "resource_names": None},
        {"verbs": ["get", "list", "watch"], "api_groups": ["rbac.authorization.k8s.io"], "resources": ["*"],
         "resource_names": None},
        {"verbs": ["get", "list", "watch"], "api_groups": ["networking.k8s.io"], "resources": ["ingresses"],
         "resource_names": None},
        {"verbs": ["create"], "api_groups": ["authorization.k8s.io"],
         "resources": ["selfsubjectaccessreviews", "selfsubjectrulesreviews"], "resource_names": None},
    ],
    "non_resource_rules": [{"verbs": ["get"], "non_resource_ur_ls": ["/version", "/healthz", "/readyz"]}],
    "incomplete": False,
    "evaluation_error": None,
}


def _wrap(value: Any) -> Any:
    if isinstance(value, dict):
        return Model(value)
    if isinstance(value, list):
        return [_wrap(v) for v in value]
    return value


# ── snake_case <-> camelCase (raw API JSON) ──────────────────────────────────
_SNAKE_TO_CAMEL_SPECIAL = {
    "_continue": "continue", "api_version": "apiVersion", "non_resource_ur_ls": "nonResourceURLs",
    "pod_ip": "podIP", "pod_i_ps": "podIPs", "host_ip": "hostIP", "host_i_ps": "hostIPs", "cluster_ip": "clusterIP",
    "cluster_i_ps": "clusterIPs", "external_i_ps": "externalIPs", "load_balancer_ip": "loadBalancerIP",
    "provider_id": "providerID", "_from": "from", "_exec": "exec", "_ref": "$ref",
    "host_pid": "hostPID", "host_ipc": "hostIPC", "pod_cidr": "podCIDR", "pod_cid_rs": "podCIDRs",
}
_CAMEL_TO_SNAKE_SPECIAL = {v: k for k, v in _SNAKE_TO_CAMEL_SPECIAL.items()}


def _camel_key(key: str) -> str:
    if key in _SNAKE_TO_CAMEL_SPECIAL:
        return _SNAKE_TO_CAMEL_SPECIAL[key]
    head, *rest = key.split("_")
    return head + "".join(p[:1].upper() + p[1:] for p in rest)


def _snake_key(key: str) -> str:
    if key in _CAMEL_TO_SNAKE_SPECIAL:
        return _CAMEL_TO_SNAKE_SPECIAL[key]
    return re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower()


def to_camel(obj: Any, *, drop_none: bool = True, _map: bool = False) -> Any:
    """snake_case model dicts -> raw API JSON (camelCase keys; map-typed fields keep their own keys)."""
    if isinstance(obj, dict):
        if _map:
            return {k: v for k, v in obj.items() if not (drop_none and v is None)}
        return {_camel_key(k): to_camel(v, drop_none=drop_none, _map=k in MAP_FIELDS)
                for k, v in obj.items() if not (drop_none and v is None)}
    if isinstance(obj, list):
        return [to_camel(v, drop_none=drop_none) for v in obj]
    if isinstance(obj, _dt.datetime):  # the API server sends RFC 3339 strings
        if obj.tzinfo is not None:
            obj = obj.astimezone(_dt.timezone.utc).replace(tzinfo=None)
        return obj.strftime("%Y-%m-%dT%H:%M:%SZ")
    return obj


def to_snake(obj: Any, *, _map: bool = False) -> Any:
    """Raw API JSON -> snake_case dicts (the inverse of :func:`to_camel`, as ``deserialize`` would give)."""
    if isinstance(obj, dict):
        if _map:
            return dict(obj)
        out = {}
        for k, v in obj.items():
            sk = _snake_key(k)
            out[sk] = to_snake(v, _map=sk in MAP_FIELDS)
        return out
    if isinstance(obj, list):
        return [to_snake(v) for v in obj]
    return obj


class _ListResult:
    def __init__(self, items: List[Dict[str, Any]], continue_token: Optional[str] = None):
        self.items = [Model(i) for i in items]
        self.metadata = Model({"_continue": continue_token, "resource_version": "1"})

    def to_dict(self) -> Dict[str, Any]:
        return {"items": [i.to_dict() for i in self.items], "metadata": self.metadata.to_dict()}


class FakeHTTPResponse:
    """What ``_preload_content=False`` returns: an urllib3-like response with the raw JSON body."""

    def __init__(self, status: int, payload: Any, headers: Optional[Mapping[str, str]] = None):
        self.status = status
        self.reason = "OK" if status == 200 else "Created" if status == 201 else ""
        self.data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.headers = {"Content-Type": "application/json", **dict(headers or {})}

    def read(self, *args: Any, **kwargs: Any) -> bytes:
        return self.data

    def json(self) -> Any:
        return json.loads(self.data)

    def getheaders(self) -> Dict[str, str]:
        return dict(self.headers)

    def getheader(self, name: str, default: Optional[str] = None) -> Optional[str]:
        return self.headers.get(name, default)

    def release_conn(self) -> None:
        pass

    def close(self) -> None:
        pass


@dataclass
class FakeCluster:
    """One synthetic cluster. Resource lists hold snake_case dicts.

    ``errors`` maps an error key (see the module docstring: ``"pods"``, ``"pods:cluster"``,
    ``"pods:<namespace>"``, ``"pods:continue"``, ``"version"``, ``"selfsubjectrulesreviews"`` ...) to an
    :class:`ApiException` raised when that resource is read; ``"*"`` applies to every call (e.g. 401 for a
    cluster the caller cannot reach). ``error_once`` entries are raised once, then removed.
    ``self_rules`` maps a namespace (or ``"*"``) to the SelfSubjectRulesReview status (snake_case);
    :data:`DEFAULT_SELF_RULES` applies when nothing matches.
    """

    name: str
    version: Dict[str, str] = field(default_factory=lambda: {
        "major": "1", "minor": "29", "git_version": "v1.29.0-eks-demo", "platform": "linux/amd64"})
    namespaces: List[Dict[str, Any]] = field(default_factory=list)
    pods: List[Dict[str, Any]] = field(default_factory=list)
    service_accounts: List[Dict[str, Any]] = field(default_factory=list)
    roles: List[Dict[str, Any]] = field(default_factory=list)
    cluster_roles: List[Dict[str, Any]] = field(default_factory=list)
    role_bindings: List[Dict[str, Any]] = field(default_factory=list)
    cluster_role_bindings: List[Dict[str, Any]] = field(default_factory=list)
    secrets: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    ingresses: List[Dict[str, Any]] = field(default_factory=list)
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    config_maps: List[Dict[str, Any]] = field(default_factory=list)
    errors: Dict[str, BaseException] = field(default_factory=dict)
    page_size: Optional[int] = None  # honoured only when the caller passes limit=
    self_rules: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    error_once: Dict[str, BaseException] = field(default_factory=dict)


@dataclass(frozen=True)
class K8sCall:
    seq: int
    cluster: str
    api: str
    method: str
    resource: str
    kwargs: Dict[str, Any]
    outcome: str
    http_method: Optional[str] = None   # call_api only
    path: Optional[str] = None          # call_api only

    @property
    def headers(self) -> Dict[str, str]:
        return dict(self.kwargs.get("header_params") or {})

    @property
    def metadata_only(self) -> bool:
        return "as=PartialObjectMetadata" in str(self.headers.get("Accept", ""))


#: resource -> (Kind, apiVersion, REST group prefix, REST plural, namespaced)
_RESOURCES: Dict[str, Tuple[str, str, str, str, bool]] = {
    "namespaces": ("Namespace", "v1", "/api/v1", "namespaces", False),
    "pods": ("Pod", "v1", "/api/v1", "pods", True),
    "service_accounts": ("ServiceAccount", "v1", "/api/v1", "serviceaccounts", True),
    "secrets": ("Secret", "v1", "/api/v1", "secrets", True),
    "services": ("Service", "v1", "/api/v1", "services", True),
    "nodes": ("Node", "v1", "/api/v1", "nodes", False),
    "config_maps": ("ConfigMap", "v1", "/api/v1", "configmaps", True),
    "roles": ("Role", "rbac.authorization.k8s.io/v1", "/apis/rbac.authorization.k8s.io/v1", "roles", True),
    "cluster_roles": ("ClusterRole", "rbac.authorization.k8s.io/v1", "/apis/rbac.authorization.k8s.io/v1",
                      "clusterroles", False),
    "role_bindings": ("RoleBinding", "rbac.authorization.k8s.io/v1", "/apis/rbac.authorization.k8s.io/v1",
                      "rolebindings", True),
    "cluster_role_bindings": ("ClusterRoleBinding", "rbac.authorization.k8s.io/v1",
                              "/apis/rbac.authorization.k8s.io/v1", "clusterrolebindings", False),
    "ingresses": ("Ingress", "networking.k8s.io/v1", "/apis/networking.k8s.io/v1", "ingresses", True),
}
_BY_PATH = {(prefix, plural): res for res, (_k, _v, prefix, plural, _n) in _RESOURCES.items()}
SELF_RULES_PATH = "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"


def _outcome(err: BaseException) -> str:
    """``ApiException:<status>`` for API errors, the class name for transport errors (timeouts ...)."""
    status = getattr(err, "status", None)
    return f"ApiException:{status}" if isinstance(err, ApiException) else type(err).__name__


def _field_value(item: Mapping[str, Any], dotted: str) -> Any:
    cur: Any = item
    for part in dotted.split("."):
        if not isinstance(cur, Mapping):
            return None
        cur = cur.get(_snake_key(part))
    return cur


def _selector_match(item: Mapping[str, Any], field_selector: Optional[str], label_selector: Optional[str]) -> bool:
    for term in filter(None, (field_selector or "").split(",")):
        neg = "!=" in term
        key, value = term.split("!=" if neg else "==" if "==" in term else "=", 1)
        actual = _field_value(item, key.strip())
        if (str(actual) == value.strip()) == neg:
            return False
    labels = ((item.get("metadata") or {}).get("labels") or {})
    for term in filter(None, (label_selector or "").split(",")):
        if "!=" in term:
            k, v = term.split("!=", 1)
            if labels.get(k.strip()) == v.strip():
                return False
        elif "=" in term:
            k, v = term.replace("==", "=").split("=", 1)
            if labels.get(k.strip()) != v.strip():
                return False
        elif term.strip() not in labels:
            return False
    return True


def _load_kubeconfig(spec: str) -> Optional[Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any], Optional[str]]]:
    """(contexts, clusters, users, current-context) merged first-wins from ``os.pathsep``-separated files."""
    import yaml

    contexts: Dict[str, Any] = {}
    clusters: Dict[str, Any] = {}
    users: Dict[str, Any] = {}
    current: Optional[str] = None
    found = False
    for path in (p for p in str(spec).split(os.pathsep) if p):
        path = os.path.expanduser(path)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        found = True
        current = current or doc.get("current-context")
        for key, target, inner in (("contexts", contexts, "context"), ("clusters", clusters, "cluster"),
                                   ("users", users, "user")):
            for entry in doc.get(key) or []:
                target.setdefault(entry["name"], dict(entry.get(inner) or {}))
    return (contexts, clusters, users, current) if found else None


class FakeKubernetes:
    """The fake package plus its recorder."""

    def __init__(self, clusters: Mapping[str, FakeCluster]):
        # keyed by endpoint (Configuration.host)
        self.clusters: Dict[str, FakeCluster] = dict(clusters)
        self.calls: List[K8sCall] = []
        self.api_clients: List[Dict[str, Any]] = []
        #: ``{"host": ..., "token": ...}`` served by ``config.load_incluster_config`` (``None``: not in a pod).
        self.in_cluster: Optional[Dict[str, str]] = None
        #: Every ``config.load_kube_config`` call: ``{"context", "host"}``.
        self.kubeconfig_loads: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._seq = 0
        self.package = self._build_package()

    # ── install ─────────────────────────────────────────────────────────────
    def install(self, monkeypatch: Any) -> "FakeKubernetes":
        pkg = self.package
        for name in list(sys.modules):
            if name == "kubernetes" or name.startswith("kubernetes."):
                monkeypatch.delitem(sys.modules, name, raising=False)
        monkeypatch.setitem(sys.modules, "kubernetes", pkg)
        monkeypatch.setitem(sys.modules, "kubernetes.client", pkg.client)
        monkeypatch.setitem(sys.modules, "kubernetes.client.rest", pkg.client.rest)
        monkeypatch.setitem(sys.modules, "kubernetes.client.exceptions", pkg.client.exceptions)
        monkeypatch.setitem(sys.modules, "kubernetes.config", pkg.config)
        return self

    # ── recording ───────────────────────────────────────────────────────────
    def _record(self, cluster: str, api: str, method: str, resource: str, kwargs: Mapping[str, Any],
                outcome: str, http_method: Optional[str] = None, path: Optional[str] = None) -> None:
        with self._lock:
            self.calls.append(K8sCall(self._seq, cluster, api, method, resource, dict(kwargs), outcome,
                                      http_method, path))
            self._seq += 1

    def calls_for(self, cluster: Optional[str] = None, resource: Optional[str] = None) -> List[K8sCall]:
        with self._lock:
            calls = list(self.calls)
        return [c for c in calls if (cluster is None or c.cluster == cluster)
                and (resource is None or c.resource == resource)]

    def resources_read(self, cluster: Optional[str] = None) -> List[str]:
        return sorted({c.resource for c in self.calls_for(cluster)})

    # ── serving ─────────────────────────────────────────────────────────────
    def _cluster_for(self, api_client: Any) -> Tuple[str, Optional[FakeCluster]]:
        host = getattr(getattr(api_client, "configuration", None), "host", None)
        return host or "<no-host>", self.clusters.get(host or "")

    @staticmethod
    def _error(cluster: FakeCluster, resource: str, namespace: Optional[str], cont: Optional[str]
               ) -> Optional[BaseException]:
        keys = []
        if cont:
            keys.append(f"{resource}:continue")
        keys.append(f"{resource}:{namespace}" if namespace is not None else f"{resource}:cluster")
        keys += [resource, "*"]
        for key in keys:
            if key in cluster.error_once:
                return cluster.error_once.pop(key)
            if key in cluster.errors:
                return cluster.errors[key]
        return None

    def _check(self, api_client: Any, api_name: str, method: str, resource: str, kwargs: Mapping[str, Any],
               namespace: Optional[str] = None, cont: Optional[str] = None, http_method: Optional[str] = None,
               path: Optional[str] = None) -> Tuple[str, FakeCluster]:
        """Resolve the cluster and apply injected errors (recording failures)."""
        host, cluster = self._cluster_for(api_client)
        label = cluster.name if cluster else host
        if cluster is None:
            self._record(label, api_name, method, resource, kwargs, "unreachable", http_method, path)
            raise ApiException(status=0, reason=f"fake kubernetes: no cluster at {host}")
        err = self._error(cluster, resource, namespace, cont)
        if err is not None:
            self._record(label, api_name, method, resource, kwargs, _outcome(err), http_method, path)
            raise err
        return label, cluster

    @staticmethod
    def _page(cluster: FakeCluster, items: List[Dict[str, Any]], limit: Any, cont: Optional[str]
              ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        start = int(str(cont).rsplit("-", 1)[-1]) if cont else 0
        token = None
        if limit and cluster.page_size:
            size = min(int(limit), cluster.page_size)
            if start + size < len(items):
                token = f"fake-continue-{start + size}"
            items = items[start:start + size]
        elif limit:
            if start + int(limit) < len(items):
                token = f"fake-continue-{start + int(limit)}"
            items = items[start:start + int(limit)]
        return items, token

    def _items(self, cluster: FakeCluster, attr: str, namespace: Optional[str], field_selector: Optional[str],
               label_selector: Optional[str]) -> List[Dict[str, Any]]:
        items = list(getattr(cluster, attr))
        if namespace is not None:
            items = [i for i in items if (i.get("metadata") or {}).get("namespace") == namespace]
        if field_selector or label_selector:
            items = [i for i in items if _selector_match(i, field_selector, label_selector)]
        return items

    def _serve(self, api_name: str, method: str, resource: str, attr: str, api_client: Any,
               kwargs: Mapping[str, Any], namespace: Optional[str] = None) -> Any:
        cont = kwargs.get("_continue")
        label, cluster = self._check(api_client, api_name, method, resource, kwargs, namespace, cont)
        items = self._items(cluster, attr, namespace, kwargs.get("field_selector"), kwargs.get("label_selector"))
        items, token = self._page(cluster, items, kwargs.get("limit"), cont)
        self._record(label, api_name, method, resource, kwargs, "ok")
        if kwargs.get("_preload_content") is False:
            return FakeHTTPResponse(200, self._raw_list(resource, items, token))
        return _ListResult(items, token)

    @staticmethod
    def _raw_list(resource: str, items: List[Dict[str, Any]], token: Optional[str],
                  metadata_only: bool = False) -> Dict[str, Any]:
        kind, api_version = _RESOURCES[resource][0], _RESOURCES[resource][1]
        meta: Dict[str, Any] = {"resourceVersion": "1"}
        if token:
            meta["continue"] = token
        if metadata_only:
            return {"kind": "PartialObjectMetadataList", "apiVersion": "meta.k8s.io/v1", "metadata": meta,
                    "items": [{"kind": "PartialObjectMetadata", "apiVersion": "meta.k8s.io/v1",
                               "metadata": to_camel(i.get("metadata") or {})} for i in items]}
        raw_items = [to_camel({k: v for k, v in i.items() if k not in ("api_version", "kind")}) for i in items]
        return {"kind": f"{kind}List", "apiVersion": api_version, "metadata": meta, "items": raw_items}

    def _rules_review(self, cluster: FakeCluster, namespace: str) -> Dict[str, Any]:
        status = cluster.self_rules.get(namespace) or cluster.self_rules.get("*") or DEFAULT_SELF_RULES
        return {"api_version": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview",
                "metadata": {"creation_timestamp": None}, "spec": {"namespace": namespace},
                "status": copy.deepcopy(status)}

    # ── call_api (REST transport) ───────────────────────────────────────────
    def _route(self, path: str) -> Tuple[str, Optional[str], Optional[str]]:
        """``path`` -> (resource, namespace, name). Unknown paths raise 404."""
        if path == "/version":
            return "version", None, None
        if path == SELF_RULES_PATH:
            return "selfsubjectrulesreviews", None, None
        for prefix in ("/api/v1", "/apis/rbac.authorization.k8s.io/v1", "/apis/networking.k8s.io/v1"):
            if not path.startswith(prefix + "/"):
                continue
            parts = path[len(prefix) + 1:].split("/")
            if len(parts) >= 3 and parts[0] == "namespaces" and (prefix, parts[2]) in _BY_PATH:
                name = parts[3] if len(parts) > 3 else None
                return _BY_PATH[(prefix, parts[2])], parts[1], name
            if (prefix, parts[0]) in _BY_PATH:
                return _BY_PATH[(prefix, parts[0])], None, (parts[1] if len(parts) > 1 else None)
        raise ApiException(status=404, reason="Not Found", body=json.dumps({"kind": "Status", "code": 404}))

    def call_api(self, api_client: Any, resource_path: str, method: str, path_params: Optional[Mapping] = None,
                 query_params: Any = None, header_params: Optional[Mapping] = None, body: Any = None,
                 **kwargs: Any) -> Any:
        path = resource_path
        for k, v in dict(path_params or {}).items():
            path = path.replace("{" + k + "}", str(v))
        query = dict(query_params or [])
        if "?" in path:
            path, qs = path.split("?", 1)
            query.update(dict(parse_qsl(qs)))
        headers = dict(header_params or {})
        record = {"path": path, "http_method": method, "query_params": query, "header_params": headers,
                  "_request_timeout": kwargs.get("_request_timeout"), "body": copy.deepcopy(body)}
        http_method = method.upper()
        try:
            resource, namespace, name = self._route(path)
        except ApiException:
            host, cluster = self._cluster_for(api_client)
            self._record(cluster.name if cluster else host, "ApiClient", "call_api", "<unknown>", record,
                         "ApiException:404", http_method, path)
            raise
        cont = query.get("continue")
        label, cluster = self._check(api_client, "ApiClient", "call_api", resource, record,
                                     namespace if resource != "selfsubjectrulesreviews" else None, cont,
                                     http_method, path)
        status = 200
        if resource == "version":
            payload, snake = to_camel(cluster.version), dict(cluster.version)
        elif resource == "selfsubjectrulesreviews":
            if http_method != "POST":
                raise ApiException(status=405, reason="Method Not Allowed")
            spec = (body or {}).get("spec") if isinstance(body, Mapping) else getattr(body, "spec", None)
            ns = spec.get("namespace") if isinstance(spec, Mapping) else getattr(spec, "namespace", None)
            snake = self._rules_review(cluster, ns or "default")
            payload, status = to_camel(snake), 201
        elif http_method != "GET":
            raise ApiException(status=405, reason="Method Not Allowed")
        else:
            metadata_only = "as=PartialObjectMetadata" in str(headers.get("Accept", ""))
            attr = resource
            items = self._items(cluster, attr, namespace, query.get("fieldSelector"), query.get("labelSelector"))
            if name is not None:
                found = [i for i in items if (i.get("metadata") or {}).get("name") == name]
                if not found:
                    self._record(label, "ApiClient", "call_api", resource, record, "ApiException:404", http_method,
                                 path)
                    raise ApiException(status=404, reason="Not Found")
                snake = found[0]
                if metadata_only:
                    payload = {"kind": "PartialObjectMetadata", "apiVersion": "meta.k8s.io/v1",
                               "metadata": to_camel(snake.get("metadata") or {})}
                else:
                    kind, api_version = _RESOURCES[resource][0], _RESOURCES[resource][1]
                    payload = dict(to_camel({k: v for k, v in snake.items() if k not in ("api_version", "kind")}),
                                   kind=kind, apiVersion=api_version)
            else:
                items, token = self._page(cluster, items, query.get("limit"), cont)
                payload = self._raw_list(resource, items, token, metadata_only)
                snake = {"items": items, "metadata": {"_continue": token, "resource_version": "1"}}
        self._record(label, "ApiClient", "call_api", resource, record, "ok", http_method, path)
        if kwargs.get("_preload_content", True) is False:
            return FakeHTTPResponse(status, payload)
        data = Model(snake) if not (isinstance(snake, dict) and "items" in snake) else _ListResult(
            snake["items"], snake["metadata"]["_continue"])
        if kwargs.get("_return_http_data_only"):
            return data
        return data, status, {"Content-Type": "application/json"}

    # ── package construction ────────────────────────────────────────────────
    def _build_package(self) -> types.ModuleType:  # noqa: C901 - the whole fake surface in one place
        fake = self

        pkg = types.ModuleType("kubernetes")
        pkg.__path__ = []  # mark as package
        pkg.__fake__ = True
        client = types.ModuleType("kubernetes.client")
        client.__path__ = []
        rest = types.ModuleType("kubernetes.client.rest")
        exceptions = types.ModuleType("kubernetes.client.exceptions")
        config = types.ModuleType("kubernetes.config")
        rest.ApiException = ApiException
        exceptions.ApiException = ApiException
        client.ApiException = ApiException
        client.rest = rest
        client.exceptions = exceptions

        class Configuration:
            def __init__(self, host: str = "http://localhost") -> None:
                self.host = host
                self.verify_ssl = True
                self.ssl_ca_cert = None
                self.api_key: Dict[str, str] = {}
                self.api_key_prefix: Dict[str, str] = {}

        class ApiClient:
            def __init__(self, configuration: Optional[Configuration] = None, *args: Any, **kwargs: Any) -> None:
                self.configuration = configuration or Configuration()
                self.default_headers: Dict[str, str] = {}
                cfg = self.configuration
                ca = getattr(cfg, "ssl_ca_cert", None)
                with fake._lock:
                    fake.api_clients.append({
                        "host": cfg.host,
                        "verify_ssl": cfg.verify_ssl,
                        "ca_file_existed": bool(ca and os.path.isfile(ca)),
                        "auth_scheme": (cfg.api_key.get("authorization", "").split(" ", 1)[0]
                                        if cfg.api_key else None),
                        "token_prefix": (cfg.api_key.get("authorization", "").split(" ", 1)[-1][:11]
                                         if cfg.api_key else None),
                    })

            def call_api(self, resource_path: str, method: str, path_params: Optional[Mapping] = None,
                         query_params: Any = None, header_params: Optional[Mapping] = None, body: Any = None,
                         **kwargs: Any) -> Any:
                return fake.call_api(self, resource_path, method, path_params, query_params, header_params, body,
                                     **kwargs)

            def set_default_header(self, name: str, value: str) -> None:
                self.default_headers[name] = value

            def sanitize_for_serialization(self, obj: Any) -> Any:
                if isinstance(obj, Model):
                    return to_camel(obj.to_dict())
                if isinstance(obj, dict):
                    return to_camel(obj)
                return obj

            def deserialize(self, response: Any, response_type: Any = None) -> Any:
                raw = json.loads(getattr(response, "data", b"{}") or b"{}")
                snake = to_snake(raw)
                if isinstance(snake, dict) and "items" in snake:
                    return _ListResult(snake["items"], (snake.get("metadata") or {}).get("_continue"))
                return Model(snake)

            def close(self) -> None:
                pass

            def __enter__(self) -> "ApiClient":
                return self

            def __exit__(self, *exc: Any) -> None:
                self.close()

        def _method(api_name: str, method: str, resource: str, attr: str, namespaced: bool = False):
            if namespaced:
                def fn(self, namespace: str, **kwargs: Any) -> Any:
                    return fake._serve(api_name, method, resource, attr, self.api_client, kwargs, namespace)
            else:
                def fn(self, **kwargs: Any) -> Any:
                    return fake._serve(api_name, method, resource, attr, self.api_client, kwargs)
            fn.__name__ = method
            return fn

        def _api_class(api_name: str, methods: List[Tuple[str, str, str, bool]]) -> type:
            def __init__(self, api_client: Optional[ApiClient] = None) -> None:
                self.api_client = api_client or ApiClient()
            ns: Dict[str, Any] = {"__init__": __init__}
            for method, resource, attr, namespaced in methods:
                ns[method] = _method(api_name, method, resource, attr, namespaced)
            return type(api_name, (), ns)

        CoreV1Api = _api_class("CoreV1Api", [
            ("list_namespace", "namespaces", "namespaces", False),
            ("list_pod_for_all_namespaces", "pods", "pods", False),
            ("list_namespaced_pod", "pods", "pods", True),
            ("list_service_account_for_all_namespaces", "service_accounts", "service_accounts", False),
            ("list_namespaced_service_account", "service_accounts", "service_accounts", True),
            ("list_secret_for_all_namespaces", "secrets", "secrets", False),
            ("list_namespaced_secret", "secrets", "secrets", True),
            ("list_service_for_all_namespaces", "services", "services", False),
            ("list_namespaced_service", "services", "services", True),
            ("list_node", "nodes", "nodes", False),
            ("list_config_map_for_all_namespaces", "config_maps", "config_maps", False),
            ("list_namespaced_config_map", "config_maps", "config_maps", True),
        ])

        def read_namespaced_config_map(self, name: str, namespace: str, **kwargs: Any) -> Model:
            result = fake._serve("CoreV1Api", "read_namespaced_config_map", "config_maps", "config_maps",
                                 self.api_client, dict(kwargs, name=name), namespace)
            for item in result.items:
                if item.metadata.name == name:
                    return item
            raise ApiException(status=404, reason="Not Found")

        CoreV1Api.read_namespaced_config_map = read_namespaced_config_map

        RbacAuthorizationV1Api = _api_class("RbacAuthorizationV1Api", [
            ("list_role_for_all_namespaces", "roles", "roles", False),
            ("list_namespaced_role", "roles", "roles", True),
            ("list_cluster_role", "cluster_roles", "cluster_roles", False),
            ("list_role_binding_for_all_namespaces", "role_bindings", "role_bindings", False),
            ("list_namespaced_role_binding", "role_bindings", "role_bindings", True),
            ("list_cluster_role_binding", "cluster_role_bindings", "cluster_role_bindings", False),
        ])
        NetworkingV1Api = _api_class("NetworkingV1Api", [
            ("list_ingress_for_all_namespaces", "ingresses", "ingresses", False),
            ("list_namespaced_ingress", "ingresses", "ingresses", True),
        ])

        class AuthorizationV1Api:
            def __init__(self, api_client: Optional[ApiClient] = None) -> None:
                self.api_client = api_client or ApiClient()

            def create_self_subject_rules_review(self, body: Any, **kwargs: Any) -> Any:
                spec = body.get("spec") if isinstance(body, Mapping) else getattr(body, "spec", None)
                ns = spec.get("namespace") if isinstance(spec, Mapping) else getattr(spec, "namespace", None)
                record = dict(kwargs, namespace=ns)
                label, cluster = fake._check(self.api_client, "AuthorizationV1Api",
                                             "create_self_subject_rules_review", "selfsubjectrulesreviews", record)
                fake._record(label, "AuthorizationV1Api", "create_self_subject_rules_review",
                             "selfsubjectrulesreviews", record, "ok")
                review = fake._rules_review(cluster, ns or "default")
                if kwargs.get("_preload_content") is False:
                    return FakeHTTPResponse(201, to_camel(review))
                return Model(review)

        def _model(name: str) -> type:
            def __init__(self, **kwargs: Any) -> None:
                for k, v in kwargs.items():
                    setattr(self, k, v)

            def to_dict(self) -> Dict[str, Any]:
                return {k: (v.to_dict() if hasattr(v, "to_dict") else v) for k, v in vars(self).items()}

            return type(name, (), {"__init__": __init__, "to_dict": to_dict})

        class VersionApi:
            def __init__(self, api_client: Optional[ApiClient] = None) -> None:
                self.api_client = api_client or ApiClient()

            def get_code(self, **kwargs: Any) -> Model:
                label, cluster = fake._check(self.api_client, "VersionApi", "get_code", "version", kwargs)
                fake._record(label, "VersionApi", "get_code", "version", kwargs, "ok")
                return Model(cluster.version)

        ConfigException = type("ConfigException", (Exception,), {})

        def load_kube_config(config_file: Optional[str] = None, context: Optional[str] = None,
                             client_configuration: Any = None, persist_config: bool = True,
                             temp_file_path: Optional[str] = None) -> None:
            """Fills ``client_configuration`` from a kubeconfig (server, token, CA path), like the real one."""
            loaded = _load_kubeconfig(config_file or os.environ.get("KUBECONFIG") or "~/.kube/config")
            if loaded is None:
                raise ConfigException("Invalid kube-config file. No configuration found.")
            contexts, clusters, users, current = loaded
            name = context or current
            if name not in contexts:
                raise ConfigException(f"Expected key {name} in kube-config")
            ctx = contexts[name]
            cluster, user = clusters.get(ctx.get("cluster"), {}), users.get(ctx.get("user"), {})
            cfg = client_configuration if client_configuration is not None else Configuration()
            cfg.host = cluster.get("server")
            cfg.ssl_ca_cert = cluster.get("certificate-authority")
            if user.get("token"):
                cfg.api_key = {"authorization": f"Bearer {user['token']}"}
            with fake._lock:
                fake.kubeconfig_loads.append({"context": name, "host": cfg.host})

        def load_incluster_config(client_configuration: Any = None, try_refresh_token: bool = True) -> None:
            """Uses :attr:`FakeKubernetes.in_cluster` (``{"host", "token"}``); raises when it is not set."""
            if fake.in_cluster is None:
                raise ConfigException("Service host/port is not set.")
            cfg = client_configuration if client_configuration is not None else Configuration()
            cfg.host = fake.in_cluster["host"]
            cfg.api_key = {"authorization": f"Bearer {fake.in_cluster['token']}"}

        config.load_kube_config = load_kube_config
        config.load_incluster_config = load_incluster_config
        config.ConfigException = ConfigException

        client.Configuration = Configuration
        client.ApiClient = ApiClient
        client.CoreV1Api = CoreV1Api
        client.RbacAuthorizationV1Api = RbacAuthorizationV1Api
        client.NetworkingV1Api = NetworkingV1Api
        client.AuthorizationV1Api = AuthorizationV1Api
        client.VersionApi = VersionApi
        client.V1SelfSubjectRulesReview = _model("V1SelfSubjectRulesReview")
        client.V1SelfSubjectRulesReviewSpec = _model("V1SelfSubjectRulesReviewSpec")
        client.V1ObjectMeta = _model("V1ObjectMeta")
        pkg.client = client
        pkg.config = config
        pkg.__version__ = "0.0.0-fake"
        return pkg
