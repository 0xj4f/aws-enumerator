"""Shared helpers of the Kubernetes analyzers (E-k8s): accessors, node ids, the per-cluster view.

Both object layouts are read through these accessors: the d13c215 collector's full ``to_dict()`` objects and
the C-K8s projections (snake_case keys, annotation values ``null`` unless allow-listed, env entries
``{name, value_from, value_present}``). Nothing here ever reads an env ``value``, a Secret's data or an
annotation value outside :data:`ANNOTATION_VALUES` (F-009, F-054): those never reach ``graph.json``.

**Ids** (node-ids.md §2, F-025): every Kubernetes id is ``k8s://<cluster ARN>/<Kind>/<namespace|_>/<name>``.
Pods are aggregated by their controlling owner (``Pod/<ns>/Deployment:web``; a ReplicaSet created by a
Deployment is folded into the Deployment through the ``pod-template-hash`` label), a pod without an owner keeps
its own name. A Role a RoleBinding grants from a ClusterRole is the namespaced instance
``Role/<ns>/ClusterRole:<name>`` (the ClusterRole's rules, valid in that namespace only), so a namespaced grant
never reads as cluster-wide. An object whose name cannot form an id is counted, never guessed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Set, Tuple

from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.io.loaders.k8s import ClusterData, K8sData, model_of

log = logging.getLogger("aws_enumerator.engine.analyzers.k8s")

#: The legacy output every Kubernetes analyzer feeds (graph-json.md §1; rendered from the graph).
LEGACY_FILE = "k8s_relationships.json"
#: ``ctx.shared`` key of the per-cluster views (built once by the base analyzer).
VIEWS_KEY = "k8s.views"
#: Annotation values the analyzers may read (the C-K8s allow-list); every other value is ignored.
ANNOTATION_VALUES = frozenset({
    "eks.amazonaws.com/role-arn", "eks.amazonaws.com/audience",
    "service.beta.kubernetes.io/aws-load-balancer-scheme", "service.beta.kubernetes.io/aws-load-balancer-internal",
    "service.beta.kubernetes.io/aws-load-balancer-type", "alb.ingress.kubernetes.io/scheme",
    "kubernetes.io/ingress.class",
})
IRSA_ANNOTATION = "eks.amazonaws.com/role-arn"
AUDIENCE_ANNOTATION = "eks.amazonaws.com/audience"
DEFAULT_AUDIENCE = "sts.amazonaws.com"
POD_IDENTITY_AUDIENCE = "pods.eks.amazonaws.com"
#: Most pod names listed on a workload node or in finding evidence.
MAX_LISTED = 20


# ── accessors ────────────────────────────────────────────────────────────────

def mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def seq(value: Any) -> List[Any]:
    return list(value) if isinstance(value, list) else []


def text(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def meta(obj: Mapping[str, Any]) -> Mapping[str, Any]:
    return mapping(obj.get("metadata"))


def name_of(obj: Mapping[str, Any]) -> Optional[str]:
    """``metadata.name`` (or a top-level ``name``, the Secret metadata shape)."""
    return text(meta(obj).get("name")) or text(obj.get("name"))


def namespace_of(obj: Mapping[str, Any], default: Optional[str] = "default") -> Optional[str]:
    return text(meta(obj).get("namespace")) or text(obj.get("namespace")) or default


def labels_of(obj: Mapping[str, Any]) -> Dict[str, str]:
    raw = mapping(meta(obj).get("labels"))
    return {str(k): str(v) for k, v in raw.items() if isinstance(v, (str, int, float, bool))}


def annotation_keys(obj: Mapping[str, Any]) -> Tuple[str, ...]:
    return tuple(sorted(str(k) for k in mapping(meta(obj).get("annotations"))))


def annotation(obj: Mapping[str, Any], key: str) -> Optional[str]:
    """An allow-listed annotation value (:data:`ANNOTATION_VALUES`); any other key gives ``None``."""
    if key not in ANNOTATION_VALUES:
        raise KeyError(f"annotation {key!r} is not readable by the analyzers")
    return text(mapping(meta(obj).get("annotations")).get(key))


def spec_of(obj: Mapping[str, Any]) -> Mapping[str, Any]:
    return mapping(obj.get("spec"))


def flag(value: Any) -> Optional[bool]:
    """``True`` / ``False`` for a boolean field, ``None`` when unset (Kubernetes defaults apply)."""
    return value if isinstance(value, bool) else None


def capped(values: Iterable[str]) -> List[str]:
    """Sorted, de-duplicated and at most :data:`MAX_LISTED` long (evidence and props stay small)."""
    return sorted(set(values))[:MAX_LISTED]


# ── ids ──────────────────────────────────────────────────────────────────────

def k8s_id(cluster_arn: str, kind: str, namespace: Optional[str], name: Optional[str], *,
           k8s_kind: Optional[str] = None) -> Optional[str]:
    """A Kubernetes node id, or ``None`` when the parts cannot form one (hostile or missing names)."""
    if not name:
        return None
    try:
        return ids.node_id_for(kind, cluster_arn=cluster_arn, namespace=namespace or ids.K8S_CLUSTER_SCOPE,
                               name=name, **({"k8s_kind": k8s_kind} if k8s_kind else {}))
    except ValueError:
        return None


def role_id(cluster_arn: str, kind: str, name: Optional[str], namespace: Optional[str] = None) -> Optional[str]:
    """``Role/<ns>/<name>`` or ``ClusterRole/_/<name>``."""
    return k8s_id(cluster_arn, "k8srole", namespace if kind == "Role" else None, name, k8s_kind=kind)


def bound_cluster_role_id(cluster_arn: str, name: Optional[str], namespace: str) -> Optional[str]:
    """The namespaced instance of a ClusterRole granted by a RoleBinding in ``namespace`` (module docstring)."""
    return k8s_id(cluster_arn, "k8srole", namespace, f"ClusterRole:{name}" if name else None, k8s_kind="Role")


# ── workloads (pods aggregated by owner) ─────────────────────────────────────

def _controller(obj: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    refs = [r for r in seq(meta(obj).get("owner_references")) if isinstance(r, Mapping) and text(r.get("kind"))
            and text(r.get("name"))]
    for ref in refs:
        if ref.get("controller") is True:
            return ref
    return refs[0] if refs else None


def owner_of(pod: Mapping[str, Any]) -> Optional[Tuple[str, str]]:
    """``(kind, name)`` of the workload that owns ``pod``; a Deployment's ReplicaSet is folded into it."""
    ref = _controller(pod)
    if ref is None:
        return None
    kind, name = str(ref["kind"]), str(ref["name"])
    if kind == "Node":           # static (mirror) pods: one per node, keep the pod itself
        return None
    if kind == "ReplicaSet":
        h = labels_of(pod).get("pod-template-hash")
        if h and name.endswith("-" + h) and len(name) > len(h) + 1:
            return "Deployment", name[: -(len(h) + 1)]
    return kind, name


@dataclass
class Workload:
    """One pod node: every pod of one owner (or one pod without an owner) in one namespace."""

    node_id: str
    namespace: str
    name: str
    owner: Optional[Tuple[str, str]]
    pods: List[Mapping[str, Any]] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.namespace}/{self.owner[1] if self.owner else self.name}"

    def pod_names(self) -> List[str]:
        return capped(n for n in (name_of(p) for p in self.pods) if n)


def workloads(cluster_arn: str, pods: Sequence[Mapping[str, Any]]) -> Tuple[List[Workload], int]:
    """Pods grouped into :class:`Workload` nodes, plus the number of pods no id could be formed for."""
    by_id: Dict[str, Workload] = {}
    skipped = 0
    for pod in pods:
        ns, pname = namespace_of(pod), name_of(pod)
        owner = owner_of(pod)
        agg = f"{owner[0]}:{owner[1]}" if owner else pname
        node_id = k8s_id(cluster_arn, "pod", ns, agg) if ns and agg else None
        if node_id is None and owner is not None:          # an owner name that cannot form an id: the pod alone
            owner, agg = None, pname
            node_id = k8s_id(cluster_arn, "pod", ns, pname) if ns and pname else None
        if node_id is None or ns is None or agg is None:
            skipped += 1
            continue
        wl = by_id.setdefault(node_id, Workload(node_id, ns, agg, owner))
        wl.pods.append(pod)
    return [by_id[k] for k in sorted(by_id)], skipped


# ── containers, tokens, secrets ──────────────────────────────────────────────

CONTAINER_KINDS: Tuple[str, ...] = ("containers", "init_containers", "ephemeral_containers")


def containers(pod: Mapping[str, Any]) -> Iterator[Tuple[str, Mapping[str, Any]]]:
    """``(kind, container)`` over regular, init and ephemeral containers (F-035)."""
    spec = spec_of(pod)
    for kind in CONTAINER_KINDS:
        for c in seq(spec.get(kind)):
            if isinstance(c, Mapping):
                yield kind, c


def service_account_of(pod: Mapping[str, Any]) -> str:
    spec = spec_of(pod)
    return text(spec.get("service_account_name")) or text(spec.get("service_account")) or "default"


def projected_token_audiences(pod: Mapping[str, Any]) -> Set[str]:
    """Audiences of the projected service-account token volumes (``""`` = the API server's own audience)."""
    out: Set[str] = set()
    for vol in seq(spec_of(pod).get("volumes")):
        for src in seq(mapping(mapping(vol).get("projected")).get("sources")):
            token = mapping(src).get("service_account_token")
            if isinstance(token, Mapping):
                out.add(text(token.get("audience")) or "")
    return out


def api_token_mounted(pod: Mapping[str, Any], sa_record: Optional[Mapping[str, Any]]) -> bool:
    """Is the service-account API token automounted? Pod setting first, then the SA's, default yes."""
    pod_flag = flag(spec_of(pod).get("automount_service_account_token"))
    if pod_flag is not None:
        return pod_flag
    sa_flag = flag(sa_record.get("automount_service_account_token")) if sa_record else None
    return sa_flag is not False


def secret_references(pod: Mapping[str, Any]) -> Dict[str, Set[str]]:
    """Secret name → how the pod reads it (``volume``, ``projected``, ``env``, ``env_from``), all containers."""
    out: Dict[str, Set[str]] = {}

    def add(name: Any, how: str) -> None:
        if text(name):
            out.setdefault(str(name), set()).add(how)

    for vol in seq(spec_of(pod).get("volumes")):
        v = mapping(vol)
        add(mapping(v.get("secret")).get("secret_name"), "volume")
        for src in seq(mapping(v.get("projected")).get("sources")):
            add(mapping(mapping(src).get("secret")).get("name"), "projected")
    for _kind, c in containers(pod):
        for env in seq(c.get("env")):
            add(mapping(mapping(mapping(env).get("value_from")).get("secret_key_ref")).get("name"), "env")
        for env_from in seq(c.get("env_from")):
            add(mapping(mapping(env_from).get("secret_ref")).get("name"), "env_from")
    return out


# ── the per-cluster view ─────────────────────────────────────────────────────

@dataclass
class ClusterView:
    """One cluster's data plus the ids every Kubernetes analyzer agrees on."""

    data: ClusterData
    account: str
    partition: str
    workloads: List[Workload] = field(default_factory=list)
    service_accounts: Dict[Tuple[str, str], Mapping[str, Any]] = field(default_factory=dict)
    sa_keys: Set[Tuple[str, str]] = field(default_factory=set)
    unrepresentable: int = 0

    @property
    def arn(self) -> str:
        return self.data.arn

    @property
    def region(self) -> str:
        return self.data.region

    def sa_id(self, namespace: Optional[str], name: Optional[str]) -> Optional[str]:
        return k8s_id(self.arn, "sa", namespace, name)

    def namespaces(self) -> List[str]:
        """Every namespace the data names (namespace list, objects, SAs)."""
        found = {n for n in (name_of(o) for o in self.data.items("namespaces")) if n}
        found |= {ns for ns, _ in self.sa_keys}
        found |= {w.namespace for w in self.workloads}
        return sorted(found)

    def sa_ids_in(self, namespace: Optional[str]) -> List[str]:
        """Service-account node ids in ``namespace`` (every namespace when ``None``)."""
        out = [self.sa_id(ns, n) for ns, n in sorted(self.sa_keys) if namespace is None or ns == namespace]
        return [i for i in out if i]


def _subject_sas(data: ClusterData) -> Iterator[Tuple[str, str]]:
    for kind in ("role_bindings", "cluster_role_bindings"):
        for b in data.items(kind):
            default_ns = namespace_of(b) if kind == "role_bindings" else None
            for s in seq(b.get("subjects")):
                s = mapping(s)
                if s.get("kind") == "ServiceAccount" and text(s.get("name")):
                    ns = text(s.get("namespace")) or default_ns
                    if ns:
                        yield ns, str(s["name"])


def build_view(data: ClusterData, *, account: str, partition: str) -> ClusterView:
    """The cluster's workloads and its service-account universe (collected, referenced by pods, bindings and
    Pod Identity associations), so every analyzer creates and targets the same nodes."""
    view = ClusterView(data, account, partition)
    view.workloads, view.unrepresentable = workloads(data.arn, data.items("pods"))
    for sa in data.items("service_accounts"):
        ns, n = namespace_of(sa), name_of(sa)
        if ns and n:
            view.service_accounts[(ns, n)] = sa
    keys: Set[Tuple[str, str]] = set(view.service_accounts)
    keys |= {(w.namespace, service_account_of(p)) for w in view.workloads for p in w.pods}
    keys |= set(_subject_sas(data))
    for assoc in data.eks_items("pod_identity_associations"):
        ns, n = text(assoc.get("namespace")), text(assoc.get("serviceAccount"))
        if ns and n:
            keys.add((ns, n))
    view.sa_keys = {k for k in keys if view.sa_id(*k)}
    view.unrepresentable += len(keys) - len(view.sa_keys)
    return view


def cluster_views(ctx: Any) -> List[ClusterView]:
    """The views of every analysed cluster, built once per analysis and shared through ``ctx.shared``."""
    cached = ctx.shared.get(VIEWS_KEY)
    if cached is not None:
        return cached
    model = loader_model(ctx)
    views = [build_view(c, account=ctx.account_id, partition=ctx.partition) for c in model.clusters]
    ctx.shared[VIEWS_KEY] = views
    return views


def loader_model(ctx: Any) -> K8sData:
    """The k8s loader's model, or :class:`AnalyzerSkipped` when the loader produced none."""
    from aws_enumerator.engine.model import AnalyzerSkipped

    model = model_of((ctx.data or {}).get("k8s"))
    if model is None:
        raise AnalyzerSkipped("eks", "k8s", reason="the k8s loader produced no data")
    return model


def view_by_arn(ctx: Any) -> Dict[str, ClusterView]:
    return {v.arn: v for v in cluster_views(ctx)}


__all__ = [
    "ANNOTATION_VALUES", "AUDIENCE_ANNOTATION", "CONTAINER_KINDS", "ClusterView", "DEFAULT_AUDIENCE",
    "IRSA_ANNOTATION", "LEGACY_FILE", "MAX_LISTED", "POD_IDENTITY_AUDIENCE", "VIEWS_KEY", "Workload",
    "annotation", "annotation_keys", "api_token_mounted", "bound_cluster_role_id", "build_view", "capped",
    "cluster_views", "containers", "flag", "k8s_id", "labels_of", "loader_model", "mapping", "meta", "name_of",
    "namespace_of", "owner_of", "projected_token_audiences", "role_id", "secret_references", "seq",
    "service_account_of", "spec_of", "text", "view_by_arn", "workloads",
]
