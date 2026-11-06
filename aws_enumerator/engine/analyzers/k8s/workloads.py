"""Kubernetes workloads (E-k8s): service accounts, pods aggregated by owner, and what a pod gives an attacker.

Edges (traversability-table.md §5.17-§5.18):

* ``IN_CLUSTER`` pod → cluster: structural placement, never a path step (F-007).
* ``RUNS_AS`` pod → sa: the pod holds a token of the service account. Definite when the API token is
  automounted (pod setting, else the SA's, default on); **conditional, strong** when only a web-identity token
  is projected (IRSA ``sts.amazonaws.com`` or Pod Identity ``pods.eks.amazonaws.com`` audience): the pod then
  reaches the service account's AWS role but not its Kubernetes API rights, which the table cannot say, so the
  edge carries ``evidence.api_token_mounted = false`` and a higher weight. No token at all: no edge.
* ``MOUNTS_SECRET`` pod → k8ssecret: Secret volumes, projected Secret sources, ``env[].valueFrom.secretKeyRef``
  and ``envFrom[].secretRef`` of every container kind (F-035). Secret nodes come only from these references;
  the opt-in ``secrets.json`` listing is never needed (F-150) and adds only the type.
* ``CAN_REACH_NODE_IMDS`` pod → nodegroup (F-033): the pod's node (``nodes.json``; for old reports the EC2
  instance whose private DNS name is the node name) belongs to a managed node group; weight extra 0 when
  IMDSv1 is allowed or the pod uses the host network, 1 for IMDSv2 with a hop limit of 2 or more, 2 (and
  conditional) when the instance's metadata options are unknown. IMDS disabled, IMDSv2 with hop limit 1
  (unless host network) and Fargate pods: no edge. With ``NODE_ROLE`` this is the documented
  pod → node role path.

Findings are emitted **once per workload** (pods aggregated by owner, F-086): K8S-PRIV-001 (privileged
container of any kind), K8S-HOSTNET-001, K8S-HOSTPID-001, K8S-HOSTIPC-001, K8S-HOSTPATH-001, K8S-CAP-001,
K8S-ESCALATION-001 and K8S-DEFAULT-SA (only when the default service account's API token is mounted; MEDIUM
when that account holds RBAC bindings or an IRSA role, LOW otherwise).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from aws_enumerator.engine.analyzers.k8s.cluster import nodegroup_ids
from aws_enumerator.engine.analyzers.k8s.util import (
    DEFAULT_AUDIENCE, IRSA_ANNOTATION, POD_IDENTITY_AUDIENCE, ClusterView, Workload, annotation,
    api_token_mounted, capped, cluster_views, containers, flag, k8s_id, mapping, name_of, namespace_of,
    projected_token_audiences, secret_references, seq, service_account_of, spec_of, text,
)
from aws_enumerator.engine.io.loaders.k8s import InstanceFacts, K8sData

#: Capabilities that break container isolation when added (F-035).
DANGEROUS_CAPABILITIES = frozenset({"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "SYS_BOOT",
                                    "NET_ADMIN", "DAC_READ_SEARCH", "BPF", "PERFMON"})
#: Host paths that give the node (or the container runtime) to whoever mounts them.
SENSITIVE_HOST_PATHS: Tuple[str, ...] = (
    "/", "/etc", "/root", "/home", "/var/lib/kubelet", "/var/lib/docker", "/var/lib/containerd", "/proc", "/sys",
    "/dev", "/var/run/docker.sock", "/run/docker.sock", "/var/run/containerd", "/run/containerd",
    "/var/run/crio", "/run/crio", "/var/log",
)
#: Projected-token audiences that carry an AWS web identity.
WEB_IDENTITY_AUDIENCES = frozenset({DEFAULT_AUDIENCE, POD_IDENTITY_AUDIENCE})


# ── service accounts ─────────────────────────────────────────────────────────

def add_service_accounts(builder: Any, view: ClusterView) -> int:
    """One node per service account of the view's universe (collected or referenced)."""
    known = view.data.known("service_accounts")
    listed = view.data.object_status.get("service_accounts")
    for ns, name in sorted(view.sa_keys):
        node_id = view.sa_id(ns, name)
        if node_id is None:
            continue
        rec = view.service_accounts.get((ns, name))
        props: Dict[str, Any] = {"namespace": ns, "name": name}
        if rec is not None:
            props["automount_token"] = flag(rec.get("automount_service_account_token"))
            props["irsa_role_arn"] = annotation(rec, IRSA_ANNOTATION)
        elif known and listed == "complete":
            props["placeholder"] = True            # referenced, but not in a complete listing
        builder.add_node(node_id, "sa", f"{ns}/{name}", region=view.region,
                         props={k: v for k, v in props.items() if v is not None},
                         coverage_status=None if rec is not None or listed == "complete" else (
                             listed if listed in ("partial", "denied", "error") else "not-collected"))
    return len(view.sa_keys)


# ── pod → node → node group (IMDS) ───────────────────────────────────────────

@dataclass(frozen=True)
class NodeHop:
    """Where a pod's node leads: a node group, how it was found and the node's IMDS settings."""

    nodegroup_id: str
    mapping: str                              # "nodes.json" | "ec2-private-dns" | "single-nodegroup-inferred"
    instance: Optional[InstanceFacts]
    node_name: str


class NodeMap:
    """Resolves pod node names to node groups for one cluster."""

    def __init__(self, view: ClusterView, model: K8sData):
        self.view, self.model = view, model
        self.groups = nodegroup_ids(view)
        self.nodes = {n: rec for rec in view.data.items("nodes") for n in [name_of(rec)] if n}
        fargate = view.data.eks.get("fargate_profiles")
        only = list(self.groups) if len(self.groups) == 1 else []
        self.inferred = only[0] if only and fargate is not None and not fargate and \
            view.data.eks_status.get("nodegroups") == "complete" else None

    def _group_id(self, name: Optional[str]) -> Optional[str]:
        if not name or "/" in name:
            return None
        if name in self.groups:
            return self.groups[name][0]
        return self.view.arn.replace(":cluster/", ":nodegroup/", 1) + f"/{name}"

    def resolve(self, node_name: Optional[str]) -> Optional[NodeHop]:
        """The node group a pod on ``node_name`` runs in, or ``None`` (Fargate, unknown, self-managed)."""
        if not node_name or node_name.startswith("fargate-"):
            return None
        rec = self.nodes.get(node_name)
        if rec is not None:
            if str(rec.get("compute_type") or "").lower() == "fargate":
                return None
            inst = self.model.instances.get(str(rec.get("instance_id") or ""))
            gid = self._group_id(text(rec.get("nodegroup")) or (inst.nodegroup if inst else None))
            return NodeHop(gid, "nodes.json", inst, node_name) if gid else None
        iid = self.model.instances_by_dns.get((self.view.region, node_name.lower()))
        inst = self.model.instances.get(iid) if iid else None
        if inst is not None and inst.nodegroup and inst.cluster in (None, self.view.data.name):
            gid = self._group_id(inst.nodegroup)
            return NodeHop(gid, "ec2-private-dns", inst, node_name) if gid else None
        if self.inferred is not None:
            return NodeHop(self.groups[self.inferred][0], "single-nodegroup-inferred", inst, node_name)
        return None


def imds_reach(hop: NodeHop, host_network: bool) -> Optional[Tuple[int, bool, Dict[str, Any]]]:
    """``(weight_extra, definite, imds evidence)`` or ``None`` when the pod cannot reach the node's IMDS."""
    meta = hop.instance.metadata if hop.instance is not None else None
    if meta is None:
        return (0 if host_network else 2), False, {"imds": "unknown"}
    endpoint = str(meta.get("HttpEndpoint") or "enabled").lower()
    tokens = str(meta.get("HttpTokens") or "optional").lower()
    hop_limit = meta.get("HttpPutResponseHopLimit")
    hop_limit = hop_limit if isinstance(hop_limit, int) else None
    ev = {"imds": {"http_endpoint": endpoint, "http_tokens": tokens, "hop_limit": hop_limit}}
    if endpoint == "disabled":
        return None
    if host_network or tokens != "required":
        return 0, True, ev
    if hop_limit is None:
        return 2, False, ev
    return (1, True, ev) if hop_limit >= 2 else None


# ── per-workload facts ───────────────────────────────────────────────────────

@dataclass
class Facts:
    """What the pods of one workload do (union over its pods)."""

    privileged: Set[str] = field(default_factory=set)
    escalation: Set[str] = field(default_factory=set)
    capabilities: Dict[str, Set[str]] = field(default_factory=dict)
    host_paths: Set[str] = field(default_factory=set)
    host_network: bool = False
    host_pid: bool = False
    host_ipc: bool = False
    default_sa_token: bool = False


def _cap(value: Any) -> Optional[str]:
    cap = text(value)
    if cap is None:
        return None
    cap = cap.upper()
    return cap[4:] if cap.startswith("CAP_") else cap


def pod_facts(pod: Mapping[str, Any], facts: Facts) -> None:
    spec = spec_of(pod)
    facts.host_network |= spec.get("host_network") is True
    facts.host_pid |= spec.get("host_pid") is True
    facts.host_ipc |= spec.get("host_ipc") is True
    for vol in seq(spec.get("volumes")):
        path = text(mapping(mapping(vol).get("host_path")).get("path"))
        if path:
            facts.host_paths.add(path)
    for kind, c in containers(pod):
        label = f"{kind[:-1].replace('_', ' ')} {text(c.get('name')) or '?'}"
        sc = mapping(c.get("security_context"))
        if sc.get("privileged") is True:
            facts.privileged.add(label)
        elif sc.get("allow_privilege_escalation") is True:
            facts.escalation.add(label)
        added = {_cap(x) for x in seq(mapping(sc.get("capabilities")).get("add"))}
        for cap in sorted(c for c in added if c in DANGEROUS_CAPABILITIES):
            facts.capabilities.setdefault(cap, set()).add(label)


def sensitive_path(path: str) -> bool:
    clean = path.rstrip("/") or "/"
    return any(clean == p or (p != "/" and clean.startswith(p + "/")) for p in SENSITIVE_HOST_PATHS)


# ── edges ────────────────────────────────────────────────────────────────────

def token_sources(pod: Mapping[str, Any], sa: Optional[Mapping[str, Any]]) -> List[str]:
    sources = ["kube-api"] if api_token_mounted(pod, sa) else []
    audiences = projected_token_audiences(pod)
    sources += [f"projected:{a}" for a in sorted(audiences) if a in WEB_IDENTITY_AUDIENCES]
    if "" in audiences and "kube-api" not in sources:
        sources.append("kube-api")
    return sources


def _runs_as(builder: Any, view: ClusterView, wl: Workload, pod: Mapping[str, Any]) -> Optional[str]:
    sa_name = service_account_of(pod)
    sa_id = view.sa_id(wl.namespace, sa_name)
    if sa_id is None:
        return None
    sources = token_sources(pod, view.service_accounts.get((wl.namespace, sa_name)))
    if not sources:
        return None
    api = "kube-api" in sources
    builder.add_edge(wl.node_id, "RUNS_AS", sa_id, confidence=None if api else "conditional",
                     strength=None if api else "strong",
                     evidence={"token_sources": sources, "api_token_mounted": api,
                               "technique": "service-account-token"})
    return sa_name if api else None


def _mounts(builder: Any, view: ClusterView, wl: Workload, pod: Mapping[str, Any],
            types: Mapping[Tuple[str, str], str]) -> None:
    for secret, how in sorted(secret_references(pod).items()):
        sid = k8s_id(view.arn, "k8ssecret", wl.namespace, secret)
        if sid is None:
            view.unrepresentable += 1
            continue
        stype = types.get((wl.namespace, secret))
        builder.add_node(sid, "k8ssecret", f"{wl.namespace}/{secret}", region=view.region,
                         props={k: v for k, v in {"namespace": wl.namespace, "name": secret,
                                                  "secret_type": stype}.items() if v})
        builder.add_edge(wl.node_id, "MOUNTS_SECRET", sid, evidence={"via": sorted(how)})


def _imds(builder: Any, wl: Workload, pod: Mapping[str, Any], nodes: NodeMap) -> None:
    hop = nodes.resolve(text(spec_of(pod).get("node_name")))
    if hop is None:
        return
    reach = imds_reach(hop, spec_of(pod).get("host_network") is True)
    if reach is None:
        return
    extra, definite, ev = reach
    definite = definite and hop.mapping != "single-nodegroup-inferred"
    if not builder.has_node(hop.nodegroup_id):
        builder.add_node(hop.nodegroup_id, "nodegroup", hop.nodegroup_id.rsplit("/", 1)[-1],
                         region=nodes.view.region, props={"placeholder": True, "cluster": nodes.view.data.name},
                         coverage_status="not-collected")
    gaps = ["k8s:node-nodegroup-inferred"] if hop.mapping == "single-nodegroup-inferred" else []
    builder.add_edge(wl.node_id, "CAN_REACH_NODE_IMDS", hop.nodegroup_id, weight_extra=extra,
                     confidence=None if definite else "conditional", strength=None,
                     evidence=dict(ev, mapping=hop.mapping, node_names=[hop.node_name],
                                   host_network=spec_of(pod).get("host_network") is True,
                                   technique="pod-to-node-imds", **({"gaps": gaps} if gaps else {})))


def _secret_types(view: ClusterView) -> Dict[Tuple[str, str], str]:
    out = {}
    for s in view.data.items("secrets"):
        ns, n, t = namespace_of(s), name_of(s), text(s.get("type"))
        if ns and n and t:
            out[(ns, n)] = t
    return out


def add_workload(builder: Any, view: ClusterView, wl: Workload, nodes: NodeMap,
                 types: Mapping[Tuple[str, str], str]) -> Facts:
    """The workload node, its edges, and the union of its pods' facts."""
    sas = sorted({service_account_of(p) for p in wl.pods})
    props = {"namespace": wl.namespace, "pod_count": len(wl.pods), "pods": wl.pod_names(),
             "service_accounts": sas, "owner_kind": wl.owner[0] if wl.owner else None,
             "owner_name": wl.owner[1] if wl.owner else None,
             "nodes": capped(n for n in (text(spec_of(p).get("node_name")) for p in wl.pods) if n) or None}
    builder.add_node(wl.node_id, "pod", wl.label, region=view.region,
                     props={k: v for k, v in props.items() if v is not None})
    builder.add_edge(wl.node_id, "IN_CLUSTER", view.arn, evidence={"technique": "placement"})
    facts = Facts()
    for pod in sorted(wl.pods, key=lambda p: name_of(p) or ""):
        mounted = _runs_as(builder, view, wl, pod)
        facts.default_sa_token |= mounted == "default"
        _mounts(builder, view, wl, pod, types)
        _imds(builder, wl, pod, nodes)
        pod_facts(pod, facts)
    return facts


# ── findings ─────────────────────────────────────────────────────────────────

def _finding(builder: Any, view: ClusterView, wl: Workload, fid: str, severity: str, title: str,
             description: str, evidence: Mapping[str, Any], source: str) -> str:
    ev = dict(evidence, pods=wl.pod_names(), pod_count=len(wl.pods))
    return builder.add_finding(
        fid, wl.node_id, severity=severity, title=f"{title} ({wl.label}, cluster {view.data.name})",
        description=description, evidence=ev, region=view.region,
        entity=f"pod/{view.data.name}/{wl.namespace}/{wl.name}", entity_arn=wl.node_id, resource=[wl.node_id],
        source_type="k8s_pod", source_policy=source)


def _escape_findings(builder: Any, view: ClusterView, wl: Workload, f: Facts) -> List[str]:
    out = []
    if f.privileged:
        out.append(_finding(builder, view, wl, "K8S-PRIV-001", "HIGH", "Privileged container",
                            "A privileged container (regular, init or ephemeral) has every capability and the "
                            "host's devices: it can take over the node.",
                            {"containers": sorted(f.privileged)}, "securityContext.privileged"))
    for fid, on, what, field_name in (("K8S-HOSTNET-001", f.host_network, "the host's network namespace "
                                       "(every node interface, the node's IMDS)", "hostNetwork"),
                                      ("K8S-HOSTPID-001", f.host_pid, "the host's PID namespace (it can see "
                                       "and signal every process on the node)", "hostPID"),
                                      ("K8S-HOSTIPC-001", f.host_ipc, "the host's IPC namespace (shared memory "
                                       "of every process on the node)", "hostIPC")):
        if on:
            out.append(_finding(builder, view, wl, fid, "HIGH", f"Pod uses {field_name}",
                                f"The pod shares {what}.", {"field": field_name}, f"PodSpec.{field_name}"))
    if f.host_paths:
        sensitive = sorted(p for p in f.host_paths if sensitive_path(p))
        out.append(_finding(builder, view, wl, "K8S-HOSTPATH-001", "HIGH" if sensitive else "MEDIUM",
                            "Pod mounts a hostPath volume",
                            "The pod mounts directories of the node" + (
                                " that give control of the node or its container runtime." if sensitive else "."),
                            {"host_paths": sorted(f.host_paths), "sensitive": sensitive}, "volumes[].hostPath"))
    if f.capabilities:
        out.append(_finding(builder, view, wl, "K8S-CAP-001", "HIGH", "Container adds dangerous capabilities",
                            "Added Linux capabilities (" + ", ".join(sorted(f.capabilities)) + ") allow container "
                            "escape or host network control.",
                            {"capabilities": {k: sorted(v) for k, v in sorted(f.capabilities.items())}},
                            "securityContext.capabilities.add"))
    if f.escalation:
        out.append(_finding(builder, view, wl, "K8S-ESCALATION-001", "LOW",
                            "Container explicitly allows privilege escalation",
                            "allowPrivilegeEscalation is true: setuid binaries can gain more privileges than the "
                            "container process started with.", {"containers": sorted(f.escalation)},
                            "securityContext.allowPrivilegeEscalation"))
    return out


def default_sa_risky(view: ClusterView, namespace: str) -> bool:
    """Does ``namespace``'s default service account hold RBAC bindings or an IRSA role?"""
    rec = view.service_accounts.get((namespace, "default"))
    if rec is not None and annotation(rec, IRSA_ANNOTATION):
        return True
    for kind in ("role_bindings", "cluster_role_bindings"):
        for b in view.data.items(kind):
            default_ns = namespace_of(b) if kind == "role_bindings" else None
            for s in seq(b.get("subjects")):
                s = mapping(s)
                if s.get("kind") == "ServiceAccount" and s.get("name") == "default" and \
                        (text(s.get("namespace")) or default_ns) == namespace:
                    return True
    return False


def _default_sa(builder: Any, view: ClusterView, wl: Workload, f: Facts) -> Optional[str]:
    if not f.default_sa_token:
        return None
    risky = default_sa_risky(view, wl.namespace)
    return _finding(builder, view, wl, "K8S-DEFAULT-SA", "MEDIUM" if risky else "LOW",
                    "Workload runs as the default service account with its token mounted",
                    "The pods mount the API token of their namespace's default service account" + (
                        ", which holds RBAC bindings or an IRSA role: every workload of the namespace that "
                        "uses it shares those rights." if risky else
                        ". Use a dedicated service account, or set automountServiceAccountToken: false."),
                    {"default_sa_has_rights": risky}, "PodSpec.serviceAccountName")


def run_workloads(ctx: Any, builder: Any) -> int:
    """Service accounts, workloads, their edges and findings for every cluster; returns the workload count."""
    from aws_enumerator.engine.analyzers.k8s.util import loader_model

    model = loader_model(ctx)
    count = 0
    for view in cluster_views(ctx):
        add_service_accounts(builder, view)
        nodes, types = NodeMap(view, model), _secret_types(view)
        for wl in view.workloads:
            facts = add_workload(builder, view, wl, nodes, types)
            _escape_findings(builder, view, wl, facts)
            _default_sa(builder, view, wl, facts)
            count += 1
    return count


def iter_pods(view: ClusterView) -> Iterable[Tuple[Workload, Mapping[str, Any]]]:
    for wl in view.workloads:
        for pod in wl.pods:
            yield wl, pod


__all__ = ["DANGEROUS_CAPABILITIES", "Facts", "NodeHop", "NodeMap", "SENSITIVE_HOST_PATHS", "add_service_accounts",
           "add_workload", "default_sa_risky", "imds_reach", "iter_pods", "pod_facts", "run_workloads",
           "sensitive_path", "token_sources"]
