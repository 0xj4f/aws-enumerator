"""EKS clusters and node groups (E-k8s): cluster and node-group nodes, ``CLUSTER_ROLE``, ``NODE_ROLE``,
endpoint exposure, Kubernetes enumeration status and the collecting identity's own RBAC rules.

* **Cluster nodes** are keyed by the cluster ARN (F-025); their ``coverage`` says how much of the cluster was
  read (DescribeCluster, the Kubernetes lists of ``cluster_info.resources``), so a cluster the collector could
  not authenticate to never looks like an empty one (F-033).
* ``CLUSTER_ROLE`` (info) is the control-plane service role; ``NODE_ROLE`` (bridge) the node instance role,
  reached from pods through ``CAN_REACH_NODE_IMDS`` (``workloads.py``).
* **EKS-ENDPOINT-001** (MEDIUM): the API endpoint is public and open to ``0.0.0.0/0`` / ``::/0``; with it an
  ``anonymous -PUBLIC_INBOUND-> cluster`` exposure edge (not traversable: the API still authenticates).
* **K8S-AUTH-001** (INFO): the Kubernetes API of the cluster was not enumerated (``auth_status`` other than
  ``ok``, or no ``cluster_info.json``); everything Kubernetes-side of that cluster is unknown, not absent.
* **K8S-CALLER-001** (INFO): what the collecting identity may do in the cluster, from the
  SelfSubjectRulesReviews the collector saved (F-152).
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Tuple

from aws_enumerator.engine.analyzers.k8s.util import ClusterView, capped, cluster_views, mapping, seq, text
from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.io.coverage import worst

#: Lists whose status forms the cluster's coverage (``secrets`` is opt-in and never needed, F-150).
CORE_LISTS: Tuple[str, ...] = ("pods", "service_accounts", "roles", "cluster_roles", "role_bindings",
                               "cluster_role_bindings", "services", "ingresses")
#: ``auth_status`` → node coverage status (graph-json.md §7.2) and a short reason.
AUTH_STATUS: Mapping[str, Tuple[str, str]] = {
    "failed": ("error", "authentication to the Kubernetes API failed"),
    "unreachable": ("error", "the Kubernetes API endpoint could not be reached"),
    "forbidden": ("denied", "the collecting identity was authenticated, but every list request was forbidden"),
    "dependency_missing": ("skipped", "the python package 'kubernetes' was not installed"),
    "skipped": ("skipped", "the cluster was skipped by the collector"),
    "unknown": ("error", "the Kubernetes enumeration did not finish"),
}
_K8S_APIS: Mapping[str, str] = {
    "pods": "k8s:ListPods", "service_accounts": "k8s:ListServiceAccounts", "roles": "k8s:ListRoles",
    "cluster_roles": "k8s:ListClusterRoles", "role_bindings": "k8s:ListRoleBindings",
    "cluster_role_bindings": "k8s:ListClusterRoleBindings", "services": "k8s:ListServices",
    "ingresses": "k8s:ListIngresses", "nodes": "k8s:ListNodes",
}
_OPEN_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


# ── shared helpers ───────────────────────────────────────────────────────────

def role_node(builder: Any, arn: Any) -> Optional[str]:
    """The ``role`` node of an IAM role ARN, by exact ARN (F-039, F-085); ``None`` for anything else."""
    if not isinstance(arn, str) or ":role/" not in arn:
        return None
    ref = builder.ensure_principal(arn, principal_type="AWS")
    return ref.node_id if ref.node_type == "role" else None


def nodegroup_ids(view: ClusterView) -> Dict[str, Tuple[str, Mapping[str, Any]]]:
    """Node-group name → (node id, record): the collected ARN, else ``…:nodegroup/<cluster>/<name>``."""
    out: Dict[str, Tuple[str, Mapping[str, Any]]] = {}
    for ng in view.data.eks_items("nodegroups"):
        name = text(ng.get("nodegroupName")) or text(ng.get("name"))
        if not name or "/" in name:
            continue
        arn = text(ng.get("nodegroupArn"))
        if not (arn and ids.node_id_matches("nodegroup", arn)):
            arn = view.arn.replace(":cluster/", ":nodegroup/", 1) + f"/{name}"
        if ids.node_id_matches("nodegroup", arn):
            out[name] = (arn, ng)
    return out


def endpoint_access(record: Mapping[str, Any]) -> Tuple[Optional[bool], Optional[List[str]]]:
    """``(endpointPublicAccess, publicAccessCidrs)``; ``None`` when not collected."""
    vpc = mapping(record.get("resourcesVpcConfig"))
    public = vpc.get("endpointPublicAccess")
    cidrs = vpc.get("publicAccessCidrs")
    return (public if isinstance(public, bool) else None,
            [str(c) for c in cidrs] if isinstance(cidrs, list) else None)


def objects_read(view: ClusterView) -> bool:
    """True when the collector reached the Kubernetes API of the cluster (``auth_status`` ``ok``)."""
    return view.data.auth_status == "ok"


# ── coverage ─────────────────────────────────────────────────────────────────

def _manifest_module(ctx: Any, region: str) -> Optional[Mapping[str, Any]]:
    """The manifest's ``k8s`` module entry for ``region`` (manifest.md §3.6), if any."""
    for entry in seq(mapping(ctx.manifest).get("modules")):
        entry = mapping(entry)
        if entry.get("name") == "k8s" and entry.get("region") == region:
            return entry
    return None


def _k8s_module_note(ctx: Any, view: ClusterView) -> Tuple[str, str]:
    """Status and reason when no ``cluster_info.json`` exists for the cluster."""
    if view.data.layout == "legacy":
        return "not-collected", "the Kubernetes API was not enumerated for this cluster (no k8s data in the report)"
    entry = _manifest_module(ctx, view.region)
    if entry is not None and entry.get("status") in ("skipped", "not_run"):
        reason = text(entry.get("status_reason")) or "no reason recorded"
        return ("skipped" if entry["status"] == "skipped" else "not-collected",
                f"the k8s module did not run for this region ({reason})")
    module = ctx.coverage.module_status("k8s", view.region)
    if module in ("skipped", "not-collected"):
        return module, "the k8s module did not run for this region (for example --no-k8s)"
    return "error", "the collector recorded no Kubernetes status for this cluster"


def auth_note(ctx: Any, view: ClusterView) -> Optional[Tuple[str, str]]:
    """``(coverage status, reason)`` when the Kubernetes objects of the cluster were not read, else ``None``."""
    status = view.data.auth_status
    if status == "ok":
        return None
    if status is None:
        return _k8s_module_note(ctx, view)
    return AUTH_STATUS.get(status, ("error", f"the Kubernetes enumeration ended with status {status!r}"))


def cluster_coverage(ctx: Any, view: ClusterView) -> Tuple[str, List[str]]:
    """Node coverage of the cluster: DescribeCluster, the Kubernetes API, then each core list."""
    data = view.data
    statuses, gaps = [], []
    if not data.describe_ok:
        statuses.append("error")
        gaps.append("eks:DescribeCluster:error")
    note = auth_note(ctx, view)
    if note is not None:
        statuses.append(note[0])
        gaps.append(f"k8s:api:{note[0]}")
    else:
        lists = CORE_LISTS + (("nodes",) if data.layout == "v2" else ())
        for kind in lists:
            st = data.object_status.get(kind, "not-collected")
            if st != "complete":
                statuses.append(st)
                gaps.append(f"k8s:{kind}:{st}")
            if data.layout == "v2" and kind in _K8S_APIS:
                ctx.coverage.facet("k8s", _K8S_APIS[kind], view.region)
        aws_auth = _aws_auth_unknown(view)
        if aws_auth is not None:
            statuses.append(aws_auth)
            gaps.append(f"k8s:aws_auth:{aws_auth}")
    for key in ("nodegroups", "access_entries", "pod_identity_associations"):
        st = data.eks_status.get(key, "not-collected")
        if st not in ("complete",) and not (data.layout == "legacy" and st == "not-collected"):
            statuses.append(st)
            gaps.append(f"eks:{key}:{st}")
    return worst(statuses), sorted(set(gaps))


_CALL_FACET = {"denied": "denied", "throttled": "throttled", "skipped": "skipped"}


def _aws_auth_unknown(view: ClusterView) -> Optional[str]:
    """Facet status when the ``aws-auth`` mappings of a v2 cluster that uses them were not readable, else ``None``."""
    data = view.data
    mode = text(mapping(data.record.get("accessConfig")).get("authenticationMode"))
    if data.layout != "v2" or mode == "API":
        return None
    if isinstance(data.aws_auth, Mapping) and data.aws_auth.get("present") is not None:
        return None
    status = text(mapping(mapping(mapping(data.info).get("resources")).get("aws_auth")).get("status"))
    return _CALL_FACET.get(status or "", "error")


# ── nodes and edges ──────────────────────────────────────────────────────────

def _private_access(record: Mapping[str, Any]) -> Optional[bool]:
    value = mapping(record.get("resourcesVpcConfig")).get("endpointPrivateAccess")
    return value if isinstance(value, bool) else None


def oidc_issuer(record: Mapping[str, Any]) -> Optional[str]:
    """``identity.oidc.issuer`` of a DescribeCluster record (``https://oidc.eks.<region>…/id/<ID>``)."""
    return text(mapping(mapping(record.get("identity")).get("oidc")).get("issuer"))


def _props(view: ClusterView) -> Dict[str, Any]:
    rec = view.data.record
    public, cidrs = endpoint_access(rec)
    fargate = [text(p.get("fargateProfileName")) for p in view.data.eks_items("fargate_profiles")]
    props: Dict[str, Any] = {
        "name": view.data.name, "version": text(rec.get("version")), "status": text(rec.get("status")),
        "endpoint_public_access": public, "endpoint_private_access": _private_access(rec),
        "public_access_cidrs": cidrs,
        "authentication_mode": text(mapping(rec.get("accessConfig")).get("authenticationMode")),
        "oidc_issuer": oidc_issuer(rec), "k8s_auth_status": view.data.auth_status,
        "fargate_profiles": capped(f for f in fargate if f) or None,
    }
    return {k: v for k, v in props.items() if v is not None}


def add_cluster(ctx: Any, builder: Any, view: ClusterView) -> str:
    status, gaps = cluster_coverage(ctx, view)
    tags = sorted((str(k), "" if v is None else str(v)) for k, v in mapping(view.data.record.get("tags")).items())
    builder.add_node(view.arn, "cluster", view.data.name, region=view.region, props=_props(view), tags=tags,
                     coverage_status=status, coverage_gaps=gaps)
    target = role_node(builder, view.data.record.get("roleArn"))
    if target is not None:
        builder.add_edge(view.arn, "CLUSTER_ROLE", target, evidence={"technique": "eks-control-plane-role"})
    return view.arn


def add_nodegroups(builder: Any, view: ClusterView) -> int:
    """Node-group nodes and their ``NODE_ROLE`` edges; returns the number of node groups."""
    groups = nodegroup_ids(view)
    for name, (node_id, ng) in sorted(groups.items()):
        failed = bool(ng.get("CollectionErrors") or ng.get("Error"))
        builder.add_node(node_id, "nodegroup", name, region=view.region,
                         props={k: v for k, v in {"cluster": view.data.name,
                                                  "capacity_type": text(ng.get("capacityType")),
                                                  "ami_type": text(ng.get("amiType"))}.items() if v},
                         coverage_status="error" if failed else None,
                         coverage_gaps=["eks:DescribeNodegroup:error"] if failed else ())
        role = role_node(builder, ng.get("nodeRole"))
        if role is not None:
            builder.add_edge(node_id, "NODE_ROLE", role, evidence={"technique": "node-instance-role"})
    return len(groups)


def add_endpoint_exposure(builder: Any, view: ClusterView) -> Optional[str]:
    """EKS-ENDPOINT-001 and ``PUBLIC_INBOUND`` for a public endpoint open to the internet (F-033)."""
    public, cidrs = endpoint_access(view.data.record)
    if public is not True:
        return None
    unknown = cidrs is None
    if not unknown and not (_OPEN_CIDRS & set(cidrs or ())):
        return None
    evidence = {"endpoint_public_access": True, "public_access_cidrs": cidrs,
                "endpoint_private_access": _private_access(view.data.record)}
    builder.add_edge(ids.ANONYMOUS_ID, "PUBLIC_INBOUND", view.arn, confidence="conditional" if unknown else None,
                     strength="weak" if unknown else None, evidence=evidence,
                     props={"technique": "eks-public-endpoint"})
    return builder.add_finding(
        "EKS-ENDPOINT-001", view.arn, severity="MEDIUM",
        title=f"EKS cluster {view.data.name} has a public API endpoint open to the internet",
        description=(f"The Kubernetes API endpoint of cluster {view.data.name} ({view.region}) is publicly "
                     "accessible from " + (", ".join(sorted(_OPEN_CIDRS & set(cidrs or ()))) if not unknown else
                                           "an unknown set of CIDRs (publicAccessCidrs was not collected)")
                     + ". Authentication is still required, but any leaked kubeconfig, token or mapped IAM "
                       "credential is usable from anywhere, and API-server vulnerabilities are exposed."),
        evidence=evidence, confidence="conditional" if unknown else "definite", region=view.region,
        entity=f"cluster/{view.data.name}", entity_arn=view.arn, resource=[view.arn],
        source_type="eks_cluster", source_policy="resourcesVpcConfig")


def add_auth_status(ctx: Any, builder: Any, view: ClusterView) -> Optional[str]:
    """K8S-AUTH-001 (INFO) when the cluster's Kubernetes API was not enumerated (F-033 point 4)."""
    note = auth_note(ctx, view)
    if note is None:
        return None
    status, reason = note
    info = view.data.info or {}
    evidence = {"auth_status": view.data.auth_status, "coverage_status": status,
                "error_code": text(info.get("error_code")), "auth_mode": text(info.get("auth_mode")),
                "endpoint_hint": text(info.get("endpoint_hint"))}
    return builder.add_finding(
        "K8S-AUTH-001", view.arn, severity="INFO",
        title=f"Kubernetes objects of cluster {view.data.name} were not enumerated",
        description=(f"{reason[0].upper()}{reason[1:]} (cluster {view.data.name}, {view.region}). Pods, service "
                     "accounts, RBAC and network objects of this cluster are unknown: the absence of Kubernetes "
                     "edges and findings for it is not evidence of a safe cluster."),
        evidence={k: v for k, v in evidence.items() if v is not None}, region=view.region,
        entity=f"cluster/{view.data.name}", entity_arn=view.arn, resource=[view.arn], source_type="k8s_cluster",
        source_policy="cluster_info.auth_status")


# ── the collecting identity's rules (SelfSubjectRulesReview, F-152) ──────────

_NOTABLE: Tuple[Tuple[str, str, str], ...] = (
    ("*", "*", "every verb on every resource"),
    ("create", "pods", "create pods (run as any service account of the namespace)"),
    ("create", "serviceaccounts/token", "mint service-account tokens"),
    ("impersonate", "serviceaccounts", "impersonate service accounts"),
    ("list", "secrets", "list secrets (reads every value)"),
    ("get", "secrets", "read secrets"),
    ("escalate", "roles", "escalate roles"),
    ("bind", "clusterroles", "bind cluster roles"),
)


def _rule_has(rule: Mapping[str, Any], verb: str, resource: str) -> bool:
    verbs = {str(v) for v in seq(rule.get("verbs"))}
    resources = {str(r) for r in seq(rule.get("resources"))}
    if verb == "*":
        return "*" in verbs and "*" in resources
    return (verb in verbs or "*" in verbs) and (resource in resources or "*" in resources)


def notable_permissions(self_rules: List[Mapping[str, Any]]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for review in sorted(self_rules, key=lambda r: str(r.get("namespace"))):
        ns = text(review.get("namespace")) or "?"
        for verb, resource, label in _NOTABLE:
            if any(_rule_has(mapping(r), verb, resource) for r in seq(review.get("resource_rules"))):
                out.append({"namespace": ns, "permission": label})
    return out


def add_caller_rules(builder: Any, view: ClusterView) -> Optional[str]:
    """K8S-CALLER-001 (INFO): the collecting identity's Kubernetes permissions in this cluster."""
    reviews = view.data.self_rules
    if not reviews:
        return None
    notable = notable_permissions(reviews)
    incomplete = capped(text(r.get("namespace")) or "?" for r in reviews if r.get("incomplete") is True)
    summary = ", ".join(sorted({n["permission"] for n in notable})) or "no notable permission"
    return builder.add_finding(
        "K8S-CALLER-001", view.arn, severity="INFO",
        title=f"Kubernetes permissions of the collecting identity in cluster {view.data.name}",
        description=(f"SelfSubjectRulesReviews in {len(reviews)} namespace(s) of cluster {view.data.name} show: "
                     f"{summary}. They describe the identity the collector used, which is a foothold an "
                     "attacker holding the same credentials would have."),
        evidence={"namespaces_reviewed": len(reviews), "incomplete_namespaces": incomplete,
                  "notable": notable[:50]},
        region=view.region, entity=f"cluster/{view.data.name}", entity_arn=view.arn, resource=[view.arn],
        source_type="k8s_self_rules", source_policy="SelfSubjectRulesReview")


def run_clusters(ctx: Any, builder: Any) -> List[ClusterView]:
    """Cluster and node-group nodes, cluster-level edges and findings for every analysed cluster."""
    views = cluster_views(ctx)
    for view in views:
        add_cluster(ctx, builder, view)
        add_nodegroups(builder, view)
        add_endpoint_exposure(builder, view)
        add_auth_status(ctx, builder, view)
        add_caller_rules(builder, view)
    return views


__all__ = ["AUTH_STATUS", "CORE_LISTS", "add_auth_status", "add_caller_rules", "add_cluster",
           "add_endpoint_exposure", "add_nodegroups", "auth_note", "cluster_coverage", "endpoint_access",
           "nodegroup_ids", "notable_permissions", "objects_read", "oidc_issuer", "role_node", "run_clusters"]
