"""Kubernetes services and ingresses (E-k8s): ``SELECTS``, ``INGRESS_ROUTES_TO``, exposure findings.

* ``SELECTS`` k8sservice → pod (info) for every pod whose labels contain the service's selector, in the
  service's namespace. Matching uses :class:`PodIndex`: pods by namespace and by ``(namespace, key, value)``,
  so a service costs the size of its smallest selector bucket instead of a rescan of every pod (F-087; the
  d13c215 loop was O(services × pods-in-namespace × all pods)).
* ``INGRESS_ROUTES_TO`` k8singress → k8sservice (info; ``EXPOSES`` in the legacy file).
* **K8S-NET-001**: a ``LoadBalancer`` service that is internet-facing (HIGH; LOW when
  ``loadBalancerSourceRanges`` restricts it), with ``anonymous -PUBLIC_INBOUND-> k8sservice``. Internal load
  balancers are recognised (F-083): ``aws-load-balancer-internal``, ``aws-load-balancer-scheme: internal``, the
  AWS Load Balancer Controller's internal default (``loadBalancerClass service.k8s.aws/*`` or
  ``aws-load-balancer-type: external|nlb-ip`` without an internet-facing scheme) and an ``internal-`` load
  balancer hostname.
* **K8S-NET-002** (MEDIUM): an internet-facing ingress without an authentication annotation. An ALB ingress is
  internet-facing only with ``alb.ingress.kubernetes.io/scheme: internet-facing`` (the controller's default
  is internal); other ingress classes depend on their controller's service, so the finding is conditional.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Set, Tuple

from aws_enumerator.engine.analyzers.k8s.util import (
    ClusterView, Workload, annotation, annotation_keys, cluster_views, k8s_id, labels_of, mapping, name_of,
    namespace_of, seq, spec_of, text,
)
from aws_enumerator.engine.graph import ids

_INTERNAL_VALUES = frozenset({"true", "0.0.0.0/0", "yes", "1"})
_LBC_TYPES = frozenset({"external", "nlb-ip"})
_OPEN_RANGES = frozenset({"0.0.0.0/0", "::/0"})
_AUTH_PREFIXES = ("nginx.ingress.kubernetes.io/auth", "alb.ingress.kubernetes.io/auth",
                  "traefik.ingress.kubernetes.io/router.middlewares")


# ── pod index (F-087) ────────────────────────────────────────────────────────

@dataclass
class PodIndex:
    """Pods of one cluster indexed by namespace and by ``(namespace, label, value)``."""

    pods: List[Tuple[str, Dict[str, str]]] = field(default_factory=list)        # (workload node id, labels)
    pods_by_ns: Dict[str, List[int]] = field(default_factory=dict)
    by_label: Dict[Tuple[str, str, str], Set[int]] = field(default_factory=dict)

    @classmethod
    def build(cls, workloads: List[Workload]) -> "PodIndex":
        index = cls()
        for wl in workloads:
            for pod in wl.pods:
                i = len(index.pods)
                labels = labels_of(pod)
                index.pods.append((wl.node_id, labels))
                index.pods_by_ns.setdefault(wl.namespace, []).append(i)
                for key, value in labels.items():
                    index.by_label.setdefault((wl.namespace, key, value), set()).add(i)
        return index

    def selected(self, namespace: str, selector: Mapping[str, str]) -> FrozenSet[str]:
        """Workload node ids with at least one pod whose labels contain ``selector`` (empty selector: none)."""
        if not selector:
            return frozenset()
        buckets = sorted((self.by_label.get((namespace, str(k), str(v)), set()) for k, v in selector.items()),
                         key=len)
        if not buckets[0]:
            return frozenset()
        hits = set(buckets[0]).intersection(*buckets[1:])
        return frozenset(self.pods[i][0] for i in hits)

    def selected_scan(self, namespace: str, selector: Mapping[str, str]) -> FrozenSet[str]:
        """Reference implementation over ``pods_by_ns`` (tests compare it with :meth:`selected`)."""
        if not selector:
            return frozenset()
        out = set()
        for i in self.pods_by_ns.get(namespace, ()):
            node_id, labels = self.pods[i]
            if all(labels.get(str(k)) == str(v) for k, v in selector.items()):
                out.add(node_id)
        return frozenset(out)


def selector_of(svc: Mapping[str, Any]) -> Dict[str, str]:
    raw = mapping(spec_of(svc).get("selector"))
    return {str(k): str(v) for k, v in raw.items() if isinstance(v, (str, int, float, bool))}


# ── services ─────────────────────────────────────────────────────────────────

def lb_scheme(svc: Mapping[str, Any]) -> Tuple[str, str]:
    """``("internal" | "internet-facing", reason)`` of a LoadBalancer service (F-083)."""
    internal = (annotation(svc, "service.beta.kubernetes.io/aws-load-balancer-internal") or "").lower()
    if internal in _INTERNAL_VALUES:
        return "internal", "aws-load-balancer-internal annotation"
    scheme = (annotation(svc, "service.beta.kubernetes.io/aws-load-balancer-scheme") or "").lower()
    if scheme in ("internal", "internet-facing"):
        return scheme, "aws-load-balancer-scheme annotation"
    for ing in seq(mapping(mapping(mapping(svc.get("status")).get("load_balancer"))).get("ingress")):
        host = text(mapping(ing).get("hostname")) or ""
        if host.startswith("internal-"):
            return "internal", "internal load balancer hostname"
    lb_class = text(spec_of(svc).get("load_balancer_class")) or ""
    lb_type = (annotation(svc, "service.beta.kubernetes.io/aws-load-balancer-type") or "").lower()
    if lb_class.startswith("service.k8s.aws/") or lb_type in _LBC_TYPES:
        return "internal", "AWS Load Balancer Controller default scheme (internal)"
    return "internet-facing", "in-tree cloud provider default (internet-facing)"


def source_ranges(svc: Mapping[str, Any]) -> List[str]:
    return sorted(str(r) for r in seq(spec_of(svc).get("load_balancer_source_ranges")) if isinstance(r, str))


def _service_exposure(builder: Any, view: ClusterView, svc_id: str, svc: Mapping[str, Any]) -> Optional[str]:
    if text(spec_of(svc).get("type")) != "LoadBalancer":
        return None
    scheme, reason = lb_scheme(svc)
    ranges = source_ranges(svc)
    restricted = bool(ranges) and not (_OPEN_RANGES & set(ranges))
    builder.set_node_props(svc_id, lb_scheme=scheme, lb_scheme_reason=reason)
    if scheme != "internet-facing":
        return None
    ns, name = namespace_of(svc) or "default", name_of(svc) or "?"
    evidence = {"scheme": scheme, "scheme_reason": reason, "load_balancer_source_ranges": ranges}
    builder.add_edge(ids.ANONYMOUS_ID, "PUBLIC_INBOUND", svc_id, evidence=evidence,
                     props={"technique": "k8s-load-balancer"})
    return builder.add_finding(
        "K8S-NET-001", svc_id, severity="LOW" if restricted else "HIGH",
        title=f"Service {ns}/{name} is an internet-facing load balancer (cluster {view.data.name})",
        description=(f"Service {ns}/{name} of type LoadBalancer gets an internet-facing AWS load balancer "
                     f"({reason})" + (f", restricted to {', '.join(ranges)}." if restricted else
                                      ", open to any source address.")),
        evidence=evidence, region=view.region, entity=f"k8sservice/{view.data.name}/{ns}/{name}",
        entity_arn=svc_id, resource=[svc_id], source_type="k8s_service", source_policy="Service.spec.type")


def add_services(builder: Any, view: ClusterView, index: PodIndex) -> Dict[Tuple[str, str], str]:
    """Service nodes, ``SELECTS`` edges and K8S-NET-001; returns (namespace, name) → node id."""
    out: Dict[Tuple[str, str], str] = {}
    for svc in sorted(view.data.items("services"), key=lambda s: (namespace_of(s) or "", name_of(s) or "")):
        ns, name = namespace_of(svc), name_of(svc)
        svc_id = k8s_id(view.arn, "k8sservice", ns, name)
        if svc_id is None or ns is None or name is None:
            view.unrepresentable += 1
            continue
        out[(ns, name)] = svc_id
        builder.add_node(svc_id, "k8sservice", f"{ns}/{name}", region=view.region,
                         props={"namespace": ns, "name": name, "service_type": text(spec_of(svc).get("type"))})
        for pod_id in sorted(index.selected(ns, selector_of(svc))):
            builder.add_edge(svc_id, "SELECTS", pod_id, evidence={"technique": "label-selector"})
        _service_exposure(builder, view, svc_id, svc)
    return out


# ── ingresses ────────────────────────────────────────────────────────────────

def backends(ing: Mapping[str, Any]) -> List[str]:
    """Service names an ingress routes to (rules and the default backend)."""
    names = []
    spec = spec_of(ing)
    default = mapping(mapping(spec.get("default_backend")).get("service"))
    if text(default.get("name")):
        names.append(str(default["name"]))
    for rule in seq(spec.get("rules")):
        for path in seq(mapping(mapping(rule).get("http")).get("paths")):
            svc = mapping(mapping(mapping(path).get("backend")).get("service"))
            if text(svc.get("name")):
                names.append(str(svc["name"]))
    return sorted(set(names))


def ingress_exposure(ing: Mapping[str, Any]) -> Tuple[Optional[bool], str]:
    """``(internet_facing, reason)``: ``True``/``False`` for ALB ingresses, ``None`` when it depends on the
    ingress controller's own service."""
    cls = (text(spec_of(ing).get("ingress_class_name")) or annotation(ing, "kubernetes.io/ingress.class") or "")
    scheme = (annotation(ing, "alb.ingress.kubernetes.io/scheme") or "").lower()
    if cls.lower() == "alb" or scheme:
        if scheme == "internet-facing":
            return True, "alb.ingress.kubernetes.io/scheme: internet-facing"
        return False, "ALB ingress scheme " + (scheme or "internal (controller default)")
    return None, f"ingress class {cls or 'unset'}: exposure depends on the ingress controller's service"


def _ingress_finding(builder: Any, view: ClusterView, ing_id: str, ing: Mapping[str, Any]) -> Optional[str]:
    if any(k.startswith(_AUTH_PREFIXES) for k in annotation_keys(ing)):
        return None
    facing, reason = ingress_exposure(ing)
    if facing is False:
        return None
    ns, name = namespace_of(ing) or "default", name_of(ing) or "?"
    return builder.add_finding(
        "K8S-NET-002", ing_id, severity="MEDIUM",
        title=f"Ingress {ns}/{name} has no authentication annotation (cluster {view.data.name})",
        description=(f"Ingress {ns}/{name} routes to {', '.join(backends(ing)) or 'no service'} without an "
                     f"authentication annotation ({reason}). Verify that the backends authenticate requests."),
        evidence={"exposure": reason, "backends": backends(ing)}, confidence="definite" if facing else "conditional",
        region=view.region, entity=f"k8singress/{view.data.name}/{ns}/{name}", entity_arn=ing_id,
        resource=[ing_id], source_type="k8s_ingress", source_policy="Ingress.metadata.annotations")


def add_ingresses(builder: Any, view: ClusterView, services: Mapping[Tuple[str, str], str]) -> int:
    count = 0
    for ing in sorted(view.data.items("ingresses"), key=lambda i: (namespace_of(i) or "", name_of(i) or "")):
        ns, name = namespace_of(ing), name_of(ing)
        ing_id = k8s_id(view.arn, "k8singress", ns, name)
        if ing_id is None or ns is None:
            view.unrepresentable += 1
            continue
        builder.add_node(ing_id, "k8singress", f"{ns}/{name}", region=view.region,
                         props={"namespace": ns, "name": name})
        for backend in backends(ing):
            svc_id = services.get((ns, backend)) or k8s_id(view.arn, "k8sservice", ns, backend)
            if svc_id is None:
                continue
            if not builder.has_node(svc_id):
                builder.add_node(svc_id, "k8sservice", f"{ns}/{backend}", region=view.region,
                                 props={"namespace": ns, "name": backend, "placeholder": True},
                                 coverage_status="not-collected" if not view.data.known("services") else None)
            builder.add_edge(ing_id, "INGRESS_ROUTES_TO", svc_id, evidence={"technique": "ingress-backend"})
        _ingress_finding(builder, view, ing_id, ing)
        count += 1
    return count


def run_network(ctx: Any, builder: Any) -> int:
    count = 0
    for view in cluster_views(ctx):
        services = add_services(builder, view, PodIndex.build(view.workloads))
        count += len(services) + add_ingresses(builder, view, services)
    return count


__all__ = ["PodIndex", "add_ingresses", "add_services", "backends", "ingress_exposure", "lb_scheme", "run_network",
           "selector_of", "source_ranges"]
