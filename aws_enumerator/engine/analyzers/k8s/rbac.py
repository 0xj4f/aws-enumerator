"""Kubernetes RBAC (E-k8s): roles, bindings of every subject kind, group membership and ``CAN_RUN_AS_SA``.

* **Roles.** ``Role/<ns>/<name>`` and ``ClusterRole/_/<name>`` nodes for the collected roles; a RoleBinding to
  a ClusterRole grants that ClusterRole's rules **in the binding's namespace only**, so it binds to the
  namespaced instance ``Role/<ns>/ClusterRole:<name>`` (``util.bound_cluster_role_id``) and never to the
  cluster-wide node (no false cluster-wide paths, F-007).
* ``BOUND_TO`` subject → role for ServiceAccount, **User and Group** subjects (F-035); ``MEMBER_OF_K8S_GROUP``
  sa → ``system:serviceaccounts``, ``system:serviceaccounts:<ns>`` and ``system:authenticated``, and
  k8suser → ``system:authenticated`` (``system:anonymous`` → ``system:unauthenticated``), each only when a
  binding or a mapping names that group. ``system:masters`` is the API server's superuser group: it is bound to
  ``cluster-admin`` whatever the collected bindings say.
* ``CAN_RUN_AS_SA`` role → sa when the role's rules (exact Kubernetes RBAC matching, :func:`rule_allows`)
  allow creating pods or pod-owning workloads, updating / patching those workloads, minting the service
  account's token (``serviceaccounts/token``) or impersonating it, in the service account's namespace. Emitted
  for roles somebody holds (a binding, an EKS access entry or an aws-auth group), cluster-wide only for a
  ClusterRole bound cluster-wide.
* Findings: **K8S-RBAC-001** a service account bound to ``cluster-admin`` or a wildcard role (CRITICAL
  cluster-wide, HIGH through a RoleBinding); **K8S-RBAC-003** an all-identities group or user
  (``system:authenticated``, ``system:unauthenticated``, ``system:anonymous``, ``system:serviceaccounts[:ns]``)
  bound to such a role (CRITICAL / HIGH); **K8S-RBAC-002** (HIGH) a role with every verb on every resource,
  **built-in roles excluded** (``cluster-admin``, ``system:*``, ``eks:*``, ``rbac-defaults``, F-086).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from aws_enumerator.engine.analyzers.k8s.util import (
    ClusterView, bound_cluster_role_id, cluster_views, k8s_id, labels_of, mapping, name_of, namespace_of,
    role_id, seq, text,
)

#: Built-in ClusterRole rules used when the cluster's roles were not collected (EKS access policies map to them).
BUILTIN_RULES: Mapping[str, Tuple[Mapping[str, Any], ...]] = {
    "cluster-admin": ({"api_groups": ["*"], "resources": ["*"], "verbs": ["*"]},),
    "admin": ({"api_groups": [""], "resources": ["pods", "serviceaccounts"], "verbs": ["create", "impersonate"]},
              {"api_groups": ["apps"], "resources": ["deployments"], "verbs": ["create", "patch"]}),
    "edit": ({"api_groups": [""], "resources": ["pods", "serviceaccounts"], "verbs": ["create", "impersonate"]},
             {"api_groups": ["apps"], "resources": ["deployments"], "verbs": ["create", "patch"]}),
    "view": ({"api_groups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]},),
}
#: Groups / users that stand for every identity of a kind (F-035).
BROAD_SUBJECTS = frozenset({("Group", "system:authenticated"), ("Group", "system:unauthenticated"),
                            ("Group", "system:serviceaccounts"), ("User", "system:anonymous")})
SUPERUSER_GROUP = "system:masters"

#: (verb, api group, resource) requests that run code as an arbitrary service account of the namespace.
_RUN_AS_ANY: Tuple[Tuple[str, str, str], ...] = tuple(
    [("create", "", "pods"), ("create", "", "replicationcontrollers"), ("update", "", "replicationcontrollers"),
     ("patch", "", "replicationcontrollers")]
    + [(verb, "apps", res) for res in ("deployments", "replicasets", "statefulsets", "daemonsets")
       for verb in ("create", "update", "patch")]
    + [(verb, "batch", res) for res in ("jobs", "cronjobs") for verb in ("create", "update", "patch")])
#: (verb, resource) requests on one named service account.
_RUN_AS_NAMED: Tuple[Tuple[str, str], ...] = (("create", "serviceaccounts/token"), ("impersonate", "serviceaccounts"))


# ── rule matching (Kubernetes RBAC semantics) ────────────────────────────────

def _strings(value: Any) -> List[str]:
    return [str(v) for v in seq(value) if isinstance(v, str)]


def resource_matches(rule_resources: Iterable[str], resource: str) -> bool:
    """``rbac.ResourceMatches``: ``*``, an exact ``res[/sub]``, or ``*/sub`` for a subresource request."""
    sub = resource.split("/", 1)[1] if "/" in resource else ""
    for r in rule_resources:
        if r == "*" or r == resource or (sub and r == f"*/{sub}"):
            return True
    return False


def rule_allows(rule: Mapping[str, Any], verb: str, group: str, resource: str, name: str = "") -> bool:
    """``rbac.RuleAllows`` for a resource request (non-resource URLs are not modelled)."""
    verbs, groups = _strings(rule.get("verbs")), _strings(rule.get("api_groups"))
    if not ("*" in verbs or verb in verbs) or not ("*" in groups or group in groups):
        return False
    if not resource_matches(_strings(rule.get("resources")), resource):
        return False
    names = _strings(rule.get("resource_names"))
    return not names or (bool(name) and name in names)


def is_wildcard(rules: Iterable[Mapping[str, Any]]) -> bool:
    """A rule with every verb on every resource (of its API groups): the d13c215 "* on *" test."""
    return any("*" in _strings(r.get("verbs")) and "*" in _strings(r.get("resources")) for r in rules)


def run_as(rules: Iterable[Mapping[str, Any]], sa_name: str) -> List[str]:
    """How ``rules`` let their holder run as ``sa_name`` in the role's namespace (empty: they do not)."""
    rules = [mapping(r) for r in rules]
    out = [f"{verb} {group + '/' if group else ''}{res}" for verb, group, res in _RUN_AS_ANY
           if any(rule_allows(r, verb, group, res) for r in rules)]
    out += [f"{verb} {res}" for verb, res in _RUN_AS_NAMED if any(rule_allows(r, verb, "", res, sa_name)
                                                                  for r in rules)]
    return out


def builtin(role: Mapping[str, Any], name: str) -> bool:
    """Kubernetes / EKS default roles (F-086: never K8S-RBAC-002)."""
    return name == "cluster-admin" or name.startswith(("system:", "eks:")) or \
        labels_of(role).get("kubernetes.io/bootstrapping") == "rbac-defaults"


# ── the RBAC model of one cluster ────────────────────────────────────────────

@dataclass(frozen=True)
class RoleRef:
    """A node a subject can be bound to: its id, the rules, and the namespace it applies in (``None``: all)."""

    node_id: str
    kind: str                     # Role, ClusterRole, BoundClusterRole (namespaced instance), AccessPolicy (EKS)
    name: str
    namespace: Optional[str]
    source: str                   # collected, builtin-default, eks-access-policy or unknown


@dataclass
class Grant:
    """One subject → role binding (a RoleBinding, a ClusterRoleBinding, or an implicit superuser grant)."""

    subject_kind: str             # ServiceAccount | User | Group
    subject_name: str
    subject_ns: Optional[str]
    role: RoleRef
    binding: str
    binding_kind: str


@dataclass
class Rbac:
    """Roles (by node id) with their rules, the grants, and the group / user names anything refers to."""

    roles: Dict[str, RoleRef] = field(default_factory=dict)
    rules: Dict[str, List[Mapping[str, Any]]] = field(default_factory=dict)
    grants: List[Grant] = field(default_factory=list)
    groups: Set[str] = field(default_factory=set)
    users: Set[str] = field(default_factory=set)
    cluster_role_rules: Optional[Dict[str, Tuple[List[Mapping[str, Any]], str]]] = None
    namespaced_roles: Optional[Dict[Tuple[Optional[str], Optional[str]], Mapping[str, Any]]] = None


def _cluster_role_rules(view: ClusterView) -> Dict[str, Tuple[List[Mapping[str, Any]], str]]:
    out: Dict[str, Tuple[List[Mapping[str, Any]], str]] = {}
    for name, rules in BUILTIN_RULES.items():
        out[name] = ([dict(r) for r in rules], "builtin-default")
    for cr in view.data.items("cluster_roles"):
        n = name_of(cr)
        if n:
            out[n] = ([mapping(r) for r in seq(cr.get("rules"))], "collected")
    return out


def role_for(view: ClusterView, model: Rbac, kind: str, name: str, namespace: Optional[str]) -> Optional[RoleRef]:
    """The role node a binding (or an EKS access policy) grants; ``namespace`` scopes a ClusterRole grant."""
    if model.cluster_role_rules is None:
        model.cluster_role_rules = _cluster_role_rules(view)
    if kind == "ClusterRole":
        rules, source = model.cluster_role_rules.get(name, ([], "unknown"))
        node = role_id(view.arn, "ClusterRole", name) if namespace is None else \
            bound_cluster_role_id(view.arn, name, namespace)
        ref_kind = "ClusterRole" if namespace is None else "BoundClusterRole"
    else:
        if model.namespaced_roles is None:
            model.namespaced_roles = {(namespace_of(r), name_of(r)): r for r in view.data.items("roles")}
        rec = model.namespaced_roles.get((namespace, name))
        rules = [mapping(r) for r in seq(rec.get("rules"))] if rec else []
        source = "collected" if rec else "unknown"
        node, ref_kind = role_id(view.arn, "Role", name, namespace), "Role"
    if node is None:
        return None
    ref = model.roles.setdefault(node, RoleRef(node, ref_kind, name, namespace, source))
    model.rules.setdefault(node, rules)
    return ref


def _bindings(view: ClusterView) -> Iterable[Tuple[str, Mapping[str, Any]]]:
    for kind, key in (("RoleBinding", "role_bindings"), ("ClusterRoleBinding", "cluster_role_bindings")):
        for b in sorted(view.data.items(key), key=lambda x: (namespace_of(x) or "", name_of(x) or "")):
            yield kind, b


def build_rbac(view: ClusterView) -> Rbac:
    """Every grant of the collected bindings, plus ``system:masters`` → ``cluster-admin``."""
    model = Rbac()
    for binding_kind, b in _bindings(view):
        ref = mapping(b.get("role_ref"))
        role_kind, role_name = text(ref.get("kind")), text(ref.get("name"))
        ns = namespace_of(b) if binding_kind == "RoleBinding" else None
        if role_kind not in ("Role", "ClusterRole") or not role_name or (role_kind == "Role" and ns is None):
            continue                                   # a ClusterRoleBinding can only reference a ClusterRole
        role = role_for(view, model, role_kind, role_name, ns)
        if role is None:
            view.unrepresentable += 1
            continue
        for s in seq(b.get("subjects")):
            s = mapping(s)
            skind, sname = text(s.get("kind")), text(s.get("name"))
            if skind not in ("ServiceAccount", "User", "Group") or not sname:
                continue
            sns = (text(s.get("namespace")) or ns) if skind == "ServiceAccount" else None
            if skind == "ServiceAccount" and not sns:
                continue
            model.grants.append(Grant(skind, sname, sns, role, name_of(b) or "?", binding_kind))
            (model.groups if skind == "Group" else model.users if skind == "User" else set()).add(sname)
    return model


def add_superuser(view: ClusterView, model: Rbac) -> None:
    """``system:masters`` bypasses RBAC: bind it to ``cluster-admin`` when anything maps into that group."""
    if SUPERUSER_GROUP in model.groups:
        role = role_for(view, model, "ClusterRole", "cluster-admin", None)
        if role is not None and not any(g.subject_name == SUPERUSER_GROUP and g.role.node_id == role.node_id
                                        for g in model.grants):
            model.grants.append(Grant("Group", SUPERUSER_GROUP, None, role, "system:masters (API server superuser)",
                                      "implicit"))


# ── nodes and edges ──────────────────────────────────────────────────────────

def subject_id(view: ClusterView, kind: str, name: str, namespace: Optional[str]) -> Optional[str]:
    if kind == "ServiceAccount":
        return view.sa_id(namespace, name)
    return k8s_id(view.arn, "k8sgroup" if kind == "Group" else "k8suser", None, name)


def ensure_subject(builder: Any, view: ClusterView, kind: str, name: str, namespace: Optional[str]) -> Optional[str]:
    node_id = subject_id(view, kind, name, namespace)
    if node_id is None:
        view.unrepresentable += 1
        return None
    if not builder.has_node(node_id):
        ntype = {"ServiceAccount": "sa", "Group": "k8sgroup", "User": "k8suser"}[kind]
        label = f"{namespace}/{name}" if kind == "ServiceAccount" else name
        builder.add_node(node_id, ntype, label, region=view.region,
                         props={k: v for k, v in {"name": name, "namespace": namespace}.items() if v})
    return node_id


def role_label(role: RoleRef) -> str:
    """Display label: ``name``, ``ns/name``, ``ns/name (ClusterRole)`` or ``name (EKS access policy)``."""
    if role.kind == "AccessPolicy":
        scope = f"{role.namespace}/" if role.namespace else ""
        return f"{scope}{role.name} (EKS access policy)"
    if role.kind == "ClusterRole":
        return role.name
    suffix = " (ClusterRole)" if role.kind == "BoundClusterRole" else ""
    return f"{role.namespace}/{role.name}{suffix}"


def ensure_role(builder: Any, view: ClusterView, role: RoleRef) -> str:
    if not builder.has_node(role.node_id):
        label = role_label(role)
        props = {"name": role.name, "namespace": role.namespace, "role_kind": role.kind, "rules_source": role.source}
        if role.kind == "BoundClusterRole":
            props["cluster_role"] = role_id(view.arn, "ClusterRole", role.name)
        builder.add_node(role.node_id, "k8srole", label, region=view.region,
                         props={k: v for k, v in props.items() if v},
                         coverage_status="not-collected" if role.source == "unknown" else None)
    return role.node_id


def add_roles(builder: Any, view: ClusterView, model: Rbac) -> None:
    """Nodes for every collected Role / ClusterRole (bound or not) and every role a grant names."""
    for kind, key in (("Role", "roles"), ("ClusterRole", "cluster_roles")):
        for r in view.data.items(key):
            ref = role_for(view, model, kind, name_of(r) or "", namespace_of(r) if kind == "Role" else None)
            if ref is not None:
                ensure_role(builder, view, ref)
    for ref in model.roles.values():
        ensure_role(builder, view, ref)


def add_bindings(builder: Any, view: ClusterView, model: Rbac) -> int:
    for g in model.grants:
        src = ensure_subject(builder, view, g.subject_kind, g.subject_name, g.subject_ns)
        if src is None:
            continue
        builder.add_edge(src, "BOUND_TO", ensure_role(builder, view, g.role),
                         evidence={"binding": g.binding, "binding_kind": g.binding_kind,
                                   "role_kind": g.role.kind, "technique": "rbac-binding"})
    return len(model.grants)


def implicit_groups(view: ClusterView, model: Rbac, sa: Tuple[str, str]) -> List[str]:
    ns = sa[0]
    return [g for g in ("system:serviceaccounts", f"system:serviceaccounts:{ns}", "system:authenticated")
            if g in model.groups]


def add_memberships(builder: Any, view: ClusterView, model: Rbac) -> int:
    """``MEMBER_OF_K8S_GROUP`` for service accounts and users into the implicit groups that are named."""
    count = 0
    for key in sorted(view.sa_keys):
        sa_id = view.sa_id(*key)
        for group in implicit_groups(view, model, key):
            gid = ensure_subject(builder, view, "Group", group, None)
            if sa_id and gid and builder.has_node(sa_id):
                builder.add_edge(sa_id, "MEMBER_OF_K8S_GROUP", gid, evidence={"implicit": True})
                count += 1
    for user in sorted(model.users):
        group = "system:unauthenticated" if user == "system:anonymous" else "system:authenticated"
        uid = ensure_subject(builder, view, "User", user, None)
        if group in model.groups and uid is not None:
            gid = ensure_subject(builder, view, "Group", group, None)
            if gid is not None:
                builder.add_edge(uid, "MEMBER_OF_K8S_GROUP", gid, evidence={"implicit": True})
                count += 1
    return count


def held_roles(model: Rbac, extra: Iterable[str] = ()) -> Set[str]:
    return {g.role.node_id for g in model.grants} | set(extra)


def add_run_as(builder: Any, view: ClusterView, model: Rbac, held: Set[str]) -> int:
    """``CAN_RUN_AS_SA`` from every held role to the service accounts its rules let it run as."""
    count = 0
    for node_id in sorted(held):
        role = model.roles.get(node_id)
        rules = model.rules.get(node_id) or []
        if role is None or not rules:
            continue
        ensure_role(builder, view, role)
        for ns, sa in sorted(view.sa_keys):
            if role.namespace is not None and ns != role.namespace:
                continue
            how = run_as(rules, sa)
            sa_id = view.sa_id(ns, sa)
            if how and sa_id and builder.has_node(sa_id):
                builder.add_edge(node_id, "CAN_RUN_AS_SA", sa_id,
                                 evidence={"via": how, "rules_source": role.source, "technique": "run-as-sa"})
                count += 1
    return count


# ── findings ─────────────────────────────────────────────────────────────────

def admin_like(model: Rbac, role: RoleRef) -> bool:
    return role.name == "cluster-admin" or is_wildcard(model.rules.get(role.node_id) or [])


def _binding_findings(builder: Any, view: ClusterView, model: Rbac) -> List[str]:
    out = []
    for g in model.grants:
        if g.binding_kind == "implicit" or g.binding.startswith(("system:", "eks:")) or not admin_like(model, g.role):
            continue
        broad = (g.subject_kind, g.subject_name) in BROAD_SUBJECTS or \
            (g.subject_kind == "Group" and g.subject_name.startswith("system:serviceaccounts:"))
        if g.subject_kind != "ServiceAccount" and not broad:
            continue
        node_id = subject_id(view, g.subject_kind, g.subject_name, g.subject_ns)
        if node_id is None:
            continue
        wide = g.role.namespace is None
        subject = f"{g.subject_ns}/{g.subject_name}" if g.subject_ns else g.subject_name
        fid = "K8S-RBAC-001" if g.subject_kind == "ServiceAccount" else "K8S-RBAC-003"
        what = "ServiceAccount" if fid == "K8S-RBAC-001" else f"{g.subject_kind} (every identity of that kind)"
        out.append(builder.add_finding(
            fid, node_id, severity="CRITICAL" if wide else "HIGH",
            title=f"{what} {subject} bound to {g.role.name} (cluster {view.data.name})",
            description=(f"{g.binding_kind} {g.binding!r} grants {subject} every verb on every resource "
                         + ("in the whole cluster." if wide else f"in namespace {g.role.namespace}.")
                         + (" Every pod running as this service account controls the cluster."
                            if fid == "K8S-RBAC-001" else " Anyone in that group or user gets these rights.")),
            evidence={"binding": g.binding, "binding_kind": g.binding_kind, "role": g.role.name,
                      "scope": "cluster" if wide else g.role.namespace},
            matched_actions=["*"], region=view.region, entity=f"{g.subject_kind.lower()}/{view.data.name}/{subject}",
            entity_arn=node_id, resource=[node_id], source_type="k8s_rbac", source_policy=g.binding))
    return out


def _wildcard_role_findings(builder: Any, view: ClusterView) -> List[str]:
    out = []
    for kind, key in (("Role", "roles"), ("ClusterRole", "cluster_roles")):
        for r in view.data.items(key):
            name, ns = name_of(r), namespace_of(r) if kind == "Role" else None
            node = role_id(view.arn, kind, name, ns) if name else None
            if node is None or builtin(r, name or "") or not is_wildcard([mapping(x) for x in seq(r.get("rules"))]):
                continue
            label = f"{ns}/{name}" if ns else name
            out.append(builder.add_finding(
                "K8S-RBAC-002", node, severity="HIGH", title=f"{kind} {label} allows * on * (cluster {view.data.name})",
                description=(f"{kind} {label!r} allows every verb on every resource; whoever is bound to it has "
                             "unrestricted access " + ("to the cluster." if kind == "ClusterRole" else
                                                       f"to namespace {ns}.")),
                evidence={"role_kind": kind}, matched_actions=["*"], region=view.region,
                entity=f"k8srole/{view.data.name}/{ns or 'cluster'}/{name}", entity_arn=node, resource=[node],
                source_type="k8s_rbac", source_policy=name))
    return out


# ── entry point ──────────────────────────────────────────────────────────────

def rbac_model(ctx: Any, view: ClusterView) -> Rbac:
    """The cluster's RBAC model, shared by the RBAC and EKS-identity analyzers (``ctx.shared``)."""
    store = ctx.shared.setdefault("k8s.rbac", {})
    if view.arn not in store:
        store[view.arn] = build_rbac(view)
    return store[view.arn]


def run_rbac(ctx: Any, builder: Any) -> int:
    from aws_enumerator.engine.analyzers.k8s.eks_identity import mapped_identities

    count = 0
    for view in cluster_views(ctx):
        model = rbac_model(ctx, view)
        mapped = mapped_identities(view, model, ctx)     # access entries / aws-auth: their groups and roles
        add_superuser(view, model)
        add_roles(builder, view, model)
        count += add_bindings(builder, view, model)
        add_memberships(builder, view, model)
        add_run_as(builder, view, model, held_roles(model, mapped.role_ids))
        _binding_findings(builder, view, model)
        _wildcard_role_findings(builder, view)
    return count


__all__ = ["BROAD_SUBJECTS", "BUILTIN_RULES", "Grant", "Rbac", "RoleRef", "SUPERUSER_GROUP", "add_bindings",
           "add_memberships", "add_roles", "add_run_as", "add_superuser", "admin_like", "build_rbac", "builtin",
           "ensure_role", "ensure_subject", "held_roles", "is_wildcard", "rbac_model", "resource_matches",
           "role_for", "role_label", "rule_allows", "run_as", "run_rbac", "subject_id"]
