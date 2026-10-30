"""EKS identity (E-k8s): IAM principals mapped into Kubernetes by access entries and ``aws-auth`` (F-050, F-033).

Two sources say which Kubernetes identity an IAM principal becomes when it authenticates to the cluster:

* **EKS access entries** (``eks/access_entries.json``, ``API`` and ``API_AND_CONFIG_MAP`` clusters):
  ``EKS_ACCESS_ENTRY`` principal → each ``kubernetesGroups`` group, → the entry's ``username`` when an RBAC
  binding names it, and → one node per associated **access policy**. Access policies are EKS-managed
  authorizations, not ClusterRoles of the cluster: they get their own ``k8srole`` nodes
  (``ClusterRole/_/AccessPolicy:<name>`` for a cluster scope, ``Role/<ns>/AccessPolicy:<name>`` per namespace of
  a namespace scope) with the rules of the Kubernetes role AWS documents as equivalent
  (:data:`ACCESS_POLICY_RULES`), so ``CAN_RUN_AS_SA`` follows from them like from any held role.
* **The ``aws-auth`` ConfigMap** (``k8s/<cluster>/aws_auth.json``, data only, ``CONFIG_MAP`` and
  ``API_AND_CONFIG_MAP`` clusters): ``AWS_AUTH_MAPPING`` principal → groups and bound username. ``mapRoles``
  matches the way the AWS IAM authenticator does: the caller's role session is reduced to
  ``arn:<p>:iam::<account>:role/<name>`` (**no path**), so an entry without a path maps the role of that name in
  that account (node-ids.md rule 3, the session → role mapping), and an entry *with* a path never matches at run
  time (counted in ``props.aws_auth_ineffective_mappings``, no edge). ``mapUsers`` matches the user ARN exactly.
  ``mapAccounts`` maps every principal of the account to its ARN with no group.

Every mapped identity is also in ``system:authenticated``; that group gets an edge when a binding names it.
``system:masters`` is bound to ``cluster-admin`` by the RBAC module (``rbac.add_superuser``).
The authentication mode decides which source counts: ``API`` ignores ``aws-auth``, ``CONFIG_MAP`` has no access
entries; a cluster record without ``accessConfig`` (older clusters, old reports) is treated as using both.

Findings: **EKS-ADMIN-001** (INFO) an IAM principal that is cluster administrator (``system:masters`` or
``AmazonEKSClusterAdminPolicy`` cluster-wide), one per (cluster, principal); **EKS-AUTH-MAP-001** an account in
``mapAccounts`` (LOW for the cluster's own account, MEDIUM for another account).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from aws_enumerator.engine.analyzers.k8s.rbac import (
    BUILTIN_RULES, SUPERUSER_GROUP, Rbac, RoleRef, ensure_role, ensure_subject, rbac_model,
)
from aws_enumerator.engine.analyzers.k8s.util import ClusterView, cluster_views, k8s_id, mapping, seq, text
from aws_enumerator.engine.graph import ids

#: EKS access policy name → the Kubernetes default role whose rules it is documented to match.
ACCESS_POLICY_RULES: Mapping[str, str] = {
    "AmazonEKSClusterAdminPolicy": "cluster-admin",
    "AmazonEKSAdminPolicy": "admin",
    "AmazonEKSEditPolicy": "edit",
    "AmazonEKSViewPolicy": "view",
    "AmazonEKSAdminViewPolicy": "view",
}
ALL_AUTHENTICATED = "system:authenticated"
ADMIN_ACCESS_POLICY = "AmazonEKSClusterAdminPolicy"
#: Mapping sources (``evidence.source``).
SRC_ACCESS_ENTRY, SRC_MAP_ROLES, SRC_MAP_USERS, SRC_MAP_ACCOUNTS = (
    "access-entry", "aws-auth:mapRoles", "aws-auth:mapUsers", "aws-auth:mapAccounts")
_EDGE_OF = {SRC_ACCESS_ENTRY: "EKS_ACCESS_ENTRY", SRC_MAP_ROLES: "AWS_AUTH_MAPPING",
            SRC_MAP_USERS: "AWS_AUTH_MAPPING", SRC_MAP_ACCOUNTS: "AWS_AUTH_MAPPING"}
_SHARED_KEY = "k8s.mapped"


# ── the model ────────────────────────────────────────────────────────────────

@dataclass
class Mapping_:
    """One IAM principal (ARN as written in the mapping) and the Kubernetes identity it becomes."""

    principal_arn: str
    source: str
    username: Optional[str]
    groups: Tuple[str, ...]
    roles: Tuple[RoleRef, ...] = ()
    entry_type: Optional[str] = None
    policies: Tuple[str, ...] = ()


@dataclass
class Mapped:
    """Every mapping of one cluster plus what the RBAC module needs from them."""

    mappings: List[Mapping_] = field(default_factory=list)
    role_ids: Set[str] = field(default_factory=set)
    accounts: List[str] = field(default_factory=list)
    ineffective: int = 0
    aws_auth_used: bool = True
    access_entries_used: bool = True


def auth_mode(view: ClusterView) -> Tuple[bool, bool]:
    """``(access entries used, aws-auth used)`` from ``accessConfig.authenticationMode``."""
    mode = text(mapping(view.data.record.get("accessConfig")).get("authenticationMode"))
    if mode == "API":
        return True, False
    if mode == "CONFIG_MAP":
        return False, True
    return True, True


def policy_name(policy_arn: Any) -> Optional[str]:
    """``arn:aws:eks::aws:cluster-access-policy/<name>`` → ``<name>``."""
    value = text(policy_arn)
    if value is None or "cluster-access-policy/" not in value:
        return None
    name = value.rsplit("/", 1)[-1]
    return name if name and ":" not in name else None


def access_policy_role(view: ClusterView, model: Rbac, name: str, namespace: Optional[str]) -> Optional[RoleRef]:
    """The ``k8srole`` node of an access policy (cluster scope when ``namespace`` is ``None``)."""
    node = k8s_id(view.arn, "k8srole", namespace, f"AccessPolicy:{name}",
                  k8s_kind="Role" if namespace else "ClusterRole")
    if node is None:
        return None
    builtin = ACCESS_POLICY_RULES.get(name)
    ref = model.roles.setdefault(node, RoleRef(node, "AccessPolicy", name, namespace,
                                               "eks-access-policy" if builtin else "unknown"))
    model.rules.setdefault(node, [dict(r) for r in BUILTIN_RULES.get(builtin or "", ())])
    return ref


def _entry_roles(view: ClusterView, model: Rbac, entry: Mapping[str, Any]) -> Tuple[List[RoleRef], List[str]]:
    roles: List[RoleRef] = []
    names: List[str] = []
    for assoc in seq(entry.get("associatedAccessPolicies")):
        assoc = mapping(assoc)
        name = policy_name(assoc.get("policyArn"))
        if name is None:
            continue
        names.append(name)
        scope = mapping(assoc.get("accessScope"))
        if text(scope.get("type")) == "namespace":
            spaces = [n for n in (text(x) for x in seq(scope.get("namespaces"))) if n]
        else:
            spaces = [None]
        for ns in spaces:
            ref = access_policy_role(view, model, name, ns)
            if ref is not None:
                roles.append(ref)
    return roles, sorted(set(names))


def _access_entries(view: ClusterView, model: Rbac, out: Mapped) -> None:
    for entry in view.data.eks_items("access_entries"):
        arn = text(entry.get("principalArn"))
        if arn is None:
            continue
        roles, names = _entry_roles(view, model, entry)
        groups = tuple(sorted({g for g in (text(x) for x in seq(entry.get("kubernetesGroups"))) if g}))
        out.mappings.append(Mapping_(arn, SRC_ACCESS_ENTRY, text(entry.get("username")), groups, tuple(roles),
                                     text(entry.get("type")), tuple(names)))
        out.role_ids |= {r.node_id for r in roles}


def _aws_auth(view: ClusterView, out: Mapped) -> None:
    data = view.data.aws_auth
    if not isinstance(data, Mapping):
        return
    for key, source, arn_key in (("map_roles", SRC_MAP_ROLES, "rolearn"), ("map_users", SRC_MAP_USERS, "userarn")):
        for entry in seq(data.get(key)):
            entry = mapping(entry)
            arn = text(entry.get(arn_key))
            if arn is None:
                continue
            groups = tuple(sorted({g for g in (text(x) for x in seq(entry.get("groups"))) if g}))
            out.mappings.append(Mapping_(arn, source, text(entry.get("username")), groups))
    out.accounts = sorted({str(a) for a in seq(data.get("map_accounts")) if isinstance(a, (str, int))})


def mapped_identities(view: ClusterView, model: Rbac, ctx: Any = None) -> Mapped:
    """Every mapping of the cluster; registers the mapped groups and access-policy roles in ``model``."""
    if ctx is not None:
        cached = ctx.shared.get(_SHARED_KEY, {}).get(view.arn)
        if cached is not None:
            return cached
    out = Mapped()
    out.access_entries_used, out.aws_auth_used = auth_mode(view)
    if out.access_entries_used:
        _access_entries(view, model, out)
    if out.aws_auth_used:
        _aws_auth(view, out)
    for m in out.mappings:
        model.groups.update(m.groups)
    if ctx is not None:
        ctx.shared.setdefault(_SHARED_KEY, {})[view.arn] = out
    return out


# ── principal resolution ─────────────────────────────────────────────────────

def _role_by_name(builder: Any, account: str, name: str) -> Optional[str]:
    """The role node named ``name`` in ``account`` (role names are unique per account, case-insensitively)."""
    wanted = name.lower()
    hits = [n.id for n in builder.nodes("role")
            if n.account == account and not n.props.get("placeholder") and n.id.rsplit("/", 1)[-1].lower() == wanted]
    return hits[0] if len(hits) == 1 else None


def resolve_principal(builder: Any, m: Mapping_) -> Tuple[Optional[str], Dict[str, Any]]:
    """``(user or role node id, evidence)`` for a mapping's principal; ``None`` when it maps no node."""
    parts = ids.parse_arn(m.principal_arn)
    if parts is None or parts.service != "iam":
        return None, {"unresolved": "not an IAM user or role ARN"}
    if m.source == SRC_MAP_ROLES and parts.resource.startswith("role/"):
        name = parts.resource[len("role/"):]
        if "/" in name:
            return None, {"ineffective": "aws-auth role ARNs must not contain a path"}
        node = builder.node(m.principal_arn)
        if node is None or node.type != "role" or node.props.get("placeholder"):
            by_name = _role_by_name(builder, parts.account, name)
            if by_name is not None and by_name != m.principal_arn:
                return by_name, {"match": "role-name-in-account (the IAM authenticator drops role paths)"}
    ref = builder.ensure_principal(m.principal_arn)
    if ref.node_type in ("user", "role"):
        return ref.node_id, {"match": "exact-arn"}
    return None, {"unresolved": ref.reason or ref.node_type}


# ── edges and findings ───────────────────────────────────────────────────────

def _targets(builder: Any, view: ClusterView, model: Rbac, m: Mapping_, bound: Set[Tuple[str, str]]
             ) -> List[Tuple[str, Dict[str, Any]]]:
    out: List[Tuple[str, Dict[str, Any]]] = []
    groups = set(m.groups)
    if ("Group", ALL_AUTHENTICATED) in bound:
        groups.add(ALL_AUTHENTICATED)
    for group in sorted(groups):
        gid = ensure_subject(builder, view, "Group", group, None)
        if gid is not None:
            out.append((gid, {"kubernetes_group": group, "implicit": group not in m.groups}))
    user = m.username
    if user and "{{" not in user and ("User", user) in bound:
        uid = ensure_subject(builder, view, "User", user, None)
        if uid is not None:
            out.append((uid, {"kubernetes_user": user}))
    for role in m.roles:
        out.append((ensure_role(builder, view, role), {"access_policy": role.name,
                                                        "access_scope": role.namespace or "cluster"}))
    return out


def _is_admin(m: Mapping_) -> bool:
    return SUPERUSER_GROUP in m.groups or any(r.name == ADMIN_ACCESS_POLICY and r.namespace is None for r in m.roles)


def _admin_finding(builder: Any, view: ClusterView, m: Mapping_, principal: str) -> str:
    via = sorted(({f"group {SUPERUSER_GROUP}"} if SUPERUSER_GROUP in m.groups else set())
                 | ({f"access policy {ADMIN_ACCESS_POLICY}"} if any(r.name == ADMIN_ACCESS_POLICY and
                                                                     r.namespace is None for r in m.roles) else set()))
    return builder.add_finding(
        "EKS-ADMIN-001", view.arn, severity="INFO",
        title=f"{principal} is a cluster administrator of EKS cluster {view.data.name}",
        description=(f"The {m.source} mapping of {principal} gives it full control of cluster {view.data.name} "
                     f"({', '.join(via)}). Whoever can use this IAM principal controls every workload, secret "
                     "and service-account identity of the cluster."),
        evidence={"principal": principal, "source": m.source, "via": via}, discriminator=principal,
        related_node_ids=[principal], region=view.region, entity=f"cluster/{view.data.name}",
        entity_arn=view.arn, resource=[view.arn], source_type="eks_identity", source_policy=m.source)


def _accounts_finding(builder: Any, view: ClusterView, account: str) -> str:
    own = account == view.account
    return builder.add_finding(
        "EKS-AUTH-MAP-001", view.arn, severity="LOW" if own else "MEDIUM",
        title=f"aws-auth of cluster {view.data.name} maps every principal of account {account}",
        description=(f"mapAccounts lists {account}: every IAM user and role of "
                     + ("this account" if own else "that other account")
                     + f" can authenticate to cluster {view.data.name} (as its ARN, in system:authenticated). "
                       "Map individual roles instead."),
        evidence={"account": account, "same_account": own}, discriminator=account, region=view.region,
        entity=f"cluster/{view.data.name}", entity_arn=view.arn, resource=[view.arn], source_type="eks_identity",
        source_policy="aws-auth:mapAccounts")


def _account_principals(builder: Any, account: str) -> List[str]:
    return [n.id for t in ("user", "role") for n in builder.nodes(t)
            if n.account == account and not n.props.get("placeholder")]


def add_mappings(builder: Any, view: ClusterView, model: Rbac, mapped: Mapped) -> int:
    """The mapping edges and findings of one cluster; returns the number of edges."""
    bound = {(g.subject_kind, g.subject_name) for g in model.grants}
    count = 0
    for m in mapped.mappings:
        principal, how = resolve_principal(builder, m)
        if principal is None:
            mapped.ineffective += 1 if "ineffective" in how else 0
            continue
        for target, extra in _targets(builder, view, model, m, bound):
            builder.add_edge(principal, _EDGE_OF[m.source], target,
                             evidence=dict(how, source=m.source, entry_type=m.entry_type, **extra))
            count += 1
        if _is_admin(m):
            _admin_finding(builder, view, m, principal)
    for account in mapped.accounts:
        _accounts_finding(builder, view, account)
        if ("Group", ALL_AUTHENTICATED) in bound:
            gid = ensure_subject(builder, view, "Group", ALL_AUTHENTICATED, None)
            for principal in _account_principals(builder, account) if gid else ():
                builder.add_edge(principal, "AWS_AUTH_MAPPING", gid,
                                 evidence={"source": SRC_MAP_ACCOUNTS, "kubernetes_group": ALL_AUTHENTICATED,
                                           "implicit": True})
                count += 1
    if mapped.ineffective:
        builder.set_node_props(view.arn, aws_auth_ineffective_mappings=mapped.ineffective)
    return count


def run_eks_identity(ctx: Any, builder: Any) -> int:
    """Access-entry and aws-auth edges for every cluster (after the RBAC module built its model)."""
    count = 0
    for view in cluster_views(ctx):
        model = rbac_model(ctx, view)
        count += add_mappings(builder, view, model, mapped_identities(view, model, ctx))
    return count


__all__ = [
    "ACCESS_POLICY_RULES", "ADMIN_ACCESS_POLICY", "ALL_AUTHENTICATED", "Mapped", "Mapping_", "access_policy_role",
    "add_mappings", "auth_mode", "mapped_identities", "policy_name", "resolve_principal", "run_eks_identity",
]
