"""EKS clusters and the IAM-to-Kubernetes identity data around them (collectors-cli.md §5.14).

Every list call follows pagination (F-107). For each cluster the module also reads its access entries
(only when ``accessConfig.authenticationMode`` is ``API`` or ``API_AND_CONFIG_MAP``; a ``CONFIG_MAP`` cluster
records a deliberate skip and an empty list) with their associated access policies, and its EKS Pod Identity
associations (F-050). Add-on ``configurationValues`` are never written, only whether they are set.

Output (``<region>/eks/``):

``clusters.json``
    list: the full ``DescribeCluster`` result per cluster; a failed describe keeps
    ``{name, arn, CollectionErrors}``.
``nodegroups.json``
    dict ``{cluster: [DescribeNodegroup ...]}``; a failed describe keeps
    ``{nodegroupName, clusterName, CollectionErrors}``.
``fargate_profiles.json``
    dict ``{cluster: [DescribeFargateProfile ...]}`` (same failure shape, ``fargateProfileName``).
``addons.json``
    dict ``{cluster: [DescribeAddon ...]}`` with ``configurationValues`` replaced by
    ``configurationValuesPresent: bool``.
``access_entries.json``
    dict ``{cluster: [DescribeAccessEntry + associatedAccessPolicies: [{policyArn, accessScope{type,
    namespaces}, associatedAt, modifiedAt}] | null]}``; ``[]`` for a ``CONFIG_MAP`` cluster.
``pod_identity_associations.json``
    dict ``{cluster: [DescribePodIdentityAssociation ...]}`` (``roleArn`` is ``null`` when the describe failed).

In the dicts a cluster whose listing call failed has **no key** (unknown); the failure is in
``_coverage.json`` (``item_errors``). The module returns ``{"clusters": [...], "namespaces": {cluster:
[namespaces named by access-entry scopes and Pod Identity]}}`` for the k8s module (no disk reads, F-108).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="eks", scope="regional", output_dir="eks", services=("eks",),
    tier=1, cost="low", noise="low", default=True, groups=("@compute", "@k8s"),
    actions=(
        "eks:ListClusters", "eks:DescribeCluster", "eks:ListNodegroups", "eks:DescribeNodegroup",
        "eks:ListFargateProfiles", "eks:DescribeFargateProfile", "eks:ListAddons", "eks:DescribeAddon",
        "eks:ListAccessEntries", "eks:DescribeAccessEntry", "eks:ListAssociatedAccessPolicies",
        "eks:ListPodIdentityAssociations", "eks:DescribePodIdentityAssociation",
    ),
    probe=("eks", "ListClusters", (("maxResults", 1),)),
    outputs=(
        ("clusters.json", "list"), ("nodegroups.json", "dict"), ("fargate_profiles.json", "dict"),
        ("addons.json", "dict"), ("access_entries.json", "dict"), ("pod_identity_associations.json", "dict"),
    ),
    description=("EKS clusters, node groups, Fargate profiles, add-ons, access entries and Pod Identity "
                 "associations"),
)

_PAGE = 100  # maxResults upper bound of the EKS list operations
#: Access entries exist only in these authentication modes; CONFIG_MAP clusters use aws-auth alone.
_ACCESS_ENTRY_MODES = ("API", "API_AND_CONFIG_MAP")


def _failure(item: Dict[str, Any], result: Any) -> Dict[str, Any]:
    error = result.collection_error()
    if error:
        item["CollectionErrors"] = [error]
    return item


class _Cluster:
    """Everything read for one cluster."""

    def __init__(self, ctx: Any, client: Any, name: str):
        self.ctx = ctx
        self.client = client
        self.name = name
        self.arn = ctx.arn("eks", f"cluster/{name}")
        self.info: Dict[str, Any] = {"name": name, "arn": self.arn}
        self.namespaces: Set[str] = set()

    def describe(self) -> Dict[str, Any]:
        r = self.ctx.call(self.client, "describe_cluster", item=self.arn, name=self.name)
        cluster = r.get("cluster") if r.has_data else None
        if isinstance(cluster, dict):
            self.info = cluster
            self.arn = cluster.get("arn") or self.arn
        else:
            self.info = _failure({"name": self.name, "arn": self.arn}, r)
        return self.info

    def _listing(self, op: str, key: str) -> Optional[List[Any]]:
        """All pages of one per-cluster listing, or ``None`` when it failed (the key is then omitted)."""
        r = self.ctx.paginate(self.client, op, key, page_size=_PAGE, item=self.arn, clusterName=self.name)
        if r.ok:
            return [] if r.not_configured else list(r.value)
        return None

    def _described(self, names: List[str], op: str, param: str, key: str, item_kind: str) -> List[Dict[str, Any]]:
        out = []
        for value in sorted({n for n in names if isinstance(n, str)}):
            item = self.ctx.arn("eks", f"{item_kind}/{self.name}/{value}")
            r = self.ctx.call(self.client, op, item=item, clusterName=self.name, **{param: value})
            doc = r.get(key) if r.has_data else None
            out.append(doc if isinstance(doc, dict) else _failure({param: value, "clusterName": self.name}, r))
        return out

    def nodegroups(self) -> Optional[List[Dict[str, Any]]]:
        names = self._listing("list_nodegroups", "nodegroups")
        if names is None:
            return None
        return self._described(names, "describe_nodegroup", "nodegroupName", "nodegroup", "nodegroup")

    def fargate_profiles(self) -> Optional[List[Dict[str, Any]]]:
        names = self._listing("list_fargate_profiles", "fargateProfileNames")
        if names is None:
            return None
        return self._described(names, "describe_fargate_profile", "fargateProfileName", "fargateProfile",
                               "fargateprofile")

    def addons(self) -> Optional[List[Dict[str, Any]]]:
        names = self._listing("list_addons", "addons")
        if names is None:
            return None
        out = []
        for addon in self._described(names, "describe_addon", "addonName", "addon", "addon"):
            if "CollectionErrors" not in addon:
                addon = dict(addon)
                addon["configurationValuesPresent"] = bool(addon.pop("configurationValues", None))
            out.append(addon)
        return out

    def access_entries(self) -> Optional[List[Dict[str, Any]]]:
        access_config = self.info.get("accessConfig")
        mode = access_config.get("authenticationMode") if isinstance(access_config, dict) else None
        if mode is not None and mode not in _ACCESS_ENTRY_MODES:
            self.ctx.cov.skip("eks:ListAccessEntries", f"AuthenticationMode:{mode}", item=self.arn)
            return []
        principals = self._listing("list_access_entries", "accessEntries")
        if principals is None:
            return None
        return [self._access_entry(p) for p in sorted({p for p in principals if isinstance(p, str)})]

    def _access_entry(self, principal: str) -> Dict[str, Any]:
        item = f"{self.arn}/access-entry/{principal}"
        r = self.ctx.call(self.client, "describe_access_entry", item=item, clusterName=self.name,
                          principalArn=principal)
        entry = r.get("accessEntry") if r.has_data else None
        entry = dict(entry) if isinstance(entry, dict) else _failure({"principalArn": principal,
                                                                       "clusterName": self.name}, r)
        p = self.ctx.paginate(self.client, "list_associated_access_policies", "associatedAccessPolicies",
                              page_size=_PAGE, item=item, clusterName=self.name, principalArn=principal)
        if p.ok:
            policies = sorted((x for x in p.value if isinstance(x, dict)), key=lambda x: str(x.get("policyArn")))
            entry["associatedAccessPolicies"] = policies
            for policy in policies:
                scope = policy.get("accessScope") if isinstance(policy.get("accessScope"), dict) else {}
                self.namespaces.update(n for n in scope.get("namespaces") or [] if isinstance(n, str))
        else:
            entry["associatedAccessPolicies"] = None
            entry.setdefault("CollectionErrors", []).append(p.collection_error())
        return entry

    def pod_identity_associations(self) -> Optional[List[Dict[str, Any]]]:
        listed = self._listing("list_pod_identity_associations", "associations")
        if listed is None:
            return None
        out = []
        for summary in sorted((a for a in listed if isinstance(a, dict)), key=lambda a: str(a.get("associationId"))):
            item = summary.get("associationArn") or f"{self.arn}/podidentityassociation/{summary.get('associationId')}"
            r = self.ctx.call(self.client, "describe_pod_identity_association", item=item, clusterName=self.name,
                              associationId=summary.get("associationId"))
            doc = r.get("association") if r.has_data else None
            assoc = doc if isinstance(doc, dict) else _failure(dict(summary, roleArn=None), r)
            if isinstance(assoc.get("namespace"), str):
                self.namespaces.add(assoc["namespace"])
            out.append(assoc)
        return out


def _per_cluster(ctx: Any, cluster: _Cluster, files: Dict[str, Dict[str, Any]]) -> None:
    for section, file, reader in (
        ("nodegroups", "nodegroups.json", cluster.nodegroups),
        ("fargate_profiles", "fargate_profiles.json", cluster.fargate_profiles),
        ("addons", "addons.json", cluster.addons),
        ("access_entries", "access_entries.json", cluster.access_entries),
        ("pod_identity", "pod_identity_associations.json", cluster.pod_identity_associations),
    ):
        with ctx.section(section):
            value = reader()
            if value is not None:
                files[file][cluster.name] = value


def collect(ctx: Any) -> Dict[str, Any]:
    client = ctx.client("eks")
    names: List[str] = []
    with ctx.section("clusters"):
        listed = ctx.paginate(client, "list_clusters", "clusters", page_size=_PAGE, primary=True)
        names = sorted({n for n in listed.value if isinstance(n, str)})
    clusters: List[Dict[str, Any]] = []
    files: Dict[str, Dict[str, Any]] = {name: {} for name in (
        "nodegroups.json", "fargate_profiles.json", "addons.json", "access_entries.json",
        "pod_identity_associations.json")}
    namespaces: Dict[str, List[str]] = {}
    for name in names:
        cluster = _Cluster(ctx, client, name)
        with ctx.section("describe"):
            cluster.describe()
        clusters.append(cluster.info)
        _per_cluster(ctx, cluster, files)
        namespaces[name] = sorted(cluster.namespaces)
    with ctx.section("write"):
        ctx.out.write("clusters.json", clusters)
        for file, data in files.items():
            ctx.out.write(file, data)
    ctx.log.info("%d cluster(s)", len(clusters))
    return {"clusters": clusters, "namespaces": namespaces}
