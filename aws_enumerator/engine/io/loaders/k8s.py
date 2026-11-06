"""EKS clusters and their Kubernetes objects: the ``k8s`` loader (E-k8s, Wave 2).

Reads only the explicit units of the analysis context (``ctx.region_dirs``), never sibling directories
(F-010, F-025, F-063). Two layouts are read:

* **v2 collectors** (C-K8s, Wave 1): ``<region>/eks/{clusters,nodegroups,fargate_profiles,access_entries,
  pod_identity_associations}.json`` and ``<region>/k8s/<cluster dir>/`` with projected objects (no Secret
  values, no env values, F-009/F-054), ``nodes.json``, ``aws_auth.json``, ``self_rules.json`` and
  ``cluster_info.json`` (``auth_status`` plus a per-list ``resources`` status). ``secrets.json`` exists only
  with ``--k8s-secrets`` and is **not** needed: Secret nodes come from pod references (F-150).
* **legacy** (d13c215): the same file names under ``<region>/eks`` and ``<region>/k8s/<cluster name>``, full
  ``to_dict()`` objects and ``{"error": ...}`` / ``{"Error": ...}`` stubs for failed calls.

**Unknown is never empty** (coverage-schema.md §1): a list that was not read (stub, file missing, a cluster
key missing from an EKS map, ``null``) is ``None`` in :class:`ClusterData`, with its facet status in
``object_status`` / ``eks_status``; analyzers turn that into node coverage and gaps instead of "nothing
there". The cluster ARN (from the record, or built from the region) qualifies every Kubernetes id, so
same-named clusters of two regions never collide (F-025).

``LoadResult.data`` is a mapping: ``{"clusters": {region: [records]}, "model": K8sData}``: the raw cluster
records per region, and ``model``, what the analyzers read.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from aws_enumerator.engine.io.loaders import LoadResult, region_items

log = logging.getLogger(__name__)

#: Kubernetes list files read per cluster (``secrets`` only when the operator opted in).
K8S_LISTS: Tuple[str, ...] = (
    "namespaces", "pods", "service_accounts", "roles", "cluster_roles", "role_bindings", "cluster_role_bindings",
    "services", "ingresses", "nodes", "secrets",
)
#: Per-cluster EKS maps (``{cluster name: [records]}``) under ``<region>/eks/``.
EKS_MAPS: Tuple[str, ...] = ("nodegroups", "fargate_profiles", "access_entries", "pod_identity_associations")
#: Lists the d13c215 collector never wrote (their absence in a legacy report is "not collected", not a gap).
_NEW_IN_V2 = frozenset({"nodes", "access_entries", "pod_identity_associations", "self_rules", "aws_auth"})

#: Facet status (graph-json.md §7.2) of a ``cluster_info.resources[*].status`` value (C-K8s collector).
_RESOURCE_STATUS = {"ok": "complete", "partial": "partial", "denied": "denied", "error": "error",
                    "throttled": "throttled", "skipped": "skipped"}
_CLUSTER_ARN = re.compile(r"^arn:aws(?:-[a-z]+)*:eks:[a-z]{2}(?:-[a-z]+)+-\d+:\d{12}:cluster/[^/]+$")
_STUB_KEYS = ("Error", "error", "_error")
#: Facet statuses of ``eks:ListClusters`` that leave a region's cluster list unknown.
_LISTING_UNKNOWN = frozenset({"denied", "error", "throttled"})


# ── records ──────────────────────────────────────────────────────────────────

@dataclass
class ClusterData:
    """Everything collected about one EKS cluster in one region (``None`` = unknown, never "empty")."""

    region: str
    name: str
    arn: str
    record: Dict[str, Any]
    layout: str                                           # "v2" | "legacy"
    describe_ok: bool = True
    eks: Dict[str, Optional[List[Dict[str, Any]]]] = field(default_factory=dict)
    eks_status: Dict[str, str] = field(default_factory=dict)
    k8s_dir: Optional[Path] = None
    info: Optional[Dict[str, Any]] = None
    objects: Dict[str, Optional[List[Dict[str, Any]]]] = field(default_factory=dict)
    object_status: Dict[str, str] = field(default_factory=dict)
    aws_auth: Optional[Dict[str, Any]] = None
    self_rules: Optional[List[Dict[str, Any]]] = None
    gaps: List[str] = field(default_factory=list)

    @property
    def auth_status(self) -> Optional[str]:
        """``cluster_info.auth_status`` (``ok``, ``failed``, ``unreachable`` …) or ``None`` when not written."""
        value = (self.info or {}).get("auth_status")
        return value if isinstance(value, str) and value else None

    def known(self, kind: str) -> bool:
        return self.objects.get(kind) is not None

    def items(self, kind: str) -> List[Dict[str, Any]]:
        """The records of one Kubernetes list (``[]`` when unknown: check :meth:`known` first)."""
        return list(self.objects.get(kind) or ())

    def eks_items(self, key: str) -> List[Dict[str, Any]]:
        return list(self.eks.get(key) or ())


@dataclass(frozen=True)
class InstanceFacts:
    """The EC2 facts the pod → node → node group path needs (IMDS reachability, F-033)."""

    instance_id: str
    region: str
    private_dns: Optional[str]
    metadata: Optional[Dict[str, Any]]                    # MetadataOptions, ``None`` when not collected
    nodegroup: Optional[str]                              # tag ``eks:nodegroup-name``
    cluster: Optional[str]                                # tag ``eks:cluster-name``
    state: Optional[str]


@dataclass
class K8sData:
    """The ``model`` of the loader: clusters sorted by (region, name), EC2 node facts by instance id."""

    clusters: Tuple[ClusterData, ...] = ()
    instances: Dict[str, InstanceFacts] = field(default_factory=dict)
    instances_by_dns: Dict[Tuple[str, str], str] = field(default_factory=dict)
    regions_unknown: Tuple[str, ...] = ()                 # regions whose cluster list could not be read


# ── small readers ────────────────────────────────────────────────────────────

def _read(path: Path) -> Tuple[Any, str]:
    """``(data, status)``: ``ok``, ``missing``, ``invalid`` or ``error-stub``."""
    from aws_enumerator.engine.io.fs import read_json

    res = read_json(path)
    return res.data, res.status


def _stub_code(record: Mapping[str, Any]) -> Optional[str]:
    """A d13c215 per-item failure (``{"name": ..., "Error": ...}``): its error code, else ``None``."""
    from aws_enumerator.engine.io.fs import error_code_from_stub

    for key in _STUB_KEYS:
        if key in record and record[key]:
            return error_code_from_stub(record[key]) or "Error"
    return None


def _status_of(read_status: str, *, legacy: bool, name: str) -> str:
    """Facet status of a file that was not readable as data."""
    if read_status == "missing":
        if legacy and name in _NEW_IN_V2:
            return "not-collected"
        return "legacy-unknown" if legacy else "not-collected"
    return "error"


def _dict_list(value: Any) -> Optional[List[Dict[str, Any]]]:
    if not isinstance(value, list):
        return None
    return [v for v in value if isinstance(v, dict)]


def _tags(value: Any) -> Dict[str, str]:
    """EC2 tags as a map, from the v2 map form or the d13c215 ``[{Key, Value}]`` list."""
    if isinstance(value, Mapping):
        return {str(k): "" if v is None else str(v) for k, v in value.items()}
    out: Dict[str, str] = {}
    for t in value if isinstance(value, list) else ():
        if isinstance(t, Mapping) and isinstance(t.get("Key"), str):
            out[t["Key"]] = "" if t.get("Value") is None else str(t.get("Value"))
    return out


# ── EKS ──────────────────────────────────────────────────────────────────────

def cluster_arn_for(record: Mapping[str, Any], *, region: str, account: str, partition: str) -> Optional[str]:
    """The cluster's ARN: the collected one when it is well formed, else built from the region (F-025)."""
    arn = record.get("arn")
    if isinstance(arn, str) and _CLUSTER_ARN.match(arn):
        return arn
    name = record.get("name")
    if not isinstance(name, str) or not name or "/" in name:
        return None
    built = f"arn:{partition}:eks:{region}:{account}:cluster/{name}"
    return built if _CLUSTER_ARN.match(built) else None


def _eks_maps(edir: Path, legacy: bool) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    """``{map name: {cluster: value}}`` and the read status of each map file."""
    maps: Dict[str, Dict[str, Any]] = {}
    statuses: Dict[str, str] = {}
    for key in EKS_MAPS:
        data, status = _read(edir / f"{key}.json")
        if status == "ok" and isinstance(data, dict):
            maps[key], statuses[key] = data, "complete"
        else:
            maps[key] = {}
            statuses[key] = _status_of(status if status != "ok" else "invalid", legacy=legacy, name=key)
    return maps, statuses


def _eks_value(maps: Mapping[str, Mapping[str, Any]], statuses: Mapping[str, str], key: str, name: str,
               legacy: bool) -> Tuple[Optional[List[Dict[str, Any]]], str]:
    """One cluster's entry of an EKS map: a missing key or an ``{"Error"}`` value is unknown."""
    if statuses[key] != "complete":
        return None, statuses[key]
    value = maps[key].get(name)
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)], "complete"
    if value is None:
        # v2: a failed listing omits the key; legacy: the key is omitted when DescribeCluster failed
        return None, "not-collected" if legacy and key in _NEW_IN_V2 else "error"
    return None, "error"


# ── Kubernetes objects ───────────────────────────────────────────────────────

def _k8s_dir(k8s_root: Path, name: str, arn: str) -> Optional[Path]:
    """``<region>/k8s/<cluster>``: the cluster name, or (v2, unsafe names) the dir whose info names the ARN."""
    from aws_enumerator.engine.io.fs import ls_sorted

    direct = k8s_root / name
    if (direct / "cluster_info.json").is_file() or direct.is_dir():
        return direct
    for entry in ls_sorted(k8s_root):
        info, status = _read(k8s_root / entry / "cluster_info.json")
        if status == "ok" and isinstance(info, dict) and (info.get("arn") == arn or info.get("name") == name):
            return k8s_root / entry
    return None


def _resource_status(info: Optional[Mapping[str, Any]], kind: str) -> Optional[str]:
    resources = (info or {}).get("resources")
    entry = resources.get(kind) if isinstance(resources, Mapping) else None
    if not isinstance(entry, Mapping):
        return None
    return _RESOURCE_STATUS.get(str(entry.get("status")), "error")


def _read_objects(cluster: ClusterData) -> None:
    """Fill ``objects`` / ``object_status`` / ``aws_auth`` / ``self_rules`` from the cluster's k8s directory.

    The status of a readable list is the collector's own per-list verdict (``cluster_info.resources``, v2) or
    ``complete`` (legacy: the d13c215 collector wrote an error stub instead of a list when a call failed).
    """
    legacy = cluster.layout == "legacy"
    kdir = cluster.k8s_dir
    for kind in K8S_LISTS:
        if kdir is None:
            cluster.objects[kind], cluster.object_status[kind] = None, "not-collected"
            continue
        data, status = _read(kdir / f"{kind}.json")
        items = _dict_list(data) if status == "ok" else None
        if items is None:
            missing = status == "missing"
            cluster.objects[kind] = None
            cluster.object_status[kind] = ("not-collected" if missing and kind == "secrets" else
                                           _status_of(status if status != "ok" else "invalid", legacy=legacy,
                                                      name=kind))
            continue
        facet = _resource_status(cluster.info, kind) or "complete"
        # a list the collector wrote although the call failed holds what it got (often nothing): unknown, not empty
        usable = facet in ("complete", "partial") or bool(items)
        cluster.objects[kind] = items if usable else None
        cluster.object_status[kind] = facet
    if kdir is None:
        return
    auth, status = _read(kdir / "aws_auth.json")
    cluster.aws_auth = auth if status == "ok" and isinstance(auth, dict) else None
    rules, status = _read(kdir / "self_rules.json")
    cluster.self_rules = _dict_list(rules) if status == "ok" else None


def _cluster(record: Dict[str, Any], *, region: str, rdir: Path, account: str, partition: str, layout: str,
             maps: Mapping[str, Mapping[str, Any]], statuses: Mapping[str, str]) -> Optional[ClusterData]:
    name = record.get("name")
    arn = cluster_arn_for(record, region=region, account=account, partition=partition)
    if not isinstance(name, str) or not name or arn is None:
        return None
    legacy = layout == "legacy"
    failed = bool(record.get("CollectionErrors")) or _stub_code(record) is not None
    cluster = ClusterData(region=region, name=name, arn=arn, record=record, layout=layout, describe_ok=not failed)
    for key in EKS_MAPS:
        cluster.eks[key], cluster.eks_status[key] = _eks_value(maps, statuses, key, name, legacy)
    kdir = _k8s_dir(rdir / "k8s", name, arn)
    cluster.k8s_dir = kdir
    if kdir is not None:
        info, status = _read(kdir / "cluster_info.json")
        cluster.info = info if status == "ok" and isinstance(info, dict) else None
    _read_objects(cluster)
    if failed:
        cluster.gaps.append("eks:DescribeCluster:failed")
    return cluster


def _clusters_of_region(region: str, rdir: Path, *, account: str, partition: str, layout: str
                        ) -> Tuple[List[Dict[str, Any]], List[ClusterData], bool, int]:
    """``(raw records, clusters, known, unusable)``; ``known`` is False when the cluster list itself was
    unreadable, ``unusable`` counts records without a name or ARN that can form an id (never guessed)."""
    data, status = _read(rdir / "eks" / "clusters.json")
    records = _dict_list(data) if status == "ok" else None
    if records is None:
        return [], [], status == "missing", 0
    maps, statuses = _eks_maps(rdir / "eks", layout == "legacy")
    out = []
    for rec in records:
        cluster = _cluster(rec, region=region, rdir=rdir, account=account, partition=partition, layout=layout,
                           maps=maps, statuses=statuses)
        if cluster is not None:
            out.append(cluster)
    return records, sorted(out, key=lambda c: (c.region, c.name, c.arn)), True, len(records) - len(out)


# ── EC2 node facts ───────────────────────────────────────────────────────────

def _instances(region: str, rdir: Path) -> List[InstanceFacts]:
    data, status = _read(rdir / "ec2" / "instances.json")
    records = (_dict_list(data) or []) if status == "ok" else []
    out = []
    for rec in records:
        iid = rec.get("InstanceId")
        if not isinstance(iid, str) or not iid:
            continue
        tags = _tags(rec.get("Tags"))
        state = rec.get("State")
        state = state.get("Name") if isinstance(state, Mapping) else state
        meta = rec.get("MetadataOptions") if isinstance(rec.get("MetadataOptions"), dict) else None
        dns = rec.get("PrivateDnsName") if isinstance(rec.get("PrivateDnsName"), str) else None
        out.append(InstanceFacts(iid, region, dns or None, dict(meta) if meta else None,
                                 tags.get("eks:nodegroup-name") or None, tags.get("eks:cluster-name") or None,
                                 state if isinstance(state, str) else None))
    return out


# ── entry point ──────────────────────────────────────────────────────────────

def build_model(region_dirs: Mapping[str, Any], *, account: str, partition: str, layout: str,
                listing_status: Optional[Callable[[str], str]] = None,
                ) -> Tuple[K8sData, Dict[str, List[Dict[str, Any]]], Dict[str, str], int]:
    """The model plus the raw ``clusters`` table, the gaps and the number of cluster files read.

    ``listing_status(region)`` is the facet status of ``eks:ListClusters`` in the run's coverage (v2 runs): a
    listing that was denied or failed leaves the region's clusters unknown even though ``clusters.json`` is a
    readable ``[]``.
    """
    clusters: List[ClusterData] = []
    raw: Dict[str, List[Dict[str, Any]]] = {}
    gaps: Dict[str, str] = {}
    unknown: List[str] = []
    model = K8sData()
    seen = unusable = 0
    for region, base in region_items(region_dirs):
        rdir = Path(base)
        records, found, known, bad = _clusters_of_region(region, rdir, account=account, partition=partition,
                                                         layout=layout)
        raw[region] = records
        unusable += bad
        if (rdir / "eks" / "clusters.json").exists():
            seen += 1
            if not known:
                unknown.append(region)
                gaps[f"{region}/eks/clusters.json:error"] = f"{region}/eks/clusters.json could not be read"
            elif listing_status is not None and listing_status(region) in _LISTING_UNKNOWN:
                unknown.append(region)
        clusters.extend(found)
        if found:
            for inst in _instances(region, rdir):
                model.instances[inst.instance_id] = inst
                if inst.private_dns:
                    model.instances_by_dns[(region, inst.private_dns.lower())] = inst.instance_id
    model.clusters = tuple(sorted(clusters, key=lambda c: (c.region, c.name, c.arn)))
    model.regions_unknown = tuple(unknown)
    if unusable:
        gaps["k8s:clusters-unrepresentable"] = (f"{unusable} EKS cluster record(s) without a name or ARN that can "
                                                "form a node id were left out")
    return model, raw, gaps, seen


def load(ctx: Any) -> LoadResult:
    layout = "legacy" if getattr(ctx, "is_legacy", False) else "v2"
    coverage = getattr(ctx, "coverage", None)
    listing = (lambda region: coverage.facet("eks", "eks:ListClusters", region)) if (
        layout == "v2" and coverage is not None) else None
    model, raw, gaps, seen = build_model(dict(ctx.region_dirs), account=ctx.account_id, partition=ctx.partition,
                                         layout=layout, listing_status=listing)
    status = "missing" if seen == 0 else ("partial" if gaps else "ok")
    log.debug("k8s loader: %d cluster(s) in %d region(s)", len(model.clusters), len(raw))
    return LoadResult({"clusters": raw, "model": model}, status, gaps, files=seen)


def model_of(data: Any) -> Optional[K8sData]:
    """The :class:`K8sData` inside ``ctx.data["k8s"]`` (``None`` when the loader did not run)."""
    if isinstance(data, Mapping) and isinstance(data.get("model"), K8sData):
        return data["model"]
    return None


def iter_clusters(data: Any) -> Iterable[ClusterData]:
    model = model_of(data)
    return model.clusters if model is not None else ()


__all__ = ["ClusterData", "EKS_MAPS", "InstanceFacts", "K8S_LISTS", "K8sData", "build_model", "cluster_arn_for",
           "iter_clusters", "load", "model_of"]
