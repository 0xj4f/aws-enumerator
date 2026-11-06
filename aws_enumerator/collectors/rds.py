"""RDS: DB instances, Aurora/Multi-AZ clusters, and manual snapshots with their sharing
(never data or credentials).

Output (``<region>/rds/``):

* ``resources.json`` (list), sorted by (``Kind``, ``Arn``). Every item has ``Type: "rds"`` and a ``Kind``:

  - ``instance``: ``{Arn, Name, Public: bool|null, Encrypted: bool|null, KmsKeyId, IAMAuth: bool|null,
    Engine, DBClusterIdentifier|null}``;
  - ``cluster``: ``{Arn, Name, Public: bool|null, Encrypted, KmsKeyId, IAMAuth, Engine, Members: [...]}``;
  - ``snapshot``: ``{Arn, Name, DBInstanceIdentifier, PublicSnapshot: bool|null, SharedAccounts: [...]|null,
    Encrypted, KmsKeyId, CollectionErrors?}``;
  - ``cluster_snapshot``: ``{Arn, Name, DBClusterIdentifier, PublicSnapshot, SharedAccounts, Encrypted,
    KmsKeyId, CollectionErrors?}``.

The snapshot ``restore`` attribute lists ``all`` (public) and the account ids it is shared with:
both are recorded (F-056). When the attribute call fails, ``PublicSnapshot`` and ``SharedAccounts``
are ``null``, never ``false``/``[]`` (F-059). Aurora cluster snapshots come from
``DescribeDBClusterSnapshots``, which ``DescribeDBSnapshots`` does not return (F-056). Only manual
snapshots are listed: automated snapshots cannot be shared.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from aws_enumerator.collectors._common import add_error
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="rds", scope="regional", output_dir="rds", services=("rds",),
    tier=1, cost="low", noise="low", default=True, groups=("@data",),
    actions=("rds:DescribeDBInstances", "rds:DescribeDBSnapshots", "rds:DescribeDBSnapshotAttributes",
             "rds:DescribeDBClusters", "rds:DescribeDBClusterSnapshots", "rds:DescribeDBClusterSnapshotAttributes"),
    probe=("rds", "DescribeDBInstances", (("MaxRecords", 20),)),
    outputs=(("resources.json", "list"),),
    description="RDS instances, clusters and manual (cluster) snapshots: exposure, sharing, encryption",
)

_KIND_ORDER = {"instance": 0, "cluster": 1, "snapshot": 2, "cluster_snapshot": 3}


def _bool(value: Any) -> Optional[bool]:
    return None if value is None else bool(value)


def restore_sharing(attributes: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    """``(public, shared_accounts)`` from a snapshot's attribute list (``restore`` values)."""
    values: List[str] = []
    for attr in attributes:
        if attr.get("AttributeName") == "restore":
            values.extend(str(v) for v in attr.get("AttributeValues") or [])
    return "all" in values, sorted({v for v in values if v != "all"})


def _instances(ctx: Any, rds: Any, out: List[Dict[str, Any]]) -> None:
    listed = ctx.paginate(rds, "describe_db_instances", "DBInstances", page_size=100, primary=True)
    out.extend({
        "Type": "rds", "Kind": "instance", "Arn": db.get("DBInstanceArn"), "Name": db.get("DBInstanceIdentifier"),
        "Public": _bool(db.get("PubliclyAccessible")), "Encrypted": _bool(db.get("StorageEncrypted")),
        "KmsKeyId": db.get("KmsKeyId"), "IAMAuth": _bool(db.get("IAMDatabaseAuthenticationEnabled")),
        "Engine": db.get("Engine"), "DBClusterIdentifier": db.get("DBClusterIdentifier"),
    } for db in listed.value)


def _clusters(ctx: Any, rds: Any, out: List[Dict[str, Any]]) -> None:
    listed = ctx.paginate(rds, "describe_db_clusters", "DBClusters", page_size=100)
    out.extend({
        "Type": "rds", "Kind": "cluster", "Arn": c.get("DBClusterArn"), "Name": c.get("DBClusterIdentifier"),
        "Public": _bool(c.get("PubliclyAccessible")), "Encrypted": _bool(c.get("StorageEncrypted")),
        "KmsKeyId": c.get("KmsKeyId"), "IAMAuth": _bool(c.get("IAMDatabaseAuthenticationEnabled")),
        "Engine": c.get("Engine"),
        "Members": sorted(m.get("DBInstanceIdentifier") for m in c.get("DBClusterMembers") or []
                          if m.get("DBInstanceIdentifier")),
    } for c in listed.value)


def _sharing(ctx: Any, rds: Any, item: Dict[str, Any], op: str, result_key: str, **params: Any) -> None:
    """Fill ``PublicSnapshot``/``SharedAccounts`` from the snapshot's ``restore`` attribute (``null`` on failure)."""
    result = ctx.call(rds, op, item=item["Arn"], **params)
    if result.ok:
        attrs = (result.get(f"{result_key}Result") or {}).get(result_key) or []
        item["PublicSnapshot"], item["SharedAccounts"] = restore_sharing(attrs)
    else:
        item["PublicSnapshot"] = item["SharedAccounts"] = None
        add_error(item, result)


def _snapshots(ctx: Any, rds: Any, out: List[Dict[str, Any]]) -> None:
    listed = ctx.paginate(rds, "describe_db_snapshots", "DBSnapshots", page_size=100, SnapshotType="manual")
    for snap in listed.value:
        sid = snap.get("DBSnapshotIdentifier")
        item = {"Type": "rds", "Kind": "snapshot",
                "Arn": snap.get("DBSnapshotArn") or ctx.arn("rds", f"snapshot:{sid}"), "Name": sid,
                "DBInstanceIdentifier": snap.get("DBInstanceIdentifier"), "PublicSnapshot": None,
                "SharedAccounts": None, "Encrypted": _bool(snap.get("Encrypted")), "KmsKeyId": snap.get("KmsKeyId")}
        _sharing(ctx, rds, item, "describe_db_snapshot_attributes", "DBSnapshotAttributes",
                 DBSnapshotIdentifier=sid)
        out.append(item)


def _cluster_snapshots(ctx: Any, rds: Any, out: List[Dict[str, Any]]) -> None:
    listed = ctx.paginate(rds, "describe_db_cluster_snapshots", "DBClusterSnapshots", page_size=100,
                          SnapshotType="manual")
    for snap in listed.value:
        sid = snap.get("DBClusterSnapshotIdentifier")
        item = {"Type": "rds", "Kind": "cluster_snapshot",
                "Arn": snap.get("DBClusterSnapshotArn") or ctx.arn("rds", f"cluster-snapshot:{sid}"), "Name": sid,
                "DBClusterIdentifier": snap.get("DBClusterIdentifier"), "PublicSnapshot": None,
                "SharedAccounts": None, "Encrypted": _bool(snap.get("StorageEncrypted")),
                "KmsKeyId": snap.get("KmsKeyId")}
        _sharing(ctx, rds, item, "describe_db_cluster_snapshot_attributes", "DBClusterSnapshotAttributes",
                 DBClusterSnapshotIdentifier=sid)
        out.append(item)


def collect(ctx: Any) -> None:
    rds = ctx.client("rds")
    resources: List[Dict[str, Any]] = []
    for section, fetch in (("instances", _instances), ("clusters", _clusters), ("snapshots", _snapshots),
                           ("cluster_snapshots", _cluster_snapshots)):
        with ctx.section(section):
            fetch(ctx, rds, resources)
    resources.sort(key=lambda r: (_KIND_ORDER.get(r["Kind"], 9), str(r["Arn"])))
    ctx.out.write("resources.json", resources)
    ctx.log.info("%d RDS resources", len(resources))
