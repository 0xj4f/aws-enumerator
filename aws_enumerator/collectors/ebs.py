"""EBS: self-owned snapshots, their public / cross-account sharing, and the account's snapshot
settings (never volume data).

Output (``<region>/ebs/``):

* ``resources.json`` (list), sorted by ``Id``::

    {Type: "ebssnapshot", Id, Arn, Name, Public: bool|null, SharedAccounts: [account]|null,
     SharingChecked: bool, Encrypted, KmsKeyId, VolumeId, StartTime, CollectionErrors?}

  ``Public`` comes from one paginated ``DescribeSnapshots(OwnerIds=[self], RestorableByUserIds=[all])``
  call instead of one attribute call per snapshot (F-104). Cross-account shares need
  ``DescribeSnapshotAttribute`` per snapshot; that budget is ``--ebs-share-check all|none|cap:N``
  (option ``ebs_share_check``, default ``cap:1000``, newest snapshots first). A snapshot beyond the
  budget has ``SharingChecked: false`` and ``SharedAccounts: null``; a failed attribute call gives
  ``SharedAccounts: null`` and ``CollectionErrors`` - never ``false``/``[]`` (F-104, F-059).
* ``account_settings.json`` (dict): ``{SnapshotBlockPublicAccessState: str|null,
  EbsEncryptionByDefault: bool|null, CollectionErrors?}``. ``block-all-sharing`` neutralises public
  snapshots (F-080).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

from aws_enumerator.collectors._common import add_error
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="ebs", scope="regional", output_dir="ebs", services=("ec2",),
    tier=1, cost="medium", noise="low", default=True, groups=("@compute", "@data"),
    actions=("ec2:DescribeSnapshots", "ec2:DescribeSnapshotAttribute", "ec2:GetSnapshotBlockPublicAccessState",
             "ec2:GetEbsEncryptionByDefault"),
    probe=("ec2", "DescribeSnapshots", (("OwnerIds", ("self",)), ("MaxResults", 5))),
    outputs=(("resources.json", "list"), ("account_settings.json", "dict")),
    description="EBS snapshots (public and cross-account sharing) and snapshot account settings",
)

DEFAULT_SHARE_CHECK = "cap:1000"
_API_ATTRIBUTE = "ec2:DescribeSnapshotAttribute"
_SHARE_CHECK = re.compile(r"^(all|none|cap:(\d+))$")


def share_check_budget(value: Any) -> Optional[int]:
    """``--ebs-share-check`` as a number of attribute calls (``None`` = unlimited)."""
    match = _SHARE_CHECK.match(str(value if value is not None else DEFAULT_SHARE_CHECK).strip().lower())
    if not match:
        raise ValueError(f"ebs_share_check must be all, none or cap:N, got {value!r}")
    if match.group(1) == "all":
        return None
    if match.group(1) == "none":
        return 0
    return int(match.group(2))


def _public_ids(ctx: Any, ec2: Any) -> Optional[Set[str]]:
    result = ctx.paginate(ec2, "describe_snapshots", "Snapshots", page_size=1000, OwnerIds=["self"],
                          RestorableByUserIds=["all"])
    return {s["SnapshotId"] for s in result.value if s.get("SnapshotId")} if result.ok else None


def _check_sharing(ctx: Any, ec2: Any, item: Dict[str, Any]) -> None:
    result = ctx.call(ec2, "describe_snapshot_attribute", item=item["Arn"], SnapshotId=item["Id"],
                      Attribute="createVolumePermission")
    item["SharingChecked"] = result.ok
    if not result.ok:
        add_error(item, result)
        return
    perms = result.get("CreateVolumePermissions") or []
    item["SharedAccounts"] = sorted({p["UserId"] for p in perms if p.get("UserId")})
    if any(p.get("Group") == "all" for p in perms):
        item["Public"] = True
    elif item["Public"] is None:
        item["Public"] = False


def _snapshot_item(ctx: Any, snap: Dict[str, Any], public: Optional[Set[str]]) -> Dict[str, Any]:
    sid = snap["SnapshotId"]
    return {"Type": "ebssnapshot", "Id": sid, "Arn": ctx.arn("ec2", f"snapshot/{sid}", account=""), "Name": sid,
            "Public": None if public is None else sid in public, "SharedAccounts": None, "SharingChecked": False,
            "Encrypted": snap.get("Encrypted"), "KmsKeyId": snap.get("KmsKeyId"), "VolumeId": snap.get("VolumeId"),
            "StartTime": snap.get("StartTime")}


def _newest_first(snaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(snaps, key=lambda s: (str(s.get("StartTime") or ""), s["SnapshotId"]), reverse=True)


def _snapshots(ctx: Any, ec2: Any, out: List[Dict[str, Any]]) -> None:
    budget = share_check_budget(ctx.option("ebs_share_check", DEFAULT_SHARE_CHECK))
    listed = ctx.paginate(ec2, "describe_snapshots", "Snapshots", page_size=1000, primary=True, OwnerIds=["self"])
    snaps = [s for s in listed.value if s.get("SnapshotId")]
    public = _public_ids(ctx, ec2) if snaps else set()
    checked = 0
    for snap in _newest_first(snaps):
        item = _snapshot_item(ctx, snap, public)
        if budget is None or checked < budget:
            checked += 1
            _check_sharing(ctx, ec2, item)
        else:
            ctx.cov.skip(_API_ATTRIBUTE, "ShareCheckBudget")
        out.append(item)


def _setting(ctx: Any, ec2: Any, out: Dict[str, Any], op: str, key: str, field: str) -> None:
    result = ctx.call(ec2, op)
    if result.ok:
        out[field] = result.get(key)
    else:
        add_error(out, result)


def _account_settings(ctx: Any, ec2: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"SnapshotBlockPublicAccessState": None, "EbsEncryptionByDefault": None}
    _setting(ctx, ec2, out, "get_snapshot_block_public_access_state", "State", "SnapshotBlockPublicAccessState")
    _setting(ctx, ec2, out, "get_ebs_encryption_by_default", "EbsEncryptionByDefault", "EbsEncryptionByDefault")
    return out


def collect(ctx: Any) -> None:
    ec2 = ctx.client("ec2")
    snapshots: List[Dict[str, Any]] = []
    settings: Dict[str, Any] = {"SnapshotBlockPublicAccessState": None, "EbsEncryptionByDefault": None}
    with ctx.section("snapshots"):
        _snapshots(ctx, ec2, snapshots)
    snapshots.sort(key=lambda s: s["Id"])
    ctx.out.write("resources.json", snapshots)
    with ctx.section("account_settings"):
        settings = _account_settings(ctx, ec2)
    ctx.out.write("account_settings.json", settings)
    public = sum(1 for s in snapshots if s["Public"])
    ctx.log.info("%d snapshots, %d public", len(snapshots), public)
