"""
AWS EBS Snapshot Enumeration Module

Collects self-owned EBS snapshots and their createVolumePermission sharing
(never volume data). Flags publicly shared snapshots ('all' group) and
cross-account shared snapshots — a classic data-exfiltration vector.

reports/{account}/{region}/ebs/
└── resources.json   # Normalized: {Type, Id, Name, Public, SharedAccounts, Encrypted, KmsKeyId}
"""

import json
import os
from botocore.exceptions import ClientError


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m EBS Snapshot Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    ec2 = session.client("ec2")

    snapshots = []
    try:
        for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"]):
            snapshots.extend(page.get("Snapshots", []))
    except ClientError as e:
        with open(f"{path}/resources.json", "w") as f:
            json.dump({"Error": str(e)}, f, indent=2)
        print(f"    \033[1;33m[!]\033[0m EBS describe_snapshots failed: {e}")
        return

    resources = []
    for snap in snapshots:
        snap_id = snap.get("SnapshotId")
        public, shared = False, []
        try:
            perms = ec2.describe_snapshot_attribute(
                SnapshotId=snap_id, Attribute="createVolumePermission"
            ).get("CreateVolumePermissions", [])
            for p in perms:
                if p.get("Group") == "all":
                    public = True
                elif p.get("UserId"):
                    shared.append(p["UserId"])
        except ClientError:
            pass
        resources.append({
            "Type": "ebssnapshot",
            "Id": snap_id,
            "Name": snap_id,
            "Public": public,
            "SharedAccounts": shared,
            "Encrypted": bool(snap.get("Encrypted")),
            "KmsKeyId": snap.get("KmsKeyId"),
            "VolumeId": snap.get("VolumeId"),
        })

    with open(f"{path}/resources.json", "w") as f:
        json.dump(resources, f, indent=2, default=str)

    pub = sum(1 for r in resources if r["Public"])
    print(f"    \033[1;32m[+]\033[0m EBS Snapshot Enumeration Finished ({len(resources)} snapshots, {pub} public)")
