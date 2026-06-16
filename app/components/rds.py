"""
AWS RDS Enumeration Module

Collects DB instance + manual snapshot metadata (never data/credentials).
Flags public instances, public snapshots (data-leak vector), and unencrypted
storage; links encrypted resources to their KMS key.

reports/{account}/{region}/rds/
└── resources.json   # Normalized: {Type, Arn, Name, Kind, Public, Encrypted, KmsKeyId, ...}
"""

import json
import os
from botocore.exceptions import ClientError


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m RDS Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    client = session.client("rds")
    resources = []
    failed = False

    # DB instances
    try:
        paginator = client.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                resources.append({
                    "Type": "rds",
                    "Kind": "instance",
                    "Arn": db.get("DBInstanceArn"),
                    "Name": db.get("DBInstanceIdentifier"),
                    "Public": bool(db.get("PubliclyAccessible")),
                    "Encrypted": bool(db.get("StorageEncrypted")),
                    "KmsKeyId": db.get("KmsKeyId"),
                    "IAMAuth": bool(db.get("IAMDatabaseAuthenticationEnabled")),
                    "Engine": db.get("Engine"),
                })
    except ClientError as e:
        failed = True
        print(f"    \033[1;33m[!]\033[0m RDS describe_db_instances failed: {e}")

    # Manual snapshots — check for public sharing
    try:
        paginator = client.get_paginator("describe_db_snapshots")
        for page in paginator.paginate(SnapshotType="manual"):
            for snap in page.get("DBSnapshots", []):
                snap_id = snap.get("DBSnapshotIdentifier")
                public = False
                try:
                    attrs = client.describe_db_snapshot_attributes(
                        DBSnapshotIdentifier=snap_id
                    )["DBSnapshotAttributesResult"]["DBSnapshotAttributes"]
                    for a in attrs:
                        if a.get("AttributeName") == "restore" and "all" in a.get("AttributeValues", []):
                            public = True
                except ClientError:
                    pass
                resources.append({
                    "Type": "rds",
                    "Kind": "snapshot",
                    "Arn": snap.get("DBSnapshotArn"),
                    "Name": snap_id,
                    "PublicSnapshot": public,
                    "Encrypted": bool(snap.get("Encrypted")),
                    "KmsKeyId": snap.get("KmsKeyId"),
                })
    except ClientError as e:
        failed = True
        print(f"    \033[1;33m[!]\033[0m RDS describe_db_snapshots failed: {e}")

    if failed and not resources:
        with open(f"{path}/resources.json", "w") as f:
            json.dump({"Error": "RDS enumeration failed"}, f, indent=2)
        return

    with open(f"{path}/resources.json", "w") as f:
        json.dump(resources, f, indent=2, default=str)

    print(f"    \033[1;32m[+]\033[0m RDS Enumeration Finished ({len(resources)} instances/snapshots)")
