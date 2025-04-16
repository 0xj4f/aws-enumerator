"""
List all S3 buckets.

For each bucket:
- Retrieve its region.
- Get its bucket policy (if exists).
- Get ACL (Access Control List).
- Get CORS and Lifecycle config (optional but valuable).
- Optionally get Public Access Block configuration.
- Check if versioning is enabled.
- Optionally log how many objects and the total size (expensive in large buckets, so make this optional or summarized only).


aws-enum/
└── app/
    └── components/
        └── s3.py                # S3 enumeration

reports/{account}/{region}/s3/
├── buckets.json                  # All buckets + basic metadata
├── policies/
│   ├── {bucket}.json             # Individual policy files
├── acls/
│   ├── {bucket}.json
├── public_access_block/
│   ├── {bucket}.json
├── versioning/
│   ├── {bucket}.json

"""

import json
import os
import boto3
from botocore.exceptions import ClientError

def enumerate(session, path):
    os.makedirs(path, exist_ok=True)

    s3_client = session.client("s3")

    # Step 1: List all buckets
    try:
        buckets_response = s3_client.list_buckets()
        buckets = buckets_response.get("Buckets", [])
    except ClientError as e:
        with open(f"{path}/buckets.json", "w") as f:
            json.dump({"Error": str(e)}, f, indent=2)
        return

    buckets_metadata = []
    policies_dir = os.path.join(path, "policies")
    acls_dir = os.path.join(path, "acls")
    public_access_dir = os.path.join(path, "public_access_block")
    versioning_dir = os.path.join(path, "versioning")

    os.makedirs(policies_dir, exist_ok=True)
    os.makedirs(acls_dir, exist_ok=True)
    os.makedirs(public_access_dir, exist_ok=True)
    os.makedirs(versioning_dir, exist_ok=True)

    for bucket in buckets:
        bucket_name = bucket["Name"]
        bucket_info = {
            "Name": bucket_name,
            "CreationDate": str(bucket["CreationDate"])
        }

        # Get bucket location
        try:
            loc = s3_client.get_bucket_location(Bucket=bucket_name)
            bucket_info["Region"] = loc.get("LocationConstraint") or "us-east-1"
        except Exception as e:
            bucket_info["RegionError"] = str(e)

        # Save policy
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            with open(f"{policies_dir}/{bucket_name}.json", "w") as f:
                json.dump(json.loads(policy["Policy"]), f, indent=2)
        except ClientError:
            pass

        # Save ACL
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            with open(f"{acls_dir}/{bucket_name}.json", "w") as f:
                json.dump(acl, f, indent=2)
        except ClientError:
            pass

        # Save public access block
        try:
            public_block = s3_client.get_bucket_policy_status(Bucket=bucket_name)
            with open(f"{public_access_dir}/{bucket_name}.json", "w") as f:
                json.dump(public_block, f, indent=2)
        except ClientError:
            pass

        # Save versioning
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            with open(f"{versioning_dir}/{bucket_name}.json", "w") as f:
                json.dump(versioning, f, indent=2)
        except ClientError:
            pass

        buckets_metadata.append(bucket_info)

    with open(f"{path}/buckets.json", "w") as f:
        json.dump(buckets_metadata, f, indent=2)
