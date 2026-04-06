"""
S3 Enumeration Module

For each bucket:
- Region, policy, ACL, public access block, versioning
- Encryption, tagging, logging, CORS configuration

reports/{account}/{region}/s3/
├── buckets.json
├── policies/{bucket}.json
├── acls/{bucket}.json
├── public_access_block/{bucket}.json
├── versioning/{bucket}.json
├── encryption/{bucket}.json
├── tagging/{bucket}.json
├── logging/{bucket}.json
└── cors/{bucket}.json
"""

import json
import os
from botocore.exceptions import ClientError


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m S3 Enumeration Starting...")
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

    subdirs = ["policies", "acls", "public_access_block", "versioning",
               "encryption", "tagging", "logging", "cors"]
    dirs = {}
    for subdir in subdirs:
        d = os.path.join(path, subdir)
        os.makedirs(d, exist_ok=True)
        dirs[subdir] = d

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
        except ClientError as e:
            bucket_info["RegionError"] = str(e)

        # Save policy
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            with open(f"{dirs['policies']}/{bucket_name}.json", "w") as f:
                json.dump(json.loads(policy["Policy"]), f, indent=2)
        except ClientError:
            pass

        # Save ACL
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            with open(f"{dirs['acls']}/{bucket_name}.json", "w") as f:
                json.dump(acl, f, indent=2, default=str)
        except ClientError:
            pass

        # Save public access block
        try:
            pub_block = s3_client.get_public_access_block(Bucket=bucket_name)
            with open(f"{dirs['public_access_block']}/{bucket_name}.json", "w") as f:
                json.dump(pub_block.get("PublicAccessBlockConfiguration", {}), f, indent=2)
        except ClientError:
            pass

        # Save versioning
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            with open(f"{dirs['versioning']}/{bucket_name}.json", "w") as f:
                json.dump(versioning, f, indent=2, default=str)
        except ClientError:
            pass

        # Save encryption
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            with open(f"{dirs['encryption']}/{bucket_name}.json", "w") as f:
                json.dump(encryption.get("ServerSideEncryptionConfiguration", {}), f, indent=2)
        except ClientError:
            pass

        # Save tagging
        try:
            tagging = s3_client.get_bucket_tagging(Bucket=bucket_name)
            with open(f"{dirs['tagging']}/{bucket_name}.json", "w") as f:
                json.dump(tagging.get("TagSet", []), f, indent=2)
        except ClientError:
            pass

        # Save logging
        try:
            logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)
            log_data = logging_config.get("LoggingEnabled", {"LoggingEnabled": False})
            with open(f"{dirs['logging']}/{bucket_name}.json", "w") as f:
                json.dump(log_data, f, indent=2)
        except ClientError:
            pass

        # Save CORS
        try:
            cors = s3_client.get_bucket_cors(Bucket=bucket_name)
            with open(f"{dirs['cors']}/{bucket_name}.json", "w") as f:
                json.dump(cors.get("CORSRules", []), f, indent=2)
        except ClientError:
            pass

        buckets_metadata.append(bucket_info)

    with open(f"{path}/buckets.json", "w") as f:
        json.dump(buckets_metadata, f, indent=2)

    print("    \033[1;32m[+]\033[0m S3 Enumeration Finished!")
