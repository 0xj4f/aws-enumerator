"""
AWS Secrets Manager Enumeration Module

Collects secret metadata and resource policies. Never reads secret values.

reports/{account}/{region}/secretsmanager/
├── secrets.json                      # All secret metadata (name, ARN, KmsKeyId, rotation, etc.)
└── resource_policies/
    └── {secret_name}.json            # Per-secret resource policy
"""

import json
import os
from botocore.exceptions import ClientError


def _safe_filename(secret_name):
    """Make a secret name safe for use as a filename."""
    return secret_name.replace('/', '_').replace(':', '_').replace(' ', '_')


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m Secrets Manager Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    client = session.client("secretsmanager")

    # List all secrets (paginated)
    secrets = []
    try:
        paginator = client.get_paginator("list_secrets")
        for page in paginator.paginate():
            secrets.extend(page.get("SecretList", []))
    except ClientError as e:
        with open(f"{path}/secrets.json", "w") as f:
            json.dump({"Error": str(e)}, f, indent=2)
        print(f"    \033[1;33m[!]\033[0m Secrets Manager list_secrets failed: {e}")
        return

    if not secrets:
        with open(f"{path}/secrets.json", "w") as f:
            json.dump([], f, indent=2)
        print("    \033[1;32m[+]\033[0m Secrets Manager Enumeration Finished (no secrets)")
        return

    # Save bulk metadata
    with open(f"{path}/secrets.json", "w") as f:
        json.dump(secrets, f, indent=2, default=str)

    # Per-secret resource policy
    policies_dir = os.path.join(path, "resource_policies")
    os.makedirs(policies_dir, exist_ok=True)

    for secret in secrets:
        secret_arn = secret.get("ARN")
        secret_name = secret.get("Name", "")
        if not secret_arn:
            continue

        try:
            resp = client.get_resource_policy(SecretId=secret_arn)
            policy_str = resp.get("ResourcePolicy")
            if policy_str:
                # Resource policy is returned as JSON string — parse it for clean storage
                try:
                    policy_doc = json.loads(policy_str)
                except json.JSONDecodeError:
                    policy_doc = {"_raw": policy_str}

                with open(f"{policies_dir}/{_safe_filename(secret_name)}.json", "w") as f:
                    json.dump({
                        "SecretArn": secret_arn,
                        "SecretName": secret_name,
                        "ResourcePolicy": policy_doc
                    }, f, indent=2, default=str)
        except ClientError:
            pass  # No resource policy is normal

    print(f"    \033[1;32m[+]\033[0m Secrets Manager Enumeration Finished ({len(secrets)} secrets)")
