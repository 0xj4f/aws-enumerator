"""
AWS KMS Enumeration Module

Collects KMS key metadata, key policies, grants, and aliases. KMS is a separate
authorization plane: a key policy can grant decrypt independently of IAM, so this
answers "who can actually decrypt the keys that protect secrets / params / S3 / EBS".

Key policies + grants are collected for CUSTOMER-managed keys (AWS-managed key
policies are not editable and add only noise); AWS-managed keys are still recorded
as metadata so encryption edges from other services resolve to a real node.

reports/{account}/{region}/kms/
├── keys.json                  # Per-key metadata: Arn, KeyManager, KeyState, Aliases, Grants
└── key_policies/
    └── {key_id}.json          # Per-key parsed key policy (customer keys)
"""

import json
import os
from botocore.exceptions import ClientError


def _aliases_by_key(client):
    """Build {target_key_id: [alias_name, ...]} from list_aliases."""
    mapping = {}
    try:
        paginator = client.get_paginator("list_aliases")
        for page in paginator.paginate():
            for alias in page.get("Aliases", []):
                tgt = alias.get("TargetKeyId")
                if tgt:
                    mapping.setdefault(tgt, []).append(alias.get("AliasName"))
    except ClientError:
        pass
    return mapping


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m KMS Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    client = session.client("kms")

    # List all key IDs (paginated)
    key_ids = []
    try:
        paginator = client.get_paginator("list_keys")
        for page in paginator.paginate():
            key_ids.extend(k["KeyId"] for k in page.get("Keys", []))
    except ClientError as e:
        with open(f"{path}/keys.json", "w") as f:
            json.dump({"Error": str(e)}, f, indent=2)
        print(f"    \033[1;33m[!]\033[0m KMS list_keys failed: {e}")
        return

    aliases = _aliases_by_key(client)

    keys = []
    policies_dir = os.path.join(path, "key_policies")

    for key_id in key_ids:
        try:
            meta = client.describe_key(KeyId=key_id)["KeyMetadata"]
        except ClientError:
            continue

        key_arn = meta.get("Arn")
        entry = {
            "KeyId": meta.get("KeyId"),
            "Arn": key_arn,
            "KeyManager": meta.get("KeyManager"),
            "KeyState": meta.get("KeyState"),
            "Origin": meta.get("Origin"),
            "Description": meta.get("Description"),
            "Enabled": meta.get("Enabled"),
            "Aliases": aliases.get(key_id, []),
            "Grants": [],
        }

        # Policies + grants are only meaningful/editable for customer-managed keys.
        if meta.get("KeyManager") == "CUSTOMER":
            try:
                policy_str = client.get_key_policy(KeyId=key_id, PolicyName="default").get("Policy")
                if policy_str:
                    try:
                        policy_doc = json.loads(policy_str)
                    except json.JSONDecodeError:
                        policy_doc = {"_raw": policy_str}
                    os.makedirs(policies_dir, exist_ok=True)
                    with open(f"{policies_dir}/{key_id}.json", "w") as f:
                        json.dump({"KeyId": key_id, "Arn": key_arn, "Policy": policy_doc},
                                  f, indent=2, default=str)
            except ClientError:
                pass

            try:
                gpaginator = client.get_paginator("list_grants")
                for gpage in gpaginator.paginate(KeyId=key_id):
                    for g in gpage.get("Grants", []):
                        entry["Grants"].append({
                            "GrantId": g.get("GrantId"),
                            "GranteePrincipal": g.get("GranteePrincipal"),
                            "Operations": g.get("Operations", []),
                        })
            except ClientError:
                pass

        keys.append(entry)

    with open(f"{path}/keys.json", "w") as f:
        json.dump(keys, f, indent=2, default=str)

    customer = sum(1 for k in keys if k.get("KeyManager") == "CUSTOMER")
    print(f"    \033[1;32m[+]\033[0m KMS Enumeration Finished ({len(keys)} keys, {customer} customer-managed)")
