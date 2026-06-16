"""
AWS DynamoDB Enumeration Module

Collects table metadata + resource-based policies (never table data/items).
A table resource policy can grant access cross-account or publicly.

reports/{account}/{region}/dynamodb/
└── resources.json   # Normalized: {Type, Arn, Name, Policy}
"""

import json
import os
from botocore.exceptions import ClientError


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m DynamoDB Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    client = session.client("dynamodb")

    names = []
    try:
        paginator = client.get_paginator("list_tables")
        for page in paginator.paginate():
            names.extend(page.get("TableNames", []))
    except ClientError as e:
        with open(f"{path}/resources.json", "w") as f:
            json.dump({"Error": str(e)}, f, indent=2)
        print(f"    \033[1;33m[!]\033[0m DynamoDB list_tables failed: {e}")
        return

    resources = []
    for name in names:
        try:
            table_arn = client.describe_table(TableName=name)["Table"].get("TableArn")
        except ClientError:
            continue
        policy = None
        if table_arn:
            try:
                policy_str = client.get_resource_policy(ResourceArn=table_arn).get("Policy")
                if policy_str:
                    try:
                        policy = json.loads(policy_str)
                    except json.JSONDecodeError:
                        policy = {"_raw": policy_str}
            except ClientError:
                pass  # PolicyNotFoundException is normal
        resources.append({
            "Type": "dynamodb",
            "Arn": table_arn,
            "Name": name,
            "Policy": policy,
        })

    with open(f"{path}/resources.json", "w") as f:
        json.dump(resources, f, indent=2, default=str)

    print(f"    \033[1;32m[+]\033[0m DynamoDB Enumeration Finished ({len(resources)} tables)")
