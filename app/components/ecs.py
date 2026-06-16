"""
AWS ECS Enumeration Module

Collects ECS task definitions and the IAM roles they carry (task role +
execution role) — the PassRole→ECS privesc target (PRIVESC-017).

reports/{account}/{region}/ecs/
└── resources.json   # Normalized compute resources: {Type, Arn, Name, Roles}
"""

import json
import os
from botocore.exceptions import ClientError


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m ECS Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    client = session.client("ecs")

    td_arns = []
    try:
        paginator = client.get_paginator("list_task_definitions")
        for page in paginator.paginate():
            td_arns.extend(page.get("taskDefinitionArns", []))
    except ClientError as e:
        with open(f"{path}/resources.json", "w") as f:
            json.dump({"Error": str(e)}, f, indent=2)
        print(f"    \033[1;33m[!]\033[0m ECS list_task_definitions failed: {e}")
        return

    resources = []
    for arn in td_arns:
        try:
            td = client.describe_task_definition(taskDefinition=arn)["taskDefinition"]
        except ClientError:
            continue
        roles = [r for r in (td.get("taskRoleArn"), td.get("executionRoleArn")) if r]
        resources.append({
            "Type": "ecstask",
            "Arn": td.get("taskDefinitionArn", arn),
            "Name": td.get("family"),
            "Roles": sorted(set(roles)),
        })

    with open(f"{path}/resources.json", "w") as f:
        json.dump(resources, f, indent=2, default=str)

    print(f"    \033[1;32m[+]\033[0m ECS Enumeration Finished ({len(resources)} task definitions)")
