"""
AWS CloudFormation Enumeration Module

Collects stacks and the IAM service role each runs as — the PassRole→CFN
privesc target (PRIVESC-016). A stack's RoleARN is assumed during operations,
so controlling stack creation/updates can wield that role.

reports/{account}/{region}/cloudformation/
└── resources.json   # Normalized compute resources: {Type, Arn, Name, Roles}
"""

import json
import os
from botocore.exceptions import ClientError


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m CloudFormation Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    client = session.client("cloudformation")

    stacks = []
    try:
        paginator = client.get_paginator("describe_stacks")
        for page in paginator.paginate():
            stacks.extend(page.get("Stacks", []))
    except ClientError as e:
        with open(f"{path}/resources.json", "w") as f:
            json.dump({"Error": str(e)}, f, indent=2)
        print(f"    \033[1;33m[!]\033[0m CloudFormation describe_stacks failed: {e}")
        return

    resources = []
    for st in stacks:
        role_arn = st.get("RoleARN")
        resources.append({
            "Type": "cfnstack",
            "Arn": st.get("StackId"),
            "Name": st.get("StackName"),
            "Roles": [role_arn] if role_arn else [],
            "StackStatus": st.get("StackStatus"),
        })

    with open(f"{path}/resources.json", "w") as f:
        json.dump(resources, f, indent=2, default=str)

    print(f"    \033[1;32m[+]\033[0m CloudFormation Enumeration Finished ({len(resources)} stacks)")
