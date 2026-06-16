"""
AWS CodeBuild Enumeration Module

Collects CodeBuild projects and the IAM service role each runs as — the
PassRole→CodeBuild privesc target (PRIVESC-019). A build runs arbitrary
commands as its service role.

reports/{account}/{region}/codebuild/
└── resources.json   # Normalized compute resources: {Type, Arn, Name, Roles}
"""

import json
import os
from botocore.exceptions import ClientError


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m CodeBuild Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    client = session.client("codebuild")

    names = []
    try:
        paginator = client.get_paginator("list_projects")
        for page in paginator.paginate():
            names.extend(page.get("projects", []))
    except ClientError as e:
        with open(f"{path}/resources.json", "w") as f:
            json.dump({"Error": str(e)}, f, indent=2)
        print(f"    \033[1;33m[!]\033[0m CodeBuild list_projects failed: {e}")
        return

    resources = []
    # batch_get_projects accepts up to 100 names per call
    for i in range(0, len(names), 100):
        batch = names[i:i + 100]
        try:
            projects = client.batch_get_projects(names=batch).get("projects", [])
        except ClientError:
            continue
        for p in projects:
            role = p.get("serviceRole")
            resources.append({
                "Type": "codebuild",
                "Arn": p.get("arn"),
                "Name": p.get("name"),
                "Roles": [role] if role else [],
            })

    with open(f"{path}/resources.json", "w") as f:
        json.dump(resources, f, indent=2, default=str)

    print(f"    \033[1;32m[+]\033[0m CodeBuild Enumeration Finished ({len(resources)} projects)")
