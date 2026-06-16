"""
AWS ECR Enumeration Module

Collects ECR repositories and their repository policies (who can pull/push
images). A repo policy can grant pull/push cross-account or publicly.

reports/{account}/{region}/ecr/
└── resources.json   # Normalized: {Type, Arn, Name, Policy}
"""

import json
import os
from botocore.exceptions import ClientError


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m ECR Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    client = session.client("ecr")

    repos = []
    try:
        paginator = client.get_paginator("describe_repositories")
        for page in paginator.paginate():
            repos.extend(page.get("repositories", []))
    except ClientError as e:
        with open(f"{path}/resources.json", "w") as f:
            json.dump({"Error": str(e)}, f, indent=2)
        print(f"    \033[1;33m[!]\033[0m ECR describe_repositories failed: {e}")
        return

    resources = []
    for repo in repos:
        name = repo.get("repositoryName")
        policy = None
        try:
            policy_str = client.get_repository_policy(repositoryName=name).get("policyText")
            if policy_str:
                try:
                    policy = json.loads(policy_str)
                except json.JSONDecodeError:
                    policy = {"_raw": policy_str}
        except ClientError:
            pass  # RepositoryPolicyNotFoundException is normal
        resources.append({
            "Type": "ecr",
            "Arn": repo.get("repositoryArn"),
            "Name": name,
            "Policy": policy,
        })

    with open(f"{path}/resources.json", "w") as f:
        json.dump(resources, f, indent=2, default=str)

    print(f"    \033[1;32m[+]\033[0m ECR Enumeration Finished ({len(resources)} repositories)")
