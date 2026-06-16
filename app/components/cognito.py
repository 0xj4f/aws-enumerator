"""
AWS Cognito Enumeration Module

Collects Cognito identity pools (and their authenticated/unauthenticated IAM
role mappings) plus user pools. Identity pools are a direct external→IAM-role
bridge: an unauthenticated role means anonymous internet users can obtain
credentials for that role.

reports/{account}/{region}/cognito/
└── resources.json   # Normalized: identity pools {Type, Id, Name, AuthRole, UnauthRole, AllowUnauth} + user pools
"""

import json
import os
from botocore.exceptions import ClientError


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m Cognito Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    resources = []

    # ── Identity pools (the IAM-role bridge) ──
    try:
        idp = session.client("cognito-identity")
        pools = []
        for page in idp.get_paginator("list_identity_pools").paginate(MaxResults=60):
            pools.extend(page.get("IdentityPools", []))
        for pool in pools:
            pool_id = pool.get("IdentityPoolId")
            auth_role = unauth_role = None
            allow_unauth = None
            try:
                roles = idp.get_identity_pool_roles(IdentityPoolId=pool_id).get("Roles", {})
                auth_role = roles.get("authenticated")
                unauth_role = roles.get("unauthenticated")
            except ClientError:
                pass
            try:
                allow_unauth = idp.describe_identity_pool(
                    IdentityPoolId=pool_id).get("AllowUnauthenticatedIdentities")
            except ClientError:
                pass
            resources.append({
                "Type": "cognito",
                "Kind": "identity_pool",
                "Id": pool_id,
                "Name": pool.get("IdentityPoolName"),
                "AuthRole": auth_role,
                "UnauthRole": unauth_role,
                "AllowUnauth": allow_unauth,
            })
    except ClientError as e:
        print(f"    \033[1;33m[!]\033[0m Cognito identity pools failed: {e}")

    # ── User pools (metadata only) ──
    try:
        cidp = session.client("cognito-idp")
        for page in cidp.get_paginator("list_user_pools").paginate(MaxResults=60):
            for up in page.get("UserPools", []):
                resources.append({
                    "Type": "cognito",
                    "Kind": "user_pool",
                    "Id": up.get("Id"),
                    "Name": up.get("Name"),
                })
    except ClientError as e:
        print(f"    \033[1;33m[!]\033[0m Cognito user pools failed: {e}")

    with open(f"{path}/resources.json", "w") as f:
        json.dump(resources, f, indent=2, default=str)

    pools_n = sum(1 for r in resources if r.get("Kind") == "identity_pool")
    print(f"    \033[1;32m[+]\033[0m Cognito Enumeration Finished ({pools_n} identity pools, {len(resources) - pools_n} user pools)")
