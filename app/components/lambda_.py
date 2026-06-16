"""
AWS Lambda Enumeration Module

Collects function metadata, execution roles, resource policies, and function-URL
config. Environment variable VALUES are never stored — only their key names — so
the report stays safe to share (values frequently contain secrets).

reports/{account}/{region}/lambda/
├── functions.json                   # Per-function metadata (incl. execution Role, env var NAMES)
└── resource_policies/
    └── {function_name}.json         # Per-function resource-based policy (who can invoke)
"""

import json
import os
from botocore.exceptions import ClientError


def _safe_filename(name):
    """Make a function name safe for use as a filename."""
    return name.replace('/', '_').replace(':', '_').replace(' ', '_')


def _clean_function(fn):
    """Project a FunctionConfiguration to stored metadata, redacting env var values."""
    env_var_names = sorted((fn.get("Environment", {}).get("Variables", {}) or {}).keys())
    return {
        "FunctionName": fn.get("FunctionName"),
        "FunctionArn": fn.get("FunctionArn"),
        "Runtime": fn.get("Runtime"),
        "Handler": fn.get("Handler"),
        "Role": fn.get("Role"),  # execution role ARN — the privesc bridge
        "MemorySize": fn.get("MemorySize"),
        "Timeout": fn.get("Timeout"),
        "LastModified": fn.get("LastModified"),
        "PackageType": fn.get("PackageType"),
        "Layers": [layer.get("Arn") for layer in fn.get("Layers", [])],
        "VpcConfig": {
            "VpcId": fn.get("VpcConfig", {}).get("VpcId"),
            "SubnetIds": fn.get("VpcConfig", {}).get("SubnetIds", []),
            "SecurityGroupIds": fn.get("VpcConfig", {}).get("SecurityGroupIds", []),
        },
        "EnvironmentVariableNames": env_var_names,  # KEYS only — values redacted
    }


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m Lambda Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    client = session.client("lambda")

    # List all functions (paginated)
    raw_functions = []
    try:
        paginator = client.get_paginator("list_functions")
        for page in paginator.paginate():
            raw_functions.extend(page.get("Functions", []))
    except ClientError as e:
        with open(f"{path}/functions.json", "w") as f:
            json.dump({"Error": str(e)}, f, indent=2)
        print(f"    \033[1;33m[!]\033[0m Lambda list_functions failed: {e}")
        return

    functions = [_clean_function(fn) for fn in raw_functions]

    # Enrich each with function-URL config (NONE auth == publicly invocable)
    for cleaned, raw in zip(functions, raw_functions):
        try:
            url_cfg = client.get_function_url_config(FunctionName=raw["FunctionName"])
            cleaned["FunctionUrl"] = {
                "Url": url_cfg.get("FunctionUrl"),
                "AuthType": url_cfg.get("AuthType"),
            }
        except ClientError:
            pass  # No function URL is normal

    with open(f"{path}/functions.json", "w") as f:
        json.dump(functions, f, indent=2, default=str)

    if not functions:
        print("    \033[1;32m[+]\033[0m Lambda Enumeration Finished (no functions)")
        return

    # Per-function resource-based policy (grants invoke to principals/services)
    policies_dir = os.path.join(path, "resource_policies")
    os.makedirs(policies_dir, exist_ok=True)

    for fn in functions:
        fn_name = fn.get("FunctionName")
        fn_arn = fn.get("FunctionArn")
        if not fn_name:
            continue

        try:
            resp = client.get_policy(FunctionName=fn_name)
            policy_str = resp.get("Policy")
            if policy_str:
                try:
                    policy_doc = json.loads(policy_str)
                except json.JSONDecodeError:
                    policy_doc = {"_raw": policy_str}

                with open(f"{policies_dir}/{_safe_filename(fn_name)}.json", "w") as f:
                    json.dump({
                        "FunctionArn": fn_arn,
                        "FunctionName": fn_name,
                        "ResourcePolicy": policy_doc
                    }, f, indent=2, default=str)
        except ClientError:
            pass  # No resource policy is normal

    print(f"    \033[1;32m[+]\033[0m Lambda Enumeration Finished ({len(functions)} functions)")
