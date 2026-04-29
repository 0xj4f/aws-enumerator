"""
SSM Parameter Store Enumeration Module

Collects parameter metadata only — never reads parameter values.

reports/{account}/{region}/ssm/
└── parameters.json   # Name, Type (String|StringList|SecureString), KMS key, version, last modified
"""

import json
import os
from botocore.exceptions import ClientError


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m SSM Parameter Store Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    client = session.client("ssm")

    parameters = []
    try:
        paginator = client.get_paginator("describe_parameters")
        for page in paginator.paginate():
            parameters.extend(page.get("Parameters", []))
    except ClientError as e:
        with open(f"{path}/parameters.json", "w") as f:
            json.dump({"Error": str(e)}, f, indent=2)
        print(f"    \033[1;33m[!]\033[0m SSM describe_parameters failed: {e}")
        return

    with open(f"{path}/parameters.json", "w") as f:
        json.dump(parameters, f, indent=2, default=str)

    print(f"    \033[1;32m[+]\033[0m SSM Parameter Store Enumeration Finished ({len(parameters)} parameters)")
