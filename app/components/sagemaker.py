"""
AWS SageMaker Enumeration Module

Collects SageMaker notebook instances and the IAM execution role each carries —
the PassRole→SageMaker privesc target (PRIVESC-020).

reports/{account}/{region}/sagemaker/
└── resources.json   # Normalized compute resources: {Type, Arn, Name, Roles}
"""

import json
import os
from botocore.exceptions import ClientError


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m SageMaker Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    client = session.client("sagemaker")

    summaries = []
    try:
        paginator = client.get_paginator("list_notebook_instances")
        for page in paginator.paginate():
            summaries.extend(page.get("NotebookInstances", []))
    except ClientError as e:
        with open(f"{path}/resources.json", "w") as f:
            json.dump({"Error": str(e)}, f, indent=2)
        print(f"    \033[1;33m[!]\033[0m SageMaker list_notebook_instances failed: {e}")
        return

    resources = []
    for s in summaries:
        name = s.get("NotebookInstanceName")
        try:
            d = client.describe_notebook_instance(NotebookInstanceName=name)
        except ClientError:
            continue
        role = d.get("RoleArn")
        resources.append({
            "Type": "sagemaker",
            "Arn": d.get("NotebookInstanceArn"),
            "Name": name,
            "Roles": [role] if role else [],
        })

    with open(f"{path}/resources.json", "w") as f:
        json.dump(resources, f, indent=2, default=str)

    print(f"    \033[1;32m[+]\033[0m SageMaker Enumeration Finished ({len(resources)} notebook instances)")
