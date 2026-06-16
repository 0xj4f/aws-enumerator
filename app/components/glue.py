"""
AWS Glue Enumeration Module

Collects Glue jobs and dev endpoints and the IAM role each runs as — the
PassRole→Glue privesc target (PRIVESC-018).

reports/{account}/{region}/glue/
└── resources.json   # Normalized compute resources: {Type, Arn, Name, Roles}
"""

import json
import os
from botocore.exceptions import ClientError


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m Glue Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    client = session.client("glue")
    resources = []
    failed = False

    try:
        paginator = client.get_paginator("get_jobs")
        for page in paginator.paginate():
            for job in page.get("Jobs", []):
                resources.append({
                    "Type": "gluejob",
                    "Arn": job.get("Name"),  # Glue jobs are identified by name
                    "Name": job.get("Name"),
                    "Roles": [job.get("Role")] if job.get("Role") else [],
                })
    except ClientError as e:
        failed = True
        print(f"    \033[1;33m[!]\033[0m Glue get_jobs failed: {e}")

    try:
        paginator = client.get_paginator("get_dev_endpoints")
        for page in paginator.paginate():
            for ep in page.get("DevEndpoints", []):
                resources.append({
                    "Type": "gluejob",
                    "Arn": ep.get("EndpointName"),
                    "Name": ep.get("EndpointName"),
                    "Roles": [ep.get("RoleArn")] if ep.get("RoleArn") else [],
                })
    except ClientError as e:
        failed = True
        print(f"    \033[1;33m[!]\033[0m Glue get_dev_endpoints failed: {e}")

    if failed and not resources:
        with open(f"{path}/resources.json", "w") as f:
            json.dump({"Error": "Glue enumeration failed"}, f, indent=2)
        return

    with open(f"{path}/resources.json", "w") as f:
        json.dump(resources, f, indent=2, default=str)

    print(f"    \033[1;32m[+]\033[0m Glue Enumeration Finished ({len(resources)} jobs/endpoints)")
