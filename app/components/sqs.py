"""
AWS SQS Enumeration Module

Collects SQS queues and their access policies (never message data). The queue
policy can grant send/receive cross-account or publicly.

reports/{account}/{region}/sqs/
└── resources.json   # Normalized: {Type, Arn, Name, Policy}
"""

import json
import os
from botocore.exceptions import ClientError


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m SQS Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    client = session.client("sqs")

    urls = []
    try:
        paginator = client.get_paginator("list_queues")
        for page in paginator.paginate():
            urls.extend(page.get("QueueUrls", []))
    except ClientError as e:
        with open(f"{path}/resources.json", "w") as f:
            json.dump({"Error": str(e)}, f, indent=2)
        print(f"    \033[1;33m[!]\033[0m SQS list_queues failed: {e}")
        return

    resources = []
    for url in urls:
        try:
            attrs = client.get_queue_attributes(
                QueueUrl=url, AttributeNames=["QueueArn", "Policy"]
            ).get("Attributes", {})
        except ClientError:
            continue
        policy = None
        policy_str = attrs.get("Policy")
        if policy_str:
            try:
                policy = json.loads(policy_str)
            except json.JSONDecodeError:
                policy = {"_raw": policy_str}
        arn = attrs.get("QueueArn") or url
        resources.append({
            "Type": "sqs",
            "Arn": arn,
            "Name": url.split("/")[-1],
            "Policy": policy,
        })

    with open(f"{path}/resources.json", "w") as f:
        json.dump(resources, f, indent=2, default=str)

    print(f"    \033[1;32m[+]\033[0m SQS Enumeration Finished ({len(resources)} queues)")
