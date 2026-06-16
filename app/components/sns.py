"""
AWS SNS Enumeration Module

Collects SNS topics and their access policies (never message data). The topic
policy can grant publish/subscribe cross-account or publicly.

reports/{account}/{region}/sns/
└── resources.json   # Normalized: {Type, Arn, Name, Policy}
"""

import json
import os
from botocore.exceptions import ClientError


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m SNS Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    client = session.client("sns")

    topic_arns = []
    try:
        paginator = client.get_paginator("list_topics")
        for page in paginator.paginate():
            topic_arns.extend(t["TopicArn"] for t in page.get("Topics", []))
    except ClientError as e:
        with open(f"{path}/resources.json", "w") as f:
            json.dump({"Error": str(e)}, f, indent=2)
        print(f"    \033[1;33m[!]\033[0m SNS list_topics failed: {e}")
        return

    resources = []
    for arn in topic_arns:
        policy = None
        try:
            attrs = client.get_topic_attributes(TopicArn=arn).get("Attributes", {})
            policy_str = attrs.get("Policy")
            if policy_str:
                try:
                    policy = json.loads(policy_str)
                except json.JSONDecodeError:
                    policy = {"_raw": policy_str}
        except ClientError:
            pass
        resources.append({
            "Type": "sns",
            "Arn": arn,
            "Name": arn.split(":")[-1],
            "Policy": policy,
        })

    with open(f"{path}/resources.json", "w") as f:
        json.dump(resources, f, indent=2, default=str)

    print(f"    \033[1;32m[+]\033[0m SNS Enumeration Finished ({len(resources)} topics)")
