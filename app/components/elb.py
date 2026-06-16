"""
AWS Elastic Load Balancer Enumeration Module

Collects ALB/NLB (elbv2) and classic (elb) load balancers, their scheme
(internet-facing vs internal), and backend targets. Internet-facing LBs are
public entry points; their targets (EC2 instances / Lambda) are the exposure path.

reports/{account}/{region}/elb/
└── resources.json   # Normalized: {Type, Arn, Name, Scheme, DNSName, Targets:[{kind,id}]}
"""

import json
import os
from botocore.exceptions import ClientError


def _v2_targets(client, lb_arn):
    targets = []
    try:
        tgs = client.describe_target_groups(LoadBalancerArn=lb_arn).get("TargetGroups", [])
    except ClientError:
        return targets
    for tg in tgs:
        ttype = tg.get("TargetType")  # instance | ip | lambda | alb
        try:
            healths = client.describe_target_health(
                TargetGroupArn=tg["TargetGroupArn"]).get("TargetHealthDescriptions", [])
        except ClientError:
            continue
        for h in healths:
            tid = h.get("Target", {}).get("Id")
            if tid:
                targets.append({"kind": ttype, "id": tid})
    return targets


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m ELB Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    resources = []
    failed = False

    # ── ALB / NLB (elbv2) ──
    try:
        v2 = session.client("elbv2")
        lbs = []
        for page in v2.get_paginator("describe_load_balancers").paginate():
            lbs.extend(page.get("LoadBalancers", []))
        for lb in lbs:
            resources.append({
                "Type": "elb",
                "Arn": lb.get("LoadBalancerArn"),
                "Name": lb.get("LoadBalancerName"),
                "Scheme": lb.get("Scheme"),
                "DNSName": lb.get("DNSName"),
                "LBType": lb.get("Type"),
                "Targets": _v2_targets(v2, lb["LoadBalancerArn"]),
            })
    except ClientError as e:
        failed = True
        print(f"    \033[1;33m[!]\033[0m ELBv2 failed: {e}")

    # ── Classic ELB (v1) ──
    try:
        v1 = session.client("elb")
        for page in v1.get_paginator("describe_load_balancers").paginate():
            for lb in page.get("LoadBalancerDescriptions", []):
                resources.append({
                    "Type": "elb",
                    "Arn": lb.get("LoadBalancerName"),  # classic ELBs have no ARN
                    "Name": lb.get("LoadBalancerName"),
                    "Scheme": lb.get("Scheme"),
                    "DNSName": lb.get("DNSName"),
                    "LBType": "classic",
                    "Targets": [{"kind": "instance", "id": i.get("InstanceId")}
                                for i in lb.get("Instances", []) if i.get("InstanceId")],
                })
    except ClientError as e:
        failed = True
        print(f"    \033[1;33m[!]\033[0m ELB (classic) failed: {e}")

    if failed and not resources:
        with open(f"{path}/resources.json", "w") as f:
            json.dump({"Error": "ELB enumeration failed"}, f, indent=2)
        return

    with open(f"{path}/resources.json", "w") as f:
        json.dump(resources, f, indent=2, default=str)

    public = sum(1 for r in resources if r.get("Scheme") == "internet-facing")
    print(f"    \033[1;32m[+]\033[0m ELB Enumeration Finished ({len(resources)} load balancers, {public} internet-facing)")
