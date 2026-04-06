import os
import json

def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m Flow Logs Enumeration Starting...")
    os.makedirs(path, exist_ok=True)
    ec2_client = session.client("ec2")

    # Describe VPC Flow Logs
    flow_logs = []
    paginator = ec2_client.get_paginator("describe_flow_logs")
    for page in paginator.paginate():
        flow_logs.extend(page.get("FlowLogs", []))

    # Save to JSON
    with open(f"{path}/flowlogs.json", "w") as f:
        json.dump(flow_logs, f, default=str, indent=2)

    print("    \033[1;32m[+]\033[0m Flow Logs Enumeration Finished!")
