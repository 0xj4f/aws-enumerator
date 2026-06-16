import json
import os

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def get_boto3_session(region):
    return boto3.Session(region_name=region)


def save_json(path, filename, data):
    """Write data as pretty JSON under path, creating the directory if needed."""
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, filename), "w") as f:
        json.dump(data, f, indent=2, default=str)


def safe(label, fn, default=None):
    """Run fn() and return its result; on an AWS call failure, warn and return default.

    Lets a single denied/throttled/transient API call degrade gracefully instead
    of aborting the surrounding enumeration.
    """
    try:
        return fn()
    except (BotoCoreError, ClientError) as e:
        if isinstance(e, ClientError):
            detail = e.response.get("Error", {}).get("Code", "ClientError")
        else:
            detail = type(e).__name__
        print(f"    \033[1;33m[!]\033[0m {label} failed ({detail})")
        return default


def get_enabled_regions(session):
    """Query EC2 for all enabled regions in this account."""
    ec2 = session.client('ec2')
    response = ec2.describe_regions(
        Filters=[{'Name': 'opt-in-status', 'Values': ['opt-in-not-required', 'opted-in']}]
    )
    return sorted([r['RegionName'] for r in response['Regions']])
