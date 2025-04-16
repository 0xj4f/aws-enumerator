
#!/usr/bin/env python3
import argparse
import boto3
import json
import os
from components import cloudfront
# from components import iam, vpc, sg, ec2, ecr, cloudtrail, cloudfront, waf, flowlogs
from utils.aws_utils import get_boto3_session

def parse_args():
    parser = argparse.ArgumentParser(description="AWS Enumeration Tool")
    parser.add_argument("--region", default="eu-west-2", help="AWS Region (default eu-west-2)")
    parser.add_argument("--all", action="store_true", help="Enumerate all regions (future)")
    return parser.parse_args()

def main():
    args = parse_args()
    session = get_boto3_session(args.region)
    sts = session.client('sts')
    account_number = sts.get_caller_identity()['Account']

    base_path = f"reports/{account_number}/{args.region}"
    os.makedirs(base_path, exist_ok=True)

    # Enumerate each AWS component
    # iam.enumerate(session, f"{base_path}/iam")
    # vpc.enumerate(session, f"{base_path}/vpc")
    # sg.enumerate(session, f"{base_path}/sg")
    # ec2.enumerate(session, f"{base_path}/ec2")
    # flowlogs.enumerate(session, f"{base_path}/flowlogs")
    # ecr.enumerate(session, f"{base_path}/ecr")
    # cloudtrail.enumerate(session, f"{base_path}/cloudtrail")
    cloudfront.enumerate(session, f"{base_path}/cloudfront")
    # waf.enumerate(session, f"{base_path}/waf")
    

if __name__ == "__main__":
    main()