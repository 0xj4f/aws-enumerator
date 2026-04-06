
#!/usr/bin/env python3
import argparse
import boto3
import json
import os
import shutil
from components import iam, vpc, sg, ec2, s3, cloudtrail, cloudfront, waf, flowlogs, policy_parser
from utils.aws_utils import get_boto3_session
from datetime import datetime

VERSION = "0.2.0"

def print_banner(account_number, region, caller_identity):
    banner = f"""
    \033[1;34m╔══════════════════════════════════════╗
    ║\033[1;37m      AWS  Enumerator  v{VERSION}         \033[1;34m║
    ║\033[1;33m           Author: 0xj4f              \033[1;34m║
    ╚══════════════════════════════════════╝\033[0m

    \033[1;32m[*]\033[0m Account:  {account_number}
    \033[1;32m[*]\033[0m Region:   {region}
    \033[1;32m[*]\033[0m Caller:   {caller_identity['Arn']}
    \033[1;32m[*]\033[0m Date:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    \033[1;34m──────────────────────────────────────\033[0m
    """
    print(banner)


def generate_manifest(base_path, account_number, region, caller_identity, start_time):
    end_time = datetime.now()
    modules = []

    for entry in sorted(os.listdir(base_path)):
        entry_path = os.path.join(base_path, entry)
        if os.path.isdir(entry_path):
            files = []
            for root, dirs, filenames in os.walk(entry_path):
                for fname in filenames:
                    rel = os.path.relpath(os.path.join(root, fname), entry_path)
                    files.append(rel)
            modules.append({
                "name": entry,
                "path": f"{entry}/",
                "file_count": len(files),
                "files": sorted(files)
            })

    manifest = {
        "tool": "aws-enumerator",
        "version": VERSION,
        "author": "0xj4f",
        "run_metadata": {
            "account_id": account_number,
            "region": region,
            "caller_arn": caller_identity['Arn'],
            "caller_user_id": caller_identity.get('UserId', ''),
            "timestamp_start": start_time.isoformat(),
            "timestamp_end": end_time.isoformat(),
            "duration_seconds": round((end_time - start_time).total_seconds(), 2)
        },
        "modules_executed": modules
    }

    with open(os.path.join(base_path, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2, default=str)


def parse_args():
    parser = argparse.ArgumentParser(description="AWS Enumerator - by 0xj4f")
    parser.add_argument("--region", default="eu-west-2", help="AWS Region (default eu-west-2)")
    parser.add_argument("--all", action="store_true", help="Enumerate all regions (future)")
    parser.add_argument("--zip", action="store_true", help="Create a zip archive of the report")
    return parser.parse_args()

def main():
    args = parse_args()
    session = get_boto3_session(args.region)
    sts = session.client('sts')
    caller_identity = sts.get_caller_identity()
    account_number = caller_identity['Account']
    date_today = datetime.now().strftime("%Y%m%d")

    base_path = f"reports/{date_today}/{account_number}/{args.region}"
    os.makedirs(base_path, exist_ok=True)

    print_banner(account_number, args.region, caller_identity)

    start_time = datetime.now()

    # Enumerate each AWS component
    iam.enumerate(session, f"{base_path}/iam")
    vpc.enumerate(session, f"{base_path}/vpc")
    sg.enumerate(session, f"{base_path}/sg")
    ec2.enumerate(session, f"{base_path}/ec2")
    s3.enumerate(session, f"{base_path}/s3")
    flowlogs.enumerate(session, f"{base_path}/flowlogs")
    cloudtrail.enumerate(session, f"{base_path}/cloudtrail")
    cloudfront.enumerate(session, f"{base_path}/cloudfront")
    waf.enumerate(session, f"{base_path}/waf")

    # Run policy analysis
    policy_parser.analyze(base_path)

    generate_manifest(base_path, account_number, args.region, caller_identity, start_time)

    elapsed = round((datetime.now() - start_time).total_seconds(), 2)
    print(f"\n    \033[1;32m[+]\033[0m Enumeration complete in {elapsed}s")
    print(f"    \033[1;32m[+]\033[0m Reports saved to: {base_path}")
    print(f"    \033[1;32m[+]\033[0m Manifest: {base_path}/manifest.json")

    if args.zip:
        zip_path = shutil.make_archive(base_path, 'zip', os.path.dirname(base_path), os.path.basename(base_path))
        print(f"    \033[1;32m[+]\033[0m Zip archive: {zip_path}")

    print()


if __name__ == "__main__":
    main()
