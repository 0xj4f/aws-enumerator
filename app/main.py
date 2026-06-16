
#!/usr/bin/env python3
import argparse
import boto3
import json
import os
import shutil
from datetime import datetime

try:
    from app.components import (iam, vpc, sg, ec2, s3, cloudtrail, cloudfront, waf,
                                 flowlogs, eks, k8s, secretsmanager, ssm, lambda_, kms,
                                 ecs, cloudformation, glue, codebuild, sagemaker,
                                 sns, sqs, ecr, rds, dynamodb, apigateway,
                                 cognito, ebs, elb, route53, policy_parser)
    from app.utils.aws_utils import get_boto3_session, get_enabled_regions
    from app.utils.dashboard import serve_dashboard
except ImportError:
    from components import (iam, vpc, sg, ec2, s3, cloudtrail, cloudfront, waf,
                            flowlogs, eks, k8s, secretsmanager, ssm, lambda_, kms,
                            ecs, cloudformation, glue, codebuild, sagemaker,
                            sns, sqs, ecr, rds, dynamodb, apigateway,
                            cognito, ebs, elb, route53, policy_parser)
    from utils.aws_utils import get_boto3_session, get_enabled_regions
    from utils.dashboard import serve_dashboard

VERSION = "0.2.0"


def print_banner(account_number, caller_identity, region=None, all_regions=False):
    mode_line = "    \033[1;32m[*]\033[0m Mode:     All regions" if all_regions else f"    \033[1;32m[*]\033[0m Region:   {region}"
    banner = f"""
    \033[1;34m╔══════════════════════════════════════╗
    ║\033[1;37m      AWS  Enumerator  v{VERSION}         \033[1;34m║
    ║\033[1;33m           Author: 0xj4f              \033[1;34m║
    ╚══════════════════════════════════════╝\033[0m

    \033[1;32m[*]\033[0m Account:  {account_number}
{mode_line}
    \033[1;32m[*]\033[0m Caller:   {caller_identity['Arn']}
    \033[1;32m[*]\033[0m Date:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    \033[1;34m──────────────────────────────────────\033[0m
    """
    print(banner)


def generate_manifest(base_path, account_number, caller_identity, start_time,
                      mode="single_region", region=None, regions_enumerated=None):
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
            "mode": mode,
            "region": region,
            "regions_enumerated": regions_enumerated or [],
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


def run_module(label, fn, *args, **kwargs):
    """Run one enumeration module, isolating failures.

    A crash in a single module (e.g. an unexpected error or a permission wall
    that raises) is logged and swallowed so the rest of the run continues.
    """
    try:
        fn(*args, **kwargs)
    except Exception as e:
        print(f"    \033[1;31m[-]\033[0m {label} module failed: {e}")


def enumerate_single_region(session, base_path):
    """Run all services in a single region directory (original behavior)."""
    run_module("iam", iam.enumerate, session, f"{base_path}/iam")
    run_module("vpc", vpc.enumerate, session, f"{base_path}/vpc")
    run_module("sg", sg.enumerate, session, f"{base_path}/sg")
    run_module("ec2", ec2.enumerate, session, f"{base_path}/ec2")
    run_module("s3", s3.enumerate, session, f"{base_path}/s3")
    run_module("flowlogs", flowlogs.enumerate, session, f"{base_path}/flowlogs")
    run_module("cloudtrail", cloudtrail.enumerate, session, f"{base_path}/cloudtrail")
    run_module("cloudfront", cloudfront.enumerate, session, f"{base_path}/cloudfront")
    run_module("waf", waf.enumerate, session, f"{base_path}/waf")
    run_module("eks", eks.enumerate, session, f"{base_path}/eks")
    run_module("k8s", k8s.enumerate, session, f"{base_path}/eks", f"{base_path}/k8s")
    run_module("secretsmanager", secretsmanager.enumerate, session, f"{base_path}/secretsmanager")
    run_module("ssm", ssm.enumerate, session, f"{base_path}/ssm")
    run_module("lambda", lambda_.enumerate, session, f"{base_path}/lambda")
    run_module("kms", kms.enumerate, session, f"{base_path}/kms")
    run_module("ecs", ecs.enumerate, session, f"{base_path}/ecs")
    run_module("cloudformation", cloudformation.enumerate, session, f"{base_path}/cloudformation")
    run_module("glue", glue.enumerate, session, f"{base_path}/glue")
    run_module("codebuild", codebuild.enumerate, session, f"{base_path}/codebuild")
    run_module("sagemaker", sagemaker.enumerate, session, f"{base_path}/sagemaker")
    run_module("sns", sns.enumerate, session, f"{base_path}/sns")
    run_module("sqs", sqs.enumerate, session, f"{base_path}/sqs")
    run_module("ecr", ecr.enumerate, session, f"{base_path}/ecr")
    run_module("rds", rds.enumerate, session, f"{base_path}/rds")
    run_module("dynamodb", dynamodb.enumerate, session, f"{base_path}/dynamodb")
    run_module("apigateway", apigateway.enumerate, session, f"{base_path}/apigateway")
    run_module("cognito", cognito.enumerate, session, f"{base_path}/cognito")
    run_module("ebs", ebs.enumerate, session, f"{base_path}/ebs")
    run_module("elb", elb.enumerate, session, f"{base_path}/elb")
    run_module("route53", route53.enumerate, session, f"{base_path}/route53")

    # Run policy analysis
    run_module("policy_parser", policy_parser.analyze, base_path)


def enumerate_global_services(session, global_path):
    """Enumerate global AWS services (IAM, S3, CloudFront, WAF CloudFront scope)."""
    print("    \033[1;36m[*]\033[0m Enumerating global services...\n")

    run_module("iam", iam.enumerate, session, f"{global_path}/iam")
    run_module("s3", s3.enumerate, session, f"{global_path}/s3")
    run_module("cloudfront", cloudfront.enumerate, session, f"{global_path}/cloudfront")
    run_module("waf", waf.enumerate, session, f"{global_path}/waf_cloudfront", scope="CLOUDFRONT")
    run_module("route53", route53.enumerate, session, f"{global_path}/route53")

    # Policy analysis on global IAM data
    run_module("policy_parser", policy_parser.analyze, global_path)


def enumerate_regional_services(session, region_path):
    """Enumerate regional AWS services for a single region."""
    run_module("vpc", vpc.enumerate, session, f"{region_path}/vpc")
    run_module("sg", sg.enumerate, session, f"{region_path}/sg")
    run_module("ec2", ec2.enumerate, session, f"{region_path}/ec2")
    run_module("cloudtrail", cloudtrail.enumerate, session, f"{region_path}/cloudtrail")
    run_module("flowlogs", flowlogs.enumerate, session, f"{region_path}/flowlogs")
    run_module("waf", waf.enumerate, session, f"{region_path}/waf", scope="REGIONAL")
    run_module("eks", eks.enumerate, session, f"{region_path}/eks")
    run_module("k8s", k8s.enumerate, session, f"{region_path}/eks", f"{region_path}/k8s")
    run_module("secretsmanager", secretsmanager.enumerate, session, f"{region_path}/secretsmanager")
    run_module("ssm", ssm.enumerate, session, f"{region_path}/ssm")
    run_module("lambda", lambda_.enumerate, session, f"{region_path}/lambda")
    run_module("kms", kms.enumerate, session, f"{region_path}/kms")
    run_module("ecs", ecs.enumerate, session, f"{region_path}/ecs")
    run_module("cloudformation", cloudformation.enumerate, session, f"{region_path}/cloudformation")
    run_module("glue", glue.enumerate, session, f"{region_path}/glue")
    run_module("codebuild", codebuild.enumerate, session, f"{region_path}/codebuild")
    run_module("sagemaker", sagemaker.enumerate, session, f"{region_path}/sagemaker")
    run_module("sns", sns.enumerate, session, f"{region_path}/sns")
    run_module("sqs", sqs.enumerate, session, f"{region_path}/sqs")
    run_module("ecr", ecr.enumerate, session, f"{region_path}/ecr")
    run_module("rds", rds.enumerate, session, f"{region_path}/rds")
    run_module("dynamodb", dynamodb.enumerate, session, f"{region_path}/dynamodb")
    run_module("apigateway", apigateway.enumerate, session, f"{region_path}/apigateway")
    run_module("cognito", cognito.enumerate, session, f"{region_path}/cognito")
    run_module("ebs", ebs.enumerate, session, f"{region_path}/ebs")
    run_module("elb", elb.enumerate, session, f"{region_path}/elb")


def parse_args():
    parser = argparse.ArgumentParser(description="AWS Enumerator - by 0xj4f")
    parser.add_argument("--region", default="eu-west-2", help="AWS Region (default eu-west-2)")
    parser.add_argument("--all", action="store_true", help="Enumerate all enabled regions")
    parser.add_argument("--zip", action="store_true", help="Create a zip archive of the report")
    parser.add_argument("--dashboard", action="store_true",
                        help="Serve the attack-graph dashboard locally and open it in the browser (no AWS creds needed)")
    parser.add_argument("--port", type=int, default=8000, help="Port for --dashboard (default 8000)")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.dashboard:
        serve_dashboard(args.port)
        return

    # Resilience: adaptive retries + a higher attempt cap so throttling
    # (429) and transient errors are retried with backoff across every client.
    os.environ.setdefault("AWS_RETRY_MODE", "adaptive")
    os.environ.setdefault("AWS_MAX_ATTEMPTS", "10")

    session = get_boto3_session(args.region)
    sts = session.client('sts')
    caller_identity = sts.get_caller_identity()
    account_number = caller_identity['Account']
    date_today = datetime.now().strftime("%Y%m%d")

    start_time = datetime.now()

    if args.all:
        # ── All regions mode ──
        account_path = f"reports/{date_today}/{account_number}"
        os.makedirs(account_path, exist_ok=True)

        print_banner(account_number, caller_identity, all_regions=True)

        # Global services (use us-east-1 session)
        global_session = get_boto3_session("us-east-1")
        global_path = f"{account_path}/global"
        os.makedirs(global_path, exist_ok=True)
        enumerate_global_services(global_session, global_path)

        # Discover enabled regions
        regions = get_enabled_regions(global_session)
        print(f"\n    \033[1;36m[*]\033[0m Discovered {len(regions)} enabled regions")
        print(f"    \033[1;36m[*]\033[0m Enumerating regional services...\n")

        # Sequential regional enumeration
        for i, region in enumerate(regions, 1):
            print(f"    \033[1;36m[*]\033[0m Region [{i}/{len(regions)}]: {region}\n")
            region_session = get_boto3_session(region)
            region_path = f"{account_path}/{region}"
            os.makedirs(region_path, exist_ok=True)
            enumerate_regional_services(region_session, region_path)
            print()

        # Manifest at account level
        generate_manifest(
            account_path, account_number, caller_identity, start_time,
            mode="all_regions", regions_enumerated=regions
        )

        elapsed = round((datetime.now() - start_time).total_seconds(), 2)
        print(f"    \033[1;32m[+]\033[0m Enumeration complete in {elapsed}s")
        print(f"    \033[1;32m[+]\033[0m Reports saved to: {account_path}")
        print(f"    \033[1;32m[+]\033[0m Manifest: {account_path}/manifest.json")

        if args.zip:
            zip_path = shutil.make_archive(
                account_path, 'zip',
                os.path.dirname(account_path), os.path.basename(account_path)
            )
            print(f"    \033[1;32m[+]\033[0m Zip archive: {zip_path}")

    else:
        # ── Single region mode (original behavior) ──
        base_path = f"reports/{date_today}/{account_number}/{args.region}"
        os.makedirs(base_path, exist_ok=True)

        print_banner(account_number, caller_identity, region=args.region)

        enumerate_single_region(session, base_path)

        generate_manifest(
            base_path, account_number, caller_identity, start_time,
            mode="single_region", region=args.region
        )

        elapsed = round((datetime.now() - start_time).total_seconds(), 2)
        print(f"\n    \033[1;32m[+]\033[0m Enumeration complete in {elapsed}s")
        print(f"    \033[1;32m[+]\033[0m Reports saved to: {base_path}")
        print(f"    \033[1;32m[+]\033[0m Manifest: {base_path}/manifest.json")

        if args.zip:
            zip_path = shutil.make_archive(
                base_path, 'zip',
                os.path.dirname(base_path), os.path.basename(base_path)
            )
            print(f"    \033[1;32m[+]\033[0m Zip archive: {zip_path}")

    print(f"    \033[1;36m[*]\033[0m Dashboard: run 'aws-enumerator --dashboard' and load the report")
    print()


if __name__ == "__main__":
    main()
