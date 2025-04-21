# AWS ENUMERATOR

The goal is to enumerate and map out resources and configurations in an AWS account, saving outputs as JSON files in a structured directory for easy review and further analysis.

---

##  Project Structure

The following directory layout clearly organizes your modules and outputs:

```
aws-enum/
├── app/
│   ├── main.py               # Entry-point (CLI handling)
│   ├── components/
│   │   ├── __init__.py
│   │   ├── iam.py            # IAM Users, Roles, Policies
│   │   ├── vpc.py            # VPCs, Subnets, Route Tables, Internet Gateways, NACLs
│   │   ├── sg.py             # Security Groups and Rules
│   │   ├── ec2.py            # EC2 instances and details
│   │   ├── ecr.py            # ECR repositories and details
│   │   ├── cloudtrail.py     # CloudTrail info
│   │   ├── cloudfront.py     # CloudFront distributions
│   │   ├── waf.py            # WAF WebACL configurations
│   │   └── flowlogs.py       # VPC Flow Logs
│   └── utils/
│       ├── __init__.py
│       └── aws_utils.py      # Boto3 session/helper functions
├── reports/                  # Output directory (generated)
│   └── {account_number}/
│       └── {region}/
│           ├── iam/
│           │   ├── users.json
│           │   ├── roles.json
│           │   └── policies.json
│           ├── vpc/
│           │   ├── vpcs.json
│           │   ├── subnets.json
│           │   ├── route_tables.json
│           │   ├── internet_gateways.json
│           │   ├── nat_gateways.json
│           │   └── nacls.json
│           ├── sg/
│           │   └── security_groups.json
│           ├── ec2/
│           │   └── instances.json
│           ├── ecr/
│           │   └── repositories.json
│           ├── cloudtrail/
│           │   └── trails.json
│           ├── cloudfront/
│           │   └── distributions.json
│           ├── waf/
│           │   └── web_acls.json
│           └── flowlogs/
│               └── flowlogs.json
├── requirements.txt          # Python dependencies
└── README.md
```

---

##  Command Line Interface (CLI)

Usage:

```bash
./app/main.py [--region REGION] [--all]
```

- Default region: `eu-west-2`
- `--region` to override region
- `--all` for future use (loop all regions - MVP skips this initially)

---

##  Workflow and Logic (Step-by-Step)

1. Initialize AWS Session (utils/aws_utils.py)  
   Create a reusable session function.
   
   ```python
   def get_boto3_session(region):
       import boto3
       return boto3.Session(region_name=region)
   ```

2. IAM Enumeration (components/iam.py)  
   - List all users, groups, roles, policies
   - Save descriptions for each into structured JSONs
   - Output examples:
     - `reports/{account}/{region}/iam/users.json`
     - `reports/{account}/{region}/iam/roles.json`
     - `reports/{account}/{region}/iam/policies.json`

3. EC2 Enumeration (components/ec2.py)  
   - Describe instances with details (ID, type, state, security groups)
   - Output to:
     - `reports/{account}/{region}/ec2/instances.json`

4. ECR Enumeration (components/ecr.py)  
   - List repositories and detailed metadata
   - Output to:
     - `reports/{account}/{region}/ecr/repositories.json`

5. CloudTrail Enumeration (components/cloudtrail.py)  
   - List Trails
   - Save details:
     - `reports/{account}/{region}/cloudtrail/trails.json`

6. CloudFront Enumeration (components/cloudfront.py)  
   - List distributions, configurations, origins
   - Output:
     - `reports/{account}/{region}/cloudfront/distributions.json`

7. WAF Enumeration (components/waf.py)  
   - List WebACLs, rules, configurations
   - Output:
     - `reports/{account}/{region}/waf/web_acls.json`

8. FlowLogs Enumeration (components/flowlogs.py)  
   - List VPC flow logs configurations
   - Output:
     - `reports/{account}/{region}/flowlogs/flowlogs.json`

---

##  Python Dependencies (`requirements.txt`)

Your MVP needs only minimal dependencies:

```text
boto3
```

Install using:

```bash
pip3 install -r requirements.txt
```

---

##  Sample Implementation (Skeleton - main.py)

Here's how your entry point might look (`app/main.py`):

```python
#!/usr/bin/env python3
import argparse
import boto3
import json
import os
from components import iam, ec2, ecr, cloudtrail, cloudfront, waf, flowlogs
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
    iam.enumerate(session, f"{base_path}/iam")
    ec2.enumerate(session, f"{base_path}/ec2")
    ecr.enumerate(session, f"{base_path}/ecr")
    cloudtrail.enumerate(session, f"{base_path}/cloudtrail")
    cloudfront.enumerate(session, f"{base_path}/cloudfront")
    waf.enumerate(session, f"{base_path}/waf")
    flowlogs.enumerate(session, f"{base_path}/flowlogs")

if __name__ == "__main__":
    main()
```

---

##  Component Example (IAM)

(`components/iam.py`):

```python
import boto3, json, os

def enumerate(session, path):
    os.makedirs(path, exist_ok=True)
    iam_client = session.client('iam')

    # Users
    users = iam_client.list_users()['Users']
    with open(f"{path}/users.json", "w") as f:
        json.dump(users, f, default=str, indent=2)

    # Roles
    roles = iam_client.list_roles()['Roles']
    with open(f"{path}/roles.json", "w") as f:
        json.dump(roles, f, default=str, indent=2)

    # Policies
    policies = iam_client.list_policies(Scope='Local')['Policies']
    with open(f"{path}/policies.json", "w") as f:
        json.dump(policies, f, default=str, indent=2)
```

This provides a straightforward and consistent pattern to repeat for other components.

---

##  Validation Checklist

| Task                          | Status  |
|-------------------------------|---------|
| Directory structure           |  Done |
| CLI & Argument Parsing        |  Done |
| IAM component                 |  Sample |
| EC2 component                 |  Planned |
| ECR component                 |  Planned |
| CloudTrail component          |  Planned |
| CloudFront component          |  Planned |
| WAF component                 |  Planned |
| FlowLogs component            |  Planned |
| JSON outputs structure        |  Done |
| Dependency management         |  Done |

---

##  Future Enhancements (Post-MVP)

- Multi-region (`--all` flag)
- Comprehensive error handling & logging
- Parallel requests for speed optimization
- Encryption & security for generated reports

---

## Next Steps:

- Validate this structure and approach meets your requirements.
- Proceed to implement the rest of the components following the IAM example.
- Run initial tests to verify JSON output formatting.

# AWS COMMANDS

```bash

aws sts assume-role \
  --role-arn arn:aws:iam::00000000:role/test-role \
  --role-session-name test-session

{
    "Credentials": {
        "AccessKeyId": "x",
        "SecretAccessKey": "x",
        "SessionToken": "x",
        "Expiration": "x"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "XXXXX:test-session",
        "Arn": "arn:aws:sts::XXXXXX:assumed-role/test-role/test-session"
    }
}

```



Get Access And Secret Key of Account
```bash
aws sts get-session-token --duration-seconds 3600 # 1 hr

aws configure export-credentials --format env
aws configure export-credentials --profile not_default --format env
```