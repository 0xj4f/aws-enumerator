"""World "acme": synthetic AWS account 111122223333 for collector characterisation.

Deterministic resources answering **every** API call the 30 baseline collectors
make, in two regions (``eu-west-1``, ``eu-west-2``) plus ``us-east-1`` for the
global services (IAM, S3, CloudFront, Route 53, WAF CLOUDFRONT scope, STS).

* ``eu-west-2`` is the "rich" region: every service has resources, a few per-item
  denies/not-founds exercise the per-item error paths.
* ``eu-west-1`` is the "partially denied" region: several list calls are denied,
  one call raises a ``BotoCoreError`` (EndpointConnectionError) and one a read
  timeout, so module-level error encodings (A/B/B'/F/G in
  ``internal-docs/fix-plan/explore-contract-map.md`` section 1) are exercised.
* The EKS cluster ``demo-cluster`` (eu-west-2) has a matching fake Kubernetes
  cluster (:func:`build_k8s_clusters`); ``demo-west-cluster`` (eu-west-1) answers
  401 Unauthorized.

Secret canaries (:data:`CANARIES`) are planted wherever a later stream must
redact; the baseline code leaks some of them (characterised in
``tests/python/collectors/test_collectors_v0_golden.py``).

**Wave 1 operations** (collectors-cli.md §5, request regressions-py-2): the world also answers every call
the migrated collectors make (GAAD with pagination, boundaries, tags and policy versions; the credential
report; S3 policy status / ownership / website / replication and the account PAB; EC2 addresses, launch
templates, AMIs, transit gateways, VPN, prefix lists, block-public-access states; Lambda URL configs,
aliases, layers, event source mappings; ECS families/services; stack sets; SageMaker domains; SNS
subscriptions; ECR registry; Aurora clusters; API Gateway stages/routes; Cognito user pools; ELB
listeners; EKS access entries and Pod Identity; Organizations; GuardDuty; Security Hub; Config; Access
Analyzer). That data lives in keys the baseline handlers never return (see ``_extend_eu_west_2``), so the
collectors-v0 goldens only show it once a collector is migrated. ``cognito-idp:DescribeUserPoolClient`` is
deliberately **not** modelled: it returns the client secret and must never be called.

**Ids follow docs/contracts/node-ids.md**: EC2-family ids are hexadecimal (``i-0dec0eeb000000002``,
``sg-0dec0abb000000002`` ...; "dec0" reads "demo"), so a v2 engine can build a valid ``graph.json`` from an
acme run. Tests read ids from :data:`REGIONAL` rather than hard-coding them.

Only placeholder account IDs (111122223333 / 999999999999) and ``demo-*`` /
``example.com`` names are used.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from dateutil.tz import tzutc

from tests.support.fake_kubernetes import DEFAULT_SELF_RULES, ApiException, FakeCluster
from tests.support.fakeaws import AWSError, PaginationSpec, Request, World, botocore_error

# ── Identity ─────────────────────────────────────────────────────────────────
ACCOUNT_ID = "111122223333"
EXTERNAL_ACCOUNT_ID = "999999999999"
PARTITION = "aws"
REGIONS = ("eu-west-1", "eu-west-2")
GLOBAL_REGION = "us-east-1"
NOT_OPTED_IN_REGIONS = ("af-south-1",)   # listed by DescribeRegions as not-opted-in
SINGLE_REGION = "eu-west-2"

CALLER = {
    "UserId": "AROAEXAMPLEDEMOAUDIT01:demo-session",
    "Account": ACCOUNT_ID,
    "Arn": f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/demo-audit-role/demo-session",
}

UTC = tzutc()


def ts(day: int = 15, hour: int = 10, minute: int = 0, month: int = 1, year: int = 2024) -> datetime:
    return datetime(year, month, day, hour, minute, 0, tzinfo=UTC)


T0 = ts()

# ── Canaries (must never appear in a report once redaction lands) ────────────
CANARY = "CANARY-SECRET-VALUE"
CANARIES: Dict[str, str] = {
    "cloudfront_custom_header": f"{CANARY}-cloudfront-origin-header",
    "k8s_secret_last_applied": f"{CANARY}-k8s-last-applied",
    "k8s_pod_env": f"{CANARY}-k8s-pod-env",
    "k8s_init_container_env": f"{CANARY}-k8s-init-container-env",
    "lambda_env": f"{CANARY}-lambda-env",
    "codebuild_env": f"{CANARY}-codebuild-env",
    "codebuild_source_url": f"{CANARY}-codebuild-source-token",
    "cfn_parameter": f"{CANARY}-cfn-parameter",
    "cfn_output": f"{CANARY}-cfn-output",
    "glue_args": f"{CANARY}-glue-default-args",
    "ecs_env": f"{CANARY}-ecs-container-env",
    "ssm_description": f"{CANARY}-ssm-description",
    "secrets_description": f"{CANARY}-secrets-description",
    "route53_txt": f"{CANARY}-route53-txt",
    "eks_addon_config": f"{CANARY}-eks-addon-config",
    "ec2_user_data": f"{CANARY}-ec2-user-data",
    # Wave 1 calls only (collectors-cli.md §5); the baseline collectors never read these locations.
    "launch_template_user_data": f"{CANARY}-launch-template-user-data",
    "vpn_psk": f"{CANARY}-vpn-pre-shared-key",
    "cfn_stackset_parameter": f"{CANARY}-cfn-stackset-parameter",
    "sns_endpoint_token": f"{CANARY}-sns-endpoint-token",
}


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


# ── ARN helpers ──────────────────────────────────────────────────────────────
def iam_arn(kind: str, name: str, path: str = "/") -> str:
    return f"arn:aws:iam::{ACCOUNT_ID}:{kind}{path}{name}"


def role_arn(name: str) -> str:
    return iam_arn("role", name)


def policy_arn(name: str) -> str:
    return iam_arn("policy", name)


def managed_arn(name: str) -> str:
    return f"arn:aws:iam::aws:policy/{name}"


def lambda_arn(region: str, name: str) -> str:
    return f"arn:aws:lambda:{region}:{ACCOUNT_ID}:function:{name}"


def kms_arn(region: str, key_id: str) -> str:
    return f"arn:aws:kms:{region}:{ACCOUNT_ID}:key/{key_id}"


def _doc(*statements: Dict[str, Any]) -> Dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _allow(actions: Any, resources: Any = "*", **extra: Any) -> Dict[str, Any]:
    stmt = {"Effect": "Allow", "Action": actions, "Resource": resources}
    stmt.update(extra)
    return stmt


def _trust(principal: Dict[str, Any], action: str = "sts:AssumeRole", condition: Optional[Dict] = None) -> Dict:
    stmt: Dict[str, Any] = {"Effect": "Allow", "Principal": principal, "Action": action}
    if condition:
        stmt["Condition"] = condition
    return _doc(stmt)


# ═════════════════════════════════════════════════════════════════════════════
# IAM (global)
# ═════════════════════════════════════════════════════════════════════════════
OIDC_ISSUER = "oidc.eks.eu-west-2.amazonaws.com/id/DEMO0000000000000000000000000002"
OIDC_PROVIDER_ARN = f"arn:aws:iam::{ACCOUNT_ID}:oidc-provider/{OIDC_ISSUER}"

AWS_MANAGED: Dict[str, Dict[str, Any]] = {
    "AdministratorAccess": {"id": "ANPAIWMBCKSKIEE64ZLYK", "version": "v1",
                            "doc": _doc(_allow("*", "*"))},
    "ReadOnlyAccess": {"id": "ANPAILL3HVNFSB6DCOWYQ", "version": "v118",
                       "doc": _doc(_allow(["s3:Get*", "s3:List*", "ec2:Describe*", "iam:Get*", "iam:List*"]))},
    "AmazonEKSWorkerNodePolicy": {"id": "ANPAIBVMOY52IPQ6HD3PO", "version": "v3",
                                  "doc": _doc(_allow(["ec2:DescribeInstances", "eks:DescribeCluster"]))},
    "AmazonEKSClusterPolicy": {"id": "ANPAIBTLDQMIC6UOIGFWA", "version": "v5",
                               "doc": _doc(_allow(["ec2:CreateNetworkInterface", "ec2:Describe*"]))},
}

CUSTOMER_POLICIES: Dict[str, Dict[str, Any]] = {
    "demo-app-policy": {
        "id": "ANPAEXAMPLEAPPPOLICY01", "default": "v1", "attachments": 1,
        "versions": {"v1": _doc(
            _allow(["s3:GetObject", "s3:PutObject"], "arn:aws:s3:::demo-data-bucket/*"),
            _allow(["sqs:SendMessage"], f"arn:aws:sqs:eu-west-2:{ACCOUNT_ID}:demo-queue"),
        )},
    },
    "demo-broken-policy": {
        "id": "ANPAEXAMPLEBROKENPOL01", "default": "v1", "attachments": 0,
        "versions": {"v1": _doc(_allow("s3:ListAllMyBuckets"))},
    },
    "demo-ci-deploy": {
        "id": "ANPAEXAMPLECIDEPLOY001", "default": "v1", "attachments": 1,
        "versions": {"v1": _doc(
            _allow(["lambda:CreateFunction", "lambda:UpdateFunctionCode", "lambda:InvokeFunction"]),
            _allow("iam:PassRole", role_arn("demo-lambda-role")),
            _allow(["cloudformation:CreateStack", "cloudformation:UpdateStack"]),
        )},
    },
    "demo-dev-policy": {
        "id": "ANPAEXAMPLEDEVPOLICY01", "default": "v2", "attachments": 2,
        "versions": {
            "v1": _doc(_allow("ec2:Describe*")),
            "v2": _doc(
                _allow(["ec2:Describe*", "ec2:RunInstances"]),
                _allow("iam:PassRole", role_arn("demo-app-role")),
                _allow("s3:GetObject", "arn:aws:s3:::demo-data-bucket/*"),
            ),
        },
    },
}


def _attached(names: List[str]) -> List[Dict[str, str]]:
    out = []
    for n in names:
        arn = managed_arn(n) if n in AWS_MANAGED else policy_arn(n)
        out.append({"PolicyName": n, "PolicyArn": arn})
    return out


USERS: List[Dict[str, Any]] = [
    {
        "UserName": "demo-alice", "UserId": "AIDAEXAMPLEALICE00001", "CreateDate": ts(2), "PasswordLastUsed": ts(14),
        "groups": ["demo-developers"], "attached": ["demo-dev-policy"],
        "inline": {"demo-alice-s3-inline": _doc(_allow(["s3:ListBucket"], "arn:aws:s3:::demo-data-bucket"))},
        "login": ts(2), "mfa": [f"arn:aws:iam::{ACCOUNT_ID}:mfa/demo-alice"],
        "keys": [("AKIAEXAMPLEALICE0001", "Active", ts(3))],
    },
    {
        "UserName": "demo-bob", "UserId": "AIDAEXAMPLEBOB0000001", "CreateDate": ts(4),
        "groups": ["demo-admins"], "attached": [], "inline": {},
        "login": None, "mfa": [],
        "keys": [("AKIAEXAMPLEBOB000001", "Active", ts(4)), ("AKIAEXAMPLEBOB000002", "Inactive", ts(5))],
    },
    {
        "UserName": "demo-ci", "UserId": "AIDAEXAMPLECI00000001", "CreateDate": ts(6),
        "groups": [], "attached": ["demo-ci-deploy"],
        "inline": {"demo-ci-passrole": _doc(_allow("iam:PassRole", role_arn("demo-build-role")),
                                            _allow("codebuild:StartBuild"))},
        "login": None, "mfa": [],
        "keys": [("AKIAEXAMPLECI0000001", "Active", ts(6))],
    },
]

GROUPS: List[Dict[str, Any]] = [
    {"GroupName": "demo-admins", "GroupId": "AGPAEXAMPLEADMINS0001", "attached": ["AdministratorAccess"], "inline": {}},
    {"GroupName": "demo-developers", "GroupId": "AGPAEXAMPLEDEVS000001", "attached": ["demo-dev-policy"],
     "inline": {"demo-dev-ssm-inline": _doc(_allow(["ssm:StartSession", "ssm:SendCommand"]))}},
]

ROLES: List[Dict[str, Any]] = [
    {"RoleName": "demo-admin-role", "RoleId": "AROAEXAMPLEADMINROLE1",
     "trust": _trust({"AWS": iam_arn("user", "demo-alice")}), "attached": ["AdministratorAccess"], "inline": {}},
    {"RoleName": "demo-app-role", "RoleId": "AROAEXAMPLEAPPROLE001",
     "trust": _trust({"Service": "ec2.amazonaws.com"}), "attached": ["demo-app-policy"],
     "inline": {"demo-app-secrets-inline": _doc(
         _allow("secretsmanager:GetSecretValue", f"arn:aws:secretsmanager:eu-west-2:{ACCOUNT_ID}:secret:demo/*"),
         _allow(["kms:Decrypt"], kms_arn("eu-west-2", "1111aaaa-0000-4000-8000-0000000000a1")),
         _allow(["ssm:GetParameter"], f"arn:aws:ssm:eu-west-2:{ACCOUNT_ID}:parameter/demo/*"),
     )}},
    {"RoleName": "demo-build-role", "RoleId": "AROAEXAMPLEBUILDROLE1",
     "trust": _trust({"Service": "codebuild.amazonaws.com"}), "attached": ["AdministratorAccess"], "inline": {}},
    {"RoleName": "demo-cfn-role", "RoleId": "AROAEXAMPLECFNROLE001",
     "trust": _trust({"Service": "cloudformation.amazonaws.com"}), "attached": ["AdministratorAccess"], "inline": {}},
    {"RoleName": "demo-cognito-unauth-role", "RoleId": "AROAEXAMPLECOGNITO001",
     "trust": _trust({"Federated": "cognito-identity.amazonaws.com"}, "sts:AssumeRoleWithWebIdentity",
                     {"StringEquals": {"cognito-identity.amazonaws.com:aud":
                                       "eu-west-2:11111111-2222-4333-8444-55555555555a"},
                      "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "unauthenticated"}}),
     "attached": [], "inline": {"demo-cognito-s3": _doc(_allow("s3:GetObject", "arn:aws:s3:::demo-public-site/*"))}},
    {"RoleName": "demo-cross-account-role", "RoleId": "AROAEXAMPLEXACCOUNT01",
     "trust": _trust({"AWS": f"arn:aws:iam::{EXTERNAL_ACCOUNT_ID}:root"}, condition={
         "StringEquals": {"sts:ExternalId": "demo-external-id"}}),
     "attached": ["ReadOnlyAccess"], "inline": {}},
    {"RoleName": "demo-ecs-task-role", "RoleId": "AROAEXAMPLEECSTASK001",
     "trust": _trust({"Service": "ecs-tasks.amazonaws.com"}), "attached": [],
     "inline": {"demo-ecs-sqs": _doc(_allow(["sqs:ReceiveMessage", "sqs:DeleteMessage"]))}},
    {"RoleName": "demo-eks-cluster-role", "RoleId": "AROAEXAMPLEEKSCLUST01",
     "trust": _trust({"Service": "eks.amazonaws.com"}), "attached": ["AmazonEKSClusterPolicy"], "inline": {}},
    {"RoleName": "demo-eks-node-role", "RoleId": "AROAEXAMPLEEKSNODE001",
     "trust": _trust({"Service": "ec2.amazonaws.com"}), "attached": ["AmazonEKSWorkerNodePolicy"], "inline": {}},
    {"RoleName": "demo-glue-role", "RoleId": "AROAEXAMPLEGLUEROLE01",
     "trust": _trust({"Service": "glue.amazonaws.com"}), "attached": [],
     "inline": {"demo-glue-s3": _doc(_allow(["s3:*"], "arn:aws:s3:::demo-data-bucket*"))}},
    {"RoleName": "demo-irsa-role", "RoleId": "AROAEXAMPLEIRSAROLE01",
     "trust": _trust({"Federated": OIDC_PROVIDER_ARN}, "sts:AssumeRoleWithWebIdentity",
                     {"StringEquals": {f"{OIDC_ISSUER}:sub": "system:serviceaccount:demo-apps:demo-api"}}),
     "attached": [], "inline": {"demo-irsa-secrets": _doc(
         _allow("secretsmanager:GetSecretValue", f"arn:aws:secretsmanager:eu-west-2:{ACCOUNT_ID}:secret:demo/*"))}},
    {"RoleName": "demo-lambda-role", "RoleId": "AROAEXAMPLELAMBDAR001",
     "trust": _trust({"Service": "lambda.amazonaws.com"}), "attached": [],
     "inline": {"demo-lambda-inline": _doc(_allow(["iam:CreateAccessKey"])),
                "demo-lambda-logs": _doc(_allow(["logs:CreateLogStream", "logs:PutLogEvents"]))}},
    {"RoleName": "demo-sagemaker-role", "RoleId": "AROAEXAMPLESAGEMAKER1",
     "trust": _trust({"Service": "sagemaker.amazonaws.com"}), "attached": [], "inline": {}},
]

INSTANCE_PROFILES = [
    ("demo-app-profile", "AIPAEXAMPLEAPPPROF001", "demo-app-role"),
    ("demo-eks-node-profile", "AIPAEXAMPLENODEPROF01", "demo-eks-node-role"),
]


def _iam_user(u: Dict[str, Any]) -> Dict[str, Any]:
    out = {"Path": "/", "UserName": u["UserName"], "UserId": u["UserId"],
           "Arn": iam_arn("user", u["UserName"]), "CreateDate": u["CreateDate"]}
    if u.get("PasswordLastUsed"):
        out["PasswordLastUsed"] = u["PasswordLastUsed"]
    return out


def _iam_group(g: Dict[str, Any]) -> Dict[str, Any]:
    return {"Path": "/", "GroupName": g["GroupName"], "GroupId": g["GroupId"],
            "Arn": iam_arn("group", g["GroupName"]), "CreateDate": ts(1)}


def _iam_role(r: Dict[str, Any]) -> Dict[str, Any]:
    return {"Path": "/", "RoleName": r["RoleName"], "RoleId": r["RoleId"], "Arn": role_arn(r["RoleName"]),
            "CreateDate": ts(1), "AssumeRolePolicyDocument": World.iam_doc(r["trust"]),
            "Description": f"{r['RoleName']} (acme synthetic)", "MaxSessionDuration": 3600}


def _by(items: List[Dict[str, Any]], key: str) -> Dict[str, Dict[str, Any]]:
    return {i[key]: i for i in items}


# ═════════════════════════════════════════════════════════════════════════════
# S3 (global)
# ═════════════════════════════════════════════════════════════════════════════
OWNER = {"DisplayName": "demo-owner", "ID": "0" * 64}
KEY_W2 = "1111aaaa-0000-4000-8000-0000000000a1"

S3_BUCKETS: List[Dict[str, Any]] = [
    {
        "Name": "demo-data-bucket", "CreationDate": ts(1), "location": "eu-west-2",
        "policy": _doc(
            {"Sid": "AppRead", "Effect": "Allow", "Principal": {"AWS": role_arn("demo-app-role")},
             "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::demo-data-bucket/*"},
            {"Sid": "DenyInsecure", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
             "Resource": ["arn:aws:s3:::demo-data-bucket", "arn:aws:s3:::demo-data-bucket/*"],
             "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
        ),
        "acl": {"Owner": OWNER, "Grants": [{"Grantee": {"Type": "CanonicalUser", "ID": OWNER["ID"],
                                                        "DisplayName": "demo-owner"}, "Permission": "FULL_CONTROL"}]},
        "pab": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True},
        "versioning": {"Status": "Enabled", "MFADelete": "Disabled"},
        "encryption": {"Rules": [{"ApplyServerSideEncryptionByDefault": {
            "SSEAlgorithm": "aws:kms", "KMSMasterKeyID": kms_arn("eu-west-2", KEY_W2)}, "BucketKeyEnabled": True}]},
        "tags": [{"Key": "env", "Value": "demo"}, {"Key": "owner", "Value": "demo-team"}],
        "logging": {"TargetBucket": "demo-logs-bucket", "TargetPrefix": "data/"},
        "cors": None,
        "notifications": {
            "LambdaFunctionConfigurations": [{"Id": "demo-on-upload",
                                              "LambdaFunctionArn": lambda_arn("eu-west-2", "demo-processor"),
                                              "Events": ["s3:ObjectCreated:*"]}],
            "QueueConfigurations": [{"Id": "demo-to-queue",
                                     "QueueArn": f"arn:aws:sqs:eu-west-2:{ACCOUNT_ID}:demo-queue",
                                     "Events": ["s3:ObjectRemoved:*"]}],
        },
    },
    {
        "Name": "demo-denied-bucket", "CreationDate": ts(2), "location": "eu-west-2",
        "policy": None, "acl": None, "pab": None, "versioning": {}, "encryption": None, "tags": None,
        "logging": None, "cors": None, "notifications": {},
    },
    {
        "Name": "demo-legacy-eu-bucket", "CreationDate": ts(3), "location": "EU",
        "policy": _doc(_allow("s3:GetObject", "arn:aws:s3:::demo-legacy-eu-bucket/*", Principal="*")),
        "acl": None, "pab": None, "versioning": {"Status": "Suspended"},
        "encryption": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                                  "BucketKeyEnabled": False}]},
        "tags": None, "logging": None, "cors": None, "notifications": {},
    },
    {
        "Name": "demo-logs-bucket", "CreationDate": ts(4), "location": None,
        "policy": None,
        "acl": {"Owner": OWNER, "Grants": [
            {"Grantee": {"Type": "CanonicalUser", "ID": OWNER["ID"], "DisplayName": "demo-owner"},
             "Permission": "FULL_CONTROL"},
            {"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"},
             "Permission": "WRITE"}]},
        "pab": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True},
        "versioning": {},
        "encryption": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                                  "BucketKeyEnabled": False}]},
        "tags": [{"Key": "env", "Value": "demo"}], "logging": None, "cors": None, "notifications": {},
    },
    {
        "Name": "demo-public-site", "CreationDate": ts(5), "location": "eu-west-1",
        "policy": _doc({"Sid": "PublicRead", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::demo-public-site/*"}),
        "acl": {"Owner": OWNER, "Grants": [
            {"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
             "Permission": "READ"}]},
        "pab": None,  # NoSuchPublicAccessBlockConfiguration
        "versioning": {},
        "encryption": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                                  "BucketKeyEnabled": False}]},
        "tags": None,
        "logging": None,
        "cors": [{"AllowedMethods": ["GET"], "AllowedOrigins": ["*"], "AllowedHeaders": ["*"], "MaxAgeSeconds": 300}],
        "notifications": {},
    },
]

# ═════════════════════════════════════════════════════════════════════════════
# CloudFront (global)
# ═════════════════════════════════════════════════════════════════════════════
CF_ACL_ID = "c0c0c0c0-0000-4000-8000-0000000000c1"
CF_ACL_ARN = f"arn:aws:wafv2:us-east-1:{ACCOUNT_ID}:global/webacl/demo-cf-acl/{CF_ACL_ID}"


def _cf_origin(origin_id: str, domain: str, *, s3: bool = False, headers=()) -> Dict[str, Any]:
    custom_headers: Dict[str, Any] = {"Quantity": len(headers)}
    if headers:
        custom_headers["Items"] = [{"HeaderName": n, "HeaderValue": v} for n, v in headers]
    origin: Dict[str, Any] = {"Id": origin_id, "DomainName": domain, "OriginPath": "",
                              "CustomHeaders": custom_headers, "ConnectionAttempts": 3, "ConnectionTimeout": 10,
                              "OriginAccessControlId": ""}
    if s3:
        origin["S3OriginConfig"] = {"OriginAccessIdentity": ""}
    else:
        origin["CustomOriginConfig"] = {"HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only",
                                        "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                                        "OriginReadTimeout": 30, "OriginKeepaliveTimeout": 5}
    return origin


def _cf_behavior(origin_id: str) -> Dict[str, Any]:
    return {"TargetOriginId": origin_id, "ViewerProtocolPolicy": "redirect-to-https",
            "TrustedSigners": {"Enabled": False, "Quantity": 0},
            "TrustedKeyGroups": {"Enabled": False, "Quantity": 0},
            "AllowedMethods": {"Quantity": 2, "Items": ["HEAD", "GET"],
                               "CachedMethods": {"Quantity": 2, "Items": ["HEAD", "GET"]}},
            "SmoothStreaming": False, "Compress": True,
            "LambdaFunctionAssociations": {"Quantity": 0}, "FunctionAssociations": {"Quantity": 0},
            "FieldLevelEncryptionId": "", "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6"}


CF_DISTRIBUTIONS: List[Dict[str, Any]] = [
    {
        "Id": "E1DEMOEXAMPLE01", "DomainName": "d111111abcdef8.cloudfront.net", "Comment": "demo public site",
        "Aliases": ["www.example.com"], "WebACLId": CF_ACL_ARN, "PriceClass": "PriceClass_100",
        "Origins": [
            _cf_origin("s3-site", "demo-public-site.s3.eu-west-1.amazonaws.com", s3=True),
            _cf_origin("api-origin", "api.example.com",
                       headers=[("X-Origin-Verify", CANARIES["cloudfront_custom_header"])]),
        ],
        "Logging": {"Enabled": True, "IncludeCookies": False, "Bucket": "demo-logs-bucket.s3.amazonaws.com",
                    "Prefix": "cf/"},
        "Cert": {"ACMCertificateArn": f"arn:aws:acm:us-east-1:{ACCOUNT_ID}:certificate/"
                                      f"a1b2c3d4-0000-4000-8000-0000000000d1",
                 "SSLSupportMethod": "sni-only", "MinimumProtocolVersion": "TLSv1.2_2021",
                 "CloudFrontDefaultCertificate": False, "Certificate": "", "CertificateSource": "acm"},
    },
    {
        "Id": "E2DEMOEXAMPLE02", "DomainName": "d222222abcdef8.cloudfront.net", "Comment": "demo alb front",
        "Aliases": [], "WebACLId": "", "PriceClass": "PriceClass_All",
        "Origins": [_cf_origin("alb-origin", "demo-public-alb-1234567890.eu-west-2.elb.amazonaws.com")],
        "Logging": {"Enabled": False, "IncludeCookies": False, "Bucket": "", "Prefix": ""},
        "Cert": {"CloudFrontDefaultCertificate": True, "MinimumProtocolVersion": "TLSv1",
                 "CertificateSource": "cloudfront"},
    },
]


def _cf_common(d: Dict[str, Any]) -> Dict[str, Any]:
    aliases: Dict[str, Any] = {"Quantity": len(d["Aliases"])}
    if d["Aliases"]:
        aliases["Items"] = list(d["Aliases"])
    return {
        "Aliases": aliases,
        "Origins": {"Quantity": len(d["Origins"]), "Items": d["Origins"]},
        "OriginGroups": {"Quantity": 0},
        "DefaultCacheBehavior": _cf_behavior(d["Origins"][0]["Id"]),
        "CacheBehaviors": {"Quantity": 0},
        "CustomErrorResponses": {"Quantity": 0},
        "Comment": d["Comment"],
        "PriceClass": d["PriceClass"],
        "Enabled": True,
        "ViewerCertificate": d["Cert"],
        "Restrictions": {"GeoRestriction": {"RestrictionType": "none", "Quantity": 0}},
        "WebACLId": d["WebACLId"],
        "HttpVersion": "http2",
        "IsIPV6Enabled": True,
    }


def _cf_summary(d: Dict[str, Any]) -> Dict[str, Any]:
    out = {"Id": d["Id"], "ARN": f"arn:aws:cloudfront::{ACCOUNT_ID}:distribution/{d['Id']}",
           "Status": "Deployed", "LastModifiedTime": ts(10), "DomainName": d["DomainName"], "Staging": False}
    out.update(_cf_common(d))
    return out


def _cf_config(d: Dict[str, Any]) -> Dict[str, Any]:
    out = {"CallerReference": f"demo-{d['Id']}", "DefaultRootObject": "index.html", "Logging": d["Logging"],
           "Staging": False}
    out.update(_cf_common(d))
    return out


# ═════════════════════════════════════════════════════════════════════════════
# Route 53 (global)
# ═════════════════════════════════════════════════════════════════════════════
ROUTE53_ZONES: List[Dict[str, Any]] = [
    {"Id": "/hostedzone/Z0DEMOPUBLIC00001", "Name": "example.com.", "CallerReference": "demo-public-zone",
     "Config": {"Comment": "demo public zone", "PrivateZone": False}, "ResourceRecordSetCount": 6,
     "records": [
         {"Name": "example.com.", "Type": "NS", "TTL": 172800,
          "ResourceRecords": [{"Value": "ns-1.awsdns-01.org."}, {"Value": "ns-2.awsdns-02.co.uk."}]},
         {"Name": "example.com.", "Type": "SOA", "TTL": 900,
          "ResourceRecords": [{"Value": "ns-1.awsdns-01.org. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400"}]},
         {"Name": "example.com.", "Type": "TXT", "TTL": 300,
          "ResourceRecords": [{"Value": f'"demo-verification={CANARIES["route53_txt"]}"'}]},
         {"Name": "app.example.com.", "Type": "A",
          "AliasTarget": {"HostedZoneId": "ZHURV8PSTC4K8", "EvaluateTargetHealth": True,
                          "DNSName": "dualstack.demo-public-alb-1234567890.eu-west-2.elb.amazonaws.com."}},
         {"Name": "old.example.com.", "Type": "CNAME", "TTL": 300,
          "ResourceRecords": [{"Value": "demo-old-site.s3-website-eu-west-1.amazonaws.com"}]},
         {"Name": "www.example.com.", "Type": "CNAME", "TTL": 300,
          "ResourceRecords": [{"Value": "d111111abcdef8.cloudfront.net"}]},
     ]},
    {"Id": "/hostedzone/Z0DEMOPRIVATE0002", "Name": "internal.example.com.", "CallerReference": "demo-private-zone",
     "Config": {"Comment": "demo private zone", "PrivateZone": True}, "ResourceRecordSetCount": 3,
     "records": [{"Name": "db.internal.example.com.", "Type": "CNAME", "TTL": 60,
                  "ResourceRecords": [{"Value": "demo-db.abcdefghij.eu-west-2.rds.amazonaws.com"}]}]},
]

# ═════════════════════════════════════════════════════════════════════════════
# Regional data
# ═════════════════════════════════════════════════════════════════════════════
EKS_ENDPOINTS = {
    "demo-cluster": "https://DEMO0000000000000000000000000002.gr7.eu-west-2.eks.amazonaws.com",
    "demo-west-cluster": "https://DEMO0000000000000000000000000001.gr7.eu-west-1.eks.amazonaws.com",
}
EKS_CA_DATA = _b64("-----BEGIN CERTIFICATE-----\nZmFrZS1kZW1vLWNh\n-----END CERTIFICATE-----\n")


def _tags(**kv: str) -> List[Dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in kv.items()]


def _waf_visibility(name: str) -> Dict[str, Any]:
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": name}


def _waf_acl(region_or_global: str, scope_word: str, name: str, acl_id: str, *, rules=None,
             resources=None, default="Allow") -> Dict[str, Any]:
    region = "us-east-1" if scope_word == "global" else region_or_global
    return {
        "Name": name, "Id": acl_id, "Description": f"{name} (acme)",
        "ARN": f"arn:aws:wafv2:{region}:{ACCOUNT_ID}:{scope_word}/webacl/{name}/{acl_id}",
        "DefaultAction": {default: {}},
        "Rules": rules if rules is not None else [{
            "Name": "AWS-AWSManagedRulesCommonRuleSet", "Priority": 0,
            "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet"}},
            "OverrideAction": {"None": {}}, "VisibilityConfig": _waf_visibility("common")}],
        "VisibilityConfig": _waf_visibility(name), "Capacity": 700,
        "resources": resources or {},
    }


def _region_eu_west_2() -> Dict[str, Any]:
    r = "eu-west-2"
    vpc = "vpc-0dec000000000002"
    subnet_pub, subnet_priv = "subnet-0dec0b0b0000002", "subnet-0dec0ba1b000002"
    web_sg, app_sg, default_sg = "sg-0dec0eeb000000002", "sg-0dec0abb000000002", "sg-0dec0defa01700002"
    alb_arn = f"arn:aws:elasticloadbalancing:{r}:{ACCOUNT_ID}:loadbalancer/app/demo-public-alb/0123456789abcdef"
    nlb_arn = f"arn:aws:elasticloadbalancing:{r}:{ACCOUNT_ID}:loadbalancer/net/demo-internal-nlb/fedcba9876543210"
    w = "a1a1a1a1-0000-4000-8000-0000000000a"
    return {
        "ec2": {
            "Vpcs": [{"VpcId": vpc, "CidrBlock": "10.20.0.0/16", "State": "available", "IsDefault": False,
                      "OwnerId": ACCOUNT_ID, "DhcpOptionsId": "dopt-0dec00000000002", "InstanceTenancy": "default",
                      "Tags": _tags(Name="demo-vpc")}],
            "Subnets": [
                {"SubnetId": subnet_pub, "VpcId": vpc, "CidrBlock": "10.20.1.0/24", "AvailabilityZone": "eu-west-2a",
                 "MapPublicIpOnLaunch": True, "State": "available", "AvailableIpAddressCount": 250},
                {"SubnetId": subnet_priv, "VpcId": vpc, "CidrBlock": "10.20.2.0/24", "AvailabilityZone": "eu-west-2b",
                 "MapPublicIpOnLaunch": False, "State": "available", "AvailableIpAddressCount": 248},
            ],
            "RouteTables": [
                {"RouteTableId": "rtb-0dec0b0b0000002", "VpcId": vpc, "OwnerId": ACCOUNT_ID,
                 "Routes": [{"DestinationCidrBlock": "10.20.0.0/16", "GatewayId": "local", "State": "active",
                             "Origin": "CreateRouteTable"},
                            {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-0dec00000000002",
                             "State": "active", "Origin": "CreateRoute"}],
                 "Associations": [{"RouteTableAssociationId": "rtbassoc-0dec000002a",
                                   "RouteTableId": "rtb-0dec0b0b0000002", "SubnetId": subnet_pub, "Main": False}]},
                {"RouteTableId": "rtb-0dec0ca1a000002", "VpcId": vpc, "OwnerId": ACCOUNT_ID,
                 "Routes": [{"DestinationCidrBlock": "10.20.0.0/16", "GatewayId": "local", "State": "active",
                             "Origin": "CreateRouteTable"},
                            {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-0dec000000000002",
                             "State": "active", "Origin": "CreateRoute"}],
                 "Associations": [{"RouteTableAssociationId": "rtbassoc-0dec000002b",
                                   "RouteTableId": "rtb-0dec0ca1a000002", "Main": True}]},
            ],
            "InternetGateways": [{"InternetGatewayId": "igw-0dec00000000002", "OwnerId": ACCOUNT_ID,
                                  "Attachments": [{"VpcId": vpc, "State": "available"}]}],
            "NatGateways": [{"NatGatewayId": "nat-0dec000000000002", "SubnetId": subnet_pub, "VpcId": vpc,
                             "State": "available", "CreateTime": ts(2),
                             "NatGatewayAddresses": [{"PublicIp": "203.0.113.20", "PrivateIp": "10.20.1.5",
                                                      "AllocationId": "eipalloc-0dec0000002"}]}],
            "NetworkAcls": [{"NetworkAclId": "acl-0dec00000000002", "VpcId": vpc, "IsDefault": True,
                             "Entries": [{"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow",
                                          "Egress": False, "CidrBlock": "0.0.0.0/0"},
                                         {"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow",
                                          "Egress": True, "CidrBlock": "0.0.0.0/0"}]}],
            "VpcEndpoints": [{"VpcEndpointId": "vpce-0dec0000000002", "VpcEndpointType": "Gateway", "VpcId": vpc,
                              "ServiceName": "com.amazonaws.eu-west-2.s3", "State": "available",
                              "PolicyDocument": World.json_doc(_doc(_allow("*", "*", Principal="*"))),
                              "RouteTableIds": ["rtb-0dec0ca1a000002"]}],
            "DhcpOptions": [{"DhcpOptionsId": "dopt-0dec00000000002", "OwnerId": ACCOUNT_ID,
                             "DhcpConfigurations": [{"Key": "domain-name-servers",
                                                     "Values": [{"Value": "AmazonProvidedDNS"}]}]}],
            "VpcPeeringConnections": [{
                "VpcPeeringConnectionId": "pcx-0dec00000000002",
                "AccepterVpcInfo": {"OwnerId": EXTERNAL_ACCOUNT_ID, "VpcId": "vpc-0e87eaaa1000000009",
                                    "CidrBlock": "10.99.0.0/16", "Region": "eu-west-2"},
                "RequesterVpcInfo": {"OwnerId": ACCOUNT_ID, "VpcId": vpc, "CidrBlock": "10.20.0.0/16",
                                     "Region": "eu-west-2"},
                "Status": {"Code": "active", "Message": "Active"}}],
            "SecurityGroups": [
                {"GroupId": web_sg, "GroupName": "demo-web", "Description": "demo web tier", "VpcId": vpc,
                 "OwnerId": ACCOUNT_ID,
                 "IpPermissions": [
                     {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                      "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "ssh from anywhere"}],
                      "Ipv6Ranges": [], "UserIdGroupPairs": [], "PrefixListIds": []},
                     {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [],
                      "Ipv6Ranges": [{"CidrIpv6": "::/0"}], "UserIdGroupPairs": [], "PrefixListIds": []}],
                 "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                          "Ipv6Ranges": [], "UserIdGroupPairs": [], "PrefixListIds": []}]},
                {"GroupId": app_sg, "GroupName": "demo-app", "Description": "demo app tier", "VpcId": vpc,
                 "OwnerId": ACCOUNT_ID,
                 "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080, "IpRanges": [],
                                    "Ipv6Ranges": [], "PrefixListIds": [],
                                    "UserIdGroupPairs": [{"GroupId": web_sg, "UserId": ACCOUNT_ID}]}],
                 "IpPermissionsEgress": []},
                {"GroupId": default_sg, "GroupName": "default", "Description": "default VPC security group",
                 "VpcId": vpc, "OwnerId": ACCOUNT_ID, "IpPermissions": [], "IpPermissionsEgress": []},
            ],
            "NetworkInterfaces": [
                {"NetworkInterfaceId": "eni-0dec0eeb0000002", "PrivateIpAddress": "10.20.1.10",
                 "Description": "demo web instance", "SubnetId": subnet_pub, "VpcId": vpc, "Status": "in-use",
                 "Groups": [{"GroupId": web_sg, "GroupName": "demo-web"}],
                 "Attachment": {"AttachmentId": "eni-attach-0dec00002a", "InstanceId": "i-0dec0eeb000000002",
                                "Status": "attached", "DeviceIndex": 0, "AttachTime": ts(3)}},
                {"NetworkInterfaceId": "eni-0dec0abb0000002", "PrivateIpAddress": "10.20.2.10",
                 "Description": "demo app instance", "SubnetId": subnet_priv, "VpcId": vpc, "Status": "in-use",
                 "Groups": [{"GroupId": app_sg, "GroupName": "demo-app"}],
                 "Attachment": {"AttachmentId": "eni-attach-0dec00002b", "InstanceId": "i-0dec0abb000000002",
                                "Status": "attached", "DeviceIndex": 0, "AttachTime": ts(3)}},
                {"NetworkInterfaceId": "eni-0dec0a1b0000002", "PrivateIpAddress": "10.20.1.20",
                 "Description": "ELB app/demo-public-alb/0123456789abcdef", "SubnetId": subnet_pub, "VpcId": vpc,
                 "Status": "in-use", "Groups": [{"GroupId": web_sg, "GroupName": "demo-web"}]},
            ],
            "Reservations": [
                {"ReservationId": "r-0dec0000000000021", "OwnerId": ACCOUNT_ID, "Instances": [{
                    "InstanceId": "i-0dec0eeb000000002", "ImageId": "ami-0dec0000000000002",
                    "InstanceType": "t3.micro", "KeyName": "demo-key", "LaunchTime": ts(3),
                    "Placement": {"AvailabilityZone": "eu-west-2a"}, "PrivateIpAddress": "10.20.1.10",
                    "PublicIpAddress": "203.0.113.10", "SubnetId": subnet_pub, "VpcId": vpc,
                    "State": {"Code": 16, "Name": "running"},
                    "IamInstanceProfile": {"Arn": iam_arn("instance-profile", "demo-app-profile"),
                                           "Id": "AIPAEXAMPLEAPPPROF001"},
                    "SecurityGroups": [{"GroupId": web_sg, "GroupName": "demo-web"}],
                    "NetworkInterfaces": [{"NetworkInterfaceId": "eni-0dec0eeb0000002",
                                           "PrivateIpAddress": "10.20.1.10", "SubnetId": subnet_pub, "VpcId": vpc,
                                           "MacAddress": "02:00:00:00:00:21", "Status": "in-use",
                                           "Association": {"PublicIp": "203.0.113.10", "IpOwnerId": "amazon"}}],
                    "MetadataOptions": {"State": "applied", "HttpTokens": "optional", "HttpPutResponseHopLimit": 1,
                                        "HttpEndpoint": "enabled"},
                    "Monitoring": {"State": "disabled"}, "Tags": _tags(Name="demo-web", env="demo")}]},
                {"ReservationId": "r-0dec0000000000022", "OwnerId": ACCOUNT_ID, "Instances": [{
                    "InstanceId": "i-0dec0abb000000002", "ImageId": "ami-0dec0000000000002",
                    "InstanceType": "m5.large", "LaunchTime": ts(4),
                    "Placement": {"AvailabilityZone": "eu-west-2b"}, "PrivateIpAddress": "10.20.2.10",
                    "SubnetId": subnet_priv, "VpcId": vpc, "State": {"Code": 16, "Name": "running"},
                    "IamInstanceProfile": {"Arn": iam_arn("instance-profile", "demo-eks-node-profile"),
                                           "Id": "AIPAEXAMPLENODEPROF01"},
                    "SecurityGroups": [{"GroupId": app_sg, "GroupName": "demo-app"}],
                    "NetworkInterfaces": [{"NetworkInterfaceId": "eni-0dec0abb0000002",
                                           "PrivateIpAddress": "10.20.2.10", "SubnetId": subnet_priv,
                                           "VpcId": vpc, "MacAddress": "02:00:00:00:00:22", "Status": "in-use"}],
                    "MetadataOptions": {"State": "applied", "HttpTokens": "required", "HttpPutResponseHopLimit": 2,
                                        "HttpEndpoint": "enabled"},
                    "Monitoring": {"State": "enabled"}, "Tags": _tags(Name="demo-eks-node")}]},
            ],
            "UserData": {"i-0dec0eeb000000002": _b64(f"#!/bin/bash\nexport DB_PASSWORD={CANARIES['ec2_user_data']}\n")},
            "FlowLogs": [
                {"FlowLogId": "fl-0dec000000000021", "CreationTime": ts(2), "DeliverLogsStatus": "SUCCESS",
                 "FlowLogStatus": "ACTIVE", "LogGroupName": "demo-vpc-flow", "ResourceId": vpc,
                 "TrafficType": "ALL", "LogDestinationType": "cloud-watch-logs",
                 "DeliverLogsPermissionArn": role_arn("demo-flowlogs-role"), "MaxAggregationInterval": 600,
                 "LogFormat": "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr}"},
                {"FlowLogId": "fl-0dec000000000022", "CreationTime": ts(3), "DeliverLogsStatus": "SUCCESS",
                 "FlowLogStatus": "ACTIVE", "ResourceId": subnet_pub, "TrafficType": "REJECT",
                 "LogDestinationType": "s3", "LogDestination": "arn:aws:s3:::demo-logs-bucket/flow/",
                 "MaxAggregationInterval": 60, "LogFormat": "${version} ${srcaddr}"},
            ],
            "Snapshots": [
                {"SnapshotId": "snap-0dec0b0b11c000021", "VolumeId": "vol-0dec000000000021", "State": "completed",
                 "StartTime": ts(5), "Progress": "100%", "OwnerId": ACCOUNT_ID, "Description": "demo public snapshot",
                 "VolumeSize": 8, "Encrypted": False, "perms": [{"Group": "all"}]},
                {"SnapshotId": "snap-0dec054aaed000022", "VolumeId": "vol-0dec000000000022", "State": "completed",
                 "StartTime": ts(6), "Progress": "100%", "OwnerId": ACCOUNT_ID, "Description": "demo shared snapshot",
                 "VolumeSize": 20, "Encrypted": True, "KmsKeyId": kms_arn(r, KEY_W2),
                 "perms": [{"UserId": EXTERNAL_ACCOUNT_ID}]},
                {"SnapshotId": "snap-0dec0ba1ba7e00023", "VolumeId": "vol-0dec000000000023", "State": "completed",
                 "StartTime": ts(7), "Progress": "100%", "OwnerId": ACCOUNT_ID, "Description": "demo private snapshot",
                 "VolumeSize": 8, "Encrypted": True, "KmsKeyId": kms_arn(r, KEY_W2), "perms": []},
            ],
        },
        "cloudtrail": {"trails": [
            {"Name": "demo-org-trail", "S3BucketName": "demo-logs-bucket", "IncludeGlobalServiceEvents": True,
             "IsMultiRegionTrail": True, "HomeRegion": "eu-west-2",
             "TrailARN": f"arn:aws:cloudtrail:eu-west-2:{ACCOUNT_ID}:trail/demo-org-trail",
             "LogFileValidationEnabled": True, "HasCustomEventSelectors": False, "HasInsightSelectors": True,
             "IsOrganizationTrail": False, "KmsKeyId": kms_arn("eu-west-2", KEY_W2)},
        ]},
        "waf": {
            "web_acls": [
                _waf_acl(r, "regional", "demo-api-acl", w + "2",
                         rules=[{"Name": "demo-rate-limit", "Priority": 0,
                                 "Statement": {"RateBasedStatement": {"Limit": 1000, "AggregateKeyType": "IP"}},
                                 "Action": {"Block": {}}, "VisibilityConfig": _waf_visibility("rate")}],
                         resources={"APPLICATION_LOAD_BALANCER": [],
                                    "API_GATEWAY": [f"arn:aws:apigateway:{r}::/restapis/demorest01/stages/prod"],
                                    "COGNITO_USER_POOL": [f"arn:aws:cognito-idp:{r}:{ACCOUNT_ID}:userpool/"
                                                          "eu-west-2_DemoPool1"]}),
                _waf_acl(r, "regional", "demo-regional-acl", w + "1",
                         resources={"APPLICATION_LOAD_BALANCER": [alb_arn]}),
            ],
            "rule_groups": [{"Name": "demo-rate-rules", "Id": w + "3", "Capacity": 2,
                             "ARN": f"arn:aws:wafv2:{r}:{ACCOUNT_ID}:regional/rulegroup/demo-rate-rules/{w}3",
                             "Rules": [], "VisibilityConfig": _waf_visibility("demo-rate-rules")}],
            "ip_sets": [{"Name": "demo-blocklist", "Id": w + "4", "IPAddressVersion": "IPV4",
                         "ARN": f"arn:aws:wafv2:{r}:{ACCOUNT_ID}:regional/ipset/demo-blocklist/{w}4",
                         "Addresses": ["203.0.113.0/24", "198.51.100.7/32"]}],
            "logging": [{"ResourceArn": f"arn:aws:wafv2:{r}:{ACCOUNT_ID}:regional/webacl/demo-regional-acl/{w}1",
                         "LogDestinationConfigs": [f"arn:aws:logs:{r}:{ACCOUNT_ID}:log-group:aws-waf-logs-demo"]}],
        },
        "eks": {"clusters": [{
            "name": "demo-cluster", "arn": f"arn:aws:eks:{r}:{ACCOUNT_ID}:cluster/demo-cluster",
            "createdAt": ts(2), "version": "1.29", "endpoint": EKS_ENDPOINTS["demo-cluster"],
            "roleArn": role_arn("demo-eks-cluster-role"),
            "resourcesVpcConfig": {"subnetIds": [subnet_pub, subnet_priv], "securityGroupIds": [app_sg],
                                   "clusterSecurityGroupId": "sg-0dec0c1057ea00002", "vpcId": vpc,
                                   "endpointPublicAccess": True, "endpointPrivateAccess": True,
                                   "publicAccessCidrs": ["0.0.0.0/0"]},
            "kubernetesNetworkConfig": {"serviceIpv4Cidr": "172.20.0.0/16", "ipFamily": "ipv4"},
            "logging": {"clusterLogging": [{"types": ["api", "audit"], "enabled": True}]},
            "identity": {"oidc": {"issuer": f"https://{OIDC_ISSUER}"}},
            "status": "ACTIVE", "certificateAuthority": {"data": EKS_CA_DATA}, "platformVersion": "eks.7",
            "tags": {"env": "demo"}, "accessConfig": {"authenticationMode": "API_AND_CONFIG_MAP"},
            "nodegroups": [{"nodegroupName": "demo-ng",
                            "nodegroupArn": f"arn:aws:eks:{r}:{ACCOUNT_ID}:nodegroup/demo-cluster/demo-ng/abc",
                            "clusterName": "demo-cluster", "version": "1.29", "status": "ACTIVE",
                            "nodeRole": role_arn("demo-eks-node-role"), "subnets": [subnet_priv],
                            "instanceTypes": ["m5.large"], "amiType": "AL2_x86_64",
                            "scalingConfig": {"minSize": 1, "maxSize": 3, "desiredSize": 2}, "createdAt": ts(3)}],
            "fargate": [{"fargateProfileName": "demo-fp",
                         "fargateProfileArn": f"arn:aws:eks:{r}:{ACCOUNT_ID}:fargateprofile/demo-cluster/demo-fp/abc",
                         "clusterName": "demo-cluster", "createdAt": ts(3),
                         "podExecutionRoleArn": role_arn("demo-eks-node-role"), "subnets": [subnet_priv],
                         "selectors": [{"namespace": "demo-batch", "labels": {"runtime": "fargate"}}],
                         "status": "ACTIVE"}],
            "addons": [
                {"addonName": "demo-observability", "clusterName": "demo-cluster", "status": "ACTIVE",
                 "addonVersion": "v1.0.0-eksbuild.1",
                 "addonArn": f"arn:aws:eks:{r}:{ACCOUNT_ID}:addon/demo-cluster/demo-observability/abc",
                 "createdAt": ts(3), "modifiedAt": ts(4),
                 "configurationValues": json.dumps({"apiKey": CANARIES["eks_addon_config"]})},
                {"addonName": "vpc-cni", "clusterName": "demo-cluster", "status": "ACTIVE",
                 "addonVersion": "v1.16.0-eksbuild.1",
                 "addonArn": f"arn:aws:eks:{r}:{ACCOUNT_ID}:addon/demo-cluster/vpc-cni/abc",
                 "createdAt": ts(3), "modifiedAt": ts(3), "serviceAccountRoleArn": role_arn("demo-eks-node-role")},
            ],
        }]},
        "secretsmanager": {"secrets": [
            {"ARN": f"arn:aws:secretsmanager:{r}:{ACCOUNT_ID}:secret:demo/db-creds-AbCdEf", "Name": "demo/db-creds",
             "Description": f"db credentials {CANARIES['secrets_description']}",
             "KmsKeyId": kms_arn(r, KEY_W2), "RotationEnabled": True,
             "RotationLambdaARN": lambda_arn(r, "demo-rotator"), "LastChangedDate": ts(8),
             "Tags": _tags(env="demo"), "CreatedDate": ts(1),
             "policy": _doc({"Sid": "CrossAccountRead", "Effect": "Allow",
                             "Principal": {"AWS": f"arn:aws:iam::{EXTERNAL_ACCOUNT_ID}:root"},
                             "Action": "secretsmanager:GetSecretValue", "Resource": "*"})},
            {"ARN": f"arn:aws:secretsmanager:{r}:{ACCOUNT_ID}:secret:demo_db-creds-GhIjKl", "Name": "demo_db-creds",
             "Description": "name collides with demo/db-creds after '/'->'_' (F-114)",
             "RotationEnabled": False, "LastChangedDate": ts(8), "CreatedDate": ts(2),
             "policy": _doc({"Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
                             "Action": "secretsmanager:GetSecretValue", "Resource": "*"})},
            {"ARN": f"arn:aws:secretsmanager:{r}:{ACCOUNT_ID}:secret:demo/api-key-MnOpQr", "Name": "demo/api-key",
             "Description": "no resource policy", "RotationEnabled": False, "LastChangedDate": ts(9),
             "CreatedDate": ts(3), "policy": None},
            {"ARN": f"arn:aws:secretsmanager:{r}:{ACCOUNT_ID}:secret:demo/denied-StUvWx", "Name": "demo/denied",
             "Description": "GetResourcePolicy denied", "RotationEnabled": False, "LastChangedDate": ts(9),
             "CreatedDate": ts(4), "policy": None},
        ]},
        "ssm": {"parameters": [
            {"Name": "/demo/app/endpoint", "ARN": f"arn:aws:ssm:{r}:{ACCOUNT_ID}:parameter/demo/app/endpoint",
             "Type": "String", "LastModifiedDate": ts(5), "LastModifiedUser": iam_arn("user", "demo-alice"),
             "Description": f"endpoint {CANARIES['ssm_description']}", "Version": 3, "Tier": "Standard",
             "Policies": [], "DataType": "text"},
            {"Name": "/demo/app/hosts", "ARN": f"arn:aws:ssm:{r}:{ACCOUNT_ID}:parameter/demo/app/hosts",
             "Type": "StringList", "LastModifiedDate": ts(5), "LastModifiedUser": iam_arn("user", "demo-ci"),
             "Version": 1, "Tier": "Standard", "Policies": [], "DataType": "text"},
            {"Name": "/demo/db/password", "ARN": f"arn:aws:ssm:{r}:{ACCOUNT_ID}:parameter/demo/db/password",
             "Type": "SecureString", "KeyId": "alias/demo-key", "LastModifiedDate": ts(6),
             "LastModifiedUser": iam_arn("user", "demo-alice"), "Version": 2, "Tier": "Standard",
             "Policies": [], "DataType": "text"},
        ]},
        "lambda": {"functions": [
            {"FunctionName": "demo-layered", "Runtime": "python3.12", "Role": role_arn("demo-app-role"),
             "Handler": "app.handler", "MemorySize": 256, "Timeout": 30,
             "Layers": [{"Arn": f"arn:aws:lambda:{r}:{ACCOUNT_ID}:layer:demo-deps:3", "CodeSize": 1024}],
             "VpcConfig": {"SubnetIds": [subnet_priv], "SecurityGroupIds": [app_sg], "VpcId": vpc},
             "Environment": {"Variables": {"STAGE": "demo"}},
             "url": "denied",
             "policy": _doc({"Sid": "XAccountInvoke", "Effect": "Allow",
                             "Principal": {"AWS": f"arn:aws:iam::{EXTERNAL_ACCOUNT_ID}:root"},
                             "Action": "lambda:InvokeFunction", "Resource": lambda_arn(r, "demo-layered")})},
            {"FunctionName": "demo-internal", "Runtime": "nodejs20.x", "Role": role_arn("demo-app-role"),
             "Handler": "index.handler", "MemorySize": 128, "Timeout": 3, "url": None, "policy": None},
            {"FunctionName": "demo-processor", "Runtime": "python3.12", "Role": role_arn("demo-lambda-role"),
             "Handler": "main.handler", "MemorySize": 512, "Timeout": 60,
             "Environment": {"Variables": {"DB_PASSWORD": CANARIES["lambda_env"], "LOG_LEVEL": "INFO"}},
             "url": {"AuthType": "NONE", "Url": "https://demoprocessor0001.lambda-url.eu-west-2.on.aws/"},
             "policy": _doc(
                 {"Sid": "S3Invoke", "Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"},
                  "Action": "lambda:InvokeFunction", "Resource": lambda_arn(r, "demo-processor"),
                  "Condition": {"ArnLike": {"AWS:SourceArn": "arn:aws:s3:::demo-data-bucket"}}},
                 {"Sid": "PublicUrl", "Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunctionUrl",
                  "Resource": lambda_arn(r, "demo-processor"),
                  "Condition": {"StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}}})},
        ]},
        "kms": {
            "keys": [
                {"KeyId": KEY_W2, "KeyManager": "CUSTOMER", "Description": "demo customer key", "Enabled": True,
                 "KeyState": "Enabled",
                 "policy": _doc({"Sid": "Root", "Effect": "Allow",
                                 "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
                                 "Action": "kms:*", "Resource": "*"},
                                {"Sid": "AppDecrypt", "Effect": "Allow",
                                 "Principal": {"AWS": role_arn("demo-app-role")},
                                 "Action": ["kms:Decrypt", "kms:DescribeKey"], "Resource": "*"}),
                 "grants": [{"GrantId": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd01",
                             "Name": "demo-lambda-grant", "GranteePrincipal": role_arn("demo-lambda-role"),
                             "Operations": ["Decrypt", "GenerateDataKey"]}]},
                {"KeyId": "1111aaaa-0000-4000-8000-0000000000a2", "KeyManager": "AWS",
                 "Description": "Default key that protects my S3 objects when no other key is defined",
                 "Enabled": True, "KeyState": "Enabled", "policy": None, "grants": []},
                {"KeyId": "1111aaaa-0000-4000-8000-0000000000a3", "KeyManager": "CUSTOMER",
                 "Description": "DescribeKey denied", "Enabled": True, "KeyState": "Enabled", "policy": None,
                 "grants": []},
                {"KeyId": "1111aaaa-0000-4000-8000-0000000000a4", "KeyManager": "CUSTOMER",
                 "Description": "policy and grants denied", "Enabled": False, "KeyState": "Disabled",
                 "policy": None, "grants": []},
            ],
            "aliases": [
                {"AliasName": "alias/demo-key", "TargetKeyId": KEY_W2},
                {"AliasName": "alias/demo-key-secondary", "TargetKeyId": KEY_W2},
                {"AliasName": "alias/aws/s3", "TargetKeyId": "1111aaaa-0000-4000-8000-0000000000a2"},
                {"AliasName": "alias/aws/rds"},  # AWS-managed alias with no key yet
            ],
        },
        "ecs": {"task_definitions": [
            {"family": "demo-api", "revision": 1, "taskRoleArn": role_arn("demo-ecs-task-role"),
             "executionRoleArn": role_arn("demo-ecs-task-role"),
             "env": [{"name": "API_TOKEN", "value": CANARIES["ecs_env"]}]},
            {"family": "demo-api", "revision": 2, "taskRoleArn": role_arn("demo-ecs-task-role"),
             "executionRoleArn": role_arn("demo-ecs-task-role"), "env": []},
            {"family": "demo-batch", "revision": 1, "taskRoleArn": None, "executionRoleArn": None, "env": []},
        ]},
        "cloudformation": {"stacks": [
            {"StackName": "demo-app-stack", "RoleARN": role_arn("demo-cfn-role"), "StackStatus": "UPDATE_COMPLETE",
             "Parameters": [{"ParameterKey": "DbPassword", "ParameterValue": CANARIES["cfn_parameter"]},
                            {"ParameterKey": "Stage", "ParameterValue": "demo"}],
             "Outputs": [{"OutputKey": "ApiToken", "OutputValue": CANARIES["cfn_output"],
                          "Description": "demo output"}]},
            {"StackName": "demo-network-stack", "RoleARN": None, "StackStatus": "CREATE_COMPLETE",
             "Parameters": [], "Outputs": []},
        ]},
        "glue": {
            "jobs": [{"Name": "demo-etl-job", "Role": role_arn("demo-glue-role"),
                      "DefaultArguments": {"--db-password": CANARIES["glue_args"], "--job-language": "python"}}],
            "dev_endpoints": [{"EndpointName": "demo-dev-endpoint", "RoleArn": role_arn("demo-glue-role"),
                               "Status": "READY", "PublicAddress": "ec2-203-0-113-30.eu-west-2.compute.amazonaws.com"}],
        },
        "codebuild": {"projects": [
            {"name": "demo-build", "serviceRole": role_arn("demo-build-role"),
             "source_location": f"https://demo-user:{CANARIES['codebuild_source_url']}@git.example.com/demo/app.git",
             "env": [{"name": "NPM_TOKEN", "value": CANARIES["codebuild_env"], "type": "PLAINTEXT"},
                     {"name": "DB_PASSWORD", "value": "/demo/db/password", "type": "PARAMETER_STORE"}]},
            {"name": "demo-deploy", "serviceRole": role_arn("demo-build-role"),
             "source_location": "https://git.example.com/demo/deploy.git", "env": []},
        ]},
        "sagemaker": {"notebooks": [
            {"NotebookInstanceName": "demo-notebook", "RoleArn": role_arn("demo-sagemaker-role"),
             "DirectInternetAccess": "Enabled", "RootAccess": "Enabled"},
        ]},
        "sns": {"topics": [
            {"Name": "demo-alerts", "policy": _doc(
                {"Sid": "XAccountPublish", "Effect": "Allow",
                 "Principal": {"AWS": f"arn:aws:iam::{EXTERNAL_ACCOUNT_ID}:root"},
                 "Action": "SNS:Publish", "Resource": f"arn:aws:sns:{r}:{ACCOUNT_ID}:demo-alerts"})},
            {"Name": "demo-events", "policy": None},
        ]},
        "sqs": {"queues": [
            {"Name": "demo-denied-queue", "policy": None},
            {"Name": "demo-dlq", "policy": None},
            {"Name": "demo-queue", "policy": _doc(
                {"Sid": "FromSns", "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
                 "Action": "sqs:SendMessage", "Resource": f"arn:aws:sqs:{r}:{ACCOUNT_ID}:demo-queue",
                 "Condition": {"ArnEquals": {"aws:SourceArn": f"arn:aws:sns:{r}:{ACCOUNT_ID}:demo-alerts"}}})},
        ]},
        "ecr": {"repositories": [
            {"repositoryName": "demo-api", "policy": _doc(
                {"Sid": "XAccountPull", "Effect": "Allow",
                 "Principal": {"AWS": f"arn:aws:iam::{EXTERNAL_ACCOUNT_ID}:root"},
                 "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]})},
            {"repositoryName": "demo-base", "policy": None},
        ]},
        "rds": {
            "instances": [
                {"DBInstanceIdentifier": "demo-db", "Engine": "postgres", "PubliclyAccessible": True,
                 "StorageEncrypted": False, "IAMDatabaseAuthenticationEnabled": False},
                {"DBInstanceIdentifier": "demo-db-private", "Engine": "aurora-postgresql",
                 "PubliclyAccessible": False, "StorageEncrypted": True, "KmsKeyId": kms_arn(r, KEY_W2),
                 "IAMDatabaseAuthenticationEnabled": True},
            ],
            "snapshots": [
                {"DBSnapshotIdentifier": "demo-db-snap-denied", "DBInstanceIdentifier": "demo-db",
                 "SnapshotType": "manual", "Encrypted": False, "restore": None},
                {"DBSnapshotIdentifier": "demo-db-snap-public", "DBInstanceIdentifier": "demo-db",
                 "SnapshotType": "manual", "Encrypted": False, "restore": ["all"]},
                {"DBSnapshotIdentifier": "demo-db-snap-shared", "DBInstanceIdentifier": "demo-db-private",
                 "SnapshotType": "manual", "Encrypted": True, "KmsKeyId": kms_arn(r, KEY_W2),
                 "restore": [EXTERNAL_ACCOUNT_ID]},
                {"DBSnapshotIdentifier": "rds:demo-db-2024-01-15", "DBInstanceIdentifier": "demo-db",
                 "SnapshotType": "automated", "Encrypted": False, "restore": []},
            ],
        },
        "dynamodb": {"tables": [
            {"TableName": "demo-denied-table", "policy": None},
            {"TableName": "demo-orders", "policy": _doc(
                {"Sid": "XAccountRead", "Effect": "Allow",
                 "Principal": {"AWS": f"arn:aws:iam::{EXTERNAL_ACCOUNT_ID}:root"},
                 "Action": ["dynamodb:GetItem", "dynamodb:Query"],
                 "Resource": f"arn:aws:dynamodb:{r}:{ACCOUNT_ID}:table/demo-orders"})},
            {"TableName": "demo-sessions", "policy": None},
        ]},
        "apigateway": {
            "rest_apis": [
                {"id": "demorest01", "name": "demo-rest-api", "authorizers": [],
                 "resources": [
                     {"id": "root000001", "path": "/"},
                     {"id": "res0000001", "parentId": "root000001", "pathPart": "orders", "path": "/orders",
                      "methods": {
                          "GET": {"type": "AWS_PROXY", "httpMethod": "POST",
                                  "uri": f"arn:aws:apigateway:{r}:lambda:path/2015-03-31/functions/"
                                         f"{lambda_arn(r, 'demo-processor')}/invocations"},
                          "POST": None,  # GetIntegration -> NotFoundException
                      }},
                 ]},
                {"id": "demorest02", "name": "demo-rest-auth",
                 "authorizers": [{"id": "auth01", "name": "demo-lambda-authorizer", "type": "TOKEN"}],
                 "resources": [
                     {"id": "root000002", "path": "/"},
                     {"id": "res0000002", "parentId": "root000002", "pathPart": "{proxy+}", "path": "/{proxy+}",
                      "methods": {"ANY": {"type": "AWS_PROXY", "httpMethod": "POST",
                                          "uri": f"arn:aws:apigateway:{r}:lambda:path/2015-03-31/functions/"
                                                 f"{lambda_arn(r, 'demo-internal')}:live/invocations"}}},
                 ]},
            ],
            "http_apis": [
                {"ApiId": "demohttp01", "Name": "demo-http-api", "ProtocolType": "HTTP",
                 "integrations": [{"IntegrationId": "int0001", "IntegrationType": "AWS_PROXY",
                                   "IntegrationUri": lambda_arn(r, "demo-processor"),
                                   "PayloadFormatVersion": "2.0"},
                                  {"IntegrationId": "int0002", "IntegrationType": "HTTP_PROXY",
                                   "IntegrationUri": "https://api.example.com/{proxy}",
                                   "PayloadFormatVersion": "1.0"}],
                 "authorizers": [{"AuthorizerId": "jwt001", "Name": "demo-jwt", "AuthorizerType": "JWT",
                                  "IdentitySource": ["$request.header.Authorization"]}]},
                {"ApiId": "demows0001", "Name": "demo-ws-api", "ProtocolType": "WEBSOCKET",
                 "integrations": [], "authorizers": []},
            ],
        },
        "cognito": {
            "identity_pools": [
                {"IdentityPoolId": "eu-west-2:11111111-2222-4333-8444-55555555555a",
                 "IdentityPoolName": "demo_identity_pool", "AllowUnauthenticatedIdentities": True,
                 "roles": {"unauthenticated": role_arn("demo-cognito-unauth-role")}},
                {"IdentityPoolId": "eu-west-2:11111111-2222-4333-8444-55555555555b",
                 "IdentityPoolName": "demo_roles_denied_pool", "AllowUnauthenticatedIdentities": False,
                 "roles": None},
            ],
            "user_pools": [{"Id": "eu-west-2_DemoPool1", "Name": "demo-user-pool"}],
        },
        "elb": {
            "v2": [
                {"LoadBalancerArn": alb_arn, "LoadBalancerName": "demo-public-alb", "Scheme": "internet-facing",
                 "DNSName": "demo-public-alb-1234567890.eu-west-2.elb.amazonaws.com", "Type": "application",
                 "VpcId": vpc, "SecurityGroups": [web_sg],
                 "target_groups": [
                     {"TargetGroupName": "demo-web-tg", "TargetType": "instance", "Protocol": "HTTP", "Port": 80,
                      "targets": ["i-0dec0eeb000000002"]},
                     {"TargetGroupName": "demo-lambda-tg", "TargetType": "lambda",
                      "targets": [lambda_arn(r, "demo-processor")]},
                 ]},
                {"LoadBalancerArn": nlb_arn, "LoadBalancerName": "demo-internal-nlb", "Scheme": "internal",
                 "DNSName": "demo-internal-nlb-fedcba9876543210.elb.eu-west-2.amazonaws.com", "Type": "network",
                 "VpcId": vpc,
                 "target_groups": [{"TargetGroupName": "demo-denied-tg", "TargetType": "ip", "Protocol": "TCP",
                                    "Port": 5432, "targets": ["10.20.2.50"]}]},
            ],
            "classic": [{"LoadBalancerName": "demo-classic-elb", "Scheme": "internet-facing",
                         "DNSName": "demo-classic-elb-111.eu-west-2.elb.amazonaws.com",
                         "Instances": [{"InstanceId": "i-0dec0eeb000000002"}]}],
        },
    }


def _region_eu_west_1() -> Dict[str, Any]:
    r = "eu-west-1"
    vpc = "vpc-0dec000000000001"
    w = "b1b1b1b1-0000-4000-8000-0000000000b"
    return {
        "ec2": {
            "Vpcs": [{"VpcId": vpc, "CidrBlock": "10.10.0.0/16", "State": "available", "IsDefault": False,
                      "OwnerId": ACCOUNT_ID, "Tags": _tags(Name="demo-west-vpc")}],
            "Subnets": [{"SubnetId": "subnet-0dec0ee5700001", "VpcId": vpc, "CidrBlock": "10.10.1.0/24",
                         "AvailabilityZone": "eu-west-1a", "MapPublicIpOnLaunch": True, "State": "available",
                         "AvailableIpAddressCount": 251}],
            "RouteTables": [{"RouteTableId": "rtb-0dec0ee57000001", "VpcId": vpc, "OwnerId": ACCOUNT_ID,
                             "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-0dec00000000001",
                                         "State": "active", "Origin": "CreateRoute"}],
                             "Associations": [{"RouteTableAssociationId": "rtbassoc-0dec000001a",
                                               "RouteTableId": "rtb-0dec0ee57000001", "Main": True}]}],
            "InternetGateways": [{"InternetGatewayId": "igw-0dec00000000001", "OwnerId": ACCOUNT_ID,
                                  "Attachments": [{"VpcId": vpc, "State": "available"}]}],
            "NatGateways": [],
            "NetworkAcls": [],
            "VpcEndpoints": [],
            "DhcpOptions": [],
            "VpcPeeringConnections": [],
            "SecurityGroups": [{"GroupId": "sg-0dec0ee5700000001", "GroupName": "demo-west", "VpcId": vpc,
                                "Description": "demo west", "OwnerId": ACCOUNT_ID,
                                "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
                                                   "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [],
                                                   "UserIdGroupPairs": [], "PrefixListIds": []}],
                                "IpPermissionsEgress": []}],
            "NetworkInterfaces": [],
            "Reservations": [{"ReservationId": "r-0dec0000000000011", "OwnerId": ACCOUNT_ID, "Instances": [{
                "InstanceId": "i-0dec0ee5700000001", "ImageId": "ami-0dec0000000000001", "InstanceType": "t3.small",
                "LaunchTime": ts(5), "Placement": {"AvailabilityZone": "eu-west-1a"},
                "PrivateIpAddress": "10.10.1.10", "SubnetId": "subnet-0dec0ee5700001", "VpcId": vpc,
                "State": {"Code": 80, "Name": "stopped"},
                "SecurityGroups": [{"GroupId": "sg-0dec0ee5700000001", "GroupName": "demo-west"}],
                "NetworkInterfaces": [], "MetadataOptions": {"HttpTokens": "optional", "HttpPutResponseHopLimit": 1,
                                                             "HttpEndpoint": "disabled"},
                "Monitoring": {"State": "disabled"}, "Tags": _tags(Name="demo-west")}]}],
            "UserData": {},
            "FlowLogs": [],
            "Snapshots": [],
        },
        "cloudtrail": {"trails": [], "shadow_from": "eu-west-2"},
        "waf": {
            "web_acls": [_waf_acl(r, "regional", "demo-west-acl", w + "1", resources={})],
            "rule_groups": [], "ip_sets": [], "logging": [],
        },
        "eks": {"clusters": [
            {"name": "demo-denied-cluster", "denied": True},
            {"name": "demo-west-cluster", "arn": f"arn:aws:eks:{r}:{ACCOUNT_ID}:cluster/demo-west-cluster",
             "createdAt": ts(6), "version": "1.28", "endpoint": EKS_ENDPOINTS["demo-west-cluster"],
             "roleArn": role_arn("demo-eks-cluster-role"),
             "resourcesVpcConfig": {"subnetIds": ["subnet-0dec0ee5700001"], "vpcId": vpc,
                                    "endpointPublicAccess": True, "endpointPrivateAccess": False,
                                    "publicAccessCidrs": ["198.51.100.0/24"]},
             "identity": {"oidc": {"issuer": "https://oidc.eks.eu-west-1.amazonaws.com/id/"
                                             "DEMO0000000000000000000000000001"}},
             "status": "ACTIVE", "certificateAuthority": {"data": EKS_CA_DATA}, "platformVersion": "eks.12",
             "accessConfig": {"authenticationMode": "API"},
             "nodegroups": [], "fargate": None, "addons": []},
        ]},
        "secretsmanager": {"secrets": []},
        "ssm": {"parameters": [
            {"Name": "/demo/west/flag", "ARN": f"arn:aws:ssm:{r}:{ACCOUNT_ID}:parameter/demo/west/flag",
             "Type": "String", "LastModifiedDate": ts(5), "LastModifiedUser": iam_arn("user", "demo-ci"),
             "Version": 1, "Tier": "Standard", "Policies": [], "DataType": "text"},
        ]},
        "lambda": {"functions": [
            {"FunctionName": "demo-west-fn", "Runtime": "python3.11", "Role": role_arn("demo-lambda-role"),
             "Handler": "main.handler", "MemorySize": 128, "Timeout": 3, "url": None, "policy": None},
        ]},
        "kms": {"keys": [
            {"KeyId": "2222bbbb-0000-4000-8000-0000000000b1", "KeyManager": "CUSTOMER",
             "Description": "demo west key", "Enabled": True, "KeyState": "Enabled",
             "policy": _doc({"Sid": "Root", "Effect": "Allow",
                             "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
                             "Action": "kms:*", "Resource": "*"}),
             "grants": []},
        ], "aliases": [{"AliasName": "alias/demo-west-key", "TargetKeyId": "2222bbbb-0000-4000-8000-0000000000b1"}]},
        "ecs": {"task_definitions": []},
        "cloudformation": {"stacks": []},
        "glue": {"jobs": [{"Name": "demo-west-job", "Role": role_arn("demo-glue-role"), "DefaultArguments": {}}],
                 "dev_endpoints": []},
        "codebuild": {"projects": []},
        "sagemaker": {"notebooks": []},
        "sns": {"topics": []},
        "sqs": {"queues": [{"Name": "demo-west-queue", "policy": None}]},
        "ecr": {"repositories": []},
        "rds": {"instances": [], "snapshots": []},
        "dynamodb": {"tables": []},
        "apigateway": {"rest_apis": [], "http_apis": []},
        "cognito": {"identity_pools": [], "user_pools": []},
        "elb": {"v2": [], "classic": []},
    }


REGIONAL: Dict[str, Dict[str, Any]] = {"eu-west-2": _region_eu_west_2(), "eu-west-1": _region_eu_west_1()}

WAF_CLOUDFRONT = {
    "web_acls": [_waf_acl("us-east-1", "global", "demo-cf-acl", CF_ACL_ID,
                          resources={"CLOUDFRONT": [
                              f"arn:aws:cloudfront::{ACCOUNT_ID}:distribution/E1DEMOEXAMPLE01"]})],
    "rule_groups": [],
    "ip_sets": [{"Name": "demo-cf-allowlist", "Id": "c0c0c0c0-0000-4000-8000-0000000000c2", "IPAddressVersion": "IPV4",
                 "ARN": f"arn:aws:wafv2:us-east-1:{ACCOUNT_ID}:global/ipset/demo-cf-allowlist/"
                        f"c0c0c0c0-0000-4000-8000-0000000000c2",
                 "Addresses": ["192.0.2.0/24"]}],
    "logging": [],
}

_EMPTY_REGION = {
    "ec2": {k: [] for k in ("Vpcs", "Subnets", "RouteTables", "InternetGateways", "NatGateways", "NetworkAcls",
                            "VpcEndpoints", "DhcpOptions", "VpcPeeringConnections", "SecurityGroups",
                            "NetworkInterfaces", "Reservations", "FlowLogs", "Snapshots")},
    "cloudtrail": {"trails": []}, "waf": {"web_acls": [], "rule_groups": [], "ip_sets": [], "logging": []},
    "eks": {"clusters": []}, "secretsmanager": {"secrets": []}, "ssm": {"parameters": []},
    "lambda": {"functions": []}, "kms": {"keys": [], "aliases": []}, "ecs": {"task_definitions": []},
    "cloudformation": {"stacks": []}, "glue": {"jobs": [], "dev_endpoints": []}, "codebuild": {"projects": []},
    "sagemaker": {"notebooks": []}, "sns": {"topics": []}, "sqs": {"queues": []}, "ecr": {"repositories": []},
    "rds": {"instances": [], "snapshots": []}, "dynamodb": {"tables": []},
    "apigateway": {"rest_apis": [], "http_apis": []}, "cognito": {"identity_pools": [], "user_pools": []},
    "elb": {"v2": [], "classic": []},
}
_EMPTY_REGION["ec2"]["UserData"] = {}


# ═════════════════════════════════════════════════════════════════════════════
# Wave 1 data: resources only the migrated collectors read (collectors-cli.md §5)
# ═════════════════════════════════════════════════════════════════════════════
# Everything below is served only by operations the baseline (d13c215) collectors never call, or by
# parameters they never pass (DescribeParameters(Shared=True), ListSecrets(IncludePlannedDeletion=True),
# GetResources(embed=[methods]) ...), so the collectors-v0 goldens are unaffected. Keys starting with "_"
# and the keys in _EKS_PRIVATE_KEYS / _LAMBDA_PRIVATE_KEYS are never returned by a baseline call.

_EKS_PRIVATE_KEYS = ("nodegroups", "fargate", "addons", "denied", "access_entries", "pod_identity")
_LAMBDA_PRIVATE_KEYS = ("url", "policy", "aliases", "versions")

GITHUB_OIDC_URL = "token.actions.githubusercontent.com"
SAML_PROVIDER_ARN = f"arn:aws:iam::{ACCOUNT_ID}:saml-provider/demo-idp"
OIDC_PROVIDERS: List[Dict[str, Any]] = [
    {"Arn": OIDC_PROVIDER_ARN, "Url": OIDC_ISSUER, "ClientIDList": ["sts.amazonaws.com"],
     "ThumbprintList": ["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"], "CreateDate": ts(2)},
    {"Arn": f"arn:aws:iam::{ACCOUNT_ID}:oidc-provider/{GITHUB_OIDC_URL}", "Url": GITHUB_OIDC_URL,
     "ClientIDList": ["sts.amazonaws.com"], "ThumbprintList": ["6938fd4d98bab03faadb97b34396831e3780aea1"],
     "CreateDate": ts(3)},
]
SAML_PROVIDERS: List[Dict[str, Any]] = [
    {"Arn": SAML_PROVIDER_ARN, "ValidUntil": ts(1, year=2034), "CreateDate": ts(3)},
]

#: Per-entity IAM facts GAAD / GetUser / GetRole return (the baseline List* calls never show them).
IAM_USER_EXTRAS: Dict[str, Dict[str, Any]] = {
    "demo-alice": {"tags": _tags(team="demo-dev", owner="demo-team"), "boundary": None,
                   "ssh_keys": [("APKAEXAMPLEALICESSH01", "Active")], "service_credentials": [],
                   "signing_certificates": []},
    "demo-bob": {"tags": [], "boundary": None, "ssh_keys": [], "service_credentials": [],
                 "signing_certificates": [("DEMOCERTBOB0000000000000000000001", "Active")]},
    "demo-ci": {"tags": _tags(purpose="ci"), "boundary": managed_arn("ReadOnlyAccess"), "ssh_keys": [],
                "service_credentials": [("codecommit.amazonaws.com", "demo-ci-at-111122223333", "Active")],
                "signing_certificates": []},
}
IAM_ROLE_EXTRAS: Dict[str, Dict[str, Any]] = {
    "demo-admin-role": {"tags": _tags(tier="admin"), "last_used": {"LastUsedDate": ts(14), "Region": "eu-west-2"}},
    "demo-app-role": {"tags": _tags(app="demo", env="demo")},
    "demo-lambda-role": {"boundary": policy_arn("demo-app-policy")},
}
#: An assigned and a spare virtual MFA device (ListVirtualMFADevices).
VIRTUAL_MFA_SPARE = f"arn:aws:iam::{ACCOUNT_ID}:mfa/demo-spare-device"

#: S3 sub-resources only the migrated collector reads (collectors-cli.md §5.2).
S3_EXTRAS: Dict[str, Dict[str, Any]] = {
    "demo-data-bucket": {"ownership": "BucketOwnerEnforced", "website": None,
                         "replication": {"Role": role_arn("demo-app-role"), "Rules": [
                             {"ID": "demo-to-partner", "Priority": 1, "Status": "Enabled", "Filter": {"Prefix": ""},
                              "DeleteMarkerReplication": {"Status": "Disabled"},
                              "Destination": {"Bucket": "arn:aws:s3:::demo-partner-replica",
                                              "Account": EXTERNAL_ACCOUNT_ID}}]}},
    "demo-denied-bucket": {"ownership": None, "website": None, "replication": None},
    "demo-legacy-eu-bucket": {"ownership": "ObjectWriter", "website": None, "replication": None},
    "demo-logs-bucket": {"ownership": "BucketOwnerPreferred", "website": None, "replication": None},
    "demo-public-site": {"ownership": None, "replication": None,
                         "website": {"IndexDocument": {"Suffix": "index.html"},
                                     "ErrorDocument": {"Key": "error.html"}}},
}
S3_ACCOUNT_PAB = {"BlockPublicAcls": True, "IgnorePublicAcls": False, "BlockPublicPolicy": True,
                  "RestrictPublicBuckets": False}

#: AWS Organizations as seen from acme, a member account (collectors-cli.md §5.15).
ORG_ID = "o-exampleorg1"
ORG_ROOT_ID = "r-exam"
ORG_OU_ID = "ou-exam-demo0001"
ORGANIZATION: Dict[str, Any] = {
    "Id": ORG_ID, "Arn": f"arn:aws:organizations::{EXTERNAL_ACCOUNT_ID}:organization/{ORG_ID}",
    "FeatureSet": "ALL", "MasterAccountArn": f"arn:aws:organizations::{EXTERNAL_ACCOUNT_ID}:account/{ORG_ID}/"
                                             f"{EXTERNAL_ACCOUNT_ID}",
    "MasterAccountId": EXTERNAL_ACCOUNT_ID, "MasterAccountEmail": "aws-management@example.com",
    "AvailablePolicyTypes": [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"},
                             {"Type": "RESOURCE_CONTROL_POLICY", "Status": "ENABLED"}],
}
ORG_PARENTS = {ACCOUNT_ID: (ORG_OU_ID, "ORGANIZATIONAL_UNIT"), ORG_OU_ID: (ORG_ROOT_ID, "ROOT")}
ORG_OUS = {ORG_OU_ID: {"Id": ORG_OU_ID, "Name": "demo-workloads",
                       "Arn": f"arn:aws:organizations::{EXTERNAL_ACCOUNT_ID}:ou/{ORG_ID}/{ORG_OU_ID}"}}


def _org_policy(pid: str, name: str, ptype: str, content: Dict[str, Any], aws_managed: bool = False) -> Dict[str, Any]:
    kind = "service_control_policy" if ptype == "SERVICE_CONTROL_POLICY" else "resource_control_policy"
    arn = (f"arn:aws:organizations::aws:policy/{kind}/{pid}" if aws_managed
           else f"arn:aws:organizations::{EXTERNAL_ACCOUNT_ID}:policy/{ORG_ID}/{kind}/{pid}")
    return {"Id": pid, "Arn": arn,
            "Name": name, "Description": f"{name} (acme)", "Type": ptype, "AwsManaged": aws_managed,
            "content": content}


ORG_POLICIES: Dict[str, Dict[str, Any]] = {p["Id"]: p for p in (
    _org_policy("p-FullAWSAccess", "FullAWSAccess", "SERVICE_CONTROL_POLICY", _doc(_allow("*", "*")), True),
    _org_policy("p-demo0deny01", "demo-deny-leave-org", "SERVICE_CONTROL_POLICY",
                _doc({"Effect": "Deny", "Action": "organizations:LeaveOrganization", "Resource": "*"})),
    _org_policy("p-demo0region", "demo-region-lock", "SERVICE_CONTROL_POLICY",
                _doc({"Effect": "Deny", "NotAction": ["iam:*", "sts:*", "organizations:*", "support:*"],
                      "Resource": "*", "Condition": {"StringNotEquals": {
                          "aws:RequestedRegion": ["eu-west-1", "eu-west-2", "us-east-1"]}}})),
    _org_policy("p-RCPFullAWSAccess", "RCPFullAWSAccess", "RESOURCE_CONTROL_POLICY", _doc(_allow("*", "*",
                Principal="*")), True),
)}
ORG_TARGET_POLICIES: Dict[str, List[str]] = {
    ORG_ROOT_ID: ["p-FullAWSAccess", "p-RCPFullAWSAccess"],
    ORG_OU_ID: ["p-FullAWSAccess", "p-demo0deny01"],
    ACCOUNT_ID: ["p-FullAWSAccess", "p-demo0region"],
}


def _extend_eu_west_2(d: Dict[str, Any]) -> None:  # noqa: C901 - one data block per service, kept flat
    r = "eu-west-2"
    vpc = d["ec2"]["Vpcs"][0]["VpcId"]
    subnet_pub = d["ec2"]["Subnets"][0]["SubnetId"]
    web_sg = d["ec2"]["SecurityGroups"][0]["GroupId"]
    web_iid = d["ec2"]["Reservations"][0]["Instances"][0]["InstanceId"]
    app_iid = d["ec2"]["Reservations"][1]["Instances"][0]["InstanceId"]
    lt_web = "lt-0dec0eeb000000002"
    tgw = "tgw-0dec0000000000002"
    vgw = "vgw-0dec0000000000002"
    pl_office = "pl-0dec00ff1ce000002"
    ec2 = d["ec2"]
    ec2["Addresses"] = [
        {"PublicIp": "203.0.113.20", "AllocationId": "eipalloc-0dec0000002", "AssociationId": "eipassoc-0dec0000002",
         "Domain": "vpc", "NetworkInterfaceId": "eni-0dec0a7a0000002", "PrivateIpAddress": "10.20.1.5",
         "NetworkBorderGroup": r, "PublicIpv4Pool": "amazon", "Tags": _tags(Name="demo-nat-eip")},
        {"PublicIp": "198.51.100.20", "AllocationId": "eipalloc-0dec0000003", "Domain": "vpc",
         "NetworkBorderGroup": r, "PublicIpv4Pool": "amazon", "Tags": _tags(Name="demo-unused-eip")},
    ]
    ec2["LaunchTemplates"] = [
        {"LaunchTemplateId": lt_web, "LaunchTemplateName": "demo-web-lt", "CreateTime": ts(3),
         "CreatedBy": iam_arn("user", "demo-alice"), "DefaultVersionNumber": 1, "LatestVersionNumber": 2,
         "Tags": _tags(Name="demo-web-lt")},
    ]
    ec2["LaunchTemplateVersions"] = {lt_web: [
        {"LaunchTemplateId": lt_web, "LaunchTemplateName": "demo-web-lt", "VersionNumber": 1,
         "VersionDescription": "initial", "CreateTime": ts(3), "CreatedBy": iam_arn("user", "demo-alice"),
         "DefaultVersion": True,
         "LaunchTemplateData": {
             "ImageId": "ami-0dec0000000000002", "InstanceType": "t3.micro", "SecurityGroupIds": [web_sg],
             "IamInstanceProfile": {"Arn": iam_arn("instance-profile", "demo-app-profile")},
             "MetadataOptions": {"HttpTokens": "optional", "HttpPutResponseHopLimit": 1, "HttpEndpoint": "enabled"},
             "UserData": _b64(f"#!/bin/bash\nexport API_TOKEN={CANARIES['launch_template_user_data']}\n")}},
        {"LaunchTemplateId": lt_web, "LaunchTemplateName": "demo-web-lt", "VersionNumber": 2,
         "VersionDescription": "imdsv2", "CreateTime": ts(9), "CreatedBy": iam_arn("user", "demo-ci"),
         "DefaultVersion": False,
         "LaunchTemplateData": {
             "ImageId": "ami-0dec0000000000002", "InstanceType": "t3.small",
             "IamInstanceProfile": {"Arn": iam_arn("instance-profile", "demo-app-profile")},
             "MetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 2, "HttpEndpoint": "enabled"}}},
    ]}
    ec2["Images"] = [
        {"ImageId": "ami-0dec0000000000002", "Name": "demo-web-ami", "Public": False, "OwnerId": ACCOUNT_ID,
         "State": "available", "CreationDate": "2024-01-10T10:00:00.000Z", "ImageType": "machine",
         "Architecture": "x86_64", "RootDeviceType": "ebs", "VirtualizationType": "hvm",
         "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {
             "SnapshotId": "snap-0dec0ba1ba7e00023", "VolumeSize": 8, "Encrypted": True}}],
         "_launch": [{"UserId": EXTERNAL_ACCOUNT_ID}]},
        {"ImageId": "ami-0dec0b0b11c000002", "Name": "demo-public-ami", "Public": True, "OwnerId": ACCOUNT_ID,
         "State": "available", "CreationDate": "2024-01-11T10:00:00.000Z", "ImageType": "machine",
         "Architecture": "x86_64", "RootDeviceType": "ebs", "VirtualizationType": "hvm",
         "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {
             "SnapshotId": "snap-0dec0b0b11c000021", "VolumeSize": 8, "Encrypted": False}}],
         "_launch": [{"Group": "all"}]},
    ]
    ec2["ImageBlockPublicAccessState"] = "unblocked"
    ec2["SnapshotBlockPublicAccessState"] = "unblocked"
    ec2["EbsEncryptionByDefault"] = False
    ec2["TransitGateways"] = [
        {"TransitGatewayId": tgw, "TransitGatewayArn": f"arn:aws:ec2:{r}:{ACCOUNT_ID}:transit-gateway/{tgw}",
         "State": "available", "OwnerId": ACCOUNT_ID, "Description": "demo transit gateway", "CreationTime": ts(2),
         "Options": {"AmazonSideAsn": 64512, "AutoAcceptSharedAttachments": "enable",
                     "DefaultRouteTableAssociation": "enable", "DefaultRouteTablePropagation": "enable",
                     "VpnEcmpSupport": "enable", "DnsSupport": "enable"},
         "Tags": _tags(Name="demo-tgw")},
    ]
    ec2["TransitGatewayAttachments"] = [
        {"TransitGatewayAttachmentId": "tgw-attach-0dec0000000000021", "TransitGatewayId": tgw,
         "TransitGatewayOwnerId": ACCOUNT_ID, "ResourceOwnerId": ACCOUNT_ID, "ResourceType": "vpc",
         "ResourceId": vpc, "State": "available", "CreationTime": ts(2),
         "Association": {"TransitGatewayRouteTableId": "tgw-rtb-0dec0000000000021", "State": "associated"}},
        {"TransitGatewayAttachmentId": "tgw-attach-0dec0000000000022", "TransitGatewayId": tgw,
         "TransitGatewayOwnerId": ACCOUNT_ID, "ResourceOwnerId": EXTERNAL_ACCOUNT_ID, "ResourceType": "vpc",
         "ResourceId": "vpc-0e87eaaa1000000009", "State": "available", "CreationTime": ts(4)},
    ]
    ec2["VpnGateways"] = [
        {"VpnGatewayId": vgw, "State": "available", "Type": "ipsec.1", "AmazonSideAsn": 64512,
         "VpcAttachments": [{"VpcId": vpc, "State": "attached"}], "Tags": _tags(Name="demo-vgw")},
    ]
    psk = CANARIES["vpn_psk"]
    ec2["VpnConnections"] = [
        {"VpnConnectionId": "vpn-0dec0000000000002", "CustomerGatewayId": "cgw-0dec0000000000002",
         "CustomerGatewayConfiguration": ("<?xml version=\"1.0\" encoding=\"UTF-8\"?><vpn_connection>"
                                          f"<ipsec_tunnel><ike><pre_shared_key>{psk}</pre_shared_key></ike>"
                                          "</ipsec_tunnel></vpn_connection>"),
         "Category": "VPN", "State": "available", "Type": "ipsec.1", "VpnGatewayId": vgw,
         "Options": {"StaticRoutesOnly": True, "TunnelOptions": [
             {"OutsideIpAddress": "198.51.100.30", "PreSharedKey": psk}]},
         "Routes": [{"DestinationCidrBlock": "192.168.0.0/16", "Source": "Static", "State": "available"}],
         "VgwTelemetry": [{"OutsideIpAddress": "198.51.100.30", "Status": "UP", "LastStatusChange": ts(5),
                           "AcceptedRouteCount": 1, "StatusMessage": ""}],
         "Tags": _tags(Name="demo-office-vpn")},
    ]
    ec2["ManagedPrefixLists"] = [
        {"PrefixListId": pl_office, "AddressFamily": "IPv4", "State": "create-complete",
         "PrefixListArn": f"arn:aws:ec2:{r}:{ACCOUNT_ID}:prefix-list/{pl_office}",
         "PrefixListName": "demo-office-cidrs", "MaxEntries": 5, "Version": 2, "OwnerId": ACCOUNT_ID,
         "Tags": _tags(Name="demo-office-cidrs")},
        {"PrefixListId": "pl-7ca54a1e", "AddressFamily": "IPv4", "State": "create-complete",
         "PrefixListArn": f"arn:aws:ec2:{r}:aws:prefix-list/pl-7ca54a1e",
         "PrefixListName": f"com.amazonaws.{r}.s3", "OwnerId": "AWS"},
    ]
    ec2["PrefixListEntries"] = {pl_office: [
        {"Cidr": "198.51.100.0/24", "Description": "demo office"},
        {"Cidr": "0.0.0.0/0", "Description": "demo: far too broad (F-076)"},
    ]}
    d["network_firewall"] = {"firewalls": [
        {"FirewallName": "demo-egress-fw", "FirewallArn": f"arn:aws:network-firewall:{r}:{ACCOUNT_ID}:firewall/"
                                                          "demo-egress-fw"}]}
    d["cloudtrail"]["event_data_stores"] = [
        {"EventDataStoreArn": f"arn:aws:cloudtrail:{r}:{ACCOUNT_ID}:eventdatastore/"
                              "dec0dec0-0000-4000-8000-0000000000f2", "Name": "demo-lake",
         "Status": "ENABLED", "MultiRegionEnabled": True, "OrganizationEnabled": False, "RetentionPeriod": 2557,
         "TerminationProtectionEnabled": True, "CreatedTimestamp": ts(2), "UpdatedTimestamp": ts(9)}]
    d["secretsmanager"]["secrets"].append(
        {"ARN": f"arn:aws:secretsmanager:{r}:{ACCOUNT_ID}:secret:demo/retired-token-XyZaBc",
         "Name": "demo/retired-token",
         "Description": "scheduled for deletion", "RotationEnabled": False, "LastChangedDate": ts(10),
         "CreatedDate": ts(2), "DeletedDate": ts(14), "policy": None, "_planned_deletion": True})
    shared_param = f"arn:aws:ssm:{r}:{EXTERNAL_ACCOUNT_ID}:parameter/shared/demo-config"
    d["ssm"].update({
        "shared_parameters": [
            {"Name": shared_param, "ARN": shared_param, "Type": "String", "Tier": "Advanced",
             "LastModifiedDate": ts(5), "Version": 1, "Policies": [], "DataType": "text"}],
        "parameter_policies": {shared_param: _doc({
            "Sid": "ShareWithAcme", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
            "Action": ["ssm:GetParameter"], "Resource": shared_param})},
        "documents": [
            {"Name": "demo-run-shell", "Owner": ACCOUNT_ID, "DocumentType": "Command", "DocumentFormat": "JSON",
             "DocumentVersion": "1", "SchemaVersion": "2.2", "PlatformTypes": ["Linux"], "_share": ["all"]},
            {"Name": "demo-patch-baseline", "Owner": ACCOUNT_ID, "DocumentType": "Automation",
             "DocumentFormat": "YAML", "DocumentVersion": "3", "SchemaVersion": "0.3", "PlatformTypes": ["Linux"],
             "_share": [EXTERNAL_ACCOUNT_ID]},
            {"Name": "demo-private-doc", "Owner": ACCOUNT_ID, "DocumentType": "Command", "DocumentFormat": "JSON",
             "DocumentVersion": "1", "SchemaVersion": "2.2", "PlatformTypes": ["Linux"], "_share": []},
        ],
        "aws_documents": [
            {"Name": "AWS-RunShellScript", "Owner": "Amazon", "DocumentType": "Command", "DocumentFormat": "JSON",
             "DocumentVersion": "1", "SchemaVersion": "1.2", "PlatformTypes": ["Linux", "MacOS"]}],
        "managed_instances": [
            {"InstanceId": web_iid, "PingStatus": "Online", "LastPingDateTime": ts(15), "AgentVersion": "3.3.0.0",
             "IsLatestVersion": True, "PlatformType": "Linux", "PlatformName": "Amazon Linux",
             "PlatformVersion": "2023", "ResourceType": "EC2Instance", "IPAddress": "10.20.1.10",
             "ComputerName": "ip-10-20-1-10.eu-west-2.compute.internal"},
            {"InstanceId": app_iid, "PingStatus": "ConnectionLost", "LastPingDateTime": ts(12),
             "AgentVersion": "3.2.0.0", "IsLatestVersion": False, "PlatformType": "Linux",
             "PlatformName": "Amazon Linux", "PlatformVersion": "2", "ResourceType": "EC2Instance",
             "IPAddress": "10.20.2.10", "ComputerName": "ip-10-20-2-10.eu-west-2.compute.internal"}],
    })
    fns = {f["FunctionName"]: f for f in d["lambda"]["functions"]}
    fns["demo-internal"]["versions"] = ["1"]
    fns["demo-internal"]["aliases"] = [
        {"Name": "live", "FunctionVersion": "1", "Description": "production alias",
         "url": {"AuthType": "NONE", "Url": "https://demointernallive.lambda-url.eu-west-2.on.aws/"},
         "policy": _doc({"Sid": "PublicAliasUrl", "Effect": "Allow", "Principal": "*",
                         "Action": "lambda:InvokeFunctionUrl", "Resource": lambda_arn(r, "demo-internal") + ":live",
                         "Condition": {"StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}}})}]
    fns["demo-processor"]["versions"] = ["1", "2"]
    fns["demo-processor"]["aliases"] = [
        {"Name": "stable", "FunctionVersion": "2", "Description": "stable alias", "url": None, "policy": None}]
    d["lambda"]["layers"] = [
        {"LayerName": "demo-deps", "versions": [
            {"Version": 3, "CompatibleRuntimes": ["python3.12"], "policy": _doc(
                {"Sid": "PublicLayer", "Effect": "Allow", "Principal": "*", "Action": "lambda:GetLayerVersion",
                 "Resource": f"arn:aws:lambda:{r}:{ACCOUNT_ID}:layer:demo-deps:3"})},
            {"Version": 2, "CompatibleRuntimes": ["python3.11"], "policy": None}]}]
    d["lambda"]["event_source_mappings"] = [
        {"UUID": "dec0dec0-0000-4000-8000-0000000000e5",
         "EventSourceArn": f"arn:aws:sqs:{r}:{ACCOUNT_ID}:demo-queue",
         "FunctionArn": lambda_arn(r, "demo-processor"), "State": "Enabled", "BatchSize": 10,
         "LastModified": ts(9), "StateTransitionReason": "USER_INITIATED"}]
    d["ecs"]["clusters"] = [
        {"clusterName": "demo-ecs", "services": [
            {"serviceName": "demo-api-svc", "taskDefinition": "demo-api:2", "launchType": "FARGATE",
             "enableExecuteCommand": True, "assignPublicIp": "ENABLED", "subnets": [subnet_pub],
             "securityGroups": [web_sg]}]}]
    d["cloudformation"]["stack_sets"] = [
        {"StackSetName": "demo-baseline", "StackSetId": "demo-baseline:dec0dec0-0000-4000-8000-0000000000c5",
         "Status": "ACTIVE", "PermissionModel": "SELF_MANAGED",
         "AdministrationRoleARN": role_arn("demo-cfn-role"), "ExecutionRoleName": "demo-stackset-execution",
         "Parameters": [{"ParameterKey": "ApiKey", "ParameterValue": CANARIES["cfn_stackset_parameter"]}]}]
    d["codebuild"]["source_credentials"] = [
        {"arn": f"arn:aws:codebuild:{r}:{ACCOUNT_ID}:token/github", "serverType": "GITHUB",
         "authType": "PERSONAL_ACCESS_TOKEN"}]
    d["sagemaker"]["domains"] = [
        {"DomainId": "d-0dec0a1b2c3d4", "DomainName": "demo-studio", "AuthMode": "IAM",
         "ExecutionRole": role_arn("demo-sagemaker-role"), "SpaceRole": role_arn("demo-sagemaker-role"),
         "AppNetworkAccessType": "PublicInternetOnly", "VpcId": vpc, "SubnetIds": [subnet_pub],
         "users": [{"UserProfileName": "demo-analyst", "ExecutionRole": role_arn("demo-app-role")},
                   {"UserProfileName": "demo-default-user", "ExecutionRole": None}]}]
    topics = {t["Name"]: t for t in d["sns"]["topics"]}
    topics["demo-alerts"]["subscriptions"] = [
        {"Protocol": "sqs", "Endpoint": f"arn:aws:sqs:{r}:{ACCOUNT_ID}:demo-queue"},
        {"Protocol": "email", "Endpoint": "security-team@example.com"},
        {"Protocol": "https", "Endpoint": f"https://hooks.example.com/demo/alerts?token={CANARIES['sns_endpoint_token']}"},
        {"Protocol": "lambda", "Endpoint": lambda_arn(r, "demo-processor")},
    ]
    topics["demo-events"]["subscriptions"] = []
    d["ecr"]["registry_policy"] = _doc({
        "Sid": "ReplicateFromPartner", "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{EXTERNAL_ACCOUNT_ID}:root"},
        "Action": ["ecr:CreateRepository", "ecr:ReplicateImage"],
        "Resource": f"arn:aws:ecr:{r}:{ACCOUNT_ID}:repository/*"})
    d["ecr"]["replication_rules"] = [{"destinations": [{"region": "eu-west-1", "registryId": EXTERNAL_ACCOUNT_ID}]}]
    d["rds"]["clusters"] = [
        {"DBClusterIdentifier": "demo-aurora", "Engine": "aurora-postgresql", "StorageEncrypted": True,
         "KmsKeyId": kms_arn(r, KEY_W2), "IAMDatabaseAuthenticationEnabled": True, "PubliclyAccessible": False,
         "members": ["demo-db-private"]}]
    d["rds"]["cluster_snapshots"] = [
        {"DBClusterSnapshotIdentifier": "demo-aurora-snap-shared", "DBClusterIdentifier": "demo-aurora",
         "SnapshotType": "manual", "StorageEncrypted": True, "KmsKeyId": kms_arn(r, KEY_W2),
         "restore": [EXTERNAL_ACCOUNT_ID]},
        {"DBClusterSnapshotIdentifier": "demo-aurora-snap-public", "DBClusterIdentifier": "demo-aurora",
         "SnapshotType": "manual", "StorageEncrypted": False, "restore": ["all"]},
        {"DBClusterSnapshotIdentifier": "rds:demo-aurora-2024-01-15", "DBClusterIdentifier": "demo-aurora",
         "SnapshotType": "automated", "StorageEncrypted": True, "KmsKeyId": kms_arn(r, KEY_W2), "restore": []},
    ]
    apis = {a["id"]: a for a in d["apigateway"]["rest_apis"]}
    acl_arn = d["waf"]["web_acls"][0]["ARN"]
    apis["demorest01"]["stages"] = [
        {"stageName": "prod", "deploymentId": "dep0001", "variables": {"lambdaAlias": "live"},
         "webAclArn": acl_arn, "createdDate": ts(3), "lastUpdatedDate": ts(9),
         "accessLogSettings": {"destinationArn": f"arn:aws:logs:{r}:{ACCOUNT_ID}:log-group:demo-api-access",
                               "format": "$context.requestId"}}]
    apis["demorest02"]["stages"] = [{"stageName": "dev", "deploymentId": "dep0002", "createdDate": ts(4),
                                     "lastUpdatedDate": ts(4)}]
    apis["demorest02"]["resources"][1]["auth"] = {"ANY": ("CUSTOM", "auth01")}
    https = {a["ApiId"]: a for a in d["apigateway"]["http_apis"]}
    https["demohttp01"]["routes"] = [
        {"RouteId": "rt00001", "RouteKey": "GET /orders", "Target": "integrations/int0001",
         "AuthorizationType": "NONE", "ApiKeyRequired": False},
        {"RouteId": "rt00002", "RouteKey": "ANY /{proxy+}", "Target": "integrations/int0002",
         "AuthorizationType": "JWT", "AuthorizerId": "jwt001", "ApiKeyRequired": False}]
    https["demohttp01"]["stages"] = [{"StageName": "$default", "AutoDeploy": True, "CreatedDate": ts(3),
                                      "StageVariables": {}}]
    https["demows0001"]["routes"] = [{"RouteId": "rt00003", "RouteKey": "$connect", "AuthorizationType": "NONE",
                                      "ApiKeyRequired": False}]
    https["demows0001"]["stages"] = []
    d["cognito"]["user_pool_details"] = {
        "eu-west-2_DemoPool1": {"AllowAdminCreateUserOnly": False, "MfaConfiguration": "OFF",
                                "clients": [{"ClientId": "dec0c1e47000000000000000a1", "ClientName": "demo-web-client"},
                                            {"ClientId": "dec0c1e47000000000000000b2",
                                             "ClientName": "demo-backend-client"}]}}
    lbs = {lb["LoadBalancerName"]: lb for lb in d["elb"]["v2"]}
    alb, nlb = lbs["demo-public-alb"], lbs["demo-internal-nlb"]
    alb["listeners"] = [
        {"Port": 443, "Protocol": "HTTPS", "DefaultActions": [
            {"Type": "authenticate-cognito", "Order": 1, "AuthenticateCognitoConfig": {
                "UserPoolArn": f"arn:aws:cognito-idp:{r}:{ACCOUNT_ID}:userpool/eu-west-2_DemoPool1",
                "UserPoolClientId": "dec0c1e47000000000000000a1", "UserPoolDomain": "demo-auth"}},
            {"Type": "forward", "Order": 2, "tg": "demo-web-tg"}]},
        {"Port": 80, "Protocol": "HTTP", "DefaultActions": [
            {"Type": "redirect", "Order": 1, "RedirectConfig": {"Protocol": "HTTPS", "Port": "443",
                                                                "StatusCode": "HTTP_301"}}]},
        {"Port": 8443, "Protocol": "HTTPS",
         "DefaultActions": [{"Type": "forward", "Order": 1, "tg": "demo-lambda-tg"}]},
    ]
    nlb["listeners"] = [{"Port": 5432, "Protocol": "TCP", "DefaultActions": [
        {"Type": "forward", "Order": 1, "tg": "demo-denied-tg"}]}]
    cluster = d["eks"]["clusters"][0]
    cluster["access_entries"] = [
        {"principalArn": role_arn("demo-eks-node-role"), "type": "EC2_LINUX",
         "username": "system:node:{{EC2PrivateDNSName}}", "kubernetesGroups": [], "policies": []},
        {"principalArn": role_arn("demo-admin-role"), "type": "STANDARD", "username": "demo-admin",
         "kubernetesGroups": [], "policies": [
             {"policyArn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
              "accessScope": {"type": "cluster", "namespaces": []}}]},
        {"principalArn": iam_arn("user", "demo-alice"), "type": "STANDARD", "username": "demo-alice",
         "kubernetesGroups": ["demo-viewers"], "policies": [
             {"policyArn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy",
              "accessScope": {"type": "namespace", "namespaces": ["demo-apps"]}}]},
    ]
    cluster["pod_identity"] = [
        {"associationId": "a-dec0a55oc1a7e01", "namespace": "demo-apps", "serviceAccount": "demo-worker",
         "roleArn": role_arn("demo-app-role")}]
    d["guardduty"] = {"detectors": [{"DetectorId": "dec0dec0dec0dec0dec0dec0dec0dec2", "Status": "ENABLED",
                                     "Features": [{"Name": "S3_DATA_EVENTS", "Status": "ENABLED"},
                                                  {"Name": "EKS_AUDIT_LOGS", "Status": "DISABLED"},
                                                  {"Name": "RUNTIME_MONITORING", "Status": "DISABLED"}]}]}
    d["securityhub"] = {"hub": {"HubArn": f"arn:aws:securityhub:{r}:{ACCOUNT_ID}:hub/default",
                                "SubscribedAt": "2024-01-02T10:00:00.000Z", "AutoEnableControls": True},
                        "standards": [
                            {"StandardsArn": f"arn:aws:securityhub:{r}::standards/aws-foundational-security-best-"
                                             "practices/v/1.0.0",
                             "StandardsSubscriptionArn": f"arn:aws:securityhub:{r}:{ACCOUNT_ID}:subscription/"
                                                         "aws-foundational-security-best-practices/v/1.0.0",
                             "StandardsStatus": "READY"}]}
    config_role = iam_arn("role", "AWSServiceRoleForConfig", "/aws-service-role/config.amazonaws.com/")
    d["config"] = {"recorders": [{"name": "default", "roleARN": config_role,
                                  "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True}}],
                   "status": [{"name": "default", "recording": True, "lastStatus": "SUCCESS",
                               "lastStartTime": ts(1), "lastStatusChangeTime": ts(15)}],
                   "channels": [{"name": "default", "s3BucketName": "demo-logs-bucket", "s3KeyPrefix": "config"}]}
    d["accessanalyzer"] = {"analyzers": [
        {"arn": f"arn:aws:access-analyzer:{r}:{ACCOUNT_ID}:analyzer/demo-account-analyzer",
         "name": "demo-account-analyzer", "type": "ACCOUNT", "createdAt": ts(2), "status": "ACTIVE"}]}


def _extend_eu_west_1(d: Dict[str, Any]) -> None:
    ec2 = d["ec2"]
    ec2.update({"Addresses": [], "LaunchTemplates": [], "LaunchTemplateVersions": {}, "Images": [],
                "ImageBlockPublicAccessState": "block-new-sharing",
                "SnapshotBlockPublicAccessState": "block-all-sharing",
                "EbsEncryptionByDefault": True, "TransitGateways": [], "TransitGatewayAttachments": [],
                "VpnGateways": [], "VpnConnections": [], "ManagedPrefixLists": [], "PrefixListEntries": {}})
    d["network_firewall"] = {"firewalls": []}
    d["cloudtrail"]["event_data_stores"] = []
    d["ssm"].update({"shared_parameters": [], "parameter_policies": {}, "documents": [], "aws_documents": [],
                     "managed_instances": []})
    d["lambda"].update({"layers": [], "event_source_mappings": []})
    d["ecs"]["clusters"] = []
    d["cloudformation"]["stack_sets"] = []
    d["codebuild"]["source_credentials"] = []
    d["sagemaker"]["domains"] = []
    d["ecr"].update({"registry_policy": None, "replication_rules": []})
    d["rds"].update({"clusters": [], "cluster_snapshots": []})
    d["cognito"]["user_pool_details"] = {}
    west = [c for c in d["eks"]["clusters"] if c["name"] == "demo-west-cluster"][0]
    west["access_entries"] = [
        {"principalArn": role_arn("demo-admin-role"), "type": "STANDARD", "username": "demo-admin",
         "kubernetesGroups": [], "policies": [
             {"policyArn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
              "accessScope": {"type": "cluster", "namespaces": []}}]}]
    west["pod_identity"] = []
    d["guardduty"] = {"detectors": []}
    d["securityhub"] = {"hub": None, "standards": []}
    d["config"] = {"recorders": [], "status": [], "channels": []}
    d["accessanalyzer"] = {"analyzers": []}


def _extend_empty_region(d: Dict[str, Any]) -> None:
    d["ec2"].update({
        "Addresses": [], "LaunchTemplates": [], "LaunchTemplateVersions": {}, "Images": [],
        "ImageBlockPublicAccessState": "unblocked", "SnapshotBlockPublicAccessState": "unblocked",
        "EbsEncryptionByDefault": False, "TransitGateways": [], "TransitGatewayAttachments": [], "VpnGateways": [],
        "VpnConnections": [], "ManagedPrefixLists": [], "PrefixListEntries": {}})
    d["network_firewall"] = {"firewalls": []}
    d["cloudtrail"]["event_data_stores"] = []
    d["ssm"].update({"shared_parameters": [], "parameter_policies": {}, "documents": [], "aws_documents": [],
                     "managed_instances": []})
    d["lambda"].update({"layers": [], "event_source_mappings": []})
    d["ecs"]["clusters"] = []
    d["cloudformation"]["stack_sets"] = []
    d["codebuild"]["source_credentials"] = []
    d["sagemaker"]["domains"] = []
    d["ecr"].update({"registry_policy": None, "replication_rules": []})
    d["rds"].update({"clusters": [], "cluster_snapshots": []})
    d["cognito"]["user_pool_details"] = {}
    d["guardduty"] = {"detectors": []}
    d["securityhub"] = {"hub": None, "standards": []}
    d["config"] = {"recorders": [], "status": [], "channels": []}
    d["accessanalyzer"] = {"analyzers": []}


_extend_eu_west_2(REGIONAL["eu-west-2"])
_extend_eu_west_1(REGIONAL["eu-west-1"])
_extend_empty_region(_EMPTY_REGION)


def regional(req: Request, service: str) -> Dict[str, Any]:
    return REGIONAL.get(req.region or "", _EMPTY_REGION)[service]


def _not_found(code: str, message: str) -> AWSError:
    return AWSError(code, message, 404)


def lambda_function(req: Request) -> "tuple[Dict[str, Any], Optional[str]]":
    """(function record, qualifier) for ``FunctionName`` (name, ARN, ``name:qualifier`` or qualified ARN)
    plus an optional ``Qualifier`` parameter; ``$LATEST`` counts as unqualified."""
    raw = req.params["FunctionName"]
    name, qualifier = raw, None
    if raw.startswith("arn:"):
        rest = raw.split(":function:", 1)[-1]
        name, _, q = rest.partition(":")
        qualifier = q or None
    elif ":" in raw:
        name, _, q = raw.partition(":")
        qualifier = q or None
    qualifier = req.params.get("Qualifier") or qualifier
    if qualifier == "$LATEST":
        qualifier = None
    for f in regional(req, "lambda")["functions"]:
        if f["FunctionName"] == name:
            return f, qualifier
    raise _not_found("ResourceNotFoundException", f"Function not found: {lambda_arn(req.region or '', raw)}")


def lambda_alias(f: Dict[str, Any], qualifier: str) -> Dict[str, Any]:
    """The alias record named ``qualifier`` (``{}`` for a plain version number)."""
    for alias in f.get("aliases") or []:
        if alias["Name"] == qualifier:
            return alias
    if qualifier in (f.get("versions") or []):
        return {}
    raise _not_found("ResourceNotFoundException", f"Function not found: {f['FunctionName']}:{qualifier}")


# ═════════════════════════════════════════════════════════════════════════════
# The world
# ═════════════════════════════════════════════════════════════════════════════
def build_world() -> World:  # noqa: C901 - one registration block per service, kept flat on purpose
    """A fresh :class:`World` for acme (handlers + injections). Tests may add more injections."""
    w = World("acme", ACCOUNT_ID, partition=PARTITION, caller_arn=CALLER["Arn"],
              regions=[GLOBAL_REGION, *REGIONS])
    w.meta.update(canaries=dict(CANARIES), eks_endpoints=dict(EKS_ENDPOINTS))
    _register_sts_ec2_regions(w)
    _register_iam(w)
    _register_s3(w)
    _register_cloudfront_route53(w)
    _register_waf(w)
    _register_network(w)
    _register_cloudtrail(w)
    _register_eks(w)
    _register_secrets_ssm_lambda_kms(w)
    _register_compute(w)
    _register_messaging_data(w)
    _register_apigw_cognito_elb(w)
    _register_wave1(w)
    _register_injections(w)
    _register_pagination(w)
    return w


# ── STS / regions ────────────────────────────────────────────────────────────
def _register_sts_ec2_regions(w: World) -> None:
    @w.op("sts", "GetCallerIdentity")
    def get_caller_identity(req: Request):
        # Regional STS: a region the account has not opted into rejects the credentials (cli.md §3.1, F-064).
        if req.region in NOT_OPTED_IN_REGIONS:
            raise AWSError("InvalidClientTokenId", "The security token included in the request is invalid.", 403)
        return dict(CALLER)

    @w.op("ec2", "DescribeRegions")
    def describe_regions(req: Request):
        regions = [{"RegionName": n, "Endpoint": f"ec2.{n}.amazonaws.com", "OptInStatus": "opt-in-not-required"}
                   for n in sorted({GLOBAL_REGION, *REGIONS})]
        regions.append({"RegionName": "af-south-1", "Endpoint": "ec2.af-south-1.amazonaws.com",
                        "OptInStatus": "not-opted-in"})
        allowed = None
        for f in req.params.get("Filters", []):
            if f.get("Name") == "opt-in-status":
                allowed = set(f.get("Values", []))
        if allowed is not None:
            regions = [r for r in regions if r["OptInStatus"] in allowed]
        return {"Regions": regions}


# ── IAM ──────────────────────────────────────────────────────────────────────
def _register_iam(w: World) -> None:
    users, groups, roles = _by(USERS, "UserName"), _by(GROUPS, "GroupName"), _by(ROLES, "RoleName")

    def no_such(kind: str, name: str) -> AWSError:
        return _not_found("NoSuchEntity", f"The {kind} with name {name} cannot be found.")

    @w.op("iam", "GetAccountPasswordPolicy")
    def password_policy(req: Request):
        raise _not_found("NoSuchEntity", f"The Password Policy with domain name {ACCOUNT_ID} cannot be found.")

    w.static("iam", "GetAccountSummary", {"SummaryMap": {
        "Users": len(USERS), "Groups": len(GROUPS), "Roles": len(ROLES), "Policies": len(CUSTOMER_POLICIES),
        "AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0, "MFADevices": 1, "MFADevicesInUse": 1,
        "UsersQuota": 5000, "PolicyVersionsInUse": 9}})

    @w.op("iam", "ListUsers")
    def list_users(req: Request):
        return {"Users": [_iam_user(u) for u in USERS], "IsTruncated": False}

    def user(req: Request) -> Dict[str, Any]:
        name = req.params["UserName"]
        if name not in users:
            raise no_such("user", name)
        return users[name]

    @w.op("iam", "ListAccessKeys")
    def list_access_keys(req: Request):
        u = user(req)
        return {"AccessKeyMetadata": [{"UserName": u["UserName"], "AccessKeyId": k, "Status": s, "CreateDate": d}
                                      for k, s, d in u["keys"]], "IsTruncated": False}

    @w.op("iam", "ListMFADevices")
    def list_mfa(req: Request):
        u = user(req)
        return {"MFADevices": [{"UserName": u["UserName"], "SerialNumber": sn, "EnableDate": ts(3)}
                               for sn in u["mfa"]], "IsTruncated": False}

    @w.op("iam", "GetLoginProfile")
    def get_login_profile(req: Request):
        u = user(req)
        if not u["login"]:
            raise _not_found("NoSuchEntity", f"Login Profile for User {u['UserName']} cannot be found.")
        return {"LoginProfile": {"UserName": u["UserName"], "CreateDate": u["login"],
                                 "PasswordResetRequired": False}}

    @w.op("iam", "ListGroupsForUser")
    def list_groups_for_user(req: Request):
        u = user(req)
        return {"Groups": [_iam_group(groups[g]) for g in u["groups"]], "IsTruncated": False}

    @w.op("iam", "ListAttachedUserPolicies")
    def list_attached_user(req: Request):
        return {"AttachedPolicies": _attached(user(req)["attached"]), "IsTruncated": False}

    @w.op("iam", "ListGroups")
    def list_groups(req: Request):
        return {"Groups": [_iam_group(g) for g in GROUPS], "IsTruncated": False}

    def group(req: Request) -> Dict[str, Any]:
        name = req.params["GroupName"]
        if name not in groups:
            raise no_such("group", name)
        return groups[name]

    @w.op("iam", "ListAttachedGroupPolicies")
    def list_attached_group(req: Request):
        return {"AttachedPolicies": _attached(group(req)["attached"]), "IsTruncated": False}

    @w.op("iam", "ListRoles")
    def list_roles(req: Request):
        return {"Roles": [_iam_role(r) for r in ROLES], "IsTruncated": False}

    def role(req: Request) -> Dict[str, Any]:
        name = req.params["RoleName"]
        if name not in roles:
            raise no_such("role", name)
        return roles[name]

    @w.op("iam", "ListAttachedRolePolicies")
    def list_attached_role(req: Request):
        return {"AttachedPolicies": _attached(role(req)["attached"]), "IsTruncated": False}

    @w.op("iam", "ListPolicies")
    def list_policies(req: Request):
        if req.params.get("Scope", "All") not in ("Local", "All"):
            return {"Policies": [], "IsTruncated": False}
        out = []
        for name, p in sorted(CUSTOMER_POLICIES.items()):
            out.append({"PolicyName": name, "PolicyId": p["id"], "Arn": policy_arn(name), "Path": "/",
                        "DefaultVersionId": p["default"], "AttachmentCount": p["attachments"],
                        "PermissionsBoundaryUsageCount": 0, "IsAttachable": True,
                        "CreateDate": ts(1), "UpdateDate": ts(9)})
        return {"Policies": out, "IsTruncated": False}

    def lookup_policy(arn: str):
        if arn.startswith("arn:aws:iam::aws:policy/"):
            name = arn.rsplit("/", 1)[-1]
            if name in AWS_MANAGED:
                m = AWS_MANAGED[name]
                return name, m["id"], m["version"], {m["version"]: m["doc"]}, "/"
        elif arn.startswith(f"arn:aws:iam::{ACCOUNT_ID}:policy/"):
            name = arn.rsplit("/", 1)[-1]
            if name in CUSTOMER_POLICIES:
                p = CUSTOMER_POLICIES[name]
                return name, p["id"], p["default"], p["versions"], "/"
        raise _not_found("NoSuchEntity", f"Policy {arn} does not exist or is not attachable.")

    @w.op("iam", "GetPolicy")
    def get_policy(req: Request):
        name, pid, default, _versions, path = lookup_policy(req.params["PolicyArn"])
        return {"Policy": {"PolicyName": name, "PolicyId": pid, "Arn": req.params["PolicyArn"], "Path": path,
                           "DefaultVersionId": default, "AttachmentCount": 1, "IsAttachable": True,
                           "CreateDate": ts(1), "UpdateDate": ts(9)}}

    @w.op("iam", "GetPolicyVersion")
    def get_policy_version(req: Request):
        _name, _pid, default, versions, _path = lookup_policy(req.params["PolicyArn"])
        vid = req.params["VersionId"]
        if vid not in versions:
            raise _not_found("NoSuchEntity", f"Policy {req.params['PolicyArn']} version {vid} does not exist.")
        return {"PolicyVersion": {"Document": World.iam_doc(versions[vid]), "VersionId": vid,
                                  "IsDefaultVersion": vid == default, "CreateDate": ts(9)}}

    @w.op("iam", "ListInstanceProfiles")
    def list_instance_profiles(req: Request):
        return {"InstanceProfiles": [
            {"Path": "/", "InstanceProfileName": name, "InstanceProfileId": pid,
             "Arn": iam_arn("instance-profile", name), "CreateDate": ts(2), "Roles": [_iam_role(roles[rname])]}
            for name, pid, rname in INSTANCE_PROFILES], "IsTruncated": False}

    def inline_ops(kind: str, entity_key: str, lookup):
        @w.op("iam", f"List{kind}Policies")
        def list_inline(req: Request):
            return {"PolicyNames": sorted(lookup(req)["inline"]), "IsTruncated": False}

        @w.op("iam", f"Get{kind}Policy")
        def get_inline(req: Request):
            entity = lookup(req)
            pname = req.params["PolicyName"]
            if pname not in entity["inline"]:
                raise _not_found("NoSuchEntity", f"The {kind.lower()} policy with name {pname} cannot be found.")
            return {entity_key: entity[entity_key], "PolicyName": pname,
                    "PolicyDocument": World.iam_doc(entity["inline"][pname])}

    inline_ops("User", "UserName", user)
    inline_ops("Role", "RoleName", role)
    inline_ops("Group", "GroupName", group)


# ── S3 ───────────────────────────────────────────────────────────────────────
def _register_s3(w: World) -> None:
    buckets = _by(S3_BUCKETS, "Name")

    def bucket(req: Request) -> Dict[str, Any]:
        name = req.params["Bucket"]
        if name not in buckets:
            raise _not_found("NoSuchBucket", "The specified bucket does not exist")
        return buckets[name]

    @w.op("s3", "ListBuckets")
    def list_buckets(req: Request):
        out = []
        for b in S3_BUCKETS:
            region = {None: "us-east-1", "EU": "eu-west-1"}.get(b["location"], b["location"])
            out.append({"Name": b["Name"], "CreationDate": b["CreationDate"], "BucketRegion": region})
        return {"Buckets": out, "Owner": OWNER}

    @w.op("s3", "GetBucketLocation")
    def get_location(req: Request):
        loc = bucket(req)["location"]
        return {"LocationConstraint": loc} if loc else {}

    @w.op("s3", "GetBucketPolicy")
    def get_policy(req: Request):
        b = bucket(req)
        if not b["policy"]:
            raise _not_found("NoSuchBucketPolicy", "The bucket policy does not exist")
        return {"Policy": World.json_doc(b["policy"])}

    @w.op("s3", "GetBucketAcl")
    def get_acl(req: Request):
        b = bucket(req)
        return b["acl"] or {"Owner": OWNER, "Grants": [
            {"Grantee": {"Type": "CanonicalUser", "ID": OWNER["ID"], "DisplayName": "demo-owner"},
             "Permission": "FULL_CONTROL"}]}

    @w.op("s3", "GetPublicAccessBlock")
    def get_pab(req: Request):
        b = bucket(req)
        if not b["pab"]:
            raise _not_found("NoSuchPublicAccessBlockConfiguration",
                             "The public access block configuration was not found")
        return {"PublicAccessBlockConfiguration": b["pab"]}

    @w.op("s3", "GetBucketVersioning")
    def get_versioning(req: Request):
        return dict(bucket(req)["versioning"] or {})

    @w.op("s3", "GetBucketEncryption")
    def get_encryption(req: Request):
        b = bucket(req)
        if not b["encryption"]:
            raise _not_found("ServerSideEncryptionConfigurationNotFoundError",
                             "The server side encryption configuration was not found")
        return {"ServerSideEncryptionConfiguration": b["encryption"]}

    @w.op("s3", "GetBucketTagging")
    def get_tagging(req: Request):
        b = bucket(req)
        if not b["tags"]:
            raise _not_found("NoSuchTagSet", "The TagSet does not exist")
        return {"TagSet": b["tags"]}

    @w.op("s3", "GetBucketLogging")
    def get_logging(req: Request):
        b = bucket(req)
        return {"LoggingEnabled": b["logging"]} if b["logging"] else {}

    @w.op("s3", "GetBucketCors")
    def get_cors(req: Request):
        b = bucket(req)
        if not b["cors"]:
            raise _not_found("NoSuchCORSConfiguration", "The CORS configuration does not exist")
        return {"CORSRules": b["cors"]}

    @w.op("s3", "GetBucketNotificationConfiguration")
    def get_notifications(req: Request):
        return dict(bucket(req)["notifications"] or {})


# ── CloudFront / Route 53 ────────────────────────────────────────────────────
def _register_cloudfront_route53(w: World) -> None:
    dists = _by(CF_DISTRIBUTIONS, "Id")

    @w.op("cloudfront", "ListDistributions")
    def list_distributions(req: Request):
        return {"DistributionList": {"Marker": req.params.get("Marker", ""), "MaxItems": 100,
                                     "IsTruncated": False, "Quantity": len(CF_DISTRIBUTIONS),
                                     "Items": [_cf_summary(d) for d in CF_DISTRIBUTIONS]}}

    @w.op("cloudfront", "GetDistributionConfig")
    def get_distribution_config(req: Request):
        d = dists.get(req.params["Id"])
        if d is None:
            raise _not_found("NoSuchDistribution", "The specified distribution does not exist.")
        return {"DistributionConfig": _cf_config(d), "ETag": f"E{d['Id'][-4:]}ETAG"}

    zones = {z["Id"].rsplit("/", 1)[-1]: z for z in ROUTE53_ZONES}

    @w.op("route53", "ListHostedZones")
    def list_hosted_zones(req: Request):
        return {"HostedZones": [{k: v for k, v in z.items() if k != "records"} for z in ROUTE53_ZONES],
                "Marker": req.params.get("Marker", ""), "IsTruncated": False, "MaxItems": "100"}

    @w.op("route53", "ListResourceRecordSets")
    def list_rrsets(req: Request):
        zid = req.params["HostedZoneId"].rsplit("/", 1)[-1]
        if zid not in zones:
            raise _not_found("NoSuchHostedZone", f"No hosted zone found with ID: {zid}")
        return {"ResourceRecordSets": zones[zid]["records"], "IsTruncated": False, "MaxItems": "300"}


# ── WAFv2 ────────────────────────────────────────────────────────────────────
def _register_waf(w: World) -> None:
    def data(req: Request) -> Dict[str, Any]:
        scope = req.params.get("Scope")
        if scope == "CLOUDFRONT":
            if req.region != "us-east-1":
                raise AWSError("WAFInvalidParameterException",
                               "Error reason: The scope is not valid., field: SCOPE_VALUE, parameter: CLOUDFRONT", 400)
            return WAF_CLOUDFRONT
        return regional(req, "waf")

    def find(items: List[Dict[str, Any]], req: Request, kind: str) -> Dict[str, Any]:
        for item in items:
            if item["Id"] == req.params.get("Id") and item["Name"] == req.params.get("Name"):
                return item
        raise _not_found("WAFNonexistentItemException",
                         f"AWS WAF couldn't perform the operation because your {kind} doesn't exist.")

    def summary(item: Dict[str, Any]) -> Dict[str, Any]:
        out = {"Name": item["Name"], "Id": item["Id"], "LockToken": "0000000a-lock-4000-8000-000000000000",
               "ARN": item["ARN"]}
        if item.get("Description"):
            out["Description"] = item["Description"]
        return out

    @w.op("wafv2", "ListWebACLs")
    def list_web_acls(req: Request):
        return {"WebACLs": [summary(a) for a in data(req)["web_acls"]]}

    @w.op("wafv2", "GetWebACL")
    def get_web_acl(req: Request):
        acl = find(data(req)["web_acls"], req, "web ACL")
        return {"WebACL": {k: v for k, v in acl.items() if k != "resources"},
                "LockToken": "0000000a-lock-4000-8000-000000000000"}

    @w.op("wafv2", "ListResourcesForWebACL")
    def list_resources(req: Request):
        rtype = req.params.get("ResourceType", "APPLICATION_LOAD_BALANCER")
        if rtype == "CLOUDFRONT":
            # Real WAFv2: CLOUDFRONT is not a valid ResourceType (use ListDistributionsByWebACLId) - F-118.
            raise AWSError("WAFInvalidParameterException",
                           "Error reason: The parameter contains formatting that isn't valid., "
                           "field: RESOURCE_TYPE, parameter: CLOUDFRONT", 400)
        arn = req.params["WebACLArn"]
        for scope_data in [WAF_CLOUDFRONT, *(REGIONAL[r]["waf"] for r in REGIONAL)]:
            for acl in scope_data["web_acls"]:
                if acl["ARN"] == arn:
                    return {"ResourceArns": list(acl["resources"].get(rtype, []))}
        raise _not_found("WAFNonexistentItemException", "web ACL does not exist")

    @w.op("wafv2", "ListRuleGroups")
    def list_rule_groups(req: Request):
        return {"RuleGroups": [summary(g) for g in data(req)["rule_groups"]]}

    @w.op("wafv2", "GetRuleGroup")
    def get_rule_group(req: Request):
        return {"RuleGroup": find(data(req)["rule_groups"], req, "rule group"),
                "LockToken": "0000000a-lock-4000-8000-000000000000"}

    @w.op("wafv2", "ListIPSets")
    def list_ip_sets(req: Request):
        return {"IPSets": [summary(s) for s in data(req)["ip_sets"]]}

    @w.op("wafv2", "GetIPSet")
    def get_ip_set(req: Request):
        return {"IPSet": find(data(req)["ip_sets"], req, "IP set"),
                "LockToken": "0000000a-lock-4000-8000-000000000000"}

    @w.op("wafv2", "ListLoggingConfigurations")
    def list_logging(req: Request):
        return {"LoggingConfigurations": data(req)["logging"]}


# ── EC2 / VPC / SG / Flow logs / EBS ─────────────────────────────────────────
def _register_network(w: World) -> None:
    simple = {
        "DescribeVpcs": "Vpcs", "DescribeSubnets": "Subnets", "DescribeRouteTables": "RouteTables",
        "DescribeInternetGateways": "InternetGateways", "DescribeNatGateways": "NatGateways",
        "DescribeNetworkAcls": "NetworkAcls", "DescribeVpcEndpoints": "VpcEndpoints",
        "DescribeDhcpOptions": "DhcpOptions", "DescribeVpcPeeringConnections": "VpcPeeringConnections",
        "DescribeSecurityGroups": "SecurityGroups", "DescribeInstances": "Reservations",
        "DescribeFlowLogs": "FlowLogs",
    }
    for op, key in simple.items():
        def handler(req: Request, _key: str = key):
            return {_key: regional(req, "ec2")[_key]}
        w.handlers[("ec2", op)] = handler

    @w.op("ec2", "DescribeNetworkInterfaces")
    def describe_enis(req: Request):
        enis = regional(req, "ec2")["NetworkInterfaces"]
        for f in req.params.get("Filters", []):
            if f.get("Name") == "group-id":
                wanted = set(f.get("Values", []))
                enis = [e for e in enis if wanted & {g["GroupId"] for g in e.get("Groups", [])}]
        return {"NetworkInterfaces": enis}

    @w.op("ec2", "DescribeInstanceAttribute")
    def describe_instance_attribute(req: Request):
        iid = req.params["InstanceId"]
        out: Dict[str, Any] = {"InstanceId": iid}
        if req.params.get("Attribute") == "userData":
            data = regional(req, "ec2")["UserData"].get(iid)
            out["UserData"] = {"Value": data} if data else {}
        return out

    @w.op("ec2", "DescribeSnapshots")
    def describe_snapshots(req: Request):
        owners = req.params.get("OwnerIds")
        snaps = regional(req, "ec2")["Snapshots"]
        if owners and "self" not in owners and ACCOUNT_ID not in owners:
            snaps = []
        restorable = req.params.get("RestorableByUserIds")
        if restorable:
            wanted = set(restorable)
            snaps = [s for s in snaps if any(p.get("Group") in wanted or p.get("UserId") in wanted
                                             for p in s["perms"])]
        return {"Snapshots": [{k: v for k, v in s.items() if k != "perms"} for s in snaps]}

    @w.op("ec2", "DescribeSnapshotAttribute")
    def describe_snapshot_attribute(req: Request):
        sid = req.params["SnapshotId"]
        for s in regional(req, "ec2")["Snapshots"]:
            if s["SnapshotId"] == sid:
                return {"SnapshotId": sid, "CreateVolumePermissions": s["perms"]}
        raise AWSError("InvalidSnapshot.NotFound", f"The snapshot '{sid}' does not exist.", 400)


# ── CloudTrail ───────────────────────────────────────────────────────────────
def _register_cloudtrail(w: World) -> None:
    def all_trails() -> Dict[str, Dict[str, Any]]:
        return {t["Name"]: t for r in REGIONAL.values() for t in r["cloudtrail"]["trails"]}

    @w.op("cloudtrail", "DescribeTrails")
    def describe_trails(req: Request):
        data = regional(req, "cloudtrail")
        trails = list(data["trails"])
        if req.params.get("includeShadowTrails", True):
            # Multi-region trails homed elsewhere appear as shadow trails (F-045).
            for t in all_trails().values():
                if t["IsMultiRegionTrail"] and t["HomeRegion"] != req.region and t not in trails:
                    trails.append(t)
        return {"trailList": trails}

    def trail_for(name: str) -> Dict[str, Any]:
        trails = all_trails()
        for t in trails.values():
            if name in (t["Name"], t["TrailARN"]):
                return t
        raise AWSError("TrailNotFoundException", f"Unknown trail: {name} for the user: {ACCOUNT_ID}", 400)

    @w.op("cloudtrail", "GetTrailStatus")
    def get_trail_status(req: Request):
        trail_for(req.params["Name"])
        return {"IsLogging": True, "LatestDeliveryTime": ts(15, 9), "StartLoggingTime": ts(1),
                "LatestDigestDeliveryTime": ts(15, 9), "TimeLoggingStarted": "2024-01-01T00:00:00Z",
                "TimeLoggingStopped": ""}

    @w.op("cloudtrail", "GetInsightSelectors")
    def get_insight_selectors(req: Request):
        t = trail_for(req.params.get("TrailName", ""))
        return {"TrailARN": t["TrailARN"], "InsightSelectors": [{"InsightType": "ApiCallRateInsight"}]}

    @w.op("cloudtrail", "GetEventSelectors")
    def get_event_selectors(req: Request):
        t = trail_for(req.params["TrailName"])
        return {"TrailARN": t["TrailARN"], "EventSelectors": [
            {"ReadWriteType": "All", "IncludeManagementEvents": True, "DataResources": []}]}


# ── EKS ──────────────────────────────────────────────────────────────────────
def _register_eks(w: World) -> None:
    def cluster(req: Request) -> Dict[str, Any]:
        name = req.params.get("name") or req.params.get("clusterName")
        for c in regional(req, "eks")["clusters"]:
            if c["name"] == name:
                return c
        raise _not_found("ResourceNotFoundException", f"No cluster found for name: {name}.")

    @w.op("eks", "ListClusters")
    def list_clusters(req: Request):
        return {"clusters": [c["name"] for c in regional(req, "eks")["clusters"]]}

    @w.op("eks", "DescribeCluster")
    def describe_cluster(req: Request):
        c = cluster(req)
        return {"cluster": {k: v for k, v in c.items() if k not in _EKS_PRIVATE_KEYS}}

    @w.op("eks", "ListNodegroups")
    def list_nodegroups(req: Request):
        return {"nodegroups": [n["nodegroupName"] for n in cluster(req)["nodegroups"]]}

    @w.op("eks", "DescribeNodegroup")
    def describe_nodegroup(req: Request):
        for n in cluster(req)["nodegroups"]:
            if n["nodegroupName"] == req.params["nodegroupName"]:
                return {"nodegroup": n}
        raise _not_found("ResourceNotFoundException", "No node group found.")

    @w.op("eks", "ListFargateProfiles")
    def list_fargate(req: Request):
        return {"fargateProfileNames": [f["fargateProfileName"] for f in cluster(req)["fargate"] or []]}

    @w.op("eks", "DescribeFargateProfile")
    def describe_fargate(req: Request):
        for f in cluster(req)["fargate"] or []:
            if f["fargateProfileName"] == req.params["fargateProfileName"]:
                return {"fargateProfile": f}
        raise _not_found("ResourceNotFoundException", "No Fargate profile found.")

    @w.op("eks", "ListAddons")
    def list_addons(req: Request):
        return {"addons": [a["addonName"] for a in cluster(req)["addons"]]}

    @w.op("eks", "DescribeAddon")
    def describe_addon(req: Request):
        for a in cluster(req)["addons"]:
            if a["addonName"] == req.params["addonName"]:
                return {"addon": a}
        raise _not_found("ResourceNotFoundException", "No addon found.")

    _register_eks_access(w, cluster)


# ── Secrets Manager / SSM / Lambda / KMS ─────────────────────────────────────
def _register_secrets_ssm_lambda_kms(w: World) -> None:
    @w.op("secretsmanager", "ListSecrets")
    def list_secrets(req: Request):
        include_deleted = bool(req.params.get("IncludePlannedDeletion"))
        return {"SecretList": [{k: v for k, v in s.items() if k != "policy" and not k.startswith("_")}
                               for s in regional(req, "secretsmanager")["secrets"]
                               if include_deleted or not s.get("_planned_deletion")]}

    @w.op("secretsmanager", "GetResourcePolicy")
    def get_resource_policy(req: Request):
        sid = req.params["SecretId"]
        for s in regional(req, "secretsmanager")["secrets"]:
            if sid in (s["ARN"], s["Name"]):
                out = {"ARN": s["ARN"], "Name": s["Name"]}
                if s["policy"]:
                    out["ResourcePolicy"] = World.json_doc(s["policy"])
                return out
        raise _not_found("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")

    @w.op("ssm", "DescribeParameters")
    def describe_parameters(req: Request):
        if req.params.get("Shared"):
            return {"Parameters": regional(req, "ssm").get("shared_parameters", [])}
        return {"Parameters": regional(req, "ssm")["parameters"]}

    def fn_config(req: Request, f: Dict[str, Any]) -> Dict[str, Any]:
        out = {k: v for k, v in f.items() if k not in _LAMBDA_PRIVATE_KEYS}
        out.update({"FunctionArn": lambda_arn(req.region or "", f["FunctionName"]), "CodeSize": 2048,
                    "Description": f"{f['FunctionName']} (acme)", "LastModified": "2024-01-15T10:00:00.000+0000",
                    "CodeSha256": "ZmFrZS1zaGEyNTY=", "Version": "$LATEST", "PackageType": "Zip",
                    "Architectures": ["x86_64"], "TracingConfig": {"Mode": "PassThrough"}})
        return out

    def function(req: Request) -> Dict[str, Any]:
        return lambda_function(req)[0]

    @w.op("lambda", "ListFunctions")
    def list_functions(req: Request):
        return {"Functions": [fn_config(req, f) for f in regional(req, "lambda")["functions"]]}

    @w.op("lambda", "GetFunctionUrlConfig")
    def get_url_config(req: Request):
        f, qualifier = lambda_function(req)
        url = f["url"] if qualifier is None else lambda_alias(f, qualifier).get("url")
        if not isinstance(url, dict):
            raise _not_found("ResourceNotFoundException", "The resource you requested does not exist.")
        return {"FunctionUrl": url["Url"], "FunctionArn": lambda_arn(req.region or "", f["FunctionName"]),
                "AuthType": url["AuthType"], "CreationTime": "2024-01-15T10:00:00.000Z",
                "LastModifiedTime": "2024-01-15T10:00:00.000Z", "InvokeMode": "BUFFERED"}

    @w.op("lambda", "GetPolicy")
    def get_policy(req: Request):
        f, qualifier = lambda_function(req)
        if qualifier is not None:  # an alias (or version) policy, F-055
            alias_policy = lambda_alias(f, qualifier).get("policy")
            if not alias_policy:
                raise _not_found("ResourceNotFoundException", "The resource you requested does not exist.")
            return {"Policy": World.json_doc(alias_policy), "RevisionId": "00000000-rev1-4000-8000-0000000000e2"}
        if not f["policy"]:
            raise _not_found("ResourceNotFoundException", "The resource you requested does not exist.")
        return {"Policy": World.json_doc(f["policy"]), "RevisionId": "00000000-rev0-4000-8000-0000000000e1"}

    def key(req: Request) -> Dict[str, Any]:
        kid = req.params["KeyId"]
        for k in regional(req, "kms")["keys"]:
            if kid in (k["KeyId"], kms_arn(req.region or "", k["KeyId"])):
                return k
        raise _not_found("NotFoundException", f"Key '{kid}' does not exist")

    @w.op("kms", "ListKeys")
    def list_keys(req: Request):
        return {"Keys": [{"KeyId": k["KeyId"], "KeyArn": kms_arn(req.region or "", k["KeyId"])}
                         for k in regional(req, "kms")["keys"]], "Truncated": False}

    @w.op("kms", "ListAliases")
    def list_aliases(req: Request):
        out = []
        for a in regional(req, "kms")["aliases"]:
            item = {"AliasName": a["AliasName"],
                    "AliasArn": f"arn:aws:kms:{req.region}:{ACCOUNT_ID}:{a['AliasName']}"}
            if a.get("TargetKeyId"):
                item.update(TargetKeyId=a["TargetKeyId"], CreationDate=ts(2), LastUpdatedDate=ts(2))
            out.append(item)
        return {"Aliases": out, "Truncated": False}

    @w.op("kms", "DescribeKey")
    def describe_key(req: Request):
        k = key(req)
        return {"KeyMetadata": {"AWSAccountId": ACCOUNT_ID, "KeyId": k["KeyId"],
                                "Arn": kms_arn(req.region or "", k["KeyId"]), "CreationDate": ts(1),
                                "Enabled": k["Enabled"], "Description": k["Description"],
                                "KeyUsage": "ENCRYPT_DECRYPT", "KeyState": k["KeyState"], "Origin": "AWS_KMS",
                                "KeyManager": k["KeyManager"], "CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
                                "KeySpec": "SYMMETRIC_DEFAULT", "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
                                "MultiRegion": False}}

    @w.op("kms", "GetKeyPolicy")
    def get_key_policy(req: Request):
        k = key(req)
        policy = k["policy"] or _doc({"Sid": "Root", "Effect": "Allow",
                                      "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
                                      "Action": "kms:*", "Resource": "*"})
        return {"Policy": json.dumps(policy, indent=2), "PolicyName": req.params.get("PolicyName", "default")}

    @w.op("kms", "ListGrants")
    def list_grants(req: Request):
        k = key(req)
        return {"Grants": [dict(g, KeyId=kms_arn(req.region or "", k["KeyId"]), CreationDate=ts(3),
                                IssuingAccount=f"arn:aws:iam::{ACCOUNT_ID}:root") for g in k["grants"]],
                "Truncated": False}


# ── ECS / CloudFormation / Glue / CodeBuild / SageMaker ──────────────────────
def _register_compute(w: World) -> None:
    def td_arn(region: str, td: Dict[str, Any]) -> str:
        return f"arn:aws:ecs:{region}:{ACCOUNT_ID}:task-definition/{td['family']}:{td['revision']}"

    @w.op("ecs", "ListTaskDefinitions")
    def list_task_definitions(req: Request):
        tds = list(regional(req, "ecs")["task_definitions"])
        prefix = req.params.get("familyPrefix")
        if prefix:
            tds = [t for t in tds if t["family"] == prefix]
        if req.params.get("status", "ACTIVE") != "ACTIVE":
            tds = []  # acme has no INACTIVE revisions
        if req.params.get("sort") == "DESC":
            tds = sorted(tds, key=lambda t: (t["family"], -t["revision"]))
        elif req.params.get("sort") == "ASC":
            tds = sorted(tds, key=lambda t: (t["family"], t["revision"]))
        return {"taskDefinitionArns": [td_arn(req.region or "", t) for t in tds]}

    @w.op("ecs", "DescribeTaskDefinition")
    def describe_task_definition(req: Request):
        wanted = req.params["taskDefinition"]
        for t in regional(req, "ecs")["task_definitions"]:
            arn = td_arn(req.region or "", t)
            if wanted in (arn, f"{t['family']}:{t['revision']}"):
                out = {"taskDefinitionArn": arn, "family": t["family"], "revision": t["revision"],
                       "status": "ACTIVE", "networkMode": "awsvpc", "requiresCompatibilities": ["FARGATE"],
                       "cpu": "256", "memory": "512",
                       "containerDefinitions": [{"name": t["family"], "essential": True,
                                                 "image": f"{ACCOUNT_ID}.dkr.ecr.{req.region}.amazonaws.com/"
                                                          f"{t['family']}:latest",
                                                 "environment": t["env"]}]}
                if t["taskRoleArn"]:
                    out["taskRoleArn"] = t["taskRoleArn"]
                if t["executionRoleArn"]:
                    out["executionRoleArn"] = t["executionRoleArn"]
                return {"taskDefinition": out, "tags": []}
        raise AWSError("ClientException", "Unable to describe task definition.", 400)

    @w.op("cloudformation", "DescribeStacks")
    def describe_stacks(req: Request):
        out = []
        for s in regional(req, "cloudformation")["stacks"]:
            stack = {"StackId": f"arn:aws:cloudformation:{req.region}:{ACCOUNT_ID}:stack/{s['StackName']}/"
                                f"00000000-0000-4000-8000-0000000000f1",
                     "StackName": s["StackName"], "Description": f"{s['StackName']} (acme)",
                     "Parameters": s["Parameters"], "CreationTime": ts(2), "LastUpdatedTime": ts(9),
                     "StackStatus": s["StackStatus"], "DisableRollback": False,
                     "Capabilities": ["CAPABILITY_NAMED_IAM"], "Outputs": s["Outputs"], "Tags": _tags(env="demo"),
                     "EnableTerminationProtection": False,
                     "DriftInformation": {"StackDriftStatus": "NOT_CHECKED"}}
            if s["RoleARN"]:
                stack["RoleARN"] = s["RoleARN"]
            out.append(stack)
        return {"Stacks": out}

    @w.op("glue", "GetJobs")
    def get_jobs(req: Request):
        return {"Jobs": [{"Name": j["Name"], "Role": j["Role"], "CreatedOn": ts(3), "LastModifiedOn": ts(9),
                          "Command": {"Name": "glueetl", "ScriptLocation": f"s3://demo-data-bucket/{j['Name']}.py",
                                      "PythonVersion": "3"},
                          "DefaultArguments": j["DefaultArguments"], "MaxRetries": 0, "Timeout": 60,
                          "GlueVersion": "4.0"} for j in regional(req, "glue")["jobs"]]}

    @w.op("glue", "GetDevEndpoints")
    def get_dev_endpoints(req: Request):
        return {"DevEndpoints": regional(req, "glue")["dev_endpoints"]}

    @w.op("codebuild", "ListProjects")
    def list_projects(req: Request):
        return {"projects": [p["name"] for p in regional(req, "codebuild")["projects"]]}

    @w.op("codebuild", "BatchGetProjects")
    def batch_get_projects(req: Request):
        projects = {p["name"]: p for p in regional(req, "codebuild")["projects"]}
        found, missing = [], []
        for name in req.params["names"]:
            p = projects.get(name)
            if p is None:
                missing.append(name)
                continue
            found.append({
                "name": name, "arn": f"arn:aws:codebuild:{req.region}:{ACCOUNT_ID}:project/{name}",
                "description": f"{name} (acme)",
                "source": {"type": "GITHUB", "location": p["source_location"]},
                "artifacts": {"type": "NO_ARTIFACTS"},
                "environment": {"type": "LINUX_CONTAINER", "image": "aws/codebuild/standard:7.0",
                                "computeType": "BUILD_GENERAL1_SMALL", "environmentVariables": p["env"],
                                "privilegedMode": False},
                "serviceRole": p["serviceRole"], "created": ts(2), "lastModified": ts(9)})
        out: Dict[str, Any] = {"projects": found}
        if missing:
            out["projectsNotFound"] = missing
        return out

    @w.op("sagemaker", "ListNotebookInstances")
    def list_notebooks(req: Request):
        return {"NotebookInstances": [
            {"NotebookInstanceName": n["NotebookInstanceName"],
             "NotebookInstanceArn": f"arn:aws:sagemaker:{req.region}:{ACCOUNT_ID}:notebook-instance/"
                                    f"{n['NotebookInstanceName']}",
             "NotebookInstanceStatus": "InService", "InstanceType": "ml.t3.medium", "CreationTime": ts(4),
             "LastModifiedTime": ts(9)} for n in regional(req, "sagemaker")["notebooks"]]}

    @w.op("sagemaker", "DescribeNotebookInstance")
    def describe_notebook(req: Request):
        for n in regional(req, "sagemaker")["notebooks"]:
            if n["NotebookInstanceName"] == req.params["NotebookInstanceName"]:
                return {"NotebookInstanceArn": f"arn:aws:sagemaker:{req.region}:{ACCOUNT_ID}:notebook-instance/"
                                               f"{n['NotebookInstanceName']}",
                        "NotebookInstanceName": n["NotebookInstanceName"], "NotebookInstanceStatus": "InService",
                        "InstanceType": "ml.t3.medium", "RoleArn": n["RoleArn"],
                        "DirectInternetAccess": n["DirectInternetAccess"], "RootAccess": n["RootAccess"],
                        "VolumeSizeInGB": 5, "CreationTime": ts(4), "LastModifiedTime": ts(9)}
        raise AWSError("ValidationException", "RecordNotFound", 400)


# ── SNS / SQS / ECR / RDS / DynamoDB ─────────────────────────────────────────
def _register_messaging_data(w: World) -> None:
    def topic_arn(req: Request, name: str) -> str:
        return f"arn:aws:sns:{req.region}:{ACCOUNT_ID}:{name}"

    @w.op("sns", "ListTopics")
    def list_topics(req: Request):
        return {"Topics": [{"TopicArn": topic_arn(req, t["Name"])} for t in regional(req, "sns")["topics"]]}

    @w.op("sns", "GetTopicAttributes")
    def get_topic_attributes(req: Request):
        for t in regional(req, "sns")["topics"]:
            arn = topic_arn(req, t["Name"])
            if arn == req.params["TopicArn"]:
                attrs = {"TopicArn": arn, "Owner": ACCOUNT_ID, "DisplayName": t["Name"],
                         "SubscriptionsConfirmed": "1", "SubscriptionsPending": "0"}
                if t["policy"]:
                    attrs["Policy"] = World.json_doc(t["policy"])
                return {"Attributes": attrs}
        raise _not_found("NotFound", "Topic does not exist")

    def queue_url(req: Request, name: str) -> str:
        return f"https://sqs.{req.region}.amazonaws.com/{ACCOUNT_ID}/{name}"

    @w.op("sqs", "ListQueues")
    def list_queues(req: Request):
        return {"QueueUrls": [queue_url(req, q["Name"]) for q in regional(req, "sqs")["queues"]]}

    @w.op("sqs", "GetQueueAttributes")
    def get_queue_attributes(req: Request):
        for q in regional(req, "sqs")["queues"]:
            if queue_url(req, q["Name"]) == req.params["QueueUrl"]:
                names = set(req.params.get("AttributeNames") or [])
                attrs = {"QueueArn": f"arn:aws:sqs:{req.region}:{ACCOUNT_ID}:{q['Name']}"}
                if q["policy"]:
                    attrs["Policy"] = World.json_doc(q["policy"])
                if "All" not in names:
                    attrs = {k: v for k, v in attrs.items() if k in names}
                return {"Attributes": attrs}
        raise AWSError("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist.", 400)

    @w.op("ecr", "DescribeRepositories")
    def describe_repositories(req: Request):
        return {"repositories": [
            {"repositoryArn": f"arn:aws:ecr:{req.region}:{ACCOUNT_ID}:repository/{r['repositoryName']}",
             "registryId": ACCOUNT_ID, "repositoryName": r["repositoryName"],
             "repositoryUri": f"{ACCOUNT_ID}.dkr.ecr.{req.region}.amazonaws.com/{r['repositoryName']}",
             "createdAt": ts(3), "imageTagMutability": "MUTABLE",
             "imageScanningConfiguration": {"scanOnPush": False},
             "encryptionConfiguration": {"encryptionType": "AES256"}} for r in regional(req, "ecr")["repositories"]]}

    @w.op("ecr", "GetRepositoryPolicy")
    def get_repository_policy(req: Request):
        for r in regional(req, "ecr")["repositories"]:
            if r["repositoryName"] == req.params["repositoryName"]:
                if not r["policy"]:
                    raise AWSError("RepositoryPolicyNotFoundException",
                                   "Repository policy does not exist for the repository with name "
                                   f"'{r['repositoryName']}' in the registry with id '{ACCOUNT_ID}'", 400)
                return {"registryId": ACCOUNT_ID, "repositoryName": r["repositoryName"],
                        "policyText": json.dumps(r["policy"], indent=2)}
        raise AWSError("RepositoryNotFoundException", "repository does not exist", 400)

    @w.op("rds", "DescribeDBInstances")
    def describe_db_instances(req: Request):
        out = []
        for d in regional(req, "rds")["instances"]:
            item = {"DBInstanceIdentifier": d["DBInstanceIdentifier"], "DBInstanceClass": "db.t3.micro",
                    "Engine": d["Engine"], "DBInstanceStatus": "available",
                    "Endpoint": {"Address": f"{d['DBInstanceIdentifier']}.abcdefghij.{req.region}.rds.amazonaws.com",
                                 "Port": 5432},
                    "PubliclyAccessible": d["PubliclyAccessible"], "StorageEncrypted": d["StorageEncrypted"],
                    "DBInstanceArn": f"arn:aws:rds:{req.region}:{ACCOUNT_ID}:db:{d['DBInstanceIdentifier']}",
                    "IAMDatabaseAuthenticationEnabled": d["IAMDatabaseAuthenticationEnabled"],
                    "InstanceCreateTime": ts(2)}
            if d.get("KmsKeyId"):
                item["KmsKeyId"] = d["KmsKeyId"]
            out.append(item)
        return {"DBInstances": out}

    @w.op("rds", "DescribeDBSnapshots")
    def describe_db_snapshots(req: Request):
        stype = req.params.get("SnapshotType")
        out = []
        for s in regional(req, "rds")["snapshots"]:
            if stype and s["SnapshotType"] != stype:
                continue
            item = {"DBSnapshotIdentifier": s["DBSnapshotIdentifier"],
                    "DBInstanceIdentifier": s["DBInstanceIdentifier"], "SnapshotCreateTime": ts(8),
                    "Engine": "postgres", "SnapshotType": s["SnapshotType"], "Encrypted": s["Encrypted"],
                    "DBSnapshotArn": f"arn:aws:rds:{req.region}:{ACCOUNT_ID}:snapshot:{s['DBSnapshotIdentifier']}",
                    "Status": "available"}
            if s.get("KmsKeyId"):
                item["KmsKeyId"] = s["KmsKeyId"]
            out.append(item)
        return {"DBSnapshots": out}

    @w.op("rds", "DescribeDBSnapshotAttributes")
    def describe_db_snapshot_attributes(req: Request):
        sid = req.params["DBSnapshotIdentifier"]
        for s in regional(req, "rds")["snapshots"]:
            if s["DBSnapshotIdentifier"] == sid:
                return {"DBSnapshotAttributesResult": {"DBSnapshotIdentifier": sid, "DBSnapshotAttributes": [
                    {"AttributeName": "restore", "AttributeValues": list(s["restore"] or [])}]}}
        raise _not_found("DBSnapshotNotFound", f"DBSnapshot {sid} not found.")

    def table_arn(req: Request, name: str) -> str:
        return f"arn:aws:dynamodb:{req.region}:{ACCOUNT_ID}:table/{name}"

    @w.op("dynamodb", "ListTables")
    def list_tables(req: Request):
        return {"TableNames": [t["TableName"] for t in regional(req, "dynamodb")["tables"]]}

    @w.op("dynamodb", "DescribeTable")
    def describe_table(req: Request):
        for t in regional(req, "dynamodb")["tables"]:
            if t["TableName"] == req.params["TableName"]:
                return {"Table": {"TableName": t["TableName"], "TableArn": table_arn(req, t["TableName"]),
                                  "TableStatus": "ACTIVE", "CreationDateTime": ts(2), "ItemCount": 0,
                                  "TableSizeBytes": 0,
                                  "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                                  "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                                  "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"}}}
        raise AWSError("ResourceNotFoundException", "Requested resource not found", 400)

    @w.op("dynamodb", "GetResourcePolicy")
    def get_resource_policy(req: Request):
        for t in regional(req, "dynamodb")["tables"]:
            if table_arn(req, t["TableName"]) == req.params["ResourceArn"]:
                if not t["policy"]:
                    raise AWSError("PolicyNotFoundException",
                                   f"Resource-based policy not found for the provided ResourceArn: "
                                   f"{req.params['ResourceArn']}", 400)
                return {"Policy": World.json_doc(t["policy"]), "RevisionId": "1705312800000"}
        raise AWSError("ResourceNotFoundException", "Requested resource not found", 400)


# ── API Gateway / Cognito / ELB ──────────────────────────────────────────────
def _register_apigw_cognito_elb(w: World) -> None:
    def rest_api(req: Request) -> Dict[str, Any]:
        for a in regional(req, "apigateway")["rest_apis"]:
            if a["id"] == req.params["restApiId"]:
                return a
        raise _not_found("NotFoundException", "Invalid API identifier specified")

    @w.op("apigateway", "GetRestApis")
    def get_rest_apis(req: Request):
        return {"items": [{"id": a["id"], "name": a["name"], "createdDate": ts(3),
                           "endpointConfiguration": {"types": ["REGIONAL"]}}
                          for a in regional(req, "apigateway")["rest_apis"]]}

    @w.op("apigateway", "GetResources")
    def get_resources(req: Request):
        embed = "methods" in (req.params.get("embed") or [])
        items = []
        for res in rest_api(req)["resources"]:
            item = {k: v for k, v in res.items() if k not in ("methods", "auth")}
            if res.get("methods"):
                methods = {}
                for m, integ in res["methods"].items():
                    auth_type, authorizer = (res.get("auth") or {}).get(m, ("NONE", None))
                    method: Dict[str, Any] = {"httpMethod": m, "authorizationType": auth_type, "apiKeyRequired": False}
                    if authorizer:
                        method["authorizerId"] = authorizer
                    if embed and integ:
                        method["methodIntegration"] = dict(integ)
                    methods[m] = method
                item["resourceMethods"] = methods
            items.append(item)
        return {"items": items}

    @w.op("apigateway", "GetIntegration")
    def get_integration(req: Request):
        for res in rest_api(req)["resources"]:
            if res["id"] == req.params["resourceId"]:
                integ = (res.get("methods") or {}).get(req.params["httpMethod"])
                if integ:
                    return dict(integ)
        raise _not_found("NotFoundException", "Invalid Integration identifier specified")

    @w.op("apigateway", "GetAuthorizers")
    def get_authorizers_v1(req: Request):
        return {"items": rest_api(req)["authorizers"]}

    def http_api(req: Request) -> Dict[str, Any]:
        for a in regional(req, "apigateway")["http_apis"]:
            if a["ApiId"] == req.params["ApiId"]:
                return a
        raise _not_found("NotFoundException", "Invalid API identifier specified")

    @w.op("apigatewayv2", "GetApis")
    def get_apis(req: Request):
        return {"Items": [{"ApiId": a["ApiId"], "Name": a["Name"], "ProtocolType": a["ProtocolType"],
                           "RouteSelectionExpression": "$request.method $request.path",
                           "ApiEndpoint": f"https://{a['ApiId']}.execute-api.{req.region}.amazonaws.com",
                           "CreatedDate": ts(3)} for a in regional(req, "apigateway")["http_apis"]]}

    @w.op("apigatewayv2", "GetIntegrations")
    def get_integrations(req: Request):
        return {"Items": http_api(req)["integrations"]}

    @w.op("apigatewayv2", "GetAuthorizers")
    def get_authorizers_v2(req: Request):
        return {"Items": http_api(req)["authorizers"]}

    def identity_pool(req: Request) -> Dict[str, Any]:
        for p in regional(req, "cognito")["identity_pools"]:
            if p["IdentityPoolId"] == req.params["IdentityPoolId"]:
                return p
        raise _not_found("ResourceNotFoundException", "IdentityPool not found")

    @w.op("cognito-identity", "ListIdentityPools")
    def list_identity_pools(req: Request):
        return {"IdentityPools": [{"IdentityPoolId": p["IdentityPoolId"], "IdentityPoolName": p["IdentityPoolName"]}
                                  for p in regional(req, "cognito")["identity_pools"]]}

    @w.op("cognito-identity", "GetIdentityPoolRoles")
    def get_identity_pool_roles(req: Request):
        p = identity_pool(req)
        return {"IdentityPoolId": p["IdentityPoolId"], "Roles": dict(p["roles"] or {})}

    @w.op("cognito-identity", "DescribeIdentityPool")
    def describe_identity_pool(req: Request):
        p = identity_pool(req)
        return {"IdentityPoolId": p["IdentityPoolId"], "IdentityPoolName": p["IdentityPoolName"],
                "AllowUnauthenticatedIdentities": p["AllowUnauthenticatedIdentities"], "AllowClassicFlow": True}

    @w.op("cognito-idp", "ListUserPools")
    def list_user_pools(req: Request):
        return {"UserPools": [{"Id": u["Id"], "Name": u["Name"], "Status": "Enabled", "CreationDate": ts(2),
                               "LastModifiedDate": ts(9)} for u in regional(req, "cognito")["user_pools"]]}

    def lb_by_arn(req: Request, arn: str) -> Dict[str, Any]:
        for lb in regional(req, "elb")["v2"]:
            if lb["LoadBalancerArn"] == arn:
                return lb
        raise AWSError("LoadBalancerNotFound", "One or more load balancers not found", 400)

    def tg_arn(req: Request, tg: Dict[str, Any]) -> str:
        return (f"arn:aws:elasticloadbalancing:{req.region}:{ACCOUNT_ID}:targetgroup/"
                f"{tg['TargetGroupName']}/0123456789abcdef")

    @w.op("elbv2", "DescribeLoadBalancers")
    def describe_lbs_v2(req: Request):
        return {"LoadBalancers": [
            {"LoadBalancerArn": lb["LoadBalancerArn"], "DNSName": lb["DNSName"],
             "CanonicalHostedZoneId": "ZHURV8PSTC4K8", "CreatedTime": ts(3),
             "LoadBalancerName": lb["LoadBalancerName"], "Scheme": lb["Scheme"], "VpcId": lb["VpcId"],
             "State": {"Code": "active"}, "Type": lb["Type"], "IpAddressType": "ipv4",
             **({"SecurityGroups": lb["SecurityGroups"]} if lb.get("SecurityGroups") else {})}
            for lb in regional(req, "elb")["v2"]]}

    @w.op("elbv2", "DescribeTargetGroups")
    def describe_target_groups(req: Request):
        lb = lb_by_arn(req, req.params["LoadBalancerArn"])
        out = []
        for tg in lb["target_groups"]:
            item = {"TargetGroupArn": tg_arn(req, tg), "TargetGroupName": tg["TargetGroupName"],
                    "TargetType": tg["TargetType"], "LoadBalancerArns": [lb["LoadBalancerArn"]]}
            if tg.get("Protocol"):
                item.update(Protocol=tg["Protocol"], Port=tg["Port"], VpcId=lb["VpcId"])
            out.append(item)
        return {"TargetGroups": out}

    @w.op("elbv2", "DescribeTargetHealth")
    def describe_target_health(req: Request):
        for lb in regional(req, "elb")["v2"]:
            for tg in lb["target_groups"]:
                if tg_arn(req, tg) == req.params["TargetGroupArn"]:
                    return {"TargetHealthDescriptions": [
                        {"Target": {"Id": t}, "TargetHealth": {"State": "healthy"}} for t in tg["targets"]]}
        raise AWSError("TargetGroupNotFound", "One or more target groups not found", 400)

    @w.op("elb", "DescribeLoadBalancers")
    def describe_lbs_classic(req: Request):
        return {"LoadBalancerDescriptions": [
            dict(lb, CreatedTime=ts(3), VPCId="vpc-0dec000000000002", ListenerDescriptions=[])
            for lb in regional(req, "elb")["classic"]]}


# ── Wave 1 operations (collectors-cli.md §5) ─────────────────────────────────
def _register_wave1(w: World) -> None:
    """Operations the migrated collectors call. The baseline collectors call none of them."""
    _register_wave1_iam(w)
    _register_wave1_s3(w)
    _register_wave1_ec2(w)
    _register_wave1_services(w)
    _register_wave1_compute(w)
    _register_wave1_data(w)
    _register_wave1_edge(w)
    _register_wave1_posture(w)


def _token(op: str, offset: int) -> str:
    return f"fakeaws-{op}-{offset}"


def _offset(token: Optional[str], op: str) -> int:
    if not token:
        return 0
    prefix = f"fakeaws-{op}-"
    if not token.startswith(prefix):
        raise AWSError("InvalidInput", f"invalid pagination token for {op}", 400)
    return int(token[len(prefix):])


def _gaad_inline(policies: Dict[str, Any]) -> List[Dict[str, str]]:
    return [{"PolicyName": n, "PolicyDocument": World.iam_doc(d)} for n, d in sorted(policies.items())]


def _boundary(arn: Optional[str]) -> Dict[str, Any]:
    return {"PermissionsBoundary": {"PermissionsBoundaryType": "PermissionsBoundaryPolicy",
                                    "PermissionsBoundaryArn": arn}} if arn else {}


def _gaad_entities(filters: Optional[List[str]]) -> List[Tuple[str, Dict[str, Any]]]:
    """GetAccountAuthorizationDetails items in API order: users, groups, roles, then policies."""
    wanted = set(filters or ["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"])
    roles_by_name = _by(ROLES, "RoleName")
    out: List[Tuple[str, Dict[str, Any]]] = []
    if "User" in wanted:
        for u in USERS:
            extra = IAM_USER_EXTRAS.get(u["UserName"], {})
            user = {k: v for k, v in _iam_user(u).items() if k != "PasswordLastUsed"}  # not in GAAD's UserDetail
            out.append(("UserDetailList", dict(
                user, UserPolicyList=_gaad_inline(u["inline"]), GroupList=list(u["groups"]),
                AttachedManagedPolicies=_attached(u["attached"]), Tags=list(extra.get("tags", [])),
                **_boundary(extra.get("boundary")))))
    if "Group" in wanted:
        for g in GROUPS:
            out.append(("GroupDetailList", dict(_iam_group(g), GroupPolicyList=_gaad_inline(g["inline"]),
                                                AttachedManagedPolicies=_attached(g["attached"]))))
    if "Role" in wanted:
        for r in ROLES:
            extra = IAM_ROLE_EXTRAS.get(r["RoleName"], {})
            profiles = [{"Path": "/", "InstanceProfileName": name, "InstanceProfileId": pid,
                         "Arn": iam_arn("instance-profile", name), "CreateDate": ts(2),
                         "Roles": [_iam_role(roles_by_name[rname])]}
                        for name, pid, rname in INSTANCE_PROFILES if rname == r["RoleName"]]
            role = {k: v for k, v in _iam_role(r).items() if k not in ("Description", "MaxSessionDuration")}
            out.append(("RoleDetailList", dict(
                role, InstanceProfileList=profiles, RolePolicyList=_gaad_inline(r["inline"]),
                AttachedManagedPolicies=_attached(r["attached"]), Tags=list(extra.get("tags", [])),
                RoleLastUsed=dict(extra.get("last_used", {})), **_boundary(extra.get("boundary")))))
    if "LocalManagedPolicy" in wanted:
        for name, p in sorted(CUSTOMER_POLICIES.items()):
            out.append(("Policies", {
                "PolicyName": name, "PolicyId": p["id"], "Arn": policy_arn(name), "Path": "/",
                "DefaultVersionId": p["default"], "AttachmentCount": p["attachments"],
                "PermissionsBoundaryUsageCount": 1 if name == "demo-app-policy" else 0, "IsAttachable": True,
                "CreateDate": ts(1), "UpdateDate": ts(9),
                "PolicyVersionList": [{"Document": World.iam_doc(doc), "VersionId": vid,
                                       "IsDefaultVersion": vid == p["default"], "CreateDate": ts(9)}
                                      for vid, doc in sorted(p["versions"].items())]}))
    if "AWSManagedPolicy" in wanted:
        for name, m in sorted(AWS_MANAGED.items()):  # GAAD returns AWS managed policies in use only
            out.append(("Policies", {
                "PolicyName": name, "PolicyId": m["id"], "Arn": managed_arn(name), "Path": "/",
                "DefaultVersionId": m["version"], "AttachmentCount": 1,
                "PermissionsBoundaryUsageCount": 1 if name == "ReadOnlyAccess" else 0, "IsAttachable": True,
                "CreateDate": ts(1), "UpdateDate": ts(9),
                "PolicyVersionList": [{"Document": World.iam_doc(m["doc"]), "VersionId": m["version"],
                                       "IsDefaultVersion": True, "CreateDate": ts(9)}]}))
    return out


def _credential_report_csv() -> bytes:
    cols = ["user", "arn", "user_creation_time", "password_enabled", "password_last_used", "password_last_changed",
            "password_next_rotation", "mfa_active", "access_key_1_active", "access_key_1_last_rotated",
            "access_key_1_last_used_date", "access_key_1_last_used_region", "access_key_1_last_used_service",
            "access_key_2_active", "access_key_2_last_rotated", "access_key_2_last_used_date",
            "access_key_2_last_used_region", "access_key_2_last_used_service", "cert_1_active",
            "cert_1_last_rotated", "cert_2_active", "cert_2_last_rotated"]
    iso = "%Y-%m-%dT%H:%M:%S+00:00"
    rows = [{"user": "<root_account>", "arn": f"arn:aws:iam::{ACCOUNT_ID}:root",
             "user_creation_time": ts(1).strftime(iso), "password_enabled": "not_supported",
             "password_last_used": ts(5).strftime(iso), "password_last_changed": "not_supported",
             "password_next_rotation": "not_supported", "mfa_active": "true"}]
    for u in USERS:
        keys = u["keys"]
        row = {"user": u["UserName"], "arn": iam_arn("user", u["UserName"]),
               "user_creation_time": u["CreateDate"].strftime(iso),
               "password_enabled": "true" if u["login"] else "false",
               "password_last_used": u["PasswordLastUsed"].strftime(iso) if u.get("PasswordLastUsed") else "N/A",
               "password_last_changed": u["login"].strftime(iso) if u["login"] else "N/A",
               "password_next_rotation": "N/A", "mfa_active": "true" if u["mfa"] else "false"}
        for i in (1, 2):
            k = keys[i - 1] if len(keys) >= i else None
            row[f"access_key_{i}_active"] = "true" if k and k[1] == "Active" else "false"
            row[f"access_key_{i}_last_rotated"] = k[2].strftime(iso) if k else "N/A"
            row[f"access_key_{i}_last_used_date"] = ts(14).strftime(iso) if k and k[1] == "Active" else "N/A"
            row[f"access_key_{i}_last_used_region"] = "eu-west-2" if k and k[1] == "Active" else "N/A"
            row[f"access_key_{i}_last_used_service"] = "s3" if k and k[1] == "Active" else "N/A"
        row["cert_1_active"] = "true" if IAM_USER_EXTRAS.get(u["UserName"], {}).get("signing_certificates") else "false"
        rows.append(row)
    lines = [",".join(cols)]
    for row in rows:
        lines.append(",".join(row.get(c, "N/A" if not c.startswith(("access_key", "cert")) or not c.endswith(
            "_active") else "false") for c in cols))
    return ("\n".join(lines)).encode("utf-8")


def _register_wave1_iam(w: World) -> None:  # noqa: C901 - one handler per operation
    users, roles = _by(USERS, "UserName"), _by(ROLES, "RoleName")

    def no_such(kind: str, name: str) -> AWSError:
        return _not_found("NoSuchEntity", f"The {kind} with name {name} cannot be found.")

    @w.op("iam", "GetAccountAuthorizationDetails")
    def gaad(req: Request):
        op = "GetAccountAuthorizationDetails"
        entities = _gaad_entities(req.params.get("Filter"))
        size = req.world.page_sizes.get(("iam", op)) or req.params.get("MaxItems") or 100
        size = min(int(size), int(req.params.get("MaxItems") or size))
        start = _offset(req.params.get("Marker"), op)
        chunk = entities[start:start + size]
        out: Dict[str, Any] = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
        for key, item in chunk:
            out[key].append(item)
        more = start + size < len(entities)
        out["IsTruncated"] = more
        if more:
            out["Marker"] = _token(op, start + size)
        return out

    @w.op("iam", "GetUser")
    def get_user(req: Request):
        name = req.params.get("UserName") or "demo-alice"
        if name not in users:
            raise no_such("user", name)
        extra = IAM_USER_EXTRAS.get(name, {})
        user = dict(_iam_user(users[name]), **_boundary(extra.get("boundary")))
        if extra.get("tags"):
            user["Tags"] = list(extra["tags"])
        return {"User": user}

    @w.op("iam", "GetRole")
    def get_role(req: Request):
        name = req.params["RoleName"]
        if name not in roles:
            raise no_such("role", name)
        extra = IAM_ROLE_EXTRAS.get(name, {})
        role = dict(_iam_role(roles[name]), RoleLastUsed=dict(extra.get("last_used", {})),
                    **_boundary(extra.get("boundary")))
        if extra.get("tags"):
            role["Tags"] = list(extra["tags"])
        return {"Role": role}

    @w.op("iam", "ListUserTags")
    def list_user_tags(req: Request):
        if req.params["UserName"] not in users:
            raise no_such("user", req.params["UserName"])
        return {"Tags": list(IAM_USER_EXTRAS.get(req.params["UserName"], {}).get("tags", [])), "IsTruncated": False}

    @w.op("iam", "ListRoleTags")
    def list_role_tags(req: Request):
        if req.params["RoleName"] not in roles:
            raise no_such("role", req.params["RoleName"])
        return {"Tags": list(IAM_ROLE_EXTRAS.get(req.params["RoleName"], {}).get("tags", [])), "IsTruncated": False}

    @w.op("iam", "ListPolicyVersions")
    def list_policy_versions(req: Request):
        arn = req.params["PolicyArn"]
        if arn.startswith("arn:aws:iam::aws:policy/") and arn.rsplit("/", 1)[-1] in AWS_MANAGED:
            m = AWS_MANAGED[arn.rsplit("/", 1)[-1]]
            versions = [(m["version"], True)]
        elif arn.startswith(f"arn:aws:iam::{ACCOUNT_ID}:policy/") and arn.rsplit("/", 1)[-1] in CUSTOMER_POLICIES:
            p = CUSTOMER_POLICIES[arn.rsplit("/", 1)[-1]]
            versions = [(v, v == p["default"]) for v in sorted(p["versions"])]
        else:
            raise _not_found("NoSuchEntity", f"Policy {arn} does not exist or is not attachable.")
        return {"Versions": [{"VersionId": v, "IsDefaultVersion": d, "CreateDate": ts(9)} for v, d in versions],
                "IsTruncated": False}

    @w.op("iam", "GenerateCredentialReport")
    def generate_credential_report(req: Request):
        # STARTED on the first call, COMPLETE once polled `credential_report_polls` more times (default 1).
        meta = req.world.meta
        calls = meta["credential_report_calls"] = meta.get("credential_report_calls", 0) + 1
        done = calls > int(meta.get("credential_report_polls", 1))
        meta["credential_report_state"] = "COMPLETE" if done else "STARTED"
        return {"State": "COMPLETE" if done else ("STARTED" if calls == 1 else "INPROGRESS"),
                "Description": "No report exists. Starting a new report generation task" if calls == 1 else ""}

    @w.op("iam", "GetCredentialReport")
    def get_credential_report(req: Request):
        state = req.world.meta.get("credential_report_state")
        if state is None:
            raise AWSError("ReportNotPresent", "Credential report not present.", 410)
        if state != "COMPLETE":
            raise AWSError("ReportInProgress", "Credential report generation in progress.", 404)
        return {"Content": _credential_report_csv(), "ReportFormat": "text/csv", "GeneratedTime": ts(15, 9)}

    @w.op("iam", "ListVirtualMFADevices")
    def list_virtual_mfa(req: Request):
        status = req.params.get("AssignmentStatus", "Any")
        devices = []
        if status in ("Assigned", "Any"):
            for u in USERS:
                for serial in u["mfa"]:
                    devices.append({"SerialNumber": serial, "User": _iam_user(u), "EnableDate": ts(3)})
        if status in ("Unassigned", "Any"):
            devices.append({"SerialNumber": VIRTUAL_MFA_SPARE})
        return {"VirtualMFADevices": devices, "IsTruncated": False}

    @w.op("iam", "ListOpenIDConnectProviders")
    def list_oidc(req: Request):
        return {"OpenIDConnectProviderList": [{"Arn": p["Arn"]} for p in OIDC_PROVIDERS]}

    @w.op("iam", "GetOpenIDConnectProvider")
    def get_oidc(req: Request):
        for p in OIDC_PROVIDERS:
            if p["Arn"] == req.params["OpenIDConnectProviderArn"]:
                return {k: v for k, v in p.items() if k != "Arn"}
        raise _not_found("NoSuchEntity", f"OpenIDConnect Provider not found for arn "
                                         f"{req.params['OpenIDConnectProviderArn']}")

    @w.op("iam", "ListSAMLProviders")
    def list_saml(req: Request):
        return {"SAMLProviderList": [dict(p) for p in SAML_PROVIDERS]}

    def user_name(req: Request) -> str:
        name = req.params.get("UserName") or "demo-alice"
        if name not in users:
            raise no_such("user", name)
        return name

    @w.op("iam", "ListSSHPublicKeys")
    def list_ssh_keys(req: Request):
        name = user_name(req)
        return {"SSHPublicKeys": [{"UserName": name, "SSHPublicKeyId": kid, "Status": st, "UploadDate": ts(4)}
                                  for kid, st in IAM_USER_EXTRAS.get(name, {}).get("ssh_keys", [])],
                "IsTruncated": False}

    @w.op("iam", "ListServiceSpecificCredentials")
    def list_service_credentials(req: Request):
        name = user_name(req)
        return {"ServiceSpecificCredentials": [
            {"UserName": name, "Status": st, "ServiceUserName": su, "CreateDate": ts(5),
             "ServiceSpecificCredentialId": "ACCAEXAMPLESERVICE001", "ServiceName": svc}
            for svc, su, st in IAM_USER_EXTRAS.get(name, {}).get("service_credentials", [])]}

    @w.op("iam", "ListSigningCertificates")
    def list_signing_certificates(req: Request):
        name = user_name(req)
        return {"Certificates": [
            {"UserName": name, "CertificateId": cid, "Status": st, "UploadDate": ts(5),
             "CertificateBody": "-----BEGIN CERTIFICATE-----\nZmFrZS1kZW1vLWNlcnQ=\n-----END CERTIFICATE-----\n"}
            for cid, st in IAM_USER_EXTRAS.get(name, {}).get("signing_certificates", [])], "IsTruncated": False}


def _register_wave1_s3(w: World) -> None:
    buckets = _by(S3_BUCKETS, "Name")

    def bucket(req: Request) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        name = req.params["Bucket"]
        if name not in buckets:
            raise _not_found("NoSuchBucket", "The specified bucket does not exist")
        return buckets[name], S3_EXTRAS.get(name, {})

    @w.op("s3", "GetBucketPolicyStatus")
    def get_policy_status(req: Request):
        b, _extra = bucket(req)
        if not b["policy"]:
            raise _not_found("NoSuchBucketPolicy", "The bucket policy does not exist")
        public = any(s.get("Effect") == "Allow" and s.get("Principal") in ("*", {"AWS": "*"}) and not s.get("Condition")
                     for s in b["policy"]["Statement"])
        return {"PolicyStatus": {"IsPublic": public}}

    @w.op("s3", "GetBucketOwnershipControls")
    def get_ownership(req: Request):
        _b, extra = bucket(req)
        if not extra.get("ownership"):
            raise _not_found("OwnershipControlsNotFoundError", "The bucket ownership controls were not found")
        return {"OwnershipControls": {"Rules": [{"ObjectOwnership": extra["ownership"]}]}}

    @w.op("s3", "GetBucketWebsite")
    def get_website(req: Request):
        _b, extra = bucket(req)
        if not extra.get("website"):
            raise _not_found("NoSuchWebsiteConfiguration", "The specified bucket does not have a website configuration")
        return dict(extra["website"])

    @w.op("s3", "GetBucketReplication")
    def get_replication(req: Request):
        _b, extra = bucket(req)
        if not extra.get("replication"):
            raise _not_found("ReplicationConfigurationNotFoundError", "The replication configuration was not found")
        return {"ReplicationConfiguration": extra["replication"]}

    @w.op("s3control", "GetPublicAccessBlock")
    def get_account_pab(req: Request):
        if req.params["AccountId"] != ACCOUNT_ID:
            raise req.deny()
        return {"PublicAccessBlockConfiguration": dict(S3_ACCOUNT_PAB)}


def _register_wave1_ec2(w: World) -> None:  # noqa: C901 - one handler per operation
    def ec2(req: Request) -> Dict[str, Any]:
        return regional(req, "ec2")

    @w.op("ec2", "DescribeAddresses")
    def describe_addresses(req: Request):
        return {"Addresses": [dict(a) for a in ec2(req).get("Addresses", [])]}

    @w.op("ec2", "DescribeLaunchTemplates")
    def describe_launch_templates(req: Request):
        lts = ec2(req).get("LaunchTemplates", [])
        ids, names = set(req.params.get("LaunchTemplateIds") or []), set(req.params.get("LaunchTemplateNames") or [])
        if ids or names:
            lts = [lt for lt in lts if lt["LaunchTemplateId"] in ids or lt["LaunchTemplateName"] in names]
        return {"LaunchTemplates": [dict(lt) for lt in lts]}

    @w.op("ec2", "DescribeLaunchTemplateVersions")
    def describe_launch_template_versions(req: Request):
        data = ec2(req)
        lt = None
        for cand in data.get("LaunchTemplates", []):
            if req.params.get("LaunchTemplateId") in (cand["LaunchTemplateId"], None) and \
                    req.params.get("LaunchTemplateName") in (cand["LaunchTemplateName"], None):
                lt = cand
                break
        if lt is None:
            raise AWSError("InvalidLaunchTemplateId.NotFound", "The specified launch template does not exist.", 400)
        versions = data["LaunchTemplateVersions"].get(lt["LaunchTemplateId"], [])
        wanted = req.params.get("Versions")
        if wanted:
            keep = set()
            for v in wanted:
                if v == "$Default":
                    keep.add(lt["DefaultVersionNumber"])
                elif v == "$Latest":
                    keep.add(lt["LatestVersionNumber"])
                else:
                    keep.add(int(v))
            versions = [v for v in versions if v["VersionNumber"] in keep]
        return {"LaunchTemplateVersions": [dict(v) for v in versions]}

    @w.op("ec2", "DescribeImages")
    def describe_images(req: Request):
        images = ec2(req).get("Images", [])
        owners = req.params.get("Owners")
        if owners and not ({"self", ACCOUNT_ID} & set(owners)):
            images = []
        ids = set(req.params.get("ImageIds") or [])
        if ids:
            images = [i for i in images if i["ImageId"] in ids]
        return {"Images": [{k: v for k, v in i.items() if not k.startswith("_")} for i in images]}

    @w.op("ec2", "DescribeImageAttribute")
    def describe_image_attribute(req: Request):
        for i in ec2(req).get("Images", []):
            if i["ImageId"] == req.params["ImageId"]:
                if req.params["Attribute"] != "launchPermission":
                    return {"ImageId": i["ImageId"]}
                return {"ImageId": i["ImageId"], "LaunchPermissions": [dict(p) for p in i["_launch"]]}
        raise AWSError("InvalidAMIID.NotFound", f"The image id '[{req.params['ImageId']}]' does not exist", 400)

    @w.op("ec2", "GetImageBlockPublicAccessState")
    def get_image_bpa(req: Request):
        return {"ImageBlockPublicAccessState": ec2(req).get("ImageBlockPublicAccessState", "unblocked")}

    @w.op("ec2", "GetSnapshotBlockPublicAccessState")
    def get_snapshot_bpa(req: Request):
        return {"State": ec2(req).get("SnapshotBlockPublicAccessState", "unblocked")}

    @w.op("ec2", "GetEbsEncryptionByDefault")
    def get_ebs_encryption_default(req: Request):
        return {"EbsEncryptionByDefault": bool(ec2(req).get("EbsEncryptionByDefault", False)), "SseType": "sse-ebs"}

    simple = {"DescribeTransitGateways": "TransitGateways",
              "DescribeTransitGatewayAttachments": "TransitGatewayAttachments",
              "DescribeVpnGateways": "VpnGateways", "DescribeVpnConnections": "VpnConnections",
              "DescribeManagedPrefixLists": "PrefixLists"}
    source = {"PrefixLists": "ManagedPrefixLists"}
    for op, key in simple.items():
        def handler(req: Request, _key: str = key):
            return {_key: [dict(x) for x in ec2(req).get(source.get(_key, _key), [])]}
        w.handlers[("ec2", op)] = handler

    @w.op("ec2", "GetManagedPrefixListEntries")
    def get_prefix_list_entries(req: Request):
        pl = req.params["PrefixListId"]
        entries = ec2(req).get("PrefixListEntries", {})
        if pl not in entries:
            if any(p["PrefixListId"] == pl for p in ec2(req).get("ManagedPrefixLists", [])):
                return {"Entries": []}
            raise AWSError("InvalidPrefixListID.NotFound", f"The prefix list ID '{pl}' does not exist", 400)
        return {"Entries": [dict(e) for e in entries[pl]]}

    @w.op("network-firewall", "ListFirewalls")
    def list_firewalls(req: Request):
        return {"Firewalls": [dict(f) for f in regional(req, "network_firewall")["firewalls"]]}


def _register_wave1_services(w: World) -> None:  # noqa: C901 - one handler per operation
    @w.op("cloudtrail", "ListEventDataStores")
    def list_event_data_stores(req: Request):
        return {"EventDataStores": [dict(s) for s in regional(req, "cloudtrail").get("event_data_stores", [])]}

    @w.op("ssm", "GetResourcePolicies")
    def get_resource_policies(req: Request):
        arn = req.params["ResourceArn"]
        data = regional(req, "ssm")
        policy = data.get("parameter_policies", {}).get(arn)
        known = {p["ARN"] for p in data["parameters"]} | {p["ARN"] for p in data.get("shared_parameters", [])}
        if policy is None and arn not in known:
            raise AWSError("ResourceNotFoundException", f"Resource {arn} not found", 400)
        return {"Policies": [{"PolicyId": "dec0policy0001", "PolicyHash": "dec0hash0001",
                              "Policy": World.json_doc(policy)}] if policy else []}

    def documents(req: Request) -> List[Dict[str, Any]]:
        return regional(req, "ssm").get("documents", [])

    @w.op("ssm", "ListDocuments")
    def list_documents(req: Request):
        docs = list(documents(req))
        owner_self = any(f.get("Key") == "Owner" and "Self" in f.get("Values", [])
                         for f in req.params.get("Filters", []))
        if not owner_self:
            docs += regional(req, "ssm").get("aws_documents", [])
        return {"DocumentIdentifiers": [{k: v for k, v in d.items() if not k.startswith("_")} for d in docs]}

    @w.op("ssm", "DescribeDocumentPermission")
    def describe_document_permission(req: Request):
        for d in documents(req):
            if d["Name"] == req.params["Name"]:
                return {"AccountIds": list(d["_share"]),
                        "AccountSharingInfoList": [{"AccountId": a, "SharedDocumentVersion": "$DEFAULT"}
                                                   for a in d["_share"]]}
        raise AWSError("InvalidDocument", "The specified document does not exist.", 400)

    @w.op("ssm", "DescribeInstanceInformation")
    def describe_instance_information(req: Request):
        return {"InstanceInformationList": [dict(i) for i in regional(req, "ssm").get("managed_instances", [])]}

    @w.op("lambda", "ListFunctionUrlConfigs")
    def list_function_url_configs(req: Request):
        f, _q = lambda_function(req)
        if f["url"] == "denied":
            raise req.deny(lambda_arn(req.region or "", f["FunctionName"]))
        out = []
        base = lambda_arn(req.region or "", f["FunctionName"])
        if isinstance(f["url"], dict):
            out.append((base, f["url"]))
        for alias in f.get("aliases") or []:
            if alias.get("url"):
                out.append((f"{base}:{alias['Name']}", alias["url"]))
        return {"FunctionUrlConfigs": [
            {"FunctionUrl": u["Url"], "FunctionArn": arn, "AuthType": u["AuthType"], "InvokeMode": "BUFFERED",
             "CreationTime": "2024-01-15T10:00:00.000Z", "LastModifiedTime": "2024-01-15T10:00:00.000Z"}
            for arn, u in out]}

    @w.op("lambda", "ListAliases")
    def list_aliases(req: Request):
        f, _q = lambda_function(req)
        base = lambda_arn(req.region or "", f["FunctionName"])
        return {"Aliases": [{"AliasArn": f"{base}:{a['Name']}", "Name": a["Name"],
                             "FunctionVersion": a["FunctionVersion"], "Description": a.get("Description", ""),
                             "RevisionId": "00000000-rev2-4000-8000-0000000000e3"}
                            for a in f.get("aliases") or []]}

    @w.op("lambda", "ListVersionsByFunction")
    def list_versions(req: Request):
        f, _q = lambda_function(req)
        base = {k: v for k, v in f.items() if k not in _LAMBDA_PRIVATE_KEYS}
        arn = lambda_arn(req.region or "", f["FunctionName"])
        out = [dict(base, FunctionArn=f"{arn}:$LATEST", Version="$LATEST")]
        out += [dict(base, FunctionArn=f"{arn}:{v}", Version=v) for v in f.get("versions") or []]
        return {"Versions": out}

    def layer_arn(req: Request, name: str) -> str:
        return f"arn:aws:lambda:{req.region}:{ACCOUNT_ID}:layer:{name}"

    def layer(req: Request) -> Dict[str, Any]:
        name = req.params["LayerName"].rsplit(":", 1)[-1] if req.params["LayerName"].startswith("arn:") \
            else req.params["LayerName"]
        for lyr in regional(req, "lambda").get("layers", []):
            if lyr["LayerName"] == name:
                return lyr
        raise _not_found("ResourceNotFoundException", "The resource you requested does not exist.")

    def version_item(req: Request, lyr: Dict[str, Any], v: Dict[str, Any]) -> Dict[str, Any]:
        return {"LayerVersionArn": f"{layer_arn(req, lyr['LayerName'])}:{v['Version']}", "Version": v["Version"],
                "Description": f"{lyr['LayerName']} v{v['Version']}", "CreatedDate": "2024-01-10T10:00:00.000+0000",
                "CompatibleRuntimes": list(v["CompatibleRuntimes"])}

    @w.op("lambda", "ListLayers")
    def list_layers(req: Request):
        return {"Layers": [{"LayerName": lyr["LayerName"], "LayerArn": layer_arn(req, lyr["LayerName"]),
                            "LatestMatchingVersion": version_item(req, lyr, max(lyr["versions"],
                                                                               key=lambda v: v["Version"]))}
                           for lyr in regional(req, "lambda").get("layers", [])]}

    @w.op("lambda", "ListLayerVersions")
    def list_layer_versions(req: Request):
        lyr = layer(req)
        return {"LayerVersions": [version_item(req, lyr, v)
                                  for v in sorted(lyr["versions"], key=lambda v: -v["Version"])]}

    @w.op("lambda", "GetLayerVersionPolicy")
    def get_layer_version_policy(req: Request):
        lyr = layer(req)
        for v in lyr["versions"]:
            if v["Version"] == req.params["VersionNumber"] and v["policy"]:
                return {"Policy": World.json_doc(v["policy"]), "RevisionId": "00000000-rev3-4000-8000-0000000000e4"}
        raise _not_found("ResourceNotFoundException", "No policy is associated with the given resource.")

    @w.op("lambda", "ListEventSourceMappings")
    def list_event_source_mappings(req: Request):
        maps = regional(req, "lambda").get("event_source_mappings", [])
        fn = req.params.get("FunctionName")
        if fn:
            maps = [m for m in maps if fn in (m["FunctionArn"], m["FunctionArn"].rsplit(":", 1)[-1])]
        return {"EventSourceMappings": [dict(m) for m in maps]}


def _register_wave1_compute(w: World) -> None:  # noqa: C901 - one handler per operation
    def cluster_arn(req: Request, name: str) -> str:
        return f"arn:aws:ecs:{req.region}:{ACCOUNT_ID}:cluster/{name}"

    def ecs_cluster(req: Request) -> Dict[str, Any]:
        wanted = req.params.get("cluster", "default")
        for c in regional(req, "ecs").get("clusters", []):
            if wanted in (c["clusterName"], cluster_arn(req, c["clusterName"])):
                return c
        raise AWSError("ClusterNotFoundException", "Cluster not found.", 400)

    @w.op("ecs", "ListTaskDefinitionFamilies")
    def list_families(req: Request):
        fams = sorted({t["family"] for t in regional(req, "ecs")["task_definitions"]})
        prefix = req.params.get("familyPrefix")
        if prefix:
            fams = [f for f in fams if f.startswith(prefix)]
        if req.params.get("status", "ACTIVE") == "INACTIVE":
            fams = []
        return {"families": fams}

    @w.op("ecs", "ListClusters")
    def list_clusters(req: Request):
        return {"clusterArns": [cluster_arn(req, c["clusterName"]) for c in regional(req, "ecs").get("clusters", [])]}

    def service_arn(req: Request, c: Dict[str, Any], s: Dict[str, Any]) -> str:
        return f"arn:aws:ecs:{req.region}:{ACCOUNT_ID}:service/{c['clusterName']}/{s['serviceName']}"

    @w.op("ecs", "ListServices")
    def list_services(req: Request):
        c = ecs_cluster(req)
        return {"serviceArns": [service_arn(req, c, s) for s in c["services"]]}

    @w.op("ecs", "DescribeServices")
    def describe_services(req: Request):
        c = ecs_cluster(req)
        out, failures = [], []
        for wanted in req.params["services"]:
            for s in c["services"]:
                if wanted in (s["serviceName"], service_arn(req, c, s)):
                    td = f"arn:aws:ecs:{req.region}:{ACCOUNT_ID}:task-definition/{s['taskDefinition']}"
                    out.append({"serviceArn": service_arn(req, c, s), "serviceName": s["serviceName"],
                                "clusterArn": cluster_arn(req, c["clusterName"]), "status": "ACTIVE",
                                "taskDefinition": td, "desiredCount": 1, "runningCount": 1,
                                "launchType": s["launchType"], "enableExecuteCommand": s["enableExecuteCommand"],
                                "networkConfiguration": {"awsvpcConfiguration": {
                                    "subnets": list(s["subnets"]), "securityGroups": list(s["securityGroups"]),
                                    "assignPublicIp": s["assignPublicIp"]}},
                                "createdAt": ts(5)})
                    break
            else:
                failures.append({"arn": wanted, "reason": "MISSING"})
        return {"services": out, "failures": failures}

    def stack_set(req: Request) -> Dict[str, Any]:
        for s in regional(req, "cloudformation").get("stack_sets", []):
            if req.params["StackSetName"] in (s["StackSetName"], s["StackSetId"]):
                return s
        raise AWSError("StackSetNotFoundException", "StackSet not found", 404)

    @w.op("cloudformation", "ListStackSets")
    def list_stack_sets(req: Request):
        sets = regional(req, "cloudformation").get("stack_sets", [])
        if req.params.get("Status") == "DELETED":
            sets = []
        return {"Summaries": [{"StackSetName": s["StackSetName"], "StackSetId": s["StackSetId"],
                               "Status": s["Status"], "PermissionModel": s["PermissionModel"],
                               "Description": f"{s['StackSetName']} (acme)"} for s in sets]}

    @w.op("cloudformation", "DescribeStackSet")
    def describe_stack_set(req: Request):
        s = stack_set(req)
        return {"StackSet": {"StackSetName": s["StackSetName"], "StackSetId": s["StackSetId"],
                             "Description": f"{s['StackSetName']} (acme)", "Status": s["Status"],
                             "Parameters": [dict(p) for p in s["Parameters"]],
                             "Capabilities": ["CAPABILITY_NAMED_IAM"],
                             "StackSetARN": f"arn:aws:cloudformation:{req.region}:{ACCOUNT_ID}:stackset/"
                                            f"{s['StackSetId']}",
                             "AdministrationRoleARN": s["AdministrationRoleARN"],
                             "ExecutionRoleName": s["ExecutionRoleName"], "PermissionModel": s["PermissionModel"]}}

    @w.op("codebuild", "ListSourceCredentials")
    def list_source_credentials(req: Request):
        return {"sourceCredentialsInfos": [dict(c) for c in regional(req, "codebuild").get("source_credentials", [])]}

    def domain(req: Request) -> Dict[str, Any]:
        wanted = req.params.get("DomainId") or req.params.get("DomainIdEquals")
        for d in regional(req, "sagemaker").get("domains", []):
            if d["DomainId"] == wanted:
                return d
        raise AWSError("ResourceNotFound", f"Domain {wanted} not found", 400)

    def domain_arn(req: Request, d: Dict[str, Any]) -> str:
        return f"arn:aws:sagemaker:{req.region}:{ACCOUNT_ID}:domain/{d['DomainId']}"

    @w.op("sagemaker", "ListDomains")
    def list_domains(req: Request):
        return {"Domains": [{"DomainArn": domain_arn(req, d), "DomainId": d["DomainId"], "DomainName": d["DomainName"],
                             "Status": "InService", "CreationTime": ts(4), "LastModifiedTime": ts(9),
                             "Url": f"https://{d['DomainId']}.studio.{req.region}.sagemaker.aws"}
                            for d in regional(req, "sagemaker").get("domains", [])]}

    @w.op("sagemaker", "DescribeDomain")
    def describe_domain(req: Request):
        d = domain(req)
        return {"DomainArn": domain_arn(req, d), "DomainId": d["DomainId"], "DomainName": d["DomainName"],
                "Status": "InService", "AuthMode": d["AuthMode"], "CreationTime": ts(4), "LastModifiedTime": ts(9),
                "DefaultUserSettings": {"ExecutionRole": d["ExecutionRole"]},
                "DefaultSpaceSettings": {"ExecutionRole": d["SpaceRole"]},
                "AppNetworkAccessType": d["AppNetworkAccessType"], "VpcId": d["VpcId"],
                "SubnetIds": list(d["SubnetIds"]),
                "Url": f"https://{d['DomainId']}.studio.{req.region}.sagemaker.aws"}

    @w.op("sagemaker", "ListUserProfiles")
    def list_user_profiles(req: Request):
        out = []
        for d in regional(req, "sagemaker").get("domains", []):
            if req.params.get("DomainIdEquals") not in (None, d["DomainId"]):
                continue
            out += [{"DomainId": d["DomainId"], "UserProfileName": u["UserProfileName"], "Status": "InService",
                     "CreationTime": ts(5), "LastModifiedTime": ts(9)} for u in d["users"]]
        return {"UserProfiles": out}

    @w.op("sagemaker", "DescribeUserProfile")
    def describe_user_profile(req: Request):
        d = domain(req)
        for u in d["users"]:
            if u["UserProfileName"] == req.params["UserProfileName"]:
                out = {"DomainId": d["DomainId"], "UserProfileName": u["UserProfileName"], "Status": "InService",
                       "UserProfileArn": f"arn:aws:sagemaker:{req.region}:{ACCOUNT_ID}:user-profile/{d['DomainId']}/"
                                         f"{u['UserProfileName']}", "CreationTime": ts(5), "LastModifiedTime": ts(9),
                       "UserSettings": {"ExecutionRole": u["ExecutionRole"]} if u["ExecutionRole"] else {}}
                return out
        raise AWSError("ResourceNotFound", "User profile not found", 400)


def _register_wave1_data(w: World) -> None:  # noqa: C901 - one handler per operation
    @w.op("sns", "ListSubscriptionsByTopic")
    def list_subscriptions(req: Request):
        for t in regional(req, "sns")["topics"]:
            arn = f"arn:aws:sns:{req.region}:{ACCOUNT_ID}:{t['Name']}"
            if arn == req.params["TopicArn"]:
                return {"Subscriptions": [
                    {"SubscriptionArn": f"{arn}:dec0dec0-0000-4000-8000-00000000000{i}", "Owner": ACCOUNT_ID,
                     "Protocol": s["Protocol"], "Endpoint": s["Endpoint"], "TopicArn": arn}
                    for i, s in enumerate(t.get("subscriptions", []))]}
        raise _not_found("NotFound", "Topic does not exist")

    @w.op("ecr", "GetRegistryPolicy")
    def get_registry_policy(req: Request):
        policy = regional(req, "ecr").get("registry_policy")
        if not policy:
            raise AWSError("RegistryPolicyNotFoundException",
                           f"Registry policy does not exist in the registry with id '{ACCOUNT_ID}'", 400)
        return {"registryId": ACCOUNT_ID, "policyText": json.dumps(policy, indent=2)}

    @w.op("ecr", "DescribeRegistry")
    def describe_registry(req: Request):
        return {"registryId": ACCOUNT_ID,
                "replicationConfiguration": {"rules": [dict(r) for r in regional(req, "ecr").get("replication_rules",
                                                                                                  [])]}}

    @w.op("rds", "DescribeDBClusters")
    def describe_db_clusters(req: Request):
        out = []
        for c in regional(req, "rds").get("clusters", []):
            item = {"DBClusterIdentifier": c["DBClusterIdentifier"], "Engine": c["Engine"], "Status": "available",
                    "DBClusterArn": f"arn:aws:rds:{req.region}:{ACCOUNT_ID}:cluster:{c['DBClusterIdentifier']}",
                    "Endpoint": f"{c['DBClusterIdentifier']}.cluster-abcdefghij.{req.region}.rds.amazonaws.com",
                    "StorageEncrypted": c["StorageEncrypted"],
                    "IAMDatabaseAuthenticationEnabled": c["IAMDatabaseAuthenticationEnabled"],
                    "PubliclyAccessible": c["PubliclyAccessible"], "ClusterCreateTime": ts(2),
                    "DBClusterMembers": [{"DBInstanceIdentifier": m, "IsClusterWriter": i == 0}
                                         for i, m in enumerate(c["members"])]}
            if c.get("KmsKeyId"):
                item["KmsKeyId"] = c["KmsKeyId"]
            out.append(item)
        return {"DBClusters": out}

    @w.op("rds", "DescribeDBClusterSnapshots")
    def describe_db_cluster_snapshots(req: Request):
        stype = req.params.get("SnapshotType")
        out = []
        for s in regional(req, "rds").get("cluster_snapshots", []):
            if stype and s["SnapshotType"] != stype:
                continue
            item = {"DBClusterSnapshotIdentifier": s["DBClusterSnapshotIdentifier"],
                    "DBClusterIdentifier": s["DBClusterIdentifier"], "SnapshotCreateTime": ts(8),
                    "Engine": "aurora-postgresql", "SnapshotType": s["SnapshotType"], "Status": "available",
                    "StorageEncrypted": s["StorageEncrypted"],
                    "DBClusterSnapshotArn": f"arn:aws:rds:{req.region}:{ACCOUNT_ID}:cluster-snapshot:"
                                            f"{s['DBClusterSnapshotIdentifier']}"}
            if s.get("KmsKeyId"):
                item["KmsKeyId"] = s["KmsKeyId"]
            out.append(item)
        return {"DBClusterSnapshots": out}

    @w.op("rds", "DescribeDBClusterSnapshotAttributes")
    def describe_db_cluster_snapshot_attributes(req: Request):
        sid = req.params["DBClusterSnapshotIdentifier"]
        for s in regional(req, "rds").get("cluster_snapshots", []):
            if s["DBClusterSnapshotIdentifier"] == sid:
                return {"DBClusterSnapshotAttributesResult": {
                    "DBClusterSnapshotIdentifier": sid,
                    "DBClusterSnapshotAttributes": [{"AttributeName": "restore",
                                                     "AttributeValues": list(s["restore"] or [])}]}}
        raise _not_found("DBClusterSnapshotNotFoundFault", f"DBClusterSnapshot {sid} not found.")

    def rest_api(req: Request) -> Dict[str, Any]:
        for a in regional(req, "apigateway")["rest_apis"]:
            if a["id"] == req.params["restApiId"]:
                return a
        raise _not_found("NotFoundException", "Invalid API identifier specified")

    @w.op("apigateway", "GetStages")
    def get_stages_v1(req: Request):
        return {"item": [dict(s) for s in rest_api(req).get("stages", [])]}

    def http_api(req: Request) -> Dict[str, Any]:
        for a in regional(req, "apigateway")["http_apis"]:
            if a["ApiId"] == req.params["ApiId"]:
                return a
        raise _not_found("NotFoundException", "Invalid API identifier specified")

    @w.op("apigatewayv2", "GetRoutes")
    def get_routes(req: Request):
        return {"Items": [dict(r) for r in http_api(req).get("routes", [])]}

    @w.op("apigatewayv2", "GetStages")
    def get_stages_v2(req: Request):
        return {"Items": [dict(s) for s in http_api(req).get("stages", [])]}

    def user_pool(req: Request) -> Dict[str, Any]:
        pid = req.params["UserPoolId"]
        details = regional(req, "cognito").get("user_pool_details", {})
        for p in regional(req, "cognito")["user_pools"]:
            if p["Id"] == pid and pid in details:
                return dict(p, **details[pid])
        raise _not_found("ResourceNotFoundException", f"User pool {pid} does not exist.")

    @w.op("cognito-idp", "DescribeUserPool")
    def describe_user_pool(req: Request):
        p = user_pool(req)
        return {"UserPool": {"Id": p["Id"], "Name": p["Name"],
                             "Arn": f"arn:aws:cognito-idp:{req.region}:{ACCOUNT_ID}:userpool/{p['Id']}",
                             "Status": "Enabled", "CreationDate": ts(2), "LastModifiedDate": ts(9),
                             "MfaConfiguration": p["MfaConfiguration"],
                             "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": p["AllowAdminCreateUserOnly"]},
                             "Domain": "demo-auth"}}

    @w.op("cognito-idp", "ListUserPoolClients")
    def list_user_pool_clients(req: Request):
        p = user_pool(req)
        return {"UserPoolClients": [dict(c, UserPoolId=p["Id"]) for c in p["clients"]]}

    def tg_arn(req: Request, name: str) -> str:
        return f"arn:aws:elasticloadbalancing:{req.region}:{ACCOUNT_ID}:targetgroup/{name}/0123456789abcdef"

    @w.op("elbv2", "DescribeListeners")
    def describe_listeners(req: Request):
        for lb in regional(req, "elb")["v2"]:
            if lb["LoadBalancerArn"] == req.params.get("LoadBalancerArn"):
                out = []
                for n, lst in enumerate(lb.get("listeners", []), start=1):
                    actions = []
                    for a in lst["DefaultActions"]:
                        action = {k: v for k, v in a.items() if k != "tg"}
                        if a.get("tg"):
                            action["TargetGroupArn"] = tg_arn(req, a["tg"])
                        actions.append(action)
                    out.append({"ListenerArn": lb["LoadBalancerArn"].replace(":loadbalancer/", ":listener/")
                                + f"/{n:016x}", "LoadBalancerArn": lb["LoadBalancerArn"], "Port": lst["Port"],
                                "Protocol": lst["Protocol"], "DefaultActions": actions})
                return {"Listeners": out}
        raise AWSError("LoadBalancerNotFound", "One or more load balancers not found", 400)


def _register_wave1_edge(w: World) -> None:
    @w.op("cloudfront", "ListDistributionsByWebACLId")
    def list_by_web_acl(req: Request):
        items = [_cf_summary(d) for d in CF_DISTRIBUTIONS if d["WebACLId"] and d["WebACLId"] == req.params["WebACLId"]]
        out: Dict[str, Any] = {"Marker": req.params.get("Marker", ""), "MaxItems": 100, "IsTruncated": False,
                               "Quantity": len(items)}
        if items:
            out["Items"] = items
        return {"DistributionList": out}


def _register_eks_access(w: World, cluster) -> None:
    """EKS access entries and Pod Identity (collectors-cli.md §5.14)."""
    def entries(req: Request) -> List[Dict[str, Any]]:
        c = cluster(req)
        mode = (c.get("accessConfig") or {}).get("authenticationMode", "CONFIG_MAP")
        if mode == "CONFIG_MAP":
            raise AWSError("InvalidRequestException",
                           "The cluster's authentication mode must be set to one of [API, API_AND_CONFIG_MAP] to "
                           "perform this operation.", 400)
        return c.get("access_entries") or []

    def entry(req: Request) -> Dict[str, Any]:
        for e in entries(req):
            if e["principalArn"] == req.params["principalArn"]:
                return e
        raise _not_found("ResourceNotFoundException", "The specified access entry could not be found.")

    @w.op("eks", "ListAccessEntries")
    def list_access_entries(req: Request):
        return {"accessEntries": [e["principalArn"] for e in entries(req)]}

    @w.op("eks", "DescribeAccessEntry")
    def describe_access_entry(req: Request):
        e = entry(req)
        name = req.params["clusterName"]
        return {"accessEntry": {
            "clusterName": name, "principalArn": e["principalArn"], "kubernetesGroups": list(e["kubernetesGroups"]),
            "accessEntryArn": f"arn:aws:eks:{req.region}:{ACCOUNT_ID}:access-entry/{name}/"
                              f"{e['type'].lower()}/{e['username'].split(':')[-1]}",
            "createdAt": ts(4), "modifiedAt": ts(4), "tags": {}, "username": e["username"], "type": e["type"]}}

    @w.op("eks", "ListAssociatedAccessPolicies")
    def list_associated_access_policies(req: Request):
        e = entry(req)
        return {"clusterName": req.params["clusterName"], "principalArn": e["principalArn"],
                "associatedAccessPolicies": [dict(p, associatedAt=ts(4), modifiedAt=ts(4)) for p in e["policies"]]}

    def association_arn(req: Request, a: Dict[str, Any]) -> str:
        return f"arn:aws:eks:{req.region}:{ACCOUNT_ID}:podidentityassociation/{req.params['clusterName']}/" \
               f"{a['associationId']}"

    @w.op("eks", "ListPodIdentityAssociations")
    def list_pod_identity(req: Request):
        c = cluster(req)
        return {"associations": [
            {"clusterName": c["name"], "namespace": a["namespace"], "serviceAccount": a["serviceAccount"],
             "associationArn": association_arn(req, a), "associationId": a["associationId"]}
            for a in c.get("pod_identity") or []
            if req.params.get("namespace") in (None, a["namespace"])]}

    @w.op("eks", "DescribePodIdentityAssociation")
    def describe_pod_identity(req: Request):
        c = cluster(req)
        for a in c.get("pod_identity") or []:
            if a["associationId"] == req.params["associationId"]:
                return {"association": {"clusterName": c["name"], "namespace": a["namespace"],
                                        "serviceAccount": a["serviceAccount"], "roleArn": a["roleArn"],
                                        "associationArn": association_arn(req, a),
                                        "associationId": a["associationId"], "tags": {}, "createdAt": ts(5),
                                        "modifiedAt": ts(5)}}
        raise _not_found("ResourceNotFoundException", "Pod identity association not found.")


def _register_wave1_posture(w: World) -> None:  # noqa: C901 - one handler per operation
    """organizations (global) and the regional posture services (collectors-cli.md §5.15)."""
    @w.op("organizations", "DescribeOrganization")
    def describe_organization(req: Request):
        return {"Organization": dict(ORGANIZATION)}

    @w.op("organizations", "ListParents")
    def list_parents(req: Request):
        child = req.params["ChildId"]
        if child not in ORG_PARENTS:
            raise AWSError("ChildNotFoundException", "We can't find an organizational unit (OU) or AWS account "
                                                     "with the ChildId that you specified.", 400)
        pid, ptype = ORG_PARENTS[child]
        return {"Parents": [{"Id": pid, "Type": ptype}]}

    @w.op("organizations", "DescribeOrganizationalUnit")
    def describe_ou(req: Request):
        ou = ORG_OUS.get(req.params["OrganizationalUnitId"])
        if ou is None:
            raise AWSError("OrganizationalUnitNotFoundException", "We can't find an OU with the OrganizationalUnitId "
                                                                  "that you specified.", 400)
        return {"OrganizationalUnit": dict(ou)}

    def summary(p: Dict[str, Any]) -> Dict[str, Any]:
        return {k: v for k, v in p.items() if k != "content"}

    @w.op("organizations", "ListPoliciesForTarget")
    def list_policies_for_target(req: Request):
        target = req.params["TargetId"]
        if target not in ORG_TARGET_POLICIES:
            raise AWSError("TargetNotFoundException", "We can't find a root, OU, account, or policy with the "
                                                      "TargetId that you specified.", 400)
        return {"Policies": [summary(ORG_POLICIES[pid]) for pid in ORG_TARGET_POLICIES[target]
                             if ORG_POLICIES[pid]["Type"] == req.params["Filter"]]}

    @w.op("organizations", "DescribePolicy")
    def describe_policy(req: Request):
        p = ORG_POLICIES.get(req.params["PolicyId"])
        if p is None:
            raise AWSError("PolicyNotFoundException", "We can't find a policy with the PolicyId that you specified.",
                           400)
        return {"Policy": {"PolicySummary": summary(p), "Content": World.json_doc(p["content"])}}

    @w.op("guardduty", "ListDetectors")
    def list_detectors(req: Request):
        return {"DetectorIds": [d["DetectorId"] for d in regional(req, "guardduty")["detectors"]]}

    @w.op("guardduty", "GetDetector")
    def get_detector(req: Request):
        for d in regional(req, "guardduty")["detectors"]:
            if d["DetectorId"] == req.params["DetectorId"]:
                role = iam_arn("role", "AWSServiceRoleForAmazonGuardDuty", "/aws-service-role/guardduty.amazonaws.com/")
                return {"Status": d["Status"], "ServiceRole": role,
                        "CreatedAt": "2024-01-02T10:00:00.000Z", "UpdatedAt": "2024-01-09T10:00:00.000Z",
                        "FindingPublishingFrequency": "SIX_HOURS",
                        "Features": [dict(f, UpdatedAt=ts(9)) for f in d["Features"]]}
        raise AWSError("BadRequestException", "The request is rejected because the input detectorId is not owned by "
                                              "the current account.", 400)

    @w.op("securityhub", "DescribeHub")
    def describe_hub(req: Request):
        hub = regional(req, "securityhub")["hub"]
        if hub is None:
            raise AWSError("InvalidAccessException", f"Account {ACCOUNT_ID} is not subscribed to AWS Security Hub",
                           401)
        return dict(hub)

    @w.op("securityhub", "GetEnabledStandards")
    def get_enabled_standards(req: Request):
        data = regional(req, "securityhub")
        if data["hub"] is None:
            raise AWSError("InvalidAccessException", f"Account {ACCOUNT_ID} is not subscribed to AWS Security Hub",
                           401)
        return {"StandardsSubscriptions": [dict(s, StandardsInput={}) for s in data["standards"]]}

    @w.op("config", "DescribeConfigurationRecorders")
    def describe_recorders(req: Request):
        return {"ConfigurationRecorders": [dict(r) for r in regional(req, "config")["recorders"]]}

    @w.op("config", "DescribeConfigurationRecorderStatus")
    def describe_recorder_status(req: Request):
        return {"ConfigurationRecordersStatus": [dict(s) for s in regional(req, "config")["status"]]}

    @w.op("config", "DescribeDeliveryChannels")
    def describe_delivery_channels(req: Request):
        return {"DeliveryChannels": [dict(c) for c in regional(req, "config")["channels"]]}

    @w.op("accessanalyzer", "ListAnalyzers")
    def list_analyzers(req: Request):
        analyzers = regional(req, "accessanalyzer")["analyzers"]
        if req.params.get("type"):
            analyzers = [a for a in analyzers if a["type"] == req.params["type"]]
        return {"analyzers": [dict(a) for a in analyzers]}


# ── Injections (part of the acme world, so goldens exercise error paths) ─────
def _register_injections(w: World) -> None:
    sm = "arn:aws:secretsmanager:eu-west-2:111122223333:secret:demo/denied-StUvWx"
    # IAM per-item failures
    w.deny("iam", "ListMFADevices", {"UserName": "demo-bob"}, note="users.json MFADevicesError (D)")
    w.deny("iam", "GetRolePolicy", {"RoleName": "demo-lambda-role", "PolicyName": "demo-lambda-inline"},
           note="inline policy {'Error'} (D)")
    w.deny("iam", "GetPolicyVersion", {"PolicyArn": policy_arn("demo-broken-policy")},
           note="policy_documents/<name>_error.json (E)")
    # S3 per-bucket failures
    w.deny("s3", "*", {"Bucket": "demo-denied-bucket"}, note="RegionError (D) + silent sub-config skips (F)")
    w.deny("s3", "GetBucketPolicy", {"Bucket": "demo-legacy-eu-bucket"}, note="silent (F)")
    w.deny("s3", "GetBucketAcl", {"Bucket": "demo-legacy-eu-bucket"}, note="silent (F)")
    # CloudFront
    w.deny("cloudfront", "GetDistributionConfig", {"Id": "E2DEMOEXAMPLE02"}, note="{'Id','Error'} item (D)")
    # Route 53
    w.deny("route53", "ListResourceRecordSets", {"HostedZoneId": "Z0DEMOPRIVATE0002"},
           note="empty Records (F)")
    # eu-west-2 per-item failures
    w.deny("ec2", "DescribeSnapshotAttribute", {"SnapshotId": "snap-0dec0ba1ba7e00023"}, region="eu-west-2",
           note="Public=False written on failure (F-104)")
    w.deny("secretsmanager", "GetResourcePolicy", {"SecretId": sm}, note="silent (F)")
    w.deny("lambda", "GetFunctionUrlConfig", {"FunctionName": "demo-layered"}, region="eu-west-2",
           note="silent (F)")
    w.deny("kms", "DescribeKey", {"KeyId": "1111aaaa-0000-4000-8000-0000000000a3"}, note="key dropped (F)")
    w.deny("kms", "GetKeyPolicy", {"KeyId": "1111aaaa-0000-4000-8000-0000000000a4"}, note="silent (F)")
    w.deny("kms", "ListGrants", {"KeyId": "1111aaaa-0000-4000-8000-0000000000a4"}, note="silent (F)")
    w.deny("ecs", "DescribeTaskDefinition",
           {"taskDefinition": "arn:aws:ecs:eu-west-2:111122223333:task-definition/demo-batch:1"},
           note="item dropped (F)")
    w.deny("sns", "GetTopicAttributes", {"TopicArn": "arn:aws:sns:eu-west-2:111122223333:demo-events"},
           note="Policy None (F)")
    w.deny("sqs", "GetQueueAttributes",
           {"QueueUrl": "https://sqs.eu-west-2.amazonaws.com/111122223333/demo-denied-queue"},
           note="item dropped (F)")
    w.deny("rds", "DescribeDBSnapshotAttributes", {"DBSnapshotIdentifier": "demo-db-snap-denied"},
           note="PublicSnapshot=False (F)")
    w.deny("dynamodb", "DescribeTable", {"TableName": "demo-denied-table"}, note="item dropped (F)")
    w.deny("cognito-identity", "GetIdentityPoolRoles",
           {"IdentityPoolId": "eu-west-2:11111111-2222-4333-8444-55555555555b"}, note="roles None (F)")
    w.deny("elbv2", "DescribeTargetHealth",
           {"TargetGroupArn": "arn:aws:elasticloadbalancing:eu-west-2:111122223333:targetgroup/"
                              "demo-denied-tg/0123456789abcdef"}, note="targets skipped (F)")
    w.throttle("ecr", "GetRepositoryPolicy", {"repositoryName": "demo-base"}, region="eu-west-2",
               note="throttle swallowed as 'no policy' (F)")
    # eu-west-1: the partially denied region
    r1 = "eu-west-1"
    w.raise_exc("ec2", "DescribeNatGateways",
                botocore_error("EndpointConnectionError", endpoint_url="https://ec2.eu-west-1.amazonaws.com/"),
                region=r1, note="safe() swallows BotoCoreError -> [] (A)")
    w.deny("ec2", "DescribeVpcPeeringConnections", region=r1, note="safe() -> [] (A)")
    w.deny("ec2", "DescribeNetworkInterfaces", region=r1, note="AssociatedResources [] (A)")
    w.raise_exc("ec2", "DescribeFlowLogs",
                botocore_error("ReadTimeoutError", endpoint_url="https://ec2.eu-west-1.amazonaws.com/"),
                region=r1, note="unguarded -> module aborts, no flowlogs.json (G)")
    w.deny("ec2", "DescribeSnapshots", region=r1, note="ebs resources.json {'Error'} (B)")
    w.deny("wafv2", "ListRuleGroups", region=r1, note="{'Scope','Error'} record in data list (D)")
    w.deny("eks", "DescribeCluster", {"name": "demo-denied-cluster"}, region=r1, note="{'name','Error'} item (D)")
    w.deny("eks", "ListFargateProfiles", {"clusterName": "demo-west-cluster"}, region=r1,
           note="map value {'Error'} (C)")
    w.deny("secretsmanager", "ListSecrets", region=r1, note="secrets.json {'Error'} (B)")
    w.deny("kms", "ListAliases", region=r1, note="aliases silently empty (F)")
    w.deny("cloudformation", "DescribeStacks", region=r1, note="resources.json {'Error'} (B)")
    w.deny("glue", "GetDevEndpoints", region=r1, note="partial failure printed only (B')")
    w.deny("sagemaker", "ListNotebookInstances", region=r1, note="resources.json {'Error'} (B)")
    w.deny("rds", "DescribeDBInstances", region=r1, note="B' when everything failed")
    w.deny("rds", "DescribeDBSnapshots", region=r1, note="B' when everything failed")
    w.deny("apigateway", "GetRestApis", region=r1, note="B' when everything failed")
    w.deny("cognito-identity", "ListIdentityPools", region=r1, note="printed only")
    w.deny("elbv2", "DescribeLoadBalancers", region=r1, note="B' when everything failed")
    # Wave 1 calls only (the baseline never makes them)
    w.deny("iam", "ListSSHPublicKeys", {"UserName": "demo-bob"},
           note="per-user extra denied -> item_errors / CollectionErrors on the user (F-111)")
    w.deny("eks", "DescribeAccessEntry", {"principalArn": iam_arn("user", "demo-alice")}, region="eu-west-2",
           note="one access entry unreadable -> CollectionErrors on that entry")


def _register_pagination(w: World) -> None:
    w.page_sizes.update({
        ("iam", "ListUsers"): 2,
        ("iam", "ListRoles"): 5,
        ("cloudfront", "ListDistributions"): 1,
        ("secretsmanager", "ListSecrets"): 2,
        ("ssm", "DescribeParameters"): 2,
        ("lambda", "ListFunctions"): 2,
        ("kms", "ListKeys"): 3,
        ("kms", "ListAliases"): 2,
        ("ec2", "DescribeFlowLogs"): 1,
        ("dynamodb", "ListTables"): 2,
        ("sns", "ListTopics"): 1,
        ("wafv2", "ListWebACLs"): 1,
        ("route53", "ListHostedZones"): 1,
        ("eks", "ListClusters"): 1,
        ("ecs", "ListTaskDefinitions"): 2,
        # Wave 1 calls (the baseline never makes them): several pages each
        ("iam", "GetAccountAuthorizationDetails"): 10,
        ("iam", "ListVirtualMFADevices"): 1,
        ("lambda", "ListAliases"): 1,
        ("ec2", "DescribeAddresses"): 1,
        ("eks", "ListAccessEntries"): 2,
    })
    # wafv2 has no paginator model; the collector follows NextMarker by hand.
    w.pagination[("wafv2", "ListWebACLs")] = PaginationSpec("NextMarker", "NextMarker", "WebACLs", None, "Limit")


# ═════════════════════════════════════════════════════════════════════════════
# Kubernetes (fake cluster behind the demo-cluster endpoint)
# ═════════════════════════════════════════════════════════════════════════════
def _meta(name: str, namespace: Optional[str] = None, **extra: Any) -> Dict[str, Any]:
    uid = "00000000-0000-4000-8000-e" + format(sum(map(ord, (namespace or "") + "/" + name)), "011d")
    meta: Dict[str, Any] = {"name": name, "uid": uid, "creation_timestamp": ts(3), "resource_version": "1000"}
    if namespace is not None:
        meta["namespace"] = namespace
    meta.update(extra)
    return meta


def build_k8s_clusters() -> Dict[str, FakeCluster]:
    """{endpoint: FakeCluster} for the EKS clusters in acme."""
    secret_manifest = json.dumps({
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {"annotations": {}, "name": "demo-db-secret", "namespace": "demo-apps"},
        "stringData": {"password": CANARIES["k8s_secret_last_applied"]}, "type": "Opaque",
    }, separators=(",", ":"))
    demo = FakeCluster(
        name="demo-cluster",
        version={"major": "1", "minor": "29", "git_version": "v1.29.4-eks-demo", "platform": "linux/amd64"},
        namespaces=[
            {"api_version": None, "kind": None,
             "metadata": _meta(n, labels={"kubernetes.io/metadata.name": n}),
             "spec": {"finalizers": ["kubernetes"]}, "status": {"phase": "Active"}}
            for n in ("default", "demo-apps", "kube-system")],
        pods=[
            {"api_version": None, "kind": None,
             "metadata": _meta("demo-api-7d9f8c6b5-abcde", "demo-apps", labels={"app": "demo-api"},
                               annotations={"kubectl.kubernetes.io/restartedAt": "2024-01-15T10:00:00Z"},
                               owner_references=[{"api_version": "apps/v1", "kind": "ReplicaSet",
                                                  "name": "demo-api-7d9f8c6b5", "controller": True}]),
             "spec": {"service_account_name": "demo-api", "service_account": "demo-api",
                      "automount_service_account_token": True, "node_name": "ip-10-20-2-10.eu-west-2.compute.internal",
                      "host_network": None, "host_pid": None, "host_ipc": None,
                      "containers": [{
                          "name": "api", "image": f"{ACCOUNT_ID}.dkr.ecr.eu-west-2.amazonaws.com/demo-api:1.0",
                          "env": [{"name": "DB_PASSWORD", "value": CANARIES["k8s_pod_env"], "value_from": None},
                                  {"name": "API_KEY", "value": None, "value_from": {
                                      "secret_key_ref": {"name": "demo-db-secret", "key": "api-key",
                                                         "optional": None}}}],
                          "security_context": {"privileged": False, "run_as_non_root": True},
                          "volume_mounts": [{"name": "db-creds", "mount_path": "/var/run/secrets/db",
                                             "read_only": True}]}],
                      "init_containers": None,
                      "volumes": [{"name": "db-creds", "secret": {"secret_name": "demo-db-secret",
                                                                  "default_mode": 420}},
                                  {"name": "aws-iam-token", "projected": {"sources": [{"service_account_token": {
                                      "audience": "sts.amazonaws.com", "expiration_seconds": 86400,
                                      "path": "token"}}]}}]},
             "status": {"phase": "Running", "pod_ip": "10.20.2.15", "host_ip": "10.20.2.10"}},
            {"api_version": None, "kind": None,
             "metadata": _meta("demo-worker-0", "demo-apps", labels={"app": "demo-worker"}),
             "spec": {"service_account_name": "demo-worker", "service_account": "demo-worker",
                      "host_network": True, "host_pid": True, "host_ipc": None,
                      "containers": [{"name": "worker", "image": "public.ecr.aws/demo/worker:latest",
                                      "env": [{"name": "MODE", "value": "batch", "value_from": None}],
                                      "security_context": {"privileged": True}}],
                      "init_containers": [{"name": "init", "image": "public.ecr.aws/demo/init:latest",
                                           "env": [{"name": "BOOTSTRAP_TOKEN",
                                                    "value": CANARIES["k8s_init_container_env"],
                                                    "value_from": None}]}],
                      "volumes": [{"name": "host-root", "host_path": {"path": "/", "type": "Directory"}}]},
             "status": {"phase": "Running", "pod_ip": "10.20.2.10", "host_ip": "10.20.2.10"}},
            {"api_version": None, "kind": None,
             "metadata": _meta("aws-node-xyz12", "kube-system", labels={"k8s-app": "aws-node"}),
             "spec": {"service_account_name": "aws-node", "service_account": "aws-node", "host_network": True,
                      "containers": [{"name": "aws-node", "image": "public.ecr.aws/demo/amazon-k8s-cni:v1.16.0",
                                      "env": [{"name": "AWS_VPC_K8S_CNI_LOGLEVEL", "value": "DEBUG",
                                               "value_from": None}],
                                      "security_context": {"privileged": False}}],
                      "volumes": []},
             "status": {"phase": "Running"}},
        ],
        service_accounts=[
            {"api_version": None, "kind": None, "metadata": _meta("default", "default")},
            {"api_version": None, "kind": None,
             "metadata": _meta("demo-api", "demo-apps",
                               annotations={"eks.amazonaws.com/role-arn": role_arn("demo-irsa-role")})},
            {"api_version": None, "kind": None, "metadata": _meta("demo-worker", "demo-apps")},
            {"api_version": None, "kind": None,
             "metadata": _meta("aws-node", "kube-system",
                               annotations={"eks.amazonaws.com/role-arn": role_arn("demo-eks-node-role")})},
        ],
        roles=[{"api_version": None, "kind": None, "metadata": _meta("demo-secret-reader", "demo-apps"),
                "rules": [{"api_groups": [""], "resources": ["secrets"], "verbs": ["get", "list"],
                           "resource_names": None}]}],
        cluster_roles=[
            {"api_version": None, "kind": None, "metadata": _meta("cluster-admin"),
             "rules": [{"api_groups": ["*"], "resources": ["*"], "verbs": ["*"]},
                       {"non_resource_ur_ls": ["*"], "verbs": ["*"]}]},
            {"api_version": None, "kind": None, "metadata": _meta("demo-pod-reader"),
             "rules": [{"api_groups": [""], "resources": ["pods", "pods/log"], "verbs": ["get", "list", "watch"]}]},
        ],
        role_bindings=[{"api_version": None, "kind": None,
                        "metadata": _meta("demo-secret-reader-binding", "demo-apps"),
                        "role_ref": {"api_group": "rbac.authorization.k8s.io", "kind": "Role",
                                     "name": "demo-secret-reader"},
                        "subjects": [{"kind": "ServiceAccount", "name": "demo-api", "namespace": "demo-apps",
                                      "api_group": None}]}],
        cluster_role_bindings=[
            {"api_version": None, "kind": None, "metadata": _meta("cluster-admin"),
             "role_ref": {"api_group": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
             "subjects": [{"kind": "Group", "name": "system:masters", "api_group": "rbac.authorization.k8s.io",
                           "namespace": None}]},
            {"api_version": None, "kind": None, "metadata": _meta("demo-worker-admin"),
             "role_ref": {"api_group": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
             "subjects": [{"kind": "ServiceAccount", "name": "demo-worker", "namespace": "demo-apps",
                           "api_group": None}]},
        ],
        secrets=[
            {"api_version": None, "kind": None, "type": "Opaque",
             "metadata": _meta("demo-db-secret", "demo-apps",
                               annotations={
                                   "kubectl.kubernetes.io/last-applied-configuration": secret_manifest + "\n"}),
             "data": {"password": _b64(CANARIES["k8s_secret_last_applied"]), "api-key": _b64("demo-api-key")}},
            {"api_version": None, "kind": None, "type": "kubernetes.io/service-account-token",
             "metadata": _meta("demo-sa-token", "kube-system",
                               annotations={"kubernetes.io/service-account.name": "aws-node"}),
             "data": {"token": _b64("fake-service-account-token")}},
        ],
        services=[
            {"api_version": None, "kind": None, "metadata": _meta("demo-api-lb", "demo-apps"),
             "spec": {"type": "LoadBalancer", "selector": {"app": "demo-api"}, "cluster_ip": "172.20.10.10",
                      "ports": [{"port": 80, "target_port": 8080, "protocol": "TCP", "name": "http"}]},
             "status": {"load_balancer": {"ingress": [{"hostname": "demo-api-lb.eu-west-2.elb.amazonaws.com"}]}}},
            {"api_version": None, "kind": None, "metadata": _meta("kubernetes", "default"),
             "spec": {"type": "ClusterIP", "selector": None, "cluster_ip": "172.20.0.1",
                      "ports": [{"port": 443, "target_port": 443, "protocol": "TCP", "name": "https"}]},
             "status": {"load_balancer": {}}},
        ],
        ingresses=[{"api_version": None, "kind": None,
                    "metadata": _meta("demo-api-ingress", "demo-apps",
                                      annotations={"alb.ingress.kubernetes.io/scheme": "internet-facing"}),
                    "spec": {"ingress_class_name": "alb", "rules": [{"host": "api.example.com", "http": {"paths": [
                        {"path": "/", "path_type": "Prefix",
                         "backend": {"service": {"name": "demo-api-lb", "port": {"number": 80}}}}]}}]}}],
        nodes=[{"api_version": None, "kind": None,
                "metadata": _meta("ip-10-20-2-10.eu-west-2.compute.internal",
                                  labels={"eks.amazonaws.com/nodegroup": "demo-ng"}),
                "spec": {"provider_id": "aws:///eu-west-2b/i-0dec0abb000000002"}}],
        config_maps=[{"api_version": None, "kind": None, "metadata": _meta("aws-auth", "kube-system"),
                      "data": {"mapRoles": f"- rolearn: {role_arn('demo-eks-node-role')}\n"
                                           "  username: system:node:{{EC2PrivateDNSName}}\n"
                                           "  groups:\n  - system:bootstrappers\n  - system:nodes\n"
                                           f"- rolearn: {role_arn('demo-admin-role')}\n"
                                           "  username: demo-admin\n  groups:\n  - system:masters\n"}}],
    )
    # SelfSubjectRulesReview (Wave 1): read-only everywhere, plus Secret reads in demo-apps only.
    secret_reader = dict(DEFAULT_SELF_RULES, resource_rules=list(DEFAULT_SELF_RULES["resource_rules"]) + [
        {"verbs": ["get", "list"], "api_groups": [""], "resources": ["secrets"], "resource_names": None}])
    demo.self_rules = {"*": DEFAULT_SELF_RULES, "demo-apps": secret_reader}
    west = FakeCluster(name="demo-west-cluster",
                       errors={"*": ApiException(status=401, reason="Unauthorized")})
    return {EKS_ENDPOINTS["demo-cluster"]: demo, EKS_ENDPOINTS["demo-west-cluster"]: west}
