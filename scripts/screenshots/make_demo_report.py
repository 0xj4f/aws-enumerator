#!/usr/bin/env python3
"""Build the synthetic demo run behind the README screenshots, then analyse (and zip) it (F-134).

The run is a fake AWS estate made with the test-suite builders (``tests/support/report_builder.py``): no
collector runs, nothing talks to AWS, and every identifier is a placeholder.

* accounts: only ``111122223333`` (the "target") and ``999999999999`` (an external partner account);
* names: ``demo-*`` (and ``example.com`` hosts); EC2-family ids are the builders' hexadecimal placeholders;
  public IPs come from TEST-NET-3 (203.0.113.0/24, RFC 5737);
* content: IAM (users, roles, groups, an OIDC provider), S3 (one public bucket), a VPC with a public web
  instance (open security group, IMDSv1), Lambda (a public function URL), Secrets Manager, KMS, an EKS
  cluster with IRSA service accounts, RBAC and privileged pods, an internet-facing load balancer and a
  cross-account trust, so the graph shows public exposure and several privilege-escalation paths.

::

    .venv/bin/python scripts/screenshots/make_demo_report.py OUT_DIR [--zip] [--no-analyze]

prints the run root (``OUT_DIR/111122223333/<run id>``) on stdout; ``--zip`` also writes
``OUT_DIR/demo-run.zip`` with ``aws-enumerator package``. ``OUT_DIR`` must be outside the git work tree
(``analyze`` refuses to write inside one without ``--allow-in-repo``) and empty or absent.

After writing, the script scans every file it produced and fails (exit 1) when a 12-digit number other
than the two placeholder accounts appears (``scan_tree``), so a builder default can never leak another id
into the screenshots. ``tests/python/docs/test_screenshots.py`` runs the same check.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.support import report_builder as rb  # noqa: E402  (needs the repo root on sys.path)
from tests.support.report_builder import allow, grant, resource_policy, trust  # noqa: E402

ACCOUNT = "111122223333"
EXTERNAL_ACCOUNT = "999999999999"
#: The only 12-digit numbers the demo run may contain.
ALLOWED_ACCOUNTS = frozenset({ACCOUNT, EXTERNAL_ACCOUNT})
REGION = "eu-west-2"
RUN_ID = "20260101T090000Z-dec0de"
#: The operator (the credentials the "assessment" ran with): a developer user with a privilege-escalation path.
OPERATOR_ARN = f"arn:aws:iam::{ACCOUNT}:user/demo-dev"
#: Pinned analysis clock (2026-01-01T09:00:00Z): the dashboard header shows ``generated_at``.
SOURCE_DATE_EPOCH = "1767258000"
ZIP_NAME = "demo-run.zip"

# 12 digits not glued to other alphanumerics (the same shape scripts/scan_sensitive.py looks for)
ACCOUNT_RE = re.compile(r"(?<![0-9A-Za-z.])(?<![0-9A-Fa-f]{4}-)(\d{12})(?![0-9A-Za-z])(?!\.\d)")

VPC = "vpc-0dec0a1b2c3d4e5f6"
PUBLIC_SUBNET = "subnet-0dec0a1b2c3d4e501"
PRIVATE_SUBNET = "subnet-0dec0a1b2c3d4e502"
IGW = "igw-0dec0a1b2c3d4e5f6"
WEB_SG = "sg-0dec0a1b2c3d4e501"
DB_SG = "sg-0dec0a1b2c3d4e502"
WEB_INSTANCE = "i-0dec0a1b2c3d4e501"
BATCH_INSTANCE = "i-0dec0a1b2c3d4e502"


def _iam() -> rb.Iam:
    """Identities: the operator's privilege-escalation path, an instance role, Lambda and IRSA roles, a partner."""
    iam = rb.Iam(ACCOUNT)
    a = iam.arn
    # developers: the operator can pass the admin role to a new Lambda function (PassRole + CreateFunction)
    iam.managed("demo-developer-policy", [
        allow(["lambda:CreateFunction", "lambda:InvokeFunction", "lambda:GetFunction", "lambda:List*"], "*"),
        allow("iam:PassRole", [a("role", "demo-deploy-role"), a("role", "demo-lambda-exec")]),
        allow(["logs:*", "cloudwatch:Get*"], "*"),
    ], customer=True)
    iam.group("demo-developers", attached=["demo-developer-policy"])
    iam.user("demo-dev", groups=["demo-developers"], access_keys=1, login=True, mfa=True)
    # CI user: can rewrite its own customer-managed policy (CreatePolicyVersion -> admin)
    iam.managed("demo-ci-policy", [
        allow(["ecr:*", "s3:PutObject", "s3:GetObject"], "*"),
        allow(["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
              f"arn:aws:iam::{ACCOUNT}:policy/demo-ci-policy"),
    ], customer=True)
    iam.user("demo-ci", attached=["demo-ci-policy"], access_keys=2)
    iam.user("demo-auditor", attached=["ReadOnlyAccess"], login=True, mfa=True)
    # the admin role: Lambda and CloudFormation may assume it (so whoever can pass it to them is admin)
    iam.role("demo-deploy-role", trust({"Service": ["lambda.amazonaws.com", "cloudformation.amazonaws.com"]}),
             attached=["AdministratorAccess"], description="demo deployment role")
    # web tier (public instance with IMDSv1): the instance role reads the customer data and the web secrets
    iam.role("demo-web-role", trust({"Service": "ec2.amazonaws.com"}), inline={"web": [
        allow(["s3:GetObject", "s3:ListBucket"],
              ["arn:aws:s3:::demo-customer-data", "arn:aws:s3:::demo-customer-data/*"]),
        allow(["secretsmanager:GetSecretValue"], f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:demo/web/*"),
        allow(["ssm:GetParameter*"], "*")]})
    iam.instance_profile("demo-web-profile", ["demo-web-role"])
    # batch tier: may redeploy the report worker, whose execution role is the admin deploy role
    iam.role("demo-batch-role", trust({"Service": "ec2.amazonaws.com"}), inline={"batch": [
        allow(["s3:GetObject", "s3:PutObject"], "arn:aws:s3:::demo-build-artifacts/*"),
        allow(["lambda:UpdateFunctionCode", "lambda:InvokeFunction"],
              f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:demo-report-worker")]})
    iam.instance_profile("demo-batch-profile", ["demo-batch-role"])
    # Lambda execution role behind the public function URL
    iam.role("demo-lambda-exec", trust({"Service": "lambda.amazonaws.com"}), inline={"fn": [
        allow(["secretsmanager:GetSecretValue"], f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:demo/db-*"),
        allow(["kms:Decrypt"], "*"), allow(["dynamodb:*"], "*")]})
    # partner account trusted without an ExternalId
    iam.role("demo-partner-access", trust({"AWS": f"arn:aws:iam::{EXTERNAL_ACCOUNT}:root"}),
             attached=["ReadOnlyAccess"], inline={"support": [allow(["ssm:SendCommand", "ssm:StartSession"], "*")]})
    return iam


def _eks(iam: rb.Iam, r: rb.Scope) -> Dict[str, object]:
    """One EKS cluster with IRSA, a nodegroup, RBAC and a privileged debug pod."""
    a = iam.arn
    cluster = rb.eks_cluster("demo-eks", account=ACCOUNT, region=REGION, role_arn=a("role", "demo-eks-cluster-role"))
    cluster["resourcesVpcConfig"].update({"subnetIds": [PRIVATE_SUBNET], "vpcId": VPC,
                                          "clusterSecurityGroupId": "sg-0dec0a1b2c3d4e5c0"})
    oidc = rb.oidc_provider_arn(ACCOUNT, cluster)
    issuer = cluster["identity"]["oidc"]["issuer"].replace("https://", "")
    iam.oidc_provider(issuer)
    iam.role("demo-eks-cluster-role", trust({"Service": "eks.amazonaws.com"}),
             attached=[iam.managed("AmazonEKSClusterPolicy", [allow(["ec2:Describe*", "elasticloadbalancing:*"],
                                                                    "*")])])
    iam.role("demo-eks-node-role", trust({"Service": "ec2.amazonaws.com"}),
             attached=[iam.managed("AmazonEKSWorkerNodePolicy", [allow(["ec2:Describe*", "eks:DescribeCluster"],
                                                                       "*")])],
             inline={"ecr": [allow(["ecr:GetAuthorizationToken", "ecr:BatchGetImage"], "*")]})
    payments_sub = {f"{issuer}:sub": "system:serviceaccount:payments:payments-sa", f"{issuer}:aud": "sts.amazonaws.com"}
    iam.role("demo-irsa-payments", trust({"Federated": oidc}, "sts:AssumeRoleWithWebIdentity",
                                         {"StringEquals": payments_sub}),
             inline={"payments": [allow(["s3:*"], ["arn:aws:s3:::demo-customer-data",
                                                   "arn:aws:s3:::demo-customer-data/*"]),
                                  allow(["secretsmanager:GetSecretValue"], "*")]})
    iam.role("demo-irsa-web", trust({"Federated": oidc}, "sts:AssumeRoleWithWebIdentity",
                                    {"StringLike": {f"{issuer}:sub": "system:serviceaccount:web:*"}}),
             inline={"read": [allow(["s3:GetObject"], "arn:aws:s3:::demo-public-assets/*")]})
    r.write("eks/clusters.json", [cluster])
    r.write("eks/nodegroups.json", {"demo-eks": [{
        "nodegroupName": "demo-ng", "nodegroupArn": f"arn:aws:eks:{REGION}:{ACCOUNT}:nodegroup/demo-eks/demo-ng/dec0",
        "clusterName": "demo-eks", "version": "1.30", "status": "ACTIVE", "capacityType": "ON_DEMAND",
        "instanceTypes": ["t3.large"], "nodeRole": a("role", "demo-eks-node-role"), "subnets": [PRIVATE_SUBNET],
        "scalingConfig": {"minSize": 2, "maxSize": 4, "desiredSize": 2}}]})
    r.write("eks/fargate_profiles.json", {"demo-eks": []})
    r.write("eks/addons.json", {"demo-eks": [{"addonName": "vpc-cni", "clusterName": "demo-eks", "status": "ACTIVE",
                                              "addonVersion": "v1.18.0-eksbuild.1"}]})
    k = "k8s/demo-eks"
    r.write(f"{k}/cluster_info.json", {"name": "demo-eks", "endpoint": cluster["endpoint"], "auth_status": "ok",
                                       "version": {"major": "1", "minor": "30", "git_version": "v1.30.0-eks",
                                                   "platform": "linux/amd64"}})
    r.write(f"{k}/namespaces.json", [rb.k8s_namespace(n) for n in ("default", "kube-system", "payments", "web")])
    r.write(f"{k}/service_accounts.json", [
        rb.k8s_sa("default", "default"), rb.k8s_sa("default", "kube-system"),
        rb.k8s_sa("payments-sa", "payments", role_arn=a("role", "demo-irsa-payments")),
        rb.k8s_sa("web-sa", "web", role_arn=a("role", "demo-irsa-web")),
        rb.k8s_sa("demo-deployer", "kube-system"),
    ])
    r.write(f"{k}/pods.json", [
        rb.k8s_pod("payments-api-0", "payments", sa="payments-sa", labels={"app": "payments"}),
        rb.k8s_pod("web-frontend-0", "web", sa="web-sa", labels={"app": "web"}),
        rb.k8s_pod("node-debugger", "kube-system", sa="demo-deployer", privileged=True, host_network=True,
                   host_pid=True),
    ])
    r.write(f"{k}/roles.json", [rb.k8s_role("secret-reader", "payments",
                                            [{"resources": ["secrets"], "verbs": ["get", "list"]}])])
    r.write(f"{k}/cluster_roles.json", [
        rb.k8s_role("cluster-admin", None, [{"api_groups": ["*"], "resources": ["*"], "verbs": ["*"]}]),
        rb.k8s_role("view", None, [{"resources": ["pods", "services"], "verbs": ["get", "list", "watch"]}]),
    ])
    r.write(f"{k}/role_bindings.json", [
        rb.k8s_binding("read-secrets", "payments", "Role", "secret-reader",
                       [{"kind": "ServiceAccount", "name": "payments-sa", "namespace": "payments"}]),
        rb.k8s_binding("web-view", "web", "ClusterRole", "view",
                       [{"kind": "ServiceAccount", "name": "web-sa", "namespace": "web"}]),
    ])
    r.write(f"{k}/cluster_role_bindings.json", [
        rb.k8s_binding("deployer-admin", None, "ClusterRole", "cluster-admin",
                       [{"kind": "ServiceAccount", "name": "demo-deployer", "namespace": "kube-system"}]),
    ])
    r.write(f"{k}/services.json", [
        rb.k8s_service("web-lb", "web", svc_type="LoadBalancer", selector={"app": "web"}),
        rb.k8s_service("payments-svc", "payments", selector={"app": "payments"}),
    ])
    r.write(f"{k}/ingresses.json", [rb.k8s_ingress("web-ingress", "web", "web-lb")])
    return cluster


def build(out_dir: Path) -> rb.V2Run:
    """Write the demo run under ``out_dir/<account>/<run id>/`` and return it (manifest finalised)."""
    run = rb.V2Run(out_dir, account=ACCOUNT, run_id=RUN_ID, regions=[REGION], operator_arn=OPERATOR_ARN,
                   started_at="2026-01-01T09:00:00Z")
    g, r = run.unit("global"), run.unit(REGION)
    iam = _iam()
    cluster = _eks(iam, r)
    iam.write(g, layout="gaad")
    run.coverage("iam", "global", calls=[
        {"api": "iam:GetAccountAuthorizationDetails", "primary": True, "items": 24, "pages": 1},
        {"api": "iam:GetCredentialReport"}, {"api": "iam:GenerateCredentialReport"}])

    # S3: a public asset bucket, a private customer-data bucket, a build bucket shared with the partner account
    key = rb.kms_key("0dec0de0-aaaa-4bbb-8ccc-0123456789ab", account=ACCOUNT, region=REGION,
                     aliases=["alias/demo-data"])
    g.write("s3/buckets.json", [
        rb.s3_bucket(g, "demo-public-assets", region=REGION, policy=resource_policy(
            grant("*", "s3:GetObject", "arn:aws:s3:::demo-public-assets/*")),
            acl=rb.acl(ACCOUNT, public_read=True),
            public_access_block={"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False,
                                 "RestrictPublicBuckets": False}),
        rb.s3_bucket(g, "demo-customer-data", region=REGION, encryption=rb.kms_encryption(key["Arn"]),
                     tagging=[{"Key": "classification", "Value": "confidential"}]),
        rb.s3_bucket(g, "demo-build-artifacts", region=REGION, policy=resource_policy(
            grant({"AWS": f"arn:aws:iam::{EXTERNAL_ACCOUNT}:root"}, ["s3:GetObject", "s3:PutObject"],
                  "arn:aws:s3:::demo-build-artifacts/*"))),
    ])
    run.coverage("s3", "global", calls=[
        {"api": "s3:ListBuckets", "primary": True, "items": 3, "pages": 1},
        {"api": "s3:GetBucketPolicy", "error_code": "NoSuchBucketPolicy", "not_configured": True}])

    # network: a VPC with a public subnet; the web instance is reachable from the internet with IMDSv1
    rb.vpc_network(r, vpc=VPC, public_subnet=PUBLIC_SUBNET, private_subnet=PRIVATE_SUBNET, igw=IGW)
    run.coverage("vpc", REGION, calls=[{"api": "ec2:DescribeVpcs", "primary": True, "items": 1}])
    r.write("sg/security_groups.json", [
        rb.security_group(WEB_SG, "demo-web", vpc=VPC, inbound=[
            rb.sg_rule("tcp", 22, cidrs=["0.0.0.0/0"], account=ACCOUNT, description="ssh from anywhere"),
            rb.sg_rule("tcp", 443, cidrs=["0.0.0.0/0"], account=ACCOUNT)], attached_instances=[WEB_INSTANCE]),
        rb.security_group(DB_SG, "demo-batch", vpc=VPC, inbound=[
            rb.sg_rule("tcp", 22, groups=[WEB_SG], account=ACCOUNT)], attached_instances=[BATCH_INSTANCE]),
    ])
    run.coverage("sg", REGION, calls=[{"api": "ec2:DescribeSecurityGroups", "primary": True, "items": 2}])
    r.write("ec2/instances.json", [
        rb.ec2_instance(WEB_INSTANCE, account=ACCOUNT, region=REGION, profile=iam.arn("instance-profile",
                                                                                       "demo-web-profile"),
                        http_tokens="optional", public_ip="203.0.113.10", private_ip="10.0.1.10",
                        subnet=PUBLIC_SUBNET, vpc=VPC, sgs=[{"GroupId": WEB_SG, "GroupName": "demo-web"}],
                        tags={"Name": "demo-web-1"}),
        rb.ec2_instance(BATCH_INSTANCE, account=ACCOUNT, region=REGION, profile=iam.arn("instance-profile",
                                                                                         "demo-batch-profile"),
                        private_ip="10.0.2.20", subnet=PRIVATE_SUBNET, vpc=VPC,
                        sgs=[{"GroupId": DB_SG, "GroupName": "demo-batch"}], tags={"Name": "demo-batch-1"}),
    ])
    run.coverage("ec2", REGION, calls=[{"api": "ec2:DescribeInstances", "primary": True, "items": 2}])

    # Lambda: a function URL without auth, running as a role that reads the database secret
    fn = rb.lambda_function("demo-public-api", account=ACCOUNT, region=REGION, role=iam.arn("role", "demo-lambda-exec"),
                            url_auth="NONE", env_names=["DB_HOST", "STAGE"])
    worker = rb.lambda_function("demo-report-worker", account=ACCOUNT, region=REGION,
                                role=iam.arn("role", "demo-deploy-role"))
    r.write("lambda/functions.json", [fn, worker])
    r.write(f"lambda/resource_policies/{rb.safe_filename(fn['FunctionName'])}.json", rb.lambda_policy_file(
        fn, resource_policy(grant("*", "lambda:InvokeFunctionUrl", fn["FunctionArn"]))))
    run.coverage("lambda", REGION, calls=[{"api": "lambda:ListFunctions", "primary": True, "items": 2}])

    # secrets and keys
    r.write("secretsmanager/secrets.json", [
        rb.secret("demo/db-password", account=ACCOUNT, region=REGION, kms_key=key["Arn"], rotation=False),
        rb.secret("demo/web/api-token", account=ACCOUNT, region=REGION),
    ])
    run.coverage("secretsmanager", REGION, calls=[{"api": "secretsmanager:ListSecrets", "primary": True, "items": 2}])
    r.write("kms/keys.json", [key])
    r.write(f"kms/key_policies/{key['KeyId']}.json", rb.kms_policy_file(key, resource_policy(
        grant({"AWS": f"arn:aws:iam::{ACCOUNT}:root"}, "kms:*"))))
    run.coverage("kms", REGION, calls=[{"api": "kms:ListKeys", "primary": True, "items": 1}])

    # an internet-facing load balancer in front of the web instance
    r.write("elb/resources.json", [
        {"Type": "elb", "Arn": f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/demo-web-alb/"
                               "0dec0de0dec0de01", "Name": "demo-web-alb", "Scheme": "internet-facing",
         "DNSName": f"demo-web-alb.{REGION}.elb.amazonaws.com", "LBType": "application",
         "Targets": [{"kind": "instance", "id": WEB_INSTANCE}]}])
    run.coverage("elb", REGION, calls=[{"api": "elbv2:DescribeLoadBalancers", "primary": True, "items": 1}])

    run.coverage("eks", REGION, calls=[{"api": "eks:ListClusters", "primary": True, "items": 1},
                                       {"api": "eks:DescribeCluster", "item": cluster["arn"]}])
    run.coverage("k8s", REGION, calls=[{"api": "eks:DescribeCluster", "primary": True, "items": 1}])
    run.finalize()
    return run


def _run_cli(args: Sequence[str], env: Dict[str, str]) -> None:
    cmd = [sys.executable, "-m", "aws_enumerator", args[0], "-q", *args[1:]]
    proc = subprocess.run(cmd, cwd=str(REPO_ROOT), env=env, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout + proc.stderr)
        raise SystemExit(f"make_demo_report: {' '.join(args[:1])} failed with exit status {proc.returncode}")


def cli_env() -> Dict[str, str]:
    env = dict(os.environ)
    env.update({"SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH, "NO_COLOR": "1", "PYTHONDONTWRITEBYTECODE": "1"})
    for var in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        env.pop(var, None)  # analyze and package never call AWS; make sure nothing could
    return env


def scan_text(text: str, where: str) -> List[str]:
    """Problems: every 12-digit number in ``text`` outside :data:`ALLOWED_ACCOUNTS` (masked)."""
    return [f"{where}: 12-digit id {m.group(1)[:2]}********{m.group(1)[-2:]} is not a demo placeholder"
            for m in ACCOUNT_RE.finditer(text) if m.group(1) not in ALLOWED_ACCOUNTS]


def scan_tree(root: Path) -> List[str]:
    """:func:`scan_text` over every file under ``root``, including the members of any zip."""
    problems = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if path.suffix == ".zip":
            with zipfile.ZipFile(path) as zf:
                for name in sorted(zf.namelist()):
                    problems += scan_text(zf.read(name).decode("utf-8", errors="replace"), f"{rel}!{name}")
            continue
        problems += scan_text(path.read_bytes().decode("utf-8", errors="replace"), rel)
    return problems


def _inside_git_work_tree(path: Path) -> bool:
    for parent in (path, *path.parents):
        if (parent / ".git").exists():
            return True
    return False


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Build, analyse and (optionally) zip the synthetic screenshot run.")
    ap.add_argument("out_dir", help="empty or absent directory outside the git work tree")
    ap.add_argument("--zip", action="store_true", help=f"also write OUT_DIR/{ZIP_NAME} (aws-enumerator package)")
    ap.add_argument("--no-analyze", action="store_true", help="write the collector tree only")
    args = ap.parse_args(argv)
    out = Path(args.out_dir).resolve()
    if _inside_git_work_tree(out):
        print(f"make_demo_report: {out} is inside a git work tree; use a temporary directory", file=sys.stderr)
        return 64
    if out.exists() and any(out.iterdir()):
        print(f"make_demo_report: {out} is not empty", file=sys.stderr)
        return 64
    run = build(out)
    env = cli_env()
    if not args.no_analyze:
        _run_cli(["analyze", str(run.path)], env)
    if args.zip:
        _run_cli(["package", str(run.path), "--output", str(out / ZIP_NAME)], env)
    problems = scan_tree(out)
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(run.path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
