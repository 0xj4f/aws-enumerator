# Offline guard: fake credentials, no config files, no IMDS, and a dead proxy, so any
# accidental AWS call fails locally instead of reaching a real account.
import os
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_SESSION_TOKEN="testing",
                  AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
                  AWS_EC2_METADATA_DISABLED="true", HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9")
os.environ.pop("AWS_PROFILE", None)
import sys, os, json, shutil
from unittest import mock
import tempfile
REPO = os.getcwd()  # run from the repository root
sys.path.insert(0, REPO)
RUN = tempfile.mkdtemp(prefix="f010-")  # synthetic reports go to a temp dir, never into the repo
os.chdir(RUN)

import app.main as M
from app.components import policy_parser as PP

ACCT = "111122223333"
GEN = {"n": 1}

def w(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f: json.dump(data, f)

def fake_iam(session, out):
    w(f"{out}/roles.json", [{"RoleName": "AppRole", "Arn": f"arn:aws:iam::{ACCT}:role/AppRole",
        "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}}])
    w(f"{out}/users.json", [{"UserName": "dev", "Arn": f"arn:aws:iam::{ACCT}:user/dev"}])
    w(f"{out}/instance_profiles.json", [{"InstanceProfileName": "AppProfile", "Arn": f"arn:aws:iam::{ACCT}:instance-profile/AppProfile",
        "Roles": [{"RoleName": "AppRole", "Arn": f"arn:aws:iam::{ACCT}:role/AppRole"}]}])
    w(f"{out}/inline_policies/roles/AppRole.json", {"InlinePolicies": {"p": {"Statement": [
        {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue", "lambda:UpdateFunctionCode", "ssm:GetParameter"], "Resource": "*"}]}}})
    w(f"{out}/inline_policies/users/dev.json", {"InlinePolicies": {"p": {"Statement": [
        {"Effect": "Allow", "Action": ["ec2:*"], "Resource": "*"}]}}})

def fake_ec2(session, out):
    w(f"{out}/instances.json", [{"InstanceId": f"i-gen{GEN['n']}", "IamInstanceProfile": {"Arn": f"arn:aws:iam::{ACCT}:instance-profile/AppProfile"},
        "MetadataOptions": {"HttpTokens": "optional"}, "SecurityGroups": [], "State": {"Name": "running"}}])

def fake_sm(session, out):
    w(f"{out}/secrets.json", [{"ARN": f"arn:aws:secretsmanager:eu-west-1:{ACCT}:secret:gen{GEN['n']}-abc", "Name": f"gen{GEN['n']}"}])

def fake_lambda(session, out):
    w(f"{out}/functions.json", [{"FunctionName": f"fn{GEN['n']}", "FunctionArn": f"arn:aws:lambda:eu-west-1:{ACCT}:function:fn{GEN['n']}",
        "Role": f"arn:aws:iam::{ACCT}:role/AppRole"}])

collectors = ["iam","vpc","sg","ec2","s3","cloudtrail","cloudfront","waf","flowlogs","eks","k8s","secretsmanager","ssm",
              "lambda_","kms","ecs","cloudformation","glue","codebuild","sagemaker","sns","sqs","ecr","rds","dynamodb",
              "apigateway","cognito","ebs","elb","route53"]
special = {"iam": fake_iam, "ec2": fake_ec2, "secretsmanager": fake_sm, "lambda_": fake_lambda}
patches = []
for c in collectors:
    mod = getattr(M, c)
    patches.append(mock.patch.object(mod, "enumerate", special.get(c, lambda *a, **k: None)))

sess = mock.MagicMock()
sess.client.return_value.get_caller_identity.return_value = {"Account": ACCT, "Arn": f"arn:aws:iam::{ACCT}:user/caller", "UserId": "X"}
patches += [mock.patch.object(M, "get_boto3_session", return_value=sess),
            mock.patch.object(M, "get_enabled_regions", return_value=["eu-west-1"])]

calls = []
real_analyze = PP.analyze
def spy(path):
    calls.append((path, sorted(os.listdir(os.path.dirname(path)))))
    return real_analyze(path)
patches.append(mock.patch.object(M.policy_parser, "analyze", spy))

def edge_summary(gpath):
    out = {}
    adir = os.path.join(gpath, "analysis")
    for f in sorted(os.listdir(adir)):
        if f.endswith("_relationships.json") and f != "trust_relationships.json":
            d = json.load(open(os.path.join(adir, f)))
            out[f.replace("_relationships.json","")] = [ (e.get("type"), e.get("target")) for e in d.get("edges", [])]
    return out

for p in patches: p.start()
import io, contextlib
sys.argv = ["aws-enumerator", "--all"]
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    M.main()
from datetime import datetime
acct_path = os.path.join("reports", datetime.now().strftime("%Y%m%d"), ACCT)
gpath = os.path.join(acct_path, "global")
print("RUN1 analyze calls (path, siblings at call time):", calls)
print("RUN1 edges:", {k: len(v) for k, v in edge_summary(gpath).items()})
print("RUN1 region files present after run:", sorted(os.listdir(os.path.join(acct_path, "eu-west-1"))))

# Run 2 same day: regional data changes (gen2)
GEN["n"] = 2; calls.clear()
with contextlib.redirect_stdout(io.StringIO()):
    M.main()
es = edge_summary(gpath)
print("RUN2 analyze calls:", calls)
print("RUN2 edges:", {k: v for k, v in es.items() if v})
print("RUN2 on-disk instances now:", [i["InstanceId"] for i in json.load(open(os.path.join(acct_path, "eu-west-1/ec2/instances.json")))])
for p in patches: p.stop()

# Re-run analyze after the fact
with contextlib.redirect_stdout(io.StringIO()):
    real_analyze(gpath)
print("POST-HOC analyze edges:", {k: v for k, v in edge_summary(gpath).items() if v})
