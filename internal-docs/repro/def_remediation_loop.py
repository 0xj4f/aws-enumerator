"""Apply the tool's own remediation text to a policy and check whether the finding clears."""
# Offline guard: fake credentials, no config files, no IMDS, and a dead proxy, so any
# accidental AWS call fails locally instead of reaching a real account.
import os
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_SESSION_TOKEN="testing",
                  AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
                  AWS_EC2_METADATA_DISABLED="true", HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9")
os.environ.pop("AWS_PROFILE", None)
import sys, json
sys.path.insert(0, '.')
from app.components import policy_parser as p
A = "000000000000"
def run(label, statements):
    users = [{"UserName": "u", "Arn": f"arn:aws:iam::{A}:user/u"}]
    inline = {"users": {"u": {"p": {"Version": "2012-10-17", "Statement": statements}}}, "roles": {}, "groups": {}}
    pm = p._build_permission_map(users, [], {}, {"u": []}, {}, {}, inline, {})
    ids = sorted({f["id"]: f["severity"] for f in p._detect_privesc_paths(pm)}.items())
    rem = {f["id"]: f["remediation"] for f in p._detect_privesc_paths(pm)}
    print(f"{label:58s} -> {ids}")
    return rem
rem = run("BEFORE: iam:PassRole * + ec2:RunInstances",
    [{"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}])
print("   tool says:", rem.get("PRIVESC-015"))
run("AFTER: PassRole scoped to one low-priv role ARN",
    [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": f"arn:aws:iam::{A}:role/app-readonly"},
     {"Effect": "Allow", "Action": "ec2:RunInstances", "Resource": "*"}])
rem = run("BEFORE: iam:CreateAccessKey on *",
    [{"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"}])
print("   tool says:", rem.get("PRIVESC-009"))
run("AFTER: CreateAccessKey on user/${aws:username}",
    [{"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": f"arn:aws:iam::{A}:user/${{aws:username}}"}])
rem = run("BEFORE: iam:CreatePolicyVersion on *",
    [{"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}])
print("   tool says:", rem.get("PRIVESC-001"))
run("AFTER: CreatePolicyVersion on one specific policy ARN",
    [{"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": f"arn:aws:iam::{A}:policy/app-only"}])
