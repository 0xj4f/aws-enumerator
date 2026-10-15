"""Labelled synthetic micro-benchmark for the IAM half of the engine.

Purely synthetic: placeholder account 123456789012, invented role names.
Ground truth = "principal is admin-equivalent or can escalate to admin".
Purpose: illustrate a precision/recall KPI harness, NOT a representative score.
"""
# Offline guard: fake credentials, no config files, no IMDS, and a dead proxy, so any
# accidental AWS call fails locally instead of reaching a real account.
import os
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_SESSION_TOKEN="testing",
                  AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
                  AWS_EC2_METADATA_DISABLED="true", HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9")
os.environ.pop("AWS_PROFILE", None)
import json, os, sys, tempfile, shutil, io, contextlib
sys.path.insert(0, os.getcwd())
from app.components import policy_parser as pp

ACCT = "123456789012"
TRUST = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}

def doc(*stmts):
    return {"Version": "2012-10-17", "Statement": list(stmts)}

CASES = {
    # name: (ground_truth_positive, inline_policy_doc, extra_role_fields, note)
    "c01-admin": (True, doc({"Effect": "Allow", "Action": "*", "Resource": "*"}), {}, "Action:* on *"),
    "c02-poweruser-notaction": (True, doc({"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"], "Resource": "*"}), {}, "PowerUserAccess shape"),
    "c03-putrolepolicy": (True, doc({"Effect": "Allow", "Action": "iam:PutRolePolicy", "Resource": "*"}), {}, "classic privesc"),
    "c04-attachuserpolicy": (True, doc({"Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"}), {}, "classic privesc"),
    "c05-iam-notresource": (True, doc({"Effect": "Allow", "Action": "iam:*", "NotResource": f"arn:aws:iam::{ACCT}:role/breakglass"}), {}, "iam:* except one role"),
    "c06-quarantined": (False, doc({"Effect": "Allow", "Action": "*", "Resource": "*"}, {"Effect": "Deny", "Action": "*", "Resource": "*"}), {}, "explicit Deny *"),
    "c07-passrole-scoped": (False, doc({"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": f"arn:aws:iam::{ACCT}:role/low-priv-lambda"},
                                        {"Effect": "Allow", "Action": ["lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"}), {}, "PassRole to one low-priv role"),
    "c08-self-service-keys": (False, doc({"Effect": "Allow", "Action": ["iam:CreateAccessKey", "iam:UpdateLoginProfile"], "Resource": f"arn:aws:iam::{ACCT}:user/${{aws:username}}"}), {}, "self-service creds"),
    "c09-boundary-capped": (False, doc({"Effect": "Allow", "Action": "*", "Resource": "*"}),
                            {"PermissionsBoundary": {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}}, "admin capped by read-only boundary"),
    "c10-readonly": (False, doc({"Effect": "Allow", "Action": ["s3:Get*", "s3:List*", "ec2:Describe*"], "Resource": "*"}), {}, "read-only"),
}

def build(tmp):
    iam = os.path.join(tmp, "iam")
    os.makedirs(os.path.join(iam, "inline_policies", "roles"), exist_ok=True)
    roles = []
    for name, (_, d, extra, _) in CASES.items():
        r = {"RoleName": name, "Arn": f"arn:aws:iam::{ACCT}:role/{name}", "AssumeRolePolicyDocument": TRUST}
        r.update(extra)
        roles.append(r)
        with open(os.path.join(iam, "inline_policies", "roles", f"{name}.json"), "w") as f:
            json.dump({"InlinePolicies": {"p": d}}, f)
    with open(os.path.join(iam, "roles.json"), "w") as f:
        json.dump(roles, f)
    for fn in ("users.json",):
        with open(os.path.join(iam, fn), "w") as f:
            json.dump([], f)

def main():
    tmp = tempfile.mkdtemp()
    try:
        build(tmp)
        with contextlib.redirect_stdout(io.StringIO()):
            pp.analyze(tmp)
        findings = json.load(open(os.path.join(tmp, "analysis", "findings.json")))["findings"]
        per = {}
        for f in findings:
            ent = f.get("entity", "")
            per.setdefault(ent.split("/", 1)[-1], []).append(f)
        tp = fp = fn = tn = 0
        rows = []
        for name, (gt, *_rest) in CASES.items():
            fs = per.get(name, [])
            flagged = any(x["severity"] in ("CRITICAL", "HIGH") and x["category"] in ("privilege_escalation", "dangerous_permission") for x in fs)
            if gt and flagged: tp += 1; v = "TP"
            elif gt and not flagged: fn += 1; v = "FN"
            elif not gt and flagged: fp += 1; v = "FP"
            else: tn += 1; v = "TN"
            rows.append((name, gt, len(fs), v))
        for r in rows:
            print(f"{r[0]:26s} truth={'pos' if r[1] else 'neg'} findings={r[2]:3d} -> {r[3]}")
        print(f"TP={tp} FP={fp} FN={fn} TN={tn} precision={tp/(tp+fp):.2f} recall={tp/(tp+fn):.2f} total_findings={len(findings)}")
    finally:
        shutil.rmtree(tmp)

if __name__ == "__main__":
    main()
