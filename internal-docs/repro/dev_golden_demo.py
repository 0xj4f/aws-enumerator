"""Demonstrate that a synthetic golden fixture runs analyze() end-to-end quickly,
and that table-driven / regression tests are cheap. No AWS calls."""
# Offline guard: fake credentials, no config files, no IMDS, and a dead proxy, so any
# accidental AWS call fails locally instead of reaching a real account.
import os
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_SESSION_TOKEN="testing",
                  AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
                  AWS_EC2_METADATA_DISABLED="true", HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9")
os.environ.pop("AWS_PROFILE", None)
import json, os, sys, time, tempfile, shutil, hashlib
sys.path.insert(0, os.getcwd())  # run from the repository root
from app.components import policy_parser as pp

def w(base, rel, data):
    p = os.path.join(base, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
    json.dump(data, open(p, 'w'))

def make_report(root, single_obj_trust=False):
    acct = '111122223333'
    rp = os.path.join(root, 'reports', '20260101', acct, 'eu-west-2')
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{acct}:user/alice"}, "Action": "sts:AssumeRole"}]}
    if single_obj_trust:
        trust["Statement"] = trust["Statement"][0]
    w(rp, 'iam/users.json', [{"UserName": "alice", "Arn": f"arn:aws:iam::{acct}:user/alice"}])
    w(rp, 'iam/roles.json', [{"RoleName": "admin", "Arn": f"arn:aws:iam::{acct}:role/admin", "AssumeRolePolicyDocument": trust},
                             {"RoleName": "app", "Arn": f"arn:aws:iam::{acct}:role/app", "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}}])
    w(rp, 'iam/groups.json', [])
    w(rp, 'iam/role_attached_policies.json', {"admin": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}], "app": []})
    w(rp, 'iam/user_attached_policies.json', {"alice": []})
    w(rp, 'iam/group_attached_policies.json', {})
    w(rp, 'iam/user_group_memberships.json', {"alice": []})
    w(rp, 'iam/policy_documents/AdministratorAccess_v1.json', {"PolicyName": "AdministratorAccess", "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}})
    w(rp, 'iam/inline_policies/users/alice.json', {"InlinePolicies": {"p": {"Statement": [{"Effect": "Allow", "Action": ["ssm:StartSession"], "Resource": "*"}]}}})
    w(rp, 'ec2/instances.json', [{"InstanceId": f"i-{n:04d}", "IamInstanceProfile": {"Arn": f"arn:aws:iam::{acct}:instance-profile/app"}, "MetadataOptions": {"HttpTokens": "required"}} for n in range(3)])
    w(rp, 'iam/instance_profiles.json', [{"InstanceProfileName": "app", "Arn": f"arn:aws:iam::{acct}:instance-profile/app", "Roles": [{"RoleName": "app", "Arn": f"arn:aws:iam::{acct}:role/app"}]}])
    return rp

def digest(rp):
    out = {}
    for f in sorted(os.listdir(os.path.join(rp, 'analysis'))):
        out[f] = hashlib.sha256(open(os.path.join(rp, 'analysis', f), 'rb').read()).hexdigest()[:12]
    return out

tmp = tempfile.mkdtemp()
import io, contextlib
try:
    rp = make_report(tmp)
    t = time.perf_counter()
    with contextlib.redirect_stdout(io.StringIO()):
        pp.analyze(rp)
    dt = time.perf_counter() - t
    files = sorted(os.listdir(os.path.join(rp, 'analysis')))
    ec2 = json.load(open(os.path.join(rp, 'analysis', 'ec2_relationships.json')))
    f = json.load(open(os.path.join(rp, 'analysis', 'findings.json')))['findings']
    print(f"analyze() on synthetic fixture: {dt*1000:.0f} ms, {len(files)} files")
    print("finding ids:", sorted({x['id'] for x in f}))
    conn = [e for e in ec2['edges'] if e['type'] == 'CAN_CONNECT']
    print("CAN_CONNECT edges (alice ssm:StartSession on * over 3 instances):", len(conn), "-> targets", [e['target'] for e in conn])
    print("INSTANCE_ROLE edges:", len([e for e in ec2['edges'] if e['type'] == 'INSTANCE_ROLE']))
    d1 = digest(rp)
    with contextlib.redirect_stdout(io.StringIO()):
        pp.analyze(rp)
    print("re-run byte-identical:", d1 == digest(rp))
    # F-002 regression shape
    tmp2 = tempfile.mkdtemp()
    rp2 = make_report(tmp2, single_obj_trust=True)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            pp.analyze(rp2)
        print("single-object Statement: no exception")
    except Exception as e:
        print("single-object Statement:", type(e).__name__, e, "| files written:", os.listdir(os.path.join(rp2, 'analysis')))
    shutil.rmtree(tmp2)
finally:
    shutil.rmtree(tmp)

# table-driven _action_matches
cases = [("s3:*", "s3:GetObject", True), ("S3:get*", "s3:GetObject", True), ("*", "iam:PassRole", True),
         ("iam:Pass?ole", "iam:PassRole", True), ("s3:Get*", "s3:PutObject", False), ("ec2:*", "ec2messages:SendReply", False)]
for pat, act, exp in cases:
    got = pp._action_matches(pat, act)
    print(f"_action_matches({pat!r}, {act!r}) = {got} {'OK' if got == exp else 'MISMATCH'}")
