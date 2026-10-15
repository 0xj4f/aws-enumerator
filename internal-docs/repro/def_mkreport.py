# Offline guard: fake credentials, no config files, no IMDS, and a dead proxy, so any
# accidental AWS call fails locally instead of reaching a real account.
import os
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_SESSION_TOKEN="testing",
                  AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
                  AWS_EC2_METADATA_DISABLED="true", HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9")
os.environ.pop("AWS_PROFILE", None)
import json, os, sys, shutil
R = sys.argv[1]; quarantine = len(sys.argv) > 2 and sys.argv[2] == "quarantine"
MARK = os.path.join(R, ".synthetic-report")
if os.path.exists(R) and not os.path.exists(MARK):
    sys.exit(f"refusing to overwrite {R}: not a synthetic report made by this script")
shutil.rmtree(R, ignore_errors=True); os.makedirs(R); open(MARK, "w").close()
A = "000000000000"
def w(rel, obj):
    p = os.path.join(R, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
    json.dump(obj, open(p, "w"), indent=1)
arn = lambda kind, n: f"arn:aws:iam::{A}:{kind}/{n}"
users = [{"UserName": u, "Arn": arn("user", u), "AccessKeys":[{"AccessKeyId":"TEST-KEY-ID","Status":"Active","CreateDate":"2019-01-01"}], "MFADevices": [], "HasLoginProfile": True} for u in ["leaked-user", "admin-user"]]
def trust(p): return {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":p,"Action":"sts:AssumeRole"}]}
roles = [
  {"RoleName":"fn-admin-role","Arn":arn("role","fn-admin-role"),"AssumeRolePolicyDocument":trust({"Service":"lambda.amazonaws.com"})},
  {"RoleName":"admin-role","Arn":arn("role","admin-role"),"AssumeRolePolicyDocument":trust({"AWS":arn("user","admin-user")})},
  {"RoleName":"gha-deploy","Arn":arn("role","gha-deploy"),"AssumeRolePolicyDocument":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":f"arn:aws:iam::{A}:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:*"}}}]}},
]
w("iam/users.json", users); w("iam/roles.json", roles); w("iam/groups.json", [{"GroupName":"devs","Arn":arn("group","devs")}])
w("iam/policies.json", [])
w("iam/user_group_memberships.json", {"leaked-user":[{"GroupName":"devs"}], "admin-user":[{"GroupName":"devs"}]})
AA = {"PolicyName":"AdministratorAccess","PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}
w("iam/user_attached_policies.json", {"leaked-user":[], "admin-user":[AA]})
w("iam/role_attached_policies.json", {"fn-admin-role":[AA], "admin-role":[AA], "gha-deploy":[AA]})
w("iam/group_attached_policies.json", {"devs":[]})
w("iam/policy_documents/AdministratorAccess_v1.json", {"PolicyName":"AdministratorAccess","PolicyArn":AA["PolicyArn"],"Document":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}})
stmts = [{"Effect":"Allow","Action":["lambda:UpdateFunctionCode","lambda:GetFunction"],"Resource":"*"},
         {"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::data-bucket","arn:aws:s3:::data-bucket/*"]}]
if quarantine:
    stmts.append({"Effect":"Deny","Action":"*","Resource":"*"})
w("iam/inline_policies/users/leaked-user.json", {"InlinePolicies":{"dev":{"Version":"2012-10-17","Statement":stmts}}})
w("iam/inline_policies/groups/devs.json", {"InlinePolicies":{}})
w("s3/buckets.json", [{"Name":"data-bucket"},{"Name":"other-bucket"}])
w("lambda/functions.json", [{"FunctionName":"etl","FunctionArn":f"arn:aws:lambda:eu-west-2:{A}:function:etl","Role":arn("role","fn-admin-role")}])
