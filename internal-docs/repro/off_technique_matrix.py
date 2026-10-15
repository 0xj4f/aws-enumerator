# Offline guard: fake credentials, no config files, no IMDS, and a dead proxy, so any
# accidental AWS call fails locally instead of reaching a real account.
import os
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_SESSION_TOKEN="testing",
                  AWS_CONFIG_FILE="/dev/null", AWS_SHARED_CREDENTIALS_FILE="/dev/null",
                  AWS_EC2_METADATA_DISABLED="true", HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9")
os.environ.pop("AWS_PROFILE", None)
# Synthetic technique matrix: one role per technique, placeholder identifiers only.
import sys
sys.path.insert(0, '.')
from app.components import policy_parser as pp

ACCT = "123456789012"
def allow(actions, resources="*", cond=None):
    s = {"Effect": "Allow", "Action": actions, "Resource": resources}
    if cond: s["Condition"] = cond
    return s

T = {
 "CreatePolicyVersion":            [allow("iam:CreatePolicyVersion")],
 "SetDefaultPolicyVersion":        [allow("iam:SetDefaultPolicyVersion")],
 "PutRolePolicy (self)":           [allow("iam:PutRolePolicy")],
 "AttachRolePolicy":               [allow("iam:AttachRolePolicy")],
 "CreateAccessKey (other user)":   [allow("iam:CreateAccessKey")],
 "UpdateLoginProfile":             [allow("iam:UpdateLoginProfile")],
 "AddUserToGroup":                 [allow("iam:AddUserToGroup")],
 "UpdateAssumeRolePolicy":         [allow("iam:UpdateAssumeRolePolicy")],
 "Put/DeleteRolePermissionsBoundary":[allow(["iam:DeleteRolePermissionsBoundary","iam:PutRolePermissionsBoundary"])],
 "sts:AssumeRole on *":            [allow("sts:AssumeRole")],
 "sts:AssumeRole on one role ARN": [allow("sts:AssumeRole", f"arn:aws:iam::{ACCT}:role/example-admin")],
 "PassRole+lambda:CreateFunction+Invoke": [allow(["iam:PassRole","lambda:CreateFunction","lambda:InvokeFunction"])],
 "lambda:UpdateFunctionCode alone":[allow("lambda:UpdateFunctionCode")],
 "lambda:UpdateFunctionConfiguration alone":[allow("lambda:UpdateFunctionConfiguration")],
 "PassRole+ec2:RunInstances":      [allow(["iam:PassRole","ec2:RunInstances"])],
 "PassRole+ec2:AssociateIamInstanceProfile":[allow(["iam:PassRole","ec2:AssociateIamInstanceProfile"])],
 "ec2:CreateLaunchTemplateVersion+ModifyLaunchTemplate":[allow(["ec2:CreateLaunchTemplateVersion","ec2:ModifyLaunchTemplate"])],
 "PassRole+autoscaling LC/ASG":    [allow(["iam:PassRole","autoscaling:CreateLaunchConfiguration","autoscaling:CreateAutoScalingGroup"])],
 "PassRole+ec2:RequestSpotInstances":[allow(["iam:PassRole","ec2:RequestSpotInstances"])],
 "ssm:SendCommand alone":          [allow("ssm:SendCommand")],
 "ssm:StartSession alone":         [allow("ssm:StartSession")],
 "PassRole+cloudformation:CreateStack":[allow(["iam:PassRole","cloudformation:CreateStack"])],
 "cloudformation:UpdateStack alone":[allow("cloudformation:UpdateStack")],
 "PassRole+ecs:RunTask":           [allow(["iam:PassRole","ecs:RunTask","ecs:RegisterTaskDefinition"])],
 "PassRole+ecs:RegisterTaskDefinition only":[allow(["iam:PassRole","ecs:RegisterTaskDefinition"])],
 "ecs:ExecuteCommand alone":       [allow("ecs:ExecuteCommand")],
 "PassRole+glue:CreateDevEndpoint":[allow(["iam:PassRole","glue:CreateDevEndpoint"])],
 "glue:UpdateDevEndpoint alone":   [allow("glue:UpdateDevEndpoint")],
 "PassRole+codebuild:CreateProject+StartBuild":[allow(["iam:PassRole","codebuild:CreateProject","codebuild:StartBuild"])],
 "codebuild:StartBuild alone":     [allow("codebuild:StartBuild")],
 "PassRole+sagemaker:CreateNotebookInstance":[allow(["iam:PassRole","sagemaker:CreateNotebookInstance","sagemaker:CreatePresignedNotebookInstanceUrl"])],
 "sagemaker:CreatePresignedNotebookInstanceUrl alone":[allow("sagemaker:CreatePresignedNotebookInstanceUrl")],
 "PassRole+sagemaker:CreateTrainingJob":[allow(["iam:PassRole","sagemaker:CreateTrainingJob"])],
 "PassRole+datapipeline":          [allow(["iam:PassRole","datapipeline:CreatePipeline","datapipeline:PutPipelineDefinition","datapipeline:ActivatePipeline"])],
 "PassRole+ssm:StartAutomationExecution":[allow(["iam:PassRole","ssm:StartAutomationExecution"])],
 "PassRole+states:CreateStateMachine+StartExecution":[allow(["iam:PassRole","states:CreateStateMachine","states:StartExecution"])],
 "PassRole+cognito SetIdentityPoolRoles":[allow(["iam:PassRole","cognito-identity:SetIdentityPoolRoles"])],
 # fidelity probes
 "PowerUser shape (NotAction iam:*)": [{"Effect":"Allow","NotAction":["iam:*","organizations:*","account:*"],"Resource":"*"}],
 "Admin + explicit Deny iam:*":    [allow("*"), {"Effect":"Deny","Action":"iam:*","Resource":"*"}],
 "PassRole PassedToService=ec2 + lambda:CreateFunction":[allow("iam:PassRole","*",{"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}}), allow("lambda:CreateFunction")],
 "PassRole on one low-priv role + ec2:RunInstances":[allow("iam:PassRole", f"arn:aws:iam::{ACCT}:role/example-lowpriv"), allow("ec2:RunInstances")],
 "Self-service keys (${aws:username})":[allow(["iam:CreateAccessKey","iam:UpdateLoginProfile"], f"arn:aws:iam::{ACCT}:user/${{aws:username}}")],
 "GetSecretValue on secret ARN wildcard":[allow("secretsmanager:GetSecretValue", "arn:aws:secretsmanager:*:*:secret:*")],
 "ssm:GetParameters on *":         [allow(["ssm:GetParameter","ssm:GetParameters","ssm:GetParametersByPath"])],
}

for name, stmts in T.items():
    rn = "example-role"
    roles = [{"RoleName": rn, "Arn": f"arn:aws:iam::{ACCT}:role/{rn}", "AssumeRolePolicyDocument": {"Statement": []}}]
    inline = {"users": {}, "roles": {rn: {"p": {"Version": "2012-10-17", "Statement": stmts}}}, "groups": {}}
    pm = pp._build_permission_map([], roles, {}, {}, {}, {}, inline, {})
    pv = sorted({f["id"] for f in pp._detect_privesc_paths(pm)})
    dg = sorted({f["id"] for f in pp._detect_dangerous_permissions(pm)})
    print(f"{name:55s} | privesc={','.join(pv) or '-'} | danger={','.join(dg) or '-'}")
