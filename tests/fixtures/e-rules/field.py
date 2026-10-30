"""A field-shaped synthetic account for the subsumption KPI (engine.md §3.4; F-018).

The review measured real accounts where 86-96 % of the findings sat on administrator-equivalent principals. This
world has the same shape at a smaller scale: a dozen administrator-equivalent principals (admin roles, admin users,
an admin group with members, full-IAM roles) among about a hundred ordinary ones (application roles, CI roles with
scoped PassRole, developers, PowerUser-style roles), plus functions and instances that make some of the ordinary
principals' escalation paths real. Only placeholder accounts and ``demo-*`` names are used.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import List, Tuple

W = importlib.import_module("tests.fixtures.e-rules.worlds")
rb = W.rb
allow = W.allow

APP_SERVICES = ("lambda.amazonaws.com", "ecs-tasks.amazonaws.com", "ec2.amazonaws.com")
POWER = {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"], "Resource": "*"}


def _admins(w: "W.World") -> List[str]:
    out = [w.admin_role(f"demo-admin-{i}", W.trusts_account()) for i in range(4)]
    out.append(w.admin_role("demo-admin-lambda", W.trusts_service("lambda.amazonaws.com")))
    out.append(w.admin_role("demo-admin-ec2", W.trusts_service("ec2.amazonaws.com")))
    out += [w.admin_user(f"demo-breakglass-{i}", login=True) for i in range(2)]
    out += [w.role(f"demo-iam-operator-{i}", allow("iam:*"), trust=W.trusts_account()) for i in range(2)]
    w.group("demo-platform-admins", attached=[W.ADMIN_POLICY])
    out.append(W.arn("group", "demo-platform-admins"))
    for i in range(4):
        out.append(w.user(f"demo-platform-{i}", groups=["demo-platform-admins"]))
    return out


def _apps(w: "W.World", n: int) -> List[str]:
    out = []
    for i in range(n):
        svc = APP_SERVICES[i % len(APP_SERVICES)]
        out.append(w.role(f"demo-app-{i:02d}",
                          allow(["s3:GetObject", "s3:PutObject"], f"arn:aws:s3:::demo-app-{i:02d}/*"),
                          allow(["dynamodb:GetItem", "dynamodb:PutItem"],
                                f"arn:aws:dynamodb:{W.REGION}:{W.ACCT}:table/demo-app-{i:02d}"),
                          trust=W.trusts_service(svc)))
    return out


def _ci(w: "W.World", n: int) -> List[str]:
    out = []
    for i in range(n):
        app = W.arn("role", f"demo-app-{i:02d}")
        out.append(w.role(f"demo-ci-{i}", allow("iam:PassRole", app),
                          allow(["lambda:CreateFunction", "lambda:UpdateFunctionCode", "lambda:InvokeFunction",
                                 "ecs:RegisterTaskDefinition", "ecs:UpdateService"]),
                          trust=W.trusts_account()))
    out.append(w.role("demo-ci-wide", allow(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]),
                      trust=W.trusts_account()))
    return out


def _developers(w: "W.World", n: int) -> List[str]:
    w.group("demo-developers", allow(["s3:List*", "s3:Get*", "logs:*", "cloudwatch:Get*", "ec2:Describe*"]))
    out = [w.user(f"demo-dev-{i:02d}", groups=["demo-developers"], access_keys=1) for i in range(n)]
    out.append(w.user("demo-dev-keys", allow("iam:CreateAccessKey"), groups=["demo-developers"]))
    out.append(w.user("demo-dev-ssm", allow("ssm:StartSession"), groups=["demo-developers"]))
    out += [w.role(f"demo-power-{i}", POWER, trust=W.trusts_account()) for i in range(3)]
    return out


def build(root: Path) -> Tuple["W.World", List[str]]:
    """The field-shaped world (not yet analysed) and the ids of its administrator-equivalent principals."""
    w = W.World(root)
    admins = _admins(w)
    _apps(w, 60)
    _ci(w, 10)
    _developers(w, 20)
    w.write("lambda/functions.json", [W.lambda_function(f"demo-fn-{i:02d}", W.arn("role", f"demo-app-{i:02d}"))
                                      for i in range(0, 60, 3)]
            + [W.lambda_function("demo-fn-admin", W.arn("role", "demo-admin-lambda"))])
    profile = w.iam.instance_profile("demo-admin-profile", ["demo-admin-ec2"])
    w.write("ec2/instances.json", [rb.ec2_instance("i-0a1b2c3d4e5f60001", account=W.ACCT, region=W.REGION,
                                                   profile=profile)])
    return w, admins
