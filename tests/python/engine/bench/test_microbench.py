"""Labelled micro-benchmark of the rules (engine.md §3.6; F-011, F-012, F-014, F-016, F-017, F-018, F-069).

``po_microbench.py`` of the review (10 labelled roles; d13c215: precision 0.50, recall 0.80) ported to the v2
pipeline and extended with cases for the Wave 2 techniques and false-positive sources. Each case is its own
synthetic report (so targets of one case never help another), analysed by ``analyze_report``.

A principal is **flagged** when ``graph.json`` has a CRITICAL or HIGH privilege-escalation / dangerous-permission
finding on it (the review's criterion, ADMIN-001 included) or a directed path of definite edges from it to the
account-admin node (a conditional path, e.g. through an admin capped by an uncollected boundary, is not an alarm).
The label is the ground truth: the principal is administrator-equivalent, can become an administrator, or holds
account-wide dangerous power. Gate: precision ≥ 0.85 and recall ≥ 0.90.
"""

from __future__ import annotations

import importlib
from typing import Callable, Dict, Tuple

import pytest

from tests.support import report_builder as rb

W = importlib.import_module("tests.fixtures.e-rules.worlds")
allow, deny = W.allow, W.deny
CATEGORIES = ("privilege_escalation", "dangerous_permission")
LAMBDA_CHAIN = ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]
MFA = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}


def _review_case(name: str) -> Callable[[W.World], str]:
    case = rb.MICROBENCH_CASES[name]

    def build(w: W.World) -> str:
        return w.iam.role(name, rb.MICROBENCH_TRUST, inline={"p": case["doc"]}, extra=case.get("extra"))
    return build


def _fn(role: str) -> Dict:
    return W.lambda_function("demo-fn", role)


def _instance(w: W.World, role_name: str) -> Dict:
    profile = w.iam.instance_profile("demo-profile", [role_name])
    return rb.ec2_instance("i-0a1b2c3d4e5f60001", account=W.ACCT, region=W.REGION, profile=profile)


def e01(w):  # PassRole into a new Lambda function with an admin role
    w.admin_role("demo-fn-admin", W.trusts_service("lambda.amazonaws.com"))
    return w.user("demo-x", allow(LAMBDA_CHAIN))


def e02(w):  # PassRole to a role that can assume an admin role (closure-aware tier)
    admin = w.admin_role("demo-admin", rb.trust({"AWS": W.arn("role", "demo-fn")}))
    w.role("demo-fn", allow("sts:AssumeRole", admin), trust=W.trusts_service("lambda.amazonaws.com"))
    return w.user("demo-x", allow(LAMBDA_CHAIN))


def e03(w):  # AttachRolePolicy + AssumeRole on a low-privilege role (closure)
    w.role("demo-low", allow("s3:ListBucket"), trust=W.trusts_account())
    return w.user("demo-x", allow(["iam:AttachRolePolicy", "sts:AssumeRole"]))


def e04(w):  # CreateAccessKey on an admin user
    victim = w.admin_user("demo-victim")
    return w.user("demo-x", allow("iam:CreateAccessKey", victim))


def e05(w):  # AddUserToGroup into an admin group
    w.group("demo-admins", attached=[W.ADMIN_POLICY])
    return w.user("demo-x", allow("iam:AddUserToGroup", W.arn("group", "demo-admins")))


def e06(w):  # UpdateFunctionCode on a function running as an admin role
    admin = w.admin_role("demo-fn-admin", W.trusts_service("lambda.amazonaws.com"))
    w.write("lambda/functions.json", [_fn(admin)])
    return w.user("demo-x", allow("lambda:UpdateFunctionCode"))


def e07(w):  # ssm:SendCommand on an instance with an admin instance profile
    w.admin_role("demo-ec2-admin", W.trusts_service("ec2.amazonaws.com"))
    w.write("ec2/instances.json", [_instance(w, "demo-ec2-admin")])
    return w.user("demo-x", allow("ssm:SendCommand"))


def e08(w):  # iam:* (full IAM control: administrator-equivalent)
    return w.role("demo-x", allow("iam:*"))


def e09(w):  # member of an admin group
    w.group("demo-admins", attached=[W.ADMIN_POLICY])
    return w.user("demo-x", groups=["demo-admins"])


def e10(w):  # sts:AssumeRole into an admin role that trusts the account
    w.admin_role("demo-admin", W.trusts_account())
    return w.user("demo-x", allow("sts:AssumeRole"))


def e11(w):  # MFA-conditioned admin is still an admin
    return w.user("demo-x", allow("*", "*", MFA))


def e12(w):  # PassRole + EC2 Spot request into an admin instance role (pathfinding ec2-003)
    w.admin_role("demo-ec2-admin", W.trusts_service("ec2.amazonaws.com"))
    w.iam.instance_profile("demo-admin-profile", ["demo-ec2-admin"])
    return w.user("demo-x", allow(["iam:PassRole", "ec2:RequestSpotInstances"]))


def n01(w):  # complete PassRole chain, but no role trusts Lambda (INFO only, F-012)
    w.admin_role("demo-ec2-admin", W.trusts_service("ec2.amazonaws.com"))
    return w.user("demo-x", allow(LAMBDA_CHAIN))


def n02(w):  # PassRole scoped to a low-privilege role (F-012, F-017)
    w.admin_role("demo-fn-admin", W.trusts_service("lambda.amazonaws.com"))
    w.role("demo-fn-low", allow("logs:CreateLogStream"), trust=W.trusts_service("lambda.amazonaws.com"))
    return w.user("demo-x", allow("iam:PassRole", W.arn("role", "demo-fn-low")),
                  allow(["lambda:CreateFunction", "lambda:InvokeFunction"]))


def n03(w):  # PassRole limited to EC2 by iam:PassedToService, Lambda chain (F-015)
    w.admin_role("demo-fn-admin", W.trusts_service("lambda.amazonaws.com"))
    return w.user("demo-x", allow("iam:PassRole", "*", {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}),
                  allow(["lambda:CreateFunction", "lambda:InvokeFunction"]))


def n04(w):  # RegisterTaskDefinition without a way to run it (F-069)
    w.admin_role("demo-task-admin", W.trusts_service("ecs-tasks.amazonaws.com"))
    return w.user("demo-x", allow(["iam:PassRole", "ecs:RegisterTaskDefinition"], "*"))


def n05(w):  # CreateAccessKey on a low-privilege user
    victim = w.user("demo-victim", allow("s3:ListAllMyBuckets"))
    return w.user("demo-x", allow("iam:CreateAccessKey", victim))


def n06(w):  # UpdateFunctionCode on a function whose role is low-privilege
    low = w.role("demo-fn-low", allow("logs:CreateLogStream"), trust=W.trusts_service("lambda.amazonaws.com"))
    w.write("lambda/functions.json", [_fn(low)])
    return w.user("demo-x", allow("lambda:UpdateFunctionCode"))


def n07(w):  # AssumeRole on one low-privilege role
    low = w.role("demo-low", allow("s3:ListBucket"), trust=W.trusts_account())
    return w.user("demo-x", allow("sts:AssumeRole", low))


def n08(w):  # invoke-only on an admin function: invoking does not give its role (F-004)
    admin = w.admin_role("demo-fn-admin", W.trusts_service("lambda.amazonaws.com"))
    w.write("lambda/functions.json", [_fn(admin)])
    return w.user("demo-x", allow("lambda:InvokeFunction"))


def n09(w):  # Step Functions hijack: state machines are not collected (LOW, conditional)
    return w.user("demo-x", allow(["states:UpdateStateMachine", "states:StartExecution"]))


def n10(w):  # self-service credentials on its own user (F-017)
    return w.user("demo-x", allow(["iam:CreateAccessKey", "iam:UpdateLoginProfile"],
                                  f"arn:aws:iam::{W.ACCT}:user/${{aws:username}}"))


#: name -> (builder, ground truth). The first ten are the review's po_microbench cases with its labels.
CASES: Dict[str, Tuple[Callable[[W.World], str], bool]] = {
    **{name: (_review_case(name), c["positive"]) for name, c in rb.MICROBENCH_CASES.items()},
    **{f.__name__: (f, True) for f in (e01, e02, e03, e04, e05, e06, e07, e08, e09, e10, e11, e12)},
    **{f.__name__: (f, False) for f in (n01, n02, n03, n04, n05, n06, n07, n08, n09, n10)},
}


def flagged(out, subject: str) -> bool:
    severe = [f for f in out.graph["findings"] if f.get("category") in CATEGORIES
              and f["severity"] in ("CRITICAL", "HIGH") and f.get("status") == "open"
              and (f["node_id"] == subject or subject in (f.get("affected_members") or ()))]
    return bool(severe) or out.path(subject, definite_only=True) is not None


@pytest.fixture(scope="module")
def results(tmp_path_factory):
    out = {}
    for name, (build, truth) in CASES.items():
        w = W.World(tmp_path_factory.mktemp(name.replace("-", "_")))
        subject = build(w)
        out[name] = (flagged(w.analyze(), subject), truth)
    return out


@pytest.mark.finding("F-011", "F-012", "F-014", "F-016", "F-017", "F-018", "F-069")
def test_microbench_precision_and_recall(results):
    tp = sum(1 for f, t in results.values() if f and t)
    fp = sum(1 for f, t in results.values() if f and not t)
    fn = sum(1 for f, t in results.values() if not f and t)
    precision, recall = tp / (tp + fp), tp / (tp + fn)
    wrong = sorted(n for n, (f, t) in results.items() if f != t)
    assert precision >= 0.85 and recall >= 0.90, (round(precision, 3), round(recall, 3), wrong)


@pytest.mark.finding("F-001", "F-012", "F-014", "F-017", "F-052")
def test_review_cases_reproduce_the_corrected_labels(results):
    """The d13c215 baseline flagged c06-c09 and missed c02 (P 0.50 / R 0.80)."""
    review = {n: results[n][0] for n in rb.MICROBENCH_CASES}
    assert review == {n: c["positive"] for n, c in rb.MICROBENCH_CASES.items()}


def test_the_extended_set_is_balanced():
    assert len(CASES) == 32
    assert sum(1 for _, t in CASES.values() if t) == 17 and sum(1 for _, t in CASES.values() if not t) == 15
