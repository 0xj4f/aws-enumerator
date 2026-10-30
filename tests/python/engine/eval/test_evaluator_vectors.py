"""Table-driven evaluator vectors (engine.md §2, PLAN.md risk mitigation: >= 250 vectors).

Each vector states the policies literally, one request, and the expected :class:`Decision` (plus, where it
matters, the condition strength or the reason). ``doc`` names the AWS documentation concept the vector encodes
(the keys of :data:`DOCS`, each a page of the IAM / KMS / Organizations user guides). Vectors run against a
fresh :class:`~tests.python.engine.eval.conftest.PolicyKit` (local account 111122223333, foreign account
999999999999, reference time 2026-06-01T12:00:00Z).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

import pytest

from aws_enumerator.engine.model import Decision, Strength

ACCT, OTHER = "111122223333", "999999999999"
_UG = "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
DOCS: Dict[str, str] = {
    "pel": _UG + "reference_policies_evaluation-logic.html",
    "pel-account": _UG + "reference_policies_evaluation-logic_policy-eval-basics.html",
    "action": _UG + "reference_policies_elements_action.html",
    "notaction": _UG + "reference_policies_elements_notaction.html",
    "resource": _UG + "reference_policies_elements_resource.html",
    "notresource": _UG + "reference_policies_elements_notresource.html",
    "principal": _UG + "reference_policies_elements_principal.html",
    "notprincipal": _UG + "reference_policies_elements_notprincipal.html",
    "effect": _UG + "reference_policies_elements_effect.html",
    "statement": _UG + "reference_policies_elements_statement.html",
    "condition-ops": _UG + "reference_policies_elements_condition_operators.html",
    "missing-key": _UG + "reference_policies_elements_condition_operators.html#Conditions_IfExists",
    "null": _UG + "reference_policies_elements_condition_operators.html#Conditions_Null",
    "multivalued": _UG + "reference_policies_condition-single-vs-multi-valued-context-keys.html",
    "global-keys": _UG + "reference_policies_condition-keys.html",
    "variables": _UG + "reference_policies_variables.html",
    "boundaries": _UG + "access_policies_boundaries.html",
    "cross-account": _UG + "reference_policies_evaluation-logic-cross-account.html",
    "arn": _UG + "reference-arns.html",
    "passrole": _UG + "id_roles_use_passrole.html",
    "trust": _UG + "id_roles_terms-and-concepts.html",
    "web-identity": _UG + "id_roles_providers_oidc.html",
    "saml": _UG + "id_roles_providers_saml.html",
    "scp": "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html",
    "scp-eval": "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html",
    "rcp": "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html",
    "kms-keypolicy": "https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html",
    "kms-default": "https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html",
    "kms-grants": "https://docs.aws.amazon.com/kms/latest/developerguide/grants.html",
    "kms-aws-managed": "https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#aws-managed-key",
    "s3-bucket-policy": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html",
    "service-linked": _UG + "using-service-linked-roles.html",
}

A, D, C, N = "allow", "deny", "conditional", "not_allowed"
BUCKET = "arn:aws:s3:::demo-bucket"
OBJ = "arn:aws:s3:::demo-bucket/reports/q1.csv"
QUEUE = f"arn:aws:sqs:eu-west-2:{ACCT}:demo-queue"
SECRET = f"arn:aws:secretsmanager:eu-west-2:{ACCT}:secret:demo/db-AbCdEf"
KEY = f"arn:aws:kms:eu-west-2:{ACCT}:key/1234abcd-12ab-34cd-56ef-1234567890ab"
ROLE_T = f"arn:aws:iam::{ACCT}:role/demo-target"
FN = f"arn:aws:lambda:eu-west-2:{ACCT}:function:demo-fn"


def al(action: Any = "*", resource: Any = "*", cond: Optional[Mapping[str, Any]] = None, **kw: Any) -> Dict[str, Any]:
    s: Dict[str, Any] = {"Effect": "Allow", "Action": action, "Resource": resource}
    if cond:
        s["Condition"] = dict(cond)
    s.update(kw)
    if "NotAction" in kw:
        s.pop("Action")
    if "NotResource" in kw:
        s.pop("Resource")
    return s


def dn(action: Any = "*", resource: Any = "*", cond: Optional[Mapping[str, Any]] = None, **kw: Any) -> Dict[str, Any]:
    s = al(action, resource, cond, **kw)
    s["Effect"] = "Deny"
    return s


def rp(principal: Any, action: Any = "*", resource: Any = "*", cond: Optional[Mapping[str, Any]] = None,
       effect: str = "Allow", **kw: Any) -> Dict[str, Any]:
    s = al(action, resource, cond, **kw)
    s["Effect"] = effect
    if principal is not None:
        s["Principal"] = principal
    return s


@dataclass(frozen=True)
class V:
    id: str
    doc: str
    expect: str
    action: str
    resource: str
    identity: Tuple[Mapping[str, Any], ...] = ()
    who: str = "role:dev"                         # role:<n> | user:<n> | ext-role:<n> | ext-root | anon | any | svc:<p>
    boundary: Any = None                          # statements, "missing" or None
    respol: Optional[Tuple[Mapping[str, Any], ...]] = None
    context: Optional[Mapping[str, Any]] = None
    tags: Mapping[str, str] = field(default_factory=dict)
    scp: Optional[Tuple[Tuple[Mapping[str, Any], ...], ...]] = None   # org levels; None = no org model
    rcp: Optional[Tuple[Tuple[Mapping[str, Any], ...], ...]] = None
    management: bool = False
    service_linked: bool = False
    strength: Optional[str] = None
    reason: Optional[str] = None
    gaps: Tuple[str, ...] = ()
    aws_managed_key: bool = False
    grants: Tuple[Tuple[str, Tuple[str, ...]], ...] = ()
    mode: str = "evaluate"                        # evaluate | any | covers | overlaps
    note: str = ""
    pgaps: Tuple[str, ...] = ()                   # principal-model gaps (e.g. iam:tags-unknown)


VECTORS: List[V] = []


def v(*args: Any, **kw: Any) -> None:
    VECTORS.append(V(*args, **kw))


# ── A. basic identity evaluation (pel, action, resource, effect, statement) ──
v("A01", "pel", A, "s3:GetObject", OBJ, (al("s3:GetObject", "*"),))
v("A02", "pel", N, "s3:GetObject", OBJ, (), reason="no_allow", note="implicit deny")
v("A03", "pel", N, "s3:PutObject", OBJ, (al("s3:GetObject"),))
v("A04", "action", A, "s3:GetObject", OBJ, (al("s3:Get*"),))
v("A05", "action", N, "s3:PutObject", OBJ, (al("s3:Get*"),))
v("A06", "action", A, "iam:PassRole", ROLE_T, (al("*"),))
v("A07", "action", A, "S3:GETOBJECT", OBJ, (al("s3:getobject"),), note="actions are case-insensitive")
v("A08", "action", A, "iam:PassRole", ROLE_T, (al("iam:Pass?ole"),))
v("A09", "action", N, "ec2messages:SendReply", "*", (al("ec2:*"),), note="prefix ec2 is not ec2messages")
v("A10", "pel", D, "s3:GetObject", OBJ, (al("*"), dn("s3:GetObject")), reason="explicit_deny")
v("A11", "pel", A, "s3:GetObject", OBJ, (al("*"), dn("s3:PutObject")))
v("A12", "pel", D, "s3:GetObject", OBJ, (al("s3:GetObject"), dn("s3:*")))
v("A13", "pel", D, "s3:GetObject", OBJ, (dn("*"), al("s3:GetObject")), note="statement order is irrelevant")
v("A14", "resource", N, "s3:GetObject", OBJ, (al("s3:GetObject", "arn:aws:s3:::other-bucket/*"),))
v("A15", "resource", A, "s3:GetObject", OBJ, (al("s3:GetObject", "arn:aws:s3:::demo-bucket/*"),))
v("A16", "resource", N, "s3:GetObject", OBJ, (al("s3:GetObject", BUCKET),), note="bucket ARN is not an object ARN")
v("A17", "resource", N, "s3:GetObject", OBJ, (al("s3:GetObject", "arn:aws:s3:::DEMO-BUCKET/*"),),
  note="the resource part of an ARN is case-sensitive")
v("A18", "resource", A, "sqs:SendMessage", QUEUE, (al("sqs:SendMessage", f"arn:aws:sqs:*:{ACCT}:demo-*"),))
v("A19", "resource", A, "sqs:SendMessage", QUEUE, (al("sqs:SendMessage", ["arn:aws:sqs:*:*:x", QUEUE]),))
v("A20", "effect", N, "s3:GetObject", OBJ, ({"Effect": "allow", "Action": "s3:GetObject", "Resource": "*"},),
  note="Effect values are case-sensitive")
v("A21", "action", N, "s3:GetObject", OBJ, (al("s3:Get[O]bject"),), note="IAM has no character classes")
v("A22", "pel", A, "s3:GetObject", OBJ, (al("*"), dn("s3:GetObject", "arn:aws:s3:::other/*")))
v("A23", "resource", A, "sqs:SendMessage", QUEUE, (al("sqs:SendMessage", "arn:aws:sqs:eu-west-?:*:demo-queue"),))
v("A24", "resource", N, "sqs:SendMessage", QUEUE, (al("sqs:SendMessage", f"arn:aws:sqs:us-east-1:{ACCT}:demo-queue"),))
v("A25", "resource", N, "sqs:SendMessage", QUEUE, (al("sqs:SendMessage", f"arn:aws:sqs:eu-west-2:{OTHER}:demo-queue"),))
v("A26", "resource", A, "secretsmanager:GetSecretValue", SECRET,
  (al("secretsmanager:GetSecretValue", f"arn:aws:secretsmanager:*:{ACCT}:secret:demo/*"),))
v("A27", "resource", N, "secretsmanager:GetSecretValue", SECRET,
  (al("secretsmanager:GetSecretValue", f"arn:aws:secretsmanager:*:{ACCT}:secret:DEMO/*"),))
v("A28", "resource", A, "lambda:InvokeFunction", FN, (al("lambda:InvokeFunction", "arn:aws:lambda:*:*:function:*"),))
v("A29", "pel", A, "iam:CreateUser", f"arn:aws:iam::{ACCT}:user/x", (al(["s3:*", "iam:Create*"]),))
v("A30", "pel", D, "iam:CreateUser", f"arn:aws:iam::{ACCT}:user/x", (al("*"), dn(["iam:Create*", "iam:Delete*"])))
v("A31", "resource", A, "s3:ListBucket", BUCKET, (al("s3:ListBucket", "arn:aws:s3:::demo-*"),))
v("A32", "resource", A, "s3:GetObject", OBJ, (al("s3:GetObject", "arn:aws:s3:::demo-bucket/*/q1.csv"),),
  note="* spans '/' in resource patterns")
v("A33", "resource", N, "s3:GetObject", OBJ, (al("s3:GetObject", "arn:aws:s3:::demo-bucket/*/q2.csv"),))
v("A34", "action", A, "iam:PassRole", ROLE_T, (al("iam:*Role"),))
v("A35", "action", N, "iam:PassRoles", ROLE_T, (al("iam:PassRole"),))

# ── B. NotAction ─────────────────────────────────────────────────────────────
POWER = al(NotAction=["iam:*", "organizations:*", "account:*"])
v("B01", "notaction", A, "s3:GetObject", OBJ, (POWER,))
v("B02", "notaction", N, "iam:PassRole", ROLE_T, (POWER,))
v("B03", "notaction", N, "organizations:ListAccounts", "*", (POWER,))
v("B04", "notaction", A, "kms:Decrypt", KEY, (POWER,), respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:root"}, "kms:*"),))
v("B05", "notaction", A, "lambda:UpdateFunctionCode", FN, (POWER,))
v("B06", "notaction", N, "IAM:CreateUser", "*", (POWER,), note="NotAction matching is case-insensitive")
v("B07", "notaction", D, "s3:GetObject", OBJ, (al("*"), dn(NotAction=["iam:Get*", "iam:List*"])),
  note="quarantine shape: Deny everything except IAM reads")
v("B08", "notaction", A, "iam:GetUser", f"arn:aws:iam::{ACCT}:user/x", (al("*"), dn(NotAction=["iam:Get*"])))
v("B09", "notaction", N, "s3:GetObject", OBJ, (al(NotAction="*"),), note="NotAction * matches nothing")
v("B10", "notaction", A, "s3:GetObject", OBJ, (al("*"), dn(NotAction="*")))
v("B11", "notaction", A, "s3:GetObject", OBJ, (al(NotAction="iam:*", Resource=OBJ),))
v("B12", "notaction", N, "s3:GetObject", OBJ, (al(NotAction="iam:*", Resource="arn:aws:s3:::x/*"),))
v("B13", "notaction", N, "s3:PutObject", OBJ, (al(NotAction=["s3:Put*", "iam:*"]),))
v("B14", "notaction", A, "s3:GetObject", OBJ, (al(NotAction=["s3:Put*"]),))
v("B15", "notaction", N, "sts:AssumeRole", ROLE_T, (al(NotAction="sts:*"),))
v("B16", "notaction", A, "sts:AssumeRole", ROLE_T, (POWER,), respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:root"},
  "sts:AssumeRole"),))

# ── C. NotResource ───────────────────────────────────────────────────────────
STAR_NR = al("*", NotResource=["arn:aws:s3:::demo-bucket/*"])
v("C01", "notresource", A, "s3:PutBucketPolicy", BUCKET, (STAR_NR,), note="bucket ARN is not excluded")
v("C02", "notresource", N, "s3:GetObject", OBJ, (STAR_NR,))
v("C03", "notresource", A, "s3:GetObject", "arn:aws:s3:::other/k", (STAR_NR,))
v("C04", "notresource", A, "iam:PassRole", ROLE_T, (al("iam:*", NotResource=f"arn:aws:iam::{ACCT}:role/breakglass"),))
v("C05", "notresource", N, "iam:PassRole", f"arn:aws:iam::{ACCT}:role/breakglass",
  (al("iam:*", NotResource=f"arn:aws:iam::{ACCT}:role/breakglass"),))
v("C06", "notresource", D, "s3:GetObject", "arn:aws:s3:::other/k", (al("*"), dn("s3:*",
  NotResource="arn:aws:s3:::demo-bucket*")),
  note="Deny everything except the listed resources")
v("C07", "notresource", A, "s3:GetObject", OBJ, (al("*"), dn("s3:*", NotResource="arn:aws:s3:::demo-bucket*")))
v("C08", "notresource", N, "sqs:SendMessage", QUEUE, (al("sqs:*", NotResource="arn:aws:sqs:*:*:demo-*"),))
v("C09", "notresource", A, "sqs:SendMessage", QUEUE, (al("sqs:*", NotResource="arn:aws:sqs:*:*:prod-*"),))
v("C10", "notresource", A, "s3:GetObject", OBJ, (al(NotAction="iam:*", NotResource="arn:aws:s3:::x/*"),))
v("C11", "notresource", N, "iam:CreateUser", "*", (al(NotAction="iam:*", NotResource="arn:aws:s3:::x/*"),))
v("C12", "notresource", N, "s3:GetObject", OBJ, (al("*", NotResource="*"),))

# ── D. condition operators with known values ─────────────────────────────────
SC = {"aws:SecureTransport": "true"}
v("D01", "condition-ops", A, "s3:GetObject", OBJ, (al("s3:GetObject", "*",
  {"StringEquals": {"aws:UserAgent": "demo"}}),),
  context={"aws:UserAgent": "demo"})
v("D02", "condition-ops", N, "s3:GetObject", OBJ, (al("s3:GetObject", "*",
  {"StringEquals": {"aws:UserAgent": "demo"}}),),
  context={"aws:UserAgent": "other"})
v("D03", "condition-ops", A, "s3:GetObject", OBJ, (al("s3:GetObject", "*",
  {"StringNotEquals": {"aws:UserAgent": "bad"}}),),
  context={"aws:UserAgent": "good"})
v("D04", "condition-ops", N, "s3:GetObject", OBJ, (al("s3:GetObject", "*",
  {"StringNotEquals": {"aws:UserAgent": "bad"}}),),
  context={"aws:UserAgent": "bad"})
v("D05", "condition-ops", A, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"StringEqualsIgnoreCase": {"aws:UserAgent": "DEMO"}}),), context={"aws:UserAgent": "demo"})
v("D06", "condition-ops", N, "s3:GetObject", OBJ, (al("s3:GetObject", "*",
  {"StringEquals": {"aws:UserAgent": "DEMO"}}),),
  context={"aws:UserAgent": "demo"}, note="StringEquals is case-sensitive")
v("D07", "condition-ops", A, "s3:GetObject", OBJ, (al("s3:GetObject", "*",
  {"StringLike": {"aws:UserAgent": "aws-cli/*"}}),),
  context={"aws:UserAgent": "aws-cli/2.15"})
v("D08", "condition-ops", N, "s3:GetObject", OBJ, (al("s3:GetObject", "*",
  {"StringLike": {"aws:UserAgent": "aws-cli/?"}}),),
  context={"aws:UserAgent": "aws-cli/22"})
v("D09", "condition-ops", N, "s3:GetObject", OBJ, (al("s3:GetObject", "*",
  {"StringNotLike": {"aws:UserAgent": "aws-*"}}),),
  context={"aws:UserAgent": "aws-sdk"})
v("D10", "condition-ops", A, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"StringEquals": {"aws:UserAgent": ["a", "b", "demo"]}}),),
  context={"aws:UserAgent": "demo"},
  note="values of one key are ORed")
v("D11", "condition-ops", N, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"StringEquals": {"aws:UserAgent": "demo", "aws:Referer": "x"}}),),
  context={"aws:UserAgent": "demo", "aws:Referer": "y"}, note="keys are ANDed")
v("D12", "condition-ops", N, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"StringEquals": {"aws:UserAgent": "demo"}, "Bool": {"aws:SecureTransport": "true"}}),),
  context={"aws:UserAgent": "demo", "aws:SecureTransport": "false"}, note="operators are ANDed")
v("D13", "condition-ops", A, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"StringEquals": {"aws:UserAgent": "demo"}, "Bool": {"aws:SecureTransport": "true"}}),),
  context={"aws:UserAgent": "demo", "aws:SecureTransport": "true"})
v("D14", "condition-ops", A, "s3:GetObject", OBJ, (al("s3:GetObject", "*",
  {"NumericLessThan": {"s3:max-keys": "10"}}),),
  context={"s3:max-keys": "5"})
v("D15", "condition-ops", N, "s3:GetObject", OBJ, (al("s3:GetObject", "*",
  {"NumericLessThan": {"s3:max-keys": "10"}}),),
  context={"s3:max-keys": "10"})
v("D16", "condition-ops", A, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"NumericGreaterThanEquals": {"s3:max-keys": "10"}}),), context={"s3:max-keys": "10"})
v("D17", "condition-ops", A, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"NumericNotEquals": {"s3:max-keys": "10"}}),), context={"s3:max-keys": "11"})
v("D18", "condition-ops", A, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"DateGreaterThan": {"aws:CurrentTime": "2026-01-01T00:00:00Z"}}),),
  note="evaluated against the report reference time")
v("D19", "condition-ops", C, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"DateGreaterThan": {"aws:CurrentTime": "2027-01-01T00:00:00Z"}}),),
  note="a window that opens in the future is satisfiable later")
v("D20", "condition-ops", N, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"DateLessThan": {"aws:CurrentTime": "2025-01-01T00:00:00Z"}}),),
  note="a window that closed before the report is FALSE")
v("D21", "condition-ops", A, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"DateLessThan": {"aws:EpochTime": "1893456000"}}),), note="epoch seconds")
v("D22", "condition-ops", A, "s3:GetObject", OBJ, (al("s3:GetObject", "*", {"Bool": {"aws:SecureTransport": "true"}}),),
  context=SC)
v("D23", "condition-ops", N, "s3:GetObject", OBJ, (al("s3:GetObject", "*", {"Bool": {"aws:SecureTransport": "true"}}),),
  context={"aws:SecureTransport": "false"})
v("D24", "condition-ops", A, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}),),
  context={"aws:SourceIp": "203.0.113.7"})
v("D25", "condition-ops", N, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}),),
  context={"aws:SourceIp": "198.51.100.7"})
v("D26", "condition-ops", A, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"}}),),
  context={"aws:SourceIp": "198.51.100.7"})
v("D27", "condition-ops", A, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"IpAddress": {"aws:SourceIp": "2001:db8::/32"}}),), context={"aws:SourceIp": "2001:db8::1"})
v("D28", "condition-ops", A, "sqs:SendMessage", QUEUE,
  (al("sqs:SendMessage", "*", {"ArnLike": {"aws:SourceArn": "arn:aws:sns:*:111122223333:demo-*"}}),),
  context={"aws:SourceArn": "arn:aws:sns:eu-west-2:111122223333:demo-topic"})
v("D29", "condition-ops", N, "sqs:SendMessage", QUEUE,
  (al("sqs:SendMessage", "*", {"ArnEquals": {"aws:SourceArn": "arn:aws:sns:eu-west-2:111122223333:demo-topic"}}),),
  context={"aws:SourceArn": "arn:aws:sns:eu-west-2:111122223333:other"})
v("D30", "condition-ops", A, "sqs:SendMessage", QUEUE,
  (al("sqs:SendMessage", "*", {"ArnNotLike": {"aws:SourceArn": "arn:aws:sns:*:999999999999:*"}}),),
  context={"aws:SourceArn": "arn:aws:sns:eu-west-2:111122223333:x"})
v("D31", "condition-ops", A, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"BinaryEquals": {"aws:UserAgent": "QmluYXJ5"}}),), context={"aws:UserAgent": "QmluYXJ5"})
v("D32", "condition-ops", D, "s3:GetObject", OBJ,
  (al("*"), dn("s3:*", "*", {"Bool": {"aws:SecureTransport": "false"}})), context={"aws:SecureTransport": "false"})
v("D33", "condition-ops", A, "s3:GetObject", OBJ,
  (al("*"), dn("s3:*", "*", {"Bool": {"aws:SecureTransport": "false"}})), context=SC)
v("D34", "condition-ops", A, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"StringLike": {"s3:prefix": ["home/", "home/*"]}}),), context={"s3:prefix": "home/x"})
v("D35", "condition-ops", N, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"NumericLessThanEquals": {"s3:max-keys": "abc"}}),), context={"s3:max-keys": "1"},
  note="a non-numeric policy value never matches")

# ── E. missing keys, IfExists, Null ─────────────────────────────────────────
v("E01", "missing-key", N, "s3:GetObject", OBJ, (al("s3:GetObject", "*",
  {"StringEquals": {"aws:SourceVpc": "vpc-1"}}),),
  context={"aws:SourceVpc": None}, note="positive operator on a missing key is false")
v("E02", "missing-key", A, "s3:GetObject", OBJ, (al("s3:GetObject", "*",
  {"StringNotEquals": {"aws:SourceVpc": "vpc-1"}}),),
  context={"aws:SourceVpc": None}, note="negated operator on a missing key is true")
v("E03", "missing-key", A, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"StringEqualsIfExists": {"aws:SourceVpc": "vpc-1"}}),), context={"aws:SourceVpc": None})
v("E04", "missing-key", N, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"StringEqualsIfExists": {"aws:SourceVpc": "vpc-1"}}),), context={"aws:SourceVpc": "vpc-2"})
v("E05", "null", A, "s3:GetObject", OBJ, (al("s3:GetObject", "*", {"Null": {"aws:SourceVpc": "true"}}),),
  context={"aws:SourceVpc": None})
v("E06", "null", N, "s3:GetObject", OBJ, (al("s3:GetObject", "*", {"Null": {"aws:SourceVpc": "false"}}),),
  context={"aws:SourceVpc": None})
v("E07", "null", A, "s3:GetObject", OBJ, (al("s3:GetObject", "*", {"Null": {"aws:SourceVpc": "false"}}),),
  context={"aws:SourceVpc": "vpc-1"})
v("E08", "null", D, "s3:GetObject", OBJ, (al("*"), dn("*", "*", {"Null": {"aws:MultiFactorAuthAge": "true"}})),
  context={"aws:MultiFactorAuthAge": None}, note="deny when MFA age is absent")
v("E09", "missing-key", D, "s3:GetObject", OBJ,
  (al("*"), dn("*", "*", {"NumericGreaterThanIfExists": {"aws:MultiFactorAuthAge": "3600"}})),
  context={"aws:MultiFactorAuthAge": None}, note="...IfExists over a missing key is true: the Deny applies")
v("E10", "missing-key", D, "s3:GetObject", OBJ,
  (al("*"), dn("*", "*", {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}})),
  context={"aws:MultiFactorAuthPresent": None}, note="IfExists makes a missing key true: the deny applies")
v("E11", "missing-key", D, "s3:GetObject", OBJ,
  (al("*"), dn("*", "*", {"StringNotEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}})), who="anon",
  respol=(rp("*", "s3:GetObject"), rp("*", "s3:*", "*", {"StringNotEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}},
                                     effect="Deny")),
  note="anonymous callers have no PrincipalOrgID: the org guard denies them definitely (F-031 case C)")
v("E12", "missing-key", N, "s3:GetObject", OBJ, (al("s3:GetObject", "*", {"StringLike": {"aws:userid": "AIDA*"}}),),
  context={"aws:userid": None})
v("E13", "missing-key", A, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"ArnNotLikeIfExists": {"aws:SourceArn": "arn:aws:sns:*:*:x"}}),),
  context={"aws:SourceArn": None})
v("E14", "missing-key", N, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}),), context={"aws:SourceIp": None})
v("E15", "missing-key", A, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"}}),), context={"aws:SourceIp": None})
v("E16", "missing-key", N, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"DateGreaterThan": {"aws:TokenIssueTime": "2020-01-01T00:00:00Z"}}),),
  context={"aws:TokenIssueTime": None}, note="long-term credentials have no TokenIssueTime")
v("E17", "missing-key", A, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"DateGreaterThanIfExists": {"aws:TokenIssueTime": "2020-01-01T00:00:00Z"}}),),
  context={"aws:TokenIssueTime": None})
v("E18", "null", A, "s3:GetObject", OBJ, (al("s3:GetObject", "*", {"Null": {"aws:TokenIssueTime": ["true",
  "false"]}}),),
  context={"aws:TokenIssueTime": None}, note="Null with both values is a tautology")

# ── F. unknown values, attacker model, strength ──────────────────────────────
v("F01", "condition-ops", C, "s3:GetObject", OBJ, (al("s3:GetObject", "*",
  {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}),),
  strength="strong", note="an unknown source IP gate: conditional, strong")
v("F02", "condition-ops", C, "s3:GetObject", OBJ, (al("s3:GetObject", "*",
  {"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}}),),
  strength="none", note="0.0.0.0/0 restricts nobody")
v("F03", "condition-ops", C, "s3:GetObject", OBJ, (al("s3:GetObject", "*",
  {"IpAddress": {"aws:SourceIp": "10.0.0.0/4"}}),),
  strength="weak", note="a prefix shorter than /8 is weak")
v("F04", "condition-ops", A, "s3:GetObject", OBJ, (al("s3:GetObject", "*", {"Bool": {"aws:SecureTransport": "true"}}),),
  note="request keys are attacker-chosen: an Allow over them is satisfiable")
v("F05", "condition-ops", A, "s3:GetObject", OBJ, (al("*"), dn("*", "*", {"Bool": {"aws:SecureTransport": "false"}})),
  note="request keys are attacker-chosen: a Deny over them is avoidable")
v("F06", "condition-ops", D, "s3:GetObject", OBJ, (al("*"), dn("*", "*", {"StringLike": {"aws:RequestedRegion": "*"}})),
  note="a tautology over an always-present key cannot be avoided")
v("F07", "condition-ops", C, "s3:GetObject", OBJ, (al("s3:GetObject", "*",
  {"Bool": {"aws:MultiFactorAuthPresent": "true"}}),),
  strength="weak", note="MFA is a session property: conditional, weak (F-015)")
v("F08", "condition-ops", C, "iam:PassRole", ROLE_T,
  (al("iam:PassRole", "*", {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}),), strength="strong",
  note="PassedToService not probed: conditional, strong")
v("F09", "passrole", A, "iam:PassRole", ROLE_T,
  (al("iam:PassRole", "*", {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}),),
  context={"iam:PassedToService": "ec2.amazonaws.com"})
v("F10", "passrole", N, "iam:PassRole", ROLE_T,
  (al("iam:PassRole", "*", {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}),),
  context={"iam:PassedToService": "lambda.amazonaws.com"}, note="F-015")
v("F11", "condition-ops", C, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"StringEquals": {"aws:ResourceTag/team": "red"}}),), strength="weak",
  note="resource tags were not collected")
v("F12", "condition-ops", C, "s3:GetObject", OBJ, (al("s3:GetObject", "*", {"StringEquals": {"demo:customKey": "x"}}),),
  strength="weak", note="unknown keys are conservative (weak)")
v("F13", "condition-ops", C, "s3:GetObject", OBJ,
  (al("*"), dn("*", "*", {"StringNotEquals": {"aws:SourceVpce": "vpce-1a2b"}})), strength="strong",
  note="a conditional deny leaves a conditional allow")
v("F14", "condition-ops", C, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"StringEquals": {"aws:SourceVpc": "vpc-1"}}),), strength="strong")
v("F15", "condition-ops", C, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"StringNotEquals": {"aws:SourceVpc": "vpc-1"}}),), strength="none",
  note="an exclusion gate restricts nobody in particular")
v("F16", "condition-ops", C, "sts:AssumeRole", ROLE_T, (al("sts:AssumeRole", "*",
  {"StringEquals": {"sts:ExternalId": "x"}}),),
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:root"}, "sts:AssumeRole"),), strength="weak")
v("F17", "condition-ops", C, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"Bool": {"aws:MultiFactorAuthPresent": "true"},
                             "IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}),), strength="strong",
  note="an Allow needs every gate: the strongest counts")
v("F18", "condition-ops", A, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"StringEqualsIfExists": {"aws:SourceVpc": "vpc-1"}}),),
  context={"aws:SourceVpc": None}, note="IfExists over an omitted network key")
v("F19", "condition-ops", C, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"StringEqualsIfExists": {"aws:SourceVpc": "vpc-1"}}),), strength="none",
  note="IfExists over a key the attacker can omit: no gate")
v("F20", "condition-ops", C, "s3:GetObject", OBJ,
  (al("s3:GetObject", "*", {"ForAnyValue:StringEquals": {"aws:CalledVia": "athena.amazonaws.com"}}),), strength="weak")

# ── G. multivalued keys (ForAllValues / ForAnyValue) ─────────────────────────
TK = "aws:TagKeys"
v("G01", "multivalued", A, "ec2:CreateTags", "*", (al("ec2:CreateTags", "*",
  {"ForAllValues:StringEquals": {TK: ["env", "team"]}}),),
  context={TK: ("env",)})
v("G02", "multivalued", N, "ec2:CreateTags", "*", (al("ec2:CreateTags", "*",
  {"ForAllValues:StringEquals": {TK: ["env", "team"]}}),),
  context={TK: ("env", "owner")})
v("G03", "multivalued", A, "ec2:CreateTags", "*", (al("ec2:CreateTags", "*",
  {"ForAllValues:StringEquals": {TK: ["env"]}}),),
  context={TK: None}, note="ForAllValues over a missing key is true")
v("G04", "multivalued", A, "ec2:CreateTags", "*", (al("ec2:CreateTags", "*",
  {"ForAnyValue:StringEquals": {TK: ["env"]}}),),
  context={TK: ("env", "owner")})
v("G05", "multivalued", N, "ec2:CreateTags", "*", (al("ec2:CreateTags", "*",
  {"ForAnyValue:StringEquals": {TK: ["env"]}}),),
  context={TK: ("owner",)})
v("G06", "multivalued", N, "ec2:CreateTags", "*", (al("ec2:CreateTags", "*",
  {"ForAnyValue:StringEquals": {TK: ["env"]}}),),
  context={TK: None}, note="ForAnyValue over a missing key is false")
v("G07", "multivalued", A, "ec2:CreateTags", "*", (al("ec2:CreateTags", "*",
  {"ForAllValues:StringLike": {TK: ["team-*"]}}),),
  context={TK: ("team-a", "team-b")})
v("G08", "multivalued", N, "ec2:CreateTags", "*", (al("ec2:CreateTags", "*",
  {"ForAllValues:StringLike": {TK: ["team-*"]}}),),
  context={TK: ("team-a", "env")})
v("G09", "multivalued", D, "ec2:CreateTags", "*",
  (al("*"), dn("ec2:CreateTags", "*", {"ForAnyValue:StringEquals": {TK: ["owner"]}})), context={TK: ("env", "owner")})
v("G10", "multivalued", A, "ec2:CreateTags", "*",
  (al("*"), dn("ec2:CreateTags", "*", {"ForAnyValue:StringEquals": {TK: ["owner"]}})), context={TK: ("env",)})
v("G11", "multivalued", A, "ec2:CreateTags", "*",
  (al("ec2:CreateTags", "*", {"ForAllValues:StringNotEquals": {TK: ["owner"]}}),), context={TK: ("env", "team")})
v("G12", "multivalued", N, "ec2:CreateTags", "*",
  (al("ec2:CreateTags", "*", {"ForAllValues:StringNotEquals": {TK: ["owner"]}}),), context={TK: ("env", "owner")})
v("G13", "multivalued", A, "ec2:CreateTags", "*", (al("ec2:CreateTags", "*",
  {"ForAnyValue:StringLike": {TK: ["t*"]}}),),
  context={TK: ("env", "team")})

# ── H. policy variables ──────────────────────────────────────────────────────
SELF = f"arn:aws:iam::{ACCT}:user/${{aws:username}}"
v("H01", "variables", A, "iam:CreateAccessKey", f"arn:aws:iam::{ACCT}:user/alice", (al("iam:CreateAccessKey", SELF),),
  who="user:alice", note="self-scoped resource (F-017)")
v("H02", "variables", N, "iam:CreateAccessKey", f"arn:aws:iam::{ACCT}:user/bob", (al("iam:CreateAccessKey", SELF),),
  who="user:alice")
v("H03", "variables", N, "iam:CreateAccessKey", f"arn:aws:iam::{ACCT}:user/dev", (al("iam:CreateAccessKey", SELF),),
  who="role:dev", note="roles have no aws:username: the element does not match")
v("H04", "variables", A, "s3:GetObject", "arn:aws:s3:::home/alice/notes.txt",
  (al("s3:GetObject", "arn:aws:s3:::home/${aws:username}/*"),), who="user:alice")
v("H05", "variables", N, "s3:GetObject", "arn:aws:s3:::home/bob/notes.txt",
  (al("s3:GetObject", "arn:aws:s3:::home/${aws:username}/*"),), who="user:alice")
v("H06", "variables", A, "s3:GetObject", "arn:aws:s3:::team/red/x",
  (al("s3:GetObject", "arn:aws:s3:::team/${aws:PrincipalTag/team}/*"),), tags={"team": "red"})
v("H07", "variables", N, "s3:GetObject", "arn:aws:s3:::team/blue/x",
  (al("s3:GetObject", "arn:aws:s3:::team/${aws:PrincipalTag/team}/*"),), tags={"team": "red"})
v("H08", "variables", N, "s3:GetObject", "arn:aws:s3:::team/red/x",
  (al("s3:GetObject", "arn:aws:s3:::team/${aws:PrincipalTag/team}/*"),), note="a tag the principal lacks is absent")
v("H09", "variables", A, "sqs:SendMessage", QUEUE, (al("sqs:SendMessage", "arn:aws:sqs:*:${aws:PrincipalAccount}:*"),))
v("H10", "variables", N, "sqs:SendMessage", f"arn:aws:sqs:eu-west-2:{OTHER}:q",
  (al("sqs:SendMessage", "arn:aws:sqs:*:${aws:PrincipalAccount}:*"),), respol=())
v("H11", "variables", A, "s3:GetObject", "arn:aws:s3:::lit/*/x", (al("s3:GetObject", "arn:aws:s3:::lit/${*}/x"),),
  note="${*} is a literal asterisk")
v("H12", "variables", N, "s3:GetObject", "arn:aws:s3:::lit/abc/x", (al("s3:GetObject", "arn:aws:s3:::lit/${*}/x"),))
v("H13", "variables", A, "s3:GetObject", "arn:aws:s3:::lit/?/x", (al("s3:GetObject", "arn:aws:s3:::lit/${?}/x"),))
v("H14", "variables", A, "s3:GetObject", "arn:aws:s3:::lit/$/x", (al("s3:GetObject", "arn:aws:s3:::lit/${$}/x"),))
v("H15", "variables", A, "s3:GetObject", "arn:aws:s3:::team/none/x",
  (al("s3:GetObject", "arn:aws:s3:::team/${aws:PrincipalTag/team, 'none'}/*"),), note="default value form")
v("H16", "variables", A, "s3:ListBucket", BUCKET,
  (al("s3:ListBucket", BUCKET, {"StringLike": {"s3:prefix": ["home/${aws:username}/*"]}}),), who="user:alice",
  context={"s3:prefix": "home/alice/x"}, note="variables in condition values")
v("H17", "variables", N, "s3:ListBucket", BUCKET,
  (al("s3:ListBucket", BUCKET, {"StringLike": {"s3:prefix": ["home/${aws:username}/*"]}}),), who="user:alice",
  context={"s3:prefix": "home/bob/x"})
v("H18", "variables", C, "s3:GetObject", "arn:aws:s3:::team/red/x",
  (al("s3:GetObject", "arn:aws:s3:::team/${aws:PrincipalTag/team}/*"),),
  gaps=("variable-unresolved:aws:principaltag/team",),
  pgaps=("iam:tags-unknown",), strength="weak", note="tags not collected (legacy layout): unresolved variable")
v("H19", "variables", A, "iam:ChangePassword", f"arn:aws:iam::{ACCT}:user/alice",
  (al("iam:ChangePassword", "arn:aws:iam::*:user/${aws:username}"),), who="user:alice")

# ── I. permissions boundaries ────────────────────────────────────────────────
RO = (al(["s3:Get*", "s3:List*", "ec2:Describe*"]),)
v("I01", "boundaries", A, "s3:GetObject", OBJ, (al("*"),), boundary=RO)
v("I02", "boundaries", N, "s3:PutObject", OBJ, (al("*"),), boundary=RO, reason="boundary")
v("I03", "boundaries", N, "iam:CreateUser", "*", (al("*"),), boundary=RO, reason="boundary")
v("I04", "boundaries", N, "s3:PutObject", OBJ, (al("s3:GetObject"),), boundary=(al("*"),), reason="no_allow",
  note="a boundary never grants")
v("I05", "boundaries", D, "s3:GetObject", OBJ, (al("*"),), boundary=(al("*"), dn("s3:GetObject")))
v("I06", "boundaries", C, "s3:GetObject", OBJ, (al("*"),), boundary="missing", strength="strong",
  gaps=("boundary:doc-missing",), note="boundary document not collected")
v("I07", "boundaries", A, "s3:GetObject", OBJ, (al("s3:GetObject"),), boundary=(al(NotAction="iam:*"),))
v("I08", "boundaries", N, "iam:PassRole", ROLE_T, (al("*"),), boundary=(al(NotAction="iam:*"),))
v("I09", "boundaries", A, "s3:GetObject", OBJ, (), who="user:alice", boundary=RO,
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:user/alice"}, "s3:GetObject"),),
  note="same account: a resource policy naming the user ARN is not limited by the boundary")
v("I10", "boundaries", A, "s3:PutObject", OBJ, (), who="user:alice", boundary=RO,
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:user/alice"}, "s3:PutObject"),),
  note="even for actions outside the boundary (implicit deny in the boundary does not apply)")
v("I11", "boundaries", N, "s3:PutObject", OBJ, (), who="role:dev", boundary=RO,
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:role/dev"}, "s3:PutObject"),),
  note="a resource policy naming the role ARN is limited by the boundary")
v("I12", "boundaries", A, "s3:GetObject", OBJ, (), who="role:dev", boundary=RO,
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:role/dev"}, "s3:GetObject"),))
v("I13", "boundaries", D, "s3:GetObject", OBJ, (), who="user:alice", boundary=(al("*"), dn("s3:*")),
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:user/alice"}, "s3:GetObject"),),
  note="an explicit deny in the boundary still applies")
v("I14", "boundaries", N, "s3:GetObject", OBJ, (al("*"),), boundary=(al("s3:GetObject", "arn:aws:s3:::other/*"),))
v("I15", "boundaries", A, "s3:GetObject", OBJ, (al("*"),), boundary=(al("s3:GetObject", "arn:aws:s3:::demo-*"),))
v("I16", "boundaries", C, "s3:GetObject", OBJ, (al("*"),),
  boundary=(al("s3:*", "*", {"Bool": {"aws:MultiFactorAuthPresent": "true"}}),), strength="weak")
v("I17", "boundaries", N, "s3:GetObject", OBJ, (al("*"),), boundary=(),
  note="an empty boundary allows nothing")

# ── J. service control policies ──────────────────────────────────────────────
FULL = (al("*"),)
v("J01", "scp", A, "s3:GetObject", OBJ, (al("*"),), scp=(FULL, FULL, FULL))
v("J02", "scp", N, "s3:GetObject", OBJ, (al("*"),), scp=(FULL, (al("ec2:*"),), FULL), reason="scp",
  note="every level must allow")
v("J03", "scp", D, "s3:GetObject", OBJ, (al("*"),), scp=(FULL, (al("*"), dn("s3:*")), FULL))
v("J04", "scp", N, "s3:GetObject", OBJ, (), scp=(FULL, FULL, FULL), reason="no_allow", note="an SCP never grants")
v("J05", "scp-eval", A, "s3:GetObject", OBJ, (al("*"),), scp=(FULL, (al("ec2:*"),), FULL), management=True,
  note="SCPs do not apply to the management account")
v("J06", "service-linked", A, "s3:GetObject", OBJ, (al("*"),), scp=(FULL, (al("ec2:*"),), FULL), service_linked=True,
  note="SCPs do not restrict service-linked roles")
v("J07", "scp", A, "s3:GetObject", OBJ, (al("*"),), scp=None, gaps=("org:scp-unknown",),
  note="organisation not collected: a report-level gap, never a downgrade")
v("J08", "scp", N, "iam:CreateUser", "*", (al("*"),), scp=(FULL, (al(NotAction="iam:*"),), FULL), reason="scp")
v("J09", "scp", A, "s3:GetObject", OBJ, (al("*"),), scp=(FULL, (al(NotAction="iam:*"),), FULL))
v("J10", "scp", D, "s3:GetObject", OBJ, (al("*"),),
  scp=((al("*"), dn("*", "*", {"StringNotEquals": {"aws:RequestedRegion": ["eu-west-2"]}})),),
  context={"aws:RequestedRegion": "us-east-1"}, note="region guard SCP")
v("J11", "scp", A, "s3:GetObject", OBJ, (al("*"),),
  scp=((al("*"), dn("*", "*", {"StringNotEquals": {"aws:RequestedRegion": ["eu-west-2"]}})),),
  context={"aws:RequestedRegion": "eu-west-2"})
v("J12", "scp", A, "s3:GetObject", OBJ, (al("*"),),
  scp=((al("*"), dn("*", "*", {"StringNotEquals": {"aws:RequestedRegion": ["eu-west-2"]}})),),
  note="requested region unknown: attacker picks the allowed region")
v("J13", "scp", N, "s3:GetObject", OBJ, (al("*"),), scp=((al("s3:GetObject", "arn:aws:s3:::other/*"),),), reason="scp")
v("J14", "scp", C, "s3:GetObject", OBJ, (al("*"),),
  scp=((al("*"), dn("*", "*", {"Bool": {"aws:MultiFactorAuthPresent": "false"}})),), strength="weak")
v("J15", "scp", A, "s3:GetObject", OBJ, (al("*"),), scp=((al("*"),), (al("s3:*"), al("ec2:*"))),
  note="within a level one allowing policy suffices")

# ── K. resource control policies ─────────────────────────────────────────────
v("K01", "rcp", D, "s3:GetObject", OBJ, (al("*"),), scp=(FULL,), rcp=((al("*"), dn("s3:*")),))
v("K02", "rcp", A, "s3:GetObject", OBJ, (al("*"),), scp=(FULL,), rcp=((al("*"),),))
v("K03", "rcp", A, "lambda:InvokeFunction", FN, (al("*"),), scp=(FULL,), rcp=((al("*"), dn("*")),),
  note="RCPs only govern supported services (Lambda is not one)")
v("K04", "rcp", N, "s3:GetObject", OBJ, (al("*"),), scp=(FULL,), rcp=((al("sqs:*"),),), reason="rcp")
v("K05", "rcp", D, "s3:GetObject", OBJ, (), who="ext-role:partner", scp=(FULL,),
  rcp=((al("*"), dn("s3:*", "*", {"StringNotEqualsIfExists": {"aws:PrincipalOrgID": "o-exampleorgid"}})),),
  respol=(rp({"AWS": f"arn:aws:iam::{OTHER}:role/partner"}, "s3:GetObject"),),
  context={"aws:PrincipalOrgID": "o-other"},
  note="data perimeter RCP blocks principals of another organisation")
v("K06", "rcp", A, "s3:GetObject", OBJ, (al("*"),), management=True, scp=(FULL,), rcp=((al("*"), dn("s3:*")),),
  note="RCPs do not apply to resources in the management account")
v("K07", "rcp", D, "sqs:SendMessage", QUEUE, (al("*"),), scp=(FULL,), rcp=((al("*"), dn("sqs:SendMessage")),))
v("K08", "rcp", A, "s3:GetObject", OBJ, (), who="svc:cloudtrail.amazonaws.com", scp=(FULL,), rcp=((al("*"),
  dn("s3:*")),),
  respol=(rp({"Service": "cloudtrail.amazonaws.com"}, "s3:GetObject"),),
  note="RCPs do not restrict AWS service principals")

# ── L. cross-account and resource policies ───────────────────────────────────
v("L01", "cross-account", C, "s3:GetObject", OBJ, (), who="ext-role:partner",
  respol=(rp({"AWS": f"arn:aws:iam::{OTHER}:role/partner"}, "s3:GetObject"),), gaps=("external-identity-unknown",),
  note="identity of an external principal is not visible")
v("L02", "cross-account", C, "s3:GetObject", OBJ, (), who="ext-role:partner",
  respol=(rp({"AWS": f"arn:aws:iam::{OTHER}:root"}, "s3:GetObject"),))
v("L03", "principal", C, "s3:GetObject", OBJ, (), who="ext-role:partner", respol=(rp({"AWS": OTHER}, "s3:GetObject"),),
  note="a bare account id is the account root (F-072)")
v("L04", "cross-account", N, "s3:GetObject", OBJ, (), who="ext-role:partner",
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:root"}, "s3:GetObject"),), reason="resource_policy")
v("L05", "cross-account", N, "s3:GetObject", OBJ, (), who="ext-role:partner", respol=(), reason="resource_policy",
  note="resource collected without a policy: no cross-account access")
v("L06", "cross-account", C, "s3:GetObject", OBJ, (), who="ext-role:partner", gaps=("resource-policy-unknown",),
  note="resource policy not collected")
v("L07", "cross-account", D, "s3:GetObject", OBJ, (), who="ext-role:partner",
  respol=(rp({"AWS": OTHER}, "s3:GetObject"), rp({"AWS": OTHER}, "s3:*", effect="Deny")))
v("L08", "s3-bucket-policy", A, "s3:GetObject", OBJ, (), who="anon", respol=(rp("*", "s3:GetObject"),))
v("L09", "s3-bucket-policy", A, "s3:GetObject", OBJ, (), who="anon", respol=(rp({"AWS": "*"}, "s3:GetObject"),))
v("L10", "s3-bucket-policy", N, "s3:GetObject", OBJ, (), who="anon",
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:root"}, "s3:GetObject"),))
v("L11", "notprincipal", A, "s3:GetObject", OBJ, (), who="anon",
  respol=({"Effect": "Allow", "NotPrincipal": {"AWS": f"arn:aws:iam::{ACCT}:role/admin"}, "Action": "s3:GetObject",
           "Resource": "*"},), note="Allow + NotPrincipal is public except the listed principals")
v("L12", "notprincipal", N, "s3:GetObject", OBJ, (), who="role:admin",
  respol=({"Effect": "Allow", "NotPrincipal": {"AWS": f"arn:aws:iam::{ACCT}:role/admin"}, "Action": "s3:GetObject",
           "Resource": "*"},))
v("L13", "notprincipal", D, "s3:GetObject", OBJ, (al("*"),), who="role:dev",
  respol=({"Effect": "Deny", "NotPrincipal": {"AWS": f"arn:aws:iam::{ACCT}:role/admin"}, "Action": "s3:*",
           "Resource": "*"},))
v("L14", "notprincipal", A, "s3:GetObject", OBJ, (al("*"),), who="role:admin",
  respol=({"Effect": "Deny", "NotPrincipal": {"AWS": f"arn:aws:iam::{ACCT}:role/admin"}, "Action": "s3:*",
           "Resource": "*"},))
v("L15", "pel-account", A, "s3:GetObject", OBJ, (), who="role:dev",
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:role/dev"}, "s3:GetObject"),),
  note="same account: a resource policy naming the principal is sufficient")
v("L16", "pel-account", N, "s3:GetObject", OBJ, (), who="role:dev",
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:root"}, "s3:GetObject"),),
  note="an account-root principal delegates to IAM: the identity policy must allow")
v("L17", "pel-account", A, "s3:GetObject", OBJ, (al("s3:GetObject"),), who="role:dev",
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:root"}, "s3:GetObject"),))
v("L18", "pel-account", D, "s3:GetObject", OBJ, (al("*"),), who="role:dev",
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:role/dev"}, "s3:GetObject", effect="Deny"),))
v("L19", "principal", C, "s3:GetObject", OBJ, (), who="role:dev",
  respol=(rp({"AWS": f"arn:aws:sts::{ACCT}:assumed-role/dev/session-1"}, "s3:GetObject"),), strength="weak",
  note="a policy naming one session of the role: the session name is not known")
v("L20", "cross-account", A, "sqs:SendMessage", f"arn:aws:sqs:eu-west-2:{OTHER}:q", (al("sqs:SendMessage"),),
  who="role:dev",
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:root"}, "sqs:SendMessage"),),
  note="local principal into a foreign resource: identity AND resource policy")
v("L21", "cross-account", N, "sqs:SendMessage", f"arn:aws:sqs:eu-west-2:{OTHER}:q", (), who="role:dev",
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:root"}, "sqs:SendMessage"),))
v("L22", "cross-account", N, "sqs:SendMessage", f"arn:aws:sqs:eu-west-2:{OTHER}:q", (al("sqs:SendMessage"),),
  who="role:dev",
  respol=(), reason="resource_policy")
v("L23", "cross-account", C, "sqs:SendMessage", f"arn:aws:sqs:eu-west-2:{OTHER}:q", (al("sqs:SendMessage"),),
  who="role:dev",
  gaps=("resource-policy-unknown",))
v("L24", "s3-bucket-policy", C, "s3:GetObject", OBJ, (), who="any",
  respol=(rp("*", "s3:GetObject", "*", {"StringEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}}),), strength="strong",
  note="any AWS principal, guarded by the organisation id")
v("L25", "s3-bucket-policy", N, "s3:GetObject", OBJ, (), who="anon",
  respol=(rp("*", "s3:GetObject", "*", {"StringEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}}),),
  note="anonymous callers have no organisation")
v("L26", "s3-bucket-policy", A, "s3:GetObject", OBJ, (), who="anon",
  respol=(rp("*", "s3:GetObject", "*", {"Bool": {"aws:SecureTransport": "true"}}),),
  note="a request-key condition restricts nobody (F-031 case A)")
v("L27", "s3-bucket-policy", C, "s3:GetObject", OBJ, (), who="anon",
  respol=(rp("*", "s3:GetObject", "*", {"ArnLike": {"aws:SourceArn": "*"}}),), strength="none",
  note="F-031 case F: a wildcard SourceArn admits a request from any service in any account (no gate)")
v("L28", "s3-bucket-policy", N, "s3:GetObject", OBJ, (), who="svc:logging.s3.amazonaws.com",
  respol=(rp({"Service": "cloudtrail.amazonaws.com"}, "s3:GetObject"),))
v("L29", "s3-bucket-policy", A, "s3:PutObject", OBJ, (), who="svc:logging.s3.amazonaws.com",
  respol=(rp({"Service": "logging.s3.amazonaws.com"}, "s3:PutObject"),))
v("L30", "resource", A, "s3:GetObject", OBJ, (), who="role:dev",
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:role/dev"}, "s3:GetObject", "arn:aws:s3:::demo-bucket/reports/*"),))
v("L31", "resource", N, "s3:GetObject", OBJ, (), who="role:dev",
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:role/dev"}, "s3:GetObject", "arn:aws:s3:::demo-bucket/private/*"),))
v("L32", "principal", N, "s3:GetObject", OBJ, (), who="role:dev",
  respol=(rp({"AWS": "AROAEXAMPLEDELETEDROLE"}, "s3:GetObject"),),
  note="a unique id (deleted principal) never matches")

# ── M. KMS ───────────────────────────────────────────────────────────────────
ROOT_DELEGATION = rp({"AWS": f"arn:aws:iam::{ACCT}:root"}, "kms:*")
v("M01", "kms-default", A, "kms:Decrypt", KEY, (al("kms:Decrypt"),), respol=(ROOT_DELEGATION,))
v("M02", "kms-default", N, "kms:Decrypt", KEY, (), respol=(ROOT_DELEGATION,), note="delegation needs an identity grant")
v("M03", "kms-keypolicy", A, "kms:Decrypt", KEY, (), respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:role/dev"},
  "kms:Decrypt"),),
  note="a key policy naming the principal grants directly")
v("M04", "kms-keypolicy", N, "kms:Decrypt", KEY, (al("kms:Decrypt"),),
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:role/other"}, "kms:Decrypt"),), reason="kms_key_policy",
  note="without account delegation IAM policies cannot grant key access")
v("M05", "kms-keypolicy", D, "kms:Decrypt", KEY, (al("kms:Decrypt"),),
  respol=(ROOT_DELEGATION, rp({"AWS": "*"}, "kms:Decrypt", effect="Deny")))
v("M06", "kms-aws-managed", C, "kms:Decrypt", KEY, (al("kms:Decrypt"),), aws_managed_key=True, strength="strong",
  note="AWS-managed key, policy not collected: usable only via the service")
v("M07", "kms-keypolicy", C, "kms:Decrypt", KEY, (al("kms:Decrypt"),), strength="weak",
  gaps=("kms:key-policy-unknown",),
  note="customer key, policy not collected")
v("M08", "kms-grants", A, "kms:Decrypt", KEY, (), respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:role/other"},
  "kms:Decrypt"),),
  grants=((f"arn:aws:iam::{ACCT}:role/dev", ("Decrypt",)),))
v("M09", "kms-grants", N, "kms:Decrypt", KEY, (), respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:role/other"},
  "kms:Decrypt"),),
  grants=((f"arn:aws:iam::{ACCT}:role/dev", ("Encrypt",)),))
v("M10", "kms-keypolicy", N, "kms:Decrypt", KEY, (al("kms:Decrypt", f"arn:aws:kms:eu-west-2:{ACCT}:alias/demo"),),
  respol=(ROOT_DELEGATION,), reason="no_allow", note="an alias ARN in Resource never authorises the key")
v("M11", "kms-keypolicy", C, "kms:Decrypt", KEY, (), who="ext-role:partner",
  respol=(rp({"AWS": f"arn:aws:iam::{OTHER}:root"}, "kms:Decrypt"),), note="cross-account key use")
v("M12", "kms-keypolicy", N, "kms:Decrypt", KEY, (), who="ext-role:partner", respol=(ROOT_DELEGATION,))
v("M13", "kms-keypolicy", A, "kms:Decrypt", KEY, (al("kms:Decrypt"),),
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:root"}, "kms:*", "*", {"StringEquals": {"kms:CallerAccount": ACCT}}),),
  context={"kms:CallerAccount": ACCT})
v("M14", "kms-keypolicy", C, "kms:Decrypt", KEY, (al("kms:Decrypt"),),
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:root"}, "kms:*", "*",
  {"StringEquals": {"kms:ViaService": "s3.eu-west-2.amazonaws.com"}}),),
  strength="strong")
v("M15", "kms-keypolicy", N, "kms:Decrypt", KEY, (al("kms:*"),), boundary=(al("s3:*"),), respol=(ROOT_DELEGATION,))

# ── N. trust policies and AssumeRole ─────────────────────────────────────────
v("N01", "trust", A, "sts:AssumeRole", ROLE_T, (), who="user:alice",
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:user/alice"}, "sts:AssumeRole"),),
  note="same-account trust naming the caller needs no identity permission")
v("N02", "trust", N, "sts:AssumeRole", ROLE_T, (), who="user:alice",
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:root"}, "sts:AssumeRole"),), note="root trust needs identity sts:AssumeRole")
v("N03", "trust", A, "sts:AssumeRole", ROLE_T, (al("sts:AssumeRole"),), who="user:alice",
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:root"}, "sts:AssumeRole"),))
v("N04", "trust", N, "sts:AssumeRole", ROLE_T, (al("sts:AssumeRole"),), who="user:alice",
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:user/bob"}, "sts:AssumeRole"),), reason="trust_policy")
v("N05", "trust", D, "sts:AssumeRole", ROLE_T, (al("sts:AssumeRole"),), who="user:alice",
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:root"}, "sts:AssumeRole"),
          rp({"AWS": f"arn:aws:iam::{ACCT}:user/alice"}, "sts:AssumeRole", effect="Deny")), note="trust Deny (F-073)")
v("N06", "trust", A, "sts:AssumeRole", ROLE_T, (), who="svc:lambda.amazonaws.com",
  respol=(rp({"Service": "lambda.amazonaws.com"}, "sts:AssumeRole"),))
v("N07", "trust", N, "sts:AssumeRole", ROLE_T, (), who="svc:ec2.amazonaws.com",
  respol=(rp({"Service": "lambda.amazonaws.com"}, "sts:AssumeRole"),))
v("N08", "trust", A, "sts:AssumeRole", ROLE_T, (), who="any", respol=(rp({"AWS": "*"}, "sts:AssumeRole"),),
  note="wildcard trust: any AWS principal")
v("N09", "trust", C, "sts:AssumeRole", ROLE_T, (), who="any",
  respol=(rp({"AWS": "*"}, "sts:AssumeRole", "*", {"StringEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}}),),
  strength="strong")
v("N10", "trust", C, "sts:AssumeRole", ROLE_T, (), who="any",
  respol=(rp({"AWS": "*"}, "sts:AssumeRole", "*", {"StringEquals": {"sts:ExternalId": "abc"}}),), strength="weak")
v("N11", "trust", C, "sts:AssumeRole", ROLE_T, (), who="any",
  respol=(rp({"AWS": "*"}, "sts:AssumeRole", "*", {"StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:*"}}),),
  strength="none", note="a wildcard-account PrincipalArn restricts nobody (F-021)")
v("N12", "trust", C, "sts:AssumeRole", ROLE_T, (), who="ext-root",
  respol=(rp({"AWS": f"arn:aws:iam::{OTHER}:root"}, "sts:AssumeRole"),), gaps=("external-identity-unknown",))
v("N13", "trust", N, "sts:AssumeRole", ROLE_T, (), who="ext-root",
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:root"}, "sts:AssumeRole"),))
v("N14", "web-identity", A, "sts:AssumeRoleWithWebIdentity", ROLE_T, (),
  who="arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com",
  respol=(rp({"Federated": f"arn:aws:iam::{ACCT}:oidc-provider/token.actions.githubusercontent.com"},
             "sts:AssumeRoleWithWebIdentity", "*",
             {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:demo-org/*"}}),),
  context={"token.actions.githubusercontent.com:sub": "repo:demo-org/app:ref:refs/heads/main"})
v("N15", "web-identity", N, "sts:AssumeRoleWithWebIdentity", ROLE_T, (),
  who="arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com",
  respol=(rp({"Federated": f"arn:aws:iam::{ACCT}:oidc-provider/token.actions.githubusercontent.com"},
             "sts:AssumeRoleWithWebIdentity", "*",
             {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:demo-org/*"}}),),
  context={"token.actions.githubusercontent.com:sub": "repo:attacker/x:ref:refs/heads/main"})
v("N16", "web-identity", C, "sts:AssumeRoleWithWebIdentity", ROLE_T, (),
  who="arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com",
  respol=(rp({"Federated": f"arn:aws:iam::{ACCT}:oidc-provider/token.actions.githubusercontent.com"},
             "sts:AssumeRoleWithWebIdentity", "*",
             {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:demo-org/*"}}),),
  strength="weak", note="claims not supplied: conditional on the provider's subject")
v("N17", "saml", A, "sts:AssumeRoleWithSAML", ROLE_T, (), who=f"arn:aws:iam::{ACCT}:saml-provider/demo-idp",
  respol=(rp({"Federated": f"arn:aws:iam::{ACCT}:saml-provider/demo-idp"}, "sts:AssumeRoleWithSAML", "*",
             {"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}}),),
  context={"SAML:aud": "https://signin.aws.amazon.com/saml"})
v("N18", "trust", C, "sts:AssumeRole", ROLE_T, (al("sts:AssumeRole"),), who="user:alice", gaps=("trust:unknown",),
  note="trust policy not collected")
v("N19", "trust", A, "sts:AssumeRole", ROLE_T, (), who="role:dev",
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:role/dev"}, "sts:AssumeRole"),), note="role chaining")
v("N20", "boundaries", N, "sts:AssumeRole", ROLE_T, (), who="role:dev", boundary=(al("s3:*"),),
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:role/dev"}, "sts:AssumeRole"),),
  note="a trust naming a role ARN is limited by that role's boundary")
v("N21", "trust", A, "sts:AssumeRole", ROLE_T, (), who="user:alice", boundary=(al("s3:*"),),
  respol=(rp({"AWS": f"arn:aws:iam::{ACCT}:user/alice"}, "sts:AssumeRole"),),
  note="a trust naming a user ARN is not limited by the user's boundary")
v("N22", "trust", N, "sts:AssumeRole", ROLE_T, (al("*"),), who="user:alice",
  respol=(rp({"Service": "ec2.amazonaws.com"}, "sts:AssumeRole"),), reason="trust_policy",
  note="identity sts:AssumeRole * alone is not enough: the trust decides (DANGER-005)")

# ── P. partitions and ARNs ───────────────────────────────────────────────────
GOV_OBJ = "arn:aws-us-gov:s3:::gov-bucket/k"
v("P01", "arn", A, "s3:GetObject", GOV_OBJ, (al("s3:GetObject", "arn:aws-us-gov:s3:::gov-bucket/*"),),
  note="GovCloud ARNs match (F-119)")
v("P02", "arn", N, "s3:GetObject", GOV_OBJ, (al("s3:GetObject", "arn:aws:s3:::gov-bucket/*"),),
  note="partitions are compared, never assumed")
v("P03", "arn", A, "s3:GetObject", GOV_OBJ, (al("s3:GetObject", "arn:*:s3:::gov-bucket/*"),))
v("P04", "arn", A, "s3:GetObject", "arn:aws-cn:s3:::cn-bucket/k", (al("s3:GetObject", "arn:aws-cn:s3:::cn-*/*"),))
v("P05", "arn", A, "secretsmanager:GetSecretValue",
  f"arn:aws-us-gov:secretsmanager:us-gov-west-1:{ACCT}:secret:demo-AbCdEf",
  (al("secretsmanager:GetSecretValue", "arn:aws-us-gov:secretsmanager:*:*:secret:demo-*"),))
v("P06", "arn", A, "sqs:SendMessage", QUEUE, (al("sqs:SendMessage", "arn:aws:SQS:EU-WEST-2:111122223333:demo-queue"),),
  note="service and region compare case-insensitively")
v("P07", "arn", N, "sqs:SendMessage", QUEUE, (al("sqs:SendMessage", "arn:aws:sqs:eu-west-2:111122223333:DEMO-QUEUE"),))
v("P08", "arn", A, "ssm:GetParameter", f"arn:aws:ssm:eu-west-2:{ACCT}:parameter/prod/db/password",
  (al("ssm:GetParameter", f"arn:aws:ssm:*:{ACCT}:parameter/prod/*"),))

# ── T. template queries (evaluate_any / evaluate_capability, F-019) ───────────
ROLES_T = f"arn:aws:iam::{ACCT}:role/*"
v("T01", "resource", A, "iam:PassRole", ROLES_T, (al("iam:PassRole", "arn:aws:iam::*:role/*"),), mode="covers",
  note="'every role' via an ARN wildcard counts as unrestricted (F-019)")
v("T02", "resource", A, "iam:PassRole", ROLES_T, (al("iam:PassRole", ROLES_T),), mode="covers")
v("T03", "resource", N, "iam:PassRole", ROLES_T, (al("iam:PassRole", f"arn:aws:iam::{ACCT}:role/app-*"),),
  mode="covers")
v("T04", "resource", A, "iam:PassRole", ROLES_T, (al("iam:PassRole", f"arn:aws:iam::{ACCT}:role/app-*"),),
  mode="overlaps")
v("T05", "resource", A, "secretsmanager:GetSecretValue", f"arn:aws:secretsmanager:*:{ACCT}:secret:*",
  (al("secretsmanager:GetSecretValue", "arn:aws:secretsmanager:*:*:secret:*"),), mode="covers")
v("T06", "resource", A, "kms:Decrypt", f"arn:aws:kms:*:{ACCT}:key/*", (al("kms:Decrypt", "arn:aws:kms:*:*:key/*"),),
  mode="covers")
v("T07", "resource", A, "s3:*", "arn:aws:s3:::*", (al("s3:*", "arn:aws:s3:::*"),), mode="covers")
v("T08", "resource", A, "s3:*", "arn:aws:s3:::*", (al("s3:*", "*"),), mode="covers")
v("T09", "resource", N, "s3:*", "arn:aws:s3:::*", (al("s3:*", "arn:aws:s3:::*/*"),), mode="covers",
  note="objects only is not every bucket")
v("T10", "action", N, "s3:*", "arn:aws:s3:::*", (al("s3:Get*", "*"),), mode="covers")
v("T11", "action", A, "ssm:GetParameters", f"arn:aws:ssm:*:{ACCT}:parameter/*", (al(["ssm:GetParameter",
  "ssm:GetParameters"]),),
  mode="covers", note="concrete SSM read actions count for DANGER-009")
v("T12", "notaction", A, "s3:*", "arn:aws:s3:::*", (al(NotAction=["iam:*", "organizations:*"]),), mode="covers")
v("T13", "notaction", N, "*", "*", (al(NotAction=["iam:*"]),), mode="covers", note="NotAction iam:* is not admin")
v("T14", "pel", D, "*", "*", (al("*"), dn("iam:*")), mode="covers", note="an overlapping Deny breaks 'unrestricted'")
v("T15", "pel", A, "s3:*", "arn:aws:s3:::*", (al("*"), dn("iam:*")), mode="covers")
v("T16", "notresource", N, "*", "*", (al("*", NotResource="arn:aws:s3:::demo/*"),), mode="covers")
v("T17", "notresource", A, "iam:*", f"arn:aws:iam::{ACCT}:*", (al("*", NotResource="arn:aws:s3:::demo/*"),),
  mode="covers")
v("T18", "pel", A, "s3:GetObject", "arn:aws:s3:::demo-bucket/*", (al("s3:GetObject", OBJ),), mode="any",
  note="existential: some object of the bucket is readable")
v("T19", "pel", A, "s3:GetObject", "arn:aws:s3:::demo-bucket/*", (al("s3:GetObject"), dn("s3:GetObject", OBJ)),
  mode="any",
  note="a Deny on one object leaves others (partial deny, a note)")
v("T20", "pel", D, "s3:GetObject", "arn:aws:s3:::demo-bucket/*", (al("s3:GetObject"), dn("s3:GetObject",
  "arn:aws:s3:::demo-*")),
  mode="any", note="a Deny covering the whole template")
v("T21", "pel", N, "s3:GetObject", "arn:aws:s3:::demo-bucket/*", (al("s3:GetObject", "arn:aws:s3:::other/*"),),
  mode="any")
v("T22", "variables", N, "iam:CreateAccessKey", f"arn:aws:iam::{ACCT}:user/~any~", (al("iam:CreateAccessKey", SELF),),
  who="user:alice", note="a self-scoped grant never reaches another user")
v("T23", "pel", C, "iam:PassRole", ROLES_T,
  (al("iam:PassRole", "*", {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}),), mode="covers",
  strength="strong")
v("T24", "boundaries", N, "s3:*", "arn:aws:s3:::*", (al("*"),), boundary=RO, mode="covers",
  note="a capability must also be covered by the boundary")
v("T25", "scp", N, "s3:*", "arn:aws:s3:::*", (al("*"),), scp=(FULL, (al("ec2:*"),), FULL), mode="covers", reason="scp")

# ── runner ───────────────────────────────────────────────────────────────────

def _who(kit: Any, vec: V) -> Any:
    who = vec.who
    kw: Dict[str, Any] = {"boundary": vec.boundary, "tags": vec.tags, "service_linked": vec.service_linked,
                          "gaps": vec.pgaps}
    if who.startswith("role:"):
        return kit.role(who[5:], list(vec.identity), **kw)
    if who.startswith("user:"):
        return kit.user(who[5:], list(vec.identity), **kw)
    if who.startswith("ext-role:"):
        return f"arn:aws:iam::{OTHER}:role/{who[9:]}"
    if who == "any":
        from aws_enumerator.engine.policy.resource_policy import ANY_AWS
        return ANY_AWS
    return {"ext-root": f"arn:aws:iam::{OTHER}:root", "anon": "aws-enumerator:anonymous"}.get(who, who)


def _setup(kit: Any, vec: V) -> Tuple[Any, Any]:
    requester = _who(kit, vec)
    if vec.respol is not None:
        layer = "trust" if vec.action.lower().startswith("sts:assumerole") else (
            "key_policy" if vec.action.lower().startswith("kms:") else "resource")
        if vec.respol:
            kit.resource_policy(vec.resource, list(vec.respol), layer=layer)
        else:
            kit.resources.mark_absent(vec.resource, layer=layer)
    if vec.aws_managed_key:
        kit.resources.set_aws_managed_key(vec.resource)
    for grantee, ops in vec.grants:
        kit.resources.add_kms_grant(vec.resource, grantee, ops)
    if vec.scp is not None:
        kit.org_model(levels=[list(level) for level in vec.scp],
                      rcp_levels=[list(level) for level in vec.rcp] if vec.rcp is not None else None,
                      management=ACCT if vec.management else None)
    return requester, kit.evaluator()


def _decide(ev: Any, requester: Any, vec: V) -> Any:
    from aws_enumerator.engine.model import Capability
    if vec.mode == "evaluate":
        return ev.evaluate(requester, vec.action, vec.resource, context=vec.context)
    if vec.mode == "any":
        return ev.evaluate_any(requester, vec.action, vec.resource, context=vec.context)
    return ev.evaluate_capability(requester, Capability(vec.resource, action_glob=vec.action, mode=vec.mode))


def test_there_are_at_least_250_vectors_each_citing_aws_documentation():
    assert len(VECTORS) >= 250, len(VECTORS)
    ids = [x.id for x in VECTORS]
    assert len(ids) == len(set(ids))
    for x in VECTORS:
        assert x.doc in DOCS and DOCS[x.doc].startswith("https://docs.aws.amazon.com/"), x.id


@pytest.mark.finding("F-001", "F-014", "F-015", "F-017", "F-019", "F-052", "F-072", "F-079", "F-119", "F-126")
@pytest.mark.parametrize("vec", VECTORS, ids=[x.id for x in VECTORS])
def test_vector(vec: V, kit_factory) -> None:
    kit = kit_factory()
    requester, ev = _setup(kit, vec)
    result = _decide(ev, requester, vec)
    assert result.decision.value == vec.expect, (vec.id, vec.note, result)
    if vec.strength is not None:
        assert result.strength is Strength(vec.strength), (vec.id, result.strength, result.condition_notes)
    if vec.reason is not None:
        assert result.reason == vec.reason, (vec.id, result.reason)
    for gap in vec.gaps:
        assert gap in result.gaps or gap in ev.report_gaps(), (vec.id, gap, result.gaps)
    if result.decision is Decision.CONDITIONAL:
        assert result.confidence == "conditional"
    else:
        assert result.strength is Strength.NONE
