"""The shared resource-policy walker: ``Evaluator.resource_policy_grants`` (F-031; engine.md §2.4, doc-05 A–H).

The decision is per principal: the statement's own conditions, every Deny of the same policy that can apply to
that principal, ``NotPrincipal`` as "everyone except", and the shared strength classifier.
"""

from __future__ import annotations

import pytest

from aws_enumerator.engine.model import Decision, Strength
from aws_enumerator.engine.policy.parse import parse_policy
from aws_enumerator.engine.policy.resource_policy import ResourcePolicyIndex, grants_by_principal, strongest_public

pytestmark = pytest.mark.finding("F-031")

ACCT, OTHER = "111122223333", "999999999999"
TABLE = f"arn:aws:dynamodb:eu-west-2:{ACCT}:table/demo"
BUCKET = "arn:aws:s3:::demo-bucket"


def _grants(kit, statements, resource=TABLE):
    doc = parse_policy({"Statement": statements}, layer="resource", source_type="resource", policy_arn=resource)
    return kit.evaluator().resource_policy_grants(doc, resource)


def _by_kind(grants):
    return {g.principal.kind: g for g in grants}


def pub(action="dynamodb:Query", cond=None, effect="Allow", principal="*"):
    s = {"Effect": effect, "Principal": principal, "Action": action, "Resource": TABLE}
    if cond:
        s["Condition"] = cond
    return s


def test_case_a_request_key_condition_restricts_nobody(kit):
    g = _by_kind(_grants(kit, [pub(cond={"Bool": {"aws:SecureTransport": "true"}})]))
    assert g["anonymous"].decision is Decision.ALLOW and g["wildcard"].decision is Decision.ALLOW


def test_case_b_org_condition_is_a_strong_gate(kit):
    g = _by_kind(_grants(kit, [pub(cond={"StringEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}})]))
    assert "anonymous" not in g                     # no PrincipalOrgID for unsigned callers: never granted
    assert g["wildcard"].decision is Decision.CONDITIONAL and g["wildcard"].strength is Strength.STRONG


def test_case_c_deny_unless_org_blocks_anonymous_and_gates_everyone_else(kit):
    g = _by_kind(_grants(kit, [pub(), pub("dynamodb:*", {"StringNotEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}},
                                          effect="Deny")]))
    assert g["anonymous"].decision is Decision.DENY
    assert g["wildcard"].decision is Decision.CONDITIONAL and g["wildcard"].strength is Strength.STRONG
    assert g["wildcard"].deny_offsets == (1,)


def test_case_d_allow_with_notprincipal_is_public_except_the_listed(kit):
    stmt = {"Effect": "Allow", "NotPrincipal": {"AWS": f"arn:aws:iam::{ACCT}:role/admin"},
            "Action": "dynamodb:Query", "Resource": TABLE}
    grants = _grants(kit, [stmt])
    assert {g.principal.kind for g in grants} == {"anonymous", "wildcard"}
    assert all(g.has_notprincipal and g.decision is Decision.ALLOW for g in grants)


def test_case_e_bare_account_id_is_the_account_root(kit):
    (g,) = _grants(kit, [pub(principal={"AWS": OTHER})])
    assert g.principal.kind == "aws_root" and g.principal.account == OTHER
    assert g.principal.arn == f"arn:aws:iam::{OTHER}:root"


def test_case_f_wildcard_source_arn_is_no_gate(kit):
    g = _by_kind(_grants(kit, [pub(cond={"ArnLike": {"aws:SourceArn": "*"}})]))
    assert g["wildcard"].decision is Decision.CONDITIONAL and g["wildcard"].strength is Strength.NONE


def test_case_g_partial_deny_does_not_remove_the_grant(kit):
    g = _by_kind(_grants(kit, [pub("dynamodb:*"), pub("dynamodb:DeleteTable", effect="Deny")]))
    assert g["wildcard"].decision is Decision.ALLOW
    assert g["wildcard"].deny_offsets == (1,)       # recorded, not applied: it removes only one action


def test_case_h_service_principal_with_source_account(kit):
    stmt = {"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "dynamodb:PutItem",
            "Resource": TABLE, "Condition": {"StringEquals": {"aws:SourceAccount": ACCT}}}
    (g,) = _grants(kit, [stmt])
    assert g.principal.kind == "service" and g.decision is Decision.CONDITIONAL and g.strength is Strength.STRONG


def test_explicit_principal_and_strongest_public(kit):
    grants = _grants(kit, [pub(principal={"AWS": f"arn:aws:iam::{ACCT}:role/app"}),
                           pub(cond={"StringEquals": {"aws:SourceVpce": "vpce-1"}})])
    by = grants_by_principal(grants)
    assert by[f"arn:aws:iam::{ACCT}:role/app"][0].decision is Decision.ALLOW
    best = strongest_public(grants)
    assert best is not None and best.decision is Decision.CONDITIONAL
    assert strongest_public(_grants(kit, [pub(principal={"AWS": OTHER})])) is None


def test_object_children_count_for_bucket_policies(kit):
    stmt = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"{BUCKET}/*"}
    grants = _grants(kit, [stmt], resource=BUCKET)
    assert _by_kind(grants)["anonymous"].decision is Decision.ALLOW


def test_index_status_and_candidates():
    idx = ResourcePolicyIndex(default_owner=ACCT)
    idx.add(BUCKET, {"Statement": []})
    assert idx.status(f"{BUCKET}/k") == "present"            # an object inherits its bucket's policy
    idx.mark_absent("arn:aws:sqs:eu-west-2:111122223333:q")
    assert idx.status("arn:aws:sqs:eu-west-2:111122223333:q") == "absent"
    idx.mark_unknown("arn:aws:sns:eu-west-2:111122223333:t")
    assert idx.status("arn:aws:sns:eu-west-2:111122223333:t") == "unknown"
    assert idx.status("arn:aws:ec2:eu-west-2:111122223333:instance/i-0abc") == "absent"   # no resource policies
    assert idx.status("arn:aws:secretsmanager:eu-west-2:111122223333:secret:x") == "unknown"
    fn = f"arn:aws:lambda:eu-west-2:{ACCT}:function:f"
    idx.add(fn, {"Statement": []})
    assert idx.policy_for(f"{fn}:prod") is not None          # qualified ARN falls back to the function
    assert idx.status(f"arn:aws:iam::{ACCT}:role/r", "trust") == "unknown"
