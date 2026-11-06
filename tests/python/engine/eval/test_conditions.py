"""Condition parsing, operators, key classes, policy variables and the shared strength classifier
(engine.md §2.3; F-015, F-021, F-031)."""

from __future__ import annotations

import pytest

from aws_enumerator.engine.model import ABSENT, KeyClass, Known, Strength, Tri, Unknown
from aws_enumerator.engine.policy import conditions as C


def _cond(block):
    (cond,) = C.parse_conditions(block)
    return cond


@pytest.mark.finding("F-015")
@pytest.mark.parametrize("raw,expected", [
    ("StringEquals", ("StringEquals", "", False, False)),
    ("StringNotLikeIfExists", ("StringNotLike", "", True, True)),
    ("ForAnyValue:StringLike", ("StringLike", "ForAnyValue", False, False)),
    ("ForAllValues:ArnNotEqualsIfExists", ("ArnNotEquals", "ForAllValues", True, True)),
    ("Null", ("Null", "", False, False)),
    ("NotIpAddress", ("NotIpAddress", "", False, True)),
    ("bool", ("Bool", "", False, False)),
])
def test_parse_operator(raw, expected):
    assert C.parse_operator(raw) == expected


@pytest.mark.finding("F-015")
def test_parse_conditions_keeps_every_key_lower_cased_and_sorted():
    conds = C.parse_conditions({"Bool": {"aws:MultiFactorAuthPresent": True},
                                "StringEquals": {"iam:PassedToService": ["ec2.amazonaws.com", "lambda.amazonaws.com"]}})
    assert [(c.operator, c.key, c.values) for c in conds] == [
        ("Bool", "aws:multifactorauthpresent", ("true",)),
        ("StringEquals", "iam:passedtoservice", ("ec2.amazonaws.com", "lambda.amazonaws.com"))]
    assert conds[1].key_class is KeyClass.PROBE
    assert C.parse_conditions(None) == () and C.parse_conditions("x") == ()


@pytest.mark.parametrize("key,cls", [
    ("aws:PrincipalOrgID", KeyClass.IDENTITY), ("aws:PrincipalTag/team", KeyClass.IDENTITY),
    ("iam:PassedToService", KeyClass.PROBE), ("kms:ViaService", KeyClass.PROBE),
    ("aws:ResourceTag/env", KeyClass.RESOURCE), ("s3:ExistingObjectTag/x", KeyClass.RESOURCE),
    ("ec2:ResourceTag/x", KeyClass.RESOURCE), ("aws:RequestTag/x", KeyClass.REQUEST),
    ("aws:SecureTransport", KeyClass.REQUEST), ("s3:x-amz-acl", KeyClass.REQUEST),
    ("kms:EncryptionContext:app", KeyClass.REQUEST), ("aws:SourceIp", KeyClass.NETWORK),
    ("aws:SourceVpce", KeyClass.NETWORK), ("aws:SourceArn", KeyClass.SERVICE), ("aws:SourceAccount", KeyClass.SERVICE),
    ("aws:MultiFactorAuthPresent", KeyClass.SESSION), ("sts:ExternalId", KeyClass.SESSION),
    ("saml:aud", KeyClass.SESSION), ("token.actions.githubusercontent.com:sub", KeyClass.SESSION),
    ("aws:CurrentTime", KeyClass.TIME), ("demo:whatever", KeyClass.UNKNOWN),
])
def test_key_classes(key, cls):
    assert C.classify_key(key) is cls


@pytest.mark.parametrize("block,value,expected", [
    ({"StringEquals": {"k:k": "a"}}, Known(("a",)), Tri.TRUE),
    ({"StringEquals": {"k:k": "a"}}, ABSENT, Tri.FALSE),
    ({"StringNotEquals": {"k:k": "a"}}, ABSENT, Tri.TRUE),
    ({"StringEqualsIfExists": {"k:k": "a"}}, ABSENT, Tri.TRUE),
    ({"StringEquals": {"k:k": "a"}}, Unknown(KeyClass.UNKNOWN), Tri.MAYBE),
    ({"Null": {"k:k": "true"}}, ABSENT, Tri.TRUE),
    ({"Null": {"k:k": "true"}}, Known(("x",)), Tri.FALSE),
    ({"Null": {"k:k": "false"}}, Known(("x",)), Tri.TRUE),
    ({"ForAllValues:StringEquals": {"k:k": ["a", "b"]}}, ABSENT, Tri.TRUE),
    ({"ForAnyValue:StringEquals": {"k:k": ["a", "b"]}}, ABSENT, Tri.FALSE),
    ({"ForAllValues:StringEquals": {"k:k": ["a", "b"]}}, Known(("a", "c")), Tri.FALSE),
    ({"ForAnyValue:StringEquals": {"k:k": ["a", "b"]}}, Known(("a", "c")), Tri.TRUE),
    ({"StringNotEquals": {"k:k": ["a", "b"]}}, Known(("c",)), Tri.TRUE),
    ({"StringNotEquals": {"k:k": ["a", "b"]}}, Known(("b",)), Tri.FALSE),
    ({"NumericLessThan": {"k:k": "10"}}, Known(("9.5",)), Tri.TRUE),
    ({"DateLessThan": {"k:k": "2026-01-01T00:00:00Z"}}, Known(("2025-12-31T23:59:59Z",)), Tri.TRUE),
    ({"DateLessThan": {"k:k": "2026-01-01T00:00:00Z"}}, Known(("1767225600",)), Tri.FALSE),
    ({"IpAddress": {"k:k": "10.0.0.0/8"}}, Known(("10.1.2.3",)), Tri.TRUE),
    ({"IpAddress": {"k:k": "10.0.0.0/8"}}, Known(("10.1.0.0/16",)), Tri.TRUE),
    ({"NotIpAddress": {"k:k": "10.0.0.0/8"}}, Known(("192.0.2.1",)), Tri.TRUE),
    ({"ArnLike": {"k:k": "arn:aws:sns:*:*:t-*"}}, Known(("arn:aws:sns:eu-west-2:111122223333:t-1",)), Tri.TRUE),
    ({"Bool": {"k:k": "true"}}, Known(("True",)), Tri.TRUE),
    ({"BogusOperator": {"k:k": "x"}}, Known(("x",)), Tri.MAYBE),
])
def test_cond_eval_truth_table(block, value, expected):
    assert C.cond_eval(_cond(block), value) is expected


@pytest.mark.finding("F-021", "F-031")
@pytest.mark.parametrize("block,effect,expected", [
    (None, "Allow", Strength.NONE),
    ({}, "Allow", Strength.NONE),
    ({"StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:*"}}, "Allow", Strength.NONE),
    ({"StringEquals": {"aws:PrincipalArn": "arn:aws:iam::111122223333:role/x"}}, "Allow", Strength.STRONG),
    ({"StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/deploy"}}, "Allow", Strength.WEAK),
    ({"StringEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}}, "Allow", Strength.STRONG),
    ({"StringEquals": {"aws:PrincipalAccount": "111122223333"}}, "Allow", Strength.STRONG),
    ({"StringEquals": {"aws:SourceAccount": "111122223333"}}, "Allow", Strength.STRONG),
    ({"ArnLike": {"aws:SourceArn": "*"}}, "Allow", Strength.NONE),
    ({"ArnLike": {"aws:SourceArn": "arn:aws:sns:*:*:*"}}, "Allow", Strength.NONE),
    ({"ArnLike": {"aws:SourceArn": "arn:aws:sns:eu-west-2:111122223333:t"}}, "Allow", Strength.STRONG),
    ({"ArnLike": {"aws:SourceArn": "arn:aws:s3:::*"}}, "Allow", Strength.NONE),
    ({"ArnLike": {"aws:SourceArn": "arn:aws:s3:::demo-logs"}}, "Allow", Strength.WEAK),
    ({"StringEquals": {"sts:ExternalId": "x"}}, "Allow", Strength.WEAK),
    ({"Bool": {"aws:SecureTransport": "true"}}, "Allow", Strength.NONE),
    ({"StringEquals": {"aws:UserAgent": "x"}}, "Allow", Strength.NONE),
    ({"StringEquals": {"aws:RequestTag/env": "x"}}, "Allow", Strength.NONE),
    ({"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}}, "Allow", Strength.NONE),
    ({"IpAddress": {"aws:SourceIp": "10.0.0.0/4"}}, "Allow", Strength.WEAK),
    ({"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}, "Allow", Strength.STRONG),
    ({"StringEquals": {"aws:SourceVpce": "vpce-1"}}, "Allow", Strength.STRONG),
    ({"StringEqualsIfExists": {"aws:SourceVpce": "vpce-1"}}, "Allow", Strength.NONE),
    ({"StringNotEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}}, "Allow", Strength.NONE),
    ({"StringNotEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}}, "Deny", Strength.STRONG),
    ({"StringEquals": {"aws:PrincipalOrgID": "o-exampleorgid"}}, "Deny", Strength.NONE),
    ({"Bool": {"aws:PrincipalIsAWSService": "true"}}, "Allow", Strength.STRONG),
    ({"StringEquals": {"aws:PrincipalOrgID": "o-x", "sts:ExternalId": "y"}}, "Allow", Strength.STRONG),
    ({"StringEquals": {"aws:PrincipalOrgID": "o-x"}, "Bool": {"aws:SecureTransport": "false"}}, "Deny",
     Strength.NONE),
    ({"StringEquals": {"demo:custom": "x"}}, "Allow", Strength.WEAK),
])
def test_classify_strength_is_the_shared_helper(block, effect, expected):
    """One classifier for trust, S3 and every resource-policy walker (F-021): it never treats a condition as a
    mitigation just because it exists."""
    assert C.classify_strength(block, effect) is expected


@pytest.mark.finding("F-017")
def test_substitute_variables():
    keys = C.ContextKeys({"aws:username": Known(("alice",)), "aws:principaltag/team": Known(("r*d",))},
                         absent_prefixes=("aws:principaltag/",))
    assert C.substitute_variables("user/${aws:username}", keys).text == "user/alice"
    sub = C.substitute_variables("team/${aws:PrincipalTag/team}/*", keys)
    assert sub.outcome is Tri.TRUE and sub.text.startswith("team/r") and "*" not in sub.text[:-1]
    assert C.substitute_variables("team/${aws:PrincipalTag/missing}", keys).text is None
    assert C.substitute_variables("team/${aws:PrincipalTag/missing, 'none'}", keys).text == "team/none"
    unknown = C.substitute_variables("x/${aws:SourceIdentity}", keys)
    assert unknown.outcome is Tri.MAYBE and unknown.unresolved == ("aws:sourceidentity",) and unknown.text == "x/*"
    assert C.substitute_variables("no-vars", keys).outcome is Tri.TRUE


def test_context_keys_absent_families():
    keys = C.ContextKeys({"a:b": Known(("1",))}, absent_prefixes=("aws:principaltag/",))
    assert keys.get("a:b") == Known(("1",))
    assert keys.get("aws:principaltag/x") is ABSENT
    assert keys.get("other:key") is None
    assert "aws:principaltag/y" in keys and list(keys) == ["a:b"] and len(keys) == 1


def test_request_condition_avoidability():
    assert C.request_condition_avoidable(_cond({"Bool": {"aws:SecureTransport": "false"}}))
    assert not C.request_condition_avoidable(_cond({"StringLike": {"aws:RequestedRegion": "*"}}))
    assert not C.request_condition_avoidable(_cond({"Bool": {"aws:SecureTransport": ["true", "false"]}}))
    assert C.request_condition_avoidable(_cond({"StringLike": {"aws:UserAgent": "*"}}))


def test_dates_and_time_windows():
    assert C.parse_date("2026-01-01T00:00:00Z") == C.parse_date("1767225600")
    assert C.parse_date("garbage") is None
    future = _cond({"DateGreaterThan": {"aws:CurrentTime": "2030-01-01T00:00:00Z"}})
    assert C.is_satisfiable_later(future, C.parse_date("2026-01-01T00:00:00Z"))
    past = _cond({"DateLessThan": {"aws:CurrentTime": "2020-01-01T00:00:00Z"}})
    assert not C.is_satisfiable_later(past, C.parse_date("2026-01-01T00:00:00Z"))
