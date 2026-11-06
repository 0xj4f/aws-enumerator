"""Policy parsing (engine.md §2.1; F-001, F-002, F-014, F-015, F-072)."""

from __future__ import annotations

import json
from urllib.parse import quote

import pytest

from aws_enumerator.engine.policy import parse as P


@pytest.mark.finding("F-002")  # parsing half only (walkers: E-core trust.py, Wave 2 analyzers)
@pytest.mark.parametrize("document", [
    {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}},
    {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]},
    json.dumps({"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}),
    quote(json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})),
])
def test_single_object_list_json_and_url_encoded_documents(document):
    stmts = list(P.iter_statements(document))
    assert len(stmts) == 1 and stmts[0][1]["Action"] == "s3:GetObject"


@pytest.mark.parametrize("document", [None, "", "not json", {"Statement": "x"}, {"Statement": [1, "a"]}, 42])
def test_garbage_documents_yield_nothing(document):
    assert list(P.iter_statements(document)) == []


@pytest.mark.finding("F-001", "F-014", "F-015")
def test_parse_statement_keeps_deny_notaction_notresource_and_conditions():
    doc = {"Statement": [
        {"Sid": "PowerUser", "Effect": "Allow", "NotAction": ["IAM:*", "organizations:*"], "Resource": "*"},
        {"Effect": "Deny", "Action": "s3:*", "NotResource": "arn:aws:s3:::keep/*",
         "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}},
        {"Effect": "Audit", "Action": "*", "Resource": "*"},
    ]}
    pol = P.parse_policy(doc, layer="identity", source_type="inline", policy_name="p")
    assert len(pol.statements) == 2                       # an Effect other than Allow/Deny is ignored
    power, guard = pol.statements
    assert power.actions is None and power.not_actions == ("iam:*", "organizations:*")
    assert power.source.sid == "PowerUser" and power.service_prefixes is None
    assert guard.effect == "Deny" and guard.not_resources == ("arn:aws:s3:::keep/*",)
    assert guard.conditions[0].key == "aws:multifactorauthpresent"
    assert guard.source.statement_index == 1 and guard.service_prefixes == frozenset({"s3"})


@pytest.mark.finding("F-072")
@pytest.mark.parametrize("ptype,raw,kind,account,arn", [
    ("AWS", "999999999999", "aws_root", "999999999999", "arn:aws:iam::999999999999:root"),
    ("AWS", "arn:aws:iam::999999999999:root", "aws_root", "999999999999", "arn:aws:iam::999999999999:root"),
    ("AWS", "arn:aws:iam::111122223333:user/a/b", "aws_user", "111122223333", "arn:aws:iam::111122223333:user/a/b"),
    ("AWS", "arn:aws:sts::111122223333:assumed-role/r/s", "aws_assumed_role", "111122223333",
     "arn:aws:sts::111122223333:assumed-role/r/s"),
    ("AWS", "AROAEXAMPLEDELETEDROLE01", "unique_id", None, None),
    ("AWS", "*", "wildcard", None, None),
    ("Service", "lambda.amazonaws.com", "service", None, None),
    ("Federated", "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com", "federated_oidc",
     "111122223333", "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"),
    ("Federated", "arn:aws:iam::111122223333:saml-provider/demo", "federated_saml", "111122223333",
     "arn:aws:iam::111122223333:saml-provider/demo"),
    ("Federated", "cognito-identity.amazonaws.com", "federated_oidc", None, None),
    ("CanonicalUser", "79a59df900b949e55d96a1e698fbaced", "canonical_user", None, None),
])
def test_parse_principal(ptype, raw, kind, account, arn):
    p = P.parse_principal(ptype, raw)
    assert (p.kind, p.account, p.arn) == (kind, account, arn)


@pytest.mark.finding("F-072", "F-119")
def test_bare_account_uses_the_report_partition():
    assert P.parse_principal("AWS", "999999999999", partition="aws-cn").arn == "arn:aws-cn:iam::999999999999:root"


def test_parse_principals_shapes():
    assert [p.kind for p in P.parse_principals("*")] == ["wildcard"]
    assert [p.kind for p in P.parse_principals({"AWS": ["*", "111122223333"], "Service": "ec2.amazonaws.com"})] == \
        ["wildcard", "aws_root", "service"]
    assert P.parse_principals(None) is None


def test_request_principal():
    assert P.request_principal("svc:lambda.amazonaws.com").kind == "service"
    assert P.request_principal("aws-enumerator:anonymous").kind == "anonymous"
    assert P.request_principal("arn:aws:iam::111122223333:role/x").kind == "aws_role"
    assert P.request_principal("arn:aws:iam::111122223333:oidc-provider/x.example.com").kind == "federated_oidc"


def test_source_type_and_provenance():
    assert P.source_type_for("arn:aws:iam::aws:policy/AdministratorAccess") == "aws_managed"
    assert P.source_type_for("arn:aws-us-gov:iam::aws:policy/ReadOnlyAccess") == "aws_managed"
    assert P.source_type_for("arn:aws:iam::111122223333:policy/x") == "managed"
    pol = P.parse_policy({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}, layer="identity",
                         source_type="managed", policy_arn="arn:aws:iam::111122223333:policy/x", policy_name="x",
                         version_id="v3", via_group="arn:aws:iam::111122223333:group/g")
    src = pol.statements[0].source
    assert (src.policy_arn, src.version_id, src.via_group, src.statement_index) == (
        "arn:aws:iam::111122223333:policy/x", "v3", "arn:aws:iam::111122223333:group/g", 0)


def test_legacy_helpers_unchanged():
    assert P._normalize_to_list("a") == ["a"] and P._normalize_to_list(None) == []
    assert P._extract_statements({"Statement": {"Effect": "Allow", "Action": "x"}}) == [{"Effect": "Allow",
                                                                                          "Action": "x"}]
    assert not hasattr(P, "_extract_principals")                      # d13c215 helper removed (D-53)
