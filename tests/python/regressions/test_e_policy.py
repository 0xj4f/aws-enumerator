"""Regression tests owned by stream E-policy (evaluator, statement parsing).

xfail-first: each test describes the CORRECT behaviour and is ``xfail(strict=True)`` while the bug is
present. The stream that fixes the finding removes the marker in the same change (AGENT_RULES rule 9).
Analysis runs through ``tests/fixtures/regressions/support.analyze_tree`` (``analyze_report`` once it
exists, else the legacy ``analyze()``) and the assertions read the per-domain legacy files, which the
engine keeps writing for one release (engine-api.md §3.3 ``legacy_outputs``).
"""

from __future__ import annotations

import pytest

from tests.fixtures.regressions import support as S
from tests.support import report_builder as rb

ACCT, R = S.ACCT, S.REGION


# ── F-001: NotAction / NotResource ───────────────────────────────────────────
@pytest.fixture
def poweruser(tmp_path):
    S.build_scenario("poweruser_notaction", tmp_path)
    return S.analyze_tree(tmp_path / ACCT / R)


def _secret_arn():
    return rb.secret("demo/notaction", account=ACCT, region=R)["ARN"]


def _key_arn():
    return rb.kms_key("5e6f7a8b-aaaa-4bbb-8ccc-9c0d1e2f3a4b", account=ACCT, region=R)["Arn"]


def _lambda_arn():
    return f"arn:aws:lambda:{R}:{ACCT}:function:demo-na-fn"


@pytest.mark.finding("F-001")
def test_f001_poweruser_notaction_reaches_the_data_it_really_grants(poweruser):
    """PowerUserAccess (Allow NotAction iam:*, organizations:*, account:* on *) grants s3:*,
    secretsmanager:GetSecretValue, lambda:UpdateFunctionCode and kms:Decrypt."""
    edges = poweruser.edges()
    role = S.iam_arn("role", "demo-poweruser")
    missing = []
    for name, target in (("s3", "demo-notaction-data"), ("secret", _secret_arn()),
                         ("lambda", _lambda_arn()), ("kms", _key_arn())):
        if not S.edges_from(edges, role, target):
            missing.append(name)
    assert missing == [], f"no edge from {role} to: {missing}"
    lam = S.edges_from(edges, role, _lambda_arn())
    assert "CAN_UPDATE_CODE" in {e.get("type") for e in lam}
    # NotAction iam:* means no IAM-based privilege escalation (PRIVESC-001 is iam:CreatePolicyVersion)
    assert not S.findings_for(poweruser.findings(), "PRIVESC-001", role)


@pytest.mark.finding("F-001")
def test_f001_notaction_via_group_reaches_the_bucket(poweruser):
    edges = poweruser.edges("s3")
    user = S.iam_arn("user", "demo-notaction-user")
    group = S.iam_arn("group", "demo-power-group")
    # The engine may emit group capability edges from the group node (MEMBER_OF user -> group).
    assert S.edges_from(edges, user, "demo-notaction-data") or S.edges_from(edges, group, "demo-notaction-data")


@pytest.mark.finding("F-001")
def test_f001_action_star_notresource_still_reaches_the_bucket(poweruser):
    """``Allow * NotResource arn:aws:s3:::demo-notaction-data/*`` excludes the objects, not the bucket:
    bucket-level actions (ListBucket, PutBucketPolicy ...) on ``arn:aws:s3:::demo-notaction-data`` remain."""
    role = S.iam_arn("role", "demo-star-notresource")
    assert S.edges_from(poweruser.edges("s3"), role, "demo-notaction-data")


# ── F-002 (parsing half): single-object Statement ────────────────────────────
WALKERS = ("trust", "s3", "secrets", "lambda", "kms", "sqs", "ecr", "dynamodb")
EXPECTED_FINDING = {"s3": "S3-PUBLIC-001", "secrets": "SECRET-PUB-001", "lambda": "LAMBDA-PUB-001",
                    "kms": "KMS-PUB-001", "sqs": "MSG-PUB-001", "ecr": "ECR-PUB-001", "dynamodb": "DDB-PUB-001"}


def _policy(single: bool, stmt):
    return {"Version": "2012-10-17", "Statement": stmt if single else [stmt]}


def build_single_statement_tree(root, walker: str, single: bool = True):
    """One resource whose policy has ``Statement`` as a single object (valid IAM grammar)."""
    s = rb.Scope(root, ACCT, R)
    iam = rb.Iam(ACCT)
    trust_stmt = {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    iam.role("demo-fn-role", _policy(single and walker == "trust", trust_stmt))
    iam.write(s)

    def pub(action, resource):
        return _policy(single, {"Effect": "Allow", "Principal": "*", "Action": action, "Resource": resource})

    if walker == "s3":
        s.write("s3/buckets.json", [rb.s3_bucket(s, "demo-single-bucket",
                                                 policy=pub("s3:GetObject", "arn:aws:s3:::demo-single-bucket/*"))])
    elif walker == "secrets":
        sec = rb.secret("demo/single", account=ACCT, region=R)
        s.write("secretsmanager/secrets.json", [sec])
        s.write("secretsmanager/resource_policies/demo_single.json",
                {"SecretArn": sec["ARN"], "SecretName": sec["Name"],
                 "ResourcePolicy": pub("secretsmanager:GetSecretValue", "*")})
    elif walker == "lambda":
        fn = rb.lambda_function("demo-single-fn", account=ACCT, region=R, role=iam.arn("role", "demo-fn-role"))
        s.write("lambda/functions.json", [fn])
        s.write("lambda/resource_policies/demo-single-fn.json",
                rb.lambda_policy_file(fn, pub("lambda:InvokeFunction", fn["FunctionArn"])))
    elif walker == "kms":
        key = rb.kms_key("6a7b8c9d-aaaa-4bbb-8ccc-0e1f2a3b4c5d", account=ACCT, region=R)
        s.write("kms/keys.json", [key])
        s.write(f"kms/key_policies/{key['KeyId']}.json", rb.kms_policy_file(key, pub("kms:Decrypt", "*")))
    elif walker == "sqs":
        q = f"arn:aws:sqs:{R}:{ACCT}:demo-single-queue"
        s.write("sqs/resources.json", [rb.policy_resource("sqs", q, "demo-single-queue", pub("sqs:SendMessage", q))])
    elif walker == "ecr":
        a = f"arn:aws:ecr:{R}:{ACCT}:repository/demo-single-repo"
        s.write("ecr/resources.json", [rb.policy_resource("ecr", a, "demo-single-repo",
                                                          pub(["ecr:BatchGetImage"], "*"))])
    elif walker == "dynamodb":
        a = f"arn:aws:dynamodb:{R}:{ACCT}:table/demo-single-table"
        s.write("dynamodb/resources.json", [rb.policy_resource("dynamodb", a, "demo-single-table",
                                                               pub(["dynamodb:Query"], a))])
    return s.path


_F002_XFAIL = pytest.mark.xfail(strict=True, raises=(AttributeError, AssertionError),
                                reason="F-002: iterating a single-object Statement yields its keys ('str' object has "
                                       "no attribute 'get'); the policy must be read as a one-statement list")
#: Walkers fixed so far (Wave 1: the trust walker reads statements through policy.parse.iter_statements).
F002_FIXED = ("trust", "lambda", "sqs", "s3", "secrets", "kms", "ecr", "dynamodb")


@pytest.mark.finding("F-002")
@pytest.mark.parametrize("walker", [w if w in F002_FIXED else pytest.param(w, marks=_F002_XFAIL) for w in WALKERS])
def test_f002_single_object_statement_is_honoured(tmp_path, walker):
    analysis = S.analyze_tree(build_single_statement_tree(tmp_path, walker))
    if walker == "trust":
        rels = analysis.trust()
        assert any(S.refers(t.get("role_arn") or t.get("role_name"), "demo-fn-role")
                   and "lambda.amazonaws.com" in str(t.get("trusted_principal")) for t in rels), rels
    else:
        ids = {i for f in analysis.findings() for i in S.finding_ids(f)}
        assert EXPECTED_FINDING[walker] in ids, ids
