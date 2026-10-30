"""SVC-DEPUTY-001 (F-033 sub-item 1, Wave 4): resource-policy grants to AWS service principals without a source
condition.

A service principal acts for every AWS customer: a Lambda permission for ``s3.amazonaws.com``, a queue policy for
``sns.amazonaws.com`` or a bucket policy for ``logging.s3.amazonaws.com`` without ``aws:SourceArn`` /
``aws:SourceAccount`` / ``aws:SourceOrgID`` lets that service act on the resource for resources of any account.
The check is ``policy.resource_policy.unguarded_service_grants`` over the shared walker (``policy_grants``); the
lambda, messaging, s3 and data-stores analyzers emit one LOW finding per (resource, service principal).
"""

from __future__ import annotations

import importlib

import pytest

from tests.support import targets

C = importlib.import_module("tests.fixtures.e-compute.kit")
N = importlib.import_module("tests.fixtures.e-net.kit")
D = importlib.import_module("tests.fixtures.e-data.kit")
rb = C.rb

pytestmark = pytest.mark.finding("F-033")

ID = "SVC-DEPUTY-001"
FN = C.fn_arn("demo-fn")
Q, T = C.queue_arn("demo-q"), C.topic_arn("demo-t")
SOURCE_ARN = {"ArnLike": {"AWS:SourceArn": "arn:aws:s3:::demo-data-bucket"}}
SOURCE_ACCOUNT = {"StringEquals": {"aws:SourceAccount": C.ACCT}}
SOURCE_ORG = {"StringEquals": {"aws:SourceOrgID": "o-a1b2c3d4e5"}}


# ── the policy-level check ────────────────────────────────────────────────────

def _unguarded(policy, resource=FN):
    rp = targets.engine_module("policy.resource_policy")
    parse = targets.engine_module("policy.parse").parse_policy
    ev = targets.engine_module("policy.evaluator").Evaluator
    doc = parse(policy, layer="resource", source_type="resource", policy_arn=resource, policy_name="p")
    evaluator = ev(_Ctx(), {}, None, None)
    return [(g.principal.raw, g.decision.value) for g in
            rp.unguarded_service_grants(doc, evaluator.resource_policy_grants(doc, resource))]


class _Ctx:
    """The minimal context a resource-policy-only evaluator needs."""

    account_id = C.ACCT
    partition = "aws"
    reference_time = None
    shared: dict = {}

    def add_gap(self, *args, **kwargs):
        return None


@pytest.mark.parametrize("cond, expected", [
    (None, [("s3.amazonaws.com", "allow")]),
    (SOURCE_ARN, []),
    (SOURCE_ACCOUNT, []),
    (SOURCE_ORG, []),
    ({"ForAnyValue:StringLike": {"aws:SourceOrgPaths": ["o-a1b2c3d4e5/r-ab12/*"]}}, []),
    # a condition that does not name the source keeps the grant open to every account's resources
    ({"Bool": {"aws:SecureTransport": "true"}}, [("s3.amazonaws.com", "allow")]),
    ({"StringEquals": {"aws:PrincipalTag/team": "demo"}}, [("s3.amazonaws.com", "conditional")]),
])
def test_only_a_source_condition_guards_a_service_principal(cond, expected):
    policy = rb.resource_policy(rb.grant({"Service": "s3.amazonaws.com"}, "lambda:InvokeFunction", FN, cond))
    assert _unguarded(policy) == expected


def test_a_deny_on_a_foreign_source_account_also_guards_it():
    deny = {"Effect": "Deny", "Principal": "*", "Action": "lambda:InvokeFunction", "Resource": FN,
            "Condition": {"StringNotEquals": {"aws:SourceAccount": C.ACCT}}}
    open_ = rb.grant({"Service": "events.amazonaws.com"}, "lambda:InvokeFunction", FN)
    assert _unguarded(rb.resource_policy(open_, deny)) == []
    # a Deny for another service or other actions does not
    other = dict(deny, Principal={"Service": "sns.amazonaws.com"})
    assert _unguarded(rb.resource_policy(open_, other)) == [("events.amazonaws.com", "allow")]
    unrelated = dict(deny, Action="lambda:GetFunction")
    assert _unguarded(rb.resource_policy(open_, unrelated)) == [("events.amazonaws.com", "allow")]


def test_account_and_public_principals_are_not_deputies():
    policy = rb.resource_policy(rb.grant("*", "lambda:InvokeFunction", FN),
                                rb.grant({"AWS": f"arn:aws:iam::{C.FOREIGN}:root"}, "lambda:InvokeFunction", FN))
    assert _unguarded(policy) == []


# ── Lambda permissions ────────────────────────────────────────────────────────

def _lambda(tmp_path, cond):
    t = C.LegacyTree(tmp_path)
    t.iam.role("demo-fn-role", rb.trust({"Service": "lambda.amazonaws.com"}))
    fn = rb.lambda_function("demo-fn", account=C.ACCT, region=C.REGION, role=C.iam_arn("role", "demo-fn-role"))
    t.put("lambda/functions.json", [fn])
    t.put("lambda/resource_policies/demo-fn.json", rb.lambda_policy_file(fn, rb.resource_policy(
        rb.grant({"Service": "s3.amazonaws.com"}, "lambda:InvokeFunction", FN, cond, sid="S3Invoke"))))
    return t.analyze().graph


def test_lambda_permission_for_s3_without_source_arn_is_low(tmp_path):
    g = _lambda(tmp_path, None)
    f = C.only(C.findings(g, ID, FN))
    assert f["severity"] == "LOW" and f["confidence"] == "definite"
    assert f["evidence"]["service"] == "s3.amazonaws.com"
    assert [a.lower() for a in f["evidence"]["actions"]] == ["lambda:invokefunction"]
    assert [s["sid"] for s in f["evidence"]["statements"]] == ["S3Invoke"]
    assert "aws:SourceArn" in f["evidence"]["missing_conditions"]
    assert "svc:s3.amazonaws.com" in f["related_node_ids"]
    assert f["reference"].endswith("#resource-exposure--external-access-findings")
    assert C.problems(g) == []


@pytest.mark.parametrize("cond", [SOURCE_ARN, SOURCE_ACCOUNT], ids=["source-arn", "source-account"])
def test_lambda_permission_with_a_source_condition_is_not_reported(tmp_path, cond):
    g = _lambda(tmp_path, cond)
    assert C.findings(g, ID) == []
    assert C.edges(g, "LAMBDA_GRANTS_INVOKE", "svc:s3.amazonaws.com", FN)     # the grant itself is still drawn


# ── SQS and SNS policies ──────────────────────────────────────────────────────

def _messaging(tmp_path, queue_cond, topic_cond):
    t = C.LegacyTree(tmp_path)
    queue = rb.resource_policy(rb.grant({"Service": "sns.amazonaws.com"}, "sqs:SendMessage", Q, queue_cond))
    topic = rb.resource_policy(rb.grant({"Service": "events.amazonaws.com"}, "sns:Publish", T, topic_cond))
    t.put("sqs/resources.json", [dict(rb.policy_resource("sqs", Q, "demo-q", queue), PolicyStatus="present")])
    t.put("sns/resources.json", [dict(rb.policy_resource("sns", T, "demo-t", topic), PolicyStatus="present")])
    return t.analyze().graph


def test_queue_and_topic_policies_for_services_without_source_conditions(tmp_path):
    g = _messaging(tmp_path, None, None)
    q, t = C.only(C.findings(g, ID, Q)), C.only(C.findings(g, ID, T))
    assert (q["evidence"]["service"], t["evidence"]["service"]) == ("sns.amazonaws.com", "events.amazonaws.com")
    assert q["severity"] == t["severity"] == "LOW"
    assert "SQS queue 'demo-q'" in q["title"] and "SNS topic 'demo-t'" in t["title"]
    assert C.problems(g) == []


def test_queue_and_topic_policies_with_source_conditions_are_not_reported(tmp_path):
    g = _messaging(tmp_path, {"ArnEquals": {"aws:SourceArn": T}}, SOURCE_ACCOUNT)
    assert C.findings(g, ID) == []


# ── S3 bucket policies and ECR repositories ──────────────────────────────────

def _bucket(tmp_path, cond):
    t = N.Tree(tmp_path)
    t.write()
    stmt = rb.grant({"Service": "logging.s3.amazonaws.com"}, "s3:PutObject", "arn:aws:s3:::demo-logs/*", cond)
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, "demo-logs", policy=rb.resource_policy(stmt))])
    return t.analyze().graph


def test_bucket_policy_for_the_logging_service(tmp_path):
    g = _bucket(tmp_path, None)
    f = C.only(C.findings(g, ID, N.bucket("demo-logs")))
    assert f["evidence"]["service"] == "logging.s3.amazonaws.com" and f["severity"] == "LOW"
    assert C.problems(g) == []


def test_bucket_policy_for_the_logging_service_with_source_account(tmp_path):
    assert C.findings(_bucket(tmp_path, SOURCE_ACCOUNT), ID) == []


def test_ecr_repository_policy_for_lambda_pulls(tmp_path):
    run = D.Run(tmp_path)
    arn = f"arn:aws:ecr:{D.REGION}:{D.ACCT}:repository/demo-images"
    open_ = rb.resource_policy(rb.grant({"Service": "lambda.amazonaws.com"}, ["ecr:BatchGetImage"], arn))
    run.write_json(D.REGION, "ecr/resources.json", [D.v2_policy_resource("ecr", "demo-images", policy=open_)])
    run.finish()
    g = run.analyze().graph
    f = C.only(C.findings(g, ID, arn))
    assert f["evidence"]["service"] == "lambda.amazonaws.com" and "ECR repository 'demo-images'" in f["title"]
    assert D.problems(g) == []
