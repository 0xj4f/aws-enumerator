"""Messaging analyzer (analyzers/messaging.py, loader io/loaders/messaging.py): SNS and SQS on the evaluator.

Covers F-001/F-014/F-015 (decisions from the evaluator), F-002 (single-object statements), F-031/F-037/F-039
(resource-policy grants normalised grantee → resource, anonymous node, exact external principals), F-059 (an
unreadable policy is "exposure unknown", never "not public"), F-116 (SUBSCRIBES, MSG_ENCRYPTED_BY) and request
c-b-1 (``null`` = unknown).
"""

from __future__ import annotations

import importlib

import pytest

K = importlib.import_module("tests.fixtures.e-compute.kit")
rb = K.rb
R, A = K.REGION, K.ACCT
Q, T = K.queue_arn("demo-q"), K.topic_arn("demo-t")


def _queue(policy=None, **extra):
    rec = dict(rb.policy_resource("sqs", Q, "demo-q", policy), PolicyStatus="present" if policy else "absent")
    rec.update(extra)
    return rec


def _topic(policy=None, **extra):
    rec = dict(rb.policy_resource("sns", T, "demo-t", policy), PolicyStatus="present" if policy else "absent")
    rec.update(extra)
    return rec


@pytest.mark.finding("F-001", "F-014", "F-015")
def test_identity_edges_come_from_the_evaluator(tmp_path):
    t = K.LegacyTree(tmp_path)
    t.iam.user("demo-sender", inline={"p": [rb.allow("sqs:SendMessage", Q)]})
    t.iam.user("demo-worker", inline={"p": [rb.allow(["sqs:ReceiveMessage", "sqs:SendMessage"], "*")]})
    t.iam.user("demo-owner", inline={"p": [rb.allow("sqs:*", Q)]})
    t.iam.user("demo-power", attached=["PowerUserAccess"])
    t.iam.user("demo-denied", inline={"p": [rb.allow("sqs:*", "*"), rb.deny("sqs:*", Q)]})
    t.iam.user("demo-vpc", inline={"p": [rb.allow("sqs:SendMessage", Q,
                                                  {"StringEquals": {"aws:SourceVpce": "vpce-1"}})]})
    t.iam.user("demo-unrelated", inline={"p": [rb.allow("s3:GetObject", "*")]})
    t.put("sqs/resources.json", [_queue()])
    g = t.analyze().graph
    assert K.problems(g) == []
    u = {n: K.iam_arn("user", n) for n in ("demo-sender", "demo-worker", "demo-owner", "demo-power", "demo-denied",
                                            "demo-vpc", "demo-unrelated")}
    assert K.edge_types(g, u["demo-sender"], Q) == {"CAN_SEND"}
    assert K.edge_types(g, u["demo-worker"], Q) == {"CAN_RECEIVE", "CAN_SEND"}
    assert K.edge_types(g, u["demo-owner"], Q) == {"CAN_ADMIN_MSG"}          # can rewrite the policy: the rest follows
    assert K.edge_types(g, u["demo-power"], Q) == {"CAN_ADMIN_MSG"}          # NotAction iam:* grants sqs:*
    assert K.edge_types(g, u["demo-denied"], Q) == set()
    assert K.edge_types(g, u["demo-unrelated"], Q) == set()
    vpc = K.only(K.edges(g, "CAN_SEND", u["demo-vpc"], Q))
    assert vpc["confidence"] == "conditional"


@pytest.mark.finding("F-031", "F-037", "F-039")
def test_resource_policy_grants_are_normalised_and_graded(tmp_path):
    t = K.LegacyTree(tmp_path)
    t.iam.role("demo-named", rb.trust({"Service": "ec2.amazonaws.com"}))
    foreign = f"arn:aws:iam::{K.FOREIGN}:root"
    t.put("sqs/resources.json", [_queue(rb.resource_policy(
        rb.grant({"AWS": foreign}, "sqs:SendMessage", Q),
        rb.grant({"AWS": K.iam_arn("role", "demo-named")}, "sqs:ReceiveMessage", Q),
        rb.grant({"Service": "sns.amazonaws.com"}, "sqs:SendMessage", Q, {"ArnEquals": {"aws:SourceArn": T}})))])
    t.put("sns/resources.json", [_topic(rb.resource_policy(
        rb.grant("*", "sns:Publish", T),
        rb.grant("*", "sns:Subscribe", T, {"StringEquals": {"aws:SourceOwner": A}})))])
    g = t.analyze().graph
    assert K.problems(g) == []
    xacct = K.only(K.edges(g, "MSG_GRANTS_CROSS_ACCOUNT", foreign, Q))
    assert xacct["props"]["cross_account"] is True and K.nodes(g)[foreign]["type"] == "external_account"
    assert K.only(K.findings(g, "MSG-XACCT-001", Q))["severity"] == "MEDIUM"
    public = K.only(K.edges(g, "MSG_GRANTS_PUBLIC", K.ANON, T))
    assert [a.lower() for a in public["evidence"]["actions"]] == ["sns:publish"]
    assert K.only(K.findings(g, "MSG-PUB-001", T))["severity"] == "HIGH"
    assert not K.findings(g, "MSG-PUB-001", Q)                               # service grant gated by SourceArn
    named = K.iam_arn("role", "demo-named")                                   # same-account grant alone
    assert K.edge_types(g, named, Q) == {"CAN_RECEIVE"}
    assert not K.edges(g, source=named, target=T)                            # forced only for its own service


@pytest.mark.finding("F-002")
def test_single_object_statement_in_a_queue_policy(tmp_path):
    t = K.LegacyTree(tmp_path)
    t.put("sqs/resources.json", [_queue({"Version": "2012-10-17",
                                         "Statement": rb.grant("*", "sqs:SendMessage", Q)})])
    g = t.analyze().graph
    assert K.findings(g, "MSG-PUB-001", Q) and K.edges(g, "MSG_GRANTS_PUBLIC", K.ANON, Q)


@pytest.mark.finding("F-059")
def test_unreadable_policy_is_exposure_unknown(tmp_path):
    t = K.LegacyTree(tmp_path)
    denied = rb.mark_item(_queue(), rb.collection_error("sqs:GetQueueAttributes"), policy_status="denied",
                          unknown=["Policy", "KmsMasterKeyId", "SqsManagedSseEnabled"])
    t.put("sqs/resources.json", [denied])
    t.put("sns/resources.json", [{"Type": "sns", "Arn": T, "Name": "demo-t", "Policy": None}])   # d13c215: no status
    g = t.analyze().graph
    q = K.nodes(g)[Q]
    assert q["props"]["exposure_unknown"] is True and q["props"]["policy_status"] == "unknown"
    assert q["coverage"]["status"] == "partial"
    assert "sqs:GetQueueAttributes:denied" in q["coverage"]["gaps"]
    assert "sse" not in q["props"]                                          # unknown, not "unencrypted"
    assert K.nodes(g)[T]["props"]["exposure_unknown"] is True              # legacy null policy: unknown
    assert not K.findings(g, "MSG-PUB-001")


@pytest.mark.finding("F-116")
def test_subscriptions_and_encryption(tmp_path):
    t = K.LegacyTree(tmp_path)
    key = f"arn:aws:kms:{R}:{A}:key/0a1b2c3d-aaaa-4bbb-8ccc-0d1e2f3a4b5c"
    fn = K.fn_arn("demo-fn")
    foreign_q = f"arn:aws:sqs:{R}:{K.FOREIGN}:demo-drop"
    t.put("sqs/resources.json", [_queue(KmsMasterKeyId="alias/aws/sqs"),
                                 dict(rb.policy_resource("sqs", K.queue_arn("demo-sse"), "demo-sse", None),
                                      PolicyStatus="absent", KmsMasterKeyId=None, SqsManagedSseEnabled=True)])
    t.put("sns/resources.json", [_topic(KmsMasterKeyId=key, Subscriptions=[
        {"Protocol": "sqs", "Endpoint": Q, "Owner": A},
        {"Protocol": "sqs", "Endpoint": foreign_q, "Owner": K.FOREIGN},
        {"Protocol": "lambda", "Endpoint": fn + ":live", "Owner": A},
        {"Protocol": "https", "Endpoint": "https://hooks.example.invalid", "Owner": A},
        {"Protocol": "email", "Endpoint": "example.invalid", "Owner": A}])])
    g = t.analyze().graph
    assert K.problems(g) == []
    assert K.only(K.edges(g, "SUBSCRIBES", T, Q))["traversable"] is False
    assert K.only(K.edges(g, "SUBSCRIBES", T, foreign_q))["evidence"]["subscription_owner"] == K.FOREIGN
    assert K.only(K.edges(g, "SUBSCRIBES", T, fn))["evidence"]["qualifiers"] == ["live"]
    assert K.nodes(g)[T]["props"]["subscriptions_other"] == ["email:example.invalid",
                                                             "https:https://hooks.example.invalid"]
    assert K.edges(g, "MSG_ENCRYPTED_BY", T, key)
    alias = f"arn:aws:kms:{R}:{A}:alias/aws/sqs"
    assert K.edges(g, "MSG_ENCRYPTED_BY", Q, alias)
    assert K.nodes(g)[alias]["props"]["unresolved_alias"] is True
    assert K.nodes(g)[K.queue_arn("demo-sse")]["props"]["sse"] == "sqs-managed"
    assert not K.edges(g, "MSG_ENCRYPTED_BY", K.queue_arn("demo-sse"))


@pytest.mark.finding("F-116")
def test_unknown_subscriptions_are_a_gap(tmp_path):
    t = K.LegacyTree(tmp_path)
    topic = rb.mark_item(_topic(), rb.collection_error("sns:ListSubscriptionsByTopic"), unknown=["Subscriptions"])
    t.put("sns/resources.json", [topic])
    g = t.analyze().graph
    node = K.nodes(g)[T]
    assert node["coverage"]["status"] == "partial"
    assert "sns:ListSubscriptionsByTopic:unknown" in node["coverage"]["gaps"]
    assert "subscription_count" not in node["props"]


@pytest.mark.finding("F-030")
def test_unrelated_principals_are_never_evaluated_per_resource(tmp_path, monkeypatch):
    """The prefilter keeps the per-resource evaluation to principals that can act on the service at all."""
    t = K.LegacyTree(tmp_path)
    for i in range(20):
        t.iam.role(f"demo-app-{i:02d}", rb.trust({"Service": "ec2.amazonaws.com"}),
                   inline={"p": [rb.allow(["s3:GetObject", "ec2:Describe*", "logs:PutLogEvents"], "*")]})
    t.iam.user("demo-sender", inline={"p": [rb.allow("sqs:SendMessage", "*")]})
    t.put("sqs/resources.json", [dict(rb.policy_resource("sqs", K.queue_arn(f"demo-q{i:03d}"), f"demo-q{i:03d}",
                                                         None), PolicyStatus="absent") for i in range(50)])
    evaluator_mod = K.engine("policy.evaluator")
    seen = []
    original = evaluator_mod.Evaluator.evaluate

    def counting(self, principal, action, resource, **kw):
        if ":sqs:" in resource:
            seen.append(getattr(principal, "id", principal))
        return original(self, principal, action, resource, **kw)

    monkeypatch.setattr(evaluator_mod.Evaluator, "evaluate", counting)
    g = t.analyze().graph
    assert len(K.edges(g, "CAN_SEND", K.iam_arn("user", "demo-sender"))) == 50
    assert {s for s in seen if isinstance(s, str)} <= {K.iam_arn("user", "demo-sender")}


@pytest.mark.finding("F-059")
def test_records_without_a_usable_arn_are_a_counted_gap(tmp_path):
    t = K.LegacyTree(tmp_path)
    t.put("sqs/resources.json", [{"Type": "sqs", "Arn": None, "Name": "demo-broken", "Policy": None}, _queue()])
    g = t.analyze().graph
    assert Q in K.nodes(g)
    gaps = {gap["code"]: gap for gap in g["evaluation_gaps"]}
    assert gaps["messaging:unrecognised-id"]["count"] == 1
