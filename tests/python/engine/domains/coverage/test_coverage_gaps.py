"""Collection gaps (analyzers/coverage_gaps.py; F-058, F-059, engine.md §6.7).

A denied call is never "empty": every failing (API, unit) of the run's ``_coverage.json`` files becomes one
INFO ``COLLECTION-GAP-001`` (stable fingerprint per facet and unit), and every collected item that failed is a node
whose ``coverage.status`` is ``partial`` -- its exposure is unknown, never "not public".
"""

from __future__ import annotations

import importlib

import pytest

K = importlib.import_module("tests.fixtures.e-compute.kit")
rb = K.rb
R, A = K.REGION, K.ACCT
REGION_ANCHOR = f"aws-enumerator:region/{A}/{R}"
ACCOUNT_ANCHOR = f"aws-enumerator:account/{A}"


def _gaps(g):
    return {f["evidence"]["facet"]: f for f in K.findings(g, "COLLECTION-GAP-001")}


def _denied_function(run):
    fn = rb.lambda_function("demo-fn", account=A, region=R, role=None)
    rb.mark_item(fn, rb.collection_error("lambda:GetPolicy"), policy_status="denied")
    run.put(R, "lambda/functions.json", [fn], calls=[
        {"api": "lambda:ListFunctions", "primary": True, "items": 1, "pages": 1},
        {"api": "lambda:GetPolicy", "status": "denied", "item": fn["FunctionArn"]}])
    return fn["FunctionArn"]


@pytest.mark.finding("F-059")
def test_denied_item_call_is_a_gap_finding_and_a_partial_node(tmp_path):
    run = K.RunTree(tmp_path)
    fn = _denied_function(run)
    g = run.analyze().graph
    assert K.problems(g) == []
    gap = _gaps(g)["lambda:GetPolicy"]
    assert gap["severity"] == "INFO" and gap["node_id"] == REGION_ANCHOR and gap["region"] == R
    assert gap["evidence"]["affected_resources"] == [fn] and gap["related_node_ids"] == [fn]
    assert gap["evidence"]["status"] == "denied" and gap["evidence"]["error_codes"] == ["AccessDenied"]
    assert "unknown, not absent" in gap["description"]
    node = K.nodes(g)[fn]
    assert node["coverage"]["status"] == "partial" and "lambda:GetPolicy:denied" in node["coverage"]["gaps"]


@pytest.mark.finding("F-058")
def test_denied_bucket_policy_read_is_reported_not_treated_as_no_policy(tmp_path):
    run = K.RunTree(tmp_path)
    bucket = "arn:aws:s3:::demo-data"
    run.put("global", "s3/buckets.json", [rb.s3_bucket(run.unit("global"), "demo-data")], calls=[
        {"api": "s3:ListBuckets", "primary": True, "items": 1, "pages": 1},
        {"api": "s3:GetBucketPolicy", "status": "denied", "item": bucket},
        {"api": "s3:GetPublicAccessBlock", "status": "ok", "error_code": "NoSuchPublicAccessBlockConfiguration",
         "not_configured": True, "item": bucket}])
    g = run.analyze().graph
    gaps = _gaps(g)
    gap = gaps["s3:GetBucketPolicy"]
    assert gap["node_id"] == ACCOUNT_ANCHOR and gap.get("region") is None          # global unit: account anchor
    assert gap["evidence"]["affected_resources"] == [bucket]
    assert "s3:GetPublicAccessBlock" not in gaps                                    # "not configured" is no gap


@pytest.mark.finding("F-058")
def test_breaker_skips_sections_and_failed_modules_are_gaps_deliberate_skips_are_not(tmp_path):
    run = K.RunTree(tmp_path)
    run.coverage("sqs", R, calls=[{"api": "sqs:ListQueues", "status": "denied", "primary": True}])
    run.coverage("sns", R, calls=[
        {"api": "sns:ListTopics", "primary": True, "items": 3, "pages": 1},
        {"api": "sns:GetTopicAttributes", "status": "denied", "item": K.topic_arn("demo-a"), "count": 3},
        {"api": "sns:GetTopicAttributes", "status": "skipped", "error_code": "CircuitOpen:AccessDenied",
         "item": K.topic_arn("demo-b")},
        {"api": "sns:ListSubscriptionsByTopic", "status": "skipped", "error_code": "Disabled"}])
    run.coverage("ecs", R, calls=["ecs:ListTaskDefinitions"], sections=[("services", RuntimeError("boom"))])
    run.coverage("glue", R, status="failed")
    g = run.analyze().graph
    assert K.problems(g) == []
    gaps = _gaps(g)
    assert gaps["sqs:ListQueues"]["evidence"]["status"] == "denied"
    attrs = gaps["sns:GetTopicAttributes"]
    assert attrs["evidence"]["statuses"] == {"denied": 3, "skipped": 1} and attrs["evidence"]["calls"] == 4
    assert attrs["evidence"]["affected_resources"] == sorted([K.topic_arn("demo-a"), K.topic_arn("demo-b")])
    assert "sns:ListSubscriptionsByTopic" not in gaps                               # a deliberate skip
    assert "section:ecs/services" in gaps and "module:glue" in gaps


@pytest.mark.finding("F-058")
def test_gap_fingerprints_are_stable_across_analyses(tmp_path):
    def build(root):
        run = K.RunTree(root)
        _denied_function(run)
        run.coverage("sqs", R, calls=[{"api": "sqs:ListQueues", "status": "denied", "primary": True}])
        return run.analyze().graph

    first, second = build(tmp_path / "a"), build(tmp_path / "b")
    assert sorted(f["fingerprint"] for f in K.findings(first, "COLLECTION-GAP-001")) == \
        sorted(f["fingerprint"] for f in K.findings(second, "COLLECTION-GAP-001"))


@pytest.mark.finding("F-058")
def test_legacy_reports_have_no_ledger_and_skip_the_analyzer(tmp_path):
    t = K.LegacyTree(tmp_path)
    g = t.analyze().graph
    assert K.status_of(g, "coverage-gaps") == "skipped"
    assert not K.findings(g, "COLLECTION-GAP-001")
    assert "coverage-not-recorded" in {gap["code"] for gap in g["evaluation_gaps"]}


@pytest.mark.finding("F-059")
def test_policy_state_reads_status_before_the_document():
    cg = K.engine("analyzers.coverage_gaps")
    assert cg.policy_state({}, "present") == "unknown"                           # "present" but nothing readable
    assert cg.policy_state({"Statement": []}, "present") == "present"
    assert cg.policy_state(None, "absent") == "absent"
    for status in ("denied", "error", "skipped"):
        assert cg.policy_state(None, status) == "unknown"
    assert cg.policy_state(None, None) == "unknown"                              # d13c215: null is ambiguous
    assert cg.policy_state({"_raw": "not json"}, None) == "unknown"
    assert cg.item_coverage({"CollectionErrors": [{"api": "x:Y", "status": "denied"}]}) == ("partial", ["x:Y:denied"])
    assert cg.item_coverage({}, legacy=True) == ("legacy-unknown", [])
