"""Performance budget of the E-net analyzers (marked ``perf``; run with ``-m perf``): 100 roles x 100 buckets x
100 instances, every role touching both services, stays well under the budget thanks to the evaluator memo and
the per-signature result sharing of ``analyzers.s3.ResultCache``; the wildcard read fan-out is one all-buckets
summary edge per role (F-022, ``tests/python/perf/test_w4_engine_s3_fanout.py``)."""

from __future__ import annotations

import importlib

import pytest

K = importlib.import_module("tests.fixtures.e-net.kit")
rb = K.rb

BUDGET_SECONDS = 10.0


@pytest.mark.perf
def test_s3_and_ec2_analyzers_scale_to_ten_thousand_pairs_each(tmp_path):
    t = K.Tree(tmp_path)
    for i in range(100):
        stmts = [rb.allow(["s3:GetObject", "s3:ListBucket"], "*"),
                 rb.allow("s3:PutObject", f"arn:aws:s3:::demo-b{i % 7}*/*"),
                 rb.allow(["ssm:StartSession", "ec2:StopInstances", "ec2:StartInstances"], "*")]
        if i % 5 == 0:
            stmts.append(rb.deny("s3:*", f"arn:aws:s3:::demo-b1{i % 3}*"))
        t.iam.role(f"demo-role-{i}", K.EC2_TRUST, inline={"p": stmts})
    t.write(skip={"ec2"})
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, f"demo-b{i}") for i in range(100)])
    t.scope.write("ec2/instances.json", [rb.ec2_instance(f"i-0a1b2c3d4e5f{i:05x}", account=K.ACCT, region=K.REGION)
                                         for i in range(100)])
    out = t.analyze()
    took = {s.name: s.duration_seconds or 0.0 for s in out.result.analyzer_status}
    assert took["s3"] + took["ec2"] < BUDGET_SECONDS, took
    # every role reads every bucket through its wildcard statement, except the 20 roles that deny themselves one
    # bucket: one all-buckets summary edge per role (F-022) whose elided count adds up to the 9,980 grants
    reads = K.edges(out.graph, "CAN_READ")
    assert len(reads) == 100 and {e["target"] for e in reads} == {f"arn:aws:s3:::*:{K.ACCT}"}
    assert sum(e["evidence"]["summary"]["elided"] for e in reads) == 100 * 100 - 20
    excluded = {e["source"].rsplit("/", 1)[-1]: e["evidence"]["summary"]["excluded"] for e in reads}
    assert {k: v for k, v in excluded.items() if v} == {
        f"demo-role-{i}": [K.bucket(f"demo-b1{i % 3}")] for i in range(0, 100, 5)}
