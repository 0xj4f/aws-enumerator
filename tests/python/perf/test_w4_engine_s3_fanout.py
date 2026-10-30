"""Size budget of the S3 fan-out (F-022, marked ``perf``; run with ``-m perf``).

The finding's scale run: 300 roles x 500 buckets, every role with ``s3:*`` and ``s3:GetObject`` on ``*``. d13c215
wrote 300,000 edges (144 MB); before the all-buckets summary the engine still wrote 150,000 edges, a 104 MB
``graph.json`` and a 69 MB pretty-printed ``s3_relationships.json``. Now every role has one ``FULL_ACCESS`` edge
to the account's all-buckets node, so the access edges grow with the principals, not principals x buckets.
"""

from __future__ import annotations

import importlib
import json

import pytest

K = importlib.import_module("tests.fixtures.e-net.kit")
rb = K.rb

ROLES, BUCKETS = 300, 500
GRAPH_BUDGET_BYTES = 5_000_000            # measured ~1.0 MB (was ~104 MB)
LEGACY_BUDGET_BYTES = 1_000_000           # measured ~0.2 MB (was ~69 MB)
ANALYSIS_BUDGET_SECONDS = 60.0            # measured ~12 s on the reference laptop (was ~31 s)
ACCESS = ("FULL_ACCESS", "CAN_ADMIN", "CAN_WRITE", "CAN_READ")


@pytest.mark.perf
@pytest.mark.finding("F-022")
def test_wildcard_fanout_of_300_roles_to_500_buckets_stays_linear(tmp_path):
    t = K.Tree(tmp_path)
    for i in range(ROLES):
        t.iam.role(f"demo-role-{i:03d}", K.EC2_TRUST,
                   inline={"p": [rb.allow("s3:*", "*"), rb.allow("s3:GetObject", "*")]})
    t.write(skip={"ec2"})
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, f"demo-b{i:03d}") for i in range(BUCKETS)])
    out = t.analyze()
    took = sum(s.duration_seconds or 0.0 for s in out.result.analyzer_status)
    access = [e for e in out.graph["edges"] if e["type"] in ACCESS]
    assert len(access) == ROLES                                         # O(principals), not O(principals x buckets)
    all_buckets = f"arn:aws:s3:::*:{K.ACCT}"
    assert {e["target"] for e in access} == {all_buckets}
    assert all(e["evidence"]["summary"]["elided"] == BUCKETS for e in access)
    graph_bytes = (out.dir / "graph.json").stat().st_size
    legacy_path = out.dir / "s3_relationships.json"
    assert graph_bytes < GRAPH_BUDGET_BYTES, graph_bytes
    assert legacy_path.stat().st_size < LEGACY_BUDGET_BYTES, legacy_path.stat().st_size
    assert len(json.loads(legacy_path.read_text())["edges"]) == ROLES
    assert took < ANALYSIS_BUDGET_SECONDS, took
