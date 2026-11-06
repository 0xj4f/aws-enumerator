"""S3 fan-out (F-022, Wave 4): the all-buckets summary edge and the provenance of dominated classes.

* A principal whose wildcard-resource access of one class is the same on at least ``ALL_BUCKETS_MIN`` buckets gets
  **one** edge to the account's all-buckets node (``arn:<p>:s3:::*:<account>``, type ``bucket``) instead of one
  edge per bucket; ``evidence.summary`` records ``bucket_count``, ``elided`` and the ``excluded`` buckets.
* Per-bucket edges stay where a bucket-policy grant, a specific or prefixed resource ARN, or a different decision
  (a Deny, a condition) applies, and below the threshold.
* When a higher class dominates (``FULL_ACCESS`` over ``CAN_READ``), the statements that granted only the lower
  class are listed on the surviving edge (``evidence.dominated``) and in the legacy record's ``source_policies``.
"""

from __future__ import annotations

import importlib
import json

import pytest

K = importlib.import_module("tests.fixtures.e-net.kit")
rb = K.rb

S3 = K.engine("analyzers.s3")
N = S3.ALL_BUCKETS_MIN + 5
ALL = f"arn:aws:s3:::*:{K.ACCT}"


def _buckets(t, n=N, extra=None):
    """``n`` buckets ``demo-bucket-000`` …; ``extra`` maps a bucket index to its sub-configs (``policy=`` …)."""
    extra = extra or {}
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, f"demo-bucket-{i:03d}", **extra.get(i, {}))
                                      for i in range(n)])
    return [K.bucket(f"demo-bucket-{i:03d}") for i in range(n)]


def _bucket_edges(g, source):
    return sorted((e["type"], e["target"]) for e in K.edges(g, source=source) if e["target"].startswith("arn:aws:s3:::"))


def _tls_policy(name):
    return {"Version": "2012-10-17", "Statement": [{
        "Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
        "Resource": [K.bucket(name), K.bucket(name) + "/*"], "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}


# ── the summary edge ──────────────────────────────────────────────────────────

@pytest.mark.finding("F-022")
def test_wildcard_access_to_every_bucket_is_one_summary_edge_per_class(tmp_path):
    t = K.Tree(tmp_path)
    t.iam.role("demo-s3-admin", K.EC2_TRUST, inline={"p": [rb.allow("s3:*", "*")]})
    t.iam.role("demo-reader", K.EC2_TRUST, inline={"p": [rb.allow(["s3:GetObject", "s3:ListBucket"],
                                                                     ["arn:aws:s3:::*", "arn:aws:s3:::*/*"])]})
    t.write()
    # a bucket policy that neither grants nor denies these principals (TLS only) does not split the summary
    buckets = _buckets(t, extra={3: {"policy": _tls_policy("demo-bucket-003")}})
    out = t.analyze()
    g = out.graph
    admin, reader = K.iam_arn("role", "demo-s3-admin"), K.iam_arn("role", "demo-reader")
    assert _bucket_edges(g, admin) == [("FULL_ACCESS", ALL)]
    assert _bucket_edges(g, reader) == [("CAN_READ", ALL)]
    edge = K.edges(g, "FULL_ACCESS", admin, ALL)[0]
    assert edge["evidence"]["summary"] == {"kind": "all-buckets", "bucket_count": N, "elided": N, "excluded": []}
    assert edge["confidence"] == "definite" and edge["traversable"] is True
    assert edge["evidence"]["layers"]["resource"] == "n/a"           # represented by a policy-less bucket
    node = K.nodes_by_id(g)[ALL]
    assert node["type"] == "bucket" and node["account"] == K.ACCT and node["label"] == f"All buckets ({N})"
    assert node["props"]["aggregate"] == "all-buckets" and node["props"]["bucket_count"] == N
    assert node["props"]["members"] == sorted(buckets) and node["props"]["data_asset"] is True
    # the path finder reaches the summary; the real buckets keep their nodes (exposure, encryption ...)
    path = K.engine("graph.traverse").shortest_path(g, admin, ALL)
    assert path is not None and path.edge_types == ("FULL_ACCESS",)
    assert set(buckets) <= set(K.nodes_by_id(g))
    legacy = [r for r in out.legacy("s3_relationships.json")["edges"] if r["source"] == admin]
    assert len(legacy) == 1 and legacy[0]["target"] == f"bucket:*:{K.ACCT}"
    assert legacy[0]["summary"] == {"kind": "all-buckets", "bucket_count": N, "elided": N}
    assert K.problems(g) == []


@pytest.mark.finding("F-022")
def test_buckets_with_another_decision_are_excluded_and_keep_their_own_edges(tmp_path):
    t = K.Tree(tmp_path)
    t.iam.role("demo-mostly", K.EC2_TRUST, inline={"p": [
        rb.allow("s3:GetObject", "*"),
        rb.deny("s3:*", [K.bucket("demo-bucket-001"), K.bucket("demo-bucket-001") + "/*"]),
        rb.allow("s3:GetObject", K.bucket("demo-bucket-002") + "/*",
                 cond={"Bool": {"aws:MultiFactorAuthPresent": "true"}})]})
    t.write()
    buckets = _buckets(t)
    g = t.analyze().graph
    role = K.iam_arn("role", "demo-mostly")
    # 001: denied there, no edge at all; 002: a specific-ARN statement applies too, so it keeps its own edge
    assert _bucket_edges(g, role) == [("CAN_READ", ALL), ("CAN_READ", buckets[2])]
    summary = K.edges(g, "CAN_READ", role, ALL)[0]["evidence"]["summary"]
    assert summary["bucket_count"] == N and summary["elided"] == N - 2
    assert summary["excluded"] == [buckets[1], buckets[2]]
    own = K.edges(g, "CAN_READ", role, buckets[2])[0]["evidence"]
    assert "summary" not in own and [c["key"] for c in own["conditions"]] == ["aws:multifactorauthpresent"]
    assert K.problems(g) == []


@pytest.mark.finding("F-022")
def test_bucket_policy_grants_and_specific_arns_keep_per_bucket_edges(tmp_path):
    t = K.Tree(tmp_path)
    reader = t.iam.role("demo-reader", K.EC2_TRUST, inline={"p": [rb.allow("s3:GetObject", "*")]})
    t.iam.role("demo-prefix", K.EC2_TRUST, inline={"p": [rb.allow("s3:GetObject", "arn:aws:s3:::demo-*/*")]})
    t.write()
    grant = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": reader}, "Action": ["s3:PutObject", "s3:GetObject"],
        "Resource": K.bucket("demo-bucket-004") + "/*"}]}
    buckets = _buckets(t, extra={4: {"policy": grant}})
    g = t.analyze().graph
    got = _bucket_edges(g, reader)
    # the bucket policy adds CAN_WRITE (and a resource-layer CAN_READ) on bucket 004 only
    assert ("CAN_WRITE", buckets[4]) in got and ("CAN_READ", ALL) in got
    assert ("CAN_READ", buckets[4]) in got and len(got) == 3
    summary = K.edges(g, "CAN_READ", reader, ALL)[0]["evidence"]["summary"]
    assert summary["excluded"] == [buckets[4]] and summary["elided"] == N - 1
    # a prefixed resource ARN is not "every bucket": one edge per bucket, as before
    prefix = _bucket_edges(g, K.iam_arn("role", "demo-prefix"))
    assert prefix == [("CAN_READ", b) for b in buckets]
    assert K.problems(g) == []


@pytest.mark.finding("F-022")
def test_below_the_threshold_every_bucket_keeps_its_edge(tmp_path, monkeypatch):
    t = K.Tree(tmp_path)
    t.iam.role("demo-s3-admin", K.EC2_TRUST, inline={"p": [rb.allow("s3:*", "*")]})
    t.write()
    buckets = _buckets(t, n=S3.ALL_BUCKETS_MIN - 1)
    g = t.analyze().graph
    assert _bucket_edges(g, K.iam_arn("role", "demo-s3-admin")) == [("FULL_ACCESS", b) for b in buckets]
    assert ALL not in K.nodes_by_id(g)
    # the threshold is the module constant (here lowered: the same world is summarised)
    monkeypatch.setattr(S3, "ALL_BUCKETS_MIN", 3)
    g = t.analyze().graph
    assert _bucket_edges(g, K.iam_arn("role", "demo-s3-admin")) == [("FULL_ACCESS", ALL)]


@pytest.mark.finding("F-022")
def test_group_members_reach_the_summary_through_member_of(tmp_path):
    t = K.Tree(tmp_path)
    t.iam.group("demo-readers", inline={"p": [rb.allow("s3:GetObject", "*")]})
    t.iam.user("demo-member", groups=["demo-readers"])
    t.write()
    _buckets(t)
    g = t.analyze().graph
    group, user = K.iam_arn("group", "demo-readers"), K.iam_arn("user", "demo-member")
    assert _bucket_edges(g, group) == [("CAN_READ", ALL)]
    assert _bucket_edges(g, user) == []
    path = K.engine("graph.traverse").shortest_path(g, user, ALL)
    assert path is not None and path.edge_types == ("MEMBER_OF", "CAN_READ")


@pytest.mark.finding("F-022")
def test_summary_keeps_graph_json_linear_in_principals(tmp_path):
    """A small version of the perf budget (tests/python/perf/test_w4_engine_s3_fanout.py) in the normal suite."""
    t = K.Tree(tmp_path)
    roles = 40
    for i in range(roles):
        t.iam.role(f"demo-role-{i:02d}", K.EC2_TRUST, inline={"p": [rb.allow("s3:*", "*"),
                                                                     rb.allow("s3:GetObject", "*")]})
    t.write(skip={"ec2"})
    _buckets(t, n=60)
    out = t.analyze()
    access = [e for e in out.graph["edges"] if e["type"] in ("FULL_ACCESS", "CAN_ADMIN", "CAN_WRITE", "CAN_READ")]
    assert len(access) == roles and {e["target"] for e in access} == {ALL}
    size = (out.dir / "graph.json").stat().st_size
    assert size < 400_000, size                                 # was ~2.4 MB with 2,400 per-bucket edges
    assert len(out.legacy("s3_relationships.json")["edges"]) == roles


# ── dominated classes keep their provenance ──────────────────────────────────

@pytest.mark.finding("F-022")
def test_dominated_lower_class_statements_stay_on_the_surviving_edge(tmp_path):
    t = K.Tree(tmp_path)
    full = t.iam.managed("demo-s3-full", [rb.allow("s3:*", "*")], customer=True)
    read = t.iam.managed("demo-s3-read", [rb.allow("s3:GetObject", "*")], customer=True)
    t.iam.role("demo-both", K.EC2_TRUST, attached=[full, read])
    t.write()
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, "demo-data-bucket")])
    out = t.analyze()
    role, b = K.iam_arn("role", "demo-both"), K.bucket("demo-data-bucket")
    edges = K.edges(out.graph, source=role, target=b)
    assert [e["type"] for e in edges] == ["FULL_ACCESS"]            # one edge: FULL_ACCESS dominates CAN_READ
    ev = edges[0]["evidence"]
    assert [s["policy_name"] for s in ev["statements"]] == ["demo-s3-full"]
    assert ev["dominated"] == [{"class": "CAN_READ", "actions": ["s3:GetObject"], "statements": [
        {"layer": "identity", "policy_arn": f"arn:aws:iam::{K.ACCT}:policy/demo-s3-read",
         "policy_name": "demo-s3-read", "sid": None, "source_type": "managed", "statement_index": 0,
         "version_id": "v1", "via_group": None}]}]
    named = {s["policy_name"] for s in ev["statements"]} | {
        s["policy_name"] for d in ev["dominated"] for s in d["statements"]}
    assert named == {"demo-s3-full", "demo-s3-read"}                # both statements are on the edge
    rec = [r for r in out.legacy("s3_relationships.json")["edges"] if r["source"] == role]
    assert len(rec) == 1 and rec[0]["type"] == "FULL_ACCESS"
    assert rec[0]["source_policies"] == ["demo-s3-full", "demo-s3-read"]
    assert K.problems(out.graph) == []


@pytest.mark.finding("F-022")
def test_no_dominated_entry_when_the_lower_class_adds_no_statement(tmp_path):
    t = K.Tree(tmp_path)
    t.iam.role("demo-star", K.EC2_TRUST, inline={"p": [rb.allow("s3:*", "*")]})
    t.write()
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, "demo-data-bucket")])
    g = t.analyze().graph
    edge = K.edges(g, "FULL_ACCESS", K.iam_arn("role", "demo-star"), K.bucket("demo-data-bucket"))[0]
    assert "dominated" not in edge["evidence"]
    assert json.dumps(edge["evidence"]).count("statement_index") == 1
