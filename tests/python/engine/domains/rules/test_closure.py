"""Privilege escalation as edges, and the closure (engine.md §4.4-§4.6; F-016).

Rules emit single-hop edges (CAN_PASS_ROLE_TO, CAN_TAKEOVER, CAN_MODIFY_PERMISSIONS_OF, CAN_ESCALATE …);
``graph/closure.py`` derives ``P -CAN_ESCALATE-> account-admin`` when P can modify a principal it can already act
as, iterates to a fixpoint and publishes ``reaches_admin``. The tests go through ``analyze_report`` (graph.json) and
through :func:`compute_closure` on a hand-built :class:`GraphBuilder`.
"""

from __future__ import annotations

import importlib

import pytest

from aws_enumerator.engine.graph import closure as C
from aws_enumerator.engine.graph.builder import GraphBuilder

W = importlib.import_module("tests.fixtures.e-rules.worlds")
allow = W.allow
LAMBDA_CHAIN = allow(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"])


@pytest.mark.finding("F-016")
def test_f016_user_passrole_admin_role_secret_is_one_directed_path(tmp_path):
    """user -> PassRole -> admin role -> secret is one directed path (the d13c215 graph had no escalation hop)."""
    w = W.World(tmp_path)
    admin = w.admin_role("demo-fn-admin", W.trusts_service("lambda.amazonaws.com"))
    dev = w.user("demo-dev", LAMBDA_CHAIN)
    secret = W.rb.secret("demo-db-password", account=W.ACCT, region=W.REGION)
    w.write("secretsmanager/secrets.json", [secret])
    out = w.analyze()
    (secret_id,) = [n["id"] for n in out.graph["nodes"] if n["type"] == "secret"]
    p = out.path(dev, secret_id)
    assert p is not None and p.nodes[:2] == (dev, admin) and p.edge_types[0] == "CAN_PASS_ROLE_TO"
    edge = out.edges("CAN_PASS_ROLE_TO", source=dev, target=admin)[0]
    assert edge["traversable"] and edge["evidence"]["via"] == ["lambda"] and "PRIVESC-014" in edge["evidence"][
        "rule_ids"]
    assert out.path_types(dev) == ["CAN_PASS_ROLE_TO", "IS_ADMIN_EQUIVALENT"]
    assert W.graph_problems(out.graph) == []


@pytest.mark.finding("F-016")
def test_takeover_and_self_escalation_edges(tmp_path):
    w = W.World(tmp_path)
    victim = w.admin_user("demo-victim")
    keys = w.user("demo-keys", allow("iam:CreateAccessKey", victim))
    selfish = w.user("demo-selfish", allow("iam:PutUserPolicy", W.arn("user", "demo-selfish")))
    out = w.analyze()
    assert out.edges("CAN_TAKEOVER", source=keys, target=victim)
    assert out.path_types(keys) == ["CAN_TAKEOVER", "IS_ADMIN_EQUIVALENT"]
    assert out.edges("CAN_ESCALATE", source=selfish, target=W.ADMIN_NODE)
    assert out.path_types(selfish) == ["CAN_ESCALATE"]


@pytest.mark.finding("F-016", "F-068")
def test_closure_turns_modify_plus_assume_into_an_escalation(tmp_path):
    """pathfinding.cloud iam-014: AttachRolePolicy + AssumeRole on a low-privilege role that trusts the account."""
    w = W.World(tmp_path)
    low = w.role("demo-low", allow("s3:ListBucket"), trust=W.trusts_account())
    attacker = w.user("demo-attacker", allow(["iam:AttachRolePolicy", "sts:AssumeRole"], "*"))
    out = w.analyze()
    modify = out.edges("CAN_MODIFY_PERMISSIONS_OF", source=attacker, target=low)
    assume = out.edges("CAN_ASSUME", source=attacker, target=low)
    assert modify and assume and not modify[0]["traversable"]
    (esc,) = out.edges("CAN_ESCALATE", source=attacker)
    assert esc["evidence"]["chain"] == [modify[0]["id"], assume[0]["id"]]
    assert esc["evidence"]["derived_by"] == "closure" and esc["confidence"] == "definite"
    f = out.finding("PRIVESC-008", attacker)
    assert (f["severity"], f["evidence"]["closure"]["previous_severity"]) == ("CRITICAL", "HIGH")
    assert out.node(attacker)["props"]["reaches_admin"] == "definite"
    assert out.path_types(attacker) == ["CAN_ESCALATE"]


@pytest.mark.finding("F-016", "F-068")
def test_modify_without_a_way_to_act_as_the_target_is_no_escalation(tmp_path):
    """The negative twin: AttachRolePolicy alone modifies the role but gives no path; it stays HIGH."""
    w = W.World(tmp_path)
    w.role("demo-low", allow("s3:ListBucket"), trust=W.trusts_account())
    attacker = w.user("demo-attacker", allow("iam:AttachRolePolicy", "*"))
    out = w.analyze()
    assert out.edges("CAN_MODIFY_PERMISSIONS_OF", source=attacker)
    assert not out.edges("CAN_ESCALATE", source=attacker)
    assert out.finding("PRIVESC-008", attacker)["severity"] == "HIGH"
    assert out.path(attacker) is None and "reaches_admin" not in out.node(attacker)["props"]


@pytest.mark.finding("F-016", "F-068")
def test_passrole_to_a_role_that_reaches_admin_is_critical(tmp_path):
    """Closure-aware tier: the passed role has no dangerous capability itself but can assume an admin role."""
    w = W.World(tmp_path)
    admin = w.admin_role("demo-admin", W.rb.trust({"AWS": W.arn("role", "demo-fn")}))
    fn = w.role("demo-fn", allow("sts:AssumeRole", admin), trust=W.trusts_service("lambda.amazonaws.com"))
    dev = w.user("demo-dev", LAMBDA_CHAIN)
    out = w.analyze()
    f = out.finding("PRIVESC-014", dev)
    assert f["severity"] == "CRITICAL" and f["evidence"]["closure"]["previous_severity"] == "MEDIUM"
    assert f["targets"] == [{"node_id": fn, "tier": "CRITICAL", "decision": "allow"}]
    assert out.path_types(dev) == ["CAN_PASS_ROLE_TO", "CAN_ASSUME", "IS_ADMIN_EQUIVALENT"]


@pytest.mark.finding("F-016", "F-068")
def test_takeover_of_a_user_that_can_escalate_is_critical(tmp_path):
    w = W.World(tmp_path)
    victim = w.user("demo-victim", allow("iam:PutUserPolicy", W.arn("user", "demo-victim")))
    keys = w.user("demo-keys", allow("iam:CreateAccessKey", victim))
    out = w.analyze()
    assert out.finding("PRIVESC-009", keys)["severity"] == "CRITICAL"
    assert out.path_types(keys) == ["CAN_TAKEOVER", "CAN_ESCALATE"]


# ── compute_closure on a hand-built builder ──────────────────────────────────

ACCT = W.ACCT


def _builder():
    b = GraphBuilder(account_id=ACCT)
    for name in ("p", "q", "r"):
        b.add_node(W.arn("user", name), "user", name)
    b.add_node(W.arn("role", "t"), "role", "t")
    return b


@pytest.mark.finding("F-016")
def test_closure_fixpoint_and_conditional_chains():
    b = _builder()
    p, q, r, t = W.arn("user", "p"), W.arn("user", "q"), W.arn("user", "r"), W.arn("role", "t")
    admin = W.ADMIN_NODE
    # p can take over q (definite); q can assume t with a WEAK condition; p can modify t's permissions
    b.add_edge(p, "CAN_TAKEOVER", q, confidence="definite")
    b.add_edge(q, "CAN_ASSUME", t, confidence="conditional", strength="weak")
    b.add_edge(p, "CAN_MODIFY_PERMISSIONS_OF", t, confidence="definite", evidence={"rule_ids": ["PRIVESC-008"]})
    b.add_edge(r, "CAN_TAKEOVER", p, confidence="definite")
    result = C.compute_closure(b, admin)
    (esc,) = result.escalations
    assert (esc.source, esc.target, esc.confidence, esc.strength) == (p, t, "conditional", "weak")
    assert esc.rule_ids == ("PRIVESC-008",) and len(esc.chain) == 3
    edge = next(b.edges("CAN_ESCALATE"))
    assert (edge.source, edge.confidence) == (p, "conditional")
    # r reaches the admin node through p (conditional, since p's escalation is conditional)
    assert result.reach_of(p) == "conditional" and result.reach_of(r) == "conditional"
    assert result.reach_of(q) is None and result.reach_of(admin) == "definite"
    assert result.iterations <= 3


@pytest.mark.finding("F-016")
def test_definite_path_wins_over_a_conditional_one():
    b = _builder()
    p, q, t = W.arn("user", "p"), W.arn("user", "q"), W.arn("role", "t")
    b.add_edge(p, "CAN_ASSUME", t, confidence="conditional", strength="strong")
    b.add_edge(p, "CAN_TAKEOVER", q, confidence="definite")
    b.add_edge(q, "CAN_ASSUME", t, confidence="definite")
    b.add_edge(p, "CAN_MODIFY_PERMISSIONS_OF", t, confidence="definite")
    (esc,) = C.compute_closure(b, W.ADMIN_NODE).escalations
    assert esc.confidence == "definite" and len(esc.chain) == 3


@pytest.mark.finding("F-016", "F-162")
def test_closure_is_deterministic_and_idempotent():
    def run():
        b = _builder()
        p, q, t = W.arn("user", "p"), W.arn("user", "q"), W.arn("role", "t")
        b.add_edge(p, "CAN_TAKEOVER", q, confidence="definite")
        b.add_edge(q, "CAN_ASSUME", t, confidence="definite")
        b.add_edge(p, "CAN_MODIFY_PERMISSIONS_OF", t, confidence="definite")
        first = C.compute_closure(b, W.ADMIN_NODE)
        second = C.compute_closure(b, W.ADMIN_NODE)
        return first, second, sorted((e.source, e.type, e.target) for e in b.edges())
    a1, a2, edges_a = run()
    b1, _, edges_b = run()
    assert a1.escalations == b1.escalations == a2.escalations and edges_a == edges_b
    assert a1.reaches_admin == b1.reaches_admin


def test_closure_registers_phase_closure():
    (spec,) = C.ANALYZERS
    assert (spec.name, spec.phase.name) == ("closure", "CLOSURE")
