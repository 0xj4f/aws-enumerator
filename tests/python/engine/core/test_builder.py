"""GraphBuilder: identity, merging, weights, anchors, operator, invariants (graph-json.md, node-ids.md)."""

from __future__ import annotations

import pytest

ROLE = "arn:aws:iam::123456789012:role/demo-app-role"
USER = "arn:aws:iam::123456789012:user/demo-user"
BUCKET = "arn:aws:s3:::demo-data-bucket"
INSTANCE = "arn:aws:ec2:eu-west-2:123456789012:instance/i-0123456789abcdef0"
FN = "arn:aws:lambda:eu-west-2:123456789012:function:demo-fn"


def _builder(h, **kw):
    builder_mod = h.engine("graph.builder")
    catalog = h.engine("findings.catalog").build_catalog()
    return builder_mod.GraphBuilder("123456789012", "aws", catalog=catalog, **kw)


def _finalize(h, b, **kw):
    builder_mod = h.engine("graph.builder")
    run = builder_mod.RunInfo("20260101T000000Z-a1b2c3", "123456789012", "aws", "run", ("eu-west-2",),
                              "2026-01-01T00:00:00Z", None)
    gen = {"tool": "aws-enumerator", "version": "0.3.0", "engine_version": "1.0.0", "rules_version": "x",
           "git_sha": None}
    cov = {"source": "ledger", "status": "complete", "modules": []}
    return b.finalize(run, generator=gen, coverage=cov, **kw)


def _principals(h, b):
    b.add_node(USER, "user", "demo-user", props={"attached_policies_status": "complete"})
    b.add_node(ROLE, "role", "demo-app-role", props={"attached_policies_status": "complete"})
    b.add_node(BUCKET, "bucket", "demo-data-bucket", region="eu-west-2")


@pytest.mark.finding("F-037")
def test_synthetic_anonymous_and_account_admin_nodes_are_always_emitted(h):
    graph = _finalize(h, _builder(h))
    ids = {n["id"]: n for n in graph["nodes"]}
    assert ids["aws-enumerator:anonymous"]["props"] == {"entry_point": True}
    assert ids["aws-enumerator:account-admin/123456789012"]["props"]["high_value"] is True
    assert graph["meta"] == {"default_sources": ["aws-enumerator:anonymous"],
                             "default_targets": ["aws-enumerator:account-admin/123456789012"]}
    assert h.graph_problems(graph) == []


@pytest.mark.finding("F-022")
def test_edges_merge_on_source_type_target(h):
    b = _builder(h)
    _principals(h, b)
    ev1 = {"statements": [{"policy_name": "p1", "sid": "a"}], "actions": ["s3:GetObject"]}
    ev2 = {"statements": [{"policy_name": "p2", "sid": "b"}], "actions": ["s3:ListBucket", "s3:GetObject"]}
    id1 = b.add_edge(USER, "CAN_READ", BUCKET, confidence="conditional", strength="weak", evidence=ev1)
    id2 = b.add_edge(USER, "CAN_READ", BUCKET, evidence=ev2)
    assert id1 == id2 == h.engine("graph.ids").edge_id(USER, "CAN_READ", BUCKET)
    graph = _finalize(h, b)
    [edge] = h.edges(graph, "CAN_READ")
    assert edge["confidence"] == "definite" and edge["weight"] == 1          # definite wins, minimum weight
    assert edge["evidence"]["actions"] == ["s3:GetObject", "s3:ListBucket"]
    assert len(edge["evidence"]["statements"]) == 2
    assert "condition_strength" not in edge["evidence"]
    assert h.graph_problems(graph) == []


@pytest.mark.finding("F-040")
def test_weights_are_numeric_zero_is_legal_and_never_below_base(h):
    b = _builder(h)
    _principals(h, b)
    b.add_edge(USER, "FULL_ACCESS", BUCKET)
    b.add_edge(ROLE, "FULL_ACCESS", BUCKET, confidence="conditional", strength="strong")
    graph = _finalize(h, b)
    weights = {e["source"]: e["weight"] for e in h.edges(graph, "FULL_ACCESS")}
    assert weights[USER] == 0 and isinstance(weights[USER], (int, float))
    assert weights[ROLE] == 3                                                 # base 0 + strong penalty
    assert h.engine("graph.traverse").shortest_path(graph, USER, BUCKET).cost == 0


@pytest.mark.finding("F-005")
def test_findings_are_attached_and_missing_anchors_are_created(h):
    b = _builder(h)
    fp = b.add_finding("S3-PUBLIC-001", BUCKET, severity="HIGH", title="t", description="d")
    fp2 = b.add_finding("EC2-IMDS-001", INSTANCE, severity="MEDIUM", title="t", description="d")
    graph = _finalize(h, b)
    nodes = h.nodes_by_id(graph)
    assert nodes[BUCKET]["type"] == "bucket" and fp in nodes[BUCKET]["findings"]
    assert nodes[INSTANCE]["type"] == "instance" and fp2 in nodes[INSTANCE]["findings"]
    assert nodes[BUCKET]["max_severity"] == "HIGH"
    assert {f["node_id"] for f in graph["findings"]} == {BUCKET, INSTANCE}
    with pytest.raises(ValueError):
        b.add_finding("S3-PUBLIC-001", "bucket/not-an-id", severity="HIGH", title="t", description="d")
    assert h.graph_problems(graph) == []


def test_unknown_finding_ids_and_edge_types_are_catalog_errors(h):
    b = _builder(h)
    _principals(h, b)
    err = h.engine("graph.builder").CatalogError
    with pytest.raises(err):
        b.add_finding("NOT-A-REAL-ID-999", BUCKET, severity="LOW", title="t", description="d")
    with pytest.raises(err):
        b.add_edge(USER, "NOT_A_TYPE", BUCKET)
    with pytest.raises(ValueError):
        b.add_edge(BUCKET, "CAN_READ", USER)                                   # endpoint types


@pytest.mark.finding("F-039")
def test_principals_resolve_by_exact_arn_never_by_name(h):
    b = _builder(h)
    _principals(h, b)
    foreign = "arn:aws:iam::999999999999:role/demo-app-role"
    ref = b.ensure_principal(foreign)
    assert ref.node_id == foreign and ref.node_type == "external_principal" and ref.external
    assert b.ensure_principal("999999999999").node_id == "arn:aws:iam::999999999999:root"
    local = "arn:aws:iam::123456789012:role/demo-uncollected"
    ref = b.ensure_principal(local)
    assert ref.node_type == "role" and ref.placeholder and b.node(local).props["placeholder"] is True
    assert b.ensure_principal("*").node_id == "aws-enumerator:anonymous"
    assert b.ensure_principal("arn:aws:iam::123456789012:root").node_id is None   # identity policies decide
    graph = _finalize(h, b)
    nodes = h.nodes_by_id(graph)
    assert nodes[foreign]["props"]["external"] is True and nodes[ROLE]["account"] == "123456789012"
    assert h.graph_problems(graph) == []


@pytest.mark.finding("F-146")
def test_operator_session_maps_to_its_role_and_redaction_uses_the_principal(h):
    op = h.engine("graph.builder").OperatorInput
    b = _builder(h)
    _principals(h, b)
    graph = _finalize(h, b, operator=op("arn:aws:sts::123456789012:assumed-role/demo-app-role/demo-session"))
    assert graph["run"]["operator"] == {"arn": "arn:aws:sts::123456789012:assumed-role/demo-app-role/demo-session",
                                        "node_id": ROLE, "resolution": "assumed-role", "redacted": False}
    assert ROLE in graph["meta"]["default_sources"]
    graph = _finalize(h, b, operator=op(None, "arn:aws:iam::123456789012:role/demo-app-role", True))
    assert graph["run"]["operator"]["redacted"] is True and graph["run"]["operator"]["node_id"] == ROLE
    graph = _finalize(h, b, operator=op("arn:aws:sts::999999999999:assumed-role/x/y"))
    assert graph["run"]["operator"]["resolution"] == "cross-account" and graph["run"]["operator"]["node_id"] is None
    assert _finalize(h, b)["run"]["operator"]["resolution"] == "unavailable"


def test_bridge_invariant_demotes_non_control_edges_into_compute(h):
    b = _builder(h)
    _principals(h, b)
    b.add_node(FN, "lambda", "demo-fn")
    b.add_edge(USER, "CAN_INVOKE", FN)
    b.add_edge(USER, "CAN_UPDATE_CODE", FN)
    graph = _finalize(h, b)
    by_type = {e["type"]: e for e in graph["edges"]}
    assert by_type["CAN_UPDATE_CODE"]["traversable"] is True
    assert by_type["CAN_INVOKE"]["traversable"] is False
    assert h.graph_problems(graph) == []


def test_conditional_rule_edges_carry_their_rule_and_merge_to_holds(h):
    b = _builder(h)
    b.add_node(USER, "user", "u", props={"attached_policies_status": "complete"})
    group = "arn:aws:iam::123456789012:group/demo-group"
    b.add_node(group, "group", "g", props={"attached_policies_status": "complete"})
    b.add_edge(USER, "MEMBER_OF", group, holds=False)
    graph = _finalize(h, b)
    [edge] = graph["edges"]
    assert edge["traversable"] is False and edge["evidence"]["traversable_rule"] == {
        "rule": "member-not-reduced", "holds": False}
    b.add_edge(USER, "MEMBER_OF", group, holds=True)
    [edge] = _finalize(h, b)["edges"]
    assert edge["traversable"] is True and edge["evidence"]["traversable_rule"]["holds"] is True


@pytest.mark.finding("F-002")
def test_rollback_removes_a_failed_analyzers_partial_output(h):
    b = _builder(h)
    _principals(h, b)
    mark = b.mark()
    b.add_node(FN, "lambda", "demo-fn")
    b.add_edge(USER, "CAN_UPDATE_CODE", FN)
    b.add_finding("LAMBDA-URL-001", FN, severity="HIGH", title="t", description="d")
    assert b.rollback(mark) == 3
    assert not b.has_node(FN) and not list(b.edges()) and not b.findings()


def test_finding_targets_are_normalised_to_the_contract_shape(h):
    b = _builder(h)
    _principals(h, b)
    b.add_finding("DANGER-001", USER, severity="CRITICAL", title="t", description="d",
                  targets=[{"node_id": ROLE, "arn": ROLE, "tier": "self", "decision": "allow", "probe": True},
                           {"arn": "no-node-id"}])
    graph = _finalize(h, b)
    assert graph["findings"][0]["targets"] == [{"node_id": ROLE, "decision": "allow"}]
    assert h.graph_problems(graph) == []


def test_props_with_forbidden_keys_are_refused(h):
    b = _builder(h)
    with pytest.raises(ValueError):
        b.add_node(USER, "user", "u", props={"__proto__": 1})
    with pytest.raises(ValueError):
        b.add_node(USER, "user", "u", props={"nested": {"constructor": 1}})


@pytest.mark.finding("F-027", "F-059")
def test_a_placeholder_upgraded_by_the_collected_record_takes_its_coverage(h):
    """A node first created from a reference (an encryption key another domain names) is ``not-collected``; when the
    collecting domain adds the real record, its label and coverage replace the placeholder's (request e-data-1 §1).
    Merging two collected records still keeps the worse coverage."""
    key = "arn:aws:kms:eu-west-2:123456789012:key/1a2b3c4d-aaaa-4bbb-8ccc-0e1f2a3b4c5d"
    b = _builder(h)
    b.add_node(key, "kms", "key/1a2b3c4d", props={"placeholder": True}, coverage_status="not-collected")
    b.add_node(key, "kms", "demo-key", props={"key_manager": "CUSTOMER"}, coverage_status="partial",
               coverage_gaps=["kms:grants-unknown"])
    node = b.node(key)
    assert (node.label, node.coverage_status, node.coverage_gaps) == ("demo-key", "partial", ["kms:grants-unknown"])
    assert "placeholder" not in node.props and node.props["key_manager"] == "CUSTOMER"
    b.add_node(key, "kms", "demo-key", coverage_status="error", coverage_gaps=["kms:key-policy-unknown"])
    assert b.node(key).coverage_status == "error"                          # collected + collected: worse wins
    assert b.node(key).coverage_gaps == ["kms:grants-unknown", "kms:key-policy-unknown"]
    assert h.graph_problems(_finalize(h, b)) == []
