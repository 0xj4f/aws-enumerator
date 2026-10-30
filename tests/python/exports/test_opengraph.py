"""BloodHound OpenGraph export (exports.md §6; F-141): ARN-keyed nodes, AE-prefixed kinds, only traversable edges
by default (so BloodHound never walks a structural edge, F-007), flat properties, finding ids per node (D-26)."""

from __future__ import annotations

import json

import pytest

from aws_enumerator.engine import writers
from aws_enumerator.engine.writers import opengraph as og

pytestmark = pytest.mark.finding("F-141")

PRIMITIVES = (str, int, float, bool)


def _doc(graph, **kw):
    return json.loads(writers.export(graph, "opengraph", **kw))


def _flat(value) -> bool:
    if isinstance(value, PRIMITIVES):
        return True
    return isinstance(value, list) and all(isinstance(v, PRIMITIVES) for v in value)


@pytest.mark.parametrize("name", ["example", "hostile", "analysed"])
def test_payload_shape_kinds_and_flat_properties(name, request):
    graph = request.getfixturevalue(name)
    doc = _doc(graph)
    assert doc["metadata"] == {"source_kind": "AWSEnumerator"}
    node_ids = {n["id"] for n in graph["nodes"]}
    out_nodes = doc["graph"]["nodes"]
    assert [n["id"] for n in out_nodes] == sorted(node_ids)
    types = {n["id"]: n["type"] for n in graph["nodes"]}
    for n in out_nodes:
        assert n["kinds"] == [og.kind_for(types[n["id"]]), "AWSEnumerator"]
        props = n["properties"]
        assert props["objectid"] == n["id"] and props["name"] == props["displayname"]
        assert all(_flat(v) for v in props.values()), n["id"]
    for e in doc["graph"]["edges"]:
        assert e["kind"].startswith("AE") and e["start"]["match_by"] == e["end"]["match_by"] == "id"
        assert e["start"]["value"] in node_ids and e["end"]["value"] in node_ids
        assert e["properties"]["traversable"] is True
        assert all(_flat(v) for v in e["properties"].values())


def test_only_traversable_edges_unless_all_edges(example):
    default = _doc(example)["graph"]["edges"]
    every = _doc(example, all_edges=True)["graph"]["edges"]
    assert len(default) == sum(1 for e in example["edges"] if e["traversable"])
    assert len(every) == len(example["edges"]) > len(default)
    hidden = [e for e in every if e["properties"]["traversable"] is False]
    assert hidden and all(e["kind"] != "" for e in hidden)
    ids = {e["properties"]["edge_id"] for e in every}
    assert ids == {e["id"] for e in example["edges"]}


def test_node_findings_are_finding_ids_of_exported_findings(example):
    by_fp = {f["fingerprint"]: f for f in example["findings"]}
    doc = _doc(example)
    for n in doc["graph"]["nodes"]:
        src = next(x for x in example["nodes"] if x["id"] == n["id"])
        fps = list(src.get("findings") or []) + list(src.get("inherited_findings") or [])
        expected = sorted({by_fp[fp]["id"] for fp in fps if by_fp[fp]["status"] == "open"})
        assert n["properties"].get("findings", []) == expected
        if src.get("max_severity"):
            assert n["properties"]["max_severity"] == src["max_severity"]
    with_suppressed = _doc(example, include_suppressed=True)
    total = sum(len(n["properties"].get("findings", [])) for n in with_suppressed["graph"]["nodes"])
    assert total >= sum(len(n["properties"].get("findings", [])) for n in doc["graph"]["nodes"])


def test_escalation_edges_reach_bloodhound(analysed):
    kinds = {e["kind"] for e in _doc(analysed)["graph"]["edges"]}
    assert {"AECanPassRoleTo", "AEIsAdminEquivalent", "AECanTakeover"} <= kinds
    assert "AECanModifyPermissionsOf" not in kinds and "AEHasPolicy" not in kinds   # not traversable


def test_kind_names_and_value_flattening():
    assert og.kind_for("external_principal") == "AEExternalPrincipal" and og.kind_for("k8ssecret") == "AEK8ssecret"
    assert og.kind_for("CAN_ASSUME") == "AECanAssume" and og.kind_for("MEMBER_OF") == "AEMemberOf"
    assert og.flat_value({"a": [1]}) == '{"a":[1]}' and og.flat_value([1, "x"]) == [1, "x"]
    assert og.flat_value([{"k": 1}]) == '[{"k":1}]' and og.flat_value(None) is None
