"""BloodHound OpenGraph export of the attack graph (exports.md §6; F-141).

The payload is ``{"metadata": {"source_kind": "AWSEnumerator"}, "graph": {"nodes": [...], "edges": [...]}}``
for BloodHound CE's generic ingest:

* **node kinds** ``"AE" + PascalCase(node type)`` plus the base kind ``AWSEnumerator`` (``role`` → ``AERole``,
  ``external_principal`` → ``AEExternalPrincipal``); **edge kinds** ``"AE" + PascalCase(edge type)``
  (``CAN_ASSUME`` → ``AECanAssume``). The prefix avoids colliding with other AWS collectors' kinds;
* **only traversable edges by default**: BloodHound walks every edge it is given, so exporting structural or info
  edges would recreate the undirected-path bug (F-007) there. ``all_edges`` exports them too, still marked
  ``traversable: false``;
* **flat properties**: strings, numbers, booleans or arrays of those. Primitive ``props`` (and arrays of
  primitives) are copied; anything else is serialised as a JSON string; ``null`` values are left out. Node
  ``findings`` lists the distinct finding **ids** (not fingerprints, D-26) of the exported findings anchored at
  or inherited by the node, sorted;
* node ids are the graph's ids (full ARNs or the engine's synthetic ids), so the exports of several accounts, or
  of ``aws-enumerator merge``, join on ARNs. Output is sorted and deterministic.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Mapping, Optional, Set

from aws_enumerator.engine.writers.csv import select_findings

SOURCE_KIND = "AWSEnumerator"
KIND_PREFIX = "AE"
_SPLIT = re.compile(r"[^A-Za-z0-9]+")
#: Node keys exported as fixed properties; ``props`` never overwrite them.
_FIXED_NODE_KEYS = frozenset({"name", "displayname", "objectid", "account", "region", "partition", "high_value",
                              "max_severity", "findings", "node_type", "coverage_status"})
_FIXED_EDGE_KEYS = frozenset({"traversal", "traversable", "weight", "confidence", "category", "edge_id",
                              "edge_type"})


def pascal_case(name: str) -> str:
    """``external_principal`` → ``ExternalPrincipal``; ``CAN_ASSUME`` → ``CanAssume``; ``k8ssecret`` → ``K8ssecret``."""
    return "".join(part[:1].upper() + part[1:].lower() for part in _SPLIT.split(name) if part)


def kind_for(type_name: str) -> str:
    return KIND_PREFIX + pascal_case(type_name)


def _primitive(value: Any) -> bool:
    return value is None or isinstance(value, (str, bool, int, float))


def flat_value(value: Any) -> Any:
    """An OpenGraph property value: primitives and primitive arrays as they are, everything else as JSON text."""
    if _primitive(value):
        return value
    if isinstance(value, (list, tuple)) and all(_primitive(v) and v is not None for v in value):
        return list(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _copy_props(target: Dict[str, Any], props: Any, reserved: frozenset) -> None:
    if not isinstance(props, Mapping):
        return
    for key in sorted(props):
        if not isinstance(key, str) or key in reserved or key in target:
            continue
        value = flat_value(props[key])
        if value is not None:
            target[key] = value


def _node_finding_ids(graph: Mapping[str, Any], exported_fps: Set[str]) -> Dict[str, List[str]]:
    by_fp = {f["fingerprint"]: f.get("id") for f in graph.get("findings") or ()
             if isinstance(f, Mapping) and isinstance(f.get("fingerprint"), str)}
    out: Dict[str, List[str]] = {}
    for node in graph.get("nodes") or ():
        if not isinstance(node, Mapping):
            continue
        fps = list(node.get("findings") or ()) + list(node.get("inherited_findings") or ())
        ids = {by_fp[fp] for fp in fps if fp in exported_fps and isinstance(by_fp.get(fp), str)}
        out[node.get("id")] = sorted(ids)
    return out


def _node(node: Mapping[str, Any], finding_ids: List[str]) -> Dict[str, Any]:
    label = node.get("label") if isinstance(node.get("label"), str) else node.get("id")
    props: Mapping[str, Any] = node.get("props") if isinstance(node.get("props"), Mapping) else {}
    coverage = node.get("coverage") if isinstance(node.get("coverage"), Mapping) else {}
    fixed = {
        "name": label, "displayname": label, "objectid": node.get("id"), "node_type": node.get("type"),
        "account": node.get("account"), "region": node.get("region"), "partition": node.get("partition"),
        "high_value": props.get("high_value") is True, "max_severity": node.get("max_severity"),
        "findings": finding_ids, "coverage_status": coverage.get("status"),
    }
    properties = {k: v for k, v in fixed.items() if v is not None}
    _copy_props(properties, props, _FIXED_NODE_KEYS)
    return {"id": node.get("id"), "kinds": [kind_for(str(node.get("type"))), SOURCE_KIND],
            "properties": properties}


def _edge(edge: Mapping[str, Any]) -> Dict[str, Any]:
    fixed = {"traversal": edge.get("traversal"), "traversable": edge.get("traversable") is True,
             "weight": edge.get("weight"), "confidence": edge.get("confidence"), "category": edge.get("category"),
             "edge_id": edge.get("id"), "edge_type": edge.get("type")}
    properties = {k: v for k, v in fixed.items() if v is not None}
    _copy_props(properties, edge.get("props"), _FIXED_EDGE_KEYS)
    return {"kind": kind_for(str(edge.get("type"))),
            "start": {"value": edge.get("source"), "match_by": "id"},
            "end": {"value": edge.get("target"), "match_by": "id"},
            "properties": properties}


def document(graph: Mapping[str, Any], *, min_severity: Optional[str] = None, include_suppressed: bool = False,
             all_edges: bool = False) -> Dict[str, Any]:
    """The OpenGraph payload (nodes sorted by id, edges by (source, type, target))."""
    sel = select_findings(graph, min_severity=min_severity, include_suppressed=include_suppressed)
    exported = {f["fingerprint"] for f in sel.findings if isinstance(f.get("fingerprint"), str)}
    per_node = _node_finding_ids(graph, exported)
    nodes = [_node(n, per_node.get(n.get("id"), [])) for n in graph.get("nodes") or ()
             if isinstance(n, Mapping) and isinstance(n.get("id"), str)]
    edges = [_edge(e) for e in graph.get("edges") or ()
             if isinstance(e, Mapping) and (all_edges or e.get("traversable") is True)]
    nodes.sort(key=lambda n: n["id"])
    edges.sort(key=lambda e: (str(e["start"]["value"]), e["kind"], str(e["end"]["value"])))
    return {"metadata": {"source_kind": SOURCE_KIND}, "graph": {"nodes": nodes, "edges": edges}}


def render(graph: Mapping[str, Any], *, min_severity: Optional[str] = None, include_suppressed: bool = False,
           all_edges: bool = False) -> bytes:
    """``opengraph.json`` (exports.md §6)."""
    doc = document(graph, min_severity=min_severity, include_suppressed=include_suppressed, all_edges=all_edges)
    return (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


__all__ = ["KIND_PREFIX", "SOURCE_KIND", "document", "flat_value", "kind_for", "pascal_case", "render"]
