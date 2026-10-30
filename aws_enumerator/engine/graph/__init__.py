"""Graph contract: ``graph.json`` 1.x (docs/contracts/graph-json.md; 1.0 for analyses, 1.1 for ``merge``).

* :mod:`.edge_types` — the single traversability table and node-type registry (frozen).
* :mod:`.ids` — node, edge and finding identity.
* :func:`validate_graph` — the semantic invariants the JSON Schema cannot express (unique ids, no dangling
  references, registry and table consistency, the bridge invariant, finding attachment, ordering, and the
  merge-mode readings of graph-json.md §12.2). A ``graph.json`` is valid when it passes **both** the schema of
  its minor (:func:`graph_schema_name`: ``schema/graph-1.0.schema.json`` or ``graph-1.1.schema.json``) and
  this function.

Standard library only (the JSON Schema check needs ``jsonschema``, a dev dependency, and lives in tests).
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

#: What analyses write (graph-json.md §14: the lowest minor that can express the document).
GRAPH_SCHEMA_VERSION = "1.0.0"
#: What ``aws-enumerator merge`` writes (graph-json.md §4.2, D-42).
GRAPH_MERGE_SCHEMA_VERSION = "1.1.0"
FINDINGS_SCHEMA_VERSION = "1.0.0"
DIFF_SCHEMA_VERSION = "1.0.0"
SUPPRESSIONS_FILE_VERSION = 1

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schema"
SCHEMA_FILES: Mapping[str, str] = {
    "graph": "graph-1.0.schema.json",
    "graph-1.1": "graph-1.1.schema.json",
    "findings": "findings-1.0.schema.json",
}
#: graph.json minor version -> ``SCHEMA_FILES`` key (the shipped minors of graph-json.md §14).
GRAPH_SCHEMAS_BY_MINOR: Mapping[int, str] = {0: "graph", 1: "graph-1.1"}
MERGE_MODE = "merge"

SEVERITIES: Tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_RANK: Mapping[str, int] = {s: i for i, s in enumerate(SEVERITIES)}


def schema_path(name: str) -> Path:
    """Path of a shipped JSON Schema: ``"graph"`` (1.0), ``"graph-1.1"`` or ``"findings"``."""
    return SCHEMA_DIR / SCHEMA_FILES[name]


def load_schema(name: str) -> Dict[str, Any]:
    with open(schema_path(name), encoding="utf-8") as fh:
        return json.load(fh)


def graph_version(version: object) -> Optional[Tuple[int, int]]:
    """``(major, minor)`` of a ``schema_version`` string such as ``1.1.0``; ``None`` when unparsable."""
    if not isinstance(version, str):
        return None
    parts = version.split(".")
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
        return None
    return int(parts[0]), int(parts[1])


def graph_schema_name(version: object) -> Optional[str]:
    """The ``SCHEMA_FILES`` key that validates a document of ``version`` (graph-json.md §12.1).

    1.0 → ``"graph"``, 1.1 → ``"graph-1.1"``; a newer 1.x minor → ``None`` (readers then check
    :func:`validate_graph` only, §14). Anything else (another major, an unparsable value) → ``"graph"``, whose
    ``schema_version`` pattern reports the problem.
    """
    parsed = graph_version(version)
    if parsed is None or parsed[0] != 1:
        return "graph"
    return GRAPH_SCHEMAS_BY_MINOR.get(parsed[1])


def is_merge(doc: Any) -> bool:
    """``run.mode == "merge"`` (a 1.1 merged graph, graph-json.md §4.2)."""
    run = doc.get("run") if isinstance(doc, dict) else None
    return isinstance(run, dict) and run.get("mode") == MERGE_MODE


@dataclass(frozen=True)
class Problem:
    """One violated invariant. ``code`` values are listed in docs/contracts/graph-json.md §9."""

    code: str
    path: str
    message: str


def _major(version: object) -> Optional[int]:
    if not isinstance(version, str):
        return None
    head = version.split(".", 1)[0]
    return int(head) if head.isdigit() else None


def _is_weight(w: object) -> bool:
    return isinstance(w, (int, float)) and not isinstance(w, bool) and math.isfinite(w) and w >= 0


def node_sort_key(node: Mapping[str, Any]) -> Tuple[str]:
    return (str(node.get("id")),)


def edge_sort_key(edge: Mapping[str, Any]) -> Tuple[str, str, str]:
    return (str(edge.get("source")), str(edge.get("type")), str(edge.get("target")))


def finding_sort_key(f: Mapping[str, Any]) -> Tuple[int, str, str, str]:
    return (SEVERITY_RANK.get(str(f.get("severity")), 99), str(f.get("id")), str(f.get("node_id")),
            str(f.get("fingerprint")))


class _Ctx:
    """State shared by the checker functions of :func:`validate_graph`."""

    def __init__(self, doc: Mapping[str, Any], check_table: bool, check_id_patterns: bool):
        from aws_enumerator.engine.graph import edge_types, ids  # lazy: keeps `-m ...edge_types` clean

        self.et = edge_types
        self.ids = ids
        self.check_table = check_table
        self.check_id_patterns = check_id_patterns
        self.out: List[Problem] = []
        self.nodes = _list(doc, "nodes")
        self.edges = _list(doc, "edges")
        self.findings = _list(doc, "findings")
        self.node_reg = doc.get("node_types") if isinstance(doc.get("node_types"), dict) else {}
        self.edge_reg = doc.get("edge_types") if isinstance(doc.get("edge_types"), dict) else {}
        self.node_type: Dict[str, str] = {}
        self.node_by_id: Dict[str, Mapping[str, Any]] = {}
        self.by_fp: Dict[str, Mapping[str, Any]] = {}
        self.merge = is_merge(doc)

    def add(self, code: str, path: str, message: str) -> None:
        self.out.append(Problem(code, path, message))


def _list(doc: Mapping[str, Any], key: str) -> List[Tuple[int, Mapping[str, Any]]]:
    items = doc.get(key) if isinstance(doc.get(key), list) else []
    return [(i, x) for i, x in enumerate(items) if isinstance(x, dict)]


def _check_nodes(c: _Ctx) -> None:
    for i, n in c.nodes:
        nid, ntype = n.get("id"), n.get("type")
        p = f"/nodes/{i}"
        if not isinstance(nid, str):
            continue
        if nid in c.node_type:
            c.add("duplicate-node-id", p + "/id", f"node id {nid!r} appears more than once")
            continue
        c.node_type[nid] = str(ntype)
        c.node_by_id[nid] = n
        if nid.startswith("principal:"):
            c.add("principal-wildcard-node", p + "/id", "the principal:* placeholder is not a node")
        if ntype not in c.node_reg:
            c.add("node-type-unregistered", p + "/type", f"node type {ntype!r} missing from node_types")
        if c.check_table and ntype not in c.et.NODE_TYPES:
            c.add("unknown-node-type", p + "/type", f"node type {ntype!r} is not in the node-type table")
        if c.check_id_patterns and isinstance(ntype, str) and not c.ids.node_id_matches(ntype, nid):
            c.add("node-id-pattern", p + "/id", f"id {nid!r} does not follow the {ntype} id scheme")
        nt = c.et.NODE_TYPES.get(str(ntype))
        props = n.get("props")
        if c.check_table and nt is not None and isinstance(props, dict):
            if (props.get("data_asset") is True) != nt.data_asset:
                c.add("props-data-asset", p + "/props", f"data_asset must be {nt.data_asset} for {nt.name}")
            if props.get("entry_point") is True and not nt.default_source:
                c.add("props-entry-point", p + "/props", f"{nt.name} nodes are not entry points")


def _check_edge_record(c: _Ctx, i: int, e: Mapping[str, Any]) -> None:
    p = f"/edges/{i}"
    eid, src, tgt, etype = e.get("id"), e.get("source"), e.get("target"), e.get("type")
    if isinstance(src, str) and isinstance(tgt, str) and isinstance(etype, str):
        if eid != c.ids.edge_id(src, etype, tgt):
            c.add("edge-id-mismatch", p + "/id", "edge id is not ids.edge_id(source, type, target)")
    if src not in c.node_type:
        c.add("dangling-edge-source", p + "/source", f"source {src!r} is not a node")
    if tgt not in c.node_type:
        c.add("dangling-edge-target", p + "/target", f"target {tgt!r} is not a node")
    if src == tgt:
        c.add("self-loop", p, "an edge must connect two different nodes")
    if not _is_weight(e.get("weight")):
        c.add("bad-weight", p + "/weight", "weight must be a finite number >= 0")
    if not isinstance(e.get("traversable"), bool):
        c.add("bad-traversable", p + "/traversable", "traversable must be a boolean")
    if etype not in c.edge_reg:
        c.add("edge-type-unregistered", p + "/type", f"edge type {etype!r} missing from edge_types")


def _check_edge_table(c: _Ctx, i: int, e: Mapping[str, Any]) -> None:
    p = f"/edges/{i}"
    src, tgt, etype = e.get("source"), e.get("target"), e.get("type")
    et = c.et.EDGE_TYPES.get(etype) if isinstance(etype, str) else None
    if et is None:
        c.add("unknown-edge-type", p + "/type", f"edge type {etype!r} is not in the traversability table")
        return
    if e.get("category") != et.category:
        c.add("edge-category-mismatch", p + "/category", f"{etype} has category {et.category!r}")
    if e.get("traversal") != et.traversal:
        c.add("edge-traversal-mismatch", p + "/traversal", f"{etype} has traversal {et.traversal!r}")
    if e.get("traversable") is True and not et.may_traverse:
        c.add("edge-traversable-not-allowed", p + "/traversable", f"{etype} is never traversable")
    if _is_weight(e.get("weight")) and e["weight"] < et.base_weight:
        c.add("weight-below-base", p + "/weight", f"{etype} weight is below base {et.base_weight}")
    st, tt = c.node_type.get(str(src)), c.node_type.get(str(tgt))
    if st in c.et.NODE_TYPES and st not in et.sources and not _resolved_foreign(c, et.sources, src, tgt):
        c.add("edge-source-type", p + "/source", f"{etype} may not start at a {st} node")
    if tt in c.et.NODE_TYPES and tt not in et.targets and not _resolved_foreign(c, et.targets, tgt, src):
        c.add("edge-target-type", p + "/target", f"{etype} may not end at a {tt} node")
    ev = e.get("evidence") if isinstance(e.get("evidence"), dict) else {}
    rule = ev.get("traversable_rule")
    if et.traversable_rule and e.get("traversable") is True:
        holds = isinstance(rule, dict) and rule.get("rule") == et.traversable_rule and rule.get("holds") is True
        if not holds:
            c.add("traversable-rule-missing", p + "/evidence", f"{etype} is traversable only with "
                  f"evidence.traversable_rule {{rule: {et.traversable_rule!r}, holds: true}}")
    if e.get("traversable") is True and st in c.et.NODE_TYPES and c.et.NODE_TYPES[st].data_asset:
        c.add("data-asset-outgoing", p, f"traversable edge leaves data asset {src!r}")


def _resolved_foreign(c: _Ctx, allowed: Any, endpoint: Any, other: Any) -> bool:
    """Merge mode (graph-json.md §12.2): where the table admits ``external_principal`` for an endpoint, a ``user``
    or ``role`` node of another account than the other endpoint is accepted (a foreign principal resolved to the
    record of the account that collected it, §4.2)."""
    if not c.merge or "external_principal" not in allowed:
        return False
    node, peer = c.node_by_id.get(str(endpoint)), c.node_by_id.get(str(other))
    if node is None or peer is None or node.get("type") not in ("user", "role"):
        return False
    account = node.get("account")
    return isinstance(account, str) and account != peer.get("account")


def _check_edges(c: _Ctx) -> None:
    seen = set()
    incoming: Dict[str, List[Tuple[int, Mapping[str, Any]]]] = {}
    for i, e in c.edges:
        if e.get("id") in seen:
            c.add("duplicate-edge-id", f"/edges/{i}/id", f"edge id {e.get('id')!r} appears more than once")
        seen.add(e.get("id"))
        _check_edge_record(c, i, e)
        if c.check_table:
            _check_edge_table(c, i, e)
        if e.get("traversable") is True and isinstance(e.get("target"), str):
            incoming.setdefault(e["target"], []).append((i, e))
    # bridge invariant: traversable edges into compute bridges must be control (F-004)
    for tgt, ins in incoming.items():
        nt = c.et.NODE_TYPES.get(c.node_type.get(tgt, ""))
        if nt is None or not nt.is_compute_bridge:
            continue
        for i, e in ins:
            if e.get("traversal") != "control":
                c.add("bridge-invariant", f"/edges/{i}",
                      f"traversable {e.get('traversal')} edge into compute bridge {tgt!r}")


def _check_registries(c: _Ctx) -> None:
    if not c.check_table:
        return
    for name, entry in sorted(c.node_reg.items()):
        if name in c.et.NODE_TYPES and entry != c.et.node_type_entry(name):
            c.add("node-registry-mismatch", f"/node_types/{name}", "entry differs from the node-type table")
    for name, entry in sorted(c.edge_reg.items()):
        if name in c.et.EDGE_TYPES and entry != c.et.edge_type_entry(name):
            c.add("edge-registry-mismatch", f"/edge_types/{name}", "entry differs from the traversability table")


def _check_findings(c: _Ctx) -> None:
    for i, f in c.findings:
        p = f"/findings/{i}"
        fp = f.get("fingerprint")
        if fp in c.by_fp:
            c.add("duplicate-finding-fingerprint", p + "/fingerprint", f"fingerprint {fp!r} appears more than once")
        c.by_fp[str(fp)] = f
        nid = f.get("node_id")
        node = c.node_by_id.get(nid) if isinstance(nid, str) else None
        if node is None:
            c.add("finding-node-missing", p + "/node_id", f"finding node_id {nid!r} is not a node")
        elif fp not in (node.get("findings") or []):
            c.add("finding-not-on-node", p, f"node {nid!r} does not list fingerprint {fp!r}")
        refs = [(f"{p}/{k}/{j}", r) for k in ("related_node_ids", "affected_members")
                for j, r in enumerate(f.get(k) or [])]
        refs += [(f"{p}/targets/{j}", t.get("node_id")) for j, t in enumerate(f.get("targets") or [])
                 if isinstance(t, dict)]
        for path, ref in refs:
            if ref not in c.node_type:
                c.add("finding-ref-missing", path, f"{ref!r} is not a node")
    for i, n in c.nodes:
        p = f"/nodes/{i}"
        sev_seen: List[str] = []
        for key in ("findings", "inherited_findings"):
            for j, fp in enumerate(n.get(key) or []):
                f = c.by_fp.get(fp)
                if f is None:
                    c.add("node-finding-unknown", f"{p}/{key}/{j}", f"fingerprint {fp!r} is not a finding")
                    continue
                if key == "findings" and f.get("node_id") != n.get("id"):
                    c.add("node-finding-elsewhere", f"{p}/{key}/{j}", "finding is anchored at another node")
                if f.get("status") == "open":
                    sev_seen.append(str(f.get("severity")))
        expected = min(sev_seen, key=lambda s: SEVERITY_RANK.get(s, 99)) if sev_seen else None
        if n.get("max_severity") != expected:
            c.add("max-severity-mismatch", p + "/max_severity", f"expected {expected!r} from open findings")


def _merge_sources(run: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    sources = run.get("sources")
    return [s for s in sources if isinstance(s, dict)] if isinstance(sources, list) else []


def _check_merge_sources(c: _Ctx, run: Mapping[str, Any]) -> None:
    """``merge-sources`` (graph-json.md §12.2, 1.1 merge mode)."""
    sources = _merge_sources(run)
    keys = [(str(s.get("account_id")), str(s.get("run_id"))) for s in sources]
    accounts = [k[0] for k in keys]
    why = []
    if len(sources) < 2:
        why.append("fewer than 2 sources")
    if keys != sorted(keys):
        why.append("not sorted by (account_id, run_id)")
    if len(set(accounts)) != len(accounts):
        why.append("an account_id appears twice")
    if any(s.get("partition") != run.get("partition") for s in sources):
        why.append("a source partition differs from run.partition")
    if any(s.get("mode") == MERGE_MODE for s in sources):
        why.append("a source is itself a merge")
    if sources and run.get("account_id") != sources[0].get("account_id"):
        why.append("run.account_id is not sources[0].account_id")
    for reason in why:
        c.add("merge-sources", "/run/sources", reason)


def _check_run_meta(c: _Ctx, doc: Mapping[str, Any]) -> None:
    run = doc.get("run") if isinstance(doc.get("run"), dict) else {}
    op = run.get("operator") if isinstance(run.get("operator"), dict) else {}
    op_node = op.get("node_id")
    if op_node is not None and op_node not in c.node_type:
        c.add("operator-node-missing", "/run/operator/node_id", "operator node_id is not a node")
    if c.merge:
        _check_merge_sources(c, run)
    accounts = [run.get("account_id")]
    if c.merge:   # every source account's admin node (§12.2 merge mode)
        accounts += [s.get("account_id") for s in _merge_sources(run)]
    required_nodes = [(c.ids.ANONYMOUS_ID, "anonymous")]
    required_nodes += [(f"aws-enumerator:account-admin/{a}", "account_admin")
                       for a in sorted({a for a in accounts if isinstance(a, str)})]
    for required, ntype in required_nodes:
        if c.node_type.get(required) != ntype:
            c.add("synthetic-node-missing", "/nodes", f"the {ntype} node {required!r} is always emitted")
    meta = doc.get("meta") if isinstance(doc.get("meta"), dict) else {}
    for key in ("default_sources", "default_targets"):
        vals = meta.get(key) if isinstance(meta.get(key), list) else []
        for j, ref in enumerate(vals):
            if ref not in c.node_type:
                c.add("meta-ref-missing", f"/meta/{key}/{j}", f"{key} entry {ref!r} is not a node")
        if vals != sorted(set(vals), key=str):
            c.add("meta-order", f"/meta/{key}", f"{key} must be sorted and unique")

    def flagged(flag: str) -> set:
        return {nid for nid, n in c.node_by_id.items()
                if isinstance(n.get("props"), dict) and n["props"].get(flag) is True}

    entry = flagged("entry_point")
    operators = [op_node]
    if c.merge:   # every source operator node is a default source (§5, §12.2 merge mode)
        operators += [(s.get("operator") or {}).get("node_id") if isinstance(s.get("operator"), dict) else None
                      for s in _merge_sources(run)]
    entry.update(o for o in operators if isinstance(o, str) and o in c.node_type)
    if set(meta.get("default_sources") or []) != entry:
        c.add("meta-sources-mismatch", "/meta/default_sources",
              "default_sources must be the entry_point nodes plus the operator node"
              + (" and every source operator node" if c.merge else ""))
    if set(meta.get("default_targets") or []) != flagged("high_value"):
        c.add("meta-targets-mismatch", "/meta/default_targets", "default_targets must be the high_value nodes")


def _check_order(c: _Ctx, doc: Mapping[str, Any]) -> None:
    for key, sort_key in (("nodes", node_sort_key), ("edges", edge_sort_key), ("findings", finding_sort_key)):
        items = [x for _, x in _list(doc, key)]
        if items != sorted(items, key=sort_key):
            c.add("order", f"/{key}", f"{key} are not in canonical order")
    for i, n in c.nodes:
        tags = [t for t in (n.get("tags") or []) if isinstance(t, dict)]
        if tags != sorted(tags, key=lambda t: (str(t.get("key")), str(t.get("value")))):
            c.add("order", f"/nodes/{i}/tags", "tags must be sorted by key, value")


def validate_graph(doc: Any, *, check_table: bool = True, strict_order: bool = False,
                   check_id_patterns: bool = True) -> List[Problem]:
    """Semantic validation of a parsed ``graph.json`` 1.x. Returns problems; an empty list means valid.

    A merged document (``run.mode == "merge"``, 1.1) is read with the merge rules of graph-json.md §12.2:
    ``merge-sources``, an admin node per source account, the source operators among the default sources, and
    foreign principals resolved to ``user`` / ``role`` nodes where the table admits ``external_principal``.

    ``check_table``: edge records, node props and registry entries must agree with
    :data:`edge_types.EDGE_TYPES` / :data:`edge_types.NODE_TYPES` (types unknown to the table are reported
    as ``unknown-*-type``). ``strict_order``: nodes, edges, findings and tags must be in canonical order
    (F-162). ``check_id_patterns``: node ids must follow :data:`ids.NODE_ID_PATTERNS` for their type.
    """
    if not isinstance(doc, dict):
        return [Problem("not-an-object", "", "graph.json must be a JSON object")]
    c = _Ctx(doc, check_table, check_id_patterns)
    if _major(doc.get("schema_version")) != 1:
        c.add("schema-major", "/schema_version", f"unsupported schema_version {doc.get('schema_version')!r}")
    _check_nodes(c)
    _check_edges(c)
    _check_registries(c)
    _check_findings(c)
    _check_run_meta(c, doc)
    if strict_order:
        _check_order(c, doc)
    return c.out


__all__ = [
    "DIFF_SCHEMA_VERSION", "FINDINGS_SCHEMA_VERSION", "GRAPH_MERGE_SCHEMA_VERSION", "GRAPH_SCHEMAS_BY_MINOR",
    "GRAPH_SCHEMA_VERSION", "MERGE_MODE", "Problem", "SCHEMA_DIR", "SCHEMA_FILES", "SEVERITIES", "SEVERITY_RANK",
    "SUPPRESSIONS_FILE_VERSION", "edge_sort_key", "finding_sort_key", "graph_schema_name", "graph_version",
    "is_merge", "load_schema", "node_sort_key", "schema_path", "validate_graph",
]
