"""The twelve d13c215 outputs, kept for one release (graph-json.md §1, DECISIONS.md D-22; F-164).

``permission_map.json``, ``trust_relationships.json`` and the ten per-domain ``*_relationships.json`` files
keep their d13c215 names and shapes. graph.json is the contract readers should move to: it carries every edge
of every domain in one versioned, domain-neutral document (types and categories from the traversability table),
so the chronological ``newsurface`` / ``extra`` groupings are no longer part of any contract (F-164) and survive
only as these legacy names (the analyzers themselves are ``data_stores`` and ``edge_services``).

For each file, in order of preference:

1. the document an analyzer stored with ``ctx.set_legacy_output`` (an analyzer may render its own, e.g. s3 and
   ec2, to keep the d13c215 record fields);
2. otherwise a rendering of the graph's edges through ``EdgeType.legacy_*`` (old names, old directions,
   d13c215 node-id strings) plus the findings of the analyzers that declared the file;
3. an empty ``{"edges": [], "findings": []}``.

A file whose analyzer did not finish carries ``"status"`` (``error`` / ``skipped`` / ``not_implemented``), so
an empty file is never mistaken for "nothing found" (F-002, F-061).
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, Mapping, Sequence, Set

from aws_enumerator.engine.graph import edge_types as ET
from aws_enumerator.engine.graph import ids

#: The domain files, in graph-json.md §1 order.
DOMAIN_FILES: Sequence[str] = (
    "s3_relationships.json", "ec2_relationships.json", "secrets_relationships.json", "lambda_relationships.json",
    "kms_relationships.json", "compute_relationships.json", "messaging_relationships.json",
    "newsurface_relationships.json", "extra_relationships.json", "k8s_relationships.json",
)
#: Every legacy output (``AnalysisOptions.legacy_outputs``).
LEGACY_OUTPUTS: Sequence[str] = ("permission_map.json", "trust_relationships.json") + tuple(DOMAIN_FILES)
#: The analyzer (domain) behind each chronologically named file (F-164).
DOMAIN_OF_FILE: Mapping[str, str] = {
    "newsurface_relationships.json": "data_stores", "extra_relationships.json": "edge_services",
}

_K8S_LEGACY = {"Pod": "pod", "ServiceAccount": "sa", "Role": "k8srole", "ClusterRole": "k8srole",
               "Secret": "k8ssecret", "Service": "k8sservice", "Ingress": "k8singress"}
_RESOURCE_ID_TYPES = frozenset({"instance", "sg", "vpc", "subnet"})
_ARN_TYPES = frozenset({"user", "role", "group", "policy", "external_account", "external_principal", "idp"})
_LEGACY_FINDING_KEYS = ("entity", "entity_arn", "source_policy", "source_type", "resource")


def _k8s_ref(node_id: str) -> str:
    body = node_id[len(ids.K8S_PREFIX):]
    cluster_arn, _, rest = body.partition(":cluster/")
    cluster, _, tail = rest.partition("/")
    kind, _, tail = tail.partition("/")
    ns, _, name = tail.partition("/")
    ns = "cluster" if kind == "ClusterRole" else ns
    return f"{_K8S_LEGACY.get(kind, kind.lower())}:{cluster}/{ns}/{name}"


def legacy_ref(node: Mapping[str, Any]) -> str:
    """The d13c215 node-id string of a graph node (how the old files named it)."""
    nid, ntype = str(node["id"]), str(node["type"])
    if ntype == "anonymous":
        return "principal:*"
    if ntype in _ARN_TYPES:
        return nid
    if ntype in _RESOURCE_ID_TYPES:
        return nid.rsplit("/", 1)[-1]
    if ntype == "bucket":
        return "bucket:" + nid.split(":::", 1)[-1]
    if ntype == "ebssnapshot":
        return "ebssnapshot:" + nid.rsplit("/", 1)[-1]
    if ntype == "cognito":
        return "cognito:" + nid.split(":identitypool/", 1)[-1]
    if ntype == "cluster":
        return "cluster:" + nid.rsplit("/", 1)[-1]
    if ntype == "nodegroup":
        # ARN resource ``nodegroup/<cluster>/<name>/<uuid>``; d13c215 named it ``nodegroup:<cluster>/<name>``
        return "nodegroup:" + "/".join(nid.split(":nodegroup/", 1)[-1].split("/")[:2])
    if nid.startswith(ids.K8S_PREFIX):
        return _k8s_ref(nid)
    prefix = "rds" if ntype == "rdssnapshot" else ntype
    return f"{prefix}:{nid}"


def _edge_record(e: Mapping[str, Any], nodes: Mapping[str, Mapping[str, Any]], et: ET.EdgeType) -> Dict[str, Any]:
    src, dst = nodes[e["source"]], nodes[e["target"]]
    a, b = legacy_ref(src), legacy_ref(dst)
    if et.legacy_reversed:
        a, b = b, a
    rec: Dict[str, Any] = {"source": a, "target": b, "type": et.legacy_name, "weight": e["weight"],
                           "category": et.legacy_category or e["category"], "edge_id": e["id"]}
    ev = e.get("evidence") or {}
    if ev.get("actions"):
        rec["matched_actions"] = list(ev["actions"])
    if e.get("confidence") == "conditional":
        rec["has_conditions"] = True
    if (e.get("props") or {}).get("cross_account"):
        rec["is_cross_account"] = True
    return rec


def legacy_finding(f: Mapping[str, Any]) -> Dict[str, Any]:
    """A graph finding in the d13c215 finding shape (plus its fingerprint and anchor)."""
    rec = {"id": f["id"], "severity": f["severity"], "category": f.get("category"), "title": f["title"],
           "description": f["description"], "matched_actions": list(f.get("matched_actions") or []),
           "remediation": f["remediation"], "reference": f.get("reference"), "fingerprint": f["fingerprint"],
           "node_id": f["node_id"]}
    for key in _LEGACY_FINDING_KEYS:
        if key in f:
            rec[key] = f[key]
    rec.setdefault("entity_arn", f["node_id"])
    return rec


def render_from_graph(graph: Mapping[str, Any], name: str, finding_fps: Iterable[str] = ()) -> Dict[str, Any]:
    """Rebuild one domain file from the graph (for domains whose analyzer is native, step 2 above)."""
    nodes = {n["id"]: n for n in graph["nodes"]}
    edges = []
    for e in graph["edges"]:
        et = ET.EDGE_TYPES.get(e["type"])
        src = nodes.get(e["source"])
        if et is None or src is None or et.legacy_file_for(src["type"]) != name:
            continue
        edges.append(_edge_record(e, nodes, et))
    wanted: Set[str] = set(finding_fps)
    findings = [legacy_finding(f) for f in graph["findings"] if f["fingerprint"] in wanted]
    return {"edges": sorted(edges, key=_canon), "findings": sorted(findings, key=_canon)}


def _canon(record: Any) -> str:
    return json.dumps(record, sort_keys=True, default=str)


def legacy_documents(stored: Mapping[str, Any], graph: Mapping[str, Any], *,
                     file_status: Mapping[str, str], file_findings: Mapping[str, Sequence[str]]) -> Dict[str, Any]:
    """Every legacy output: ``stored`` (``ctx.legacy_outputs()``) first, else rendered, with a ``status``."""
    out: Dict[str, Any] = {
        "permission_map.json": stored.get("permission_map.json") or {"users": {}, "roles": {}, "groups": {}},
        "trust_relationships.json": stored.get("trust_relationships.json") or [],
    }
    for name in DOMAIN_FILES:
        doc = stored.get(name)
        doc = dict(doc) if isinstance(doc, Mapping) else render_from_graph(graph, name, file_findings.get(name, ()))
        status = file_status.get(name, "ok")
        if status != "ok":
            doc["status"] = status
        out[name] = doc
    return out


def render(doc: Any) -> bytes:
    """Legacy files: compact JSON (no indentation; ``,``/``:`` separators) with sorted keys for determinism.

    d13c215 wrote them with ``indent=2``, which more than doubled the size of large accounts' relationship files
    (F-022); the content is unchanged, and ``jq .`` or ``python -m json.tool`` pretty-prints them for reading.
    """
    return (json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
            + "\n").encode("utf-8")


def domain_edge_counts(documents: Mapping[str, Any]) -> Dict[str, int]:
    """``{domain: number of legacy edges}`` for the console and ``summary.legacy_edge_counts``."""
    out: Dict[str, int] = {}
    for name in DOMAIN_FILES:
        doc = documents.get(name)
        domain = DOMAIN_OF_FILE.get(name, name[: -len("_relationships.json")])
        out[domain] = len(doc.get("edges", [])) if isinstance(doc, Mapping) else 0
    return out


__all__ = [
    "DOMAIN_FILES", "DOMAIN_OF_FILE", "LEGACY_OUTPUTS", "domain_edge_counts", "legacy_documents", "legacy_finding",
    "legacy_ref", "render", "render_from_graph",
]
