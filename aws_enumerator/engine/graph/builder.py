"""``GraphBuilder``: the one place that turns analyzer output into ``graph.json`` records (engine-api.md §6.2).

Analyzers never build records by hand. The builder

* creates nodes idempotently (props merged; a placeholder is upgraded when the real resource arrives) and
  validates every id against the node-id scheme (node-ids.md);
* resolves policy principals by **exact ARN** and creates placeholder, external, service, IdP and anonymous
  nodes on demand (F-039, F-037);
* stamps ``category``, ``traversal``, ``traversable`` and ``weight`` on every edge from the traversability
  table, merges emissions on (source, type, target) (F-022) and keeps weights numeric, ``0`` included
  (F-040);
* attaches every finding to a node, creating the anchor node when needed (F-005), computes ``fp1``
  fingerprints and merges findings that share one (F-143);
* at :meth:`finalize`, enforces the bridge invariant by demotion (F-004) and data-asset terminality,
  resolves ``run.operator`` (F-146), fills ``meta``, the registries and ``max_severity``, and sorts
  everything deterministically (F-162).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Set, Tuple

from aws_enumerator.engine.graph import (
    GRAPH_SCHEMA_VERSION, SEVERITY_RANK, edge_sort_key, finding_sort_key, node_sort_key,
)
from aws_enumerator.engine.graph import edge_types as ET
from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.model import (
    FORBIDDEN_KEYS, SEVERITIES, Decision, Edge, EvalResult, Finding, Node, Strength, Tag, Tri,
)

log = logging.getLogger(__name__)

#: Evidence lists whose order carries meaning (never sorted).
ORDERED_EVIDENCE: frozenset = frozenset({"chain", "steps"})
#: Evidence lists that are unioned when two emissions of one edge merge.
MERGED_EVIDENCE_LISTS: Tuple[str, ...] = ("statements", "actions", "rule_ids", "gaps", "conditions", "via")

#: Node coverage statuses from best to worst (a merge keeps the worst).
_COVERAGE_ORDER: Tuple[str, ...] = (
    "not-applicable", "complete", "legacy-unknown", "skipped", "partial", "throttled", "error", "denied",
    "not-collected",
)
_PROP_KEY_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_")
_UNSET: Any = object()


class CatalogError(ValueError):
    """An unknown finding id or edge type (``AnalysisOptions.strict_catalog`` lets it propagate)."""


def _check_props(props: Mapping[str, Any], where: str) -> None:
    for key in props:
        if not isinstance(key, str) or not key or not key[0].isalpha() or not set(key) <= _PROP_KEY_CHARS \
                or key in FORBIDDEN_KEYS:
            raise ValueError(f"{where}: bad props key {key!r}")
    _check_nested(props, where)


def _check_nested(value: Any, where: str) -> None:
    if isinstance(value, Mapping):
        for k, v in value.items():
            if k in FORBIDDEN_KEYS:
                raise ValueError(f"{where}: forbidden key {k!r}")
            _check_nested(v, where)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _check_nested(v, where)


def _jsonable(value: Any) -> Any:
    """Plain JSON value (tuples → lists, enums → values, sets → sorted lists)."""
    if isinstance(value, (Tri, Decision, Strength)):
        return value.value
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted((_jsonable(v) for v in value), key=_canon)
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def _union(a: Iterable[Any], b: Iterable[Any]) -> List[Any]:
    seen: Dict[str, Any] = {}
    for v in list(a) + list(b):
        seen.setdefault(_canon(v), v)
    return list(seen.values())


def _sort_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in evidence.items():
        if isinstance(value, list) and key not in ORDERED_EVIDENCE:
            value = sorted(_union(value, ()), key=_canon)
        elif isinstance(value, dict):
            value = _sort_evidence(value)
        out[key] = value
    return out


def _arn_bits(node_id: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """(partition, region, account) of an ARN-shaped id (``None`` parts when absent)."""
    target = node_id
    if node_id.startswith(ids.K8S_PREFIX):
        target = node_id[len(ids.K8S_PREFIX):].split("/", 2)
        target = "/".join(target[:2]) if len(target) >= 2 else node_id
    p = ids.parse_arn(target)
    if p is None:
        return None, None, None
    acct = p.account if ids._ACCT_RE.match(p.account) else None
    region = p.region if ids._REGION_RE.match(p.region) else None
    return p.partition, region, acct


def infer_node_type(node_id: str, account_id: Optional[str] = None) -> Optional[str]:
    """The node type whose id pattern ``node_id`` matches (used to create finding anchors), else ``None``.

    An IAM user or role ARN of another account than ``account_id`` is an ``external_principal``.
    """
    matches = [t for t, pat in ids.NODE_ID_PATTERNS.items() if pat.match(node_id)]
    if "external_principal" in matches and account_id is not None:
        p = ids.parse_arn(node_id)
        if p is not None and p.account != account_id:
            return "external_principal"
        matches.remove("external_principal")
    if len(matches) == 1:
        return matches[0]
    for preferred in ("user", "role", "group", "policy", "idp", "lambda", "instance", "bucket"):
        if preferred in matches:
            return preferred
    return matches[0] if matches else None


@dataclass
class RunInfo:
    """What :meth:`GraphBuilder.finalize` needs about the run (``graph.run`` minus ``operator``)."""

    run_id: str
    account_id: str
    partition: str
    mode: str
    regions: Tuple[str, ...]
    generated_at: str
    source_manifest_sha256: Optional[str] = None


@dataclass
class OperatorInput:
    """The manifest's operator identity (graph-json.md §4.1, DECISIONS.md D-02)."""

    caller_arn: Optional[str] = None
    principal_arn: Optional[str] = None
    redacted: bool = False


@dataclass
class _FindingMeta:
    origin: Optional[str] = None
    merged: int = 0


@dataclass
class GraphBuilder:
    """Collects nodes, edges and findings for one analysis; :meth:`finalize` renders ``graph.json``."""

    account_id: str
    partition: str = "aws"
    catalog: Any = None
    strict: bool = False
    _nodes: Dict[str, Node] = field(default_factory=dict)
    _edges: Dict[Tuple[str, str, str], Edge] = field(default_factory=dict)
    _findings: Dict[str, Finding] = field(default_factory=dict)
    _fmeta: Dict[str, _FindingMeta] = field(default_factory=dict)
    _edge_origin: Dict[Tuple[str, str, str], Set[str]] = field(default_factory=dict)
    _lookup: Optional[ids.PrincipalLookup] = None
    origin: Optional[str] = None
    problems: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        ids._acct(self.account_id)
        self.add_node(ids.ANONYMOUS_ID, "anonymous", "Anyone (internet / any AWS account)", account=None,
                      partition=None, props={"entry_point": True}, coverage_status="not-applicable")
        self.add_node(ids.account_admin_id(self.account_id), "account_admin",
                      f"Administrator of {self.account_id}", account=self.account_id, partition=self.partition,
                      props={"high_value": True, "high_value_reason": "account-admin"},
                      coverage_status="not-applicable")

    # ── nodes ────────────────────────────────────────────────────────────────
    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def node(self, node_id: str) -> Optional[Node]:
        return self._nodes.get(node_id)

    def nodes(self, node_type: Optional[str] = None) -> Iterator[Node]:
        for nid in sorted(self._nodes):
            n = self._nodes[nid]
            if node_type is None or n.type == node_type:
                yield n

    def add_node(self, node_id: str, node_type: str, label: str, *, account: Any = _UNSET,
                 region: Optional[str] = None, partition: Any = _UNSET, props: Optional[Mapping[str, Any]] = None,
                 tags: Iterable[Tuple[str, str]] = (), coverage_status: Optional[str] = None,
                 coverage_gaps: Iterable[str] = ()) -> str:
        """Create or update a node; returns its id. Raises ``ValueError`` for an id outside the scheme."""
        nt = ET.NODE_TYPES.get(node_type)
        if nt is None:
            raise CatalogError(f"unknown node type {node_type!r}")
        if not isinstance(node_id, str) or not node_id or not ids.node_id_matches(node_type, node_id):
            raise ValueError(f"{node_type}: id {node_id!r} does not follow the node-id scheme")
        props = _jsonable(dict(props or {}))
        _check_props(props, f"node {node_id!r}")
        part_d, region_d, acct_d = _arn_bits(node_id)
        account = self._default_account(node_type, acct_d) if account is _UNSET else account
        partition = self._default_partition(node_type, part_d) if partition is _UNSET else partition
        region = region if region is not None else (region_d if node_type not in _GLOBAL_TYPES else None)
        status = coverage_status or ("not-applicable" if nt.synthetic else "complete")
        tag_list = [Tag(str(k), "" if v is None else str(v)) for k, v in tags]
        existing = self._nodes.get(node_id)
        if existing is None:
            self._nodes[node_id] = Node(node_id, node_type, label or node_id, account, region, partition,
                                        props, tag_list, status, list(coverage_gaps))
            self._lookup = None
            return node_id
        self._merge_node(existing, label, account, region, partition, props, tag_list, coverage_status,
                         coverage_gaps)
        return node_id

    def _default_account(self, node_type: str, from_id: Optional[str]) -> Optional[str]:
        if node_type in ("anonymous", "service_principal"):
            return None
        if from_id:
            return from_id
        if node_type in ("account_admin", "account", "region", "route53zone", "bucket", "ami", "ebssnapshot"):
            return self.account_id
        return None

    def _default_partition(self, node_type: str, from_id: Optional[str]) -> Optional[str]:
        if node_type in ("anonymous", "service_principal"):
            return None
        return from_id or self.partition

    @staticmethod
    def _merge_node(n: Node, label: str, account: Any, region: Optional[str], partition: Any,
                    props: Dict[str, Any], tags: List[Tag], status: Optional[str], gaps: Iterable[str]) -> None:
        upgrade = n.props.get("placeholder") and not props.get("placeholder")
        known = {(t.key, t.value) for t in n.tags}
        n.tags.extend(t for t in tags if (t.key, t.value) not in known)
        if upgrade:
            # the collected record replaces the reference: label, location, props and coverage (a placeholder's
            # ``not-collected`` describes the reference, not the resource; requests/e-data-1.md §1)
            n.props.pop("placeholder", None)
            n.label = label or n.label
            n.account = account if account is not None else n.account
            n.region = region if region is not None else n.region
            n.partition = partition if partition is not None else n.partition
            n.props.update(props)
            n.coverage_status = status or "complete"
            n.coverage_gaps = sorted(set(gaps))
            return
        for k, v in props.items():
            if k not in n.props or n.props[k] is None:
                n.props[k] = v
        if n.region is None and region is not None:
            n.region = region
        if status and _COVERAGE_ORDER.index(status) > _COVERAGE_ORDER.index(n.coverage_status):
            n.coverage_status = status
        n.coverage_gaps = sorted(set(n.coverage_gaps) | set(gaps))

    def set_node_props(self, node_id: str, **props: Any) -> None:
        """Overwrite props of an existing node (engine-internal flags such as ``high_value``)."""
        clean = _jsonable(props)
        _check_props(clean, f"node {node_id!r}")
        self._nodes[node_id].props.update(clean)

    def lookup(self) -> ids.PrincipalLookup:
        if self._lookup is None:
            self._lookup = ids.PrincipalLookup({nid: n.type for nid, n in self._nodes.items()})
        return self._lookup

    def ensure_principal(self, raw: str, *, principal_type: str = "AWS") -> ids.PrincipalRef:
        """Resolve a policy principal (node-ids.md §3) and create its node when the resolution names one."""
        ref = ids.resolve_principal(raw, self.lookup(), self.account_id, principal_type=principal_type,
                                    partition=self.partition)
        if ref.node_id is None or ref.node_id in self._nodes:
            return ref
        label, props = _principal_label(ref, raw)
        self.add_node(ref.node_id, ref.node_type or "external_principal", label, props=props,
                      coverage_status="not-collected" if ref.placeholder else None)
        return ref

    # ── edges ────────────────────────────────────────────────────────────────
    def has_edge(self, source: str, edge_type: str, target: str) -> bool:
        return (source, edge_type, target) in self._edges

    def edges(self, edge_type: Optional[str] = None) -> Iterator[Edge]:
        for key in sorted(self._edges):
            e = self._edges[key]
            if edge_type is None or e.type == edge_type:
                yield e

    def edge_origins(self, edge: Edge) -> Set[str]:
        return set(self._edge_origin.get((edge.source, edge.type, edge.target), ()))

    def add_edge(self, source: str, edge_type: str, target: str, *, result: Optional[EvalResult] = None,
                 confidence: Optional[str] = None, strength: Optional[str] = None, holds: Optional[bool] = None,
                 weight_extra: float = 0, evidence: Optional[Mapping[str, Any]] = None,
                 props: Optional[Mapping[str, Any]] = None) -> str:
        """Add (or merge into) the edge ``source -edge_type-> target``; returns its id."""
        et = ET.EDGE_TYPES.get(edge_type)
        if et is None:
            raise CatalogError(f"unknown edge type {edge_type!r}")
        src, tgt = self._nodes.get(source), self._nodes.get(target)
        if src is None or tgt is None:
            raise ValueError(f"{edge_type}: endpoint missing ({source!r} -> {target!r})")
        if source == target:
            raise ValueError(f"{edge_type}: self-loop on {source!r}")
        if src.type not in et.sources or tgt.type not in et.targets:
            raise ValueError(f"{edge_type} may not connect {src.type} -> {tgt.type}")
        conf, stren, ev = _decision_evidence(result, confidence, strength)
        ev.update(_jsonable(dict(evidence or {})))
        if weight_extra:
            ev["weight_extra"] = weight_extra
        traversable = self._traversable(et, holds, ev)
        weight = ET.edge_weight(edge_type, conf, stren, weight_extra)
        clean_props = _jsonable(dict(props or {}))
        _check_props(clean_props, f"edge {edge_type}")
        _check_nested(ev, f"edge {edge_type} evidence")
        key = (source, edge_type, target)
        self._edge_origin.setdefault(key, set()).add(self.origin or "engine")
        existing = self._edges.get(key)
        if existing is None:
            self._edges[key] = Edge(ids.edge_id(source, edge_type, target), source, target, edge_type,
                                    et.category, et.traversal, traversable, weight, conf, ev, clean_props)
        else:
            _merge_edge(existing, traversable, weight, conf, ev, clean_props)
        return ids.edge_id(source, edge_type, target)

    @staticmethod
    def _traversable(et: ET.EdgeType, holds: Optional[bool], ev: Dict[str, Any]) -> bool:
        rule = et.traversable_rule
        if rule:
            ok = bool(holds)
            ev["traversable_rule"] = {"rule": rule, "holds": ok}
            return ok
        return et.traversable is True

    # ── findings ─────────────────────────────────────────────────────────────
    def findings(self) -> List[Finding]:
        return [self._findings[fp] for fp in sorted(self._findings)]

    def finding(self, fingerprint: str) -> Optional[Finding]:
        return self._findings.get(fingerprint)

    def finding_origin(self, fingerprint: str) -> Optional[str]:
        meta = self._fmeta.get(fingerprint)
        return meta.origin if meta else None

    def remove_finding(self, fingerprint: str) -> None:
        self._findings.pop(fingerprint, None)
        self._fmeta.pop(fingerprint, None)

    def add_finding(self, finding_id: str, node_id: str, *, severity: str, title: str, description: str,
                    remediation: Optional[str] = None, evidence: Optional[Mapping[str, Any]] = None,
                    discriminator: str = "", confidence: str = "definite", base_severity: Optional[str] = None,
                    **optional: Any) -> str:
        """Record a finding anchored at ``node_id`` (created when missing, F-005); returns the fingerprint."""
        entry = self.catalog.get(finding_id) if self.catalog is not None else None
        if self.catalog is not None and entry is None:
            raise CatalogError(f"unknown finding id {finding_id!r}")
        canonical = entry.id if entry else finding_id
        severity = str(severity).upper()
        if severity not in SEVERITIES:
            raise ValueError(f"{finding_id}: bad severity {severity!r}")
        self._ensure_anchor(node_id)
        fp = ids.finding_fingerprint(canonical, self.account_id, node_id, discriminator or "")
        legacy_ids = sorted(set(entry.legacy_ids if entry else ()) | ({finding_id} - {canonical}))
        reference = optional.pop("reference", None) or (entry.reference if entry else None)
        category = optional.pop("category", None) or (entry.category if entry else None)
        account = optional.pop("account", self.account_id)
        extra = _finding_optional(optional)
        rec = Finding(
            fingerprint=fp, id=canonical, severity=severity, node_id=node_id, title=title or canonical,
            description=description or title or canonical,
            remediation=remediation or (entry.remediation if entry else "Review the finding."),
            reference=reference, legacy_ids=legacy_ids, base_severity=(base_severity or severity).upper(),
            confidence="conditional" if confidence == "conditional" else "definite",
            evidence=_jsonable(dict(evidence or {})), category=category, account=account, **extra,
        )
        _check_nested(rec.evidence, f"finding {canonical} evidence")
        existing = self._findings.get(fp)
        if existing is None:
            self._findings[fp] = rec
            self._fmeta[fp] = _FindingMeta(origin=self.origin)
        else:
            _merge_finding(existing, rec)
            self._fmeta[fp].merged += 1
        return fp

    def _ensure_anchor(self, node_id: str) -> None:
        if node_id in self._nodes:
            return
        ntype = infer_node_type(node_id, self.account_id) if isinstance(node_id, str) else None
        if ntype is None:
            raise ValueError(f"finding anchor {node_id!r} is not a node and its type cannot be inferred")
        self.add_node(node_id, ntype, _label_from_id(node_id), props={"placeholder": True}
                      if ntype in ("user", "role", "group") else None)

    # ── finalisation ─────────────────────────────────────────────────────────
    def finalize(self, run: RunInfo, *, generator: Mapping[str, Any], coverage: Mapping[str, Any],
                 evaluation_gaps: Iterable[Mapping[str, Any]] = (), analyzer_status: Iterable[Mapping[str, Any]] = (),
                 operator: Optional[OperatorInput] = None) -> Dict[str, Any]:
        """Apply the invariants and return the complete ``graph.json`` document (graph-json.md §2)."""
        self._apply_bridge_invariant()
        self._apply_data_asset_terminality()
        self._normalise_flags()
        self._attach_findings()
        op = self._operator(operator)
        nodes = sorted((n.to_json() for n in self._nodes.values()), key=node_sort_key)
        edges = sorted((self._edge_json(e) for e in self._edges.values()), key=edge_sort_key)
        findings = sorted((self._finding_json(f) for f in self._findings.values()), key=finding_sort_key)
        node_reg, edge_reg = ET.registries_for((n["type"] for n in nodes), (e["type"] for e in edges))
        return {
            "schema_version": GRAPH_SCHEMA_VERSION,
            "generator": dict(generator),
            "run": {"run_id": run.run_id, "account_id": run.account_id, "partition": run.partition,
                    "mode": run.mode, "regions": list(run.regions), "generated_at": run.generated_at,
                    "source_manifest_sha256": run.source_manifest_sha256, "operator": op.to_json()},
            "meta": self._meta(nodes, op),
            "node_types": node_reg, "edge_types": edge_reg,
            "nodes": nodes, "edges": edges, "findings": findings,
            "coverage": dict(coverage),
            "evaluation_gaps": sorted((dict(g) for g in evaluation_gaps), key=lambda g: str(g.get("code"))),
            "analyzer_status": [dict(s) for s in analyzer_status],
        }

    @staticmethod
    def _finding_json(f: Finding) -> Dict[str, Any]:
        out = f.to_json()
        out["evidence"] = _sort_evidence(out["evidence"])
        return out

    @staticmethod
    def _edge_json(e: Edge) -> Dict[str, Any]:
        out = e.to_json()
        out["evidence"] = _sort_evidence(out["evidence"])
        return out

    def _apply_bridge_invariant(self) -> None:
        """A compute bridge is entered only through control edges (F-004); others are demoted."""
        for e in self._edges.values():
            tgt = self._nodes[e.target]
            nt = ET.NODE_TYPES[tgt.type]
            if e.traversable and nt.is_compute_bridge and e.traversal != "control":
                e.traversable = False
                e.evidence["demoted_by"] = "bridge-invariant"
                self.problems.append(f"bridge-invariant: demoted {e.type} {e.source} -> {e.target}")

    def _apply_data_asset_terminality(self) -> None:
        for e in self._edges.values():
            if e.traversable and ET.NODE_TYPES[self._nodes[e.source].type].data_asset:
                e.traversable = False
                e.evidence["demoted_by"] = "data-asset-terminal"
                self.problems.append(f"data-asset: demoted {e.type} {e.source} -> {e.target}")

    def _normalise_flags(self) -> None:
        for n in self._nodes.values():
            nt = ET.NODE_TYPES[n.type]
            if nt.data_asset:
                n.props["data_asset"] = True
            else:
                n.props.pop("data_asset", None)
            if n.type in ET.EXTERNAL:
                n.props["external"] = True
            if n.props.get("entry_point") and not nt.default_source:
                n.props.pop("entry_point", None)
            if n.type == "anonymous":
                n.props["entry_point"] = True
            if n.type in ("user", "role", "group") and "attached_policies_status" not in n.props:
                n.props["attached_policies_status"] = "not-collected" if n.props.get("placeholder") else \
                    "legacy-unknown"
            if n.props.get("high_value") and not n.props.get("high_value_reason"):
                n.props["high_value_reason"] = "operator-marked"

    def _attach_findings(self) -> None:
        for n in self._nodes.values():
            n.findings, n.inherited_findings = [], []
        for f in self._findings.values():
            f.related_node_ids = [r for r in f.related_node_ids if r in self._nodes]
            f.affected_members = [m for m in f.affected_members if m in self._nodes]
            f.targets = [t for t in f.targets if t.get("node_id") in self._nodes]
            self._nodes[f.node_id].findings.append(f.fingerprint)
            for member in f.affected_members:
                if member != f.node_id:
                    self._nodes[member].inherited_findings.append(f.fingerprint)
        for n in self._nodes.values():
            sevs = [self._findings[fp].severity for fp in set(n.findings) | set(n.inherited_findings)
                    if self._findings[fp].status == "open"]
            n.max_severity = min(sevs, key=lambda s: SEVERITY_RANK.get(s, 99)) if sevs else None

    def _operator(self, op: Optional[OperatorInput]) -> ids.OperatorRef:
        op = op or OperatorInput()
        if not (op.caller_arn or op.principal_arn):
            return ids.OperatorRef(None, None, "unavailable", bool(op.redacted))
        return ids.resolve_operator(op.caller_arn, self.lookup(), self.account_id,
                                    principal_arn=op.principal_arn, redacted=bool(op.redacted))

    @staticmethod
    def _meta(nodes: List[Dict[str, Any]], op: ids.OperatorRef) -> Dict[str, List[str]]:
        sources = {n["id"] for n in nodes if n["props"].get("entry_point") is True}
        if op.node_id and any(n["id"] == op.node_id for n in nodes):
            sources.add(op.node_id)
        targets = {n["id"] for n in nodes if n["props"].get("high_value") is True}
        return {"default_sources": sorted(sources), "default_targets": sorted(targets)}

    # ── isolation (F-002) ────────────────────────────────────────────────────
    def mark(self) -> Tuple[frozenset, frozenset, frozenset]:
        """A checkpoint: the node, edge and finding keys present now."""
        return frozenset(self._nodes), frozenset(self._edges), frozenset(self._findings)

    def rollback(self, mark: Tuple[frozenset, frozenset, frozenset]) -> int:
        """Remove every node, edge and finding added after ``mark`` (a failed analyzer's partial output).

        Evidence merged into records that existed at ``mark`` stays (it is additive and attributed).
        Returns the number of records removed.
        """
        nodes, edges, findings = mark
        new_edges = [k for k in self._edges if k not in edges]
        new_findings = [fp for fp in self._findings if fp not in findings]
        new_nodes = [n for n in self._nodes if n not in nodes]
        for key in new_edges:
            del self._edges[key]
            self._edge_origin.pop(key, None)
        for fp in new_findings:
            self.remove_finding(fp)
        for nid in new_nodes:
            del self._nodes[nid]
        self._lookup = None
        return len(new_edges) + len(new_findings) + len(new_nodes)

    def finding_origins(self) -> Dict[str, Optional[str]]:
        """``{fingerprint: analyzer that first emitted it}``."""
        return {fp: meta.origin for fp, meta in self._fmeta.items()}

    def counts(self) -> Dict[str, int]:
        out = {"nodes": len(self._nodes), "edges": len(self._edges), "findings": len(self._findings)}
        for sev in SEVERITIES:
            out[sev.lower()] = sum(1 for f in self._findings.values() if f.severity == sev and f.status == "open")
        return out


_GLOBAL_TYPES = frozenset({
    "user", "role", "group", "policy", "idp", "service_principal", "anonymous", "account_admin", "account",
    "external_account", "external_principal", "route53zone", "cloudfront",
})
_ALLOWED_FINDING_OPTIONAL = frozenset({
    "region", "matched_actions", "related_node_ids", "targets", "subsumes", "via_group", "affected_members",
    "gaps", "detection_hint", "validate_hint", "rule_version", "suppression", "baseline_state", "status",
})
_LEGACY_FINDING_KEYS = ("entity", "entity_arn", "source_policy", "source_type", "resource")


def _finding_optional(optional: Mapping[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    legacy = {k: _jsonable(optional[k]) for k in _LEGACY_FINDING_KEYS if k in optional}
    unknown = set(optional) - _ALLOWED_FINDING_OPTIONAL - set(_LEGACY_FINDING_KEYS)
    if unknown:
        raise ValueError(f"unknown finding fields {sorted(unknown)}")
    for key in _ALLOWED_FINDING_OPTIONAL & set(optional):
        value = optional[key]
        if key in ("matched_actions", "related_node_ids", "subsumes", "affected_members", "gaps"):
            value = sorted({str(v) for v in (value or ()) if v})
        elif key == "targets":
            value = _clean_targets(value)
        out[key] = _jsonable(value)
    if legacy:
        out["legacy"] = legacy
    return out


_TARGET_DECISIONS = frozenset({"allow", "conditional"})


def _clean_targets(value: Any) -> List[Dict[str, Any]]:
    """``finding.targets`` in the contract shape ``{node_id, tier?, decision?}`` (graph-json.md §9).

    Emitters may attach more facts to a target (ARN, probe flags); the record keeps only the contract keys, a
    ``tier`` that is a severity and a ``decision`` of ``allow`` / ``conditional``. Entries without a string
    ``node_id`` are dropped (finalisation also drops targets that are not nodes).
    """
    out: List[Dict[str, Any]] = []
    for t in value or ():
        if not isinstance(t, Mapping) or not isinstance(t.get("node_id"), str) or not t.get("node_id"):
            continue
        entry: Dict[str, Any] = {"node_id": t["node_id"]}
        tier = str(t.get("tier") or "").upper()
        if tier in SEVERITIES:
            entry["tier"] = tier
        decision = t.get("decision")
        if decision in _TARGET_DECISIONS:
            entry["decision"] = decision
        if entry not in out:
            out.append(entry)
    return out


def _principal_label(ref: ids.PrincipalRef, raw: str) -> Tuple[str, Dict[str, Any]]:
    props: Dict[str, Any] = {}
    if ref.placeholder:
        props["placeholder"] = True
    if ref.node_type == "idp":
        props["provider"] = idp_provider(ref.node_id or raw)
    if ref.node_type == "external_account":
        acct = ids.parse_arn(ref.node_id or "")
        return f"External account {acct.account if acct else raw}", props
    if ref.node_type == "service_principal":
        return raw, props
    return _label_from_id(ref.node_id or raw), props


def idp_provider(node_id_or_host: str) -> str:
    """``props.provider`` of an IdP node: github, eks, cognito, saml, google, facebook, amazon or generic."""
    s = node_id_or_host.lower()
    if "saml-provider/" in s:
        return "saml"
    for needle, name in (("token.actions.githubusercontent.com", "github"), ("oidc.eks.", "eks"),
                         ("cognito-identity.amazonaws.com", "cognito"), ("accounts.google.com", "google"),
                         ("graph.facebook.com", "facebook"), ("www.amazon.com", "amazon")):
        if needle in s:
            return name
    return "generic"


def _label_from_id(node_id: str) -> str:
    """A readable label for an id that has no better one (labels are display text, never parsed)."""
    if node_id.startswith(ids.K8S_PREFIX):
        parts = node_id.split("/")
        return "/".join(parts[-2:]) if len(parts) >= 2 else node_id
    p = ids.parse_arn(node_id)
    if p is None:
        return node_id
    res = p.resource
    if p.service in ("iam", "sts"):
        return res.rsplit("/", 1)[-1] or node_id
    cut = min((i for i in (res.find("/"), res.find(":")) if i >= 0), default=-1)
    return (res[cut + 1:] if cut >= 0 else res) or node_id


def _decision_evidence(result: Optional[EvalResult], confidence: Optional[str],
                       strength: Optional[str]) -> Tuple[str, str, Dict[str, Any]]:
    ev: Dict[str, Any] = {}
    if result is not None:
        conf = result.confidence
        stren = result.strength.value if conf == "conditional" else "none"
        if not result.decision.grants:
            raise ValueError(f"an edge needs an ALLOW or CONDITIONAL decision, got {result.decision.value}")
        ev["decision"] = result.decision.value
        if result.layers:
            ev["layers"] = {k: (v.value if isinstance(v, Tri) else v) for k, v in result.layers.items()}
        if result.allow_refs:
            ev["statements"] = [r.to_json() for r in result.allow_refs]
        if result.condition_notes:
            ev["conditions"] = [{"key": n.key, "operator": n.operator, "values": list(n.values),
                                 "class": n.key_class.value, "strength": n.strength.value,
                                 "outcome": n.outcome.value} for n in result.condition_notes]
        if result.gaps:
            ev["gaps"] = sorted(result.gaps)
    else:
        conf = "conditional" if confidence == "conditional" else "definite"
        stren = (strength or "none") if conf == "conditional" else "none"
        ev["decision"] = "conditional" if conf == "conditional" else "allow"
    if stren not in ET.STRENGTH_VALUES:
        raise ValueError(f"bad condition strength {stren!r}")
    if conf == "conditional":
        ev["condition_strength"] = stren
    return conf, stren, ev


def _merge_edge(e: Edge, traversable: bool, weight: float, conf: str, ev: Dict[str, Any],
                props: Dict[str, Any]) -> None:
    """Union evidence lists, keep the more definite confidence and the minimum weight (F-022)."""
    if conf == "definite" and e.confidence == "conditional":
        e.confidence = "definite"
        e.evidence.pop("condition_strength", None)
        e.evidence["decision"] = "allow"
    for key in MERGED_EVIDENCE_LISTS:
        if key in ev or key in e.evidence:
            e.evidence[key] = _union(e.evidence.get(key, []), ev.get(key, []))
    for key, value in ev.items():
        if key not in e.evidence:
            e.evidence[key] = value
    rule = ev.get("traversable_rule")
    if rule and rule.get("holds") and not e.traversable:
        e.evidence["traversable_rule"] = rule
    e.traversable = e.traversable or traversable
    e.weight = min(e.weight, weight)
    for k, v in props.items():
        e.props.setdefault(k, v)


def _merge_finding(f: Finding, new: Finding) -> None:
    if SEVERITY_RANK[new.severity] < SEVERITY_RANK[f.severity]:
        f.severity = new.severity
    if SEVERITY_RANK[new.base_severity or new.severity] < SEVERITY_RANK[f.base_severity or f.severity]:
        f.base_severity = new.base_severity
    if new.confidence == "definite":
        f.confidence = "definite"
    f.matched_actions = sorted(set(f.matched_actions) | set(new.matched_actions))
    f.related_node_ids = sorted(set(f.related_node_ids) | set(new.related_node_ids))
    f.affected_members = sorted(set(f.affected_members) | set(new.affected_members))
    f.gaps = sorted(set(f.gaps) | set(new.gaps))
    f.targets = _union(f.targets, new.targets)
    merged = f.evidence.setdefault("merged", [])
    if new.evidence or new.legacy:
        merged.append({k: v for k, v in {"evidence": new.evidence or None,
                                         "source_policy": new.legacy.get("source_policy")}.items() if v})
    if "resource" in new.legacy:
        old = f.legacy.get("resource")
        if isinstance(old, list) and isinstance(new.legacy["resource"], list):
            f.legacy["resource"] = _union(old, new.legacy["resource"])


__all__ = ["CatalogError", "GraphBuilder", "OperatorInput", "RunInfo", "idp_provider", "infer_node_type"]
