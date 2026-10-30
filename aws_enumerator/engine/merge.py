"""Multi-account merge (``aws-enumerator merge``; graph.json 1.1, F-126, DECISIONS.md D-42 to D-45).

The rules are graph-json.md §4.2; the API is engine-api.md §3.5:

* :func:`plan_merge` checks the inputs. Usage problems (fewer than two roots, a root without
  ``analysis/graph.json``, a merge as input, an account twice, mixed partitions) raise
  :class:`~aws_enumerator.engine.model.AnalysisUsageError` (CLI exit 64); a source ``graph.json`` that cannot be
  read or parsed, whose major is not 1 or whose minor this build does not know, or that fails its schema or
  ``validate_graph`` raises :class:`MergeInvalid` (exit 1).
* :func:`merge_graphs` is pure: it builds the merged schema-1.1 document and validates it in memory
  (``graph-1.1.schema.json`` + ``validate_graph(strict_order=True)``), raising :class:`MergeInvalid` otherwise.
* :func:`write_merged` writes ``<run_root>/analysis/graph.json`` (0600) through ``analysis.tmp/``. Nothing else:
  ``manifest.json``, ``HANDLING.txt`` and ``SHA256SUMS`` are the CLI's (D-17, D-44).

The merge re-uses each source's analysis: nothing is re-collected or re-evaluated. Node records that share an id
are resolved by the (*second-hand*, *not-own-account*, *source index*) rule, so the account that collected a
principal provides its record and the other accounts' references (``external_principal``) join it by id. Edges
are unioned with the builder's §8 merging rule, findings by fingerprint; coverage, gaps and analyzer status are
kept per account.
"""

from __future__ import annotations

import copy
import datetime as _dt
import hashlib
import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from aws_enumerator.engine.model import AnalysisUsageError

ANALYSIS_DIR, TMP_DIR = "analysis", "analysis.tmp"
GRAPH_FILE = "graph.json"
#: Module coverage statuses that leave a merged coverage ``complete`` (graph-json.md §10.1).
_COMPLETE_MODULE_STATUSES = ("ok", "skipped")


class MergeInvalid(ValueError):
    """A source graph or the merged document violates the graph contract (CLI exit 1); ``problems`` lists why."""

    def __init__(self, message: str, problems: Sequence[str] = ()):
        detail = "; ".join(list(problems)[:10])
        more = f" (+{len(problems) - 10} more)" if len(problems) > 10 else ""
        super().__init__(f"{message}: {detail}{more}" if detail else message)
        self.problems = list(problems)


@dataclass(frozen=True)
class MergeSource:
    """One analysed run to merge (engine-api.md §3.5)."""

    run_root: Path
    account_id: str
    run_id: str
    partition: str
    graph: Dict[str, Any]
    graph_sha256: str


# ── plan ─────────────────────────────────────────────────────────────────────
def _graph_path(run_root: Path) -> Path:
    if not run_root.is_dir():
        raise AnalysisUsageError(f"{run_root.name}: not a directory")
    path = run_root / ANALYSIS_DIR / GRAPH_FILE
    if not path.is_file():
        raise AnalysisUsageError(f"{run_root.name}: no analysis/graph.json (run `aws-enumerator analyze` on it first)")
    return path


def _source_problems(doc: Mapping[str, Any]) -> List[str]:
    from aws_enumerator.engine.writers.graph_json import problems

    return problems(doc)


def _read_source(run_root: Path, path: Path) -> MergeSource:
    from aws_enumerator.engine.graph import GRAPH_SCHEMAS_BY_MINOR, graph_version, is_merge

    name = run_root.name
    try:
        raw = path.read_bytes()
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise MergeInvalid(f"{name}: analysis/graph.json cannot be read or parsed ({type(exc).__name__})") from None
    if not isinstance(doc, dict):
        raise MergeInvalid(f"{name}: analysis/graph.json is not a JSON object")
    version = graph_version(doc.get("schema_version"))
    if version is None or version[0] != 1:
        raise MergeInvalid(f"{name}: graph.json schema_version {doc.get('schema_version')!r} is not 1.x")
    if version[1] not in GRAPH_SCHEMAS_BY_MINOR:
        raise MergeInvalid(f"{name}: graph.json {doc.get('schema_version')} is newer than this build knows "
                           f"(1.{max(GRAPH_SCHEMAS_BY_MINOR)}); use a newer aws-enumerator")
    if is_merge(doc):
        raise AnalysisUsageError(f"{name}: is itself a merged graph; merge its sources instead")
    found = _source_problems(doc)
    if found:
        raise MergeInvalid(f"{name}: analysis/graph.json is invalid (re-run `aws-enumerator analyze` on it "
                           f"with this version)", found)
    run = doc["run"]
    return MergeSource(run_root, str(run["account_id"]), str(run["run_id"]), str(run["partition"]), doc,
                       hashlib.sha256(raw).hexdigest())


def plan_merge(run_roots: Sequence["str | os.PathLike[str]"]) -> Tuple[MergeSource, ...]:
    """Check the merge inputs; returns the sources sorted by (``account_id``, ``run_id``)."""
    roots = [Path(p).expanduser().absolute() for p in run_roots]
    if len(roots) < 2:
        raise AnalysisUsageError("merge needs at least two analysed runs (RUN_DIR RUN_DIR ...)")
    paths = [(root, _graph_path(root)) for root in roots]            # every 64 of this kind before any read
    sources = sorted((_read_source(root, path) for root, path in paths), key=lambda s: (s.account_id, s.run_id))
    accounts = [s.account_id for s in sources]
    twice = sorted({a for a in accounts if accounts.count(a) > 1})
    if twice:
        raise AnalysisUsageError(f"account {twice[0]} appears in more than one run; merge different accounts only "
                                 "(collect one account's regions in one run, or use --global-from)")
    partitions = sorted({s.partition for s in sources})
    if len(partitions) > 1:
        raise AnalysisUsageError(f"the runs belong to different partitions ({', '.join(partitions)})")
    return tuple(sources)


# ── merge ────────────────────────────────────────────────────────────────────
def _generated_at(value: Optional[str]) -> str:
    if value:
        return value
    raw = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    now = _dt.datetime.fromtimestamp(int(raw), _dt.timezone.utc) if raw.isdigit() else \
        _dt.datetime.now(_dt.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def _generator(git_sha: Optional[str]) -> Dict[str, Any]:
    """The merging build's ``generator`` (graph-json.md §3, §4.2)."""
    from aws_enumerator import __version__
    from aws_enumerator.engine import ENGINE_SCHEMA_VERSION
    from aws_enumerator.engine.findings.catalog import rules_version

    sha = git_sha.lower() if isinstance(git_sha, str) else None
    if sha is not None and not (7 <= len(sha) <= 40 and all(c in "0123456789abcdef" for c in sha)):
        sha = None
    return {"tool": "aws-enumerator", "version": __version__, "engine_version": ENGINE_SCHEMA_VERSION,
            "rules_version": rules_version(), "git_sha": sha}


def _source_record(s: MergeSource) -> Dict[str, Any]:
    run = s.graph["run"]
    return {"run_id": run["run_id"], "account_id": run["account_id"], "partition": run["partition"],
            "mode": run["mode"], "regions": list(run.get("regions") or []), "generated_at": run["generated_at"],
            "source_manifest_sha256": run.get("source_manifest_sha256"), "graph_sha256": s.graph_sha256,
            "generator": copy.deepcopy(s.graph["generator"]), "operator": copy.deepcopy(run["operator"])}


def _node_key(node: Mapping[str, Any], account: str, index: int) -> Tuple[bool, bool, int]:
    props = node.get("props") if isinstance(node.get("props"), dict) else {}
    second_hand = props.get("external") is True or props.get("placeholder") is True
    return second_hand, node.get("account") != account, index


def _merge_nodes(sources: Sequence[MergeSource]) -> Dict[str, Dict[str, Any]]:
    """One record per id: the smallest (second-hand, not-own-account, source index) wins (§4.2)."""
    best: Dict[str, Tuple[Tuple[bool, bool, int], Mapping[str, Any]]] = {}
    for index, s in enumerate(sources):
        for node in s.graph["nodes"]:
            key = _node_key(node, s.account_id, index)
            held = best.get(node["id"])
            if held is None or key < held[0]:
                best[node["id"]] = (key, node)
    return {nid: copy.deepcopy(node) for nid, (_key, node) in best.items()}


def _merge_edge(held: Dict[str, Any], new: Mapping[str, Any]) -> None:
    """graph-json.md §8: union the evidence lists, the more definite confidence, the minimum weight."""
    from aws_enumerator.engine.graph.builder import MERGED_EVIDENCE_LISTS, _union

    ev, new_ev = held.setdefault("evidence", {}), new.get("evidence") or {}
    if new.get("confidence") == "definite" and held.get("confidence") == "conditional":
        held["confidence"] = "definite"
        ev.pop("condition_strength", None)
        if "decision" in ev:
            ev["decision"] = "allow"
    for key in MERGED_EVIDENCE_LISTS:
        if key in ev or key in new_ev:
            ev[key] = _union(ev.get(key, []), new_ev.get(key, []))
    rule = new_ev.get("traversable_rule")
    if new.get("traversable") is True and held.get("traversable") is not True:
        held["traversable"] = True
        if isinstance(rule, dict):
            ev["traversable_rule"] = copy.deepcopy(rule)
    held["weight"] = min(held["weight"], new["weight"])


def _merge_edges(sources: Sequence[MergeSource]) -> List[Dict[str, Any]]:
    from aws_enumerator.engine.graph import edge_sort_key
    from aws_enumerator.engine.graph.builder import _sort_evidence

    merged: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for s in sources:
        for edge in s.graph["edges"]:
            key = edge_sort_key(edge)
            if key in merged:
                _merge_edge(merged[key], edge)
            else:
                merged[key] = copy.deepcopy(edge)
    out = []
    for key in sorted(merged):
        edge = merged[key]
        edge["evidence"] = _sort_evidence(edge.get("evidence") or {})
        out.append(edge)
    return out


def _merge_findings(sources: Sequence[MergeSource]) -> List[Dict[str, Any]]:
    from aws_enumerator.engine.graph import finding_sort_key

    seen: Dict[str, Dict[str, Any]] = {}
    for s in sources:
        for finding in s.graph["findings"]:
            if finding["fingerprint"] in seen:
                continue                                        # the first source in order wins
            record = copy.deepcopy(finding)
            if not record.get("account"):
                record["account"] = s.account_id
            seen[record["fingerprint"]] = record
    return sorted(seen.values(), key=finding_sort_key)


def _attach_findings(nodes: Dict[str, Dict[str, Any]], findings: Sequence[Mapping[str, Any]]) -> None:
    """Node ``findings`` / ``inherited_findings`` / ``max_severity`` exactly as the builder computes them."""
    from aws_enumerator.engine.graph import SEVERITY_RANK

    for node in nodes.values():
        node["findings"], node["inherited_findings"] = [], []
    by_fp = {f["fingerprint"]: f for f in findings}
    for f in findings:
        nodes[f["node_id"]]["findings"].append(f["fingerprint"])
        for member in f.get("affected_members") or []:
            if member != f["node_id"] and member in nodes:
                nodes[member]["inherited_findings"].append(f["fingerprint"])
    for node in nodes.values():
        sevs = [by_fp[fp]["severity"] for fp in set(node["findings"]) | set(node["inherited_findings"])
                if by_fp[fp].get("status") == "open"]
        node["max_severity"] = min(sevs, key=lambda sev: SEVERITY_RANK.get(sev, 99)) if sevs else None


def _with_account(items: Iterable[Mapping[str, Any]], account: str) -> List[Dict[str, Any]]:
    return [{**copy.deepcopy(dict(item)), "account": account} for item in items]


def _merge_coverage(sources: Sequence[MergeSource]) -> Dict[str, Any]:
    """graph-json.md §10.1 merge rule: the sources' lists concatenated, each entry with its ``account``."""
    covs = [(s.account_id, s.graph.get("coverage") or {}) for s in sources]
    source = "ledger" if all(c.get("source") == "ledger" for _a, c in covs) else "legacy-unknown"
    modules = [m for a, c in covs for m in _with_account(c.get("modules") or [], a)]
    if source != "ledger":
        status = "unknown"
    else:
        status = "complete" if all(m.get("status") in _COMPLETE_MODULE_STATUSES for m in modules) else "partial"
    out: Dict[str, Any] = {"source": source, "status": status, "modules": modules}
    for key in ("denied_apis", "facets"):
        entries = [e for a, c in covs for e in _with_account(c.get(key) or [], a)]
        if entries:
            out[key] = entries
    return out


def _merge_gaps(sources: Sequence[MergeSource]) -> List[Dict[str, Any]]:
    """§10.2 merge rule: one entry per code, first detail, summed counts, the reporting accounts."""
    gaps: Dict[str, Dict[str, Any]] = {}
    counts: Dict[str, List[int]] = {}
    for s in sources:
        for gap in s.graph.get("evaluation_gaps") or []:
            code = gap["code"]
            entry = gaps.setdefault(code, {"code": code, "detail": gap.get("detail"), "accounts": []})
            if s.account_id not in entry["accounts"]:
                entry["accounts"].append(s.account_id)
            if isinstance(gap.get("count"), int) and not isinstance(gap.get("count"), bool):
                counts.setdefault(code, []).append(gap["count"])
    for code, entry in gaps.items():
        entry["accounts"] = sorted(entry["accounts"])
        if code in counts:
            entry["count"] = sum(counts[code])
    return [gaps[code] for code in sorted(gaps)]


def _meta(nodes: Mapping[str, Mapping[str, Any]], records: Sequence[Mapping[str, Any]]) -> Dict[str, List[str]]:
    """§5: entry points plus every source operator node; every high-value node (each account's admin)."""
    def flagged(flag: str) -> set:
        return {nid for nid, n in nodes.items() if isinstance(n.get("props"), dict) and n["props"].get(flag) is True}

    sources = flagged("entry_point")
    sources.update(r["operator"].get("node_id") for r in records
                   if isinstance(r["operator"].get("node_id"), str) and r["operator"]["node_id"] in nodes)
    return {"default_sources": sorted(sources), "default_targets": sorted(flagged("high_value"))}


def merged_problems(doc: Mapping[str, Any]) -> List[str]:
    """Schema-1.1 and ``validate_graph(strict_order=True)`` problems of a merged document."""
    from aws_enumerator.engine.writers.graph_json import schema_problems
    from aws_enumerator.engine.graph import validate_graph

    out = schema_problems(doc, "graph-1.1")
    out.extend(f"{p.code}:{p.path}: {p.message}" for p in validate_graph(doc, strict_order=True))
    return out


def merge_graphs(sources: Sequence[MergeSource], *, run_id: str, generated_at: Optional[str] = None,
                 git_sha: Optional[str] = None) -> Dict[str, Any]:
    """The merged ``graph.json`` 1.1 document (pure; validated in memory, :class:`MergeInvalid` otherwise).

    ``generated_at`` defaults to ``SOURCE_DATE_EPOCH`` / now (UTC ``Z``); ``git_sha`` is the merging build's
    revision (``generator.git_sha``, the CLI passes ``buildinfo``'s value).
    """
    from aws_enumerator.engine.graph import GRAPH_MERGE_SCHEMA_VERSION, MERGE_MODE, node_sort_key
    from aws_enumerator.engine.graph import edge_types as ET

    sources = sorted(sources, key=lambda s: (s.account_id, s.run_id))
    if len(sources) < 2:
        raise AnalysisUsageError("merge needs at least two analysed runs")
    records = [_source_record(s) for s in sources]
    nodes = _merge_nodes(sources)
    edges = _merge_edges(sources)
    findings = _merge_findings(sources)
    _attach_findings(nodes, findings)
    node_list = sorted(nodes.values(), key=node_sort_key)
    node_reg, edge_reg = ET.registries_for((n["type"] for n in node_list), (e["type"] for e in edges))
    redacted = any(r["operator"].get("redacted") is True for r in records)
    doc = {
        "schema_version": GRAPH_MERGE_SCHEMA_VERSION,
        "generator": _generator(git_sha),
        "run": {"run_id": run_id, "account_id": records[0]["account_id"], "partition": records[0]["partition"],
                "mode": MERGE_MODE, "regions": sorted({r for rec in records for r in rec["regions"]}),
                "generated_at": _generated_at(generated_at), "source_manifest_sha256": None,
                "operator": {"arn": None, "node_id": None, "resolution": "unavailable", "redacted": redacted},
                "sources": records},
        "meta": _meta(nodes, records),
        "node_types": node_reg, "edge_types": edge_reg,
        "nodes": node_list, "edges": edges, "findings": findings,
        "coverage": _merge_coverage(sources),
        "evaluation_gaps": _merge_gaps(sources),
        "analyzer_status": [st for s in sources for st in _with_account(s.graph.get("analyzer_status") or [],
                                                                         s.account_id)],
    }
    found = merged_problems(doc)
    if found:
        raise MergeInvalid("the merged graph is invalid (were the sources analysed with another version? re-run "
                           "`aws-enumerator analyze` on them)", found)
    return doc


# ── write ────────────────────────────────────────────────────────────────────
def write_merged(doc: Mapping[str, Any], run_root: "str | os.PathLike[str]") -> Path:
    """Write ``<run_root>/analysis/graph.json`` (0600, 0700 directories) through ``analysis.tmp/``."""
    from aws_enumerator.engine.writers.graph_json import render
    from aws_enumerator.util.fsio import atomic_write_bytes, ensure_dir

    root = Path(run_root)
    tmp, final = root / TMP_DIR, root / ANALYSIS_DIR
    if final.exists():
        raise FileExistsError(f"{final} already exists")
    if tmp.exists():
        shutil.rmtree(tmp)
    ensure_dir(tmp)
    atomic_write_bytes(tmp / GRAPH_FILE, render(doc))
    os.rename(tmp, final)
    return final / GRAPH_FILE


__all__ = ["MergeInvalid", "MergeSource", "merge_graphs", "merged_problems", "plan_merge", "write_merged"]
