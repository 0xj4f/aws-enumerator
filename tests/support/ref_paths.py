"""Reference directed Dijkstra over a ``graph.json`` document (test-only).

This is the executable definition of the path semantics in docs/contracts/graph-json.md §8. The shared
vectors in ``tests/fixtures/graph/path_cases.json`` are checked against it; the production traversal
(``engine/graph/traverse.py``, Wave 1) and the dashboard's ``graph-core.js`` must give the same answers.

Semantics:

* Walk only edges whose record has ``traversable: true``, from ``source`` to ``target``.
* Cost is the sum of stored weights; ``0`` is a real zero cost (F-040). A missing or invalid weight counts
  as 1 (only possible in schema-invalid input).
* ``source == target`` is not a path query: no path is returned.
* Options: ``exclude_categories`` (hidden edge categories), ``exclude_node_types`` (an edge is usable only
  when neither endpoint's type is hidden), ``definite_only`` (skip ``confidence: conditional`` edges).
* Ties break by (cost, hops, then the sequence of edge ids, lexicographically) — the same rule as
  ``graph-core.js`` ``dijkstra`` (docs/contracts/dashboard-core-api.md §2.5).

Also re-exports :func:`engine_module` / :func:`engine_schema_dir` and the fixture/contract directories for
existing callers; they are thin aliases of the ``tests/support/targets.py`` accessors added for request
``contracts-engine-1`` (new code should call ``targets`` directly).
"""

from __future__ import annotations

import heapq
import itertools
import math
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from tests.support import targets

FIXTURES_GRAPH_DIR = targets.GRAPH_FIXTURES_DIR
FIXTURES_GRAPH_INVALID_DIR = targets.GRAPH_INVALID_FIXTURES_DIR
CONTRACTS_DIR = targets.CONTRACTS_DIR


def engine_module(name: str) -> ModuleType:
    """``aws_enumerator.engine.<name>`` (alias of ``targets.engine_module``)."""
    return targets.engine_module(name)


def engine_schema_dir() -> Path:
    """The engine schema directory (alias of ``targets.engine_schema_dir``)."""
    return targets.engine_schema_dir()


@dataclass(frozen=True)
class PathResult:
    cost: float
    hops: int
    nodes: Tuple[str, ...]
    edges: Tuple[str, ...]
    edge_types: Tuple[str, ...]


def _weight(e: Mapping[str, Any]) -> float:
    w = e.get("weight")
    if isinstance(w, (int, float)) and not isinstance(w, bool) and math.isfinite(w) and w >= 0:
        return w
    return 1


def usable_edges(graph: Mapping[str, Any], *, exclude_categories: Iterable[str] = (),
                 exclude_node_types: Iterable[str] = (),
                 definite_only: bool = False) -> Dict[str, List[Mapping[str, Any]]]:
    """Adjacency (source id → edges) of the active subgraph."""
    nodes = {n["id"]: n for n in graph.get("nodes", []) if isinstance(n, dict) and "id" in n}
    hidden_cats = set(exclude_categories)
    hidden_types = set(exclude_node_types)
    adj: Dict[str, List[Mapping[str, Any]]] = {}
    for e in graph.get("edges", []):
        if not isinstance(e, dict) or e.get("traversable") is not True:
            continue
        s, t = e.get("source"), e.get("target")
        if s not in nodes or t not in nodes or s == t:
            continue
        if e.get("category") in hidden_cats:
            continue
        if definite_only and e.get("confidence") != "definite":
            continue
        if nodes[s].get("type") in hidden_types or nodes[t].get("type") in hidden_types:
            continue
        adj.setdefault(s, []).append(e)
    return adj


def shortest_path(graph: Mapping[str, Any], source: str, target: str, *, exclude_categories: Iterable[str] = (),
                  exclude_node_types: Iterable[str] = (), definite_only: bool = False) -> Optional[PathResult]:
    """Cheapest directed path, or ``None``. See the module docstring for the exact semantics."""
    if source == target:
        return None
    adj = usable_edges(graph, exclude_categories=exclude_categories, exclude_node_types=exclude_node_types,
                       definite_only=definite_only)
    node_ids = {n.get("id") for n in graph.get("nodes", []) if isinstance(n, dict)}
    if source not in node_ids or target not in node_ids:
        return None
    counter = itertools.count()
    # (cost, hops, edge-id sequence, tiebreak, node, edges)
    heap: List[Tuple[float, int, Tuple[str, ...], int, str, Tuple[Mapping[str, Any], ...]]] = [
        (0, 0, (), next(counter), source, ())]
    best: Dict[str, Tuple[float, int, Tuple[str, ...]]] = {source: (0, 0, ())}
    while heap:
        cost, hops, key, _, node, path = heapq.heappop(heap)
        if best.get(node) != (cost, hops, key):
            continue
        if node == target:
            return PathResult(cost, hops, (source,) + tuple(e["target"] for e in path),
                              tuple(e["id"] for e in path), tuple(e["type"] for e in path))
        for e in adj.get(node, ()):
            nxt = e["target"]
            cand = (cost + _weight(e), hops + 1, key + (str(e["id"]),))
            if nxt not in best or cand < best[nxt]:
                best[nxt] = cand
                heapq.heappush(heap, (cand[0], cand[1], cand[2], next(counter), nxt, path + (e,)))
    return None


def reachable(graph: Mapping[str, Any], source: str, **opts: Any) -> List[str]:
    """Sorted ids reachable from ``source`` over usable edges (``source`` excluded)."""
    adj = usable_edges(graph, **opts)
    seen = {source}
    stack = [source]
    while stack:
        n = stack.pop()
        for e in adj.get(n, ()):
            if e["target"] not in seen:
                seen.add(e["target"])
                stack.append(e["target"])
    seen.discard(source)
    return sorted(seen)
