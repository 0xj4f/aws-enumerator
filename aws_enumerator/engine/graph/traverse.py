"""Directed path finding over a ``graph.json`` document (graph-json.md §11, normative).

Semantics, shared with the dashboard's ``graph-core.js`` and the test reference ``tests/support/ref_paths.py``
through the vectors in ``tests/fixtures/graph/path_cases.json``:

1. Walk an edge only from ``source`` to ``target`` (F-007), and only when ``traversable is True``.
2. Cost is the sum of stored weights; ``0`` is a real zero (F-040). A non-numeric, negative or non-finite
   weight (only possible in invalid input) counts as 1.
3. ``source == target`` is not a path query.
4. Ties: lowest cost, then fewest hops, then the lexicographically smallest sequence of edge ids.
5. Options: ``exclude_categories``, ``exclude_node_types`` (an edge is usable only when neither endpoint's
   type is hidden) and ``definite_only`` (conditional edges are skipped).
"""

from __future__ import annotations

import heapq
import itertools
import math
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


@dataclass(frozen=True)
class PathResult:
    """One cheapest path: total cost, hop count, node ids, edge ids and edge types in walk order."""

    cost: float
    hops: int
    nodes: Tuple[str, ...]
    edges: Tuple[str, ...]
    edge_types: Tuple[str, ...]


def edge_weight(edge: Mapping[str, Any]) -> float:
    """The stored weight, or 1 for an invalid one (graph-json.md §11.3)."""
    w = edge.get("weight")
    if isinstance(w, (int, float)) and not isinstance(w, bool) and math.isfinite(w) and w >= 0:
        return w
    return 1


class PathIndex:
    """Adjacency of the active subgraph of one document, built once for many queries."""

    def __init__(self, graph: Mapping[str, Any], *, exclude_categories: Iterable[str] = (),
                 exclude_node_types: Iterable[str] = (), definite_only: bool = False):
        self.node_types: Dict[str, Any] = {
            n["id"]: n.get("type") for n in graph.get("nodes", []) if isinstance(n, Mapping) and "id" in n}
        hidden_cats, hidden_types = set(exclude_categories), set(exclude_node_types)
        self.adj: Dict[str, List[Mapping[str, Any]]] = {}
        for e in graph.get("edges", []):
            if self._usable(e, hidden_cats, hidden_types, definite_only):
                self.adj.setdefault(e["source"], []).append(e)

    def _usable(self, e: Any, hidden_cats: set, hidden_types: set, definite_only: bool) -> bool:
        if not isinstance(e, Mapping) or e.get("traversable") is not True:
            return False
        s, t = e.get("source"), e.get("target")
        if s not in self.node_types or t not in self.node_types or s == t:
            return False
        if e.get("category") in hidden_cats or (definite_only and e.get("confidence") != "definite"):
            return False
        return self.node_types[s] not in hidden_types and self.node_types[t] not in hidden_types

    def shortest_path(self, source: str, target: str) -> Optional[PathResult]:
        """Cheapest directed path from ``source`` to ``target``, or ``None``."""
        if source == target or source not in self.node_types or target not in self.node_types:
            return None
        counter = itertools.count()
        heap: List[Tuple[float, int, Tuple[str, ...], int, str, Tuple[Mapping[str, Any], ...]]] = [
            (0, 0, (), next(counter), source, ())]
        best: Dict[str, Tuple[float, int, Tuple[str, ...]]] = {source: (0, 0, ())}
        while heap:
            cost, hops, key, _, node, path = heapq.heappop(heap)
            if best.get(node) != (cost, hops, key):
                continue
            if node == target:
                return PathResult(cost, hops, (source,) + tuple(e["target"] for e in path),
                                  tuple(str(e["id"]) for e in path), tuple(str(e["type"]) for e in path))
            for e in self.adj.get(node, ()):
                nxt = e["target"]
                cand = (cost + edge_weight(e), hops + 1, key + (str(e.get("id")),))
                if nxt not in best or cand < best[nxt]:
                    best[nxt] = cand
                    heapq.heappush(heap, (cand[0], cand[1], cand[2], next(counter), nxt, path + (e,)))
        return None

    def reachable(self, source: str) -> List[str]:
        """Sorted ids reachable from ``source`` (``source`` excluded)."""
        seen = {source}
        stack = [source]
        while stack:
            for e in self.adj.get(stack.pop(), ()):
                if e["target"] not in seen:
                    seen.add(e["target"])
                    stack.append(e["target"])
        seen.discard(source)
        return sorted(seen)


def shortest_path(graph: Mapping[str, Any], source: str, target: str, **options: Any) -> Optional[PathResult]:
    """Cheapest directed path (module docstring); ``options`` are the :class:`PathIndex` keywords."""
    return PathIndex(graph, **options).shortest_path(source, target)


def reachable(graph: Mapping[str, Any], source: str, **options: Any) -> List[str]:
    """Sorted node ids reachable from ``source`` over usable edges."""
    return PathIndex(graph, **options).reachable(source)


__all__ = ["PathIndex", "PathResult", "edge_weight", "reachable", "shortest_path"]
