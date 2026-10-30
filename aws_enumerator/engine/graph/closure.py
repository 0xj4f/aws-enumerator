"""Privilege-escalation closure over the attack graph (engine.md §4.6; F-016, F-068).

Phase CLOSURE runs after the rules emitted their single-hop edges (CAN_PASS_ROLE_TO, CAN_TAKEOVER, CAN_ESCALATE,
CAN_MODIFY_PERMISSIONS_OF, CAN_HIJACK …) and the identity analyzers emitted CAN_ASSUME / MEMBER_OF /
IS_ADMIN_EQUIVALENT:

1. ``reach(P)`` over **traversable** edges, by a deterministic breadth-first search (neighbours in
   (target, type, edge id) order);
2. every ``P -CAN_MODIFY_PERMISSIONS_OF-> Q`` whose target ``Q`` is ``P`` or in ``reach(P)`` becomes
   ``P -CAN_ESCALATE-> account-admin`` with ``evidence.chain = [modify edge id, path edge ids …]``: P can act as
   Q and rewrite Q's permissions (pathfinding.cloud's "AttachRolePolicy + AssumeRole" family, iam-014 … iam-021).
   The derived edge is definite only when the modify edge and the whole path are definite; otherwise it is
   conditional with the strongest condition strength of the chain;
3. steps 1-2 repeat until no edge is added (monotone, so it terminates; capped for safety);
4. ``reaches_admin`` = the nodes with a traversable path to the account-admin node, by a reverse search:
   ``definite`` when a path of definite edges exists, else ``conditional``. It is published as
   ``props.reaches_admin`` on those nodes and in ``ctx.shared["closure"]`` for the severity policy
   (``rules/severity.py``), which raises rule findings whose targets reach the admin node (engine.md §3.3).
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from aws_enumerator.engine.graph import ids

log = logging.getLogger(__name__)

MODIFY = "CAN_MODIFY_PERMISSIONS_OF"
ESCALATE = "CAN_ESCALATE"
MAX_ITERATIONS = 16
_STRENGTH_RANK = {"none": 0, "weak": 1, "strong": 2}
_STRENGTHS = ("none", "weak", "strong")


@dataclass(frozen=True)
class Escalation:
    """One closure-derived escalation: ``source`` can act as ``target`` and modify its permissions."""

    source: str
    target: str
    modify_edge: str
    chain: Tuple[str, ...]
    confidence: str
    strength: str
    rule_ids: Tuple[str, ...]


@dataclass
class ClosureResult:
    """What the closure found (``ctx.shared["closure"]``)."""

    admin_id: str
    escalations: List[Escalation] = field(default_factory=list)
    reaches_admin: Dict[str, str] = field(default_factory=dict)
    iterations: int = 0

    def justified(self, source: str, target: str) -> Optional[Escalation]:
        """The escalation derived from ``source -CAN_MODIFY_PERMISSIONS_OF-> target``, if any."""
        for esc in self.escalations:
            if esc.source == source and esc.target == target:
                return esc
        return None

    def reach_of(self, node_id: Optional[str]) -> Optional[str]:
        """``definite`` / ``conditional`` when ``node_id`` reaches the admin node (the admin node itself too)."""
        if node_id is None:
            return None
        if node_id == self.admin_id:
            return "definite"
        return self.reaches_admin.get(node_id)


# ── graph views over the builder ─────────────────────────────────────────────

@dataclass(frozen=True)
class _Arc:
    target: str
    edge_id: str
    edge_type: str
    definite: bool
    strength: str


def _strength_of(edge: Any) -> str:
    if edge.confidence != "conditional":
        return "none"
    value = (edge.evidence or {}).get("condition_strength")
    return value if value in _STRENGTH_RANK else "weak"


def _adjacency(edges: Iterable[Any], *, reverse: bool = False) -> Dict[str, List[_Arc]]:
    """Traversable edges as sorted adjacency lists (forward: source → arcs; reverse: target → arcs)."""
    adj: Dict[str, List[_Arc]] = {}
    for e in edges:
        if not e.traversable:
            continue
        frm, to = (e.target, e.source) if reverse else (e.source, e.target)
        adj.setdefault(frm, []).append(_Arc(to, e.id, e.type, e.confidence == "definite", _strength_of(e)))
    for arcs in adj.values():
        arcs.sort(key=lambda a: (a.target, a.edge_type, a.edge_id))
    return adj


def _bfs_paths(adj: Mapping[str, Sequence[_Arc]], start: str, wanted: Set[str], *,
               definite_only: bool) -> Dict[str, List[_Arc]]:
    """Shortest (fewest hops, then lexical) paths from ``start`` to every reachable node of ``wanted``."""
    parents: Dict[str, Tuple[str, _Arc]] = {}
    seen = {start}
    queue: Deque[str] = deque([start])
    remaining = set(wanted) - {start}
    while queue and remaining:
        node = queue.popleft()
        for arc in adj.get(node, ()):
            if definite_only and not arc.definite:
                continue
            if arc.target in seen:
                continue
            seen.add(arc.target)
            parents[arc.target] = (node, arc)
            remaining.discard(arc.target)
            queue.append(arc.target)
    out: Dict[str, List[_Arc]] = {}
    for goal in wanted:
        if goal == start:
            out[goal] = []
        elif goal in parents:
            path: List[_Arc] = []
            cur = goal
            while cur != start:
                prev, arc = parents[cur]
                path.append(arc)
                cur = prev
            out[goal] = list(reversed(path))
    return out


def _reverse_reach(radj: Mapping[str, Sequence[_Arc]], admin_id: str, *, definite_only: bool) -> Set[str]:
    seen = {admin_id}
    queue: Deque[str] = deque([admin_id])
    while queue:
        node = queue.popleft()
        for arc in radj.get(node, ()):
            if (definite_only and not arc.definite) or arc.target in seen:
                continue
            seen.add(arc.target)
            queue.append(arc.target)
    seen.discard(admin_id)
    return seen


# ── the fixpoint ─────────────────────────────────────────────────────────────

def _modify_edges(builder: Any) -> Dict[str, List[Any]]:
    by_source: Dict[str, List[Any]] = {}
    for e in builder.edges(MODIFY):
        by_source.setdefault(e.source, []).append(e)
    return by_source


def _escalations_for(source: str, modifies: Sequence[Any], adj: Mapping[str, Sequence[_Arc]]) -> List[Escalation]:
    wanted = {m.target for m in modifies}
    definite_paths = _bfs_paths(adj, source, wanted, definite_only=True)
    missing = wanted - set(definite_paths)
    any_paths = _bfs_paths(adj, source, missing, definite_only=False) if missing else {}
    out = []
    for m in sorted(modifies, key=lambda e: (e.target, e.id)):
        path = definite_paths.get(m.target)
        if path is None:
            path = any_paths.get(m.target)
        if path is None:
            continue
        strengths = [_strength_of(m)] + [a.strength for a in path]
        definite = m.confidence == "definite" and all(a.definite for a in path)
        strength = "none" if definite else max(strengths, key=_STRENGTH_RANK.__getitem__)
        if not definite and strength == "none":
            strength = "weak"
        rule_ids = tuple(sorted(str(r) for r in (m.evidence or {}).get("rule_ids") or ()))
        out.append(Escalation(source, m.target, m.id, (m.id,) + tuple(a.edge_id for a in path),
                              "definite" if definite else "conditional", strength, rule_ids))
    return out


def _add_escalation(builder: Any, esc: Escalation, admin_id: str, existing: Mapping[str, str]) -> bool:
    """Add the derived CAN_ESCALATE edge unless an equally definite one exists; True when the graph changed.

    ``existing`` maps a source to the confidence of its current CAN_ESCALATE edge (updated in place by callers).
    """
    have = existing.get(esc.source)
    if have is not None and (have == "definite" or esc.confidence == "conditional"):
        return False
    builder.add_edge(esc.source, ESCALATE, admin_id, confidence=esc.confidence,
                     strength=esc.strength if esc.confidence == "conditional" else None,
                     evidence={"chain": list(esc.chain), "rule_ids": list(esc.rule_ids),
                               "technique": "modify-reachable-principal", "derived_by": "closure"})
    return True


def compute_closure(builder: Any, admin_id: str, *, max_iterations: int = MAX_ITERATIONS) -> ClosureResult:
    """Run the closure on ``builder`` (adds the derived edges) and return what it found."""
    result = ClosureResult(admin_id)
    found: Dict[Tuple[str, str], Escalation] = {}
    for iteration in range(1, max_iterations + 1):
        result.iterations = iteration
        adj = _adjacency(builder.edges())
        existing = {e.source: e.confidence for e in builder.edges(ESCALATE) if e.target == admin_id}
        changed = False
        for source, modifies in sorted(_modify_edges(builder).items()):
            for esc in _escalations_for(source, modifies, adj):
                key = (esc.source, esc.target)
                if key in found and not (found[key].confidence == "conditional" and esc.confidence == "definite"):
                    continue
                found[key] = esc
                if _add_escalation(builder, esc, admin_id, existing):
                    existing[esc.source] = "definite" if esc.confidence == "definite" else \
                        existing.get(esc.source, "conditional")
                    changed = True
        if not changed:
            break
    else:
        log.warning("privilege-escalation closure stopped after %d iterations", max_iterations)
    result.escalations = [found[k] for k in sorted(found)]
    radj = _adjacency(builder.edges(), reverse=True)
    definite = _reverse_reach(radj, admin_id, definite_only=True)
    reached = _reverse_reach(radj, admin_id, definite_only=False)
    result.reaches_admin = {n: ("definite" if n in definite else "conditional") for n in sorted(reached)}
    return result


def publish_reach(builder: Any, result: ClosureResult) -> None:
    """``props.reaches_admin`` on every node with a traversable path to the account admin."""
    for node_id, how in result.reaches_admin.items():
        if builder.has_node(node_id):
            builder.set_node_props(node_id, reaches_admin=how)


# ── pipeline registration (engine-api.md §5) ─────────────────────────────────

def run(ctx: Any, builder: Any) -> None:
    """Phase CLOSURE: derived CAN_ESCALATE edges, ``reaches_admin``, and the result for the severity policy."""
    admin_id = ids.account_admin_id(ctx.account_id)
    result = compute_closure(builder, admin_id)
    publish_reach(builder, result)
    ctx.shared["closure"] = result
    log.debug("closure: %d derived escalations, %d nodes reach the account admin (%d iterations)",
              len(result.escalations), len(result.reaches_admin), result.iterations)


def _analyzers() -> Tuple[Any, ...]:
    from aws_enumerator.engine.model import AnalyzerSpec, Phase

    return (AnalyzerSpec("closure", Phase.CLOSURE, run, inputs=("iam.authorization_details",)),)


ANALYZERS = _analyzers()

__all__ = ["ANALYZERS", "ClosureResult", "Escalation", "MAX_ITERATIONS", "compute_closure", "publish_reach", "run"]
