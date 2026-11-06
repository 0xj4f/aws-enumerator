"""Directed blast radius over a legacy report's ``analysis/*_relationships.json``.

Port of internal-docs/repro/def_blast.py as a function: a BFS that pivots only
through control edges and skips grant edges (which point resource -> principal).
Reads analysis output files only; never touches production code.
"""

from __future__ import annotations

import collections
import glob
import json
import os
from typing import Dict, List, Tuple

PIVOT = frozenset({
    "CAN_UPDATE_CODE", "USES_ROLE", "INSTANCE_ROLE", "CAN_CONNECT", "IRSA_BRIDGE",
    "RUNS_AS", "NODE_ROLE", "POOL_AUTH_ROLE", "POOL_UNAUTH_ROLE", "CAN_ASSUME",
})


def _is_grant(edge: Dict) -> bool:
    etype = str(edge.get("type", ""))
    return edge.get("direction") == "bucket_to_entity" or "_GRANTS_" in etype or etype.startswith("GRANTS_")


def load_out_edges(report_dir: str) -> Dict[str, List[Dict]]:
    out: Dict[str, List[Dict]] = collections.defaultdict(list)
    for path in sorted(glob.glob(os.path.join(report_dir, "analysis", "*_relationships.json"))):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list):  # trust_relationships.json: exact-ARN trusts only
            for t in data:
                if t.get("principal_type") == "AWS":
                    out[t["trusted_principal"]].append({"type": "CAN_ASSUME", "target": t["role_arn"]})
            continue
        for e in data.get("edges", []):
            if _is_grant(e):
                continue
            out[e["source"]].append(e)
    return out


def blast_radius(report_dir: str, start: str) -> Tuple[Dict[str, int], List[Tuple[int, str, str, str]]]:
    """Return ({reached node: hop depth}, [(hop, source, edge type, target) ...]).

    ``reached`` includes ``start`` at depth 0 and every node entered through a PIVOT edge.
    The hop list records every out-edge seen from a visited node (pivot or not).
    """
    out = load_out_edges(report_dir)
    reached: Dict[str, int] = {start: 0}
    hops: List[Tuple[int, str, str, str]] = []
    queue = collections.deque([(start, 0)])
    while queue:
        node, depth = queue.popleft()
        for e in out.get(node, []):
            hops.append((depth + 1, node, e["type"], e["target"]))
            if e["type"] in PIVOT and e["target"] not in reached:
                reached[e["target"]] = depth + 1
                queue.append((e["target"], depth + 1))
    return reached, hops
