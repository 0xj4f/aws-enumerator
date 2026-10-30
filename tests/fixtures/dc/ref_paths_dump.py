"""Python reference answers for the dashboard's path-finding parity tests (Dc stream, test-only).

``tests/js/golden/ref-parity.test.js`` sends a JSON list of requests on stdin; each request names a graph
(``{"graph": <graph.json document>}``, or ``{"generate": {"scale": n, "seed": s}}`` for
``tests/fixtures/graph/gen_large.py``) plus ``sources``/``targets`` (lists of node ids, or null for every
node) and path-vector ``options`` (``exclude_categories``, ``exclude_node_types``, ``definite_only``).
For every (source, target) pair the answer of ``tests/support/ref_paths.shortest_path`` is written to stdout:
``[{"graph": <doc when generated, else null>, "results": [[source, target, result-or-null], ...]}]`` with
``result = {"cost", "hops", "nodes", "edges"}``.

Offline and side-effect free: it reads stdin and writes stdout only.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.support import ref_paths  # noqa: E402  (needs REPO_ROOT on sys.path)


GEN_LARGE = REPO_ROOT / "tests" / "fixtures" / "graph" / "gen_large.py"


def _generate(scale: int, seed: int) -> Dict[str, Any]:
    spec = importlib.util.spec_from_file_location("gen_large", GEN_LARGE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.generate(scale=scale, seed=seed)


def _answer(doc: Dict[str, Any], sources: Optional[List[str]], targets: Optional[List[str]],
            options: Dict[str, Any]) -> List[List[Any]]:
    ids = [n["id"] for n in doc["nodes"]]
    results: List[List[Any]] = []
    for s in sources if sources is not None else ids:
        for t in targets if targets is not None else ids:
            r = ref_paths.shortest_path(
                doc, s, t,
                exclude_categories=options.get("exclude_categories") or (),
                exclude_node_types=options.get("exclude_node_types") or (),
                definite_only=bool(options.get("definite_only")),
            )
            results.append([s, t, None if r is None else
                            {"cost": r.cost, "hops": r.hops, "nodes": list(r.nodes), "edges": list(r.edges)}])
    return results


def main() -> int:
    requests = json.load(sys.stdin)
    out = []
    for req in requests:
        gen = req.get("generate")
        doc = _generate(int(gen["scale"]), int(gen["seed"])) if gen else req["graph"]
        out.append({
            "graph": doc if gen else None,
            "results": _answer(doc, req.get("sources"), req.get("targets"), req.get("options") or {}),
        })
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
