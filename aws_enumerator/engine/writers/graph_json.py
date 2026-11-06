"""``graph.json`` rendering and validation (graph-json.md §1, §12, §13).

The file is canonical JSON: ``sort_keys=True``, compact separators, UTF-8 without ASCII escaping (labels are
raw strings, F-008), so two analyses of the same input with the same ``SOURCE_DATE_EPOCH`` are byte-identical
(F-162) and large graphs stay small (F-022, F-086). The writer refuses a document that fails the JSON Schema of
the version it carries (``graph-1.0`` for analyses, ``graph-1.1`` for merges; graph-json.md §12.1) or
``validate_graph(strict_order=True)``: nothing invalid is ever renamed into ``analysis/``.
"""

from __future__ import annotations

import json
import logging
from typing import Any, List, Mapping, Optional

from aws_enumerator.engine.graph import graph_schema_name, validate_graph

log = logging.getLogger(__name__)


class GraphInvalid(ValueError):
    """The rendered document violates the graph contract; ``problems`` lists why."""

    def __init__(self, problems: List[str]):
        super().__init__("graph.json is invalid: " + "; ".join(problems[:10])
                         + (f" (+{len(problems) - 10} more)" if len(problems) > 10 else ""))
        self.problems = problems


def dumps_canonical(doc: Any) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def render(doc: Mapping[str, Any]) -> bytes:
    """The bytes of ``graph.json``."""
    return dumps_canonical(doc).encode("utf-8")


def schema_problems(doc: Mapping[str, Any], schema_name: str = "graph") -> List[str]:
    """JSON Schema violations of ``doc`` under the engine schema ``schema_name`` (``graph``, ``graph-1.1``).

    Uses the compiled validator (:mod:`aws_enumerator.engine.graph.schema_check`): standard library only, so the
    check runs in every install, and fast on large graphs. ``tests/python/engine/core/test_schema_check.py``
    proves it agrees with ``jsonschema``.
    """
    from aws_enumerator.engine.graph import schema_check

    return schema_check.problems(doc, schema_name)


def schema_for(doc: Any) -> Optional[str]:
    """The schema of ``doc``'s minor (``"graph"`` = 1.0, ``"graph-1.1"``); ``None`` for a newer 1.x minor."""
    return graph_schema_name(doc.get("schema_version") if isinstance(doc, Mapping) else None)


def problems(doc: Mapping[str, Any]) -> List[str]:
    """Every schema and semantic problem of ``doc`` (graph-json.md §12), with the schema of its minor."""
    name = schema_for(doc)
    out = schema_problems(doc, name) if name else []
    out.extend(f"{p.code}:{p.path}: {p.message}" for p in validate_graph(doc, strict_order=True))
    return out


def checked(doc: Mapping[str, Any]) -> bytes:
    """Validate and render; raises :class:`GraphInvalid`."""
    found = problems(doc)
    if found:
        raise GraphInvalid(found)
    return render(doc)


__all__ = ["GraphInvalid", "checked", "dumps_canonical", "problems", "render", "schema_for", "schema_problems"]
