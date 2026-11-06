"""``findings.json`` and ``diff.json`` (finding-identity.md §3-§4; F-143).

``findings.json`` keeps the d13c215 ``findings`` key (old readers only read that) inside a wrapper with the
run context: schema and tool versions, rules version, account, partition, regions, mode, run id and the UTC
generation time. The records are exactly ``graph.json``'s ``findings[]`` (same order, same fingerprints).
"""

from __future__ import annotations

from typing import Any, Dict, Mapping

from aws_enumerator._version import __version__
from aws_enumerator.engine.graph import FINDINGS_SCHEMA_VERSION
from aws_enumerator.engine.writers.graph_json import dumps_canonical


def findings_document(graph: Mapping[str, Any]) -> Dict[str, Any]:
    """The ``findings.json`` document of a rendered ``graph.json`` (all ten keys, no others)."""
    run = graph["run"]
    return {
        "schema_version": FINDINGS_SCHEMA_VERSION,
        "tool_version": __version__,
        "rules_version": graph["generator"]["rules_version"],
        "account_id": run["account_id"],
        "partition": run["partition"],
        "regions": list(run["regions"]),
        "mode": run["mode"],
        "run_id": run["run_id"],
        "generated_at": run["generated_at"],
        "findings": [dict(f) for f in graph["findings"]],
    }


def render(doc: Mapping[str, Any]) -> bytes:
    """``findings.json`` / ``diff.json`` bytes: canonical JSON, indented for humans, keys sorted."""
    import json

    return (json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def render_compact(doc: Mapping[str, Any]) -> bytes:
    return dumps_canonical(doc).encode("utf-8")


__all__ = ["findings_document", "render", "render_compact"]
