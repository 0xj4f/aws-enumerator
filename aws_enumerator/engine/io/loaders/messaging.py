"""SNS topics and SQS queues loader (E-compute).

Reads only the explicit units of the analysis context (``ctx.region_dirs``), never sibling directories (F-010,
F-025, F-063). Both layouts share ``{Type, Arn, Name, Policy}``; the v2 collectors add ``PolicyStatus``
(``present`` / ``absent`` / ``denied`` / ``error`` / ``skipped``), ``KmsMasterKeyId``, SNS ``Subscriptions`` and
SQS ``SqsManagedSseEnabled``, with ``null`` for unknown values (coverage-schema.md §1). A ``Policy`` stored as a
JSON string is parsed; one that is not JSON stays ``{"_raw": ...}`` (unreadable, never "no policy").

``data`` (``ctx.data["messaging"]``): ``{"sns": {unit: [record]}, "sqs": {unit: [record]}}``.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Mapping

from aws_enumerator.engine.io.loaders import LoadResult, read_scoped

GLOBAL_FILES: Dict[str, str] = {}
REGIONAL_FILES: Dict[str, str] = {
    "sns": "sns/resources.json",
    "sqs": "sqs/resources.json",
}


def normalise_record(rec: Mapping[str, Any]) -> Dict[str, Any]:
    """A topic / queue record with a parsed ``Policy`` (a JSON string becomes a dict)."""
    out = dict(rec)
    policy = out.get("Policy")
    if isinstance(policy, str):
        try:
            parsed = json.loads(policy)
        except ValueError:
            parsed = None
        out["Policy"] = parsed if isinstance(parsed, dict) else {"_raw": policy}
    return out


def load(ctx: Any) -> LoadResult:
    """``ctx.data["messaging"]`` (module docstring)."""
    result = read_scoped(ctx, GLOBAL_FILES, REGIONAL_FILES)
    data: Dict[str, Any] = {}
    for key, units in result.data.items():
        data[key] = {unit: [normalise_record(r) for r in records] for unit, records in sorted(units.items())}
    empty: Dict[str, List[Dict[str, Any]]] = {}
    for key in REGIONAL_FILES:
        data.setdefault(key, empty)
    return LoadResult(data, result.status, dict(result.gaps), files=result.files)


__all__ = ["GLOBAL_FILES", "REGIONAL_FILES", "load", "normalise_record"]
