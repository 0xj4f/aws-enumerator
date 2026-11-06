"""Shared collector helpers (registry-skipped: the leading ``_`` keeps it out of the registry, registry.md §1).

Approved by DECISIONS.md D-47 (request ``c-b-4``): the collectors used to carry their own copies of these two
helpers. They are pure functions with no AWS access; a collector imports them by name::

    from aws_enumerator.collectors._common import add_error, policy_doc
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from aws_enumerator.coverage import CallResult

__all__ = ["add_error", "policy_doc"]


def policy_doc(text: Any) -> Optional[Dict[str, Any]]:
    """A JSON policy string as a dict (``{"_raw": text}`` when it is not JSON; ``None`` when empty)."""
    if not text:
        return None
    if isinstance(text, dict):
        return text
    try:
        doc = json.loads(text)
    except (TypeError, ValueError):
        return {"_raw": str(text)}
    return doc if isinstance(doc, dict) else {"_raw": str(text)}


def add_error(item: Dict[str, Any], result: CallResult) -> None:
    """Append ``result``'s ``CollectionErrors`` entry to ``item`` (nothing when the call succeeded)."""
    err = result.collection_error()
    if err is not None:
        item.setdefault("CollectionErrors", []).append(err)
