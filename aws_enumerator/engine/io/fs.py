"""Read-only report file-system helpers for the engine (engine.md §1.1 ``io/fs.py``).

Every directory listing the engine makes goes through :func:`ls_sorted`, so outputs never depend on the
order the file system returns entries in (F-162). JSON reads go through :func:`read_json` /
:func:`read_list` / :func:`read_map`, which return the data **and** a status: the d13c215 collectors wrote
``{"Error": "<botocore message>"}`` (or ``{"_error": ...}``) in place of a list or a map when a call failed,
and those stubs must become a coverage gap, never data (F-006, F-058, F-059).
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

#: ``status`` values of :class:`ReadResult`.
READ_STATUSES: Tuple[str, ...] = ("ok", "missing", "invalid", "error-stub")

_CODE_IN_MESSAGE = re.compile(r"\(([A-Za-z][A-Za-z0-9.:_-]*)\)")
_STUB_KEYS = ("Error", "_error", "error")


@dataclass(frozen=True)
class ReadResult:
    """Outcome of reading one JSON file.

    * ``status``: ``ok`` (parsed), ``missing`` (no such file), ``invalid`` (not JSON), ``error-stub`` (a
      collector error marker such as ``{"Error": "... (AccessDenied) ..."}``).
    * ``error_code``: the AWS error code found in a stub (``AccessDenied``), else ``None``.
    """

    data: Any
    status: str
    error_code: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def ls_sorted(path: "os.PathLike[str] | str") -> List[str]:
    """Entry names of ``path`` in sorted order; ``[]`` when it is not a readable directory (F-162)."""
    try:
        return sorted(os.listdir(path))
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return []


def is_error_stub(value: Any) -> bool:
    """True for a collector error marker: a dict whose only meaningful key is ``Error`` / ``_error``."""
    if not isinstance(value, dict) or not value:
        return False
    keys = set(value)
    return bool(keys & set(_STUB_KEYS)) and keys <= set(_STUB_KEYS) | {"Code", "Message", "code", "message"}


def error_code_from_stub(value: Any) -> Optional[str]:
    """The AWS error code inside a stub or a botocore message (``"... (AccessDenied) when ..."``)."""
    if isinstance(value, dict):
        for key in ("Code", "code"):
            if isinstance(value.get(key), str) and value[key]:
                return value[key]
        for key in _STUB_KEYS:
            if key in value:
                return error_code_from_stub(value[key])
        return None
    if isinstance(value, str):
        match = _CODE_IN_MESSAGE.search(value)
        if match:
            return match.group(1)
    return None


def stub_status(code: Optional[str]) -> str:
    """Facet status (graph-json.md §7.2) of a collector error code: ``denied``, ``throttled`` or ``error``."""
    from aws_enumerator.coverage import DENIED_CODES, THROTTLE_CODES  # lazy: optional dependency direction

    if not code:
        return "error"
    if code in DENIED_CODES or code.startswith(("AccessDenied", "AuthorizationError", "Unauthorized")):
        return "denied"
    if code in THROTTLE_CODES or code.startswith("Throttl"):
        return "throttled"
    return "error"


def read_json(path: "os.PathLike[str] | str") -> ReadResult:
    """Parse ``path``; never raises for a missing, unreadable or malformed file."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return ReadResult(None, "missing")
    except (OSError, ValueError) as exc:
        log.debug("unreadable JSON %s: %s", path, type(exc).__name__)
        return ReadResult(None, "invalid")
    if is_error_stub(data):
        return ReadResult(None, "error-stub", error_code_from_stub(data))
    return ReadResult(data, "ok")


def read_list(path: "os.PathLike[str] | str") -> Tuple[List[Any], ReadResult]:
    """``(items, result)``: a list file; anything that is not a list gives ``[]`` (status kept)."""
    res = read_json(path)
    if res.ok and not isinstance(res.data, list):
        return [], ReadResult(None, "invalid")
    return (list(res.data) if res.ok else []), res


def read_map(path: "os.PathLike[str] | str") -> Tuple[Dict[str, Any], ReadResult]:
    """``(mapping, result)``: a JSON object file; anything else gives ``{}`` (status kept)."""
    res = read_json(path)
    if res.ok and not isinstance(res.data, dict):
        return {}, ReadResult(None, "invalid")
    return (dict(res.data) if res.ok else {}), res


__all__ = [
    "READ_STATUSES", "ReadResult", "error_code_from_stub", "is_error_stub", "ls_sorted", "read_json",
    "read_list", "read_map", "stub_status",
]
