"""Finding suppression (``--suppress FILE``, finding-identity.md §5, F-143).

A suppression entry names a finding by ``fingerprint`` or by ``rule_id`` (canonical id or a legacy alias)
plus ``node_id_glob`` (IAM glob semantics: ``*`` any run including ``:`` and ``/``, ``?`` one character,
case-sensitive). ``reason`` and ``expires`` (``YYYY-MM-DD``) are required. Matching findings stay in every
output with ``status: "suppressed"``; an expired entry is ignored and produces one INFO
``SUPPRESSION-EXPIRED-001`` at the account anchor. A file that breaks the schema is a usage error.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from aws_enumerator.engine.model import AnalysisUsageError

_FP_RE = re.compile(r"^[0-9a-f]{32}$")
_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*$")
_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_ENTRY_KEYS = frozenset({"fingerprint", "rule_id", "node_id_glob", "reason", "expires", "owner"})


@dataclass(frozen=True)
class Suppression:
    """One validated entry. ``match`` is ``fingerprint`` or ``rule``."""

    reason: str
    expires: _dt.date
    owner: Optional[str]
    fingerprint: Optional[str] = None
    rule_id: Optional[str] = None
    node_id_glob: Optional[str] = None

    @property
    def match(self) -> str:
        return "fingerprint" if self.fingerprint else "rule"

    @property
    def key(self) -> str:
        """The SUPPRESSION-EXPIRED-001 discriminator: the fingerprint or ``rule_id:node_id_glob``."""
        return self.fingerprint or f"{self.rule_id}:{self.node_id_glob}"

    def to_json(self) -> Dict[str, Any]:
        return {"reason": self.reason, "expires": self.expires.isoformat(), "owner": self.owner,
                "match": self.match}


def _fail(msg: str) -> None:
    raise AnalysisUsageError(f"invalid suppression file: {msg}")


def _entry(i: int, raw: Any) -> Suppression:
    where = f"suppressions[{i}]"
    if not isinstance(raw, Mapping):
        _fail(f"{where} is not an object")
    extra = set(raw) - _ENTRY_KEYS
    if extra:
        _fail(f"{where} has unknown keys {sorted(extra)}")
    fp, rule, glob = raw.get("fingerprint"), raw.get("rule_id"), raw.get("node_id_glob")
    by_fp = "fingerprint" in raw
    if by_fp == ("rule_id" in raw or "node_id_glob" in raw):
        _fail(f"{where} needs either fingerprint or rule_id + node_id_glob")
    if by_fp and not (isinstance(fp, str) and _FP_RE.match(fp)):
        _fail(f"{where}.fingerprint must be 32 lower-case hex characters")
    if not by_fp and not (isinstance(rule, str) and _ID_RE.match(rule) and isinstance(glob, str) and glob):
        _fail(f"{where} needs a finding-id rule_id and a non-empty node_id_glob")
    reason, expires, owner = raw.get("reason"), raw.get("expires"), raw.get("owner")
    if not isinstance(reason, str) or not reason.strip():
        _fail(f"{where}.reason is required")
    if not isinstance(expires, str) or not _DATE_RE.match(expires):
        _fail(f"{where}.expires must be YYYY-MM-DD")
    try:
        day = _dt.date.fromisoformat(expires)
    except ValueError:
        _fail(f"{where}.expires is not a calendar date")
    if owner is not None and not isinstance(owner, str):
        _fail(f"{where}.owner must be a string or null")
    return Suppression(reason, day, owner, fp if by_fp else None, None if by_fp else rule, None if by_fp else glob)


def parse_suppressions(doc: Any) -> List[Suppression]:
    """Validate a parsed suppression file (``$defs/suppressionFile``); raises :class:`AnalysisUsageError`."""
    if not isinstance(doc, Mapping):
        _fail("the document must be an object")
    if set(doc) - {"version", "suppressions"}:
        _fail(f"unknown top-level keys {sorted(set(doc) - {'version', 'suppressions'})}")
    if doc.get("version") != 1:
        _fail("version must be 1")
    entries = doc.get("suppressions")
    if not isinstance(entries, list):
        _fail("suppressions must be a list")
    return [_entry(i, raw) for i, raw in enumerate(entries)]


def load_suppressions(path: "str | Path") -> List[Suppression]:
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        raise AnalysisUsageError(f"suppression file not found: {path}") from None
    except (OSError, ValueError) as exc:
        raise AnalysisUsageError(f"suppression file {path} is not valid JSON: {exc}") from None
    return parse_suppressions(doc)


@lru_cache(maxsize=None)
def _compile_glob(pattern: str) -> "re.Pattern[str]":
    out = []
    for ch in pattern:
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
    return re.compile("".join(out), re.DOTALL)


def glob_match(pattern: str, value: str) -> bool:
    """IAM glob: ``*`` any run (``:`` and ``/`` included), ``?`` one character, case-sensitive."""
    return bool(_compile_glob(pattern).fullmatch(value))


def split_expired(entries: Sequence[Suppression], today: _dt.date) -> Tuple[List[Suppression], List[Suppression]]:
    """``(active, expired)``: an entry is expired when ``expires`` is before ``today`` (UTC run date)."""
    active = [e for e in entries if e.expires >= today]
    expired = [e for e in entries if e.expires < today]
    return active, expired


def match(entries: Sequence[Suppression], *, fingerprint: str, ids: Sequence[str], node_id: str) \
        -> Optional[Suppression]:
    """The first active entry matching a finding (fingerprint first, then rule + glob), else ``None``."""
    for e in entries:
        if e.fingerprint and e.fingerprint == fingerprint:
            return e
    for e in entries:
        if e.rule_id and e.rule_id in ids and glob_match(e.node_id_glob or "", node_id):
            return e
    return None


__all__ = [
    "AnalysisUsageError", "Suppression", "glob_match", "load_suppressions", "match", "parse_suppressions",
    "split_expired",
]
