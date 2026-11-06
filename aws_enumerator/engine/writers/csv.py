"""Findings CSV export (exports.md §1, §3; F-165) and the finding selection every export shares.

The CSV is formula-injection safe and byte-identical to the dashboard's ``AEExports.findingsCsv`` for the same
findings (dashboard-core-api.md §4; D-12, D-24, D-25, D-50):

* UTF-8 without a BOM, ``,`` separator, CRLF line ends with a trailing CRLF, a header row;
* **every** field quoted, ``"`` doubled; ``null``/missing values are empty cells (``""``);
* a cell whose text starts with ``=``, ``+``, ``-``, ``@``, TAB or CR gets a leading ``'``;
* severity is copied as stored (upper-case), a global resource's region is an empty cell, the account is the
  finding's ``account`` (falling back to ``run.account_id``).

:func:`select_findings` implements the common rules of exports.md §1 (suppressed findings only with
``include_suppressed``, ``min_severity`` compared case-insensitively, the canonical order severity rank → ``id``
→ ``node_id`` → ``fingerprint`` in code-point order) and is reused by the other export writers, so every format
exports exactly the same findings in the same order. Renderers are pure: no file system, clock or network.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

#: Export severity vocabulary, most severe first (exports.md §1); unknown values rank as ``info`` (as graph-core.js).
SEVERITY_ORDER: Tuple[str, ...] = ("critical", "high", "medium", "low", "info")
_SEVERITY_INDEX = {s: i for i, s in enumerate(SEVERITY_ORDER)}

#: exports.md §3 columns, in order.
COLUMNS: Tuple[str, ...] = ("severity", "id", "title", "node_id", "node_label", "node_type", "account", "region",
                            "confidence", "category", "status", "fingerprint", "reference")

_FORMULA_PREFIX = re.compile(r"^[=+\-@\t\r]")


def severity_class(value: Any) -> str:
    """Lower-case export severity of a stored value; anything unknown is ``info`` (graph-core.js parity)."""
    if not isinstance(value, str):
        return "info"
    s = value.strip().lower()
    return s if s in _SEVERITY_INDEX else "info"


def severity_rank(value: Any) -> int:
    """0 for critical … 4 for info."""
    return _SEVERITY_INDEX[severity_class(value)]


def parse_min_severity(value: Optional[str]) -> Optional[int]:
    """Rank of ``--min-severity`` (``None`` keeps everything); an unknown level raises ``ValueError``."""
    if value is None:
        return None
    level = str(value).strip().lower()
    if level not in _SEVERITY_INDEX:
        raise ValueError(f"unknown severity {value!r}; expected one of {', '.join(SEVERITY_ORDER)}")
    return _SEVERITY_INDEX[level]


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def finding_order_key(f: Mapping[str, Any]) -> Tuple[int, str, str, str]:
    """exports.md §1 order. Python compares ``str`` by code point, as ``exports.js`` does (D-12)."""
    return (severity_rank(f.get("severity")), _text(f.get("id")), _text(f.get("node_id")),
            _text(f.get("fingerprint")))


@dataclass(frozen=True)
class Selection:
    """The exported findings (filtered and ordered) and the node index they refer to."""

    findings: Tuple[Mapping[str, Any], ...]
    nodes: Mapping[str, Mapping[str, Any]]
    run: Mapping[str, Any]
    generator: Mapping[str, Any]

    def node(self, node_id: Any) -> Optional[Mapping[str, Any]]:
        return self.nodes.get(node_id) if isinstance(node_id, str) else None

    def node_label(self, f: Mapping[str, Any]) -> str:
        node = self.node(f.get("node_id"))
        return _text(node.get("label")) if node else ""

    def node_type(self, f: Mapping[str, Any]) -> str:
        node = self.node(f.get("node_id"))
        return _text(node.get("type")) if node else ""

    def account(self, f: Mapping[str, Any]) -> Optional[str]:
        """The finding's account, else ``run.account_id`` (exports.md §1, D-50)."""
        acct = f.get("account")
        if isinstance(acct, str) and acct:
            return acct
        run_acct = self.run.get("account_id")
        return run_acct if isinstance(run_acct, str) and run_acct else None


def node_index(graph: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    """Node id → node record (the first record wins, as the dashboard reader does)."""
    out: Dict[str, Mapping[str, Any]] = {}
    for node in graph.get("nodes") or ():
        if isinstance(node, Mapping) and isinstance(node.get("id"), str):
            out.setdefault(node["id"], node)
    return out


def select_findings(graph: Mapping[str, Any], *, min_severity: Optional[str] = None,
                    include_suppressed: bool = False) -> Selection:
    """The findings every export writes (exports.md §1), in the canonical order."""
    threshold = parse_min_severity(min_severity)
    kept: List[Mapping[str, Any]] = []
    for f in graph.get("findings") or ():
        if not isinstance(f, Mapping):
            continue
        if f.get("status") == "suppressed" and not include_suppressed:
            continue
        if threshold is not None and severity_rank(f.get("severity")) > threshold:
            continue
        kept.append(f)
    run = graph.get("run") if isinstance(graph.get("run"), Mapping) else {}
    generator = graph.get("generator") if isinstance(graph.get("generator"), Mapping) else {}
    return Selection(tuple(sorted(kept, key=finding_order_key)), node_index(graph), run, generator)


# ── CSV cells (exports.md §3; exports.js csvCell) ────────────────────────────

def _number_text(value: float) -> str:
    """``String(n)`` of JavaScript for the numbers a report holds (integers and plain decimals)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "Infinity" if value > 0 else "-Infinity"
    if value == int(value) and abs(value) < 1e21:
        return str(int(value))
    return repr(value)


def cell_text(value: Any) -> str:
    """Text of one value before quoting: ``None`` → empty, lists joined with ``;``, objects as JSON."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float)):
        return _number_text(value)
    if isinstance(value, (list, tuple)):
        return ";".join(cell_text(json.dumps(v, separators=(",", ":"), ensure_ascii=False))
                        if isinstance(v, (list, tuple)) else cell_text(v) for v in value)
    if isinstance(value, Mapping):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    return ""


def neutralise(text: str) -> str:
    """Formula-injection guard: a leading ``= + - @ TAB CR`` gets a ``'``."""
    return "'" + text if _FORMULA_PREFIX.match(text) else text


def csv_cell(value: Any) -> str:
    """One quoted CSV field."""
    return '"' + neutralise(cell_text(value)).replace('"', '""') + '"'


def to_csv(header: Sequence[Any], rows: Iterable[Sequence[Any]]) -> str:
    """CRLF records, header first, trailing CRLF, no BOM."""
    lines = [",".join(csv_cell(h) for h in header)]
    lines.extend(",".join(csv_cell(v) for v in row) for row in rows)
    return "\r\n".join(lines) + "\r\n"


def finding_row(sel: Selection, f: Mapping[str, Any]) -> List[Any]:
    """One exports.md §3 row (``region: null`` stays an empty cell, D-25)."""
    node = sel.node(f.get("node_id"))
    return [f.get("severity"), f.get("id"), f.get("title"), f.get("node_id"),
            node.get("label") if node else None, node.get("type") if node else None, sel.account(f),
            f.get("region"), f.get("confidence"), f.get("category"), f.get("status"), f.get("fingerprint"),
            f.get("reference")]


def render(graph: Mapping[str, Any], *, min_severity: Optional[str] = None, include_suppressed: bool = False,
           all_edges: bool = False) -> bytes:
    """``findings.csv`` (exports.md §3). ``all_edges`` does not apply to findings and is ignored."""
    del all_edges
    sel = select_findings(graph, min_severity=min_severity, include_suppressed=include_suppressed)
    return to_csv(COLUMNS, (finding_row(sel, f) for f in sel.findings)).encode("utf-8")


__all__ = [
    "COLUMNS", "SEVERITY_ORDER", "Selection", "cell_text", "csv_cell", "finding_order_key", "finding_row",
    "neutralise", "node_index", "parse_min_severity", "render", "select_findings", "severity_class",
    "severity_rank", "to_csv",
]
