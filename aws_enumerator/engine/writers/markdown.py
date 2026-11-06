"""Findings Markdown export (exports.md §4; F-165), byte-identical to the dashboard's ``findingsMarkdown``.

Layout: a title line with the account and run id, a "Generated … by aws-enumerator <version>. Regions: …"
line with the CONFIDENTIAL notice, a summary table of all five severities (zeros included), then one findings
table in the exports.md §1 order, or the line ``No findings.`` The text ends with one ``\\n``.

Every report-derived string goes through :func:`md_escape` (``& < >`` as entities; ``\\ | ` [ ]`` escaped
with a backslash; CR and LF become a space). Report data is never placed in a code span, so no raw HTML or link
syntax can be produced from it. Missing values use the fallbacks pinned at the Wave 1/2 sync (D-50):
``unknown account``, ``unknown run``, ``at an unknown time``, ``unknown version``, regions ``none``.
"""

from __future__ import annotations

from typing import Any, List, Mapping, Optional

from aws_enumerator.engine.writers.csv import SEVERITY_ORDER, Selection, select_findings, severity_class

_MD_ESCAPES = {"&": "&amp;", "<": "&lt;", ">": "&gt;", "\\": "\\\\", "|": "\\|", "`": "\\`", "[": "\\[",
               "]": "\\]", "\r": " ", "\n": " "}
_TRANSLATION = str.maketrans(_MD_ESCAPES)
SEVERITY_LABELS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}


def md_escape(text: Any) -> str:
    """exports.md §4 escaping (one pass, equivalent to the ordered replacements)."""
    if text is None:
        return ""
    return str(text).translate(_TRANSLATION)


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _row(cells: List[str]) -> str:
    return "| " + " | ".join(cells) + " |"


def _header(sel: Selection) -> List[str]:
    run, gen = sel.run, sel.generator
    regions = [r for r in run.get("regions") or () if isinstance(r, str)] \
        if isinstance(run.get("regions"), list) else []
    return [
        f"# aws-enumerator findings: {md_escape(_text(run.get('account_id'))) or 'unknown account'} "
        f"({md_escape(_text(run.get('run_id'))) or 'unknown run'})",
        "",
        f"Generated {md_escape(_text(run.get('generated_at'))) or 'at an unknown time'} by aws-enumerator "
        f"{md_escape(_text(gen.get('version'))) or 'unknown version'}. Regions: "
        f"{', '.join(md_escape(r) for r in regions) if regions else 'none'}. CONFIDENTIAL: see HANDLING.txt.",
        "",
    ]


def _summary(sel: Selection) -> List[str]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in sel.findings:
        counts[severity_class(f.get("severity"))] += 1
    lines = ["| Severity | Count |", "|---|---|"]
    lines.extend(_row([SEVERITY_LABELS[s], str(counts[s])]) for s in SEVERITY_ORDER)
    lines.append("")
    return lines


def _resource(sel: Selection, f: Mapping[str, Any]) -> str:
    node = sel.node(f.get("node_id"))
    node_id = md_escape(_text(f.get("node_id")))
    return f"{md_escape(node.get('label'))} ({node_id})" if node else node_id


def _region(f: Mapping[str, Any]) -> str:
    region = f.get("region")
    return region if isinstance(region, str) and region else "global"


def render_selection(sel: Selection) -> str:
    """The Markdown text of an already selected set of findings."""
    lines = _header(sel) + _summary(sel)
    if not sel.findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"
    lines += ["| Severity | ID | Title | Resource | Type | Region |", "|---|---|---|---|---|---|"]
    for f in sel.findings:
        node = sel.node(f.get("node_id"))
        lines.append(_row([md_escape(_text(f.get("severity"))), md_escape(_text(f.get("id"))),
                           md_escape(_text(f.get("title"))), _resource(sel, f),
                           md_escape(node.get("type") if node else ""), md_escape(_region(f))]))
    return "\n".join(lines) + "\n"


def render(graph: Mapping[str, Any], *, min_severity: Optional[str] = None, include_suppressed: bool = False,
           all_edges: bool = False) -> bytes:
    """``findings.md`` (exports.md §4). ``all_edges`` does not apply to findings and is ignored."""
    del all_edges
    sel = select_findings(graph, min_severity=min_severity, include_suppressed=include_suppressed)
    return render_selection(sel).encode("utf-8")


__all__ = ["SEVERITY_LABELS", "md_escape", "render", "render_selection"]
