"""Output writers (engine-api.md §6.3; engine.md §6.6, §6.8).

Writers **render bytes**; files are written by their callers (the pipeline's WRITE phase stages them into
``analysis.tmp/``; the CLI's ``export`` command writes exports wherever the operator asked). Every renderer is
deterministic: sorted keys, sorted records, no clock other than ``run.generated_at`` (F-162).

* :mod:`.graph_json` — ``graph.json`` (compact canonical JSON) and its validation (schema + ``validate_graph``);
* :mod:`.findings` — ``findings.json`` (finding-identity.md §3) and ``diff.json``;
* :mod:`.summary` — ``summary.json`` (finding-identity.md §6, all five severities, F-074);
* :mod:`.legacy` — the twelve d13c215 outputs kept for one release (graph-json.md §1).

:func:`export` is the one dispatcher for the export formats of exports.md (D-23); the format renderers
``writers/{sarif,csv,markdown,asff,opengraph}.py`` are E-rules' (Wave 2).
"""

from __future__ import annotations

import importlib
from typing import Any, Mapping, Optional, Tuple

#: format -> (renderer module, default file name, media type) (exports.md §1).
EXPORT_FORMATS: Mapping[str, Tuple[str, str, str]] = {
    "sarif": ("sarif", "findings.sarif", "application/sarif+json"),
    "csv": ("csv", "findings.csv", "text/csv; charset=utf-8"),
    "md": ("markdown", "findings.md", "text/markdown; charset=utf-8"),
    "asff": ("asff", "findings.asff.json", "application/json"),
    "opengraph": ("opengraph", "opengraph.json", "application/json"),
}


def export(graph: Mapping[str, Any], fmt: str, *, min_severity: Optional[str] = None,
           include_suppressed: bool = False, all_edges: bool = False) -> bytes:
    """Render ``graph`` (a valid ``graph.json`` document) in export format ``fmt``.

    Raises ``ValueError`` for an unknown format and ``NotImplementedError`` when the format's module has no
    ``render`` function (the CLI exits 1, engine-api.md §6.3). Every format of :data:`EXPORT_FORMATS` ships its
    module, so an import failure is a real defect and propagates as itself (F-121).
    """
    if fmt not in EXPORT_FORMATS:
        raise ValueError(f"unknown export format {fmt!r}; expected one of {sorted(EXPORT_FORMATS)}")
    module = importlib.import_module(f"{__name__}.{EXPORT_FORMATS[fmt][0]}")
    render = getattr(module, "render", None)
    if not callable(render):
        raise NotImplementedError(f"export format {fmt!r} has no renderer in this build")
    out = render(graph, min_severity=min_severity, include_suppressed=include_suppressed, all_edges=all_edges)
    if not isinstance(out, (bytes, bytearray)):
        raise TypeError(f"the {fmt} renderer returned {type(out).__name__}, not bytes")
    return bytes(out)


def export_file_name(fmt: str) -> str:
    """The default file name of an export format (``analysis/exports/<name>``)."""
    if fmt not in EXPORT_FORMATS:
        raise ValueError(f"unknown export format {fmt!r}")
    return EXPORT_FORMATS[fmt][1]


__all__ = ["EXPORT_FORMATS", "export", "export_file_name"]
