"""Domain loaders: phase 2 (LOAD) of the pipeline (engine-api.md §5).

Each loader module exports ``load(ctx: AnalysisContext) -> LoadResult`` and reads only the explicit
``ctx.global_dir`` / ``ctx.region_dirs`` (no sibling-directory scan anywhere, F-010, F-025, F-063). Loaders
run in isolation: a failing loader becomes an ``analyzer_status`` entry (phase ``load``) and its domain is
simply missing from ``ctx.data``.

:data:`LOADER_MODULES` is the static list of every planned loader (Wave 2 streams fill in their domain's
module without editing this file or ``pipeline.py``). ``iam`` and ``org`` are E-core's; the domain loaders
are E-core stubs with the d13c215 file reading until their Wave 2 owners rewrite them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple

#: domain name → loader module (``ctx.data[domain]`` holds the loader's ``data``).
LOADER_MODULES: Mapping[str, str] = {
    "iam": "aws_enumerator.engine.io.loaders.iam",
    "org": "aws_enumerator.engine.io.loaders.org",
    "s3": "aws_enumerator.engine.io.loaders.s3",
    "ec2": "aws_enumerator.engine.io.loaders.ec2",
    "edge_services": "aws_enumerator.engine.io.loaders.edge_services",
    "posture": "aws_enumerator.engine.io.loaders.posture",
    "k8s": "aws_enumerator.engine.io.loaders.k8s",
    "kms": "aws_enumerator.engine.io.loaders.kms",
    "secrets": "aws_enumerator.engine.io.loaders.secrets",
    "data_stores": "aws_enumerator.engine.io.loaders.data_stores",
    "lambda": "aws_enumerator.engine.io.loaders.lambda_",
    "compute": "aws_enumerator.engine.io.loaders.compute",
    "messaging": "aws_enumerator.engine.io.loaders.messaging",
}


@dataclass
class LoadResult:
    """What one loader returns.

    * ``data``: the domain's normalised data (``ctx.data[domain]``).
    * ``status``: ``ok`` (everything readable), ``partial`` (some files were error stubs or unreadable),
      ``missing`` (the domain was not collected) or ``error``.
    * ``gaps``: input gap codes for ``evaluation_gaps`` / node coverage (``iam:inline-unknown`` …).
    """

    data: Any
    status: str = "ok"
    gaps: Dict[str, str] = field(default_factory=dict)
    files: int = 0

    def input_files(self) -> int:
        return self.files


def region_items(region_dirs: Mapping[str, Any]) -> Tuple[Tuple[str, Any], ...]:
    """``(region, dir)`` pairs in sorted region order (deterministic iteration, F-162)."""
    return tuple(sorted(region_dirs.items()))


def read_unit_lists(units: Mapping[str, Any], files: Mapping[str, str]) -> LoadResult:
    """Read list files per unit: ``data[key][unit] = [records]`` for every ``files[key]`` relative path.

    ``units`` maps a unit name (``global`` or a region) to its directory. A missing file is "not collected"
    (``[]``, no gap); an ``{"Error"}`` stub or unreadable file is ``[]`` plus a gap ``<path>:<status>`` and a
    ``partial`` status, so a denied listing is never mistaken for "no resources" (F-058, F-059).
    """
    from aws_enumerator.engine.io.fs import read_list, stub_status  # lazy: keep this package light

    data: Dict[str, Dict[str, List[Any]]] = {key: {} for key in files}
    gaps: Dict[str, str] = {}
    seen = 0
    for unit, base in region_items(units):
        for key, rel in sorted(files.items()):
            items, res = read_list(Path(base) / rel)
            data[key][unit] = [i for i in items if isinstance(i, dict)]
            if res.status == "missing":
                continue
            seen += 1
            if not res.ok:
                status = stub_status(res.error_code) if res.status == "error-stub" else "error"
                gaps[f"{rel}:{status}"] = f"{unit}/{rel} could not be read ({res.error_code or res.status})"
    status = "missing" if seen == 0 else ("partial" if gaps else "ok")
    return LoadResult(data, status, gaps, files=seen)


def read_scoped(ctx: Any, global_files: Mapping[str, str], regional_files: Mapping[str, str]) -> LoadResult:
    """:func:`read_unit_lists` over the context's explicit units: ``global_files`` from the global unit only
    (``data[key]["global"]``), ``regional_files`` from each analysed region (``data[key][<region>]``)."""
    glob = read_unit_lists({"global": ctx.global_dir}, global_files) if global_files else None
    regional = read_unit_lists(dict(ctx.region_dirs), regional_files) if regional_files else None
    parts = [r for r in (glob, regional) if r is not None]
    data: Dict[str, Any] = {}
    gaps: Dict[str, str] = {}
    for r in parts:
        data.update(r.data)
        gaps.update(r.gaps)
    statuses = {r.status for r in parts}
    status = "partial" if "partial" in statuses else ("ok" if "ok" in statuses else "missing")
    return LoadResult(data, status, gaps, files=sum(r.files for r in parts))


__all__ = ["LOADER_MODULES", "LoadResult", "read_scoped", "read_unit_lists", "region_items"]
