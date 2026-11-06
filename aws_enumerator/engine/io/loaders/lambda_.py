"""Lambda loader: functions, resource policies per qualifier, layers and event source mappings (E-compute).

Reads only the explicit units of the analysis context (``ctx.region_dirs``), never sibling directories (F-010,
F-025, F-063), in both collector layouts:

* **v2** (collectors-cli.md, ``collectors/lambda_.py``): ``functions.json`` with ``FunctionUrls`` / ``Aliases`` /
  ``PolicyStatus`` (``null`` = unknown), ``resource_policies/<slug>-<sha12>.json`` holding
  ``{FunctionArn (unqualified), FunctionName, Qualifier, QualifiedArn, ResourcePolicy}`` (one file per policy:
  the function's own and each alias's, F-055, F-114), ``layers.json`` and ``event_source_mappings.json`` (F-116);
* **legacy** (d13c215): ``functions.json`` with a single ``FunctionUrl`` and ``resource_policies/<name>.json``
  holding ``{FunctionArn, FunctionName, ResourcePolicy}`` (no qualifier, no ``PolicyStatus``).

``data`` (``ctx.data["lambda"]``)::

    {"functions": {unit: [record]},                     # as collected (the rules read FunctionArn / Role)
     "policies": {unit: [{FunctionArn, FunctionName, Qualifier, QualifiedArn, ResourcePolicy, File}]},
     "layers": {unit: [record]}, "event_source_mappings": {unit: [record]}}

Policies are keyed by (``FunctionArn``, ``Qualifier``), never by ``FunctionArn`` alone, so an alias policy can no
longer overwrite the function's own policy (request c-b-1). ``FunctionArn`` is always the **unqualified** ARN; a
legacy file whose ``FunctionArn`` carries a qualifier is split. An ``{"Error"}`` stub or unreadable file becomes a
gap (``<path>:<status>``), never data (F-058, F-059).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from aws_enumerator.engine.io.fs import ls_sorted, read_json, stub_status
from aws_enumerator.engine.io.loaders import LoadResult, read_scoped, region_items

GLOBAL_FILES: Dict[str, str] = {}
REGIONAL_FILES: Dict[str, str] = {
    "functions": "lambda/functions.json",
    "layers": "lambda/layers.json",
    "event_source_mappings": "lambda/event_source_mappings.json",
}
POLICY_DIR = "lambda/resource_policies"


def split_function_arn(arn: Any) -> Tuple[Optional[str], Optional[str]]:
    """``(unqualified ARN, qualifier)`` of a function ARN; ``(None, None)`` when it is not one.

    ``$LATEST`` is the unqualified function (Lambda resolves it to the same resource policy).
    """
    if not isinstance(arn, str) or not arn.startswith("arn:"):
        return None, None
    parts = arn.split(":")
    if len(parts) < 7 or parts[2] != "lambda" or parts[5] != "function" or not parts[6]:
        return None, None
    base = ":".join(parts[:7])
    qualifier = ":".join(parts[7:]) or None
    return base, (None if qualifier == "$LATEST" else qualifier)


def normalise_policy(rec: Mapping[str, Any], file_name: str) -> Optional[Dict[str, Any]]:
    """One policy file as ``{FunctionArn, FunctionName, Qualifier, QualifiedArn, ResourcePolicy, File}``."""
    base, arn_qualifier = split_function_arn(rec.get("FunctionArn"))
    if base is None:
        base, arn_qualifier = split_function_arn(rec.get("QualifiedArn"))
    if base is None:
        return None
    qualifier = rec.get("Qualifier") if isinstance(rec.get("Qualifier"), str) and rec.get("Qualifier") else None
    qualifier = qualifier or arn_qualifier
    if qualifier == "$LATEST":
        qualifier = None
    return {"FunctionArn": base, "FunctionName": rec.get("FunctionName") or base.rsplit(":", 1)[-1],
            "Qualifier": qualifier, "QualifiedArn": f"{base}:{qualifier}" if qualifier else base,
            "ResourcePolicy": rec.get("ResourcePolicy"), "File": file_name}


def _read_policies(unit: str, base: Path, gaps: Dict[str, str]) -> Tuple[List[Dict[str, Any]], int]:
    """Every policy file of one unit, keyed (FunctionArn, Qualifier); a duplicate key keeps the first file."""
    out: Dict[Tuple[str, Optional[str]], Dict[str, Any]] = {}
    seen = 0
    for name in ls_sorted(base / POLICY_DIR):
        if not name.endswith(".json"):
            continue
        seen += 1
        res = read_json(base / POLICY_DIR / name)
        if not res.ok:
            status = stub_status(res.error_code) if res.status == "error-stub" else "error"
            gaps[f"{POLICY_DIR}/{name}:{status}"] = f"{unit}/{POLICY_DIR}/{name} could not be read"
            continue
        rec = normalise_policy(res.data, name) if isinstance(res.data, Mapping) else None
        if rec is None:
            gaps[f"{POLICY_DIR}/{name}:error"] = f"{unit}/{POLICY_DIR}/{name} names no function"
            continue
        out.setdefault((rec["FunctionArn"], rec["Qualifier"] or ""), rec)
    return [out[k] for k in sorted(out)], seen


def load(ctx: Any) -> LoadResult:
    """``ctx.data["lambda"]`` (module docstring)."""
    result = read_scoped(ctx, GLOBAL_FILES, REGIONAL_FILES)
    data: Dict[str, Any] = dict(result.data)
    policies: Dict[str, List[Dict[str, Any]]] = {}
    gaps = dict(result.gaps)
    files = result.files
    for unit, base in region_items(ctx.region_dirs):
        policies[unit], seen = _read_policies(unit, Path(base), gaps)
        files += seen
    data["policies"] = policies
    status = result.status
    if status == "missing" and any(policies.values()):
        status = "ok"
    if gaps and status == "ok":
        status = "partial"
    return LoadResult(data, status, gaps, files=files)


__all__ = ["GLOBAL_FILES", "POLICY_DIR", "REGIONAL_FILES", "load", "normalise_policy", "split_function_arn"]
