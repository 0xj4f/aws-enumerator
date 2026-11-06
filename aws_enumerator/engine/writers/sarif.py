"""SARIF 2.1.0 export of the findings (exports.md §2; F-165).

One ``run`` whose ``tool.driver.rules`` holds one rule per distinct finding ``id`` (in id order) and whose
``results`` hold one result per exported finding, in the exports.md §1 order:

* ``level`` and the rule's ``security-severity`` come from the severity table of exports.md §1;
  ``properties.severity`` copies the stored value unchanged (D-24);
* the real location of a finding is its **logical** location (the node id, i.e. the resource ARN); the
  ``physicalLocation`` (``analysis/graph.json`` under the ``RUNROOT`` base id) exists because code-scanning
  consumers require one;
* ``partialFingerprints["awsEnumeratorFingerprint/v1"]`` is the finding's ``fp1`` fingerprint (F-143), so
  re-uploads of a re-run deduplicate;
* a suppressed finding (exported only with ``include_suppressed``) carries an external suppression with the
  suppression reason;
* per-finding ``account`` is the finding's account (falling back to ``run.account_id``), a global resource's
  region is ``global`` (D-25, D-50).

Rule metadata (short and full description, help URI) is taken from the graph itself (the first exported
finding of each id), so the export depends only on its input.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Mapping, Optional, Tuple

from aws_enumerator.engine.findings.references import REPOSITORY_URL
from aws_enumerator.engine.writers.csv import Selection, select_findings, severity_class, severity_rank

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
FINGERPRINT_KEY = "awsEnumeratorFingerprint/v1"
#: exports.md §1: severity → (SARIF level, security-severity).
LEVELS: Mapping[str, Tuple[str, str]] = {
    "critical": ("error", "9.5"), "high": ("error", "8.0"), "medium": ("warning", "5.5"),
    "low": ("note", "3.0"), "info": ("note", "0.0"),
}


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _region(f: Mapping[str, Any]) -> str:
    region = f.get("region")
    return region if isinstance(region, str) and region else "global"


def _rules(sel: Selection) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """One rule per finding id (id order); the rule severity is the worst exported severity of that id."""
    firsts: Dict[str, Mapping[str, Any]] = {}
    worst: Dict[str, int] = {}
    for f in sel.findings:
        fid = _text(f.get("id"))
        firsts.setdefault(fid, f)
        worst[fid] = min(worst.get(fid, 99), severity_rank(f.get("severity")))
    rules: List[Dict[str, Any]] = []
    index: Dict[str, int] = {}
    for fid in sorted(firsts):
        first = firsts[fid]
        level, score = LEVELS[("critical", "high", "medium", "low", "info")[worst[fid]]]
        rule: Dict[str, Any] = {
            "id": fid, "name": fid,
            "shortDescription": {"text": _text(first.get("title")) or fid},
            "fullDescription": {"text": _text(first.get("description")) or _text(first.get("title")) or fid},
            "defaultConfiguration": {"level": level},
            "properties": {"tags": ["security", "aws"] + ([first["category"]] if _text(first.get("category"))
                                                          else []),
                           "security-severity": score},
        }
        if _text(first.get("reference")):
            rule["helpUri"] = first["reference"]
        index[fid] = len(rules)
        rules.append(rule)
    return rules, index


def _location(sel: Selection, f: Mapping[str, Any]) -> Dict[str, Any]:
    logical: Dict[str, Any] = {"fullyQualifiedName": _text(f.get("node_id"))}
    label, node_type = sel.node_label(f), sel.node_type(f)
    if label:
        logical["name"] = label
    if node_type:
        logical["kind"] = node_type
    return {"physicalLocation": {"artifactLocation": {"uri": "analysis/graph.json", "uriBaseId": "RUNROOT"},
                                 "region": {"startLine": 1}},
            "logicalLocations": [logical]}


def _result(sel: Selection, f: Mapping[str, Any], rule_index: int) -> Dict[str, Any]:
    label = sel.node_label(f)
    title = _text(f.get("title")) or _text(f.get("id"))
    props: Dict[str, Any] = {
        "severity": f.get("severity"), "confidence": f.get("confidence"), "account": sel.account(f),
        "region": _region(f), "node_type": sel.node_type(f),
        "related_node_ids": sorted(r for r in f.get("related_node_ids") or () if isinstance(r, str)),
        "status": f.get("status"),
    }
    out: Dict[str, Any] = {
        "ruleId": _text(f.get("id")), "ruleIndex": rule_index,
        "level": LEVELS[severity_class(f.get("severity"))][0],
        "message": {"text": f"{title} ({label})" if label else title},
        "locations": [_location(sel, f)],
        "partialFingerprints": {FINGERPRINT_KEY: _text(f.get("fingerprint"))},
        "properties": {k: v for k, v in props.items() if v is not None},
    }
    if f.get("status") == "suppressed":
        supp = f.get("suppression") if isinstance(f.get("suppression"), Mapping) else {}
        out["suppressions"] = [{"kind": "external",
                                "justification": _text(supp.get("reason")) or "suppressed by the operator"}]
    return out


def document(sel: Selection) -> Dict[str, Any]:
    """The SARIF log object for a selection of findings."""
    rules, index = _rules(sel)
    version = _text(sel.generator.get("version")) or "unknown"
    account = _text(sel.run.get("account_id")) or "unknown"
    run_id = _text(sel.run.get("run_id")) or "unknown"
    invocation: Dict[str, Any] = {"executionSuccessful": True}
    if _text(sel.run.get("generated_at")):
        invocation["endTimeUtc"] = sel.run["generated_at"]
    driver = {"name": "aws-enumerator", "version": version, "semanticVersion": version,
              "informationUri": REPOSITORY_URL, "rules": rules}
    run = {
        "tool": {"driver": driver},
        "automationDetails": {"id": f"aws-enumerator/{account}/{run_id}"},
        "invocations": [invocation],
        "originalUriBaseIds": {"RUNROOT": {"description": {"text": "aws-enumerator run root"}}},
        "results": [_result(sel, f, index[_text(f.get("id"))]) for f in sel.findings],
    }
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def render(graph: Mapping[str, Any], *, min_severity: Optional[str] = None, include_suppressed: bool = False,
           all_edges: bool = False) -> bytes:
    """``findings.sarif`` (exports.md §2). ``all_edges`` does not apply to findings and is ignored."""
    del all_edges
    sel = select_findings(graph, min_severity=min_severity, include_suppressed=include_suppressed)
    return (json.dumps(document(sel), indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


__all__ = ["FINGERPRINT_KEY", "LEVELS", "SARIF_SCHEMA", "SARIF_VERSION", "document", "render"]
