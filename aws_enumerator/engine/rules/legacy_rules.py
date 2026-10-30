"""Permission-map entry points of the data-driven rules engine (the d13c215 names, kept for callers that hold a
permission map instead of a collected report: the rule characterisation tests and ad-hoc checks).

The d13c215 rule tables (``PRIVESC_RULES`` / ``DANGEROUS_RULES``) are gone (Wave 3, DECISIONS.md D-53); the rules
are ``rules/data/*.json``. :func:`_detect_privesc_paths` and :func:`_detect_dangerous_permissions` keep their
signatures but evaluate ``rules/data/*.json`` through the policy evaluator (F-001, F-012, F-014, F-015, F-017,
F-019, F-069, F-071): the permission map is turned back into principal models
(:func:`~aws_enumerator.engine.iam.principals.models_from_permission_map`), so Deny, NotAction, NotResource,
conditions, boundaries, resource scope and PassRole targets all count. The output keeps the d13c215 finding keys
and adds ``base_severity``, ``confidence``, ``targets`` and ``evidence``. The analysis pipeline does not use these
entry points (its rules analyzer is :mod:`aws_enumerator.engine.rules.runner`).
"""

from typing import Any, Dict, List, Mapping, Optional, Tuple

from aws_enumerator.engine.iam.principals import models_from_permission_map
from aws_enumerator.engine.policy.evaluator import Evaluator
from aws_enumerator.engine.rules.catalogue import load_catalogue
from aws_enumerator.engine.rules.runner import (
    PrivilegeOracle, RulesContext, legacy_finding, run_danger_rule, run_privesc_rule,
)


# ──────────────────────────────────────────────────────────────
# Detection over the permission map (d13c215 signatures)
# ──────────────────────────────────────────────────────────────

def _legacy_session(permission_map: Mapping[str, Any], account_id: Optional[str], partition: Optional[str]
                    ) -> Tuple[Any, RulesContext, PrivilegeOracle]:
    pset = models_from_permission_map(permission_map, account_id=account_id, partition=partition)
    evaluator = Evaluator(None, pset.models, pset.resource_index(), None, account_id=pset.account_id,
                          partition=pset.partition)
    catalogue = load_catalogue()
    rctx = RulesContext(evaluator, pset, {}, catalogue)
    return pset, rctx, PrivilegeOracle(rctx, catalogue)


def _entities(permission_map: Mapping[str, Any], pset: Any, entity_types: Tuple[str, ...]
              ) -> List[Tuple[str, str, str, Any]]:
    """(kind, name, legacy entity_arn, model) in permission-map order (the d13c215 iteration order)."""
    out = []
    for entity_type in entity_types:
        kind = entity_type.rstrip("s")
        for name, entry in (permission_map.get(entity_type) or {}).items():
            arn = entry.get("arn", "") if isinstance(entry, Mapping) else ""
            model_id = arn or f"arn:{pset.partition}:iam::{pset.account_id or '000000000000'}:{kind}/{name}"
            model = pset.models.get(model_id)
            if model is not None:
                out.append((kind, name, arn, model))
    return out


def _collapse_no_candidate(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One INFO "no passable role" record per entity (the lowest rule id; the others in ``subsumes``).

    The same collapse as ``rules/subsume.py`` step 4, so the 40-odd PassRole rules of the imported catalogue do
    not give a broad principal one note each.
    """
    notes = [r for r in records if r.get("no_candidate")]
    if len(notes) < 2:
        return records
    keep = dict(notes[0])
    services = sorted({s for r in notes for s in (r.get("evidence") or {}).get("services") or ()})
    keep["title"] = "PassRole chains without a passable role: no passable role currently trusts " + ", ".join(services)
    keep["subsumes"] = sorted({r["id"] for r in notes[1:]})
    return [keep if r is notes[0] else r for r in records if r is notes[0] or not r.get("no_candidate")]


def _detect_privesc_paths(permission_map, *, account_id: Optional[str] = None, partition: Optional[str] = None):
    """Privilege-escalation findings for every user and role of the permission map (d13c215 signature)."""
    pset, rctx, oracle = _legacy_session(permission_map, account_id, partition)
    findings: List[Dict[str, Any]] = []
    for kind, name, arn, model in _entities(permission_map, pset, ("users", "roles")):
        records = []
        for rule in rctx.catalogue.privesc:
            hit = run_privesc_rule(rule, model, rctx, oracle)
            if hit is not None:
                records.append(legacy_finding(hit, entity_kind=kind, entity_name=name, entity_arn=arn))
        findings.extend(_collapse_no_candidate(records))
    return findings


def _detect_dangerous_permissions(permission_map, *, account_id: Optional[str] = None,
                                  partition: Optional[str] = None):
    """Dangerous-permission findings for every user, role and group (d13c215 signature).

    A rule fires when one Allow statement covers the rule's capability (action glob and resource template)
    and no Deny overlaps it (F-019, F-014); NotAction/NotResource grants count (F-001).
    """
    pset, rctx, _ = _legacy_session(permission_map, account_id, partition)
    findings: List[Dict[str, Any]] = []
    for kind, name, arn, model in _entities(permission_map, pset, ("users", "roles", "groups")):
        for rule in rctx.catalogue.dangerous:
            hit = run_danger_rule(rule, model, rctx)
            if hit is not None:
                findings.append(legacy_finding(hit, entity_kind=kind, entity_name=name, entity_arn=arn))
    return findings
