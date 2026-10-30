"""Subsumption and group dedup of rule findings (engine.md §3.4; F-018).

An administrator-equivalent principal has nothing to escalate to, so its 20-odd PRIVESC rows and its DANGER rows
all restate "this is admin" (F-018 measured 86-96 % of the findings of real accounts on such principals). Phase
POSTPROCESS therefore rewrites the rules' findings (origin ``rules``):

1. **ADMIN-001.** Every administrator-equivalent principal (``RulesResult.admins``: its identity allows ``*`` on
   ``*``, or it holds full IAM control and can definitely modify its own permissions) gets **one** ADMIN-001
   CRITICAL finding whose ``subsumes`` lists the rule ids it replaces; those PRIVESC-* and DANGER-* rows (the
   INFO "no passable role" notes included) are dropped. TRUST, hygiene and resource findings stay.
2. **Non-admin subsumption.** DANGER-002 (full IAM control) subsumes PRIVESC-001..013 and DANGER-001 subsumes
   DANGER-003/004/007 on the same principal, but only rows that are not more severe than the subsuming one (a
   row that is more severe carries information the other does not).
3. **Groups.** Rules also run on groups. A member's finding is dropped and the member is listed in the group
   finding's ``affected_members`` (the member node then carries it in ``inherited_findings``) when the member's
   result is the group's: same id, severity and confidence, every granting statement came through that group,
   and no target the group finding lacks. A member-only grant, or a member boundary or deny that changes the
   decision, keeps the member's own finding.
4. **Notes.** A principal's INFO "no passable role currently trusts <service>" notes (one per PassRole rule,
   F-012) collapse into one note (the lowest rule id) that names every service and lists the other rule ids in
   ``subsumes``; likewise its LOW notes for take-overs of resource types no collector lists (App Runner, Batch,
   Bedrock AgentCore, CodeDeploy, Step Functions) collapse into one.

``ctx.shared["subsume"]`` records the counts; ``summary.json`` ``subsumed_count`` counts the distinct subsumed ids.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Set, Tuple

from aws_enumerator.engine.findings.catalog import CatalogEntry
from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.model import SEVERITY_RANK

log = logging.getLogger(__name__)

ADMIN_ID = "ADMIN-001"
RULE_ORIGINS = frozenset({"rules", "subsume"})
#: (subsuming id, ids it subsumes) for principals that are not administrator-equivalent (engine.md §3.4).
NON_ADMIN_SUBSUMPTION: Tuple[Tuple[str, frozenset], ...] = (
    ("DANGER-002", frozenset(f"PRIVESC-{n:03d}" for n in range(1, 14))),
    ("DANGER-001", frozenset({"DANGER-003", "DANGER-004", "DANGER-007"})),
)
_BASIS_TEXT = {
    "allow-star": "its effective permissions allow every action on every resource",
    "iam-self-escalation": "it has full IAM control and can grant itself any permission",
}

FINDINGS: Tuple[CatalogEntry, ...] = (
    CatalogEntry(
        ADMIN_ID, "CRITICAL", "dangerous_permission", "Administrator-equivalent principal",
        "Treat this principal as an account administrator: limit who can use it (trust policy, group membership, "
        "credentials), require MFA, and replace broad grants (Action:* or iam:*) by the permissions it needs.",
        "#high-value-targets-to-hunt",
        description="The principal can perform every action in the account; its individual privilege-escalation "
                    "and dangerous-permission findings are summarised in this one finding.",
    ),
)


@dataclass
class SubsumeStats:
    """What the pass changed (``ctx.shared["subsume"]``)."""

    admins: int = 0
    subsumed_by_admin: int = 0
    subsumed_non_admin: int = 0
    group_deduplicated: int = 0
    notes_collapsed: int = 0
    subsumed_ids: Set[str] = field(default_factory=set)

    def to_json(self) -> Dict[str, Any]:
        return {"admins": self.admins, "subsumed_by_admin": self.subsumed_by_admin,
                "subsumed_non_admin": self.subsumed_non_admin, "group_deduplicated": self.group_deduplicated,
                "notes_collapsed": self.notes_collapsed, "subsumed_ids": sorted(self.subsumed_ids)}


def _is_rule_id(fid: str) -> bool:
    return fid.startswith("PRIVESC-") or fid.startswith("DANGER-")


def _rule_findings(builder: Any) -> Dict[str, List[Any]]:
    """Node id → the native rules' findings anchored there (fingerprint order)."""
    out: Dict[str, List[Any]] = {}
    for f in builder.findings():
        if builder.finding_origin(f.fingerprint) in RULE_ORIGINS and (_is_rule_id(f.id) or f.id == ADMIN_ID):
            out.setdefault(f.node_id, []).append(f)
    return out


def _sev_rank(f: Any) -> int:
    return SEVERITY_RANK.get(str(f.severity).upper(), len(SEVERITY_RANK))


# ── 1. ADMIN-001 ─────────────────────────────────────────────────────────────

def _admin_finding(builder: Any, pid: str, basis: Mapping[str, Any], rows: Sequence[Any], account: str) -> str:
    subsumed = sorted(rows, key=lambda f: (f.id, f.fingerprint))
    grant = next((f for f in subsumed if f.id in ("DANGER-001", "DANGER-002")), None)
    kind = builder.node(pid).type if builder.node(pid) else "principal"
    reason = _BASIS_TEXT.get(str(basis.get("basis")), "it is administrator-equivalent")
    evidence = {"basis": basis.get("basis"), "rule_ids": sorted(basis.get("rule_ids") or ()),
                "subsumed": [{"id": f.id, "severity": f.severity, "fingerprint": f.fingerprint} for f in subsumed],
                "subsumed_count": len(subsumed)}
    if grant is not None and grant.evidence.get("steps"):
        evidence["steps"] = grant.evidence["steps"]
    return builder.add_finding(
        ADMIN_ID, pid, severity="CRITICAL", title="Administrator-equivalent principal",
        description=f"This {kind} is administrator-equivalent: {reason}. Its {len(subsumed)} individual "
                    "privilege-escalation and dangerous-permission findings are summarised here.",
        evidence=evidence, confidence="definite", subsumes=sorted({f.id for f in subsumed}),
        matched_actions=sorted({a for f in subsumed for a in f.matched_actions if f.id.startswith("DANGER-")}),
        via_group=grant.via_group if grant is not None else None,
        related_node_ids=[ids.account_admin_id(account)])


def subsume_admins(builder: Any, admins: Mapping[str, Mapping[str, Any]], account: str,
                   stats: SubsumeStats) -> None:
    by_node = _rule_findings(builder)
    for pid in sorted(admins):
        if not builder.has_node(pid):
            continue
        rows = [f for f in by_node.get(pid, ()) if _is_rule_id(f.id)]
        _admin_finding(builder, pid, admins[pid], rows, account)
        for f in rows:
            builder.remove_finding(f.fingerprint)
            stats.subsumed_ids.add(f.id)
        stats.admins += 1
        stats.subsumed_by_admin += len(rows)


# ── 2. non-admin subsumption ─────────────────────────────────────────────────

def subsume_non_admin(builder: Any, stats: SubsumeStats) -> None:
    for _node_id, rows in sorted(_rule_findings(builder).items()):
        for head_id, covered in NON_ADMIN_SUBSUMPTION:
            head = next((f for f in rows if f.id == head_id), None)
            if head is None:
                continue
            dropped = [f for f in rows if f.id in covered and _sev_rank(f) >= _sev_rank(head)]
            if not dropped:
                continue
            head.subsumes = sorted(set(head.subsumes) | {f.id for f in dropped})
            head.evidence.setdefault("subsumed", []).extend(
                {"id": f.id, "severity": f.severity, "fingerprint": f.fingerprint} for f in dropped)
            for f in dropped:
                builder.remove_finding(f.fingerprint)
                stats.subsumed_ids.add(f.id)
            stats.subsumed_non_admin += len(dropped)
            rows = [f for f in rows if f not in dropped]


# ── 3. groups ────────────────────────────────────────────────────────────────

def _target_ids(f: Any) -> Set[str]:
    return {t.get("node_id") for t in f.targets if isinstance(t, Mapping) and t.get("node_id")}


def same_result(group_f: Any, member_f: Any, group_id: str) -> bool:
    """The member's finding repeats the group's (engine.md §3.4)."""
    return (member_f.severity == group_f.severity and member_f.confidence == group_f.confidence
            and member_f.via_group == group_id and _target_ids(member_f) <= _target_ids(group_f) | {member_f.node_id}
            and (member_f.evidence or {}).get("no_candidate") == (group_f.evidence or {}).get("no_candidate"))


def dedup_groups(builder: Any, group_members: Mapping[str, Sequence[str]], stats: SubsumeStats) -> None:
    by_node = _rule_findings(builder)
    for gid in sorted(group_members):
        group_rows = {f.id: f for f in by_node.get(gid, ())}
        if not group_rows:
            continue
        for member in sorted(set(group_members[gid])):
            for mf in list(by_node.get(member, ())):
                gf = group_rows.get(mf.id)
                if gf is None or builder.finding(mf.fingerprint) is None or not same_result(gf, mf, gid):
                    continue
                gf.affected_members = sorted(set(gf.affected_members) | {member})
                builder.remove_finding(mf.fingerprint)
                stats.group_deduplicated += 1


# ── 4. no-candidate notes ────────────────────────────────────────────────────

def _services(f: Any) -> List[str]:
    services = (f.evidence or {}).get("services")
    return [str(s) for s in services] if isinstance(services, list) else []


def collapse_notes(builder: Any, stats: SubsumeStats) -> None:
    for _node_id, rows in sorted(_rule_findings(builder).items()):
        notes = sorted((f for f in rows if (f.evidence or {}).get("no_candidate") and f.severity == "INFO"),
                       key=lambda f: (f.id, f.fingerprint))
        if len(notes) < 2:
            continue
        keep, rest = notes[0], notes[1:]
        services = sorted({s for f in notes for s in _services(f)})
        keep.title = ("PassRole chains without a passable role: no passable role currently trusts "
                      + ", ".join(services))
        keep.description = (f"This principal holds {len(notes)} complete PassRole chains "
                            f"({', '.join(f.id for f in notes)}) but no role it may pass trusts the service and is "
                            "more privileged than the principal.")
        keep.subsumes = sorted(set(keep.subsumes) | {f.id for f in rest})
        keep.evidence["services"] = services
        keep.evidence["collapsed"] = [{"id": f.id, "fingerprint": f.fingerprint, "services": _services(f)}
                                      for f in rest]
        keep.affected_members = sorted(set(keep.affected_members).union(*(f.affected_members for f in rest)))
        for f in rest:
            builder.remove_finding(f.fingerprint)
            stats.subsumed_ids.add(f.id)
        stats.notes_collapsed += len(rest)


def _uncollected_types(f: Any) -> List[str]:
    """Resource types of a finding whose every target is an uncollected-type probe (else ``[]``)."""
    details = (f.evidence or {}).get("targets_detail") or []
    if not details or any(d.get("tier_class") != "uncollected" for d in details):
        return []
    return sorted({str(d.get("resource_type")) for d in details if d.get("resource_type")})


def collapse_uncollected(builder: Any, stats: SubsumeStats) -> None:
    """One LOW note per principal for the take-overs of resource types aws-enumerator does not collect."""
    from aws_enumerator.engine.rules.inventory import resource_label

    for _node_id, rows in sorted(_rule_findings(builder).items()):
        notes = sorted((f for f in rows if _uncollected_types(f)), key=lambda f: (f.id, f.fingerprint))
        if len(notes) < 2:
            continue
        keep, rest = notes[0], notes[1:]
        labels = sorted({resource_label(t) for f in notes for t in _uncollected_types(f)})
        keep.title = "May take over resources aws-enumerator does not collect: " + ", ".join(labels)
        keep.description = (f"This principal holds the permissions of {len(notes)} take-over techniques "
                            f"({', '.join(f.id for f in notes)}) on resource types that are not collected; whether "
                            "any of them runs as a privileged role is unknown.")
        keep.subsumes = sorted(set(keep.subsumes) | {f.id for f in rest})
        keep.gaps = sorted(set(keep.gaps).union(*(f.gaps for f in rest)))
        keep.evidence["collapsed"] = [
            {"id": f.id, "fingerprint": f.fingerprint, "resource_types": _uncollected_types(f)} for f in rest]
        keep.affected_members = sorted(set(keep.affected_members).union(*(f.affected_members for f in rest)))
        for f in rest:
            builder.remove_finding(f.fingerprint)
            stats.subsumed_ids.add(f.id)
        stats.notes_collapsed += len(rest)


# ── pipeline registration ────────────────────────────────────────────────────

def admins_from_graph(builder: Any) -> Dict[str, Dict[str, Any]]:
    """Principals with a definite IS_ADMIN_EQUIVALENT edge (the identity analyzer's evaluator decision)."""
    out: Dict[str, Dict[str, Any]] = {}
    for e in builder.edges("IS_ADMIN_EQUIVALENT"):
        if e.confidence == "definite":
            out[e.source] = {"basis": "allow-star", "rule_ids": ["DANGER-001"]}
    return out


def subsume(builder: Any, admins: Mapping[str, Mapping[str, Any]], group_members: Mapping[str, Iterable[str]],
            account: str) -> SubsumeStats:
    """Steps 1-4 of the module docstring on ``builder``; returns what changed."""
    stats = SubsumeStats()
    subsume_admins(builder, admins, account, stats)
    subsume_non_admin(builder, stats)
    dedup_groups(builder, {g: list(m) for g, m in group_members.items()}, stats)
    collapse_notes(builder, stats)
    collapse_uncollected(builder, stats)
    return stats


def _run(ctx: Any, builder: Any) -> None:
    """Phase POSTPROCESS: ADMIN-001, non-admin subsumption, group dedup, no-candidate notes."""
    admins = dict(admins_from_graph(builder))
    admins.update(ctx.shared.get("rules.admins") or {})
    pset = ctx.shared.get("iam.principal_set")
    members: Mapping[str, Iterable[str]] = getattr(pset, "group_members", None) or {}
    stats = subsume(builder, admins, members, ctx.account_id)
    ctx.shared["subsume"] = stats.to_json()
    log.debug("subsumption: %s", stats.to_json())


def _analyzers() -> Tuple[Any, ...]:
    from aws_enumerator.engine.model import AnalyzerSpec, Phase

    return (AnalyzerSpec("subsume", Phase.POSTPROCESS, _run, inputs=("iam.authorization_details",),
                         requires=("rules",)),)


ANALYZERS = _analyzers()

__all__ = [
    "ADMIN_ID", "ANALYZERS", "FINDINGS", "NON_ADMIN_SUBSUMPTION", "SubsumeStats", "admins_from_graph",
    "collapse_notes", "dedup_groups", "same_result", "subsume", "subsume_admins", "subsume_non_admin",
]
