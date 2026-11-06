"""AWS Organizations loader (``global/organizations/``, F-126 data side).

Reads the organizations collector's output (collectors-cli.md §5.15): ``organization.json``
(``InOrganization``, ``Id``, ``ManagementAccountId``, ``IsManagementAccount``, ``AvailablePolicyTypes``,
``PolicyCollection`` …), ``ou_path.json`` (``{Complete, Path}``: the chain root → OUs → account) and
``policies.json`` (SCPs and RCPs with ``Targets`` and ``Content``). The result is an :class:`OrgData` the
evaluator uses for the SCP / RCP layers.

Completeness is tracked **per policy type** from ``organization.json`` ``PolicyCollection``
(``complete | imported | partial | not_collected | not_applicable``; requests ``c-b-2``, ``e-policy-2``):
only a ``complete`` or ``imported`` set is evaluated. A ``partial`` set is a lower bound (a missing Allow at
some level would make the evaluator deny everything), so its policies are kept apart in
:attr:`OrgData.uncollected_policies` and never reach the evaluator; the report-level gap
``org:scp-unknown`` / ``org:rcp-unknown`` is raised instead of silently assuming "no SCP". A policy type that
``AvailablePolicyTypes`` shows as not enabled applies to nobody, so it is never reported as unknown. Reports
written before ``PolicyCollection`` existed fall back to "``policies.json`` readable = both types collected".
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from aws_enumerator.engine.io.fs import read_json, read_list
from aws_enumerator.engine.io.loaders import LoadResult

SCP = "SERVICE_CONTROL_POLICY"
RCP = "RESOURCE_CONTROL_POLICY"
POLICY_TYPES: Tuple[str, ...] = (SCP, RCP)
#: ``PolicyCollection`` states whose policy list is the full set for that type.
COLLECTED_STATES: Tuple[str, ...] = ("complete", "imported")
_GAP_CODES: Mapping[str, Tuple[str, str]] = {
    SCP: ("org:scp-unknown", "Service control policies"),
    RCP: ("org:rcp-unknown", "Resource control policies"),
}


@dataclass
class OrgPolicy:
    id: str
    arn: Optional[str]
    name: str
    type: str                     # SERVICE_CONTROL_POLICY | RESOURCE_CONTROL_POLICY
    aws_managed: bool
    targets: Tuple[str, ...]      # root / OU / account ids the policy is attached to
    document: Any


@dataclass
class OrgData:
    """Organisation membership and its control policies; ``None`` values are unknown, never "false".

    * ``policies``: the policies of the types that were fully collected (what the evaluator may use);
    * ``uncollected_policies``: policies read for a type whose set is incomplete (a lower bound, never evaluated);
    * ``policies_collected``: ``True`` when at least one type's set is complete (``policies`` is meaningful);
      ``collected_types`` says which;
    * ``policy_collection``: ``PolicyCollection`` per type as collected (``None`` when the report predates it);
    * ``available_policy_types``: ``AvailablePolicyTypes`` (``[{Type, Status}]``) as collected, ``None`` unknown;
    * ``path_complete``: ``ou_path.json`` ``Complete`` (``None`` when unknown); an incomplete path is ``()``.
    """

    in_organization: Optional[bool] = None
    org_id: Optional[str] = None
    management_account: Optional[str] = None
    is_management_account: Optional[bool] = None
    path: Tuple[str, ...] = ()                       # root id, OU ids …, account id
    path_complete: Optional[bool] = None
    available_policy_types: Optional[List[Dict[str, Any]]] = None
    policy_collection: Optional[Dict[str, Optional[str]]] = None
    collected_types: Tuple[str, ...] = ()
    policies: List[OrgPolicy] = field(default_factory=list)
    uncollected_policies: List[OrgPolicy] = field(default_factory=list)
    policies_collected: bool = False
    raw: Dict[str, Any] = field(default_factory=dict)   # organization / ou_path / policies documents as read

    def type_collected(self, policy_type: str) -> bool:
        return policy_type in self.collected_types

    def type_enabled(self, policy_type: str) -> Optional[bool]:
        """``True``/``False`` from ``AvailablePolicyTypes``; ``None`` when that list is unknown."""
        if not isinstance(self.available_policy_types, list):
            return None
        return any(isinstance(t, Mapping) and str(t.get("Type", "")).upper() == policy_type
                   and str(t.get("Status", "")).upper() == "ENABLED" for t in self.available_policy_types)

    def chain(self, policy_type: str = SCP) -> Optional[Tuple[Tuple[OrgPolicy, ...], ...]]:
        """Policies per level root → … → account; ``None`` when the chain cannot be built (unknown)."""
        if not self.type_collected(policy_type) or not self.path:
            return None
        return tuple(tuple(p for p in self.policies if p.type == policy_type and level in p.targets)
                     for level in self.path)

    def gaps(self) -> Dict[str, str]:
        """``org:scp-unknown`` / ``org:rcp-unknown`` for each policy type that may apply and is not known."""
        if self.in_organization is False or self.is_management_account:
            return {}
        out: Dict[str, str] = {}
        for ptype in POLICY_TYPES:
            if self.type_enabled(ptype) is False:
                continue                                     # a disabled type applies to nobody
            if self.type_collected(ptype) and self.path:
                continue
            code, label = _GAP_CODES[ptype]
            out[code] = f"{label} are unknown ({self._why(ptype)})"
        return out

    def _why(self, policy_type: str) -> str:
        if self.in_organization is None and not self.type_collected(policy_type):
            return "membership unknown"
        if not self.path:
            return "OU path unknown"
        state = (self.policy_collection or {}).get(policy_type)
        if state == "partial":
            return "control policies partially collected"
        return "control policies not collected"


def _path(raw: Any) -> Tuple[str, ...]:
    if isinstance(raw, Mapping):
        if raw.get("Complete") is False:
            return ()                                        # PartialPath is never a chain
        raw = raw.get("Path") or raw.get("path") or []
    out: List[str] = []
    for item in raw or ():
        ident = item.get("Id") if isinstance(item, Mapping) else item
        if isinstance(ident, str) and ident:
            out.append(ident)
    return tuple(out)


def _path_complete(raw: Any) -> Optional[bool]:
    if isinstance(raw, Mapping):
        value = raw.get("Complete")
        return value if isinstance(value, bool) else None
    return None


def _policy(rec: Mapping[str, Any]) -> Optional[OrgPolicy]:
    pid = rec.get("PolicyId") or rec.get("Id")
    if not isinstance(pid, str):
        return None
    content = rec.get("Content")
    if isinstance(content, str):
        try:
            content = json.loads(content)
        except ValueError:
            content = None
    targets = tuple(sorted(str(t.get("TargetId") if isinstance(t, Mapping) else t)
                           for t in rec.get("Targets") or ()))
    return OrgPolicy(pid, rec.get("Arn"), str(rec.get("Name") or pid), str(rec.get("Type") or SCP),
                     bool(rec.get("AwsManaged")), targets, content)


def _policy_collection(org: Mapping[str, Any]) -> Optional[Dict[str, Optional[str]]]:
    raw = org.get("PolicyCollection")
    if not isinstance(raw, Mapping):
        return None
    return {t: (raw.get(t) if isinstance(raw.get(t), str) else None) for t in POLICY_TYPES}


def _collected_types(collection: Optional[Mapping[str, Optional[str]]], listing_ok: bool) -> Tuple[str, ...]:
    if not listing_ok:
        return ()
    if collection is None:                                   # report predates PolicyCollection
        return POLICY_TYPES
    return tuple(t for t in POLICY_TYPES if collection.get(t) in COLLECTED_STATES)


def _read_organization(data: OrgData, org: Any) -> None:
    if not (org.ok and isinstance(org.data, Mapping)):
        return
    d = org.data
    data.in_organization = d.get("InOrganization") if isinstance(d.get("InOrganization"), bool) else None
    data.org_id, data.management_account = d.get("Id"), d.get("ManagementAccountId")
    data.is_management_account = d.get("IsManagementAccount") if isinstance(
        d.get("IsManagementAccount"), bool) else None
    available = d.get("AvailablePolicyTypes")
    data.available_policy_types = [dict(t) for t in available if isinstance(t, Mapping)] \
        if isinstance(available, list) else None
    data.policy_collection = _policy_collection(d)


def load_org(global_dir: "Path | str") -> Tuple[OrgData, str]:
    base = Path(global_dir) / "organizations"
    if not base.is_dir():
        return OrgData(), "missing"
    org = read_json(base / "organization.json")
    data = OrgData()
    _read_organization(data, org)
    path = read_json(base / "ou_path.json")
    data.path = _path(path.data) if path.ok else ()
    data.path_complete = _path_complete(path.data) if path.ok else None
    items, res = read_list(base / "policies.json")
    data.collected_types = _collected_types(data.policy_collection, res.ok)
    data.policies_collected = bool(data.collected_types)
    every = sorted((p for p in (_policy(r) for r in items if isinstance(r, Mapping)) if p),
                   key=lambda p: (p.type, p.id))
    data.policies = [p for p in every if p.type in data.collected_types]
    data.uncollected_policies = [p for p in every if p.type not in data.collected_types]
    data.raw = {"organization": org.data if org.ok else None, "ou_path": path.data if path.ok else None,
                "policies": items if res.ok else None}
    return data, "ok" if org.ok and res.ok else "partial"


def load(ctx: Any) -> LoadResult:
    data, status = load_org(ctx.global_dir)
    gaps = data.gaps()
    return LoadResult(data, status, gaps)


__all__ = ["COLLECTED_STATES", "OrgData", "OrgPolicy", "POLICY_TYPES", "RCP", "SCP", "load", "load_org"]
