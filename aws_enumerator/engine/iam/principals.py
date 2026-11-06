"""Principal models for the evaluator, and the legacy ``permission_map.json`` view (engine.md §1.1, §2.1).

Two products, one parser:

* :func:`build_principal_set` turns the IAM loader's :class:`~aws_enumerator.engine.io.loaders.iam.IamData`
  (both collector layouts, keyed by ARN) into one :class:`~aws_enumerator.engine.model.PrincipalModel` per user,
  role and group: identity statements with ``Deny``, ``NotAction``, ``NotResource`` and ``Condition`` intact
  (F-001, F-014, F-015), group statements inherited by members with ``source.via_group`` set, the permissions
  boundary layer (F-052; a boundary whose document was not collected is ``"missing"``), the SCP chain from the
  organisation data when it was collected (F-126), principal tags, the service-linked exemption and a
  per-service action index (F-142 / F-030 prefilter).
* :func:`_build_permission_map` keeps the d13c215 signature and output shape for the legacy output
  ``permission_map.json`` (one release). Each entity entry additionally records what the old map dropped, so the file is
  a faithful view of the policies: ``not_actions`` / ``not_resources`` / ``conditions`` / ``sid`` on effective
  statements (only when present), ``deny_statements`` (only when present), ``permissions_boundary`` (only when
  set) and, for roles, ``trust_policy``. Allow-statement entries keep ``actions`` / ``resources`` exactly as
  before, so analyzers that still iterate them see the same data (an Allow ``NotAction`` statement has
  ``actions: []`` there, as it had in d13c215). :func:`models_from_permission_map` rebuilds principal models from
  this view (the legacy rule entry points use it).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from aws_enumerator.engine.model import ActionIndex, PolicyDoc, Principal, PrincipalModel, Statement
from aws_enumerator.engine.policy.arn import parse_arn
from aws_enumerator.engine.policy.org import OrgModel
from aws_enumerator.engine.policy.evaluator import UNKNOWN_POLICY_GAPS
from aws_enumerator.engine.policy.parse import (
    _extract_statements, _normalize_to_list, iter_statements, load_document, parse_policy, source_type_for,
)
from aws_enumerator.engine.policy.resource_policy import ResourcePolicyIndex

log = logging.getLogger(__name__)

_SERVICE_LINKED_PATH = "/aws-service-role/"
Boundary = Union[Tuple[Statement, ...], None, str]


# ── action index (engine.md §2.6) ────────────────────────────────────────────

def build_action_index(statements: Sequence[Statement]) -> ActionIndex:
    """``service -> statement indices`` plus the statements that may match any service (wildcards, NotAction)."""
    by_service: Dict[str, List[int]] = {}
    wildcard: List[int] = []
    for i, stmt in enumerate(statements):
        if stmt.service_prefixes is None:
            wildcard.append(i)
            continue
        for svc in stmt.service_prefixes:
            by_service.setdefault(svc, []).append(i)
    return ActionIndex(by_service={k: tuple(v) for k, v in sorted(by_service.items())}, wildcard=tuple(wildcard))


# ── the principal set ────────────────────────────────────────────────────────

@dataclass
class PrincipalSet:
    """Everything phase 3 (PRINCIPALS) produces for the evaluator and the rules.

    * ``models``: node id (ARN) → :class:`PrincipalModel` for every user, role and group.
    * ``trust``: role ARN → parsed trust policy (also registered in :meth:`resource_index`).
    * ``policy_holders``: customer-managed policy ARN → principals it is attached to (users, roles, groups).
    * ``policy_versions``: customer-managed policy ARN → ``{version_id: PolicyDoc}`` when every version was
      collected (GAAD layout), ``None`` when only the default version is known (legacy layout).
    * ``group_members``: group ARN → member user ARNs.
    * ``login_profiles``: user ARN → ``True``/``False`` (``None`` unknown).
    * ``listing_complete``: ``user``/``role``/``group`` → whether the listing was readable.
    * ``gaps``: report-level gap code → detail.
    """

    account_id: Optional[str]
    partition: str
    models: Dict[str, PrincipalModel] = field(default_factory=dict)
    trust: Dict[str, PolicyDoc] = field(default_factory=dict)
    policy_holders: Dict[str, List[str]] = field(default_factory=dict)
    policy_versions: Dict[str, Optional[Dict[str, PolicyDoc]]] = field(default_factory=dict)
    group_members: Dict[str, List[str]] = field(default_factory=dict)
    login_profiles: Dict[str, Optional[bool]] = field(default_factory=dict)
    instance_profile_roles: Optional[frozenset] = None
    listing_complete: Dict[str, bool] = field(default_factory=lambda: {"user": True, "role": True, "group": True})
    gaps: Dict[str, str] = field(default_factory=dict)

    def of_kind(self, kind: str) -> List[PrincipalModel]:
        """Models of one kind (``user``, ``role``, ``group``) in ARN order."""
        marker = f":{kind}/"
        return [self.models[a] for a in sorted(self.models) if marker in a]

    def resource_index(self) -> ResourcePolicyIndex:
        """A :class:`ResourcePolicyIndex` holding every role's trust policy (other domains add theirs)."""
        index = ResourcePolicyIndex(default_owner=self.account_id, partition=self.partition)
        for arn in sorted(self.trust):
            index.add(arn, self.trust[arn], layer="trust", owner=self.account_id)
        return index


def _principal_for(kind: str, arn: str, name: str) -> Principal:
    parsed = parse_arn(arn)
    account = parsed.account if parsed and parsed.account else None
    partition = parsed.partition if parsed else None
    pkind = {"user": "aws_user", "role": "aws_role"}.get(kind, "aws_user")
    # Groups are evaluated on behalf of an unknown member user (engine.md §3.4); they never match ARNs.
    return Principal(pkind, arn, arn, account, partition, name if kind != "group" else None)


def _parse_doc_statements(doc: Any, **kw: Any) -> Tuple[Statement, ...]:
    return parse_policy(doc, **kw).statements if doc is not None else ()


def _managed_statements(policy_arns: Iterable[str], policies: Mapping[str, Any], partition: str,
                        via_group: Optional[str], gaps: set) -> List[Statement]:
    out: List[Statement] = []
    for parn in policy_arns:
        pol = policies.get(parn)
        doc = getattr(pol, "document", None) if pol is not None else None
        if doc is None:
            gaps.add("iam:policy-doc-missing")
            continue
        out.extend(_parse_doc_statements(
            doc, layer="identity", source_type=source_type_for(parn), policy_arn=parn,
            policy_name=getattr(pol, "name", None), version_id=getattr(pol, "default_version", None),
            via_group=via_group, partition=partition))
    return out


def _inline_statements(inline: Mapping[str, Any], partition: str, via_group: Optional[str]) -> List[Statement]:
    out: List[Statement] = []
    for pname in sorted(inline):
        out.extend(_parse_doc_statements(inline[pname], layer="identity", source_type="inline", policy_name=pname,
                                         via_group=via_group, partition=partition))
    return out


def _entity_gaps(ent: Any) -> set:
    gaps = set(getattr(ent, "gaps", ()) or ())
    if getattr(ent, "attached_status", "complete") != "complete":
        gaps.add("iam:attached-unknown")
    if getattr(ent, "inline_status", "complete") != "complete":
        gaps.add("iam:inline-unknown")
    if getattr(ent, "groups_status", "complete") != "complete":
        gaps.add("iam:groups-unknown")
    return gaps


def _own_statements(ent: Any, policies: Mapping[str, Any], partition: str, via_group: Optional[str],
                    gaps: set) -> List[Statement]:
    stmts = _managed_statements(getattr(ent, "attached", ()) or (), policies, partition, via_group, gaps)
    stmts.extend(_inline_statements(getattr(ent, "inline", {}) or {}, partition, via_group))
    return stmts


def _boundary(ent: Any, policies: Mapping[str, Any], partition: str) -> Boundary:
    barn = getattr(ent, "boundary_arn", None)
    if not barn:
        return None
    pol = policies.get(barn)
    doc = getattr(pol, "document", None) if pol is not None else None
    if doc is None:
        return "missing"
    return parse_policy(doc, layer="boundary", source_type="boundary", policy_arn=barn,
                        policy_name=getattr(pol, "name", None), version_id=getattr(pol, "default_version", None),
                        partition=partition).statements


def _make_model(kind: str, ent: Any, identity: Sequence[Statement], boundary: Boundary, tags: Mapping[str, str],
                scp_chain: Optional[Tuple[Tuple[Statement, ...], ...]], gaps: set) -> PrincipalModel:
    identity = tuple(identity)
    path = str(getattr(ent, "path", "/") or "/")
    groups = tuple(sorted(getattr(ent, "groups", ()) or ())) if kind == "user" else ()
    return PrincipalModel(
        id=ent.arn, principal=_principal_for(kind, ent.arn, ent.name), identity=identity, boundary=boundary,
        groups=groups, tags=dict(tags), scp_chain=scp_chain,
        is_service_linked=kind == "role" and path.startswith(_SERVICE_LINKED_PATH),
        action_index=build_action_index(identity), gaps=frozenset(gaps))


def build_principal_set(iam: Any, *, account_id: Optional[str] = None, partition: Optional[str] = None,
                        org: Optional[OrgModel] = None) -> PrincipalSet:
    """Principal models from the IAM loader's ``IamData`` (duck-typed; see the module docstring)."""
    account = account_id or (iam.account_id() if callable(getattr(iam, "account_id", None)) else None)
    part = partition or _partition_of(e.arn for e in _all_entities(iam)) or "aws"
    pset = PrincipalSet(account_id=account, partition=part)
    policies: Mapping[str, Any] = getattr(iam, "policies", {}) or {}
    legacy = getattr(iam, "layout", "") == "legacy"
    scp_chain = org.scp_chain(account) if org is not None and account else None
    group_stmts: Dict[str, List[Statement]] = {}
    group_gaps: Dict[str, set] = {}
    for g in _sorted_entities(getattr(iam, "groups", {})):
        gaps = _entity_gaps(g)
        group_stmts[g.arn] = _own_statements(g, policies, part, g.arn, gaps)
        group_gaps[g.arn] = gaps
        own = _own_statements(g, policies, part, None, set())
        pset.models[g.arn] = _make_model("group", g, own, None, {}, scp_chain, gaps)
        _record_holders(pset, g.arn, getattr(g, "attached", ()))
    for kind, table in (("user", getattr(iam, "users", {})), ("role", getattr(iam, "roles", {}))):
        for ent in _sorted_entities(table):
            gaps = _entity_gaps(ent)
            stmts = _own_statements(ent, policies, part, None, gaps)
            for garn in sorted(getattr(ent, "groups", ()) or ()) if kind == "user" else ():
                stmts.extend(group_stmts.get(garn, ()))
                gaps |= group_gaps.get(garn, set())
                pset.group_members.setdefault(garn, []).append(ent.arn)
            tags = dict(getattr(ent, "tags", ()) or ())
            if legacy:
                gaps.add("iam:tags-unknown")
            pset.models[ent.arn] = _make_model(kind, ent, stmts, _boundary(ent, policies, part), tags, scp_chain,
                                               gaps)
            _record_holders(pset, ent.arn, getattr(ent, "attached", ()))
            if kind == "role":
                pset.trust[ent.arn] = parse_policy(getattr(ent, "trust_policy", None), layer="trust",
                                                   source_type="resource", policy_arn=ent.arn,
                                                   policy_name="trust", partition=part)
            else:
                pset.login_profiles[ent.arn] = _login_profile(getattr(ent, "record", {}) or {})
    _record_versions(pset, policies, part, legacy)
    pset.instance_profile_roles = _instance_profile_roles(getattr(iam, "instance_profiles", None))
    _listing_status(pset, getattr(iam, "gaps", {}) or {})
    return pset


def _all_entities(iam: Any) -> List[Any]:
    out: List[Any] = []
    for attr in ("users", "roles", "groups"):
        out.extend(_sorted_entities(getattr(iam, attr, {}) or {}))
    return out


def _sorted_entities(table: Any) -> List[Any]:
    if isinstance(table, Mapping):
        return [table[k] for k in sorted(table)]
    return list(table or ())


def _partition_of(arns: Iterable[str]) -> Optional[str]:
    for arn in arns:
        parsed = parse_arn(arn)
        if parsed is not None:
            return parsed.partition
    return None


def _record_holders(pset: PrincipalSet, holder: str, attached: Iterable[str]) -> None:
    for parn in attached or ():
        if source_type_for(parn) == "managed":
            pset.policy_holders.setdefault(parn, []).append(holder)


def _record_versions(pset: PrincipalSet, policies: Mapping[str, Any], partition: str, legacy: bool) -> None:
    for parn in sorted(pset.policy_holders):
        pol = policies.get(parn)
        versions = getattr(pol, "versions", None) if pol is not None else None
        if legacy or not isinstance(versions, Mapping) or not versions:
            pset.policy_versions[parn] = None
            continue
        default = getattr(pol, "default_version", None)
        pset.policy_versions[parn] = {
            str(vid): parse_policy(doc, layer="identity", source_type="managed", policy_arn=parn,
                                   policy_name=getattr(pol, "name", None), version_id=str(vid), partition=partition,
                                   is_default_version=str(vid) == default)
            for vid, doc in sorted(versions.items())}


def _login_profile(record: Mapping[str, Any]) -> Optional[bool]:
    value = record.get("HasLoginProfile")
    if isinstance(value, bool):
        return value
    if "LoginProfile" in record:
        return bool(record.get("LoginProfile"))
    return None


def _instance_profile_roles(profiles: Any) -> Optional[frozenset]:
    if not isinstance(profiles, list):
        return None
    out = set()
    for prof in profiles:
        for role in (prof.get("Roles") or ()) if isinstance(prof, Mapping) else ():
            if isinstance(role, Mapping) and isinstance(role.get("Arn"), str):
                out.add(role["Arn"])
    return frozenset(out)


def _listing_status(pset: PrincipalSet, loader_gaps: Mapping[str, str]) -> None:
    for kind, plural in (("user", "users"), ("role", "roles"), ("group", "groups")):
        if any(code.startswith(f"iam:{plural}-") for code in loader_gaps):
            pset.listing_complete[kind] = False
    for code, detail in sorted(loader_gaps.items()):
        pset.gaps[code] = detail


# ── legacy permission map (d13c215 view, extended) ───────────────────────────

def _legacy_entry(raw: Mapping[str, Any], source: str, source_type: str, idx: int) -> Dict[str, Any]:
    """One statement in the legacy shape; new keys only when the statement uses them."""
    entry: Dict[str, Any] = {
        "actions": _normalize_to_list(raw.get("Action", [])),
        "resources": _normalize_to_list(raw.get("Resource", [])),
        "source": source,
        "source_type": source_type,
    }
    if "NotAction" in raw:
        entry["not_actions"] = _normalize_to_list(raw.get("NotAction"))
    if "NotResource" in raw:
        entry["not_resources"] = _normalize_to_list(raw.get("NotResource"))
    if isinstance(raw.get("Condition"), Mapping) and raw.get("Condition"):
        entry["conditions"] = raw["Condition"]
    if isinstance(raw.get("Sid"), str) and raw.get("Sid"):
        entry["sid"] = raw["Sid"]
    if any(k in entry for k in ("not_actions", "not_resources", "conditions")) or raw.get("Effect") == "Deny":
        entry["statement_index"] = idx
    return entry


def _legacy_split(doc: Any, source: str, source_type: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """(allow entries, deny entries) of one policy document."""
    allows: List[Dict[str, Any]] = []
    denies: List[Dict[str, Any]] = []
    for idx, raw in iter_statements(doc):
        effect = raw.get("Effect")
        if effect == "Allow":
            allows.append(_legacy_entry(raw, source, source_type, idx))
        elif effect == "Deny":
            denies.append(_legacy_entry(raw, source, source_type, idx))
    return allows, denies


def _collect_policies(entry: Dict[str, Any], attached: Any, inline: Mapping[str, Any],
                      policy_docs: Mapping[str, Any]) -> None:
    """Fill ``attached_policies``, ``inline_policies``, ``effective_statements`` and ``deny_statements``."""
    denies: List[Dict[str, Any]] = []
    if isinstance(attached, list):
        for pol in attached:
            pol_name = pol.get('PolicyName', '') if isinstance(pol, Mapping) else ''
            entry["attached_policies"].append(pol_name)
            if pol_name in policy_docs:
                rec = policy_docs[pol_name]
                doc = rec.get('Document', {})
                allows, dens = _legacy_split(doc, pol_name, "managed")
                parn = pol.get('PolicyArn') or rec.get('PolicyArn')
                if isinstance(parn, str) and parn.startswith("arn:") and parn != pol_name:
                    for item in allows + dens:
                        item["policy_arn"] = parn
                entry["effective_statements"].extend(allows)
                denies.extend(dens)
    elif isinstance(attached, Mapping) and "Error" in attached:
        entry["attached_policies_error"] = str(attached.get("Error"))
    unreadable = []
    for pol_name, doc in (inline or {}).items():
        if isinstance(doc, dict) and 'Error' not in doc:
            entry["inline_policies"].append(pol_name)
            allows, dens = _legacy_split(doc, pol_name, "inline")
            entry["effective_statements"].extend(allows)
            denies.extend(dens)
        else:
            unreadable.append(pol_name)
    if unreadable:
        entry["inline_policy_errors"] = sorted(unreadable)
    if denies:
        entry["deny_statements"] = denies


def _legacy_boundary(record: Mapping[str, Any], policy_docs: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    pb = record.get("PermissionsBoundary")
    barn = pb.get("PermissionsBoundaryArn") if isinstance(pb, Mapping) else None
    if not isinstance(barn, str) or not barn:
        return None
    doc_rec = policy_docs.get(barn) or policy_docs.get(barn.rsplit("/", 1)[-1])
    if isinstance(doc_rec, Mapping) and doc_rec.get("PolicyArn") not in (None, barn):
        doc_rec = None
    if not isinstance(doc_rec, Mapping) or "Document" not in doc_rec:
        return {"arn": barn, "status": "missing"}
    allows, denies = _legacy_split(doc_rec.get("Document"), barn, "boundary")
    out: Dict[str, Any] = {"arn": barn, "status": "collected", "effective_statements": allows}
    if denies:
        out["deny_statements"] = denies
    return out


def _legacy_entity(record: Mapping[str, Any], attached: Any, inline: Mapping[str, Any],
                   policy_docs: Mapping[str, Any], *, groups: Optional[List[str]] = None) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"arn": record.get('Arn', ''), "attached_policies": [], "inline_policies": []}
    if groups is not None:
        entry["groups"] = groups
    entry["effective_statements"] = []
    _collect_policies(entry, attached, inline, policy_docs)
    boundary = _legacy_boundary(record, policy_docs)
    if boundary is not None:
        entry["permissions_boundary"] = boundary
    return entry


def _build_permission_map(users, roles, role_attached, user_attached, group_attached,
                          policy_docs, inline_policies, user_groups):
    """Build a map of entity → effective permissions (d13c215 signature; extended entries, module docstring)."""
    perm_map = {"users": {}, "roles": {}, "groups": {}}
    for user in users:
        username = user.get('UserName', '')
        if not username:
            continue
        gnames = []
        groups_for_user = user_groups.get(username, [])
        for g in groups_for_user if isinstance(groups_for_user, list) else []:
            gnames.append(g.get('GroupName', '') if isinstance(g, dict) else str(g))
        perm_map["users"][username] = _legacy_entity(
            user, user_attached.get(username, []), inline_policies.get("users", {}).get(username, {}), policy_docs,
            groups=gnames)
    for role in roles:
        rolename = role.get('RoleName', '')
        if not rolename:
            continue
        entry = _legacy_entity(role, role_attached.get(rolename, []),
                               inline_policies.get("roles", {}).get(rolename, {}), policy_docs)
        trust = load_document(role.get('AssumeRolePolicyDocument'))
        if trust is not None:
            entry["trust_policy"] = trust
        if role.get('Path') not in (None, "", "/"):
            entry["path"] = role['Path']
        perm_map["roles"][rolename] = entry
    for gname, attached_list in group_attached.items():
        perm_map["groups"][gname] = _legacy_entity(
            {}, attached_list, inline_policies.get("groups", {}).get(gname, {}), policy_docs)
        perm_map["groups"][gname].pop("arn", None)
    for gname in sorted(inline_policies.get("groups", {}) or {}):
        if gname not in perm_map["groups"]:
            perm_map["groups"][gname] = _legacy_entity({}, [], inline_policies["groups"][gname], policy_docs)
            perm_map["groups"][gname].pop("arn", None)
    _propagate_groups(perm_map)
    return perm_map


def _propagate_groups(perm_map: Dict[str, Any]) -> None:
    """Member users inherit their groups' Allow and Deny statements, each tagged ``via_group``."""
    for user_entry in perm_map["users"].values():
        for gname in user_entry.get("groups", []):
            group_entry = perm_map["groups"].get(gname)
            if not group_entry:
                continue
            for key in ("effective_statements", "deny_statements"):
                for stmt in group_entry.get(key, []):
                    inherited = dict(stmt)
                    inherited["via_group"] = gname
                    user_entry.setdefault(key, []).append(inherited)


# ── principal models from the legacy view ────────────────────────────────────

def _raw_statement(entry: Mapping[str, Any], effect: str) -> Dict[str, Any]:
    raw: Dict[str, Any] = {"Effect": effect}
    if "not_actions" in entry:
        raw["NotAction"] = list(entry["not_actions"])
    else:
        raw["Action"] = list(entry.get("actions", []))
    if "not_resources" in entry:
        raw["NotResource"] = list(entry["not_resources"])
    else:
        raw["Resource"] = list(entry.get("resources", []))
    if entry.get("conditions"):
        raw["Condition"] = entry["conditions"]
    if entry.get("sid"):
        raw["Sid"] = entry["sid"]
    return raw


def _entry_statements(entry: Mapping[str, Any], partition: str, group_arn: Mapping[str, str],
                      layer: str = "identity") -> List[Statement]:
    """Statements of a legacy entity entry (Allow then Deny), with provenance rebuilt from the entry."""
    out: List[Statement] = []
    for key, effect in (("effective_statements", "Allow"), ("deny_statements", "Deny")):
        for i, item in enumerate(entry.get(key, []) or []):
            if not isinstance(item, Mapping):
                continue
            source = str(item.get("source") or "unknown")
            stype = item.get("source_type") or "inline"
            parn = item.get("policy_arn") or (source if source.startswith("arn:") else None)
            via = item.get("via_group")
            doc = {"Statement": [_raw_statement(item, effect)]}
            parsed = parse_policy(doc, layer=layer, source_type=_legacy_source_type(stype, parn),
                                  policy_arn=parn, policy_name=None if parn == source else source,
                                  via_group=group_arn.get(via, via) if via else None, partition=partition)
            for stmt in parsed.statements:
                idx = item.get("statement_index", i)
                out.append(_with_index(stmt, idx if isinstance(idx, int) else i))
    return out


def _with_index(stmt: Statement, idx: int) -> Statement:
    from dataclasses import replace
    return replace(stmt, source=replace(stmt.source, statement_index=idx, sid=stmt.source.sid))


def _legacy_source_type(stype: str, policy_arn: Optional[str]) -> Any:
    if stype == "managed":
        return source_type_for(policy_arn) if policy_arn else "managed"
    return stype if stype in ("inline", "boundary") else "inline"


def _legacy_boundary_layer(entry: Mapping[str, Any], partition: str) -> Boundary:
    pb = entry.get("permissions_boundary")
    if not isinstance(pb, Mapping):
        return None
    if pb.get("status") != "collected":
        return "missing"
    return tuple(_entry_statements(pb, partition, {}, layer="boundary"))


def models_from_permission_map(permission_map: Mapping[str, Any], *, account_id: Optional[str] = None,
                               partition: Optional[str] = None) -> PrincipalSet:
    """Rebuild a :class:`PrincipalSet` from a (extended) legacy permission map (legacy rule entry points)."""
    users = permission_map.get("users", {}) or {}
    roles = permission_map.get("roles", {}) or {}
    groups = permission_map.get("groups", {}) or {}
    arns = [e.get("arn", "") for e in list(users.values()) + list(roles.values()) if isinstance(e, Mapping)]
    part = partition or _partition_of(a for a in arns if a) or "aws"
    account = account_id or next((p.account for p in (parse_arn(a) for a in arns if a) if p and p.account), None)
    pset = PrincipalSet(account_id=account, partition=part)
    group_arn = {g: f"arn:{part}:iam::{account or '000000000000'}:group/{g}" for g in sorted(groups)}
    _models_for_groups(pset, groups, group_arn, part)
    for kind, table in (("user", users), ("role", roles)):
        for name in sorted(table):
            entry = table[name]
            arn = entry.get("arn") if isinstance(entry, Mapping) else None
            if not isinstance(arn, str) or not arn:
                continue
            stmts = _entry_statements(entry, part, group_arn)
            member_of = [group_arn.get(g, g) for g in entry.get("groups", []) or []] if kind == "user" else []
            for garn in member_of:
                pset.group_members.setdefault(garn, []).append(arn)
            ent = _LegacyEntity(arn, name, str(entry.get("path") or "/"), member_of)
            pset.models[arn] = _make_model(kind, ent, stmts, _legacy_boundary_layer(entry, part), {}, None,
                                           _legacy_gaps(entry, groups, entry.get("groups", []) or []))
            _legacy_holders(pset, arn, entry)
            if kind == "role" and entry.get("trust_policy") is not None:
                pset.trust[arn] = parse_policy(entry["trust_policy"], layer="trust", source_type="resource",
                                               policy_arn=arn, policy_name="trust", partition=part)
            if kind == "user":
                pset.login_profiles[arn] = None
    for parn in sorted(pset.policy_holders):
        pset.policy_versions[parn] = None
    return pset


def _legacy_gaps(entry: Mapping[str, Any], groups: Mapping[str, Any] = None, member_of: Sequence[str] = ()) -> set:
    """Principal gaps visible in a legacy entry (and in the entries of its groups)."""
    gaps = {"iam:tags-unknown"}
    for e in [entry] + [groups.get(g) for g in member_of if groups and isinstance(groups.get(g), Mapping)]:
        if e.get("attached_policies_error"):
            gaps.add("iam:attached-unknown")
        if e.get("inline_policy_errors"):
            gaps.add("iam:inline-unknown")
    return gaps


@dataclass
class _LegacyEntity:
    arn: str
    name: str
    path: str
    groups: List[str]


def _models_for_groups(pset: PrincipalSet, groups: Mapping[str, Any], group_arn: Mapping[str, str],
                       partition: str) -> None:
    for gname in sorted(groups):
        entry = groups[gname]
        if not isinstance(entry, Mapping):
            continue
        garn = group_arn[gname]
        ent = _LegacyEntity(garn, gname, "/", [])
        pset.models[garn] = _make_model("group", ent, _entry_statements(entry, partition, group_arn), None, {},
                                        None, _legacy_gaps(entry))
        _legacy_holders(pset, garn, entry)


def _legacy_holders(pset: PrincipalSet, holder: str, entry: Mapping[str, Any]) -> None:
    for item in entry.get("effective_statements", []) or []:
        if not isinstance(item, Mapping) or item.get("via_group") or item.get("source_type") != "managed":
            continue
        parn = item.get("policy_arn") or item.get("source")
        if isinstance(parn, str) and parn and source_type_for(parn) == "managed":
            holders = pset.policy_holders.setdefault(parn if parn.startswith("arn:") else
                                                     f"arn:{pset.partition}:iam::{pset.account_id}:policy/{parn}",
                                                     [])
            if holder not in holders:
                holders.append(holder)


# ── pipeline registration (engine-api.md §5, phase PRINCIPALS) ───────────────

#: Coverage facet of the IAM authorization details (the pipeline skips the phase when it was not collected).
IAM_FACET = "iam.authorization_details"

def _loader_data(value: Any) -> Any:
    """``ctx.data[domain]`` may hold the loader's data or its ``LoadResult``."""
    return value.data if hasattr(value, "data") and hasattr(value, "status") else value


def build_evaluator(ctx: Any) -> Tuple[PrincipalSet, Any]:
    """Principal set and :class:`~aws_enumerator.engine.policy.evaluator.Evaluator` for an analysis context."""
    from aws_enumerator.engine.policy.evaluator import Evaluator

    from aws_enumerator.engine.model import AnalyzerSkipped

    data = getattr(ctx, "data", {}) or {}
    iam = _loader_data(data.get("iam"))
    if iam is None or getattr(iam, "layout", "") == "missing":
        raise AnalyzerSkipped(IAM_FACET, reason="IAM data was not collected")
    org_data = _loader_data(data.get("org"))
    org = OrgModel.from_org_data(org_data, account_id=ctx.account_id, partition=ctx.partition) \
        if org_data is not None else None
    pset = build_principal_set(iam, account_id=ctx.account_id, partition=ctx.partition, org=org)
    return pset, Evaluator(ctx, pset.models, pset.resource_index(), org)


def _run(ctx: Any, builder: Any) -> None:
    """Phase PRINCIPALS: build the models and hand the evaluator to the context (``ctx.set_evaluator``)."""
    pset, evaluator = build_evaluator(ctx)
    ctx.shared["iam.principal_set"] = pset
    ctx.set_evaluator(evaluator, pset.models)


def _analyzers() -> Tuple[Any, ...]:
    from aws_enumerator.engine.model import AnalyzerSpec, Phase
    return (AnalyzerSpec("principals", Phase.PRINCIPALS, _run, inputs=(IAM_FACET,)),)


ANALYZERS = _analyzers()


__all__ = [
    "ANALYZERS", "PrincipalSet", "build_evaluator", "UNKNOWN_POLICY_GAPS", "build_action_index", "build_principal_set",
    "models_from_permission_map", "_build_permission_map", "_extract_statements",
]
