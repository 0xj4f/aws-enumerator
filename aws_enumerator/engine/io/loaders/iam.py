"""IAM loader (``global/iam/``) for both collector layouts (engine.md §1.1, F-013, F-109, F-110, F-053, F-111).

* **legacy** (d13c215 per-entity collector): ``policy_documents/<name>_<version>.json`` with only the
  default version, per-entity ``*_attached_policies.json`` maps that may hold ``{"Error": ...}`` stubs,
  inline policies per entity, ``users.json`` with ``*Error`` sibling keys.
* **gaad** (collectors-cli.md §5.1): ``policy_documents/<slug>-<sha12(PolicyArn)>.json`` with
  ``PolicyType`` and **every** version, ``EntityArn`` in inline/boundary files, ``credential_report.json``
  and ``identity_providers.json``.

Both produce one :class:`IamData`, **keyed by ARN**: a customer policy named like an AWS-managed policy
keeps its own document (F-013), a name collision becomes an ``IAM-POLICY-COLLISION-001`` input instead of
an order-dependent overwrite, and an ``{"Error"}`` stub becomes a status (``attached_status``,
``inline_status``), never data (F-006, F-111).

Inline policies that could not be read are **unknown, not absent** (F-111). Besides the d13c215 ``{"Error"}``
stubs, the v2 collector reports them in two places, and both set ``inline_status`` to something other than
``complete`` and add the entity gap ``iam:inline-unknown`` (which makes the evaluator's decisions for that
principal conditional, ``policy.evaluator.UNKNOWN_POLICY_GAPS``):

* a failed ``iam:List{User,Role,Group}Policies`` call is an ``item_errors`` entry of ``iam/_coverage.json``
  whose ``resource`` is the entity ARN, and **no** inline file is written (status ``denied`` / ``throttled`` /
  ``error``; a call skipped by an open circuit breaker counts as the failure that opened it). When
  ``item_errors`` was truncated and the listing failed for some entities, every entity of that kind without an
  inline file is unknown too (status ``partial``, run gap ``iam:item-errors-truncated``);
* a failed ``iam:Get{User,Role,Group}Policy`` call is a ``CollectionErrors`` entry of
  ``inline_policies/<kind>/<name>.json``; the documents that were read are kept (status ``partial``).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from aws_enumerator.engine.io.coverage import COVERAGE_FILE, worst
from aws_enumerator.engine.io.fs import (
    error_code_from_stub, is_error_stub, ls_sorted, read_json, read_list, read_map, stub_status,
)
from aws_enumerator.engine.io.loaders import LoadResult

log = logging.getLogger(__name__)

KINDS: Tuple[str, ...] = ("user", "role", "group")
_PLURAL = {"user": "users", "role": "roles", "group": "groups"}
_NAME_KEY = {"user": "UserName", "role": "RoleName", "group": "GroupName"}

#: The v2 collector's per-entity inline-policy calls (collectors/iam.py ``_pe_attached_and_inline``, F-111).
INLINE_LIST_API: Dict[str, str] = {"user": "iam:ListUserPolicies", "role": "iam:ListRolePolicies",
                                   "group": "iam:ListGroupPolicies"}
INLINE_GET_API: Dict[str, str] = {"user": "iam:GetUserPolicy", "role": "iam:GetRolePolicy",
                                  "group": "iam:GetGroupPolicy"}
INLINE_UNKNOWN = "iam:inline-unknown"
_FAILURE_STATUSES = ("denied", "throttled", "error")


# ── data model ────────────────────────────────────────────────────────────────

@dataclass
class ManagedPolicy:
    """A managed policy keyed by ARN with every collected version (F-110)."""

    arn: str
    name: str
    aws_managed: bool
    default_version: Optional[str]
    versions: Dict[str, Any] = field(default_factory=dict)       # version id -> document
    document_status: str = "complete"                            # "error"/"denied" when not readable
    error_code: Optional[str] = None

    @property
    def document(self) -> Any:
        """The default version's document (``None`` when not collected)."""
        if self.default_version and self.default_version in self.versions:
            return self.versions[self.default_version]
        return next(iter(self.versions.values()), None) if len(self.versions) == 1 else None


@dataclass
class IamEntity:
    """One user, role or group, keyed by its ARN exactly as collected (the path is part of it)."""

    kind: str
    arn: str
    name: str
    path: str
    record: Dict[str, Any]
    attached: List[str] = field(default_factory=list)            # policy ARNs
    attached_status: str = "complete"
    attached_error: Optional[str] = None
    inline: Dict[str, Any] = field(default_factory=dict)          # policy name -> document
    inline_status: str = "complete"
    boundary_arn: Optional[str] = None
    groups: List[str] = field(default_factory=list)              # users: group ARNs
    groups_status: str = "complete"
    tags: List[Tuple[str, str]] = field(default_factory=list)
    has_credentials: Optional[bool] = None                       # users: None = unknown
    trust_policy: Any = None                                     # roles: parsed document
    gaps: Set[str] = field(default_factory=set)


@dataclass
class IamData:
    """Everything the engine reads from ``iam/``."""

    layout: str                                                  # "legacy" | "gaad" | "missing"
    users: Dict[str, IamEntity] = field(default_factory=dict)
    roles: Dict[str, IamEntity] = field(default_factory=dict)
    groups: Dict[str, IamEntity] = field(default_factory=dict)
    policies: Dict[str, ManagedPolicy] = field(default_factory=dict)
    instance_profiles: List[Dict[str, Any]] = field(default_factory=list)
    instance_profiles_status: str = "complete"
    password_policy: Optional[Dict[str, Any]] = None
    account_summary: Optional[Dict[str, Any]] = None
    credential_report: Optional[Dict[str, Any]] = None
    identity_providers: Dict[str, List[Dict[str, Any]]] = field(default_factory=lambda: {"oidc": [], "saml": []})
    name_collisions: Dict[str, List[str]] = field(default_factory=dict)   # policy name -> ARNs
    gaps: Dict[str, str] = field(default_factory=dict)

    def entities(self, kind: Optional[str] = None) -> List[IamEntity]:
        tables = [self.users, self.roles, self.groups] if kind is None else [getattr(self, _PLURAL[kind])]
        return [t[arn] for t in tables for arn in sorted(t)]

    def by_name(self, kind: str, name: str) -> Optional[IamEntity]:
        for e in getattr(self, _PLURAL[kind]).values():
            if e.name == name:
                return e
        return None

    def account_id(self) -> Optional[str]:
        for e in self.entities():
            parts = e.arn.split(":")
            if len(parts) > 4 and parts[4].isdigit() and len(parts[4]) == 12:
                return parts[4]
        return None


# ── loading ───────────────────────────────────────────────────────────────────

def _layout(iam_dir: Path) -> str:
    if not iam_dir.is_dir():
        return "missing"
    if (iam_dir / "credential_report.json").exists() or (iam_dir / "identity_providers.json").exists():
        return "gaad"
    for name in ls_sorted(iam_dir / "policy_documents"):
        res = read_json(iam_dir / "policy_documents" / name)
        if res.ok and isinstance(res.data, Mapping) and ("Versions" in res.data or "PolicyType" in res.data):
            return "gaad"
    return "legacy"


def _parse_doc(doc: Any) -> Any:
    if isinstance(doc, str):
        try:
            return json.loads(doc)
        except ValueError:
            return None
    return doc


def _load_policies(iam_dir: Path, data: IamData) -> None:
    by_name: Dict[str, Set[str]] = {}
    for fname in ls_sorted(iam_dir / "policy_documents"):
        if not fname.endswith(".json"):
            continue
        raw = read_json(iam_dir / "policy_documents" / fname)
        rec = raw.data if raw.ok and isinstance(raw.data, Mapping) else None
        if rec is None:
            continue
        arn, name = rec.get("PolicyArn"), rec.get("PolicyName")
        if not isinstance(arn, str) or not arn.startswith("arn:"):
            data.gaps["iam:policy-arn-missing"] = "a policy document file has no PolicyArn"
            continue
        pol = data.policies.get(arn) or ManagedPolicy(
            arn, str(name or arn.rsplit("/", 1)[-1]), ":iam::aws:policy/" in arn,
            rec.get("DefaultVersionId") or rec.get("VersionId"))
        data.policies[arn] = pol
        by_name.setdefault(pol.name, set()).add(arn)
        if "Error" in rec and "Document" not in rec:
            pol.error_code = error_code_from_stub(rec.get("Error"))
            pol.document_status = stub_status(pol.error_code)
            continue
        _add_versions(pol, rec)
    data.name_collisions = {n: sorted(a) for n, a in sorted(by_name.items()) if len(a) > 1}


def _add_versions(pol: ManagedPolicy, rec: Mapping[str, Any]) -> None:
    for v in rec.get("Versions") or ():
        if isinstance(v, Mapping) and v.get("VersionId"):
            pol.versions[str(v["VersionId"])] = _parse_doc(v.get("Document"))
            if v.get("IsDefaultVersion"):
                pol.default_version = str(v["VersionId"])
    vid = rec.get("VersionId") or rec.get("DefaultVersionId") or "default"
    if "Document" in rec:
        pol.versions.setdefault(str(vid), _parse_doc(rec.get("Document")))
        if rec.get("DefaultVersionId") or pol.default_version is None:
            pol.default_version = str(rec.get("DefaultVersionId") or vid)


def _tags(record: Mapping[str, Any]) -> List[Tuple[str, str]]:
    out = []
    for t in record.get("Tags") or ():
        if isinstance(t, Mapping) and "Key" in t:
            out.append((str(t["Key"]), "" if t.get("Value") is None else str(t["Value"])))
    return sorted(out)


def _boundary_arn(record: Mapping[str, Any]) -> Optional[str]:
    pb = record.get("PermissionsBoundary")
    if isinstance(pb, Mapping):
        arn = pb.get("PermissionsBoundaryArn")
        return arn if isinstance(arn, str) else None
    return None


def _entities(iam_dir: Path, kind: str, data: IamData) -> Dict[str, IamEntity]:
    items, res = read_list(iam_dir / f"{_PLURAL[kind]}.json")
    if not res.ok:
        data.gaps[f"iam:{_PLURAL[kind]}-{res.status}"] = f"{_PLURAL[kind]}.json is {res.status}"
    out: Dict[str, IamEntity] = {}
    for rec in items:
        if not isinstance(rec, Mapping) or not isinstance(rec.get("Arn"), str) or not rec.get(_NAME_KEY[kind]):
            continue
        ent = IamEntity(kind, rec["Arn"], str(rec[_NAME_KEY[kind]]), str(rec.get("Path") or "/"), dict(rec),
                        tags=_tags(rec), boundary_arn=_boundary_arn(rec))
        if kind == "role":
            ent.trust_policy = _parse_doc(rec.get("AssumeRolePolicyDocument"))
        out[ent.arn] = ent
    return out


def _resolve_attachment(entry: Any, data: IamData) -> Optional[str]:
    if not isinstance(entry, Mapping):
        return None
    arn, name = entry.get("PolicyArn"), entry.get("PolicyName")
    if isinstance(arn, str) and arn.startswith("arn:"):
        return arn
    matches = sorted(a for a, p in data.policies.items() if p.name == name)
    return matches[0] if len(matches) == 1 else None


def _apply_attachments(iam_dir: Path, kind: str, data: IamData) -> None:
    table, res = read_map(iam_dir / f"{kind}_attached_policies.json")
    for ent in getattr(data, _PLURAL[kind]).values():
        value = table.get(ent.name)
        if not res.ok:
            ent.attached_status = stub_status(res.error_code) if res.status == "error-stub" else "not-collected"
            ent.attached_error = res.error_code
        elif is_error_stub(value):
            ent.attached_error = error_code_from_stub(value)
            ent.attached_status = stub_status(ent.attached_error)
        elif isinstance(value, list):
            ent.attached = sorted({a for a in (_resolve_attachment(v, data) for v in value) if a})
        else:
            # d13c215 wrote every entity, GAAD omits an entity whose attachments are unknown (item_errors)
            ent.attached_status = "not-collected"


def _inline_unknown(ent: IamEntity, status: str) -> None:
    """Mark ``ent``'s inline policies as not (fully) readable: the least complete status wins (F-111)."""
    ent.inline_status = worst((ent.inline_status, status))
    ent.gaps.add(INLINE_UNKNOWN)


def _failure_status(status: Any, error_code: Any) -> str:
    """Facet status of a failed collector call; a circuit-breaker skip is the failure that opened it."""
    from aws_enumerator.coverage import CIRCUIT_OPEN_DENIED, CIRCUIT_OPEN_THROTTLED  # lazy, like stub_status

    if status in _FAILURE_STATUSES:
        return str(status)
    if status == "skipped":
        return {CIRCUIT_OPEN_DENIED: "denied", CIRCUIT_OPEN_THROTTLED: "throttled"}.get(str(error_code), "skipped")
    return "error"


def _apply_inline(iam_dir: Path, kind: str, data: IamData) -> Set[str]:
    """Read ``inline_policies/<kind>/``; returns the ARNs of the entities that have an inline file."""
    kdir = iam_dir / "inline_policies" / _PLURAL[kind]
    seen: Set[str] = set()
    for fname in ls_sorted(kdir):
        if not fname.endswith(".json"):
            continue
        res = read_json(kdir / fname)
        rec = res.data if res.ok and isinstance(res.data, Mapping) else None
        name = fname[: -len(".json")]
        arn = rec.get("EntityArn") if rec else None
        ent = getattr(data, _PLURAL[kind]).get(arn) if isinstance(arn, str) else data.by_name(kind, name)
        if ent is None:
            continue
        seen.add(ent.arn)
        if rec is None:
            _inline_unknown(ent, stub_status(res.error_code) if res.status == "error-stub" else "error")
            continue
        for pname, doc in sorted((rec.get("InlinePolicies") or {}).items()):
            if is_error_stub(doc):
                _inline_unknown(ent, "partial")
            else:
                ent.inline[str(pname)] = _parse_doc(doc)
        _apply_inline_errors(ent, kind, rec.get("CollectionErrors"))
    return seen


def _apply_inline_errors(ent: IamEntity, kind: str, errors: Any) -> None:
    """``CollectionErrors`` of an inline file: a failed ``Get*Policy`` leaves the read documents, unknown rest."""
    if not isinstance(errors, list):
        return
    for err in errors:
        if not isinstance(err, Mapping) or err.get("status") == "ok":
            continue
        if err.get("api") == INLINE_GET_API[kind]:
            _inline_unknown(ent, "partial")
        elif err.get("api") == INLINE_LIST_API[kind]:
            _inline_unknown(ent, _failure_status(err.get("status"), err.get("error_code")))


def _apply_inline_coverage(iam_dir: Path, data: IamData, with_file: Mapping[str, Set[str]]) -> None:
    """Failed ``List*Policies`` calls of ``_coverage.json``: the entity has no inline file and is unknown."""
    res = read_json(iam_dir / COVERAGE_FILE)
    doc = res.data if res.ok and isinstance(res.data, Mapping) else None
    if doc is None:
        return
    failed: Dict[Tuple[str, str], str] = {}
    for err in doc.get("item_errors") or ():
        if isinstance(err, Mapping) and err.get("api") in INLINE_LIST_API.values() and err.get("status") != "ok":
            key = (str(err["api"]), str(err.get("resource")))
            failed[key] = worst((failed.get(key, "complete"), _failure_status(err.get("status"),
                                                                              err.get("error_code"))))
    truncated = doc.get("item_errors_truncated") is True
    calls = [c for c in doc.get("calls") or () if isinstance(c, Mapping)]
    for kind in KINDS:
        api = INLINE_LIST_API[kind]
        listing_failed = truncated and any(c.get("api") == api and c.get("status") != "ok" for c in calls)
        for ent in data.entities(kind):
            status = failed.get((api, ent.arn))
            if status is not None:
                _inline_unknown(ent, status)
            elif listing_failed and ent.record and ent.arn not in with_file.get(kind, ()):
                _inline_unknown(ent, "partial")
        if listing_failed:
            data.gaps["iam:item-errors-truncated"] = (
                "_coverage.json item_errors was truncated while some inline-policy listings failed: the inline "
                "policies of entities without an inline file are unknown")


def _apply_memberships(iam_dir: Path, data: IamData) -> None:
    table, res = read_map(iam_dir / "user_group_memberships.json")
    groups_by_name = {g.name: g.arn for g in data.groups.values()}
    for user in data.users.values():
        value = table.get(user.name)
        if is_error_stub(value) or (not res.ok and res.status != "missing"):
            user.groups_status = stub_status(error_code_from_stub(value)) if value else "error"
            user.gaps.add("iam:groups-unknown")
            continue
        for g in value or ():
            gname = g.get("GroupName") if isinstance(g, Mapping) else str(g)
            garn = g.get("Arn") if isinstance(g, Mapping) else None
            garn = garn if isinstance(garn, str) else groups_by_name.get(str(gname))
            if garn is None and gname:
                garn = user.arn.split(":user/")[0] + f":group/{gname}"
            if garn:
                user.groups.append(garn)
        user.groups = sorted(set(user.groups))


def _credentials(user: IamEntity, report_rows: Mapping[str, Mapping[str, Any]]) -> Optional[bool]:
    """True when the user has an active access key or a console password; ``None`` when unknown."""
    row = report_rows.get(user.arn)
    if row is not None:
        flags = (row.get("password_enabled"), row.get("access_key_1_active"), row.get("access_key_2_active"))
        return any(str(f).lower() == "true" for f in flags)
    rec = user.record
    keys, login = rec.get("AccessKeys"), rec.get("HasLoginProfile")
    if "AccessKeysError" in rec or "LoginProfileError" in rec or keys is None or login is None:
        known_true = bool(login) or any(isinstance(k, Mapping) and k.get("Status") == "Active" for k in keys or ())
        return True if known_true else None
    return bool(login) or any(isinstance(k, Mapping) and k.get("Status") == "Active" for k in keys)


def _load_extras(iam_dir: Path, data: IamData) -> None:
    profiles, res = read_list(iam_dir / "instance_profiles.json")
    data.instance_profiles = [p for p in profiles if isinstance(p, Mapping)]
    if not res.ok:
        data.instance_profiles_status = stub_status(res.error_code) if res.status == "error-stub" else res.status
    pw = read_json(iam_dir / "account_password_policy.json")
    data.password_policy = pw.data if pw.ok and isinstance(pw.data, Mapping) else None
    summ = read_json(iam_dir / "account_summary.json")
    data.account_summary = summ.data if summ.ok and isinstance(summ.data, Mapping) else None
    cred = read_json(iam_dir / "credential_report.json")
    data.credential_report = cred.data if cred.ok and isinstance(cred.data, Mapping) else None
    idps = read_json(iam_dir / "identity_providers.json")
    if idps.ok and isinstance(idps.data, Mapping):
        data.identity_providers = {k: [p for p in idps.data.get(k) or () if isinstance(p, Mapping)]
                                   for k in ("oidc", "saml")}
    for fname in ls_sorted(iam_dir / "permission_boundaries"):
        rec = read_json(iam_dir / "permission_boundaries" / fname)
        if rec.ok and isinstance(rec.data, Mapping):
            _apply_boundary_file(rec.data, fname, data)


def _apply_boundary_file(rec: Mapping[str, Any], fname: str, data: IamData) -> None:
    arn = _boundary_arn(rec)
    if arn is None:
        return
    entity_arn = rec.get("EntityArn")
    kind = str(rec.get("EntityType") or "").lower()
    if isinstance(entity_arn, str):
        ent = data.users.get(entity_arn) or data.roles.get(entity_arn)
    else:
        name = str(rec.get("EntityName") or fname[: -len(".json")])
        ent = data.by_name(kind, name) if kind in ("user", "role") else None
    if ent is not None and ent.boundary_arn is None:
        ent.boundary_arn = arn


def load_iam(global_dir: "Path | str") -> IamData:
    """Read ``<global_dir>/iam`` in whichever layout it has (module docstring)."""
    iam_dir = Path(global_dir) / "iam"
    data = IamData(_layout(iam_dir))
    if data.layout == "missing":
        return data
    _load_policies(iam_dir, data)
    data.users = _entities(iam_dir, "user", data)
    data.roles = _entities(iam_dir, "role", data)
    data.groups = _entities(iam_dir, "group", data)
    _apply_memberships(iam_dir, data)
    for user in data.users.values():
        for garn in user.groups:
            if garn not in data.groups:
                data.groups[garn] = IamEntity("group", garn, garn.rsplit("/", 1)[-1], "/", {},
                                              attached_status="not-collected", inline_status="not-collected")
    with_file: Dict[str, Set[str]] = {}
    for kind in KINDS:
        _apply_attachments(iam_dir, kind, data)
        with_file[kind] = _apply_inline(iam_dir, kind, data)
    _apply_inline_coverage(iam_dir, data, with_file)
    _load_extras(iam_dir, data)
    rows = {}
    if data.credential_report:
        rows = {r.get("arn"): r for r in data.credential_report.get("Rows") or () if isinstance(r, Mapping)}
    for user in data.users.values():
        user.has_credentials = _credentials(user, rows)
    if data.layout == "legacy":
        data.gaps["iam:legacy-layout"] = "IAM was collected with the per-entity (d13c215) layout: no policy " \
                                         "versions, no identity providers, boundaries and tags may be missing"
    return data


def load(ctx: Any) -> LoadResult:
    """Pipeline entry point: ``ctx.data["iam"]`` is an :class:`IamData`."""
    data = load_iam(ctx.global_dir)
    status = "missing" if data.layout == "missing" else "ok"
    if any(e.attached_status != "complete" or e.inline_status != "complete" or e.gaps for e in data.entities()):
        status = "partial" if status == "ok" else status
    return LoadResult(data, status, dict(data.gaps), files=sum(1 for _ in Path(ctx.global_dir, "iam").rglob("*.json"))
                      if data.layout != "missing" else 0)


# ── legacy permission-map inputs (ARN-keyed, F-013) ───────────────────────────

def legacy_permission_inputs(data: IamData) -> Tuple[Any, ...]:
    """Arguments for the d13c215 ``_build_permission_map`` with policy documents keyed **by ARN**.

    The legacy builder resolves attachments by ``PolicyName``; passing the ARN in that field makes it
    resolve the right document even when a customer policy shares an AWS-managed policy's name (F-013).
    :func:`restore_policy_names` turns the ARNs in its output back into names for the legacy file.
    """
    docs = {arn: {"PolicyName": arn, "PolicyArn": arn, "Document": p.document}
            for arn, p in data.policies.items() if p.document is not None}

    def attached(kind: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for e in data.entities(kind):
            if e.attached_status in ("denied", "error", "throttled"):
                out[e.name] = {"Error": e.attached_error or e.attached_status}
            else:
                out[e.name] = [{"PolicyName": a, "PolicyArn": a} for a in e.attached]
        return out

    inline = {_PLURAL[k]: {e.name: dict(e.inline) for e in data.entities(k)} for k in KINDS}
    users = [dict(e.record) for e in data.entities("user")]
    roles = [dict(e.record) for e in data.entities("role")]
    groups_by_arn = {g.arn: g.name for g in data.groups.values()}
    memberships = {u.name: [{"GroupName": groups_by_arn.get(g, g.rsplit("/", 1)[-1])} for g in u.groups]
                   for u in data.entities("user")}
    return users, roles, attached("role"), attached("user"), attached("group"), docs, inline, memberships


def restore_policy_names(permission_map: Dict[str, Any], data: IamData) -> Dict[str, Any]:
    """Replace policy ARNs in a legacy permission map by names; keep the ARN as ``policy_arn``."""
    names = {arn: p.name for arn, p in data.policies.items()}
    for table in permission_map.values():
        if not isinstance(table, dict):
            continue
        for entry in table.values():
            arns = list(entry.get("attached_policies", []))
            entry["attached_policies"] = [names.get(a, a) for a in arns]
            entry["attached_policy_arns"] = arns
            for stmt in entry.get("effective_statements", []):
                src = stmt.get("source")
                if stmt.get("source_type") == "managed" and src in names:
                    stmt["policy_arn"] = src
                    stmt["source"] = names[src]
    return permission_map


__all__ = [
    "IamData", "IamEntity", "KINDS", "ManagedPolicy", "legacy_permission_inputs", "load", "load_iam",
    "restore_policy_names",
]
