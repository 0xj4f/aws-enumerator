"""IAM identities, policies, federation providers and credential hygiene (global).

**Entities** come from one paginated ``GetAccountAuthorizationDetails`` (GAAD, all five filters; F-109):
it returns boundaries, tags, ``RoleLastUsed``, inline and attached policies and every version of each
local managed policy (F-052, F-110), with no per-entity calls. ``ListRoles`` is merged in for
``Description`` and ``MaxSessionDuration``, which GAAD does not return. Policy documents that entities
reference (attached or as a boundary) but GAAD did not return are fetched with ``GetPolicy`` +
``GetPolicyVersion``. When GAAD fails (or with ``--iam-mode per-entity``) the per-entity fallback runs
the list calls with paginators plus ``GetUser`` / ``GetRole`` (boundary, tags, last use) and
``ListPolicyVersions`` + ``GetPolicyVersion`` for every version; each phase is its own section (F-053)
and a failed per-entity call is an ``item_errors`` entry (F-111). ``--iam-gaad-file`` imports an
exported GAAD JSON instead of calling the API.

**Credentials** come from the credential report (``GenerateCredentialReport``, polled, then
``GetCredentialReport``; F-148) instead of per-user ``GetLoginProfile`` / ``ListMFADevices`` calls and
their NoSuchEntity bursts (F-167), plus ``ListVirtualMFADevices``. Per-user ``ListAccessKeys``,
``ListSSHPublicKeys``, ``ListServiceSpecificCredentials`` and ``ListSigningCertificates`` run unless
``--no-iam-user-details`` (F-110). ``ListMFADevices`` is called only for a user whose report row says
MFA is active while no virtual device is assigned to it (a hardware or U2F device). Only when the report
is disabled or unavailable does each user get ``GetLoginProfile`` + ``ListMFADevices``.
**Federation**: OIDC and SAML providers (F-110).

Options (``ctx.option``): ``iam_mode`` (``gaad`` | ``per-entity``), ``iam_gaad_file`` (path),
``credential_report`` / ``no_credential_report``, ``iam_user_details`` / ``no_iam_user_details``.

Output (``global/iam/``); ``null`` = unknown, ``CollectionErrors`` only on items with a failure:

``users.json``
    list, sorted by ``UserName``::

        {UserName, UserId, Arn, Path, CreateDate, PasswordLastUsed, PasswordLastChanged, Tags,
         PermissionsBoundary: {PermissionsBoundaryType, PermissionsBoundaryArn} | null,
         HasLoginProfile, MFAActive, MFADevices: [{SerialNumber, Source}] | null,
         AccessKeys: [{AccessKeyId | null, Status, LastRotated, LastUsedDate, LastUsedService,
                       LastUsedRegion}] | null,
         SSHPublicKeys: [{SSHPublicKeyId, Status, UploadDate}] | null,
         ServiceSpecificCredentials: [{ServiceName, ServiceSpecificCredentialId, Status, CreateDate}] | null,
         SigningCertificates: [{CertificateId, Status, UploadDate}] | null, CollectionErrors?}

    ``MFADevices[].Source`` is ``virtual``, ``u2f`` or ``hardware``.
``roles.json``
    list, sorted by ``RoleName``: ``{Path, RoleName, RoleId, Arn, CreateDate, AssumeRolePolicyDocument,
    Description, MaxSessionDuration, PermissionsBoundary, Tags, RoleLastUsed, InstanceProfileArns,
    CollectionErrors?}``.
``groups.json``
    list, sorted by ``GroupName``: ``{Path, GroupName, GroupId, Arn, CreateDate}``.
``policies.json``
    list, sorted by ``Arn``: local (customer) managed policies ``{PolicyName, PolicyId, Arn, Path,
    DefaultVersionId, AttachmentCount, PermissionsBoundaryUsageCount, IsAttachable, CreateDate,
    UpdateDate}``.
``user_attached_policies.json``, ``group_attached_policies.json``, ``role_attached_policies.json``
    ``{EntityName: [{PolicyName, PolicyArn}]}``; an entity whose attachments are unknown is omitted
    (its failure is in ``_coverage.json`` ``item_errors``).
``user_group_memberships.json``
    ``{UserName: [{GroupName, GroupId, Arn, Path}]}``.
``instance_profiles.json``
    list, sorted by ``Arn``: ``{Path, InstanceProfileName, InstanceProfileId, Arn, CreateDate,
    Roles: [{Path, RoleName, RoleId, Arn, CreateDate}]}`` (GAAD lists the profiles that hold a role).
``policy_documents/<slug(name)>-<sha256(PolicyArn)[:12]>.json``
    one file **per policy ARN** (F-013): ``{PolicyName, PolicyArn, PolicyType: "AWS" | "Local",
    DefaultVersionId, VersionId, Document, Versions: [{VersionId, IsDefaultVersion, CreateDate,
    Document}] | null, CollectionErrors?}``. ``Versions`` holds every version of a local policy
    (``[]`` for AWS managed policies, ``null`` when unknown). A policy whose default document could
    not be read has no file.
``inline_policies/{users,roles,groups}/<EntityName>.json``
    ``{UserName | RoleName | GroupName, EntityArn, InlinePolicies: {PolicyName: Document},
    CollectionErrors?}`` for entities with inline policies.
``permission_boundaries/<EntityName>.json``
    ``{EntityType: "User" | "Role", EntityName, EntityArn, PermissionsBoundary}`` (a user that shares
    its name with a role that also has a boundary is written as ``<EntityName>@user.json``).
``account_password_policy.json``
    ``{Configured: bool | null, ...PasswordPolicy}``.
``account_summary.json``
    ``SummaryMap`` (``{}`` when unreadable).
``credential_report.json``
    ``{GeneratedTime, Rows: [{column: value}]} `` (root row first; ``Rows`` is ``null`` when the report
    is disabled or unavailable). Values are the CSV strings.
``identity_providers.json``
    ``{oidc: [{Arn, Url, ClientIDList, ThumbprintList, CreateDate, CollectionErrors?}] | null,
    saml: [{Arn, ValidUntil, CreateDate}] | null}``.
``_coverage.json``
    every call (docs/contracts/coverage-schema.md).
"""

from __future__ import annotations

import csv
import io
import json
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from aws_enumerator.collectors._common import add_error
from aws_enumerator.collectors.base import CollectContext
from aws_enumerator.coverage import CallResult
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="iam", scope="global", output_dir="iam", services=("iam",),
    tier=1, cost="low", noise="medium", default=True, groups=("@identity",),
    actions=(
        "iam:GetAccountAuthorizationDetails", "iam:ListRoles", "iam:GetPolicy", "iam:GetPolicyVersion",
        "iam:GetAccountPasswordPolicy", "iam:GetAccountSummary", "iam:GenerateCredentialReport",
        "iam:GetCredentialReport", "iam:ListVirtualMFADevices", "iam:ListAccessKeys", "iam:ListSSHPublicKeys",
        "iam:ListServiceSpecificCredentials", "iam:ListSigningCertificates", "iam:ListOpenIDConnectProviders",
        "iam:GetOpenIDConnectProvider", "iam:ListSAMLProviders",
    ),
    optional_actions=(
        "iam:ListUsers", "iam:ListGroups", "iam:ListPolicies", "iam:ListInstanceProfiles", "iam:GetUser",
        "iam:GetRole", "iam:ListGroupsForUser", "iam:ListAttachedUserPolicies", "iam:ListAttachedGroupPolicies",
        "iam:ListAttachedRolePolicies", "iam:ListUserPolicies", "iam:GetUserPolicy", "iam:ListGroupPolicies",
        "iam:GetGroupPolicy", "iam:ListRolePolicies", "iam:GetRolePolicy", "iam:ListPolicyVersions",
        "iam:GetLoginProfile", "iam:ListMFADevices",
    ),
    probe=("iam", "GetAccountAuthorizationDetails", (("MaxItems", 1),)),
    outputs=(
        ("users.json", "list"), ("roles.json", "list"), ("groups.json", "list"), ("policies.json", "list"),
        ("user_attached_policies.json", "dict"), ("group_attached_policies.json", "dict"),
        ("role_attached_policies.json", "dict"), ("user_group_memberships.json", "dict"),
        ("instance_profiles.json", "list"), ("account_password_policy.json", "dict"),
        ("account_summary.json", "dict"), ("credential_report.json", "dict"), ("identity_providers.json", "dict"),
        ("policy_documents/*.json", "dict"), ("inline_policies/*.json", "dict"),
        ("permission_boundaries/*.json", "dict"),
    ),
    description="IAM users, groups, roles, policies (all versions), instance profiles, federation providers, "
                "credential hygiene",
)

GAAD_FILTERS = ["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"]
_PAGE = 1000
#: Seconds to wait between credential-report polls (a short first wait, then every 2 s), and the cap.
_REPORT_POLL_DELAYS: Tuple[float, ...] = (0.5, 1.0, 2.0)
_REPORT_TIMEOUT = 60.0
_KINDS = (("users", "user", "UserName", "User"), ("groups", "group", "GroupName", "Group"),
          ("roles", "role", "RoleName", "Role"))
_POLICY_SUMMARY_KEYS = ("PolicyName", "PolicyId", "Arn", "Path", "DefaultVersionId", "AttachmentCount",
                        "PermissionsBoundaryUsageCount", "IsAttachable", "CreateDate", "UpdateDate")
_ENTITY_BASE_KEYS = {"user": ("UserName", "UserId", "Arn", "Path", "CreateDate"),
                     "group": ("Path", "GroupName", "GroupId", "Arn", "CreateDate"),
                     "role": ("Path", "RoleName", "RoleId", "Arn", "CreateDate", "AssumeRolePolicyDocument")}
_PROFILE_ROLE_KEYS = ("Path", "RoleName", "RoleId", "Arn", "CreateDate")
_NOT_A_TIME = frozenset({"", "N/A", "no_information", "not_supported"})


@dataclass
class Entities:
    """Everything the entity phase collected, keyed for deterministic output."""

    users: Dict[str, Dict[str, Any]] = field(default_factory=dict)          # UserName -> record
    groups: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    roles: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    attached: Dict[str, Dict[str, List[Dict[str, str]]]] = field(
        default_factory=lambda: {"users": {}, "groups": {}, "roles": {}})
    inline: Dict[str, Dict[str, Dict[str, Any]]] = field(
        default_factory=lambda: {"users": {}, "groups": {}, "roles": {}})
    inline_errors: Dict[str, Dict[str, List[Dict[str, Any]]]] = field(
        default_factory=lambda: {"users": {}, "groups": {}, "roles": {}})
    memberships: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    local_policies: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # Arn -> summary
    documents: Dict[str, Dict[str, Any]] = field(default_factory=dict)       # Arn -> document record
    instance_profiles: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # Arn -> profile
    password_last_used: Dict[str, Any] = field(default_factory=dict)       # UserName -> ListUsers value


# ── entry point ──────────────────────────────────────────────────────────────
def collect(ctx: CollectContext) -> None:
    """Account settings, entities, missing policy documents, credentials, federation providers."""
    iam = ctx.client("iam")
    with ctx.section("account"):
        _account(ctx, iam)
    entities = Entities()
    with ctx.section("entities"):
        _collect_entities(ctx, iam, entities)
    with ctx.section("policy_documents"):
        _fetch_referenced_documents(ctx, iam, entities)
    _write_entities(ctx, entities)
    with ctx.section("credentials"):
        users = _credentials(ctx, iam, entities)
    ctx.out.write("users.json", users)
    with ctx.section("identity_providers"):
        _identity_providers(ctx, iam)


# ── helpers ──────────────────────────────────────────────────────────────────
def _document(value: Any) -> Any:
    """A policy document as a dict: botocore already decodes IAM documents; files may hold strings."""
    if isinstance(value, str):
        text = urllib.parse.unquote(value)
        try:
            return json.loads(text)
        except ValueError:
            return text
    return value


def _boundary(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, dict) or not value.get("PermissionsBoundaryArn"):
        return None
    return {"PermissionsBoundaryType": value.get("PermissionsBoundaryType"),
            "PermissionsBoundaryArn": value["PermissionsBoundaryArn"]}


def _refs(attached: Iterable[Any]) -> List[Dict[str, str]]:
    refs = [{"PolicyName": p.get("PolicyName"), "PolicyArn": p.get("PolicyArn")}
            for p in attached if isinstance(p, dict) and p.get("PolicyArn")]
    return sorted(refs, key=lambda r: r["PolicyArn"])


def _version_key(version: Dict[str, Any]) -> Tuple[int, str]:
    vid = str(version.get("VersionId") or "")
    return (int(vid[1:]) if vid[:1] == "v" and vid[1:].isdigit() else 1 << 30, vid)


def is_aws_managed(arn: str) -> bool:
    """``arn:<partition>:iam::aws:policy/...`` (AWS managed) versus a local (customer) policy."""
    return ":iam::aws:policy/" in arn


def _option_on(ctx: CollectContext, name: str, default: bool = True) -> bool:
    """A boolean option that may arrive as ``name`` or as ``no_<name>`` (``--no-...`` flags)."""
    if ctx.option(f"no_{name}", False):
        return False
    value = ctx.option(name, default)
    return default if value is None else bool(value)


# ── account ──────────────────────────────────────────────────────────────────
def _account(ctx: CollectContext, iam: Any) -> None:
    policy = ctx.call(iam, "get_account_password_policy")
    if policy.has_data:
        doc: Dict[str, Any] = {"Configured": True}
        doc.update(policy.get("PasswordPolicy") or {})
    else:
        doc = {"Configured": False if policy.ok else None}  # NoSuchEntity: no password policy
    ctx.out.write("account_password_policy.json", doc)
    summary = ctx.call(iam, "get_account_summary")
    ctx.out.write("account_summary.json", dict(summary.get("SummaryMap") or {}))


# ── entities: mode selection ─────────────────────────────────────────────────
def _collect_entities(ctx: CollectContext, iam: Any, entities: Entities) -> None:
    gaad_file = ctx.option("iam_gaad_file")
    mode = str(ctx.option("iam_mode", "gaad") or "gaad").replace("_", "-").lower()
    if gaad_file:
        ctx.cov.skip("iam:GetAccountAuthorizationDetails", "imported from --iam-gaad-file")
        _from_gaad(ctx, _load_gaad_file(Path(str(gaad_file))), entities)
        _merge_list_roles(ctx, iam, entities)
        return
    if mode not in ("gaad", "per-entity"):
        ctx.log.warning("unknown iam_mode %r; using 'gaad'", mode)
        mode = "gaad"
    if mode == "gaad":
        details = ctx.paginate(iam, "get_account_authorization_details",
                               ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies"),
                               page_size=_PAGE, optional=True, Filter=list(GAAD_FILTERS))
        if details.ok:
            _from_gaad(ctx, details.value, entities)
            _merge_list_roles(ctx, iam, entities)
            return
        ctx.log.warning("GetAccountAuthorizationDetails %s (%s); falling back to per-entity IAM calls",
                        details.status, details.error_code)
    _per_entity(ctx, iam, entities)


def _load_gaad_file(path: Path) -> Dict[str, List[Any]]:
    """An exported GAAD document (one response, or a list of pages) as ``{list key: items}``."""
    data = json.loads(path.read_text(encoding="utf-8"))
    pages = data if isinstance(data, list) else [data]
    keys = ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies")
    merged: Dict[str, List[Any]] = {k: [] for k in keys}
    for page in pages:
        if not isinstance(page, dict):
            raise ValueError(f"{path}: not a GetAccountAuthorizationDetails export")
        for key in keys:
            merged[key].extend(page.get(key) or [])
    return merged


# ── entities: GAAD ───────────────────────────────────────────────────────────
def _from_gaad(ctx: CollectContext, details: Dict[str, List[Any]], entities: Entities) -> None:
    groups_by_name: Dict[str, Dict[str, Any]] = {}
    for group in details.get("GroupDetailList") or []:
        if isinstance(group, dict) and group.get("GroupName"):
            base = {k: group.get(k) for k in _ENTITY_BASE_KEYS["group"]}
            groups_by_name[group["GroupName"]] = base
            entities.groups[group["GroupName"]] = base
            _gaad_policies(entities, "groups", group, "GroupPolicyList")
    for user in details.get("UserDetailList") or []:
        if isinstance(user, dict) and user.get("UserName"):
            _gaad_user(entities, user, groups_by_name)
    for role in details.get("RoleDetailList") or []:
        if isinstance(role, dict) and role.get("RoleName"):
            _gaad_role(entities, role)
    for policy in details.get("Policies") or []:
        if isinstance(policy, dict) and policy.get("Arn"):
            _gaad_policy(entities, policy)


def _gaad_policies(entities: Entities, kind: str, entity: Dict[str, Any], inline_key: str) -> None:
    name = entity[{"users": "UserName", "groups": "GroupName", "roles": "RoleName"}[kind]]
    entities.attached[kind][name] = _refs(entity.get("AttachedManagedPolicies") or [])
    inline = {p["PolicyName"]: _document(p.get("PolicyDocument"))
              for p in entity.get(inline_key) or [] if isinstance(p, dict) and p.get("PolicyName")}
    if inline:
        entities.inline[kind][name] = dict(sorted(inline.items()))


def _gaad_user(entities: Entities, user: Dict[str, Any], groups_by_name: Dict[str, Dict[str, Any]]) -> None:
    record = {k: user.get(k) for k in _ENTITY_BASE_KEYS["user"]}
    record.update(Tags=list(user.get("Tags") or []), PermissionsBoundary=_boundary(user.get("PermissionsBoundary")))
    entities.users[user["UserName"]] = record
    _gaad_policies(entities, "users", user, "UserPolicyList")
    memberships = []
    for group_name in user.get("GroupList") or []:
        group = groups_by_name.get(group_name) or {}
        memberships.append({"GroupName": group_name, "GroupId": group.get("GroupId"), "Arn": group.get("Arn"),
                            "Path": group.get("Path")})
    entities.memberships[user["UserName"]] = sorted(memberships, key=lambda g: str(g["GroupName"]))


def _gaad_role(entities: Entities, role: Dict[str, Any]) -> None:
    record = {k: role.get(k) for k in _ENTITY_BASE_KEYS["role"]}
    record["AssumeRolePolicyDocument"] = _document(record["AssumeRolePolicyDocument"])
    record.update(Description=None, MaxSessionDuration=None,
                  PermissionsBoundary=_boundary(role.get("PermissionsBoundary")), Tags=list(role.get("Tags") or []),
                  RoleLastUsed=dict(role.get("RoleLastUsed") or {}))
    entities.roles[role["RoleName"]] = record
    _gaad_policies(entities, "roles", role, "RolePolicyList")
    for profile in role.get("InstanceProfileList") or []:
        if isinstance(profile, dict) and profile.get("Arn"):
            entities.instance_profiles[profile["Arn"]] = _profile(profile)


def _profile(profile: Dict[str, Any]) -> Dict[str, Any]:
    roles = [{k: r.get(k) for k in _PROFILE_ROLE_KEYS} for r in profile.get("Roles") or [] if isinstance(r, dict)]
    return {"Path": profile.get("Path"), "InstanceProfileName": profile.get("InstanceProfileName"),
            "InstanceProfileId": profile.get("InstanceProfileId"), "Arn": profile.get("Arn"),
            "CreateDate": profile.get("CreateDate"), "Roles": sorted(roles, key=lambda r: str(r["Arn"]))}


def _version_record(version: Dict[str, Any]) -> Dict[str, Any]:
    return {"VersionId": version.get("VersionId"), "IsDefaultVersion": bool(version.get("IsDefaultVersion")),
            "CreateDate": version.get("CreateDate"), "Document": _document(version.get("Document"))}


def _gaad_policy(entities: Entities, policy: Dict[str, Any]) -> None:
    arn = policy["Arn"]
    versions = sorted((_version_record(v) for v in policy.get("PolicyVersionList") or [] if isinstance(v, dict)),
                      key=_version_key)
    default_id = policy.get("DefaultVersionId")
    default = next((v for v in versions if v["VersionId"] == default_id), None) or \
        next((v for v in versions if v["IsDefaultVersion"]), None)
    aws = is_aws_managed(arn)
    if not aws:
        entities.local_policies[arn] = {k: policy.get(k) for k in _POLICY_SUMMARY_KEYS}
    if default is None:
        return
    entities.documents[arn] = _document_record(policy.get("PolicyName"), arn, default_id or default["VersionId"],
                                               default["Document"], [] if aws else versions)


def _document_record(name: Any, arn: str, default_id: Any, document: Any,
                     versions: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
    return {"PolicyName": name, "PolicyArn": arn, "PolicyType": "AWS" if is_aws_managed(arn) else "Local",
            "DefaultVersionId": default_id, "VersionId": default_id, "Document": document, "Versions": versions}


def _merge_list_roles(ctx: CollectContext, iam: Any, entities: Entities) -> None:
    """``Description`` / ``MaxSessionDuration`` for GAAD roles (GAAD does not return them)."""
    if not entities.roles:
        return
    listed = ctx.paginate(iam, "list_roles", "Roles", page_size=_PAGE)
    by_arn = {r.get("Arn"): r for r in listed.value if isinstance(r, dict)}
    for record in entities.roles.values():
        source = by_arn.get(record["Arn"])
        if source is not None:
            record["Description"] = source.get("Description")
            record["MaxSessionDuration"] = source.get("MaxSessionDuration")


# ── entities: per-entity fallback ────────────────────────────────────────────
def _per_entity(ctx: CollectContext, iam: Any, entities: Entities) -> None:
    """The list/get calls of the fallback, one section per phase (F-053)."""
    with ctx.section("users"):
        _pe_users(ctx, iam, entities)
    with ctx.section("groups"):
        _pe_groups(ctx, iam, entities)
    with ctx.section("roles"):
        _pe_roles(ctx, iam, entities)
    with ctx.section("instance_profiles"):
        listed = ctx.paginate(iam, "list_instance_profiles", "InstanceProfiles", page_size=_PAGE)
        for profile in listed.value:
            if isinstance(profile, dict) and profile.get("Arn"):
                entities.instance_profiles[profile["Arn"]] = _profile(profile)
    with ctx.section("policies"):
        _pe_local_policies(ctx, iam, entities)


def _pe_attached_and_inline(ctx: CollectContext, iam: Any, entities: Entities, kind: str, name: str,
                            arn: str) -> None:
    singular, key = {"users": ("user", "UserName"), "groups": ("group", "GroupName"),
                     "roles": ("role", "RoleName")}[kind]
    attached = ctx.paginate(iam, f"list_attached_{singular}_policies", "AttachedPolicies", page_size=_PAGE,
                            item=arn, **{key: name})
    if attached.ok:
        entities.attached[kind][name] = _refs(attached.value)
    listed = ctx.paginate(iam, f"list_{singular}_policies", "PolicyNames", page_size=_PAGE, item=arn, **{key: name})
    if not listed.ok:
        return  # unknown inline policies: an item_errors entry, no file (F-111)
    documents: Dict[str, Any] = {}
    for policy_name in sorted(p for p in listed.value if isinstance(p, str)):
        got = ctx.call(iam, f"get_{singular}_policy", item=arn, **{key: name, "PolicyName": policy_name})
        if got.has_data:
            documents[policy_name] = _document(got.get("PolicyDocument"))
        elif got.collection_error() is not None:
            entities.inline_errors[kind].setdefault(name, []).append(got.collection_error())
    if documents or entities.inline_errors[kind].get(name):
        entities.inline[kind][name] = documents


def _pe_users(ctx: CollectContext, iam: Any, entities: Entities) -> None:
    listed = ctx.paginate(iam, "list_users", "Users", page_size=_PAGE)
    for user in sorted((u for u in listed.value if isinstance(u, dict) and u.get("UserName")),
                       key=lambda u: u["UserName"]):
        name, arn = user["UserName"], user.get("Arn")
        record = {k: user.get(k) for k in _ENTITY_BASE_KEYS["user"]}
        record.update(Tags=None, PermissionsBoundary=None)
        entities.password_last_used[name] = user.get("PasswordLastUsed")
        got = ctx.call(iam, "get_user", item=arn, UserName=name)
        if got.has_data:
            detail = got.get("User") or {}
            record.update(Tags=list(detail.get("Tags") or []),
                          PermissionsBoundary=_boundary(detail.get("PermissionsBoundary")))
        else:
            add_error(record, got)
        entities.users[name] = record
        groups = ctx.paginate(iam, "list_groups_for_user", "Groups", page_size=_PAGE, item=arn, UserName=name)
        if groups.ok:
            entities.memberships[name] = sorted(
                ({k: g.get(k) for k in ("GroupName", "GroupId", "Arn", "Path")} for g in groups.value
                 if isinstance(g, dict)), key=lambda g: str(g["GroupName"]))
        _pe_attached_and_inline(ctx, iam, entities, "users", name, arn)


def _pe_groups(ctx: CollectContext, iam: Any, entities: Entities) -> None:
    listed = ctx.paginate(iam, "list_groups", "Groups", page_size=_PAGE)
    for group in sorted((g for g in listed.value if isinstance(g, dict) and g.get("GroupName")),
                        key=lambda g: g["GroupName"]):
        entities.groups[group["GroupName"]] = {k: group.get(k) for k in _ENTITY_BASE_KEYS["group"]}
        _pe_attached_and_inline(ctx, iam, entities, "groups", group["GroupName"], group.get("Arn"))


def _pe_roles(ctx: CollectContext, iam: Any, entities: Entities) -> None:
    listed = ctx.paginate(iam, "list_roles", "Roles", page_size=_PAGE, primary=True)
    for role in sorted((r for r in listed.value if isinstance(r, dict) and r.get("RoleName")),
                       key=lambda r: r["RoleName"]):
        name, arn = role["RoleName"], role.get("Arn")
        record = {k: role.get(k) for k in _ENTITY_BASE_KEYS["role"]}
        record["AssumeRolePolicyDocument"] = _document(record["AssumeRolePolicyDocument"])
        record.update(Description=role.get("Description"), MaxSessionDuration=role.get("MaxSessionDuration"),
                      PermissionsBoundary=None, Tags=None, RoleLastUsed=None)
        got = ctx.call(iam, "get_role", item=arn, RoleName=name)
        if got.has_data:
            detail = got.get("Role") or {}
            record.update(PermissionsBoundary=_boundary(detail.get("PermissionsBoundary")),
                          Tags=list(detail.get("Tags") or []), RoleLastUsed=dict(detail.get("RoleLastUsed") or {}))
        else:
            add_error(record, got)
        entities.roles[name] = record
        _pe_attached_and_inline(ctx, iam, entities, "roles", name, arn)


def _pe_local_policies(ctx: CollectContext, iam: Any, entities: Entities) -> None:
    listed = ctx.paginate(iam, "list_policies", "Policies", page_size=_PAGE, Scope="Local", OnlyAttached=False)
    for policy in sorted((p for p in listed.value if isinstance(p, dict) and p.get("Arn")),
                         key=lambda p: p["Arn"]):
        entities.local_policies[policy["Arn"]] = {k: policy.get(k) for k in _POLICY_SUMMARY_KEYS}
        _all_versions(ctx, iam, entities, policy)


def _all_versions(ctx: CollectContext, iam: Any, entities: Entities, policy: Dict[str, Any]) -> None:
    """Every version of one local policy (F-110); the default alone when the versions cannot be listed."""
    arn, default_id = policy["Arn"], policy.get("DefaultVersionId")
    listed = ctx.paginate(iam, "list_policy_versions", "Versions", page_size=_PAGE, item=arn, PolicyArn=arn)
    wanted = sorted({v.get("VersionId") for v in listed.value if isinstance(v, dict)} - {None}) if listed.ok else []
    if default_id and default_id not in wanted:
        wanted.append(default_id)
    versions: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    for version_id in wanted:
        got = ctx.call(iam, "get_policy_version", item=arn, PolicyArn=arn, VersionId=version_id)
        if got.has_data:
            versions.append(_version_record(got.get("PolicyVersion") or {}))
        elif got.collection_error() is not None:
            errors.append(got.collection_error())
    versions.sort(key=_version_key)
    default = next((v for v in versions if v["VersionId"] == default_id), None)
    if default is None:
        return  # no default document: no file (the failure is in item_errors)
    complete = listed.ok and not errors
    record = _document_record(policy.get("PolicyName"), arn, default_id, default["Document"],
                              versions if complete else None)
    if errors:
        record["CollectionErrors"] = errors
    entities.documents[arn] = record


# ── documents referenced but not collected ───────────────────────────────────
def _fetch_referenced_documents(ctx: CollectContext, iam: Any, entities: Entities) -> None:
    """``GetPolicy`` + ``GetPolicyVersion`` for attached / boundary policies with no document yet."""
    referenced: Dict[str, Any] = {}
    for table in entities.attached.values():
        for refs in table.values():
            for ref in refs:
                referenced.setdefault(ref["PolicyArn"], ref.get("PolicyName"))
    for record in list(entities.users.values()) + list(entities.roles.values()):
        boundary = record.get("PermissionsBoundary")
        if boundary:
            referenced.setdefault(boundary["PermissionsBoundaryArn"], None)
    for arn in sorted(set(referenced) - set(entities.documents)):
        got = ctx.call(iam, "get_policy", item=arn, PolicyArn=arn)
        if not got.has_data:
            continue
        summary = got.get("Policy") or {}
        default_id = summary.get("DefaultVersionId")
        if not is_aws_managed(arn) and arn not in entities.local_policies:
            entities.local_policies[arn] = {k: summary.get(k) for k in _POLICY_SUMMARY_KEYS}
        version = ctx.call(iam, "get_policy_version", item=arn, PolicyArn=arn, VersionId=default_id)
        if version.has_data:
            document = _document((version.get("PolicyVersion") or {}).get("Document"))
            versions = [] if is_aws_managed(arn) else None
            entities.documents[arn] = _document_record(summary.get("PolicyName") or referenced[arn], arn,
                                                       default_id, document, versions)


# ── writing the entity files ─────────────────────────────────────────────────
def _write_entities(ctx: CollectContext, entities: Entities) -> None:
    profiles_by_role: Dict[str, List[str]] = {}
    for profile in entities.instance_profiles.values():
        for role in profile["Roles"]:
            profiles_by_role.setdefault(str(role.get("Arn")), []).append(profile["Arn"])
    roles = []
    for name in sorted(entities.roles):
        record = dict(entities.roles[name])
        record["InstanceProfileArns"] = sorted(profiles_by_role.get(str(record["Arn"]), []))
        errors = record.pop("CollectionErrors", None)
        if errors:
            record["CollectionErrors"] = errors
        roles.append(record)
    ctx.out.write("roles.json", roles)
    ctx.out.write("groups.json", [entities.groups[n] for n in sorted(entities.groups)])
    ctx.out.write("policies.json", [entities.local_policies[a] for a in sorted(entities.local_policies)])
    for kind, singular, _key, _label in _KINDS:
        table = entities.attached[kind]
        ctx.out.write(f"{singular}_attached_policies.json", {n: table[n] for n in sorted(table)})
    ctx.out.write("user_group_memberships.json", {n: entities.memberships[n] for n in sorted(entities.memberships)})
    ctx.out.write("instance_profiles.json",
                  [entities.instance_profiles[a] for a in sorted(entities.instance_profiles)])
    with ctx.section("write_policy_documents"):
        for arn in sorted(entities.documents):
            record = entities.documents[arn]
            ctx.out.write_item("policy_documents", arn, record, hint=str(record.get("PolicyName") or arn))
    with ctx.section("write_inline_policies"):
        _write_inline(ctx, entities)
    with ctx.section("write_permission_boundaries"):
        _write_boundaries(ctx, entities)


def _write_inline(ctx: CollectContext, entities: Entities) -> None:
    records = {"users": entities.users, "groups": entities.groups, "roles": entities.roles}
    for kind, singular, key, _label in _KINDS:
        for name in sorted(entities.inline[kind]):
            entity = records[kind].get(name) or {}
            doc: Dict[str, Any] = {key: name, "EntityArn": entity.get("Arn") or ctx.arn("iam", f"{singular}/{name}"),
                                   "InlinePolicies": entities.inline[kind][name]}
            if entities.inline_errors[kind].get(name):
                doc["CollectionErrors"] = entities.inline_errors[kind][name]
            ctx.out.write(f"inline_policies/{kind}/{name}.json", doc)


def _write_boundaries(ctx: CollectContext, entities: Entities) -> None:
    written = set()
    for label, records in (("Role", entities.roles), ("User", entities.users)):
        for name in sorted(records):
            boundary = records[name].get("PermissionsBoundary")
            if not boundary:
                continue
            filename = name if name not in written else f"{name}@user"
            written.add(filename)
            ctx.out.write(f"permission_boundaries/{filename}.json",
                          {"EntityType": label, "EntityName": name, "EntityArn": records[name].get("Arn"),
                           "PermissionsBoundary": boundary})


# ── credentials ──────────────────────────────────────────────────────────────
def _credentials(ctx: CollectContext, iam: Any, entities: Entities) -> List[Dict[str, Any]]:
    """The final ``users.json`` records: entity data plus credential hygiene."""
    rows, generated = _credential_report(ctx, iam)
    ctx.out.write("credential_report.json", {"GeneratedTime": generated, "Rows": rows})
    by_arn = {row.get("arn"): row for row in rows or []}
    virtual = _virtual_mfa(ctx, iam) if entities.users else None
    details_on = _option_on(ctx, "iam_user_details")
    if entities.users and not details_on:
        for api in ("iam:ListAccessKeys", "iam:ListSSHPublicKeys", "iam:ListServiceSpecificCredentials",
                    "iam:ListSigningCertificates"):
            ctx.cov.skip(api, "iam_user_details=off")
    users = []
    for name in sorted(entities.users):
        record = dict(entities.users[name])
        errors = record.pop("CollectionErrors", [])
        row = by_arn.get(record["Arn"]) if rows is not None else None
        creds = _UserCredentials(ctx, iam, record, row, errors)
        creds.fill(rows is not None, virtual, details_on, entities.password_last_used.get(name))
        if errors:
            record["CollectionErrors"] = errors
        users.append(record)
    return users


def _credential_report(ctx: CollectContext, iam: Any) -> Tuple[Optional[List[Dict[str, str]]], Any]:
    """``(rows, generated_time)``; ``(None, None)`` when disabled or unavailable (optional calls)."""
    if not _option_on(ctx, "credential_report"):
        ctx.cov.skip("iam:GenerateCredentialReport", "credential report disabled (--no-credential-report)")
        return None, None
    deadline = time.monotonic() + _REPORT_TIMEOUT
    attempt = 0
    while True:
        state = ctx.call(iam, "generate_credential_report", optional=True)
        if not state.ok:
            return None, None
        if state.get("State") == "COMPLETE":
            break
        if time.monotonic() >= deadline:
            ctx.log.warning("credential report not ready after %.0f s; using per-user calls", _REPORT_TIMEOUT)
            return None, None
        delay = _REPORT_POLL_DELAYS[min(attempt, len(_REPORT_POLL_DELAYS) - 1)]
        attempt += 1
        ctx.run.stop_event.wait(delay)
        ctx.check_stop()
    report = ctx.call(iam, "get_credential_report", optional=True)
    if not report.has_data:
        return None, None
    content = report.get("Content") or b""
    text = content.decode("utf-8-sig") if isinstance(content, (bytes, bytearray)) else str(content)
    rows = [dict(row) for row in csv.DictReader(io.StringIO(text))]
    rows.sort(key=lambda r: (r.get("user") != "<root_account>", str(r.get("arn"))))
    return rows, report.get("GeneratedTime")


def _virtual_mfa(ctx: CollectContext, iam: Any) -> Optional[Dict[str, List[str]]]:
    listed = ctx.paginate(iam, "list_virtual_mfa_devices", "VirtualMFADevices", page_size=_PAGE,
                          AssignmentStatus="Assigned")
    if not listed.ok:
        return None
    out: Dict[str, List[str]] = {}
    for device in listed.value:
        user_arn = ((device or {}).get("User") or {}).get("Arn") if isinstance(device, dict) else None
        if user_arn and device.get("SerialNumber"):
            out.setdefault(user_arn, []).append(device["SerialNumber"])
    return out


def _report_time(value: Any) -> Optional[datetime]:
    """A credential-report timestamp (``2024-01-15T10:00:00+00:00``) as UTC; ``None`` for N/A & co."""
    if not isinstance(value, str) or value.strip() in _NOT_A_TIME:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def _report_text(value: Any) -> Optional[str]:
    return None if not isinstance(value, str) or value.strip() in _NOT_A_TIME else value


def _mfa_source(serial: str) -> str:
    if ":mfa/" in serial:
        return "virtual"
    if ":u2f/" in serial:
        return "u2f"
    return "hardware"


class _UserCredentials:
    """Fills the credential fields of one ``users.json`` record."""

    def __init__(self, ctx: CollectContext, iam: Any, record: Dict[str, Any], row: Optional[Dict[str, str]],
                 errors: List[Dict[str, Any]]):
        self.ctx, self.iam, self.record, self.row, self.errors = ctx, iam, record, row, errors
        self.arn, self.name = record["Arn"], record["UserName"]

    def _call(self, op: str, **params: Any) -> CallResult:
        result = self.ctx.call(self.iam, op, item=self.arn, UserName=self.name, **params)
        if result.collection_error() is not None:
            self.errors.append(result.collection_error())
        return result

    def _list(self, op: str, key: str) -> Optional[List[Dict[str, Any]]]:
        result = self.ctx.paginate(self.iam, op, key, page_size=_PAGE, item=self.arn, UserName=self.name)
        if result.collection_error() is not None:
            self.errors.append(result.collection_error())
        return [i for i in result.value if isinstance(i, dict)] if result.ok else None

    def fill(self, report_available: bool, virtual: Optional[Dict[str, List[str]]], details_on: bool,
             listed_last_used: Any) -> None:
        row, record = self.row, self.record
        record.update(PasswordLastUsed=None, PasswordLastChanged=None, HasLoginProfile=None, MFAActive=None)
        mfa: Optional[List[Dict[str, str]]] = None
        if virtual is not None:
            mfa = [{"SerialNumber": s, "Source": "virtual"} for s in sorted(virtual.get(self.arn, []))]
        if row is not None:
            record["PasswordLastUsed"] = _report_time(row.get("password_last_used"))
            record["PasswordLastChanged"] = _report_time(row.get("password_last_changed"))
            record["HasLoginProfile"] = {"true": True, "false": False}.get(str(row.get("password_enabled")))
            record["MFAActive"] = {"true": True, "false": False}.get(str(row.get("mfa_active")))
            if record["MFAActive"] and not mfa:
                # MFA is on but no virtual device is visible: a hardware / U2F device (or the virtual
                # listing failed). One targeted ListMFADevices, never one per user (F-167).
                mfa = self._listed_mfa(mfa)
        elif not report_available:
            record["PasswordLastUsed"] = listed_last_used
            mfa = self._fallback_login_and_mfa(mfa)
        record["MFADevices"] = mfa
        keys = self._list("list_access_keys", "AccessKeyMetadata") if details_on else None
        record["AccessKeys"] = _access_keys(keys, row)
        self._alternate_credentials(details_on)

    def _fallback_login_and_mfa(self, mfa: Optional[List[Dict[str, str]]]) -> Optional[List[Dict[str, str]]]:
        """Without a credential report: ``GetLoginProfile`` and ``ListMFADevices`` for this user."""
        login = self._call("get_login_profile")
        if login.ok:
            self.record["HasLoginProfile"] = login.has_data  # NoSuchEntity = no console password
        listed = self._listed_mfa(mfa)
        if listed is not None:
            self.record["MFAActive"] = bool(listed)
            return listed
        return mfa

    def _listed_mfa(self, mfa: Optional[List[Dict[str, str]]]) -> Optional[List[Dict[str, str]]]:
        """``ListMFADevices`` for this user merged with the virtual serials; ``None`` when unreadable."""
        devices = self._list("list_mfa_devices", "MFADevices")
        if devices is None:
            return None
        serials = {d["SerialNumber"] for d in devices if d.get("SerialNumber")} | {m["SerialNumber"] for m in mfa or []}
        return [{"SerialNumber": s, "Source": _mfa_source(s)} for s in sorted(serials)]

    def _alternate_credentials(self, details_on: bool) -> None:
        record = self.record
        record.update(SSHPublicKeys=None, ServiceSpecificCredentials=None, SigningCertificates=None)
        if not details_on:
            return
        ssh = self._list("list_ssh_public_keys", "SSHPublicKeys")
        if ssh is not None:
            record["SSHPublicKeys"] = sorted(({"SSHPublicKeyId": k.get("SSHPublicKeyId"), "Status": k.get("Status"),
                                               "UploadDate": k.get("UploadDate")} for k in ssh),
                                             key=lambda k: str(k["SSHPublicKeyId"]))
        service = self._call("list_service_specific_credentials")
        if service.ok:
            keys = ("ServiceName", "ServiceSpecificCredentialId", "Status", "CreateDate")
            record["ServiceSpecificCredentials"] = sorted(
                ({k: c.get(k) for k in keys} for c in service.get("ServiceSpecificCredentials") or []
                 if isinstance(c, dict)),
                key=lambda c: (str(c["ServiceName"]), str(c["ServiceSpecificCredentialId"])))
        certificates = self._list("list_signing_certificates", "Certificates")
        if certificates is not None:  # the certificate body is never kept
            record["SigningCertificates"] = sorted(
                ({"CertificateId": c.get("CertificateId"), "Status": c.get("Status"), "UploadDate": c.get("UploadDate")}
                 for c in certificates), key=lambda c: str(c["CertificateId"]))


def _report_keys(row: Optional[Dict[str, str]]) -> List[Dict[str, Any]]:
    keys = []
    for index in (1, 2):
        active = row.get(f"access_key_{index}_active") if row else None
        rotated = _report_time(row.get(f"access_key_{index}_last_rotated")) if row else None
        if active != "true" and rotated is None:
            continue  # no such key
        keys.append({"Status": "Active" if active == "true" else "Inactive", "LastRotated": rotated,
                     "LastUsedDate": _report_time(row.get(f"access_key_{index}_last_used_date")),
                     "LastUsedService": _report_text(row.get(f"access_key_{index}_last_used_service")),
                     "LastUsedRegion": _report_text(row.get(f"access_key_{index}_last_used_region"))})
    return keys


def _same_second(a: Any, b: Any) -> bool:
    if not isinstance(a, datetime) or not isinstance(b, datetime):
        return False
    return _utc(a).replace(microsecond=0) == _utc(b).replace(microsecond=0)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _access_keys(listed: Optional[List[Dict[str, Any]]], row: Optional[Dict[str, str]]) -> Optional[List[Dict]]:
    """Merge ``ListAccessKeys`` (ids) with the report's key columns (rotation and last use)."""
    report = _report_keys(row)
    if listed is None:
        if row is None:
            return None
        return [dict(AccessKeyId=None, **k) for k in report]
    listed = sorted(listed, key=lambda k: (str(k.get("CreateDate")), str(k.get("AccessKeyId"))))
    matched: Dict[int, Dict[str, Any]] = {}
    for i, key in enumerate(listed):
        for k in report:
            if _same_second(k["LastRotated"], key.get("CreateDate")):
                matched[i] = k
                report.remove(k)
                break
    for i in range(len(listed)):  # unmatched keys pair with the remaining report columns in order
        if i not in matched and report:
            matched[i] = report.pop(0)
    out = []
    for i, key in enumerate(listed):
        usage = matched.get(i) or {}
        out.append({"AccessKeyId": key.get("AccessKeyId"), "Status": key.get("Status"),
                    "LastRotated": key.get("CreateDate"), "LastUsedDate": usage.get("LastUsedDate"),
                    "LastUsedService": usage.get("LastUsedService"), "LastUsedRegion": usage.get("LastUsedRegion")})
    return sorted(out, key=lambda k: str(k["AccessKeyId"]))


# ── federation providers ─────────────────────────────────────────────────────
def _identity_providers(ctx: CollectContext, iam: Any) -> None:
    doc: Dict[str, Any] = {"oidc": None, "saml": None}
    listed = ctx.call(iam, "list_open_id_connect_providers")
    if listed.ok:
        oidc = []
        for entry in listed.get("OpenIDConnectProviderList") or []:
            arn = entry.get("Arn") if isinstance(entry, dict) else None
            if not arn:
                continue
            record: Dict[str, Any] = {"Arn": arn, "Url": None, "ClientIDList": None, "ThumbprintList": None,
                                      "CreateDate": None}
            got = ctx.call(iam, "get_open_id_connect_provider", item=arn, OpenIDConnectProviderArn=arn)
            if got.has_data:
                record.update(Url=got.get("Url"), ClientIDList=sorted(got.get("ClientIDList") or []),
                              ThumbprintList=sorted(got.get("ThumbprintList") or []), CreateDate=got.get("CreateDate"))
            add_error(record, got)
            oidc.append(record)
        doc["oidc"] = sorted(oidc, key=lambda p: p["Arn"])
    saml = ctx.call(iam, "list_saml_providers")
    if saml.ok:
        doc["saml"] = sorted(({k: p.get(k) for k in ("Arn", "ValidUntil", "CreateDate")}
                              for p in saml.get("SAMLProviderList") or [] if isinstance(p, dict)),
                             key=lambda p: str(p["Arn"]))
    ctx.out.write("identity_providers.json", doc)
