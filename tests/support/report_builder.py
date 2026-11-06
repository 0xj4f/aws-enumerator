"""Synthetic collector-output trees in the baseline (d13c215) layout and file shapes.

Every tree is nested two levels deep, ``<root>/<account>/<region>`` (single-region)
or ``<root>/<account>/{global,<region>...}`` (all-mode), because the baseline engine
scans every sibling of ``dirname(report_path)`` when local data is missing; a
report placed directly in pytest's ``tmp_path`` would read other tests' data.

File shapes follow the collectors in ``app/components/*.py`` and
internal-docs/fix-plan/explore-contract-map.md sections 2, 4 and 6.

Only placeholder accounts are used: 123456789012, 111122223333, 999999999999 and
000000000000. Names are ``demo-*`` / ``example-*``. The ``hostile_strings``
scenario carries HTML/JS-looking **canaries** for our own dashboard tests; they
only ever set ``window.__aeXssCanary`` and are not payloads against anything else.

EC2-family ids are hexadecimal and bucket / Kubernetes object names never contain ``/``, as
docs/contracts/node-ids.md requires (request regressions-py-1), so the same trees can feed a v2 engine.

**v2 runs** (request contracts-runtime-3): :class:`V2Run` builds a run root
``<root>/<account>/<run_id>/`` (report-layout.md §1) with ``manifest.json`` (schema 2.0),
``HANDLING.txt``, ``SHA256SUMS``, ``global/`` and ``<region>/`` units, and per-module ``_coverage.json``
(coverage-1) rendered by the production ``Coverage`` class; :func:`mark_item` / :func:`collection_error`
add the per-item markers (``CollectionErrors``, ``PolicyStatus``, ``null`` unknowns);
``Iam.write(scope, layout="gaad")`` writes the migrated IAM collector's output schema
(collectors-cli.md §5.1). :func:`build_v2_example` is a complete, schema-valid example.

Static copies live under ``tests/fixtures/scenarios/<name>/tree/`` so the JS tests
can reuse them. Regenerate with::

    .venv/bin/python -m tests.support.report_builder --write-fixtures

``tests/python/unit/test_report_builder.py`` fails when the committed trees drift
from this module.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "scenarios"

# ── Placeholders ─────────────────────────────────────────────────────────────
ACCT_MAIN = "123456789012"
ACCT_ALT = "111122223333"
ACCT_EXT = "999999999999"
ACCT_ZERO = "000000000000"
PLACEHOLDER_ACCOUNTS = frozenset({ACCT_MAIN, ACCT_ALT, ACCT_EXT, ACCT_ZERO})

TS = "2026-01-01 00:00:00+00:00"       # str(datetime) as the collectors write it
TS_ISO = "2026-01-01T00:00:00+00:00"
TS_Z = "2026-01-01T00:00:00Z"          # UTC with Z, as v2 writers (fsio.json_default) write datetimes (F-171)
MANIFEST_TS = "2026-01-01T00:00:00"    # naive local ISO, as generate_manifest writes it
BASELINE_VERSION = "0.2.0"

#: Dashboard XSS canaries (they only set window.__aeXssCanary) plus parser edge cases.
HOSTILE_STRINGS: List[str] = [
    "<img src=x onerror=window.__aeXssCanary=1>",
    "\"><svg onload=window.__aeXssCanary=1>",
    "</script><script>window.__aeXssCanary=1</script>",
    "javascript:window.__aeXssCanary=1",
    "' onmouseover='window.__aeXssCanary=1' x='",
    "\" onfocus=\"window.__aeXssCanary=1\" autofocus=\"",
    "demo\\\\path\\\"quote\\'single",
    "${window.__aeXssCanary=1}",
    "{{constructor.constructor('window.__aeXssCanary=1')()}}",
    "demo‮​unicode line",
]
#: Names that break plain-object maps in JS (F-042).
PROTO_NAMES: List[str] = ["constructor", "__proto__", "hasOwnProperty", "toString"]


# ── Low-level writers ────────────────────────────────────────────────────────
def dump_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=True)
        fh.write("\n")


class Scope:
    """One report directory: ``<root>/<account>/<name>`` (name = region or 'global').

    ``path`` overrides the location (v2 runs put units at ``<run_root>/<name>``, see :class:`V2Run`);
    ``global_region`` is the region the global unit's records use (``us-east-1`` in partition ``aws``).
    """

    def __init__(self, root: Path, account: str, name: str, *, path: Optional[Path] = None,
                 global_region: str = "us-east-1"):
        self.root = Path(root)
        self.account = account
        self.name = name
        self.path = Path(path) if path is not None else self.root / account / name
        self.global_region = global_region

    def write(self, rel: str, data: Any) -> None:
        dump_json(self.path / rel, data)

    @property
    def region(self) -> str:
        return self.global_region if self.name == "global" else self.name


def _letters(seed: str, n: int) -> str:
    """Deterministic uppercase letters (no digit runs, so the sensitive-data scan stays quiet)."""
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()
    out = "".join(chr(ord("A") + int(c, 16)) for c in digest)
    while len(out) < n:
        out += out
    return out[:n]


def _hex(seed: str, n: int) -> str:
    """Deterministic lowercase hex that never contains a run of 6+ digits."""
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()
    out, run = [], 0
    for c in (digest * 4):
        if c.isdigit():
            run += 1
            if run > 5:
                c, run = "a", 0
        else:
            run = 0
        out.append(c)
        if len(out) == n:
            break
    return "".join(out)


def _z(value: Any) -> Any:
    """Legacy builder timestamps (``TS`` / ``TS_ISO``) as v2 UTC-Z strings; ``""`` becomes ``None``."""
    if value in (TS, TS_ISO):
        return TS_Z
    if value == "":
        return None
    return value


def _gaad_boundary(boundary: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """``{PermissionsBoundaryType, PermissionsBoundaryArn}`` or ``None`` (collectors-cli.md §5.1)."""
    if not boundary:
        return None
    return {"PermissionsBoundaryType": boundary.get("PermissionsBoundaryType", "Policy"),
            "PermissionsBoundaryArn": boundary["PermissionsBoundaryArn"]}


def doc(*statements: Dict[str, Any]) -> Dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(actions: Any, resources: Any = "*", cond: Optional[Dict[str, Any]] = None, sid: str = "") -> Dict[str, Any]:
    stmt: Dict[str, Any] = {}
    if sid:
        stmt["Sid"] = sid
    stmt.update({"Effect": "Allow", "Action": actions, "Resource": resources})
    if cond:
        stmt["Condition"] = cond
    return stmt


def deny(actions: Any, resources: Any = "*") -> Dict[str, Any]:
    return {"Effect": "Deny", "Action": actions, "Resource": resources}


def trust(principal: Any, action: str = "sts:AssumeRole", cond: Optional[Dict[str, Any]] = None,
          single_object: bool = False) -> Dict[str, Any]:
    stmt: Dict[str, Any] = {"Effect": "Allow", "Principal": principal, "Action": action}
    if cond:
        stmt["Condition"] = cond
    return {"Version": "2012-10-17", "Statement": stmt if single_object else [stmt]}


def resource_policy(*statements: Dict[str, Any]) -> Dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def grant(principal: Any, actions: Any, resource: Any = "*", cond: Optional[Dict[str, Any]] = None,
          sid: str = "") -> Dict[str, Any]:
    stmt: Dict[str, Any] = {}
    if sid:
        stmt["Sid"] = sid
    stmt.update({"Effect": "Allow", "Principal": principal, "Action": actions, "Resource": resource})
    if cond:
        stmt["Condition"] = cond
    return stmt


# ── IAM (app/components/iam.py layout) ───────────────────────────────────────
AWS_MANAGED_DOCS: Dict[str, Dict[str, Any]] = {
    "AdministratorAccess": doc(allow("*", "*")),
    "ReadOnlyAccess": doc(allow(["s3:Get*", "s3:List*", "ec2:Describe*", "iam:Get*", "iam:List*"], "*")),
    "PowerUserAccess": doc(
        {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"], "Resource": "*"},
        allow(["iam:CreateServiceLinkedRole", "iam:DeleteServiceLinkedRole", "iam:ListRoles",
               "organizations:DescribeOrganization", "account:ListRegions", "account:GetAccountInformation"],
              "*"),
    ),
}


class Iam:
    """Accumulates IAM entities and writes the 13 collector files under ``<scope>/iam``."""

    def __init__(self, account: str):
        self.account = account
        self.users: List[Dict[str, Any]] = []
        self.groups: List[Dict[str, Any]] = []
        self.roles: List[Dict[str, Any]] = []
        self.customer_policies: List[Dict[str, Any]] = []
        self.policy_docs: Dict[str, Dict[str, Any]] = {}       # filename -> record
        self.refs: Dict[str, Dict[str, str]] = {}               # policy name -> {PolicyName, PolicyArn}
        self.user_groups: Dict[str, Any] = {}
        self.user_attached: Dict[str, Any] = {}
        self.group_attached: Dict[str, Any] = {}
        self.role_attached: Dict[str, Any] = {}
        self.inline: Dict[str, Dict[str, Any]] = {"users": {}, "roles": {}, "groups": {}}
        self.instance_profiles: List[Dict[str, Any]] = []
        self.boundary_files: Dict[str, Dict[str, Any]] = {}
        self.password_policy: Any = {
            "MinimumPasswordLength": 14, "RequireSymbols": True, "RequireNumbers": True,
            "RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True,
            "AllowUsersToChangePassword": True, "ExpirePasswords": False, "HardExpiry": False,
        }
        self.account_summary: Any = {"Users": 0, "Roles": 0, "Groups": 0, "Policies": 0,
                                     "AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
        self.overrides: Dict[str, Any] = {}
        self.extra_files: Dict[str, Any] = {}
        # GAAD layout only (collectors-cli.md §5.1): identity providers and extra per-user credentials
        self.oidc_providers: List[Dict[str, Any]] = []
        self.saml_providers: List[Dict[str, Any]] = []
        self.user_extras: Dict[str, Dict[str, Any]] = {}
        self.policy_versions: Dict[str, List[Dict[str, Any]]] = {}   # customer policy ARN -> all versions
        self.root_account: Dict[str, str] = {"mfa_active": "true", "access_key_1_active": "false",
                                             "access_key_2_active": "false"}

    # identifiers
    def arn(self, kind: str, name: str, path: str = "/") -> str:
        return f"arn:aws:iam::{self.account}:{kind}{path}{name}"

    def _ref(self, policy: Any) -> Dict[str, str]:
        if isinstance(policy, dict):
            return policy
        if policy not in self.refs:
            if policy in AWS_MANAGED_DOCS:
                self.managed(policy, AWS_MANAGED_DOCS[policy])
            else:
                raise KeyError(f"policy {policy!r} not registered; call managed() first")
        return self.refs[policy]

    @staticmethod
    def _doc(value: Any) -> Any:
        if isinstance(value, list):
            return doc(*value)
        return value

    def managed(self, name: str, document: Any, *, customer: bool = False, version: str = "v1",
                path: str = "/", doc_filename: Optional[str] = None) -> Dict[str, str]:
        arn = (f"arn:aws:iam::{self.account}:policy{path}{name}" if customer
               else f"arn:aws:iam::aws:policy{path}{name}")
        ref = {"PolicyName": name, "PolicyArn": arn}
        self.refs[name] = ref
        safe = doc_filename or name.replace("/", "_")
        self.policy_docs[f"{safe}_{version}.json"] = {
            "PolicyName": name, "PolicyArn": arn, "VersionId": version, "Document": self._doc(document)}
        if customer:
            self.customer_policies.append({
                "PolicyName": name, "PolicyId": "ANPA" + _letters(arn, 17), "Arn": arn, "Path": path,
                "DefaultVersionId": version, "AttachmentCount": 0, "PermissionsBoundaryUsageCount": 0,
                "IsAttachable": True, "CreateDate": TS, "UpdateDate": TS})
        return ref

    def _bump_attachment(self, ref: Dict[str, str]) -> None:
        for p in self.customer_policies:
            if p["Arn"] == ref.get("PolicyArn"):
                p["AttachmentCount"] += 1

    def _attach(self, table: Dict[str, Any], name: str, attached: Iterable[Any]) -> None:
        refs = [self._ref(p) for p in attached]
        for r in refs:
            self._bump_attachment(r)
        table[name] = [{"PolicyName": r["PolicyName"], "PolicyArn": r["PolicyArn"]} for r in refs]

    def _inline(self, kind: str, name: str, key: str, inline: Optional[Dict[str, Any]]) -> None:
        if inline:
            self.inline[kind][name] = {key: name, "InlinePolicies": {k: self._doc(v) for k, v in inline.items()}}

    def group_record(self, name: str, path: str = "/") -> Dict[str, Any]:
        return {"Path": path, "GroupName": name, "GroupId": "AGPA" + _letters("g" + name, 17),
                "Arn": self.arn("group", name, path), "CreateDate": TS}

    def user(self, name: str, *, groups: Sequence[str] = (), attached: Sequence[Any] = (),
             inline: Optional[Dict[str, Any]] = None, access_keys: int = 0, key_status: str = "Active",
             mfa: bool = False, login: bool = False, path: str = "/", tags: Optional[list] = None,
             boundary: Optional[Dict[str, Any]] = None, password_last_used: str = "") -> str:
        arn = self.arn("user", name, path)
        rec: Dict[str, Any] = {
            "UserName": name, "UserId": "AIDA" + _letters("u" + name, 17), "Arn": arn, "CreateDate": TS,
            "PasswordLastUsed": password_last_used, "Path": path, "Tags": tags or [],
            "AccessKeys": [{"AccessKeyId": f"AKIAEXAMPLE{_letters('k' + name + str(i), 9)}",
                            "Status": key_status, "CreateDate": TS} for i in range(access_keys)],
            "MFADevices": ([{"SerialNumber": f"arn:aws:iam::{self.account}:mfa/{name}", "EnableDate": TS}]
                           if mfa else []),
            "HasLoginProfile": bool(login),
        }
        if login:
            rec["LoginProfileCreateDate"] = TS
        rec["PermissionsBoundary"] = boundary
        self.users.append(rec)
        self.user_groups[name] = [self.group_record(g) for g in groups]
        self._attach(self.user_attached, name, attached)
        self._inline("users", name, "UserName", inline)
        return arn

    def group(self, name: str, *, attached: Sequence[Any] = (), inline: Optional[Dict[str, Any]] = None,
              path: str = "/") -> str:
        self.groups.append(self.group_record(name, path))
        self._attach(self.group_attached, name, attached)
        self._inline("groups", name, "GroupName", inline)
        return self.arn("group", name, path)

    def role(self, name: str, trust_doc: Any, *, attached: Sequence[Any] = (),
             inline: Optional[Dict[str, Any]] = None, path: str = "/", description: str = "",
             max_session: int = 3600, extra: Optional[Dict[str, Any]] = None) -> str:
        arn = self.arn("role", name, path)
        rec: Dict[str, Any] = {
            "Path": path, "RoleName": name, "RoleId": "AROA" + _letters("r" + name, 17), "Arn": arn,
            "CreateDate": TS, "AssumeRolePolicyDocument": trust_doc, "Description": description,
            "MaxSessionDuration": max_session}
        rec.update(extra or {})
        self.roles.append(rec)
        self._attach(self.role_attached, name, attached)
        self._inline("roles", name, "RoleName", inline)
        return arn

    def role_record(self, name: str) -> Dict[str, Any]:
        for r in self.roles:
            if r["RoleName"] == name:
                return r
        raise KeyError(name)

    def instance_profile(self, name: str, role_names: Sequence[str], path: str = "/") -> str:
        arn = self.arn("instance-profile", name, path)
        self.instance_profiles.append({
            "Path": path, "InstanceProfileName": name, "InstanceProfileId": "AIPA" + _letters("p" + name, 17),
            "Arn": arn, "CreateDate": TS, "Roles": [self.role_record(r) for r in role_names]})
        return arn

    def boundary_file(self, entity_type: str, name: str, boundary: Dict[str, Any]) -> None:
        self.boundary_files[name] = {"EntityType": entity_type, "EntityName": name, "PermissionsBoundary": boundary}

    def override(self, rel: str, data: Any) -> None:
        """Replace a generated file under iam/ (error stubs, malformed shapes)."""
        self.overrides[rel] = data

    # GAAD-layout extras (ignored by the legacy write) --------------------------
    def oidc_provider(self, url: str, *, client_ids: Sequence[str] = ("sts.amazonaws.com",),
                      thumbprints: Sequence[str] = ()) -> str:
        """Register an IAM OIDC provider (``url`` without ``https://``); returns its ARN."""
        arn = f"arn:aws:iam::{self.account}:oidc-provider/{url}"
        self.oidc_providers.append({"Arn": arn, "Url": url, "ClientIDList": list(client_ids),
                                    "ThumbprintList": list(thumbprints) or [_hex("thumb" + url, 40)],
                                    "CreateDate": TS_Z})
        return arn

    def saml_provider(self, name: str) -> str:
        arn = f"arn:aws:iam::{self.account}:saml-provider/{name}"
        self.saml_providers.append({"Arn": arn, "ValidUntil": "2036-01-01T00:00:00Z", "CreateDate": TS_Z})
        return arn

    def user_credentials(self, name: str, *, ssh_keys: int = 0, service_credentials: Sequence[str] = (),
                         signing_certificates: int = 0, errors: Sequence[Dict[str, Any]] = ()) -> None:
        """Per-user extras of the GAAD layout (SSH keys, service-specific credentials, certificates)."""
        self.user_extras[name] = {
            "SSHPublicKeys": [{"SSHPublicKeyId": "APKA" + _letters(f"ssh{name}{i}", 17), "Status": "Active",
                               "UploadDate": TS_Z} for i in range(ssh_keys)],
            "ServiceSpecificCredentials": [{"ServiceName": s, "Status": "Active"} for s in service_credentials],
            "SigningCertificates": [{"CertificateId": _hex(f"cert{name}{i}", 24).upper(), "Status": "Active"}
                                    for i in range(signing_certificates)],
            "CollectionErrors": [dict(e) for e in errors],
        }

    def policy_version(self, policy: str, version: str, document: Any, *, default: bool = False) -> None:
        """Add a (non-default) version to a registered customer policy (GAAD ``Versions``, F-110)."""
        ref = self._ref(policy)
        self.policy_versions.setdefault(ref["PolicyArn"], []).append(
            {"VersionId": version, "IsDefaultVersion": default, "CreateDate": TS_Z, "Document": self._doc(document)})

    def write(self, scope: Scope, layout: str = "legacy") -> None:
        """Write ``<scope>/iam/``: ``layout="legacy"`` (d13c215 shapes) or ``"gaad"`` (collectors-cli.md §5.1)."""
        if layout == "gaad":
            self.write_gaad(scope)
            return
        if layout != "legacy":
            raise ValueError(f"unknown IAM layout {layout!r}")
        self._write_legacy(scope)

    def write_gaad(self, scope: Scope) -> None:
        """The migrated IAM collector's output schema (collectors-cli.md §5.1, GAAD mode).

        Differences from the legacy layout: richer ``users.json`` / ``roles.json`` records,
        ``user_group_memberships.json`` without ``CreateDate``, policy documents **keyed by ARN**
        (``policy_documents/<slug>-<sha12(PolicyArn)>.json``, F-013) with ``PolicyType`` and
        ``Versions``, ``EntityArn`` in inline-policy and boundary files, ``account_password_policy.json``
        with ``Configured``, and the new ``credential_report.json`` / ``identity_providers.json``.
        Unknown values are ``null``; ``CollectionErrors`` appears only on items with a failure.
        """
        from tests.support import targets  # lazy: production fsio names the hashed files

        hashed = targets.fsio_module().hashed_filename
        files: Dict[str, Any] = {}
        role_profiles: Dict[str, List[str]] = {}
        for prof in self.instance_profiles:
            for r in prof["Roles"]:
                role_profiles.setdefault(r["RoleName"], []).append(prof["Arn"])

        users = []
        for u in self.users:
            extra = self.user_extras.get(u["UserName"], {})
            rec: Dict[str, Any] = {
                "UserName": u["UserName"], "UserId": u["UserId"], "Arn": u["Arn"], "Path": u["Path"],
                "CreateDate": _z(u["CreateDate"]), "PasswordLastUsed": _z(u.get("PasswordLastUsed")) or None,
                "PasswordLastChanged": TS_Z if u.get("HasLoginProfile") else None,
                "Tags": list(u.get("Tags") or []),
                "PermissionsBoundary": _gaad_boundary(u.get("PermissionsBoundary")),
                "HasLoginProfile": u.get("HasLoginProfile"),
                "MFAActive": (bool(u["MFADevices"]) if "MFADevices" in u else None),
                "MFADevices": ([{"SerialNumber": d["SerialNumber"], "Source": "virtual"} for d in u["MFADevices"]]
                               if "MFADevices" in u else None),
                "AccessKeys": ([{"AccessKeyId": k["AccessKeyId"], "Status": k["Status"], "LastRotated": TS_Z,
                                 "LastUsedDate": None, "LastUsedService": None, "LastUsedRegion": None}
                                for k in u["AccessKeys"]] if "AccessKeys" in u else None),
                "SSHPublicKeys": list(extra.get("SSHPublicKeys", [])),
                "ServiceSpecificCredentials": list(extra.get("ServiceSpecificCredentials", [])),
                "SigningCertificates": list(extra.get("SigningCertificates", [])),
            }
            errors = list(extra.get("CollectionErrors", []))
            if errors:
                rec["CollectionErrors"] = errors
            users.append(rec)
        roles = []
        for r in self.roles:
            rec = {k: (_z(v) if k == "CreateDate" else v) for k, v in r.items() if k != "PermissionsBoundary"}
            rec["PermissionsBoundary"] = _gaad_boundary(r.get("PermissionsBoundary"))
            rec.setdefault("Tags", [])
            rec.setdefault("RoleLastUsed", {})
            rec["InstanceProfileArns"] = sorted(role_profiles.get(r["RoleName"], []))
            roles.append(rec)

        files["users.json"] = users
        files["roles.json"] = roles
        files["groups.json"] = [dict(g, CreateDate=_z(g["CreateDate"])) for g in self.groups]
        files["policies.json"] = [dict(p, CreateDate=_z(p["CreateDate"]), UpdateDate=_z(p["UpdateDate"]))
                                  for p in self.customer_policies]
        files["user_group_memberships.json"] = {
            name: [{k: g[k] for k in ("GroupName", "GroupId", "Arn", "Path")} for g in groups]
            for name, groups in self.user_groups.items() if isinstance(groups, list)}
        for fname, table in (("user_attached_policies.json", self.user_attached),
                             ("group_attached_policies.json", self.group_attached),
                             ("role_attached_policies.json", self.role_attached)):
            files[fname] = {k: v for k, v in table.items() if isinstance(v, list)}  # unknown entity: omitted
        files["instance_profiles.json"] = [dict(p, CreateDate=_z(p["CreateDate"])) for p in self.instance_profiles]
        if isinstance(self.password_policy, dict) and "Status" not in self.password_policy:
            files["account_password_policy.json"] = dict(self.password_policy, Configured=True)
        else:
            files["account_password_policy.json"] = {"Configured": False}
        files["account_summary.json"] = dict(self.account_summary, Users=len(self.users), Roles=len(self.roles),
                                             Groups=len(self.groups), Policies=len(self.customer_policies))
        for rec in self.policy_docs.values():
            arn = rec["PolicyArn"]
            local = not arn.startswith("arn:aws:iam::aws:")
            versions = self.policy_versions.get(arn, [])
            if local:
                versions = [{"VersionId": rec["VersionId"], "IsDefaultVersion": True, "CreateDate": TS_Z,
                             "Document": rec["Document"]}] + [v for v in versions if v["VersionId"] != rec["VersionId"]]
            files[f"policy_documents/{hashed(arn, rec['PolicyName'])}"] = {
                "PolicyName": rec["PolicyName"], "PolicyArn": arn, "PolicyType": "Local" if local else "AWS",
                "DefaultVersionId": rec["VersionId"], "VersionId": rec["VersionId"], "Document": rec["Document"],
                "Versions": sorted(versions, key=lambda v: v["VersionId"]) if local else []}
        kind_arn = {"users": "user", "roles": "role", "groups": "group"}
        for kind in ("users", "roles", "groups"):
            for name, rec in self.inline[kind].items():
                files[f"inline_policies/{kind}/{name}.json"] = dict(rec, EntityArn=self._entity_arn(kind_arn[kind],
                                                                                                    name))
        for name, rec in self.boundary_files.items():
            files[f"permission_boundaries/{name}.json"] = dict(
                rec, EntityArn=self._entity_arn(rec["EntityType"].lower(), name))
        files["credential_report.json"] = {"GeneratedTime": TS_Z, "Rows": self._credential_report_rows()}
        files["identity_providers.json"] = {"oidc": list(self.oidc_providers), "saml": list(self.saml_providers)}
        files.update(self.extra_files)
        files.update(self.overrides)
        for rel in sorted(files):
            if files[rel] is not None:
                scope.write(f"iam/{rel}", files[rel])

    def _entity_arn(self, kind: str, name: str) -> str:
        records = {"user": self.users, "role": self.roles, "group": self.groups}[kind]
        key = {"user": "UserName", "role": "RoleName", "group": "GroupName"}[kind]
        for rec in records:
            if rec[key] == name:
                return rec["Arn"]
        return self.arn(kind, name)

    def _credential_report_rows(self) -> List[Dict[str, str]]:
        """Parsed credential-report CSV rows (all values strings, as the CSV has them), root row first."""
        na = "N/A"
        root = {"user": "<root_account>", "arn": f"arn:aws:iam::{self.account}:root",
                "user_creation_time": TS_Z, "password_enabled": "not_supported", "password_last_used": TS_Z,
                "password_last_changed": "not_supported", "password_next_rotation": "not_supported",
                "mfa_active": "true", "access_key_1_active": "false", "access_key_1_last_rotated": na,
                "access_key_1_last_used_date": na, "access_key_1_last_used_region": na,
                "access_key_1_last_used_service": na, "access_key_2_active": "false",
                "access_key_2_last_rotated": na, "access_key_2_last_used_date": na,
                "access_key_2_last_used_region": na, "access_key_2_last_used_service": na,
                "cert_1_active": "false", "cert_1_last_rotated": na, "cert_2_active": "false",
                "cert_2_last_rotated": na}
        root.update(self.root_account)
        rows = [root]
        for u in self.users:
            keys = [k for k in u.get("AccessKeys") or []]
            row = dict(root, user=u["UserName"], arn=u["Arn"], user_creation_time=_z(u["CreateDate"]),
                       password_enabled="true" if u.get("HasLoginProfile") else "false",
                       password_last_used=_z(u.get("PasswordLastUsed")) or "no_information",
                       password_last_changed=TS_Z if u.get("HasLoginProfile") else na,
                       password_next_rotation=na,
                       mfa_active="true" if u.get("MFADevices") else "false")
            for i in (1, 2):
                k = keys[i - 1] if len(keys) >= i else None
                row[f"access_key_{i}_active"] = "true" if k and k["Status"] == "Active" else "false"
                row[f"access_key_{i}_last_rotated"] = TS_Z if k else na
            rows.append(row)
        return rows

    def _write_legacy(self, scope: Scope) -> None:
        self.account_summary.update({"Users": len(self.users), "Roles": len(self.roles),
                                     "Groups": len(self.groups), "Policies": len(self.customer_policies)})
        files: Dict[str, Any] = {
            "account_password_policy.json": self.password_policy,
            "account_summary.json": self.account_summary,
            "users.json": self.users,
            "user_group_memberships.json": self.user_groups,
            "user_attached_policies.json": self.user_attached,
            "groups.json": self.groups,
            "group_attached_policies.json": self.group_attached,
            "roles.json": self.roles,
            "role_attached_policies.json": self.role_attached,
            "policies.json": self.customer_policies,
            "instance_profiles.json": self.instance_profiles,
        }
        for fname, rec in self.policy_docs.items():
            files[f"policy_documents/{fname}"] = rec
        for kind in ("users", "roles", "groups"):
            for name, rec in self.inline[kind].items():
                files[f"inline_policies/{kind}/{name}.json"] = rec
        for name, rec in self.boundary_files.items():
            files[f"permission_boundaries/{name}.json"] = rec
        files.update(self.extra_files)
        files.update(self.overrides)
        for rel in sorted(files):
            if files[rel] is not None:
                scope.write(f"iam/{rel}", files[rel])


# ── Record shapes for the other collectors ───────────────────────────────────
def ec2_instance(iid: str, *, account: str, region: str, profile: Optional[str] = None,
                 http_tokens: Optional[str] = "required", public_ip: Optional[str] = None,
                 private_ip: str = "10.0.1.10", subnet: str = "subnet-0a1b2c3d4e5f6aaaa",
                 vpc: str = "vpc-0a1b2c3d4e5f6aaaa", sgs: Sequence[Dict[str, str]] = (),
                 tags: Optional[Dict[str, str]] = None, state: str = "running",
                 instance_type: str = "t3.micro") -> Dict[str, Any]:
    return {
        "InstanceId": iid, "InstanceType": instance_type, "State": state, "LaunchTime": TS,
        "AvailabilityZone": f"{region}a", "AmiId": "ami-0a1b2c3d4e5f6abcd",
        "PublicIpAddress": public_ip, "PrivateIpAddress": private_ip, "SubnetId": subnet, "VpcId": vpc,
        "IamInstanceProfile": ({"Arn": profile, "Id": "AIPA" + _letters(profile, 17)} if profile else {}),
        "SecurityGroups": [dict(g) for g in sgs],
        "NetworkInterfaces": [{"NetworkInterfaceId": "eni-" + _hex(iid, 17), "PrivateIpAddress": private_ip,
                               "SubnetId": subnet, "VpcId": vpc, "MacAddress": "02:00:00:00:00:01",
                               "Status": "in-use"}],
        "MetadataOptions": {"HttpTokens": http_tokens, "HttpPutResponseHopLimit": 1},
        "Monitoring": "disabled",
        "Tags": dict(tags or {}),
    }


def sg_rule(protocol: str = "tcp", from_port: Optional[int] = None, to_port: Optional[int] = None, *,
            cidrs: Sequence[str] = (), cidrs6: Sequence[str] = (), groups: Sequence[str] = (),
            account: str = ACCT_MAIN, description: str = "") -> Dict[str, Any]:
    rule: Dict[str, Any] = {"IpProtocol": protocol}
    if protocol != "-1":
        rule["FromPort"] = from_port
        rule["ToPort"] = to_port if to_port is not None else from_port
    rule["IpRanges"] = [{"CidrIp": c, **({"Description": description} if description else {})} for c in cidrs]
    rule["Ipv6Ranges"] = [{"CidrIpv6": c} for c in cidrs6]
    rule["PrefixListIds"] = []
    rule["UserIdGroupPairs"] = [{"GroupId": g, "UserId": account} for g in groups]
    return rule


def security_group(gid: str, name: str, *, vpc: str, inbound: Sequence[Dict[str, Any]] = (),
                   description: str = "demo security group",
                   attached_instances: Sequence[str] = ()) -> Dict[str, Any]:
    return {
        "GroupId": gid, "GroupName": name, "Description": description, "VpcId": vpc,
        "InboundRules": list(inbound),
        "OutboundRules": [sg_rule("-1", cidrs=["0.0.0.0/0"])],
        "AssociatedResources": [
            {"NetworkInterfaceId": "eni-" + _hex(gid + i, 17), "PrivateIpAddress": "10.0.1.10",
             "Attachment": {"AttachmentId": "eni-attach-" + _hex(i, 17), "InstanceId": i, "Status": "attached"},
             "Description": "", "InstanceId": i}
            for i in attached_instances],
    }


VPC_FILES = ("vpcs.json", "subnets.json", "route_tables.json", "internet_gateways.json", "nat_gateways.json",
             "nacls.json", "vpc_endpoints.json", "dhcp_options.json", "vpc_peering_connections.json")
WAF_FILES = ("web_acls.json", "rule_groups.json", "ip_sets.json", "logging_configs.json")
RESOURCE_MODULES = ("ecs", "cloudformation", "glue", "codebuild", "sagemaker", "sns", "sqs", "ecr", "rds",
                    "dynamodb", "apigateway", "cognito", "ebs", "elb")


def write_empty_regional(scope: Scope, skip: Iterable[str] = ()) -> None:
    """The files every regional collector writes when the region holds nothing."""
    skip = set(skip)
    if "vpc" not in skip:
        for f in VPC_FILES:
            scope.write(f"vpc/{f}", [])
    simple = {"sg": "sg/security_groups.json", "ec2": "ec2/instances.json",
              "cloudtrail": "cloudtrail/trails.json", "flowlogs": "flowlogs/flowlogs.json",
              "eks": "eks/clusters.json", "secretsmanager": "secretsmanager/secrets.json",
              "ssm": "ssm/parameters.json", "lambda": "lambda/functions.json", "kms": "kms/keys.json"}
    for mod, rel in simple.items():
        if mod not in skip:
            scope.write(rel, [])
    if "waf" not in skip:
        for f in WAF_FILES:
            scope.write(f"waf/{f}", [])
    for mod in RESOURCE_MODULES:
        if mod not in skip:
            scope.write(f"{mod}/resources.json", [])


def vpc_network(scope: Scope, *, vpc: str, public_subnet: str, private_subnet: str, igw: str,
                cidr: str = "10.0.0.0/16") -> None:
    """VPC with an IGW-routed public subnet (explicit association) and a private subnet."""
    acct = scope.account
    scope.write("vpc/vpcs.json", [{"CidrBlock": cidr, "DhcpOptionsId": "dopt-0a1b2c3d", "State": "available",
                                   "VpcId": vpc, "OwnerId": acct, "InstanceTenancy": "default",
                                   "IsDefault": False, "Tags": [{"Key": "Name", "Value": "demo-vpc"}]}])
    scope.write("vpc/subnets.json", [
        {"AvailabilityZone": f"{scope.region}a", "CidrBlock": "10.0.1.0/24", "MapPublicIpOnLaunch": True,
         "State": "available", "SubnetId": public_subnet, "VpcId": vpc, "OwnerId": acct},
        {"AvailabilityZone": f"{scope.region}b", "CidrBlock": "10.0.2.0/24", "MapPublicIpOnLaunch": False,
         "State": "available", "SubnetId": private_subnet, "VpcId": vpc, "OwnerId": acct},
    ])
    scope.write("vpc/route_tables.json", [
        {"RouteTableId": "rtb-0a1b2c3d4e5f6ab01", "VpcId": vpc, "OwnerId": acct,
         "Associations": [{"Main": False, "RouteTableAssociationId": "rtbassoc-0a1b2c3daaaa",
                           "RouteTableId": "rtb-0a1b2c3d4e5f6ab01", "SubnetId": public_subnet}],
         "Routes": [{"DestinationCidrBlock": cidr, "GatewayId": "local", "State": "active"},
                    {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": igw, "State": "active"}]},
        {"RouteTableId": "rtb-0a1b2c3d4e5f6ab00", "VpcId": vpc, "OwnerId": acct,
         "Associations": [{"Main": True, "RouteTableAssociationId": "rtbassoc-0a1b2c3dbbbb",
                           "RouteTableId": "rtb-0a1b2c3d4e5f6ab00"}],
         "Routes": [{"DestinationCidrBlock": cidr, "GatewayId": "local", "State": "active"},
                    {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-0a1b2c3d4e5f6aaaa",
                     "State": "active"}]},
    ])
    scope.write("vpc/internet_gateways.json", [{"InternetGatewayId": igw, "OwnerId": acct,
                                                "Attachments": [{"State": "available", "VpcId": vpc}]}])
    scope.write("vpc/nat_gateways.json", [{"NatGatewayId": "nat-0a1b2c3d4e5f6aaaa", "SubnetId": public_subnet,
                                           "VpcId": vpc, "State": "available"}])
    scope.write("vpc/nacls.json", [{"NetworkAclId": "acl-0a1b2c3d", "VpcId": vpc, "IsDefault": True,
                                    "Entries": [{"CidrBlock": "0.0.0.0/0", "Egress": False, "Protocol": "-1",
                                                 "RuleAction": "allow", "RuleNumber": 100}]}])
    scope.write("vpc/vpc_endpoints.json", [])
    scope.write("vpc/dhcp_options.json", [{"DhcpOptionsId": "dopt-0a1b2c3d", "OwnerId": acct,
                                           "DhcpConfigurations": []}])
    scope.write("vpc/vpc_peering_connections.json", [])


def s3_bucket(scope: Scope, name: str, *, region: Optional[str] = None, policy: Any = None,
              acl: Optional[Dict[str, Any]] = None, public_access_block: Optional[Dict[str, Any]] = None,
              versioning: Optional[Dict[str, Any]] = None, encryption: Optional[Dict[str, Any]] = None,
              tagging: Optional[list] = None, logging: Optional[Dict[str, Any]] = None,
              cors: Optional[list] = None, notifications: Optional[Dict[str, Any]] = None,
              region_error: Optional[str] = None) -> Dict[str, Any]:
    """Write the per-bucket sub-config files the S3 collector writes; return the buckets.json entry."""
    for sub, data in (("policies", policy), ("acls", acl), ("public_access_block", public_access_block),
                      ("versioning", versioning), ("encryption", encryption), ("tagging", tagging),
                      ("logging", logging), ("cors", cors), ("notifications", notifications)):
        if data is not None:
            scope.write(f"s3/{sub}/{name}.json", data)
    rec: Dict[str, Any] = {"Name": name, "CreationDate": TS}
    if region_error:
        rec["RegionError"] = region_error
    else:
        rec["Region"] = region or scope.region
    return rec


def kms_encryption(key_arn: str) -> Dict[str, Any]:
    return {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": key_arn},
                       "BucketKeyEnabled": True}]}


def acl(owner_account: str, *, public_read: bool = False) -> Dict[str, Any]:
    grants = [{"Grantee": {"ID": _hex("owner" + owner_account, 64), "Type": "CanonicalUser"},
               "Permission": "FULL_CONTROL"}]
    if public_read:
        grants.append({"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                       "Permission": "READ"})
    return {"Owner": {"ID": _hex("owner" + owner_account, 64)}, "Grants": grants}


def lambda_function(name: str, *, account: str, region: str, role: Optional[str], url_auth: Optional[str] = None,
                    env_names: Sequence[str] = (), runtime: str = "python3.12") -> Dict[str, Any]:
    arn = f"arn:aws:lambda:{region}:{account}:function:{name}"
    rec: Dict[str, Any] = {
        "FunctionName": name, "FunctionArn": arn, "Runtime": runtime, "Handler": "app.handler", "Role": role,
        "MemorySize": 128, "Timeout": 30, "LastModified": "2026-01-01T00:00:00.000+0000", "PackageType": "Zip",
        "Layers": [], "VpcConfig": {"VpcId": None, "SubnetIds": [], "SecurityGroupIds": []},
        "EnvironmentVariableNames": sorted(env_names),
    }
    if url_auth:
        rec["FunctionUrl"] = {"Url": f"https://{_hex(name, 32)}.lambda-url.{region}.on.aws/", "AuthType": url_auth}
    return rec


def lambda_policy_file(fn: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    return {"FunctionArn": fn["FunctionArn"], "FunctionName": fn["FunctionName"], "ResourcePolicy": policy}


def safe_filename(name: str) -> str:
    """Same as the secretsmanager / lambda collectors' _safe_filename."""
    return name.replace("/", "_").replace(":", "_").replace(" ", "_")


def secret(name: str, *, account: str, region: str, kms_key: Optional[str] = None,
           rotation: bool = False) -> Dict[str, Any]:
    rec: Dict[str, Any] = {
        "ARN": f"arn:aws:secretsmanager:{region}:{account}:secret:{name}-{_letters(name, 6).lower()}",
        "Name": name, "Description": "demo secret", "LastChangedDate": TS, "LastAccessedDate": TS,
        "Tags": [], "SecretVersionsToStages": {_hex(name, 8) + "-v1": ["AWSCURRENT"]}, "CreatedDate": TS,
        "RotationEnabled": rotation}
    if kms_key:
        rec["KmsKeyId"] = kms_key
    return rec


def ssm_parameter(name: str, *, account: str, region: str, ptype: str = "String",
                  key_id: Optional[str] = None) -> Dict[str, Any]:
    rec: Dict[str, Any] = {
        "Name": name, "ARN": f"arn:aws:ssm:{region}:{account}:parameter/{name.lstrip('/')}", "Type": ptype,
        "LastModifiedDate": TS, "LastModifiedUser": f"arn:aws:iam::{account}:user/demo-operator",
        "Version": 1, "Tier": "Standard", "Policies": [], "DataType": "text"}
    if key_id:
        rec["KeyId"] = key_id
    return rec


def kms_key(key_id: str, *, account: str, region: str, manager: str = "CUSTOMER", aliases: Sequence[str] = (),
            grants: Sequence[Dict[str, Any]] = (), description: str = "demo key") -> Dict[str, Any]:
    return {"KeyId": key_id, "Arn": f"arn:aws:kms:{region}:{account}:key/{key_id}", "KeyManager": manager,
            "KeyState": "Enabled", "Origin": "AWS_KMS", "Description": description, "Enabled": True,
            "Aliases": list(aliases), "Grants": [dict(g) for g in grants]}


def kms_policy_file(key: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    return {"KeyId": key["KeyId"], "Arn": key["Arn"], "Policy": policy}


def eks_cluster(name: str, *, account: str, region: str, role_arn: str, version: str = "1.30") -> Dict[str, Any]:
    oidc_id = _letters("oidc" + name, 32)
    return {
        "name": name, "arn": f"arn:aws:eks:{region}:{account}:cluster/{name}", "createdAt": TS,
        "version": version, "endpoint": f"https://{oidc_id}.gr7.{region}.eks.amazonaws.com",
        "roleArn": role_arn,
        "resourcesVpcConfig": {"subnetIds": ["subnet-0a1b2c3d4e5f6aaaa"], "securityGroupIds": [],
                               "clusterSecurityGroupId": "sg-0a1b2c3d4e5f6c0de", "vpcId": "vpc-0a1b2c3d4e5f6aaaa",
                               "endpointPublicAccess": True, "endpointPrivateAccess": False,
                               "publicAccessCidrs": ["0.0.0.0/0"]},
        "kubernetesNetworkConfig": {"serviceIpv4Cidr": "172.20.0.0/16", "ipFamily": "ipv4"},
        "logging": {"clusterLogging": [{"types": ["api", "audit"], "enabled": False}]},
        "identity": {"oidc": {"issuer": f"https://oidc.eks.{region}.amazonaws.com/id/{oidc_id}"}},
        "status": "ACTIVE",
        "certificateAuthority": {"data": "RVhBTVBMRS1DQS1EQVRBLU5PVC1BLUNFUlQ="},
        "platformVersion": "eks.1", "tags": {},
        "accessConfig": {"authenticationMode": "API_AND_CONFIG_MAP"},
    }


def oidc_provider_arn(account: str, cluster: Dict[str, Any]) -> str:
    issuer = cluster["identity"]["oidc"]["issuer"].replace("https://", "")
    return f"arn:aws:iam::{account}:oidc-provider/{issuer}"


def k8s_meta(name: str, namespace: Optional[str] = None, *, labels: Optional[Dict[str, str]] = None,
             annotations: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    return {"name": name, "namespace": namespace, "labels": labels, "annotations": annotations,
            "uid": f"{_hex('uid' + str(namespace) + name, 8)}-aaaa-4bbb-8ccc-{_hex(name, 12)}",
            "creation_timestamp": TS, "resource_version": "1000", "owner_references": None,
            "managed_fields": None}


def k8s_pod(name: str, namespace: str, *, sa: Optional[str] = None, labels: Optional[Dict[str, str]] = None,
            privileged: bool = False, host_network: bool = False, host_pid: bool = False,
            secret_volumes: Sequence[str] = (), env: Sequence[Dict[str, Any]] = (),
            image: str = "public.ecr.aws/docker/library/busybox:1.36") -> Dict[str, Any]:
    container: Dict[str, Any] = {
        "name": "main", "image": image, "command": None, "args": None, "env": list(env) or None,
        "env_from": None, "ports": None,
        "security_context": ({"privileged": True, "run_as_user": None} if privileged else None),
        "volume_mounts": [{"name": v, "mount_path": f"/var/run/{v}", "read_only": True} for v in secret_volumes]
        or None,
    }
    spec: Dict[str, Any] = {
        "containers": [container], "init_containers": None, "ephemeral_containers": None,
        "service_account_name": sa, "service_account": sa, "automount_service_account_token": None,
        "host_network": host_network or None, "host_pid": host_pid or None, "host_ipc": None,
        "node_name": "ip-10-0-1-10.demo.internal", "security_context": {},
        "volumes": [{"name": v, "secret": {"secret_name": v, "default_mode": 420}} for v in secret_volumes] or None,
    }
    return {"api_version": None, "kind": None, "metadata": k8s_meta(name, namespace, labels=labels),
            "spec": spec, "status": {"phase": "Running", "pod_ip": "10.0.1.20", "host_ip": "10.0.1.10"}}


def k8s_sa(name: str, namespace: str, *, role_arn: Optional[str] = None) -> Dict[str, Any]:
    ann = {"eks.amazonaws.com/role-arn": role_arn} if role_arn else None
    return {"api_version": None, "kind": None, "metadata": k8s_meta(name, namespace, annotations=ann),
            "automount_service_account_token": None, "image_pull_secrets": None, "secrets": None}


def k8s_role(name: str, namespace: Optional[str], rules: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    return {"api_version": None, "kind": None, "metadata": k8s_meta(name, namespace),
            "rules": [{"api_groups": r.get("api_groups", [""]), "resources": r.get("resources"),
                       "verbs": r.get("verbs"), "resource_names": None, "non_resource_ur_ls": None}
                      for r in rules], "aggregation_rule": None}


def k8s_binding(name: str, namespace: Optional[str], role_kind: str, role_name: str,
                subjects: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    return {"api_version": None, "kind": None, "metadata": k8s_meta(name, namespace),
            "role_ref": {"api_group": "rbac.authorization.k8s.io", "kind": role_kind, "name": role_name},
            "subjects": [dict({"api_group": None}, **s) for s in subjects]}


def k8s_service(name: str, namespace: str, *, svc_type: str = "ClusterIP",
                selector: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    return {"api_version": None, "kind": None, "metadata": k8s_meta(name, namespace),
            "spec": {"type": svc_type, "selector": selector, "cluster_ip": "172.20.0.10",
                     "ports": [{"port": 443, "protocol": "TCP", "target_port": 8443}]},
            "status": {"load_balancer": {}}}


def k8s_ingress(name: str, namespace: str, backend_service: str, *,
                annotations: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    return {"api_version": None, "kind": None, "metadata": k8s_meta(name, namespace, annotations=annotations),
            "spec": {"ingress_class_name": "alb", "rules": [{"host": "demo.example.com", "http": {"paths": [
                {"path": "/", "path_type": "Prefix",
                 "backend": {"service": {"name": backend_service, "port": {"number": 443}}}}]}}]},
            "status": {}}


def k8s_namespace(name: str) -> Dict[str, Any]:
    return {"api_version": None, "kind": None, "metadata": k8s_meta(name), "spec": {"finalizers": ["kubernetes"]},
            "status": {"phase": "Active"}}


def compute_resource(rtype: str, arn: str, name: str, roles: Sequence[str], **extra) -> Dict[str, Any]:
    rec = {"Type": rtype, "Arn": arn, "Name": name, "Roles": sorted(set(roles)) if rtype == "ecstask" else list(roles)}
    rec.update(extra)
    return rec


def policy_resource(rtype: str, arn: str, name: str, policy: Any) -> Dict[str, Any]:
    return {"Type": rtype, "Arn": arn, "Name": name, "Policy": policy}


def write_manifest(scope_dir: Path, *, account: str, mode: str, region: Optional[str],
                   regions: Sequence[str] = (), caller: Optional[str] = None) -> None:
    """manifest.json with app.main.generate_manifest's shape and fixed timestamps."""
    modules = []
    for entry in sorted(os.listdir(scope_dir)):
        entry_path = scope_dir / entry
        if entry_path.is_dir():
            files = sorted(p.relative_to(entry_path).as_posix() for p in entry_path.rglob("*") if p.is_file())
            modules.append({"name": entry, "path": f"{entry}/", "file_count": len(files), "files": files})
    dump_json(scope_dir / "manifest.json", {
        "tool": "aws-enumerator", "version": BASELINE_VERSION, "author": "0xj4f",
        "run_metadata": {
            "account_id": account, "mode": mode, "region": region, "regions_enumerated": list(regions),
            "caller_arn": caller or f"arn:aws:iam::{account}:user/demo-operator",
            "caller_user_id": "AIDA" + _letters("caller" + account, 17),
            "timestamp_start": MANIFEST_TS, "timestamp_end": MANIFEST_TS, "duration_seconds": 0.0},
        "modules_executed": modules,
    })


# ── Per-item markers (docs/contracts/coverage-schema.md §1) ──────────────────
POLICY_STATUSES = ("present", "absent", "denied", "error", "skipped")


def collection_error(api: str, status: str = "denied", error_code: Optional[str] = None) -> Dict[str, Any]:
    """One ``CollectionErrors`` entry ``{api, status, error_code}`` (default code per status)."""
    if status not in ("denied", "error", "throttled", "skipped"):
        raise ValueError(f"a collection error needs a failure status, got {status!r}")
    default = {"denied": "AccessDenied", "throttled": "Throttling", "error": "InternalFailure",
               "skipped": "CircuitOpen:AccessDenied"}[status]
    return {"api": api, "status": status, "error_code": error_code if error_code is not None else default}


def mark_item(record: Dict[str, Any], *errors: Dict[str, Any], policy_status: Optional[str] = None,
              unknown: Iterable[str] = ()) -> Dict[str, Any]:
    """Add the v2 per-item markers to ``record`` (in place) and return it.

    * ``errors``: ``CollectionErrors`` entries (see :func:`collection_error`); the key is added only when
      at least one is given (it is present **only** when something failed for the item);
    * ``policy_status``: ``PolicyStatus`` of a resource-policy read (:data:`POLICY_STATUSES`);
    * ``unknown``: fields that could not be read; they become ``null`` (never ``false``/``[]``, F-059, F-104).
    """
    if errors:
        record.setdefault("CollectionErrors", []).extend(dict(e) for e in errors)
    if policy_status is not None:
        if policy_status not in POLICY_STATUSES:
            raise ValueError(f"unknown PolicyStatus {policy_status!r}")
        record["PolicyStatus"] = policy_status
    for key in unknown:
        record[key] = None
    return record


# ── v2 run layout (docs/contracts/report-layout.md §1, manifest.md, coverage-schema.md) ──────────────
V2_RUN_ID = "20260101T000000Z-a1b2c3"
V2_TOOL_VERSION = "0.3.0"
CLASSIFICATION = "CONFIDENTIAL: pre-computed attack map of the target account; see HANDLING.txt"
HANDLING_TEMPLATE = """aws-enumerator report: CONFIDENTIAL

Run:      {run_id}
Account:  {account_id}
Created:  {started_at}

This directory is a pre-computed attack map of the AWS account above: identities and
their effective permissions, trust relationships, network exposure, and resource policies.
Treat it like a credential.

  - Keep it encrypted at rest and in transit (aws-enumerator package --encrypt ...).
  - Do not commit it to version control or attach it to tickets or chat.
  - Share it only with people covered by the written authorisation for this assessment.
  - Delete it when the engagement's retention period ends.
  - Open the dashboard only on this machine (aws-enumerator dashboard binds 127.0.0.1),
    and open reports you did not produce only in an isolated browser profile.

The report contains no secret values by design (no S3 objects, no secret or parameter
values, no Kubernetes Secret data, no environment-variable values), but it does contain
names, ARNs, policy documents and configuration that an attacker could use.
"""
GLOBAL_REGION_BY_PARTITION = {"aws": "us-east-1", "aws-us-gov": "us-gov-west-1", "aws-cn": "cn-north-1",
                              "aws-iso": "us-iso-east-1", "aws-iso-b": "us-isob-east-1"}
#: Files the manifest's ``files`` list and SHA256SUMS never cover (report-layout.md §7).
_DIGEST_EXCLUDED = ("manifest.json", "SHA256SUMS", "run.log")


def _spec_info(module: str) -> Dict[str, Any]:
    """Registry facts for ``module`` (scope, output_dir, services), with a fallback for unknown names."""
    from tests.support import targets

    try:
        spec = targets.registry_module().get_registry().get(module)
        return {"scope": spec.scope, "output_dir": spec.output_dir, "services": tuple(spec.services)}
    except Exception:  # not a registry module (custom test module): derive
        return {"scope": "regional", "output_dir": module, "services": (module.replace("_", "-"),)}


def _registry_order() -> List[str]:
    from tests.support import targets

    try:
        return targets.registry_names()
    except Exception:
        return []


#: The primary listing call of each registry module (collectors-cli.md §5), used for default coverage rows.
PRIMARY_API: Dict[str, str] = {
    "iam": "iam:GetAccountAuthorizationDetails", "organizations": "organizations:DescribeOrganization",
    "s3": "s3:ListBuckets", "cloudfront": "cloudfront:ListDistributions", "waf_cloudfront": "wafv2:ListWebACLs",
    "route53": "route53:ListHostedZones", "vpc": "ec2:DescribeVpcs", "sg": "ec2:DescribeSecurityGroups",
    "ec2": "ec2:DescribeInstances", "cloudtrail": "cloudtrail:DescribeTrails", "flowlogs": "ec2:DescribeFlowLogs",
    "waf": "wafv2:ListWebACLs", "eks": "eks:ListClusters", "k8s": "eks:DescribeCluster",
    "secretsmanager": "secretsmanager:ListSecrets", "ssm": "ssm:DescribeParameters",
    "lambda": "lambda:ListFunctions", "kms": "kms:ListKeys", "ecs": "ecs:ListTaskDefinitionFamilies",
    "cloudformation": "cloudformation:DescribeStacks", "glue": "glue:GetJobs", "codebuild": "codebuild:ListProjects",
    "sagemaker": "sagemaker:ListNotebookInstances", "sns": "sns:ListTopics", "sqs": "sqs:ListQueues",
    "ecr": "ecr:DescribeRepositories", "rds": "rds:DescribeDBInstances", "dynamodb": "dynamodb:ListTables",
    "apigateway": "apigateway:GetRestApis", "cognito": "cognito-identity:ListIdentityPools",
    "ebs": "ec2:DescribeSnapshots", "elb": "elbv2:DescribeLoadBalancers", "guardduty": "guardduty:ListDetectors",
    "securityhub": "securityhub:DescribeHub", "config": "config:DescribeConfigurationRecorders",
    "accessanalyzer": "accessanalyzer:ListAnalyzers",
}


def _default_api(module: str, services: Sequence[str]) -> str:
    if module in PRIMARY_API:
        return PRIMARY_API[module]
    camel = "".join(part.capitalize() for part in module.split("_"))
    return f"{services[0] if services else module}:List{camel}"


def _fanout_api(module: str, services: Sequence[str]) -> str:
    """A per-item call of ``module`` for the default ``partial`` coverage."""
    service = _default_api(module, services).split(":", 1)[0]
    return f"{service}:GetResourcePolicy"


class V2Run:
    """A synthetic v2 run root ``<root>/<account>/<run_id>/`` (report-layout.md §1) for engine,
    orchestration and dashboard tests that must not run collectors.

    ::

        run = V2Run(tmp_path, account=ACCT_MAIN, regions=["eu-west-1", "eu-west-2"])
        g = run.unit("global")                        # a Scope at <run_root>/global
        iam = Iam(ACCT_MAIN); iam.user("demo-user"); iam.write(g, layout="gaad")
        run.coverage("iam", "global")                 # global/iam/_coverage.json, status ok
        run.coverage("s3", "global", calls=[{"api": "s3:ListBuckets", "primary": True, "items": 2},
                                           {"api": "s3:GetBucketPolicy", "status": "denied",
                                            "item": "arn:aws:s3:::demo-bucket"}])   # -> partial
        run.skip("k8s", "eu-west-2", "disabled by --no-k8s")
        run.finalize()                                # HANDLING.txt, manifest.json, SHA256SUMS

    Coverage documents are rendered by the production ``aws_enumerator.coverage.Coverage`` (through
    ``tests/support/targets.py``), with every clock value fixed to :data:`TS_Z`, so they validate against
    ``coverage-1.schema.json``; the manifest validates against ``manifest-2.0.schema.json``.
    """

    def __init__(self, root: Path, *, account: str = ACCT_MAIN, run_id: str = V2_RUN_ID,
                 regions: Sequence[str] = ("eu-west-2",), partition: str = "aws", home_region: Optional[str] = None,
                 region_source: str = "explicit", operator_arn: Optional[str] = None, redacted: bool = False,
                 k8s: bool = True, k8s_secrets: bool = False, started_at: str = TS_Z, kind: str = "collect"):
        self.root = Path(root)
        self.account = account
        self.run_id = run_id
        self.regions = sorted(regions)
        self.partition = partition
        self.global_region = GLOBAL_REGION_BY_PARTITION.get(partition, "us-east-1")
        self.home_region = home_region or (list(regions)[0] if regions else self.global_region)
        self.region_source = region_source
        self.redacted = redacted
        self.k8s = k8s
        self.k8s_secrets = k8s_secrets
        self.started_at = started_at
        self.kind = kind
        self.path = self.root / account / run_id
        self.operator_arn = operator_arn or f"arn:{partition}:sts::{account}:assumed-role/demo-operator/demo-session"
        self.entries: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.denied: Dict[str, List[str]] = {}       # api -> units
        self.throttled = 0
        self.analysis: Dict[str, Any] = {"status": "not_run", "engine": None, "started_at": None,
                                         "duration_seconds": None, "error": None, "dir": "analysis",
                                         "graph_schema_version": None}
        self.regions_skipped: List[Dict[str, str]] = []

    # units ---------------------------------------------------------------------
    @property
    def units(self) -> List[str]:
        return ["global"] + list(self.regions)

    def unit(self, name: str) -> Scope:
        """The ``Scope`` for unit ``global`` or a region: ``<run_root>/<name>`` (existing writers work on it)."""
        if name != "global" and name not in self.regions:
            raise KeyError(f"{name!r} is not a unit of this run (regions: {self.regions})")
        return Scope(self.root, self.account, name, path=self.path / name, global_region=self.global_region)

    def module_dir(self, module: str, unit: str) -> Path:
        return self.path / unit / _spec_info(module)["output_dir"]

    # coverage ------------------------------------------------------------------
    def coverage(self, module: str, unit: str, *, status: Optional[str] = None,
                 calls: Optional[Sequence[Any]] = None, item_errors: Sequence[Dict[str, Any]] = (),
                 sections: Sequence[Any] = (), services: Optional[Sequence[str]] = None,
                 protocol: str = "ctx", reason: Optional[str] = None, error: Optional[BaseException] = None,
                 write: bool = True) -> Dict[str, Any]:
        """Write ``<unit>/<module dir>/_coverage.json`` and record the module's manifest entry.

        ``calls``: items are ``"api"`` strings (an ok call), or dicts of :class:`CallResult` fields plus
        ``count`` (how many identical calls). Without ``calls`` a status-shaped default is used:
        ``ok`` one ok primary call; ``partial`` one ok primary call plus one denied fan-out call;
        ``denied`` a denied primary call; ``failed`` a ``RuntimeError``; ``interrupted``;
        ``skipped`` / ``not_run`` record a manifest entry only (no directory, report-layout.md §1).
        ``item_errors``: ``{resource, api, status, error_code}`` added with ``Coverage.item_error``.
        ``sections``: names (ok) or ``(name, exception)`` pairs (an erroring section).
        Returns the ``_coverage.json`` document (``{}`` for skipped / not_run).
        """
        from tests.support import targets

        cov_mod = targets.coverage_module()
        info = _spec_info(module)
        svc = tuple(services) if services is not None else info["services"]
        if status in ("skipped", "not_run"):
            return self._forced(module, unit, status, reason or ("disabled" if status == "skipped" else
                                                                  "run stopped before this module"), svc)
        cov = cov_mod.Coverage(module, unit, svc, protocol=protocol)
        primary_api = _default_api(module, svc)
        if calls is None:
            calls = []
            if status in (None, "ok", "partial"):
                calls.append({"api": primary_api, "primary": True, "items": 1, "pages": 1})
            if status == "partial":
                calls.append({"api": _fanout_api(module, svc), "status": "denied", "item": f"{module}-item-1"})
            if status == "denied":
                calls.append({"api": primary_api, "status": "denied", "primary": True})
        for call in calls:
            spec = {"api": call} if isinstance(call, str) else dict(call)
            count = int(spec.pop("count", 1))
            if spec.get("status", "ok") != "ok" and "error_code" not in spec:
                spec["error_code"] = collection_error(spec["api"], spec["status"])["error_code"]
            for _ in range(count):
                result = cov.record(cov_mod.CallResult(**spec))
                if result.status == "denied":
                    self.denied.setdefault(result.api, [])
                    if unit not in self.denied[result.api]:
                        self.denied[result.api].append(unit)
        for e in item_errors:
            cov.item_error(e["resource"], e["api"], e.get("status", "denied"), e.get("error_code", "AccessDenied"))
        for sec in sections:
            name, exc = (sec, None) if isinstance(sec, str) else sec
            entry = cov.section_started(name)
            if exc is not None:
                cov.section_error(entry, exc)
        if status == "failed" or error is not None:
            cov.mark_failed(error or RuntimeError("synthetic failure"))
        if status == "interrupted":
            cov.mark_interrupted()
        cov.started_at, cov.ended_at, cov.duration_seconds = TS_Z, TS_Z, 0.0
        doc = cov.to_json()
        if status is not None and doc["status"] != status:
            raise ValueError(f"{module}@{unit}: calls give status {doc['status']!r}, not {status!r}")
        self.throttled += doc["summary"]["throttled"]
        out_dir = self.path / unit / info["output_dir"]
        if write:
            dump_json(out_dir / "_coverage.json", doc)
        self.entries[(unit, module)] = {
            "name": module, "scope": info["scope"], "region": unit, "status": doc["status"],
            "status_reason": doc["status_reason"], "started_at": TS_Z, "ended_at": TS_Z, "duration_seconds": 0.0,
            "error": doc["error"], "coverage": doc["summary"], "throttle_events": cov.throttle_events,
            "resumed": False, "dir": f"{unit}/{info['output_dir']}" if write else None}
        return doc

    def skip(self, module: str, unit: str, reason: str) -> Dict[str, Any]:
        """A ``skipped`` manifest entry (no directory), e.g. ``"disabled by --no-k8s"``."""
        return self._forced(module, unit, "skipped", reason, _spec_info(module)["services"])

    def not_run(self, module: str, unit: str, reason: str = "run stopped before this module") -> Dict[str, Any]:
        return self._forced(module, unit, "not_run", reason, _spec_info(module)["services"])

    def _forced(self, module: str, unit: str, status: str, reason: str, services: Sequence[str]) -> Dict[str, Any]:
        info = _spec_info(module)
        self.entries[(unit, module)] = {
            "name": module, "scope": info["scope"], "region": unit, "status": status, "status_reason": reason,
            "started_at": None, "ended_at": None, "duration_seconds": None, "error": None, "coverage": None,
            "throttle_events": 0, "resumed": False, "dir": None}
        return {}

    def set_analysis(self, status: str = "ok", *, engine: str = "v2", graph_schema_version: Optional[str] = "1.0",
                     error: Optional[str] = None) -> None:
        self.analysis = {"status": status, "engine": engine, "started_at": TS_Z, "duration_seconds": 0.0,
                         "error": error, "dir": "analysis", "graph_schema_version": graph_schema_version}

    # manifest ------------------------------------------------------------------
    def modules(self) -> List[Dict[str, Any]]:
        order = {name: i for i, name in enumerate(_registry_order())}
        unit_rank = {u: i for i, u in enumerate(self.units)}
        keys = sorted(self.entries, key=lambda k: (unit_rank.get(k[0], len(unit_rank)), order.get(k[1], 999), k[1]))
        return [dict(self.entries[k]) for k in keys]

    def coverage_summary(self) -> Dict[str, Any]:
        mods = self.modules()
        by_status: Dict[str, int] = {}
        for m in mods:
            by_status[m["status"]] = by_status.get(m["status"], 0) + 1
        unit_rank = {u: i for i, u in enumerate(self.units)}
        return {
            "modules_by_status": by_status,
            "denied_apis": [{"api": api, "regions": sorted(units, key=lambda u: unit_rank.get(u, 999))}
                            for api, units in sorted(self.denied.items())],
            "partial_modules": sorted(f"{m['name']}@{m['region']}" for m in mods if m["status"] == "partial"),
            "failed_modules": sorted(f"{m['name']}@{m['region']}" for m in mods if m["status"] == "failed"),
            "throttled_calls": self.throttled,
            "item_errors": sum((m["coverage"] or {}).get("item_errors", 0) for m in mods),
        }

    def run_status(self) -> Tuple[str, int]:
        """(``run.status``, exit code) derived as in manifest.md §2 (no signal, no fatal error)."""
        statuses = [m["status"] for m in self.modules()]
        ran = [s for s in statuses if s not in ("skipped",)]
        if ran and all(s == "failed" for s in ran):
            return "failed", 1
        if any(s in ("partial", "denied", "failed") for s in statuses) or self.analysis["status"] in (
                "failed", "partial"):
            return "partial", 2
        return "complete", 0

    def manifest(self, *, status: Optional[str] = None, exit_code: Optional[int] = None,
                 files: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        derived_status, derived_code = self.run_status()
        status = status or derived_status
        if exit_code is None and status != "in_progress":
            exit_code = derived_code if status == derived_status else {"complete": 0, "partial": 2, "failed": 1,
                                                                       "interrupted": 130}[status]
        modules = self.modules()
        selected = [n for n in _registry_order() if any(m["name"] == n for m in modules)] or sorted(
            {m["name"] for m in modules})
        skipped = sorted({(m["name"], m["status_reason"]) for m in modules if m["status"] == "skipped"})
        ended = None if status == "in_progress" else TS_Z
        caller = None if self.redacted else self.operator_arn
        return {
            "schema_version": "2.0",
            "tool": {"name": "aws-enumerator", "version": V2_TOOL_VERSION, "git_sha": None, "python": "3.10.11",
                     "boto3": "1.37.34", "botocore": "1.37.34", "kubernetes": None},
            "run": {"run_id": self.run_id, "kind": self.kind, "status": status, "started_at": self.started_at,
                    "ended_at": ended, "duration_seconds": None if ended is None else 0.0,
                    "exit_code": None if status == "in_progress" else exit_code,
                    "argv": ["collect", "--regions", ",".join(self.regions)] + ([] if self.k8s else ["--no-k8s"]),
                    "options": {"regions_requested": list(self.regions), "modules": selected,
                                "skipped_modules": [{"name": n, "reason": r} for n, r in skipped],
                                "k8s": self.k8s, "k8s_secrets": self.k8s_secrets, "concurrency": 3,
                                "rate_limit": {"enabled": True, "default_rps": 5, "max_rps": None, "overrides": {}},
                                "max_tier": 2, "deny_breaker": 3, "redact_identity": self.redacted},
                    "resumes": [], "global_source": None},
            "target": {"account_id": self.account, "partition": self.partition, "home_region": self.home_region,
                       "global_region": self.global_region, "regions": list(self.regions),
                       "region_source": self.region_source, "regions_skipped": list(self.regions_skipped)},
            "operator": {"caller_arn": caller,
                         "caller_user_id": None if self.redacted else "AROAEXAMPLEDEMOOPER01:demo-session",
                         "caller_arn_sha256": hashlib.sha256(self.operator_arn.encode()).hexdigest(),
                         "principal_arn": _principal_of(self.operator_arn),
                         "principal_type": _principal_type(self.operator_arn), "redacted": self.redacted},
            "classification": CLASSIFICATION,
            "preflight": None,
            "modules": modules,
            "analysis": dict(self.analysis),
            "coverage_summary": self.coverage_summary(),
            "files": list(files or []),
        }

    def write_handling(self) -> Path:
        path = self.path / "HANDLING.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(HANDLING_TEMPLATE.format(run_id=self.run_id, account_id=self.account,
                                                 started_at=self.started_at), encoding="utf-8")
        return path

    def file_digests(self) -> List[Dict[str, Any]]:
        """``manifest.files``: every regular file under the run root minus the report-layout.md §7 exclusions."""
        out = []
        for p in sorted(self.path.rglob("*")):
            if not p.is_file() or p.is_symlink():
                continue
            rel = p.relative_to(self.path).as_posix()
            if rel in _DIGEST_EXCLUDED or rel.endswith(".zip") or rel.startswith("analysis/exports/"):
                continue
            data = p.read_bytes()
            out.append({"path": rel, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
        return sorted(out, key=lambda f: f["path"])

    def write_manifest(self, *, status: Optional[str] = None, exit_code: Optional[int] = None,
                       digests: bool = True) -> Path:
        self.path.mkdir(parents=True, exist_ok=True)
        doc = self.manifest(status=status, exit_code=exit_code, files=self.file_digests() if digests else [])
        dump_json(self.path / "manifest.json", doc)
        return self.path / "manifest.json"

    def finalize(self, *, status: Optional[str] = None, exit_code: Optional[int] = None,
                 sha256sums: bool = True) -> Path:
        """HANDLING.txt, then the final manifest (with digests), then SHA256SUMS (report-layout.md §6-7)."""
        self.write_handling()
        manifest = self.write_manifest(status=status, exit_code=exit_code)
        if sha256sums:
            lines = [f"{f['sha256']}  {f['path']}" for f in self.file_digests()]
            lines.append(f"{hashlib.sha256(manifest.read_bytes()).hexdigest()}  manifest.json")
            (self.path / "SHA256SUMS").write_text("\n".join(sorted(lines, key=lambda s: s[66:])) + "\n",
                                                  encoding="utf-8")
        return self.path


def _principal_of(caller_arn: str) -> Optional[str]:
    parts = caller_arn.split(":", 5)
    if len(parts) < 6:
        return None
    partition, service, account, resource = parts[1], parts[2], parts[4], parts[5]
    if service == "sts" and resource.startswith("assumed-role/"):
        return f"arn:{partition}:iam::{account}:role/{resource.split('/')[1]}"
    return caller_arn


def _principal_type(caller_arn: str) -> str:
    resource = caller_arn.split(":", 5)[-1]
    if resource.startswith("assumed-role/"):
        return "assumed-role"
    if resource.startswith("user/"):
        return "user"
    if resource == "root":
        return "root"
    if resource.startswith("federated-user/"):
        return "federated-user"
    return "unknown"


def build_v2_example(root: Path, *, regions: Sequence[str] = ("eu-west-1", "eu-west-2")) -> V2Run:
    """A small, schema-valid v2 run used by the harness self-tests and as a template for other tests.

    global: GAAD-layout IAM (ok), s3 (partial: one denied bucket policy, PolicyStatus/CollectionErrors on the
    item); per region: ec2 (ok, contract-valid hex ids), lambda (one ok region, one denied region),
    k8s skipped by ``--no-k8s``.
    """
    run = V2Run(root, account=ACCT_MAIN, regions=regions, k8s=False)
    g = run.unit("global")
    iam = Iam(ACCT_MAIN)
    oidc = iam.oidc_provider("token.actions.githubusercontent.com")
    iam.saml_provider("ExampleIdP")
    boundary = {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
    dev = iam.user("demo-dev", access_keys=1, login=True, mfa=True, boundary=boundary,
                   inline={"p": [allow(["ec2:Describe*"], "*")]})
    iam.boundary_file("User", "demo-dev", boundary)
    iam.user_credentials("demo-dev", ssh_keys=1, service_credentials=["codecommit.amazonaws.com"])
    iam.user("demo-ci")
    iam.user_credentials("demo-ci", errors=[collection_error("iam:ListSSHPublicKeys", "denied")])
    iam.managed("demo-app-policy", [allow(["s3:GetObject"], "arn:aws:s3:::demo-v2-data/*")], customer=True,
                version="v2")
    iam.policy_version("demo-app-policy", "v1", [allow(["s3:*"], "*")])
    iam.role("demo-app-role", trust({"Service": "ec2.amazonaws.com"}), attached=["demo-app-policy"])
    iam.role("demo-admin-role", trust({"AWS": dev}), attached=["AdministratorAccess"])
    iam.role("demo-gha-role", trust({"Federated": oidc}, "sts:AssumeRoleWithWebIdentity",
                                    {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:example-org/*"}}))
    prof = iam.instance_profile("demo-app-profile", ["demo-app-role"])
    iam.write(g, layout="gaad")
    run.coverage("iam", "global", calls=[
        {"api": "iam:GetAccountAuthorizationDetails", "primary": True, "items": 9, "pages": 2},
        {"api": "iam:GetCredentialReport"}, {"api": "iam:GenerateCredentialReport"},
        {"api": "iam:ListSSHPublicKeys", "status": "denied", "item": iam.arn("user", "demo-ci"),
         "optional": True}])
    buckets = [
        mark_item({"Name": "demo-v2-data", "CreationDate": TS_Z, "Region": regions[0]}, policy_status="absent"),
        mark_item({"Name": "demo-v2-locked", "CreationDate": TS_Z, "Region": regions[-1]},
                  collection_error("s3:GetBucketPolicy", "denied"), policy_status="denied",
                  unknown=["PolicyIsPublic"]),
    ]
    g.write("s3/buckets.json", buckets)
    run.coverage("s3", "global", calls=[
        {"api": "s3:ListBuckets", "primary": True, "items": 2, "pages": 1},
        {"api": "s3:GetBucketPolicy", "error_code": "NoSuchBucketPolicy", "not_configured": True},
        {"api": "s3:GetBucketPolicy", "status": "denied", "item": "arn:aws:s3:::demo-v2-locked"}])
    for n, region in enumerate(run.regions, start=1):
        r = run.unit(region)
        iid = f"i-0a1b2c3d4e5f6e{n:03d}"
        r.write("ec2/instances.json", [ec2_instance(iid, account=ACCT_MAIN, region=region, profile=prof,
                                                    subnet=f"subnet-0a1b2c3d4e5f6e{n:03d}",
                                                    vpc=f"vpc-0a1b2c3d4e5f6e{n:03d}")])
        run.coverage("ec2", region, calls=[{"api": "ec2:DescribeInstances", "primary": True, "items": 1,
                                            "pages": 1}])
        if n == 1:
            r.write("lambda/functions.json", [])
            run.coverage("lambda", region, status="denied")
        else:
            r.write("lambda/functions.json", [lambda_function("demo-v2-fn", account=ACCT_MAIN, region=region,
                                                              role=iam.arn("role", "demo-app-role"))])
            run.coverage("lambda", region, calls=[{"api": "lambda:ListFunctions", "primary": True, "items": 1}])
        run.skip("k8s", region, "disabled by --no-k8s")
    run.finalize()
    return run


# ── Scenario registry ────────────────────────────────────────────────────────
@dataclass
class Scenario:
    name: str
    description: str
    account: str
    layout: str                      # "single_region" | "all_mode"
    regions: List[str]
    build: Callable[[Path], None]
    expect_exception: bool = False
    extra_files: Dict[str, Any] = field(default_factory=dict)  # written next to tree/ (labels.json ...)

    @property
    def report_dirs(self) -> List[str]:
        """Where the baseline engine's analyze() runs (relative to the tree root)."""
        if self.layout == "all_mode":
            return [f"{self.account}/global"]
        return [f"{self.account}/{self.regions[0]}"]

    @property
    def scope_dirs(self) -> List[str]:
        if self.layout == "all_mode":
            return [f"{self.account}/global"] + [f"{self.account}/{r}" for r in self.regions]
        return [f"{self.account}/{self.regions[0]}"]

    def meta(self) -> Dict[str, Any]:
        return {"name": self.name, "description": self.description, "account": self.account,
                "layout": self.layout, "regions": list(self.regions), "report_dirs": self.report_dirs,
                "scope_dirs": self.scope_dirs, "expect_exception": self.expect_exception,
                "baseline": "d13c215"}


SCENARIOS: Dict[str, Scenario] = {}


def scenario(name: str, description: str, account: str, layout: str, regions: Sequence[str],
             expect_exception: bool = False, extra_files: Optional[Dict[str, Any]] = None):
    def deco(fn: Callable[[Path], None]):
        SCENARIOS[name] = Scenario(name, description, account, layout, list(regions), fn,
                                   expect_exception, dict(extra_files or {}))
        return fn
    return deco


def _finish_single(scope: Scope) -> None:
    write_manifest(scope.path, account=scope.account, mode="single_region", region=scope.name)


# 1 ─ single_region_minimal (internal-docs/repro/dev_golden_demo.py) ─────────
@scenario("single_region_minimal",
          "dev_golden_demo: alice (ssm:StartSession on *), admin role trusting alice, app role + instance "
          "profile, 3 EC2 instances running as app (F-003 shape: 1 of 3 CAN_CONNECT edges).",
          ACCT_ALT, "single_region", ["eu-west-2"])
def build_single_region_minimal(root: Path, single_obj_trust: bool = False) -> None:
    s = Scope(root, ACCT_ALT, "eu-west-2")
    iam = Iam(ACCT_ALT)
    alice = iam.user("alice", inline={"p": [allow(["ssm:StartSession"], "*")]})
    iam.role("admin", trust({"AWS": alice}, single_object=single_obj_trust), attached=["AdministratorAccess"])
    iam.role("app", trust({"Service": "ec2.amazonaws.com"}))
    prof = iam.instance_profile("app", ["app"])
    iam.write(s)
    s.write("ec2/instances.json", [ec2_instance(f"i-0a1b2c3d4e5f6000{n}", account=ACCT_ALT, region=s.region,
                                                profile=prof) for n in range(3)])
    _finish_single(s)


# 2 ─ all_mode (global + eu-west-1 + eu-west-2) ──────────────────────────────
@scenario("all_mode",
          "--all layout: global (iam, s3, cloudfront, waf_cloudfront, route53) plus eu-west-1 and eu-west-2 "
          "with EC2, Lambda, Secrets Manager, SSM, KMS and EKS data. analyze() runs on global/ only.",
          ACCT_ALT, "all_mode", ["eu-west-1", "eu-west-2"])
def build_all_mode(root: Path) -> None:
    acct = ACCT_ALT
    g = Scope(root, acct, "global")
    iam = Iam(acct)
    dev = iam.user("dev", access_keys=1, inline={"p": [allow(["ec2:*"], "*")]})
    iam.user("auditor", attached=["ReadOnlyAccess"], mfa=True, login=True)
    iam.role("AppRole", trust({"Service": "ec2.amazonaws.com"}), inline={"p": [allow(
        ["secretsmanager:GetSecretValue", "lambda:UpdateFunctionCode", "ssm:GetParameter", "kms:Decrypt"], "*")]})
    iam.role("demo-admin", trust({"AWS": dev}), attached=["AdministratorAccess"])
    iam.role("demo-lambda-exec", trust({"Service": "lambda.amazonaws.com"}),
             inline={"logs": [allow(["logs:CreateLogStream", "logs:PutLogEvents"], "*")]})
    iam.role("demo-eks-cluster", trust({"Service": "eks.amazonaws.com"}))
    iam.role("demo-eks-node", trust({"Service": "ec2.amazonaws.com"}))
    iam.role("demo-irsa-west1", trust({"Federated": f"arn:aws:iam::{acct}:oidc-provider/oidc.eks.eu-west-1."
                                                    f"amazonaws.com/id/{_letters('oidc' + 'demo-eks-west1', 32)}"},
                                      "sts:AssumeRoleWithWebIdentity"), attached=["AdministratorAccess"])
    prof = iam.instance_profile("AppProfile", ["AppRole"])
    iam.write(g)
    buckets = [
        s3_bucket(g, "demo-all-mode-logs", region="eu-west-1",
                  policy=resource_policy(grant({"Service": "logging.s3.amazonaws.com"}, "s3:PutObject",
                                               "arn:aws:s3:::demo-all-mode-logs/*"))),
        s3_bucket(g, "demo-all-mode-data", region="eu-west-2", versioning={"Status": "Enabled"},
                  public_access_block={"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                       "BlockPublicPolicy": True, "RestrictPublicBuckets": True}),
    ]
    g.write("s3/buckets.json", buckets)
    g.write("cloudfront/distributions.json", [])
    for f in WAF_FILES:
        g.write(f"waf_cloudfront/{f}", [])
    g.write("route53/resources.json", [])

    for region, n in (("eu-west-1", 1), ("eu-west-2", 2)):
        r = Scope(root, acct, region)
        write_empty_regional(r, skip={"vpc", "sg", "ec2", "eks", "secretsmanager", "ssm", "lambda", "kms"})
        vpc = f"vpc-0a1b2c3d4e5f6{n:04d}"
        pub, priv, igw = f"subnet-0a1b2c3d4e5f6c{n:03d}", f"subnet-0a1b2c3d4e5f6d{n:03d}", f"igw-0a1b2c3d4e5f6{n:04d}"
        vpc_network(r, vpc=vpc, public_subnet=pub, private_subnet=priv, igw=igw)
        sg_id = f"sg-0a1b2c3d4e5f6b{n:03d}"
        r.write("sg/security_groups.json", [security_group(sg_id, f"demo-web-{region}", vpc=vpc, inbound=[
            sg_rule("tcp", 443, cidrs=["0.0.0.0/0"])], attached_instances=[f"i-0a1b2c3d4e5f6a{n:03d}"])])
        r.write("ec2/instances.json", [ec2_instance(
            f"i-0a1b2c3d4e5f6a{n:03d}", account=acct, region=region, profile=prof, http_tokens="optional",
            public_ip=f"203.0.113.{10 + n}", subnet=pub, vpc=vpc, sgs=[{"GroupId": sg_id, "GroupName": "demo-web"}],
            tags={"Name": f"demo-web-{region}"})])
        key = kms_key(f"1a2b3c4d-aaaa-4bbb-8ccc-0a0b0c0d0e0{n}", account=acct, region=region,
                      aliases=[f"alias/demo-{region}"])
        r.write("kms/keys.json", [key])
        r.write(f"kms/key_policies/{key['KeyId']}.json", kms_policy_file(key, resource_policy(
            grant({"AWS": f"arn:aws:iam::{acct}:root"}, "kms:*"))))
        sec = secret(f"demo/{region}/db", account=acct, region=region, kms_key=key["Arn"])
        r.write("secretsmanager/secrets.json", [sec])
        r.write("ssm/parameters.json", [ssm_parameter(f"/demo/{region}/db_password", account=acct, region=region)])
        fn = lambda_function(f"demo-fn-{region}", account=acct, region=region,
                             role=f"arn:aws:iam::{acct}:role/demo-lambda-exec", env_names=["STAGE"])
        r.write("lambda/functions.json", [fn])
        cluster_name = f"demo-eks-west{n}"
        cluster = eks_cluster(cluster_name, account=acct, region=region,
                              role_arn=f"arn:aws:iam::{acct}:role/demo-eks-cluster")
        r.write("eks/clusters.json", [cluster])
        r.write("eks/nodegroups.json", {cluster_name: [{"nodegroupName": f"demo-ng-{n}",
                                                        "nodegroupArn": f"arn:aws:eks:{region}:{acct}:nodegroup/"
                                                                        f"{cluster_name}/demo-ng-{n}/abcd",
                                                        "clusterName": cluster_name,
                                                        "nodeRole": f"arn:aws:iam::{acct}:role/demo-eks-node",
                                                        "status": "ACTIVE"}]})
        r.write("eks/fargate_profiles.json", {cluster_name: []})
        r.write("eks/addons.json", {cluster_name: []})
        kdir = f"k8s/{cluster_name}"
        r.write(f"{kdir}/cluster_info.json", {"name": cluster_name, "endpoint": cluster["endpoint"],
                                              "auth_status": "ok", "version": {"major": "1", "minor": "30",
                                                                               "git_version": "v1.30.0-eks",
                                                                               "platform": "linux/amd64"}})
        r.write(f"{kdir}/namespaces.json", [k8s_namespace("default"), k8s_namespace("apps")])
        irsa = f"arn:aws:iam::{acct}:role/demo-irsa-west1" if n == 1 else None
        r.write(f"{kdir}/service_accounts.json", [k8s_sa("default", "apps"), k8s_sa("apps-sa", "apps",
                                                                                     role_arn=irsa)])
        r.write(f"{kdir}/pods.json", [k8s_pod(f"apps-{n}", "apps", sa="apps-sa", labels={"app": "apps"})])
        for fname in ("roles", "cluster_roles", "role_bindings", "cluster_role_bindings", "secrets",
                      "services", "ingresses"):
            r.write(f"{kdir}/{fname}.json", [])
    write_manifest(root / acct, account=acct, mode="all_regions", region=None,
                   regions=["eu-west-1", "eu-west-2"])


# 3 ─ malformed (F-002 characterisation) ─────────────────────────────────────
ERR_DENIED = ("An error occurred (AccessDenied) when calling the {op} operation: User: "
              "arn:aws:iam::123456789012:user/demo-operator is not authorized to perform: {action}")


@scenario("malformed",
          "Single-object Statement in a trust policy and a bucket policy, {\"Error\"} stubs in every "
          "attached-policy map, error files and empty lists. The baseline engine raises (F-002).",
          ACCT_MAIN, "single_region", ["eu-west-2"], expect_exception=True)
def build_malformed(root: Path, single_object: bool = True) -> None:
    acct = ACCT_MAIN
    s = Scope(root, acct, "eu-west-2")
    iam = Iam(acct)
    iam.user("example-user", access_keys=1, inline={"p": [allow("s3:GetObject", "*")],
                                                    "denied": {"Error": ERR_DENIED.format(
                                                        op="GetUserPolicy", action="iam:GetUserPolicy")}})
    iam.user("example-user-noread")
    iam.group("example-group", inline={"g": [allow("sqs:SendMessage", "*")]})
    iam.role("example-single-stmt", trust({"Service": "lambda.amazonaws.com"}, single_object=single_object),
             inline={"p": [allow("lambda:InvokeFunction", "*")]})
    iam.role("example-string-trust", json.dumps(trust({"AWS": f"arn:aws:iam::{acct}:root"})))
    iam.role("example-empty-trust", {})
    iam.managed("example-customer", [allow("ec2:Describe*", "*")], customer=True)
    # Error stubs in every per-entity map (encoding C) and users.json sibling *Error keys (D)
    iam.user_attached["example-user"] = {"Error": ERR_DENIED.format(op="ListAttachedUserPolicies",
                                                                    action="iam:ListAttachedUserPolicies")}
    iam.user_attached["example-user-noread"] = []
    iam.role_attached["example-single-stmt"] = {"Error": ERR_DENIED.format(op="ListAttachedRolePolicies",
                                                                           action="iam:ListAttachedRolePolicies")}
    iam.role_attached["example-string-trust"] = [{"PolicyName": "example-customer",
                                                  "PolicyArn": f"arn:aws:iam::{acct}:policy/example-customer"}]
    iam.group_attached["example-group"] = {"Error": ERR_DENIED.format(op="ListAttachedGroupPolicies",
                                                                      action="iam:ListAttachedGroupPolicies")}
    iam.user_groups["example-user"] = {"Error": ERR_DENIED.format(op="ListGroupsForUser",
                                                                  action="iam:ListGroupsForUser")}
    u = iam.users[1]
    for k in ("AccessKeys", "MFADevices", "HasLoginProfile"):
        u.pop(k, None)
    u["AccessKeysError"] = ERR_DENIED.format(op="ListAccessKeys", action="iam:ListAccessKeys")
    u["MFADevicesError"] = ERR_DENIED.format(op="ListMFADevices", action="iam:ListMFADevices")
    u["LoginProfileError"] = ERR_DENIED.format(op="GetLoginProfile", action="iam:GetLoginProfile")
    iam.extra_files["policy_documents/example-denied_error.json"] = {
        "PolicyName": "example-denied", "PolicyArn": f"arn:aws:iam::{acct}:policy/example-denied",
        "Error": ERR_DENIED.format(op="GetPolicyVersion", action="iam:GetPolicyVersion")}
    iam.override("instance_profiles.json", {"Error": ERR_DENIED.format(op="ListInstanceProfiles",
                                                                       action="iam:ListInstanceProfiles")})
    iam.override("account_summary.json", {"Error": ERR_DENIED.format(op="GetAccountSummary",
                                                                     action="iam:GetAccountSummary")})
    iam.override("account_password_policy.json", {"Status": "No password policy configured"})
    iam.write(s)

    bucket_policy = {"Version": "2012-10-17", "Statement": grant("*", "s3:GetObject",
                                                                 "arn:aws:s3:::example-malformed-bucket/*")}
    if not single_object:
        bucket_policy["Statement"] = [bucket_policy["Statement"]]
    s.write("s3/buckets.json", [
        s3_bucket(s, "example-malformed-bucket", policy=bucket_policy),
        s3_bucket(s, "example-region-error", region_error=ERR_DENIED.format(op="GetBucketLocation",
                                                                            action="s3:GetBucketLocation")),
    ])
    s.write("s3/encryption/example-region-error.json", {"Rules": []})
    # file-level error encodings (B / B')
    s.write("secretsmanager/secrets.json", {"Error": ERR_DENIED.format(op="ListSecrets",
                                                                       action="secretsmanager:ListSecrets")})
    s.write("ssm/parameters.json", [])
    s.write("lambda/functions.json", {"Error": ERR_DENIED.format(op="ListFunctions", action="lambda:ListFunctions")})
    s.write("kms/keys.json", [])
    s.write("ec2/instances.json", [])
    s.write("sg/security_groups.json", [])
    for f in VPC_FILES:
        s.write(f"vpc/{f}", [])
    s.write("glue/resources.json", {"Error": "Glue enumeration failed"})
    s.write("rds/resources.json", {"Error": "RDS enumeration failed"})
    s.write("sns/resources.json", {"Error": ERR_DENIED.format(op="ListTopics", action="sns:ListTopics")})
    s.write("sqs/resources.json", [])
    s.write("cognito/resources.json", [])
    s.write("ebs/resources.json", [])
    s.write("elb/resources.json", {"Error": "ELB enumeration failed"})
    s.write("route53/resources.json", [])
    # eks: one cluster record that failed DescribeCluster (D) and one with k8s {"error"} dumps (H)
    s.write("eks/clusters.json", [
        {"name": "demo-err", "Error": ERR_DENIED.format(op="DescribeCluster", action="eks:DescribeCluster")},
        eks_cluster("demo-unreachable", account=acct, region=s.region,
                    role_arn=f"arn:aws:iam::{acct}:role/example-single-stmt"),
    ])
    s.write("eks/nodegroups.json", {"demo-unreachable": {"Error": ERR_DENIED.format(op="ListNodegroups",
                                                                                     action="eks:ListNodegroups")}})
    s.write("eks/fargate_profiles.json", {"demo-unreachable": []})
    s.write("eks/addons.json", {"demo-unreachable": []})
    s.write("k8s/demo-unreachable/cluster_info.json", {"name": "demo-unreachable", "endpoint": "https://demo.invalid",
                                                       "auth_status": "ok"})
    for fname in ("namespaces", "pods", "service_accounts", "roles", "cluster_roles", "role_bindings",
                  "cluster_role_bindings", "secrets", "services", "ingresses"):
        s.write(f"k8s/demo-unreachable/{fname}.json", {"error": f"{fname}: ApiException: (403) Forbidden"})
    _finish_single(s)


@scenario("malformed_stubs",
          "Same as malformed but with list-shaped Statements, so analyze() completes and the golden shows how "
          "the baseline treats {\"Error\"} stubs, error files and empty lists.",
          ACCT_MAIN, "single_region", ["eu-west-2"])
def build_malformed_stubs(root: Path) -> None:
    build_malformed(root, single_object=False)


# 4 ─ eks_irsa ────────────────────────────────────────────────────────────────
@scenario("eks_irsa",
          "One EKS cluster with a nodegroup, 2 IRSA service accounts (admin and read-only roles), RBAC bindings "
          "incl. cluster-admin, privileged/hostNetwork/hostPID pods, default-SA pods, LoadBalancer service and "
          "ingresses with and without auth annotations, secret mounts and a secrets.json annotation canary.",
          ACCT_MAIN, "single_region", ["eu-west-2"])
def build_eks_irsa(root: Path) -> None:
    acct, region = ACCT_MAIN, "eu-west-2"
    s = Scope(root, acct, region)
    iam = Iam(acct)
    cluster_role = iam.arn("role", "demo-eks-cluster-role")
    cluster = eks_cluster("demo-eks", account=acct, region=region, role_arn=cluster_role)
    oidc = oidc_provider_arn(acct, cluster)
    issuer = cluster["identity"]["oidc"]["issuer"].replace("https://", "")
    iam.role("demo-eks-cluster-role", trust({"Service": "eks.amazonaws.com"}),
             attached=[iam.managed("AmazonEKSClusterPolicy", [allow(["ec2:Describe*", "elasticloadbalancing:*"],
                                                                    "*")])])
    iam.role("demo-eks-node-role", trust({"Service": "ec2.amazonaws.com"}),
             attached=[iam.managed("AmazonEKSWorkerNodePolicy", [allow(["ec2:Describe*", "eks:DescribeCluster"],
                                                                       "*")])])
    iam.role("demo-irsa-admin", trust({"Federated": oidc}, "sts:AssumeRoleWithWebIdentity",
                                      {"StringEquals": {f"{issuer}:sub": "system:serviceaccount:payments:payments-sa",
                                                        f"{issuer}:aud": "sts.amazonaws.com"}}),
             attached=["AdministratorAccess"])
    iam.role("demo-irsa-reader", trust({"Federated": oidc}, "sts:AssumeRoleWithWebIdentity",
                                       {"StringLike": {f"{issuer}:sub": "system:serviceaccount:web:*"}}),
             inline={"read": [allow(["s3:GetObject", "s3:ListBucket"],
                                    ["arn:aws:s3:::demo-eks-data", "arn:aws:s3:::demo-eks-data/*"])]})
    iam.user("demo-platform-engineer", inline={"eks": [allow(["eks:DescribeCluster", "eks:ListClusters"], "*")]})
    iam.write(s)
    s.write("s3/buckets.json", [s3_bucket(s, "demo-eks-data")])
    s.write("eks/clusters.json", [cluster])
    s.write("eks/nodegroups.json", {"demo-eks": [{
        "nodegroupName": "demo-ng", "nodegroupArn": f"arn:aws:eks:{region}:{acct}:nodegroup/demo-eks/demo-ng/abcd",
        "clusterName": "demo-eks", "version": "1.30", "status": "ACTIVE", "capacityType": "ON_DEMAND",
        "instanceTypes": ["t3.large"], "nodeRole": iam.arn("role", "demo-eks-node-role"),
        "subnets": ["subnet-0a1b2c3d4e5f6aaaa"], "scalingConfig": {"minSize": 1, "maxSize": 3, "desiredSize": 2}}]})
    s.write("eks/fargate_profiles.json", {"demo-eks": []})
    s.write("eks/addons.json", {"demo-eks": [{"addonName": "vpc-cni", "clusterName": "demo-eks", "status": "ACTIVE",
                                              "addonVersion": "v1.18.0-eksbuild.1"}]})
    k = "k8s/demo-eks"
    s.write(f"{k}/cluster_info.json", {"name": "demo-eks", "endpoint": cluster["endpoint"], "auth_status": "ok",
                                       "version": {"major": "1", "minor": "30", "git_version": "v1.30.0-eks",
                                                   "platform": "linux/amd64"}})
    s.write(f"{k}/namespaces.json", [k8s_namespace(n) for n in ("default", "kube-system", "payments", "web")])
    s.write(f"{k}/service_accounts.json", [
        k8s_sa("default", "default"), k8s_sa("default", "payments"), k8s_sa("default", "kube-system"),
        k8s_sa("payments-sa", "payments", role_arn=iam.arn("role", "demo-irsa-admin")),
        k8s_sa("web-sa", "web", role_arn=iam.arn("role", "demo-irsa-reader")),
        k8s_sa("ci-deployer", "kube-system"),
    ])
    env_canary = [{"name": "DB_PASSWORD", "value": "AE-ENV-CANARY-not-a-real-secret", "value_from": None},
                  {"name": "API_TOKEN", "value": None,
                   "value_from": {"secret_key_ref": {"name": "db-creds", "key": "token"}}}]
    s.write(f"{k}/pods.json", [
        k8s_pod("payments-api-0", "payments", sa="payments-sa", labels={"app": "payments"},
                secret_volumes=["db-creds"], env=env_canary),
        k8s_pod("web-frontend-0", "web", sa="web-sa", labels={"app": "web"}),
        k8s_pod("node-debugger", "kube-system", sa=None, privileged=True, host_network=True, host_pid=True),
        k8s_pod("legacy-app", "default", sa="default", labels={"app": "legacy"}),
    ])
    s.write(f"{k}/roles.json", [k8s_role("secret-reader", "payments",
                                         [{"resources": ["secrets"], "verbs": ["get", "list"]}])])
    s.write(f"{k}/cluster_roles.json", [
        k8s_role("cluster-admin", None, [{"api_groups": ["*"], "resources": ["*"], "verbs": ["*"]}]),
        k8s_role("view", None, [{"resources": ["pods", "services"], "verbs": ["get", "list", "watch"]}]),
        k8s_role("demo-wildcard", None, [{"resources": ["*"], "verbs": ["*"]}]),
    ])
    s.write(f"{k}/role_bindings.json", [
        k8s_binding("read-secrets", "payments", "Role", "secret-reader",
                    [{"kind": "ServiceAccount", "name": "payments-sa", "namespace": "payments"}]),
        k8s_binding("web-view", "web", "ClusterRole", "view",
                    [{"kind": "ServiceAccount", "name": "web-sa", "namespace": "web"}]),
    ])
    s.write(f"{k}/cluster_role_bindings.json", [
        k8s_binding("ci-deployer-admin", None, "ClusterRole", "cluster-admin",
                    [{"kind": "ServiceAccount", "name": "ci-deployer", "namespace": "kube-system"},
                     {"kind": "User", "name": "demo-admin@example.com"}]),
        k8s_binding("wildcard-binding", None, "ClusterRole", "demo-wildcard",
                    [{"kind": "Group", "name": "system:masters"}]),
    ])
    s.write(f"{k}/secrets.json", [{
        "name": "db-creds", "namespace": "payments", "type": "Opaque", "creation_timestamp": TS,
        "annotations": {"kubectl.kubernetes.io/last-applied-configuration":
                        "{\"apiVersion\":\"v1\",\"data\":{\"password\":\"QUUtU0VDUkVULUNBTkFSWQ==\"},"
                        "\"kind\":\"Secret\",\"metadata\":{\"name\":\"db-creds\",\"namespace\":\"payments\"}}"}}])
    s.write(f"{k}/services.json", [
        k8s_service("web-lb", "web", svc_type="LoadBalancer", selector={"app": "web"}),
        k8s_service("payments-svc", "payments", selector={"app": "payments"}),
    ])
    s.write(f"{k}/ingresses.json", [
        k8s_ingress("web-ingress", "web", "web-lb"),
        k8s_ingress("payments-ingress", "payments", "payments-svc",
                    annotations={"alb.ingress.kubernetes.io/auth-type": "cognito"}),
    ])
    _finish_single(s)


# 5 ─ data_services (every non-core collector) ────────────────────────────────
@scenario("data_services",
          "Every non-core service with data: secretsmanager, ssm, lambda, kms, ecs, cloudformation, glue, "
          "codebuild, sagemaker, sns, sqs, ecr, rds, dynamodb, apigateway, cognito, ebs, elb, route53 (with "
          "public and cross-account resource policies), plus cloudtrail, cloudfront, waf and flowlogs files.",
          ACCT_MAIN, "single_region", ["eu-west-2"])
def build_data_services(root: Path) -> None:
    acct, region = ACCT_MAIN, "eu-west-2"
    s = Scope(root, acct, region)
    iam = Iam(acct)
    key = kms_key("4b2c1a3d-aaaa-4bbb-8ccc-1d2e3f4a5b6c", account=acct, region=region, aliases=["alias/demo-app"],
                  grants=[{"GrantId": _hex("grant1", 64), "GranteePrincipal": iam.arn("role", "demo-app-role"),
                           "Operations": ["Decrypt", "GenerateDataKey"]},
                          {"GrantId": _hex("grant2", 64), "GranteePrincipal": "rds.eu-west-2.amazonaws.com",
                           "Operations": ["Decrypt"]}])
    aws_key = kms_key("9f8e7d6c-aaaa-4bbb-8ccc-6c5b4a3f2e1d", account=acct, region=region, manager="AWS",
                      aliases=["alias/aws/ssm"], description="Default key that protects my SSM parameters")
    sec_db = secret("demo/db-password", account=acct, region=region, kms_key=key["Arn"], rotation=True)
    sec_api = secret("demo/api-token", account=acct, region=region)
    fn_etl = lambda_function("demo-etl", account=acct, region=region, role=iam.arn("role", "demo-lambda-exec"),
                             url_auth="AWS_IAM", env_names=["DB_HOST", "STAGE"])
    fn_pub = lambda_function("demo-public-fn", account=acct, region=region, role=iam.arn("role", "demo-lambda-exec"),
                             url_auth="NONE")
    topic = f"arn:aws:sns:{region}:{acct}:demo-topic"
    queue = f"arn:aws:sqs:{region}:{acct}:demo-queue"
    table = f"arn:aws:dynamodb:{region}:{acct}:table/demo-table"

    iam.role("demo-app-role", trust({"Service": "ecs-tasks.amazonaws.com"}), inline={"app": [
        allow(["secretsmanager:GetSecretValue"], f"arn:aws:secretsmanager:{region}:{acct}:secret:demo/*"),
        allow(["ssm:GetParameter", "ssm:GetParameters"], f"arn:aws:ssm:{region}:{acct}:parameter/demo/*"),
        allow(["kms:Decrypt"], key["Arn"]),
        allow(["sqs:SendMessage", "sqs:ReceiveMessage"], queue),
        allow(["sns:Publish"], topic),
        allow(["dynamodb:GetItem", "dynamodb:PutItem"], table),
        allow(["lambda:InvokeFunction"], fn_etl["FunctionArn"]),
    ]})
    for rname, svc in (("demo-lambda-exec", "lambda"), ("demo-ecs-exec", "ecs-tasks"),
                       ("demo-cfn-role", "cloudformation"), ("demo-glue-role", "glue"),
                       ("demo-codebuild-role", "codebuild"), ("demo-sagemaker-role", "sagemaker")):
        iam.role(rname, trust({"Service": f"{svc}.amazonaws.com"}))
    iam.role("demo-cognito-auth", trust({"Federated": "cognito-identity.amazonaws.com"},
                                        "sts:AssumeRoleWithWebIdentity",
                                        {"StringEquals": {"cognito-identity.amazonaws.com:aud":
                                                          "eu-west-2:5e6f7a8b-aaaa-4bbb-8ccc-9d0e1f2a3b4c"}}),
             inline={"p": [allow(["s3:GetObject"], "arn:aws:s3:::demo-data-bucket/*")]})
    iam.user("demo-deployer", access_keys=1, inline={"deploy": [
        allow(["iam:PassRole"], "*"),
        allow(["lambda:UpdateFunctionCode", "lambda:GetFunction"], "*"),
        allow(["ecs:RunTask", "ecs:RegisterTaskDefinition"], "*"),
        allow(["cloudformation:CreateStack", "cloudformation:UpdateStack"], "*"),
        allow(["codebuild:StartBuild"], f"arn:aws:codebuild:{region}:{acct}:project/demo-build"),
        allow(["glue:CreateJob", "glue:StartJobRun"], "*"),
        allow(["sagemaker:CreatePresignedNotebookInstanceUrl"], "*"),
        allow(["kms:PutKeyPolicy", "kms:CreateGrant"], key["Arn"]),
        allow(["sqs:*"], f"arn:aws:sqs:{region}:{acct}:demo-*"),
        allow(["dynamodb:Scan"], "*"),
    ]})
    iam.user("demo-analyst", attached=["ReadOnlyAccess"], login=True, mfa=True)
    iam.write(s)

    s.write("s3/buckets.json", [s3_bucket(s, "demo-data-bucket", encryption=kms_encryption(key["Arn"]))])
    s.write("secretsmanager/secrets.json", [sec_db, sec_api])
    s.write(f"secretsmanager/resource_policies/{safe_filename(sec_db['Name'])}.json", {
        "SecretArn": sec_db["ARN"], "SecretName": sec_db["Name"], "ResourcePolicy": resource_policy(
            grant({"AWS": f"arn:aws:iam::{ACCT_EXT}:root"}, "secretsmanager:GetSecretValue"),
            grant({"AWS": iam.arn("role", "demo-app-role")}, "secretsmanager:GetSecretValue"))})
    s.write(f"secretsmanager/resource_policies/{safe_filename(sec_api['Name'])}.json", {
        "SecretArn": sec_api["ARN"], "SecretName": sec_api["Name"], "ResourcePolicy": resource_policy(
            grant("*", "secretsmanager:GetSecretValue"))})
    s.write("ssm/parameters.json", [
        ssm_parameter("/demo/db/password", account=acct, region=region),
        ssm_parameter("/demo/app/config", account=acct, region=region, ptype="SecureString",
                      key_id="alias/aws/ssm"),
        ssm_parameter("/demo/api_key", account=acct, region=region),
        ssm_parameter("/other/feature-flags", account=acct, region=region, ptype="StringList"),
    ])
    s.write("lambda/functions.json", [fn_etl, fn_pub])
    s.write(f"lambda/resource_policies/{safe_filename(fn_etl['FunctionName'])}.json", lambda_policy_file(
        fn_etl, resource_policy(
            grant({"Service": "s3.amazonaws.com"}, "lambda:InvokeFunction", fn_etl["FunctionArn"],
                  {"ArnLike": {"AWS:SourceArn": "arn:aws:s3:::demo-data-bucket"}}),
            grant({"AWS": f"arn:aws:iam::{ACCT_ALT}:root"}, "lambda:InvokeFunction", fn_etl["FunctionArn"]))))
    s.write(f"lambda/resource_policies/{safe_filename(fn_pub['FunctionName'])}.json", lambda_policy_file(
        fn_pub, resource_policy(grant("*", "lambda:InvokeFunctionUrl", fn_pub["FunctionArn"],
                                      {"StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}}),
                                grant({"AWS": "*"}, "lambda:InvokeFunction", fn_pub["FunctionArn"]))))
    s.write("kms/keys.json", [key, aws_key])
    s.write(f"kms/key_policies/{key['KeyId']}.json", kms_policy_file(key, resource_policy(
        grant({"AWS": f"arn:aws:iam::{acct}:root"}, "kms:*", sid="Enable IAM User Permissions"),
        grant({"AWS": f"arn:aws:iam::{ACCT_EXT}:role/demo-partner"}, ["kms:Decrypt", "kms:DescribeKey"]),
        grant({"AWS": "*"}, ["kms:Decrypt"], "*", {"StringEquals": {"kms:CallerAccount": acct}}),
        grant({"Service": "logs.eu-west-2.amazonaws.com"}, ["kms:Encrypt"]))))
    s.write("ecs/resources.json", [compute_resource(
        "ecstask", f"arn:aws:ecs:{region}:{acct}:task-definition/demo-task:3", "demo-task",
        [iam.arn("role", "demo-app-role"), iam.arn("role", "demo-ecs-exec")])])
    s.write("cloudformation/resources.json", [compute_resource(
        "cfnstack", f"arn:aws:cloudformation:{region}:{acct}:stack/demo-stack/{_hex('stack', 8)}-aaaa-4bbb-8ccc-"
                    f"{_hex('stackid', 12)}", "demo-stack", [iam.arn("role", "demo-cfn-role")],
        StackStatus="CREATE_COMPLETE")])
    s.write("glue/resources.json", [
        compute_resource("gluejob", "demo-glue-job", "demo-glue-job", ["demo-glue-role"]),
        compute_resource("gluejob", "demo-dev-endpoint", "demo-dev-endpoint", [iam.arn("role", "demo-glue-role")]),
    ])
    s.write("codebuild/resources.json", [compute_resource(
        "codebuild", f"arn:aws:codebuild:{region}:{acct}:project/demo-build", "demo-build",
        [iam.arn("role", "demo-codebuild-role")])])
    s.write("sagemaker/resources.json", [compute_resource(
        "sagemaker", f"arn:aws:sagemaker:{region}:{acct}:notebook-instance/demo-notebook", "demo-notebook",
        [iam.arn("role", "demo-sagemaker-role")])])
    s.write("sns/resources.json", [
        policy_resource("sns", topic, "demo-topic", resource_policy(
            grant({"AWS": "*"}, "sns:Publish", topic, {"StringEquals": {"AWS:SourceOwner": acct}}),
            grant({"AWS": f"arn:aws:iam::{ACCT_EXT}:root"}, "sns:Subscribe", topic))),
        policy_resource("sns", f"arn:aws:sns:{region}:{acct}:demo-quiet-topic", "demo-quiet-topic", None),
    ])
    s.write("sqs/resources.json", [
        policy_resource("sqs", queue, "demo-queue", resource_policy(grant("*", "sqs:SendMessage", queue))),
        policy_resource("sqs", f"arn:aws:sqs:{region}:{acct}:demo-raw-policy", "demo-raw-policy",
                        {"_raw": "not-json"}),
    ])
    s.write("ecr/resources.json", [
        policy_resource("ecr", f"arn:aws:ecr:{region}:{acct}:repository/demo-repo", "demo-repo", resource_policy(
            grant({"AWS": f"arn:aws:iam::{ACCT_ALT}:root"}, ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]))),
        policy_resource("ecr", f"arn:aws:ecr:{region}:{acct}:repository/demo-public-repo", "demo-public-repo",
                        resource_policy(grant("*", ["ecr:BatchGetImage"]))),
        policy_resource("ecr", f"arn:aws:ecr:{region}:{acct}:repository/demo-private-repo", "demo-private-repo",
                        None),
    ])
    s.write("rds/resources.json", [
        {"Type": "rds", "Kind": "instance", "Arn": f"arn:aws:rds:{region}:{acct}:db:demo-db", "Name": "demo-db",
         "Public": False, "Encrypted": True, "KmsKeyId": key["Arn"], "IAMAuth": True, "Engine": "postgres"},
        {"Type": "rds", "Kind": "snapshot", "Arn": f"arn:aws:rds:{region}:{acct}:snapshot:demo-db-snap",
         "Name": "demo-db-snap", "PublicSnapshot": False, "Encrypted": True, "KmsKeyId": key["Arn"]},
    ])
    s.write("dynamodb/resources.json", [
        policy_resource("dynamodb", table, "demo-table", resource_policy(
            grant({"AWS": f"arn:aws:iam::{ACCT_EXT}:role/demo-partner"}, ["dynamodb:GetItem"], table))),
        policy_resource("dynamodb", f"arn:aws:dynamodb:{region}:{acct}:table/demo-open-table", "demo-open-table",
                        resource_policy(grant("*", ["dynamodb:Query"]))),
    ])
    s.write("apigateway/resources.json", [
        {"Type": "apigw", "Arn": f"arn:aws:apigateway:{region}::/restapis/a1b2c3d4e5", "Name": "demo-rest-api",
         "Protocol": "REST", "LambdaTargets": [fn_etl["FunctionArn"]], "HasAuthorizer": True},
        {"Type": "apigw", "Arn": f"arn:aws:apigateway:{region}::/apis/f6g7h8i9j0", "Name": "demo-http-api",
         "Protocol": "HTTP", "LambdaTargets": [fn_pub["FunctionArn"]], "HasAuthorizer": False},
    ])
    s.write("cognito/resources.json", [
        {"Type": "cognito", "Kind": "identity_pool", "Id": "eu-west-2:5e6f7a8b-aaaa-4bbb-8ccc-9d0e1f2a3b4c",
         "Name": "demo_pool", "AuthRole": iam.arn("role", "demo-cognito-auth"), "UnauthRole": None,
         "AllowUnauth": False},
        {"Type": "cognito", "Kind": "user_pool", "Id": "eu-west-2_EXAMPLEab", "Name": "demo-users"},
    ])
    s.write("ebs/resources.json", [
        {"Type": "ebssnapshot", "Id": "snap-0a1b2c3d4e5f6aaa1", "Name": "snap-0a1b2c3d4e5f6aaa1", "Public": False,
         "SharedAccounts": [ACCT_ALT], "Encrypted": True, "KmsKeyId": key["Arn"], "VolumeId": "vol-0a1b2c3d4e5faaa1"},
    ])
    s.write("elb/resources.json", [
        {"Type": "elb", "Arn": f"arn:aws:elasticloadbalancing:{region}:{acct}:loadbalancer/app/demo-alb/"
                               f"{_hex('alb', 16)}", "Name": "demo-alb", "Scheme": "internal",
         "DNSName": "internal-demo-alb.eu-west-2.elb.amazonaws.com", "LBType": "application",
         "Targets": [{"kind": "lambda", "id": fn_etl["FunctionArn"]}, {"kind": "ip", "id": "10.0.1.20"}]},
        {"Type": "elb", "Arn": "demo-classic-elb", "Name": "demo-classic-elb", "Scheme": "internal",
         "DNSName": "internal-demo-classic-elb.eu-west-2.elb.amazonaws.com", "LBType": "classic", "Targets": []},
    ])
    s.write("route53/resources.json", [{
        "Type": "route53zone", "Id": "Z0EXAMPLEZONEAAA", "Name": "example.com.", "Private": False, "RecordCount": 2,
        "Records": [{"Name": "example.com.", "Type": "NS", "Targets": ["ns-1.awsdns-00.org."]},
                    {"Name": "www.example.com.", "Type": "CNAME", "Targets": ["demo-alb.eu-west-2.elb.amazonaws.com"]}],
        "TakeoverCandidates": [{"Name": "www.example.com.", "Target": "demo-alb.eu-west-2.elb.amazonaws.com"}]}])
    # collectors the engine does not read (layout completeness)
    s.write("cloudtrail/trails.json", [{
        "Name": "demo-trail", "S3BucketName": "demo-trail-logs", "IsMultiRegionTrail": True,
        "HomeRegion": region, "TrailARN": f"arn:aws:cloudtrail:{region}:{acct}:trail/demo-trail",
        "LogFileValidationEnabled": True, "HasCustomEventSelectors": False, "IsOrganizationTrail": False,
        "Status": {"IsLogging": True}, "InsightSelectors": []}])
    s.write("cloudfront/distributions.json", [])
    for f in WAF_FILES:
        s.write(f"waf/{f}", [])
    s.write("flowlogs/flowlogs.json", [{"FlowLogId": "fl-0a1b2c3d4e5f6aaaa", "ResourceId": "vpc-0a1b2c3d4e5f6aaaa",
                                        "TrafficType": "ALL", "LogDestinationType": "s3",
                                        "FlowLogStatus": "ACTIVE"}])
    s.write("ec2/instances.json", [])
    s.write("sg/security_groups.json", [])
    for f in VPC_FILES:
        s.write(f"vpc/{f}", [])
    s.write("eks/clusters.json", [])
    _finish_single(s)


# 6 ─ cross_account ───────────────────────────────────────────────────────────
@scenario("cross_account",
          "Trusts to a same-named external role (F-039), external and same-account :root, ExternalId, GitHub "
          "OIDC, SAML, wildcard with and without conditions, a bare account-id principal and a JSON-string "
          "trust document; cross-account S3/Secrets/KMS grants.",
          ACCT_MAIN, "single_region", ["eu-west-2"])
def build_cross_account(root: Path) -> None:
    acct, region = ACCT_MAIN, "eu-west-2"
    s = Scope(root, acct, region)
    iam = Iam(acct)
    iam.role("deploy", trust({"AWS": f"arn:aws:iam::{ACCT_EXT}:role/deploy"}), attached=["AdministratorAccess"])
    iam.user("deploy", inline={"self": [allow(["sts:AssumeRole"], iam.arn("role", "deploy"))]})
    iam.role("audit", trust({"AWS": f"arn:aws:iam::{ACCT_ALT}:root"}, cond={"StringEquals": {
        "sts:ExternalId": "example-external-id"}}), attached=["ReadOnlyAccess"])
    iam.role("same-account-root", trust({"AWS": f"arn:aws:iam::{acct}:root"}),
             inline={"p": [allow(["s3:*"], "*")]})
    gh_oidc = f"arn:aws:iam::{acct}:oidc-provider/token.actions.githubusercontent.com"
    iam.role("gha-deploy", trust({"Federated": gh_oidc},
                                 "sts:AssumeRoleWithWebIdentity",
                                 {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:example-org/*"},
                                  "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}),
             attached=["AdministratorAccess"])
    iam.role("saml-admin", trust({"Federated": f"arn:aws:iam::{acct}:saml-provider/ExampleIdP"},
                                 "sts:AssumeRoleWithSAML",
                                 {"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}}),
             attached=["AdministratorAccess"])
    iam.role("wildcard-org", trust({"AWS": "*"}, cond={"StringEquals": {"aws:PrincipalOrgID": "o-exampleorg1"}}))
    iam.role("wildcard-open", trust("*"), inline={"p": [allow(["sqs:*"], "*")]})
    iam.role("bare-account", trust({"AWS": ACCT_EXT}))
    iam.role("multi-principal", trust({"AWS": [f"arn:aws:iam::{ACCT_EXT}:user/partner",
                                               f"arn:aws:iam::{acct}:user/deploy"],
                                       "Service": ["ec2.amazonaws.com", "lambda.amazonaws.com"]}))
    iam.role("string-trust", json.dumps(trust({"AWS": f"arn:aws:iam::{ACCT_ZERO}:root"})))
    iam.write(s)
    s.write("s3/buckets.json", [s3_bucket(s, "demo-shared-bucket", policy=resource_policy(
        grant({"AWS": f"arn:aws:iam::{ACCT_EXT}:role/deploy"}, ["s3:GetObject", "s3:ListBucket"],
              ["arn:aws:s3:::demo-shared-bucket", "arn:aws:s3:::demo-shared-bucket/*"]),
        grant({"AWS": iam.arn("role", "audit")}, "s3:GetObject", "arn:aws:s3:::demo-shared-bucket/*"),
        grant({"Service": "cloudtrail.amazonaws.com"}, "s3:PutObject", "arn:aws:s3:::demo-shared-bucket/*"),
        {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::demo-shared-bucket/*",
         "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
    ))])
    sec = secret("demo/shared", account=acct, region=region)
    s.write("secretsmanager/secrets.json", [sec])
    s.write(f"secretsmanager/resource_policies/{safe_filename(sec['Name'])}.json", {
        "SecretArn": sec["ARN"], "SecretName": sec["Name"], "ResourcePolicy": resource_policy(
            grant({"AWS": f"arn:aws:iam::{ACCT_EXT}:role/deploy"}, "secretsmanager:GetSecretValue"))})
    key = kms_key("2c3d4e5f-aaaa-4bbb-8ccc-6a7b8c9d0e1f", account=acct, region=region, aliases=["alias/demo-shared"])
    s.write("kms/keys.json", [key])
    s.write(f"kms/key_policies/{key['KeyId']}.json", kms_policy_file(key, resource_policy(
        grant({"AWS": f"arn:aws:iam::{acct}:root"}, "kms:*"),
        grant({"AWS": f"arn:aws:iam::{ACCT_EXT}:role/deploy"}, ["kms:Decrypt"]))))
    _finish_single(s)


# 7 ─ public_exposure ─────────────────────────────────────────────────────────
@scenario("public_exposure",
          "Public bucket policy and ACL, public SG + IGW route, IMDSv1, an instance profile whose name differs "
          "from its role, an unresolvable profile, Lambda URL AuthType NONE, public EBS/RDS snapshots, public "
          "unencrypted RDS, internet-facing ELB, unauthenticated Cognito role, dangling Route53 record.",
          ACCT_MAIN, "single_region", ["eu-west-2"])
def build_public_exposure(root: Path) -> None:
    acct, region = ACCT_MAIN, "eu-west-2"
    s = Scope(root, acct, region)
    iam = Iam(acct)
    iam.role("demo-web-role", trust({"Service": "ec2.amazonaws.com"}),
             inline={"p": [allow(["s3:GetObject", "s3:PutObject"], "arn:aws:s3:::demo-public-bucket/*")]})
    iam.role("demo-guest-role", trust({"Federated": "cognito-identity.amazonaws.com"},
                                      "sts:AssumeRoleWithWebIdentity",
                                      {"ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr":
                                                                  "unauthenticated"}}),
             inline={"p": [allow(["lambda:InvokeFunction"], "*")]})
    iam.role("demo-fn-role", trust({"Service": "lambda.amazonaws.com"}))
    iam.user("demo-ops", inline={"ops": [allow(["ec2:*"], "*"), allow(["ssm:StartSession"], "*")]},
             access_keys=2, key_status="Active")
    prof = iam.instance_profile("demo-web-profile", ["demo-web-role"])
    iam.write(s)
    vpc, igw = "vpc-0a1b2c3d4e5f6aaaa", "igw-0a1b2c3d4e5f"
    pub, priv = "subnet-0a1b2c3d4e5f6ab01", "subnet-0a1b2c3d4e5f6ab02"
    vpc_network(s, vpc=vpc, public_subnet=pub, private_subnet=priv, igw=igw)
    s.write("sg/security_groups.json", [
        security_group("sg-0a1b2c3d4e5f6eb01", "demo-web", vpc=vpc, inbound=[
            sg_rule("tcp", 22, cidrs=["0.0.0.0/0"], description="ssh from anywhere"),
            sg_rule("tcp", 443, cidrs6=["::/0"]),
            sg_rule("tcp", 8080, 8090, cidrs=["10.0.0.0/8"])], attached_instances=["i-0a1b2c3d4e5f6eb01"]),
        security_group("sg-0a1b2c3ddb", "demo-db", vpc=vpc, inbound=[
            sg_rule("tcp", 5432, groups=["sg-0a1b2c3d4e5f6eb01"])]),
        security_group("sg-0a1b2c3d4e5f6a110", "demo-wide-open", vpc=vpc, inbound=[sg_rule("-1", cidrs=["0.0.0.0/0"])]),
    ])
    s.write("ec2/instances.json", [
        ec2_instance("i-0a1b2c3d4e5f6eb01", account=acct, region=region, profile=prof, http_tokens="optional",
                     public_ip="203.0.113.10", subnet=pub, vpc=vpc,
                     sgs=[{"GroupId": "sg-0a1b2c3d4e5f6eb01", "GroupName": "demo-web"}], tags={"Name": "demo-web"}),
        ec2_instance("i-0a1b2c3ddb000002", account=acct, region=region, private_ip="10.0.2.20", subnet=priv,
                     vpc=vpc, sgs=[{"GroupId": "sg-0a1b2c3ddb", "GroupName": "demo-db"}], tags={"Name": "demo-db"}),
        ec2_instance("i-0a1b2c3d4e5f60f03", account=acct, region=region,
                     profile=iam.arn("instance-profile", "demo-deleted-profile"), http_tokens="optional",
                     public_ip="203.0.113.30", subnet=priv, vpc=vpc,
                     sgs=[{"GroupId": "sg-0a1b2c3d4e5f6a110", "GroupName": "demo-wide-open"}]),
    ])
    key_arn = f"arn:aws:kms:{region}:{acct}:key/3d4e5f6a-aaaa-4bbb-8ccc-7b8c9d0e1f2a"
    fn = lambda_function("demo-url-fn", account=acct, region=region, role=iam.arn("role", "demo-fn-role"),
                         url_auth="NONE")
    s.write("s3/buckets.json", [
        s3_bucket(s, "demo-public-bucket", policy=resource_policy(
            grant("*", "s3:GetObject", "arn:aws:s3:::demo-public-bucket/*")),
            acl=acl(acct, public_read=True),
            public_access_block={"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False,
                                 "RestrictPublicBuckets": False}),
        s3_bucket(s, "demo-vpce-bucket", policy=resource_policy(
            grant({"AWS": "*"}, ["s3:GetObject"], "arn:aws:s3:::demo-vpce-bucket/*",
                  {"StringEquals": {"aws:SourceVpce": "vpce-0a1b2c3d"}}))),
        s3_bucket(s, "demo-private-bucket", encryption=kms_encryption(key_arn), logging={"LoggingEnabled": False},
                  notifications={
                      "LambdaFunctionConfigurations": [{"Id": "n1", "LambdaFunctionArn": fn["FunctionArn"],
                                                        "Events": ["s3:ObjectCreated:*"]}],
                      "QueueConfigurations": [{"Id": "n2", "QueueArn": f"arn:aws:sqs:{region}:{acct}:demo-queue",
                                               "Events": ["s3:ObjectRemoved:*"]}],
                      "TopicConfigurations": [{"Id": "n3", "TopicArn": f"arn:aws:sns:{region}:{acct}:demo-topic",
                                               "Events": ["s3:ObjectCreated:Put"]}]}),
    ])
    s.write("lambda/functions.json", [fn])
    s.write(f"lambda/resource_policies/{safe_filename(fn['FunctionName'])}.json", lambda_policy_file(
        fn, resource_policy(grant("*", "lambda:InvokeFunctionUrl", fn["FunctionArn"]))))
    s.write("ebs/resources.json", [
        {"Type": "ebssnapshot", "Id": "snap-0a1b2c3d4e5f6bb01", "Name": "snap-0a1b2c3d4e5f6bb01", "Public": True,
         "SharedAccounts": [], "Encrypted": False, "KmsKeyId": None, "VolumeId": "vol-0a1b2c3d4e5faaa2"}])
    s.write("rds/resources.json", [
        {"Type": "rds", "Kind": "instance", "Arn": f"arn:aws:rds:{region}:{acct}:db:demo-public-db",
         "Name": "demo-public-db", "Public": True, "Encrypted": False, "KmsKeyId": None, "IAMAuth": False,
         "Engine": "mysql"},
        {"Type": "rds", "Kind": "snapshot", "Arn": f"arn:aws:rds:{region}:{acct}:snapshot:demo-public-snap",
         "Name": "demo-public-snap", "PublicSnapshot": True, "Encrypted": False, "KmsKeyId": None},
    ])
    s.write("elb/resources.json", [
        {"Type": "elb", "Arn": f"arn:aws:elasticloadbalancing:{region}:{acct}:loadbalancer/app/demo-public-alb/"
                               f"{_hex('palb', 16)}", "Name": "demo-public-alb", "Scheme": "internet-facing",
         "DNSName": "demo-public-alb.eu-west-2.elb.amazonaws.com", "LBType": "application",
         "Targets": [{"kind": "instance", "id": "i-0a1b2c3d4e5f6eb01"}, {"kind": "lambda", "id": fn["FunctionArn"]}]}])
    s.write("cognito/resources.json", [
        {"Type": "cognito", "Kind": "identity_pool", "Id": "eu-west-2:6f7a8b9c-aaaa-4bbb-8ccc-0d1e2f3a4b5c",
         "Name": "demo_guest_pool", "AuthRole": None, "UnauthRole": iam.arn("role", "demo-guest-role"),
         "AllowUnauth": True}])
    s.write("apigateway/resources.json", [
        {"Type": "apigw", "Arn": f"arn:aws:apigateway:{region}::/apis/k1l2m3n4o5", "Name": "demo-open-api",
         "Protocol": "HTTP", "LambdaTargets": [fn["FunctionArn"]], "HasAuthorizer": False}])
    s.write("route53/resources.json", [{
        "Type": "route53zone", "Id": "Z0EXAMPLEZONEBBB", "Name": "example.org.", "Private": False, "RecordCount": 1,
        "Records": [{"Name": "static.example.org.", "Type": "CNAME", "Targets": ["demo-gone.s3.amazonaws.com"]}],
        "TakeoverCandidates": [{"Name": "static.example.org.", "Target": "demo-gone.s3.amazonaws.com"}]}])
    _finish_single(s)


# 8 ─ poweruser_notaction ─────────────────────────────────────────────────────
@scenario("poweruser_notaction",
          "PowerUserAccess-shaped NotAction grants (role and via group), NotResource, explicit Deny quarantine and "
          "Deny iam:*, a read-only permission boundary (roles.json key + permission_boundaries/ file), and a "
          "condition-gated PassRole; plus resources that NotAction grants would reach (F-001 shape).",
          ACCT_MAIN, "single_region", ["eu-west-2"])
def build_poweruser_notaction(root: Path) -> None:
    acct, region = ACCT_MAIN, "eu-west-2"
    s = Scope(root, acct, region)
    iam = Iam(acct)
    boundary = {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
    ec2_trust = trust({"Service": "ec2.amazonaws.com"})
    iam.role("demo-poweruser", ec2_trust, attached=["PowerUserAccess"])
    iam.role("demo-quarantined", ec2_trust, inline={"p": [allow("*", "*"), deny("*", "*")]})
    iam.role("demo-deny-iam", ec2_trust, inline={"p": [allow("*", "*"), deny("iam:*", "*")]})
    iam.role("demo-boundary-capped", ec2_trust, inline={"p": [allow("*", "*")]},
             extra={"PermissionsBoundary": boundary})
    iam.boundary_file("Role", "demo-boundary-capped", boundary)
    iam.role("demo-passrole-gated", ec2_trust, inline={"p": [
        allow("iam:PassRole", "*", {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}),
        allow(["lambda:CreateFunction", "lambda:InvokeFunction"], "*")]})
    iam.role("demo-iam-notresource", ec2_trust, inline={"p": [
        {"Effect": "Allow", "Action": "iam:*", "NotResource": f"arn:aws:iam::{acct}:role/breakglass"}]})
    iam.role("demo-star-notresource", ec2_trust, inline={"p": [
        {"Effect": "Allow", "Action": "*", "NotResource": ["arn:aws:s3:::demo-notaction-data/*"]}]})
    iam.group("demo-power-group", attached=["PowerUserAccess"])
    iam.user("demo-notaction-user", groups=["demo-power-group"], login=True)
    iam.user("demo-boundary-user", inline={"p": [allow("*", "*")]}, boundary=boundary)
    iam.boundary_file("User", "demo-boundary-user", boundary)
    iam.write(s)
    key = kms_key("5e6f7a8b-aaaa-4bbb-8ccc-9c0d1e2f3a4b", account=acct, region=region, aliases=["alias/demo-na"])
    s.write("kms/keys.json", [key])
    s.write("s3/buckets.json", [s3_bucket(s, "demo-notaction-data")])
    sec = secret("demo/notaction", account=acct, region=region, kms_key=key["Arn"])
    s.write("secretsmanager/secrets.json", [sec])
    s.write("lambda/functions.json", [lambda_function("demo-na-fn", account=acct, region=region,
                                                      role=iam.arn("role", "demo-poweruser"))])
    s.write("ec2/instances.json", [ec2_instance("i-0a1b2c3d4e5f6ac01", account=acct, region=region)])
    _finish_single(s)


# 9 ─ hostile_strings (dashboard XSS canaries) ────────────────────────────────
@scenario("hostile_strings",
          "Resource names, tags, paths and descriptions carrying HTML/JS-looking canaries (window.__aeXssCanary), "
          "quotes, backslashes, unicode controls and JS prototype names (F-008, F-041, F-042). Filenames stay safe.",
          ACCT_MAIN, "single_region", ["eu-west-2"])
def build_hostile_strings(root: Path) -> None:
    acct, region = ACCT_MAIN, "eu-west-2"
    s = Scope(root, acct, region)
    iam = Iam(acct)
    H = HOSTILE_STRINGS
    iam.group("demo-hostile-group", inline={"g": [allow(["s3:GetObject", "lambda:InvokeFunction"], "*")]})
    for i, h in enumerate(H):
        iam.user(h, groups=["demo-hostile-group"], tags=[{"Key": "Name", "Value": h}, {"Key": h, "Value": "x"}],
                 access_keys=1 if i % 2 == 0 else 0)
    iam.role(H[0], trust({"AWS": iam.arn("user", H[1])}), attached=["AdministratorAccess"], description=H[2])
    iam.role("demo-hostile-path", trust({"Service": "ec2.amazonaws.com"}), path=f"/{H[3]}/", description=H[4])
    iam.managed(H[5], [allow(["sqs:SendMessage"], "*")], customer=True, version="v1",
                doc_filename="demo-hostile-policy")  # keep filenames safe; the name lives in the content
    iam.role("demo-hostile-attached", trust({"Service": "ec2.amazonaws.com"}), attached=[H[5]])
    for p in PROTO_NAMES:
        iam.user(p, inline={"p": [allow(["s3:ListBucket", "secretsmanager:GetSecretValue"], "*")]},
                 groups=["demo-hostile-group"])
        iam.role(p, trust({"AWS": iam.arn("user", p)}), inline={"p": [allow(["iam:PassRole", "ec2:RunInstances"],
                                                                            "*")]})
    iam.write(s)
    # Bucket and Kubernetes object names never contain "/" (AWS and Kubernetes reject it, and the node-id
    # scheme in docs/contracts/node-ids.md keys on it), so H[2] ("</script>...") stays out of those names.
    s.write("s3/buckets.json", [s3_bucket(s, h) for h in H[:4] if "/" not in h]
            + [s3_bucket(s, p) for p in PROTO_NAMES])
    s.write("ec2/instances.json", [
        ec2_instance("i-0a1b2c3d4e5f6bad1", account=acct, region=region, http_tokens="optional",
                     public_ip="198.51.100.7", tags={"Name": H[0], H[1]: H[2]},
                     sgs=[{"GroupId": "sg-0a1b2c3d4e5f6bad1", "GroupName": H[3]}])])
    s.write("sg/security_groups.json", [security_group("sg-0a1b2c3d4e5f6bad1", H[3], vpc="vpc-0a1b2c3d4e5f6aaaa",
                                                       description=H[4],
                                                       inbound=[sg_rule("tcp", 80, cidrs=["0.0.0.0/0"],
                                                                        description=H[6])])])
    fns = [lambda_function(h, account=acct, region=region, role=iam.arn("role", H[0]), url_auth="NONE",
                           env_names=[h]) for h in H[:3]]
    s.write("lambda/functions.json", fns)
    s.write("secretsmanager/secrets.json", [secret(h, account=acct, region=region) for h in H[:3]])
    s.write("ssm/parameters.json", [ssm_parameter(f"/demo/{h}/password", account=acct, region=region)
                                    for h in H[:2]])
    s.write("sns/resources.json", [policy_resource("sns", f"arn:aws:sns:{region}:{acct}:{H[0]}", H[0],
                                                   resource_policy(grant("*", "sns:Publish")))])
    s.write("route53/resources.json", [{
        "Type": "route53zone", "Id": "Z0EXAMPLEZONECCC", "Name": "example.net.", "Private": False, "RecordCount": 1,
        "Records": [{"Name": H[0], "Type": "CNAME", "Targets": ["demo.cloudfront.net"]}],
        "TakeoverCandidates": [{"Name": H[0], "Target": "demo.cloudfront.net"}]}])
    s.write("ecs/resources.json", [compute_resource("ecstask", f"arn:aws:ecs:{region}:{acct}:task-definition/x:1",
                                                    H[7], [iam.arn("role", H[0])])])
    cluster = eks_cluster("demo-hostile-eks", account=acct, region=region, role_arn=iam.arn("role", H[0]))
    s.write("eks/clusters.json", [cluster])
    s.write("eks/nodegroups.json", {"demo-hostile-eks": []})
    k = "k8s/demo-hostile-eks"
    s.write(f"{k}/cluster_info.json", {"name": "demo-hostile-eks", "endpoint": cluster["endpoint"],
                                       "auth_status": "ok"})
    s.write(f"{k}/service_accounts.json", [k8s_sa(H[1], H[0], role_arn=iam.arn("role", H[0]))])
    s.write(f"{k}/pods.json", [k8s_pod(H[9], H[0], sa=H[1], labels={"app": H[3]}, secret_volumes=[H[4]],
                                       privileged=True)])
    s.write(f"{k}/services.json", [k8s_service(H[5], H[0], svc_type="LoadBalancer", selector={"app": H[3]})])
    s.write(f"{k}/ingresses.json", [k8s_ingress(H[6], H[0], H[5])])
    s.write(f"{k}/cluster_role_bindings.json", [k8s_binding(H[8], None, "ClusterRole", "cluster-admin",
                                                            [{"kind": "ServiceAccount", "name": H[1],
                                                              "namespace": H[0]}])])
    for fname in ("namespaces", "roles", "cluster_roles", "role_bindings", "secrets"):
        s.write(f"{k}/{fname}.json", [])
    _finish_single(s)


# 10/11 ─ ir_leaked_key (+ quarantine) (internal-docs/repro/def_mkreport.py) ─
def _build_ir(root: Path, quarantine: bool) -> None:
    acct = ACCT_ZERO
    s = Scope(root, acct, "eu-west-2")
    iam = Iam(acct)
    iam.group("devs")
    iam.user("leaked-user", groups=["devs"], access_keys=1, login=True, inline={"dev": [
        allow(["lambda:UpdateFunctionCode", "lambda:GetFunction"], "*"),
        allow(["s3:GetObject", "s3:ListBucket"], ["arn:aws:s3:::data-bucket", "arn:aws:s3:::data-bucket/*"]),
    ] + ([deny("*", "*")] if quarantine else [])})
    iam.user("admin-user", groups=["devs"], attached=["AdministratorAccess"], access_keys=1, login=True)
    iam.role("fn-admin-role", trust({"Service": "lambda.amazonaws.com"}), attached=["AdministratorAccess"])
    iam.role("admin-role", trust({"AWS": iam.arn("user", "admin-user")}), attached=["AdministratorAccess"])
    gh_oidc = f"arn:aws:iam::{acct}:oidc-provider/token.actions.githubusercontent.com"
    iam.role("gha-deploy", trust({"Federated": gh_oidc},
                                 "sts:AssumeRoleWithWebIdentity",
                                 {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:*"}}),
             attached=["AdministratorAccess"])
    iam.extra_files["inline_policies/groups/devs.json"] = {"GroupName": "devs", "InlinePolicies": {}}
    iam.write(s)
    s.write("s3/buckets.json", [s3_bucket(s, "data-bucket"), s3_bucket(s, "other-bucket")])
    s.write("lambda/functions.json", [lambda_function("etl", account=acct, region=s.region,
                                                      role=iam.arn("role", "fn-admin-role"))])
    _finish_single(s)


@scenario("ir_leaked_key",
          "def_mkreport incident: leaked-user can lambda:UpdateFunctionCode on etl, which runs as fn-admin-role "
          "(blast radius hop 2 = admin); GitHub OIDC trust on repo:*.",
          ACCT_ZERO, "single_region", ["eu-west-2"])
def build_ir_leaked_key(root: Path) -> None:
    _build_ir(root, quarantine=False)


@scenario("ir_leaked_key_quarantine",
          "ir_leaked_key with an explicit Deny * quarantine statement on leaked-user (the baseline ignores Deny).",
          ACCT_ZERO, "single_region", ["eu-west-2"])
def build_ir_leaked_key_quarantine(root: Path) -> None:
    _build_ir(root, quarantine=True)


# 12 ─ microbench (internal-docs/repro/po_microbench.py) ──────────────────────
MICROBENCH_TRUST = trust({"Service": "ec2.amazonaws.com"})
MICROBENCH_CASES: Dict[str, Dict[str, Any]] = {
    "c01-admin": {"positive": True, "note": "Action:* on *",
                  "doc": doc(allow("*", "*"))},
    "c02-poweruser-notaction": {"positive": True, "note": "PowerUserAccess shape",
                                "doc": doc({"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"],
                                            "Resource": "*"})},
    "c03-putrolepolicy": {"positive": True, "note": "classic privesc",
                          "doc": doc(allow("iam:PutRolePolicy", "*"))},
    "c04-attachuserpolicy": {"positive": True, "note": "classic privesc",
                             "doc": doc(allow("iam:AttachUserPolicy", "*"))},
    "c05-iam-notresource": {"positive": True, "note": "iam:* except one role",
                            "doc": doc({"Effect": "Allow", "Action": "iam:*",
                                        "NotResource": f"arn:aws:iam::{ACCT_MAIN}:role/breakglass"})},
    "c06-quarantined": {"positive": False, "note": "explicit Deny *",
                        "doc": doc(allow("*", "*"), deny("*", "*"))},
    "c07-passrole-scoped": {"positive": False, "note": "PassRole to one low-priv role",
                            "doc": doc(allow(["iam:PassRole"], f"arn:aws:iam::{ACCT_MAIN}:role/low-priv-lambda"),
                                       allow(["lambda:CreateFunction", "lambda:InvokeFunction"], "*"))},
    "c08-self-service-keys": {"positive": False, "note": "self-service creds",
                              "doc": doc(allow(["iam:CreateAccessKey", "iam:UpdateLoginProfile"],
                                               f"arn:aws:iam::{ACCT_MAIN}:user/${{aws:username}}"))},
    "c09-boundary-capped": {"positive": False, "note": "admin capped by read-only boundary",
                            "doc": doc(allow("*", "*")),
                            "extra": {"PermissionsBoundary": {
                                "PermissionsBoundaryType": "Policy",
                                "PermissionsBoundaryArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}}},
    "c10-readonly": {"positive": False, "note": "read-only",
                     "doc": doc(allow(["s3:Get*", "s3:List*", "ec2:Describe*"], "*"))},
}


@scenario("microbench",
          "po_microbench: 10 labelled roles (ground truth = admin-equivalent or can escalate to admin). "
          "labels.json holds the ground truth.",
          ACCT_MAIN, "single_region", ["eu-west-2"],
          extra_files={"labels.json": {name: {"positive": c["positive"], "note": c["note"]}
                                       for name, c in MICROBENCH_CASES.items()}})
def build_microbench(root: Path) -> None:
    s = Scope(root, ACCT_MAIN, "eu-west-2")
    iam = Iam(ACCT_MAIN)
    for name, case in MICROBENCH_CASES.items():
        iam.role(name, MICROBENCH_TRUST, inline={"p": case["doc"]}, extra=case.get("extra"))
    iam.write(s)
    _finish_single(s)


# ── Facade ───────────────────────────────────────────────────────────────────
class ReportBuilder:
    """Entry point for tests that need a custom tree in the baseline layout.

    ::

        rb = ReportBuilder(tmp_path / "tree")
        s = rb.single_region(ACCT_MAIN, "eu-west-2")       # <tree>/123456789012/eu-west-2
        iam = rb.iam(ACCT_MAIN); iam.user("demo-user", inline={"p": [allow("s3:*")]}); iam.write(s)
        s.write("s3/buckets.json", [s3_bucket(s, "demo-bucket")])
        rb.manifest(s)
        analyze(str(s.path))

    or ``rb.scenario("eks_irsa")`` for a registered scenario (built from code) and
    ``rb.materialize("eks_irsa")`` for the committed static copy.
    """

    def __init__(self, root: Path):
        self.root = Path(root)

    def scope(self, account: str, name: str) -> Scope:
        return Scope(self.root, account, name)

    def single_region(self, account: str = ACCT_MAIN, region: str = "eu-west-2") -> Scope:
        return self.scope(account, region)

    def all_mode(self, account: str = ACCT_MAIN,
                 regions: Sequence[str] = ("eu-west-1", "eu-west-2")) -> "tuple[Scope, List[Scope]]":
        return self.scope(account, "global"), [self.scope(account, r) for r in regions]

    @staticmethod
    def iam(account: str = ACCT_MAIN) -> Iam:
        return Iam(account)

    def manifest(self, scope: Scope, *, regions: Sequence[str] = ()) -> None:
        if scope.name == "global":
            write_manifest(self.root / scope.account, account=scope.account, mode="all_regions", region=None,
                           regions=regions)
        else:
            write_manifest(scope.path, account=scope.account, mode="single_region", region=scope.name)

    def scenario(self, name: str) -> List[Path]:
        build(name, self.root)
        return [self.root / rd for rd in SCENARIOS[name].report_dirs]

    def v2_run(self, account_id: str = ACCT_MAIN, run_id: str = V2_RUN_ID, regions: Sequence[str] = ("eu-west-2",),
               partition: str = "aws", **kwargs: Any) -> "V2Run":
        """A v2 run root ``<root>/<account>/<run_id>/`` (report-layout.md §1); see :class:`V2Run`."""
        return V2Run(self.root, account=account_id, run_id=run_id, regions=regions, partition=partition, **kwargs)

    def materialize(self, name: str) -> List[Path]:
        return materialize(name, self.root)


# ── Public helpers ───────────────────────────────────────────────────────────
def scenario_names() -> List[str]:
    return sorted(SCENARIOS)


def get(name: str) -> Scenario:
    return SCENARIOS[name]


def build(name: str, dest: Path) -> Scenario:
    """Build scenario ``name`` from code into ``dest`` (tree root)."""
    sc = SCENARIOS[name]
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    sc.build(dest)
    return sc


def fixture_tree(name: str) -> Path:
    return FIXTURES_DIR / name / "tree"


def materialize(name: str, dest: Path) -> List[Path]:
    """Copy the committed static tree of ``name`` into ``dest``; return absolute report dirs."""
    src = fixture_tree(name)
    if not src.is_dir():
        raise FileNotFoundError(f"{src} missing; run: python -m tests.support.report_builder --write-fixtures")
    shutil.copytree(src, dest, dirs_exist_ok=True)
    return [Path(dest) / rd for rd in SCENARIOS[name].report_dirs]


def write_fixtures(names: Optional[Iterable[str]] = None, base: Path = FIXTURES_DIR) -> List[Path]:
    """(Re)write tests/fixtures/scenarios/<name>/{tree/,scenario.json,...} from code."""
    written = []
    for name in (list(names) if names else scenario_names()):
        sc = SCENARIOS[name]
        out = Path(base) / name
        tree = out / "tree"
        if tree.exists():
            shutil.rmtree(tree)
        sc.build(tree)
        dump_json(out / "scenario.json", sc.meta())
        for fname, data in sc.extra_files.items():
            dump_json(out / fname, data)
        written.append(out)
    return written


def tree_files(root: Path) -> Dict[str, bytes]:
    root = Path(root)
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--write-fixtures", action="store_true", help="rewrite tests/fixtures/scenarios/*")
    ap.add_argument("--only", nargs="*", help="limit to these scenario names")
    ap.add_argument("--list", action="store_true", help="list scenarios")
    args = ap.parse_args(argv)
    if args.list:
        for n in scenario_names():
            print(f"{n:28s} {SCENARIOS[n].description}")
        return 0
    if args.write_fixtures:
        for out in write_fixtures(args.only):
            print(f"wrote {out.relative_to(REPO_ROOT)}")
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
