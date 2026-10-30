"""AWS Organizations model: SCP and RCP chains (engine.md §2.4 steps 2-3; F-126).

Built from the organizations collector's output (collectors-cli.md §5.15: ``organization.json``,
``ou_path.json``, ``policies.json``) by :meth:`OrgModel.from_documents`; the file loading itself is
``io/loaders/org.py`` (E-core).

Semantics (AWS "Service control policies (SCPs)" and "Resource control policies (RCPs)"):

* every level of the hierarchy (root, each OU on the path, the account) must **allow** the action — at least
  one allowing policy per level, levels ANDed; a Deny at any level denies;
* SCPs and RCPs do not apply to the management account; SCPs do not restrict service-linked roles;
* RCPs apply only to resources of the services in :data:`RCP_SUPPORTED_SERVICES`;
* when the policies of some level were not collected the chain is unknown (``None``): the evaluator reports
  the layer as ``unknown`` and the report-level gap ``org:scp-unknown`` / ``org:rcp-unknown`` — never a
  per-edge downgrade.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from aws_enumerator.engine.model import Statement
from aws_enumerator.engine.policy.parse import load_document, parse_policy

#: Services whose resources RCPs govern (AWS "Resource control policies", list at GA in November 2024 plus the
#: 2025 additions). Data, not logic: extend it when AWS adds services.
RCP_SUPPORTED_SERVICES = frozenset({"s3", "sts", "kms", "sqs", "secretsmanager", "ecr", "aoss", "cognito-idp",
                                    "logs", "dynamodb"})
RCP_SERVICES_AS_OF = "2025-06"

SCP_TYPE = "SERVICE_CONTROL_POLICY"
RCP_TYPE = "RESOURCE_CONTROL_POLICY"


@dataclass(frozen=True)
class OrgLevel:
    """One level of the path root → OU … → account with the policies attached there (``None`` = unknown)."""

    target_id: str
    target_type: str
    scps: Optional[Tuple[Statement, ...]]
    rcps: Optional[Tuple[Statement, ...]]


@dataclass(frozen=True)
class OrgModel:
    """Organization facts for the assessed account."""

    account_id: str
    in_organization: Optional[bool]
    organization_id: Optional[str] = None
    management_account_id: Optional[str] = None
    levels: Tuple[OrgLevel, ...] = ()
    org_path: Optional[str] = None            # aws:PrincipalOrgPaths form "o-x/r-x/ou-x/"
    notes: Tuple[str, ...] = field(default=())
    disabled_types: Tuple[str, ...] = ()      # policy types known to be disabled in the organization

    # ── queries ──────────────────────────────────────────────────────────────
    def is_management(self, account: Optional[str]) -> bool:
        return bool(account) and account == self.management_account_id

    def applies_to(self, account: Optional[str]) -> bool:
        """Do org policies govern ``account``? Only the assessed member account is modelled."""
        return bool(self.in_organization) and account == self.account_id and not self.is_management(account)

    def scp_chain(self, account: Optional[str]) -> Optional[Tuple[Tuple[Statement, ...], ...]]:
        """SCP statements per level for ``account`` (``()`` when SCPs do not apply, ``None`` when unknown)."""
        return self._chain(account, "scps")

    def rcp_chain(self, account: Optional[str]) -> Optional[Tuple[Tuple[Statement, ...], ...]]:
        return self._chain(account, "rcps")

    def _chain(self, account: Optional[str], attr: str) -> Optional[Tuple[Tuple[Statement, ...], ...]]:
        if self.in_organization is False or self.is_management(account):
            return ()
        if (SCP_TYPE if attr == "scps" else RCP_TYPE) in self.disabled_types:
            return ()
        if self.in_organization is None or account != self.account_id or not self.levels:
            return None
        out = []
        for level in self.levels:
            stmts = getattr(level, attr)
            if stmts is None:
                return None
            out.append(stmts)
        return tuple(out)

    # ── construction ─────────────────────────────────────────────────────────
    @classmethod
    def unknown(cls, account_id: str) -> "OrgModel":
        return cls(account_id=account_id, in_organization=None)

    @classmethod
    def from_org_data(cls, org: Any, *, account_id: str, partition: str = "aws") -> "OrgModel":
        """Build from the organizations loader's ``OrgData`` (``io/loaders/org.py``; duck-typed).

        ``OrgData.path`` lists the ids root → OUs → account; ``policies`` carry ``type``, ``targets`` and the parsed
        ``document``; ``policies_collected`` false makes both chains unknown.
        """
        if org is None:
            return cls.unknown(account_id)
        organization = {"InOrganization": getattr(org, "in_organization", None), "Id": getattr(org, "org_id", None),
                        "ManagementAccountId": getattr(org, "management_account", None),
                        "IsManagementAccount": getattr(org, "is_management_account", None),
                        "AvailablePolicyTypes": getattr(org, "available_policy_types", None)}
        if organization["InOrganization"] is None and organization["Id"] is None:
            return cls.unknown(account_id)
        policies = None
        if getattr(org, "policies_collected", False):
            policies = [{"PolicyId": p.id, "Arn": getattr(p, "arn", None), "Name": getattr(p, "name", p.id),
                         "Type": getattr(p, "type", SCP_TYPE), "Targets": list(getattr(p, "targets", ()) or ()),
                         "Content": getattr(p, "document", None)} for p in getattr(org, "policies", ()) or ()]
        return cls.from_documents(organization, list(getattr(org, "path", ()) or ()), policies,
                                  account_id=account_id, partition=partition)

    @classmethod
    def from_documents(cls, organization: Optional[Mapping[str, Any]], ou_path: Any, policies: Any, *,
                       account_id: str, partition: str = "aws") -> "OrgModel":
        """Build from the organizations collector files (shapes in the module docstring of collectors-cli §5.15).

        ``ou_path``: a list (or ``{"Path": [...]}``) of ``{Id, Type}`` from the root to the account, in either
        order. ``policies``: ``[{PolicyId, Name, Type, Targets: [ids], Content}]``; a policy without
        ``Targets`` cannot be placed, which makes its type's chain unknown.
        """
        if not isinstance(organization, Mapping):
            return cls.unknown(account_id)
        in_org = organization.get("InOrganization")
        if in_org is False:
            return cls(account_id=account_id, in_organization=False)
        org_id = organization.get("Id") if isinstance(organization.get("Id"), str) else None
        mgmt = organization.get("ManagementAccountId") or organization.get("MasterAccountId")
        if organization.get("IsManagementAccount") is True:
            mgmt = account_id
        path = _path_entries(ou_path, account_id)
        complete = not (isinstance(ou_path, Mapping) and ou_path.get("Complete") is False)
        levels, notes = _levels(path, policies, partition) if complete else ((), ["ou path incomplete"])
        org_path = _org_path(org_id, path) if complete else None
        return cls(account_id=account_id, in_organization=True if in_org is None else bool(in_org),
                   organization_id=org_id, management_account_id=mgmt if isinstance(mgmt, str) else None,
                   levels=levels, org_path=org_path, notes=tuple(notes),
                   disabled_types=_disabled_types(organization))


def _disabled_types(organization: Mapping[str, Any]) -> Tuple[str, ...]:
    """Policy types that ``AvailablePolicyTypes`` (root ``PolicyTypes``) shows as not enabled.

    Unknown (no list) disables nothing: the chain then stays unknown instead of "no policy applies".
    """
    available = organization.get("AvailablePolicyTypes")
    if not isinstance(available, list):
        return ()
    enabled = {str(t.get("Type")).upper() for t in available
               if isinstance(t, Mapping) and str(t.get("Status", "")).upper() == "ENABLED"}
    return tuple(t for t in (SCP_TYPE, RCP_TYPE) if t not in enabled)


def _path_entries(ou_path: Any, account_id: str) -> List[Tuple[str, str]]:
    raw = ou_path.get("Path") or ou_path.get("Parents") if isinstance(ou_path, Mapping) else ou_path
    entries: List[Tuple[str, str]] = []
    if isinstance(raw, list):
        for e in raw:
            if isinstance(e, Mapping) and isinstance(e.get("Id"), str):
                entries.append((e["Id"], str(e.get("Type") or _type_of(e["Id"])).upper()))
            elif isinstance(e, str):
                entries.append((e, _type_of(e)))
    if entries and entries[0][1] != "ROOT" and entries[-1][1] == "ROOT":
        entries.reverse()
    if not entries or entries[-1][0] != account_id:
        entries.append((account_id, "ACCOUNT"))
    return entries


def _type_of(target_id: str) -> str:
    if target_id.startswith("r-"):
        return "ROOT"
    if target_id.startswith("ou-"):
        return "ORGANIZATIONAL_UNIT"
    return "ACCOUNT"


def _levels(path: Sequence[Tuple[str, str]], policies: Any, partition: str) -> Tuple[Tuple[OrgLevel, ...], List[str]]:
    notes: List[str] = []
    by_target: Dict[str, Dict[str, List[Statement]]] = {}
    known = {SCP_TYPE: isinstance(policies, list), RCP_TYPE: isinstance(policies, list)}
    seen_types = set()
    for pol in policies if isinstance(policies, list) else []:
        if not isinstance(pol, Mapping):
            continue
        ptype = str(pol.get("Type") or SCP_TYPE).upper()
        seen_types.add(ptype)
        targets = pol.get("Targets")
        if not isinstance(targets, list):
            known[ptype] = False
            notes.append(f"policy {pol.get('PolicyId') or pol.get('Name')} has no targets")
            continue
        layer = "scp" if ptype == SCP_TYPE else "rcp"
        doc = parse_policy(load_document(pol.get("Content")) or {}, layer=layer, source_type=layer,
                           policy_arn=pol.get("Arn"), policy_name=pol.get("Name"), partition=partition)
        for t in targets:
            tid = t.get("TargetId") if isinstance(t, Mapping) else t
            if isinstance(tid, str):
                by_target.setdefault(tid, {}).setdefault(ptype, []).extend(doc.statements)
    for ptype in (SCP_TYPE, RCP_TYPE):
        if ptype not in seen_types:
            # None listed: the policy type is disabled or was not collected. AWS keeps at least one policy
            # (FullAWSAccess / RCPFullAWSAccess) on every level while a type is enabled, so "no policy" can only
            # mean "unknown" here; it must never read as "nothing allowed".
            known[ptype] = False
    levels = []
    for tid, ttype in path:
        pols = by_target.get(tid, {})
        # A level without any policy of an enabled type was not collected (see above): unknown.
        scps = tuple(pols[SCP_TYPE]) if known[SCP_TYPE] and pols.get(SCP_TYPE) else None
        rcps = tuple(pols[RCP_TYPE]) if known[RCP_TYPE] and pols.get(RCP_TYPE) else None
        levels.append(OrgLevel(tid, ttype, scps, rcps))
    return tuple(levels), notes


def _org_path(org_id: Optional[str], path: Sequence[Tuple[str, str]]) -> Optional[str]:
    if not org_id:
        return None
    ids = [tid for tid, ttype in path if ttype != "ACCOUNT"]
    return "/".join([org_id, *ids]) + "/"
