"""AWS Organizations (global): membership, the OU path of the account, and the service / resource control
policies (SCPs, RCPs) that apply to it (F-126).

SCPs and RCPs cap what any principal of a member account can do, whatever IAM grants. Without them the
engine cannot tell an effective permission from one an SCP denies, so it must know whether they are known.

Calls: ``DescribeOrganization`` (works from every member account); then, walking up from the account,
``ListParents`` + ``DescribeOrganizationalUnit``; for each level (root, OUs, account) and policy type,
``ListPoliciesForTarget`` + ``DescribePolicy``. Everything except ``DescribeOrganization`` is ``optional``:
member accounts are normally denied those calls, which must not degrade the run.

Output (``global/organizations/``):

* ``organization.json`` (dict)::

    {AccountId, InOrganization: bool|null, Id, Arn, FeatureSet, ManagementAccountId,
     IsManagementAccount: bool|null, AvailablePolicyTypes: [{Type, Status}]|null,
     PolicyCollection: {SERVICE_CONTROL_POLICY: <state>, RESOURCE_CONTROL_POLICY: <state>},
     CollectionErrors?}

  ``InOrganization`` is ``false`` for ``AWSOrganizationsNotInUseException`` and ``null`` when unknown. The
  management account's e-mail address is never stored. ``PolicyCollection`` says, per policy type, whether
  ``policies.json`` is ``complete`` (every level listed and every policy read), ``imported``
  (``--scp-file``), ``partial`` (some calls failed: the list is a lower bound and must not be evaluated
  as the full set), ``not_collected`` (the OU path is unknown) or ``not_applicable`` (no organization).
* ``ou_path.json`` (dict): ``{AccountId, Complete: bool, Source: "api"|"import"|null, Path: [{Id, Type,
  Name, Arn}], PartialPath?: [...]}``; ``Path`` runs root -> OUs -> account and is ``[]`` unless the walk
  reached the root (``PartialPath`` then holds the levels that were read, account first).
* ``policies.json`` (list), sorted by (``Type``, ``PolicyId``)::

    {PolicyId, Arn, Name, Description, Type, AwsManaged, Targets: [target id], Content: {...}|null,
     Source: "api"|"import", CollectionErrors?}

  ``Targets`` are the path levels the policy is attached to.

``--scp-file PATH`` (option ``scp_file``) imports policies for accounts that cannot read Organizations. It
is used when the API did not return a complete set (an API-complete set wins and the file is ignored with
a warning). Accepted JSON forms:

* ``{"OuPath": [...], "Policies": [...]}``: ``OuPath`` (optional) lists the levels root -> account as ids or
  ``{Id, Type}`` objects and must end with the target account; ``Policies`` as below;
* a list of policy records: this module's own ``policies.json`` (for example from a management-account
  run) or ``aws organizations describe-policy`` outputs (``{"Policy": {"PolicySummary": ..., "Content":
  ...}}``) with a ``Targets`` list added.

Each imported policy needs an id (``PolicyId``/``Id``), a ``Type`` (``SERVICE_CONTROL_POLICY`` or
``RESOURCE_CONTROL_POLICY``), non-empty ``Targets`` and a ``Content`` policy document (object or JSON
string). An invalid file is rejected as a whole (section ``scp_import`` fails, module ``partial``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from aws_enumerator.collectors._common import add_error, policy_doc
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="organizations", scope="global", output_dir="organizations", services=("organizations",),
    tier=1, cost="low", noise="low", default=True, groups=("@identity", "@posture"),
    actions=("organizations:DescribeOrganization",),
    optional_actions=("organizations:ListParents", "organizations:DescribeOrganizationalUnit",
                      "organizations:ListPoliciesForTarget", "organizations:DescribePolicy"),
    probe=("organizations", "DescribeOrganization", ()),
    outputs=(("organization.json", "dict"), ("ou_path.json", "dict"), ("policies.json", "list")),
    description="Organization membership, OU path and the SCPs/RCPs that apply to the account (F-126)",
)

SCP = "SERVICE_CONTROL_POLICY"
RCP = "RESOURCE_CONTROL_POLICY"
POLICY_TYPES: Tuple[str, ...] = (SCP, RCP)
#: Root + at most five nested OUs; one more level guards against a looping answer.
MAX_DEPTH = 7
#: Upper bound for an ``--scp-file`` (a full org's SCPs are a few hundred KiB at most).
MAX_IMPORT_BYTES = 10 * 1024 * 1024

COMPLETE, IMPORTED, PARTIAL, NOT_COLLECTED, NOT_APPLICABLE = (
    "complete", "imported", "partial", "not_collected", "not_applicable")


class ScpImportError(ValueError):
    """The ``--scp-file`` content is not a usable policy export."""


# ── organization ─────────────────────────────────────────────────────────────
def _organization_unknown(account_id: str) -> Dict[str, Any]:
    return {"AccountId": account_id, "InOrganization": None, "Id": None, "Arn": None, "FeatureSet": None,
            "ManagementAccountId": None, "IsManagementAccount": None, "AvailablePolicyTypes": None,
            "PolicyCollection": {t: NOT_COLLECTED for t in POLICY_TYPES}}


def _organization(ctx: Any, org: Any) -> Dict[str, Any]:
    out = _organization_unknown(ctx.account_id)
    result = ctx.call(org, "describe_organization", primary=True)
    if result.not_configured:
        out.update(InOrganization=False, IsManagementAccount=False,
                   PolicyCollection={t: NOT_APPLICABLE for t in POLICY_TYPES})
        return out
    if not result.ok:
        add_error(out, result)
        return out
    o = result.get("Organization") or {}
    management = o.get("MasterAccountId")
    out.update(InOrganization=True, Id=o.get("Id"), Arn=o.get("Arn"), FeatureSet=o.get("FeatureSet"),
               ManagementAccountId=management,
               IsManagementAccount=(management == ctx.account_id) if management else None,
               AvailablePolicyTypes=sorted(({"Type": p.get("Type"), "Status": p.get("Status")}
                                            for p in o.get("AvailablePolicyTypes") or []),
                                           key=lambda p: str(p["Type"])))
    return out


# ── OU path ──────────────────────────────────────────────────────────────────
def _level(ctx: Any, org: Any, ident: str, kind: str) -> Dict[str, Any]:
    level: Dict[str, Any] = {"Id": ident, "Type": kind, "Name": None, "Arn": None}
    if kind == "ORGANIZATIONAL_UNIT":
        result = ctx.call(org, "describe_organizational_unit", item=ident, optional=True,
                          OrganizationalUnitId=ident)
        if result.ok:
            ou = result.get("OrganizationalUnit") or {}
            level.update(Name=ou.get("Name"), Arn=ou.get("Arn"))
        else:
            add_error(level, result)
    return level


def walk_path(ctx: Any, org: Any) -> Tuple[List[Dict[str, Any]], bool]:
    """``(levels, complete)``: the account and its ancestors, **account first**; complete once the root is hit."""
    levels = [{"Id": ctx.account_id, "Type": "ACCOUNT", "Name": None, "Arn": None}]
    child = ctx.account_id
    for _ in range(MAX_DEPTH):
        result = ctx.paginate(org, "list_parents", "Parents", item=child, optional=True, ChildId=child)
        parents = [p for p in result.value if p.get("Id")]
        if not result.ok or len(parents) != 1:
            return levels, False
        parent = parents[0]
        levels.append(_level(ctx, org, parent["Id"], str(parent.get("Type") or "")))
        if parent.get("Type") == "ROOT":
            return levels, True
        child = parent["Id"]
    ctx.log.warning("OU path deeper than %d levels; giving up", MAX_DEPTH)
    return levels, False


def _ou_path(account_id: str, levels: Sequence[Dict[str, Any]], complete: bool,
             source: Optional[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"AccountId": account_id, "Complete": complete, "Source": source if complete else None,
                           "Path": list(reversed(levels)) if complete else []}
    if not complete and len(levels) > 1:
        out["PartialPath"] = list(levels)
    return out


# ── policies (API) ───────────────────────────────────────────────────────────
def _list_for_targets(ctx: Any, org: Any, targets: Iterable[str], policy_type: str,
                      found: Dict[str, Dict[str, Any]]) -> bool:
    """Merge the policies attached to ``targets`` into ``found``; ``False`` when a listing failed."""
    complete = True
    for target in targets:
        result = ctx.paginate(org, "list_policies_for_target", "Policies", item=target, optional=True,
                              TargetId=target, Filter=policy_type)
        complete = complete and result.ok
        for summary in result.value:
            pid = summary.get("Id")
            if not pid:
                continue
            rec = found.setdefault(pid, {
                "PolicyId": pid, "Arn": summary.get("Arn"), "Name": summary.get("Name"),
                "Description": summary.get("Description"), "Type": summary.get("Type") or policy_type,
                "AwsManaged": summary.get("AwsManaged"), "Targets": [], "Content": None, "Source": "api"})
            if target not in rec["Targets"]:
                rec["Targets"].append(target)
    return complete


def _describe(ctx: Any, org: Any, rec: Dict[str, Any]) -> bool:
    result = ctx.call(org, "describe_policy", item=rec["Arn"] or rec["PolicyId"], optional=True,
                      PolicyId=rec["PolicyId"])
    if not result.ok:
        add_error(rec, result)
        return False
    rec["Content"] = policy_doc((result.get("Policy") or {}).get("Content"))
    return rec["Content"] is not None


def collect_policies(ctx: Any, org: Any, path_ids: Sequence[str]) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """Policies of every type attached to the path levels, and the collection state per type."""
    policies: List[Dict[str, Any]] = []
    states: Dict[str, str] = {}
    for policy_type in POLICY_TYPES:
        found: Dict[str, Dict[str, Any]] = {}
        complete = _list_for_targets(ctx, org, path_ids, policy_type, found)
        for rec in found.values():
            complete = _describe(ctx, org, rec) and complete
            rec["Targets"] = sorted(rec["Targets"])
        states[policy_type] = COMPLETE if complete else PARTIAL
        policies.extend(found.values())
    return policies, states


# ── --scp-file import ────────────────────────────────────────────────────────
def _import_levels(raw: Any, account_id: str) -> Optional[List[str]]:
    if raw is None:
        return None
    if not isinstance(raw, list) or not raw:
        raise ScpImportError("OuPath must be a non-empty list of ids (root first)")
    ids = [str(x.get("Id") if isinstance(x, Mapping) else x) for x in raw]
    if ids[-1] != account_id:
        raise ScpImportError(f"OuPath must end with the target account {account_id}, not {ids[-1]}")
    return ids


def _import_policy(raw: Any, index: int) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise ScpImportError(f"policy #{index} is not an object")
    wrapped = raw.get("Policy") if isinstance(raw.get("Policy"), Mapping) else None
    summary = (wrapped or {}).get("PolicySummary") or raw
    content = policy_doc((wrapped or raw).get("Content"))
    pid = summary.get("PolicyId") or summary.get("Id")
    ptype = summary.get("Type")
    targets = raw.get("Targets")
    if not isinstance(pid, str) or not pid:
        raise ScpImportError(f"policy #{index} has no PolicyId/Id")
    if ptype not in POLICY_TYPES:
        raise ScpImportError(f"policy {pid}: Type must be one of {POLICY_TYPES}")
    if not isinstance(targets, list) or not targets:
        raise ScpImportError(f"policy {pid}: Targets must be a non-empty list of root/OU/account ids")
    if not isinstance(content, dict) or "Statement" not in content:
        raise ScpImportError(f"policy {pid}: Content is not a policy document")
    ids = sorted({str(t.get("TargetId") if isinstance(t, Mapping) else t) for t in targets})
    return {"PolicyId": pid, "Arn": summary.get("Arn"), "Name": summary.get("Name"),
            "Description": summary.get("Description"), "Type": ptype, "AwsManaged": summary.get("AwsManaged"),
            "Targets": ids, "Content": content, "Source": "import"}


def parse_scp_import(data: Any, account_id: str) -> Tuple[List[Dict[str, Any]], Optional[List[str]]]:
    """``(policies, ou path ids or None)`` from the parsed ``--scp-file`` JSON; raises :class:`ScpImportError`."""
    if isinstance(data, Mapping):
        raw_policies, path = data.get("Policies"), _import_levels(data.get("OuPath"), account_id)
    elif isinstance(data, list):
        raw_policies, path = data, None
    else:
        raise ScpImportError("expected an object with 'Policies' or a list of policies")
    if not isinstance(raw_policies, list) or not raw_policies:
        raise ScpImportError("no policies to import")
    policies = [_import_policy(p, i) for i, p in enumerate(raw_policies)]
    if len({p["PolicyId"] for p in policies}) != len(policies):
        raise ScpImportError("duplicate policy ids")
    return policies, path


def load_scp_file(path: Any, account_id: str) -> Tuple[List[Dict[str, Any]], Optional[List[str]]]:
    """Read and validate an ``--scp-file`` (size-capped JSON)."""
    file = Path(path).expanduser()
    # Messages carry the file name only: the full path may hold a user name, and they reach coverage.
    try:
        size = file.stat().st_size
        text = file.read_text(encoding="utf-8") if size <= MAX_IMPORT_BYTES else ""
    except (OSError, UnicodeDecodeError) as exc:
        raise ScpImportError(f"{file.name}: cannot be read ({exc.__class__.__name__})") from None
    if size > MAX_IMPORT_BYTES:
        raise ScpImportError(f"{file.name}: larger than {MAX_IMPORT_BYTES} bytes")
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ScpImportError(f"{file.name}: not valid JSON ({exc.__class__.__name__})") from None
    return parse_scp_import(data, account_id)


# ── module ───────────────────────────────────────────────────────────────────
class _State:
    """What the sections build; written once at the end so every file keeps a stable shape."""

    def __init__(self, ctx: Any):
        self.organization: Dict[str, Any] = _organization_unknown(ctx.account_id)
        self.levels: List[Dict[str, Any]] = [{"Id": ctx.account_id, "Type": "ACCOUNT", "Name": None, "Arn": None}]
        self.path_complete = False
        self.path_source: Optional[str] = None
        self.policies: List[Dict[str, Any]] = []


def _api_policies(ctx: Any, org: Any, state: _State) -> None:
    if state.organization.get("InOrganization") is False:
        state.levels, state.path_complete, state.path_source = [], True, "api"   # no organization, no path
        return
    state.levels, state.path_complete = walk_path(ctx, org)
    state.path_source = "api" if state.path_complete else None
    if state.path_complete:
        ids = [lvl["Id"] for lvl in reversed(state.levels)]
        state.policies, collection = collect_policies(ctx, org, ids)
        state.organization["PolicyCollection"] = collection


def _apply_import(ctx: Any, state: _State, scp_file: Any) -> None:
    collection = state.organization["PolicyCollection"]
    if all(collection.get(t) == NOT_APPLICABLE for t in POLICY_TYPES):
        ctx.log.warning("--scp-file ignored: the account is not in an organization")
        return
    if all(collection.get(t) == COMPLETE for t in POLICY_TYPES):
        ctx.log.warning("--scp-file ignored: the policies were read from AWS Organizations")
        return
    policies, path = load_scp_file(scp_file, ctx.account_id)
    if path is not None and not state.path_complete:
        state.levels = [{"Id": i, "Type": None, "Name": None, "Arn": None} for i in reversed(path)]
        state.path_complete, state.path_source = True, "import"
    state.policies = policies
    state.organization["PolicyCollection"] = {t: IMPORTED for t in POLICY_TYPES}
    ctx.log.info("imported %d control policies from --scp-file", len(policies))


def collect(ctx: Any) -> None:
    org = ctx.client("organizations")
    state = _State(ctx)
    with ctx.section("organization"):
        state.organization = _organization(ctx, org)
    with ctx.section("policies"):
        _api_policies(ctx, org, state)
    scp_file = ctx.option("scp_file")
    if scp_file:
        with ctx.section("scp_import"):
            _apply_import(ctx, state, scp_file)
    state.policies.sort(key=lambda p: (p["Type"], p["PolicyId"]))
    ctx.out.write("organization.json", state.organization)
    ctx.out.write("ou_path.json", _ou_path(ctx.account_id, state.levels, state.path_complete, state.path_source))
    ctx.out.write("policies.json", state.policies)
    ctx.log.info("in organization: %s; %d control policies (%s)", state.organization.get("InOrganization"),
                 len(state.policies), ", ".join(f"{k}={v}" for k, v in
                                                sorted(state.organization["PolicyCollection"].items())))

