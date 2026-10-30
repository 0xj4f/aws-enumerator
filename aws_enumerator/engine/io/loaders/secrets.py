"""Secrets Manager and SSM loader: secrets, their resource policies, parameters, parameter policies, parameters
shared with the account and SSM documents (F-079, F-114, F-116).

Reads only the explicit units of the analysis context, never sibling directories (F-010, F-025, F-063), in both
layouts:

* **v2**: ``secretsmanager/secrets.json`` items carry ``PolicyStatus`` (``skipped`` for a secret scheduled for
  deletion), ``DeletedDate`` and ``CollectionErrors``; resource policies are in
  ``secretsmanager/resource_policies/<slug>-<sha>.json``; ``ssm/`` adds ``parameter_policies/``,
  ``parameters_shared_with_account.json`` and ``documents.json`` (``Public``/``SharedAccounts`` ``null`` =
  unknown).
* **legacy** (d13c215): no status fields; resource policy files are named after the secret, so they are matched by
  the ``SecretArn`` **inside** the file, never by the file name (F-114).

Parameters are identified by their **collected ARN** (F-079); a legacy record without one gets the ARN
``ssm_parameter_arn`` builds for the unit's Region and the run's account.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.io.loaders import LoadResult, read_scoped
from aws_enumerator.engine.io.loaders.kms import (
    ItemErrors, is_v2, iter_units, merge_results, policy_status, read_dict_files, record_account, str_tuple,
    unit_region, usable_policy,
)
from aws_enumerator.engine.policy.arn import ssm_parameter_arn

GLOBAL_FILES: Dict[str, str] = {}
REGIONAL_FILES = {
    "secrets": "secretsmanager/secrets.json",
    "parameters": "ssm/parameters.json",
    "shared_parameters": "ssm/parameters_shared_with_account.json",
    "documents": "ssm/documents.json",
}
SECRET_POLICY_DIR = "secretsmanager/resource_policies"
PARAMETER_POLICY_DIR = "ssm/parameter_policies"


@dataclass(frozen=True)
class Secret:
    """One Secrets Manager secret (metadata only; values are never collected)."""

    arn: str
    name: str
    region: str
    account: str
    kms_key_id: Optional[str]
    pending_deletion: bool
    rotation_enabled: Optional[bool]
    owning_service: Optional[str]
    policy: Optional[Mapping[str, Any]]
    policy_status: str
    errors: ItemErrors = field(default_factory=ItemErrors)
    legacy: bool = False


@dataclass(frozen=True)
class Parameter:
    """One SSM parameter (metadata only)."""

    arn: str
    name: str
    region: str
    account: str
    type: Optional[str]
    key_id: Optional[str]
    tier: Optional[str]
    policy: Optional[Mapping[str, Any]]        # the parameter's resource policies, merged into one document
    policy_status: str
    errors: ItemErrors = field(default_factory=ItemErrors)
    legacy: bool = False
    inbound: bool = False                       # shared WITH this account by another account (F-116)


@dataclass(frozen=True)
class SsmDocument:
    """One SSM document owned by the account, with its sharing (F-116)."""

    arn: str
    name: str
    region: str
    account: str
    document_type: Optional[str]
    public: Optional[bool]                      # None = unknown
    shared_accounts: Optional[Tuple[str, ...]]  # None = unknown
    errors: ItemErrors = field(default_factory=ItemErrors)


@dataclass
class SecretsInventory:
    secrets: Tuple[Secret, ...] = ()
    parameters: Tuple[Parameter, ...] = ()
    shared_parameters: Tuple[Parameter, ...] = ()
    documents: Tuple[SsmDocument, ...] = ()


def _secret(unit: str, rec: Mapping[str, Any], policies: Mapping[str, Mapping[str, Any]],
            account: str) -> Optional[Secret]:
    arn = rec.get("ARN")
    if not isinstance(arn, str) or not ids.node_id_matches("secret", arn):
        return None
    region = unit_region(unit, arn)
    if region is None:
        return None
    raw_policy = policies.get(arn)
    rotation = rec.get("RotationEnabled")
    return Secret(
        arn=arn, name=str(rec.get("Name") or arn.split(":secret:", 1)[-1]), region=region,
        account=record_account(arn, account),
        kms_key_id=rec.get("KmsKeyId") if isinstance(rec.get("KmsKeyId"), str) and rec.get("KmsKeyId") else None,
        pending_deletion=bool(rec.get("DeletedDate")),
        rotation_enabled=rotation if isinstance(rotation, bool) else None,
        owning_service=rec.get("OwningService") if isinstance(rec.get("OwningService"), str) else None,
        policy=usable_policy(raw_policy), policy_status=policy_status(rec, raw_policy), errors=ItemErrors.of(rec),
        legacy=not is_v2(rec))


def _secret_policies(files: Sequence[Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    """Resource policies keyed by the ``SecretArn`` inside each file (F-114: never by the file name)."""
    out: Dict[str, Mapping[str, Any]] = {}
    for f in files:
        arn, doc = f.get("SecretArn"), f.get("ResourcePolicy")
        if isinstance(arn, str) and isinstance(doc, Mapping):
            out[arn] = doc
    return out


def _parameter_policies(files: Sequence[Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    """Parameter resource policies keyed by ``ParameterArn``; several policies merge into one document.

    A parameter whose policies include one that cannot be read keeps the unreadable marker (its grants are
    unknown, :func:`~aws_enumerator.engine.io.loaders.kms.usable_policy`).
    """
    out: Dict[str, Mapping[str, Any]] = {}
    for f in files:
        arn = f.get("ParameterArn")
        if not isinstance(arn, str):
            continue
        statements: List[Any] = []
        unreadable = False
        for entry in f.get("Policies") or ():
            doc = usable_policy(entry.get("Policy") if isinstance(entry, Mapping) else None)
            if doc is None:
                unreadable = True
                continue
            body = doc.get("Statement", [])
            statements.extend(body if isinstance(body, list) else [body])
        if unreadable:
            out[arn] = {"_raw": "unreadable parameter policy"}
        elif statements:
            out[arn] = {"Version": "2012-10-17", "Statement": statements}
    return out


def _parameter(unit: str, rec: Mapping[str, Any], policies: Mapping[str, Mapping[str, Any]], *, account: str,
               partition: str, inbound: bool = False) -> Optional[Parameter]:
    name = rec.get("Name")
    if not isinstance(name, str) or not name:
        return None
    arn = rec.get("ARN") if isinstance(rec.get("ARN"), str) else None
    region = unit_region(unit, arn)
    if region is None:
        return None
    if arn is None and not inbound:
        arn = ssm_parameter_arn(name, partition=partition, region=region, account=account)
    if arn is None or not ids.node_id_matches("ssmparam", arn):
        return None
    raw_policy = policies.get(arn)
    if inbound:
        status = "skipped"            # another account's parameter: its policy is the owner's to read
    else:
        status = policy_status(rec, raw_policy)
    policy = usable_policy(raw_policy)
    key_id = rec.get("KeyId") if isinstance(rec.get("KeyId"), str) and rec.get("KeyId") else None
    return Parameter(arn=arn, name=name, region=region, account=record_account(arn, account),
                     type=rec.get("Type") if isinstance(rec.get("Type"), str) else None, key_id=key_id,
                     tier=rec.get("Tier") if isinstance(rec.get("Tier"), str) else None, policy=policy,
                     policy_status=status, errors=ItemErrors.of(rec), legacy=not is_v2(rec) and not inbound,
                     inbound=inbound)


def _document(unit: str, rec: Mapping[str, Any], *, account: str, partition: str) -> Optional[SsmDocument]:
    name = rec.get("Name")
    if not isinstance(name, str) or not name:
        return None
    arn = rec.get("Arn") if isinstance(rec.get("Arn"), str) else None
    region = unit_region(unit, arn)
    if region is None:
        return None
    arn = arn or f"arn:{partition}:ssm:{region}:{account}:document/{name}"
    if not ids.node_id_matches("ssmdocument", arn):
        return None
    public = rec.get("Public")
    return SsmDocument(arn=arn, name=name, region=region, account=record_account(arn, account),
                       document_type=rec.get("DocumentType") if isinstance(rec.get("DocumentType"), str) else None,
                       public=public if isinstance(public, bool) else None,
                       shared_accounts=str_tuple(rec.get("SharedAccounts")), errors=ItemErrors.of(rec))


def build_inventory(data: Mapping[str, Mapping[str, Sequence[Any]]], secret_files: Mapping[str, Sequence[Any]],
                    param_files: Mapping[str, Sequence[Any]], *, account: str, partition: str) -> SecretsInventory:
    secrets: List[Secret] = []
    params: List[Parameter] = []
    shared: List[Parameter] = []
    docs: List[SsmDocument] = []
    spol = {u: _secret_policies(files) for u, files in secret_files.items()}
    ppol = {u: _parameter_policies(files) for u, files in param_files.items()}
    for unit, rec in iter_units(data.get("secrets", {})):
        item = _secret(unit, rec, spol.get(unit, {}), account)
        if item is not None:
            secrets.append(item)
    for unit, rec in iter_units(data.get("parameters", {})):
        p = _parameter(unit, rec, ppol.get(unit, {}), account=account, partition=partition)
        if p is not None:
            params.append(p)
    for unit, rec in iter_units(data.get("shared_parameters", {})):
        p = _parameter(unit, rec, {}, account=account, partition=partition, inbound=True)
        if p is not None:
            shared.append(p)
    for unit, rec in iter_units(data.get("documents", {})):
        d = _document(unit, rec, account=account, partition=partition)
        if d is not None:
            docs.append(d)
    return SecretsInventory(tuple(_unique(secrets)), tuple(_unique(params)), tuple(_unique(shared)),
                            tuple(_unique(docs)))


def _unique(items: Sequence[Any]) -> List[Any]:
    seen: Dict[str, Any] = {}
    for item in items:
        seen.setdefault(item.arn, item)
    return [seen[k] for k in sorted(seen)]


def load(ctx: Any) -> LoadResult:
    """Phase LOAD: the list files per unit plus ``"inventory"`` (:class:`SecretsInventory`)."""
    base = read_scoped(ctx, GLOBAL_FILES, REGIONAL_FILES)
    units = dict(ctx.region_dirs)
    secret_files, gaps = read_dict_files(units, SECRET_POLICY_DIR)
    param_files, gaps2 = read_dict_files(units, PARAMETER_POLICY_DIR)
    data = dict(base.data)
    data["inventory"] = build_inventory(data, secret_files, param_files, account=ctx.account_id,
                                        partition=ctx.partition)
    return merge_results(LoadResult(data, base.status, dict(base.gaps), base.files), {**gaps, **gaps2})


def secrets_inventory(ctx: Any) -> SecretsInventory:
    data = (getattr(ctx, "data", None) or {}).get("secrets")
    inv = data.get("inventory") if isinstance(data, Mapping) else None
    return inv if isinstance(inv, SecretsInventory) else SecretsInventory()


__all__ = ["Parameter", "Secret", "SecretsInventory", "SsmDocument", "build_inventory", "load", "secrets_inventory"]
