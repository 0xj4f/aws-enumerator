"""KMS loader: keys, aliases, key policies and grants, plus the shared KMS reference resolver (F-027, F-081).

Reads only the explicit units of the analysis context (``ctx.region_dirs``), never sibling directories (F-010,
F-025, F-063), in both layouts:

* **v2** (``collect(ctx)`` collectors): ``kms/keys.json`` items carry ``PolicyStatus``, ``CollectionErrors`` and
  ``null`` for what could not be read (``Grants``, ``Aliases``, key metadata). ``null`` is **unknown**, never
  "no grants" or "no aliases" (coverage-schema.md §1, F-059).
* **legacy** (d13c215): no ``PolicyStatus``; key policies and grants were collected for customer-managed keys
  only and every failure was swallowed. A customer key without a policy file therefore has an **unknown**
  policy (every KMS key has a key policy), and an AWS-managed key's empty ``Grants`` list means "not collected".

Key policies are keyed by the **key ARN** of the unit they were read in, so the replicas of a multi-Region key
(same ``mrk-…`` key id, one policy per Region) are never mixed up (F-081).

:class:`KmsResolver` normalises every KMS reference a collector records (key ARN, key id, alias name, alias ARN,
or nothing with a service default such as ``alias/aws/secretsmanager``) to the key's node id through
``ids.kms_key_node_id`` and the collected aliases of the reference's Region (F-027). Other domains use it through
:func:`kms_resolver` (S3 default encryption, EBS, RDS, SNS/SQS, Secrets Manager, SSM).

The module also holds the small reading helpers the E-data loaders share (``secrets``, ``data_stores``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.io.fs import ls_sorted, read_map, stub_status
from aws_enumerator.engine.io.loaders import LoadResult, read_scoped
from aws_enumerator.engine.policy.arn import is_account_id, parse_arn

log = logging.getLogger(__name__)

GLOBAL_FILES: Dict[str, str] = {}
REGIONAL_FILES = {
    "keys": "kms/keys.json",
}
POLICY_DIR = "kms/key_policies"

#: ``PolicyStatus`` values (coverage-schema.md §1) plus ``unknown`` (no status and no policy).
POLICY_STATUSES: Tuple[str, ...] = ("present", "absent", "denied", "error", "skipped", "unknown")
#: Policy statuses that mean "the policy could not be read" (evaluated as unknown, never as absent).
UNREADABLE = frozenset({"denied", "error", "unknown"})
_MISSING: Any = object()


# ── shared reading helpers (E-data loaders) ──────────────────────────────────

@dataclass(frozen=True)
class ItemErrors:
    """``CollectionErrors`` of one record as gap codes ``<api>:<status>`` (graph-json.md §7.2)."""

    gaps: Tuple[str, ...] = ()

    @classmethod
    def of(cls, record: Mapping[str, Any]) -> "ItemErrors":
        out = set()
        for err in record.get("CollectionErrors") or ():
            if isinstance(err, Mapping) and err.get("api"):
                out.add(f"{err.get('api')}:{err.get('status') or 'error'}")
        return cls(tuple(sorted(out)))

    def __bool__(self) -> bool:
        return bool(self.gaps)


def usable_policy(raw: Any) -> Optional[Mapping[str, Any]]:
    """``raw`` when it is a policy document the evaluator can read, else ``None``.

    The collectors keep a policy that is not JSON as ``{"_raw": text}``; such a document (or any mapping without
    a ``Statement``) cannot be evaluated, so its grants are unknown, never "none".
    """
    if isinstance(raw, Mapping) and "Statement" in raw:
        return raw
    return None


def policy_status(record: Mapping[str, Any], policy: Any, *, legacy_missing: str = "absent") -> str:
    """The resource-policy status of a record (v2 ``PolicyStatus``; legacy: from the policy's presence).

    ``policy`` is the policy as collected. A policy that is there but cannot be read (:func:`usable_policy`) is
    ``error``; a v2 record that says ``present`` but whose policy is missing is ``unknown``; a ``null`` status is
    ``present`` when the policy is there, else ``unknown``.
    """
    raw = record.get("PolicyStatus", _MISSING) if isinstance(record, Mapping) else _MISSING
    has_policy = isinstance(policy, Mapping) and bool(policy)
    readable = usable_policy(policy) is not None
    if raw is not _MISSING and raw is not None and str(raw).lower() != "present":
        status = str(raw).lower()
        return status if status in POLICY_STATUSES else "unknown"
    if readable:
        return "present"
    if has_policy:
        return "error"
    if raw is _MISSING:
        return legacy_missing
    return "unknown"


def is_v2(record: Mapping[str, Any]) -> bool:
    """A record written by a ``collect(ctx)`` collector (it carries ``PolicyStatus``)."""
    return isinstance(record, Mapping) and "PolicyStatus" in record


def unit_region(unit: str, arn: Optional[str] = None) -> Optional[str]:
    """The record's region: from its ARN when it has one, else the unit name (``None`` for ``global``)."""
    p = parse_arn(arn) if isinstance(arn, str) else None
    if p is not None and p.region:
        return p.region
    return None if unit == "global" else unit


def record_account(arn: Optional[str], default: str) -> str:
    p = parse_arn(arn) if isinstance(arn, str) else None
    return p.account if p is not None and is_account_id(p.account) else default


def read_dict_files(units: Mapping[str, Any], rel_dir: str) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, str]]:
    """``{unit: [dict files of <unit>/<rel_dir>/*.json]}`` (sorted) and unreadable-file gaps."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    gaps: Dict[str, str] = {}
    for unit, base in sorted(units.items()):
        folder = Path(base) / rel_dir
        files: List[Dict[str, Any]] = []
        for name in ls_sorted(folder):
            if not name.endswith(".json"):
                continue
            data, res = read_map(folder / name)
            if res.ok:
                files.append(data)
            elif res.status != "missing":
                status = stub_status(res.error_code) if res.status == "error-stub" else "error"
                gaps[f"{rel_dir}:{status}"] = (f"{unit}/{rel_dir}/{name} could not be read "
                                               f"({res.error_code or res.status})")
        out[unit] = files
    return out, gaps


def merge_results(base: LoadResult, gaps: Mapping[str, str]) -> LoadResult:
    """``base`` with extra gaps (``partial`` when there are any)."""
    if not gaps:
        return base
    merged = dict(base.gaps)
    merged.update(gaps)
    status = "partial" if base.status in ("ok", "partial") else base.status
    return LoadResult(base.data, status, merged, base.files)


def str_tuple(value: Any) -> Optional[Tuple[str, ...]]:
    """A list of strings as a sorted tuple; ``None`` stays ``None`` (unknown)."""
    if value is None:
        return None
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(sorted({str(v) for v in value if isinstance(v, (str, int)) and str(v)}))
    return None


# ── KMS records ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class KmsGrantRecord:
    """One KMS grant (``ListGrants``): ``grantee`` may call ``operations`` on the key."""

    grant_id: Optional[str]
    grantee: str
    operations: Tuple[str, ...]
    constrained: bool = False      # EncryptionContextEquals/Subset constraints (the caller must match them)
    name: Optional[str] = None


@dataclass(frozen=True)
class KmsKey:
    """One collected key (one Region's replica for multi-Region keys)."""

    arn: str
    key_id: str
    region: str
    account: str
    manager: Optional[str]                         # "AWS" | "CUSTOMER" | None (DescribeKey failed)
    state: Optional[str]
    multi_region: Optional[bool]
    key_usage: Optional[str]
    aliases: Optional[Tuple[str, ...]]             # alias names; None = unknown
    grants: Optional[Tuple[KmsGrantRecord, ...]]   # None = unknown
    policy: Optional[Mapping[str, Any]]
    policy_status: str
    errors: ItemErrors = field(default_factory=ItemErrors)
    legacy: bool = False

    @property
    def aws_managed(self) -> bool:
        if self.manager is not None:
            return self.manager.upper() == "AWS"
        return any(a.startswith("alias/aws/") for a in self.aliases or ())

    @property
    def label(self) -> str:
        names = [a for a in self.aliases or () if a]
        return names[0] if names else self.key_id


@dataclass
class KmsInventory:
    """Every collected key of the analysed units, the alias map and what could not be read."""

    keys: Tuple[KmsKey, ...] = ()
    aliases: Dict[str, str] = field(default_factory=dict)            # alias ARN -> key ARN
    alias_unknown: Tuple[str, ...] = ()                               # regions whose aliases are unknown
    by_arn: Dict[str, KmsKey] = field(default_factory=dict)

    def key(self, arn: str) -> Optional[KmsKey]:
        return self.by_arn.get(arn)


def _grants(raw: Any, *, legacy: bool, manager: Optional[str]) -> Optional[Tuple[KmsGrantRecord, ...]]:
    if raw is None:
        return None
    if legacy and (manager or "").upper() == "AWS":
        return None          # d13c215 never listed the grants of AWS-managed keys
    out: List[KmsGrantRecord] = []
    for g in raw if isinstance(raw, list) else ():
        if not isinstance(g, Mapping) or not isinstance(g.get("GranteePrincipal"), str):
            continue
        ops = tuple(sorted({str(o) for o in g.get("Operations") or () if isinstance(o, str)}))
        constraints = g.get("Constraints") if isinstance(g.get("Constraints"), Mapping) else {}
        out.append(KmsGrantRecord(g.get("GrantId"), g["GranteePrincipal"], ops,
                                  bool(constraints and any(constraints.values())), g.get("Name")))
    return tuple(sorted(out, key=lambda r: (str(r.grant_id), r.grantee)))


def _key_record(unit: str, rec: Mapping[str, Any], policies: Mapping[str, Mapping[str, Any]],
                account: str) -> Optional[KmsKey]:
    arn, key_id = rec.get("Arn"), rec.get("KeyId")
    if not isinstance(arn, str) or not ids.node_id_matches("kms", arn) or ":key/" not in arn:
        return None
    region = unit_region(unit, arn)
    if region is None:
        return None
    legacy = not is_v2(rec)
    manager = rec.get("KeyManager") if isinstance(rec.get("KeyManager"), str) else None
    raw_policy = (policies.get(arn) or {}).get("Policy")
    status = policy_status(rec, raw_policy,
                           legacy_missing="skipped" if (manager or "").upper() == "AWS" else "unknown")
    policy = usable_policy(raw_policy)
    multi = rec.get("MultiRegion")
    return KmsKey(
        arn=arn, key_id=str(key_id or arn.rsplit("/", 1)[-1]), region=region, account=record_account(arn, account),
        manager=manager, state=rec.get("KeyState") if isinstance(rec.get("KeyState"), str) else None,
        multi_region=multi if isinstance(multi, bool) else (True if str(key_id or "").startswith("mrk-") else None),
        key_usage=rec.get("KeyUsage") if isinstance(rec.get("KeyUsage"), str) else None,
        aliases=str_tuple(rec.get("Aliases")) if "Aliases" in rec else None,
        grants=_grants(rec.get("Grants"), legacy=legacy, manager=manager),
        policy=policy, policy_status=status, errors=ItemErrors.of(rec), legacy=legacy)


def _policies_by_arn(files: Sequence[Mapping[str, Any]], region: Optional[str], account: str,
                     partition: str) -> Dict[str, Mapping[str, Any]]:
    """Key policy files of one unit keyed by key ARN (F-081: never by the shared ``mrk-`` key id)."""
    out: Dict[str, Mapping[str, Any]] = {}
    for f in files:
        arn = f.get("Arn") if isinstance(f.get("Arn"), str) else None
        if arn is None and isinstance(f.get("KeyId"), str) and region:
            arn = f"arn:{partition}:kms:{region}:{account}:key/{f['KeyId']}"
        if arn:
            out[arn] = f
    return out


def build_inventory(keys: Mapping[str, Sequence[Mapping[str, Any]]],
                    policy_files: Mapping[str, Sequence[Mapping[str, Any]]], *, account: str,
                    partition: str) -> KmsInventory:
    """:class:`KmsInventory` from the per-unit key lists and key-policy files."""
    out: List[KmsKey] = []
    aliases: Dict[str, str] = {}
    unknown = set()
    for unit in sorted(keys):
        region = unit_region(unit)
        policies = _policies_by_arn(policy_files.get(unit, ()), region, account, partition)
        for rec in keys[unit]:
            key = _key_record(unit, rec, policies, account) if isinstance(rec, Mapping) else None
            if key is None:
                continue
            out.append(key)
            if key.aliases is None:
                unknown.add(key.region)
            for alias in key.aliases or ():
                alias_arn = alias if alias.startswith("arn:") else \
                    f"arn:{partition}:kms:{key.region}:{key.account}:{alias}"
                aliases.setdefault(alias_arn, key.arn)
    out.sort(key=lambda k: k.arn)
    inv = KmsInventory(tuple(out), aliases, tuple(sorted(unknown)))
    inv.by_arn = {k.arn: k for k in out}
    return inv


# ── the resolver (F-027) ─────────────────────────────────────────────────────

class KmsResolver:
    """KMS references → key node ids through ``ids.kms_key_node_id`` and the collected aliases (F-027)."""

    def __init__(self, inventory: KmsInventory, *, account: str, partition: str):
        self.inventory = inventory
        self.account = account
        self.partition = partition

    def resolve(self, ref: Optional[str], *, region: Optional[str], account: Optional[str] = None,
                default_alias: Optional[str] = None) -> Optional[ids.KmsRef]:
        """The key node a reference names, ``None`` when there is no reference (and no default).

        ``region``/``account`` are those of the resource that holds the reference (an alias or key id is
        relative to them). An unresolvable alias yields the region-qualified alias ARN (a placeholder node).
        """
        if not region:
            p = parse_arn(ref) if isinstance(ref, str) else None
            region = p.region if p is not None and p.region else None
        if not region:
            return None
        try:
            return ids.kms_key_node_id(ref if isinstance(ref, str) else None, partition=self.partition,
                                       region=region, account=account or self.account,
                                       aliases=self.inventory.aliases, default_alias=default_alias)
        except ValueError as exc:
            log.debug("unusable KMS reference: %s", exc)
            return None

    def is_collected(self, key_arn: str) -> bool:
        return key_arn in self.inventory.by_arn

    def aliases_unknown(self, region: Optional[str]) -> bool:
        """True when the aliases of ``region`` could not be listed (an unresolved alias is then unknown)."""
        return region in self.inventory.alias_unknown


# ── loader entry points ──────────────────────────────────────────────────────

def load(ctx: Any) -> LoadResult:
    """Phase LOAD: ``ctx.data["kms"] = {"keys": {unit: [records]}, "inventory": KmsInventory}``."""
    base = read_scoped(ctx, GLOBAL_FILES, REGIONAL_FILES)
    policy_files, gaps = read_dict_files(dict(ctx.region_dirs), POLICY_DIR)
    data = dict(base.data)
    data["inventory"] = build_inventory(data.get("keys", {}), policy_files, account=ctx.account_id,
                                        partition=ctx.partition)
    return merge_results(LoadResult(data, base.status, dict(base.gaps), base.files), gaps)


def kms_inventory(ctx: Any) -> KmsInventory:
    """The loaded :class:`KmsInventory` (empty when KMS was not loaded)."""
    data = (getattr(ctx, "data", None) or {}).get("kms")
    inv = data.get("inventory") if isinstance(data, Mapping) else None
    return inv if isinstance(inv, KmsInventory) else KmsInventory()


def kms_resolver(ctx: Any) -> KmsResolver:
    """The run's :class:`KmsResolver` (one per context, cached in ``ctx.shared``)."""
    shared = getattr(ctx, "shared", None)
    cached = shared.get("kms.resolver") if isinstance(shared, dict) else None
    if isinstance(cached, KmsResolver):
        return cached
    resolver = KmsResolver(kms_inventory(ctx), account=ctx.account_id, partition=ctx.partition)
    if isinstance(shared, dict):
        shared["kms.resolver"] = resolver
    return resolver


def iter_units(units: Mapping[str, Iterable[Any]]) -> Iterable[Tuple[str, Mapping[str, Any]]]:
    """``(unit, record)`` pairs in sorted unit order, dict records only."""
    for unit in sorted(units):
        for rec in units[unit] or ():
            if isinstance(rec, Mapping):
                yield unit, rec


__all__ = [
    "ItemErrors", "KmsGrantRecord", "KmsInventory", "KmsKey", "KmsResolver", "POLICY_STATUSES", "UNREADABLE",
    "build_inventory", "is_v2", "iter_units", "kms_inventory", "kms_resolver", "load", "merge_results",
    "policy_status", "read_dict_files", "record_account", "str_tuple", "unit_region", "usable_policy",
]
