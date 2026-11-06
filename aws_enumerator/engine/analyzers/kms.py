"""KMS analyzer (E-data, Wave 2): who can use, administer or is granted each KMS key (engine.md §2.4 step 7).

Native on the Wave 1 policy evaluator and :class:`~aws_enumerator.engine.graph.builder.GraphBuilder`:

* **Key policy first** ("Key policies in AWS KMS"). Every collected key policy is registered with the evaluator
  (layer ``key_policy``, keyed by the key **ARN**, so the replicas of a multi-Region key keep their own policies,
  F-081), every grant from ``ListGrants`` is registered as a KMS grant, an AWS-managed key without a policy is
  registered as such (``via_service_only``: CONDITIONAL/STRONG) and a customer-managed key whose policy could not
  be read is ``unknown`` (CONDITIONAL/WEAK with the gap ``kms:key-policy-unknown``; F-028, F-029). The evaluator
  then decides each (principal, action, key) request: a principal the key policy names is allowed by the key
  policy alone; an IAM permission counts only when the key policy delegates to the account (the root principal
  or the account id) and the identity policy allows the action **on the key ARN** — an alias ARN in an IAM
  ``Resource`` never matches a key (only ``kms:ResourceAliases``, which is supplied from the collected aliases,
  can scope by alias; F-028). Deny, NotAction, conditions, boundaries and SCPs count (F-001, F-014, F-015).
* **Edges** (grantee → key, engine.md §6.3): ``CAN_DECRYPT`` (Decrypt, ReEncryptFrom), ``CAN_ADMIN_KEY``
  (PutKeyPolicy, CreateGrant, ScheduleKeyDeletion, DisableKey, CancelKeyDeletion), ``CAN_ENCRYPT`` (info:
  Encrypt, ReEncryptTo and every ``GenerateDataKey*``, which create new data keys and cannot decrypt existing
  ciphertext, F-028); a same-account principal **named** in the key policy for decrypt gets
  ``KMS_GRANTS_DECRYPT`` (F-029, F-088); a decrypt-capable grant gives ``KMS_GRANT`` from the grantee (a
  constrained grant is conditional); public and cross-account key-policy grants give ``KMS_GRANTS_PUBLIC`` from
  the anonymous node and ``KMS_GRANTS_CROSS_ACCOUNT`` from the foreign account or principal, with ``KMS-PUB-001``
  and ``KMS-XACCT-001`` graded by condition strength (a ``kms:CallerAccount`` / ``kms:ViaService`` guard is not
  public; F-031).
* **Unknown is not absent**: ``Grants: null`` / ``Aliases: null`` / ``PolicyStatus`` ``denied``/``error`` are
  node coverage gaps and report-level gaps, never "no grants" (``requests/c-b-1.md``, F-059).

The legacy ``kms_relationships.json`` is rendered from these edges by the legacy writer (one release).
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from aws_enumerator.engine.analyzers.data_stores import (
    AccessClass, AccessEmitter, Candidate, ClassResult, DomainEvaluator, ExposureSpec, add_edge, add_resource_node,
    emit_exposure, node_coverage, plain_resolver, policy_gaps,
)
from aws_enumerator.engine.findings.catalog import A_EXPOSURE, CatalogEntry
from aws_enumerator.engine.io.loaders.kms import UNREADABLE, KmsGrantRecord, KmsKey, kms_inventory
from aws_enumerator.engine.model import AnalyzerSpec, Grant, Phase, PolicyDoc
from aws_enumerator.engine.policy.glob import glob_overlap

log = logging.getLogger(__name__)

# ── action classes (d13c215 names, contents fixed by F-028) ─────────────────────

#: Actions that recover plaintext of existing ciphertext.
KMS_DECRYPT_ACTIONS = ["kms:Decrypt", "kms:ReEncryptFrom"]
#: Actions that only produce ciphertext or new data keys (info edge; GenerateDataKey* cannot decrypt, F-028).
KMS_ENCRYPT_ACTIONS = ["kms:Encrypt", "kms:ReEncryptTo", "kms:GenerateDataKey",
                       "kms:GenerateDataKeyWithoutPlaintext", "kms:GenerateDataKeyPair",
                       "kms:GenerateDataKeyPairWithoutPlaintext"]
#: Control of the key: rewrite its policy or grant oneself decrypt, or destroy it.
KMS_ADMIN_ACTIONS = ["kms:PutKeyPolicy", "kms:CreateGrant", "kms:ScheduleKeyDeletion", "kms:DisableKey",
                     "kms:CancelKeyDeletion"]

KMS_CLASSES = (AccessClass("CAN_ADMIN_KEY", tuple(KMS_ADMIN_ACTIONS)),
               AccessClass("CAN_DECRYPT", tuple(KMS_DECRYPT_ACTIONS)),
               AccessClass("CAN_ENCRYPT", tuple(KMS_ENCRYPT_ACTIONS)))
#: The info edge is redundant next to a decrypt or admin edge that is at least as definite.
KMS_DOMINANCE = {"CAN_ADMIN_KEY": ("CAN_ENCRYPT",), "CAN_DECRYPT": ("CAN_ENCRYPT",)}
#: Grant operations that recover plaintext (``ListGrants`` operation names, lower-cased).
DECRYPT_OPERATIONS = frozenset({"decrypt", "reencryptfrom"})
_GRANTEE_TYPES = frozenset({"user", "role", "external_account", "external_principal", "service_principal"})

FINDINGS: Tuple[CatalogEntry, ...] = (
    CatalogEntry("KMS-PUB-001", "HIGH", "kms_public", "Key policy grants everyone",
                 "Scope the Principal or add a restrictive Condition (kms:CallerAccount, aws:PrincipalOrgID).",
                 A_EXPOSURE),
    CatalogEntry("KMS-XACCT-001", "MEDIUM", "kms_cross_account", "Key policy grants another account",
                 "Verify that cross-account use of the key is intended; remove accounts that should not use it.",
                 A_EXPOSURE),
)

KMS_EXPOSURE = ExposureSpec("KMS_GRANTS_PUBLIC", "KMS_GRANTS_CROSS_ACCOUNT", "KMS-PUB-001", "KMS-XACCT-001",
                            tuple(KMS_DECRYPT_ACTIONS + KMS_ENCRYPT_ACTIONS + KMS_ADMIN_ACTIONS), "KMS key", "kms",
                            "KeyPolicy", "kms_key_policy")


# ── per key ──────────────────────────────────────────────────────────────────

def key_context(key: KmsKey):
    """``context_for(account)``: the KMS request keys the collected data fixes for a caller of ``account``.

    ``kms:CallerAccount`` is the caller's account (unknown for "any AWS principal"); ``kms:ResourceAliases`` is
    the key's collected alias list (left unknown when the aliases could not be listed).
    """
    aliases = tuple(key.aliases) if key.aliases is not None else None

    def context_for(account: Optional[str]) -> Optional[Mapping[str, Any]]:
        out: Dict[str, Any] = {}
        if account:
            out["kms:CallerAccount"] = account
        if aliases is not None:
            out["kms:ResourceAliases"] = aliases if aliases else None
        return out or None

    return context_for


def register_key(dev: DomainEvaluator, key: KmsKey) -> Optional[PolicyDoc]:
    """Key policy, grants and AWS-managed status into the evaluator's index (requests/e-policy-1.md)."""
    res = dev.resources
    for g in key.grants or ():
        res.add_kms_grant(key.arn, g.grantee, g.operations, g.grant_id)
    res.set_owner(key.arn, key.account)
    if key.policy_status == "present" and key.policy is not None:
        return res.add(key.arn, dict(key.policy), layer="key_policy", owner=key.account)
    if key.aws_managed:
        res.set_aws_managed_key(key.arn)
    else:
        res.mark_unknown(key.arn, layer="key_policy")
    return None


def _key_gaps(dev: DomainEvaluator, key: KmsKey) -> List[str]:
    gaps = policy_gaps(dev.ctx, "kms", "kms:GetKeyPolicy", key.region, key.arn,
                       "unknown" if key.policy_status == "absent" else key.policy_status)
    if key.legacy:
        return gaps
    if key.aliases is None:
        gaps.append("kms:ListAliases:unknown")
    if key.grants is None:
        gaps.append("kms:ListGrants:unknown")
    if key.manager is None:
        gaps.append("kms:DescribeKey:unknown")
    return gaps


def key_node(dev: DomainEvaluator, builder: Any, key: KmsKey) -> str:
    props = {"key_id": key.key_id, "aliases": list(key.aliases) if key.aliases is not None else None,
             "key_manager": key.manager, "aws_managed": key.aws_managed, "key_state": key.state,
             "multi_region": key.multi_region, "key_usage": key.key_usage, "policy_status": key.policy_status,
             "grant_count": len(key.grants) if key.grants is not None else None}
    return add_resource_node(builder, "kms", key.arn, key.label, region=key.region, account=key.account,
                             props=props, coverage=node_coverage(dev.ctx, "kms", key.region, key.errors,
                                                                 legacy=key.legacy, extra=_key_gaps(dev, key)))


def _decrypt_grantees(builder: Any, dev: DomainEvaluator, grants: List[Grant]) -> Set[str]:
    """Same-account users/roles the key policy names directly for a decrypt action (``KMS_GRANTS_DECRYPT``)."""
    out: Set[str] = set()
    for g in grants:
        p = g.principal
        if p.kind not in ("aws_user", "aws_role", "aws_assumed_role") or p.account != dev.account:
            continue
        if not g.decision.grants or not any(glob_overlap(a, d.lower()) for a in g.actions
                                            for d in KMS_DECRYPT_ACTIONS):
            continue
        ref = builder.ensure_principal(p.arn or p.raw, principal_type="AWS")
        if ref.node_id is not None:
            out.add(ref.node_id)
    return out


def key_access(dev: DomainEvaluator, builder: Any, emitter: AccessEmitter, key: KmsKey, grants: List[Grant], *,
               public_allows: bool) -> int:
    """Identity / key-policy access edges to one key (key-policy-first, module docstring)."""
    named = _decrypt_grantees(builder, dev, grants)

    def rename(cand: Candidate, res: ClassResult) -> str:
        if res.edge_type == "CAN_DECRYPT" and cand.node_id in named:
            return "KMS_GRANTS_DECRYPT"
        return res.edge_type

    resolve = plain_resolver(dev, key.arn, context_for=key_context(key), key_policy=True)
    return emitter.emit(key.arn, emitter.candidates(grants), resolve, public_allows=public_allows, rename=rename,
                        evidence={"key_policy": key.policy_status, "aws_managed": key.aws_managed or None})


def _grantee_type(grantee: str) -> str:
    """``GranteePrincipal`` is an ARN, an account id or a service principal (``rds.eu-west-1.amazonaws.com``)."""
    if grantee.endswith(".amazonaws.com") or grantee.endswith(".amazonaws.com.cn"):
        return "Service"
    return "AWS"


def grant_edges(builder: Any, key: KmsKey) -> int:
    """``KMS_GRANT`` grantee → key for every grant whose operations can decrypt (F-029, F-039)."""
    count = 0
    for g in key.grants or ():
        if not {o.lower() for o in g.operations} & DECRYPT_OPERATIONS:
            continue
        ref = builder.ensure_principal(g.grantee, principal_type=_grantee_type(g.grantee))
        if ref.node_id is None or ref.node_type not in _GRANTEE_TYPES:
            continue
        add_edge(builder, ref.node_id, "KMS_GRANT", key.arn, confidence="conditional" if g.constrained else None,
                 strength="weak" if g.constrained else None,
                 evidence={"grant_id": g.grant_id, "operations": sorted(g.operations),
                           "constrained": g.constrained or None},
                 props={"cross_account": True} if ref.external else None)
        count += 1
    return count


# ── the analyzer ─────────────────────────────────────────────────────────────

def run_kms(ctx: Any, builder: Any) -> None:
    """Analyzer ``kms`` (phase RESOURCES)."""
    inv = kms_inventory(ctx)
    dev = DomainEvaluator(ctx)
    docs = {key.arn: register_key(dev, key) for key in inv.keys}
    emitter = AccessEmitter(dev, builder, ("kms",), KMS_CLASSES, dominance=KMS_DOMINANCE)
    for key in inv.keys:
        key_node(dev, builder, key)
        grants = dev.grants(docs[key.arn], key.arn)
        spec = replace(KMS_EXPOSURE, context_for=key_context(key))
        exposure = emit_exposure(dev, builder, key.arn, key.arn, grants, spec, name=key.label, region=key.region)
        key_access(dev, builder, emitter, key, grants, public_allows=exposure.public_allows)
        grant_edges(builder, key)
    report_gaps(ctx, inv.keys, inv.alias_unknown)


def report_gaps(ctx: Any, keys: Tuple[KmsKey, ...], alias_unknown: Tuple[str, ...]) -> None:
    unknown = [k for k in keys if not k.aws_managed and (k.policy_status in UNREADABLE or k.policy_status in
                                                          ("absent", "skipped"))]
    if unknown:
        ctx.add_gap("kms:key-policy-unknown", "Customer-managed KMS keys whose key policy could not be read: who "
                    "may use them is evaluated as conditional (the key policy decides first).", len(unknown))
    grants = sum(1 for k in keys if k.grants is None and not (k.legacy and k.aws_managed))
    if grants:
        ctx.add_gap("kms:grants-unknown", "KMS keys whose grants could not be listed: grant-based access to them "
                    "is unknown, not absent.", grants)
    if alias_unknown:
        ctx.add_gap("kms:aliases-unknown", "KMS aliases could not be listed in " + ", ".join(alias_unknown)
                    + ": key references by alias there stay unresolved placeholders.", len(alias_unknown))


ANALYZERS: Tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec("kms", Phase.RESOURCES, run_kms, inputs=("kms",), legacy_files=("kms_relationships.json",)),
)


__all__ = [
    "ANALYZERS", "DECRYPT_OPERATIONS", "FINDINGS", "KMS_ADMIN_ACTIONS", "KMS_CLASSES",
    "KMS_DECRYPT_ACTIONS", "KMS_DOMINANCE", "KMS_ENCRYPT_ACTIONS", "KMS_EXPOSURE", "KmsGrantRecord", "grant_edges",
    "key_access", "key_context", "key_node", "register_key", "report_gaps", "run_kms",
]
