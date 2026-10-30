"""KMS: keys, aliases, key policies and grants.

KMS is a separate authorisation plane: a key policy or a grant can allow decrypt independently of
IAM, so this module answers "who can decrypt the keys that protect secrets, parameters, buckets, volumes".

Output (``<region>/kms/``):

* ``keys.json`` (list), one item per key from ``ListKeys``, sorted by ``Arn``::

    {KeyId, Arn, KeyManager, KeyState, Origin, Description, Enabled, KeySpec, KeyUsage, MultiRegion,
     MultiRegionConfiguration, Aliases: [name]|null, PolicyStatus,
     Grants: [{GrantId, Name, GranteePrincipal, RetiringPrincipal, Operations, Constraints, IssuingAccount}]|null,
     CollectionErrors?}

  A key whose ``DescribeKey`` is denied is **kept** with the ARN ``ListKeys`` returned and ``null``
  metadata (F-102); its policy and grants are still attempted. ``Grants`` is ``null`` when they could
  not be listed, never ``[]`` (F-059). Grants are listed for every key (AWS-managed keys carry service
  grants too); key policies are read for customer-managed keys only (``PolicyStatus: "skipped"`` for
  AWS-managed keys, whose policies cannot be changed).
* ``key_policies/<KeyId>.json`` (dict): ``{KeyId, Arn, Policy}`` (KMS key ids are file-name safe).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_enumerator.collectors._common import add_error, policy_doc
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="kms", scope="regional", output_dir="kms", services=("kms",),
    tier=1, cost="medium", noise="low", default=True, groups=("@data",),
    actions=("kms:ListKeys", "kms:ListAliases", "kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListGrants"),
    probe=("kms", "ListKeys", (("Limit", 1),)),
    outputs=(("keys.json", "list"), ("key_policies/*.json", "dict")),
    description="KMS keys, aliases, key policies and grants",
)

_META_FIELDS = ("KeyManager", "KeyState", "Origin", "Description", "Enabled", "KeySpec", "KeyUsage", "MultiRegion",
                "MultiRegionConfiguration")
_API_KEY_POLICY = "kms:GetKeyPolicy"


def _aliases(ctx: Any, kms: Any) -> Optional[Dict[str, List[str]]]:
    """``{target key id: [alias names]}``, or ``None`` when the aliases could not be listed."""
    result = ctx.paginate(kms, "list_aliases", "Aliases", page_size=100)
    if not result.ok:
        return None
    mapping: Dict[str, List[str]] = {}
    for alias in result.value:
        target = alias.get("TargetKeyId")
        if target and alias.get("AliasName"):
            mapping.setdefault(target, []).append(alias["AliasName"])
    return {k: sorted(v) for k, v in mapping.items()}


def _describe(ctx: Any, kms: Any, item: Dict[str, Any]) -> None:
    result = ctx.call(kms, "describe_key", item=item["Arn"], KeyId=item["KeyId"])
    if not result.ok:
        add_error(item, result)
        return
    meta = result.get("KeyMetadata") or {}
    item["Arn"] = meta.get("Arn") or item["Arn"]
    item.update({k: meta.get(k) for k in _META_FIELDS})


def _key_policy(ctx: Any, kms: Any, item: Dict[str, Any]) -> None:
    if item["KeyManager"] == "AWS":
        ctx.cov.skip(_API_KEY_POLICY, "AwsManagedKey")
        item["PolicyStatus"] = "skipped"
        return
    result = ctx.call(kms, "get_key_policy", item=item["Arn"], KeyId=item["KeyId"], PolicyName="default")
    if not result.ok:
        item["PolicyStatus"] = result.policy_status()
        add_error(item, result)
        return
    doc = policy_doc(result.get("Policy"))
    item["PolicyStatus"] = "present" if doc else "absent"
    if doc is None:
        return
    try:
        ctx.out.write(f"key_policies/{item['KeyId']}.json", {"KeyId": item["KeyId"], "Arn": item["Arn"],
                                                              "Policy": doc})
    except (OSError, ValueError) as exc:
        ctx.cov.item_error(item["Arn"], _API_KEY_POLICY, "error", type(exc).__name__)
        item["PolicyStatus"] = "error"
        item.setdefault("CollectionErrors", []).append(
            {"api": _API_KEY_POLICY, "status": "error", "error_code": type(exc).__name__})


def _grants(ctx: Any, kms: Any, item: Dict[str, Any]) -> None:
    result = ctx.paginate(kms, "list_grants", "Grants", item=item["Arn"], KeyId=item["KeyId"])
    if not result.ok:
        add_error(item, result)
        return
    keys = ("GrantId", "Name", "GranteePrincipal", "RetiringPrincipal", "Operations", "Constraints",
            "IssuingAccount")
    item["Grants"] = sorted(({k: g.get(k) for k in keys} for g in result.value), key=lambda g: str(g["GrantId"]))


def _key(ctx: Any, kms: Any, listed: Dict[str, Any], aliases: Optional[Dict[str, List[str]]]) -> Dict[str, Any]:
    key_id = listed["KeyId"]
    item: Dict[str, Any] = {"KeyId": key_id, "Arn": listed.get("KeyArn") or ctx.arn("kms", f"key/{key_id}")}
    item.update({k: None for k in _META_FIELDS})
    item.update({"Aliases": None if aliases is None else aliases.get(key_id, []), "PolicyStatus": None,
                 "Grants": None})
    _describe(ctx, kms, item)
    _key_policy(ctx, kms, item)
    _grants(ctx, kms, item)
    return item


def collect(ctx: Any) -> None:
    kms = ctx.client("kms")
    keys: List[Dict[str, Any]] = []
    aliases: Optional[Dict[str, List[str]]] = None
    listed: List[Dict[str, Any]] = []
    with ctx.section("keys"):
        listed = ctx.paginate(kms, "list_keys", "Keys", page_size=1000, primary=True).value
    with ctx.section("aliases"):
        aliases = _aliases(ctx, kms)
    with ctx.section("key_details"):
        for entry in sorted(listed, key=lambda k: str(k.get("KeyArn") or k.get("KeyId"))):
            if entry.get("KeyId"):
                keys.append(_key(ctx, kms, entry, aliases))
    keys.sort(key=lambda k: k["Arn"])
    ctx.out.write("keys.json", keys)
    customer = sum(1 for k in keys if k.get("KeyManager") == "CUSTOMER")
    ctx.log.info("%d keys (%d customer-managed)", len(keys), customer)
