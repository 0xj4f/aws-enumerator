"""S3 buckets: policies, ACLs, public access blocks and configuration (global). Object data is never read.

Calls:

* ``ListBuckets`` through its paginator (``MaxBuckets`` 1000; F-107). ``BucketRegion`` comes with the
  listing, so ``GetBucketLocation`` is called only when it is missing; the legacy ``EU`` location
  constraint is normalised to ``eu-west-1`` and an empty one to ``us-east-1`` (F-138).
* Per bucket, with a client in the bucket's region (``--s3-subresources``, option ``s3_subresources``):

  - ``basic`` (default, at most 7 calls per bucket; F-109): ``GetBucketPolicy``, ``GetBucketPolicyStatus``
    (skipped when the bucket has no policy: a bucket without a policy cannot be public through one),
    ``GetBucketAcl``, ``GetPublicAccessBlock``, ``GetBucketEncryption``,
    ``GetBucketNotificationConfiguration``, ``GetBucketOwnershipControls``;
  - ``full`` adds ``GetBucketVersioning``, ``GetBucketTagging``, ``GetBucketLogging``, ``GetBucketCors``,
    ``GetBucketWebsite``, ``GetBucketReplication``.

* ``s3control:GetPublicAccessBlock(AccountId)``: the account-level Block Public Access (F-023, F-105).

"Not configured" answers (``NoSuchBucketPolicy`` ...) are ``absent``, never confused with a denial (F-058).

Output (``global/s3/``):

``buckets.json``
    list, sorted by ``Name``::

        {Name, Arn, CreationDate, Region: str | null,
         SubResources: {policy, policy_status, acl, public_access_block, encryption, notifications,
                        ownership_controls, versioning, tagging, logging, cors, website, replication},
         PolicyStatus, PolicyIsPublic: bool | null, CollectionErrors?}

    Each ``SubResources`` value is ``present | absent | denied | error | skipped`` (``skipped`` = not
    collected in this mode). ``PolicyStatus`` repeats ``SubResources.policy``. ``PolicyIsPublic`` is
    AWS's own verdict (``GetBucketPolicyStatus``), ``false`` when the bucket has no policy, ``null`` when
    unknown.

Per-bucket files (written only when the sub-resource is ``present``; ``<bucket>`` is the bucket name):

    ``policies/<bucket>.json`` (policy document), ``policy_status/<bucket>.json`` ``{IsPublic}``,
    ``acls/<bucket>.json`` ``{Owner, Grants}``, ``public_access_block/<bucket>.json``,
    ``encryption/<bucket>.json`` (``ServerSideEncryptionConfiguration``),
    ``notifications/<bucket>.json``, ``ownership_controls/<bucket>.json`` ``{Rules}``; full mode also
    ``versioning/``, ``tagging/`` (list of tags), ``logging/`` (``LoggingEnabled``), ``cors/`` (list of
    rules), ``website/``, ``replication/``.

``account_public_access_block.json``
    object ``{Configured: bool | null, BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy,
    RestrictPublicBuckets}``: ``Configured: false`` with every flag ``false`` when the account has no
    configuration; every value ``null`` when it could not be read.

``_coverage.json``
    every call (docs/contracts/coverage-schema.md).
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Tuple

from aws_enumerator.collectors._common import add_error
from aws_enumerator.collectors.base import CollectContext
from aws_enumerator.coverage import CallResult
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="s3", scope="global", output_dir="s3", services=("s3", "s3control"),
    tier=1, cost="high", noise="medium", default=True, groups=("@data",),
    actions=(
        "s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetBucketPolicy", "s3:GetBucketPolicyStatus",
        "s3:GetBucketAcl", "s3:GetBucketPublicAccessBlock", "s3:GetEncryptionConfiguration",
        "s3:GetBucketNotification", "s3:GetBucketOwnershipControls", "s3:GetAccountPublicAccessBlock",
    ),
    optional_actions=(
        "s3:GetBucketVersioning", "s3:GetBucketTagging", "s3:GetBucketLogging", "s3:GetBucketCORS",
        "s3:GetBucketWebsite", "s3:GetReplicationConfiguration",
    ),
    probe=("s3", "ListBuckets", (("MaxBuckets", 1),)),
    outputs=(
        ("buckets.json", "list"), ("account_public_access_block.json", "dict"),
        ("policies/*.json", "dict"), ("policy_status/*.json", "dict"), ("acls/*.json", "dict"),
        ("public_access_block/*.json", "dict"), ("encryption/*.json", "dict"), ("notifications/*.json", "dict"),
        ("ownership_controls/*.json", "dict"), ("versioning/*.json", "dict"), ("tagging/*.json", "list"),
        ("logging/*.json", "dict"), ("cors/*.json", "list"), ("website/*.json", "dict"),
        ("replication/*.json", "dict"),
    ),
    description="S3 buckets: policies, ACLs, public access blocks, encryption, notifications (never object data)",
)

_PAB_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
_US_EAST_1 = "us-east-1"
#: Legacy location constraints that are not region names.
_LEGACY_LOCATIONS = {"EU": "eu-west-1", "": _US_EAST_1}


class SubResource(NamedTuple):
    key: str                                    # SubResources key
    op: str                                     # client method
    subdir: str                                 # per-bucket directory
    extract: Callable[[CallResult], Any]        # file content from a successful result
    full_only: bool = False


def _response(result: CallResult) -> Dict[str, Any]:
    return dict(result.value) if isinstance(result.value, dict) else {}


SUBRESOURCES: Tuple[SubResource, ...] = (
    SubResource("policy", "get_bucket_policy", "policies", lambda r: json.loads(r.get("Policy") or "{}")),
    SubResource("policy_status", "get_bucket_policy_status", "policy_status", lambda r: r.get("PolicyStatus")),
    SubResource("acl", "get_bucket_acl", "acls", lambda r: {"Owner": r.get("Owner"), "Grants": r.get("Grants") or []}),
    SubResource("public_access_block", "get_public_access_block", "public_access_block",
                lambda r: r.get("PublicAccessBlockConfiguration")),
    SubResource("encryption", "get_bucket_encryption", "encryption",
                lambda r: r.get("ServerSideEncryptionConfiguration")),
    SubResource("notifications", "get_bucket_notification_configuration", "notifications", _response),
    SubResource("ownership_controls", "get_bucket_ownership_controls", "ownership_controls",
                lambda r: r.get("OwnershipControls")),
    SubResource("versioning", "get_bucket_versioning", "versioning", _response, True),
    SubResource("tagging", "get_bucket_tagging", "tagging", lambda r: list(r.get("TagSet") or []), True),
    SubResource("logging", "get_bucket_logging", "logging", lambda r: r.get("LoggingEnabled"), True),
    SubResource("cors", "get_bucket_cors", "cors", lambda r: list(r.get("CORSRules") or []), True),
    SubResource("website", "get_bucket_website", "website", _response, True),
    SubResource("replication", "get_bucket_replication", "replication",
                lambda r: r.get("ReplicationConfiguration"), True),
)


def normalise_region(location: Optional[str]) -> str:
    """Bucket region from a ``LocationConstraint`` / ``BucketRegion`` (``None``/``""`` -> us-east-1, ``EU``
    -> eu-west-1)."""
    if location is None:
        return _US_EAST_1
    return _LEGACY_LOCATIONS.get(location, location)


def _mode(ctx: CollectContext) -> str:
    mode = str(ctx.option("s3_subresources", "basic") or "basic").lower()
    if mode not in ("basic", "full"):
        ctx.log.warning("unknown s3_subresources %r; using 'basic'", mode)
        return "basic"
    return mode


def collect(ctx: CollectContext) -> None:
    """Buckets (all pages), their sub-resources, then the account-level public access block."""
    full = _mode(ctx) == "full"
    s3 = ctx.client("s3")
    buckets: List[Dict[str, Any]] = []
    with ctx.section("buckets"):
        listed = ctx.paginate(s3, "list_buckets", "Buckets", page_size=1000, primary=True)
        buckets = sorted((b for b in listed.value if isinstance(b, dict) and b.get("Name")),
                         key=lambda b: str(b["Name"]))
    if buckets and not full:
        for sub in SUBRESOURCES:
            if sub.full_only:
                ctx.cov.skip(_api(s3, sub.op), "s3_subresources=basic")
    records: List[Dict[str, Any]] = []
    with ctx.section("bucket_details"):
        for bucket in buckets:
            records.append(_bucket(ctx, s3, bucket, full))
    ctx.out.write("buckets.json", records)

    account_pab: Dict[str, Any] = {"Configured": None, **{flag: None for flag in _PAB_FLAGS}}
    with ctx.section("account_public_access_block"):
        account_pab = _account_pab(ctx)
    ctx.out.write("account_public_access_block.json", account_pab)


def _api(client: Any, op: str) -> str:
    meta = client.meta
    return f"{meta.service_model.service_name}:{meta.method_to_api_mapping[op]}"


def _bucket(ctx: CollectContext, s3: Any, bucket: Dict[str, Any], full: bool) -> Dict[str, Any]:
    name = bucket["Name"]
    arn = ctx.arn("s3", name, region="", account="")
    record: Dict[str, Any] = {"Name": name, "Arn": arn, "CreationDate": bucket.get("CreationDate"),
                              "Region": None}
    if bucket.get("BucketRegion"):
        record["Region"] = normalise_region(bucket["BucketRegion"])
    else:
        location = ctx.call(s3, "get_bucket_location", item=arn, Bucket=name)
        if location.ok:
            record["Region"] = normalise_region(location.get("LocationConstraint"))
        add_error(record, location)
    client = ctx.client("s3", record["Region"]) if record["Region"] else s3
    statuses: Dict[str, str] = {}
    is_public: Optional[bool] = None
    for sub in SUBRESOURCES:
        if sub.full_only and not full:
            statuses[sub.key] = "skipped"
            continue
        if sub.key == "policy_status" and statuses.get("policy") == "absent":
            statuses[sub.key] = "absent"  # no policy: nothing to evaluate, no call
            continue
        statuses[sub.key], content = _subresource(ctx, client, sub, record)
        if sub.key == "policy_status" and isinstance(content, dict):
            is_public = bool(content.get("IsPublic"))
    record["SubResources"] = statuses
    record["PolicyStatus"] = statuses["policy"]
    # AWS's verdict when read; a bucket without a policy is not public through one; else unknown.
    record["PolicyIsPublic"] = False if statuses["policy_status"] == "absent" else is_public
    errors = record.pop("CollectionErrors", None)
    if errors:
        record["CollectionErrors"] = errors  # last, after the data fields
    return record


def _subresource(ctx: CollectContext, client: Any, sub: SubResource, record: Dict[str, Any]) -> Tuple[str, Any]:
    """One per-bucket call: ``(status, content)``; writes the file when present, ``CollectionErrors`` when
    it failed."""
    result = ctx.call(client, sub.op, item=record["Arn"], Bucket=record["Name"])
    add_error(record, result)
    status = result.policy_status()
    if status != "present":
        return status, None
    try:  # one malformed answer or unwritable file never aborts the other buckets
        content = sub.extract(result)
        if content is None:
            return "absent", None
        ctx.out.write(f"{sub.subdir}/{record['Name']}.json", content)
    except Exception as exc:
        code = type(exc).__name__
        ctx.cov.item_error(record["Arn"], result.api, "error", code)
        ctx.log.warning("%s for %s: cannot record the answer (%s)", result.api, record["Name"], code)
        record.setdefault("CollectionErrors", []).append({"api": result.api, "status": "error", "error_code": code})
        return "error", None
    return status, content


def _account_pab(ctx: CollectContext) -> Dict[str, Any]:
    out: Dict[str, Any] = {"Configured": None, **{flag: None for flag in _PAB_FLAGS}}
    control = ctx.client("s3control")
    result = ctx.call(control, "get_public_access_block", AccountId=ctx.account_id)
    if result.has_data:
        config = result.get("PublicAccessBlockConfiguration") or {}
        out["Configured"] = True
        out.update({flag: bool(config.get(flag, False)) for flag in _PAB_FLAGS})
    elif result.ok:  # NoSuchPublicAccessBlockConfiguration: nothing blocks at account level
        out["Configured"] = False
        out.update({flag: False for flag in _PAB_FLAGS})
    return out
