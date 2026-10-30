"""Secrets Manager: secret metadata and resource policies (never secret values).

Output (``<region>/secretsmanager/``):

* ``secrets.json`` (list), one item per secret (secrets scheduled for deletion included), sorted by ``ARN``::

    {ARN, Name, KmsKeyId, RotationEnabled, RotationLambdaARN, LastRotatedDate, LastAccessedDate,
     LastChangedDate, DeletedDate, OwningService, PrimaryRegion, CreatedDate, PolicyStatus,
     CollectionErrors?}

  ``Description`` and ``Tags`` are free text that sometimes hold hints or secrets; they are kept
  only with ``--keep-sensitive-metadata`` (option ``keep_sensitive_metadata``, F-112).
* ``resource_policies/<slug(name)>-<sha256(ARN)[:12]>.json`` (dict): ``{SecretArn, SecretName,
  ResourcePolicy}`` for every secret that has a policy. The file name comes from the ARN, so
  ``demo/db`` and ``demo_db`` never collide and long names never exceed the file-name limit (F-114).

``PolicyStatus`` is ``present``/``absent``/``denied``/``error``/``skipped`` (F-059); the policy of a
secret scheduled for deletion is not read (``skipped``).
"""

from __future__ import annotations

from typing import Any, Dict, List

from aws_enumerator.collectors._common import add_error, policy_doc
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="secretsmanager", scope="regional", output_dir="secretsmanager", services=("secretsmanager",),
    tier=1, cost="low", noise="low", default=True, groups=("@data",),
    actions=("secretsmanager:ListSecrets", "secretsmanager:GetResourcePolicy"),
    probe=("secretsmanager", "ListSecrets", (("MaxResults", 1),)),
    outputs=(("secrets.json", "list"), ("resource_policies/*.json", "dict")),
    description="Secrets Manager secret metadata and resource policies (never values)",
)

_API_POLICY = "secretsmanager:GetResourcePolicy"
_FIELDS = ("ARN", "Name", "KmsKeyId", "RotationEnabled", "RotationLambdaARN", "LastRotatedDate",
           "LastAccessedDate", "LastChangedDate", "DeletedDate", "OwningService", "PrimaryRegion", "CreatedDate")
_SENSITIVE_FIELDS = ("Description", "Tags")


def project_secret(entry: Dict[str, Any], keep_sensitive: bool) -> Dict[str, Any]:
    """The stored projection of one ``SecretListEntry`` (F-112)."""
    item = {k: entry.get(k) for k in _FIELDS}
    if keep_sensitive:
        item.update({k: entry.get(k) for k in _SENSITIVE_FIELDS})
    item["PolicyStatus"] = None
    return item


def _write_policy(ctx: Any, item: Dict[str, Any], doc: Dict[str, Any]) -> None:
    data = {"SecretArn": item["ARN"], "SecretName": item["Name"], "ResourcePolicy": doc}
    try:
        ctx.out.write_item("resource_policies", item["ARN"], data, hint=item["Name"])
    except OSError as exc:  # one bad file must not cost the other secrets their policies (F-114)
        ctx.cov.item_error(item["ARN"], _API_POLICY, "error", type(exc).__name__)
        item["PolicyStatus"] = "error"
        item.setdefault("CollectionErrors", []).append(
            {"api": _API_POLICY, "status": "error", "error_code": type(exc).__name__})


def _policy(ctx: Any, sm: Any, item: Dict[str, Any]) -> None:
    if item.get("DeletedDate"):
        ctx.cov.skip(_API_POLICY, "PlannedDeletion")
        item["PolicyStatus"] = "skipped"
        return
    result = ctx.call(sm, "get_resource_policy", item=item["ARN"], SecretId=item["ARN"])
    if not result.ok:
        item["PolicyStatus"] = result.policy_status()
        add_error(item, result)
        return
    doc = policy_doc(result.get("ResourcePolicy"))
    item["PolicyStatus"] = "present" if doc else "absent"
    if doc:
        _write_policy(ctx, item, doc)


def collect(ctx: Any) -> None:
    sm = ctx.client("secretsmanager")
    keep_sensitive = bool(ctx.option("keep_sensitive_metadata", False))
    secrets: List[Dict[str, Any]] = []
    with ctx.section("secrets"):
        listed = ctx.paginate(sm, "list_secrets", "SecretList", page_size=100, primary=True,
                              IncludePlannedDeletion=True)
        secrets = sorted((project_secret(e, keep_sensitive) for e in listed.value if e.get("ARN")),
                         key=lambda s: s["ARN"])
    with ctx.section("policies"):
        for item in secrets:
            _policy(ctx, sm, item)
    ctx.out.write("secrets.json", secrets)
    ctx.log.info("%d secrets", len(secrets))
