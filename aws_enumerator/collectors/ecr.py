"""ECR repositories and registry: repository policies, the registry policy and replication.

Output (``<region>/ecr/``):

* ``resources.json`` (list), one item per repository, sorted by ``Arn``::

    {Type: "ecr", Arn, Name, RegistryId, Policy: {...}|null, PolicyStatus, ImageTagMutability,
     ScanOnPush: bool|null, EncryptionType, KmsKey: str|null, CollectionErrors?}

  ``PolicyStatus`` separates "no policy" (``RepositoryPolicyNotFoundException`` is not
  configured, so ``absent``) from a denied or throttled read (``denied``/``error``, F-059).
* ``registry_policy.json`` (dict): ``{RegistryId, Policy: {...}|null, PolicyStatus, CollectionErrors?}``
  (the registry permission policy that can grant cross-account replication / repository creation, F-116).
* ``registry.json`` (dict): ``{RegistryId, ReplicationRules: [{Destinations: [{Region, RegistryId}],
  RepositoryFilters}]|null, CollectionErrors?}``.
"""

from __future__ import annotations

from typing import Any, Dict, List

from aws_enumerator.collectors._common import add_error, policy_doc
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="ecr", scope="regional", output_dir="ecr", services=("ecr",),
    tier=1, cost="low", noise="low", default=True, groups=("@data",),
    actions=("ecr:DescribeRepositories", "ecr:GetRepositoryPolicy", "ecr:GetRegistryPolicy",
             "ecr:DescribeRegistry"),
    probe=("ecr", "DescribeRepositories", (("maxResults", 1),)),
    outputs=(("resources.json", "list"), ("registry_policy.json", "dict"), ("registry.json", "dict")),
    description="ECR repositories, repository and registry policies, replication",
)


def _repository(ctx: Any, ecr: Any, repo: Dict[str, Any]) -> Dict[str, Any]:
    name = repo.get("repositoryName")
    arn = repo.get("repositoryArn") or ctx.arn("ecr", f"repository/{name}")
    scanning = repo.get("imageScanningConfiguration") or {}
    encryption = repo.get("encryptionConfiguration") or {}
    item: Dict[str, Any] = {
        "Type": "ecr", "Arn": arn, "Name": name, "RegistryId": repo.get("registryId"),
        "Policy": None, "PolicyStatus": None, "ImageTagMutability": repo.get("imageTagMutability"),
        "ScanOnPush": scanning.get("scanOnPush"), "EncryptionType": encryption.get("encryptionType"),
        "KmsKey": encryption.get("kmsKey"),
    }
    params = {"repositoryName": name}
    if repo.get("registryId"):
        params["registryId"] = repo["registryId"]
    result = ctx.call(ecr, "get_repository_policy", item=arn, **params)
    item["Policy"] = policy_doc(result.get("policyText")) if result.ok else None
    item["PolicyStatus"] = ("present" if item["Policy"] else "absent") if result.ok else result.policy_status()
    add_error(item, result)
    return item


def _registry_policy(ctx: Any, ecr: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"RegistryId": ctx.account_id, "Policy": None, "PolicyStatus": None}
    result = ctx.call(ecr, "get_registry_policy")
    if result.ok:
        out["RegistryId"] = result.get("registryId") or ctx.account_id
        out["Policy"] = policy_doc(result.get("policyText"))
        out["PolicyStatus"] = "present" if out["Policy"] else "absent"
    else:
        out["PolicyStatus"] = result.policy_status()
        add_error(out, result)
    return out


def _registry(ctx: Any, ecr: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"RegistryId": ctx.account_id, "ReplicationRules": None}
    result = ctx.call(ecr, "describe_registry")
    if not result.ok:
        add_error(out, result)
        return out
    out["RegistryId"] = result.get("registryId") or ctx.account_id
    rules = (result.get("replicationConfiguration") or {}).get("rules") or []
    out["ReplicationRules"] = [
        {"Destinations": [{"Region": d.get("region"), "RegistryId": d.get("registryId")}
                          for d in rule.get("destinations") or []],
         "RepositoryFilters": [{"Filter": f.get("filter"), "FilterType": f.get("filterType")}
                               for f in rule.get("repositoryFilters") or []]}
        for rule in rules]
    return out


def collect(ctx: Any) -> None:
    ecr = ctx.client("ecr")
    repos: List[Dict[str, Any]] = []
    with ctx.section("repositories"):
        listed = ctx.paginate(ecr, "describe_repositories", "repositories", page_size=1000, primary=True)
        for repo in listed.value:
            repos.append(_repository(ctx, ecr, repo))
    repos.sort(key=lambda r: r["Arn"])
    ctx.out.write("resources.json", repos)
    with ctx.section("registry_policy"):
        ctx.out.write("registry_policy.json", _registry_policy(ctx, ecr))
    with ctx.section("registry"):
        ctx.out.write("registry.json", _registry(ctx, ecr))
    ctx.log.info("%d repositories", len(repos))
