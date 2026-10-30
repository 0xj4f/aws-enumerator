"""SageMaker: notebook instances, Studio domains and user profiles, and the execution roles they use.

A notebook runs as its execution role (PRIVESC-020); a Studio user profile's apps run as the
profile's role (or the domain default) and can be entered with ``CreatePresignedDomainUrl``, so an
existing role can be taken over without ``iam:PassRole`` (F-113).

Output (``<region>/sagemaker/``):

* ``resources.json`` (list), sorted by (``Type``, ``Arn``):

  - ``{Type: "sagemaker", Kind: "notebook", Arn, Name, Roles: [role]|null, DirectInternetAccess, RootAccess,
    CollectionErrors?}``;
  - ``{Type: "sagemakerdomain", Kind: "domain", Arn, Name, DomainId, AuthMode, AppNetworkAccessType,
    DefaultUserRole, DefaultSpaceRole, Roles: [...]|null, CollectionErrors?}``;
  - ``{Type: "sagemakerdomain", Kind: "user_profile", Arn, Name, DomainId, ExecutionRole,
    InheritsDomainRole: bool|null, Roles: [role]|null, CollectionErrors?}`` (``Roles`` is the role its
    apps run as: its own, else the domain default).

  An item whose describe call fails is kept with the identity the listing gave and ``null`` roles (F-102).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_enumerator.collectors._common import add_error
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="sagemaker", scope="regional", output_dir="sagemaker", services=("sagemaker",),
    tier=1, cost="low", noise="low", default=True, groups=("@compute",),
    actions=("sagemaker:ListNotebookInstances", "sagemaker:DescribeNotebookInstance", "sagemaker:ListDomains",
             "sagemaker:DescribeDomain", "sagemaker:ListUserProfiles", "sagemaker:DescribeUserProfile"),
    probe=("sagemaker", "ListNotebookInstances", (("MaxResults", 1),)),
    outputs=(("resources.json", "list"),),
    description="SageMaker notebook instances, Studio domains and user profiles, and their execution roles",
)


def _roles(*roles: Optional[str]) -> List[str]:
    return sorted({r for r in roles if r})


def _notebooks(ctx: Any, sm: Any, out: List[Dict[str, Any]]) -> None:
    listed = ctx.paginate(sm, "list_notebook_instances", "NotebookInstances", page_size=100, primary=True)
    for summary in listed.value:
        name = summary.get("NotebookInstanceName")
        arn = summary.get("NotebookInstanceArn") or ctx.arn("sagemaker", f"notebook-instance/{name}")
        item: Dict[str, Any] = {"Type": "sagemaker", "Kind": "notebook", "Arn": arn, "Name": name, "Roles": None,
                                "DirectInternetAccess": None, "RootAccess": None}
        result = ctx.call(sm, "describe_notebook_instance", item=arn, NotebookInstanceName=name)
        if result.ok:
            item.update({"Arn": result.get("NotebookInstanceArn") or arn, "Roles": _roles(result.get("RoleArn")),
                         "DirectInternetAccess": result.get("DirectInternetAccess"),
                         "RootAccess": result.get("RootAccess")})
        else:
            add_error(item, result)
        out.append(item)


def _domain(ctx: Any, sm: Any, summary: Dict[str, Any]) -> Dict[str, Any]:
    domain_id = summary.get("DomainId")
    arn = summary.get("DomainArn") or ctx.arn("sagemaker", f"domain/{domain_id}")
    item: Dict[str, Any] = {"Type": "sagemakerdomain", "Kind": "domain", "Arn": arn, "Name": summary.get("DomainName"),
                            "DomainId": domain_id, "AuthMode": None, "AppNetworkAccessType": None,
                            "DefaultUserRole": None, "DefaultSpaceRole": None, "Roles": None}
    result = ctx.call(sm, "describe_domain", item=arn, DomainId=domain_id)
    if not result.ok:
        add_error(item, result)
        return item
    user_role = (result.get("DefaultUserSettings") or {}).get("ExecutionRole")
    space_role = (result.get("DefaultSpaceSettings") or {}).get("ExecutionRole")
    item.update({"AuthMode": result.get("AuthMode"), "AppNetworkAccessType": result.get("AppNetworkAccessType"),
                 "DefaultUserRole": user_role, "DefaultSpaceRole": space_role, "Roles": _roles(user_role, space_role)})
    return item


def _profile(ctx: Any, sm: Any, summary: Dict[str, Any], domains: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    domain_id, name = summary.get("DomainId"), summary.get("UserProfileName")
    arn = ctx.arn("sagemaker", f"user-profile/{domain_id}/{name}")
    item: Dict[str, Any] = {"Type": "sagemakerdomain", "Kind": "user_profile", "Arn": arn, "Name": name,
                            "DomainId": domain_id, "ExecutionRole": None, "InheritsDomainRole": None, "Roles": None}
    result = ctx.call(sm, "describe_user_profile", item=arn, DomainId=domain_id, UserProfileName=name)
    if not result.ok:
        add_error(item, result)
        return item
    own = (result.get("UserSettings") or {}).get("ExecutionRole")
    default = (domains.get(domain_id) or {}).get("DefaultUserRole")
    item.update({"Arn": result.get("UserProfileArn") or arn, "ExecutionRole": own,
                 "InheritsDomainRole": own is None})
    if own or default:
        item["Roles"] = _roles(own or default)
    elif domain_id in domains and domains[domain_id].get("Roles") is not None:
        item["Roles"] = []          # the domain was read and has no default role either
    return item


def _studio(ctx: Any, sm: Any, out: List[Dict[str, Any]]) -> None:
    domains = {}
    listed = ctx.paginate(sm, "list_domains", "Domains", page_size=100)
    for summary in listed.value:
        item = _domain(ctx, sm, summary)
        domains[item["DomainId"]] = item
        out.append(item)
    if listed.ok and not domains:
        return                      # no domain, hence no user profile: skip the listing
    profiles = ctx.paginate(sm, "list_user_profiles", "UserProfiles", page_size=100)
    for summary in profiles.value:
        out.append(_profile(ctx, sm, summary, domains))


def collect(ctx: Any) -> None:
    sm = ctx.client("sagemaker")
    resources: List[Dict[str, Any]] = []
    with ctx.section("notebooks"):
        _notebooks(ctx, sm, resources)
    with ctx.section("studio"):
        _studio(ctx, sm, resources)
    resources.sort(key=lambda r: (r["Type"], str(r["Arn"])))
    ctx.out.write("resources.json", resources)
    ctx.log.info("%d notebooks, domains and user profiles", len(resources))
