"""Cognito: identity pools (the external -> IAM role bridge) and user pools.

Identity pools and user pools are independent sections: a failure in one never costs the other
(F-103).

Output (``<region>/cognito/``):

* ``resources.json`` (list), sorted by (``Kind``, ``Id``):

  - identity pools::

      {Type: "cognito", Kind: "identity_pool", Id, Arn, Name,
       AuthRole, UnauthRole, RoleMappings: {...}|null,          # from GetIdentityPoolRoles
       AllowUnauth: bool|null, AllowClassicFlow: bool|null,      # from DescribeIdentityPool
       SupportedLoginProviders: {provider: app id}|null, DeveloperProviderName,
       CognitoIdentityProviders: [{ProviderName, ClientId, ServerSideTokenCheck}]|null,
       OpenIdConnectProviderARNs: [...]|null, SamlProviderARNs: [...]|null, CollectionErrors?}

    ``RoleMappings`` is kept in full (rules- and token-based mappings decide which role a user gets),
    ``AllowClassicFlow`` enables the basic (classic) flow, and the login providers say who can become
    an authenticated identity (F-048).
  - user pools::

      {Type: "cognito", Kind: "user_pool", Id, Arn, Name, SelfSignupEnabled: bool|null,
       MfaConfiguration, Domain, Clients: [{ClientId, ClientName}]|null, CollectionErrors?}

    ``SelfSignupEnabled`` is ``not AdminCreateUserConfig.AllowAdminCreateUserOnly``: anyone on the
    internet can create a user, hence an authenticated identity (F-048). ``DescribeUserPoolClient`` is
    **never** called: it returns the client secret.
"""

from __future__ import annotations

from typing import Any, Dict, List

from aws_enumerator.collectors._common import add_error
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="cognito", scope="regional", output_dir="cognito", services=("cognito-identity", "cognito-idp"),
    tier=1, cost="low", noise="low", default=True, groups=("@identity",),
    actions=("cognito-identity:ListIdentityPools", "cognito-identity:DescribeIdentityPool",
             "cognito-identity:GetIdentityPoolRoles", "cognito-idp:ListUserPools", "cognito-idp:DescribeUserPool",
             "cognito-idp:ListUserPoolClients"),
    probe=("cognito-identity", "ListIdentityPools", (("MaxResults", 1),)),
    outputs=(("resources.json", "list"),),
    description="Cognito identity pools (roles, mappings, providers, classic flow) and user pools (self sign-up)",
)

_PAGE = 60
_KIND_ORDER = {"identity_pool": 0, "user_pool": 1}


def _pool_roles(ctx: Any, idp: Any, item: Dict[str, Any]) -> None:
    result = ctx.call(idp, "get_identity_pool_roles", item=item["Arn"], IdentityPoolId=item["Id"])
    if not result.ok:
        add_error(item, result)
        return
    roles = result.get("Roles") or {}
    item["AuthRole"] = roles.get("authenticated")
    item["UnauthRole"] = roles.get("unauthenticated")
    item["RoleMappings"] = result.get("RoleMappings") or {}


def _pool_config(ctx: Any, idp: Any, item: Dict[str, Any]) -> None:
    result = ctx.call(idp, "describe_identity_pool", item=item["Arn"], IdentityPoolId=item["Id"])
    if not result.ok:
        add_error(item, result)
        return
    item["AllowUnauth"] = result.get("AllowUnauthenticatedIdentities")
    item["AllowClassicFlow"] = result.get("AllowClassicFlow")
    item["SupportedLoginProviders"] = dict(result.get("SupportedLoginProviders") or {})
    item["DeveloperProviderName"] = result.get("DeveloperProviderName")
    item["CognitoIdentityProviders"] = [
        {"ProviderName": p.get("ProviderName"), "ClientId": p.get("ClientId"),
         "ServerSideTokenCheck": p.get("ServerSideTokenCheck")} for p in result.get("CognitoIdentityProviders") or []]
    item["OpenIdConnectProviderARNs"] = sorted(result.get("OpenIdConnectProviderARNs") or [])
    item["SamlProviderARNs"] = sorted(result.get("SamlProviderARNs") or [])


def _identity_pools(ctx: Any, out: List[Dict[str, Any]]) -> None:
    idp = ctx.client("cognito-identity")
    listed = ctx.paginate(idp, "list_identity_pools", "IdentityPools", page_size=_PAGE)
    for pool in listed.value:
        pool_id = pool.get("IdentityPoolId")
        item: Dict[str, Any] = {
            "Type": "cognito", "Kind": "identity_pool", "Id": pool_id,
            "Arn": ctx.arn("cognito-identity", f"identitypool/{pool_id}"), "Name": pool.get("IdentityPoolName"),
            "AuthRole": None, "UnauthRole": None, "RoleMappings": None, "AllowUnauth": None, "AllowClassicFlow": None,
            "SupportedLoginProviders": None, "DeveloperProviderName": None, "CognitoIdentityProviders": None,
            "OpenIdConnectProviderARNs": None, "SamlProviderARNs": None,
        }
        _pool_roles(ctx, idp, item)
        _pool_config(ctx, idp, item)
        out.append(item)


def _user_pool(ctx: Any, cidp: Any, summary: Dict[str, Any]) -> Dict[str, Any]:
    pool_id = summary.get("Id")
    item: Dict[str, Any] = {"Type": "cognito", "Kind": "user_pool", "Id": pool_id,
                            "Arn": ctx.arn("cognito-idp", f"userpool/{pool_id}"), "Name": summary.get("Name"),
                            "SelfSignupEnabled": None, "MfaConfiguration": None, "Domain": None, "Clients": None}
    result = ctx.call(cidp, "describe_user_pool", item=item["Arn"], UserPoolId=pool_id)
    if result.ok:
        pool = result.get("UserPool") or {}
        admin_only = (pool.get("AdminCreateUserConfig") or {}).get("AllowAdminCreateUserOnly")
        item.update({"Arn": pool.get("Arn") or item["Arn"], "MfaConfiguration": pool.get("MfaConfiguration"),
                     "Domain": pool.get("Domain"),
                     "SelfSignupEnabled": None if admin_only is None else not admin_only})
    else:
        add_error(item, result)
    clients = ctx.paginate(cidp, "list_user_pool_clients", "UserPoolClients", page_size=_PAGE, item=item["Arn"],
                           UserPoolId=pool_id)
    if clients.ok:
        item["Clients"] = sorted(({"ClientId": c.get("ClientId"), "ClientName": c.get("ClientName")}
                                  for c in clients.value), key=lambda c: str(c["ClientId"]))
    else:
        add_error(item, clients)
    return item


def _user_pools(ctx: Any, out: List[Dict[str, Any]]) -> None:
    cidp = ctx.client("cognito-idp")
    listed = ctx.paginate(cidp, "list_user_pools", "UserPools", page_size=_PAGE)
    for summary in listed.value:
        out.append(_user_pool(ctx, cidp, summary))


def collect(ctx: Any) -> None:
    resources: List[Dict[str, Any]] = []
    with ctx.section("identity_pools"):
        _identity_pools(ctx, resources)
    with ctx.section("user_pools"):
        _user_pools(ctx, resources)
    resources.sort(key=lambda r: (_KIND_ORDER.get(r["Kind"], 9), str(r["Id"])))
    ctx.out.write("resources.json", resources)
    pools = sum(1 for r in resources if r["Kind"] == "identity_pool")
    ctx.log.info("%d identity pools, %d user pools", pools, len(resources) - pools)
