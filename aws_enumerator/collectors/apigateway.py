"""API Gateway: REST (v1), HTTP and WebSocket (v2) APIs with per-method / per-route authorisation and
their Lambda integration targets.

Output (``<region>/apigateway/``):

* ``resources.json`` (list), sorted by ``Arn``::

    {Type: "apigw", Arn (partition-aware), Name, ApiId, Protocol: "REST"|"HTTP"|"WEBSOCKET",
     EndpointTypes: [...]|null, ResourcePolicy: {...}|null, DisableExecuteApiEndpoint,
     Authorizers: [{Id, Name, Type}]|null, HasAuthorizer: bool|null,                  # backward compatible
     Stages: [{StageName, VariableNames, WebAclArn, AccessLogDestinationArn}]|null,
     Integrations: [{Method|RouteKey, Path, AuthorizationType, EffectiveAuthorizationType, AuthorizerId,
                     ApiKeyRequired, IntegrationType, LambdaArn|null, Qualifier|null, Stage|null,
                     Unresolved}]|null,
     LambdaTargets: [unqualified function ARN]|null,                                    # backward compatible
     UnauthenticatedLambdaRoutes: [{Method|RouteKey, Path, LambdaArn, Qualifier, Stage}]|null,
     CollectionErrors?}

Authorisation is read **per method / per route** (``authorizationType``; v2 ``GetRoutes``), not
inferred from whether any authorizer object exists, so ``AWS_IAM`` methods are not "unauthenticated"
and a ``NONE`` method next to a protected one is (F-044). ``EffectiveAuthorizationType`` is what a
caller must pass: the method's or route's own type, except on WebSocket APIs, where only ``$connect``
can carry an authorizer and every other route inherits it (``NONE`` without a ``$connect`` route).
An HTTP/WebSocket integration that no route targets is listed (``RouteKey: null``) but cannot be
invoked, so it counts neither in ``LambdaTargets`` nor in ``UnauthenticatedLambdaRoutes``. API keys
are not authentication: an ``apiKeyRequired`` method with ``NONE`` is still unauthenticated. REST methods come from
``GetResources(embed=["methods"])`` with page size 500, which returns each method's integration
inline: ``GetIntegration`` is called only when no embedded integration was returned for the whole
API (F-100, F-147).

Lambda targets are parsed with a partition-aware regex: the unqualified function ARN is the target
and an alias/version suffix becomes ``Qualifier``; ``${stageVariables.x}`` placeholders are resolved
per stage, else the integration is ``Unresolved`` and contributes no target (F-099). Stage variable
**values** are not stored (they sometimes carry keys); only their names are.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from aws_enumerator.collectors._common import add_error
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="apigateway", scope="regional", output_dir="apigateway", services=("apigateway", "apigatewayv2"),
    tier=1, cost="medium", noise="medium", default=True, groups=("@edge",),
    actions=("apigateway:GET",),
    resource_scoped=(("apigateway:GET", ("arn:{partition}:apigateway:*::/restapis",
                                         "arn:{partition}:apigateway:*::/restapis/*",
                                         "arn:{partition}:apigateway:*::/apis",
                                         "arn:{partition}:apigateway:*::/apis/*")),),
    probe=("apigateway", "GetRestApis", (("limit", 1),)),
    not_configured=(("apigateway:GetIntegration", ("NotFoundException",)),),
    outputs=(("resources.json", "list"),),
    description="API Gateway REST/HTTP/WebSocket APIs, per-method authorisation and Lambda targets",
)

PAGE_SIZE = 500
_LAMBDA_ARN = re.compile(r"arn:(aws[\w-]*):lambda:([^:/]+):(\d{12}):function:([^:/]+)(?::([^/]+))?")
_STAGE_VAR = re.compile(r"\$\{stageVariables\.([A-Za-z0-9_]+)\}")


def parse_rest_policy(text: Any) -> Optional[Dict[str, Any]]:
    """``GetRestApis`` returns the resource policy as an escaped JSON string (``{\\"Version\\":...}``)."""
    if not text:
        return None
    for candidate in (text, str(text).replace('\\"', '"').replace("\\\\", "\\")):
        try:
            doc = json.loads(candidate)
        except (TypeError, ValueError):
            continue
        if isinstance(doc, dict):
            return doc
    return {"_raw": str(text)}


def lambda_targets(uri: Optional[str], stage_vars: Dict[str, Dict[str, str]]) -> List[Dict[str, Any]]:
    """Lambda targets of one integration URI: ``[{LambdaArn, Qualifier, Stage, Unresolved}]`` (F-099).

    ``stage_vars`` maps stage name to its variables. A URI with ``${stageVariables.x}`` yields one target
    per stage that defines every variable it uses, or one ``Unresolved`` entry when none does.
    """
    match = _LAMBDA_ARN.search(uri or "")
    if not match:
        return []
    raw = match.group(0)
    if not _STAGE_VAR.search(raw):
        return [_target(match, None)]
    out = []
    for stage in sorted(stage_vars):
        names = _STAGE_VAR.findall(raw)
        if all(n in stage_vars[stage] for n in names):
            resolved = _STAGE_VAR.sub(lambda m, s=stage: stage_vars[s][m.group(1)], raw)
            inner = _LAMBDA_ARN.fullmatch(resolved)
            if inner and not _STAGE_VAR.search(resolved):
                out.append(_target(inner, stage))
    return out or [{"LambdaArn": None, "Qualifier": None, "Stage": None, "Unresolved": True}]


def _target(match: "re.Match[str]", stage: Optional[str]) -> Dict[str, Any]:
    partition, region, account, name, qualifier = match.groups()
    return {"LambdaArn": f"arn:{partition}:lambda:{region}:{account}:function:{name}",
            "Qualifier": qualifier or None, "Stage": stage, "Unresolved": False}


def _summaries(item: Dict[str, Any]) -> None:
    """Fill ``LambdaTargets`` and ``UnauthenticatedLambdaRoutes`` from the invocable ``Integrations``."""
    integrations = item["Integrations"]
    if integrations is None:
        return
    key = "Method" if item["Protocol"] == "REST" else "RouteKey"
    invocable = [i for i in integrations if i["LambdaArn"] and i.get(key) is not None]
    item["LambdaTargets"] = sorted({i["LambdaArn"] for i in invocable})
    item["UnauthenticatedLambdaRoutes"] = [
        {key: i[key], "Path": i.get("Path"), "LambdaArn": i["LambdaArn"], "Qualifier": i["Qualifier"],
         "Stage": i["Stage"]}
        for i in invocable if str(i.get("EffectiveAuthorizationType") or "").upper() == "NONE"]


def _base_item(ctx: Any, api_id: str, name: Any, protocol: str, path: str) -> Dict[str, Any]:
    return {"Type": "apigw", "Arn": ctx.arn("apigateway", f"/{path}/{api_id}", account=""), "Name": name,
            "ApiId": api_id, "Protocol": protocol, "EndpointTypes": None, "ResourcePolicy": None,
            "DisableExecuteApiEndpoint": None, "Authorizers": None, "HasAuthorizer": None, "Stages": None,
            "Integrations": None, "LambdaTargets": None, "UnauthenticatedLambdaRoutes": None}


# ── REST APIs (apigateway) ───────────────────────────────────────────────────
def _rest_stages(ctx: Any, gw: Any, item: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    result = ctx.call(gw, "get_stages", item=item["Arn"], restApiId=item["ApiId"])
    if not result.ok:
        add_error(item, result)
        return {}
    stages = result.get("item") or []
    item["Stages"] = sorted(({"StageName": s.get("stageName"), "VariableNames": sorted(s.get("variables") or {}),
                              "WebAclArn": s.get("webAclArn"),
                              "AccessLogDestinationArn": (s.get("accessLogSettings") or {}).get("destinationArn")}
                             for s in stages), key=lambda s: str(s["StageName"]))
    return {s.get("stageName"): dict(s.get("variables") or {}) for s in stages}


def _rest_authorizers(ctx: Any, gw: Any, item: Dict[str, Any]) -> None:
    result = ctx.paginate(gw, "get_authorizers", "items", item=item["Arn"], restApiId=item["ApiId"])
    if not result.ok:
        add_error(item, result)
        return
    item["Authorizers"] = sorted(({"Id": a.get("id"), "Name": a.get("name"), "Type": a.get("type")}
                                  for a in result.value), key=lambda a: str(a["Id"]))
    item["HasAuthorizer"] = bool(item["Authorizers"])


def _rest_methods(ctx: Any, gw: Any, item: Dict[str, Any]) -> Optional[List[Tuple[Dict, str, Dict]]]:
    """``[(resource, http method, method)]`` from ``GetResources(embed=methods)``; ``None`` on failure."""
    result = ctx.paginate(gw, "get_resources", "items", page_size=PAGE_SIZE, item=item["Arn"],
                          restApiId=item["ApiId"], embed=["methods"])
    if not result.ok:
        add_error(item, result)
        return None
    return [(res, verb, method or {}) for res in result.value
            for verb, method in sorted((res.get("resourceMethods") or {}).items())]


def _rest_integrations(ctx: Any, gw: Any, item: Dict[str, Any], stage_vars: Dict[str, Dict[str, str]]) -> None:
    methods = _rest_methods(ctx, gw, item)
    if methods is None:
        return
    embedded = any("methodIntegration" in m for _r, _v, m in methods)
    integrations = []
    for res, verb, method in methods:
        integ = method.get("methodIntegration")
        if integ is None and not embedded:     # embed unsupported: fall back to one call per method (F-100)
            result = ctx.call(gw, "get_integration", item=item["Arn"], restApiId=item["ApiId"],
                              resourceId=res.get("id"), httpMethod=verb)
            integ = result.value if result.has_data else None
            add_error(item, result)
        integ = integ or {}
        auth = method.get("authorizationType")
        base = {"Method": verb, "Path": res.get("path"), "AuthorizationType": auth, "EffectiveAuthorizationType": auth,
                "AuthorizerId": method.get("authorizerId"), "ApiKeyRequired": method.get("apiKeyRequired"),
                "IntegrationType": integ.get("type")}
        targets = lambda_targets(integ.get("uri"), stage_vars) or [
            {"LambdaArn": None, "Qualifier": None, "Stage": None, "Unresolved": False}]
        integrations.extend(dict(base, **t) for t in targets)
    item["Integrations"] = sorted(integrations, key=lambda i: (str(i["Path"]), str(i["Method"]), str(i["Stage"]),
                                                               str(i["LambdaArn"])))


def _rest_api(ctx: Any, gw: Any, api: Dict[str, Any]) -> Dict[str, Any]:
    item = _base_item(ctx, api.get("id"), api.get("name"), "REST", "restapis")
    item["EndpointTypes"] = list((api.get("endpointConfiguration") or {}).get("types") or [])
    item["ResourcePolicy"] = parse_rest_policy(api.get("policy"))
    item["DisableExecuteApiEndpoint"] = api.get("disableExecuteApiEndpoint")
    stage_vars = _rest_stages(ctx, gw, item)
    _rest_authorizers(ctx, gw, item)
    _rest_integrations(ctx, gw, item, stage_vars)
    _summaries(item)
    return item


def _rest(ctx: Any, out: List[Dict[str, Any]]) -> None:
    gw = ctx.client("apigateway")
    listed = ctx.paginate(gw, "get_rest_apis", "items", page_size=PAGE_SIZE)
    for api in sorted(listed.value, key=lambda a: str(a.get("id"))):
        out.append(_rest_api(ctx, gw, api))


# ── HTTP / WebSocket APIs (apigatewayv2) ─────────────────────────────────────
def _v2_list(ctx: Any, gw: Any, item: Dict[str, Any], op: str) -> Optional[List[Dict[str, Any]]]:
    result = ctx.paginate(gw, op, "Items", item=item["Arn"], ApiId=item["ApiId"])
    if not result.ok:
        add_error(item, result)
        return None
    return list(result.value)


def effective_route_auth(protocol: str, routes: List[Dict[str, Any]]) -> Dict[Any, Optional[str]]:
    """``{RouteKey: authorization a caller must pass}``; WebSocket routes inherit ``$connect``'s (F-044)."""
    own = {r.get("RouteKey"): r.get("AuthorizationType") or "NONE" for r in routes}
    if protocol != "WEBSOCKET":
        return own
    connect = own.get("$connect", "NONE")
    return {key: (auth if key == "$connect" else connect) for key, auth in own.items()}


def _v2_route_integrations(item: Dict[str, Any], routes: List[Dict[str, Any]], integrations: List[Dict[str, Any]],
                           stage_vars: Dict[str, Dict[str, str]]) -> List[Dict[str, Any]]:
    by_id = {i.get("IntegrationId"): i for i in integrations}
    effective = effective_route_auth(item["Protocol"], routes)
    used, out = set(), []
    for route in routes:
        target = str(route.get("Target") or "")
        integ_id = target.split("/", 1)[1] if target.startswith("integrations/") else None
        used.add(integ_id)
        integ = by_id.get(integ_id) or {}
        base = {"RouteKey": route.get("RouteKey"), "Path": None, "AuthorizationType": route.get("AuthorizationType"),
                "EffectiveAuthorizationType": effective.get(route.get("RouteKey")),
                "AuthorizerId": route.get("AuthorizerId"), "ApiKeyRequired": route.get("ApiKeyRequired"),
                "IntegrationType": integ.get("IntegrationType")}
        targets = lambda_targets(integ.get("IntegrationUri"), stage_vars) or [
            {"LambdaArn": None, "Qualifier": None, "Stage": None, "Unresolved": False}]
        out.extend(dict(base, **t) for t in targets)
    for integ_id, integ in by_id.items():      # no route targets it: listed, but it cannot be invoked
        if integ_id in used:
            continue
        base = {"RouteKey": None, "Path": None, "AuthorizationType": None, "EffectiveAuthorizationType": None,
                "AuthorizerId": None, "ApiKeyRequired": None, "IntegrationType": integ.get("IntegrationType")}
        out.extend(dict(base, **t) for t in lambda_targets(integ.get("IntegrationUri"), stage_vars))
    return sorted(out, key=lambda i: (str(i["RouteKey"]), str(i["Stage"]), str(i["LambdaArn"])))


def _v2_stages(ctx: Any, gw: Any, item: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    """Fill ``Stages`` (variable names only); returns ``{stage: variables}`` for target resolution."""
    stages = _v2_list(ctx, gw, item, "get_stages")
    if stages is None:
        return {}
    item["Stages"] = sorted(({"StageName": s.get("StageName"), "VariableNames": sorted(s.get("StageVariables") or {}),
                              "WebAclArn": None,
                              "AccessLogDestinationArn": (s.get("AccessLogSettings") or {}).get("DestinationArn")}
                             for s in stages), key=lambda s: str(s["StageName"]))
    return {s.get("StageName"): dict(s.get("StageVariables") or {}) for s in stages}


def _v2_authorizers(ctx: Any, gw: Any, item: Dict[str, Any]) -> None:
    authorizers = _v2_list(ctx, gw, item, "get_authorizers")
    if authorizers is None:
        return
    item["Authorizers"] = sorted(({"Id": a.get("AuthorizerId"), "Name": a.get("Name"), "Type": a.get("AuthorizerType")}
                                  for a in authorizers), key=lambda a: str(a["Id"]))
    item["HasAuthorizer"] = bool(item["Authorizers"])


def _v2_api(ctx: Any, gw: Any, api: Dict[str, Any]) -> Dict[str, Any]:
    item = _base_item(ctx, api.get("ApiId"), api.get("Name"), api.get("ProtocolType") or "HTTP", "apis")
    item["DisableExecuteApiEndpoint"] = api.get("DisableExecuteApiEndpoint")
    stage_vars = _v2_stages(ctx, gw, item)
    _v2_authorizers(ctx, gw, item)
    routes = _v2_list(ctx, gw, item, "get_routes")
    integrations = _v2_list(ctx, gw, item, "get_integrations")
    if routes is not None and integrations is not None:
        item["Integrations"] = _v2_route_integrations(item, routes, integrations, stage_vars)
        _summaries(item)
    return item


def _http(ctx: Any, out: List[Dict[str, Any]]) -> None:
    gw = ctx.client("apigatewayv2")
    listed = ctx.paginate(gw, "get_apis", "Items", page_size=PAGE_SIZE)
    for api in sorted(listed.value, key=lambda a: str(a.get("ApiId"))):
        out.append(_v2_api(ctx, gw, api))


def collect(ctx: Any) -> None:
    resources: List[Dict[str, Any]] = []
    with ctx.section("rest_apis"):
        _rest(ctx, resources)
    with ctx.section("http_apis"):
        _http(ctx, resources)
    resources.sort(key=lambda r: r["Arn"])
    ctx.out.write("resources.json", resources)
    ctx.log.info("%d APIs", len(resources))
