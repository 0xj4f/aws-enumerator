"""Lambda: functions, function URLs and resource policies on the function **and its aliases**,
layers with their policies, and event source mappings.

Environment variable **values are never stored**, only their names: they frequently hold secrets.

Output (``<region>/lambda/``):

* ``functions.json`` (list), sorted by ``FunctionArn``::

    {FunctionName, FunctionArn, Runtime, Handler, Role, MemorySize, Timeout, LastModified, PackageType,
     KMSKeyArn, Layers: [arn], VpcConfig: {VpcId, SubnetIds, SecurityGroupIds}, EnvironmentVariableNames,
     FunctionUrl: {Url, AuthType}|null,                       # the unqualified URL (backward compatible)
     FunctionUrls: [{Qualifier|null, FunctionUrl, AuthType, InvokeMode, CorsAllowOrigins}]|null,
     Aliases: [{Name, AliasArn, FunctionVersion, PolicyStatus}]|null,
     PolicyStatus, Versions?: [{Version, PolicyStatus}]|null, CollectionErrors?}

  ``FunctionUrls`` comes from one ``ListFunctionUrlConfigs`` call per function, which also returns
  URLs attached to aliases (F-055). ``Versions`` is present only with ``--lambda-versions``.
* ``resource_policies/<slug(name[:qualifier])>-<sha256(qualified ARN)[:12]>.json`` (dict)::

    {FunctionArn (unqualified), FunctionName, Qualifier: null|"<alias or version>", QualifiedArn, ResourcePolicy}

  one per policy: the function's own and each alias's (``GetPolicy(Qualifier=...)``, F-055); file
  names never collide (F-114).
* ``layers.json`` (list): ``{LayerName, LayerArn, Versions: [{Version, LayerVersionArn, CompatibleRuntimes,
  Policy|null, PolicyStatus, Public: bool|null, CollectionErrors?}]|null, CollectionErrors?}`` (F-116).
* ``event_source_mappings.json`` (list): ``{UUID, EventSourceArn, FunctionArn, State, BatchSize,
  LastModified}`` (F-116).

Fan-out (F-147): three calls per function (``ListFunctionUrlConfigs``, ``ListAliases``, ``GetPolicy``)
plus one ``GetPolicy`` per alias; every client comes from ``ctx.client`` so the run's rate limiter
applies, and the deny breaker stops a fan-out that keeps being denied.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aws_enumerator.collectors._common import add_error, policy_doc
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="lambda", scope="regional", output_dir="lambda", services=("lambda",),
    tier=2, cost="medium", noise="medium", default=True, groups=("@compute",),
    actions=("lambda:ListFunctions", "lambda:ListFunctionUrlConfigs", "lambda:ListAliases", "lambda:GetPolicy",
             "lambda:ListLayers", "lambda:ListLayerVersions", "lambda:GetLayerVersionPolicy",
             "lambda:ListEventSourceMappings"),
    optional_actions=("lambda:ListVersionsByFunction",),
    probe=("lambda", "ListFunctions", (("MaxItems", 1),)),
    outputs=(("functions.json", "list"), ("resource_policies/*.json", "dict"), ("layers.json", "list"),
             ("event_source_mappings.json", "list")),
    description="Lambda functions, URLs and resource policies (aliases included), layers, event source mappings",
)

_API_GET_POLICY = "lambda:GetPolicy"


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def grants_public(doc: Optional[Dict[str, Any]]) -> Optional[bool]:
    """``True`` when a policy has an unconditional ``Allow`` for ``*`` (``None`` when unknown)."""
    if doc is None:
        return None
    for st in _as_list(doc.get("Statement")):
        if not isinstance(st, dict) or st.get("Effect") != "Allow" or st.get("Condition"):
            continue
        principal = st.get("Principal")
        values = _as_list(principal.get("AWS")) if isinstance(principal, dict) else _as_list(principal)
        if "*" in values:
            return True
    return False


def project_function(fn: Dict[str, Any]) -> Dict[str, Any]:
    """Stored function metadata: environment variable NAMES only, never values."""
    vpc = fn.get("VpcConfig") or {}
    env = (fn.get("Environment") or {}).get("Variables") or {}
    return {
        "FunctionName": fn.get("FunctionName"), "FunctionArn": fn.get("FunctionArn"), "Runtime": fn.get("Runtime"),
        "Handler": fn.get("Handler"), "Role": fn.get("Role"), "MemorySize": fn.get("MemorySize"),
        "Timeout": fn.get("Timeout"), "LastModified": fn.get("LastModified"), "PackageType": fn.get("PackageType"),
        "KMSKeyArn": fn.get("KMSKeyArn"),
        "Layers": [layer.get("Arn") for layer in fn.get("Layers") or []],
        "VpcConfig": {"VpcId": vpc.get("VpcId"), "SubnetIds": list(vpc.get("SubnetIds") or []),
                      "SecurityGroupIds": list(vpc.get("SecurityGroupIds") or [])},
        "EnvironmentVariableNames": sorted(env),
        "FunctionUrl": None, "FunctionUrls": None, "Aliases": None, "PolicyStatus": None,
    }


def qualifier_of(base_arn: str, arn: Optional[str]) -> Optional[str]:
    """``"live"`` for ``<base>:live``; ``None`` for the unqualified ARN or ``$LATEST``."""
    if not arn or arn == base_arn or not arn.startswith(base_arn + ":"):
        return None
    qualifier = arn[len(base_arn) + 1:]
    return None if qualifier == "$LATEST" else qualifier


def _urls(ctx: Any, lam: Any, item: Dict[str, Any]) -> None:
    arn = item["FunctionArn"]
    result = ctx.paginate(lam, "list_function_url_configs", "FunctionUrlConfigs", item=arn, FunctionName=arn)
    if not result.ok:
        add_error(item, result)
        return
    urls = []
    for cfg in result.value:
        cors = cfg.get("Cors") or {}
        urls.append({"Qualifier": qualifier_of(arn, cfg.get("FunctionArn")), "FunctionUrl": cfg.get("FunctionUrl"),
                     "AuthType": cfg.get("AuthType"), "InvokeMode": cfg.get("InvokeMode"),
                     "CorsAllowOrigins": sorted(cors.get("AllowOrigins") or [])})
    urls.sort(key=lambda u: (u["Qualifier"] is not None, str(u["Qualifier"]), str(u["FunctionUrl"])))
    item["FunctionUrls"] = urls
    base = next((u for u in urls if u["Qualifier"] is None), None)
    item["FunctionUrl"] = {"Url": base["FunctionUrl"], "AuthType": base["AuthType"]} if base else None


def _write_policy(ctx: Any, item: Dict[str, Any], qualifier: Optional[str], doc: Dict[str, Any]) -> bool:
    arn, name = item["FunctionArn"], item["FunctionName"]
    qualified = f"{arn}:{qualifier}" if qualifier else arn
    data = {"FunctionArn": arn, "FunctionName": name, "Qualifier": qualifier, "QualifiedArn": qualified,
            "ResourcePolicy": doc}
    try:
        ctx.out.write_item("resource_policies", qualified, data, hint=f"{name}:{qualifier}" if qualifier else name)
    except OSError as exc:  # one bad file must not cost the other functions their policies (F-114)
        ctx.cov.item_error(qualified, _API_GET_POLICY, "error", type(exc).__name__)
        item.setdefault("CollectionErrors", []).append(
            {"api": _API_GET_POLICY, "status": "error", "error_code": type(exc).__name__})
        return False
    return True


def _policy(ctx: Any, lam: Any, item: Dict[str, Any], qualifier: Optional[str] = None) -> str:
    """Read one (qualified) policy, write its file; returns the ``PolicyStatus``."""
    arn = item["FunctionArn"]
    params: Dict[str, Any] = {"FunctionName": arn}
    if qualifier:
        params["Qualifier"] = qualifier
    result = ctx.call(lam, "get_policy", item=f"{arn}:{qualifier}" if qualifier else arn, **params)
    if not result.ok:
        add_error(item, result)
        return result.policy_status()
    doc = policy_doc(result.get("Policy"))
    if doc is None:
        return "absent"
    return "present" if _write_policy(ctx, item, qualifier, doc) else "error"


def _aliases(ctx: Any, lam: Any, item: Dict[str, Any]) -> None:
    arn = item["FunctionArn"]
    result = ctx.paginate(lam, "list_aliases", "Aliases", item=arn, FunctionName=arn)
    if not result.ok:
        add_error(item, result)
        return
    aliases = sorted(({"Name": a.get("Name"), "AliasArn": a.get("AliasArn"),
                       "FunctionVersion": a.get("FunctionVersion"), "PolicyStatus": None}
                      for a in result.value if a.get("Name")), key=lambda a: a["Name"])
    for alias in aliases:
        alias["PolicyStatus"] = _policy(ctx, lam, item, alias["Name"])
    item["Aliases"] = aliases


def _versions(ctx: Any, lam: Any, item: Dict[str, Any]) -> None:
    arn = item["FunctionArn"]
    result = ctx.paginate(lam, "list_versions_by_function", "Versions", item=arn, optional=True, FunctionName=arn)
    if not result.ok:
        item["Versions"] = None
        add_error(item, result)
        return
    numbers = sorted({v.get("Version") for v in result.value if v.get("Version") not in (None, "$LATEST")},
                     key=lambda v: (len(str(v)), str(v)))
    item["Versions"] = [{"Version": v, "PolicyStatus": _policy(ctx, lam, item, v)} for v in numbers]


def _function(ctx: Any, lam: Any, raw: Dict[str, Any], with_versions: bool) -> Dict[str, Any]:
    item = project_function(raw)
    _urls(ctx, lam, item)
    _aliases(ctx, lam, item)
    item["PolicyStatus"] = _policy(ctx, lam, item)
    if with_versions:
        _versions(ctx, lam, item)
    return item


def _layer_version(ctx: Any, lam: Any, layer_name: str, ver: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"Version": ver.get("Version"), "LayerVersionArn": ver.get("LayerVersionArn"),
                           "CompatibleRuntimes": sorted(ver.get("CompatibleRuntimes") or []), "Policy": None,
                           "PolicyStatus": None, "Public": None}
    result = ctx.call(lam, "get_layer_version_policy", item=out["LayerVersionArn"] or layer_name,
                      LayerName=layer_name, VersionNumber=ver.get("Version"))
    if result.ok:
        out["Policy"] = policy_doc(result.get("Policy"))
        out["PolicyStatus"] = "present" if out["Policy"] else "absent"
        out["Public"] = grants_public(out["Policy"]) if out["Policy"] else False
    else:
        out["PolicyStatus"] = result.policy_status()
        add_error(out, result)
    return out


def _layer(ctx: Any, lam: Any, layer: Dict[str, Any]) -> Dict[str, Any]:
    name, arn = layer.get("LayerName"), layer.get("LayerArn")
    item: Dict[str, Any] = {"LayerName": name, "LayerArn": arn, "Versions": None}
    versions = ctx.paginate(lam, "list_layer_versions", "LayerVersions", item=arn or name, LayerName=arn or name)
    if versions.ok:
        item["Versions"] = sorted((_layer_version(ctx, lam, arn or name, v) for v in versions.value),
                                  key=lambda v: -int(v["Version"] or 0))
    else:
        add_error(item, versions)
    return item


def _layers(ctx: Any, lam: Any, out: List[Dict[str, Any]]) -> None:
    listed = ctx.paginate(lam, "list_layers", "Layers", page_size=50)
    for layer in sorted(listed.value, key=lambda x: str(x.get("LayerArn"))):
        out.append(_layer(ctx, lam, layer))


def _event_source_mappings(ctx: Any, lam: Any, out: List[Dict[str, Any]]) -> None:
    listed = ctx.paginate(lam, "list_event_source_mappings", "EventSourceMappings", page_size=100)
    keys = ("UUID", "EventSourceArn", "FunctionArn", "State", "BatchSize", "LastModified")
    out.extend(sorted(({k: m.get(k) for k in keys} for m in listed.value), key=lambda m: str(m["UUID"])))


def _functions(ctx: Any, lam: Any, out: List[Dict[str, Any]]) -> None:
    with_versions = bool(ctx.option("lambda_versions", False))
    listed = ctx.paginate(lam, "list_functions", "Functions", page_size=50, primary=True)
    for raw in sorted(listed.value, key=lambda f: str(f.get("FunctionArn"))):
        if raw.get("FunctionArn"):
            out.append(_function(ctx, lam, raw, with_versions))


def collect(ctx: Any) -> None:
    lam = ctx.client("lambda")
    counts: Dict[str, int] = {}
    for section, name, build in (("functions", "functions.json", _functions), ("layers", "layers.json", _layers),
                                 ("event_source_mappings", "event_source_mappings.json", _event_source_mappings)):
        data: List[Dict[str, Any]] = []
        with ctx.section(section):      # a failure keeps what was built so far (F-103)
            build(ctx, lam, data)
        ctx.out.write(name, data)
        counts[section] = len(data)
    ctx.log.info("%(functions)d functions, %(layers)d layers, %(event_source_mappings)d event source mappings",
                 counts)
