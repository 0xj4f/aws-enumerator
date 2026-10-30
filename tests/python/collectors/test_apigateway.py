"""API Gateway collector (collectors-cli.md §5.12): per-method/route auth, embedded integrations, Lambda targets."""

from __future__ import annotations

import copy
import importlib
import json
from pathlib import Path

import pytest

from tests.fixtures.regressions import support as S
from tests.fixtures.worlds import acme
from tests.support import targets
from tests.support.fakeaws import FakeAWS

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

W2, ACCT = KIT.W2, KIT.ACCT
FN = f"arn:aws:lambda:{W2}:{ACCT}:function:"
URI = "arn:aws:apigateway:eu-west-2:lambda:path/2015-03-31/functions/{}/invocations"


def module():
    return targets.collector_module("apigateway")


def apis(r):
    return KIT.by(r.load("resources.json"), "ApiId")


@pytest.fixture
def gw_data(monkeypatch):
    """A private copy of acme's eu-west-2 API Gateway data the test may edit."""
    data = copy.deepcopy(acme.REGIONAL[W2]["apigateway"])
    monkeypatch.setitem(acme.REGIONAL[W2], "apigateway", data)
    return data


@pytest.mark.finding("F-044", "F-099")
def test_per_method_and_per_route_authorisation(tmp_path):
    r = KIT.run("apigateway", tmp_path)
    KIT.assert_contract(r)
    by_id = apis(r)
    assert list(by_id) == ["demohttp01", "demows0001", "demorest01", "demorest02"]   # sorted by Arn
    rest01 = by_id["demorest01"]
    assert rest01["Arn"] == f"arn:aws:apigateway:{W2}::/restapis/demorest01" and rest01["Protocol"] == "REST"
    assert rest01["EndpointTypes"] == ["REGIONAL"] and rest01["HasAuthorizer"] is False
    assert rest01["UnauthenticatedLambdaRoutes"] == [
        {"Method": "GET", "Path": "/orders", "LambdaArn": f"{FN}demo-processor", "Qualifier": None, "Stage": None}]
    assert rest01["Stages"][0]["VariableNames"] == ["lambdaAlias"] and "variables" not in json.dumps(rest01)
    rest02 = by_id["demorest02"]                             # CUSTOM authorizer on the only method
    assert rest02["UnauthenticatedLambdaRoutes"] == [] and rest02["HasAuthorizer"] is True
    assert rest02["LambdaTargets"] == [f"{FN}demo-internal"]                # alias stripped (F-099)
    assert rest02["Integrations"][0]["Qualifier"] == "live"
    assert rest02["Integrations"][0]["EffectiveAuthorizationType"] == "CUSTOM"
    http = by_id["demohttp01"]
    assert http["Protocol"] == "HTTP" and http["Arn"] == f"arn:aws:apigateway:{W2}::/apis/demohttp01"
    assert [x["RouteKey"] for x in http["UnauthenticatedLambdaRoutes"]] == ["GET /orders"]
    assert by_id["demows0001"]["Protocol"] == "WEBSOCKET" and by_id["demows0001"]["LambdaTargets"] == []


@pytest.mark.finding("F-100", "F-147")
def test_methods_are_embedded_so_no_get_integration_is_called(tmp_path):
    r = KIT.run("apigateway", tmp_path)
    assert ("apigateway", "GetIntegration") not in KIT.operations(r)
    resources = r.fake.calls_for(service="apigateway", operation="GetResources")
    assert all(c.params.get("embed") == ["methods"] and c.params.get("limit") == 500 for c in resources)
    assert [c.params.get("limit") for c in r.fake.calls_for(service="apigateway", operation="GetRestApis")] == [500]


@pytest.mark.finding("F-100")
def test_get_integration_is_the_fallback_when_methods_are_not_embedded(tmp_path):
    w = KIT.world()
    original = w.handlers[("apigateway", "GetResources")]

    def without_embed(req):
        req.params.pop("embed", None)
        return original(req)

    w.handlers[("apigateway", "GetResources")] = without_embed
    r = KIT.run("apigateway", tmp_path, w)
    KIT.assert_contract(r)
    calls = r.fake.calls_for(service="apigateway", operation="GetIntegration")
    assert sorted((c.params["restApiId"], c.params["httpMethod"]) for c in calls) == [
        ("demorest01", "GET"), ("demorest01", "POST"), ("demorest02", "ANY")]
    assert apis(r)["demorest01"]["LambdaTargets"] == [f"{FN}demo-processor"]
    rows = KIT.calls(r, "apigateway:GetIntegration")
    assert {(row["status"], row["not_configured"]) for row in rows} == {("ok", False), ("ok", True)}


@pytest.mark.finding("F-044")
def test_aws_iam_methods_are_authenticated_and_none_next_to_an_authorizer_is_not(tmp_path, gw_data):
    rest01, rest02 = gw_data["rest_apis"]
    rest01["resources"][1]["auth"] = {"GET": ("AWS_IAM", None)}
    rest02["resources"].append({"id": "res0000003", "parentId": "root000002", "pathPart": "health", "path": "/health",
                                "methods": {"GET": {"type": "AWS_PROXY", "httpMethod": "POST",
                                                    "uri": URI.format(f"{FN}demo-processor")}}})
    by_id = apis(KIT.run("apigateway", tmp_path))
    assert by_id["demorest01"]["UnauthenticatedLambdaRoutes"] == []
    assert by_id["demorest01"]["LambdaTargets"] == [f"{FN}demo-processor"]
    assert by_id["demorest02"]["HasAuthorizer"] is True
    unauthenticated = by_id["demorest02"]["UnauthenticatedLambdaRoutes"]
    assert [(x["Method"], x["Path"]) for x in unauthenticated] == [("GET", "/health")]


@pytest.mark.finding("F-099")
def test_stage_variables_are_resolved_per_stage(tmp_path, gw_data):
    rest01 = gw_data["rest_apis"][0]
    rest01["resources"][1]["methods"]["GET"]["uri"] = URI.format(f"{FN}demo-processor:${{stageVariables.lambdaAlias}}")
    rest01["stages"].append({"stageName": "beta", "deploymentId": "dep0001", "variables": {"other": "x"},
                             "createdDate": acme.ts(3), "lastUpdatedDate": acme.ts(3)})
    item = apis(KIT.run("apigateway", tmp_path))["demorest01"]
    lam = [i for i in item["Integrations"] if i["Method"] == "GET"]
    assert lam == [{"Method": "GET", "Path": "/orders", "AuthorizationType": "NONE",
                    "EffectiveAuthorizationType": "NONE", "AuthorizerId": None, "ApiKeyRequired": False,
                    "IntegrationType": "AWS_PROXY", "LambdaArn": f"{FN}demo-processor", "Qualifier": "live",
                    "Stage": "prod", "Unresolved": False}]
    assert item["LambdaTargets"] == [f"{FN}demo-processor"]


@pytest.mark.finding("F-099")
@pytest.mark.parametrize("uri, expected", [
    (URI.format(f"{FN}fn"), [(f"{FN}fn", None, None, False)]),
    (URI.format(f"{FN}fn:prod"), [(f"{FN}fn", "prod", None, False)]),
    (URI.format(f"{FN}fn:7"), [(f"{FN}fn", "7", None, False)]),
    (f"{FN}fn", [(f"{FN}fn", None, None, False)]),                                       # HTTP API form
    (URI.format("arn:aws-us-gov:lambda:us-gov-west-1:123456789012:function:gov"),
     [("arn:aws-us-gov:lambda:us-gov-west-1:123456789012:function:gov", None, None, False)]),
    (URI.format("arn:aws-cn:lambda:cn-north-1:123456789012:function:cn:live"),
     [("arn:aws-cn:lambda:cn-north-1:123456789012:function:cn", "live", None, False)]),
    (URI.format(f"{FN}${{stageVariables.fn}}"),
     [(f"{FN}a", None, "dev", False), (f"{FN}b", None, "prod", False)]),
    (URI.format(f"{FN}fn:${{stageVariables.alias}}"), [(f"{FN}fn", "blue", "prod", False)]),
    (URI.format(f"{FN}${{stageVariables.missing}}"), [(None, None, None, True)]),
    ("https://api.example.com/{proxy}", []),
    (None, []),
])
def test_lambda_target_parsing(uri, expected):
    stages = {"dev": {"fn": "a"}, "prod": {"fn": "b", "alias": "blue"}}
    got = module().lambda_targets(uri, stages)
    assert [(t["LambdaArn"], t["Qualifier"], t["Stage"], t["Unresolved"]) for t in got] == expected


@pytest.mark.finding("F-044")
def test_websocket_routes_inherit_connect_authorisation(tmp_path, gw_data):
    ws = gw_data["http_apis"][1]
    ws["integrations"] = [{"IntegrationId": "int0003", "IntegrationType": "AWS_PROXY",
                           "IntegrationUri": f"{FN}demo-processor"},
                          {"IntegrationId": "int0004", "IntegrationType": "AWS_PROXY",
                           "IntegrationUri": f"{FN}demo-internal"}]
    ws["routes"] = [{"RouteId": "rt00003", "RouteKey": "$connect", "AuthorizationType": "AWS_IAM",
                     "ApiKeyRequired": False},
                    {"RouteId": "rt00004", "RouteKey": "$default", "Target": "integrations/int0003",
                     "AuthorizationType": "NONE", "ApiKeyRequired": False}]
    item = apis(KIT.run("apigateway", tmp_path))["demows0001"]
    default = [i for i in item["Integrations"] if i["RouteKey"] == "$default"][0]
    assert default["AuthorizationType"] == "NONE" and default["EffectiveAuthorizationType"] == "AWS_IAM"
    assert item["UnauthenticatedLambdaRoutes"] == []
    assert item["LambdaTargets"] == [f"{FN}demo-processor"]                 # int0004 has no route
    unrouted = [i for i in item["Integrations"] if i["RouteKey"] is None]
    assert [i["LambdaArn"] for i in unrouted] == [f"{FN}demo-internal"]
    effective = module().effective_route_auth("WEBSOCKET", [{"RouteKey": "$default", "AuthorizationType": "NONE"}])
    assert effective == {"$default": "NONE"}                                 # no $connect: open


@pytest.mark.finding("F-044")
def test_rest_resource_policy_is_parsed(tmp_path):
    w = KIT.world()
    original = w.handlers[("apigateway", "GetRestApis")]
    policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": "*", "Action": "execute-api:Invoke", "Resource": "execute-api:/*",
        "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}}]}

    def with_policy(req):
        out = original(req)
        out["items"][0]["policy"] = json.dumps(policy).replace('"', '\\"')        # as API Gateway escapes it
        out["items"][0]["endpointConfiguration"] = {"types": ["PRIVATE"]}
        return out

    w.handlers[("apigateway", "GetRestApis")] = with_policy
    item = apis(KIT.run("apigateway", tmp_path, w))["demorest01"]
    assert item["ResourcePolicy"] == policy and item["EndpointTypes"] == ["PRIVATE"]


@pytest.mark.finding("F-102", "F-059")
def test_a_denied_resource_listing_keeps_the_api_with_unknown_routes(tmp_path):
    w = KIT.world()
    w.deny("apigateway", "GetResources", {"restApiId": "demorest01"})
    r = KIT.run("apigateway", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    item = apis(r)["demorest01"]
    assert item["Integrations"] is None and item["LambdaTargets"] is None
    assert item["UnauthenticatedLambdaRoutes"] is None                       # unknown, not "none"
    assert KIT.collection_errors(item) == [("apigateway:GetResources", "denied")]


@pytest.mark.finding("F-103")
def test_rest_listing_denied_keeps_the_http_apis(tmp_path):
    w = KIT.world()
    w.deny("apigateway", "GetRestApis")
    r = KIT.run("apigateway", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    assert sorted(apis(r)) == ["demohttp01", "demows0001"]


@pytest.mark.finding("F-099")
def test_api_arns_follow_the_partition(tmp_path):
    base = targets.collector_base_module()
    w = KIT.world()

    @w.op("apigateway", "GetRestApis")
    def gov(req):
        return {"items": [{"id": "govapi0001", "name": "demo-gov"}]}

    @w.op("apigateway", "GetResources", "GetAuthorizers")
    def empty(req):
        return {"items": []}

    @w.op("apigateway", "GetStages")
    def stages(req):
        return {"item": []}

    @w.op("apigatewayv2", "GetApis")
    def no_apis(req):
        return {"Items": []}

    fake = FakeAWS(w, strict=True)
    run = base.RunInfo(run_id="20261015T101500Z-a1b2c3", aws=base.SessionAwsProvider(fake.session_factory()),
                       run_root=Path(tmp_path))
    ctx = base.CollectContext.create(KIT.spec("apigateway"), region="us-gov-west-1", account_id=ACCT,
                                     partition="aws-us-gov", run=run, unit_dir=Path(tmp_path) / "us-gov-west-1")
    assert base.run_collector(ctx).status == "ok"
    assert [i["Arn"] for i in S.load_json(ctx.out.root / "resources.json")] == [
        "arn:aws-us-gov:apigateway:us-gov-west-1::/restapis/govapi0001"]


def test_empty_region_is_ok(tmp_path):
    r = KIT.run("apigateway", tmp_path, region=KIT.EMPTY_REGION)
    KIT.assert_contract(r)
    assert r.load("resources.json") == []


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    assert KIT.assert_each_api_denied_is_survivable("apigateway", tmp_path) == [
        "apigateway:GetAuthorizers", "apigateway:GetResources", "apigateway:GetRestApis", "apigateway:GetStages",
        "apigatewayv2:GetApis", "apigatewayv2:GetAuthorizers", "apigatewayv2:GetIntegrations",
        "apigatewayv2:GetRoutes", "apigatewayv2:GetStages"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    r = KIT.run("apigateway", tmp_path)
    KIT.assert_declared_and_read_only(r)
    spec = KIT.spec("apigateway")
    assert spec.actions == ("apigateway:GET",)
    prefix = "arn:{partition}:apigateway:*::"
    assert spec.resource_scoped[0][1] == tuple(prefix + p for p in ("/restapis", "/restapis/*", "/apis", "/apis/*"))
