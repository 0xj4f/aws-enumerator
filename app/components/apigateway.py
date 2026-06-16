"""
AWS API Gateway Enumeration Module

Collects REST (v1) and HTTP (v2) APIs, their authorizers, and Lambda integration
targets — so API Gateway → Lambda invoke paths and unauthenticated endpoints show
up in the graph.

reports/{account}/{region}/apigateway/
└── resources.json   # Normalized: {Type, Arn, Name, Protocol, LambdaTargets, HasAuthorizer}
"""

import json
import os
from botocore.exceptions import ClientError


def _extract_lambda_arn(uri):
    """Pull the Lambda function ARN out of an API Gateway integration URI."""
    if not uri or "arn:aws:lambda:" not in uri:
        return None
    arn = uri[uri.index("arn:aws:lambda:"):]
    end = arn.find("/invocations")
    if end != -1:
        arn = arn[:end]
    return arn


def _enumerate_rest(client, region, resources):
    apis = []
    paginator = client.get_paginator("get_rest_apis")
    for page in paginator.paginate():
        apis.extend(page.get("items", []))

    for api in apis:
        api_id = api.get("id")
        lambda_targets = set()
        try:
            for rpage in client.get_paginator("get_resources").paginate(restApiId=api_id):
                for res in rpage.get("items", []):
                    for method in (res.get("resourceMethods") or {}):
                        try:
                            integ = client.get_integration(
                                restApiId=api_id, resourceId=res["id"], httpMethod=method)
                            fn = _extract_lambda_arn(integ.get("uri"))
                            if fn:
                                lambda_targets.add(fn)
                        except ClientError:
                            continue
        except ClientError:
            pass

        has_auth = False
        try:
            has_auth = len(client.get_authorizers(restApiId=api_id).get("items", [])) > 0
        except ClientError:
            pass

        resources.append({
            "Type": "apigw",
            "Arn": f"arn:aws:apigateway:{region}::/restapis/{api_id}",
            "Name": api.get("name"),
            "Protocol": "REST",
            "LambdaTargets": sorted(lambda_targets),
            "HasAuthorizer": has_auth,
        })


def _enumerate_http(client, region, resources):
    apis = []
    paginator = client.get_paginator("get_apis")
    for page in paginator.paginate():
        apis.extend(page.get("Items", []))

    for api in apis:
        api_id = api.get("ApiId")
        lambda_targets = set()
        try:
            for ipage in client.get_paginator("get_integrations").paginate(ApiId=api_id):
                for integ in ipage.get("Items", []):
                    fn = _extract_lambda_arn(integ.get("IntegrationUri"))
                    if fn:
                        lambda_targets.add(fn)
        except ClientError:
            pass

        has_auth = False
        try:
            has_auth = len(client.get_authorizers(ApiId=api_id).get("Items", [])) > 0
        except ClientError:
            pass

        resources.append({
            "Type": "apigw",
            "Arn": f"arn:aws:apigateway:{region}::/apis/{api_id}",
            "Name": api.get("Name"),
            "Protocol": api.get("ProtocolType", "HTTP"),
            "LambdaTargets": sorted(lambda_targets),
            "HasAuthorizer": has_auth,
        })


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m API Gateway Enumeration Starting...")
    os.makedirs(path, exist_ok=True)
    region = session.region_name

    resources = []
    failed = False

    try:
        _enumerate_rest(session.client("apigateway"), region, resources)
    except ClientError as e:
        failed = True
        print(f"    \033[1;33m[!]\033[0m API Gateway (REST) failed: {e}")

    try:
        _enumerate_http(session.client("apigatewayv2"), region, resources)
    except ClientError as e:
        failed = True
        print(f"    \033[1;33m[!]\033[0m API Gateway (HTTP) failed: {e}")

    if failed and not resources:
        with open(f"{path}/resources.json", "w") as f:
            json.dump({"Error": "API Gateway enumeration failed"}, f, indent=2)
        return

    with open(f"{path}/resources.json", "w") as f:
        json.dump(resources, f, indent=2, default=str)

    print(f"    \033[1;32m[+]\033[0m API Gateway Enumeration Finished ({len(resources)} APIs)")
