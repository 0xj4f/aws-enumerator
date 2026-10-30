"""Cognito collector (collectors-cli.md §5.13): role mappings, classic flow, providers, self sign-up, no secrets."""

from __future__ import annotations

import importlib

import pytest

from tests.fixtures.worlds import acme
from tests.support.fakeaws import botocore_error

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

W2, ACCT = KIT.W2, KIT.ACCT
POOL_A = "eu-west-2:11111111-2222-4333-8444-55555555555a"
POOL_B = "eu-west-2:11111111-2222-4333-8444-55555555555b"
USER_POOL = "eu-west-2_DemoPool1"


def by_id(r):
    return KIT.by(r.load("resources.json"), "Id")


@pytest.mark.finding("F-048", "F-059")
def test_identity_pools_and_user_pools(tmp_path):
    r = KIT.run("cognito", tmp_path)
    KIT.assert_contract(r, statuses=("partial",))           # acme denies GetIdentityPoolRoles on pool b
    items = r.load("resources.json")
    assert [(i["Kind"], i["Id"]) for i in items] == [("identity_pool", POOL_A), ("identity_pool", POOL_B),
                                                    ("user_pool", USER_POOL)]
    a = by_id(r)[POOL_A]
    assert a["Arn"] == f"arn:aws:cognito-identity:{W2}:{ACCT}:identitypool/{POOL_A}"
    assert a["UnauthRole"] == acme.role_arn("demo-cognito-unauth-role") and a["AuthRole"] is None
    assert a["RoleMappings"] == {} and a["AllowUnauth"] is True and a["AllowClassicFlow"] is True
    assert a["SupportedLoginProviders"] == {} and a["OpenIdConnectProviderARNs"] == []
    b = by_id(r)[POOL_B]
    assert b["RoleMappings"] is None and b["UnauthRole"] is None and b["AllowUnauth"] is False   # unknown roles
    assert KIT.collection_errors(b) == [("cognito-identity:GetIdentityPoolRoles", "denied")]
    up = by_id(r)[USER_POOL]
    assert up["Arn"] == f"arn:aws:cognito-idp:{W2}:{ACCT}:userpool/{USER_POOL}"
    assert up["SelfSignupEnabled"] is True and up["MfaConfiguration"] == "OFF" and up["Domain"] == "demo-auth"
    assert up["Clients"] == [{"ClientId": "dec0c1e47000000000000000a1", "ClientName": "demo-web-client"},
                             {"ClientId": "dec0c1e47000000000000000b2", "ClientName": "demo-backend-client"}]


@pytest.mark.finding("F-048")
def test_client_secrets_are_never_requested(tmp_path):
    r = KIT.run("cognito", tmp_path)                           # strict: DescribeUserPoolClient is not modelled
    assert ("cognito-idp", "DescribeUserPoolClient") not in KIT.operations(r)
    assert KIT.S.grep_tree("ClientSecret", r.out) == []


@pytest.mark.finding("F-048")
def test_role_mappings_and_login_providers_are_kept_in_full(tmp_path):
    w = KIT.clean_world("cognito-identity")
    mappings = {"accounts.google.com": {"Type": "Rules", "AmbiguousRoleResolution": "AuthenticatedRole",
                                        "RulesConfiguration": {"Rules": [
                                            {"Claim": "email", "MatchType": "Contains", "Value": "@example.com",
                                             "RoleARN": acme.role_arn("demo-admin-role")}]}},
                f"cognito-idp.{W2}.amazonaws.com/{USER_POOL}:dec0c1e47000000000000000a1": {"Type": "Token"}}

    @w.op("cognito-identity", "GetIdentityPoolRoles")
    def roles(req):
        return {"IdentityPoolId": req.params["IdentityPoolId"], "RoleMappings": mappings,
                "Roles": {"authenticated": acme.role_arn("demo-cognito-auth-role")}}

    @w.op("cognito-identity", "DescribeIdentityPool")
    def describe(req):
        return {"IdentityPoolId": req.params["IdentityPoolId"], "IdentityPoolName": "demo",
                "AllowUnauthenticatedIdentities": False, "AllowClassicFlow": False,
                "SupportedLoginProviders": {"accounts.google.com": "demo-google-app"},
                "DeveloperProviderName": "login.example.com",
                "CognitoIdentityProviders": [{"ProviderName": f"cognito-idp.{W2}.amazonaws.com/{USER_POOL}",
                                              "ClientId": "dec0c1e47000000000000000a1", "ServerSideTokenCheck": False}],
                "OpenIdConnectProviderARNs": [f"arn:aws:iam::{ACCT}:oidc-provider/token.example.com"],
                "SamlProviderARNs": [acme.SAML_PROVIDER_ARN]}

    r = KIT.run("cognito", tmp_path, w)
    KIT.assert_contract(r)
    a = by_id(r)[POOL_A]
    assert a["RoleMappings"] == mappings and a["AuthRole"] == acme.role_arn("demo-cognito-auth-role")
    assert a["AllowClassicFlow"] is False and a["AllowUnauth"] is False
    assert a["SupportedLoginProviders"] == {"accounts.google.com": "demo-google-app"}
    assert a["DeveloperProviderName"] == "login.example.com"
    assert a["CognitoIdentityProviders"][0]["ClientId"] == "dec0c1e47000000000000000a1"
    assert a["SamlProviderARNs"] == [acme.SAML_PROVIDER_ARN]


@pytest.mark.finding("F-103", "F-048")
def test_identity_pool_failure_still_collects_user_pools(tmp_path):
    w = KIT.world()
    w.raise_exc("cognito-identity", "ListIdentityPools",
                botocore_error("EndpointConnectionError", endpoint_url="https://cognito-identity.eu-west-2.amazonaws.com/"))
    r = KIT.run("cognito", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    assert [i["Kind"] for i in r.load("resources.json")] == ["user_pool"]
    w2 = KIT.world()
    w2.deny("cognito-idp", "ListUserPools")
    r2 = KIT.run("cognito", tmp_path / "idp", w2)
    assert {i["Kind"] for i in r2.load("resources.json")} == {"identity_pool"}


@pytest.mark.finding("F-059", "F-102")
def test_a_denied_user_pool_describe_keeps_the_pool_with_unknown_sign_up(tmp_path):
    w = KIT.world()
    w.deny("cognito-idp", "DescribeUserPool")
    r = KIT.run("cognito", tmp_path, w)
    up = by_id(r)[USER_POOL]
    assert up["SelfSignupEnabled"] is None and len(up["Clients"]) == 2
    assert KIT.collection_errors(up) == [("cognito-idp:DescribeUserPool", "denied")]


def test_empty_region_is_ok(tmp_path):
    r = KIT.run("cognito", tmp_path, region=KIT.EMPTY_REGION)
    KIT.assert_contract(r)
    assert r.load("resources.json") == []


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    assert KIT.assert_each_api_denied_is_survivable("cognito", tmp_path) == [
        "cognito-identity:DescribeIdentityPool", "cognito-identity:GetIdentityPoolRoles",
        "cognito-identity:ListIdentityPools", "cognito-idp:DescribeUserPool", "cognito-idp:ListUserPoolClients",
        "cognito-idp:ListUserPools"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    KIT.assert_declared_and_read_only(KIT.run("cognito", tmp_path))
