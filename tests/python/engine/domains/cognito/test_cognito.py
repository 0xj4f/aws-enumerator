"""Cognito analyzer (analyzers/cognito.py): identity pools as bridges from the internet to IAM roles.

Covers F-032 (guest access gating), F-048 (role mappings, classic flow, public authenticated path), F-037
(anonymous node) and request c-b-1 (``null`` = unknown). The d13c215 Cognito block of ``edge_services.py`` (E-net)
is excluded from these analyses so the assertions describe this module alone.
"""

from __future__ import annotations

import importlib

import pytest

K = importlib.import_module("tests.fixtures.e-compute.kit")
rb = K.rb
R, A = K.REGION, K.ACCT
POOL_ID = f"{R}:0a1b2c3d-aaaa-4bbb-8ccc-000000000001"
POOL = f"arn:aws:cognito-identity:{R}:{A}:identitypool/{POOL_ID}"
USER_POOL_ID = f"{R}_AbCdEf123"
AUD, AMR = "cognito-identity.amazonaws.com:aud", "cognito-identity.amazonaws.com:amr"


@pytest.fixture(autouse=True)
def _cognito_only(monkeypatch):
    K.without_analyzer_modules(monkeypatch, ".edge_services")


def _trust(amr, aud=POOL_ID):
    return rb.trust({"Federated": "cognito-identity.amazonaws.com"}, "sts:AssumeRoleWithWebIdentity",
                    {"StringEquals": {AUD: aud}, "ForAnyValue:StringLike": {AMR: amr}})


def _pool(**fields):
    rec = {"Type": "cognito", "Kind": "identity_pool", "Id": POOL_ID, "Arn": POOL, "Name": "demo_pool",
           "AuthRole": None, "UnauthRole": None, "RoleMappings": {}, "AllowUnauth": False, "AllowClassicFlow": False,
           "SupportedLoginProviders": {}, "CognitoIdentityProviders": [], "OpenIdConnectProviderARNs": [],
           "SamlProviderARNs": []}
    rec.update(fields)
    return rec


def _user_pool(signup):
    return {"Type": "cognito", "Kind": "user_pool", "Id": USER_POOL_ID, "Name": "demo_users",
            "Arn": f"arn:aws:cognito-idp:{R}:{A}:userpool/{USER_POOL_ID}", "SelfSignupEnabled": signup,
            "Clients": [{"ClientId": "c1", "ClientName": "web"}]}


def _linked():
    return [{"ProviderName": f"cognito-idp.{R}.amazonaws.com/{USER_POOL_ID}", "ClientId": "c1"}]


def _tree(tmp_path, records, roles=()):
    t = K.LegacyTree(tmp_path)
    for name, trust in roles:
        t.iam.role(name, trust)
    t.put("cognito/resources.json", records)
    return t


# ── F-032: guest access ──────────────────────────────────────────────────────

@pytest.mark.finding("F-032")
@pytest.mark.parametrize("allow, edge, severity", [(True, True, "HIGH"), (False, False, None), (None, True, "MEDIUM")])
def test_unauthenticated_role_is_gated_on_allow_unauth(tmp_path, allow, edge, severity):
    t = _tree(tmp_path, [_pool(UnauthRole=K.iam_arn("role", "demo-guest"), AllowUnauth=allow)],
              [("demo-guest", _trust("unauthenticated"))])
    g = t.analyze().graph
    assert K.problems(g) == []
    role = K.iam_arn("role", "demo-guest")
    edges = K.edges(g, "POOL_UNAUTH_ROLE", POOL, role)
    assert bool(edges) is edge
    unauth = K.findings(g, "COGNITO-UNAUTH-001", POOL)
    if severity is None:
        assert not unauth and not K.edges(g, "COGNITO_PUBLIC_IDENTITY")
        assert K.only(K.findings(g, "COGNITO-UNAUTH-002", POOL))["severity"] == "INFO"
        assert K.path(g, K.ANON, role) is None
    else:
        assert K.only(unauth)["severity"] == severity
        public = K.only(K.edges(g, "COGNITO_PUBLIC_IDENTITY", K.ANON, POOL))
        assert public["confidence"] == ("definite" if allow else "conditional")
        assert K.path(g, K.ANON, role) is not None
    if allow is None:
        assert edges[0]["confidence"] == "conditional"
        assert K.nodes(g)[POOL]["coverage"]["status"] == "partial"


@pytest.mark.finding("F-032")
def test_role_whose_trust_refuses_the_pool_is_not_handed_out(tmp_path):
    other = f"{R}:0a1b2c3d-aaaa-4bbb-8ccc-000000000009"
    t = _tree(tmp_path, [_pool(UnauthRole=K.iam_arn("role", "demo-guest"), AllowUnauth=True)],
              [("demo-guest", _trust("unauthenticated", aud=other))])
    g = t.analyze().graph
    assert not K.edges(g, "POOL_UNAUTH_ROLE")
    assert K.nodes(g)[POOL]["props"]["roles_not_trusting_pool"] == [K.iam_arn("role", "demo-guest")]
    assert not K.findings(g, "COGNITO-UNAUTH-001")


# ── F-048: the authenticated path ────────────────────────────────────────────

@pytest.mark.finding("F-048")
@pytest.mark.parametrize("signup, public", [(True, True), (False, False), (None, "unknown")])
def test_self_signup_user_pool_makes_the_authenticated_role_public(tmp_path, signup, public):
    t = _tree(tmp_path, [_pool(AuthRole=K.iam_arn("role", "demo-auth"), CognitoIdentityProviders=_linked()),
                         _user_pool(signup)], [("demo-auth", _trust("authenticated"))])
    g = t.analyze().graph
    assert K.problems(g) == []
    auth = K.only(K.edges(g, "POOL_AUTH_ROLE", POOL, K.iam_arn("role", "demo-auth")))
    assert auth["traversable"] is (public is True)
    assert auth["evidence"]["traversable_rule"] == {"rule": "pool-auth-public", "holds": public is True}
    assert K.nodes(g)[POOL]["props"]["auth_public"] == public
    assert bool(K.findings(g, "COGNITO-AUTH-PUBLIC-001", POOL)) is (public is True)
    assert bool(K.edges(g, "COGNITO_PUBLIC_IDENTITY", K.ANON, POOL)) is (public is True)
    assert (K.path(g, K.ANON, K.iam_arn("role", "demo-auth")) is not None) is (public is True)
    if public == "unknown":
        gaps = K.nodes(g)[POOL]["coverage"]["gaps"]
        assert f"cognito-idp:DescribeUserPool:self-signup-unknown@{USER_POOL_ID}" in gaps
        user_pool = K.nodes(g)[f"arn:aws:cognito-idp:{R}:{A}:userpool/{USER_POOL_ID}"]
        assert user_pool["type"] == "cognitouserpool"


@pytest.mark.finding("F-048")
def test_public_social_login_provider_makes_the_authenticated_role_public(tmp_path):
    t = _tree(tmp_path, [_pool(AuthRole=K.iam_arn("role", "demo-auth"),
                               SupportedLoginProviders={"accounts.google.com": "demo.apps.example"})],
              [("demo-auth", _trust("authenticated"))])
    g = t.analyze().graph
    finding = K.only(K.findings(g, "COGNITO-AUTH-PUBLIC-001", POOL))
    assert finding["evidence"]["reasons"] == ["public login provider accounts.google.com"]
    assert K.path(g, K.ANON, K.iam_arn("role", "demo-auth")) is not None


@pytest.mark.finding("F-048")
def test_role_mappings_and_token_mappings(tmp_path):
    mappings = {
        "accounts.google.com": {"Type": "Rules", "AmbiguousRoleResolution": "Deny", "RulesConfiguration": {
            "Rules": [{"Claim": "email", "MatchType": "Contains", "Value": "@example.com",
                       "RoleARN": K.iam_arn("role", "demo-mapped")}]}},
        f"cognito-idp.{R}.amazonaws.com/{USER_POOL_ID}:c1": {"Type": "Token",
                                                            "AmbiguousRoleResolution": "AuthenticatedRole"}}
    t = _tree(tmp_path, [_pool(RoleMappings=mappings, SupportedLoginProviders={"accounts.google.com": "x"})],
              [("demo-mapped", _trust("authenticated")), ("demo-claims", _trust("authenticated")),
               ("demo-unrelated", rb.trust({"Service": "ec2.amazonaws.com"}))])
    g = t.analyze().graph
    assert K.problems(g) == []
    rules = K.only(K.edges(g, "POOL_MAPPED_ROLE", POOL, K.iam_arn("role", "demo-mapped")))
    assert rules["evidence"]["technique"] in ("rules-mapping", "token-mapping") and rules["traversable"] is True
    token = K.only(K.edges(g, "POOL_MAPPED_ROLE", POOL, K.iam_arn("role", "demo-claims")))
    assert token["evidence"]["technique"] == "token-mapping"
    assert not K.edges(g, source=POOL, target=K.iam_arn("role", "demo-unrelated"))
    assert K.only(K.findings(g, "COGNITO-TOKEN-MAP-001", POOL))["severity"] == "LOW"


@pytest.mark.finding("F-048")
def test_classic_flow_reaches_every_role_that_trusts_the_pool(tmp_path):
    loose = rb.trust({"Federated": "cognito-identity.amazonaws.com"}, "sts:AssumeRoleWithWebIdentity",
                     {"StringEquals": {AUD: POOL_ID}})
    t = _tree(tmp_path, [_pool(AllowClassicFlow=True, AllowUnauth=True)],
              [("demo-loose", loose), ("demo-authonly", _trust("authenticated"))])
    g = t.analyze().graph
    loose_arn, auth_arn = K.iam_arn("role", "demo-loose"), K.iam_arn("role", "demo-authonly")
    assert K.edges(g, "POOL_UNAUTH_ROLE", POOL, loose_arn)                  # guests + classic flow, no amr check
    assert not K.edges(g, "POOL_UNAUTH_ROLE", POOL, auth_arn)               # amr = authenticated only
    assert K.only(K.edges(g, "POOL_MAPPED_ROLE", POOL, auth_arn))["evidence"]["technique"] == "classic-flow"
    classic = K.only(K.findings(g, "COGNITO-CLASSIC-001", POOL))
    assert loose_arn in classic["related_node_ids"]
    assert "roles_not_trusting_pool" not in K.nodes(g)[POOL]["props"]


@pytest.mark.finding("F-048")
def test_classic_flow_without_any_trusting_role_is_low(tmp_path):
    t = _tree(tmp_path, [_pool(AllowClassicFlow=True)], [("demo-ec2", rb.trust({"Service": "ec2.amazonaws.com"}))])
    g = t.analyze().graph
    classic = K.only(K.findings(g, "COGNITO-CLASSIC-001", POOL))
    assert classic["severity"] == "LOW" and classic["evidence"]["roles_trusting_pool"] == []


# ── d13c215 layout and null = unknown ────────────────────────────────────────

@pytest.mark.finding("F-032", "F-059")
def test_legacy_records_and_unknown_fields(tmp_path):
    legacy = {"Type": "cognito", "Kind": "identity_pool", "Id": POOL_ID, "Name": "demo_pool",
              "AuthRole": K.iam_arn("role", "demo-auth"), "UnauthRole": None, "AllowUnauth": False}
    t = _tree(tmp_path, [legacy], [("demo-auth", _trust("authenticated"))])
    g = t.analyze().graph
    assert K.problems(g) == []
    assert K.nodes(g)[POOL]["type"] == "cognito"
    edge = K.only(K.edges(g, "POOL_AUTH_ROLE", POOL))
    assert edge["traversable"] is False and K.nodes(g)[POOL]["props"]["auth_public"] is False
    assert not K.findings(g, "COGNITO-UNAUTH-001")


@pytest.mark.finding("F-059")
def test_unknown_provider_lists_leave_the_auth_path_unknown(tmp_path):
    t = _tree(tmp_path, [rb.mark_item(_pool(AuthRole=K.iam_arn("role", "demo-auth")),
                                      rb.collection_error("cognito-identity:DescribeIdentityPool"),
                                      unknown=["SupportedLoginProviders", "CognitoIdentityProviders",
                                               "AllowClassicFlow"])],
              [("demo-auth", _trust("authenticated"))])
    g = t.analyze().graph
    node = K.nodes(g)[POOL]
    assert node["props"]["auth_public"] == "unknown" and node["coverage"]["status"] == "partial"
    edge = K.only(K.edges(g, "POOL_AUTH_ROLE", POOL))
    assert edge["traversable"] is False and edge["evidence"]["auth_public"] == "unknown"
    assert edge["evidence"]["gaps"]


@pytest.mark.finding("F-048")
def test_role_not_collected_gives_a_conditional_edge(tmp_path):
    t = _tree(tmp_path, [_pool(UnauthRole=K.iam_arn("role", "demo-missing"), AllowUnauth=True)])
    g = t.analyze().graph
    edge = K.only(K.edges(g, "POOL_UNAUTH_ROLE", POOL, K.iam_arn("role", "demo-missing")))
    assert edge["confidence"] == "conditional" and "iam:trust-unknown" in edge["evidence"]["gaps"]
