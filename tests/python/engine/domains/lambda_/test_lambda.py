"""Lambda analyzer (analyzers/lambda_.py, loader io/loaders/lambda_.py): native on the policy evaluator.

Covers F-001/F-014/F-015 (decisions from the evaluator), F-002 (single-object statements), F-004 (control vs
exposure vs invocation), F-055 (alias policies and URLs on the base node), F-080 (URL needs a public grant),
F-059 (unknown is not "not public"), F-116 (layers, event source mappings) and request c-b-1 (null = unknown).
"""

from __future__ import annotations

import importlib

import pytest

K = importlib.import_module("tests.fixtures.e-compute.kit")
rb = K.rb

FN = K.fn_arn("demo-fn")
ROLE = K.iam_arn("role", "demo-fn-role")
URL_COND = {"StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}}


def _tree(tmp_path, *, url_auth=None, policy=None, admin_role=True):
    t = K.LegacyTree(tmp_path)
    t.iam.role("demo-fn-role", rb.trust({"Service": "lambda.amazonaws.com"}),
               attached=["AdministratorAccess"] if admin_role else [])
    fn = rb.lambda_function("demo-fn", account=K.ACCT, region=K.REGION, role=ROLE, url_auth=url_auth)
    t.put("lambda/functions.json", [fn])
    if policy is not None:
        t.put("lambda/resource_policies/demo-fn.json", rb.lambda_policy_file(fn, policy))
    return t, fn


# ── F-004: control, exposure and invocation ──────────────────────────────────

@pytest.mark.finding("F-004")
def test_only_code_and_configuration_updates_are_control(tmp_path):
    t, _ = _tree(tmp_path, policy=rb.resource_policy(rb.grant("*", "lambda:InvokeFunction", FN)))
    t.iam.user("demo-updater", inline={"p": [rb.allow("lambda:UpdateFunctionCode", FN)]})
    t.iam.user("demo-config", inline={"p": [rb.allow("lambda:UpdateFunctionConfiguration", FN)]})
    t.iam.user("demo-exposer", inline={"p": [rb.allow(["lambda:AddPermission", "lambda:CreateFunctionUrlConfig",
                                                       "lambda:UpdateFunctionUrlConfig", "lambda:PublishVersion",
                                                       "lambda:UpdateAlias"], FN)]})
    t.iam.user("demo-invoker", inline={"p": [rb.allow("lambda:InvokeFunction", FN)]})
    g = t.analyze().graph
    assert K.problems(g) == []
    users = {n: K.iam_arn("user", n) for n in ("demo-updater", "demo-config", "demo-exposer", "demo-invoker")}
    assert K.edge_types(g, users["demo-updater"], FN) == {"CAN_UPDATE_CODE"}
    assert K.edge_types(g, users["demo-config"], FN) == {"CAN_MODIFY_CONFIG"}
    assert K.edge_types(g, users["demo-exposer"], FN) == {"CAN_EXPOSE"}
    assert K.edge_types(g, users["demo-invoker"], FN) == {"CAN_INVOKE"}
    for name in ("demo-updater", "demo-config"):
        assert K.path(g, users[name], ROLE) is not None, name
    for source in (users["demo-exposer"], users["demo-invoker"], K.ANON):
        assert K.path(g, source, ROLE) is None, source
    public = K.only(K.edges(g, "LAMBDA_GRANTS_PUBLIC", K.ANON, FN))
    assert public["traversable"] is False and public["traversal"] == "exposure"
    assert K.only(K.edges(g, "USES_ROLE", FN, ROLE))["traversable"] is True


@pytest.mark.finding("F-004")
def test_legacy_file_renders_the_old_names_and_directions(tmp_path):
    t, _ = _tree(tmp_path, policy=rb.resource_policy(rb.grant("*", "lambda:InvokeFunction", FN)))
    t.iam.user("demo-exposer", inline={"p": [rb.allow("lambda:AddPermission", FN)]})
    out = t.analyze()
    legacy = K.legacy_edges(out, "lambda")
    by_type = {e["type"]: e for e in legacy}
    assert by_type["CAN_MODIFY_CONFIG"]["source"] == K.iam_arn("user", "demo-exposer")    # CAN_EXPOSE, old name
    assert by_type["LAMBDA_GRANTS_PUBLIC"]["source"] == f"lambda:{FN}"                   # stored resource -> *
    assert by_type["LAMBDA_GRANTS_PUBLIC"]["target"] == "principal:*"
    assert by_type["USES_ROLE"]["target"] == ROLE
    assert K.load(out.dir / "lambda_relationships.json").get("status") is None


# ── F-001 / F-014 / F-015: decisions from the evaluator ──────────────────────

@pytest.mark.finding("F-001", "F-014", "F-015")
def test_notaction_deny_and_conditions_come_from_the_evaluator(tmp_path):
    t, _ = _tree(tmp_path)
    t.iam.user("demo-power", attached=["PowerUserAccess"])
    t.iam.user("demo-denied", inline={"p": [rb.allow("lambda:*", "*"), rb.deny("lambda:UpdateFunctionCode")]})
    t.iam.user("demo-deny-all", inline={"p": [rb.allow("lambda:*", "*"), rb.deny("lambda:*")]})
    t.iam.user("demo-mfa", inline={"p": [rb.allow("lambda:UpdateFunctionCode", FN,
                                                   {"Bool": {"aws:MultiFactorAuthPresent": "true"}})]})
    t.iam.user("demo-other-fn", inline={"p": [rb.allow("lambda:*", K.fn_arn("demo-other"))]})
    g = t.analyze().graph
    assert K.edge_types(g, K.iam_arn("user", "demo-power"), FN) == {"CAN_UPDATE_CODE"}          # NotAction iam:*
    assert K.edge_types(g, K.iam_arn("user", "demo-denied"), FN) == {"CAN_MODIFY_CONFIG"}       # Deny honoured
    assert K.edge_types(g, K.iam_arn("user", "demo-deny-all"), FN) == set()
    assert K.edge_types(g, K.iam_arn("user", "demo-other-fn"), FN) == set()
    mfa = K.only(K.edges(g, "CAN_UPDATE_CODE", K.iam_arn("user", "demo-mfa"), FN))
    assert mfa["confidence"] == "conditional" and mfa["evidence"]["condition_strength"] in ("weak", "strong")
    assert mfa["weight"] > 1                                                                     # penalised


@pytest.mark.finding("F-001")
def test_group_inherited_grants_reach_the_member(tmp_path):
    t, _ = _tree(tmp_path)
    t.iam.group("demo-devs", inline={"p": [rb.allow("lambda:UpdateFunctionCode", "*")]})
    t.iam.user("demo-dev", groups=["demo-devs"])
    g = t.analyze().graph
    assert "CAN_UPDATE_CODE" in K.edge_types(g, K.iam_arn("user", "demo-dev"), FN)


@pytest.mark.finding("F-001", "F-030")
def test_same_account_grant_in_the_function_policy_alone_gives_access(tmp_path):
    """The evaluator unions same-account resource-policy grants; the prefilter must not hide that principal."""
    t, _ = _tree(tmp_path, policy=rb.resource_policy(
        rb.grant({"AWS": K.iam_arn("role", "demo-caller")}, "lambda:InvokeFunction", FN)))
    t.iam.role("demo-caller", rb.trust({"Service": "ec2.amazonaws.com"}))
    g = t.analyze().graph
    caller = K.iam_arn("role", "demo-caller")
    assert "CAN_INVOKE" in K.edge_types(g, caller, FN)
    assert K.only(K.edges(g, "LAMBDA_GRANTS_INVOKE", caller, FN))["traversable"] is False


# ── resource-policy grants ───────────────────────────────────────────────────

@pytest.mark.finding("F-002")
def test_single_object_statement_in_a_function_policy(tmp_path):
    single = {"Version": "2012-10-17", "Statement": rb.grant("*", "lambda:InvokeFunction", FN)}
    t, _ = _tree(tmp_path, policy=single)
    g = t.analyze().graph
    assert K.findings(g, "LAMBDA-PUB-001", FN)
    assert K.edges(g, "LAMBDA_GRANTS_PUBLIC", K.ANON, FN)


@pytest.mark.finding("F-031", "F-039")
def test_cross_account_service_and_gated_grants(tmp_path):
    foreign_role = f"arn:aws:iam::{K.FOREIGN}:role/demo-caller"
    t, _ = _tree(tmp_path, policy=rb.resource_policy(
        rb.grant({"AWS": foreign_role}, "lambda:InvokeFunction", FN),
        rb.grant({"AWS": f"arn:aws:iam::{K.ACCT}:root"}, "lambda:InvokeFunction", FN),
        rb.grant({"Service": "s3.amazonaws.com"}, "lambda:InvokeFunction", FN,
                 {"ArnLike": {"aws:SourceArn": "arn:aws:s3:::demo-bucket"}}),
        rb.grant("*", "lambda:InvokeFunction", FN, {"StringEquals": {"aws:SourceAccount": K.ACCT}}),
    ))
    g = t.analyze().graph
    assert K.problems(g) == []
    xacct = K.only(K.edges(g, "LAMBDA_GRANTS_CROSS_ACCOUNT", foreign_role, FN))
    assert xacct["props"]["cross_account"] is True and K.nodes(g)[foreign_role]["type"] == "external_principal"
    assert K.only(K.findings(g, "LAMBDA-XACCT-001", FN))["severity"] == "MEDIUM"
    assert K.edges(g, "LAMBDA_GRANTS_INVOKE", "svc:s3.amazonaws.com", FN)
    assert not K.edges(g, source=f"arn:aws:iam::{K.ACCT}:root")              # same-account root = delegation
    assert not K.findings(g, "LAMBDA-PUB-001")                                 # * gated by the own account


# ── F-055: alias policies and URLs belong to the base function ───────────────

@pytest.mark.finding("F-055")
def test_alias_policy_never_overwrites_the_function_policy(tmp_path):
    foreign = f"arn:aws:iam::{K.FOREIGN}:role/demo-a"
    other = f"arn:aws:iam::{rb.ACCT_ALT}:role/demo-b"
    t, fn = _tree(tmp_path)
    fn["Aliases"] = [{"Name": "live", "AliasArn": FN + ":live", "FunctionVersion": "3", "PolicyStatus": "present"}]
    fn["PolicyStatus"] = "present"
    t.put("lambda/functions.json", [fn])
    t.put("lambda/resource_policies/demo-fn-0001.json", {
        "FunctionArn": FN, "FunctionName": "demo-fn", "Qualifier": None, "QualifiedArn": FN,
        "ResourcePolicy": rb.resource_policy(rb.grant({"AWS": foreign}, "lambda:InvokeFunction", FN))})
    t.put("lambda/resource_policies/demo-fn_live-0002.json", {
        "FunctionArn": FN, "FunctionName": "demo-fn", "Qualifier": "live", "QualifiedArn": FN + ":live",
        "ResourcePolicy": rb.resource_policy(rb.grant({"AWS": other}, "lambda:InvokeFunction", FN + ":live"))})
    g = t.analyze().graph
    assert K.problems(g) == []
    assert K.edges(g, "LAMBDA_GRANTS_CROSS_ACCOUNT", foreign, FN)
    alias = K.only(K.edges(g, "LAMBDA_GRANTS_CROSS_ACCOUNT", other, FN))
    assert alias["evidence"]["qualifiers"] == ["live"]
    assert not [n for n in K.nodes(g) if n.startswith(FN + ":")]                # no alias node
    assert K.nodes(g)[FN]["props"]["qualifiers"] == ["live"]


@pytest.mark.finding("F-055", "F-080")
def test_alias_url_is_reported_on_the_base_function(tmp_path):
    t, fn = _tree(tmp_path)
    fn["FunctionUrls"] = [{"Qualifier": "live", "FunctionUrl": "https://demo.lambda-url.eu-west-2.on.aws/",
                           "AuthType": "NONE", "InvokeMode": "BUFFERED", "CorsAllowOrigins": []}]
    fn["Aliases"] = [{"Name": "live", "AliasArn": FN + ":live", "FunctionVersion": "1", "PolicyStatus": "present"}]
    fn["PolicyStatus"] = "absent"
    t.put("lambda/functions.json", [fn])
    t.put("lambda/resource_policies/demo-fn_live.json", {
        "FunctionArn": FN, "FunctionName": "demo-fn", "Qualifier": "live", "QualifiedArn": FN + ":live",
        "ResourcePolicy": rb.resource_policy(rb.grant("*", "lambda:InvokeFunctionUrl", FN + ":live", URL_COND))})
    g = t.analyze().graph
    url = K.only(K.findings(g, "LAMBDA-URL-001", FN))
    assert url["severity"] == "HIGH" and url["evidence"]["qualifier"] == "live"
    assert K.only(K.edges(g, "LAMBDA_GRANTS_PUBLIC", K.ANON, FN))["evidence"]["qualifiers"] == ["live"]
    assert not K.findings(g, "LAMBDA-PUB-001")                     # the URL grant is reported once, as the URL


# ── F-080 / F-059: a NONE-auth URL is public only with a public grant ─────────

@pytest.mark.finding("F-080")
def test_none_auth_url_without_a_public_grant_is_info(tmp_path):
    t, fn = _tree(tmp_path, url_auth="NONE")
    fn["PolicyStatus"] = "absent"
    t.put("lambda/functions.json", [fn])
    g = t.analyze().graph
    assert not K.findings(g, "LAMBDA-URL-001")
    assert K.only(K.findings(g, "LAMBDA-URL-002", FN))["severity"] == "INFO"
    assert not K.edges(g, "LAMBDA_GRANTS_PUBLIC")


@pytest.mark.finding("F-080")
def test_none_auth_url_with_a_public_url_grant_is_high(tmp_path):
    t, _ = _tree(tmp_path, url_auth="NONE", policy=rb.resource_policy(
        rb.grant("*", "lambda:InvokeFunctionUrl", FN, URL_COND)))
    g = t.analyze().graph
    url = K.only(K.findings(g, "LAMBDA-URL-001", FN))
    assert (url["severity"], url["confidence"]) == ("HIGH", "definite")
    assert K.only(K.edges(g, "LAMBDA_GRANTS_PUBLIC", K.ANON, FN))["evidence"]["technique"] == "function-url"
    assert not K.findings(g, "LAMBDA-PUB-001")


@pytest.mark.finding("F-080")
def test_iam_auth_url_is_never_public(tmp_path):
    t, _ = _tree(tmp_path, url_auth="AWS_IAM", policy=rb.resource_policy(
        rb.grant("*", "lambda:InvokeFunctionUrl", FN, URL_COND)))
    g = t.analyze().graph
    assert not K.findings(g, "LAMBDA-URL-001") and not K.findings(g, "LAMBDA-URL-002")


@pytest.mark.finding("F-080")
def test_unconditional_url_grant_on_an_iam_auth_url_is_a_public_grant(tmp_path):
    """Any AWS principal of any account may call an AWS_IAM URL when the policy grants ``*``."""
    t, _ = _tree(tmp_path, url_auth="AWS_IAM", policy=rb.resource_policy(
        rb.grant("*", "lambda:InvokeFunctionUrl", FN)))
    g = t.analyze().graph
    assert K.only(K.findings(g, "LAMBDA-PUB-001", FN))["severity"] == "HIGH"
    assert not K.findings(g, "LAMBDA-URL-001")


@pytest.mark.finding("F-080")
def test_url_grant_without_any_url_is_dormant(tmp_path):
    t, _ = _tree(tmp_path, policy=rb.resource_policy(rb.grant("*", "lambda:InvokeFunctionUrl", FN)))
    g = t.analyze().graph
    assert not K.findings(g, "LAMBDA-PUB-001") and not K.findings(g, "LAMBDA-URL-001")
    assert not K.edges(g, "LAMBDA_GRANTS_PUBLIC")


@pytest.mark.finding("F-059", "F-080")
def test_unreadable_policy_means_exposure_unknown_not_private(tmp_path):
    t, fn = _tree(tmp_path, url_auth="NONE")
    rb.mark_item(fn, rb.collection_error("lambda:GetPolicy"), policy_status="denied")
    t.put("lambda/functions.json", [fn])
    g = t.analyze().graph
    url = K.only(K.findings(g, "LAMBDA-URL-001", FN))
    assert (url["severity"], url["confidence"]) == ("MEDIUM", "conditional")
    assert "lambda:GetPolicy:unknown" in url["gaps"]
    node = K.nodes(g)[FN]
    assert node["coverage"]["status"] == "partial" and "lambda:GetPolicy:denied" in node["coverage"]["gaps"]
    assert not K.findings(g, "LAMBDA-URL-002")


# ── c-b-1: null = unknown, never a crash ─────────────────────────────────────

@pytest.mark.finding("F-059", "F-002")
def test_null_lists_are_unknown_not_empty(tmp_path):
    t, fn = _tree(tmp_path)
    fn.update(FunctionUrls=None, Aliases=None, PolicyStatus=None, Layers=None, VpcConfig=None)
    t.put("lambda/functions.json", [fn])
    t.put("lambda/layers.json", [{"LayerName": "demo-layer", "LayerArn": "x", "Versions": None}])
    t.put("lambda/event_source_mappings.json", [{"UUID": "u1", "EventSourceArn": None, "FunctionArn": FN}])
    out = t.analyze()
    g = out.graph
    assert K.status_of(g, "lambda") == "ok" and K.problems(g) == []
    node = K.nodes(g)[FN]
    assert node["props"]["function_urls_unknown"] is True and node["props"]["aliases_unknown"] is True
    assert {"lambda:ListFunctionUrlConfigs:unknown", "lambda:ListAliases:unknown"} <= set(node["coverage"]["gaps"])


# ── F-116: layers and event source mappings ──────────────────────────────────

@pytest.mark.finding("F-116")
def test_public_layer_version_and_event_source_mappings(tmp_path):
    t, _ = _tree(tmp_path)
    layer_v = f"arn:aws:lambda:{K.REGION}:{K.ACCT}:layer:demo-layer:3"
    private_v = f"arn:aws:lambda:{K.REGION}:{K.ACCT}:layer:demo-layer:2"
    t.put("lambda/layers.json", [{"LayerName": "demo-layer", "LayerArn": layer_v[:-2], "Versions": [
        {"Version": 3, "LayerVersionArn": layer_v, "PolicyStatus": "present", "Public": True,
         "Policy": rb.resource_policy(rb.grant("*", "lambda:GetLayerVersion", layer_v))},
        {"Version": 2, "LayerVersionArn": private_v, "PolicyStatus": "absent", "Public": False, "Policy": None}]}])
    queue = K.queue_arn("demo-jobs")
    stream = f"arn:aws:dynamodb:{K.REGION}:{K.ACCT}:table/demo-orders/stream/2026-01-01T00:00:00.000"
    kinesis = f"arn:aws:kinesis:{K.REGION}:{K.ACCT}:stream/demo-events"
    t.put("lambda/event_source_mappings.json", [
        {"UUID": "a", "EventSourceArn": queue, "FunctionArn": FN, "State": "Enabled"},
        {"UUID": "b", "EventSourceArn": stream, "FunctionArn": FN + ":live", "State": "Enabled"},
        {"UUID": "c", "EventSourceArn": kinesis, "FunctionArn": FN, "State": "Disabled"}])
    g = t.analyze().graph
    assert K.problems(g) == []
    assert K.only(K.edges(g, "LAYER_GRANTS_PUBLIC", K.ANON, layer_v))["traversal"] == "exposure"
    layer_finding = K.only(K.findings(g, "LAMBDA-LAYER-PUB-001"))
    assert layer_finding["node_id"] == layer_v and layer_finding["severity"] == "MEDIUM"
    assert not K.edges(g, target=private_v)
    assert K.only(K.edges(g, "TRIGGERS", queue, FN))["traversable"] is False
    table = f"arn:aws:dynamodb:{K.REGION}:{K.ACCT}:table/demo-orders"
    assert K.only(K.edges(g, "TRIGGERS", table, FN))["evidence"]["qualifiers"] == ["live"]
    assert K.nodes(g)[FN]["props"]["event_sources_other"] == [kinesis]


@pytest.mark.finding("F-116")
def test_a_layer_shared_with_another_account_gets_a_cross_account_edge(tmp_path):
    """``LAYER_GRANTS_CROSS_ACCOUNT`` from the foreign grantee and one ``LAMBDA-LAYER-XACCT-001`` (D-52)."""
    t, _ = _tree(tmp_path)
    layer_v = f"arn:aws:lambda:{K.REGION}:{K.ACCT}:layer:demo-shared:1"
    org_v = f"arn:aws:lambda:{K.REGION}:{K.ACCT}:layer:demo-shared:2"
    partner = f"arn:aws:iam::{K.FOREIGN}:root"
    t.put("lambda/layers.json", [{"LayerName": "demo-shared", "LayerArn": layer_v[:-2], "Versions": [
        {"Version": 1, "LayerVersionArn": layer_v, "PolicyStatus": "present", "Public": False,
         "Policy": rb.resource_policy(rb.grant({"AWS": K.FOREIGN}, "lambda:GetLayerVersion", layer_v))},
        {"Version": 2, "LayerVersionArn": org_v, "PolicyStatus": "present", "Public": False,
         "Policy": rb.resource_policy(rb.grant({"AWS": partner}, "lambda:GetLayerVersion", org_v,
                                               cond={"StringEquals": {"aws:PrincipalOrgID": "o-a1b2c3d4e5"}}))}]}])
    g = t.analyze().graph
    assert K.problems(g) == []
    edge = K.only(K.edges(g, "LAYER_GRANTS_CROSS_ACCOUNT", partner, layer_v))
    assert edge["traversable"] is True and edge["props"]["cross_account"] is True
    finding = K.only([f for f in K.findings(g, "LAMBDA-LAYER-XACCT-001") if f["node_id"] == layer_v])
    assert finding["severity"] == "LOW" and finding["evidence"]["account"] == K.FOREIGN
    assert finding["confidence"] == "definite"
    gated = K.only(K.edges(g, "LAYER_GRANTS_CROSS_ACCOUNT", partner, org_v))      # behind PrincipalOrgID
    assert gated["confidence"] == "conditional" and gated["weight"] > edge["weight"]
    assert K.only([f for f in K.findings(g, "LAMBDA-LAYER-XACCT-001") if f["node_id"] == org_v])[
        "confidence"] == "conditional"
    assert not K.edges(g, "LAYER_GRANTS_PUBLIC")


# ── loader ───────────────────────────────────────────────────────────────────

@pytest.mark.finding("F-055", "F-114")
def test_loader_keys_policies_by_function_and_qualifier():
    loader = K.engine("io.loaders.lambda_")
    base = loader.normalise_policy({"FunctionArn": FN, "ResourcePolicy": {}}, "a.json")
    alias = loader.normalise_policy({"FunctionArn": FN, "Qualifier": "live", "ResourcePolicy": {}}, "b.json")
    legacy_qualified = loader.normalise_policy({"FunctionArn": FN + ":7", "ResourcePolicy": {}}, "c.json")
    latest = loader.normalise_policy({"FunctionArn": FN + ":$LATEST", "ResourcePolicy": {}}, "d.json")
    assert (base["FunctionArn"], base["Qualifier"]) == (FN, None)
    assert (alias["FunctionArn"], alias["Qualifier"], alias["QualifiedArn"]) == (FN, "live", FN + ":live")
    assert (legacy_qualified["FunctionArn"], legacy_qualified["Qualifier"]) == (FN, "7")
    assert latest["Qualifier"] is None
    assert loader.normalise_policy({"FunctionArn": "demo-fn"}, "e.json") is None
