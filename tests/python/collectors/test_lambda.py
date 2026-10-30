"""Lambda collector (collectors-cli.md §5.8): URLs and policies on aliases, layers, ESMs, fan-out and rate limit."""

from __future__ import annotations

import importlib
import re

import pytest

from tests.fixtures.worlds import acme
from tests.support import targets
from tests.support.fakeaws import FakeAWS

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

W2, ACCT, EXT = KIT.W2, KIT.ACCT, KIT.EXT
FN = f"arn:aws:lambda:{W2}:{ACCT}:function:"
LAYERED, INTERNAL, PROCESSOR = f"{FN}demo-layered", f"{FN}demo-internal", f"{FN}demo-processor"
LIVE_URL = "https://demointernallive.lambda-url.eu-west-2.on.aws/"


def policies(r):
    return {(d["FunctionArn"], d["Qualifier"]): d
            for d in (KIT.S.load_json(p) for p in KIT.S.files_under(r.out / "resource_policies"))}


@pytest.mark.finding("F-055", "F-059")
def test_alias_urls_and_alias_policies_are_collected(tmp_path):
    r = KIT.run("lambda", tmp_path)
    KIT.assert_contract(r, statuses=("partial",))            # acme denies ListFunctionUrlConfigs on demo-layered
    fns = KIT.by(r.load("functions.json"), "FunctionArn")
    assert list(fns) == sorted(fns) == [INTERNAL, LAYERED, PROCESSOR]
    internal = fns[INTERNAL]
    assert internal["FunctionUrl"] is None                   # no URL on the unqualified function
    assert internal["FunctionUrls"] == [{"Qualifier": "live", "FunctionUrl": LIVE_URL, "AuthType": "NONE",
                                         "InvokeMode": "BUFFERED", "CorsAllowOrigins": []}]
    assert internal["Aliases"] == [{"Name": "live", "AliasArn": f"{INTERNAL}:live", "FunctionVersion": "1",
                                    "PolicyStatus": "present"}]
    assert internal["PolicyStatus"] == "absent"
    processor = fns[PROCESSOR]
    assert processor["FunctionUrl"] == {"Url": "https://demoprocessor0001.lambda-url.eu-west-2.on.aws/",
                                        "AuthType": "NONE"}    # backward-compatible unqualified URL
    assert processor["Aliases"][0]["Name"] == "stable" and processor["Aliases"][0]["PolicyStatus"] == "absent"
    layered = fns[LAYERED]
    assert layered["FunctionUrls"] is None and layered["FunctionUrl"] is None
    assert KIT.collection_errors(layered) == [("lambda:ListFunctionUrlConfigs", "denied")]
    pols = policies(r)
    assert set(pols) == {(INTERNAL, "live"), (LAYERED, None), (PROCESSOR, None)}
    live = pols[(INTERNAL, "live")]
    assert live["QualifiedArn"] == f"{INTERNAL}:live" and live["FunctionName"] == "demo-internal"
    assert live["ResourcePolicy"]["Statement"][0]["Principal"] == "*"


@pytest.mark.finding("F-114")
def test_policy_file_names_are_hashed_and_qualifier_aware(tmp_path):
    r = KIT.run("lambda", tmp_path)
    names = sorted(p.name for p in KIT.S.files_under(r.out / "resource_policies"))
    assert all(re.fullmatch(r"[a-z0-9._-]{1,48}-[0-9a-f]{12}\.json", n) for n in names), names
    assert any(n.startswith("demo-internal_live-") for n in names), names


@pytest.mark.finding("F-112")
def test_environment_values_are_never_written(tmp_path):
    r = KIT.run("lambda", tmp_path)
    KIT.assert_no_canaries(r, "lambda_env")
    fn = KIT.by(r.load("functions.json"), "FunctionArn")[PROCESSOR]
    assert fn["EnvironmentVariableNames"] == ["DB_PASSWORD", "LOG_LEVEL"]
    assert "Environment" not in fn


@pytest.mark.finding("F-147", "F-055")
def test_fan_out_is_three_calls_per_function_plus_one_per_alias(tmp_path):
    r = KIT.run("lambda", tmp_path, KIT.clean_world("lambda"))
    calls = r.fake.calls_for(service="lambda")
    per_op = {}
    for c in calls:
        per_op[c.operation] = per_op.get(c.operation, 0) + 1
    assert per_op["ListFunctionUrlConfigs"] == 3 and "GetFunctionUrlConfig" not in per_op
    assert per_op["GetPolicy"] == 3 + 2                     # 3 functions + aliases live and stable
    assert per_op["ListAliases"] == 3                        # one page each (acme pages aliases one by one)
    assert not {"GetFunction", "GetFunctionConfiguration", "ListVersionsByFunction", "Invoke"} & set(per_op)
    qualifiers = sorted(c.params.get("Qualifier") or "" for c in calls if c.operation == "GetPolicy")
    assert qualifiers == ["", "", "", "live", "stable"]


@pytest.mark.finding("F-147")
def test_calls_go_through_the_run_rate_limiter(tmp_path):
    """Every Lambda call draws a token from the run's per-(service, region) bucket: <= 3 rps (fake clock)."""
    ratelimit = targets.runtime_module("ratelimit")
    now = [0.0]

    def sleep(seconds):
        now[0] += max(seconds, 1e-6)       # like a real sleep, the clock always moves forward

    limiter = ratelimit.RateLimiter(ratelimit.RateLimitConfig(), clock=lambda: now[0], sleep=sleep)
    fake = FakeAWS(KIT.clean_world("lambda"), strict=True)
    factory = fake.session_factory

    def limited_factory(**kwargs):
        make = factory(**kwargs)

        def session(region):
            sess = make(region)
            limiter.install(sess.events)          # what the runner does for every session of a run
            return sess
        return session

    fake.session_factory = limited_factory
    r = KIT.run("lambda", tmp_path, fake=fake)
    n = len(r.fake.calls_for(service="lambda"))
    rate, burst = ratelimit.DEFAULT_RATES["lambda"]
    assert n > burst and now[0] >= (n - burst) / rate - 1e-6, (n, now[0])
    assert limiter.stats()[f"lambda@{W2}"]["waited_seconds"] > 0


@pytest.mark.finding("F-055")
def test_lambda_versions_option_adds_version_policies(tmp_path):
    r = KIT.run("lambda", tmp_path, KIT.clean_world("lambda"), options={"lambda_versions": True})
    KIT.assert_contract(r, statuses=("partial",))            # demo-layered's URL listing is always denied
    fns = KIT.by(r.load("functions.json"), "FunctionArn")
    assert fns[PROCESSOR]["Versions"] == [{"Version": "1", "PolicyStatus": "absent"},
                                          {"Version": "2", "PolicyStatus": "absent"}]
    assert "Versions" not in KIT.by(KIT.run("lambda", tmp_path / "off").load("functions.json"),
                                    "FunctionArn")[PROCESSOR]


def test_a_denied_version_listing_is_optional(tmp_path):
    w = KIT.clean_world("lambda")
    w.deny("lambda", "ListVersionsByFunction")
    r = KIT.run("lambda", tmp_path, w, options={"lambda_versions": True})
    doc = KIT.assert_contract(r, statuses=("partial",))
    assert doc["status_reason"] == "lambda:ListFunctionUrlConfigs denied"   # optional: not a reason
    fn = KIT.by(r.load("functions.json"), "FunctionArn")[PROCESSOR]
    assert fn["Versions"] is None
    assert KIT.collection_errors(fn) == [("lambda:ListVersionsByFunction", "denied")]


@pytest.mark.finding("F-116")
def test_layers_and_their_public_policies(tmp_path):
    r = KIT.run("lambda", tmp_path)
    layers = r.load("layers.json")
    assert [lyr["LayerName"] for lyr in layers] == ["demo-deps"]
    versions = layers[0]["Versions"]
    assert [v["Version"] for v in versions] == [3, 2]
    assert versions[0]["Public"] is True and versions[0]["PolicyStatus"] == "present"
    assert versions[1]["Public"] is False and versions[1]["PolicyStatus"] == "absent"
    assert versions[1]["Policy"] is None


@pytest.mark.finding("F-116")
def test_event_source_mappings(tmp_path):
    r = KIT.run("lambda", tmp_path)
    assert r.load("event_source_mappings.json") == [{
        "UUID": "dec0dec0-0000-4000-8000-0000000000e5", "EventSourceArn": f"arn:aws:sqs:{W2}:{ACCT}:demo-queue",
        "FunctionArn": PROCESSOR, "State": "Enabled", "BatchSize": 10, "LastModified": "2024-01-09T10:00:00Z"}]


@pytest.mark.finding("F-059", "F-102")
def test_a_denied_function_policy_keeps_the_function(tmp_path):
    w = KIT.clean_world("lambda")
    w.deny("lambda", "GetPolicy", {"FunctionName": PROCESSOR})
    r = KIT.run("lambda", tmp_path, w)
    KIT.assert_contract(r, statuses=("partial",))
    fn = KIT.by(r.load("functions.json"), "FunctionArn")[PROCESSOR]
    assert fn["PolicyStatus"] == "denied" and fn["Aliases"][0]["PolicyStatus"] == "denied"   # alias "stable" too
    assert KIT.collection_errors(fn) == [("lambda:GetPolicy", "denied")] * 2
    assert fn["FunctionUrl"]["AuthType"] == "NONE"          # the rest of the item is still collected
    assert (PROCESSOR, None) not in policies(r) and (LAYERED, None) in policies(r)


@pytest.mark.finding("F-103", "F-061")
def test_function_listing_denied_still_collects_layers(tmp_path):
    w = KIT.world()
    w.deny("lambda", "ListFunctions")
    r = KIT.run("lambda", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("functions.json") == [] and r.load("layers.json")


def test_alias_qualifier_parsing():
    mod = targets.collector_module("lambda_")
    assert mod.qualifier_of(PROCESSOR, f"{PROCESSOR}:live") == "live"
    assert mod.qualifier_of(PROCESSOR, PROCESSOR) is None
    assert mod.qualifier_of(PROCESSOR, f"{PROCESSOR}:$LATEST") is None
    assert mod.qualifier_of(PROCESSOR, f"{INTERNAL}:live") is None
    assert mod.grants_public({"Statement": [{"Effect": "Allow", "Principal": {"AWS": ["*"]}}]}) is True
    assert mod.grants_public({"Statement": {"Effect": "Allow", "Principal": "*",
                                            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-x"}}}}) is False
    assert mod.grants_public(None) is None


def test_empty_region_is_ok(tmp_path):
    r = KIT.run("lambda", tmp_path, region=KIT.EMPTY_REGION)
    KIT.assert_contract(r)
    assert r.load("functions.json") == [] and r.load("layers.json") == []


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    assert KIT.assert_each_api_denied_is_survivable("lambda", tmp_path, base=lambda: KIT.clean_world("lambda"),
                                                    options={"lambda_versions": True}) == [
        "lambda:GetLayerVersionPolicy", "lambda:GetPolicy", "lambda:ListAliases", "lambda:ListEventSourceMappings",
        "lambda:ListFunctionUrlConfigs", "lambda:ListFunctions", "lambda:ListLayerVersions", "lambda:ListLayers",
        "lambda:ListVersionsByFunction"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    r = KIT.run("lambda", tmp_path, options={"lambda_versions": True})
    KIT.assert_declared_and_read_only(r)
    spec = KIT.spec("lambda")
    assert spec.tier == 2 and "lambda:ListVersionsByFunction" in spec.optional_actions
    assert acme.CANARIES["lambda_env"] not in str(KIT.S.files_under(r.out))
