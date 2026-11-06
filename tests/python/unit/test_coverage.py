"""Unit tests for the coverage contract (docs/contracts/coverage-schema.md).

Production code is reached through ``tests.support.targets`` (package name) only.
These tests pin the foundation; the per-finding tests (F-058, F-059, F-102, F-103, F-125 ...)
belong to the streams that migrate each collector onto it.
"""

from __future__ import annotations

import importlib
import json

import botocore.exceptions
import jsonschema
import pytest
from botocore.exceptions import ClientError

from tests.support import targets


def _mod(name: str):
    return importlib.import_module(f"{targets.PACKAGE_NAME}.{name}")


cov_mod = _mod("coverage")
SCHEMA = json.loads((targets.PACKAGE_DIR / "schemas" / "coverage-1.schema.json").read_text())
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


def client_error(code: str, status: int = 400, message: str = "msg") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message},
                        "ResponseMetadata": {"HTTPStatusCode": status}}, "Operation")


# ── classify ─────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("code,status,api,expected", [
    ("AccessDenied", 403, "s3:ListBuckets", ("denied", "AccessDenied", False)),
    ("AccessDeniedException", 400, "lambda:ListFunctions", ("denied", "AccessDeniedException", False)),
    ("UnauthorizedOperation", 403, "ec2:DescribeInstances", ("denied", "UnauthorizedOperation", False)),
    ("AuthorizationError", 403, "sns:ListTopics", ("denied", "AuthorizationError", False)),
    ("AuthorizationErrorException", 403, "sns:ListTopics", ("denied", "AuthorizationErrorException", False)),
    ("Forbidden", 403, "s3:GetBucketAcl", ("denied", "Forbidden", False)),
    ("SomethingNew", 403, "x:Y", ("denied", "SomethingNew", False)),          # any HTTP 403
    ("Throttling", 400, "iam:ListUsers", ("throttled", "Throttling", False)),
    ("ThrottlingException", 400, "kms:ListKeys", ("throttled", "ThrottlingException", False)),
    ("TooManyRequestsException", 429, "apigateway:GetRestApis", ("throttled", "TooManyRequestsException", False)),
    ("RequestLimitExceeded", 503, "ec2:DescribeVpcs", ("throttled", "RequestLimitExceeded", False)),
    ("SlowDown", 503, "s3:ListBuckets", ("throttled", "SlowDown", False)),
    ("PriorRequestNotComplete", 400, "route53:ListHostedZones", ("throttled", "PriorRequestNotComplete", False)),
    ("ProvisionedThroughputExceededException", 400, "dynamodb:ListTables",
     ("throttled", "ProvisionedThroughputExceededException", False)),
    ("WeirdRateThing", 429, "x:Y", ("throttled", "WeirdRateThing", False)),     # any HTTP 429
    ("OptInRequired", 403, "ec2:DescribeVpcs", ("skipped", "OptInRequired", False)),
    ("SubscriptionRequiredException", 400, "x:Y", ("skipped", "SubscriptionRequiredException", False)),
    ("ExpiredToken", 400, "sts:GetCallerIdentity", ("error", "ExpiredToken", True)),
    ("ExpiredTokenException", 400, "lambda:ListFunctions", ("error", "ExpiredTokenException", True)),
    ("InvalidClientTokenId", 403, "iam:ListUsers", ("error", "InvalidClientTokenId", True)),
    ("UnrecognizedClientException", 400, "kms:ListKeys", ("error", "UnrecognizedClientException", True)),
    ("RequestExpired", 400, "ec2:DescribeVpcs", ("error", "RequestExpired", True)),
    ("InvalidToken", 400, "s3:ListBuckets", ("error", "InvalidToken", True)),
    ("InvalidToken", 400, "ssm:DescribeParameters", ("error", "InvalidToken", False)),  # not a credential code there
    ("NoSuchBucketPolicy", 404, "s3:GetBucketPolicy", ("ok", "NoSuchBucketPolicy", False)),
    ("NoSuchBucketPolicy", 404, "s3:GetBucketAcl", ("error", "NoSuchBucketPolicy", False)),  # only for its API
    ("NoSuchEntity", 404, "iam:GetLoginProfile", ("ok", "NoSuchEntity", False)),
    ("NoSuchEntity", 404, "iam:GetRole", ("error", "NoSuchEntity", False)),
    ("AWSOrganizationsNotInUseException", 400, "organizations:ListParents",
     ("ok", "AWSOrganizationsNotInUseException", False)),                       # service wildcard
    ("InternalError", 500, "s3:ListBuckets", ("error", "InternalError", False)),
    ("ValidationException", 400, "x:Y", ("error", "ValidationException", False)),
])
def test_classify_client_errors(code, status, api, expected):
    assert cov_mod.classify(client_error(code, status), api) == expected


@pytest.mark.parametrize("api,codes", sorted(_mod("coverage").NOT_CONFIGURED.items()))
def test_every_not_configured_entry_classifies_as_ok(api, codes):
    concrete = api.replace("*", "AnyOperation")
    for code in codes:
        assert cov_mod.classify(client_error(code, 404), concrete) == ("ok", code, False)
        assert cov_mod.is_not_configured(concrete, code)


def test_classify_extra_not_configured_codes_from_the_spec():
    exc = client_error("ResourceNotFoundException", 404)
    assert cov_mod.classify(exc, "guardduty:GetDetector")[0] == "error"
    extra = {"guardduty:GetDetector": ("ResourceNotFoundException",)}
    assert cov_mod.classify(exc, "guardduty:GetDetector", extra) == ("ok", "ResourceNotFoundException", False)


@pytest.mark.parametrize("exc,expected", [
    (botocore.exceptions.EndpointConnectionError(endpoint_url="https://ec2.eu-west-1.amazonaws.com"),
     ("error", "EndpointConnectionError", False)),
    (botocore.exceptions.ReadTimeoutError(endpoint_url="https://kms.eu-west-2.amazonaws.com"),
     ("error", "ReadTimeoutError", False)),
    (botocore.exceptions.ConnectTimeoutError(endpoint_url="https://x"), ("error", "ConnectTimeoutError", False)),
    (botocore.exceptions.ParamValidationError(report="Unknown parameter in input: \"Name\""),
     ("error", "ParamValidationError", False)),
    (botocore.exceptions.NoCredentialsError(), ("error", "NoCredentialsError", True)),
    (botocore.exceptions.TokenRetrievalError(provider="sso", error_msg="expired"),
     ("error", "TokenRetrievalError", True)),
    (botocore.exceptions.UnknownEndpointError(service_name="x", region_name="y"),
     ("skipped", "UnknownEndpoint", False)),
    (ValueError("boom"), ("error", "ValueError", False)),
    (KeyError("Arn"), ("error", "KeyError", False)),
])
def test_classify_non_client_errors(exc, expected):
    assert cov_mod.classify(exc, "svc:Op") == expected


# ── CallResult ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize("kwargs,policy_status,has_data", [
    ({"status": "ok", "value": {"Policy": "{}"}}, "present", True),
    ({"status": "ok", "value": None, "not_configured": True, "error_code": "NoSuchBucketPolicy"}, "absent", False),
    ({"status": "ok", "value": {}}, "absent", True),
    ({"status": "denied", "error_code": "AccessDenied"}, "denied", False),
    ({"status": "throttled", "error_code": "SlowDown"}, "error", False),
    ({"status": "error", "error_code": "EndpointConnectionError"}, "error", False),
    ({"status": "skipped", "error_code": "CircuitOpen:AccessDenied"}, "skipped", False),
])
def test_call_result_policy_status(kwargs, policy_status, has_data):
    r = cov_mod.CallResult(api="s3:GetBucketPolicy", **kwargs)
    assert r.policy_status() == policy_status
    assert r.has_data is has_data
    if r.status == "ok":
        assert r.collection_error() is None
    else:
        assert r.collection_error() == {"api": "s3:GetBucketPolicy", "status": r.status, "error_code": r.error_code}


def test_call_result_get_is_safe_on_non_mappings():
    assert cov_mod.CallResult(api="a:B", value={"K": 1}).get("K") == 1
    assert cov_mod.CallResult(api="a:B", value=[1]).get("K", "d") == "d"


# ── CircuitBreaker ───────────────────────────────────────────────────────────
def test_deny_breaker_opens_after_n_consecutive_fanout_denials():
    b = cov_mod.CircuitBreaker(deny_threshold=3)
    assert b.record("s3:GetBucketPolicy", "denied", fanout=True) is None
    assert b.record("s3:GetBucketPolicy", "ok", fanout=True) is None          # resets the streak
    assert b.record("s3:GetBucketPolicy", "denied", fanout=True) is None
    assert b.record("s3:GetBucketPolicy", "denied", fanout=True) is None
    assert b.open_reason("s3:GetBucketPolicy") is None
    assert b.record("s3:GetBucketPolicy", "denied", fanout=True) == "CircuitOpen:AccessDenied"
    assert b.open_reason("s3:GetBucketPolicy") == "CircuitOpen:AccessDenied"
    assert b.open_reason("s3:GetBucketAcl") is None                          # per API
    assert b.opened() == [{"api": "s3:GetBucketPolicy", "kind": "deny", "reason": "CircuitOpen:AccessDenied",
                           "opened_after": 3, "skipped": 0}]


def test_deny_breaker_ignores_non_fanout_calls_and_can_be_disabled():
    b = cov_mod.CircuitBreaker(deny_threshold=2)
    for _ in range(5):
        b.record("iam:ListUsers", "denied", fanout=False)
    assert b.open_reason("iam:ListUsers") is None
    off = cov_mod.CircuitBreaker(deny_threshold=0, throttle_threshold=0)
    for _ in range(20):
        off.record("a:B", "denied", fanout=True)
        off.record("a:B", "throttled", fanout=True)
    assert off.opened() == []


def test_throttle_breaker_counts_final_throttles_not_necessarily_consecutive():
    b = cov_mod.CircuitBreaker(throttle_threshold=3)
    assert b.record("lambda:GetPolicy", "throttled", fanout=True) is None
    assert b.record("lambda:GetPolicy", "ok", fanout=True) is None
    assert b.record("lambda:GetPolicy", "throttled", fanout=False) is None
    assert b.record("lambda:GetPolicy", "throttled", fanout=True) == "CircuitOpen:Throttling"


def test_breaker_rejects_negative_thresholds():
    with pytest.raises(ValueError):
        cov_mod.CircuitBreaker(deny_threshold=-1)


# ── Coverage: module status derivation ───────────────────────────────────────
def _cov(**kw):
    return cov_mod.Coverage("demo", "eu-west-2", ("s3",), **kw)


def _res(api="s3:GetBucketPolicy", **kw):
    return cov_mod.CallResult(api=api, **kw)


def test_status_ok_when_everything_succeeds_or_is_not_configured():
    c = _cov()
    c.record(_res("s3:ListBuckets", status="ok", primary=True, items=3, pages=1))
    c.record(_res(status="ok", not_configured=True, error_code="NoSuchBucketPolicy", item="arn:aws:s3:::demo-a"))
    assert c.status == "ok" and c.status_reason is None
    s = c.summary()
    assert (s["calls"], s["ok"], s["not_configured"], s["item_errors"]) == (2, 2, 1, 0)


def test_primary_denied_makes_the_module_denied():
    c = _cov()
    c.record(_res("s3:ListBuckets", status="denied", error_code="AccessDenied", primary=True))
    assert c.status == "denied"
    assert "s3:ListBuckets" in c.status_reason
    assert c.denied_apis() == ["s3:ListBuckets"]


def test_non_optional_failures_make_the_module_partial():
    for status, code in (("denied", "AccessDenied"), ("error", "EndpointConnectionError"), ("throttled", "SlowDown")):
        c = _cov()
        c.record(_res(status=status, error_code=code, item="arn:aws:s3:::demo-a"))
        assert c.status == "partial", status
        assert c.to_json()["item_errors"] == [{"resource": "arn:aws:s3:::demo-a", "api": "s3:GetBucketPolicy",
                                               "status": status, "error_code": code}]


def test_optional_calls_never_degrade_the_status():
    c = _cov()
    c.record(_res("organizations:DescribeOrganization", status="denied", error_code="AccessDenied", optional=True))
    c.record(_res("organizations:ListParents", status="error", error_code="ReadTimeoutError", optional=True))
    assert c.status == "ok"
    assert c.summary()["denied"] == 1


def test_explicit_skip_does_not_degrade_but_a_circuit_skip_does():
    c = _cov()
    c.skip("iam:GetCredentialReport", "flag:--no-credential-report")
    assert c.status == "ok"
    c.record(_res(status="skipped", error_code="CircuitOpen:AccessDenied", item="arn:aws:s3:::demo-z"))
    assert c.status == "partial"


def test_section_error_failed_interrupted_and_forced_statuses():
    c = _cov()
    entry = c.section_started("policies")
    c.section_error(entry, KeyError("Policy"))
    assert c.status == "partial"
    assert c.to_json()["sections"] == [{"name": "policies", "status": "error", "error_type": "KeyError",
                                        "error_code": None, "message": "'Policy'"}]
    c.mark_failed(RuntimeError("boom"))
    assert c.status == "failed"
    c.mark_interrupted()
    assert c.status == "interrupted"
    c.mark_skipped("unavailable in partition aws-us-gov")
    assert (c.status, c.status_reason) == ("skipped", "unavailable in partition aws-us-gov")
    nr = cov_mod.Coverage.not_run("demo", "eu-west-1", "run interrupted before this unit")
    assert nr.status == "not_run"


def test_worst_status_ordering():
    assert cov_mod.worst_status([]) == "ok"
    assert cov_mod.worst_status(["ok", "skipped"]) == "skipped"
    assert cov_mod.worst_status(["ok", "partial", "denied"]) == "denied"
    assert cov_mod.worst_status(["failed", "partial"]) == "failed"
    assert cov_mod.worst_status(["failed", "interrupted"]) == "interrupted"


def test_breaker_integration_records_skips_and_logs_one_warning(caplog):
    c = _cov(deny_breaker=2)
    caplog.set_level("WARNING", logger="aws_enumerator.coverage")
    for i in range(2):
        c.record(_res(status="denied", error_code="AccessDenied", item=f"arn:aws:s3:::demo-{i}"))
    for i in range(2, 5):
        skipped = c.circuit_skip("s3:GetBucketPolicy", item=f"arn:aws:s3:::demo-{i}")
        assert skipped is not None and skipped.error_code == "CircuitOpen:AccessDenied"
    assert c.circuit_skip("s3:GetBucketAcl", item="arn:aws:s3:::demo-0") is None
    doc = c.to_json()
    assert doc["breakers"] == [{"api": "s3:GetBucketPolicy", "kind": "deny", "reason": "CircuitOpen:AccessDenied",
                                "opened_after": 2, "skipped": 3}]
    assert doc["summary"]["skipped"] == 3 and doc["summary"]["item_errors"] == 5
    assert len([r for r in caplog.records if "circuit breaker opened" in r.getMessage()]) == 1


def test_item_errors_are_capped_and_flagged():
    c = _cov(item_errors_cap=3)
    for i in range(5):
        c.item_error(f"arn:aws:kms:eu-west-2:111122223333:key/{i}", "kms:DescribeKey", "denied", "AccessDenied")
    doc = c.to_json()
    assert len(doc["item_errors"]) == 3 and doc["item_errors_truncated"] is True
    assert doc["summary"]["item_errors"] == 5
    with pytest.raises(ValueError):
        c.item_error("x", "kms:DescribeKey", "ok")


def test_aggregated_rows_and_pages():
    c = _cov()
    c.record(_res("s3:ListBuckets", status="ok", primary=True, items=2, pages=1))
    c.record(_res("s3:ListBuckets", status="ok", primary=True, items=3, pages=2))
    rows = c.calls()
    assert rows == [{"api": "s3:ListBuckets", "status": "ok", "count": 2, "items": 5, "pages": 3, "error_code": None,
                     "not_configured": False, "primary": True, "optional": False}]
    with pytest.raises(ValueError):
        c.record(_res(status="weird"))


def test_to_json_is_schema_valid_and_never_carries_aws_error_messages():
    canary = "arn:aws:sts::111122223333:assumed-role/demo-operator/session-CANARY"
    c = _cov().start()
    exc = client_error("AccessDenied", 403, message=f"User: {canary} is not authorized")
    status, code, _ = cov_mod.classify(exc, "s3:ListBuckets")
    c.record(_res("s3:ListBuckets", status=status, error_code=code, primary=True, exception=exc,
                  message=None))
    entry = c.section_started("buckets")
    c.section_error(entry, exc)
    c.mark_failed(exc)
    c.finish()
    doc = c.to_json()
    VALIDATOR.validate(doc)
    assert "CANARY" not in json.dumps(doc)
    assert doc["error"] == {"type": "ClientError", "code": "AccessDenied", "message": None}
    assert doc["started_at"].endswith("Z") and doc["duration_seconds"] >= 0


def test_empty_and_not_run_coverage_documents_are_schema_valid():
    VALIDATOR.validate(_cov().to_json())
    VALIDATOR.validate(cov_mod.Coverage.not_run("k8s", "eu-west-2", "dependency eks failed").to_json())


def test_control_flow_exceptions_are_base_exceptions():
    """Neither may be swallowed by ``except Exception`` in collectors or ctx.section."""
    assert not issubclass(cov_mod.RunInterrupted, Exception)
    assert not issubclass(cov_mod.RunAborted, Exception)
    err = cov_mod.RunAborted("x", api="sts:GetCallerIdentity", code="ExpiredToken")
    assert (err.api, err.code) == ("sts:GetCallerIdentity", "ExpiredToken")
