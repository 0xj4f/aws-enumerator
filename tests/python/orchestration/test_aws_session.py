"""The run's AWS layer (cli.md §3.1): identity and partition, regions, retries, user agent, one credential set.

Offline: clients are created but never sent (a ``before-send`` hook captures the request and stops it).
"""

from __future__ import annotations

import os
import threading

import botocore.exceptions
import pytest

from tests.support import targets

S = targets.aws_session_module()
VERSION = targets.runtime_module("_version").__version__


class _Captured(Exception):
    pass


def _env_credentials(monkeypatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLEUNITTEST01")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "example-unit-test-secret-not-real-000000000")
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)


def _context(monkeypatch, **options):
    _env_credentials(monkeypatch)
    return S.AwsContext(S.AwsOptions(**options))


def _profile_config(tmp_path, monkeypatch, body: str) -> None:
    """A config file plus credentials for profile ``demo`` (an explicit profile ignores AWS_* keys)."""
    config, creds = tmp_path / "config", tmp_path / "credentials"
    config.write_text(body, encoding="utf-8")
    creds.write_text("[demo]\naws_access_key_id = AKIAEXAMPLEPROFILE99\n"
                     "aws_secret_access_key = example-profile-secret-not-real-0000000\n", encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds))


def _user_agent(client) -> str:
    seen = {}

    def capture(request, **_kwargs):
        seen["ua"] = request.headers["User-Agent"].decode() if isinstance(request.headers["User-Agent"], bytes) \
            else request.headers["User-Agent"]
        raise _Captured()

    client.meta.events.register("before-send", capture)
    with pytest.raises(_Captured):
        client.get_caller_identity()
    return seen["ua"]


# ── identity and partition (F-119) ───────────────────────────────────────────
@pytest.mark.finding("F-119")
@pytest.mark.parametrize("arn, principal, ptype, partition", [
    ("arn:aws:sts::111122223333:assumed-role/demo-role/demo-session",
     "arn:aws:iam::111122223333:role/demo-role", "assumed-role", "aws"),
    ("arn:aws-us-gov:sts::111122223333:assumed-role/demo-role/s",
     "arn:aws-us-gov:iam::111122223333:role/demo-role", "assumed-role", "aws-us-gov"),
    ("arn:aws-cn:sts::111122223333:assumed-role/demo-role/s",
     "arn:aws-cn:iam::111122223333:role/demo-role", "assumed-role", "aws-cn"),
    ("arn:aws:iam::111122223333:user/demo-user", "arn:aws:iam::111122223333:user/demo-user", "user", "aws"),
    ("arn:aws:iam::111122223333:root", "arn:aws:iam::111122223333:root", "root", "aws"),
    ("arn:aws:sts::111122223333:federated-user/demo", "arn:aws:sts::111122223333:federated-user/demo",
     "federated-user", "aws"),
])
def test_principal_and_partition_come_from_the_caller_arn(arn, principal, ptype, partition):
    assert S.principal_from_sts_arn(arn) == (principal, ptype)
    assert S.partition_from_arn(arn) == partition


@pytest.mark.finding("F-119")
@pytest.mark.parametrize("partition, global_region", [
    ("aws", "us-east-1"), ("aws-us-gov", "us-gov-west-1"), ("aws-cn", "cn-north-1"),
])
def test_global_region_follows_the_partition(partition, global_region):
    ident = S.Identity.from_sts({"Account": "111122223333", "UserId": "AIDAEXAMPLE",
                                 "Arn": f"arn:{partition}:iam::111122223333:user/demo-user"})
    assert (ident.partition, ident.global_region) == (partition, global_region)


def test_operator_block_redaction_drops_the_caller():
    ident = S.Identity.from_sts({"Account": "111122223333", "UserId": "AROAEXAMPLE:demo-session",
                                 "Arn": "arn:aws:sts::111122223333:assumed-role/demo-role/demo-session"})
    plain, redacted = ident.operator_block(redact=False), ident.operator_block(redact=True)
    assert plain["caller_arn"].endswith("/demo-session") and plain["redacted"] is False
    assert (redacted["caller_arn"], redacted["caller_user_id"], redacted["redacted"]) == (None, None, True)
    assert redacted["caller_arn_sha256"] == plain["caller_arn_sha256"] and len(plain["caller_arn_sha256"]) == 64
    assert redacted["principal_arn"] == "arn:aws:iam::111122223333:role/demo-role"


def test_sts_without_an_account_id_is_a_setup_error():
    with pytest.raises(S.AwsSetupError):
        S.Identity.from_sts({"Arn": "arn:aws:iam::111122223333:user/x", "Account": "not-an-account"})


@pytest.mark.finding("F-119")
@pytest.mark.parametrize("region, host", [
    ("us-gov-west-1", "sts.us-gov-west-1.amazonaws.com"), ("cn-north-1", "sts.cn-north-1.amazonaws.com.cn"),
    ("eu-west-2", "sts.eu-west-2.amazonaws.com"),
])
def test_sts_uses_the_regional_endpoint_of_the_home_region(monkeypatch, region, host):
    aws = _context(monkeypatch)
    assert aws.client("sts", region).meta.endpoint_url == f"https://{host}"


@pytest.mark.finding("F-119")
def test_regions_from_another_partition_are_a_usage_error(monkeypatch):
    aws = _context(monkeypatch)
    ident = S.Identity.from_sts({"Account": "111122223333", "UserId": "AIDA",
                                 "Arn": "arn:aws:iam::111122223333:user/demo-user"})
    with pytest.raises(S.RegionUsageError, match="partition aws-cn"):
        S.plan_regions(aws, ident, home_region="eu-west-2", region=None, regions=["cn-north-1"],
                       all_regions=False, exclude=[])


# ── home region (F-124) ──────────────────────────────────────────────────────
@pytest.mark.finding("F-124")
def test_home_region_comes_from_the_environment_then_the_profile(tmp_path, monkeypatch):
    _profile_config(tmp_path, monkeypatch, "[profile demo]\nregion = eu-west-1\n")
    monkeypatch.setenv("AWS_PROFILE", "demo")
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    aws = _context(monkeypatch, profile="demo")
    assert S.home_region_from_env(aws) == "eu-west-1"
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-2")
    assert S.home_region_from_env(aws) == "eu-west-2"
    monkeypatch.setenv("AWS_REGION", "eu-north-1")
    assert S.home_region_from_env(aws) == "eu-north-1"


@pytest.mark.parametrize("bad", ["", "EU-WEST-1", "eu_west_1", "eu-west", "../eu-west-1"])
def test_region_names_are_validated(bad):
    with pytest.raises(S.RegionUsageError):
        S.validate_region(bad, "--region")


# ── regions for --all (F-064, F-140) ─────────────────────────────────────────
def _identity():
    return S.Identity.from_sts({"Account": "111122223333", "UserId": "AIDA",
                                "Arn": "arn:aws:iam::111122223333:user/demo-user"})


@pytest.mark.finding("F-064")
def test_denied_describe_regions_falls_back_to_the_sts_probe(monkeypatch):
    aws = _context(monkeypatch)

    def denied(_aws, _region):
        raise botocore.exceptions.ClientError({"Error": {"Code": "UnauthorizedOperation", "Message": "x"}},
                                              "DescribeRegions")

    probed = {}

    def probe(_aws, candidates):
        probed["candidates"] = list(candidates)
        skipped = [{"region": "af-south-1", "reason": "sts probe failed (InvalidClientTokenId)"}]
        return ["eu-west-1", "eu-west-2"], skipped

    monkeypatch.setattr(S, "describe_enabled_regions", denied)
    monkeypatch.setattr(S, "probe_regions", probe)
    plan = S.plan_regions(aws, _identity(), home_region="eu-west-2", region=None, regions=[], all_regions=True,
                          exclude=["eu-west-1"])
    assert plan.region_source == "fallback:sts-probe"
    assert plan.regions == ["eu-west-2"] and plan.regions_requested == ["all"]
    assert {s["region"] for s in plan.regions_skipped} == {"af-south-1", "eu-west-1"}
    assert {"eu-west-1", "eu-west-2", "us-east-1"} <= set(probed["candidates"])


@pytest.mark.finding("F-064")
def test_expired_credentials_on_describe_regions_are_fatal(monkeypatch):
    aws = _context(monkeypatch)

    def expired(_aws, _region):
        raise botocore.exceptions.ClientError({"Error": {"Code": "ExpiredToken", "Message": "x"}}, "DescribeRegions")

    monkeypatch.setattr(S, "describe_enabled_regions", expired)
    with pytest.raises(S.AwsSetupError):
        S.plan_regions(aws, _identity(), home_region="eu-west-2", region=None, regions=[], all_regions=True,
                       exclude=[])


@pytest.mark.finding("F-140")
def test_offline_region_list_includes_the_shipped_regions_json():
    shipped = S.shipped_regions("aws")
    assert "us-east-1" in shipped and not any(r.startswith(("cn-", "us-gov-")) for r in shipped)
    assert set(shipped) <= set(S.available_regions("aws"))
    assert set(S.available_regions("aws-us-gov")) >= {"us-gov-west-1", "us-gov-east-1"}


def test_explicit_and_profile_region_plans():
    plan = S.plan_regions(None, _identity(), home_region="eu-west-2", region=None, regions=[], all_regions=False,
                          exclude=[])
    assert (plan.regions, plan.region_source, plan.regions_requested) == (["eu-west-2"], "profile", [])


# ── retries (F-125) ──────────────────────────────────────────────────────────
@pytest.mark.finding("F-125")
def test_tool_retry_defaults_apply_only_when_the_user_set_nothing(monkeypatch):
    monkeypatch.delenv("AWS_RETRY_MODE", raising=False)
    monkeypatch.delenv("AWS_MAX_ATTEMPTS", raising=False)
    _env_credentials(monkeypatch)
    before = dict(os.environ)
    aws = S.AwsContext(S.AwsOptions())
    aws.client("sts", "eu-west-2")
    assert aws.client_config.retries == {"mode": "adaptive", "total_max_attempts": 5}
    assert dict(os.environ) == before                          # the tool never writes os.environ


@pytest.mark.finding("F-125")
def test_the_users_environment_retry_settings_win(monkeypatch):
    monkeypatch.setenv("AWS_RETRY_MODE", "standard")
    monkeypatch.setenv("AWS_MAX_ATTEMPTS", "2")
    aws = _context(monkeypatch)
    assert not aws.client_config.retries                       # botocore resolves the user's values
    assert os.environ["AWS_RETRY_MODE"] == "standard"


@pytest.mark.finding("F-125")
def test_the_profiles_retry_settings_win(tmp_path, monkeypatch):
    monkeypatch.delenv("AWS_RETRY_MODE", raising=False)
    monkeypatch.delenv("AWS_MAX_ATTEMPTS", raising=False)
    _profile_config(tmp_path, monkeypatch, "[profile demo]\nretry_mode = standard\nmax_attempts = 3\n")
    aws = _context(monkeypatch, profile="demo")
    assert not aws.client_config.retries


@pytest.mark.finding("F-125")
def test_flags_override_the_users_retry_settings(monkeypatch):
    monkeypatch.setenv("AWS_RETRY_MODE", "standard")
    aws = _context(monkeypatch, retry_mode="legacy", max_attempts=7)
    assert aws.client_config.retries == {"mode": "legacy", "total_max_attempts": 7}


# ── user agent (F-170) ───────────────────────────────────────────────────────
@pytest.mark.finding("F-170")
def test_default_app_id_carries_version_and_run_id_and_reaches_the_request(monkeypatch):
    monkeypatch.delenv("AWS_SDK_UA_APP_ID", raising=False)
    aws = _context(monkeypatch, run_id="20261015T101500Z-a1b2c3")
    assert aws.client_config.user_agent_appid == f"aws-enumerator/{VERSION}/a1b2c3"
    assert f"app/aws-enumerator-{VERSION}-a1b2c3" in _user_agent(aws.client("sts", "eu-west-2"))


@pytest.mark.finding("F-170")
def test_the_users_app_id_is_kept_and_no_ua_tag_sends_none(monkeypatch):
    monkeypatch.setenv("AWS_SDK_UA_APP_ID", "demo-team-scanner")
    aws = _context(monkeypatch, run_id="20261015T101500Z-a1b2c3")
    assert "app/demo-team-scanner" in _user_agent(aws.client("sts", "eu-west-2"))
    forced = _context(monkeypatch, run_id="20261015T101500Z-a1b2c3", ua_app_id="demo-red-team")
    assert "app/demo-red-team" in _user_agent(forced.client("sts", "eu-west-2"))
    monkeypatch.delenv("AWS_SDK_UA_APP_ID", raising=False)
    silent = _context(monkeypatch, run_id="20261015T101500Z-a1b2c3", ua_tag=False)
    assert "app/" not in _user_agent(silent.client("sts", "eu-west-2"))


# ── one credential set for the whole run (F-060 / F-167 groundwork) ──────────
def test_every_session_of_the_run_shares_one_credentials_object(monkeypatch):
    """Every client (one session per region, created on any thread) signs with the run's one Credentials."""
    aws = _context(monkeypatch)
    creds = []

    def grab(region):
        creds.append(aws.client("sts", region)._request_signer._credentials)

    threads = [threading.Thread(target=grab, args=(r,)) for r in ("eu-west-1", "eu-west-2")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    grab("us-east-1")
    assert len({id(c) for c in creds}) == 1


def test_unknown_profile_and_missing_credentials_are_setup_errors(tmp_path, monkeypatch):
    _profile_config(tmp_path, monkeypatch, "[profile demo]\nregion = eu-west-1\n")
    with pytest.raises(S.AwsSetupError, match="not found"):
        S.AwsContext(S.AwsOptions(profile="example-missing"))
    for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    with pytest.raises(S.AwsSetupError, match="no AWS credentials"):
        S.AwsContext(S.AwsOptions())
