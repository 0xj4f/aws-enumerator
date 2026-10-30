"""Collector contract for every C-A module (collector-context.md §8, dashboard-docs-tests.md §C6).

For each of iam, s3, cloudfront, waf_cloudfront, ec2, vpc, sg, flowlogs, cloudtrail, waf, guardduty,
securityhub, config and accessanalyzer, against the strict acme fake:

* happy run: ``collect(ctx)`` protocol, schema-valid ``_coverage.json``, stable shapes, sorted lists;
* empty region / empty account: every declared file is still written with its declared shape;
* every API of the happy run denied in turn: no crash, the denial is recorded, shapes stay stable (F-058);
* a ``BotoCoreError`` in the primary listing: ``partial``/``denied``/``failed`` is never silent, files remain;
* read-only, and every operation maps to a declared IAM action (F-151);
* no acme secret canary in any output file;
* the module docstring names every declared output (F-108);
* two runs give byte-identical data files (deterministic output).
"""

from __future__ import annotations

import importlib
import inspect

import pytest

from tests.support.fakeaws import botocore_error

KIT = importlib.import_module("tests.fixtures.c-a.kit")
WORLDS = importlib.import_module("tests.fixtures.c-a.worlds")
pytestmark = pytest.mark.collectors

MODULES = sorted(KIT.MODULES)

#: The primary listing of each module (the call whose denial makes the module ``denied``).
PRIMARY = {
    "iam": None,  # GAAD has a per-entity fallback; ListRoles is primary only in that fallback
    "s3": ("s3", "ListBuckets"), "cloudfront": ("cloudfront", "ListDistributions"),
    "waf_cloudfront": ("wafv2", "ListWebACLs"), "waf": ("wafv2", "ListWebACLs"),
    "ec2": ("ec2", "DescribeInstances"), "vpc": ("ec2", "DescribeVpcs"), "sg": ("ec2", "DescribeSecurityGroups"),
    "flowlogs": ("ec2", "DescribeFlowLogs"), "cloudtrail": ("cloudtrail", "DescribeTrails"),
    "guardduty": ("guardduty", "ListDetectors"), "securityhub": ("securityhub", "DescribeHub"),
    "config": ("config", "DescribeConfigurationRecorders"), "accessanalyzer": ("accessanalyzer", "ListAnalyzers"),
}


@pytest.fixture(autouse=True)
def _fast_report(monkeypatch):
    KIT.no_report_wait(monkeypatch)


def _base():
    w = WORLDS.base()
    w.errors = []          # acme's injected failures are exercised by the per-module tests
    return w


@pytest.mark.finding("F-053", "F-058", "F-108")
@pytest.mark.parametrize("name", MODULES)
def test_happy_run_is_a_ctx_module_with_stable_sorted_output(name, tmp_path):
    r = KIT.run(name, tmp_path, _base())
    KIT.assert_contract(r, statuses=("ok",))
    for pattern, _kind in KIT.spec(name).outputs:
        if "*" not in pattern:
            assert (r.out / pattern).is_file(), pattern
    assert r.result.protocol == "ctx"
    assert not hasattr(KIT.spec(name), "legacy_kwargs")      # no legacy adapter fields since Wave 3a


@pytest.mark.finding("F-058")
@pytest.mark.parametrize("name", sorted(n for n in MODULES if KIT.spec(n).scope == "regional"))
def test_an_empty_region_writes_every_declared_file(name, tmp_path):
    r = KIT.run(name, tmp_path, _base(), region=KIT.EMPTY_REGION)
    KIT.assert_contract(r, statuses=("ok",))
    for pattern, kind in KIT.spec(name).outputs:
        if "*" not in pattern:
            data = KIT.data_files(r)[pattern]
            assert isinstance(data, list if kind == "list" else dict), (pattern, kind)


@pytest.mark.finding("F-058", "F-053")
@pytest.mark.parametrize("name", MODULES)
def test_each_api_denied_in_turn_is_recorded_and_keeps_shapes(name, tmp_path):
    apis = KIT.assert_each_api_denied_is_survivable(name, tmp_path, base=_base)
    assert apis


@pytest.mark.finding("F-058")
@pytest.mark.parametrize("name", sorted(n for n in MODULES if PRIMARY[n]))
def test_denied_primary_listing_makes_the_module_denied_with_empty_files(name, tmp_path):
    service, operation = PRIMARY[name]
    w = _base()
    w.deny(service, operation)
    r = KIT.run(name, tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert f"{service}:{operation}" in r.result.denied_apis


@pytest.mark.parametrize("name", sorted(n for n in MODULES if PRIMARY[n]))
def test_a_botocore_error_in_the_primary_listing_is_recorded_not_silent(name, tmp_path):
    service, operation = PRIMARY[name]
    w = _base()
    w.raise_exc(service, operation, botocore_error("ReadTimeoutError", endpoint_url="https://example.invalid/"))
    r = KIT.run(name, tmp_path, w)
    doc = KIT.assert_contract(r, statuses=("partial",))
    rows = [row for row in doc["calls"] if row["api"] == f"{service}:{operation}"]
    assert [row["error_code"] for row in rows if row["status"] == "error"] == ["ReadTimeoutError"]
    for pattern, _kind in KIT.spec(name).outputs:
        if "*" not in pattern:
            assert (r.out / pattern).is_file(), pattern


@pytest.mark.finding("F-151")
@pytest.mark.parametrize("name", MODULES)
def test_every_call_is_read_only_and_declared(name, tmp_path):
    spec = KIT.spec(name)
    assert spec.actions, f"{name}: SPEC.actions is empty"
    assert spec.probe is not None
    r = KIT.run(name, tmp_path, KIT.world())
    KIT.assert_declared_and_read_only(r)


@pytest.mark.finding("F-151")
@pytest.mark.parametrize("name", MODULES)
def test_declared_actions_are_well_formed_and_used(name, tmp_path):
    spec = KIT.spec(name)
    for action in spec.actions + spec.optional_actions:
        prefix, _, verb = action.partition(":")
        assert prefix and verb and verb[:1].isupper(), action
    assert not set(spec.actions) & set(spec.optional_actions)
    service, op, _params = spec.probe
    assert KIT.iam_action(service, op) in KIT.declared_actions(name), spec.probe


@pytest.mark.parametrize("name", MODULES)
def test_no_secret_canary_reaches_the_output(name, tmp_path):
    r = KIT.run(name, tmp_path, KIT.world(), options={"ec2_userdata_check": True, "s3_subresources": "full"})
    KIT.assert_no_canaries(r)


@pytest.mark.finding("F-108")
@pytest.mark.parametrize("name", MODULES)
def test_module_docstring_lists_every_output(name):
    doc = inspect.getdoc(KIT.module(name)) or ""
    assert "_coverage.json" in doc
    for pattern, _kind in KIT.spec(name).outputs:
        stem = pattern.split("/", 1)[0] if "/" in pattern else pattern
        assert stem in doc, (name, pattern)


@pytest.mark.parametrize("name", MODULES)
def test_two_runs_write_identical_bytes(name, tmp_path):
    first = KIT.raw_files(KIT.run(name, tmp_path / "a", KIT.world()))
    second = KIT.raw_files(KIT.run(name, tmp_path / "b", KIT.world()))
    assert first == second
