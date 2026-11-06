"""Former characterisation of the d13c215 orchestration (``app.main``), flipped by stream R in Wave 1.

Until Wave 1 this file pinned the baseline's buggy behaviour against the acme world (request regressions-py-3:
characterisations are deliberately untagged). The R stream's CLI/runner rewrite fixed what they pinned, so, as
the file's own rule required, each assertion was flipped or deleted in the same change:

* exit 0 when modules crash, the directory-listing manifest without status (F-061, F-103, F-168, F-122):
  deleted; the fixed behaviour is asserted in ``test_collect_run.py`` (exit 2 / 1, per-module status, digests)
  and ``tests/python/regressions/test_r.py`` (F-061);
* analysis on ``global/`` before any region existed (F-010): deleted; ``test_collect_run.py::
  test_analysis_runs_once_after_every_unit_at_the_run_root`` and ``test_r.py`` (F-010);
* region discovery crashing without a manifest, and pinned to us-east-1 (F-064, F-119): deleted;
  ``test_collect_run.py::test_all_uses_describe_regions_in_the_home_region``, ``test_aws_session.py`` and
  ``test_r.py`` (F-064);
* the WAF CLOUDFRONT session rebuild (F-060): flipped below. One credential set serves the whole run
  (``aws_session.AwsContext``) and the global ``waf_cloudfront`` module uses ``ctx.client`` (stream C-A), so
  env-only credentials work and no call ever signs as an unrelated ``[default]`` profile;
* single-region analysis once after every collector: kept, in the v2 layout.
"""

from __future__ import annotations

from typing import Dict, List

import pytest

from tests.fixtures.worlds import acme
from tests.python.collectors.legacy_harness import (
    DEFAULT_PROFILE_ACCESS_KEY_ID,
    ENV_ACCESS_KEY_ID,
    PROFILE_ACCESS_KEY_ID,
    LegacyRun,
)
from tests.python.orchestration import r_harness as R

SINGLE = ["--region", acme.SINGLE_REGION]


def _signed_calls(run: LegacyRun) -> List:
    """Calls that reached signing (client-side ParamValidationError happens before: F-047)."""
    calls = run.fake.calls_for()
    unsigned = [c for c in calls if c.access_key_id is None]
    assert {c.outcome for c in unsigned} <= {"ParamValidationError"}, unsigned
    return [c for c in calls if c.access_key_id is not None]


def test_single_region_runs_analysis_once_after_all_collectors(tmp_path, monkeypatch):
    """The legacy ``--region`` invocation (translated to ``collect``) analyses once, after every module."""
    calls = R.fake_engine(monkeypatch)
    run = R.collect(SINGLE, tmp_path, monkeypatch)
    assert len(calls) == 1 and "deprecated" in run.err
    root = run.run_root
    module_dirs = {m["dir"] for m in run.manifest()["modules"] if m["dir"]}
    listed = {f"{unit}/{name}" for unit, names in calls[0].unit_dirs.items() for name in names}
    assert module_dirs <= listed                         # every module directory existed when analysis ran
    assert (root / "analysis").is_dir()


@pytest.mark.finding("F-060")
@pytest.mark.parametrize("mode", [SINGLE, ["--all"]])
def test_waf_cloudfront_works_with_env_only_credentials(tmp_path, monkeypatch, mode):
    """Flipped from ``..._rebuild_crashes_with_env_only_credentials_{single_region,all_mode}``."""
    R.fake_engine(monkeypatch)
    run = R.collect(mode, tmp_path, monkeypatch, credentials="env")
    entries = R.modules_by_unit(run.manifest())
    assert entries[("waf_cloudfront", "global")]["status"] in ("ok", "partial"), entries[("waf_cloudfront", "global")]
    assert (run.run_root / "global" / "waf_cloudfront" / "web_acls.json").is_file()
    cloudfront_scope = run.fake.calls_for(service="wafv2", region=acme.GLOBAL_REGION)
    assert cloudfront_scope and {c.access_key_id for c in cloudfront_scope} == {ENV_ACCESS_KEY_ID}
    for region in run.manifest()["target"]["regions"]:
        assert (run.run_root / region / "waf" / "web_acls.json").is_file()


@pytest.mark.finding("F-060")
def test_no_call_signs_as_an_unrelated_default_profile(tmp_path, monkeypatch):
    """Flipped from ``test_waf_cloudfront_scope_silently_uses_the_default_profile_identity``."""
    R.fake_engine(monkeypatch)
    run = R.collect(SINGLE, tmp_path, monkeypatch, credentials="env+default-profile")
    keys_by_region: Dict[str, set] = {}
    for c in _signed_calls(run):
        keys_by_region.setdefault(f"{c.service}@{c.region}", set()).add(c.access_key_id)
    assert keys_by_region.get(f"wafv2@{acme.GLOBAL_REGION}") == {ENV_ACCESS_KEY_ID}
    assert set().union(*keys_by_region.values()) == {ENV_ACCESS_KEY_ID}
    assert DEFAULT_PROFILE_ACCESS_KEY_ID not in {c.access_key_id for c in run.fake.calls_for()}


@pytest.mark.finding("F-060")
def test_a_named_profile_signs_every_call(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    run = R.collect(SINGLE, tmp_path, monkeypatch, credentials="profile")
    assert {c.access_key_id for c in _signed_calls(run)} == {PROFILE_ACCESS_KEY_ID}
    assert run.fake.calls_for(service="wafv2", region=acme.GLOBAL_REGION)
