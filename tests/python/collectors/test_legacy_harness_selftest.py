"""Self-tests for tests/python/collectors/legacy_harness.py (request rename-split-1).

The baseline main() writes AWS_RETRY_MODE / AWS_MAX_ATTEMPTS straight into os.environ (F-125). When it ran from
a module-scoped fixture, the values leaked into every later test module (tests/python/unit/test_offline_guard.py
failed in the full suite). run_legacy_main now registers both keys with the caller's monkeypatch, and
tests/conftest.py restores the guarded environment after every module as well as after every test.
"""

from __future__ import annotations

import os

import pytest

from tests.python.collectors.legacy_harness import MAIN_WRITES_ENV, _register_env_key, run_legacy_main

pytestmark = pytest.mark.collectors


def test_register_env_key_restores_an_unset_key():
    mp = pytest.MonkeyPatch()
    assert "AWS_RETRY_MODE" not in os.environ
    _register_env_key(mp, "AWS_RETRY_MODE")
    os.environ["AWS_RETRY_MODE"] = "adaptive"  # what main() does, outside any monkeypatch
    mp.undo()
    assert "AWS_RETRY_MODE" not in os.environ


def test_register_env_key_restores_a_previous_value(monkeypatch):
    monkeypatch.setenv("AWS_MAX_ATTEMPTS", "3")
    mp = pytest.MonkeyPatch()
    _register_env_key(mp, "AWS_MAX_ATTEMPTS")
    os.environ["AWS_MAX_ATTEMPTS"] = "10"
    mp.undo()
    assert os.environ["AWS_MAX_ATTEMPTS"] == "3"


def test_a_legacy_run_under_its_own_monkeypatch_leaves_no_retry_settings(tmp_path):
    mp = pytest.MonkeyPatch()
    try:
        run_legacy_main(["--region", "eu-west-2"], tmp_path, mp)  # whatever main() writes (F-125) ...
    finally:
        mp.undo()
    assert not any(k in os.environ for k in MAIN_WRITES_ENV)  # ... is gone once the monkeypatch is undone
