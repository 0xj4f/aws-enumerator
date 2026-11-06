"""Self-tests for the offline guard in tests/conftest.py.

Path-blocking tests only ever target NON-EXISTENT children of the protected paths,
so even a broken guard could not read the owner's data (it would hit
FileNotFoundError instead of the expected violation and fail).
"""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

import pytest

from tests.support import targets

REPO = Path(targets.REPO_ROOT)
MISSING = "__aws_enumerator_guard_selftest_nonexistent__"


def test_fake_aws_environment(offline_guard):
    for key, value in offline_guard.fake_env.items():
        assert os.environ.get(key) == value, key
    for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE",
                "AWS_RETRY_MODE", "AWS_MAX_ATTEMPTS"):
        assert key not in os.environ, key
    assert os.environ["AWS_CONFIG_FILE"] == "/dev/null"
    assert os.environ["KUBECONFIG"] == "/dev/null"
    home = os.environ["HOME"]
    assert "aws-enumerator-test-home-" in home and os.path.isdir(home)
    assert os.path.expanduser("~/.aws") == os.path.join(home, ".aws")


def test_env_changes_leak_step_1_sets_retry_vars():
    os.environ["AWS_RETRY_MODE"] = "adaptive"   # what app.main.main() does via setdefault
    os.environ["AWS_MAX_ATTEMPTS"] = "10"
    os.environ["AWS_PROFILE"] = "demo-should-not-survive"


def test_env_changes_leak_step_2_sees_them_restored():
    assert "AWS_RETRY_MODE" not in os.environ
    assert "AWS_MAX_ATTEMPTS" not in os.environ
    assert "AWS_PROFILE" not in os.environ


def test_external_connect_blocked(offline_guard):
    with offline_guard.expect_violation():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect(("192.0.2.1", 443))  # TEST-NET-1


def test_connect_ex_and_create_connection_blocked(offline_guard):
    with offline_guard.expect_violation():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect_ex(("198.51.100.1", 80))
    with offline_guard.expect_violation():
        socket.create_connection(("example.com", 443), timeout=0.5)


def test_dns_lookups_blocked(offline_guard):
    with offline_guard.expect_violation():
        socket.getaddrinfo("sts.amazonaws.com", 443)
    with offline_guard.expect_violation():
        socket.gethostbyname("example.com")


def test_loopback_blocked_without_marker(offline_guard):
    with offline_guard.expect_violation():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("127.0.0.1", 9))


@pytest.mark.allow_loopback
def test_loopback_allowed_with_marker(offline_guard):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
            conn, _ = server.accept()
            client.sendall(b"ping")
            assert conn.recv(4) == b"ping"
            conn.close()
    with offline_guard.expect_violation():  # still only loopback
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(("192.0.2.1", 443))


def test_boto3_call_cannot_reach_network(offline_guard):
    import boto3
    client = boto3.client("sts", region_name="us-east-1")
    with offline_guard.expect_violation():
        client.get_caller_identity()


@pytest.mark.parametrize("rel", ["reports", f"reports/{MISSING}/x.json", "tmp", "enum.sh", ".claude",
                                 f".claude/{MISSING}", "docs/features.md"])
def test_protected_paths_detected(offline_guard, rel):
    assert offline_guard.is_protected(REPO / rel)


@pytest.mark.parametrize("rel", ["docs/attack_paths.md", "reports_other", "tmp2", "enum.sh.bak", "tests/fixtures",
                                 "app/main.py"])
def test_unprotected_paths_not_detected(offline_guard, rel):
    assert not offline_guard.is_protected(REPO / rel)


@pytest.mark.skipif(sys.platform != "darwin", reason="APFS is case-insensitive")
def test_protected_paths_case_insensitive_on_macos(offline_guard):
    assert offline_guard.is_protected(REPO / "REPORTS" / MISSING)
    assert offline_guard.is_protected(REPO / "Enum.SH")


def test_open_under_reports_blocked(offline_guard):
    with offline_guard.expect_violation():
        open(REPO / "reports" / MISSING / "x.json", encoding="utf-8")


def test_relative_open_under_reports_blocked(offline_guard, monkeypatch):
    monkeypatch.chdir(REPO)
    with offline_guard.expect_violation():
        open(os.path.join("reports", MISSING, "x.json"), "rb")


def test_listdir_and_scandir_under_protected_blocked(offline_guard):
    with offline_guard.expect_violation():
        os.listdir(REPO / "reports" / MISSING)
    with offline_guard.expect_violation():
        os.scandir(REPO / ".claude" / MISSING)


def test_write_under_tmp_file_blocked(offline_guard):
    with offline_guard.expect_violation():
        os.mkdir(REPO / "tmp" / MISSING)


def test_violation_is_not_an_exception_subclass(offline_guard):
    """Product code's `except Exception` must not be able to swallow a guard violation."""
    assert not issubclass(offline_guard.Violation, Exception)
