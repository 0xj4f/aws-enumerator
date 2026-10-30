"""Unit tests for scripts/scan_sensitive.py. Synthetic inputs only; matches are never printed in full."""

from __future__ import annotations

import importlib.util
import sys

import pytest

from tests.support import targets

SCRIPT = targets.REPO_ROOT / "scripts" / "scan_sensitive.py"


@pytest.fixture(scope="module")
def scan():
    spec = importlib.util.spec_from_file_location("scan_sensitive_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(spec.name, None)


# Built from pieces so this test file itself never contains the literal patterns.
FAKE_ACCOUNT = "4" * 6 + "5" * 6
FAKE_KEY = "AK" + "IA" + "Q" * 16
FAKE_EMAIL = "someone" + "@" + "corp-mail.io"
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"


def kinds(hits):
    return sorted(h.kind for h in hits)


def test_detects_each_kind(scan):
    text = "\n".join([
        f"arn:aws:iam::{FAKE_ACCOUNT}:role/x",
        f"contact {FAKE_EMAIL}",
        f"key = {FAKE_KEY}",
        PEM,
    ])
    hits = scan.scan_text(text, "demo.txt")
    assert kinds(hits) == ["aws-access-key", "aws-account-id", "email", "private-key"]
    assert [h.line for h in hits] == sorted(h.line for h in hits)
    for h in hits:
        assert FAKE_ACCOUNT not in h.preview and FAKE_KEY not in h.preview and FAKE_EMAIL not in h.preview


@pytest.mark.parametrize("line", [
    "arn:aws:iam::123456789012:root", "arn:aws:iam::111122223333:root", "999999999999", "000000000000",
    "uuid 1111aaaa-0000-4000-8000-000000000001",     # last UUID group
    "pi = 3.141592653589793",                        # fraction digits
    "ts 1700000000000",                              # 13 digits
    "hex a1234567890123b",                           # glued to letters
    "mail demo@example.com, ops@sub.example.org, 12345+bot@users.noreply.github.com",
    "doc key AKIAIOSFODNN7EXAMPLE",
    f"suppressed {FAKE_ACCOUNT}  # scan-sensitive: allow",
])
def test_allowed_values_not_reported(scan, line):
    assert scan.scan_text(line, "ok.txt") == []


def test_mask_never_reveals_middle(scan):
    assert scan.mask(FAKE_ACCOUNT) == "44********55"
    assert scan.mask("abc") == "***"


@pytest.mark.parametrize("rel", ["tmp", "enum.sh", "docs/features.md", "reports/x/y.json", ".claude/settings.json",
                                 "internal-docs/README.md", ".venv/lib/x.py", "./tmp", "TMP"])
def test_owner_paths_excluded(scan, rel):
    assert scan.is_excluded(rel)


@pytest.mark.parametrize("rel", ["tests/fixtures/scenarios/x.json", "readme.md", "app/main.py", "tmpdir/x",
                                 "docs/attack_paths.md"])
def test_regular_paths_not_excluded(scan, rel):
    assert not scan.is_excluded(rel)


def test_main_on_explicit_paths(scan, tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(f'{{"Account": "{FAKE_ACCOUNT}"}}\n', encoding="utf-8")
    good = tmp_path / "good.json"
    good.write_text('{"Account": "123456789012"}\n', encoding="utf-8")
    binary = tmp_path / "blob.bin"
    binary.write_bytes(b"\0" + FAKE_ACCOUNT.encode())
    assert scan.main(["--paths", str(good), str(binary)]) == 0
    assert scan.main(["--paths", str(bad), str(good)]) == 1
    out = capsys.readouterr().out
    assert "bad.json:1: aws-account-id:" in out
    assert FAKE_ACCOUNT not in out


def test_known_exception_is_reported_but_not_failing(scan, monkeypatch, capsys):
    monkeypatch.setattr(scan, "scan_files", lambda files, root=None: [
        scan.Hit(".github/workflows/docker-publish.yml", 3, "email", "ab***cd")])
    monkeypatch.setattr(scan, "git_files", lambda root: [".github/workflows/docker-publish.yml"])
    assert scan.main([]) == 0
    assert "known (not failing)" in capsys.readouterr().out
