"""Unit tests for scripts/finding_coverage.py (pytest JSON + node TAP merge)."""

from __future__ import annotations

import importlib.util
import json
import sys

import pytest

from tests.support import targets

SCRIPT = targets.REPO_ROOT / "scripts" / "finding_coverage.py"

TAP = """TAP version 13
# Subtest: [F-007] directed paths
ok 1 - [F-007] directed paths
  ---
  duration_ms: 0.5
  ...
ok 2 - [F-040] [xfail] weight zero is honoured
not ok 3 - [F-041, F-008] no innerHTML
ok 4 - skipped thing [F-042] # SKIP not today
not ok 5 - todo [F-043] # TODO later
# Subtest: suite
    ok 1 - [F-096] nested
    1..1
ok 6 - suite
ok 7 - untagged
1..7
"""


@pytest.fixture(scope="module")
def cov():
    spec = importlib.util.spec_from_file_location("finding_coverage_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(spec.name, None)


def test_parse_tap(cov):
    got = {name: (outcome, ids) for name, outcome, ids in cov.parse_tap(TAP)}
    assert got == {
        "js::[F-007] directed paths": ("passed", ["F-007"]),
        "js::[F-040] [xfail] weight zero is honoured": ("xfailed", ["F-040"]),
        "js::[F-041, F-008] no innerHTML": ("failed", ["F-008", "F-041"]),
        "js::skipped thing [F-042]": ("skipped", ["F-042"]),
        "js::todo [F-043]": ("xfailed", ["F-043"]),
        "js::[F-096] nested": ("passed", ["F-096"]),
    }


def _write(tmp_path, ids, tests):
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps([{"id": i} for i in ids]), encoding="utf-8")
    report = tmp_path / "pytest.json"
    report.write_text(json.dumps({"schema": "finding-report/1", "tests": tests}), encoding="utf-8")
    tap = tmp_path / "js.tap"
    tap.write_text(TAP, encoding="utf-8")
    return str(findings), str(report), str(tap)


def test_require_all_passes_when_every_in_scope_finding_has_a_pass(cov, tmp_path, capsys):
    findings, report, tap = _write(tmp_path, ["F-001", "F-007", "F-096", "F-130"], {
        "tests/x.py::test_a": {"outcome": "passed", "findings": ["F-001"]},
        "tests/x.py::test_b": {"outcome": "xfailed", "findings": ["F-007"]},
    })
    out_json = tmp_path / "cov.json"
    rc = cov.main(["--findings", findings, "--pytest-report", report, "--tap", tap, "--require-all",
                   "--json", str(out_json)])
    out = capsys.readouterr().out
    # F-008/F-040.. are tagged in TAP but not in this small register -> unknown -> --require-all fails
    assert rc == 1
    assert "tagged IDs not in the register" in out
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["uncovered"] == []
    assert "F-130" in data["deferred"]


def test_require_all_fails_on_uncovered(cov, tmp_path, capsys):
    ids = ["F-001", "F-002", "F-007", "F-008", "F-040", "F-041", "F-042", "F-043", "F-096", "F-157"]
    findings, report, tap = _write(tmp_path, ids, {
        "tests/x.py::test_a": {"outcome": "passed", "findings": ["F-001"]},
        "tests/x.py::test_c": {"outcome": "xfailed", "findings": ["F-002"]},
    })
    assert cov.main(["--findings", findings, "--pytest-report", report, "--tap", tap]) == 0
    capsys.readouterr()
    assert cov.main(["--findings", findings, "--pytest-report", report, "--tap", tap, "--require-all"]) == 1
    out = capsys.readouterr().out
    lines = {line.split()[0]: line for line in out.splitlines() if line.startswith("F-")}
    assert lines["F-001"].endswith("covered")
    assert lines["F-002"].endswith("xfail-only")
    assert lines["F-008"].endswith("UNCOVERED")      # its only test failed
    assert lines["F-157"].endswith("deferred")
    assert "findings with failing/xpassed tests: F-008, F-041" in out


def test_missing_register_falls_back_to_172_ids(cov, tmp_path):
    ids, source = cov.load_finding_ids(tmp_path / "missing.json")
    assert len(ids) == 172 and ids[0] == "F-001" and ids[-1] == "F-172"
    assert source.startswith("fallback")


def test_unreadable_input_is_usage_error(cov, tmp_path):
    assert cov.main(["--pytest-report", str(tmp_path / "nope.json")]) == 2
