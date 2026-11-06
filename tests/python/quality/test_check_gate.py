"""The local quality gate replaces the missing pre-merge CI (F-065; the workflow half is deferred by the owner).

``scripts/check.sh all`` is the one command a contributor runs before a merge: ruff, the Python suite, the JS
suite, the goldens, the docs drift check, the performance budgets, per-finding coverage and the sensitive-data
scan. These checks keep that gate whole: no step can silently drop out of ``all``, the finding-coverage step keeps
``--require-all``, and ``scripts/finding_coverage.py`` treats deferred and pending-docs findings exactly as
PLAN.md says (deferred: F-130, F-131, F-157; Wave 3b documentation is reported as ``pending-docs`` until its drift
test exists, and ``--strict`` counts it as uncovered).
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys

import pytest

from tests.support import targets

CHECK = targets.REPO_ROOT / "scripts" / "check.sh"
COVERAGE = targets.REPO_ROOT / "scripts" / "finding_coverage.py"
GATE_STEPS = ["lint", "py", "js", "golden", "docs", "perf", "findings", "scan"]


@pytest.fixture(scope="module")
def cov():
    spec = importlib.util.spec_from_file_location("finding_coverage_gate", COVERAGE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(spec.name, None)


@pytest.mark.finding("F-065")
def test_check_all_runs_every_gate_step():
    text = CHECK.read_text(encoding="utf-8")
    body = text.split("t_all() {", 1)[1].split("\n}", 1)[0]
    steps = re.search(r"for t in ([a-z ]+); do", body)
    assert steps and steps.group(1).split() == GATE_STEPS
    for step in GATE_STEPS:
        assert re.search(rf"^t_{step}\(\) \{{", text, re.M), step
    assert '"$RUFF" check "$PKG" tests scripts' in text
    assert '-m "not perf" --finding-report' in text
    assert "local req=(--require-all)" in text


@pytest.mark.finding("F-065")
def test_deferred_and_pending_docs_tables_follow_the_plan(cov):
    assert cov.DEFERRED == frozenset({"F-130", "F-131", "F-157"})
    assert not set(cov.PENDING_DOCS) & cov.DEFERRED
    assert all(re.fullmatch(r"F-\d{3}", fid) and why.startswith("DOC") for fid, why in cov.PENDING_DOCS.items())


#: A fixed pending-docs table for the mechanism tests: the live PENDING_DOCS shrinks to empty as the Wave 3b docs
#: streams land their drift tests, so these tests must not depend on which ids are still pending.
PENDING_EXAMPLE = {"F-067": "DOC1: example pending entry", "F-134": "DOC3: example pending entry"}


def _inputs(tmp_path, tests):
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps([{"id": i} for i in ("F-001", "F-067", "F-130", "F-134")]), encoding="utf-8")
    report = tmp_path / "pytest.json"
    report.write_text(json.dumps({"schema": "finding-report/1", "tests": tests}), encoding="utf-8")
    return ["--findings", str(findings), "--pytest-report", str(report)]


@pytest.mark.finding("F-065")
def test_pending_docs_do_not_fail_require_all_but_strict_does(cov, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cov, "PENDING_DOCS", dict(PENDING_EXAMPLE))
    argv = _inputs(tmp_path, {"tests/x.py::test_a": {"outcome": "passed", "findings": ["F-001"]}})
    out_json = tmp_path / "cov.json"
    assert cov.main(argv + ["--require-all", "--json", str(out_json)]) == 0
    out = capsys.readouterr().out
    assert "pending docs (Wave 3b" in out and "F-067" in out and "F-134" in out
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert (data["uncovered"], data["pending_docs"]) == ([], ["F-067", "F-134"])
    assert cov.main(argv + ["--require-all", "--strict"]) == 1
    assert "2 in-scope finding(s) without a passing test" in capsys.readouterr().err


@pytest.mark.finding("F-065")
def test_a_pending_finding_with_a_passing_test_is_covered_and_flagged_for_removal(cov, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cov, "PENDING_DOCS", dict(PENDING_EXAMPLE))
    argv = _inputs(tmp_path, {"tests/x.py::test_a": {"outcome": "passed", "findings": ["F-001", "F-067"]},
                              "tests/x.py::test_b": {"outcome": "failed", "findings": ["F-134"]}})
    assert cov.main(argv + ["--require-all"]) == 0
    out = capsys.readouterr().out
    assert re.search(r"^F-067 +1 +0 +0 +0  covered$", out, re.M)
    assert "remove them from the table): F-067" in out
    assert re.search(r"^F-134 +0 +1 +0 +0  pending-docs$", out, re.M)
    assert cov.main(argv + ["--require-all", "--strict"]) == 1


# ── the findings step fails on a failing test run (Wave 4) ───────────────────
def _function(name: str) -> str:
    """The text of the shell function ``name`` in check.sh (from ``name() {`` to the closing ``}``)."""
    text = CHECK.read_text(encoding="utf-8")
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.M | re.S)
    assert match, name
    return match.group(0)


#: Stubs for the commands t_findings runs: pytest, node and scripts/finding_coverage.py exit with STUB_*_RC.
FINDINGS_HARNESS = r'''set -u -o pipefail
need_python() { :; }
say() { printf '==> %s\n' "$*"; }
js_test_dirs() { return 0; }
fake_pytest() { echo "pytest ran"; return "$STUB_PYTEST_RC"; }
fake_coverage() { echo "coverage args: $*"; return "$STUB_COVERAGE_RC"; }
node() { echo "TAP version 13"; [ "$STUB_NODE_RC" -eq 0 ] || echo "not ok 1 - [F-001] stub"; return "$STUB_NODE_RC"; }
PYTEST=(fake_pytest)
PY=fake_coverage
'''


def _run_findings(tmp_path, pytest_rc=0, node_rc=0, coverage_rc=0, require_all=None):
    script = tmp_path / "findings_harness.sh"
    script.write_text(FINDINGS_HARNESS + _function("t_findings") + 't_findings\necho "rc=$?"\n', encoding="utf-8")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "TMPDIR": str(tmp_path), "STUB_PYTEST_RC": str(pytest_rc),
           "STUB_NODE_RC": str(node_rc), "STUB_COVERAGE_RC": str(coverage_rc)}
    if require_all is not None:
        env["FINDINGS_REQUIRE_ALL"] = require_all
    proc = subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env, cwd=tmp_path, timeout=60,
                          check=False)
    rc = re.search(r"^rc=(\d+)$", proc.stdout, re.M)
    assert rc, (proc.stdout, proc.stderr)
    return int(rc.group(1)), proc.stdout + proc.stderr


@pytest.mark.finding("F-065")
@pytest.mark.parametrize("pytest_rc, node_rc, coverage_rc, expected", [
    (0, 0, 0, 0), (1, 0, 0, 1), (0, 1, 0, 1), (0, 0, 1, 1), (2, 1, 0, 1),
], ids=["all-pass", "pytest-fails", "node-fails", "coverage-fails", "both-fail"])
def test_findings_step_fails_when_pytest_node_or_coverage_fails(tmp_path, pytest_rc, node_rc, coverage_rc, expected):
    rc, out = _run_findings(tmp_path, pytest_rc, node_rc, coverage_rc)
    assert rc == expected, out
    assert f"pytest exit status: {pytest_rc}" in out and f"node exit status: {node_rc}" in out
    assert "--require-all" in out.split("coverage args:", 1)[1].splitlines()[0]
    if node_rc:
        assert "not ok 1 - [F-001] stub" in out                    # the failing JS test is named in the output


@pytest.mark.finding("F-065")
def test_findings_report_only_mode_reports_failures_without_failing(tmp_path):
    rc, out = _run_findings(tmp_path, pytest_rc=1, node_rc=1, require_all="0")
    assert rc == 0, out
    assert "--require-all" not in out.split("coverage args:", 1)[1].splitlines()[0]
    assert "report only (FINDINGS_REQUIRE_ALL=0): pytest 1, node 1" in out
    rc, out = _run_findings(tmp_path, coverage_rc=1, require_all="0")
    assert rc == 1, out                                            # a broken coverage run still fails


# ── doctor: offline venv and history check (Wave 4) ──────────────────────────
#: A synthetic git for the doctor: one unpushed commit adds two internal-docs files when STUB_HISTORY=dirty.
FAKE_GIT = r'''#!/bin/sh
case "$1" in
  rev-parse)
    case "$2" in
      --is-inside-work-tree) echo true; exit 0 ;;
      --verify) [ "${STUB_UPSTREAM:-}" = "missing" ] && exit 1; echo 0000000000000000000000000000000000000000; exit 0 ;;
    esac ;;
  log)
    for arg in "$@"; do spec="$arg"; done
    if [ "$spec" = "internal-docs" ] && [ "${STUB_HISTORY:-}" = "dirty" ]; then
      case "$2" in
        --format=%h) echo abc1234 ;;
        *) printf 'internal-docs/example-a.md\ninternal-docs/example-b.md\n' ;;
      esac
    fi
    exit 0 ;;
esac
exit 0
'''


def _run_doctor(tmp_path, *, lock_lines, build_requires, history="clean", upstream="present", strict=False):
    from importlib import metadata

    stub = tmp_path / "bin"
    stub.mkdir(exist_ok=True)
    (stub / "git").write_text(FAKE_GIT, encoding="utf-8")
    (stub / "git").chmod(0o755)
    lock = tmp_path / "requirements-dev.txt"
    pins = {"pytest": metadata.version("pytest"), "jsonschema": metadata.version("jsonschema")}
    lock.write_text("".join(f"{line}\n" for line in lock_lines(pins)), encoding="utf-8")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(f'[build-system]\nrequires = {json.dumps(build_requires)}\n\n[project]\nname = "x"\n',
                         encoding="utf-8")
    env = {"PATH": f"{stub}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}", "HOME": str(tmp_path),
           "DOCTOR_LOCK": str(lock), "DOCTOR_PYPROJECT": str(pyproject), "STUB_HISTORY": history,
           "STUB_UPSTREAM": upstream}
    argv = ["bash", str(CHECK), "doctor"] + (["--strict"] if strict else [])
    proc = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=120, check=False)
    return proc.returncode, proc.stdout + proc.stderr


def _clean_lock(pins):
    return [f"{name}=={version} \\\n    --hash=sha256:{'0' * 64}" for name, version in sorted(pins.items())]


@pytest.mark.finding("F-065")
def test_doctor_passes_a_matching_venv_and_a_clean_history(tmp_path):
    for strict in (False, True):
        rc, out = _run_doctor(tmp_path, lock_lines=_clean_lock, build_requires=["setuptools>=1", "wheel"],
                              strict=strict)
        assert rc == 0, out
        assert "doctor: .venv matches the 2 pins" in out and "doctor: no never-push paths in origin/main..HEAD" in out


@pytest.mark.finding("F-065")
@pytest.mark.parametrize("case", ["lock-drift", "build-requirement", "unpushed-internal-docs"])
def test_doctor_warns_and_strict_fails(tmp_path, case):
    lock, requires, history = _clean_lock, ["setuptools>=1"], "clean"
    if case == "lock-drift":
        lock = lambda pins: _clean_lock({**pins, "pytest": "0.0.1"}) + ["example-missing-dist==1.0"]  # noqa: E731
    elif case == "build-requirement":
        requires = ["setuptools>=999"]
    else:
        history = "dirty"
    rc, out = _run_doctor(tmp_path, lock_lines=lock, build_requires=requires, history=history)
    assert rc == 0, out                                              # advisory by default
    rc_strict, out_strict = _run_doctor(tmp_path, lock_lines=lock, build_requires=requires, history=history,
                                        strict=True)
    assert rc_strict == 1 and "doctor: FAILED (--strict)" in out_strict, out_strict
    if case == "lock-drift":
        assert "2 of 3 pins" in out and "example-missing-dist: lock 1.0, .venv missing" in out
        assert "pytest: lock 0.0.1, .venv" in out and "--require-hashes -r requirements-dev.txt" in out
    elif case == "build-requirement":
        assert "build requirement setuptools>=999: .venv has" in out
    else:
        assert "doctor: internal-docs: 2 file(s) added or changed by abc1234 (not on origin/main)" in out
        assert "example-a.md" not in out                             # counted, never printed
        assert "drop or rewrite those commits before any push" in out


@pytest.mark.finding("F-065")
def test_doctor_skips_the_history_check_without_the_upstream_ref(tmp_path):
    rc, out = _run_doctor(tmp_path, lock_lines=_clean_lock, build_requires=["setuptools>=1"], upstream="missing",
                          strict=True)
    assert rc == 0 and "origin/main not found (history check skipped)" in out, out


@pytest.mark.finding("F-065")
def test_check_all_runs_the_doctor_as_an_advisory_step():
    body = _function("t_all")
    assert body.index('t_doctor || failed+=("doctor")') < body.index("for t in ")
    doctor = _function("t_doctor")
    assert 'strict="${DOCTOR_STRICT:-0}"' in doctor and "return 0" in doctor
    for path in ("internal-docs", "docs/features.md", "reports"):
        assert path in CHECK.read_text(encoding="utf-8").split("NEVER_PUSH=(", 1)[1].split(")", 1)[0]


@pytest.mark.finding("F-132")
def test_setup_installs_the_hash_locked_dev_dependencies():
    """Request w4-docs-1: ``setup`` uses the lock (pip and setuptools included), never the unhashed [dev] ranges."""
    proc = subprocess.run(["bash", str(CHECK), "setup"], capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode == 0, proc.stderr
    lines = [line.strip() for line in proc.stdout.splitlines()]
    assert any(line.endswith("-m pip install --require-hashes -r requirements-dev.txt") for line in lines), lines
    assert any(line.endswith("-m pip install --no-deps -e .") for line in lines), lines
    code = [line for line in _function("t_setup").splitlines() if not line.strip().startswith("#")]
    assert ".[dev]" not in proc.stdout and not [line for line in code if ".[dev]" in line]
