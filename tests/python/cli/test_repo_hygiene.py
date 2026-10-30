"""Packaging and repository hygiene owned by stream R: .gitignore, .dockerignore, pre-commit hooks, Dockerfile,
lockfiles, the single version source, and the no-print rule for runtime modules (F-066, F-122, F-132, F-160,
F-169)."""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
import sys
from importlib import metadata
from pathlib import Path

import pytest

from tests.support import targets

ROOT = Path(targets.REPO_ROOT)
HOOK = ROOT / "scripts" / "hooks" / "reject_report_artifacts.py"
PLACEHOLDER_ACCOUNTS = {"123456789012", "111122223333", "999999999999", "000000000000"}
#: A 12-digit id outside the placeholder allow-list, assembled at run time so the source holds no account-id
#: literal for scripts/scan_sensitive.py or gitleaks to flag (it is the AWS documentation example id).
NON_PLACEHOLDER_ACCOUNT = "4444" + "5555" + "6666"
#: R-stream runtime modules that must not print (cli.py and logging_setup.py are the two allowed writers).
NO_PRINT_MODULES = ("runner", "commands", "aws_session", "ratelimit", "output", "integrity", "archive",
                    "permissions", "engine_adapter", "execution", "resume", "buildinfo", "iam_actions", "_version")


def _text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


# ── .gitignore / .dockerignore (F-066) ───────────────────────────────────────
@pytest.mark.finding("F-066")
@pytest.mark.parametrize("path, ignored", [
    ("reports/20261015/x.json", True), ("tmp", True), ("enum.sh", True), ("run.zip", True),
    ("examples/targets.local.sh", True), (".claude/settings.local.json", True), ("internal-docs/x.md", True),
    ("out/111122223333/x/manifest.json", True), ("tests/fixtures/r/reports-like.json", False),
    ("aws_enumerator/cli.py", False), ("examples/multi-target.example.sh", False),
    # the owner's notes (Wave 4: docs/features.md was untracked and one `git add docs/` from a push); their
    # neighbours in docs/ stay committable
    ("docs/features.md", True), ("docs/permissions.md", False), ("docs/contracts/report-layout.md", False),
    ("tests/fixtures/docs/features.md", False),
    # credentials files and the check.sh matrix interpreters
    (".env", True), (".env.local", True), (".env.example", False), (".venvs/py3.12/bin/python", True),
])
def test_gitignore_keeps_report_data_and_local_files_out(path, ignored):
    """Path rules only (``--no-index``): git matches the pattern and never opens the file."""
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    proc = subprocess.run(["git", "check-ignore", "-q", "--no-index", path], cwd=ROOT, check=False)
    assert (proc.returncode == 0) is ignored, path


@pytest.mark.finding("F-066")
def test_gitignore_names_the_owner_notes_with_a_reason():
    lines = _text(".gitignore").splitlines()
    index = lines.index("/docs/features.md")
    assert "never committed" in lines[index - 1] and lines[index - 1].startswith("#")


@pytest.mark.finding("F-066", "F-132")
def test_dockerignore_excludes_secrets_reports_and_tooling_state():
    entries = {line.strip() for line in _text(".dockerignore").splitlines() if line.strip()
               and not line.startswith("#")}
    assert {".git", ".venv", "reports", "tmp", "enum.sh", "internal-docs", "*.zip", ".claude", "tests"} <= entries
    # credentials files at the root and below (aws_enumerator/ is COPYed whole), report output, matrix venvs
    assert {".env", ".env.*", "**/.env", "**/.env.*", "out", ".venvs", "**/__pycache__", "**/*.py[cod]"} <= entries
    for needed in ("requirements.txt", "pyproject.toml", "aws_enumerator", "readme.md", "LICENSE"):
        assert needed not in entries


# ── pre-commit (F-066) ───────────────────────────────────────────────────────
@pytest.mark.finding("F-066")
def test_pre_commit_runs_gitleaks_with_the_repo_rules_and_the_local_artifact_hook():
    config = _text(".pre-commit-config.yaml")
    assert "https://github.com/gitleaks/gitleaks" in config and "scripts/hooks/gitleaks.toml" in config
    assert "scripts/hooks/reject_report_artifacts.py" in config and "id: ruff" in config
    tomli = pytest.importorskip("tomli")
    rules = tomli.loads(_text("scripts/hooks/gitleaks.toml"))
    assert rules["extend"]["useDefault"] is True
    regexes = {r["id"]: re.compile(r["regex"]) for r in rules["rules"]}
    assert regexes["aws-arn-with-account"].search(f"arn:aws:iam::{NON_PLACEHOLDER_ACCOUNT}:role/demo-x")
    assert regexes["aws-account-id-labelled"].search(f'"AccountId": "{NON_PLACEHOLDER_ACCOUNT}"')
    for rule in rules["rules"]:
        allowed = re.compile(rule["allowlist"]["regexes"][0])
        assert all(allowed.match(a) for a in PLACEHOLDER_ACCOUNTS) and not allowed.match(NON_PLACEHOLDER_ACCOUNT)


@pytest.mark.finding("F-066")
@pytest.mark.parametrize("path, rejected", [
    ("reports/20261015/111122223333/manifest.json", True), ("out/x/y.json", True), ("tmp", True),
    ("tmp/notes.txt", True), ("enum.sh", True), ("scans/acme.local.sh", True), ("bundle.zip", True),
    ("x.zip.age", True), ("x.zip.minisig", True), ("docs/HANDLING.txt", True),
    ("tests/fixtures/r/run/HANDLING.txt", False), ("aws_enumerator/cli.py", False), ("docs/reports.md", False),
    # the owner's notes and internal documents, by path only (synthetic arguments: no file is opened)
    ("docs/features.md", True), ("./docs/features.md", True), ("docs/Features.md", True),
    ("internal-docs/README.md", True), ("internal-docs/findings/verified-findings.json", True),
    ("docs/features-overview.md", False), ("docs/permissions.md", False), ("tests/fixtures/docs/features.md", False),
    ("examples/internal-docs.md", False),
])
def test_artifact_hook(path, rejected):
    proc = subprocess.run([sys.executable, str(HOOK), path], capture_output=True, text=True, check=False)
    assert (proc.returncode == 1) is rejected, (path, proc.stderr)


@pytest.mark.finding("F-066")
def test_artifact_hook_names_the_owner_notes_in_its_message():
    proc = subprocess.run([sys.executable, str(HOOK), "aws_enumerator/cli.py", "docs/features.md"],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    assert "refusing to commit docs/features.md: owner notes, never committed" in proc.stderr
    assert "aws_enumerator/cli.py" not in proc.stderr


# ── Dockerfile (F-132, F-160) ────────────────────────────────────────────────
@pytest.mark.finding("F-132", "F-160")
def test_dockerfile_is_pinned_multi_stage_non_root_and_carries_no_credentials():
    text = _text("Dockerfile")
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
    image = re.search(r"^ARG PYTHON_IMAGE=(\S+)$", text, re.M).group(1)
    assert re.match(r"^python:3\.13-slim@sha256:[0-9a-f]{64}$", image), image
    froms = [line for line in lines if line.startswith("FROM ")]
    assert len(froms) == 2 and all("${PYTHON_IMAGE}" in line for line in froms)
    final = text.split("AS runtime", 1)[1]
    assert re.search(r"^USER 10001(:10001)?$", final, re.M)
    assert "--require-hashes" in text and "--no-build-isolation" in text
    assert not re.search(r"^ENV\s+AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|PROFILE)", text, re.M)
    assert not re.search(r"AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)=", "\n".join(lines))
    assert "/root/.aws" not in "\n".join(lines)
    assert 'VOLUME ["/reports"]' in lines and "AWS_ENUMERATOR_OUTPUT=/reports" in text
    assert 'ENTRYPOINT ["aws-enumerator"]' in lines
    assert re.search(r"^ARG VERSION=(\S+)$", text, re.M).group(1) == targets.runtime_module("_version").__version__


# ── lockfiles (F-132) ────────────────────────────────────────────────────────
def _pins(rel: str) -> dict:
    pins = {}
    for line in _text(rel).splitlines():
        match = re.match(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", line)
        if match:
            pins[match.group(1).lower().replace("_", "-")] = match.group(2)
    return pins


@pytest.mark.finding("F-132")
@pytest.mark.parametrize("rel", ["requirements.txt", "requirements-dev.txt", "requirements-build.txt"])
def test_lockfiles_pin_every_requirement_with_hashes(rel):
    text = _text(rel)
    blocks = re.split(r"\n(?=[A-Za-z0-9_.-]+==)", text)
    reqs = [b for b in blocks if re.match(r"^[A-Za-z0-9_.-]+==", b)]
    assert reqs and all("--hash=sha256:" in b for b in reqs)
    assert not re.search(r"^[A-Za-z0-9_.-]+\s*(>=|<=|~=|$)", text, re.M)
    assert "/Users/" not in text and "/home/" not in text and "/private/" not in text


def test_runtime_lock_matches_the_tested_versions():
    pins = _pins("requirements.txt")
    for dist in ("boto3", "botocore", "kubernetes"):
        assert pins[dist] == metadata.version(dist), dist


# ── version (F-122) ──────────────────────────────────────────────────────────
@pytest.mark.finding("F-122")
def test_the_version_has_one_source():
    version = targets.runtime_module("_version").__version__
    pyproject = _text("pyproject.toml")
    assert re.search(r'^dynamic\s*=\s*\["version"\]', pyproject, re.M)
    assert 'version = {attr = "aws_enumerator._version.__version__"}' in pyproject
    assert not re.search(r'^version\s*=\s*"', pyproject, re.M)
    for name in NO_PRINT_MODULES + ("cli", "logging_setup"):
        if name == "_version":
            continue
        source = (targets.package_dir() / f"{name}.py").read_text(encoding="utf-8")
        assert f'"{version}"' not in source and '"0.2.0"' not in source, name


def test_engine_data_is_packaged():
    pyproject = _text("pyproject.toml")
    for glob in ('"engine/schema/*.json"', '"engine/rules/data/*.json"', '"engine/rules/data/NOTICE"',
                 '"engine/rules/schema.json"', '"schemas/*.json"', '"dashboard/js/*.js"'):
        assert glob in pyproject


# ── no print() / no ANSI in runtime modules (F-169) ──────────────────────────
@pytest.mark.finding("F-169")
@pytest.mark.parametrize("name", NO_PRINT_MODULES)
def test_runtime_modules_log_instead_of_printing(name):
    path = targets.package_dir() / f"{name}.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    prints = [n.lineno for n in ast.walk(tree)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "print"]
    assert prints == [], f"{name}.py prints at lines {prints}"
    assert "\\033[" not in path.read_text(encoding="utf-8")


# ── examples (F-066) ─────────────────────────────────────────────────────────
def test_example_script_uses_placeholders_only():
    text = _text("examples/multi-target.example.sh")
    assert set(re.findall(r"\b\d{12}\b", text)) <= PLACEHOLDER_ACCOUNTS
    assert re.findall(r'"([a-z0-9-]+)\|', text) and all(p.startswith("example-")
                                                        for p in re.findall(r'"([a-z0-9-]+)\|', text))
    if shutil.which("bash"):
        assert subprocess.run(["bash", "-n", str(ROOT / "examples" / "multi-target.example.sh")],
                              check=False).returncode == 0
