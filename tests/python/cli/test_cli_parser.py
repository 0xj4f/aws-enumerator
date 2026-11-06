"""Argument parsing, exit codes, legacy translation, version and help (cli.md §1, §2, §4, §6)."""

from __future__ import annotations

import subprocess
import sys

import pytest

from tests.python.orchestration import r_harness as R
from tests.support import targets

CLI = targets.main_module()
VERSION = targets.runtime_module("_version").__version__


# ── version (F-122) ──────────────────────────────────────────────────────────
@pytest.mark.finding("F-122")
@pytest.mark.parametrize("argv", [["--version"], ["version"], ["collect", "--version"], ["dashboard", "--version"],
                                  ["verify", "--version"]])
def test_every_version_entry_point_prints_the_single_source(monkeypatch, argv):
    code, out, err = R.invoke(argv, monkeypatch)
    assert (code, out.strip()) == (0, f"aws-enumerator {VERSION}"), err


@pytest.mark.finding("F-122")
def test_version_json_is_the_manifest_tool_block(monkeypatch):
    import json

    code, out, _err = R.invoke(["version", "--json"], monkeypatch)
    doc = json.loads(out)
    assert code == 0 and doc["version"] == VERSION
    assert set(doc) == {"version", "git_sha", "python", "boto3", "botocore", "kubernetes"}


# ── help, program name, authorised use (F-172, F-144) ────────────────────────
@pytest.mark.finding("F-172", "F-144")
def test_help_under_python_m_names_the_program_and_carries_the_authorised_use_line():
    proc = subprocess.run([sys.executable, "-m", targets.package_name(), "--help"], cwd=targets.REPO_ROOT,
                          capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("usage: aws-enumerator ")
    assert "Authorized use only" in " ".join(proc.stdout.split())
    assert "0xj4f" not in proc.stdout


@pytest.mark.finding("F-172")
@pytest.mark.parametrize("sub", ["collect", "preflight", "analyze"])
def test_subcommand_help_carries_the_authorised_use_line(monkeypatch, sub):
    code, out, _err = R.invoke([sub, "--help"], monkeypatch)
    assert code == 0 and "Authorized use only" in " ".join(out.split())


# ── usage errors are 64 (F-061: 2 means partial) ─────────────────────────────
@pytest.mark.finding("F-061")
@pytest.mark.parametrize("argv", [
    ["frobnicate"],
    ["collect", "--no-such-flag"],
    ["collect", "--region", "eu-west-1", "--all"],
    ["collect", "--regions", "eu-west-1", "--exclude-regions", "eu-west-2"],
    ["collect", "--retry-denied"],
    ["collect", "--concurrency", "17"],
    ["collect", "--concurrency", "0"],
    ["collect", "--rate-limit", "lambda"],
    ["collect", "--max-rps", "0"],
    ["collect", "--encrypt", "rot13:x"],
    ["collect", "--sign", "age:x"],
    ["collect", "--k8s", "--no-k8s"],
    ["collect", "--max-tier", "3"],
    ["collect", "--k8s-timeout", "5,900"],
    ["collect", "--ebs-share-check", "some"],
    ["collect", "--resume", "x", "--run-id", "y"],
    ["collect", "--k8s-auth", "token"],
    ["export", "/nowhere", "--format", "pdf"],
    ["dashboard", "--port", "-1"],
])
def test_usage_errors_exit_64(monkeypatch, argv):
    code, out, err = R.invoke(argv, monkeypatch)
    assert code == 64, (argv, out, err)
    assert out == ""


@pytest.mark.finding("F-129")
@pytest.mark.parametrize("value, ok", [("0", True), ("8000", True), ("65535", True), ("65536", False),
                                       ("70000", False), ("-1", False), ("http", False)])
def test_port_type_accepts_only_0_to_65535(value, ok):
    import argparse

    if ok:
        assert CLI.port_type(value) == int(value)
    else:
        with pytest.raises(argparse.ArgumentTypeError):
            CLI.port_type(value)


@pytest.mark.finding("F-129")
def test_legacy_dashboard_with_an_out_of_range_port_is_a_usage_error(monkeypatch):
    code, _out, err = R.invoke(["--dashboard", "--port", "70000"], monkeypatch)
    assert code == 64 and "out of range" in err


# ── legacy invocation (cli.md §4) ────────────────────────────────────────────
@pytest.mark.finding("F-124")
@pytest.mark.parametrize("old, new", [
    ([], ["collect"]),
    (["--region", "eu-west-1"], ["collect", "--region", "eu-west-1"]),
    (["--all", "--zip"], ["collect", "--all", "--zip"]),
    (["--dashboard"], ["dashboard"]),
    (["--dashboard", "--port", "9000"], ["dashboard", "--port", "9000"]),
    (["--dashboard", "--port=9000", "--region", "eu-west-1"], ["dashboard", "--port=9000"]),
    (["collect", "--all"], ["collect", "--all"]),
    (["--help"], ["--help"]),
])
def test_legacy_translation(old, new):
    translated, notice = CLI.translate_legacy(old)
    assert translated == new
    if old and old[0] in ("collect", "--help"):
        assert notice is None
    else:
        assert "is deprecated" in notice and "removed in 0.4.0" in notice
    if "--region" in old and old[0] == "--dashboard":
        assert "ignored with --dashboard: --region eu-west-1" in notice


@pytest.mark.finding("F-124")
def test_the_parser_has_no_default_region():
    args = CLI.build_parser().parse_args(["collect"])
    assert args.region is None and args.regions is None and args.all_regions is False


@pytest.mark.finding("F-062")
def test_k8s_is_on_by_default_and_secrets_are_opt_in():
    args = CLI.build_parser().parse_args(["collect"])
    assert (args.no_k8s, args.k8s_secrets) == (False, False)
    args = CLI.build_parser().parse_args(["collect", "--no-k8s", "--modules", "iam,@data", "--modules", "eks",
                                          "--skip", "s3"])
    assert args.no_k8s is True and CLI._flatten(args.modules) == ["iam", "@data", "eks"]


def test_recorded_argv_hides_local_paths_and_optionally_the_profile():
    argv = ["collect", "--output", "/home/demo/out", "--kubeconfig=/home/demo/.kube/config", "--profile", "demo",
            "--region", "eu-west-2"]
    assert CLI.recorded_argv(argv) == ["collect", "--output", "<redacted>", "--kubeconfig=<redacted>", "--profile",
                                       "demo", "--region", "eu-west-2"]
    assert CLI.recorded_argv(argv, redact_profile=True)[5] == "<redacted>"


@pytest.mark.finding("F-169")
def test_deprecation_warning_goes_to_stderr_not_stdout(monkeypatch):
    code, out, err = R.invoke(["--region"], monkeypatch)     # translated, then a usage error (missing value)
    assert code == 64 and out == ""
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    code, out, err = R.invoke([], monkeypatch)               # 'collect' with no home region: 64 before any call
    assert (code, out) == (64, "") and "deprecated" in err and "no home region" in err
