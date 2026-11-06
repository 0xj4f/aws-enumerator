"""Regression tests owned by stream R (CLI, runner, session, output layout, manifest, dashboard server wiring).

xfail-first (see test_e_policy.py). Runs go through the console entry point (``targets.main_entry``) via
``tests/python/collectors/legacy_harness.run_legacy_main`` against the acme fake world, with
``$AWS_ENUMERATOR_OUTPUT`` pointing into ``tmp_path`` (cli.md §7). Finders search both the legacy
``./reports/<date>/`` tree and the v2 output root, so the same assertion holds before and after the runner
rewrite. Legacy invocations (``--all``, ``--region R``, no arguments) are translated by the new CLI
(cli.md §4), so most tests use them; tests that need a new subcommand or flag say so in their reason.

F-121 and F-133 are already fixed by the Wave 0b rename and are plain passing tests.
"""

from __future__ import annotations

import contextlib
import http.client
import io
import re
import signal
import socketserver
import threading
import webbrowser
from pathlib import Path

import pytest

from tests.fixtures.regressions import support as S
from tests.fixtures.worlds import acme
from tests.support import targets

W1, W2 = "eu-west-1", "eu-west-2"
#: The only eu-west-1 instance in acme (read from the world, so an id change there needs no edit here).
WEST1_INSTANCE = acme.REGIONAL[W1]["ec2"]["Reservations"][0]["Instances"][0]["InstanceId"]


def _regional_ops(cli, operation="DescribeInstances", service="ec2"):
    return sorted({c.region for c in cli.legacy.fake.calls_for(service=service, operation=operation)})


# ── F-010: analysis runs once, after every region was collected ──────────────
@pytest.mark.finding("F-010")
def test_f010_all_mode_analysis_sees_the_regions(tmp_path, monkeypatch):
    cli = S.run_cli(["--all"], tmp_path, monkeypatch)
    dirs = cli.analysis_dirs()
    assert len(dirs) == 1, dirs
    counts = S.edge_counts(dirs[0])
    assert all(counts.get(name, 0) > 0 for name in ("ec2", "secrets", "lambda", "kms")), counts
    assert (dirs[0].parent / "manifest.json").is_file(), "analysis must sit at the run root"


# ── F-061: failures are visible in the exit code and the manifest ────────────
@pytest.mark.finding("F-061")
def test_f061_partial_run_exits_2_with_per_module_status(tmp_path, monkeypatch):
    cli = S.run_cli(["--all"], tmp_path, monkeypatch)   # acme: eu-west-1 flow logs time out, several denials
    assert cli.exit_code == 2, cli.exit_code
    manifest = cli.run_manifest()
    assert manifest and manifest.get("schema_version") == "2.0", manifest
    modules = {(m.get("name"), m.get("region")): m for m in manifest.get("modules", [])}
    flowlogs = modules.get(("flowlogs", W1), {})
    assert flowlogs.get("status") in ("partial", "failed"), flowlogs
    assert (manifest["run"].get("status"), manifest["run"].get("exit_code")) == ("partial", 2)


# ── F-063 / F-025: runs never share a directory ──────────────────────────────
@pytest.mark.finding("F-063", "F-025")
def test_f063_a_later_run_does_not_import_an_earlier_runs_data(tmp_path, monkeypatch):
    S.run_cli(["--region", W1], tmp_path, monkeypatch)                      # leaves WEST1_INSTANCE behind
    first = set(S.CliRun(None, None, tmp_path / "out", tmp_path / "run").analysis_dirs())
    world = acme.build_world()
    world.deny("ec2", "DescribeInstances", region=W2)                      # eu-west-2 now looks empty
    cli = S.run_cli(["--region", W2], tmp_path, monkeypatch, world=world)
    new_dirs = [d for d in cli.analysis_dirs() if d not in first]
    assert new_dirs, cli.analysis_dirs()
    leaked = [hit for d in new_dirs for hit in S.grep_tree(WEST1_INSTANCE, d)]
    assert leaked == []
    assert len({p.parent for p in cli.manifests()}) >= 2


# ── F-064: region discovery has a fallback ───────────────────────────────────
def _probe_only_known_regions(world):
    """Regions other than acme's answer InvalidClientTokenId to the STS probe (not enabled)."""
    import boto3

    for region in boto3.session.Session().get_available_regions("ec2"):
        if region not in (W1, W2, acme.GLOBAL_REGION):
            world.fail("sts", "GetCallerIdentity", "InvalidClientTokenId",
                       "The security token included in the request is invalid.", 403, region=region)
    return world


@pytest.mark.finding("F-064")
def test_f064_denied_describe_regions_falls_back_to_an_sts_probe(tmp_path, monkeypatch):
    world = _probe_only_known_regions(acme.build_world())
    world.deny("ec2", "DescribeRegions")
    cli = S.run_cli(["--all"], tmp_path, monkeypatch, world=world, patch_region_discovery=False)
    assert cli.exit_code in (0, 2), (cli.exit_code, cli.legacy.exception)
    manifest = cli.run_manifest()
    assert manifest and manifest.get("schema_version") == "2.0", manifest
    assert manifest["target"]["region_source"] == "fallback:sts-probe"
    assert {W1, W2} <= set(manifest["target"]["regions"])


# ── F-121 / F-133 (already fixed by the rename) ──────────────────────────────
def _package_sources():
    return sorted(targets.PACKAGE_DIR.rglob("*.py"))


def _import_fallbacks(path: Path):
    """``try: import X / except ImportError: import Y`` blocks (the script-vs-package dual import)."""
    import ast

    tree = ast.parse(path.read_text(encoding="utf-8"))
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        for handler in node.handlers:
            names = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
            catches_import = any(getattr(n, "id", "") in ("ImportError", "ModuleNotFoundError") for n in names)
            reimports = any(isinstance(n, (ast.Import, ast.ImportFrom)) for b in handler.body for n in ast.walk(b))
            if catches_import and reimports:
                hits.append(f"{path.name}:{handler.lineno}")
    return hits


@pytest.mark.finding("F-121")
def test_f121_no_dual_import_fallbacks():
    offenders = [hit for p in _package_sources() for hit in _import_fallbacks(p)]
    assert offenders == []
    bare = [str(p.relative_to(targets.REPO_ROOT)) for p in _package_sources()
            if re.search(r"^\s*(from|import)\s+(app|components|utils)\b", p.read_text(encoding="utf-8"), re.M)]
    assert bare == []
    assert not (targets.REPO_ROOT / "app").exists()


@pytest.mark.finding("F-133")
def test_f133_distribution_installs_a_distinctive_package():
    assert targets.PACKAGE_NAME == "aws_enumerator"
    pyproject = (targets.REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'include\s*=\s*\[\s*"aws_enumerator\*"\s*\]', pyproject)
    assert re.search(r'aws-enumerator\s*=\s*"aws_enumerator\.cli:main"', pyproject)
    assert not re.search(r'"app[\.\*"]', pyproject)


# ── F-122: one version, visible everywhere ───────────────────────────────────
@pytest.mark.finding("F-122")
def test_f122_version_flag_and_subcommand_print_the_single_source_version(monkeypatch):
    version = S.package_module("_version").__version__
    pyproject = (targets.REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    static = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
    assert static is None or static.group(1) == version          # dynamic, or equal to the single source
    for argv in (["--version"], ["version"]):
        code, out, _err = S.capture_main(argv, monkeypatch)
        assert (code, out.strip()) == (0, f"aws-enumerator {version}"), (argv, code, out)


# ── F-124: no hard-coded default region ──────────────────────────────────────
@pytest.mark.finding("F-124")
def test_f124_environment_region_is_used_when_no_region_is_given(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", W1)
    cli = S.run_cli([], tmp_path, monkeypatch, credentials="env")
    assert _regional_ops(cli) == [W1]


# ── F-125: the user's retry configuration is respected ───────────────────────
@pytest.mark.finding("F-125")
def test_f125_the_tool_never_writes_retry_settings_into_the_environment(tmp_path, monkeypatch):
    import os

    S.run_cli(["--region", W2], tmp_path, monkeypatch)
    assert "AWS_RETRY_MODE" not in os.environ
    assert "AWS_MAX_ATTEMPTS" not in os.environ


# ── F-129 / F-139: dashboard server ──────────────────────────────────────────
@pytest.mark.allow_loopback
@pytest.mark.finding("F-129")
def test_f129_port_zero_reports_the_bound_port(monkeypatch):
    opened, bound = [], []
    monkeypatch.setattr(webbrowser, "open", lambda url, *a, **k: opened.append(url) or True)
    monkeypatch.setattr(socketserver.BaseServer, "serve_forever",
                        lambda self, *a, **k: bound.append(self.server_address[1]))
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        targets.dashboard_server_module().serve_dashboard(port=0, open_browser=True)
    assert bound and bound[0] != 0, bound
    ports = {int(p) for p in re.findall(r"http://(?:127\.0\.0\.1|localhost|\[::1\]):(\d+)", out.getvalue()
                                        + " " + " ".join(opened))}
    assert ports == {bound[0]}, (ports, bound, out.getvalue())


@pytest.mark.allow_loopback
@pytest.mark.finding("F-129")
def test_f129_out_of_range_port_is_a_usage_error(monkeypatch):
    monkeypatch.setattr(webbrowser, "open", lambda *a, **k: True)
    monkeypatch.setattr(socketserver.BaseServer, "serve_forever", lambda self, *a, **k: None)
    code, _out, _err = S.capture_main(["--dashboard", "--port", "70000"], monkeypatch)
    assert code == 64


def _status(port: int, path: str, host: str) -> int:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.putrequest("GET", path, skip_host=True)
        conn.putheader("Host", host)
        conn.endheaders()
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


@pytest.mark.allow_loopback
@pytest.mark.finding("F-139")
def test_f139_no_directory_listing_and_foreign_host_refused(monkeypatch):
    results = {}
    original = socketserver.BaseServer.serve_forever

    def probing_serve_forever(self, *args, **kwargs):
        worker = threading.Thread(target=original, args=(self, 0.05), daemon=True)
        worker.start()
        try:
            port = self.server_address[1]
            local = f"127.0.0.1:{port}"
            results["index"] = _status(port, "/index.html", local)
            results["icons"] = _status(port, "/icons/", local)
            results["foreign"] = _status(port, "/index.html", "evil.example")
        finally:
            self.shutdown()
            worker.join(5)

    monkeypatch.setattr(socketserver.BaseServer, "serve_forever", probing_serve_forever)
    monkeypatch.setattr(webbrowser, "open", lambda *a, **k: True)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        targets.dashboard_server_module().serve_dashboard(port=0, open_browser=False)
    assert results.get("index") == 200, results                    # positive control
    assert results.get("icons") == 404, results
    assert results.get("foreign") in (400, 403, 421), results


# ── F-140: regions.json is used or not shipped ───────────────────────────────
@pytest.mark.finding("F-140")
def test_f140_shipped_regions_json_is_read_by_the_code(monkeypatch):
    path = targets.regions_json_path()
    if not path.exists():
        pyproject = (targets.REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        assert "regions.json" not in pyproject
        return
    users = [p for p in _package_sources() if "regions.json" in p.read_text(encoding="utf-8")]
    assert users, f"{path.name} is shipped but nothing in {targets.PACKAGE_NAME} reads it"


# ── F-153: global services once per run ──────────────────────────────────────
@pytest.mark.finding("F-153")
def test_f153_two_regions_collect_global_services_once(tmp_path, monkeypatch):
    cli = S.run_cli(["collect", "--regions", f"{W1},{W2}", "--no-k8s"], tmp_path, monkeypatch)
    iam_dirs = {p.parent for p in S.files_under(*cli.roots()) if p.parent.name == "iam" and p.name == "roles.json"}
    assert len(iam_dirs) == 1, iam_dirs
    assert _regional_ops(cli) == [W1, W2]


# ── F-155: an interrupted run is marked as such ──────────────────────────────
@pytest.mark.finding("F-155")
def test_f155_sigint_finalises_the_manifest_as_interrupted(tmp_path, monkeypatch):
    def interrupt(ctx):
        signal.raise_signal(signal.SIGINT)

    owner, attr = targets.collector_patch_point("lambda_")
    monkeypatch.setattr(owner, attr, interrupt)
    previous = signal.getsignal(signal.SIGINT)
    try:
        try:
            code = S.run_cli(["--region", W2], tmp_path, monkeypatch).exit_code
        except KeyboardInterrupt:
            code = "KeyboardInterrupt escaped main()"
    finally:
        signal.signal(signal.SIGINT, previous)
    probe = S.CliRun(None, code, tmp_path / "out", tmp_path / "run")
    statuses = [(m.get("run") or {}).get("status") for m in probe.manifest_docs() if isinstance(m, dict)]
    assert code == 130, code
    assert "interrupted" in statuses, statuses


# ── F-171: timestamps are UTC ────────────────────────────────────────────────
@pytest.mark.finding("F-171")
def test_f171_manifest_timestamps_are_utc(tmp_path, monkeypatch):
    cli = S.run_cli(["--region", W2], tmp_path, monkeypatch)
    manifest = cli.run_manifest()
    assert manifest
    run = manifest.get("run") or {}
    legacy = manifest.get("run_metadata") or {}
    stamps = ([run.get("started_at"), run.get("ended_at")] if run
              else [legacy.get("timestamp_start"), legacy.get("timestamp_end")])
    assert all(isinstance(s, str) and (s.endswith("Z") or s.endswith("+00:00")) for s in stamps), stamps


def test_regressions_cli_helper_finds_legacy_reports(tmp_path, monkeypatch):
    """Harness sanity (no finding): the layout-agnostic finders see today's ./reports/<date>/ tree."""
    cli = S.run_cli(["--region", W2], tmp_path, monkeypatch)
    assert cli.exit_code in (0, 2)
    assert cli.manifests() and cli.analysis_dirs()
    assert isinstance(cli.run_manifest(), dict)
    assert Path(cli.analysis_dirs()[0]).is_dir()
