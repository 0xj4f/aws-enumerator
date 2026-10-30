"""End-to-end ``aws-enumerator collect`` runs against the acme fake world (stream R; cli.md §3.1, §5, §6;
report-layout.md; manifest.md). No network: FakeAWS answers every call, FakeKubernetes every k8s request.

The analysis engine is replaced by a recorder (``r_harness.fake_engine``) wherever a test is about the
orchestration (when and on which directories analysis runs), so these tests do not depend on the analyzers
other streams are rewriting in parallel.
"""

from __future__ import annotations

import json
import os
import re
import signal

import pytest

from tests.fixtures.worlds import acme
from tests.python.orchestration import r_harness as R
from tests.support import targets
from tests.support.fakeaws import botocore_error

W1, W2 = acme.REGIONS
RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{6}$")


# ── layout, manifest, stdout (F-063, F-061, F-171, F-159, F-144, F-010) ──────
@pytest.mark.finding("F-063", "F-171", "F-159")
def test_run_root_layout_manifest_and_stdout(tmp_path, monkeypatch):
    calls = R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--region", W2], tmp_path, monkeypatch)
    assert run.exit_code in (0, 2), run.err[-2000:]
    root = run.run_root
    assert root.parent.name == acme.ACCOUNT_ID and root.parent.parent == tmp_path / "out"
    assert RUN_ID_RE.match(root.name), root.name
    assert run.stdout_lines() == [str(root)]                       # stdout: exactly the run root (cli.md §5)
    assert set(os.listdir(root)) <= R.RUN_ROOT_ENTRIES | {W2}
    assert {"manifest.json", "HANDLING.txt", "run.log", "SHA256SUMS", "global", W2, "analysis"} <= set(os.listdir(root))
    manifest = run.manifest()
    assert R.validate_manifest(manifest) == []
    assert manifest["run"]["run_id"] == root.name and manifest["target"]["regions"] == [W2]
    for stamp in (manifest["run"]["started_at"], manifest["run"]["ended_at"]):
        assert stamp.endswith("Z"), stamp                           # UTC everywhere (F-171)
    handling = (root / "HANDLING.txt").read_text(encoding="utf-8")
    assert "CONFIDENTIAL" in handling and root.name in handling and acme.ACCOUNT_ID in handling
    assert manifest["classification"].startswith("CONFIDENTIAL")    # F-159
    assert len(calls) == 1


@pytest.mark.finding("F-144", "F-172")
def test_banner_has_product_version_and_authorised_use_line_but_no_personal_handle(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--region", W2, "--no-k8s"], tmp_path, monkeypatch)
    version = targets.runtime_module("_version").__version__
    assert f"aws-enumerator {version}" in run.err
    assert "Authorized use only: run only against accounts you have written permission to assess" in run.err
    assert "0xj4f" not in run.err and "0xj4f" not in run.out
    manifest = run.manifest()
    assert "author" not in json.dumps(manifest["tool"]) and manifest["tool"]["version"] == version


def test_quiet_mode_suppresses_the_banner(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--region", W2, "--no-k8s", "-q"], tmp_path, monkeypatch)
    assert "Authorized use only" not in run.err
    assert run.stdout_lines() == [str(run.run_root)]


@pytest.mark.finding("F-010", "F-025")
def test_analysis_runs_once_after_every_unit_at_the_run_root(tmp_path, monkeypatch):
    calls = R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--all", "--no-k8s"], tmp_path, monkeypatch)
    assert len(calls) == 1, calls
    call = calls[0]
    root = run.run_root
    assert call.entry_point == "analyze_run"
    assert call.path == root and call.regions == [W1, W2]       # the explicit region list (F-025)
    for unit in ("global", W1, W2):                             # every unit was complete when analysis started
        assert "_coverage.json" in os.listdir(root / unit / "ec2" if unit != "global" else root / unit / "iam")
    assert (root / "analysis" / "graph.json").is_file() and not (root / "global" / "analysis").exists()
    assert run.manifest()["analysis"]["status"] == "ok"


@pytest.mark.finding("F-063", "F-025")
def test_two_runs_never_share_a_directory_or_see_each_others_data(tmp_path, monkeypatch):
    calls = R.fake_engine(monkeypatch)
    first = R.collect(["collect", "--region", W1, "--no-k8s"], tmp_path, monkeypatch, workdir_name="one")
    second = R.collect(["collect", "--region", W2, "--no-k8s"], tmp_path, monkeypatch, workdir_name="two")
    roots = second.run_roots()
    assert len(roots) == 2 and first.run_roots()[0] in roots
    newer = next(r for r in roots if r != first.run_roots()[0])
    assert sorted(p.name for p in newer.iterdir() if p.is_dir()) == ["analysis", W2, "global"]
    assert W1 not in calls[1].listing and W1 not in (calls[1].regions or [])


# ── exit codes and per-module status (F-061) ─────────────────────────────────
@pytest.mark.finding("F-061")
def test_degraded_modules_make_the_run_partial_with_exit_2(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    world = acme.build_world()
    world.raise_exc("ec2", "DescribeFlowLogs", botocore_error("ReadTimeoutError", endpoint_url="https://ec2.example"),
                    region=W2)
    run = R.collect(["collect", "--region", W2, "--no-k8s"], tmp_path, monkeypatch, world=world)
    manifest = run.manifest()
    entry = R.modules_by_unit(manifest)[("flowlogs", W2)]
    assert entry["status"] in ("partial", "failed"), entry
    assert (run.exit_code, manifest["run"]["status"], manifest["run"]["exit_code"]) == (2, "partial", 2)
    summary = manifest["coverage_summary"]
    assert f"flowlogs@{W2}" in summary["partial_modules"] + summary["failed_modules"]


@pytest.mark.finding("F-061")
def test_every_module_failing_is_a_fatal_exit_1(tmp_path, monkeypatch):
    import importlib

    R.fake_engine(monkeypatch)

    def boom(ctx):
        raise RuntimeError("synthetic collector crash")

    for spec in targets.registry_module().get_registry().implemented():
        monkeypatch.setattr(importlib.import_module(spec.module), "collect", boom)
    run = R.collect(["collect", "--region", W2, "--no-k8s"], tmp_path, monkeypatch)
    manifest = run.manifest()
    ran = [m for m in manifest["modules"] if m["status"] not in ("skipped", "not_run")]
    assert ran and all(m["status"] == "failed" for m in ran)
    assert (run.exit_code, manifest["run"]["status"]) == (1, "failed")
    assert R.validate_manifest(manifest) == []


@pytest.mark.finding("F-061")
def test_expired_credentials_abort_the_run_with_exit_1(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    world = acme.build_world()
    world.fail("s3", "ListBuckets", "ExpiredToken", "The security token included in the request is expired", 400)
    run = R.collect(["collect", "--region", W2, "--no-k8s", "--concurrency", "1"], tmp_path, monkeypatch,
                    world=world)
    manifest = run.manifest()
    assert (run.exit_code, manifest["run"]["status"]) == (1, "failed")
    assert any(m["status"] == "not_run" for m in manifest["modules"])     # the run stopped
    assert manifest["analysis"]["status"] == "not_run"


@pytest.mark.finding("F-061")
def test_skipped_modules_never_make_a_run_partial(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--region", W2, "--modules", "vpc,lambda", "--max-tier", "1", "--no-k8s"],
                    tmp_path, monkeypatch)
    manifest = run.manifest()
    entries = R.modules_by_unit(manifest)
    assert entries[("lambda", W2)]["status"] == "skipped"
    assert "--max-tier 1" in entries[("lambda", W2)]["status_reason"]
    assert entries[("vpc", W2)]["status"] == "ok", entries[("vpc", W2)]
    assert (run.exit_code, manifest["run"]["status"]) == (0, "complete")


# ── selection and K8s (F-062) ────────────────────────────────────────────────
@pytest.mark.finding("F-062")
def test_k8s_is_on_by_default_and_no_k8s_turns_it_off(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    on = R.collect(["collect", "--region", W2, "--modules", "eks,k8s"], tmp_path, monkeypatch, workdir_name="on",
                   out=tmp_path / "out-on")
    assert on.manifest()["run"]["options"]["k8s"] is True
    assert on.k8s.resources_read("demo-cluster")
    off = R.collect(["collect", "--region", W2, "--no-k8s"], tmp_path, monkeypatch,     # default selection
                    workdir_name="off", out=tmp_path / "out-off")
    options = off.manifest()["run"]["options"]
    assert options["k8s"] is False and options["k8s_secrets"] is False
    assert not off.k8s.resources_read("demo-cluster")
    assert {"name": "k8s", "reason": "disabled by --no-k8s"} in options["skipped_modules"]


@pytest.mark.finding("F-062")
def test_module_selection_runs_only_the_selected_modules(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--region", W2, "--modules", "iam,@messaging", "--skip", "sqs"], tmp_path,
                    monkeypatch)
    ran = {m["name"] for m in run.manifest()["modules"] if m["status"] not in ("skipped",)}
    assert ran == {"iam", "sns"}
    services = {c.service for c in run.fake.calls_for()} - {"sts"}
    assert services == {"iam", "sns"}, services


@pytest.mark.finding("F-062")
@pytest.mark.parametrize("argv, needle", [
    (["--modules", "lamda"], "did you mean 'lambda'"),
    (["--modules", "k8s", "--no-k8s"], "k8s"),
])
def test_bad_selection_is_a_usage_error_before_anything_is_written(tmp_path, monkeypatch, argv, needle):
    run = R.collect(["collect", "--region", W2, *argv], tmp_path, monkeypatch)
    assert run.exit_code == 64
    assert needle in run.err
    assert run.run_roots() == []


# ── regions, home region, global services (F-124, F-064, F-153) ───────────────
@pytest.mark.finding("F-124")
def test_no_region_anywhere_is_a_usage_error(tmp_path, monkeypatch):
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    run = R.collect(["collect"], tmp_path, monkeypatch, credentials="env")
    assert run.exit_code == 64 and "no home region" in run.err
    assert run.fake.calls_for() == []                     # not even STS was called


@pytest.mark.finding("F-064", "F-119", "F-124")
def test_all_uses_describe_regions_in_the_home_region(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    monkeypatch.setenv("AWS_DEFAULT_REGION", W1)            # the home region comes from the environment
    run = R.collect(["collect", "--all", "--no-k8s", "--modules", "vpc"], tmp_path, monkeypatch,
                    patch_region_discovery=False)
    calls = run.fake.calls_for(service="ec2", operation="DescribeRegions")
    assert [c.region for c in calls] == [W1]                # the home region, not a hard-coded us-east-1
    assert {c.region for c in run.fake.calls_for(service="sts")} == {W1}
    target = run.manifest()["target"]
    assert target["region_source"] == "describe_regions"
    assert set(acme.REGIONS) <= set(target["regions"]) and "af-south-1" not in target["regions"]


@pytest.mark.finding("F-153")
def test_global_services_are_collected_once_per_run(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--regions", f"{W1},{W2}", "--no-k8s"], tmp_path, monkeypatch)
    root = run.run_root
    assert sorted(p.name for p in root.iterdir() if p.is_dir()) == ["analysis", W1, W2, "global"]
    assert not (root / W1 / "iam").exists() and (root / "global" / "iam").is_dir()
    iam_regions = {c.region for c in run.fake.calls_for(service="iam")}
    assert iam_regions and not iam_regions & {W1, W2}        # IAM's global endpoint, once per run


@pytest.mark.finding("F-153")
def test_skip_global_and_global_from(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    source = R.collect(["collect", "--region", W1, "--no-k8s"], tmp_path, monkeypatch, workdir_name="src")
    source_root = source.run_root
    skip = R.collect(["collect", "--region", W2, "--no-k8s", "--skip-global"], tmp_path, monkeypatch,
                     workdir_name="skip")
    skipped_root = next(r for r in skip.run_roots() if r != source_root)
    assert not (skipped_root / "global").exists()
    reused = R.collect(["collect", "--region", W2, "--no-k8s", "--global-from", str(source_root)], tmp_path,
                       monkeypatch, workdir_name="reuse")
    reused_root = sorted(set(reused.run_roots()) - {source_root, skipped_root})[0]
    manifest = R.load(reused_root / "manifest.json")
    assert manifest["run"]["global_source"]["run_id"] == source_root.name
    assert (reused_root / "global" / "iam").is_dir()
    assert reused.fake.calls_for(service="iam") == []       # global data copied, not re-collected
    assert R.validate_manifest(manifest) == []


# ── interruption (F-155) ─────────────────────────────────────────────────────
@pytest.mark.finding("F-155")
@pytest.mark.parametrize("signum, code", [(signal.SIGTERM, 143), (signal.SIGINT, 130)])
def test_a_signal_finalises_the_manifest_as_interrupted(tmp_path, monkeypatch, signum, code):
    R.fake_engine(monkeypatch)

    def interrupt(ctx):
        signal.raise_signal(signum)

    owner, attr = targets.collector_patch_point("lambda_")
    monkeypatch.setattr(owner, attr, interrupt)
    previous = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
    try:
        run = R.collect(["collect", "--region", W2, "--no-k8s"], tmp_path, monkeypatch)
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)
    manifest = run.manifest()
    assert run.exit_code == code
    assert (manifest["run"]["status"], manifest["run"]["exit_code"]) == ("interrupted", code)
    assert manifest["analysis"]["status"] == "not_run"
    assert R.validate_manifest(manifest) == []
    assert (run.run_root / "SHA256SUMS").is_file()


# ── privacy and permissions (F-123, F-066) ───────────────────────────────────
@pytest.mark.finding("F-123")
def test_files_are_0600_and_directories_0700(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--region", W2, "--no-k8s", "--zip"], tmp_path, monkeypatch)
    root = run.run_root
    paths = [root, *root.rglob("*")]
    assert {R.mode(p) for p in paths if p.is_dir()} == {0o700}
    assert {R.mode(p) for p in paths if p.is_file()} == {0o600}
    assert R.mode(root.parent) == 0o700                     # the account directory the run created
    assert R.mode(root.parent / f"{root.name}.zip") == 0o600


@pytest.mark.finding("F-123")
def test_redact_identity_keeps_the_caller_arn_out_of_the_run(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--region", W2, "--no-k8s", "--redact-identity"], tmp_path, monkeypatch)
    operator = run.manifest()["operator"]
    assert operator["redacted"] is True and operator["caller_arn"] is None and operator["caller_user_id"] is None
    assert operator["principal_arn"] == f"arn:aws:iam::{acme.ACCOUNT_ID}:role/demo-audit-role"
    assert len(operator["caller_arn_sha256"]) == 64
    caller, user_id = acme.CALLER["Arn"], acme.CALLER["UserId"]
    leaks = [p.relative_to(run.run_root).as_posix() for p in run.run_root.rglob("*") if p.is_file()
             and (caller in p.read_text(encoding="utf-8", errors="replace")
                  or user_id in p.read_text(encoding="utf-8", errors="replace"))]
    assert leaks == []
    assert caller not in run.err and user_id not in run.err


@pytest.mark.finding("F-066")
def test_output_inside_a_git_work_tree_needs_allow_in_repo(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    refused = R.collect(["collect", "--region", W2, "--no-k8s"], tmp_path, monkeypatch, out=repo / "reports",
                        workdir_name="refused")
    assert refused.exit_code == 64 and "inside the git work tree" in refused.err
    assert not (repo / "reports" / acme.ACCOUNT_ID).exists()
    allowed = R.collect(["collect", "--region", W2, "--no-k8s", "--allow-in-repo"], tmp_path, monkeypatch,
                        out=repo / "reports", workdir_name="allowed")
    assert allowed.exit_code in (0, 2) and allowed.run_roots()


# ── concurrency and resume (F-127) ───────────────────────────────────────────
@pytest.mark.finding("F-127")
def test_units_run_concurrently(tmp_path, monkeypatch):
    import threading

    R.fake_engine(monkeypatch)
    barrier = threading.Barrier(2, timeout=10)
    owner, attr = targets.collector_patch_point("ec2")
    real = getattr(owner, attr)
    assert targets.collector_base_module().is_ctx_protocol(real), "ec2 is a collect(ctx) collector"

    def collect(ctx):
        barrier.wait()            # both regional units must be inside ec2 at the same time
        return real(ctx)

    monkeypatch.setattr(owner, attr, collect)
    run = R.collect(["collect", "--regions", f"{W1},{W2}", "--modules", "ec2", "--concurrency", "2"], tmp_path,
                    monkeypatch)
    statuses = {(m["name"], m["region"]): m["status"] for m in run.manifest()["modules"]}
    assert statuses[("ec2", W1)] != "failed" and statuses[("ec2", W2)] != "failed", statuses


@pytest.mark.finding("F-127")
def test_resume_reruns_only_the_units_that_did_not_finish(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    world = acme.build_world()
    world.raise_exc("ec2", "DescribeInstances", botocore_error("EndpointConnectionError", endpoint_url="https://x"),
                    region=W1)
    first = R.collect(["collect", "--regions", f"{W1},{W2}", "--modules", "ec2,vpc", "--no-k8s"], tmp_path,
                      monkeypatch, world=world, workdir_name="first")
    root = first.run_root
    before = R.modules_by_unit(first.manifest())
    assert before[("ec2", W1)]["status"] in ("partial", "failed")
    w2_digest = (root / W2 / "ec2" / "_coverage.json").read_bytes()
    second = R.collect(["collect", "--resume", str(root)], tmp_path, monkeypatch, workdir_name="second")
    after = R.load(root / "manifest.json")
    entries = R.modules_by_unit(after)
    assert entries[("ec2", W1)]["resumed"] is True and entries[("ec2", W1)]["status"] == "ok"
    assert entries[("ec2", W2)]["resumed"] is False
    assert (root / W2 / "ec2" / "_coverage.json").read_bytes() == w2_digest
    assert {c.region for c in second.fake.calls_for(service="ec2", operation="DescribeInstances")} == {W1}
    assert len(after["run"]["resumes"]) == 1 and after["run"]["status"] in ("complete", "partial")
    assert not list(root.glob("*.stale-*"))
    assert R.validate_manifest(after) == []
    code, out, _err = R.invoke(["verify", str(root)], monkeypatch)
    assert (code, out.strip().split()[0]) == (0, "OK")


@pytest.mark.finding("F-127")
def test_resume_refuses_a_run_of_another_account(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    first = R.collect(["collect", "--region", W2, "--modules", "vpc"], tmp_path, monkeypatch, workdir_name="a")
    manifest = first.manifest()
    manifest["target"]["account_id"] = acme.EXTERNAL_ACCOUNT_ID
    (first.run_root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    second = R.collect(["collect", "--resume", str(first.run_root)], tmp_path, monkeypatch, workdir_name="b")
    assert second.exit_code == 1 and "belongs to account" in second.err


# ── zip, digests, hint (F-168, F-145) ────────────────────────────────────────
@pytest.mark.finding("F-168", "F-145")
def test_zip_is_deterministic_verifiable_and_the_hint_names_it(tmp_path, monkeypatch):
    import zipfile

    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--region", W2, "--no-k8s", "--zip"], tmp_path, monkeypatch)
    root = run.run_root
    archive = root.parent / f"{root.name}.zip"
    digest = targets.runtime_module("archive").file_sha256(archive)
    assert f"sha256 {digest}" in run.err and f"load {archive}" in run.err
    with zipfile.ZipFile(archive) as zf:
        names = zf.namelist()
        assert all(n.startswith(f"{root.name}/") for n in names)
        assert {f"{root.name}/{n}" for n in ("manifest.json", "HANDLING.txt", "SHA256SUMS", "run.log")} <= set(names)
    assert R.mode(archive) == 0o600
    code, out, _err = R.invoke(["verify", str(archive)], monkeypatch)
    assert code == 0 and out.startswith("OK ")
    archive.unlink()                                          # run.log has grown since: repackage twice
    code, out, _err = R.invoke(["package", str(root)], monkeypatch)
    assert (code, out.strip()) == (0, str(archive))
    first_bytes = archive.read_bytes()
    second = tmp_path / "again.zip"
    code, out, _err = R.invoke(["package", str(root), "--output", str(second)], monkeypatch)
    assert (code, out.strip()) == (0, str(second))
    assert second.read_bytes() == first_bytes                 # same run root, same bytes


@pytest.mark.finding("F-145")
def test_without_zip_the_summary_points_to_aws_enumerator_package(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--region", W2, "--no-k8s"], tmp_path, monkeypatch)
    assert f"aws-enumerator package {run.run_root}" in run.err and "aws-enumerator dashboard" in run.err


@pytest.mark.finding("F-168")
def test_sha256sums_verifies_with_coreutils_format(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--region", W2, "--no-k8s"], tmp_path, monkeypatch)
    root = run.run_root
    manifest = run.manifest()
    listed = {f["path"] for f in manifest["files"]}
    assert "analysis/graph.json" in listed and "HANDLING.txt" in listed
    assert not listed & {"manifest.json", "SHA256SUMS", "run.log"}
    lines = (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    assert lines == sorted(lines, key=lambda line: line[66:])
    assert all(re.match(r"^[0-9a-f]{64}  \S+$", line) for line in lines)
    sums = {line[66:]: line[:64] for line in lines}
    assert set(sums) == listed | {"manifest.json"}
    for rel, digest in sums.items():
        assert targets.fsio_module().sha256_file(root / rel) == digest


# ── logging (F-169) ──────────────────────────────────────────────────────────
@pytest.mark.finding("F-169")
def test_run_log_is_private_json_lines_with_the_run_id(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--region", W2, "--no-k8s"], tmp_path, monkeypatch)
    log_path = run.run_root / "run.log"
    assert R.mode(log_path) == 0o600
    records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert records and all(r["run_id"] == run.run_root.name for r in records)
    assert any(r.get("event") == "run.start" for r in records) and any(r.get("event") == "run.end" for r in records)
    assert "\x1b[" not in log_path.read_text(encoding="utf-8")
    assert "\x1b[" not in run.err                          # not a TTY: no colours


@pytest.mark.finding("F-123", "F-169")
def test_run_log_never_holds_absolute_local_paths(tmp_path, monkeypatch):
    """run.log travels inside the zip: like the manifest it must not leak the operator's local paths."""
    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--region", W2, "--modules", "vpc,iam", "--zip"], tmp_path, monkeypatch)
    assert str(run.run_root) in run.err                    # stderr still shows where the run went
    text = (run.run_root / "run.log").read_text(encoding="utf-8")
    assert str(tmp_path) not in text and str(tmp_path.resolve()) not in text
    assert any(json.loads(line).get("event") == "zip.written" for line in text.splitlines())


@pytest.mark.finding("F-169")
def test_json_log_format_on_stderr(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--region", W2, "--no-k8s", "--log-format", "json"], tmp_path, monkeypatch)
    records = [json.loads(line) for line in run.err.splitlines() if line.strip()]
    assert records and list(records[0])[:4] == ["ts", "level", "logger", "msg"]
    assert all(r["ts"].endswith("Z") for r in records)


# ── user agent (F-170) ───────────────────────────────────────────────────────
@pytest.mark.finding("F-170")
def test_clients_carry_the_app_id_with_the_run_id_unless_no_ua_tag(tmp_path, monkeypatch):
    captured = {}
    aws_session = targets.aws_session_module()
    real = aws_session.build_client_config

    def spy(options, bc):
        config = real(options, bc)
        captured.setdefault("ids", []).append(getattr(config, "user_agent_appid", None))
        return config

    monkeypatch.setattr(aws_session, "build_client_config", spy)
    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--region", W2, "--modules", "vpc", "--run-id", "demo-run-abc123"], tmp_path,
                    monkeypatch, workdir_name="tagged")
    version = targets.runtime_module("_version").__version__
    assert captured["ids"] == [f"aws-enumerator/{version}/abc123"], captured
    assert run.manifest()["run"]["run_id"] == "demo-run-abc123"
    captured.clear()
    R.collect(["collect", "--region", W2, "--modules", "vpc", "--no-ua-tag"], tmp_path, monkeypatch,
              workdir_name="untagged")
    assert captured["ids"] in ([""], [None])


# ── pre-flight (F-161) ───────────────────────────────────────────────────────
@pytest.mark.finding("F-161", "F-151")
def test_preflight_probe_reports_denied_modules_and_writes_nothing(tmp_path, monkeypatch):
    world = acme.build_world()
    world.deny("sns", "ListTopics")
    run = R.collect(["preflight", "--region", W2, "--modules", "sns,sqs,vpc"], tmp_path, monkeypatch, world=world)
    assert run.exit_code == 2
    rows = {line.split()[0]: line.split()[1] for line in run.out.splitlines()[1:]}
    assert rows == {"sns": "denied", "sqs": "ok", "vpc": "ok"}
    assert run.run_roots() == []


@pytest.mark.finding("F-161")
def test_collect_preflight_is_recorded_in_the_manifest(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--region", W2, "--modules", "sns,vpc", "--preflight"], tmp_path, monkeypatch)
    preflight = run.manifest()["preflight"]
    assert preflight["mode"] == "probe" and {r["module"] for r in preflight["results"]} == {"sns", "vpc"}
    assert R.validate_manifest(run.manifest()) == []


# ── collector options reach the collectors, file options are checked first (request c-b-3) ──
@pytest.mark.parametrize("flag", ["--scp-file", "--iam-gaad-file", "--kubeconfig", "--k8s-token-file",
                                  "--k8s-ca-file"])
def test_missing_option_files_are_usage_errors_before_any_call(tmp_path, monkeypatch, flag):
    run = R.collect(["collect", "--region", W2, flag, str(tmp_path / "missing.json")], tmp_path, monkeypatch)
    assert run.exit_code == 64 and "not a readable file" in run.err
    assert run.fake.calls_for() == [] and run.run_roots() == []


def test_collector_tuning_flags_reach_run_options(tmp_path, monkeypatch):
    seen = {}
    owner, attr = targets.collector_patch_point("ecs")
    real = getattr(owner, attr)

    def collect(ctx):
        seen.update({k: ctx.option(k) for k in ("ecs_max_revisions", "ebs_share_check", "keep_sensitive_metadata",
                                                "lambda_versions", "full_dns", "k8s", "max_rps", "rate_limit")})
        return real(ctx)

    monkeypatch.setattr(owner, attr, collect)
    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--region", W2, "--modules", "ecs", "--ecs-max-revisions", "0", "--ebs-share-check",
                     "none", "--keep-sensitive-metadata", "--full-dns", "--max-rps", "2", "--rate-limit", "k8s=1"],
                    tmp_path, monkeypatch)
    assert seen == {"ecs_max_revisions": 0, "ebs_share_check": "none", "keep_sensitive_metadata": True,
                    "lambda_versions": False, "full_dns": True, "k8s": True, "max_rps": 2.0,
                    "rate_limit": {"k8s": 1.0}}
    options = run.manifest()["run"]["options"]
    assert options["ecs_max_revisions"] == 0 and options["rate_limit"]["max_rps"] == 2.0


@pytest.mark.parametrize("flag, content", [("--suppress", "not json"), ("--baseline", '{"schema_version": "0.1"}')])
def test_invalid_analysis_inputs_are_usage_errors_before_any_collection(tmp_path, monkeypatch, flag, content):
    bad = tmp_path / "input.json"
    bad.write_text(content, encoding="utf-8")
    run = R.collect(["collect", "--region", W2, flag, str(bad)], tmp_path, monkeypatch)
    assert run.exit_code == 64, run.err[-1500:]
    assert run.fake.calls_for() == [] and run.run_roots() == []


@pytest.mark.finding("F-061", "F-155")
def test_a_fatal_preflight_error_still_finalises_the_manifest(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    world = acme.build_world()
    world.fail("sns", "ListTopics", "ExpiredToken", "The security token included in the request is expired", 400)
    run = R.collect(["collect", "--region", W2, "--modules", "sns", "--preflight"], tmp_path, monkeypatch, world=world)
    manifest = run.manifest()
    assert (run.exit_code, manifest["run"]["status"], manifest["run"]["exit_code"]) == (1, "failed", 1)
    assert run.stdout_lines() == [str(run.run_root)]
    assert R.validate_manifest(manifest) == []


def test_an_internal_error_finalises_the_manifest_before_propagating(tmp_path, monkeypatch):
    R.fake_engine(monkeypatch)
    runner = targets.runner_module()

    def broken(_run):
        raise RuntimeError("synthetic internal error")

    monkeypatch.setattr(runner, "_analyze", broken)
    run = R.collect(["collect", "--region", W2, "--modules", "vpc"], tmp_path, monkeypatch)
    assert run.exit_code == 1 and isinstance(run.exception, RuntimeError)
    manifest = run.manifest()
    assert (manifest["run"]["status"], manifest["run"]["exit_code"]) == ("failed", 1)
