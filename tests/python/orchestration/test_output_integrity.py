"""Run layout, manifest store, digests, archives (report-layout.md, manifest.md; F-063, F-066, F-123, F-159,
F-168, F-171)."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tests.python.orchestration import r_harness as R
from tests.support import targets

OUT = targets.runtime_module("output")
INTEG = targets.runtime_module("integrity")
A = targets.runtime_module("archive")
FS = targets.fsio_module()


# ── run id, output root, git guard ───────────────────────────────────────────
@pytest.mark.finding("F-063", "F-171")
def test_run_ids_are_utc_unique_and_sort_chronologically():
    early = datetime(2026, 10, 15, 10, 15, 0, tzinfo=timezone(timedelta(hours=5)))
    first = OUT.new_run_id(early)
    assert re.match(r"^20261015T051500Z-[0-9a-f]{6}$", first)       # converted to UTC
    later = OUT.new_run_id(early + timedelta(seconds=1))
    assert sorted([later, first]) == [first, later]
    assert len({OUT.new_run_id(early) for _ in range(50)}) > 1


@pytest.mark.parametrize("bad", ["", ".", "..", "../x", "a/b", "x" * 65, "white space"])
def test_bad_run_ids_are_usage_errors(bad):
    with pytest.raises(OUT.OutputUsageError):
        OUT.validate_run_id(bad)


@pytest.mark.finding("F-063")
def test_output_root_precedence(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("AWS_ENUMERATOR_OUTPUT", raising=False)
    assert OUT.resolve_output_root(None) == tmp_path / "home" / ".aws-enumerator" / "reports"
    monkeypatch.setenv("AWS_ENUMERATOR_OUTPUT", str(tmp_path / "env"))
    assert OUT.resolve_output_root(None) == tmp_path / "env"
    assert OUT.resolve_output_root(str(tmp_path / "flag")) == tmp_path / "flag"


@pytest.mark.finding("F-066")
def test_git_guard(tmp_path):
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    with pytest.raises(OUT.OutputUsageError, match="inside the git work tree"):
        OUT.git_guard(tmp_path / "repo" / "a" / "b", allow=False)
    OUT.git_guard(tmp_path / "repo" / "a", allow=True)
    OUT.git_guard(tmp_path / "elsewhere", allow=False)


@pytest.mark.finding("F-063")
def test_an_existing_run_id_is_refused(tmp_path):
    layout = OUT.RunLayout(tmp_path, "111122223333", "demo-run")
    OUT.create_run_root(layout)
    assert stat.S_IMODE(layout.run_root.stat().st_mode) == 0o700
    with pytest.raises(OUT.OutputUsageError, match="already exists"):
        OUT.create_run_root(layout)


@pytest.mark.finding("F-159")
def test_handling_notice_is_the_fixed_text(tmp_path):
    layout = OUT.RunLayout(tmp_path, "111122223333", "demo-run")
    OUT.create_run_root(layout)
    OUT.write_handling(layout, "2026-10-15T10:15:00Z")
    text = layout.handling_path.read_text(encoding="utf-8")
    assert text == OUT.HANDLING_TEMPLATE.format(run_id="demo-run", account_id="111122223333",
                                              started_at="2026-10-15T10:15:00Z")
    assert text.startswith("aws-enumerator report: CONFIDENTIAL") and "Treat it like a credential." in text
    assert stat.S_IMODE(layout.handling_path.stat().st_mode) == 0o600


#: The qualified exclusion statement (request doc1-1 #2): the collectors leave secret values out by design, but
#: free text (names, tags, policy documents, configuration) is copied as it is and can hold a secret.
QUALIFIED_EXCLUSIONS = (
    "The collectors are designed to leave out secret values (no S3 objects, no secret or parameter\n"
    "values, no Kubernetes Secret data, no environment-variable values), but names, tags, policy\n"
    "documents and configuration are copied as they are and may hold more than intended.\n"
)


@pytest.mark.finding("F-159", "F-067")
def test_handling_notice_qualifies_the_secret_exclusions_instead_of_promising_none():
    text = OUT.handling_text("demo-run", "111122223333", "2026-10-15T10:15:00Z")
    assert text.endswith(QUALIFIED_EXCLUSIONS)
    for claim in ("no secret values by design", "contains no secret", "never contains"):
        assert claim not in text.lower(), claim


@pytest.mark.finding("F-159", "F-067")
def test_handling_notice_matches_the_report_layout_contract():
    contract = (targets.REPO_ROOT / "docs" / "contracts" / "report-layout.md").read_text(encoding="utf-8")
    section = contract.split("## 6. HANDLING.txt", 1)[1].split("\n---", 1)[0]
    block = re.search(r"^```\n(.*?)^```$", section, re.M | re.S)
    assert block, "report-layout.md §6 has no fenced HANDLING.txt block"
    assert block.group(1) == OUT.HANDLING_TEMPLATE


# ── manifest store ───────────────────────────────────────────────────────────
class _Result:
    def __init__(self, name, region, status, scope="regional", denied=()):
        self.name, self.region, self.status, self.scope = name, region, status, scope
        self.denied_apis = list(denied)

    def manifest_entry(self):
        return {"name": self.name, "scope": self.scope, "region": self.region, "status": self.status,
                "status_reason": None, "started_at": None, "ended_at": None, "duration_seconds": None,
                "error": None, "coverage": None, "throttle_events": 0, "resumed": False, "dir": None}


def _store(tmp_path):
    tool = targets.runtime_module("buildinfo").tool_info()
    run = {"run_id": "demo-run", "started_at": "2026-10-15T10:15:00Z", "argv": ["collect"],
           "options": {"regions_requested": ["eu-west-1", "eu-west-2"], "modules": ["iam", "ec2"],
                       "skipped_modules": [], "k8s": True, "k8s_secrets": False, "concurrency": 3,
                       "rate_limit": {"enabled": True, "default_rps": 5.0, "max_rps": None, "overrides": {}},
                       "max_tier": 2, "deny_breaker": 3, "redact_identity": False}}
    target = {"account_id": "111122223333", "partition": "aws", "home_region": "eu-west-2",
              "global_region": "us-east-1", "regions": ["eu-west-1", "eu-west-2"], "region_source": "explicit",
              "regions_skipped": []}
    operator = {"caller_arn": None, "caller_user_id": None, "caller_arn_sha256": "0" * 64,
                "principal_arn": "arn:aws:iam::111122223333:role/demo", "principal_type": "assumed-role",
                "redacted": True}
    return OUT.ManifestStore.new(tmp_path / "manifest.json", tool=tool, run=run, target=target, operator=operator,
                               order={"iam": 0, "ec2": 1})


@pytest.mark.finding("F-061", "F-155", "F-171")
def test_manifest_lifecycle_order_summary_and_schema(tmp_path):
    store = _store(tmp_path)
    store.save()
    doc = R.load(tmp_path / "manifest.json")
    assert doc["run"]["status"] == "in_progress" and doc["analysis"]["status"] == "not_run"
    assert R.validate_manifest(doc) == []
    assert list(doc["run"])[:3] == ["run_id", "kind", "status"]
    store.record([_Result("ec2", "eu-west-2", "partial", denied=["ec2:DescribeInstances"]),
                  _Result("ec2", "eu-west-1", "ok"), _Result("iam", "global", "denied", "global", ["iam:ListUsers"])])
    entries = [(e["name"], e["region"]) for e in store.entries()]
    assert entries == [("iam", "global"), ("ec2", "eu-west-1"), ("ec2", "eu-west-2")]
    summary = store.get("coverage_summary")
    assert summary["modules_by_status"] == {"ok": 1, "partial": 1, "denied": 1}
    assert summary["partial_modules"] == ["ec2@eu-west-2"]
    assert summary["denied_apis"] == [{"api": "ec2:DescribeInstances", "regions": ["eu-west-2"]},
                                      {"api": "iam:ListUsers", "regions": ["global"]}]
    store.finalize(status="partial", exit_code=2, ended_at=datetime(2026, 10, 15, 10, 16, 1, tzinfo=timezone.utc),
                   files=[])
    doc = R.load(tmp_path / "manifest.json")
    assert (doc["run"]["ended_at"], doc["run"]["duration_seconds"]) == ("2026-10-15T10:16:01Z", 61.0)
    assert R.validate_manifest(doc) == []
    reloaded = OUT.ManifestStore.load(tmp_path / "manifest.json")
    assert [(e["name"], e["region"]) for e in reloaded.entries()] == entries


# ── digests and verify (F-168) ───────────────────────────────────────────────
def _write(root: Path, rel: str, text: str = "{}") -> None:
    FS.atomic_write_text(root / rel, text)


def _finished_run(tmp_path: Path) -> Path:
    root = tmp_path / "111122223333" / "demo-run"
    store = _store(tmp_path)
    FS.ensure_dir(root)
    store.path = root / "manifest.json"
    for rel in ("global/iam/roles.json", "eu-west-2/ec2/instances.json", "analysis/graph.json", "HANDLING.txt"):
        _write(root, rel)
    _write(root, "run.log", "")
    _write(root, "analysis/exports/findings.csv", "x")
    _write(root, "analysis.tmp/graph.json")
    _write(root, "eu-west-2.stale-1/ec2/instances.json")
    files = INTEG.compute_files(root)
    store.finalize(status="complete", exit_code=0, ended_at=datetime.now(timezone.utc), files=files)
    INTEG.write_sha256sums(root, files)
    shutil.rmtree(root / "analysis.tmp")
    shutil.rmtree(root / "eu-west-2.stale-1")
    return root


@pytest.mark.finding("F-168")
def test_manifest_files_exclusions_and_coreutils_sums(tmp_path):
    root = _finished_run(tmp_path)
    listed = [f["path"] for f in R.load(root / "manifest.json")["files"]]
    assert listed == ["HANDLING.txt", "analysis/graph.json", "eu-west-2/ec2/instances.json", "global/iam/roles.json"]
    if shutil.which("shasum") or shutil.which("sha256sum"):
        cmd = ["shasum", "-a", "256", "-c", "SHA256SUMS"] if shutil.which("shasum") else ["sha256sum", "-c",
                                                                                          "SHA256SUMS"]
        assert subprocess.run(cmd, cwd=root, capture_output=True, check=False).returncode == 0
    report = INTEG.verify_path(root)
    assert report.ok and report.lines() == ["OK 5 files"]


@pytest.mark.finding("F-168")
def test_verify_reports_mismatch_missing_unlisted_and_schema_problems(tmp_path):
    root = _finished_run(tmp_path)
    (root / "global" / "iam" / "roles.json").write_text('{"tampered": true}', encoding="utf-8")
    (root / "eu-west-2" / "ec2" / "instances.json").unlink()
    _write(root, "eu-west-2/ec2/extra.json")
    lines = INTEG.verify_path(root).lines()
    assert "MISMATCH global/iam/roles.json" in lines
    assert "MISSING eu-west-2/ec2/instances.json" in lines
    assert "UNLISTED eu-west-2/ec2/extra.json" in lines
    doc = R.load(root / "manifest.json")
    doc["run"]["status"] = "bogus"
    (root / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
    lines = INTEG.verify_path(root).lines()
    assert "MISMATCH manifest.json" in lines and any(line.startswith("INVALID manifest.json") for line in lines)


def test_symlinks_are_never_listed(tmp_path):
    root = tmp_path / "run"
    _write(root, "global/iam/roles.json")
    os.symlink("/etc/hosts", root / "global" / "iam" / "link.json")
    assert [f["path"] for f in INTEG.compute_files(root)] == ["global/iam/roles.json"]


# ── archives, encryption, signing (F-168, F-123, F-145) ──────────────────────
@pytest.mark.finding("F-168", "F-123")
def test_zip_is_deterministic_private_and_complete(tmp_path):
    root = _finished_run(tmp_path)
    manifest = R.load(root / "manifest.json")
    one = A.build_zip(root, tmp_path / "one.zip", manifest)
    two = A.build_zip(root, tmp_path / "two.zip", manifest)
    assert one.read_bytes() == two.read_bytes()
    assert stat.S_IMODE(one.stat().st_mode) == 0o600
    with zipfile.ZipFile(one) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        names = [i.filename for i in infos]
        assert names == sorted(names)
        assert {n.split("/", 1)[1] for n in names} == {f["path"] for f in manifest["files"]} | {
            "manifest.json", "SHA256SUMS", "run.log"}
        assert all(i.date_time == (2026, 10, 15, 10, 15, 0) for i in infos)
        assert all((i.external_attr >> 16) & 0o777 == 0o600 for i in infos)
    assert INTEG.verify_path(one).ok


@pytest.mark.parametrize("value, allowed", [("rot13:x", A.ENCRYPT_TOOLS), ("age:", A.ENCRYPT_TOOLS),
                                            ("age:-r", A.ENCRYPT_TOOLS), ("pgp:key", A.SIGN_TOOLS)])
def test_bad_tool_specs(value, allowed):
    with pytest.raises(ValueError):
        A.parse_tool_spec(value, allowed, "--flag")


def _fake_tools(tmp_path: Path, monkeypatch, *, fail: bool = False) -> Path:
    """``age``, ``gpg`` and ``minisign`` stand-ins: copy the input to the -o/--output file (exit 1 with fail)."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = ("#!/bin/sh\n" + ("echo 'tool failed: bad recipient' >&2; exit 1\n" if fail else "") +
              'out=""; in=""; prev=""; last=""\n'
              'for a in "$@"; do\n'
              '  case "$prev" in --output|-x) out="$a";; -m) in="$a";; esac\n'
              '  prev="$a"; last="$a"\n'
              'done\n'
              '[ -n "$in" ] || in="$last"\n'
              'cp "$in" "$out"\n')
    for tool in ("age", "gpg", "minisign"):
        path = bindir / tool
        path.write_text(script, encoding="utf-8")
        path.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return bindir


@pytest.mark.finding("F-123", "F-168")
def test_encrypt_removes_the_plain_zip_and_sign_writes_a_private_signature(tmp_path, monkeypatch):
    _fake_tools(tmp_path, monkeypatch)
    root = _finished_run(tmp_path)
    plain = A.build_zip(root, tmp_path / "run.zip", R.load(root / "manifest.json"))
    encrypted = A.encrypt(plain, ("age", "age1example"))
    assert encrypted.name == "run.zip.age" and not plain.exists()
    assert stat.S_IMODE(encrypted.stat().st_mode) == 0o600
    signature = A.sign(encrypted, ("minisign", str(tmp_path / "demo.key")))
    assert signature.name == "run.zip.age.minisig" and stat.S_IMODE(signature.stat().st_mode) == 0o600


@pytest.mark.finding("F-123")
def test_missing_or_failing_tools_are_archive_errors(tmp_path, monkeypatch):
    root = _finished_run(tmp_path)
    plain = A.build_zip(root, tmp_path / "run.zip", R.load(root / "manifest.json"))
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    with pytest.raises(A.ArchiveError, match="not installed"):
        A.encrypt(plain, ("gpg", "demo@example.com"))
    _fake_tools(tmp_path, monkeypatch, fail=True)
    with pytest.raises(A.ArchiveError, match="bad recipient"):
        A.encrypt(plain, ("gpg", "demo@example.com"))
    assert plain.exists()                                      # the plain zip is kept when encryption fails


@pytest.mark.finding("F-123", "F-145")
def test_collect_encrypt_and_sign_end_to_end(tmp_path, monkeypatch):
    _fake_tools(tmp_path, monkeypatch)
    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--region", "eu-west-2", "--modules", "vpc", "--encrypt", "age:age1example",
                     "--sign", "minisign:/dev/null"], tmp_path, monkeypatch)
    root = run.run_root
    assert (root.parent / f"{root.name}.zip.age").is_file() and not (root.parent / f"{root.name}.zip").exists()
    assert (root.parent / f"{root.name}.zip.age.minisig").is_file()
    assert run.manifest()["run"]["options"]["zip"] is True
    assert f"load {root.parent / f'{root.name}.zip.age'}" in run.err


def test_collect_with_a_missing_encryption_tool_fails_before_any_aws_call(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    run = R.collect(["collect", "--region", "eu-west-2", "--encrypt", "gpg:demo@example.com"], tmp_path,
                    monkeypatch)
    assert run.exit_code == 1 and run.fake.calls_for() == [] and run.run_roots() == []


@pytest.mark.finding("F-168")
def test_collect_sign_alone_implies_the_zip(tmp_path, monkeypatch):
    _fake_tools(tmp_path, monkeypatch)
    R.fake_engine(monkeypatch)
    run = R.collect(["collect", "--region", "eu-west-2", "--modules", "vpc", "--sign", "minisign:/dev/null"],
                    tmp_path, monkeypatch)
    root = run.run_root
    assert (root.parent / f"{root.name}.zip").is_file() and (root.parent / f"{root.name}.zip.minisig").is_file()
    assert run.exit_code in (0, 2)
