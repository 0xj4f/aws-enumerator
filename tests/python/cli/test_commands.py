"""Offline subcommands: analyze, export, merge, dashboard, modules, package, verify (cli.md §3.2-§3.10)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.python.orchestration import r_harness as R
from tests.support import targets

W2 = "eu-west-2"


@pytest.fixture(scope="module")
def finished_run(tmp_path_factory):
    """One small acme run collected with --no-analysis (each test copies it before changing it)."""
    mp = pytest.MonkeyPatch()
    tmp = tmp_path_factory.mktemp("cmd-run")
    try:
        run = R.collect(["collect", "--region", W2, "--modules", "vpc,sg", "--no-analysis"], tmp, mp)
        assert run.exit_code in (0, 2), run.err[-2000:]
        return run.run_root
    finally:
        mp.undo()


@pytest.fixture
def run_root(finished_run, tmp_path):
    copy = tmp_path / "111122223333" / finished_run.name
    shutil.copytree(finished_run, copy)
    return copy


# ── analyze ──────────────────────────────────────────────────────────────────
@pytest.mark.finding("F-010", "F-168")
def test_analyze_a_v2_run_updates_the_manifest_and_the_digests(run_root, monkeypatch):
    before = R.load(run_root / "manifest.json")
    assert before["analysis"]["status"] == "skipped"            # --no-analysis
    calls = R.fake_engine(monkeypatch)
    code, out, err = R.invoke(["analyze", str(run_root)], monkeypatch)
    assert code == 0, err
    assert out.strip() == str(run_root / "analysis")
    manifest = R.load(run_root / "manifest.json")
    assert manifest["analysis"]["status"] == "ok" and manifest["analysis"]["engine"] == "v2"
    assert manifest["run"]["status"] == before["run"]["status"]  # analyze never changes run.status
    assert "analysis/graph.json" in {f["path"] for f in manifest["files"]}
    assert R.validate_manifest(manifest) == []
    assert len(calls) == 1 and calls[0].regions == [W2]
    code, out, _err = R.invoke(["verify", str(run_root)], monkeypatch)
    assert code == 0 and out.startswith("OK ")


@pytest.mark.parametrize("status, code", [("partial", 2), ("error", 1)])
def test_analyze_exit_code_follows_the_engine_result(run_root, monkeypatch, status, code):
    R.fake_engine(monkeypatch, status=status)
    got, _out, _err = R.invoke(["analyze", str(run_root)], monkeypatch)
    assert got == code
    expected = {"partial": "partial", "error": "failed"}[status]
    assert R.load(run_root / "manifest.json")["analysis"]["status"] == expected


def test_analyze_refuses_an_in_progress_run_unless_forced(run_root, monkeypatch):
    doc = R.load(run_root / "manifest.json")
    doc["run"]["status"] = "in_progress"
    (run_root / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
    R.fake_engine(monkeypatch)
    code, _out, err = R.invoke(["analyze", str(run_root)], monkeypatch)
    assert code == 64 and "in progress" in err
    code, _out, _err = R.invoke(["analyze", str(run_root), "--force"], monkeypatch)
    assert code == 0


@pytest.mark.finding("F-010")
def test_analyze_a_legacy_layout(tmp_path, monkeypatch):
    report = tmp_path / "reports" / "20261015" / "111122223333"
    (report / "global" / "iam").mkdir(parents=True)
    seen = {}

    def analyze_report(path, options=None):
        seen["path"] = path
        (Path(path) / "analysis").mkdir()
        return SimpleNamespace(status="ok", analysis_dir=str(Path(path) / "analysis"), graph_schema_version="1.0")

    monkeypatch.setattr(targets.engine_module(""), "analyze_report", analyze_report, raising=False)
    code, out, err = R.invoke(["analyze", str(report)], monkeypatch)
    assert code == 0, err
    assert seen["path"] == str(report) and out.strip() == str(report / "analysis")


@pytest.mark.parametrize("argv_tail, needle", [([], "not an aws-enumerator report"),
                                               (["--baseline", "/nonexistent/base.json"], "does not exist")])
def test_analyze_usage_errors(tmp_path, monkeypatch, argv_tail, needle):
    target = tmp_path / "x"
    target.mkdir()
    if argv_tail:
        (target / "iam").mkdir()
    code, out, err = R.invoke(["analyze", str(target), *argv_tail], monkeypatch)
    assert (code, out) == (64, "") and needle in err


@pytest.mark.finding("F-066")
def test_analyze_inside_a_git_work_tree_needs_allow_in_repo(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    report = tmp_path / "old" / "111122223333"
    (report / "iam").mkdir(parents=True)
    code, _out, err = R.invoke(["analyze", str(report)], monkeypatch)
    assert code == 64 and "inside the git work tree" in err


# ── export ───────────────────────────────────────────────────────────────────
def test_export_without_graph_json_tells_the_user_to_analyze(run_root, monkeypatch):
    code, out, err = R.invoke(["export", str(run_root), "--format", "sarif"], monkeypatch)
    assert (code, out) == (64, "") and "aws-enumerator analyze" in err


def _with_graph(run_root: Path) -> None:
    (run_root / "analysis").mkdir(exist_ok=True)
    (run_root / "analysis" / "graph.json").write_text(json.dumps({"schema_version": "1.0", "findings": []}),
                                                      encoding="utf-8")


class _Writers:
    EXPORT_FORMATS = {"csv": ("csv", "findings.csv", "text/csv")}

    def __init__(self, behaviour="ok"):
        self.behaviour, self.calls = behaviour, []

    def export(self, graph, fmt, **kwargs):
        self.calls.append((fmt, kwargs))
        if self.behaviour == "missing":
            raise NotImplementedError(fmt)
        if self.behaviour == "bad":
            raise ValueError("unknown format")
        return b"severity,id\r\n"

    def export_file_name(self, fmt):
        return self.EXPORT_FORMATS[fmt][1]


def _install_writers(monkeypatch, writers):
    import sys

    engine = targets.engine_module("")
    monkeypatch.setattr(engine, "writers", writers, raising=False)
    monkeypatch.setitem(sys.modules, f"{engine.__name__}.writers", writers)


def test_export_writes_through_the_engine_writer_api(run_root, monkeypatch):
    _with_graph(run_root)
    writers = _Writers()
    _install_writers(monkeypatch, writers)
    code, out, err = R.invoke(["export", str(run_root), "--format", "csv", "--min-severity", "HIGH"], monkeypatch)
    dest = run_root / "analysis" / "exports" / "findings.csv"
    assert (code, out.strip()) == (0, str(dest)), err
    assert dest.read_bytes() == b"severity,id\r\n" and R.mode(dest) == 0o600
    assert writers.calls == [("csv", {"min_severity": "high", "include_suppressed": False, "all_edges": False})]
    code, out, _err = R.invoke(["export", str(run_root), "--format", "csv", "--output", "-"], monkeypatch)
    assert (code, out) == (0, "severity,id\r\n")


@pytest.mark.parametrize("behaviour, code", [("missing", 1), ("bad", 64)])
def test_export_unavailable_or_rejected_formats(run_root, monkeypatch, behaviour, code):
    _with_graph(run_root)
    _install_writers(monkeypatch, _Writers(behaviour))
    got, out, err = R.invoke(["export", str(run_root), "--format", "sarif"], monkeypatch)
    assert (got, out) == (code, "")
    if behaviour == "missing":
        assert "not available in this build" in err


def test_export_with_the_real_engine_build_never_crashes(run_root, monkeypatch):
    _with_graph(run_root)
    code, _out, _err = R.invoke(["export", str(run_root), "--format", "opengraph"], monkeypatch)
    assert code in (0, 1)        # 1 until the E-rules writers exist ("not available in this build")


# ── merge (graph 1.1, D-42 to D-45; the full suite is tests/python/cli/test_merge_command.py) ──
@pytest.mark.finding("F-126")
def test_merge_of_missing_directories_is_a_usage_error(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_ENUMERATOR_OUTPUT", str(tmp_path / "out"))
    code, out, err = R.invoke(["merge", str(tmp_path / "a"), str(tmp_path / "b")], monkeypatch)
    assert (code, out) == (64, "") and "not a directory" in err
    assert not (tmp_path / "out").exists()


# ── dashboard (F-128/F-129/F-139 server side is Du's; the CLI validates and passes through) ──
def _fake_server(monkeypatch, *, result=True, error=None):
    """A ``serve_dashboard`` with the real signature (r-1, cli.md §3.7) that records its arguments."""
    server = targets.dashboard_server_module()
    calls = []

    def serve(host="127.0.0.1", port=8000, open_browser=True, allowed_hosts=(), on_listening=None):
        calls.append(dict(host=host, port=port, open_browser=open_browser, allowed_hosts=allowed_hosts))
        if error is not None:
            raise error
        if on_listening is not None and result:          # the real server announces only a bound socket
            on_listening(f"http://{host}:54321/index.html")
        return result

    monkeypatch.setattr(server, "serve_dashboard", serve)
    return calls


def test_the_fake_server_has_the_real_signature():
    import inspect

    real = inspect.signature(targets.dashboard_server_module().serve_dashboard)
    assert list(real.parameters) == ["host", "port", "open_browser", "allowed_hosts", "on_listening"]


@pytest.mark.finding("F-129")
def test_dashboard_passes_validated_options(monkeypatch):
    calls = _fake_server(monkeypatch)
    code, out, err = R.invoke(["dashboard", "--port", "0", "--no-browser", "--allowed-host", "demo.localhost"],
                              monkeypatch)
    assert code == 0, err
    assert out == "http://127.0.0.1:54321/index.html\n"          # the bound URL is the only stdout line
    assert calls == [dict(host="127.0.0.1", port=0, open_browser=False, allowed_hosts=("demo.localhost",))]


@pytest.mark.finding("F-128")
def test_dashboard_on_a_non_loopback_host_warns_and_never_opens_a_browser(monkeypatch):
    calls = _fake_server(monkeypatch)
    code, _out, err = R.invoke(["dashboard", "--host", "0.0.0.0"], monkeypatch)
    assert code == 0 and calls[0]["open_browser"] is False and "reachable beyond this machine" in err
    assert calls[0]["host"] == "0.0.0.0"


@pytest.mark.finding("F-129")
@pytest.mark.parametrize("kwargs", [{"result": False}, {"error": OSError(48, "Address already in use")}])
def test_dashboard_exits_1_when_no_port_binds(monkeypatch, kwargs):
    _fake_server(monkeypatch, **kwargs)
    code, out, _err = R.invoke(["dashboard", "--port", "8000", "--no-browser"], monkeypatch)
    assert (code, out) == (1, "")


def test_legacy_dashboard_flag_still_works(monkeypatch):
    calls = _fake_server(monkeypatch)
    code, _out, err = R.invoke(["--dashboard", "--port", "9000"], monkeypatch)
    assert code == 0 and "deprecated" in err
    assert calls == [dict(host="127.0.0.1", port=9000, open_browser=True, allowed_hosts=())]


# ── modules ──────────────────────────────────────────────────────────────────
def test_modules_table_and_json(monkeypatch):
    names = targets.registry_names()
    code, out, _err = R.invoke(["modules"], monkeypatch)
    lines = out.splitlines()
    assert code == 0 and lines[0].split()[:4] == ["name", "scope", "default", "tier"]
    assert [line.split()[0] for line in lines[1:]] == names
    code, out, _err = R.invoke(["modules", "--format", "json"], monkeypatch)
    assert code == 0 and [m["name"] for m in json.loads(out)] == names


# ── package / verify (F-145, F-168) ──────────────────────────────────────────
@pytest.mark.finding("F-145")
def test_package_usage_errors(run_root, tmp_path, monkeypatch):
    code, _out, err = R.invoke(["package", str(tmp_path / "nope")], monkeypatch)
    assert code == 64 and "not a v2 aws-enumerator run" in err
    doc = R.load(run_root / "manifest.json")
    doc["run"]["status"] = "in_progress"
    (run_root / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
    code, _out, err = R.invoke(["package", str(run_root)], monkeypatch)
    assert code == 64 and "--force" in err
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    code, _out, err = R.invoke(["package", str(run_root), "--force", "--encrypt", "age:age1example"], monkeypatch)
    assert code == 1 and "not installed" in err


@pytest.mark.finding("F-145")
def test_package_output_into_a_directory(run_root, tmp_path, monkeypatch):
    out_dir = tmp_path / "bundles"
    out_dir.mkdir()
    code, out, err = R.invoke(["package", str(run_root), "--output", str(out_dir)], monkeypatch)
    assert code == 0, err
    assert out.strip() == str(out_dir / f"{run_root.name}.zip") and R.mode(out_dir / f"{run_root.name}.zip") == 0o600


@pytest.mark.finding("F-168")
def test_verify_detects_tampering(run_root, tmp_path, monkeypatch):
    code, out, _err = R.invoke(["verify", str(run_root)], monkeypatch)
    assert code == 0 and out.startswith("OK ")
    data_file = next(p for p in (run_root / W2).rglob("*.json") if p.name != "_coverage.json")
    data_file.write_text("[]", encoding="utf-8")
    code, out, _err = R.invoke(["verify", str(run_root)], monkeypatch)
    assert code == 1 and f"MISMATCH {data_file.relative_to(run_root).as_posix()}" in out.splitlines()
    legacy = tmp_path / "legacy"
    (legacy / "iam").mkdir(parents=True)
    code, _out, _err = R.invoke(["verify", str(legacy)], monkeypatch)
    assert code == 64
    code, _out, _err = R.invoke(["verify", str(tmp_path / "missing")], monkeypatch)
    assert code == 64
