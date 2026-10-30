"""``aws-enumerator merge`` (cli.md §3.8, manifest.md §3.11, D-42 to D-45, F-126).

Exit codes 0 / 64 / 1, the merged run root (exactly ``manifest.json``, ``HANDLING.txt``, ``analysis/graph.json``,
``SHA256SUMS``), the merge manifest, ``verify`` / ``package`` / ``export`` accepting the root and ``analyze``
refusing it. The two input runs are synthetic (``tests/fixtures/e-core/merge_runs.py``).
"""

from __future__ import annotations

import importlib
import json
import shutil
import stat

import pytest

from tests.python.orchestration import r_harness as R
from tests.support import targets

MR = importlib.import_module("tests.fixtures.e-core.merge_runs")
pytestmark = pytest.mark.finding("F-126")
RUN_ID = "demo-merge-1"


@pytest.fixture(scope="module")
def pair(tmp_path_factory):
    import os

    old = os.environ.get("SOURCE_DATE_EPOCH")
    os.environ["SOURCE_DATE_EPOCH"] = MR.EPOCH
    try:
        yield MR.two_accounts(tmp_path_factory.mktemp("merge-cli"))
    finally:
        if old is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = old


def _merge(monkeypatch, tmp_path, *runs, extra=()):
    out = tmp_path / "out"
    code, stdout, err = R.invoke(["merge", *map(str, runs), "--output", str(out), *extra], monkeypatch)
    return code, stdout, err, out


def test_merge_writes_the_merged_run_root(pair, tmp_path, monkeypatch):
    code, stdout, err, out = _merge(monkeypatch, tmp_path, pair.a, pair.b, extra=["--run-id", RUN_ID])
    assert code == 0, err[-2000:]
    root = out / "merged" / RUN_ID
    assert stdout.strip() == str(root)
    assert sorted(p.name for p in root.iterdir()) == ["HANDLING.txt", "SHA256SUMS", "analysis", "manifest.json"]
    assert sorted(p.name for p in (root / "analysis").iterdir()) == ["graph.json"]
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    for f in ("manifest.json", "HANDLING.txt", "SHA256SUMS", "analysis/graph.json"):
        assert stat.S_IMODE((root / f).stat().st_mode) == 0o600, f
    graph = json.loads((root / "analysis" / "graph.json").read_text())
    assert graph["schema_version"] == "1.1.0" and graph["run"]["mode"] == "merge"
    assert graph["run"]["run_id"] == RUN_ID
    assert targets.engine_module("writers.graph_json").problems(graph) == []


def test_the_merge_manifest_follows_manifest_3_11(pair, tmp_path, monkeypatch):
    code, _stdout, err, out = _merge(monkeypatch, tmp_path, pair.b, pair.a, extra=["--run-id", RUN_ID])
    assert code == 0, err[-2000:]
    root = out / "merged" / RUN_ID
    manifest = json.loads((root / "manifest.json").read_text())
    graph = json.loads((root / "analysis" / "graph.json").read_text())
    assert R.validate_manifest(manifest) == []
    run = manifest["run"]
    assert (run["kind"], run["status"], run["exit_code"], run["run_id"]) == ("merge", "complete", 0, RUN_ID)
    assert run["sources"] == [{"run_id": s["run_id"], "account_id": s["account_id"], "graph_sha256": s["graph_sha256"]}
                              for s in graph["run"]["sources"]]
    assert run["argv"] == ["merge", "<redacted>", "<redacted>", "--output", "<redacted>", "--run-id", RUN_ID]
    assert str(tmp_path) not in json.dumps(manifest)
    assert run["options"]["modules"] == [] and run["options"]["k8s"] is False
    target = manifest["target"]
    assert target["account_id"] == MR.ACCT_B and target["region_source"] == "merge"
    assert target["regions"] == ["eu-west-1", "eu-west-2"] and target["home_region"] == "us-east-1"
    assert manifest["operator"]["principal_type"] == "unknown" and manifest["operator"]["caller_arn"] is None
    assert manifest["modules"] == [] and manifest["preflight"] is None
    assert manifest["analysis"]["graph_schema_version"] == "1.1.0" and manifest["analysis"]["status"] == "ok"
    assert [f["path"] for f in manifest["files"]] == ["HANDLING.txt", "analysis/graph.json"]
    handling = (root / "HANDLING.txt").read_text()
    assert "CONFIDENTIAL" in handling and MR.ACCT_A in handling and MR.ACCT_B in handling


def test_verify_package_and_export_accept_the_merged_root_and_analyze_refuses_it(pair, tmp_path, monkeypatch):
    code, _stdout, err, out = _merge(monkeypatch, tmp_path, pair.a, pair.b, extra=["--run-id", RUN_ID])
    assert code == 0, err[-2000:]
    root = out / "merged" / RUN_ID
    code, stdout, err = R.invoke(["verify", str(root)], monkeypatch)
    assert code == 0, (stdout, err)
    before = sorted(p.name for p in root.iterdir())
    code, stdout, err = R.invoke(["analyze", str(root)], monkeypatch)
    assert code == 64 and "merged run cannot be re-analysed" in err
    assert sorted(p.name for p in root.iterdir()) == before
    code, _o, err = R.invoke(["export", str(root), "--format", "csv", "--output", "-"], monkeypatch)
    assert code in (0, 1) and "not an aws-enumerator report" not in err      # 1 until E-rules' writers land
    code, stdout, err = R.invoke(["package", str(root)], monkeypatch)
    assert code == 0, err[-2000:]
    assert stdout.strip() == str(out / "merged" / f"{RUN_ID}.zip")


@pytest.mark.parametrize("case", ["one-run", "no-graph", "nested-merge", "same-account", "existing-run-id",
                                  "bad-run-id", "git-work-tree"])
def test_unmergeable_inputs_exit_64_and_write_nothing(pair, tmp_path, monkeypatch, case):
    runs, extra = [pair.a, pair.b], []
    if case == "one-run":
        runs = [pair.a]
    elif case == "no-graph":
        empty = tmp_path / "demo-not-analysed"
        empty.mkdir()
        runs = [pair.a, empty]
    elif case == "nested-merge":
        code, _o, err, _out = _merge(monkeypatch, tmp_path / "first", pair.a, pair.b, extra=["--run-id", "nested"])
        assert code == 0, err
        runs = [tmp_path / "first" / "out" / "merged" / "nested", pair.a]
    elif case == "same-account":
        runs = [pair.a, shutil.copytree(pair.a, tmp_path / "copy-of-a")]
    elif case == "existing-run-id":
        (tmp_path / "out" / "merged" / RUN_ID).mkdir(parents=True)
        extra = ["--run-id", RUN_ID]
    elif case == "bad-run-id":
        extra = ["--run-id", "../escape"]
    elif case == "git-work-tree":
        (tmp_path / ".git").mkdir()
    before = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if "first" not in p.parts)
    code, stdout, err, _out = _merge(monkeypatch, tmp_path, *runs, extra=extra)
    assert (code, stdout) == (64, ""), err[-2000:]
    after = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if "first" not in p.parts)
    assert after == before


@pytest.mark.parametrize("case", ["unparsable", "newer-minor", "invalid"])
def test_unreadable_or_invalid_source_graphs_exit_1_and_write_nothing(pair, tmp_path, monkeypatch, case):
    bad = shutil.copytree(pair.b, tmp_path / "demo-bad")
    doc = MR.load_graph(bad)
    if case == "unparsable":
        MR.write_graph(bad, None, raw=b"\x00\x01 not json")
    elif case == "newer-minor":
        doc["schema_version"] = "1.7.0"
        MR.write_graph(bad, doc)
    else:
        doc["findings"].append(dict(doc["findings"][0]))       # a duplicated fingerprint
        MR.write_graph(bad, doc)
    code, stdout, err, out = _merge(monkeypatch, tmp_path, pair.a, bad)
    assert (code, stdout) == (1, ""), err[-2000:]
    assert not out.exists()


def test_an_unwritable_output_exits_1(pair, tmp_path, monkeypatch):
    blocked = tmp_path / "out"
    blocked.write_text("a file where the output root should be", encoding="utf-8")
    code, stdout, err = R.invoke(["merge", str(pair.a), str(pair.b), "--output", str(blocked)], monkeypatch)
    assert (code, stdout) == (1, ""), err[-2000:]


def test_merge_help_documents_the_command(monkeypatch):
    code, stdout, _err = R.invoke(["merge", "--help"], monkeypatch)
    assert code == 0 and "not available" not in stdout
    assert "RUN_DIR" in stdout and "graph.json 1.1" in " ".join(stdout.split())
