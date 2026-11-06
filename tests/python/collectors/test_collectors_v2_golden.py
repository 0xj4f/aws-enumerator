"""Goldens of a full ``collect`` run of the 36 collectors against the synthetic ``acme`` world (collectors-v2).

``aws-enumerator collect`` runs through the routed fake AWS and the fake Kubernetes API in single-region mode
(``--region eu-west-2 --run-id golden-single``) and in ``--all`` mode (``--all --run-id golden-all``: eu-west-1 and
eu-west-2), each with a pinned analysis clock (``$SOURCE_DATE_EPOCH``) and a pinned build sha
(``$AWS_ENUMERATOR_GIT_SHA``). The v2 run tree ``<account>/<run_id>/`` (report-layout.md §1) is compared with
``tests/golden/collectors-v2/{single,all}/`` after normalisation: canonical JSON (sorted keys and lists), the date
directory stripped, the clock fields and the manifest digests of run-unique files masked
(``legacy_harness.LegacyRun.normalised_tree``), the interpreter and library versions of the manifest ``tool`` block
masked. ``run.log``, ``HANDLING.txt`` and ``SHA256SUMS`` are not JSON and not compared (the canary scan reads them).

``calls-{single,all}.json`` hold the recorded AWS / Kubernetes call inventory per collector module (the read-only
API inventory: service:Operation, regions, outcomes, parameter names), the region discovery and the engine
analysis calls; ``console-{single,all}.json`` the module statuses that are neither ``ok`` nor ``skipped`` and the
collectors' WARNING/ERROR records.

These replace the Wave 0 ``collectors-v0`` goldens (the d13c215 collectors and ``main()``) and the d13c215
``--all`` orchestration golden ``legacy/all_mode_main``; every difference was reviewed against the stream ledgers
(``tests/golden/CHANGES.d/i1-reconcile.md``). Regenerate only with ``pytest --update-golden`` and a ledger entry.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict

import pytest

from tests.fixtures.worlds import acme
from tests.python.collectors.legacy_harness import RUN_ID_TOKEN, LegacyRun, date_free, run_legacy_main
from tests.support import canonical, targets
from tests.support.fakeaws import READ_ONLY_PREFIXES

pytestmark = [pytest.mark.golden, pytest.mark.collectors]

GOLDEN_ROOT = Path(targets.REPO_ROOT) / "tests" / "golden" / "collectors-v2"

#: A fixed run id per mode keeps every path stable (report-layout.md §1.2; request r-2).
RUN_IDS = {"single": "golden-single", "all": "golden-all"}
MODES = {
    "single": ["collect", "--region", acme.SINGLE_REGION, "--run-id", RUN_IDS["single"]],
    "all": ["collect", "--all", "--run-id", RUN_IDS["all"]],
}
#: The analysis clock of the golden runs (2026-01-01T00:00:00Z): ``generated_at`` and the IAM hygiene
#: ``reference_time`` (key ages) are pinned (DECISIONS.md D-54).
SOURCE_DATE_EPOCH = "1767225600"
#: The build sha the manifest and ``graph.json`` record (otherwise the checkout's HEAD, which moves per commit).
GIT_SHA = "000000000000"
#: Manifest ``tool`` keys that describe the test interpreter, not the run.
TOOL_ENV_KEYS = ("python", "boto3", "botocore", "kubernetes")
#: Regional legacy relationship files that d13c215 left empty in ``--all`` mode (F-010).
REGIONAL_FILES = ("ec2_relationships.json", "lambda_relationships.json", "secrets_relationships.json",
                  "kms_relationships.json", "k8s_relationships.json", "compute_relationships.json",
                  "messaging_relationships.json")
CHILD_ENV = "AE_GOLDEN_CHILD_RUN"


def _fresh_run(mode: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, workdir_name: str = "run") -> LegacyRun:
    monkeypatch.setenv("AWS_ENUMERATOR_GIT_SHA", GIT_SHA)
    run = run_legacy_main(MODES[mode], tmp_path, monkeypatch, workdir_name=workdir_name,
                          source_date_epoch=SOURCE_DATE_EPOCH)
    run.mode = mode  # type: ignore[attr-defined]
    return run


@pytest.fixture(scope="module")
def golden_runs(tmp_path_factory) -> Dict[str, LegacyRun]:
    """One run per mode, shared by the read-only checks below (a run takes a few seconds).

    Every patch (env, cwd, boto3.Session, sys.modules['kubernetes'], CLI hooks) is undone right after each run;
    only the recorded results and the files on disk remain.
    """
    runs = {}
    for mode in sorted(MODES):
        mp = pytest.MonkeyPatch()
        try:
            runs[mode] = _fresh_run(mode, tmp_path_factory.mktemp(f"collectors-v2-{mode}"), mp)
        finally:
            mp.undo()
    return runs


@pytest.fixture(params=sorted(MODES))
def golden_run(request, golden_runs) -> LegacyRun:
    return golden_runs[request.param]


def run_tree(run: LegacyRun) -> Dict[str, str]:
    """The normalised run tree with the fixed run id restored in paths and texts (no ``<`` ``>`` in file names)."""
    run_id = RUN_IDS[run.mode]  # type: ignore[attr-defined]
    out = {}
    for rel, text in run.normalised_tree().items():
        rel, text = rel.replace(RUN_ID_TOKEN, run_id), text.replace(RUN_ID_TOKEN, run_id)
        if rel.endswith(f"/{run_id}/manifest.json"):
            doc = json.loads(text)
            for key in TOOL_ENV_KEYS:
                doc.get("tool", {})[key] = canonical.STRIPPED
            text = canonical.dumps(doc)
        out[rel] = text
    return out


def calls_record(run: LegacyRun) -> Dict[str, object]:
    k8s: Dict[str, Dict[str, Dict[str, int]]] = {}
    for c in run.k8s.calls_for():
        k8s.setdefault(c.cluster, {}).setdefault(c.resource, {}).setdefault(c.outcome, 0)
        k8s[c.cluster][c.resource][c.outcome] += 1
    return {
        "aws": run.fake.summary(),
        "kubernetes": {
            "calls": k8s,
            "api_clients": sorted(run.k8s.api_clients, key=lambda c: json.dumps(c, sort_keys=True)),
        },
        "region_discovery_calls": run.region_discovery_calls,
        "analyze_calls": [{"path": date_free(a.path), "regional_dirs_present": a.regional_dirs_present}
                          for a in run.analyze_calls],
    }


def _compare(golden_dir: Path, actual: Dict[str, str], update: bool) -> None:
    problem = canonical.check_or_update(golden_dir, actual, update)
    if problem:
        pytest.fail(problem, pytrace=False)


def _check_file(path: Path, text: str, update: bool) -> None:
    if update:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")
        return
    if not path.exists():
        pytest.fail(f"{path} missing; run pytest with --update-golden to create it", pytrace=False)
    expected = path.read_text(encoding="utf-8")
    if expected != text:
        import difflib
        diff = "\n".join(difflib.unified_diff(expected.splitlines(), text.splitlines(),
                                              fromfile=f"golden/{path.name}", tofile="actual", lineterm="", n=2))
        pytest.fail(f"{path.name} differs from golden:\n{diff[:12000]}", pytrace=False)


# ── the goldens ─────────────────────────────────────────────────────────────
def test_report_tree_matches_golden(golden_run: LegacyRun, update_golden: bool):
    """The normalised run tree equals tests/golden/collectors-v2/<mode>/.

    acme denies some calls on purpose, so the run is ``partial`` (exit 2, F-061) with exactly one run root.
    """
    assert golden_run.exit_code == 2, golden_run.err[-2000:]
    assert golden_run.run_ids() == [RUN_IDS[golden_run.mode]]
    _compare(GOLDEN_ROOT / golden_run.mode, run_tree(golden_run), update_golden)


def test_call_log_matches_golden(golden_run: LegacyRun, update_golden: bool):
    """The per-module AWS call inventory equals calls-<mode>.json (the read-only API inventory)."""
    _check_file(GOLDEN_ROOT / f"calls-{golden_run.mode}.json", canonical.dumps(calls_record(golden_run)),
                update_golden)


def test_console_failures_match_golden(golden_run: LegacyRun, update_golden: bool):
    """Degraded modules (manifest statuses, F-061) and the collectors' WARNING/ERROR records (F-169)."""
    text = canonical.dumps({
        "module_failures": golden_run.module_failures(),
        "collector_warnings": golden_run.collector_warnings(),
    })
    _check_file(GOLDEN_ROOT / f"console-{golden_run.mode}.json", text, update_golden)


# ── invariants ──────────────────────────────────────────────────────────────
def test_every_aws_call_is_read_only(golden_run: LegacyRun):
    """Collectors only issue read-only calls (List*/Get*/Describe*/BatchGet* and the allow-listed few)."""
    offenders = sorted({c.op for c in golden_run.fake.non_read_only_calls()})
    assert offenders == [], f"non-read-only AWS operations called: {offenders} (allowed prefixes {READ_ONLY_PREFIXES})"


def test_no_network_and_no_unhandled_operations(golden_run: LegacyRun):
    assert golden_run.fake.network_attempts == []
    assert golden_run.fake.harness_errors == []
    assert [c for c in golden_run.fake.calls_for() if c.outcome == "unhandled"] == []


@pytest.mark.finding("F-065")
def test_every_collector_issued_calls(golden_run: LegacyRun):
    """Every collector module that talks to AWS was exercised by the acme world (d13c215's collectors had mostly
    never been run)."""
    modules = set(golden_run.fake.summary())
    expected = set(targets.collector_names()) - {"k8s"}  # k8s talks to the Kubernetes API only
    expected |= set(targets.NEW_COLLECTOR_NAMES)
    assert expected <= modules, f"collectors with no recorded AWS call: {sorted(expected - modules)}"
    assert golden_run.k8s.resources_read("demo-cluster"), "k8s collector never reached the fake cluster"


@pytest.mark.finding("F-009", "F-054", "F-101", "F-112")
def test_no_canary_leaks_anywhere(golden_run: LegacyRun):
    """No secret canary of the acme world reaches any file of the run (JSON, run.log, HANDLING.txt, SHA256SUMS)
    or the console (the d13c215 collectors leaked eight of them into the report)."""
    blob = "\n".join((golden_run.date_dir / f).read_text(encoding="utf-8", errors="replace")
                     for f in golden_run.files())
    blob += "\n" + golden_run.out + "\n" + golden_run.err
    assert any(f.endswith("/run.log") for f in golden_run.files())
    assert sorted(name for name, value in acme.CANARIES.items() if value in blob) == []
    assert acme.CANARY not in blob


@pytest.mark.finding("F-010", "F-025", "F-063")
def test_all_mode_analyses_once_after_every_region(golden_runs):
    """``--all`` analyses the run root once, after both regions were collected, and the regional legacy files are
    filled (d13c215 analysed global/ before any region existed, so all of them were empty)."""
    run = golden_runs["all"]
    assert [(c.entry_point, c.regional_dirs_present) for c in run.analyze_calls] == [
        ("analyze_run", ["eu-west-1", "eu-west-2"])]
    assert sorted(run.analyze_calls[0].regions or []) == ["eu-west-1", "eu-west-2"]
    root = run.run_root
    assert not (root / "global" / "analysis").exists()
    counts = {f: len(json.loads((root / "analysis" / f).read_text(encoding="utf-8"))["edges"]) for f in REGIONAL_FILES}
    assert all(n > 0 for n in counts.values()), counts
    graph = json.loads((root / "analysis" / "graph.json").read_text(encoding="utf-8"))
    assert graph["run"]["regions"] == ["eu-west-1", "eu-west-2"] and graph["run"]["mode"] == "run"


@pytest.mark.finding("F-063", "F-162", "F-171")
@pytest.mark.parametrize("mode", sorted(MODES))
def test_golden_run_is_deterministic(mode: str, golden_runs, tmp_path, monkeypatch):
    """A second run in the same process produces the identical normalised tree and call log."""
    first = golden_runs[mode]
    second = _fresh_run(mode, tmp_path, monkeypatch, workdir_name="second")
    assert run_tree(first) == run_tree(second)
    assert canonical.dumps(calls_record(first)) == canonical.dumps(calls_record(second))


@pytest.mark.finding("F-162")
def test_goldens_hold_under_another_hash_seed(update_golden: bool):
    """The tree and call-log goldens also match in a child pytest with a different PYTHONHASHSEED."""
    if update_golden or os.environ.get(CHILD_ENV):
        pytest.skip("compares against committed goldens; not while they are being rewritten or in the child run")
    env = dict(os.environ, PYTHONHASHSEED="12345", PYTHONDONTWRITEBYTECODE="1", **{CHILD_ENV: "1"})
    test_file = Path(__file__).resolve().relative_to(targets.REPO_ROOT).as_posix()
    argv = [sys.executable, "-B", "-m", "pytest",  # no -I: it would ignore PYTHONHASHSEED
            "-q", "-p", "no:cacheprovider", test_file,
            "-k", "test_report_tree_matches_golden or test_call_log_matches_golden"]
    proc = subprocess.run(argv, cwd=str(targets.REPO_ROOT), env=env, capture_output=True, text=True,
                          timeout=600, check=False)
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[-4000:]
    assert "4 passed" in proc.stdout, proc.stdout[-2000:]
