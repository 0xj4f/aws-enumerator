"""Run the console entry point ``main()`` against a fake AWS world (the name predates the 0.3.0 CLI: it first
drove the d13c215 ``main()``; it now runs ``aws-enumerator`` exactly as the console script does).

Production code is reached only through :mod:`tests.support.targets`; AWS only
through :class:`tests.support.fakeaws.FakeAWS`; Kubernetes only through
:class:`tests.support.fake_kubernetes.FakeKubernetes`.

``run_legacy_main(argv, tmp_path, monkeypatch, ...)`` returns a
:class:`LegacyRun` with the exit code (``sys.exit(main())`` semantics, as the
console script does), captured stdout and stderr, the fake's call log, every
engine analysis call (``analyze_run``) with the directories present at that moment (F-010),
and helpers to normalise the report tree for golden comparison.

``source_date_epoch`` pins the engine's clock (``$SOURCE_DATE_EPOCH``: ``generated_at`` and the hygiene
``reference_time``), so golden runs do not drift with the wall clock (request r-2).

Since the Wave 1 CLI rewrite (stream R) ``argv`` may be a subcommand invocation (``collect --regions a,b``)
or an old flag-style one (``--region R``, ``--all``), which the CLI translates with a deprecation warning
(cli.md §4). Output goes to ``$AWS_ENUMERATOR_OUTPUT``: callers that set it (``tests/fixtures/regressions``)
keep their value; otherwise the harness points it at ``<workdir>/reports/<UTC date>`` so a run lands in
``reports/<date>/<account>/<run_id>/``. The client-side rate limiter keeps its logic but gets very high
per-service rates, so a fake run is not slowed down by real sleeps (its own tests use a fake clock).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from tests.fixtures.worlds import acme
from tests.support import canonical, targets
from tests.support.fake_kubernetes import FakeKubernetes
from tests.support.fakeaws import FakeAWS, FakeAWSHarnessError, World

ANSI = re.compile(r"\x1b\[[0-9;]*m")
#: One text-format log record on stderr (logging.md §3): ``HH:MM:SSZ LEVEL logger message``.
_LOG_LINE = re.compile(r"^\d{2}:\d{2}:\d{2}Z (?P<level>[A-Z]+)\s+(?P<logger>\S+)\s+(?P<message>.*)$")
PROFILE_NAME = "example-profile"
PROFILE_ACCESS_KEY_ID = "AKIAEXAMPLEPROFILE01"
ENV_ACCESS_KEY_ID = "AKIAEXAMPLEENVONLY01"
DEFAULT_PROFILE_ACCESS_KEY_ID = "AKIAEXAMPLEDEFAULT01"
ORCHESTRATOR = "<orchestrator>"


def collector_labeler() -> Callable[[str], str]:
    """Label calls by collector module name (rename-proof: ``iam``, ``lambda_``...)."""
    collectors_pkg = targets.collector_module("iam").__name__.rsplit(".", 1)[0]
    package = targets.package_name()

    def label(module_name: str) -> str:
        if module_name.startswith(collectors_pkg + "."):
            return module_name.rsplit(".", 1)[-1]
        if module_name == package or module_name.startswith(package + "."):
            return ORCHESTRATOR
        return "<test>"

    return label


@dataclass
class AnalyzeCall:
    path: str                  # the run root, relative to the run's working directory (or absolute outside it)
    siblings: List[str]        # entries of the run root at call time (sorted)
    regional_dirs_present: List[str]
    entry_point: str = "analyze_run"
    regions: Optional[List[str]] = None  # the explicit region list passed to analyze_run


@dataclass
class LegacyRun:
    argv: List[str]
    workdir: Path
    exit_code: Any
    stdout: str                # captured stdout + stderr (ANSI codes kept; see console_lines())
    exception: Optional[BaseException]
    fake: FakeAWS
    k8s: FakeKubernetes
    analyze_calls: List[AnalyzeCall] = field(default_factory=list)
    region_discovery_calls: List[Optional[str]] = field(default_factory=list)
    out: str = ""              # stdout only (the command's result, cli.md §5)
    err: str = ""              # stderr only (logs, banner, warnings)
    output_root: Optional[Path] = None   # $AWS_ENUMERATOR_OUTPUT during the run

    # ── v2 run roots (<output>/<account>/<run_id>/) ─────────────────────────
    def run_roots(self) -> List[Path]:
        """Every run root under the output root (directories holding a v2 manifest.json), sorted."""
        if self.output_root is None or not self.output_root.is_dir():
            return []
        return sorted(p.parent for p in self.output_root.glob("*/*/manifest.json"))

    @property
    def run_root(self) -> Path:
        roots = self.run_roots()
        assert len(roots) == 1, f"expected exactly one run root under {self.output_root}, found {roots}"
        return roots[0]

    def manifest(self) -> Dict[str, Any]:
        with open(self.run_root / "manifest.json", encoding="utf-8") as fh:
            return json.load(fh)

    def stdout_lines(self) -> List[str]:
        return [line for line in self.out.splitlines() if line.strip()]

    # ── report tree ─────────────────────────────────────────────────────────
    @property
    def reports_dir(self) -> Path:
        return self.workdir / "reports"

    @property
    def date_dir(self) -> Path:
        dates = sorted(p for p in self.reports_dir.iterdir() if p.is_dir()) if self.reports_dir.is_dir() else []
        assert len(dates) == 1, f"expected exactly one reports/<date>/ directory, found {dates}"
        return dates[0]

    @property
    def account_dir(self) -> Path:
        return self.date_dir / acme.ACCOUNT_ID

    def files(self) -> List[str]:
        """Every file under reports/<date>/ (posix, relative, sorted)."""
        root = self.date_dir
        return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())

    def dirs(self) -> List[str]:
        root = self.date_dir
        return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_dir())

    def load(self, rel: str) -> Any:
        with open(self.date_dir / rel, encoding="utf-8") as fh:
            return json.load(fh)

    def run_ids(self) -> List[str]:
        """The run ids of the v2 run roots under reports/<date>/ (``<account>/<run_id>/manifest.json``)."""
        return sorted({p.parent.name for p in self.date_dir.glob("*/*/manifest.json")})

    def normalised_tree(self) -> Dict[str, str]:
        """{path relative to reports/<date>/: canonical JSON} (date stripped, timestamps masked).

        Run-unique values are masked so two runs of the same world compare equal (report-layout.md §1.2): the
        run id (``<UTC ts>-<6 hex>``) becomes ``<RUN_ID>`` in paths and contents; ``ended_at`` (manifest and
        ``_coverage.json``) and ``graph.json``'s ``source_manifest_sha256`` join the stripped clock keys; and the
        manifest digests of the files that embed the run id or the clock (``HANDLING.txt``, ``analysis/*``,
        ``*/_coverage.json``) become ``<stripped>``.
        """
        tree = canonical.canonical_tree(self.date_dir, path_roots=[str(self.workdir)], strip_keys=RUN_STRIP_KEYS)
        run_ids = self.run_ids()
        if run_ids:
            masked = {_mask_run_ids(rel, run_ids): _mask_run_ids(text, run_ids) for rel, text in tree.items()}
            tree = {rel: _mask_manifest(rel, text) for rel, text in masked.items()}
        # Empty directories are part of the observable layout (e.g. waf/ when the module crashed).
        empty = [_mask_run_ids(d, run_ids) for d in self.dirs() if not any((self.date_dir / d).iterdir())]
        if empty:
            tree["_empty_dirs.json"] = canonical.dumps(sorted(empty))
        return tree

    # ── console ─────────────────────────────────────────────────────────────
    def console_lines(self) -> List[str]:
        return [ANSI.sub("", line).strip() for line in self.stdout.splitlines()]

    def module_failures(self) -> List[str]:
        """Every module the manifest records as neither ``ok`` nor ``skipped`` (the d13c215 console printed
        ``[-] <label> module failed``; 0.3.0 records the status, F-061): ``name@region: status (type/code)``."""
        if not self.run_roots():
            return []
        out = []
        for entry in self.manifest().get("modules") or []:
            if entry.get("status") in ("ok", "skipped"):
                continue
            error = entry.get("error") or {}
            detail = "/".join(str(v) for v in (error.get("type"), error.get("code")) if v)
            out.append(f"{entry.get('name')}@{entry.get('region')}: {entry.get('status')}"
                       + (f" ({detail})" if detail else ""))
        return sorted(out)

    def collector_warnings(self) -> List[str]:
        """WARNING/ERROR records of the collectors on stderr, clock column dropped, sorted (units run in parallel)."""
        out = []
        for line in self.console_lines():
            match = _LOG_LINE.match(line)
            if match and match.group("level") in ("WARN", "ERROR") and match.group("logger").startswith("collect."):
                out.append(f"{match.group('level')} {match.group('logger')} {match.group('message')}")
        return sorted(out)


def write_profile_config(directory: Path) -> Dict[str, str]:
    """A throwaway AWS config + credentials file with one fake named profile."""
    directory.mkdir(parents=True, exist_ok=True)
    config = directory / "config"
    creds = directory / "credentials"
    config.write_text(f"[profile {PROFILE_NAME}]\nregion = {acme.SINGLE_REGION}\n", encoding="utf-8")
    creds.write_text(f"[{PROFILE_NAME}]\naws_access_key_id = {PROFILE_ACCESS_KEY_ID}\n"
                     f"aws_secret_access_key = example-profile-secret-key-not-real-000000\n", encoding="utf-8")
    return {"AWS_CONFIG_FILE": str(config), "AWS_SHARED_CREDENTIALS_FILE": str(creds), "AWS_PROFILE": PROFILE_NAME}


def run_legacy_main(argv: Sequence[str], tmp_path: Path, monkeypatch: Any, *,
                    world: Optional[World] = None,
                    k8s_clusters: Optional[Dict[str, Any]] = None,
                    credentials: str = "profile",
                    regions: Sequence[str] = acme.REGIONS,
                    patch_region_discovery: bool = True,
                    workdir_name: str = "run",
                    fast_rate_limits: bool = True,
                    source_date_epoch: Optional[str] = None) -> LegacyRun:
    """Run the CLI in ``tmp_path/<workdir_name>`` against ``world`` (default: acme).

    ``credentials``: ``"profile"`` (a named profile via AWS_PROFILE, the usual operator setup),
    ``"env"`` (env-var credentials only, as in Docker/CI) or ``"env+default-profile"`` (env-var
    credentials plus an unrelated ``[default]`` profile on disk); see F-060.
    ``patch_region_discovery=False`` lets the real region discovery call the world's DescribeRegions.
    ``fast_rate_limits=False`` keeps the limiter's real default rates.
    ``source_date_epoch`` sets ``$SOURCE_DATE_EPOCH`` for the run (reproducible analysis clock).
    """
    world = world or acme.build_world()
    workdir = tmp_path / workdir_name
    workdir.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(workdir)

    if credentials == "profile":
        for k, v in write_profile_config(tmp_path / f"{workdir_name}-aws").items():
            monkeypatch.setenv(k, v)
        for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"):
            monkeypatch.delenv(k, raising=False)
    elif credentials in ("env", "env+default-profile"):
        monkeypatch.delenv("AWS_PROFILE", raising=False)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", ENV_ACCESS_KEY_ID)
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "example-env-secret-key-not-real-0000000000")
        monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
        monkeypatch.delenv("AWS_SECURITY_TOKEN", raising=False)
        if credentials == "env+default-profile":
            # An unrelated [default] profile on the operator's machine (F-060 case A).
            directory = tmp_path / f"{workdir_name}-aws"
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "config").write_text("[default]\nregion = us-east-1\n", encoding="utf-8")
            (directory / "credentials").write_text(
                f"[default]\naws_access_key_id = {DEFAULT_PROFILE_ACCESS_KEY_ID}\n"
                "aws_secret_access_key = example-default-secret-key-not-real-00000\n", encoding="utf-8")
            monkeypatch.setenv("AWS_CONFIG_FILE", str(directory / "config"))
            monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(directory / "credentials"))
    else:
        raise ValueError(f"unknown credentials mode {credentials!r}")

    # The d13c215 main() wrote AWS_RETRY_MODE / AWS_MAX_ATTEMPTS with os.environ.setdefault (F-125, fixed in
    # Wave 1: the CLI never writes os.environ). Both keys stay registered with this monkeypatch, so its undo()
    # restores them even when the caller is a module-scoped fixture that runs before the per-test env
    # snapshot in tests/conftest.py (request rename-split-1), should anything write them again.
    for key in MAIN_WRITES_ENV:
        _register_env_key(monkeypatch, key)

    fake = FakeAWS(world, labeler=collector_labeler())
    fake.install(monkeypatch)
    k8s = FakeKubernetes(k8s_clusters if k8s_clusters is not None else acme.build_k8s_clusters())
    k8s.install(monkeypatch)

    if not os.environ.get(OUTPUT_ENV):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        monkeypatch.setenv(OUTPUT_ENV, str(workdir / "reports" / stamp))
    if fast_rate_limits:
        _fast_rate_limits(monkeypatch)
    if source_date_epoch is not None:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", str(source_date_epoch))

    run = LegacyRun(argv=list(argv), workdir=workdir, exit_code=None, stdout="", exception=None,
                    fake=fake, k8s=k8s, output_root=Path(os.environ[OUTPUT_ENV]))
    points = targets.main_patch_points()
    if patch_region_discovery:
        owner, attr = points["region_discovery"]

        def fake_regions(_aws: Any, region: Optional[str] = None) -> List[str]:
            run.region_discovery_calls.append(region)
            return list(regions)

        monkeypatch.setattr(owner, attr, fake_regions)
    _spy_on_analysis(run, points["analyze"], monkeypatch, workdir)
    monkeypatch.setattr(sys, "argv", ["aws-enumerator", *argv])

    main = targets.main_entry()
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            sys.exit(main())  # the console-script wrapper's semantics
        except SystemExit as exc:
            run.exit_code = 0 if exc.code is None else exc.code
        except FakeAWSHarnessError:
            raise
        except Exception as exc:  # an uncaught exception exits 1 from the console script
            run.exception = exc
            run.exit_code = 1
    run.out, run.err = out.getvalue(), err.getvalue()
    run.stdout = run.out + run.err
    fake.assert_clean()
    return run


#: Output root variable of the CLI (cli.md §7).
OUTPUT_ENV = "AWS_ENUMERATOR_OUTPUT"


def _fast_rate_limits(monkeypatch: Any) -> None:
    """Very high rates for every bucket (the limiter's own tests use a fake clock and the real defaults)."""
    ratelimit = targets.runtime_module("ratelimit")
    fast = {name: (1_000_000.0, 1_000_000.0) for name in ratelimit.DEFAULT_RATES}
    monkeypatch.setattr(ratelimit, "DEFAULT_RATES", fast)


def _spy_on_analysis(run: LegacyRun, point: Any, monkeypatch: Any, workdir: Path) -> None:
    """Record every engine analysis call with the directories present at that moment (F-010)."""
    owner, attr = point
    current = getattr(owner, attr)
    real = getattr(current, "__legacy_harness_wrapped__", current)  # never stack spies

    def analyze_spy(report_path: str, *args: Any, **kwargs: Any):
        listing = sorted(os.listdir(report_path)) if os.path.isdir(report_path) else []
        regions = list(kwargs.get("regions") or [])
        regional = sorted(s for s in listing if s in acme.REGIONS)
        run.analyze_calls.append(AnalyzeCall(_rel(report_path, workdir), listing, regional, attr, regions))
        return real(report_path, *args, **kwargs)

    analyze_spy.__legacy_harness_wrapped__ = real  # type: ignore[attr-defined]
    monkeypatch.setattr(owner, attr, analyze_spy)


#: Environment variables the d13c215 main() set directly (os.environ.setdefault), see F-125.
MAIN_WRITES_ENV = ("AWS_RETRY_MODE", "AWS_MAX_ATTEMPTS")


def _register_env_key(monkeypatch: Any, key: str) -> None:
    """Make ``monkeypatch.undo()`` restore ``key`` to its current state (set or unset)."""
    current = os.environ.get(key)
    if current is None:
        # setenv records "was unset"; delenv then removes the placeholder again. undo() runs in
        # reverse order, so the key ends up unset whatever main() wrote in between.
        monkeypatch.setenv(key, "legacy-harness-placeholder")
        monkeypatch.delenv(key)
    else:
        monkeypatch.setenv(key, current)


def _rel(path: str, root: Path) -> str:
    try:
        return Path(os.path.abspath(path)).relative_to(root).as_posix()
    except ValueError:
        return str(path)


RUN_ID_TOKEN = "<RUN_ID>"
#: Wall-clock and run-unique keys never compared (the canonical defaults plus the v2 run's own).
RUN_STRIP_KEYS = frozenset(canonical.DEFAULT_STRIP_KEYS | {"ended_at", "source_manifest_sha256"})
#: Files whose bytes embed the run id or a clock value: their manifest digests are not comparable across runs.
_RUN_UNIQUE_FILES = re.compile(r"^(HANDLING\.txt|analysis/.+|.+/_coverage\.json)$")


def _mask_run_ids(text: str, run_ids: Sequence[str]) -> str:
    for run_id in sorted(run_ids, key=len, reverse=True):
        text = text.replace(run_id, RUN_ID_TOKEN)
    return text


def _mask_manifest(rel: str, text: str) -> str:
    """``<account>/<RUN_ID>/manifest.json``: mask the digests of the run-unique files."""
    if not rel.endswith(f"/{RUN_ID_TOKEN}/manifest.json"):
        return text
    doc = json.loads(text)
    for entry in doc.get("files") or []:
        if isinstance(entry, dict) and _RUN_UNIQUE_FILES.match(str(entry.get("path", ""))):
            entry["sha256"] = entry["bytes"] = canonical.STRIPPED
    return canonical.dumps(doc)


#: A generated run id (report-layout.md §1.2): ``<UTC %Y%m%dT%H%M%SZ>-<6 hex>``.
GENERATED_RUN_ID = re.compile(r"\b\d{8}T\d{6}Z-[0-9a-f]{6}\b")


def date_free(path: str) -> str:
    """``reports/20261015/111122223333/20261015T101500Z-a1b2c3`` -> ``reports/<date>/111122223333/<RUN_ID>``
    (the date directory and a generated run id are both run-unique)."""
    return GENERATED_RUN_ID.sub(RUN_ID_TOKEN, re.sub(r"reports/\d{8}/", "reports/<date>/", path))
