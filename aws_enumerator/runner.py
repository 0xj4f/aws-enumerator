"""``aws-enumerator collect``: one run from credentials to a finalised, verifiable run root (cli.md §3.1).

Sequence (cli.md §3.1 "Run sequence"):

1. ``umask 077`` (F-123); validate everything that needs no AWS call (usage errors exit 64 before any call);
2. the AWS context: one session, credentials resolved once, STS in the **home** region (F-060, F-124, F-119);
3. module selection from the registry (``--modules`` / ``--skip`` / ``--no-k8s`` / ``--max-tier``, F-062);
4. regions: explicit, the profile region, or ``--all`` with a DescribeRegions -> STS-probe fallback (F-064);
5. the output root and the git guard (F-066), then the run-unique run root (F-063) with ``manifest.json``
   (``in_progress``) and ``HANDLING.txt`` (F-159) written before any collection, and ``run.log``;
6. the banner on stderr, with the authorised-use line (F-172) and no personal handle (F-144);
7. optional pre-flight (F-161);
8. units (``global`` once per run, F-153, then each region) in a bounded pool with a shared rate limiter
   (F-127, F-154); SIGINT/SIGTERM stop the run cleanly (F-155);
9. **analysis once, after every unit** (F-010), unless ``--no-analysis``;
10. ``manifest.files``, the final manifest, ``SHA256SUMS``, and the optional zip / encryption / signature
    (F-168, F-123); a summary with the dashboard hint (F-145) on stderr, and the run root on stdout;
11. the exit code: 0 complete, 2 partial, 1 fatal, 130/143 interrupted (F-061).

``--resume`` re-runs the units that did not finish cleanly in an existing run (F-127).
"""

from __future__ import annotations

import dataclasses
import logging
import os
import shutil
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from aws_enumerator import archive, engine_adapter, integrity, output, permissions, registry
from aws_enumerator._version import PRODUCT_NAME, __version__
from aws_enumerator.aws_session import (
    AwsContext,
    AwsOptions,
    AwsSetupError,
    Identity,
    RegionPlan,
    RegionUsageError,
    home_region_from_env,
    plan_regions,
    validate_region,
)
from aws_enumerator.buildinfo import tool_info
from aws_enumerator.collectors.base import ModuleResult, RunInfo
from aws_enumerator.execution import SignalGuard, UnitPlan, UnitProgress, execute_units, run_unit
from aws_enumerator.logging_setup import CONSOLE_ONLY, attach_log_file, set_redactions, set_run_id
from aws_enumerator.ratelimit import RateLimitConfig, RateLimiter
from aws_enumerator.resume import ResumePlan, copy_global_from, load_resume
from aws_enumerator.util import fsio

__all__ = ["AUTHORIZED_USE", "CollectOutcome", "CollectRequest", "UsageFailure", "run_collect"]

log = logging.getLogger("aws_enumerator.runner")

AUTHORIZED_USE = "Authorized use only: run only against accounts you have written permission to assess."
#: Option keys whose values are local paths: passed to collectors, never written to the manifest.
PATH_OPTIONS = frozenset({"iam_gaad_file", "kubeconfig", "k8s_token_file", "k8s_ca_file", "scp_file"})


class UsageFailure(ValueError):
    """A usage error detected by the runner (exit 64)."""


@dataclass
class CollectRequest:
    """Everything ``collect`` needs, already parsed and validated by the CLI (cli.md §3.1)."""

    argv: List[str] = field(default_factory=list)
    profile: Optional[str] = None
    region: Optional[str] = None
    regions: List[str] = field(default_factory=list)
    all_regions: bool = False
    exclude_regions: List[str] = field(default_factory=list)
    skip_global: bool = False
    global_from: Optional[str] = None
    modules: List[str] = field(default_factory=list)
    skip: List[str] = field(default_factory=list)
    max_tier: int = 2
    k8s: bool = True
    k8s_secrets: bool = False
    output: Optional[str] = None
    allow_in_repo: bool = False
    run_id: Optional[str] = None
    resume: Optional[str] = None
    retry_denied: bool = False
    no_analysis: bool = False
    zip: bool = False
    encrypt: Optional[Tuple[str, str]] = None
    sign: Optional[Tuple[str, str]] = None
    redact_identity: bool = False
    shutdown_grace: float = 20.0
    baseline: Optional[str] = None
    suppress: Optional[str] = None
    legacy_outputs: bool = True
    concurrency: int = 3
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    retry_mode: Optional[str] = None
    max_attempts: Optional[int] = None
    deny_breaker: int = 3
    ua_app_id: Optional[str] = None
    ua_tag: bool = True
    preflight: bool = False
    preflight_only: bool = False
    preflight_mode: str = "probe"
    preflight_format: str = "text"
    log_file_given: bool = False
    collector_options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectOutcome:
    """The exit code and what goes to stdout (the run root, or the pre-flight table)."""

    exit_code: int
    stdout: List[str] = field(default_factory=list)


@dataclass
class _Run:
    """State of one run while it executes."""

    req: CollectRequest
    aws: AwsContext
    identity: Identity
    selection: Any
    plan: RegionPlan
    layout: output.RunLayout
    store: output.ManifestStore
    info: RunInfo
    limiter: RateLimiter
    resume: Optional[ResumePlan] = None
    signals: Optional[SignalGuard] = None
    aborted: Optional[BaseException] = None
    interrupted: bool = False
    archive_path: Optional[Path] = None
    archive_error: Optional[str] = None


# ── entry point ──────────────────────────────────────────────────────────────
def run_collect(req: CollectRequest) -> CollectOutcome:
    """Run ``collect``; maps every failure to its exit code (cli.md §6). Restores the umask afterwards."""
    previous_umask = os.umask(0o077)
    try:
        return _collect(req)
    except (UsageFailure, RegionUsageError, output.OutputUsageError, registry.SelectionError,
            engine_adapter.AnalysisUsage) as exc:
        log.error("%s", exc)
        return CollectOutcome(64)
    except (AwsSetupError, output.OutputError, archive.ArchiveError, permissions.PreflightError) as exc:
        log.error("%s", exc)
        return CollectOutcome(1)
    finally:
        os.umask(previous_umask)


def _collect(req: CollectRequest) -> CollectOutcome:
    _check_local_inputs(req)
    if not (req.resume or req.run_id or req.preflight_only):
        # Fixed before the AWS context exists, so the user-agent app id carries it (F-170).
        req = dataclasses.replace(req, run_id=output.new_run_id())
    stop_event = threading.Event()
    limiter = RateLimiter(req.rate_limit, stop_event=stop_event)
    aws = AwsContext(_aws_options(req))
    aws.install_rate_limiter(limiter)
    home = _home_region(req, aws)
    limiter.global_region = registry.global_region_for(aws.partition_for_region(home) or "aws")
    identity = aws.identify(home)
    limiter.global_region = identity.global_region
    if req.redact_identity:
        set_redactions([identity.caller_arn, identity.caller_user_id])
    if req.preflight_only:
        return _preflight_only(req, aws, identity, home)
    run = _prepare(req, aws, identity, home, limiter, stop_event)
    return _execute_run(run)


def _execute_run(run: _Run) -> CollectOutcome:
    """Banner, pre-flight, units, analysis, finalisation. A fatal error once the run root exists still
    finalises the manifest (``failed``, exit 1) so the run is never left ``in_progress`` (F-155, F-061)."""
    _banner(run)
    run.signals = SignalGuard(run.info.stop_event, on_second=lambda code: _best_effort(run, code))
    with run.signals:
        try:
            if run.req.preflight:
                _record_preflight(run)
            _run_units(run)
            _analyze(run)
            code, status = _exit_status(run)
        except (AwsSetupError, permissions.PreflightError, output.OutputError) as exc:
            log.error("%s", exc)
            code, status = 1, "failed"
        except Exception:
            log.error("internal error: the manifest is finalised as failed", exc_info=True)
            _finalize(run, 1, "failed")
            raise
        _finalize(run, code, status)
    if run.archive_error:
        log.error("the run itself is finalised (%s); retry the archive with 'aws-enumerator package %s'",
                  status, run.layout.run_root, extra={CONSOLE_ONLY: True})
        code = 1 if code == 0 else code
    _summary(run, code)
    return CollectOutcome(code, [str(run.layout.run_root)])


# ── preparation ──────────────────────────────────────────────────────────────
#: Collector options that name local files: they must be readable before any AWS call (exit 64).
FILE_OPTIONS = (("iam_gaad_file", "--iam-gaad-file"), ("scp_file", "--scp-file"), ("kubeconfig", "--kubeconfig"),
                ("k8s_token_file", "--k8s-token-file"), ("k8s_ca_file", "--k8s-ca-file"))


def _check_local_inputs(req: CollectRequest) -> None:
    if req.run_id:
        output.validate_run_id(req.run_id)
    for flag, value in (("--baseline", req.baseline), ("--suppress", req.suppress),
                        ("--global-from", req.global_from)):
        if value and not Path(value).expanduser().exists():
            raise UsageFailure(f"{flag}: {value} does not exist")
    for key, flag in FILE_OPTIONS:
        value = req.collector_options.get(key)
        if value and not (Path(value).expanduser().is_file() and os.access(Path(value).expanduser(), os.R_OK)):
            raise UsageFailure(f"{flag}: {value} is not a readable file")
    if not req.no_analysis and not req.preflight_only:
        engine_adapter.validate_analysis_inputs(baseline=req.baseline, suppress=req.suppress)
    for spec in (req.encrypt, req.sign):
        if spec and shutil.which(spec[0]) is None:
            raise archive.ArchiveError(f"'{spec[0]}' is not installed (or not on PATH); needed for "
                                       f"{'--encrypt' if spec is req.encrypt else '--sign'}")


def _aws_options(req: CollectRequest) -> AwsOptions:
    run_id = req.run_id or (Path(req.resume).name if req.resume else None)
    return AwsOptions(profile=req.profile, retry_mode=req.retry_mode, max_attempts=req.max_attempts,
                      ua_app_id=req.ua_app_id, ua_tag=req.ua_tag, run_id=run_id)


def _home_region(req: CollectRequest, aws: AwsContext) -> str:
    if req.region:
        return validate_region(req.region, "--region")
    if req.regions:
        return validate_region(req.regions[0], "--regions")
    home = home_region_from_env(aws)
    if not home:
        raise UsageFailure("no home region: pass --region R (or --regions a,b), or set AWS_REGION / the profile's "
                           "region; aws-enumerator has no default region")
    return validate_region(home, "home region (AWS_REGION / AWS_DEFAULT_REGION / profile)")


def _select(req: CollectRequest, partition: str) -> Any:
    return registry.select(req.modules or None, req.skip or None, k8s=req.k8s, max_tier=req.max_tier,
                           partition=partition, skip_global=req.skip_global or bool(req.global_from))


def _prepare(req: CollectRequest, aws: AwsContext, identity: Identity, home: str, limiter: RateLimiter,
             stop_event: threading.Event) -> _Run:
    root = output.resolve_output_root(req.output)
    output.git_guard(root, allow=req.allow_in_repo)
    if req.resume:
        resume = load_resume(req, root, identity)
        req = resume.effective_request(req)
        selection = _select(req, identity.partition)
        layout, plan, store = resume.layout, resume.region_plan, resume.store
    else:
        resume = None
        selection = _select(req, identity.partition)
        plan = plan_regions(aws, identity, home_region=home, region=req.region, regions=req.regions,
                            all_regions=req.all_regions, exclude=req.exclude_regions)
        if not plan.regions:
            raise UsageFailure("no region to collect (every discovered region was excluded or failed the probe)")
        run_id = req.run_id or output.new_run_id()
        layout = output.RunLayout(root, identity.account_id, run_id)
        output.create_run_root(layout)
        store = _new_manifest(req, identity, selection, plan, layout)
    set_run_id(layout.run_id)
    if not req.log_file_given:
        attach_log_file(str(layout.log_path))
    info = RunInfo(run_id=layout.run_id, aws=aws, options=_collector_options(req), stop_event=stop_event,
                   logger=logging.getLogger("aws_enumerator"), run_root=layout.run_root)
    run = _Run(req, aws, identity, selection, plan, layout, store, info, limiter, resume=resume)
    if resume is None:
        output.write_handling(layout, store.get("run", "started_at"))
        store.record(_skipped_results(run))
        if req.global_from:
            store.update("run", global_source=copy_global_from(Path(req.global_from), layout, identity))
    else:
        resume.begin(run_argv=req.argv)
    return run


def _manifest_options(req: CollectRequest, selection: Any, plan: RegionPlan) -> Dict[str, Any]:
    options: Dict[str, Any] = {k: v for k, v in sorted(req.collector_options.items()) if k not in PATH_OPTIONS}
    options.update({
        "regions_requested": list(plan.regions_requested),
        "modules": selection.names(),
        "skipped_modules": [{"name": n, "reason": r} for n, r in selection.skipped],
        "k8s": bool(req.k8s), "k8s_secrets": bool(req.k8s_secrets), "concurrency": int(req.concurrency),
        "rate_limit": req.rate_limit.to_manifest(), "max_tier": int(req.max_tier),
        "deny_breaker": int(req.deny_breaker), "redact_identity": bool(req.redact_identity), "zip": bool(req.zip),
    })
    return options


def _new_manifest(req: CollectRequest, identity: Identity, selection: Any, plan: RegionPlan,
                  layout: output.RunLayout) -> output.ManifestStore:
    target = {"account_id": identity.account_id, "partition": identity.partition, "home_region": plan.home_region,
              "global_region": identity.global_region, "regions": sorted(plan.regions),
              "region_source": plan.region_source, "regions_skipped": list(plan.regions_skipped)}
    run = {"run_id": layout.run_id, "started_at": output.iso(), "argv": list(req.argv),
           "options": _manifest_options(req, selection, plan)}
    order = {spec.name: i for i, spec in enumerate(registry.get_registry())}
    store = output.ManifestStore.new(layout.manifest_path, tool=tool_info(), run=run, target=target,
                                     operator=identity.operator_block(redact=req.redact_identity), order=order)
    store.save()
    return store


def _collector_options(req: CollectRequest) -> Dict[str, Any]:
    """``RunInfo.options``: the collector tuning flags plus the run-wide settings collectors read."""
    options = dict(req.collector_options)
    options.update({
        "deny_breaker": req.deny_breaker, "k8s": req.k8s, "k8s_secrets": req.k8s_secrets,
        "max_tier": req.max_tier,
        "rate_limit_enabled": req.rate_limit.enabled, "rate_limit": dict(req.rate_limit.overrides),
        "max_rps": req.rate_limit.max_rps, "ua_tag": req.ua_tag, "ua_app_id": req.ua_app_id,
    })
    return options


def _skipped_results(run: _Run) -> List[ModuleResult]:
    reg = registry.get_registry()
    out = []
    for name, reason in run.selection.skipped:
        spec = reg.get(name)
        units = ["global"] if spec.scope == "global" else list(run.plan.regions)
        out.extend(ModuleResult.skipped(spec, unit, reason) for unit in units)
    return out


# ── banner and pre-flight ────────────────────────────────────────────────────
def _banner(run: _Run) -> None:
    ident, plan = run.identity, run.plan
    extra = {"event": "run.start"}
    log.info("%s %s. %s", PRODUCT_NAME, __version__, AUTHORIZED_USE, extra=extra)
    log.info("run %s: account %s (%s), regions %s (%s), %d module(s)%s", run.layout.run_id, ident.account_id,
             ident.partition, ",".join(plan.regions), plan.region_source, len(run.selection.specs),
             " [resume]" if run.resume else "", extra=extra)
    log.info("operator: %s (%s)", ident.principal_arn or "unknown", ident.principal_type, extra=extra)
    log.info("output: %s", run.layout.run_root, extra={CONSOLE_ONLY: True})
    for warning in run.selection.warnings:
        log.info("%s", warning)
    if run.req.k8s_secrets:
        log.warning("--k8s-secrets: Secret metadata only is requested, but the 'list secrets' RBAC permission still "
                    "lets this identity read every Secret value")


def _preflight_results(req: CollectRequest, aws: AwsContext, identity: Identity, home: str,
                       specs: Sequence[Any]) -> List[permissions.PreflightResult]:
    if req.preflight_mode == "simulate":
        return permissions.run_simulate(aws, identity, specs, global_region=identity.global_region)
    return permissions.run_probe(aws, specs, home_region=home, global_region=identity.global_region)


def _preflight_only(req: CollectRequest, aws: AwsContext, identity: Identity, home: str) -> CollectOutcome:
    selection = _select(req, identity.partition)
    results = _preflight_results(req, aws, identity, home, selection.specs)
    return CollectOutcome(permissions.preflight_exit_code(results),
                          [permissions.render_preflight(results, req.preflight_format)])


def _record_preflight(run: _Run) -> None:
    results = _preflight_results(run.req, run.aws, run.identity, run.plan.home_region, run.selection.specs)
    run.store.set("preflight", permissions.preflight_block(run.req.preflight_mode, results, output.iso()))
    for res in results:
        if res.result not in ("ok", "allowed", "skipped"):
            log.warning("preflight: %s %s (%s)", res.module, res.result, res.error_code or "-")


# ── units ────────────────────────────────────────────────────────────────────
def _unit_plans(run: _Run) -> List[UnitPlan]:
    if run.resume is not None:
        return run.resume.unit_plans(run.selection)
    plans = []
    if run.selection.global_specs:
        plans.append(UnitPlan("global", list(run.selection.global_specs)))
    plans.extend(UnitPlan(region, list(run.selection.regional_specs)) for region in run.plan.regions
                 if run.selection.regional_specs)
    return plans


def _run_units(run: _Run) -> None:
    plans = _unit_plans(run)
    resumed = run.resume is not None

    def worker(plan: UnitPlan, prog: UnitProgress) -> UnitProgress:
        if run.resume is not None:
            run.resume.prepare_unit(plan.unit)
        try:
            return run_unit(plan, prog, run=run.info, run_root=run.layout.run_root,
                            account_id=run.identity.account_id, partition=run.identity.partition)
        finally:
            if run.resume is not None and prog.done and not prog.interrupted and prog.aborted is None:
                run.resume.finish_unit(plan.unit)

    def on_progress(prog: UnitProgress) -> None:
        run.store.record(prog.snapshot(), resumed=resumed)
        if prog.aborted is not None and run.aborted is None:
            run.aborted = prog.aborted
        run.interrupted = run.interrupted or prog.interrupted

    execute_units(plans, concurrency=run.req.concurrency, stop_event=run.info.stop_event,
                  grace=run.req.shutdown_grace, worker=worker, on_progress=on_progress)
    if run.signals is not None and run.signals.signum is not None:
        run.interrupted = True


# ── analysis ─────────────────────────────────────────────────────────────────
def _analyze(run: _Run) -> None:
    if run.req.no_analysis:
        run.store.update("analysis", **{**output.empty_analysis(), "status": "skipped"})
        return
    if run.aborted is not None or run.interrupted:
        return  # analysis.status stays not_run (manifest.md §3.8)
    run.store.update("analysis", status="in_progress", engine=None, started_at=output.iso())
    outcome = engine_adapter.analyze_run_root(
        run.layout.run_root, regions=run.store.get("target", "regions"), manifest=run.store.snapshot(),
        baseline=run.req.baseline, suppress=run.req.suppress, redact_identity=run.req.redact_identity,
        legacy_outputs=run.req.legacy_outputs)
    run.store.update("analysis", **outcome.manifest_fields())
    if outcome.status != "ok":
        log.warning("analysis %s: %s", outcome.status, outcome.error or "see the analyzer status in graph.json",
                    extra={"event": "analysis.end", "status": outcome.status})
    else:
        log.info("analysis ok (%s engine)", outcome.engine, extra={"event": "analysis.end", "status": "ok"})


# ── finalisation ─────────────────────────────────────────────────────────────
def _exit_status(run: _Run) -> Tuple[int, str]:
    """``(exit code, run.status)`` from the module entries and the analysis (manifest.md §2)."""
    if run.interrupted and run.signals is not None and run.signals.exit_code is not None:
        return run.signals.exit_code, "interrupted"
    if run.aborted is not None:
        log.error("run aborted: %s", run.aborted)
        return 1, "failed"
    if run.interrupted:
        return 130, "interrupted"
    entries = run.store.entries()
    ran = [e for e in entries if e["status"] not in ("skipped", "not_run")]
    if ran and all(e["status"] == "failed" for e in ran):
        return 1, "failed"
    analysis = run.store.get("analysis", "status")
    if any(e["status"] in ("partial", "denied", "failed") for e in entries) or analysis in ("partial", "failed"):
        return 2, "partial"
    return 0, "complete"


def _finalize(run: _Run, code: int, status: str) -> None:
    files = integrity.compute_files(run.layout.run_root)
    run.store.finalize(status=status, exit_code=code, ended_at=output.utc_now(), files=files)
    integrity.write_sha256sums(run.layout.run_root, files)
    if run.req.zip or run.req.encrypt:
        _package(run)


def _package(run: _Run) -> None:
    try:
        path = archive.build_zip(run.layout.run_root, run.layout.zip_path, run.store.snapshot())
        digest = archive.file_sha256(path)
        log.info("zip: %s sha256 %s", path.name, digest, extra={"event": "zip.written", "sha256": digest})
        if run.req.encrypt:
            path = archive.encrypt(path, run.req.encrypt)
            log.info("encrypted: %s sha256 %s", path.name, archive.file_sha256(path))
        if run.req.sign:
            log.info("signature: %s", archive.sign(path, run.req.sign).name)
        run.archive_path = path
    except archive.ArchiveError as exc:
        run.archive_error = str(exc)
        log.error("%s", exc)


def _best_effort(run: _Run, code: int) -> None:
    """Second SIGINT: mark the manifest interrupted without digests, then the process exits."""
    try:
        run.store.update("run", status="interrupted", exit_code=code, ended_at=output.iso())
    except Exception:  # noqa: BLE001 - nothing more can be done on the way out
        pass


def _summary(run: _Run, code: int) -> None:
    summary = run.store.get("coverage_summary")
    counts = ", ".join(f"{k} {v}" for k, v in summary["modules_by_status"].items()) or "no modules"
    analysis = run.store.get("analysis", "status")
    level = logging.INFO if code == 0 else logging.WARNING
    log.log(level, "run %s finished: %s; analysis %s; exit %d", run.layout.run_id, counts, analysis, code,
            extra={"event": "run.end", "exit_code": code})
    if summary["denied_apis"]:
        log.warning("denied APIs: %s", ", ".join(d["api"] for d in summary["denied_apis"][:10])
                    + (" ..." if len(summary["denied_apis"]) > 10 else ""))
    hint = {CONSOLE_ONLY: True}                          # absolute local paths stay out of run.log
    if run.archive_path is not None:
        log.info("dashboard: aws-enumerator dashboard, then load %s", run.archive_path, extra=hint)
    else:
        log.info("dashboard: aws-enumerator dashboard, then load %s.zip (aws-enumerator package %s) or the folder",
                 run.layout.run_root, run.layout.run_root, extra=hint)


def ensure_parent_dir(path: Path) -> Path:
    """Create ``path``'s parent with 0700 (used by commands that write single files)."""
    return fsio.ensure_dir(Path(path).parent)
