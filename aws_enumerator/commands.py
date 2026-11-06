"""Subcommands that need no AWS credentials: analyze, export, merge, dashboard, permissions, modules, package,
verify and version (cli.md §3.2-§3.11).

Each function returns a :class:`CommandOutcome` (exit code plus what the CLI writes to stdout); nothing here
prints (F-169, cli.md §5). Usage problems are exit 64, failures exit 1. Every command that writes report data
sets ``umask 077`` and applies the git guard (report-layout.md §2-§3, F-066, F-123).
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

from aws_enumerator import archive, engine_adapter, integrity
from aws_enumerator import output as run_output
from aws_enumerator.util import fsio

__all__ = [
    "CommandOutcome", "analyze", "classify_report", "dashboard", "export", "merge", "modules",
    "package", "permissions", "verify", "version",
]

log = logging.getLogger("aws_enumerator.cli")

EXIT_OK, EXIT_PARTIAL, EXIT_FATAL, EXIT_USAGE = 0, 2, 1, 64
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_ANALYSIS_EXIT = {"ok": EXIT_OK, "partial": EXIT_PARTIAL, "failed": EXIT_FATAL}


@dataclass
class CommandOutcome:
    """The exit code, stdout lines, and optional raw bytes for stdout (``export --output -``)."""

    exit_code: int
    stdout: List[str] = field(default_factory=list)
    data: Optional[bytes] = None


def _usage(message: str) -> CommandOutcome:
    log.error("%s", message)
    return CommandOutcome(EXIT_USAGE)


def _fatal(message: str) -> CommandOutcome:
    log.error("%s", message)
    return CommandOutcome(EXIT_FATAL)


@contextlib.contextmanager
def _private_umask() -> Iterator[None]:
    previous = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(previous)


def _read_manifest(run_root: Path) -> Optional[Dict[str, Any]]:
    try:
        doc = json.loads((run_root / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def classify_report(path: Path) -> Optional[str]:
    """``run`` (v2), ``legacy-all``, ``legacy-single`` or ``None`` (report-layout.md §8, D-20)."""
    doc = _read_manifest(path)
    if doc is not None and str(doc.get("schema_version", "")).split(".")[0] == "2":
        return "run"
    if (path / "global").is_dir():
        return "legacy-all"
    if (path / "iam").is_dir():
        return "legacy-single"
    return None


# ── analyze ──────────────────────────────────────────────────────────────────
def _missing_input(baseline: Optional[str], suppress: Optional[str]) -> Optional[str]:
    for flag, value in (("--baseline", baseline), ("--suppress", suppress)):
        if value and not Path(value).expanduser().exists():
            return f"{flag}: {value} does not exist"
    return None


def _refresh_digests(store: run_output.ManifestStore, run_root: Path) -> None:
    files = integrity.compute_files(run_root)
    store.set("files", files)
    integrity.write_sha256sums(run_root, files)


def _analyze_v2(run_root: Path, *, force: bool, baseline: Optional[str], suppress: Optional[str],
                redact_identity: bool, legacy_outputs: bool = True) -> CommandOutcome:
    store = run_output.ManifestStore.load(run_root / "manifest.json")
    if store.get("run").get("kind") == "merge":
        return _usage("a merged run cannot be re-analysed; run 'aws-enumerator merge' on its sources again")
    if store.get("run", "status") == "in_progress" and not force:
        return _usage(f"run {run_root.name} is still in progress; wait for it, resume it, or pass --force")
    store.update("analysis", **{**run_output.empty_analysis(), "status": "in_progress", "started_at": run_output.iso()})
    outcome = engine_adapter.analyze_run_root(run_root, regions=store.get("target", "regions"),
                                              manifest=store.snapshot(), baseline=baseline, suppress=suppress,
                                              redact_identity=redact_identity, force=True,
                                              legacy_outputs=legacy_outputs)
    store.update("analysis", **outcome.manifest_fields())
    _refresh_digests(store, run_root)
    if outcome.status != "ok":
        log.warning("analysis %s: %s", outcome.status, outcome.error or "see analyzer_status in graph.json")
    lines = [str(outcome.analysis_dir)] if outcome.analysis_dir is not None and outcome.status != "failed" else []
    return CommandOutcome(_ANALYSIS_EXIT.get(outcome.status, EXIT_FATAL), lines)


def analyze(path: str, *, force: bool = False, allow_in_repo: bool = False, baseline: Optional[str] = None,
            suppress: Optional[str] = None, redact_identity: bool = False,
            legacy_outputs: bool = True) -> CommandOutcome:
    """``aws-enumerator analyze <dir>`` (cli.md §3.2): v2 runs and the two legacy layouts.

    ``legacy_outputs=False`` (``--no-legacy-outputs``) leaves the d13c215 legacy files out of ``analysis/``.
    """
    target = Path(path).expanduser().absolute()
    kind = classify_report(target) if target.is_dir() else None
    if kind is None:
        return _usage(f"{path} is not an aws-enumerator report (no v2 manifest.json, global/ or iam/)")
    problem = _missing_input(baseline, suppress)
    if problem:
        return _usage(problem)
    try:
        engine_adapter.validate_analysis_inputs(baseline=baseline, suppress=suppress)
        run_output.git_guard(target, allow=allow_in_repo)
        with _private_umask():
            if kind == "run":
                return _analyze_v2(target, force=force, baseline=baseline, suppress=suppress,
                                   redact_identity=redact_identity, legacy_outputs=legacy_outputs)
            outcome = engine_adapter.analyze_report_dir(target, baseline=baseline, suppress=suppress,
                                                        redact_identity=redact_identity, force=force,
                                                        legacy_outputs=legacy_outputs)
    except (run_output.OutputUsageError, engine_adapter.AnalysisUsage) as exc:
        return _usage(str(exc))
    except (run_output.OutputError, OSError) as exc:
        return _fatal(f"analysis output could not be written: {exc}")
    if outcome.status != "ok":
        log.warning("analysis %s: %s", outcome.status, outcome.error or "see analyzer_status in graph.json")
    lines = [str(outcome.analysis_dir)] if outcome.analysis_dir is not None and outcome.status != "failed" else []
    return CommandOutcome(_ANALYSIS_EXIT.get(outcome.status, EXIT_FATAL), lines)


# ── export ───────────────────────────────────────────────────────────────────
def _writers() -> Any:
    """The engine's export dispatcher (engine-api.md §6.3), imported on first use."""
    from aws_enumerator.engine import writers

    return writers


def _load_graph(run_root: Path) -> Tuple[Optional[Mapping[str, Any]], Optional[CommandOutcome]]:
    graph_path = run_root / "analysis" / "graph.json"
    if not graph_path.is_file():
        if run_root.is_dir() and classify_report(run_root) is not None:
            return None, _usage(f"{run_root} has no analysis/graph.json; run 'aws-enumerator analyze {run_root}' "
                                f"first")
        return None, _usage(f"{run_root} is not an aws-enumerator report")
    try:
        graph = json.loads(graph_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, _fatal(f"cannot read {graph_path}: {type(exc).__name__}")
    if not isinstance(graph, dict) or str(graph.get("schema_version", "")).split(".")[0] != "1":
        return None, _fatal(f"{graph_path} is not a graph.json 1.x document")
    return graph, None


def export(path: str, fmt: str, *, output: Optional[str] = None, min_severity: Optional[str] = None,
           include_suppressed: bool = False, all_edges: bool = False,
           allow_in_repo: bool = False) -> CommandOutcome:
    """``aws-enumerator export <dir> --format F`` (cli.md §3.3): renders through ``engine.writers.export``."""
    run_root = Path(path).expanduser().absolute()
    graph, problem = _load_graph(run_root)
    if problem is not None:
        return problem
    writers = _writers()
    try:
        data = writers.export(graph, fmt, min_severity=min_severity, include_suppressed=include_suppressed,
                              all_edges=all_edges)
    except NotImplementedError:
        return _fatal(f"export format '{fmt}' is not available in this build")
    except ValueError as exc:
        return _usage(f"export: {exc}")
    if output == "-":
        return CommandOutcome(EXIT_OK, data=bytes(data))
    dest = (Path(output).expanduser().absolute() if output
            else run_root / "analysis" / "exports" / writers.export_file_name(fmt))
    try:
        output_guard(dest, allow_in_repo)
        with _private_umask():
            fsio.atomic_write_bytes(dest, bytes(data))
    except run_output.OutputUsageError as exc:
        return _usage(str(exc))
    except OSError as exc:
        return _fatal(f"cannot write {dest}: {exc.strerror or exc}")
    return CommandOutcome(EXIT_OK, [str(dest)])


def output_guard(dest: Path, allow_in_repo: bool) -> None:
    """The git guard for a single output file (its directory or nearest existing ancestor)."""
    run_output.git_guard(dest.parent, allow=allow_in_repo)


# ── merge ────────────────────────────────────────────────────────────────────
MERGED_DIR = "merged"
#: manifest.md §3.11: the collect-only required ``run.options`` keys, with neutral values.
MERGE_NEUTRAL_OPTIONS: Mapping[str, Any] = {
    "regions_requested": [], "modules": [], "skipped_modules": [], "k8s": False, "k8s_secrets": False,
    "concurrency": 1, "rate_limit": {"enabled": False, "default_rps": None, "max_rps": None, "overrides": {}},
    "max_tier": 2, "deny_breaker": 0, "redact_identity": False,
}


def _merge_layout(output: Optional[str], run_id: Optional[str]) -> run_output.RunLayout:
    """``<output>/merged/<run_id>/`` (cli.md §3.8); a bad or existing run id is a usage error."""
    root = run_output.resolve_output_root(output)
    rid = run_output.validate_run_id(run_id) if run_id else run_output.new_run_id()
    layout = run_output.RunLayout(root, MERGED_DIR, rid)
    if layout.run_root.exists():
        raise run_output.OutputUsageError(f"--run-id {rid}: {layout.run_root} already exists")
    return layout


def _merge_manifest(layout: run_output.RunLayout, doc: Mapping[str, Any], argv: Sequence[str], started: Any,
                    ended: Any) -> run_output.ManifestStore:
    """The merge manifest of manifest.md §3.11 (written once, ``complete`` / 0)."""
    from aws_enumerator.buildinfo import tool_info
    from aws_enumerator.registry import global_region_for

    graph_run = doc["run"]
    try:
        global_region = global_region_for(graph_run["partition"])
    except ValueError:
        global_region = "us-east-1"
    run = {"run_id": layout.run_id, "kind": "merge", "status": "complete", "exit_code": 0,
           "started_at": run_output.iso(started), "ended_at": run_output.iso(ended),
           "duration_seconds": round(max(0.0, (ended - started).total_seconds()), 3), "argv": list(argv),
           "options": json.loads(json.dumps(MERGE_NEUTRAL_OPTIONS)), "resumes": [], "global_source": None,
           "sources": [{"run_id": s["run_id"], "account_id": s["account_id"], "graph_sha256": s["graph_sha256"]}
                       for s in graph_run["sources"]]}
    target = {"account_id": graph_run["account_id"], "partition": graph_run["partition"],
              "home_region": global_region, "global_region": global_region, "regions": list(graph_run["regions"]),
              "region_source": "merge", "regions_skipped": []}
    operator = {"caller_arn": None, "caller_user_id": None, "caller_arn_sha256": None, "principal_arn": None,
                "principal_type": "unknown", "redacted": False}
    store = run_output.ManifestStore.new(layout.manifest_path, tool=tool_info(), run=run, target=target,
                                         operator=operator)
    store.set("analysis", {"status": "ok", "engine": "v2", "started_at": run_output.iso(started),
                           "duration_seconds": run["duration_seconds"], "error": None, "dir": "analysis",
                           "graph_schema_version": doc["schema_version"]}, save=False)
    return store


def _write_merged_root(layout: run_output.RunLayout, doc: Mapping[str, Any], argv: Sequence[str],
                       started: Any) -> None:
    """Run root (0700), ``analysis/graph.json``, ``HANDLING.txt``, ``manifest.json`` (once), ``SHA256SUMS``."""
    from aws_enumerator.engine import merge as engine_merge

    run_output.create_run_root(layout)
    engine_merge.write_merged(doc, layout.run_root)
    accounts = ", ".join(s["account_id"] for s in doc["run"]["sources"])
    fsio.atomic_write_text(layout.handling_path, run_output.handling_text(layout.run_id, accounts,
                                                                          run_output.iso(started)))
    files = integrity.compute_files(layout.run_root)
    store = _merge_manifest(layout, doc, argv, started, run_output.utc_now())
    store.set("files", files, save=False)
    store.save()
    integrity.write_sha256sums(layout.run_root, files)


def merge(runs: Sequence[str], *, output: Optional[str] = None, run_id: Optional[str] = None,
          allow_in_repo: bool = False, argv: Sequence[str] = ()) -> CommandOutcome:
    """``aws-enumerator merge RUN_DIR RUN_DIR ...`` (cli.md §3.8, F-126; graph 1.1, D-42 to D-45).

    The merged document is built and validated in memory before the run root exists, so a failing merge writes
    nothing. Exit 64 for unmergeable inputs and output usage errors, 1 for invalid graphs and write failures.
    """
    from aws_enumerator.buildinfo import git_sha
    from aws_enumerator.engine import merge as engine_merge
    from aws_enumerator.engine.model import AnalysisUsageError

    if len(runs) < 2:
        return _usage("merge needs at least two RUN_DIRs (analysed runs of different accounts)")
    started = run_output.utc_now()
    try:
        layout = _merge_layout(output, run_id)
        run_output.git_guard(layout.run_root.parent, allow=allow_in_repo)
        sources = engine_merge.plan_merge(list(runs))
        doc = engine_merge.merge_graphs(sources, run_id=layout.run_id, git_sha=git_sha())
    except (run_output.OutputUsageError, AnalysisUsageError) as exc:
        return _usage(f"merge: {exc}")
    except engine_merge.MergeInvalid as exc:
        return _fatal(f"merge: {exc}")
    try:
        with _private_umask():
            _write_merged_root(layout, doc, argv, started)
    except run_output.OutputUsageError as exc:
        return _usage(f"merge: {exc}")
    except (run_output.OutputError, OSError) as exc:
        return _fatal(f"merge: the merged run could not be written: {exc}")
    log.info("merged %d runs (%s) into %s", len(sources), ", ".join(s.account_id for s in sources),
             layout.run_id)
    return CommandOutcome(EXIT_OK, [str(layout.run_root)])


# ── dashboard ────────────────────────────────────────────────────────────────
def dashboard(path: Optional[str], *, host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True,
              allowed_hosts: Sequence[str] = (), announce: Optional[Callable[[str], None]] = None) -> CommandOutcome:
    """``aws-enumerator dashboard`` (cli.md §3.7): validated options passed to ``serve_dashboard``.

    ``announce(url)`` writes the URL to stdout (cli.md §5); the server calls it as ``on_listening`` once the socket
    is bound, with the bound port (F-129, F-139). A non-loopback ``host`` never opens a browser (F-128).
    """
    from aws_enumerator.dashboard import server

    loopback = host in LOOPBACK_HOSTS
    if not loopback:
        log.warning("--host %s: the dashboard is reachable beyond this machine; reports loaded into it are "
                    "confidential (no browser is opened)", host)
    if path:
        log.info("dashboard: load %s with the page's file picker (the server never serves report files)", path)
    try:
        result = server.serve_dashboard(host=host, port=port, open_browser=open_browser and loopback,
                                        allowed_hosts=tuple(allowed_hosts), on_listening=announce)
    except OSError as exc:
        return _fatal(f"dashboard: cannot bind {host}:{port} ({exc.strerror or exc})")
    return CommandOutcome(EXIT_FATAL if result is False else EXIT_OK)


# ── permissions / modules ────────────────────────────────────────────────────
def permissions(fmt: str, *, modules: Sequence[str] = (), skip: Sequence[str] = (), k8s: bool = True,
                k8s_secrets: bool = False, max_tier: int = 2, partition: str = "aws",
                include_optional: bool = False, guardrail: bool = False) -> CommandOutcome:
    """``aws-enumerator permissions`` (cli.md §3.5): offline, from the selected registry specs."""
    from aws_enumerator import permissions as perms
    from aws_enumerator import registry

    try:
        selection = registry.select(list(modules) or None, list(skip) or None, k8s=k8s, max_tier=max_tier,
                                    partition=partition)
    except registry.SelectionError as exc:
        return _usage(str(exc))
    opts = perms.PolicyOptions(partition=partition, max_tier=max_tier, include_optional=include_optional,
                               guardrail=guardrail, k8s_secrets=k8s_secrets)
    specs = list(selection.specs)
    if fmt == "k8s":
        return CommandOutcome(EXIT_OK, [perms.build_k8s_rbac(specs, opts).rstrip("\n")])
    if fmt == "markdown":
        return CommandOutcome(EXIT_OK, [perms.render_markdown(specs, opts).rstrip("\n")])
    return CommandOutcome(EXIT_OK, [json.dumps(perms.build_iam_policy(specs, opts), indent=2)])


def modules(fmt: str = "table") -> CommandOutcome:
    """``aws-enumerator modules`` (cli.md §3.6)."""
    from aws_enumerator import registry

    specs = list(registry.get_registry())
    if fmt == "json":
        return CommandOutcome(EXIT_OK, [json.dumps([spec.to_json() for spec in specs], indent=2)])
    header = ("name", "scope", "default", "tier", "cost", "noise", "groups", "actions", "state")
    rows = [header] + [(s.name, s.scope, "yes" if s.default else "no", str(s.tier), s.cost, s.noise,
                        " ".join(s.groups) or "-", str(len(s.actions)), "planned" if s.planned else "implemented")
                       for s in specs]
    widths = [max(len(row[i]) for row in rows) for i in range(len(header))]
    return CommandOutcome(EXIT_OK, ["  ".join(cell.ljust(w) for cell, w in zip(row, widths, strict=True)).rstrip()
                                    for row in rows])


# ── package / verify / version ───────────────────────────────────────────────
def _package_target(run_root: Path, run_id: str, out: Optional[str]) -> Path:
    if not out:
        return run_root.parent / f"{run_id}.zip"
    dest = Path(out).expanduser().absolute()
    return dest / f"{run_id}.zip" if dest.is_dir() or out.endswith(os.sep) else dest


def _archive(run_root: Path, dest: Path, doc: Mapping[str, Any], encrypt: Optional[archive.ToolSpec],
             sign: Optional[archive.ToolSpec]) -> Path:
    path = archive.build_zip(run_root, dest, doc)
    digest = archive.file_sha256(path)
    log.info("zip: %s sha256 %s", path, digest, extra={"event": "zip.written", "sha256": digest})
    if encrypt:
        path = archive.encrypt(path, encrypt)
        log.info("encrypted: %s sha256 %s", path, archive.file_sha256(path))
    if sign:
        log.info("signature: %s", archive.sign(path, sign))
    return path


def package(path: str, *, output: Optional[str] = None, encrypt: Optional[archive.ToolSpec] = None,
            sign: Optional[archive.ToolSpec] = None, allow_in_repo: bool = False,
            force: bool = False) -> CommandOutcome:
    """``aws-enumerator package <run>`` (cli.md §3.9, F-145): the deterministic zip, then encrypt/sign."""
    run_root = Path(path).expanduser().absolute()
    doc = _read_manifest(run_root) if run_root.is_dir() else None
    if doc is None or str(doc.get("schema_version", "")).split(".")[0] != "2":
        return _usage(f"{path} is not a v2 aws-enumerator run (legacy reports cannot be packaged)")
    if (doc.get("run") or {}).get("status") == "in_progress" and not force:
        return _usage(f"run {run_root.name} is still in progress; pass --force to package it anyway")
    for spec in (encrypt, sign):
        if spec and archive.shutil.which(spec[0]) is None:
            return _fatal(f"'{spec[0]}' is not installed (or not on PATH)")
    dest = _package_target(run_root, str((doc.get("run") or {}).get("run_id") or run_root.name), output)
    try:
        output_guard(dest, allow_in_repo)
        with _private_umask():
            final = _archive(run_root, dest, doc, encrypt, sign)
    except run_output.OutputUsageError as exc:
        return _usage(str(exc))
    except (archive.ArchiveError, OSError) as exc:
        return _fatal(str(exc))
    return CommandOutcome(EXIT_OK, [str(final)])


def verify(path: str) -> CommandOutcome:
    """``aws-enumerator verify <run|zip>`` (cli.md §3.10, F-168)."""
    target = Path(path).expanduser().absolute()
    if not target.exists():
        return _usage(f"{path} does not exist")
    try:
        report = integrity.verify_path(target)
    except (ValueError, zipfile.BadZipFile) as exc:
        return _usage(f"{path}: {exc}")
    return CommandOutcome(EXIT_OK if report.ok else EXIT_FATAL, report.lines())


def version(*, as_json: bool = False) -> CommandOutcome:
    """``aws-enumerator version [--json]`` (cli.md §3.11, F-122)."""
    from aws_enumerator.buildinfo import tool_info, version_line

    if as_json:
        info = tool_info()
        keys = ("version", "git_sha", "python", "boto3", "botocore", "kubernetes")
        return CommandOutcome(EXIT_OK, [json.dumps({k: info[k] for k in keys})])
    return CommandOutcome(EXIT_OK, [version_line()])
