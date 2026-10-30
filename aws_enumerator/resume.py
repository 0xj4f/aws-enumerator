"""``collect --resume`` and ``collect --global-from`` (cli.md §3.1; F-127, F-153).

**Resume** re-opens an existing run (by directory or run id), checks through STS that the credentials belong
to the same account (a mismatch exits 1), and re-runs every unit that did not finish cleanly:

* a unit is re-run when one of its modules is ``partial``, ``failed``, ``interrupted`` or ``not_run``
  (``denied`` only with ``--retry-denied``), when a file it wrote no longer matches ``manifest.files``, or when
  the manifest has no entry for it at all (the run was killed);
* before a unit is re-run its directory is renamed to ``<unit>.stale-<n>``; the stale copies are deleted when
  the unit completes (report-layout.md §1.1 rule 5);
* the selection, regions and collector options of the original run are reused; the new command line and its
  runtime overrides are appended to ``run.resumes``; analysis always runs again.

**--global-from RUN_DIR** copies ``global/`` from another v2 run of the same account after checking every
file against that run's ``manifest.files``, and records ``run.global_source``.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from aws_enumerator import output, registry
from aws_enumerator.aws_session import AwsSetupError, Identity, RegionPlan
from aws_enumerator.execution import UnitPlan
from aws_enumerator.util import fsio

__all__ = ["ResumePlan", "copy_global_from", "load_resume", "units_to_rerun"]

log = logging.getLogger("aws_enumerator.runner")

RERUN_STATUSES = frozenset({"partial", "failed", "interrupted", "not_run"})
#: Runtime flags a resume may change; recorded in ``run.resumes[].overrides``.
RUNTIME_FIELDS = ("concurrency", "retry_mode", "max_attempts", "retry_denied", "no_analysis", "zip",
                  "shutdown_grace")


def _usage(message: str) -> Exception:
    from aws_enumerator.runner import UsageFailure

    return UsageFailure(message)


def _load_v2(path: Path, flag: str) -> Dict[str, Any]:
    manifest = Path(path) / "manifest.json"
    try:
        doc = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise _usage(f"{flag}: {path} is not an aws-enumerator run (no readable manifest.json)") from None
    if not isinstance(doc, dict) or not str(doc.get("schema_version", "")).startswith("2."):
        raise _usage(f"{flag}: {path} is not a v2 run (legacy reports cannot be resumed or reused)")
    return doc


def _changed_units(run_root: Path, files: List[Dict[str, Any]]) -> Set[str]:
    changed = set()
    for entry in files:
        rel = str(entry.get("path", ""))
        unit = rel.split("/", 1)[0]
        if "/" not in rel or unit == "analysis":
            continue
        path = run_root / rel
        if not path.is_file() or fsio.sha256_file(path) != entry.get("sha256"):
            changed.add(unit)
    return changed


def units_to_rerun(doc: Dict[str, Any], run_root: Path, *, retry_denied: bool) -> List[str]:
    """Units of ``doc`` to collect again, ``global`` first, then regions in manifest order."""
    statuses = set(RERUN_STATUSES) | ({"denied"} if retry_denied else set())
    regions = list(doc["target"]["regions"])
    entries = doc.get("modules", [])
    seen = {e["region"] for e in entries}
    units = {e["region"] for e in entries if e["status"] in statuses}
    units |= {r for r in regions if r not in seen}
    if any(e["scope"] == "global" and e["status"] != "skipped" for e in entries) or "global" in units:
        units |= {u for u in _changed_units(run_root, doc.get("files", [])) if u == "global"}
    units |= {u for u in _changed_units(run_root, doc.get("files", [])) if u in regions}
    return sorted(units, key=lambda u: (u != "global", regions.index(u) if u in regions else 0, u))


def _denied_from_coverage(run_root: Path, entry: Dict[str, Any]) -> List[str]:
    if not entry.get("dir"):
        return []
    try:
        cov = json.loads((run_root / entry["dir"] / "_coverage.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return sorted({c["api"] for c in cov.get("calls", []) if c.get("status") == "denied" and c.get("api")})


@dataclass
class ResumePlan:
    """An existing run being resumed."""

    layout: output.RunLayout
    store: output.ManifestStore
    region_plan: RegionPlan
    units: List[str]
    old_options: Dict[str, Any] = field(default_factory=dict)

    def effective_request(self, req: Any) -> Any:
        """``req`` with the original run's selection and collector options (runtime flags stay as given)."""
        opts = self.old_options
        tuning = {k: v for k, v in opts.items() if k not in output_required_keys()}
        merged = {**req.collector_options, **tuning}
        return dataclasses.replace(
            req, modules=list(opts.get("modules", [])) or ["@default"], skip=[], k8s=bool(opts.get("k8s", True)),
            k8s_secrets=bool(opts.get("k8s_secrets", False)), max_tier=int(opts.get("max_tier", 2)),
            deny_breaker=int(opts.get("deny_breaker", req.deny_breaker)),
            redact_identity=bool(opts.get("redact_identity", req.redact_identity)), collector_options=merged,
            global_from=None, skip_global=False)

    def unit_plans(self, selection: Any) -> List[UnitPlan]:
        plans = []
        for unit in self.units:
            specs = selection.global_specs if unit == "global" else selection.regional_specs
            if specs:
                plans.append(UnitPlan(unit, list(specs)))
        return plans

    def begin(self, *, run_argv: List[str], overrides: Optional[Dict[str, Any]] = None) -> None:
        resumes = self.store.get("run", "resumes")
        resumes.append({"resumed_at": output.iso(), "argv": list(run_argv), "overrides": dict(overrides or {})})
        self.store.update("run", status="in_progress", exit_code=None, ended_at=None, duration_seconds=None,
                          resumes=resumes)
        self.store.set("analysis", output.empty_analysis())
        log.info("resuming run %s: re-running %s", self.layout.run_id, ", ".join(self.units) or "no unit")

    def prepare_unit(self, unit: str) -> None:
        current = self.layout.unit_dir(unit)
        if not current.exists():
            return
        n = 1
        while self.layout.run_root.joinpath(f"{unit}.stale-{n}").exists():
            n += 1
        os.replace(current, self.layout.run_root / f"{unit}.stale-{n}")

    def finish_unit(self, unit: str) -> None:
        for stale in sorted(self.layout.run_root.glob(f"{unit}.stale-*")):
            shutil.rmtree(stale, ignore_errors=True)


def output_required_keys() -> Set[str]:
    return {"regions_requested", "modules", "skipped_modules", "k8s", "k8s_secrets", "concurrency", "rate_limit",
            "max_tier", "deny_breaker", "redact_identity", "zip"}


def _run_root_for(value: str, output_root: Path, account_id: str) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_dir() and (candidate / "manifest.json").is_file():
        return candidate.absolute()
    output.validate_run_id(value)
    return output_root / account_id / value


def load_resume(req: Any, output_root: Path, identity: Identity) -> ResumePlan:
    run_root = _run_root_for(req.resume, output_root, identity.account_id)
    doc = _load_v2(run_root, "--resume")
    account = doc.get("target", {}).get("account_id")
    if account != identity.account_id:
        raise AwsSetupError(f"--resume: the run belongs to account {account}, but the credentials are for "
                            f"{identity.account_id}")
    output.git_guard(run_root, allow=req.allow_in_repo)
    layout = output.RunLayout(run_root.parent.parent, identity.account_id, run_root.name)
    order = {spec.name: i for i, spec in enumerate(registry.get_registry())}
    store = output.ManifestStore(layout.manifest_path, doc, order=order)
    target = doc["target"]
    plan = RegionPlan(target["home_region"], list(target["regions"]), target["region_source"],
                      list(doc["run"]["options"].get("regions_requested", [])), list(target["regions_skipped"]))
    units = units_to_rerun(doc, run_root, retry_denied=req.retry_denied)
    for entry in doc.get("modules", []):
        if entry["region"] not in units:
            store.remember_denied(entry["region"], entry["name"], _denied_from_coverage(run_root, entry))
    return ResumePlan(layout, store, plan, units, dict(doc["run"]["options"]))


def copy_global_from(source: Path, layout: output.RunLayout, identity: Identity) -> Dict[str, Any]:
    """Copy ``global/`` from another run of the same account (digests checked); returns ``run.global_source``."""
    doc = _load_v2(source, "--global-from")
    account = doc.get("target", {}).get("account_id")
    if account != identity.account_id:
        raise _usage(f"--global-from: that run belongs to account {account}, not {identity.account_id}")
    listed = [f for f in doc.get("files", []) if str(f.get("path", "")).startswith("global/")]
    if not listed:
        raise _usage(f"--global-from: {source} has no global/ data")
    for entry in listed:
        data = (Path(source) / entry["path"]).read_bytes() if (Path(source) / entry["path"]).is_file() else None
        if data is None or fsio.sha256_bytes(data) != entry["sha256"]:
            raise output.OutputError(f"--global-from: {entry['path']} is missing or does not match the source "
                                     f"manifest")
        fsio.atomic_write_bytes(layout.run_root / entry["path"], data)
    log.info("global/ copied from run %s (%d files)", doc["run"]["run_id"], len(listed))
    return {"run_id": doc["run"]["run_id"], "account_id": account,
            "manifest_sha256": fsio.sha256_file(Path(source) / "manifest.json")}
