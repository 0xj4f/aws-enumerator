"""Run layout, the git guard, ``HANDLING.txt`` and the thread-safe manifest writer.

Contracts: docs/contracts/report-layout.md (tree, run id, output root, git guard, permissions, HANDLING.txt)
and docs/contracts/manifest.md (``manifest.json`` schema 2.0, lifecycle, status, coverage summary).

* Every run gets its own directory ``<output>/<account>/<run_id>/`` (F-063, F-025): two runs never share
  files, and nothing outside the run root is read back.
* The output root is ``--output``, else ``$AWS_ENUMERATOR_OUTPUT``, else ``~/.aws-enumerator/reports``; writing
  inside a git work tree needs ``--allow-in-repo`` (exit 64 otherwise, F-066).
* Directories are created ``0700`` and files ``0600``, atomically (:mod:`aws_enumerator.util.fsio`, F-123).
* :class:`ManifestStore` writes ``manifest.json`` at run start (``in_progress``), after every unit and at
  finalisation, so an interrupted or killed run is always recognisable (F-155, F-061). Timestamps are UTC
  with ``Z`` (F-171). There is no ``author`` field (F-144).
"""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from aws_enumerator.util import fsio

__all__ = [
    "CLASSIFICATION", "DEFAULT_OUTPUT", "HANDLING_TEMPLATE", "MANIFEST_SCHEMA_VERSION", "ManifestStore",
    "OutputError", "OutputUsageError", "RunLayout", "coverage_summary", "create_run_root", "git_guard",
    "handling_text", "iso", "new_run_id", "resolve_output_root", "utc_now", "validate_run_id", "write_handling",
]

log = logging.getLogger("aws_enumerator.output")

MANIFEST_SCHEMA_VERSION = "2.0"
DEFAULT_OUTPUT = "~/.aws-enumerator/reports"
OUTPUT_ENV = "AWS_ENUMERATOR_OUTPUT"
CLASSIFICATION = "CONFIDENTIAL: pre-computed attack map of the target account; see HANDLING.txt"
RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MODULE_STATUS_ORDER = ("ok", "partial", "denied", "failed", "skipped", "interrupted", "not_run")

HANDLING_TEMPLATE = """\
aws-enumerator report: CONFIDENTIAL

Run:      {run_id}
Account:  {account_id}
Created:  {started_at}

This directory is a pre-computed attack map of the AWS account above: identities and
their effective permissions, trust relationships, network exposure, and resource policies.
Treat it like a credential.

  - Keep it encrypted at rest and in transit (aws-enumerator package --encrypt ...).
  - Do not commit it to version control or attach it to tickets or chat.
  - Share it only with people covered by the written authorisation for this assessment.
  - Delete it when the engagement's retention period ends.
  - Open the dashboard only on this machine (aws-enumerator dashboard binds 127.0.0.1),
    and open reports you did not produce only in an isolated browser profile.

The collectors are designed to leave out secret values (no S3 objects, no secret or parameter
values, no Kubernetes Secret data, no environment-variable values), but names, tags, policy
documents and configuration are copied as they are and may hold more than intended.
"""


class OutputUsageError(ValueError):
    """A bad output request (git work tree, bad or existing run id): exit 64."""


class OutputError(Exception):
    """The output cannot be written: exit 1."""


# ── time ─────────────────────────────────────────────────────────────────────
def utc_now() -> datetime:
    """The current time, aware UTC (``datetime`` is looked up here so tests can freeze it)."""
    now = datetime.now(timezone.utc)
    return now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)


def iso(value: Optional[datetime] = None) -> str:
    """``2026-10-15T10:15:02Z`` (F-171)."""
    return fsio.iso_z(value if value is not None else utc_now())


# ── output root, guard, run id ───────────────────────────────────────────────
def resolve_output_root(arg: Optional[str]) -> Path:
    """``--output``, else ``$AWS_ENUMERATOR_OUTPUT``, else ``~/.aws-enumerator/reports`` (report-layout.md §2)."""
    raw = arg or os.environ.get(OUTPUT_ENV) or DEFAULT_OUTPUT
    return Path(raw).expanduser().absolute()


def git_guard(path: Path, *, allow: bool) -> None:
    """Refuse an output path inside a git work tree unless ``--allow-in-repo`` (F-066)."""
    worktree = fsio.find_git_worktree(path)
    if worktree is None:
        return
    if allow:
        log.warning("writing inside the git work tree %s (--allow-in-repo); reports are confidential", worktree,
                    extra={"console_only": True})
        return
    raise OutputUsageError(
        f"output directory {path} is inside the git work tree {worktree}; reports are confidential.\n"
        "       Use --output outside the repository, or pass --allow-in-repo if you really mean it.")


def new_run_id(now: Optional[datetime] = None) -> str:
    """``<UTC %Y%m%dT%H%M%SZ>-<6 hex>`` (lexical order = chronological order)."""
    stamp = (now or utc_now()).astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{secrets.token_hex(3)}"


def validate_run_id(value: str) -> str:
    if not RUN_ID_RE.match(value or "") or value in (".", ".."):
        raise OutputUsageError(f"--run-id {value!r} must match {RUN_ID_RE.pattern} (and not be '.' or '..')")
    return value


@dataclass(frozen=True)
class RunLayout:
    """Paths of one run (report-layout.md §1)."""

    output_root: Path
    account_id: str
    run_id: str

    @property
    def account_dir(self) -> Path:
        return self.output_root / self.account_id

    @property
    def run_root(self) -> Path:
        return self.account_dir / self.run_id

    @property
    def manifest_path(self) -> Path:
        return self.run_root / "manifest.json"

    @property
    def handling_path(self) -> Path:
        return self.run_root / "HANDLING.txt"

    @property
    def log_path(self) -> Path:
        return self.run_root / "run.log"

    @property
    def sums_path(self) -> Path:
        return self.run_root / "SHA256SUMS"

    @property
    def analysis_dir(self) -> Path:
        return self.run_root / "analysis"

    @property
    def zip_path(self) -> Path:
        return self.account_dir / f"{self.run_id}.zip"

    def unit_dir(self, unit: str) -> Path:
        return self.run_root / unit


def create_run_root(layout: RunLayout, *, exist_ok: bool = False) -> Path:
    """Create ``<output>/<account>/<run_id>/`` (0700 for each component created)."""
    if layout.run_root.exists() and not exist_ok:
        raise OutputUsageError(f"run {layout.run_id} already exists at {layout.run_root} (use --resume)")
    try:
        return fsio.ensure_dir(layout.run_root)
    except OSError as exc:
        raise OutputError(f"cannot create the run directory {layout.run_root}: {exc.strerror or exc}") from None


def handling_text(run_id: str, account_id: str, started_at: str) -> str:
    return HANDLING_TEMPLATE.format(run_id=run_id, account_id=account_id, started_at=started_at)


def write_handling(layout: RunLayout, started_at: str) -> Path:
    """``HANDLING.txt`` at run start, so even an interrupted run carries it (F-159)."""
    return fsio.atomic_write_text(layout.handling_path, handling_text(layout.run_id, layout.account_id, started_at))


# ── manifest ─────────────────────────────────────────────────────────────────
def _unit_rank(unit: str, regions: Sequence[str]) -> Tuple[int, int, str]:
    if unit == "global":
        return 0, 0, unit
    try:
        return 1, list(regions).index(unit), unit
    except ValueError:
        return 2, 0, unit


def coverage_summary(entries: Iterable[Mapping[str, Any]],
                     denied: Mapping[Tuple[str, str], Sequence[str]]) -> Dict[str, Any]:
    """``manifest.coverage_summary`` recomputed from the module entries (manifest.md §3.9)."""
    by_status: Dict[str, int] = {}
    partial: List[str] = []
    failed: List[str] = []
    throttled = item_errors = 0
    entries = list(entries)
    for entry in entries:
        status = entry["status"]
        by_status[status] = by_status.get(status, 0) + 1
        label = f"{entry['name']}@{entry['region']}"
        if status == "partial":
            partial.append(label)
        elif status == "failed":
            failed.append(label)
        cov = entry.get("coverage") or {}
        throttled += int(cov.get("throttled", 0))
        item_errors += int(cov.get("item_errors", 0))
    apis: Dict[str, set] = {}
    for (unit, _name), names in denied.items():
        for api in names:
            apis.setdefault(api, set()).add(unit)
    denied_apis = [{"api": api, "regions": sorted(units, key=lambda u: (u != "global", u))}
                   for api, units in sorted(apis.items())]
    return {
        "modules_by_status": {k: by_status[k] for k in MODULE_STATUS_ORDER if by_status.get(k)},
        "denied_apis": denied_apis,
        "partial_modules": sorted(partial),
        "failed_modules": sorted(failed),
        "throttled_calls": throttled,
        "item_errors": item_errors,
    }


def empty_analysis() -> Dict[str, Any]:
    return {"status": "not_run", "engine": None, "started_at": None, "duration_seconds": None, "error": None,
            "dir": "analysis", "graph_schema_version": None}


class ManifestStore:
    """Thread-safe owner of one ``manifest.json``; every change is written atomically."""

    def __init__(self, path: Path, doc: Dict[str, Any], *, order: Optional[Mapping[str, int]] = None):
        self.path = Path(path)
        self._doc = doc
        self._order = dict(order or {})
        self._lock = threading.RLock()
        self._entries: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._denied: Dict[Tuple[str, str], List[str]] = {}
        for entry in doc.get("modules", []):
            self._entries[(entry["region"], entry["name"])] = dict(entry)

    # -- construction -----------------------------------------------------------
    @classmethod
    def new(cls, path: Path, *, tool: Mapping[str, Any], run: Mapping[str, Any], target: Mapping[str, Any],
            operator: Mapping[str, Any], order: Optional[Mapping[str, int]] = None) -> "ManifestStore":
        run_doc = {"run_id": None, "kind": "collect", "status": "in_progress", "started_at": None, "ended_at": None,
                   "duration_seconds": None, "exit_code": None, "argv": [], "options": {}, "resumes": [],
                   "global_source": None}
        run_doc.update(run)
        doc = {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "tool": dict(tool),
            "run": run_doc,
            "target": dict(target),
            "operator": dict(operator),
            "classification": CLASSIFICATION,
            "preflight": None,
            "modules": [],
            "analysis": empty_analysis(),
            "coverage_summary": coverage_summary([], {}),
            "files": [],
        }
        return cls(path, doc, order=order)

    @classmethod
    def load(cls, path: Path, *, order: Optional[Mapping[str, int]] = None) -> "ManifestStore":
        """Open an existing manifest; without ``order`` the module order already in the file is kept."""
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            raise OutputUsageError(f"{path} is not a readable manifest") from None
        if not isinstance(doc, dict) or not str(doc.get("schema_version", "")).startswith("2."):
            raise OutputUsageError(f"{path} is not a v2 manifest")
        if order is None:
            order = {}
            for index, entry in enumerate(doc.get("modules", [])):
                if isinstance(entry, dict) and "name" in entry:
                    order.setdefault(entry["name"], index)
        return cls(Path(path), doc, order=order)

    # -- access -------------------------------------------------------------------
    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._doc)

    def get(self, *keys: str) -> Any:
        with self._lock:
            value: Any = self._doc
            for key in keys:
                value = value[key]
            return copy.deepcopy(value)

    def entries(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(e) for e in self._sorted_entries()]

    # -- mutation -----------------------------------------------------------------
    def save(self) -> Path:
        with self._lock:
            try:
                return fsio.atomic_write_json(self.path, self._doc)
            except OSError as exc:
                raise OutputError(f"cannot write {self.path}: {exc.strerror or exc}") from None

    def update(self, section: str, **fields: Any) -> None:
        """Merge ``fields`` into ``doc[section]`` (``run``, ``analysis``, ``target`` ...) and save."""
        with self._lock:
            self._doc[section].update(fields)
            self.save()

    def set(self, key: str, value: Any, *, save: bool = True) -> None:
        with self._lock:
            self._doc[key] = value
            if save:
                self.save()

    def _sorted_entries(self) -> List[Dict[str, Any]]:
        regions = self._doc.get("target", {}).get("regions", [])
        return [self._entries[k] for k in sorted(
            self._entries, key=lambda k: (_unit_rank(k[0], regions), self._order.get(k[1], 1 << 20), k[1]))]

    def record(self, results: Iterable[Any], *, resumed: bool = False) -> None:
        """Add or replace module results (``ModuleResult``) and recompute the coverage summary; save."""
        with self._lock:
            for res in results:
                entry = res.manifest_entry()
                entry["resumed"] = bool(resumed or entry.get("resumed"))
                key = (entry["region"], entry["name"])
                self._entries[key] = entry
                self._denied[key] = list(getattr(res, "denied_apis", []) or [])
            self._refresh()
            self.save()

    def remember_denied(self, unit: str, name: str, apis: Sequence[str]) -> None:
        """Denied APIs of a module kept from an earlier run (``--resume`` reads them from ``_coverage.json``)."""
        with self._lock:
            self._denied[(unit, name)] = list(apis)

    def _refresh(self) -> None:
        entries = self._sorted_entries()
        self._doc["modules"] = entries
        self._doc["coverage_summary"] = coverage_summary(entries, self._denied)

    def refresh(self) -> None:
        with self._lock:
            self._refresh()
            self.save()

    def finalize(self, *, status: str, exit_code: int, ended_at: datetime, files: List[Dict[str, Any]]) -> None:
        with self._lock:
            run = self._doc["run"]
            started = _parse_iso(run.get("started_at"))
            run.update(status=status, exit_code=exit_code, ended_at=iso(ended_at),
                       duration_seconds=round(max(0.0, (ended_at - started).total_seconds()), 3) if started else None)
            self._doc["files"] = files
            self._refresh()
            self.save()


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
