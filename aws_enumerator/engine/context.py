"""``AnalysisContext``: what one analysis reads, built from an **explicit** region list (engine-api.md §6.1).

d13c215 discovered regions by listing sibling directories in ten different loaders, so a run imported
stale regions of an earlier run (F-063), an empty region imported its neighbour's instances and clusters
(F-025), and ``--all`` analysed before the regions existed (F-010). Here the region list is always explicit:

* a v2 run (manifest ``schema_version`` 2.x) analyses exactly ``manifest.target.regions`` (or the
  ``regions`` the runner passes); any other directory under the run root is reported in
  ``summary.ignored_dirs`` and never read;
* an old ``--all`` account directory (``legacy-all``) analyses the child directories whose names are AWS
  regions of any partition;
* an old single-region directory (``legacy-single``) analyses itself as its own region (none when its name
  is not a region: gap ``legacy:region-unknown``).

The context also fixes the run identity (account, partition, run id, mode), the operator identity
(F-146), and the only clock values: ``generated_at`` (UTC, ``SOURCE_DATE_EPOCH``-aware, F-171) and
``reference_time``, the instant the collected data describes: ``SOURCE_DATE_EPOCH`` when set, else the run's
recorded start (manifest ``run.started_at``, then ``ended_at``; old layouts: ``run_metadata.timestamp_start``, then
the ``YYYYMMDD`` date directory). Analyzers compute ages and evaluate time conditions against it, never against the
wall clock, so two analyses of the same report are identical apart from ``generated_at`` (F-162); only when the
report records no time at all does the wall clock stand in, disclosed as the gap ``clock:reference-time-unknown``.
"""

from __future__ import annotations

import datetime as _dt
import functools
import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from aws_enumerator.engine.graph.builder import OperatorInput
from aws_enumerator.engine.io.coverage import CoverageLedger
from aws_enumerator.engine.io.fs import ls_sorted, read_json
from aws_enumerator.engine.model import AnalysisOptions, AnalysisUsageError

log = logging.getLogger(__name__)

MODES: Tuple[str, ...] = ("run", "legacy-all", "legacy-single")
ANALYSIS_DIR, TMP_DIR, PREV_DIR, ORIG_DIR = "analysis", "analysis.tmp", "analysis.prev", "analysis.orig"
_RESERVED = frozenset({"global", ANALYSIS_DIR, TMP_DIR, PREV_DIR})
_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-[0-9]+$")
_ACCT_RE = re.compile(r"^\d{12}$")
_RUN_ID_BAD = re.compile(r"[^A-Za-z0-9._-]")
#: Report-level gaps every analysis discloses (graph-json.md §10.2).
ALWAYS_GAPS: Mapping[str, str] = {
    "external-identity": "Identity policies of external principals are not visible; cross-account edges are "
                         "conditional.",
    "runtime-conditions": "Condition values known only at request time (source IP, MFA, tags in the request) "
                          "are not evaluated; such decisions are conditional.",
    "session-policies": "Session policies passed at AssumeRole time can only narrow permissions and are not "
                        "modelled.",
}


# ── regions and partitions ────────────────────────────────────────────────────

@functools.lru_cache(maxsize=1)
def region_partitions() -> Mapping[str, str]:
    """Every region known to botocore (all partitions) and to ``util/regions.json`` → its partition."""
    out: Dict[str, str] = {}
    try:
        import botocore.loaders

        for part in botocore.loaders.Loader().load_data("endpoints").get("partitions", []):
            for region in part.get("regions", {}):
                out[region] = part.get("partition", "aws")
    except Exception as exc:  # noqa: BLE001 - offline data; fall back to the shipped list
        log.debug("botocore endpoint data unavailable: %s", type(exc).__name__)
    shipped = Path(__file__).resolve().parent.parent / "util" / "regions.json"
    res = read_json(shipped)
    for rec in res.data if res.ok and isinstance(res.data, list) else ():
        code = rec.get("code") if isinstance(rec, Mapping) else None
        if isinstance(code, str):
            out.setdefault(code, partition_of_region(code))
    return out


def partition_of_region(region: str) -> str:
    for prefix, part in (("cn-", "aws-cn"), ("us-gov-", "aws-us-gov"), ("us-isob-", "aws-iso-b"),
                         ("us-iso-", "aws-iso"), ("eu-isoe-", "aws-iso-e"), ("us-isof-", "aws-iso-f")):
        if region.startswith(prefix):
            return part
    return "aws"


def is_known_region(name: str) -> bool:
    return name in region_partitions()


# ── clock ─────────────────────────────────────────────────────────────────────

def _epoch(options: AnalysisOptions) -> Optional[int]:
    if options.source_date_epoch is not None:
        return int(options.source_date_epoch)
    raw = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    return int(raw) if raw.isdigit() else None


def iso_utc(value: _dt.datetime) -> str:
    return value.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc(text: Any) -> Optional[_dt.datetime]:
    if not isinstance(text, str) or not text:
        return None
    try:
        value = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=_dt.timezone.utc)


# ── the context ───────────────────────────────────────────────────────────────

@dataclass
class AnalysisContext:
    """Read-only facts of one analysis plus the shared stores the pipeline fills (engine-api.md §6.1).

    Analyzers rely on the attributes in engine-api.md §6.1. ``set_evaluator``, ``add_gap``,
    ``set_legacy_output`` and ``shared`` are the only mutation points, used by the pipeline's phases.
    """

    run_root: Path
    mode: str
    run_id: str
    account_id: str
    partition: str
    regions: Tuple[str, ...]
    global_dir: Path
    region_dirs: Mapping[str, Path]
    reference_time: _dt.datetime
    generated_at: str
    options: AnalysisOptions
    manifest: Optional[Mapping[str, Any]] = None
    manifest_sha256: Optional[str] = None
    ignored_dirs: Tuple[str, ...] = ()
    operator: OperatorInput = field(default_factory=OperatorInput)
    reproducible: bool = False
    coverage: CoverageLedger = field(default_factory=lambda: CoverageLedger("legacy-unknown", []))
    data: Dict[str, Any] = field(default_factory=dict)
    evaluator: Any = None
    principals: Mapping[str, Any] = field(default_factory=dict)
    shared: Dict[str, Any] = field(default_factory=dict)
    _gaps: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    _legacy_outputs: Dict[str, Any] = field(default_factory=dict)

    @property
    def analysis_dir(self) -> Path:
        return self.run_root / ANALYSIS_DIR

    @property
    def tmp_dir(self) -> Path:
        return self.run_root / TMP_DIR

    @property
    def is_legacy(self) -> bool:
        return self.mode != "run"

    def region_of_unit(self, unit: str) -> Optional[str]:
        """``None`` for the global unit, else the region name."""
        return None if unit == "global" else unit

    # mutation points ---------------------------------------------------------
    def set_evaluator(self, evaluator: Any, principals: Optional[Mapping[str, Any]] = None) -> None:
        """Phase 3 (PRINCIPALS) hands over the policy evaluator (E-policy, engine-api.md §4)."""
        self.evaluator = evaluator
        if principals is not None:
            self.principals = principals

    def add_gap(self, code: str, detail: str, count: Optional[int] = None) -> None:
        """Record a report-level evaluation gap (graph-json.md §10.2); counts add up."""
        entry = self._gaps.setdefault(code, {"code": code, "detail": detail, "count": None})
        if count is not None:
            entry["count"] = (entry["count"] or 0) + int(count)

    def evaluation_gaps(self) -> List[Dict[str, Any]]:
        return [dict(self._gaps[k]) for k in sorted(self._gaps)]

    def set_legacy_output(self, name: str, data: Any) -> None:
        self._legacy_outputs[name] = data

    def legacy_output(self, name: str, default: Any = None) -> Any:
        return self._legacy_outputs.get(name, default)

    def legacy_outputs(self) -> Mapping[str, Any]:
        return dict(self._legacy_outputs)


# ── layout detection ──────────────────────────────────────────────────────────

def manifest_major(doc: Any) -> Optional[int]:
    version = doc.get("schema_version") if isinstance(doc, Mapping) else None
    head = version.split(".", 1)[0] if isinstance(version, str) else ""
    return int(head) if head.isdigit() else None


def detect_layout(report_dir: Path) -> str:
    """``run`` / ``legacy-all`` / ``legacy-single`` (report-layout.md §8); usage error for anything else."""
    man = read_json(report_dir / "manifest.json")
    if man.ok and manifest_major(man.data) == 2:
        return "run"
    if (report_dir / "global").is_dir():
        return "legacy-all"
    if (report_dir / "iam").is_dir():
        return "legacy-single"
    raise AnalysisUsageError(f"{report_dir} is not an aws-enumerator report")


def _sha256(path: Path) -> Optional[str]:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _iam_account(global_dir: Path) -> Tuple[Optional[str], Optional[str]]:
    """(account, partition) from the first IAM ARN found in ``global_dir/iam``."""
    for name in ("roles.json", "users.json", "groups.json"):
        res = read_json(global_dir / "iam" / name)
        for rec in res.data if res.ok and isinstance(res.data, list) else ():
            parts = str(rec.get("Arn", "")).split(":") if isinstance(rec, Mapping) else []
            if len(parts) > 4 and _ACCT_RE.match(parts[4]):
                return parts[4], parts[1]
    return None, None


def _legacy_run_id(report_dir: Path, mode: str) -> str:
    date_dir = report_dir.parent if mode == "legacy-all" else report_dir.parent.parent
    if re.fullmatch(r"\d{8}", date_dir.name or ""):
        return f"legacy-{date_dir.name}"
    return ("legacy-" + _RUN_ID_BAD.sub("_", report_dir.name or "report"))[:64]


def _ignored(root: Path, regions: Sequence[str], reserved: frozenset) -> Tuple[str, ...]:
    out = []
    for name in ls_sorted(root):
        if (root / name).is_dir() and name not in reserved and name not in regions and \
                not name.startswith(ORIG_DIR):
            out.append(name)
    return tuple(out)


def _clock(options: AnalysisOptions, recorded: Optional[_dt.datetime]) -> Tuple[str, _dt.datetime, bool]:
    """``(generated_at, reference_time, reproducible)``; ``recorded`` is the report's own start time (module doc)."""
    epoch = _epoch(options)
    if epoch is not None:
        fixed = _dt.datetime.fromtimestamp(epoch, tz=_dt.timezone.utc)
        return iso_utc(fixed), fixed, True
    now = _dt.datetime.now(_dt.timezone.utc)
    return iso_utc(now), recorded or now, False


def _legacy_recorded(legacy: Mapping[str, Any], report_dir: Path, mode: str) -> Optional[_dt.datetime]:
    """The start time an old report recorded (naive d13c215 timestamps are read as UTC), else its date dir."""
    recorded = _parse_utc(legacy.get("timestamp_start")) or _parse_utc(legacy.get("timestamp_end"))
    if recorded is not None:
        return recorded
    date_dir = report_dir.parent if mode == "legacy-all" else report_dir.parent.parent
    if re.fullmatch(r"\d{8}", date_dir.name or ""):
        try:
            return _dt.datetime.strptime(date_dir.name, "%Y%m%d").replace(tzinfo=_dt.timezone.utc)
        except ValueError:
            return None
    return None


def _note_clock(ctx: "AnalysisContext", recorded: Optional[_dt.datetime], fixed: bool) -> None:
    if recorded is None and not fixed:
        ctx.add_gap("clock:reference-time-unknown", "The report records no collection time: ages (access keys, "
                    "certificates) and time conditions were evaluated against the analysis clock, so a later "
                    "re-analysis may differ (set SOURCE_DATE_EPOCH to pin it).")


# ── builders ──────────────────────────────────────────────────────────────────

def build_run_context(run_root: Path, *, regions: Sequence[str], account_id: Optional[str] = None,
                      partition: Optional[str] = None, manifest: Optional[Mapping[str, Any]] = None,
                      options: Optional[AnalysisOptions] = None) -> AnalysisContext:
    """Context of a v2 run root (engine-api.md §3.1)."""
    options = options or AnalysisOptions()
    run_root = Path(run_root)
    if not run_root.is_dir():
        raise FileNotFoundError(f"run root {run_root} does not exist")
    man_path = run_root / "manifest.json"
    if manifest is None:
        res = read_json(man_path)
        manifest = res.data if res.ok and isinstance(res.data, Mapping) else None
    manifest = dict(manifest or {})
    run = manifest.get("run") if isinstance(manifest.get("run"), Mapping) else {}
    if run.get("status") == "in_progress" and not options.force:
        raise AnalysisUsageError(f"{run_root}: the run is still in progress (pass force to analyse it anyway)")
    target = manifest.get("target") if isinstance(manifest.get("target"), Mapping) else {}
    regions = _check_regions(regions)
    account_id = account_id or target.get("account_id") or _iam_account(run_root / "global")[0] \
        or (run_root.parent.name if _ACCT_RE.match(run_root.parent.name) else None)
    partition = partition or target.get("partition") or _iam_account(run_root / "global")[1] or "aws"
    recorded = _parse_utc(run.get("started_at")) or _parse_utc(run.get("ended_at"))
    generated_at, reference, fixed = _clock(options, recorded)
    op = manifest.get("operator") if isinstance(manifest.get("operator"), Mapping) else {}
    ctx = AnalysisContext(
        run_root=run_root, mode="run", run_id=str(run.get("run_id") or run_root.name)[:64],
        account_id=_need_account(account_id, run_root), partition=str(partition), regions=regions,
        global_dir=run_root / "global", region_dirs={r: run_root / r for r in regions},
        reference_time=reference, generated_at=generated_at, options=options, manifest=manifest,
        manifest_sha256=_sha256(man_path) if man_path.is_file() else None,
        ignored_dirs=_ignored(run_root, regions, _RESERVED),
        operator=OperatorInput(op.get("caller_arn"), op.get("principal_arn"),
                               bool(op.get("redacted")) or options.redact_identity),
        reproducible=fixed)
    ctx.coverage = CoverageLedger.from_dirs({"global": ctx.global_dir, **ctx.region_dirs}, legacy=False,
                                            manifest=manifest)
    _note_clock(ctx, recorded, fixed)
    return ctx


def _check_regions(regions: Sequence[str]) -> Tuple[str, ...]:
    if isinstance(regions, str) or regions is None:
        raise AnalysisUsageError("regions must be an explicit list of region names")
    out = sorted({str(r) for r in regions})
    bad = [r for r in out if not _REGION_RE.match(r)]
    if bad:
        raise AnalysisUsageError(f"not region names: {bad}")
    return tuple(out)


def _need_account(account_id: Optional[str], where: Path) -> str:
    if not isinstance(account_id, str) or not _ACCT_RE.match(account_id):
        raise AnalysisUsageError(f"{where}: the assessed account id cannot be determined")
    return account_id


def build_report_context(report_dir: Path, options: Optional[AnalysisOptions] = None) -> AnalysisContext:
    """Context of an old (v0.2) report directory (engine-api.md §3.2, report-layout.md §8)."""
    options = options or AnalysisOptions()
    report_dir = Path(report_dir)
    mode = detect_layout(report_dir)
    if mode == "run":
        raise AnalysisUsageError("use build_run_context for a v2 run root")
    res = read_json(report_dir / "manifest.json")
    legacy = res.data.get("run_metadata") if res.ok and isinstance(res.data, Mapping) else None
    legacy = legacy if isinstance(legacy, Mapping) else {}
    if mode == "legacy-all":
        regions = tuple(n for n in ls_sorted(report_dir) if (report_dir / n).is_dir() and is_known_region(n))
        global_dir, region_dirs = report_dir / "global", {r: report_dir / r for r in regions}
        dir_account = report_dir.name
    else:
        regions = (report_dir.name,) if is_known_region(report_dir.name) else ()
        global_dir, region_dirs = report_dir, {r: report_dir for r in regions}
        dir_account = report_dir.parent.name
    iam_acct, iam_part = _iam_account(global_dir)
    account = legacy.get("account_id") or (dir_account if _ACCT_RE.match(dir_account) else None) or iam_acct
    partition = iam_part or (partition_of_region(regions[0]) if regions else "aws")
    recorded = _legacy_recorded(legacy, report_dir, mode)
    generated_at, reference, fixed = _clock(options, recorded)
    caller = legacy.get("caller_arn") if isinstance(legacy.get("caller_arn"), str) else None
    ctx = AnalysisContext(
        run_root=report_dir, mode=mode, run_id=_legacy_run_id(report_dir, mode),
        account_id=_need_account(account, report_dir), partition=partition, regions=regions,
        global_dir=global_dir, region_dirs=region_dirs, reference_time=reference, generated_at=generated_at,
        options=options, manifest=dict(res.data) if res.ok and isinstance(res.data, Mapping) else None,
        manifest_sha256=_sha256(report_dir / "manifest.json") if res.ok else None,
        ignored_dirs=_ignored(report_dir, regions, _RESERVED) if mode == "legacy-all" else (),
        operator=OperatorInput(caller, None, bool(options.redact_identity) and caller is not None),
        reproducible=fixed)
    if options.redact_identity:
        ctx.operator = OperatorInput(None, None, True)
    units = {"global": global_dir, **region_dirs} if mode == "legacy-all" else {"global": global_dir}
    ctx.coverage = CoverageLedger.from_dirs(units, legacy=True)
    ctx.add_gap("coverage-not-recorded", "The report predates _coverage.json: denied or failed collection "
                "cannot be told apart from empty data.")
    if mode == "legacy-single" and not regions:
        ctx.add_gap("legacy:region-unknown", f"The directory name {report_dir.name!r} is not an AWS region; "
                    "regional data was not analysed.")
    _note_clock(ctx, recorded, fixed)
    return ctx


def add_standard_gaps(ctx: AnalysisContext) -> None:
    for code, detail in ALWAYS_GAPS.items():
        ctx.add_gap(code, detail)


def provenance(ctx: AnalysisContext, *, tool_version: str, git_sha: Optional[str], input_files: int) -> Dict[str, Any]:
    """``analysis/_provenance.json`` of a legacy layout (report-layout.md §8)."""
    return {"schema_version": 1, "source_layout": ctx.mode, "analyzed_at": ctx.generated_at,
            "tool_version": tool_version, "git_sha": git_sha, "regions": list(ctx.regions),
            "account_id": ctx.account_id, "input_files": int(input_files)}


def read_manifest_bytes(path: Path) -> Optional[Mapping[str, Any]]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, Mapping) else None


__all__ = [
    "ALWAYS_GAPS", "AnalysisContext", "MODES", "add_standard_gaps", "build_report_context", "build_run_context",
    "detect_layout", "is_known_region", "iso_utc", "manifest_major", "partition_of_region", "provenance",
    "region_partitions",
]
