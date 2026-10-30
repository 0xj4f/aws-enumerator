"""S3 loader: buckets, their policies, ACLs, Block Public Access settings, policy status, encryption and
notifications, plus the account-level Block Public Access (E-net, Wave 2).

Reads only the explicit global unit (for an old single-region report: the region directory itself), never
sibling directories (F-010, F-025, F-063), in both collector layouts:

* d13c215: ``s3/buckets.json`` ``{Name, CreationDate, Region}`` and a per-bucket file per sub-resource that
  could be read (a missing file is *not collected / not configured*, which that layout cannot tell apart);
* Wave 1 (C-A): ``buckets.json`` adds ``Arn``, ``SubResources`` (``present | absent | denied | error | skipped``
  per sub-resource), ``PolicyStatus``, ``PolicyIsPublic`` and ``CollectionErrors``, plus
  ``account_public_access_block.json``.

Each bucket becomes a :class:`BucketData` in ``data["details"]["global"]``; ``data["buckets"]["global"]`` keeps
the collected records (the stub's shape). A sub-resource whose read was denied or failed is ``None`` with its
status, so the analyzer reports "exposure unknown", never "not public" (F-058, F-059). The legacy ``EU`` /
empty location constraints are normalised to ``eu-west-1`` / ``us-east-1`` (F-138).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from aws_enumerator.engine.io.fs import read_json, stub_status
from aws_enumerator.engine.io.loaders import LoadResult
from aws_enumerator.engine.io.loaders.ec2 import STATUS_KEY, TableSpec, read_tables

#: (SubResources key, per-bucket directory) of the sub-resources the analysis reads.
SUBRESOURCES: Tuple[Tuple[str, str], ...] = (
    ("policy", "policies"), ("policy_status", "policy_status"), ("acl", "acls"),
    ("public_access_block", "public_access_block"), ("encryption", "encryption"),
    ("notifications", "notifications"), ("ownership_controls", "ownership_controls"),
    ("website", "website"),
)
#: Statuses of a sub-resource whose content is known (``absent`` = read, not configured).
KNOWN_SUB = frozenset({"present", "absent"})

TABLES: Tuple[TableSpec, ...] = (
    TableSpec("buckets", "s3/buckets.json", "s3:ListBuckets", scope="global"),
    TableSpec("account_public_access_block", "s3/account_public_access_block.json",
              "s3control:GetPublicAccessBlock", scope="global", kind="dict"),
)

#: The stub's file map (kept for callers that read it).
GLOBAL_FILES: Dict[str, str] = {"buckets": "s3/buckets.json"}
REGIONAL_FILES: Dict[str, str] = {}


def normalise_region(value: Any) -> Optional[str]:
    """``EU`` → ``eu-west-1``, empty → ``us-east-1`` (GetBucketLocation quirks, F-138); ``None`` stays unknown."""
    if value is None:
        return None
    if value == "":
        return "us-east-1"
    if value == "EU":
        return "eu-west-1"
    return str(value)


@dataclass
class BucketData:
    """One bucket with its sub-resources (``None`` content = not configured or unknown, see ``status``)."""

    name: str
    record: Dict[str, Any]
    region: Optional[str]
    layout: str                                   # "v2" (SubResources recorded) | "legacy"
    status: Dict[str, str] = field(default_factory=dict)       # sub-resource -> present|absent|denied|...
    content: Dict[str, Any] = field(default_factory=dict)      # sub-resource -> parsed file content
    policy_is_public: Optional[bool] = None

    def known(self, sub: str) -> bool:
        """True when the sub-resource was read (present or not configured)."""
        return self.status.get(sub) in KNOWN_SUB


def _sub_status_v2(record: Mapping[str, Any], sub: str) -> str:
    subs = record.get("SubResources")
    value = subs.get(sub) if isinstance(subs, Mapping) else None
    return str(value) if isinstance(value, str) else "skipped"


def _read_sub(s3_dir: Path, subdir: str, name: str) -> Tuple[Any, str]:
    """``(content, status)`` of one per-bucket file (``missing`` when there is no file)."""
    res = read_json(s3_dir / subdir / f"{name}.json")
    if res.status == "missing":
        return None, "missing"
    if res.status == "error-stub":
        return None, stub_status(res.error_code)
    if res.status != "ok":
        return None, "error"
    return res.data, "present"


def _bucket(s3_dir: Path, record: Mapping[str, Any]) -> BucketData:
    name = str(record["Name"])
    layout = "v2" if isinstance(record.get("SubResources"), Mapping) else "legacy"
    region = normalise_region(record.get("Region")) if "Region" in record else None
    bucket = BucketData(name, dict(record), region, layout)
    for sub, subdir in SUBRESOURCES:
        content, file_status = _read_sub(s3_dir, subdir, name)
        if layout == "v2":
            status = _sub_status_v2(record, sub)
            if status == "present" and file_status != "present":
                status = "error" if file_status == "missing" else file_status
        else:
            # d13c215 wrote a file only when the read succeeded: a missing file is "not configured" as far as
            # that layout can tell (the report-level gap coverage-not-recorded discloses it)
            status = "absent" if file_status == "missing" else file_status
        bucket.status[sub] = status
        if status == "present":
            bucket.content[sub] = content
    pip = record.get("PolicyIsPublic")
    if isinstance(pip, bool):
        bucket.policy_is_public = pip
    elif isinstance(bucket.content.get("policy_status"), Mapping):
        value = bucket.content["policy_status"].get("IsPublic")
        bucket.policy_is_public = value if isinstance(value, bool) else None
    return bucket


def load(ctx: Any) -> LoadResult:
    """Pipeline entry point: ``ctx.data["s3"]`` (module docstring)."""
    result = read_tables(ctx, TABLES)
    data: Dict[str, Any] = result.data
    s3_dir = Path(ctx.global_dir) / "s3"
    details: List[BucketData] = []
    seen = set()
    for record in data.get("buckets", {}).get("global", []):
        name = record.get("Name")
        if not isinstance(name, str) or not name or "/" in name or name in seen:
            continue
        seen.add(name)
        details.append(_bucket(s3_dir, record))
    data["details"] = {"global": sorted(details, key=lambda b: b.name)}
    data[STATUS_KEY]["details"] = dict(data[STATUS_KEY].get("buckets", {}))
    return LoadResult(data, result.status, result.gaps, result.files)


def buckets(data: Optional[Mapping[str, Any]]) -> List[BucketData]:
    """The :class:`BucketData` records of ``ctx.data["s3"]`` (``[]`` when the loader did not run)."""
    if not isinstance(data, Mapping) or not isinstance(data.get("details"), Mapping):
        return []
    return [b for b in data["details"].get("global", ()) if isinstance(b, BucketData)]


__all__ = [
    "BucketData", "GLOBAL_FILES", "KNOWN_SUB", "REGIONAL_FILES", "SUBRESOURCES", "TABLES", "buckets", "load",
    "normalise_region",
]
