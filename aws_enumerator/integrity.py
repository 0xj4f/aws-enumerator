"""Digests of a run: ``manifest.files``, ``SHA256SUMS`` and ``aws-enumerator verify`` (F-168).

report-layout.md §7: ``manifest.files`` lists every regular file under the run root, sorted by POSIX path,
except ``manifest.json``, ``SHA256SUMS``, ``run.log``, ``*.zip``, transient names and ``analysis/exports/**``;
each entry is ``{path, sha256, bytes}``. ``SHA256SUMS`` (GNU coreutils format) covers the same set plus
``manifest.json`` and is written last, so ``shasum -a 256 -c SHA256SUMS`` verifies the run from its root.

Hashes stored next to the data detect corruption and accidental edits; they are not tamper-proof against
someone who can rewrite the manifest too. For evidence, record the zip's SHA-256 (printed at the end of the
run) out of band, or sign the archive (``--sign``).
"""

from __future__ import annotations

import json
import logging
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from aws_enumerator.util import fsio
from aws_enumerator.util.optional import optional_module

__all__ = [
    "EXCLUDED_NAMES", "VerifyReport", "compute_files", "is_listed_path", "parse_sha256sums", "render_sha256sums",
    "verify_path", "write_sha256sums",
]

log = logging.getLogger("aws_enumerator.output")

EXCLUDED_NAMES = frozenset({"manifest.json", "SHA256SUMS", "run.log"})
_PATH_RE = re.compile(r"^[A-Za-z0-9._+=,@-]+(/[A-Za-z0-9._+=,@-]+)*$")
_TRANSIENT_DIR_RE = re.compile(r"^(analysis\.tmp|analysis\.prev|.+\.stale-\d+)$")
_SUMS_LINE = re.compile(r"^([0-9a-f]{64}) [ *](.+)$")


def is_listed_path(rel: str) -> bool:
    """Whether ``rel`` (POSIX, relative to the run root) belongs in ``manifest.files``."""
    parts = PurePosixPath(rel).parts
    if not parts:
        return False
    if len(parts) == 1 and parts[0] in EXCLUDED_NAMES:
        return False
    if rel.endswith(".zip") or _TRANSIENT_DIR_RE.match(parts[0]):
        return False
    if parts[:2] == ("analysis", "exports"):
        return False
    return not (parts[-1].startswith(".") and ".tmp-" in parts[-1])


def compute_files(run_root: Path) -> List[Dict[str, Any]]:
    """``manifest.files`` for ``run_root`` (symlinks are never followed or listed)."""
    files = []
    for rel in fsio.iter_files(run_root):
        if not is_listed_path(rel):
            continue
        if not _PATH_RE.match(rel):
            log.warning("not listed in manifest.files (unsafe file name): %r", rel)
            continue
        path = Path(run_root) / rel
        files.append({"path": rel, "sha256": fsio.sha256_file(path), "bytes": path.stat().st_size})
    return files


def render_sha256sums(entries: Iterable[Tuple[str, str]]) -> str:
    """``<64 hex><two spaces><path>\\n`` per entry, sorted by path."""
    return "".join(f"{sha}  {path}\n" for path, sha in sorted(entries))


def write_sha256sums(run_root: Path, files: Iterable[Mapping[str, Any]]) -> Path:
    """Write ``SHA256SUMS`` over ``files`` plus the final ``manifest.json`` (call after the manifest)."""
    entries = [(f["path"], f["sha256"]) for f in files]
    entries.append(("manifest.json", fsio.sha256_file(Path(run_root) / "manifest.json")))
    return fsio.atomic_write_text(Path(run_root) / "SHA256SUMS", render_sha256sums(entries))


def parse_sha256sums(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in text.splitlines():
        match = _SUMS_LINE.match(line.strip())
        if match:
            out[match.group(2)] = match.group(1)
    return out


# ── verify ───────────────────────────────────────────────────────────────────
@dataclass
class VerifyReport:
    """Outcome of ``aws-enumerator verify``: problem lines, or the number of files checked."""

    checked: int = 0
    problems: List[str] = field(default_factory=list)
    schema_errors: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems and not self.schema_errors

    def lines(self) -> List[str]:
        if self.ok:
            return [f"OK {self.checked} files"]
        return [*self.problems, *(f"INVALID manifest.json: {e}" for e in self.schema_errors)]


class _Source:
    """Uniform read access to a run directory or a run zip (entries ``<run_id>/<path>``)."""

    def __init__(self, path: Path):
        self.path = path
        self.zip: Optional[zipfile.ZipFile] = None
        self.prefix = ""
        if path.is_file():
            self.zip = zipfile.ZipFile(path)
            roots = {n.split("/", 1)[0] for n in self.zip.namelist() if "/" in n}
            if len(roots) != 1:
                raise ValueError("the archive must contain exactly one run directory")
            self.prefix = roots.pop() + "/"

    def names(self) -> List[str]:
        if self.zip is None:
            return list(fsio.iter_files(self.path))
        return sorted(n[len(self.prefix):] for n in self.zip.namelist()
                      if n.startswith(self.prefix) and not n.endswith("/"))

    def read(self, rel: str) -> Optional[bytes]:
        try:
            if self.zip is None:
                return (self.path / rel).read_bytes()
            return self.zip.read(self.prefix + rel)
        except (OSError, KeyError):
            return None

    def close(self) -> None:
        if self.zip is not None:
            self.zip.close()


def _schema_errors(doc: Any) -> List[str]:
    """Validate against the manifest schema when ``jsonschema`` is installed, else a structural check."""
    jsonschema = optional_module("jsonschema")
    if jsonschema is not None:
        schema_path = Path(__file__).resolve().parent / "schemas" / "manifest-2.0.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)
        return sorted(f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message[:200]}"
                      for e in validator.iter_errors(doc))
    required = ("schema_version", "tool", "run", "target", "operator", "modules", "analysis", "files")
    missing = [k for k in required if not isinstance(doc, dict) or k not in doc]
    return [f"missing key {k}" for k in missing]


def _load_manifest(src: _Source) -> Dict[str, Any]:
    raw = src.read("manifest.json")
    if raw is None:
        raise ValueError("no manifest.json: not an aws-enumerator run")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("manifest.json is not valid JSON") from None
    if not isinstance(doc, dict) or not str(doc.get("schema_version", "")).startswith("2."):
        raise ValueError("manifest.json is not a v2 manifest (legacy reports have no digests)")
    return doc


def _check_digests(src: _Source, listed: Mapping[str, str], report: VerifyReport) -> None:
    for rel, expected in sorted(listed.items()):
        data = src.read(rel)
        if data is None:
            report.problems.append(f"MISSING {rel}")
        elif fsio.sha256_bytes(data) != expected:
            report.problems.append(f"MISMATCH {rel}")
        else:
            report.checked += 1


def verify_path(path: Path) -> VerifyReport:
    """Recompute ``manifest.files`` and ``SHA256SUMS`` of a run directory or zip (``ValueError``: not a run)."""
    src = _Source(Path(path))
    try:
        doc = _load_manifest(src)
        report = VerifyReport(schema_errors=_schema_errors(doc))
        listed = {f["path"]: f["sha256"] for f in doc.get("files", []) if isinstance(f, dict) and "path" in f}
        _check_digests(src, listed, report)
        sums_raw = src.read("SHA256SUMS")
        if sums_raw is None:
            report.problems.append("MISSING SHA256SUMS")
        else:
            sums = parse_sha256sums(sums_raw.decode("utf-8", "replace"))
            for rel in sorted(set(sums) - set(listed) - {"manifest.json"}):
                report.problems.append(f"UNLISTED {rel}")
            for rel in sorted(set(listed) - set(sums)):
                report.problems.append(f"MISMATCH {rel}")
            manifest_raw = src.read("manifest.json") or b""
            if sums.get("manifest.json") != fsio.sha256_bytes(manifest_raw):
                report.problems.append("MISMATCH manifest.json")
            else:
                report.checked += 1
        for rel in src.names():
            if is_listed_path(rel) and rel not in listed:
                report.problems.append(f"UNLISTED {rel}")
        report.problems = sorted(set(report.problems), key=lambda p: (p.split(" ", 1)[1], p))
        return report
    finally:
        src.close()

