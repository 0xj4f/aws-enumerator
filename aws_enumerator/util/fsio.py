"""Private, atomic file output for reports (contract: docs/contracts/report-layout.md).

Every report file is written through this module:

* directories are created ``0700`` (each newly created component is ``chmod``-ed
  explicitly, so a permissive umask cannot widen them) (F-123);
* files are written to a temporary sibling opened with
  ``O_CREAT | O_EXCL | O_WRONLY`` and mode ``0600``, then moved into place with
  :func:`os.replace`, so readers never see a half-written file (F-114, F-155);
* JSON goes through :func:`json_default`: datetimes become UTC ``...Z`` strings
  (F-171) and ``bytes`` **raise** so a binary blob can never be dumped by accident.

The helpers are dependency-free and safe to call from several threads, as long as
two threads never write the same path (each run unit owns its own directory).
"""

from __future__ import annotations

import datetime as _dt
import decimal
import hashlib
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any, Iterator, Optional, Tuple, Union

__all__ = [
    "DIR_MODE", "FILE_MODE", "PathLike", "UnsafePathError",
    "atomic_write_bytes", "atomic_write_json", "atomic_write_text", "dumps_json", "ensure_dir",
    "find_git_worktree", "hashed_filename", "iso_z", "iter_files", "json_default", "safe_join",
    "sha256_bytes", "sha256_file", "slug", "utc_now", "validate_relpath",
]

DIR_MODE = 0o700
FILE_MODE = 0o600

PathLike = Union[str, "os.PathLike[str]"]

#: One path segment of a report file name. Covers IAM entity names (``[\w+=,.@-]``),
#: S3 bucket names, KMS key ids and the hashed names from :func:`hashed_filename`.
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._+=,@-]{1,255}$")
_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")


class UnsafePathError(ValueError):
    """A report-relative path was absolute, escaped its root, or used unsafe characters."""


# ── time ─────────────────────────────────────────────────────────────────────
def utc_now() -> _dt.datetime:
    """The current time as an aware UTC datetime."""
    return _dt.datetime.now(_dt.timezone.utc)


def iso_z(value: Optional[_dt.datetime] = None, *, timespec: str = "seconds") -> str:
    """``2026-10-15T10:15:02Z``. Naive datetimes are taken to be UTC already."""
    value = utc_now() if value is None else value
    if value.tzinfo is not None:
        value = value.astimezone(_dt.timezone.utc).replace(tzinfo=None)
    return value.isoformat(timespec=timespec) + "Z"


# ── JSON ─────────────────────────────────────────────────────────────────────
def json_default(obj: Any) -> Any:
    """``json.dumps(default=...)`` for report data.

    * ``datetime`` -> UTC ISO-8601 with ``Z`` (microseconds kept when present);
      ``date``/``time`` -> ISO format;
    * ``Decimal`` -> ``int`` when integral, else ``float``;
    * ``set``/``frozenset``/``tuple`` -> sorted list (sets) or list (tuples);
    * ``Path`` -> ``str``;
    * ``bytes``/``bytearray``/``memoryview`` -> **TypeError** (never dump binary data);
    * anything else -> ``str(obj)`` (what the legacy writers did with ``default=str``).
    """
    if isinstance(obj, (bytes, bytearray, memoryview)):
        raise TypeError("refusing to serialise binary data into a report file")
    if isinstance(obj, _dt.datetime):
        return iso_z(obj, timespec="microseconds" if obj.microsecond else "seconds")
    if isinstance(obj, (_dt.date, _dt.time)):
        return obj.isoformat()
    if isinstance(obj, decimal.Decimal):
        return int(obj) if obj == obj.to_integral_value() else float(obj)
    if isinstance(obj, (set, frozenset)):
        try:
            return sorted(obj)
        except TypeError:
            return sorted(obj, key=repr)
    if isinstance(obj, tuple):
        return list(obj)
    if isinstance(obj, Path):
        return str(obj)
    return str(obj)


def dumps_json(data: Any, *, indent: Optional[int] = 2, sort_keys: bool = False) -> str:
    """Serialise report data (ASCII-only output, so any byte of hostile input is escaped)."""
    return json.dumps(data, default=json_default, indent=indent, sort_keys=sort_keys,
                      ensure_ascii=True, allow_nan=False)


# ── paths ────────────────────────────────────────────────────────────────────
def validate_relpath(rel: str) -> Tuple[str, ...]:
    """Split a report-relative path (``"policies/demo-bucket.json"``) into checked segments.

    Raises :class:`UnsafePathError` for absolute paths, ``.``/``..`` segments, empty
    segments, backslashes or characters outside ``[A-Za-z0-9._+=,@-]``.
    """
    if not isinstance(rel, str) or not rel:
        raise UnsafePathError(f"empty or non-string path: {rel!r}")
    if rel.startswith("/") or "\\" in rel or "\x00" in rel:
        raise UnsafePathError(f"unsafe path: {rel!r}")
    parts = tuple(rel.split("/"))
    for part in parts:
        if part in ("", ".", "..") or not _SEGMENT_RE.match(part):
            raise UnsafePathError(f"unsafe path segment {part!r} in {rel!r}")
    return parts


def safe_join(root: PathLike, rel: str) -> Path:
    """``root / rel`` after :func:`validate_relpath`; the result is always inside ``root``."""
    return Path(root).joinpath(*validate_relpath(rel))


def slug(text: Any, maxlen: int = 48) -> str:
    """A filename-safe hint: runs of characters outside ``[A-Za-z0-9._-]`` become ``_``."""
    s = _SLUG_RE.sub("_", str(text)).strip("._") or "item"
    return s[:maxlen].rstrip("._") or "item"


def hashed_filename(key: str, hint: Optional[str] = None, ext: str = ".json") -> str:
    """Collision-free item file name: ``f"{slug(hint)[:48]}-{sha256(key)[:12]}{ext}"`` (F-114).

    ``key`` is the unique identity (usually the ARN); ``hint`` is a readable part
    (usually the name). ``prod/db`` and ``prod_db`` therefore get different files.
    """
    digest = hashlib.sha256(str(key).encode("utf-8")).hexdigest()[:12]
    return f"{slug(hint if hint is not None else key)}-{digest}{ext}"


# ── directories ──────────────────────────────────────────────────────────────
def ensure_dir(path: PathLike, mode: int = DIR_MODE) -> Path:
    """Create ``path`` (and missing parents) with ``mode``; newly created dirs are chmod-ed.

    Existing directories are left as they are (``--output`` may point at a
    pre-existing shared parent); only the components this call creates get ``mode``.
    """
    p = Path(path)
    missing = []
    cur = p
    while not cur.exists():
        missing.append(cur)
        if cur.parent == cur:
            break
        cur = cur.parent
    for d in reversed(missing):
        try:
            os.mkdir(d, mode)
        except FileExistsError:
            continue
        os.chmod(d, mode)
    if not p.is_dir():
        raise NotADirectoryError(str(p))
    return p


# ── atomic writes ────────────────────────────────────────────────────────────
def atomic_write_bytes(path: PathLike, data: bytes, *, mode: int = FILE_MODE, fsync: bool = False,
                       make_parents: bool = True) -> Path:
    """Write ``data`` to ``path`` atomically with permissions ``mode`` (default ``0600``)."""
    target = Path(path)
    if make_parents:
        ensure_dir(target.parent)
    tmp = target.with_name(f".{target.name}.tmp-{os.getpid()}-{secrets.token_hex(4)}")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(tmp, flags, mode)
    try:
        try:
            os.fchmod(fd, mode)
        except (AttributeError, OSError):  # pragma: no cover - platforms without fchmod
            pass
        with os.fdopen(fd, "wb") as fh:
            fd = -1
            fh.write(data)
            if fsync:
                fh.flush()
                os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    return target


def atomic_write_text(path: PathLike, text: str, **kwargs: Any) -> Path:
    return atomic_write_bytes(path, text.encode("utf-8"), **kwargs)


def atomic_write_json(path: PathLike, data: Any, *, indent: Optional[int] = 2, sort_keys: bool = False,
                      **kwargs: Any) -> Path:
    """Serialise with :func:`dumps_json` first (so a TypeError leaves no file), then write atomically."""
    text = dumps_json(data, indent=indent, sort_keys=sort_keys)
    return atomic_write_text(path, text + "\n", **kwargs)


# ── digests / listing ────────────────────────────────────────────────────────
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: PathLike, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def iter_files(root: PathLike) -> Iterator[str]:
    """Every regular file under ``root`` as a POSIX relative path, in sorted order.

    Symlinks are not followed and not listed; temporary ``.*.tmp-*`` files are skipped.
    """
    base = Path(root)
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            full = Path(dirpath) / name
            if full.is_symlink() or not full.is_file():
                continue
            if name.startswith(".") and ".tmp-" in name:
                continue
            yield full.relative_to(base).as_posix()


def find_git_worktree(path: PathLike) -> Optional[Path]:
    """The closest ancestor of ``path`` (or ``path`` itself) containing ``.git``, else ``None``.

    Used for the ``--allow-in-repo`` guard (F-066): reports must not land in a work tree
    by accident. Works for paths that do not exist yet (the nearest existing ancestor is used).
    """
    p = Path(path).expanduser()
    try:
        p = p.resolve()
    except OSError:
        p = p.absolute()
    for cand in (p, *p.parents):
        if (cand / ".git").exists():
            return cand
    return None
