"""Deterministic run archives, optional encryption and signing (report-layout.md §10; F-123, F-145, F-168).

* :func:`build_zip` writes ``<output>/<account>/<run_id>.zip`` next to the run root: entries
  ``<run_id>/<path>`` for every file in ``manifest.files`` plus ``manifest.json``, ``SHA256SUMS`` and
  ``run.log``; sorted, timestamps fixed to ``run.started_at``, modes ``0600`` / ``0700``; the file itself is
  written atomically with mode ``0600``. The same run always gives the same bytes.
* :func:`encrypt` (``age:<recipient>`` or ``gpg:<recipient>``) and :func:`sign` (``gpg:<keyid>`` or
  ``minisign:<secret key file>``) run the external tools as subprocesses (no shell, no new Python
  dependency). The plain zip is removed after a successful encryption.
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import shutil
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Mapping, Tuple

from aws_enumerator.util import fsio

__all__ = ["ArchiveError", "ToolSpec", "archive_members", "build_zip", "encrypt", "file_sha256", "parse_tool_spec",
           "sign"]

log = logging.getLogger("aws_enumerator.output")

ENCRYPT_TOOLS = ("age", "gpg")
SIGN_TOOLS = ("gpg", "minisign")
_SPEC_RE = re.compile(r"^(?P<tool>[a-z]+):(?P<arg>[^\s].*)$")
_ALWAYS = ("manifest.json", "SHA256SUMS", "run.log")
_FILE_ATTR = (0o100600 & 0xFFFF) << 16
_DIR_ATTR = (0o040700 & 0xFFFF) << 16


class ArchiveError(Exception):
    """Archiving, encryption or signing failed: exit 1."""


ToolSpec = Tuple[str, str]


def parse_tool_spec(value: str, allowed: Tuple[str, ...], flag: str) -> ToolSpec:
    """``"age:age1..."`` -> ``("age", "age1...")``; ``ValueError`` for anything else (exit 64)."""
    match = _SPEC_RE.match(value or "")
    if not match or match.group("tool") not in allowed:
        raise ValueError(f"{flag} expects one of {', '.join(t + ':<value>' for t in allowed)}, got {value!r}")
    arg = match.group("arg")
    if arg.startswith("-"):
        raise ValueError(f"{flag}: the value must not start with '-'")
    return match.group("tool"), arg


def file_sha256(path: Path) -> str:
    return fsio.sha256_file(path)


def archive_members(run_root: Path, manifest: Mapping[str, Any]) -> List[str]:
    """Relative paths that go into the archive, sorted."""
    names = {f["path"] for f in manifest.get("files", []) if isinstance(f, Mapping) and f.get("path")}
    names.update(n for n in _ALWAYS if (Path(run_root) / n).is_file())
    return sorted(names)


def _timestamp(manifest: Mapping[str, Any]) -> Tuple[int, int, int, int, int, int]:
    raw = str((manifest.get("run") or {}).get("started_at") or "")
    try:
        when = datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        when = datetime(1980, 1, 1, tzinfo=timezone.utc)
    when = max(when, datetime(1980, 1, 1, tzinfo=timezone.utc))
    return when.year, when.month, when.day, when.hour, when.minute, when.second


def _directories(members: List[str]) -> List[str]:
    dirs = set()
    for name in members:
        parts = name.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:i]))
    return sorted(dirs)


def _info(name: str, stamp: Tuple[int, ...], attr: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=stamp)  # type: ignore[arg-type]
    info.create_system = 3
    info.external_attr = attr
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def _write_zip(fh: Any, run_root: Path, run_id: str, members: List[str], stamp: Tuple[int, ...]) -> None:
    with zipfile.ZipFile(fh, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        root = _info(f"{run_id}/", stamp, _DIR_ATTR | 0x10)
        root.compress_type = zipfile.ZIP_STORED
        zf.writestr(root, b"")
        for directory in _directories(members):
            info = _info(f"{run_id}/{directory}/", stamp, _DIR_ATTR | 0x10)
            info.compress_type = zipfile.ZIP_STORED
            zf.writestr(info, b"")
        for name in members:
            data = (Path(run_root) / name).read_bytes()
            zf.writestr(_info(f"{run_id}/{name}", stamp, _FILE_ATTR), data, compresslevel=6)


def build_zip(run_root: Path, zip_path: Path, manifest: Mapping[str, Any]) -> Path:
    """Write the deterministic archive of ``run_root`` to ``zip_path`` (0600, atomic)."""
    run_root, zip_path = Path(run_root), Path(zip_path)
    run_id = str((manifest.get("run") or {}).get("run_id") or run_root.name)
    members = archive_members(run_root, manifest)
    fsio.ensure_dir(zip_path.parent)
    tmp = zip_path.with_name(f".{zip_path.name}.tmp-{os.getpid()}-{secrets.token_hex(4)}")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(tmp, flags, 0o600)
        with os.fdopen(fd, "wb") as fh:
            _write_zip(fh, run_root, run_id, members, _timestamp(manifest))
        os.chmod(tmp, 0o600)
        os.replace(tmp, zip_path)
    except OSError as exc:
        _unlink(tmp)
        raise ArchiveError(f"cannot write {zip_path}: {exc.strerror or exc}") from None
    except BaseException:
        _unlink(tmp)
        raise
    return zip_path


def _unlink(path: Path) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _run_tool(argv: List[str], what: str) -> None:
    exe = shutil.which(argv[0])
    if exe is None:
        raise ArchiveError(f"{what}: '{argv[0]}' is not installed (or not on PATH)")
    try:
        proc = subprocess.run([exe, *argv[1:]], check=False, capture_output=True, text=True)  # noqa: S603
    except OSError as exc:
        raise ArchiveError(f"{what}: cannot run {argv[0]}: {exc.strerror or exc}") from None
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()[-1:] or [f"exit {proc.returncode}"]
        raise ArchiveError(f"{what} with {argv[0]} failed: {detail[0][:200]}")


def encrypt(path: Path, spec: ToolSpec) -> Path:
    """Encrypt ``path`` for a recipient; returns the encrypted file and removes the plain one."""
    tool, recipient = spec
    out = path.with_name(path.name + (".age" if tool == "age" else ".gpg"))
    _unlink(out)
    if tool == "age":
        argv = ["age", "--encrypt", "--recipient", recipient, "--output", str(out), str(path)]
    else:
        argv = ["gpg", "--batch", "--yes", "--encrypt", "--recipient", recipient, "--output", str(out), str(path)]
    _run_tool(argv, "encryption")
    os.chmod(out, 0o600)
    _unlink(path)
    return out


def sign(path: Path, spec: ToolSpec) -> Path:
    """Write a detached signature next to ``path``; returns the signature file."""
    tool, key = spec
    if tool == "gpg":
        out = path.with_name(path.name + ".asc")
        argv = ["gpg", "--batch", "--yes", "--local-user", key, "--armor", "--detach-sign", "--output", str(out),
                str(path)]
    else:
        out = path.with_name(path.name + ".minisig")
        argv = ["minisign", "-S", "-s", key, "-m", str(path), "-x", str(out)]
    _run_tool(argv, "signing")
    os.chmod(out, 0o600)
    return out

