"""Build and runtime provenance: the ``tool`` block of ``manifest.json`` (manifest.md §3.1, F-122).

* ``version`` comes from :mod:`aws_enumerator._version` (the single source);
* ``git_sha`` from ``$AWS_ENUMERATOR_GIT_SHA`` (set by the Docker build), else from
  ``git rev-parse --short=12 HEAD`` (1 s timeout) when the package directory sits in a git work tree,
  else ``None``;
* library versions from :mod:`importlib.metadata` (``kubernetes`` is ``None`` when not installed).

There is no ``author`` field anywhere in the run output (F-144): the author lives in package metadata only.
"""

from __future__ import annotations

import functools
import logging
import os
import platform
import re
import shutil
import subprocess
from importlib import metadata
from pathlib import Path
from typing import Dict, Optional

from aws_enumerator._version import PRODUCT_NAME, __version__

__all__ = ["git_sha", "library_version", "tool_info", "version_line"]

log = logging.getLogger(__name__)

_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
_PACKAGE_DIR = Path(__file__).resolve().parent


def version_line() -> str:
    """``aws-enumerator 0.3.0``: what ``--version`` and ``version`` print."""
    return f"{PRODUCT_NAME} {__version__}"


def _normalise_sha(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    value = value.strip().lower()
    return value if _SHA_RE.match(value) else None


@functools.lru_cache(maxsize=1)
def _git_sha_from_checkout() -> Optional[str]:
    """``git rev-parse --short=12 HEAD`` for a source checkout; ``None`` for installed wheels."""
    if not any((parent / ".git").exists() for parent in (_PACKAGE_DIR, *_PACKAGE_DIR.parents)):
        return None
    git = shutil.which("git")
    if git is None:
        return None
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [git, "rev-parse", "--short=12", "HEAD"], cwd=str(_PACKAGE_DIR), capture_output=True,
            text=True, timeout=1, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("git rev-parse failed: %s", type(exc).__name__)
        return None
    return _normalise_sha(proc.stdout) if proc.returncode == 0 else None


def git_sha() -> Optional[str]:
    """The commit the running code was built from, or ``None`` when unknown."""
    from_env = _normalise_sha(os.environ.get("AWS_ENUMERATOR_GIT_SHA"))
    if from_env:
        return from_env
    return _git_sha_from_checkout()


def library_version(distribution: str) -> Optional[str]:
    try:
        return metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return None


def tool_info() -> Dict[str, Optional[str]]:
    """The manifest ``tool`` block: ``{name, version, git_sha, python, boto3, botocore, kubernetes}``."""
    return {
        "name": PRODUCT_NAME,
        "version": __version__,
        "git_sha": git_sha(),
        "python": platform.python_version(),
        "boto3": library_version("boto3") or "unknown",
        "botocore": library_version("botocore") or "unknown",
        "kubernetes": library_version("kubernetes"),
    }
