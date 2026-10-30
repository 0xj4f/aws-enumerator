#!/usr/bin/env python3
"""Pre-commit hook: refuse to commit report data, local engagement files and owner notes (F-066).

aws-enumerator reports are pre-computed attack maps of a client account (HANDLING.txt). They belong under
``~/.aws-enumerator/reports`` (the CLI refuses to write inside a git work tree without ``--allow-in-repo``),
never in a repository. This hook rejects, among the staged paths pre-commit passes as arguments:

* anything under a top-level ``reports/`` or ``out/`` directory;
* archives and encrypted or signed bundles: ``*.zip``, ``*.age``, ``*.gpg``, ``*.minisig``;
* the owner's local engagement files: a top-level ``tmp`` (file or directory), ``enum.sh``, ``*.local.sh``;
* the owner's notes and review documents, which are never committed: ``docs/features.md`` and anything under
  ``internal-docs/`` (both are gitignored; the hook also catches ``git add -f``). Matched by path only: the hook
  never opens a file;
* run-root markers outside the test fixtures: ``HANDLING.txt`` and ``SHA256SUMS``.

Paths are compared case-insensitively where a case-insensitive file system would make two spellings one file
(``docs/Features.md`` on macOS).

Exit 0 when nothing matches, 1 otherwise (one line per rejected path on stderr). Standard library only.
"""

from __future__ import annotations

import sys
from pathlib import PurePosixPath
from typing import Iterable, List, Optional, Sequence

ARCHIVE_SUFFIXES = (".zip", ".age", ".gpg", ".minisig")
TOP_LEVEL_DIRS = ("reports", "out", "tmp")
TOP_LEVEL_FILES = ("tmp", "enum.sh")
RUN_MARKERS = ("HANDLING.txt", "SHA256SUMS")
FIXTURE_PREFIXES = ("tests/fixtures/", "tests/golden/")
#: Owner files that are never committed (lower-case, repository-relative): exact paths and top-level directories.
OWNER_FILES = {"docs/features.md": "owner notes, never committed"}
OWNER_DIRS = {"internal-docs": "internal review documents, untracked by owner decision"}


def reason_for(path: str) -> Optional[str]:
    """Why ``path`` (repository-relative, POSIX) must not be committed, or ``None``."""
    text = path.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    posix = PurePosixPath(text)
    parts = posix.parts
    if not parts:
        return None
    name = parts[-1]
    owner = OWNER_FILES.get(posix.as_posix().lower())
    if owner:
        return owner
    if len(parts) > 1 and parts[0].lower() in OWNER_DIRS:
        return OWNER_DIRS[parts[0].lower()]
    if len(parts) > 1 and parts[0] in TOP_LEVEL_DIRS:
        return f"report or local data under {parts[0]}/"
    if len(parts) == 1 and name in TOP_LEVEL_FILES:
        return "local engagement file"
    if name.endswith(".local.sh"):
        return "local engagement wrapper (*.local.sh)"
    if name.lower().endswith(ARCHIVE_SUFFIXES):
        return "archive or encrypted/signed bundle (reports are confidential)"
    if name in RUN_MARKERS and not str(posix).startswith(FIXTURE_PREFIXES):
        return f"{name} marks an aws-enumerator run root"
    return None


def rejected(paths: Iterable[str]) -> List[str]:
    out = []
    for path in paths:
        why = reason_for(path)
        if why:
            out.append(f"{path}: {why}")
    return sorted(out)


def main(argv: Optional[Sequence[str]] = None) -> int:
    problems = rejected(sys.argv[1:] if argv is None else argv)
    for line in problems:
        sys.stderr.write(f"refusing to commit {line}\n")
    if problems:
        sys.stderr.write("Reports stay outside the repository (default ~/.aws-enumerator/reports; see "
                         "HANDLING.txt), and the owner's notes and internal documents stay untracked.\n")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
