#!/usr/bin/env python3
"""Scan the repository for data that must never be committed.

Scans git-tracked files plus untracked files that are not ignored
(``git ls-files --cached --others --exclude-standard``), skipping the owner's
private paths and tool directories:

    .venv/  reports/  tmp  enum.sh  docs/features.md  .claude/  internal-docs/

and reports, per file and line:

* ``aws-account-id``   12-digit numbers outside the placeholder allow-list
                       (123456789012, 111122223333, 999999999999, 000000000000);
* ``email``            addresses outside example.com/.org/.net and *noreply* senders;
* ``aws-access-key``   ``AKIA`` / ``ASIA`` + 16 characters (AWS documentation keys
                       containing ``EXAMPLE`` are allowed);
* ``private-key``      PEM private-key blocks.

A matched value is never printed in full: only a masked preview. A line containing
``scan-sensitive: allow`` is skipped. Exit status: 0 clean, 1 hits, 2 usage error.

    .venv/bin/python scripts/scan_sensitive.py            # whole repo
    .venv/bin/python scripts/scan_sensitive.py --paths a.json b.md
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, NamedTuple, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]

PLACEHOLDER_ACCOUNTS = frozenset({"123456789012", "111122223333", "999999999999", "000000000000"})
ALLOWED_EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "example.invalid")
EXCLUDED_PREFIXES = (".venv/", "reports/", "internal-docs/", ".claude/", ".git/", "node_modules/",
                     ".pytest_cache/", ".ruff_cache/", ".mypy_cache/")
EXCLUDED_EXACT = frozenset({"tmp", "enum.sh", "docs/features.md", ".venv", "reports", ".claude",
                            "internal-docs"})
ALLOW_PRAGMA = "scan-sensitive: allow"
#: (path, kind) pairs reported but not failing, each with the reason. Keep this list tiny.
KNOWN_EXCEPTIONS = {
    (".github/workflows/docker-publish.yml", "email"):
        "maintainer git identity in the publish workflow; .github/ is frozen by owner decision (F-130/F-131/F-157)",
}
MAX_BYTES = 20 * 1024 * 1024

# 12 digits not glued to other alphanumerics, not a decimal fraction, not the last group of a UUID
ACCOUNT_RE = re.compile(r"(?<![0-9A-Za-z.])(?<![0-9A-Fa-f]{4}-)(\d{12})(?![0-9A-Za-z])(?!\.\d)")
EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}))")
ACCESS_KEY_RE = re.compile(r"(?<![A-Z0-9])((?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])")
PRIVATE_KEY_RE = re.compile(r"(-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----)")


class Hit(NamedTuple):
    path: str
    line: int
    kind: str
    preview: str

    def format(self) -> str:
        return f"{self.path}:{self.line}: {self.kind}: {self.preview}"


def mask(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    keep = 2 if len(value) < 16 else 4
    return value[:keep] + "*" * (len(value) - 2 * keep) + value[-keep:]


def _email_allowed(address: str, domain: str) -> bool:
    d = domain.lower()
    if any(d == a or d.endswith("." + a) for a in ALLOWED_EMAIL_DOMAINS):
        return True
    return "noreply" in address.lower()


def scan_text(text: str, path: str) -> List[Hit]:
    hits: List[Hit] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if ALLOW_PRAGMA in line:
            continue
        for m in ACCOUNT_RE.finditer(line):
            if m.group(1) not in PLACEHOLDER_ACCOUNTS:
                hits.append(Hit(path, lineno, "aws-account-id", mask(m.group(1))))
        for m in EMAIL_RE.finditer(line):
            if not _email_allowed(m.group(1), m.group(2)):
                hits.append(Hit(path, lineno, "email", mask(m.group(1))))
        for m in ACCESS_KEY_RE.finditer(line):
            if "EXAMPLE" not in m.group(1):
                hits.append(Hit(path, lineno, "aws-access-key", mask(m.group(1))))
        if PRIVATE_KEY_RE.search(line):
            hits.append(Hit(path, lineno, "private-key", "-----BEGIN ... PRIVATE KEY-----"))
    return hits


def is_excluded(rel: str) -> bool:
    rel = rel.replace(os.sep, "/")
    while rel.startswith("./"):
        rel = rel[2:]
    rel = rel.lower()  # APFS is case-insensitive: TMP and tmp are the same file
    if rel in EXCLUDED_EXACT:
        return True
    return any(rel.startswith(p) for p in EXCLUDED_PREFIXES)


def git_files(root: Path) -> List[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        check=True, capture_output=True).stdout
    return sorted({p for p in out.decode("utf-8", "surrogateescape").split("\0") if p})


def _read(path: Path) -> Optional[str]:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None  # binary
    return data.decode("utf-8", errors="replace")


def scan_files(files: Iterable[str], root: Path = REPO_ROOT) -> List[Hit]:
    hits: List[Hit] = []
    for rel in files:
        if is_excluded(rel):
            continue  # never open the owner's private paths
        text = _read(root / rel)
        if text is not None:
            hits.extend(scan_text(text, rel))
    return hits


def scan_paths(paths: Sequence[str], root: Path = REPO_ROOT) -> List[Hit]:
    rels = []
    for p in paths:
        ap = Path(p).resolve()
        try:
            rels.append(ap.relative_to(root.resolve()).as_posix())
        except ValueError:
            rels.append(str(ap))  # outside the repo: scanned as given
    hits = []
    for rel in rels:
        if Path(rel).is_absolute():
            text = _read(Path(rel))
            if text is not None:
                hits.extend(scan_text(text, rel))
        else:
            hits.extend(scan_files([rel], root))
    return hits


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Scan for account IDs, emails, AWS keys and private keys.")
    ap.add_argument("--paths", nargs="+", help="scan only these files instead of the git file list")
    ap.add_argument("--root", default=str(REPO_ROOT), help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    root = Path(args.root)
    try:
        hits = scan_paths(args.paths, root) if args.paths else scan_files(git_files(root), root)
    except subprocess.CalledProcessError as exc:
        print(f"scan_sensitive: git ls-files failed: {exc}", file=sys.stderr)
        return 2
    known = [h for h in hits if (h.path, h.kind) in KNOWN_EXCEPTIONS]
    hits = [h for h in hits if (h.path, h.kind) not in KNOWN_EXCEPTIONS]
    for h in hits:
        print(h.format())
    for h in known:
        print(f"known (not failing): {h.format()}  -- {KNOWN_EXCEPTIONS[(h.path, h.kind)]}")
    files = len({h.path for h in hits})
    if hits:
        print(f"scan_sensitive: {len(hits)} hit(s) in {files} file(s)", file=sys.stderr)
        return 1
    print("scan_sensitive: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
