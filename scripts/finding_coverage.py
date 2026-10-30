#!/usr/bin/env python3
"""Per-finding test coverage from pytest's --finding-report JSON and node's TAP output.

Python tests are tied to findings with ``@pytest.mark.finding("F-007")``; JS tests
put ``[F-007]`` (or ``[F-007, F-040]``) in the test name. A JS test is counted as
an expected failure when its name contains ``[xfail]`` (the tests/js xfail helper)
or when TAP marks it ``# TODO``; ``# SKIP`` counts as skipped.

    .venv/bin/python -m pytest --finding-report /tmp/x/pytest.json
    node --test --test-reporter=tap tests/js > /tmp/x/js.tap
    .venv/bin/python scripts/finding_coverage.py --pytest-report /tmp/x/pytest.json \\
        --tap /tmp/x/js.tap --require-all

The finding list comes from internal-docs/findings/verified-findings.json (172
findings). Deferred by the owner and excluded from --require-all: F-130, F-131, F-157.

``PENDING_DOCS`` lists the findings whose remaining in-scope part is documentation written by the Wave 3b docs
streams (README, field guide, generated catalogues, screenshots). Until such a finding has a passing tagged test
(a docs drift test) it is reported as ``pending-docs`` and does not fail ``--require-all``; ``--strict`` (the
Wave 3b / Wave 4 gate) counts it as uncovered. A pending finding that has a passing test is reported as covered,
with a reminder to drop it from the table.
Exit status: 0 ok, 1 --require-all violated (or unknown IDs tagged), 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FINDINGS = REPO_ROOT / "internal-docs" / "findings" / "verified-findings.json"
DEFERRED = frozenset({"F-130", "F-131", "F-157"})
#: Findings whose remaining in-scope part is Wave 3b documentation -> the docs stream that owns it.
PENDING_DOCS: Dict[str, str] = {
}
FALLBACK_COUNT = 172

ID_RE = re.compile(r"F-\d{3}")
TAG_RE = re.compile(r"\[\s*(F-\d{3}(?:\s*,\s*F-\d{3})*)\s*\]")
XFAIL_TAG_RE = re.compile(r"\[\s*xfail\s*\]", re.IGNORECASE)
TAP_LINE_RE = re.compile(r"^\s*(not ok|ok)\s+\d+(?:\s+-)?\s*(.*?)\s*$")
DIRECTIVE_RE = re.compile(r"\s#\s*(SKIP|TODO)\b.*$", re.IGNORECASE)

OUTCOMES = ("passed", "failed", "error", "xfailed", "xpassed", "skipped", "not-run")


def load_finding_ids(path: Optional[Path]) -> Tuple[List[str], str]:
    if path and path.is_file():
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        items = data if isinstance(data, list) else data.get("findings", [])
        ids = sorted({str(x["id"]) for x in items if isinstance(x, dict) and "id" in x})
        return ids, str(path)
    return [f"F-{n:03d}" for n in range(1, FALLBACK_COUNT + 1)], f"fallback F-001..F-{FALLBACK_COUNT:03d}"


def parse_pytest_report(path: Path) -> List[Tuple[str, str, List[str]]]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    tests = data.get("tests", {})
    return [(f"py::{nodeid}", rec.get("outcome", "not-run"), list(rec.get("findings", [])))
            for nodeid, rec in sorted(tests.items())]


def parse_tap(text: str, source: str = "js") -> List[Tuple[str, str, List[str]]]:
    out = []
    for line in text.splitlines():
        m = TAP_LINE_RE.match(line)
        if not m:
            continue
        status, rest = m.group(1), m.group(2)
        directive = None
        d = DIRECTIVE_RE.search(rest)
        if d:
            directive = d.group(1).upper()
            rest = rest[:d.start()]
        ids: List[str] = []
        for group in TAG_RE.findall(rest):
            ids.extend(ID_RE.findall(group))
        if not ids:
            continue
        xfail = bool(XFAIL_TAG_RE.search(rest))
        if directive == "SKIP":
            outcome = "skipped"
        elif directive == "TODO":
            outcome = "xfailed"
        elif status == "ok":
            outcome = "xfailed" if xfail else "passed"
        else:
            outcome = "failed"
        out.append((f"{source}::{rest.strip()}", outcome, sorted(set(ids))))
    return out


def merge(records: Iterable[Tuple[str, str, List[str]]]) -> Dict[str, Dict[str, List[str]]]:
    per: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
    for name, outcome, ids in records:
        for fid in ids:
            per[fid][outcome].append(name)
    return per


def _status(fid: str, counts: Dict[str, int], strict: bool) -> str:
    if fid in DEFERRED:
        return "deferred"
    if counts["passed"]:
        return "covered"
    if fid in PENDING_DOCS and not strict:
        return "pending-docs"
    return "xfail-only" if counts["xfailed"] else "UNCOVERED"


def report(ids: Sequence[str], per: Dict[str, Dict[str, List[str]]], verbose: bool,
           strict: bool = False) -> Tuple[List[str], List[str]]:
    """Print the table; return (in-scope IDs without a passing test, tagged IDs not in the register).

    ``pending-docs`` findings are not returned as uncovered unless ``strict``.
    """
    uncovered, pending = [], []
    width = max((len(i) for i in ids), default=5)
    print(f"{'finding':<{width}}  pass  fail  xfail  skip  status")
    for fid in ids:
        counts = {o: len(per.get(fid, {}).get(o, [])) for o in OUTCOMES}
        fail = counts["failed"] + counts["error"] + counts["xpassed"]
        status = _status(fid, counts, strict)
        if status == "pending-docs":
            pending.append(fid)
        elif status in ("xfail-only", "UNCOVERED"):
            uncovered.append(fid)
        print(f"{fid:<{width}}  {counts['passed']:>4}  {fail:>4}  {counts['xfailed']:>5}  "
              f"{counts['skipped']:>4}  {status}")
        if verbose:
            for outcome in OUTCOMES:
                for name in per.get(fid, {}).get(outcome, []):
                    print(f"{'':<{width}}    {outcome:<8} {name}")
    unknown = sorted(set(per) - set(ids))
    in_scope = [i for i in ids if i not in DEFERRED]
    covered = len(in_scope) - len(uncovered) - len(pending)
    print(f"\ncovered {covered}/{len(in_scope)} in-scope findings "
          f"({len(DEFERRED & set(ids))} deferred: {', '.join(sorted(DEFERRED & set(ids)))})")
    if pending:
        print(f"pending docs (Wave 3b, not counted as failures without --strict): {', '.join(pending)}")
        for fid in pending:
            print(f"  {fid}: {PENDING_DOCS[fid]}")
    done = sorted(fid for fid in PENDING_DOCS if fid in ids and per.get(fid, {}).get("passed"))
    if done:
        print(f"PENDING_DOCS entries that now have a passing test (remove them from the table): {', '.join(done)}")
    failing = sorted({fid for fid, rec in per.items() if rec.get("failed") or rec.get("error") or rec.get("xpassed")})
    if failing:
        print(f"findings with failing/xpassed tests: {', '.join(failing)}")
    if unknown:
        print(f"tagged IDs not in the register: {', '.join(unknown)}")
    return uncovered, unknown


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Merge finding-tagged test results and report coverage per finding.")
    ap.add_argument("--pytest-report", action="append", default=[], metavar="JSON",
                    help="pytest --finding-report output (repeatable)")
    ap.add_argument("--tap", action="append", default=[], metavar="FILE", help="node --test TAP output (repeatable)")
    ap.add_argument("--findings", default=str(DEFAULT_FINDINGS), help="verified-findings.json")
    ap.add_argument("--require-all", action="store_true",
                    help="exit 1 unless every in-scope finding has at least one passing test")
    ap.add_argument("--strict", action="store_true",
                    help="count the PENDING_DOCS findings as uncovered too (the Wave 3b / Wave 4 gate)")
    ap.add_argument("--json", metavar="OUT", help="also write the merged per-finding data as JSON")
    ap.add_argument("-v", "--verbose", action="store_true", help="list the tests behind every finding")
    args = ap.parse_args(argv)

    ids, source = load_finding_ids(Path(args.findings) if args.findings else None)
    records: List[Tuple[str, str, List[str]]] = []
    try:
        for p in args.pytest_report:
            records.extend(parse_pytest_report(Path(p)))
        for p in args.tap:
            records.extend(parse_tap(Path(p).read_text(encoding="utf-8", errors="replace")))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"finding_coverage: cannot read input: {exc}", file=sys.stderr)
        return 2
    print(f"findings: {len(ids)} from {source}; tagged test results: {len(records)}")
    per = merge(records)
    uncovered, unknown = report(ids, per, args.verbose, strict=args.strict)
    if args.json:
        pending = sorted(fid for fid in PENDING_DOCS if fid in ids and fid not in uncovered
                         and not per.get(fid, {}).get("passed"))
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"findings": ids, "deferred": sorted(DEFERRED), "uncovered": uncovered, "pending_docs": pending,
                       "unknown": unknown, "results": {k: dict(v) for k, v in sorted(per.items())}},
                      fh, indent=2, sort_keys=True)
            fh.write("\n")
    if args.require_all and (uncovered or unknown):
        print(f"\n--require-all: {len(uncovered)} in-scope finding(s) without a passing test"
              + (f", {len(unknown)} unknown ID(s)" if unknown else ""), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
