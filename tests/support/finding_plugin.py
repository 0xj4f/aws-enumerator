"""``@pytest.mark.finding("F-xxx", ...)`` bookkeeping and the ``--finding-report`` writer.

Registered by ``tests/conftest.py``. The report is JSON::

    {
      "schema": "finding-report/1",
      "tests": {"<nodeid>": {"outcome": "passed|failed|error|skipped|xfailed|xpassed",
                              "findings": ["F-007", ...]}, ...}
    }

Only tests that carry at least one ``finding`` marker are listed.
``scripts/finding_coverage.py`` merges it with node's TAP output.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List

import pytest

FINDING_ID = re.compile(r"^F-\d{3}$")
SCHEMA = "finding-report/1"


def finding_ids(item) -> List[str]:
    ids: List[str] = []
    for mark in item.iter_markers(name="finding"):
        for arg in mark.args:
            for fid in (arg if isinstance(arg, (list, tuple)) else [arg]):
                if fid not in ids:
                    ids.append(fid)
    return ids


class FindingReportPlugin:
    """Validates finding markers at collection; optionally records outcomes."""

    def __init__(self, report_path: str = ""):
        self.report_path = report_path
        self.findings_by_nodeid: Dict[str, List[str]] = {}
        self.outcomes: Dict[str, str] = {}

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, session, config, items):
        bad = []
        for item in items:
            ids = finding_ids(item)
            for mark in item.iter_markers(name="finding"):
                if not mark.args:
                    bad.append(f"{item.nodeid}: @pytest.mark.finding needs at least one F-xxx id")
            for fid in ids:
                if not isinstance(fid, str) or not FINDING_ID.match(fid):
                    bad.append(f"{item.nodeid}: invalid finding id {fid!r} (expected F-NNN)")
            if ids:
                self.findings_by_nodeid[item.nodeid] = ids
        if bad:
            raise pytest.UsageError("invalid finding markers:\n  " + "\n  ".join(bad))

    def pytest_runtest_logreport(self, report):
        nodeid = report.nodeid
        if nodeid not in self.findings_by_nodeid:
            return
        wasxfail = hasattr(report, "wasxfail")
        if report.when == "setup":
            if report.failed:
                self.outcomes[nodeid] = "error"
            elif report.skipped:
                self.outcomes[nodeid] = "xfailed" if wasxfail else "skipped"
        elif report.when == "call":
            if report.passed:
                self.outcomes[nodeid] = "xpassed" if wasxfail else "passed"
            elif report.skipped:
                self.outcomes[nodeid] = "xfailed" if wasxfail else "skipped"
            else:
                self.outcomes[nodeid] = "failed"
        elif report.when == "teardown" and report.failed:
            self.outcomes[nodeid] = "error"

    def pytest_sessionfinish(self, session, exitstatus):
        if not self.report_path:
            return
        tests = {
            nodeid: {"outcome": self.outcomes.get(nodeid, "not-run"), "findings": ids}
            for nodeid, ids in sorted(self.findings_by_nodeid.items())
        }
        directory = os.path.dirname(os.path.abspath(self.report_path))
        os.makedirs(directory, exist_ok=True)
        with open(self.report_path, "w", encoding="utf-8") as fh:
            json.dump({"schema": SCHEMA, "tests": tests}, fh, indent=2, sort_keys=True)
            fh.write("\n")
