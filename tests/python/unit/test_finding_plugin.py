"""Unit tests for tests/support/finding_plugin.py (finding markers and --finding-report)."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from tests.support.finding_plugin import FindingReportPlugin, finding_ids


class _Mark(SimpleNamespace):
    pass


class _Item:
    def __init__(self, nodeid, *marks):
        self.nodeid = nodeid
        self._marks = [_Mark(name="finding", args=m) for m in marks]

    def iter_markers(self, name=None):
        return [m for m in self._marks if name in (None, m.name)]


def _report(nodeid, when, outcome, wasxfail=None):
    rep = SimpleNamespace(nodeid=nodeid, when=when, passed=outcome == "passed", failed=outcome == "failed",
                          skipped=outcome == "skipped")
    if wasxfail is not None:
        rep.wasxfail = wasxfail
    return rep


def test_finding_ids_merges_marks_and_args():
    item = _Item("t::a", ("F-007",), ("F-040", "F-007"), (["F-096"],))
    assert finding_ids(item) == ["F-007", "F-040", "F-096"]


def test_invalid_ids_are_usage_errors():
    plugin = FindingReportPlugin()
    with pytest.raises(pytest.UsageError):
        plugin.pytest_collection_modifyitems(None, None, [_Item("t::bad", ("F-7",))])
    with pytest.raises(pytest.UsageError):
        plugin.pytest_collection_modifyitems(None, None, [_Item("t::empty", ())])


def test_outcomes_and_report(tmp_path):
    path = tmp_path / "out" / "report.json"
    plugin = FindingReportPlugin(str(path))
    items = [_Item("t::pass", ("F-001",)), _Item("t::fail", ("F-002",)), _Item("t::xfail", ("F-003",)),
             _Item("t::xpass", ("F-004",)), _Item("t::skip", ("F-005",)), _Item("t::err", ("F-006",)),
             _Item("t::teardown", ("F-007",)), _Item("t::untagged"), _Item("t::notrun", ("F-008",))]
    plugin.pytest_collection_modifyitems(None, None, items)
    for rep in [
        _report("t::pass", "setup", "passed"), _report("t::pass", "call", "passed"),
        _report("t::fail", "call", "failed"),
        _report("t::xfail", "call", "skipped", wasxfail="reason"),
        _report("t::xpass", "call", "passed", wasxfail="reason"),
        _report("t::skip", "setup", "skipped"),
        _report("t::err", "setup", "failed"),
        _report("t::teardown", "call", "passed"), _report("t::teardown", "teardown", "failed"),
        _report("t::untagged", "call", "failed"),
    ]:
        plugin.pytest_runtest_logreport(rep)
    plugin.pytest_sessionfinish(None, 0)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema"] == "finding-report/1"
    got = {k: (v["outcome"], v["findings"]) for k, v in data["tests"].items()}
    assert got == {
        "t::pass": ("passed", ["F-001"]), "t::fail": ("failed", ["F-002"]), "t::xfail": ("xfailed", ["F-003"]),
        "t::xpass": ("xpassed", ["F-004"]), "t::skip": ("skipped", ["F-005"]), "t::err": ("error", ["F-006"]),
        "t::teardown": ("error", ["F-007"]), "t::notrun": ("not-run", ["F-008"]),
    }


def test_no_report_without_path(tmp_path):
    plugin = FindingReportPlugin("")
    plugin.pytest_collection_modifyitems(None, None, [_Item("t::a", ("F-001",))])
    plugin.pytest_sessionfinish(None, 0)  # nothing written, no error


def test_registered_plugin_is_active(request):
    plugin = request.config.pluginmanager.get_plugin("aws-enumerator-finding-report")
    assert isinstance(plugin, FindingReportPlugin)
