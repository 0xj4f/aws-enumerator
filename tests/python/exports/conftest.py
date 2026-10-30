"""Shared fixtures for the export writer tests (exports.md; F-141, F-165)."""

from __future__ import annotations

import copy
import importlib
import json
import os
import pwd
import shutil
import subprocess
from typing import Any, Dict

import pytest

from tests.support import targets

W = importlib.import_module("tests.fixtures.e-rules.worlds")
GRAPH_FIXTURES = targets.GRAPH_FIXTURES_DIR
JS_DIR = targets.DASHBOARD_JS_DIR

#: Renders findingsCsv / findingsMarkdown of dashboard/js/exports.js for a graph.json given on stdin.
NODE_EXPORTS = r"""
const fs = require('fs');
const C = require(process.argv[1] + '/graph-core.js');
const X = require(process.argv[1] + '/exports.js');
const raw = JSON.parse(fs.readFileSync(0, 'utf8'));
const v = C.validateGraph(raw);
const index = C.buildIndex(v.graph);
const findings = v.graph.findings.concat(v.graph.unattachedFindings || []);
const meta = { run: v.graph.run, generator: v.graph.generator, schemaVersion: v.graph.schemaVersion };
process.stdout.write(JSON.stringify({ csv: X.findingsCsv(findings, index),
                                      md: X.findingsMarkdown(findings, index, meta) }));
"""


def load_fixture(name: str) -> Dict[str, Any]:
    return json.loads((GRAPH_FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def example() -> Dict[str, Any]:
    return load_fixture("example")


@pytest.fixture(scope="session")
def hostile() -> Dict[str, Any]:
    return load_fixture("hostile")


@pytest.fixture(scope="session")
def analysed(tmp_path_factory) -> Dict[str, Any]:
    """A real graph.json: escalation paths, ADMIN-001, a group finding, a resource finding."""
    w = W.World(tmp_path_factory.mktemp("exports"))
    w.admin_role("demo-fn-admin", W.trusts_service("lambda.amazonaws.com"))
    w.user("demo-dev", W.allow(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]))
    w.group("demo-admins", attached=[W.ADMIN_POLICY])
    w.user("demo-ops", groups=["demo-admins"])
    w.user("demo-keys", W.allow("iam:CreateAccessKey", "*"))
    return w.analyze().graph


def node_exports(graph: Dict[str, Any]) -> Dict[str, str]:
    """The dashboard's CSV and Markdown for ``graph`` (unfiltered findings), via node."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    # version managers' shims (asdf, nvm) look up the user's real home, which the test guard redirects
    env = dict(os.environ, HOME=pwd.getpwuid(os.getuid()).pw_dir)
    proc = subprocess.run([node, "-e", NODE_EXPORTS, str(JS_DIR)], input=json.dumps(graph).encode("utf-8"),
                          capture_output=True, timeout=60, env=env)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")[-2000:]
    return json.loads(proc.stdout.decode("utf-8"))


def merged_like(graph: Dict[str, Any], other_account: str = "999999999999") -> Dict[str, Any]:
    """A copy of ``graph`` whose findings come from two accounts (one without ``account``), as in a merge."""
    doc = copy.deepcopy(graph)
    for i, f in enumerate(doc["findings"]):
        if i % 2:
            f["account"] = other_account
        elif i % 3 == 0:
            f.pop("account", None)
    return doc


@pytest.fixture(scope="session")
def js_exports():
    """``js_exports(graph) -> {"csv": ..., "md": ...}`` from dashboard/js/exports.js (skips without node)."""
    return node_exports


@pytest.fixture(scope="session")
def merged():
    """``merged(graph) -> graph`` with findings from two accounts (see :func:`merged_like`)."""
    return merged_like
