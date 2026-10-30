"""Incident-response blast radius of a leaked access key (internal-docs repro def_mkreport + def_blast).

The scenarios ``ir_leaked_key`` and ``ir_leaked_key_quarantine`` are analysed natively (``engine.analyze_report``,
the path of ``aws-enumerator analyze``). The blast radius is computed twice: over ``graph.json`` (every
traversable edge, attack direction) and over the legacy relationship files with the def_blast pivot set
(:mod:`tests.support.blast`), which is how an incident responder used the d13c215 output.

The d13c215 engine ignored explicit Deny, so the quarantined key still reached the admin execution role at hop 2
(the Wave 0 characterisation). The evaluator honours the quarantine Deny (F-014): the key reaches nothing but its
own group.
"""

from __future__ import annotations

import collections
import json
from pathlib import Path
from typing import Dict

import pytest

from tests.support import report_builder as rb
from tests.support import targets
from tests.support.blast import blast_radius

ACCT = rb.ACCT_ZERO
LEAKED = f"arn:aws:iam::{ACCT}:user/leaked-user"
DEVS = f"arn:aws:iam::{ACCT}:group/devs"
ETL = f"arn:aws:lambda:eu-west-2:{ACCT}:function:etl"
LEGACY_ETL = f"lambda:{ETL}"
FN_ADMIN = f"arn:aws:iam::{ACCT}:role/fn-admin-role"
ADMIN = f"aws-enumerator:account-admin/{ACCT}"


def _analysed(name: str, tmp_path: Path) -> Path:
    report_dir = rb.materialize(name, tmp_path / "tree")[0]
    result = targets.engine_module().analyze_report(str(report_dir))
    assert result.status == "ok"
    return report_dir


def graph_reach(report_dir: Path, start: str) -> Dict[str, int]:
    """Breadth-first hop count to every node reachable from ``start`` over traversable edges of graph.json."""
    graph = json.loads((report_dir / "analysis" / "graph.json").read_text(encoding="utf-8"))
    out = collections.defaultdict(list)
    for edge in graph["edges"]:
        if edge["traversable"]:
            out[edge["source"]].append(edge["target"])
    reached, queue = {start: 0}, collections.deque([start])
    while queue:
        node = queue.popleft()
        for target in out[node]:
            if target not in reached:
                reached[target] = reached[node] + 1
                queue.append(target)
    return reached


@pytest.mark.finding("F-004", "F-016")
def test_leaked_key_reaches_the_account_admin_through_the_function_it_can_rewrite(tmp_path):
    """leaked-user -CAN_UPDATE_CODE-> etl -USES_ROLE-> fn-admin-role -CAN_ESCALATE-> account-admin (graph.json)."""
    reached = graph_reach(_analysed("ir_leaked_key", tmp_path), LEAKED)
    assert (reached[ETL], reached[FN_ADMIN], reached[ADMIN]) == (1, 2, 3)


def test_leaked_key_reaches_admin_role_at_hop_two_in_the_legacy_files(tmp_path):
    """The legacy relationship files rendered from graph.json still give the d13c215 incident-response answer."""
    reached, hops = blast_radius(str(_analysed("ir_leaked_key", tmp_path)), LEAKED)
    assert reached == {LEAKED: 0, LEGACY_ETL: 1, FN_ADMIN: 2}
    assert (1, LEAKED, "CAN_UPDATE_CODE", LEGACY_ETL) in hops
    assert (2, LEGACY_ETL, "USES_ROLE", FN_ADMIN) in hops


@pytest.mark.finding("F-014")
def test_quarantined_leaked_key_reaches_nothing(tmp_path):
    """The quarantine policy (explicit Deny *) removes every grant: no function, no role, no bucket is reachable."""
    report_dir = _analysed("ir_leaked_key_quarantine", tmp_path)
    assert graph_reach(report_dir, LEAKED) == {LEAKED: 0, DEVS: 1}
    reached, hops = blast_radius(str(report_dir), LEAKED)
    assert reached == {LEAKED: 0}
    assert [h for h in hops if h[1] == LEAKED] == []


@pytest.mark.finding("F-036")
def test_admin_user_trust_edge_is_followed(tmp_path):
    """admin-user is named in admin-role's trust policy: CAN_ASSUME (graph) and the trust row (legacy file)."""
    report_dir = _analysed("ir_leaked_key", tmp_path)
    admin_user, admin_role = f"arn:aws:iam::{ACCT}:user/admin-user", f"arn:aws:iam::{ACCT}:role/admin-role"
    assert graph_reach(report_dir, admin_user)[admin_role] == 1
    reached, _ = blast_radius(str(report_dir), admin_user)
    assert reached.get(admin_role) == 1
