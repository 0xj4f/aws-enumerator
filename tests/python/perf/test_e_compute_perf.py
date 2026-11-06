"""Performance budget of the messaging and compute analyzers (F-030; engine.md §2.6).

d13c215 re-classified every statement's actions per resource with no service prefilter: 200 roles × 1,000 queues
took 16.75 s in messaging and 10.44 s in compute (verified-findings F-030). The native analyzers pre-filter
principals by the action index and once per resource type (existential evaluation on the type's ARN template), so
the same world must analyse in under two seconds per analyzer.

Run with ``-m perf`` (deselected by default). Budgets are for the repo's ``.venv`` Python 3.10.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

K = importlib.import_module("tests.fixtures.e-compute.kit")
rb = K.rb

pytestmark = [pytest.mark.perf, pytest.mark.finding("F-030")]

ROLES, RESOURCES, BUDGET_S = 200, 1000, 2.0


def _world(tmp_path):
    t = K.LegacyTree(tmp_path)
    for i in range(ROLES):
        t.iam.role(f"demo-app-{i:03d}", rb.trust({"Service": "ec2.amazonaws.com"}), inline={"p": [rb.allow(
            ["s3:GetObject", "ec2:DescribeInstances", "logs:PutLogEvents", "cloudwatch:PutMetricData"], "*")]})
    for i in range(5):                                       # a few principals that do act on SQS and ECS
        t.iam.role(f"demo-ops-{i}", rb.trust({"Service": "ec2.amazonaws.com"}),
                   inline={"p": [rb.allow(["sqs:SendMessage", "ecs:RunTask"], "*")]})
    t.put("sqs/resources.json", [dict(rb.policy_resource("sqs", K.queue_arn(f"demo-q{i:04d}"), f"demo-q{i:04d}",
                                                         None), PolicyStatus="absent") for i in range(RESOURCES)])
    task = K.iam_arn("role", "demo-app-000")
    t.put("ecs/resources.json", [rb.compute_resource(
        "ecstask", f"arn:aws:ecs:{K.REGION}:{K.ACCT}:task-definition/demo-f{i:04d}:1", f"demo-f{i:04d}", [task],
        Family=f"demo-f{i:04d}", TaskRole=task, ExecutionRole=None, Revisions=[1]) for i in range(RESOURCES)])
    return t


def test_200_roles_by_1000_queues_and_task_families_under_two_seconds(tmp_path, monkeypatch):
    t = _world(tmp_path)
    t.write()
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)      # durations are recorded only when not reproducible
    result = K.engine().analyze_report(str(t.path))
    durations = {s.name: s.duration_seconds for s in result.analyzer_status}
    assert durations["messaging"] is not None and durations["compute"] is not None, durations
    assert durations["messaging"] < BUDGET_S, durations["messaging"]
    assert durations["compute"] < BUDGET_S, durations["compute"]
    graph = K.load(Path(result.graph_path))
    assert len(K.edges(graph, "CAN_SEND")) == 5 * RESOURCES          # the prefilter drops no real edge
