"""Performance budgets of the policy evaluator and the rules (engine.md §2.6; F-142).

Run with ``-m perf`` (deselected by default). Budgets are for the repo's ``.venv`` Python 3.10.
"""

from __future__ import annotations

import random
import string
import time

import pytest

from aws_enumerator.engine.iam.principals import _build_permission_map, models_from_permission_map
from aws_enumerator.engine.policy import glob as G
from aws_enumerator.engine.policy.evaluator import Evaluator
from aws_enumerator.engine.rules.runner import run_rules

pytestmark = [pytest.mark.perf, pytest.mark.finding("F-142")]

ACCT = "111122223333"
SERVICES = ("s3", "ec2", "iam", "lambda", "kms", "sqs", "sns", "dynamodb", "rds", "ssm", "secretsmanager", "glue",
            "ecs", "eks", "cloudformation", "logs", "cloudwatch", "sts")


def _actions(count: int, seed: int = 7):
    rnd = random.Random(seed)
    out = set()
    while len(out) < count:
        verb = rnd.choice(("Get", "List", "Describe", "Put", "Create", "Update"))
        out.add(f"{rnd.choice(SERVICES)}:{verb}{''.join(rnd.choice(string.ascii_letters) for _ in range(10))}")
    return sorted(out)


def _permission_map(actions):
    role = {"RoleName": "big", "Arn": f"arn:aws:iam::{ACCT}:role/big", "AssumeRolePolicyDocument": {"Statement": []}}
    doc = {"Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"},
                         {"Effect": "Allow", "Action": [a.split(":")[0] + ":Get*" for a in actions[:50]],
                          "Resource": "*"}]}
    inline = {"users": {}, "roles": {"big": {"p": doc}}, "groups": {}}
    return _build_permission_map([], [role], {}, {}, {}, {}, inline, {})


def test_1500_action_role_through_every_rule_under_50ms():
    """F-142: d13c215 took ~1.1 s for one 1,500-action role on Python 3.10 (fnmatch cache thrash)."""
    pm = _permission_map(_actions(1500))
    timings = []
    for _ in range(5):
        G.compile_glob.cache_clear()
        G.glob_overlap.cache_clear()
        G.glob_covers.cache_clear()
        start = time.perf_counter()
        pset = models_from_permission_map(pm)
        ev = Evaluator(None, pset.models, pset.resource_index(), None, account_id=ACCT, partition="aws")
        run_rules(ev, pset)
        timings.append(time.perf_counter() - start)
    assert min(timings) < 0.050, timings


def test_evaluate_scales_past_the_fnmatch_cache_size():
    """3,000 distinct action patterns: the second pass is all cache hits (no recompilation cliff)."""
    patterns = [f"svc{i % 30}:Action{i}*" for i in range(3000)]
    for p in patterns:
        G.glob_match(p, "svc1:Action1x")
    start = time.perf_counter()
    for p in patterns:
        G.glob_match(p, "svc1:Action1x")
    assert time.perf_counter() - start < 0.05
