"""Performance budget of the E-data analyzers (engine.md §2.6: classification hoisted, evaluator memoised).

Run with ``-m perf`` (deselected by default). Budgets are for the repo's ``.venv`` Python 3.10.
"""

from __future__ import annotations

import importlib

import pytest

K = importlib.import_module("tests.fixtures.e-data.kit")
rb = K.rb

pytestmark = [pytest.mark.perf, pytest.mark.finding("F-142", "F-030")]

ACTIONS = (["secretsmanager:GetSecretValue"], ["ssm:GetParameter*"], ["kms:Decrypt"], ["dynamodb:Query"], ["*"],
           ["s3:GetObject"])
#: Seconds for kms + secrets + data_stores together (about 6 s measured on the reference laptop).
BUDGET_SECONDS = 15.0


def _world(root):
    run = K.Run(root)
    for i in range(200):
        scope = "*" if i % 3 else f"arn:aws:secretsmanager:{K.REGION}:{K.ACCT}:secret:demo/{i % 7}*"
        run.iam.role(f"demo-role-{i:03d}", K.EC2_TRUST, inline={"p": [rb.allow(ACTIONS[i % len(ACTIONS)], scope)]})
    keys = [K.v2_key(f"{i:08x}-aaaa-4bbb-8ccc-1f2a3b4c5d6e") for i in range(100)]
    run.write_json(K.REGION, "kms/keys.json", keys)
    for key in keys:
        run.write_json(K.REGION, f"kms/key_policies/{key['KeyId']}.json",
                       K.key_policy_file(key, rb.resource_policy(K.root_delegation())))
    run.write_json(K.REGION, "secretsmanager/secrets.json", [K.v2_secret(f"demo/{i}") for i in range(300)])
    run.write_json(K.REGION, "ssm/parameters.json",
                   [K.v2_param(f"/demo/app{i % 20}/p{i}", ptype="SecureString") for i in range(200)])
    run.write_json(K.REGION, "dynamodb/resources.json",
                   [K.v2_policy_resource("dynamodb", f"demo-t{i}") for i in range(100)])
    run.finish()
    return run


def test_two_hundred_principals_against_seven_hundred_resources_within_budget(tmp_path):
    res = _world(tmp_path).analyze()
    took = {s.name: s.duration_seconds for s in res.result.analyzer_status
            if s.name in ("kms", "secrets", "data_stores")}
    assert set(took) == {"kms", "secrets", "data_stores"} and all(v is not None for v in took.values())
    assert sum(took.values()) < BUDGET_SECONDS, took
    assert len(K.edges(res.graph, "CAN_READ_SECRET")) > 1000          # the work was really done
