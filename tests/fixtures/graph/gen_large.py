"""Deterministic generator of large, contract-valid ``graph.json`` documents for performance tests.

Used by the perf budgets (F-038: dashboard index of 40k edges; discover-all chunking; Python traversal).
Output is valid against ``graph-1.0.schema.json`` and ``validate_graph(strict_order=True)``; the same
``(scale, seed)`` always gives the same bytes. Roughly ``21 * scale`` edges (scale 2000 ≈ 41k edges).

    .venv/bin/python tests/fixtures/graph/gen_large.py --scale 2000 --seed 1 --out /tmp/large-graph.json

From code::

    gen = importlib.util.spec_from_file_location("gen_large", ".../tests/fixtures/graph/gen_large.py")
    doc = module.generate(scale=200, seed=7)
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
import sys
from pathlib import Path
from typing import Any, Dict

HERE = Path(__file__).resolve().parent


def _builder():
    spec = importlib.util.spec_from_file_location("graph_fixture_builder", HERE / "build_fixtures.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def generate(scale: int = 100, seed: int = 1) -> Dict[str, Any]:
    if scale < 1:
        raise ValueError("scale must be >= 1")
    b = _builder()
    ids = b._ids
    rnd = random.Random(seed)
    acct, region = b.MAIN, b.REGION
    g = b.G()
    n_users = scale
    n_groups = max(1, scale // 10)
    n_roles = scale
    n_buckets = 2 * scale
    n_secrets = max(1, scale // 2)
    n_instances = max(1, scale // 2)
    n_lambdas = max(1, scale // 2)
    n_pods = max(1, scale // 2)
    cluster = f"arn:aws:eks:{region}:{acct}:cluster/demo-large"

    users = [g.node(b.arn_user(f"demo-user-{i:05d}"), "user", f"demo-user-{i:05d}") for i in range(n_users)]
    groups = [g.node(b.arn_group(f"demo-group-{i:04d}"), "group", f"demo-group-{i:04d}") for i in range(n_groups)]
    admin_roles = set(rnd.sample(range(n_roles), max(1, n_roles // 50)))
    roles = [g.node(b.arn_role(f"demo-role-{i:05d}", path="/app/"), "role", f"demo-role-{i:05d}",
                    high_value="admin-equivalent" if i in admin_roles else None) for i in range(n_roles)]
    buckets = [g.node(f"arn:aws:s3:::demo-large-bucket-{i:05d}", "bucket", f"demo-large-bucket-{i:05d}",
                      region=region) for i in range(n_buckets)]
    secrets = [g.node(f"arn:aws:secretsmanager:{region}:{acct}:secret:demo/s{i:05d}-AbCdEf", "secret",
                      f"demo/s{i:05d}", region=region) for i in range(n_secrets)]
    key = g.node(f"arn:aws:kms:{region}:{acct}:key/1234abcd-12ab-34cd-56ef-1234567890ab", "kms", "alias/demo",
                 region=region)
    instances = [g.node(ids.node_id_for("instance", region=region, account=acct, id=f"i-{i:017x}"), "instance",
                        f"demo-i-{i:05d}", region=region) for i in range(n_instances)]
    lambdas = [g.node(f"arn:aws:lambda:{region}:{acct}:function:demo-fn-{i:05d}", "lambda", f"demo-fn-{i:05d}",
                      region=region) for i in range(n_lambdas)]
    g.node(cluster, "cluster", "demo-large", region=region)
    pods, sas = [], []
    for i in range(n_pods):
        pods.append(g.node(ids.node_id_for("pod", cluster_arn=cluster, namespace="default",
                                           name=f"Deployment:demo-app-{i:05d}"), "pod", f"demo-app-{i:05d}",
                           region=region))
        sas.append(g.node(ids.node_id_for("sa", cluster_arn=cluster, namespace="default", name=f"demo-sa-{i:05d}"),
                          "sa", f"demo-sa-{i:05d}", region=region))
    admin = ids.account_admin_id(acct)
    anon = ids.ANONYMOUS_ID

    for u in users:
        for grp in rnd.sample(groups, min(2, len(groups))):
            g.edge(u, "MEMBER_OF", grp, holds=True)
        for r in rnd.sample(roles, min(3, len(roles))):
            g.edge(u, "CAN_ASSUME", r, confidence=rnd.choice(["definite", "conditional"]), strength="weak")
        g.edge(u, "CAN_UPDATE_CODE", rnd.choice(lambdas))
    for grp in groups:
        for r in rnd.sample(roles, min(5, len(roles))):
            g.edge(grp, "CAN_PASS_ROLE_TO", r)
    for i, r in enumerate(roles):
        if i in admin_roles:
            g.edge(r, "IS_ADMIN_EQUIVALENT", admin)
        for bk in rnd.sample(buckets, min(8, len(buckets))):
            g.edge(r, rnd.choice(["CAN_READ", "CAN_WRITE", "FULL_ACCESS", "CAN_ADMIN"]), bk)
        for s in rnd.sample(secrets, min(2, len(secrets))):
            g.edge(r, "CAN_READ_SECRET", s)
        g.edge(r, "CAN_DECRYPT", key)
    for i in range(0, n_roles - 1, 3):
        g.edge(roles[i], "CAN_ASSUME", roles[i + 1])
    for inst in instances:
        g.edge(inst, "INSTANCE_ROLE", rnd.choice(roles))
        if rnd.random() < 0.2:
            g.edge(anon, "PUBLIC_INBOUND", inst)
            g.edge(anon, "SSRF_TO_IMDS", inst, confidence="conditional", strength="weak")
    for fn in lambdas:
        g.edge(fn, "USES_ROLE", rnd.choice(roles))
    for pod, sa in zip(pods, sas, strict=True):
        g.edge(pod, "RUNS_AS", sa)
        g.edge(pod, "IN_CLUSTER", cluster)
        g.edge(sa, "IRSA_BRIDGE", rnd.choice(roles), holds=rnd.random() < 0.8)
    for bk in rnd.sample(buckets, max(1, n_buckets // 20)):
        g.edge(anon, "GRANTS_PUBLIC", bk)
        g.finding("S3-PUBLIC-001", bk, "HIGH", "Bucket policy allows public read")
    for i in sorted(admin_roles):
        g.finding("ADMIN-001", roles[i], "CRITICAL", "Principal is administrator-equivalent")
    for u in users[:: max(1, n_users // 20)]:
        g.finding("IAM-USER-MFA-001", u, "LOW", "Console user without MFA")
    return g.doc()


def dumps(doc: Dict[str, Any]) -> str:
    return json.dumps(doc, ensure_ascii=True, separators=(",", ":")) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scale", type=int, default=100)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default="-")
    a = ap.parse_args(argv)
    text = dumps(generate(a.scale, a.seed))
    if a.out == "-":
        sys.stdout.write(text)
    else:
        with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
