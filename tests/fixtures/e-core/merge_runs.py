"""Analysed synthetic v2 runs for the ``merge`` tests (graph.json 1.1, F-126; engine-api.md §3.5, cli.md §3.8).

Runs are built with ``tests/support/report_builder.V2Run`` (placeholder accounts, ``demo-*`` names) and analysed
with the real engine (``analyze_run``). :func:`two_accounts` gives the canonical pair:

* account A (``123456789012``): an admin user, a local role, and a KMS key whose policy grants ``kms:Decrypt``
  to account B's role ``demo-reader``, so A's graph holds the ``external_principal``
  ``arn:aws:iam::111122223333:role/demo-reader`` and a ``KMS_GRANTS_CROSS_ACCOUNT`` edge from it;
* account B (``111122223333``): an admin user, the role ``demo-reader`` and the operator's role
  ``demo-operator`` (the manifest's caller is ``assumed-role/demo-operator/...``, so ``run.operator`` resolves).

Import with ``importlib.import_module("tests.fixtures.e-core.merge_runs")`` (the directory name has a hyphen).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional, Sequence

from tests.support import report_builder as rb
from tests.support import targets

ACCT_A, ACCT_B, ACCT_C = rb.ACCT_MAIN, rb.ACCT_ALT, rb.ACCT_EXT
RUN_A, RUN_B, RUN_C = "20260101T000000Z-a1a1a1", "20260101T000000Z-b2b2b2", "20260101T000000Z-c3c3c3"
REGION, OTHER = "eu-west-2", "eu-west-1"
KEY_ID = "2c3d4e5f-aaaa-4bbb-8ccc-6a7b8c9d0e1f"
EPOCH = "1767225600"   # 2026-01-01T00:00:00Z


def role_arn(account: str, name: str) -> str:
    return f"arn:aws:iam::{account}:role/{name}"


def key_arn(account: str, region: str = REGION) -> str:
    return f"arn:aws:kms:{region}:{account}:key/{KEY_ID}"


def analysed_run(root: Path, account: str, run_id: str, *, regions: Sequence[str] = (REGION,),
                 roles: Sequence[str] = (), kms_grant_to: Optional[str] = None,
                 denied_module: Optional[str] = None) -> Path:
    """A finalised v2 run root, analysed by the real engine (``<root>/<account>/<run_id>/``)."""
    run = rb.V2Run(root, account=account, run_id=run_id, regions=list(regions))
    iam = rb.Iam(account)
    iam.user("demo-admin-user", attached=[iam.managed("demo-admin", rb.doc(rb.allow("*")), customer=True)])
    for name in roles:
        iam.role(name, rb.trust({"AWS": f"arn:aws:iam::{account}:root"}))
    g = run.unit("global")
    iam.write(g, layout="gaad")
    run.coverage("iam", "global")
    for region in run.regions:
        rb.write_empty_regional(run.unit(region))
    if kms_grant_to:
        scope = run.unit(run.regions[0])
        key = rb.kms_key(KEY_ID, account=account, region=run.regions[0])
        scope.write("kms/keys.json", [key])
        scope.write(f"kms/key_policies/{KEY_ID}.json", rb.kms_policy_file(key, rb.resource_policy(
            rb.grant({"AWS": kms_grant_to}, "kms:Decrypt"))))
        run.coverage("kms", run.regions[0])
    if denied_module:
        run.coverage(denied_module, run.regions[0], status="partial")
    run.finalize()
    result = targets.engine_module().analyze_run(str(run.path), regions=list(run.regions))
    if result.status not in ("ok", "partial"):
        raise AssertionError(f"synthetic run {account} did not analyse: {result.status} {result.error}")
    return run.path


def two_accounts(root: Path) -> SimpleNamespace:
    """The canonical pair (module docstring); ``a`` and ``b`` are run roots."""
    a = analysed_run(Path(root) / "in", ACCT_A, RUN_A, regions=(REGION,), roles=("demo-local",),
                     kms_grant_to=role_arn(ACCT_B, "demo-reader"))
    b = analysed_run(Path(root) / "in", ACCT_B, RUN_B, regions=(OTHER, REGION),
                     roles=("demo-reader", "demo-operator"), denied_module="sns")
    return SimpleNamespace(a=a, b=b, accounts=(ACCT_A, ACCT_B))


def load_graph(run_root: Path) -> Dict[str, Any]:
    return json.loads((Path(run_root) / "analysis" / "graph.json").read_text(encoding="utf-8"))


def write_graph(run_root: Path, doc: Any, *, raw: Optional[bytes] = None) -> None:
    """Replace a run's ``analysis/graph.json`` (canonical JSON, or ``raw`` bytes)."""
    path = Path(run_root) / "analysis" / "graph.json"
    path.write_bytes(raw if raw is not None else json.dumps(doc, sort_keys=True, separators=(",", ":")).encode())
