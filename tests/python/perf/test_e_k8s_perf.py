"""Performance budget of the Kubernetes analyzer (engine.md §2.6 table: 3,000 pods / 300 services < 2 s; F-087).

The d13c215 ``SELECTS`` loop rescanned every pod for every pod of every service's namespace
(O(services × pods-in-namespace × pods)); the native analyzer indexes pods by namespace and label once.
Run with ``-m perf`` (deselected by default). Budgets are for the repo's ``.venv`` Python 3.10.
"""

from __future__ import annotations

import importlib
import time

import pytest

pytestmark = [pytest.mark.perf, pytest.mark.finding("F-087")]

W = importlib.import_module("tests.fixtures.e-k8s.k8s_world")


def _big_cluster(rep, *, pods: int, services: int, namespaces: int):
    c = rep.cluster()
    for i in range(pods):
        ns = f"ns{i % namespaces}"
        app = f"app{i % services}"
        c.pod(ns, f"{app}-{i}", sa=f"sa{i % 50}", labels={"app": app, "tier": f"t{i % 3}"})
    for s in range(services):
        c.service(f"ns{s % namespaces}", f"svc{s}", selector={"app": f"app{s}"})
    return c


@pytest.mark.parametrize("namespaces", [1, 30])
def test_three_thousand_pods_and_three_hundred_services_under_two_seconds(tmp_path, namespaces):
    rep = W.K8sReport(tmp_path)
    c = _big_cluster(rep, pods=3000, services=300, namespaces=namespaces)
    path = rep.write()
    engine = importlib.import_module("tests.support.targets").engine_module()
    started = time.perf_counter()
    result = engine.analyze_report(str(path))
    total = time.perf_counter() - started
    k8s = [s for s in result.analyzer_status if s.name == "k8s"][0]
    assert k8s.status == "ok"
    elapsed = k8s.duration_seconds if k8s.duration_seconds is not None else total
    assert elapsed < 2.0, f"k8s analyzer took {elapsed:.2f}s ({namespaces} namespace(s), {c.name})"
