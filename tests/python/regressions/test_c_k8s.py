"""Regression tests owned by stream C-K8s (eks and k8s collectors, Kubernetes auth and transport).

xfail-first (see test_e_policy.py). ``eks`` then ``k8s`` run through ``collectors.base.run_collector``
(legacy adapter today, ``collect(ctx)`` after the migration) against the acme world and its fake
Kubernetes cluster ``demo-cluster`` (tests/support/fake_kubernetes.py), which records every API call.
Owner decisions (PLAN.md): K8s collection on by default; Secret listing off by default and metadata-only
with ``--k8s-secrets`` (option ``k8s_secrets``).

Note for C-K8s: the fake package serves the typed list APIs (``CoreV1Api.list_*``); a transport built on
``ApiClient.call_api`` needs the fake extended (harness-aws owns fake_kubernetes.py).
"""

from __future__ import annotations

import pytest

from tests.fixtures.regressions import support as S
from tests.fixtures.worlds import acme
from tests.support.fake_kubernetes import FakeKubernetes

pytestmark = pytest.mark.collectors

W2 = "eu-west-2"
SECRET_CANARY = acme.CANARIES["k8s_secret_last_applied"]


def run_k8s(tmp_path, monkeypatch, *, options=None, world=None):
    fake_k8s = FakeKubernetes(acme.build_k8s_clusters()).install(monkeypatch)
    world = world or acme.build_world()
    eks = S.run_module("eks", world, tmp_path, region=W2, options=options)
    k8s = S.run_module("k8s", world, tmp_path, region=W2, options=options, deps={"eks": eks.result.value})
    return eks, k8s, fake_k8s


# ── F-009: Secret values never reach the report ──────────────────────────────
@pytest.mark.finding("F-009")
def test_f009_default_collection_lists_no_secrets_and_leaks_no_values(tmp_path, monkeypatch):
    _eks, k8s, fake_k8s = run_k8s(tmp_path, monkeypatch)
    assert fake_k8s.calls_for(resource="pods"), "the cluster must have been read (k8s is on by default)"
    assert fake_k8s.calls_for(resource="secrets") == []
    assert S.grep_tree(SECRET_CANARY, tmp_path) == []


@pytest.mark.finding("F-009")
def test_f009_opt_in_secret_listing_is_metadata_only(tmp_path, monkeypatch):
    _eks, k8s, fake_k8s = run_k8s(tmp_path, monkeypatch, options={"k8s_secrets": True})
    assert fake_k8s.calls_for(resource="secrets"), "the opt-in must list secrets"
    assert S.grep_tree(SECRET_CANARY, tmp_path) == []
    files = [p for p in S.files_under(k8s.out) if p.name == "secrets.json"]
    assert files
    secrets = S.load_json(files[0])
    assert isinstance(secrets, list) and secrets
    for item in secrets:
        assert {"name", "namespace", "type"} <= set(item), item
        assert "kubectl.kubernetes.io/last-applied-configuration" not in (item.get("annotations") or {}), item
        assert not {"data", "string_data", "stringData"} & set(item), item


# ── F-107 (EKS part): list calls are paginated ───────────────────────────────
@pytest.mark.finding("F-107")
def test_f107_eks_addons_follow_pagination(tmp_path):
    world = acme.build_world()
    world.page_sizes[("eks", "ListAddons")] = 1                 # demo-cluster has two add-ons
    run = S.run_module("eks", world, tmp_path, region=W2)
    addons = (run.load("addons.json", {}) or {}).get("demo-cluster") or []
    assert {a.get("addonName") for a in addons if isinstance(a, dict)} == {"demo-observability", "vpc-cni"}


# ── F-120: Kubernetes requests carry timeouts ────────────────────────────────
@pytest.mark.finding("F-120")
def test_f120_every_kubernetes_request_has_a_finite_timeout(tmp_path, monkeypatch):
    _eks, _k8s, fake_k8s = run_k8s(tmp_path, monkeypatch)
    calls = fake_k8s.calls_for(cluster="demo-cluster")
    assert calls
    missing = sorted({c.method for c in calls if not c.kwargs.get("_request_timeout")})
    assert missing == [], f"requests without _request_timeout: {missing}"
