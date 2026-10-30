"""The R-owned harness accessors in ``tests/support/targets.py`` point at modules that exist (request ``c-k8s-2``)."""

from __future__ import annotations

import importlib

import pytest

from tests.support import targets


def test_every_module_name_constant_imports():
    names = {k: v for k, v in vars(targets).items()
             if k.isupper() and isinstance(v, str) and v.startswith(f"{targets.PACKAGE_NAME}.")}
    assert "EKS_AUTH_MODULE" in names and "MERGE_MODULE" in names
    for key, module in sorted(names.items()):
        assert importlib.import_module(module).__name__ == module, key


def test_eks_auth_and_k8s_accessors_follow_the_wave1_package():
    auth = targets.eks_auth_module()
    assert auth.__name__ == f"{targets.K8S_PACKAGE}.auth" and hasattr(auth, "kubernetes_available")
    for name in targets.K8S_MODULES:
        assert targets.k8s_module(name).__name__ == f"{targets.K8S_PACKAGE}.{name}"
    with pytest.raises(KeyError):
        targets.k8s_module("eks_auth")                      # the baseline copy is gone (F-119)


def test_merge_accessor_exposes_the_contract_api():
    merge = targets.merge_module()
    for name in ("plan_merge", "merge_graphs", "write_merged", "MergeInvalid"):
        assert hasattr(merge, name), name
    assert not hasattr(merge, "MergeUnavailable")


def test_every_new_collector_module_exists():
    for name in targets.NEW_COLLECTOR_NAMES:
        assert targets.collector_module(name).__name__ == f"{targets.COLLECTORS_PACKAGE}.{name}"
