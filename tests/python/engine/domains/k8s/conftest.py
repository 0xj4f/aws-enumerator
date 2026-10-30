"""Fixtures of the E-k8s analyzer tests: a :class:`K8sReport` factory per layout (``tests/fixtures/e-k8s``)."""

from __future__ import annotations

import importlib

import pytest

W = importlib.import_module("tests.fixtures.e-k8s.k8s_world")


@pytest.fixture
def report(tmp_path):
    """A legacy single-region report (``eu-west-2``) with the default IAM roles of the world module."""
    return W.K8sReport(tmp_path)


@pytest.fixture
def v2report(tmp_path):
    """A v2 run (manifest 2.0, ``_coverage.json``) with one region (``eu-west-2``)."""
    return W.K8sReport(tmp_path, layout="v2")
