"""Kubernetes services and ingresses (``analyzers/k8s/network.py``).

F-083: a LoadBalancer service is internet-facing only when nothing marks it internal (annotations, the AWS Load
Balancer Controller's internal default, an ``internal-`` hostname); source ranges lower the severity. F-087: the
``SELECTS`` edges come from a pod index (by namespace and label), equal to the reference scan.
"""

from __future__ import annotations

import importlib
import random

import pytest

W = importlib.import_module("tests.fixtures.e-k8s.k8s_world")
SCHEME = "service.beta.kubernetes.io/aws-load-balancer-scheme"
INTERNAL = "service.beta.kubernetes.io/aws-load-balancer-internal"
LB_TYPE = "service.beta.kubernetes.io/aws-load-balancer-type"


def _network():
    return importlib.import_module("tests.support.targets").engine_module("analyzers.k8s.network")


@pytest.mark.finding("F-083")
@pytest.mark.parametrize("kw, severity", [
    ({}, "HIGH"),                                                          # in-tree default: internet-facing
    ({"annotations": {INTERNAL: "true"}}, None),
    ({"annotations": {SCHEME: "internal"}}, None),
    ({"annotations": {SCHEME: "internet-facing", LB_TYPE: "external"}}, "HIGH"),
    ({"annotations": {LB_TYPE: "external"}}, None),                         # LB Controller default is internal
    ({"lb_class": "service.k8s.aws/nlb"}, None),
    ({"lb_hostname": "internal-demo-123.eu-west-2.elb.amazonaws.com"}, None),
    ({"source_ranges": ["203.0.113.0/24"]}, "LOW"),
    ({"source_ranges": ["0.0.0.0/0"]}, "HIGH"),
])
def test_internet_facing_load_balancers_only(report, kw, severity):
    c = report.cluster()
    c.pod("web", "web-0", labels={"app": "web"})
    c.service("web", "web-lb", svc_type="LoadBalancer", selector={"app": "web"}, **kw)
    g = report.analyze().graph
    assert W.problems(g) == []
    svc = c.id("Service", "web", "web-lb")
    found = W.findings(g, "K8S-NET-001", svc)
    inbound = W.edges(g, "PUBLIC_INBOUND", target=svc)
    if severity is None:
        assert found == [] and inbound == []
        assert W.nodes_by_id(g)[svc]["props"]["lb_scheme"] == "internal"
    else:
        assert [f["severity"] for f in found] == [severity]
        assert len(inbound) == 1 and inbound[0]["traversable"] is False


@pytest.mark.finding("F-083")
def test_ingress_exposure_depends_on_scheme_class_and_auth(report):
    c = report.cluster()
    c.service("web", "web-svc", selector={"app": "web"})
    c.ingress("web", "alb-default", "web-svc")                              # ALB controller default: internal
    c.ingress("web", "alb-public", "web-svc", annotations={"alb.ingress.kubernetes.io/scheme": "internet-facing"})
    c.ingress("web", "alb-auth", "web-svc", annotations={"alb.ingress.kubernetes.io/scheme": "internet-facing",
                                                         "alb.ingress.kubernetes.io/auth-type": "cognito"})
    c.ingress("web", "nginx", "web-svc", ingress_class="nginx")
    g = report.analyze().graph
    conf = {f["node_id"].rsplit("/", 1)[-1]: f["confidence"] for f in W.findings(g, "K8S-NET-002")}
    assert conf == {"alb-public": "definite", "nginx": "conditional"}
    routes = W.edges(g, "INGRESS_ROUTES_TO", target=c.id("Service", "web", "web-svc"))
    assert len(routes) == 4 and all(e["traversable"] is False for e in routes)


@pytest.mark.finding("F-087")
def test_selects_matches_label_selectors_within_the_namespace(report):
    c = report.cluster()
    c.pod("web", "web-0", labels={"app": "web", "tier": "front"})
    c.pod("web", "web-batch", labels={"app": "web", "tier": "batch"})
    c.pod("other", "web-0", labels={"app": "web", "tier": "front"})
    c.service("web", "front", selector={"app": "web", "tier": "front"})
    c.service("web", "all-web", selector={"app": "web"})
    c.service("web", "headless")                                            # no selector: selects nothing
    g = report.analyze().graph
    sel = lambda name: {e["target"] for e in W.edges(g, "SELECTS", source=c.id("Service", "web", name))}  # noqa: E731
    assert sel("front") == {c.id("Pod", "web", "web-0")}
    assert sel("all-web") == {c.id("Pod", "web", "web-0"), c.id("Pod", "web", "web-batch")}
    assert sel("headless") == set()
    assert all(e["traversable"] is False for e in W.edges(g, "SELECTS"))


@pytest.mark.finding("F-087")
def test_the_pod_index_equals_the_reference_scan():
    net = _network()
    util = importlib.import_module("tests.support.targets").engine_module("analyzers.k8s.util")
    rng = random.Random(87)
    pods = []
    for i in range(600):
        labels = {"app": f"a{rng.randrange(12)}", "tier": f"t{rng.randrange(3)}"}
        if rng.random() < 0.3:
            labels["canary"] = "true"
        pods.append({"metadata": {"name": f"p{i}", "namespace": f"ns{rng.randrange(4)}", "labels": labels}})
    workloads, skipped = util.workloads("arn:aws:eks:eu-west-2:123456789012:cluster/demo-eks", pods)
    assert skipped == 0
    index = net.PodIndex.build(workloads)
    for _ in range(300):
        ns = f"ns{rng.randrange(4)}"
        selector = {"app": f"a{rng.randrange(12)}"}
        if rng.random() < 0.5:
            selector["tier"] = f"t{rng.randrange(3)}"
        if rng.random() < 0.2:
            selector["canary"] = "true"
        assert index.selected(ns, selector) == index.selected_scan(ns, selector)
    assert index.selected("ns0", {}) == frozenset()
