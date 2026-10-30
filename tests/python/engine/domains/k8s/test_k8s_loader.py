"""The k8s loader (``io/loaders/k8s.py``) as the analyzers see it: explicit regions, cluster ARNs in every id,
``null`` / unreadable = unknown, no dependency on ``secrets.json``.

F-025: same-named clusters of two regions never collide; only the manifest's regions are read. F-054 / F-150:
projected pods are enough and ``secrets.json`` is never needed. F-059 (engine side): an unreadable list is a
coverage gap of the cluster node, never "no objects".
"""

from __future__ import annotations

import importlib
import json

import pytest

from tests.support import targets

W = importlib.import_module("tests.fixtures.e-k8s.k8s_world")


def _analyze(path):
    result = targets.engine_module().analyze_report(str(path))
    return json.loads(open(result.graph_path, encoding="utf-8").read())


@pytest.mark.finding("F-025")
def test_same_named_clusters_in_two_regions_never_collide(tmp_path):
    rep = W.K8sReport(tmp_path, layout="v2", regions=(W.OTHER, W.REGION))
    east, west = rep.cluster("demo-eks", region=W.REGION), rep.cluster("demo-eks", region=W.OTHER)
    for c in (east, west):
        c.pod("apps", "api", sa="api")
    g = rep.analyze().graph
    assert W.problems(g) == []
    clusters = {n["id"]: n for n in g["nodes"] if n["type"] == "cluster"}
    assert set(clusters) == {east.arn, west.arn}
    assert {clusters[east.arn]["region"], clusters[west.arn]["region"]} == {W.REGION, W.OTHER}
    for c in (east, west):
        pod = c.id("Pod", "apps", "api")
        assert W.edge(g, "IN_CLUSTER", pod, c.arn) is not None
        assert W.edge(g, "RUNS_AS", pod, c.id("ServiceAccount", "apps", "api")) is not None
    assert all(n["id"].startswith((f"k8s://{east.arn}/", f"k8s://{west.arn}/"))
               for n in g["nodes"] if n["id"].startswith("k8s://"))


@pytest.mark.finding("F-025", "F-063")
def test_only_the_manifest_regions_are_read(tmp_path):
    rep = W.K8sReport(tmp_path, layout="v2")
    rep.cluster("demo-eks")
    path = rep.write()
    stray = path / W.OTHER / "eks"                                   # a region directory the run did not collect
    stray.mkdir(parents=True)
    (stray / "clusters.json").write_text(json.dumps([W.Cluster("demo-stray", W.OTHER, W.ACCT).record()]))
    g = _analyze(path)
    assert [n["label"] for n in g["nodes"] if n["type"] == "cluster"] == ["demo-eks"]


def _region_dir(path):
    """``<run root>/<region>`` for a v2 run, the region directory itself for a legacy report."""
    return path / W.REGION if (path / W.REGION).is_dir() else path


def _rewrite(path, rel, content):
    target = _region_dir(path) / rel
    target.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")


@pytest.mark.finding("F-059", "F-152")
@pytest.mark.parametrize("layout, rel, content, gap", [
    ("v2", "k8s/demo-eks/pods.json", None, "k8s:pods:not-collected"),               # file missing
    ("v2", "k8s/demo-eks/pods.json", "null", "k8s:pods:error"),
    ("v2", "k8s/demo-eks/service_accounts.json", "{not json", "k8s:service_accounts:error"),
    ("legacy", "k8s/demo-eks/role_bindings.json", {"error": "Forbidden"}, "k8s:role_bindings:error"),
    ("v2", "eks/access_entries.json", {}, "eks:access_entries:error"),            # the cluster's key is absent
    ("v2", "eks/nodegroups.json", {"demo-eks": {"Error": "AccessDenied"}}, "eks:nodegroups:error"),
    ("v2", "k8s/demo-eks/aws_auth.json", {"present": None, "map_roles": None, "map_users": None,
                                          "map_accounts": None, "parse_errors": []}, "k8s:aws_auth:error"),
])
def test_unreadable_lists_are_unknown_not_empty(tmp_path, layout, rel, content, gap):
    rep = W.K8sReport(tmp_path, layout=layout)
    c = rep.cluster()
    c.pod("apps", "api")
    path = rep.write()
    if content is None:
        (_region_dir(path) / rel).unlink()
    else:
        _rewrite(path, rel, content)
    g = _analyze(path)
    assert W.problems(g) == [] and W.status(g) == "ok"
    cov = W.nodes_by_id(g)[c.arn]["coverage"]
    assert gap in cov["gaps"] and cov["status"] != "complete", cov


@pytest.mark.finding("F-150", "F-054")
def test_opt_in_secret_metadata_only_adds_the_type_of_referenced_secrets(tmp_path):
    rep = W.K8sReport(tmp_path, layout="v2")
    c = rep.cluster()
    c.pod("apps", "api", volumes=[W.secret_volume("db-creds")])
    path = rep.write()
    secrets = [{"name": "db-creds", "namespace": "apps", "type": "Opaque", "labels": None, "annotations": None},
               {"name": "unreferenced", "namespace": "apps", "type": "Opaque", "labels": None, "annotations": None}]
    _rewrite(path, "k8s/demo-eks/secrets.json", secrets)
    g = _analyze(path)
    nodes = W.nodes_by_id(g)
    assert nodes[c.id("Secret", "apps", "db-creds")]["props"]["secret_type"] == "Opaque"
    assert c.id("Secret", "apps", "unreferenced") not in nodes      # only what a pod reaches is a node


@pytest.mark.finding("F-025")
def test_a_collected_cluster_arn_is_the_id_and_a_bad_one_is_rebuilt(tmp_path):
    loader = targets.engine_module("io.loaders.k8s")
    rec = {"name": "demo-eks", "arn": "arn:aws:eks:eu-west-2:123456789012:cluster/demo-eks"}
    assert loader.cluster_arn_for(rec, region=W.OTHER, account=W.ACCT, partition="aws") == rec["arn"]
    rebuilt = loader.cluster_arn_for({"name": "demo-eks", "arn": "nonsense"}, region=W.OTHER, account=W.ACCT,
                                     partition="aws-us-gov")
    assert rebuilt == "arn:aws-us-gov:eks:eu-west-1:123456789012:cluster/demo-eks"
    assert loader.cluster_arn_for({"name": "a/b"}, region=W.OTHER, account=W.ACCT, partition="aws") is None


@pytest.mark.finding("F-059", "F-025")
def test_a_denied_cluster_listing_is_unknown_not_empty(tmp_path):
    rep = W.K8sReport(tmp_path, layout="v2")
    rep.coverage[("eks", W.REGION)] = {"calls": [{"api": "eks:ListClusters", "status": "denied", "primary": True}]}
    g = rep.analyze().graph
    assert W.status(g) == "ok" and [n for n in g["nodes"] if n["type"] == "cluster"] == []
    gaps = {x["code"]: x for x in g["evaluation_gaps"]}
    assert W.REGION in gaps["k8s:clusters-unknown"]["detail"]


@pytest.mark.finding("F-002", "F-025")
def test_a_cluster_record_that_cannot_form_an_id_is_counted(report):
    report.cluster()
    report.extra_cluster_records[W.REGION] = [{"name": "bad/name"}, {"arn": "nonsense"}]
    g = report.analyze().graph
    assert [n["label"] for n in g["nodes"] if n["type"] == "cluster"] == ["demo-eks"]
    assert "k8s:clusters-unrepresentable" in {x["code"] for x in g["evaluation_gaps"]}
