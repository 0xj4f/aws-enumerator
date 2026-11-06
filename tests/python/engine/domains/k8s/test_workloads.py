"""Kubernetes workloads (``analyzers/k8s/workloads.py``): pods aggregated by owner, what a pod gives an attacker, and
the pod → node → node group IMDS path.

F-035: init and ephemeral containers, hostPath, capabilities, hostIPC, env / envFrom secret references.
F-086: K8S-DEFAULT-SA once per workload and only when the default service account's token is mounted.
F-033: ``CAN_REACH_NODE_IMDS`` pod → node group, then ``NODE_ROLE``. F-054 / F-150: Secret nodes come from pod
references only; env values never reach the analysis.
"""

from __future__ import annotations

import importlib

import pytest

W = importlib.import_module("tests.fixtures.e-k8s.k8s_world")
NODE_ROLE = W.iam_arn("role", "demo-eks-node-role")


def _ids(graph, fid):
    return {f["node_id"] for f in W.findings(graph, fid)}


@pytest.mark.finding("F-035")
def test_escape_primitives_of_every_container_kind_are_found(report):
    c = report.cluster()
    c.pod("ops", "init-priv", init=[W.container("setup", privileged=True)])
    c.pod("ops", "debug", ephemeral=[W.container("debugger", privileged=True)])
    c.pod("ops", "root-mount", volumes=[W.host_path_volume("/"), W.host_path_volume("/var/run/docker.sock", "sock")])
    c.pod("ops", "cache-mount", volumes=[W.host_path_volume("/data/cache")])
    c.pod("ops", "caps", containers=[W.container(caps=["SYS_ADMIN", "NET_BIND_SERVICE"])])
    c.pod("ops", "harmless-caps", containers=[W.container(caps=["NET_BIND_SERVICE", "CHOWN"])])
    c.pod("ops", "ipc", host_ipc=True)
    c.pod("ops", "setuid", containers=[W.container(escalation=True)])
    g = report.analyze().graph
    assert W.problems(g) == [] and W.status(g) == "ok"
    pod = lambda n: c.id("Pod", "ops", n)  # noqa: E731
    assert _ids(g, "K8S-PRIV-001") == {pod("init-priv"), pod("debug")}
    [init] = W.findings(g, "K8S-PRIV-001", pod("init-priv"))
    assert init["evidence"]["containers"] == ["init container setup"]
    [eph] = W.findings(g, "K8S-PRIV-001", pod("debug"))
    assert eph["evidence"]["containers"] == ["ephemeral container debugger"]
    hp = {f["node_id"]: f for f in W.findings(g, "K8S-HOSTPATH-001")}
    assert hp[pod("root-mount")]["severity"] == "HIGH"
    assert hp[pod("root-mount")]["evidence"]["sensitive"] == ["/", "/var/run/docker.sock"]
    assert hp[pod("cache-mount")]["severity"] == "MEDIUM"
    assert _ids(g, "K8S-CAP-001") == {pod("caps")}
    assert _ids(g, "K8S-HOSTIPC-001") == {pod("ipc")}
    [esc] = W.findings(g, "K8S-ESCALATION-001")
    assert esc["node_id"] == pod("setuid") and esc["severity"] == "LOW"


@pytest.mark.finding("F-035", "F-054", "F-150")
def test_env_and_env_from_secret_references_become_mount_edges(v2report):
    c = v2report.cluster()
    c.pod("apps", "api", sa="api-sa", volumes=[W.secret_volume("tls-cert"), {
        "name": "proj", "projected": {"sources": [{"secret": {"name": "bundle"}}]}}],
        containers=[W.container(env=[W.env_secret("DB_PASSWORD", "db-creds"), W.env_value("PLAIN")],
                                env_from=[W.env_from_secret("api-keys")])],
        init=[W.container("migrate", env=[W.env_secret("MIGRATE_TOKEN", "migrate-token")])])
    out = v2report.analyze()
    g = out.graph
    assert W.problems(g) == []
    pod = c.id("Pod", "apps", "api")
    via = {e["target"].rsplit("/", 1)[-1]: e["evidence"]["via"] for e in W.edges(g, "MOUNTS_SECRET", source=pod)}
    assert via == {"tls-cert": ["volume"], "bundle": ["projected"], "db-creds": ["env"], "api-keys": ["env_from"],
                   "migrate-token": ["env"]}
    nodes = W.nodes_by_id(g)
    assert all(nodes[c.id("Secret", "apps", s)]["type"] == "k8ssecret" for s in via)
    assert not (out.path / "eu-west-2" / "k8s" / "demo-eks" / "secrets.json").exists()   # never needed (F-150)
    for f in sorted(out.dir.rglob("*")):                                                    # values never leak
        if f.is_file():
            assert W.CANARY.encode() not in f.read_bytes(), f.name


@pytest.mark.finding("F-086")
def test_pods_are_aggregated_by_their_owning_workload(report):
    c = report.cluster()
    for suffix in ("a1b2c", "d3e4f", "g5h6i"):
        c.pod("apps", f"web-5d9f8c7b6d-{suffix}", owner=("ReplicaSet", "web-5d9f8c7b6d"),
              labels={"app": "web", "pod-template-hash": "5d9f8c7b6d"})
    c.pod("kube-system", "aws-node-x1", owner=("DaemonSet", "aws-node"), sa="aws-node")
    c.pod("kube-system", "aws-node-x2", owner=("DaemonSet", "aws-node"), sa="aws-node")
    c.pod("apps", "standalone")
    g = report.analyze().graph
    pods = {n["id"]: n for n in g["nodes"] if n["type"] == "pod"}
    assert set(pods) == {c.id("Pod", "apps", "Deployment:web"), c.id("Pod", "kube-system", "DaemonSet:aws-node"),
                         c.id("Pod", "apps", "standalone")}
    web = pods[c.id("Pod", "apps", "Deployment:web")]["props"]
    assert web["pod_count"] == 3 and web["owner_kind"] == "Deployment" and len(web["pods"]) == 3
    # one default-SA finding for the three replicas, not three (F-086)
    assert _ids(g, "K8S-DEFAULT-SA") == {c.id("Pod", "apps", "Deployment:web"), c.id("Pod", "apps", "standalone")}


@pytest.mark.finding("F-086")
def test_default_sa_finding_needs_a_mounted_token_and_is_graded(report):
    c = report.cluster()
    c.sa("quiet", "default", automount=False)
    c.pod("quiet", "no-token-sa")                                  # the SA disables automount
    c.pod("apps", "no-token-pod", automount=False)                 # the pod disables it
    c.pod("apps", "token")                                         # default automount: token mounted
    c.pod("rights", "token")
    c.binding("rights", "default-edit", "ClusterRole", "edit", [W.subject("ServiceAccount", "default", "rights")])
    g = report.analyze().graph
    graded = {f["node_id"]: f["severity"] for f in W.findings(g, "K8S-DEFAULT-SA")}
    assert graded == {c.id("Pod", "apps", "token"): "LOW", c.id("Pod", "rights", "token"): "MEDIUM"}
    assert W.edges(g, "RUNS_AS", source=c.id("Pod", "quiet", "no-token-sa")) == []
    assert W.edges(g, "RUNS_AS", source=c.id("Pod", "apps", "no-token-pod")) == []


@pytest.mark.finding("F-034")
def test_a_web_identity_token_alone_is_a_conditional_runs_as(report):
    c = report.cluster()
    c.pod("apps", "aws-only", sa="worker", automount=False, volumes=[W.token_volume("sts.amazonaws.com")])
    g = report.analyze().graph
    [e] = W.edges(g, "RUNS_AS", source=c.id("Pod", "apps", "aws-only"))
    assert e["confidence"] == "conditional" and e["evidence"]["api_token_mounted"] is False
    assert e["evidence"]["token_sources"] == ["projected:sts.amazonaws.com"]


def _node_world(rep, *, tokens="optional", hop=1, endpoint="enabled", fargate=False):
    c = rep.cluster()
    ng = c.nodegroup("demo-ng", NODE_ROLE)
    c.node("ip-10-0-1-10.demo.internal", instance_id="i-0a1b2c3d4e5f60001", nodegroup="demo-ng", fargate=fargate)
    rep.instance(c.region, "i-0a1b2c3d4e5f60001", dns="ip-10-0-1-10.demo.internal", nodegroup="demo-ng",
                 cluster=c.name, tokens=tokens, hop_limit=hop, endpoint=endpoint)
    c.pod("apps", "app")
    c.pod("apps", "hostnet", host_network=True)
    return c, ng


@pytest.mark.finding("F-033")
def test_pods_reach_the_node_role_through_the_node_imds(v2report):
    c, ng = _node_world(v2report)
    g = v2report.analyze().graph
    assert W.problems(g) == []
    e = W.edge(g, "CAN_REACH_NODE_IMDS", c.id("Pod", "apps", "app"), ng)
    assert e["traversable"] is True and e["confidence"] == "definite" and e["weight"] == 1
    assert e["evidence"]["mapping"] == "nodes.json" and e["evidence"]["imds"]["http_tokens"] == "optional"
    p = W.path(g, c.id("Pod", "apps", "app"), NODE_ROLE)
    assert p is not None and tuple(p.edge_types) == ("CAN_REACH_NODE_IMDS", "NODE_ROLE")
    assert W.edge(g, "NODE_ROLE", ng, NODE_ROLE)["traversable"] is True


@pytest.mark.finding("F-033")
@pytest.mark.parametrize("kw, app_edge, hostnet_edge", [
    ({"tokens": "required", "hop": 1}, False, True),       # IMDSv2 hop limit 1: only the host network reaches it
    ({"tokens": "required", "hop": 2}, True, True),
    ({"endpoint": "disabled"}, False, False),
    ({"fargate": True}, False, False),
])
def test_imds_settings_decide_the_pod_to_node_edge(v2report, kw, app_edge, hostnet_edge):
    c, ng = _node_world(v2report, **kw)
    g = v2report.analyze().graph
    assert (W.edge(g, "CAN_REACH_NODE_IMDS", c.id("Pod", "apps", "app"), ng) is not None) is app_edge
    assert (W.edge(g, "CAN_REACH_NODE_IMDS", c.id("Pod", "apps", "hostnet"), ng) is not None) is hostnet_edge


@pytest.mark.finding("F-033")
def test_old_reports_map_nodes_through_the_instance_dns_name(report):
    c = report.cluster()
    ng = c.nodegroup("demo-ng", NODE_ROLE)
    c.omit = ("nodes",)                                            # d13c215 reports have no nodes.json
    report.instance(c.region, "i-0a1b2c3d4e5f60001", dns="ip-10-0-1-10.demo.internal", nodegroup="demo-ng",
                    cluster=c.name)
    c.pod("apps", "app")
    g = report.analyze().graph
    e = W.edge(g, "CAN_REACH_NODE_IMDS", c.id("Pod", "apps", "app"), ng)
    assert e is not None and e["evidence"]["mapping"] == "ec2-private-dns"
