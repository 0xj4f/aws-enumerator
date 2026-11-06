"""Domain analyzers → normalised graph and legacy files (F-005, F-022, F-037, F-039, F-002).

These tests pinned the d13c215 legacy adapter until Wave 3; the adapter and the d13c215 analyzers are gone
(DECISIONS.md D-53), so they now prove the same properties of the native analyzers: public grants start at the
anonymous node and the legacy files still store them resource → ``principal:*``; statements merge into one edge
and one legacy record (F-022); unknown (``null``) lists are coverage gaps, never a crash; a failing analyzer is
isolated and the analyzers that require it are skipped (requests e-net-1, e-net-2, e-compute-1, e-k8s-1).
"""

from __future__ import annotations

import pytest

from tests.fixtures.regressions import support as S

EC2_TRUST = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
ANON = "aws-enumerator:anonymous"


@pytest.fixture
def data_services_analysis(tmp_path):
    S.build_scenario("data_services", tmp_path)
    return S.analyze_tree(tmp_path / S.ACCT / S.REGION)


@pytest.fixture
def data_services(data_services_analysis):
    return data_services_analysis.graph()


@pytest.mark.finding("F-037")
def test_public_grants_come_from_the_anonymous_node(h, data_services_analysis):
    g = data_services_analysis.graph()
    public = [e for e in g["edges"] if e["type"].endswith("_PUBLIC") or e["type"] == "GRANTS_PUBLIC"]
    assert public, "the scenario has public grants"
    assert {e["source"] for e in public} == {ANON}
    assert not [n for n in g["nodes"] if n["id"].startswith("principal:")]
    et = h.engine("graph.edge_types").EDGE_TYPES
    reversed_types = {e["type"] for e in public if et[e["type"]].legacy_reversed}
    assert reversed_types, "some public type has a legacy rendering"
    legacy = [r for r in data_services_analysis.edges() if r.get("type") in {et[t].legacy_name for t in reversed_types}]
    assert legacy and all(r["target"] == "principal:*" for r in legacy)   # the legacy files keep resource -> *
    assert h.graph_problems(g) == []


@pytest.mark.finding("F-039")
def test_cross_account_grants_resolve_to_the_exact_foreign_principal(h, tmp_path):
    t = h.Tree(tmp_path)
    t.iam.role("deploy", EC2_TRUST)                                          # a LOCAL role named like the grantee
    t.write()
    key = h.rb.kms_key("2c3d4e5f-aaaa-4bbb-8ccc-6a7b8c9d0e1f", account=h.ACCT, region=h.REGION)
    t.scope.write("kms/keys.json", [key])
    foreign = f"arn:aws:iam::{h.FOREIGN}:role/deploy"
    t.scope.write(f"kms/key_policies/{key['KeyId']}.json", h.rb.kms_policy_file(key, h.rb.resource_policy(
        h.rb.grant({"AWS": foreign}, "kms:Decrypt"))))
    g = t.analyze().graph
    [edge] = h.edges(g, "KMS_GRANTS_CROSS_ACCOUNT")
    assert edge["source"] == foreign and edge["target"] == key["Arn"]
    assert h.nodes_by_id(g)[foreign]["type"] == "external_principal"
    assert not h.edges(g, source=h.iam_arn("role", "deploy"), target=key["Arn"])
    assert h.graph_problems(g) == []


@pytest.mark.finding("F-022")
def test_statements_merge_into_one_graph_edge_and_one_legacy_record(h, tmp_path):
    t = h.Tree(tmp_path)
    t.iam.user("demo-reader", inline={"a": [h.rb.allow("s3:GetObject", "*")],
                                      "b": [h.rb.allow("s3:ListBucket", "*")]})
    t.write()
    t.scope.write("s3/buckets.json", [h.rb.s3_bucket(t.scope, "demo-data")])
    out = t.analyze()
    legacy = h.load(out.dir / "s3_relationships.json")["edges"]
    reader = h.iam_arn("user", "demo-reader")
    assert len([e for e in legacy if e["source"] == reader]) == 1          # one per merged edge (d13c215: 2)
    [edge] = h.edges(out.graph, "CAN_READ", reader, "arn:aws:s3:::demo-data")
    assert edge["evidence"]["actions"] == ["s3:GetObject", "s3:ListBucket"]
    assert len(edge["evidence"]["statements"]) == 2


@pytest.mark.finding("F-005")
def test_resource_findings_anchor_at_resource_nodes(h, data_services):
    g = data_services
    nodes = h.nodes_by_id(g)
    assert g["findings"]
    for f in g["findings"]:
        assert f["node_id"] in nodes and f["fingerprint"] in nodes[f["node_id"]]["findings"]
    anchors = {f["id"]: nodes[f["node_id"]]["type"] for f in g["findings"]}
    assert anchors["DDB-PUB-001"] == "dynamodb" and anchors["ECR-PUB-001"] == "ecr"
    assert anchors["SECRET-PUB-001"] == "secret" and anchors["ROUTE53-DANGLING-001"] == "route53zone"
    assert anchors["EBS-XACCT-001"] == "ebssnapshot" and anchors["APIGW-AUTH-001"] == "apigw"


@pytest.mark.finding("F-005")
def test_kubernetes_findings_and_edges_use_cluster_arn_ids(h, tmp_path):
    S.build_scenario("eks_irsa", tmp_path)
    g = S.analyze_graph(tmp_path / S.ACCT / S.REGION)
    cluster = f"arn:aws:eks:{S.REGION}:{S.ACCT}:cluster/demo-eks"
    k8s = [n for n in g["nodes"] if n["id"].startswith("k8s://")]
    assert k8s and all(n["id"].startswith(f"k8s://{cluster}/") for n in k8s)
    roles = {n["id"]: n for n in g["nodes"] if n["type"] == "k8srole"}
    assert f"k8s://{cluster}/ClusterRole/_/cluster-admin" in roles
    for f in g["findings"]:
        if f["id"].startswith("K8S-"):
            assert f["node_id"].startswith("k8s://") or f["node_id"] == cluster, f
    assert h.graph_problems(g) == []


def test_instance_role_and_ssrf_edges(h, tmp_path):
    S.build_scenario("public_exposure", tmp_path)
    g = S.analyze_graph(tmp_path / S.ACCT / S.REGION)
    [ssrf] = h.edges(g, "SSRF_TO_IMDS")
    assert ssrf["source"] == ANON and ssrf["confidence"] == "conditional" and ssrf["weight"] == 6
    inst = h.nodes_by_id(g)[ssrf["target"]]
    assert inst["type"] == "instance" and inst["props"]["imds_v1"] is True
    assert h.edges(g, "INSTANCE_ROLE", source=ssrf["target"])
    path = h.engine("graph.traverse").shortest_path(g, ANON, h.edges(g, "INSTANCE_ROLE", source=ssrf["target"])[0][
        "target"])
    assert path is not None and path.edge_types == ("SSRF_TO_IMDS", "INSTANCE_ROLE")


def test_inventory_nodes_carry_tags_and_raw_labels(h, tmp_path):
    t = h.Tree(tmp_path)
    t.iam.role("demo-glue-role", h.rb.trust({"Service": "glue.amazonaws.com"}))
    t.write()
    tag = '"><img src=x>'
    t.scope.write("ec2/instances.json", [h.rb.ec2_instance("i-0a1b2c3d4e5f6beef", account=h.ACCT, region=h.REGION,
                                                           tags={"Name": tag, "team": "demo"})])
    t.scope.write("glue/resources.json", [h.rb.compute_resource("gluejob", "demo job/1", "demo job/1",
                                                                [h.iam_arn("role", "demo-glue-role")])])
    g = t.analyze().graph
    inst = h.nodes_by_id(g)[f"arn:aws:ec2:{h.REGION}:{h.ACCT}:instance/i-0a1b2c3d4e5f6beef"]
    assert inst["label"] == tag and {"key": "team", "value": "demo"} in inst["tags"]
    [job] = [n for n in g["nodes"] if n["type"] == "gluejob"]
    assert job["id"] == f"arn:aws:glue:{h.REGION}:{h.ACCT}:job/demo job/1" and job["props"]["arn_synthesised"]
    assert h.edges(g, "USES_ROLE", job["id"], h.iam_arn("role", "demo-glue-role"))
    assert h.graph_problems(g) == []


def test_legacy_files_pass_through_with_policy_names(h, tmp_path):
    t = h.Tree(tmp_path)
    shared = t.iam.managed("demo-s3", [h.rb.allow("s3:*", "*")], customer=True)
    t.iam.user("demo-user", attached=[shared])
    t.write()
    t.scope.write("s3/buckets.json", [h.rb.s3_bucket(t.scope, "demo-data")])
    out = t.analyze()
    [edge] = h.load(out.dir / "s3_relationships.json")["edges"]
    assert edge["source_policy"] == "demo-s3" and edge["source_policy_arn"] == shared["PolicyArn"]
    graph_edge = h.edges(out.graph, "FULL_ACCESS")[0]
    assert graph_edge["evidence"]["statements"][0]["policy_arn"] == shared["PolicyArn"]


def test_legacy_ref_round_trip(h):
    legacy = h.engine("writers.legacy")
    cases = {
        ("aws-enumerator:anonymous", "anonymous"): "principal:*",
        ("arn:aws:s3:::demo", "bucket"): "bucket:demo",
        ("arn:aws:ec2:eu-west-2:123456789012:instance/i-0abc", "instance"): "i-0abc",
        ("arn:aws:lambda:eu-west-2:123456789012:function:f", "lambda"):
            "lambda:arn:aws:lambda:eu-west-2:123456789012:function:f",
        ("k8s://arn:aws:eks:eu-west-2:123456789012:cluster/c/ClusterRole/_/admin", "k8srole"):
            "k8srole:c/cluster/admin",
        ("k8s://arn:aws:eks:eu-west-2:123456789012:cluster/c/Pod/ns/p", "pod"): "pod:c/ns/p",
    }
    for (nid, ntype), expected in cases.items():
        assert legacy.legacy_ref({"id": nid, "type": ntype}) == expected


@pytest.mark.finding("F-002", "F-059")
def test_unknown_lists_from_migrated_collectors_are_coverage_gaps(h, tmp_path):
    t = h.Tree(tmp_path)
    t.iam.role("demo-app-role", EC2_TRUST)
    t.write()
    key = h.rb.kms_key("6a7b8c9d-aaaa-4bbb-8ccc-0e1f2a3b4c5d", account=h.ACCT, region=h.REGION)
    key["Grants"] = None                                  # unknown (ListGrants denied): null, never []
    t.scope.write("kms/keys.json", [key])
    t.scope.write("ebs/resources.json", [{"Id": "snap-0a1b2c3d4e5f60001", "Public": False, "SharedAccounts": None}])
    raw = (t.path / "kms" / "keys.json").read_bytes()
    out = t.analyze()
    status = {s.name: s.status for s in out.result.analyzer_status}
    assert status["kms"] == "ok" and status["edge_services"] == "ok", status
    nodes = h.nodes_by_id(out.graph)
    assert nodes[key["Arn"]]["coverage"]["status"] == "partial"
    snap = f"arn:aws:ec2:{h.REGION}::snapshot/snap-0a1b2c3d4e5f60001"
    assert nodes[snap]["coverage"]["status"] == "partial" and nodes[snap]["coverage"]["gaps"]
    assert not h.edges(out.graph, "EBS_SHARED_CROSS_ACCOUNT", target=snap)   # unknown is not "shared"
    codes = {g["code"] for g in out.graph["evaluation_gaps"]}
    assert "legacy:unknown-lists-as-empty" not in codes                      # no sanitised view any more
    assert (t.path / "kms" / "keys.json").read_bytes() == raw         # the collected file is never changed
    assert h.graph_problems(out.graph) == []


@pytest.mark.finding("F-002")
def test_a_failing_analyzer_is_isolated_and_its_dependants_are_skipped(h, tree, monkeypatch):
    tree.iam.user("demo-admin", attached=["AdministratorAccess"], access_keys=1)
    tree.iam.role("demo-x", h.rb.trust({"AWS": f"arn:aws:iam::{h.FOREIGN}:root"}))
    tree.write()
    runner = h.engine("rules.runner")

    def broken(ctx, builder):
        raise RuntimeError("demo native failure")

    spec = runner.ANALYZERS[0]
    monkeypatch.setattr(runner, "ANALYZERS", (h.engine("model").AnalyzerSpec(
        spec.name, spec.phase, broken, inputs=spec.inputs, requires=spec.requires),))
    out = tree.analyze()
    status = {s.name: s for s in out.result.analyzer_status}
    assert status["rules"].status == "error" and status["rules"].error_type == "RuntimeError"
    assert not [n for n in status if n.endswith(":fallback")]                # no standby fallback any more
    assert status["subsume"].status == "skipped" and status["severity"].status == "skipped"
    assert out.result.status == "partial"
    assert not h.findings(out.graph, "DANGER-001")                           # the rules' output was rolled back
    assert h.findings(out.graph, "TRUST-002")                                # every other analyzer still ran
    assert h.graph_problems(out.graph) == []
