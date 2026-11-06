"""Regression tests owned by stream E-core (context, loaders, graph builder, findings, writers).

xfail-first (see test_e_policy.py). Tests that need ``graph.json`` / ``analyze_report`` /
``analyze_run`` are written against the frozen contracts (docs/contracts/engine-api.md, graph-json.md,
node-ids.md) and say "requires <API>" in their reason. Synthetic trees use ids that satisfy
node-ids.md (hex instance ids, ``[A-Z0-9]`` zone ids) so the graph validator has nothing to object to.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fixtures.regressions import support as S
from tests.support import report_builder as rb

ACCT, R, R1 = S.ACCT, S.REGION, S.OTHER_REGION
EC2_TRUST = rb.trust({"Service": "ec2.amazonaws.com"})
ADMIN_NODE = f"aws-enumerator:account-admin/{ACCT}"
GRAPH_API = "requires engine.analyze_report() writing analysis/graph.json (engine-api.md §3.2, graph-json.md)"


def instance_arn(iid: str, region: str = R) -> str:
    return f"arn:aws:ec2:{region}:{ACCT}:instance/{iid}"


# ── trees ────────────────────────────────────────────────────────────────────
def build_exposure_tree(root: Path) -> Path:
    """Resource findings of four kinds (bucket, instance, Lambda, Route 53) for F-005."""
    s = rb.Scope(root, ACCT, R)
    iam = rb.Iam(ACCT)
    iam.role("demo-web-role", EC2_TRUST)
    prof = iam.instance_profile("demo-web-profile", ["demo-web-role"])
    iam.role("demo-fn-role", rb.trust({"Service": "lambda.amazonaws.com"}))
    iam.write(s)
    rb.write_empty_regional(s, skip={"sg", "ec2", "lambda"})
    s.write("s3/buckets.json", [rb.s3_bucket(s, "demo-public-bucket", policy=rb.resource_policy(
        rb.grant("*", "s3:GetObject", "arn:aws:s3:::demo-public-bucket/*")))])
    sg = rb.security_group("sg-0a1b2c3d4e5f60001", "demo-open", vpc="vpc-0a1b2c3d4e5f6aaaa",
                           inbound=[rb.sg_rule("tcp", 22, cidrs=["0.0.0.0/0"])],
                           attached_instances=["i-0a1b2c3d4e5f60001"])
    s.write("sg/security_groups.json", [sg])
    s.write("ec2/instances.json", [rb.ec2_instance(
        "i-0a1b2c3d4e5f60001", account=ACCT, region=R, profile=prof, http_tokens="optional",
        public_ip="203.0.113.10", sgs=[{"GroupId": "sg-0a1b2c3d4e5f60001", "GroupName": "demo-open"}])])
    fn = rb.lambda_function("demo-url-fn", account=ACCT, region=R, role=iam.arn("role", "demo-fn-role"),
                            url_auth="NONE")
    s.write("lambda/functions.json", [fn])
    s.write("lambda/resource_policies/demo-url-fn.json", rb.lambda_policy_file(fn, rb.resource_policy(
        rb.grant("*", "lambda:InvokeFunctionUrl", fn["FunctionArn"],
                 {"StringEquals": {"lambda:FunctionUrlAuthType": "NONE"}}))))
    s.write("route53/resources.json", [{
        "Type": "route53zone", "Id": "Z0EXAMPLEZONEAAA", "Name": "example.org.", "Private": False,
        "RecordCount": 1, "Records": [{"Name": "static.example.org.", "Type": "CNAME",
                                       "Targets": ["demo-gone.s3.amazonaws.com"]}],
        "TakeoverCandidates": [{"Name": "static.example.org.", "Target": "demo-gone.s3.amazonaws.com"}]}])
    rb.write_manifest(s.path, account=ACCT, mode="single_region", region=R)
    return s.path


def build_shared_tree(root: Path) -> Path:
    """F-007: principals that share a group, a customer policy and a bucket, plus one real CAN_ASSUME path."""
    s = rb.Scope(root, ACCT, R)
    iam = rb.Iam(ACCT)
    iam.managed("demo-shared-policy", [rb.allow("s3:ListAllMyBuckets", "*")], customer=True)
    iam.group("demo-devs", inline={"g": [rb.allow("ec2:DescribeInstances", "*")]})
    iam.user("demo-dev", groups=["demo-devs"], attached=["demo-shared-policy"], access_keys=1)
    iam.user("demo-admin-user", groups=["demo-devs"], attached=["AdministratorAccess"], access_keys=1)
    ops = iam.user("demo-ops", access_keys=1)
    iam.role("demo-admin-role", rb.trust({"AWS": ops}), attached=["AdministratorAccess", "demo-shared-policy"])
    iam.role("demo-app-role", EC2_TRUST, inline={"p": [rb.allow("s3:GetObject", "arn:aws:s3:::demo-logs/*")]})
    iam.write(s)
    s.write("s3/buckets.json", [rb.s3_bucket(s, "demo-logs", policy=rb.resource_policy(
        rb.grant({"AWS": iam.arn("role", "demo-admin-role")}, "s3:GetObject", "arn:aws:s3:::demo-logs/*")))])
    rb.write_manifest(s.path, account=ACCT, mode="single_region", region=R)
    return s.path


HOSTILE_PATH = "<img/src=x/onerror=window.__aeXssCanary=1>"
HOSTILE_TAG = "\"><svg onload=window.__aeXssCanary=1>"
HOSTILE_JOB = "</script><script>window.__aeXssCanary=1</script>"


def build_hostile_tree(root: Path) -> Path:
    """Attacker-plantable strings in the places F-008 names: IAM path, EC2 Name tag, Glue job name."""
    s = rb.Scope(root, ACCT, R)
    iam = rb.Iam(ACCT)
    iam.role("demo-hostile-path-role", EC2_TRUST, path=f"/{HOSTILE_PATH}/")
    iam.role("demo-glue-role", rb.trust({"Service": "glue.amazonaws.com"}))
    iam.write(s)
    s.write("ec2/instances.json", [rb.ec2_instance("i-0a1b2c3d4e5f6beef", account=ACCT, region=R,
                                                   tags={"Name": HOSTILE_TAG})])
    s.write("glue/resources.json", [rb.compute_resource("gluejob", HOSTILE_JOB, HOSTILE_JOB,
                                                        [iam.arn("role", "demo-glue-role")])])
    rb.write_manifest(s.path, account=ACCT, mode="single_region", region=R)
    return s.path


def build_all_mode_tree(root: Path) -> Path:
    """Old ``--all`` layout ``<acct>/{global,eu-west-1,eu-west-2}`` with regional EC2 and Secrets data."""
    g = rb.Scope(root, ACCT, "global")
    iam = rb.Iam(ACCT)
    iam.role("demo-app-role", EC2_TRUST, inline={"p": [rb.allow("secretsmanager:GetSecretValue", "*")]})
    prof = iam.instance_profile("demo-app-profile", ["demo-app-role"])
    iam.write(g)
    g.write("s3/buckets.json", [])
    for n, region in enumerate((R1, R), start=1):
        r = rb.Scope(root, ACCT, region)
        rb.write_empty_regional(r, skip={"ec2", "secretsmanager"})
        r.write("ec2/instances.json", [rb.ec2_instance(f"i-0a1b2c3d4e5f6000{n}", account=ACCT, region=region,
                                                       profile=prof)])
        r.write("secretsmanager/secrets.json", [rb.secret(f"demo/{region}/db", account=ACCT, region=region)])
    rb.write_manifest(root / ACCT, account=ACCT, mode="all_regions", region=None, regions=[R1, R])
    return root / ACCT


# ── F-002: one failing analyzer must not lose every output ───────────────────
@pytest.mark.finding("F-002")
def test_f002_malformed_report_still_writes_every_output(tmp_path):
    S.build_scenario("malformed", tmp_path)
    analysis = S.analyze_tree(tmp_path / ACCT / R)
    for name in ("findings.json", "summary.json", "permission_map.json", "s3_relationships.json"):
        assert (analysis.dir / name).is_file(), name
    # the IAM rules still ran: example-user's inline s3:GetObject statement reached the permission map
    assert "example-user" in json.dumps(analysis.load("permission_map.json"))


# ── F-005 (engine side): every finding is attached to a node ─────────────────
@pytest.mark.finding("F-005")
def test_f005_every_finding_is_attached_to_an_existing_node(tmp_path):
    graph = S.analyze_graph(build_exposure_tree(tmp_path))
    assert S.graph_problems(graph) == []
    nodes = S.nodes_by_id(graph)
    assert graph["findings"], "the exposure tree must produce findings"
    for f in graph["findings"]:
        assert f.get("node_id") in nodes, f
        assert f["fingerprint"] in nodes[f["node_id"]]["findings"], f
    anchors = {fid: {f["node_id"] for f in S.graph_findings(graph, fid)}
               for fid in ("S3-PUBLIC-001", "EC2-IMDS-001", "LAMBDA-URL-001", "ROUTE53-DANGLING-001")}
    assert anchors["S3-PUBLIC-001"] == {"arn:aws:s3:::demo-public-bucket"}, anchors
    assert anchors["EC2-IMDS-001"] == {instance_arn("i-0a1b2c3d4e5f60001")}, anchors
    assert anchors["LAMBDA-URL-001"] == {f"arn:aws:lambda:{R}:{ACCT}:function:demo-url-fn"}, anchors
    assert anchors["ROUTE53-DANGLING-001"] == {"arn:aws:route53:::hostedzone/Z0EXAMPLEZONEAAA"}, anchors


@pytest.mark.finding("F-005")
def test_f005_kubernetes_findings_anchor_at_kubernetes_nodes(tmp_path):
    S.build_scenario("eks_irsa", tmp_path)
    graph = S.analyze_graph(tmp_path / ACCT / R)
    nodes = S.nodes_by_id(graph)
    assert all(f.get("node_id") in nodes for f in graph["findings"])
    cluster = f"arn:aws:eks:{R}:{ACCT}:cluster/demo-eks"
    priv = {f["node_id"] for f in S.graph_findings(graph, "K8S-PRIV-001")}
    assert priv == {f"k8s://{cluster}/Pod/kube-system/node-debugger"}, priv
    summary = S.load_json(tmp_path / ACCT / R / "analysis" / "summary.json", {})
    assert summary.get("unattached_count") == 0


# ── F-006 (engine side): {"Error"} attachment maps become a status, not data ─
@pytest.mark.finding("F-006")
def test_f006_error_attachment_maps_become_attached_policies_status(tmp_path):
    S.build_scenario("malformed_stubs", tmp_path)
    graph = S.analyze_graph(tmp_path / ACCT / R)
    nodes = S.nodes_by_id(graph)
    for kind, name in (("role", "example-single-stmt"), ("user", "example-user"), ("group", "example-group")):
        props = nodes[S.iam_arn(kind, name)]["props"]
        assert props.get("attached_policies_status") in ("denied", "error"), (name, props)
        assert "AccessDenied" in str(props.get("attached_policies_error")), (name, props)
    # a readable attachment list is complete
    assert nodes[S.iam_arn("role", "example-string-trust")]["props"].get("attached_policies_status") not in (
        "denied", "error")


# ── F-007 (engine side): normalised, directed, traversable edges ─────────────
@pytest.mark.finding("F-007")
def test_f007_shared_group_policy_or_bucket_is_not_an_attack_path(tmp_path):
    graph = S.analyze_graph(build_shared_tree(tmp_path))
    assert S.graph_problems(graph) == []
    dev, admin_user = S.iam_arn("user", "demo-dev"), S.iam_arn("user", "demo-admin-user")
    admin_role, app_role = S.iam_arn("role", "demo-admin-role"), S.iam_arn("role", "demo-app-role")
    ops = S.iam_arn("user", "demo-ops")
    assert S.path(graph, dev, admin_user) is None        # shared group demo-devs
    assert S.path(graph, dev, admin_role) is None        # shared customer policy demo-shared-policy
    assert S.path(graph, dev, ADMIN_NODE) is None
    assert S.path(graph, app_role, admin_role) is None   # both can read demo-logs
    # MEMBER_OF and HAS_POLICY are stored user -> group / principal -> policy and never walked backwards
    assert S.graph_edges(graph, edge_type="MEMBER_OF", source=dev, target=S.iam_arn("group", "demo-devs"))
    # the real control path is found
    real = S.path(graph, ops, admin_role)
    assert real is not None and real.edge_types == ("CAN_ASSUME",)
    assert S.path(graph, ops, ADMIN_NODE) is not None


# ── F-008 (engine side): report strings are carried raw, never as HTML ───────
@pytest.mark.finding("F-008")
def test_f008_hostile_strings_are_raw_valid_graph_data(tmp_path):
    report = build_hostile_tree(tmp_path)
    graph = S.analyze_graph(report)
    assert S.graph_problems(graph) == []
    nodes = S.nodes_by_id(graph)
    assert S.iam_arn("role", "demo-hostile-path-role", path=f"/{HOSTILE_PATH}/") in nodes
    inst = nodes[instance_arn("i-0a1b2c3d4e5f6beef")]
    assert {"key": "Name", "value": HOSTILE_TAG} in inst["tags"]
    assert HOSTILE_JOB in {n["label"] for n in graph["nodes"] if n["type"] == "gluejob"}
    text = (report / "analysis" / "graph.json").read_text(encoding="utf-8")
    assert not any(entity in text for entity in ("&lt;", "&gt;", "&quot;", "&#39;"))


# ── F-010 (engine side): old --all layouts are analysed with their regions ───
@pytest.mark.finding("F-010")
def test_f010_legacy_all_layout_analysis_has_regional_edges(tmp_path):
    acct_dir = build_all_mode_tree(tmp_path)
    graph = S.analyze_graph(acct_dir)
    assert graph["run"]["mode"] == "legacy-all"
    assert graph["run"]["regions"] == [R1, R]
    role = S.iam_arn("role", "demo-app-role")
    for n, region in enumerate((R1, R), start=1):
        inst = instance_arn(f"i-0a1b2c3d4e5f6000{n}", region)
        assert S.graph_edges(graph, edge_type="INSTANCE_ROLE", source=inst, target=role), region
        secret = rb.secret(f"demo/{region}/db", account=ACCT, region=region)["ARN"]
        assert S.graph_edges(graph, edge_type="CAN_READ_SECRET", source=role, target=secret), region
    assert (acct_dir / "analysis" / "graph.json").is_file()


# ── F-013: managed policy documents keyed by ARN, not by name ────────────────
def build_policy_name_collision_tree(root: Path) -> Path:
    s = rb.Scope(root, ACCT, R)
    iam = rb.Iam(ACCT)
    customer = iam.managed("ReadOnlyAccess", [rb.allow("*", "*")], customer=True, version="v1")
    aws = iam.managed("ReadOnlyAccess", rb.AWS_MANAGED_DOCS["ReadOnlyAccess"], version="v118")
    iam.role("demo-backdoor", EC2_TRUST, attached=[customer])
    iam.role("demo-auditor", EC2_TRUST, attached=[aws])
    iam.write(s)
    rb.write_manifest(s.path, account=ACCT, mode="single_region", region=R)
    return s.path


@pytest.mark.finding("F-013")
def test_f013_customer_policy_named_like_an_aws_policy_keeps_its_own_document(tmp_path):
    analysis = S.analyze_tree(build_policy_name_collision_tree(tmp_path))
    admin_ids = {"ADMIN-001", "DANGER-001"}
    backdoor = {i for f in S.findings_for(analysis.findings(), subject=S.iam_arn("role", "demo-backdoor"))
                for i in S.finding_ids(f)}
    auditor = {i for f in S.findings_for(analysis.findings(), subject=S.iam_arn("role", "demo-auditor"))
               for i in S.finding_ids(f)}
    assert admin_ids & backdoor, f"customer ReadOnlyAccess (Allow *:*) not evaluated: {sorted(backdoor)}"
    assert not (admin_ids & auditor), f"AWS-managed ReadOnlyAccess evaluated as admin: {sorted(auditor)}"


# ── F-025 / F-063 (engine side): explicit region list, no sibling scan ───────
@pytest.mark.finding("F-025", "F-063", "F-010")
def test_f025_analyze_run_reads_only_the_listed_regions(tmp_path):
    run = S.V2Run(tmp_path, regions=[R])
    g = run.scope("global")
    iam = rb.Iam(ACCT)
    iam.role("demo-app-role", EC2_TRUST)
    prof = iam.instance_profile("demo-app-profile", ["demo-app-role"])
    iam.write(g)
    g.write("s3/buckets.json", [])
    mine = run.scope(R)
    rb.write_empty_regional(mine, skip={"ec2"})
    mine.write("ec2/instances.json", [rb.ec2_instance("i-0a1b2c3d4e5f60aaa", account=ACCT, region=R, profile=prof)])
    stray = run.scope(R1)  # e.g. left behind by an earlier run or a .stale copy: not in manifest.target.regions
    rb.write_empty_regional(stray, skip={"ec2"})
    stray.write("ec2/instances.json", [rb.ec2_instance("i-0a1b2c3d4e5f60bbb", account=ACCT, region=R1,
                                                       profile=prof)])
    run.write_manifest()

    _result, graph = S.analyze_run_graph(run.path, [R])
    nodes = S.nodes_by_id(graph)
    assert instance_arn("i-0a1b2c3d4e5f60aaa") in nodes
    assert not [n for n in nodes if "i-0a1b2c3d4e5f60bbb" in n]
    assert graph["run"]["regions"] == [R]
    summary = S.load_json(run.path / "analysis" / "summary.json", {})
    assert R1 in (summary.get("ignored_dirs") or [])


# ── F-074: LOW (and INFO) findings are counted everywhere ────────────────────
@pytest.mark.finding("F-074")
def test_f074_summary_counts_every_severity(tmp_path):
    analysis = S.analyze_tree(build_exposure_tree(tmp_path))
    summary = analysis.summary()
    findings = analysis.findings()
    lows = [f for f in findings if f.get("severity") == "LOW" and f.get("status", "open") == "open"]
    assert lows, "the tree must contain a LOW finding (ROUTE53-DANGLING-001)"
    assert summary.get("low_count") == len(lows), summary
    assert "info_count" in summary, summary
    by_sev = summary.get("by_severity", {})
    assert set(by_sev) >= {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}, by_sev
    assert sum(by_sev.values()) == summary.get("total_findings"), summary


# ── F-162: directory listing order never changes the output ──────────────────
VOLATILE_KEYS = frozenset({"duration_seconds", "generated_at", "analyzed_at"})


def _stable(obj):
    if isinstance(obj, dict):
        return {k: _stable(v) for k, v in obj.items() if k not in VOLATILE_KEYS}
    if isinstance(obj, list):
        return [_stable(v) for v in obj]
    return obj


def _outputs(analysis):
    out = {}
    for p in sorted(analysis.dir.iterdir()):
        if p.is_file() and p.suffix == ".json" and p.name != "_provenance.json":
            out[p.name] = _stable(json.loads(p.read_text(encoding="utf-8")))
    return out


@pytest.mark.finding("F-162")
def test_f162_output_does_not_depend_on_listdir_order(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", S.SOURCE_DATE_EPOCH)
    S.build_scenario("data_services", tmp_path / "a")
    S.build_scenario("data_services", tmp_path / "b")
    first = _outputs(S.analyze_tree(tmp_path / "a" / ACCT / R))
    second = _outputs(S.with_listdir_reversed(lambda: S.analyze_tree(tmp_path / "b" / ACCT / R)))
    assert first.keys() == second.keys()
    assert (first.get("findings.json") or {}).get("findings"), "an empty analysis proves nothing about ordering"
    differing = sorted(name for name in first if first[name] != second[name])
    assert differing == []


# ── F-171 (engine side): the only clock value is UTC and reproducible ────────
@pytest.mark.finding("F-171")
def test_f171_graph_generated_at_is_utc_and_reproducible(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", S.SOURCE_DATE_EPOCH)
    graph = S.analyze_graph(build_shared_tree(tmp_path))
    assert graph["run"]["generated_at"] in ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00+00:00")


def test_regressions_v2_run_helper_writes_a_valid_manifest(tmp_path):
    """Harness sanity (no finding): the synthetic v2 run root used above carries a schema-valid manifest."""
    import jsonschema

    run = S.V2Run(tmp_path, regions=[R, R1])
    doc = S.load_json(run.write_manifest())
    schema = S.load_json(S.schema_path("manifest-2.0.schema.json"))
    jsonschema.Draft202012Validator(schema).validate(doc)
    assert run.path == tmp_path / ACCT / S.RUN_ID and doc["target"]["regions"] == [R1, R]
