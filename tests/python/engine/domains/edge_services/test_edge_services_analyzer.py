"""Edge-services analyzer (engine/analyzers/edge_services.py): EBS snapshot sharing and Block Public Access, load
balancers (scheme, security groups, targets, classic ARNs) and Route 53 takeover candidates checked against the
collected data (engine.md §5)."""

from __future__ import annotations

import importlib

import pytest

K = importlib.import_module("tests.fixtures.e-net.kit")
rb = K.rb

SNAP = "snap-0a1b2c3d4e5f60001"
SNAP2 = "snap-0a1b2c3d4e5f60002"
SNAP3 = "snap-0a1b2c3d4e5f60003"
KEY = f"arn:aws:kms:{K.REGION}:{K.ACCT}:key/1a2b3c4d-aaaa-4bbb-8ccc-0d1e2f3a4b5c"


def snap_arn(sid: str, region: str = K.REGION) -> str:
    return f"arn:aws:ec2:{region}::snapshot/{sid}"


def lb_arn(name: str) -> str:
    return f"arn:aws:elasticloadbalancing:{K.REGION}:{K.ACCT}:loadbalancer/app/{name}/0a1b2c3d4e5f6a7b"


def zone_arn(zid: str) -> str:
    return f"arn:aws:route53:::hostedzone/{zid}"


def _snapshot(sid, public=False, shared=(), **kw):
    rec = {"Type": "ebssnapshot", "Id": sid, "Arn": snap_arn(sid), "Name": sid, "Public": public,
           "SharedAccounts": list(shared) if shared is not None else None, "SharingChecked": True,
           "Encrypted": False, "KmsKeyId": None, "VolumeId": "vol-0a1b2c3d4e5f6aaa1"}
    rec.update(kw)
    return rec


# ── EBS (F-080, F-104) ───────────────────────────────────────────────────────

@pytest.mark.finding("F-080")
def test_snapshot_block_public_access_neutralises_public_snapshots(tmp_path):
    for state, expect_edge, severity in (("block-all-sharing", False, "INFO"), ("block-new-sharing", True, "HIGH"),
                                         ("unblocked", True, "HIGH")):
        run = K.Run(tmp_path / state)
        run.write_json(K.REGION, "ebs/resources.json", [_snapshot(SNAP, public=True)])
        run.write_json(K.REGION, "ebs/account_settings.json", {"SnapshotBlockPublicAccessState": state}, module="ebs")
        run.finish()
        g = run.analyze().graph
        [f] = K.findings(g, "EBS-PUB-001", snap_arn(SNAP))
        assert f["severity"] == severity, state
        assert bool(K.edges(g, "EBS_SHARED_PUBLIC", K.ANON, snap_arn(SNAP))) is expect_edge, state
        if not expect_edge:
            assert f["evidence"]["mitigated_by"] == ["account:snapshot-block-public-access"]
        assert K.problems(g) == []


@pytest.mark.finding("F-080", "F-104", "F-059")
def test_cross_account_shares_and_unknown_sharing_in_a_v2_run(tmp_path):
    run = K.Run(tmp_path)
    run.write_json(K.REGION, "ebs/resources.json", [
        _snapshot(SNAP, shared=[K.FOREIGN, rb.ACCT_ALT], Encrypted=True, KmsKeyId=KEY),
        _snapshot(SNAP2, public=None, shared=None),
        _snapshot(SNAP3, shared=None, SharingChecked=False)])
    run.finish()
    g = run.analyze().graph
    roots = {f"arn:aws:iam::{a}:root" for a in (K.FOREIGN, rb.ACCT_ALT)}
    assert {e["source"] for e in K.edges(g, "EBS_SHARED_CROSS_ACCOUNT", target=snap_arn(SNAP))} == roots
    xacct = K.findings(g, "EBS-XACCT-001", snap_arn(SNAP))
    assert len(xacct) == 2 and len({f["fingerprint"] for f in xacct}) == 2          # discriminator = account
    assert K.edges(g, "EBS_ENCRYPTED_BY", snap_arn(SNAP), KEY)
    nodes = K.nodes_by_id(g)
    assert nodes[snap_arn(SNAP2)]["coverage"]["status"] == "partial"
    assert set(nodes[snap_arn(SNAP2)]["coverage"]["gaps"]) == {"ebs:public-unknown", "ebs:sharing-unknown"}
    assert "ebs:sharing-not-checked" in nodes[snap_arn(SNAP3)]["coverage"]["gaps"]
    assert K.findings(g, node_id=snap_arn(SNAP2)) == [] and K.edges(g, target=snap_arn(SNAP2)) == []
    assert K.problems(g) == []


# ── load balancers (F-051, F-083) ────────────────────────────────────────────

@pytest.mark.finding("F-083", "F-051")
def test_internal_and_classic_load_balancers_in_an_old_report(tmp_path):
    t = K.Tree(tmp_path)
    t.write()
    fn = f"arn:aws:lambda:{K.REGION}:{K.ACCT}:function:demo-etl"
    t.scope.write("elb/resources.json", [
        {"Type": "elb", "Arn": lb_arn("demo-internal"), "Name": "demo-internal", "Scheme": "internal",
         "DNSName": "internal-demo-internal.eu-west-2.elb.amazonaws.com", "LBType": "application",
         "Targets": [{"kind": "lambda", "id": fn}, {"kind": "ip", "id": "10.0.1.20"}]},
        {"Type": "elb", "Arn": "demo-classic", "Name": "demo-classic", "Scheme": "internet-facing",
         "DNSName": "demo-classic-1.eu-west-2.elb.amazonaws.com", "LBType": "classic",
         "Targets": [{"kind": "instance", "id": "i-0a1b2c3d4e5f6c001"}]}])
    out = t.analyze()
    g = out.graph
    assert [e["type"] for e in K.edges(g, source=lb_arn("demo-internal"))] == ["FRONTS"]
    assert K.findings(g, "ELB-PUB-001", lb_arn("demo-internal")) == []
    classic = f"arn:aws:elasticloadbalancing:{K.REGION}:{K.ACCT}:loadbalancer/demo-classic"
    node = K.nodes_by_id(g)[classic]
    assert node["props"]["arn_synthesised"] is True and node["props"]["internet_facing"] is True
    assert K.edges(g, "EXPOSES", classic, K.instance("i-0a1b2c3d4e5f6c001"))
    assert K.edges(g, "PUBLIC_INBOUND", K.ANON, classic)
    assert K.findings(g, "ELB-PUB-001", classic)[0]["severity"] == "MEDIUM"
    legacy = out.legacy("extra_relationships.json")
    assert {e["type"] for e in legacy["edges"]} == {"EXPOSES"}                 # FRONTS keeps the legacy name
    assert K.problems(g) == []


@pytest.mark.finding("F-083")
def test_internet_facing_lb_whose_security_groups_are_closed_is_info(tmp_path):
    run = K.Run(tmp_path)
    run.write_json(K.REGION, "sg/security_groups.json", [
        rb.security_group("sg-0a1b2c3d4e5f6d001", "demo-open", vpc=K.VPC,
                          inbound=[rb.sg_rule("tcp", 443, cidrs=["0.0.0.0/0"])]),
        rb.security_group("sg-0a1b2c3d4e5f6d002", "demo-closed", vpc=K.VPC,
                          inbound=[rb.sg_rule("tcp", 443, cidrs=["10.0.0.0/8"])])])
    common = {"Type": "elb", "Scheme": "internet-facing", "LBType": "application", "VpcId": K.VPC,
              "Listeners": [{"Port": 443, "Protocol": "HTTPS", "DefaultActionTypes": ["forward"],
                             "AuthenticateActions": []}], "TargetGroups": [], "Targets": None}
    run.write_json(K.REGION, "elb/resources.json", [
        {**common, "Arn": lb_arn("demo-open"), "Name": "demo-open", "DNSName": "demo-open.example",
         "SecurityGroups": ["sg-0a1b2c3d4e5f6d001"]},
        {**common, "Arn": lb_arn("demo-closed"), "Name": "demo-closed", "DNSName": "demo-closed.example",
         "SecurityGroups": ["sg-0a1b2c3d4e5f6d002"]}])
    run.finish()
    g = run.analyze().graph
    [open_f] = K.findings(g, "ELB-PUB-001", lb_arn("demo-open"))
    [closed_f] = K.findings(g, "ELB-PUB-001", lb_arn("demo-closed"))
    assert open_f["severity"] == "MEDIUM" and open_f["evidence"]["ports"] == ["443/tcp"]
    assert closed_f["severity"] == "INFO"
    assert K.edges(g, "PUBLIC_INBOUND", K.ANON, lb_arn("demo-open"))
    assert K.edges(g, "PUBLIC_INBOUND", K.ANON, lb_arn("demo-closed")) == []
    node = K.nodes_by_id(g)[lb_arn("demo-open")]
    assert node["coverage"]["gaps"] == ["elb:targets-unknown"]
    assert K.problems(g) == []


# ── Route 53 (F-057, F-083) ──────────────────────────────────────────────────

def _cand(name, target, kind, claimable, *, private=False, alias=True, rtype="A"):
    return {"Name": name, "Type": rtype, "Target": target, "Kind": kind, "Claimable": claimable,
            "Private": private, "Alias": alias}


@pytest.mark.finding("F-057", "F-083")
def test_takeover_candidates_are_checked_against_collected_buckets_and_load_balancers(tmp_path):
    run = K.Run(tmp_path)
    run.write_json("global", "s3/buckets.json", [K.v2_bucket(run, "static.example.com")], module="s3")
    run.write_json(K.REGION, "elb/resources.json", [{
        "Type": "elb", "Arn": lb_arn("demo-web"), "Name": "demo-web", "Scheme": "internet-facing",
        "LBType": "application", "DNSName": "demo-web-123.eu-west-2.elb.amazonaws.com", "SecurityGroups": [],
        "Listeners": [], "TargetGroups": [], "Targets": []}])
    zone = {"Type": "route53zone", "Id": "Z0EXAMPLEZONE01", "Arn": zone_arn("Z0EXAMPLEZONE01"), "Name": "example.com.",
            "Private": False, "RecordCount": 6, "Records": [], "TakeoverCandidates": [
                _cand("static.example.com.", "s3-website.eu-west-2.amazonaws.com", "s3-website", "likely"),
                _cand("gone.example.com.", "gone.example.com.s3-website-eu-west-2.amazonaws.com", "s3-website",
                      "likely", alias=False, rtype="CNAME"),
                _cand("www.example.com.", "dualstack.demo-web-123.eu-west-2.elb.amazonaws.com", "elb", "unlikely"),
                _cand("old.example.com.", "demo-old-999.eu-west-2.elb.amazonaws.com", "elb", "unlikely"),
                _cand("cdn.example.com.", "d1234abcd.cloudfront.net", "cloudfront", "info"),
                _cand("app.example.com.", "demo-app.herokuapp.com", "heroku", "likely", alias=False, rtype="CNAME")]}
    private = {"Type": "route53zone", "Id": "Z0EXAMPLEZONE02", "Arn": zone_arn("Z0EXAMPLEZONE02"),
               "Name": "corp.internal.", "Private": True, "RecordCount": 1, "Records": [], "TakeoverCandidates": [
                   _cand("files.corp.internal.", "missing-bucket.s3.amazonaws.com", "s3", "likely", private=True,
                         alias=False, rtype="CNAME")]}
    unknown = {"Type": "route53zone", "Id": "Z0EXAMPLEZONE03", "Arn": zone_arn("Z0EXAMPLEZONE03"),
               "Name": "denied.example.", "Private": False, "RecordCount": None, "Records": None,
               "TakeoverCandidates": None}
    run.write_json("global", "route53/resources.json", [zone, private, unknown])
    run.finish()
    g = run.analyze().graph
    found = {f["evidence"]["record"]: f for f in K.findings(g, "ROUTE53-DANGLING-001")}
    assert set(found) == {"gone.example.com.", "old.example.com.", "cdn.example.com.", "app.example.com.",
                          "files.corp.internal."}
    gone = found["gone.example.com."]
    assert gone["severity"] == "MEDIUM" and gone["confidence"] == "definite"
    app = found["app.example.com."]
    assert app["severity"] == "MEDIUM" and app["confidence"] == "conditional"
    assert found["old.example.com."]["severity"] == "INFO" and found["cdn.example.com."]["severity"] == "INFO"
    assert found["files.corp.internal."]["severity"] == "INFO" and found["files.corp.internal."]["evidence"]["private"]
    assert {f["node_id"] for f in found.values()} == {zone_arn("Z0EXAMPLEZONE01"), zone_arn("Z0EXAMPLEZONE02")}
    assert K.nodes_by_id(g)[zone_arn("Z0EXAMPLEZONE03")]["coverage"]["gaps"] == ["route53:records-unknown"]
    assert K.problems(g) == []


@pytest.mark.finding("F-057")
def test_legacy_candidates_are_classified_by_the_engine(tmp_path):
    t = K.Tree(tmp_path)
    t.write()
    t.scope.write("route53/resources.json", [{
        "Type": "route53zone", "Id": "Z0EXAMPLEZONEBBB", "Name": "example.org.", "Private": False, "RecordCount": 2,
        "TakeoverCandidates": [{"Name": "static.example.org.", "Target": "demo-gone.s3.amazonaws.com"},
                               {"Name": "lb.example.org.", "Target": "demo-lb-1.eu-west-2.elb.amazonaws.com"}]}])
    t.scope.write("s3/buckets.json", [rb.s3_bucket(t.scope, "demo-present")])
    g = t.analyze().graph
    found = {f["evidence"]["record"]: f for f in K.findings(g, "ROUTE53-DANGLING-001")}
    assert found["static.example.org."]["evidence"]["kind"] == "s3"
    assert found["static.example.org."]["severity"] == "MEDIUM"
    assert found["lb.example.org."]["severity"] == "INFO"
    assert K.problems(g) == []


def test_edge_services_emit_nothing_for_cognito_pools(tmp_path):
    """Cognito is E-compute's analyzers/cognito.py; the d13c215 block (POOL_* for any configured role) is gone."""
    t = K.Tree(tmp_path)
    t.iam.role("demo-guest", rb.trust({"Federated": "cognito-identity.amazonaws.com"},
                                      "sts:AssumeRoleWithWebIdentity"))
    t.write()
    t.scope.write("cognito/resources.json", [{"Type": "cognito", "Kind": "identity_pool",
                                              "Id": "eu-west-2:6f7a8b9c-aaaa-4bbb-8ccc-0d1e2f3a4b5c",
                                              "Name": "demo_pool", "AuthRole": None,
                                              "UnauthRole": K.iam_arn("role", "demo-guest"), "AllowUnauth": False}])
    out = t.analyze()
    origins = {s.name for s in out.result.analyzer_status}
    assert "edge_services" in origins
    unauth = K.edges(out.graph, "POOL_UNAUTH_ROLE")
    assert unauth == [], "AllowUnauth false: no unauthenticated role edge"


@pytest.mark.finding("F-057")
def test_literal_a_records_are_compared_with_the_addresses_the_account_holds(tmp_path):
    run = K.Run(tmp_path)
    run.write_json(K.REGION, "ec2/instances.json", [rb.ec2_instance("i-0a1b2c3d4e5f6c001", account=K.ACCT,
                                                                    region=K.REGION, public_ip="203.0.113.10")])
    run.write_json(K.REGION, "ec2/elastic_ips.json", [{"PublicIp": "198.51.100.5",
                                                       "AllocationId": "eipalloc-0a1b2c3d4e5f60001"}], module="ec2")
    records = [{"Name": "a.example.com.", "Type": "A", "AliasTarget": None, "Values": ["203.0.113.10"]},
               {"Name": "b.example.com.", "Type": "A", "AliasTarget": None, "Values": ["198.51.100.5"]},
               {"Name": "c.example.com.", "Type": "A", "AliasTarget": None, "Values": ["192.0.2.77"]}]
    run.write_json("global", "route53/resources.json", [{
        "Type": "route53zone", "Id": "Z0EXAMPLEZONE09", "Arn": zone_arn("Z0EXAMPLEZONE09"), "Name": "example.com.",
        "Private": False, "RecordCount": 3, "Records": records, "TakeoverCandidates": []}])
    run.finish()
    g = run.analyze().graph
    props = K.nodes_by_id(g)[zone_arn("Z0EXAMPLEZONE09")]["props"]
    assert props["address_values"] == 3 and props["address_values_owned"] == 2
    assert K.findings(g, "ROUTE53-DANGLING-001") == []          # an address held elsewhere is not a takeover claim
