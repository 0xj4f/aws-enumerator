"""Regression tests owned by stream E-net (S3, EC2, edge services, posture analyzers and their loaders).

xfail-first (see test_e_policy.py). Legacy relationship files keep their edge names for one release
(edge_types.py ``legacy_name``), so the symptom tests read them; targets are matched by name or ARN
suffix (``support.refers``) so the legacy ``i-...`` / ``bucket:<name>`` renderings and ARN node ids both match.
"""

from __future__ import annotations

import collections
import json
from pathlib import Path

import pytest

from tests.fixtures.regressions import support as S
from tests.support import report_builder as rb

ACCT, R, R1 = S.ACCT, S.REGION, S.OTHER_REGION
EC2_TRUST = rb.trust({"Service": "ec2.amazonaws.com"})


def _tree(root: Path, region: str = R):
    s = rb.Scope(root, ACCT, region)
    return s, rb.Iam(ACCT)


def _finish(s):
    rb.write_manifest(s.path, account=ACCT, mode="single_region", region=s.name)
    return s.path


# ── F-003: one statement reaches every matching instance ─────────────────────
@pytest.mark.finding("F-003")
def test_f003_ssm_start_session_on_star_reaches_every_instance(tmp_path):
    S.build_scenario("single_region_minimal", tmp_path)          # alice: ssm:StartSession on *, 3 instances
    analysis = S.analyze_tree(tmp_path / "111122223333" / R)
    alice = "arn:aws:iam::111122223333:user/alice"
    reached = {iid for iid in (f"i-0a1b2c3d4e5f6000{n}" for n in range(3))
               if S.edges_from(analysis.edges("ec2"), alice, iid, types=["CAN_CONNECT"])}
    assert reached == {f"i-0a1b2c3d4e5f6000{n}" for n in range(3)}


@pytest.mark.finding("F-003")
def test_f003_statement_with_several_instance_arns_reaches_each_of_them(tmp_path):
    s, iam = _tree(tmp_path)
    ids = [f"i-0a1b2c3d4e5f6100{n}" for n in range(4)]
    iam.role("demo-ops", EC2_TRUST, inline={"p": [rb.allow(
        "ssm:StartSession", [f"arn:aws:ec2:{R}:{ACCT}:instance/{i}" for i in ids[2:]])]})
    iam.write(s)
    s.write("ec2/instances.json", [rb.ec2_instance(i, account=ACCT, region=R) for i in ids])
    analysis = S.analyze_tree(_finish(s))
    role = S.iam_arn("role", "demo-ops")
    reached = {i for i in ids if S.edges_from(analysis.edges("ec2"), role, i, types=["CAN_CONNECT"])}
    assert reached == set(ids[2:])


# ── F-022: IAM -> bucket edges are merged per (source, type, target) ─────────
@pytest.mark.finding("F-022")
def test_f022_s3_edges_are_merged_per_principal_type_and_bucket(tmp_path):
    s, iam = _tree(tmp_path)
    iam.role("demo-reader", EC2_TRUST, inline={"p": [rb.allow("s3:GetObject", "*"), rb.allow("s3:ListBucket", "*")]})
    iam.write(s)
    s.write("s3/buckets.json", [rb.s3_bucket(s, f"demo-bucket-{i}") for i in range(4)])
    analysis = S.analyze_tree(_finish(s))
    edges = S.edges_from(analysis.edges("s3"), S.iam_arn("role", "demo-reader"))
    triples = collections.Counter((e.get("source"), e.get("type"), e.get("target")) for e in edges)
    assert [t for t, n in triples.items() if n > 1] == []
    assert len(edges) == 4 and {e.get("type") for e in edges} == {"CAN_READ"}


# ── F-025 (EC2 loader): no sibling-region bleed in single-region analysis ────
def build_sibling_regions(root: Path) -> None:
    """eu-west-1 has an instance; eu-west-2 (same account, same day) has none."""
    for region, with_instance in ((R1, True), (R, False)):
        s, iam = _tree(root, region)
        iam.role("demo-app", EC2_TRUST)
        prof = iam.instance_profile("demo-app", ["demo-app"])
        iam.write(s)
        rb.write_empty_regional(s)
        if with_instance:
            s.write("ec2/instances.json", [rb.ec2_instance("i-0a1b2c3d4e5f6abcd", account=ACCT, region=region,
                                                           profile=prof, http_tokens="optional")])
        _finish(s)


@pytest.mark.finding("F-025", "F-063")
def test_f025_empty_region_does_not_import_a_sibling_regions_instances(tmp_path):
    build_sibling_regions(tmp_path)
    own = S.analyze_tree(tmp_path / ACCT / R1)       # positive control: the instance's own region sees it
    assert S.mentions(own, "i-0a1b2c3d4e5f6abcd")
    empty = S.analyze_tree(tmp_path / ACCT / R)
    assert S.mentions(empty, "i-0a1b2c3d4e5f6abcd") == []


# ── F-075: EC2 resource matching parses the ARN ──────────────────────────────
@pytest.mark.finding("F-075")
def test_f075_ec2_actions_match_instances_only_through_instance_arns(tmp_path):
    s, iam = _tree(tmp_path)
    iid = "i-0a1b2c3d4e5f6abc1"
    iam.role("demo-s3-only", EC2_TRUST, inline={"p": [rb.allow("ec2:TerminateInstances",
                                                               "arn:aws:s3:::ec2-backups/*")]})
    iam.role("demo-iam-ec2", EC2_TRUST, inline={"p": [rb.allow("ec2:TerminateInstances",
                                                               f"arn:aws:iam::{ACCT}:role/ec2-*")]})
    iam.role("demo-sg-only", EC2_TRUST, inline={"p": [rb.allow("ec2:TerminateInstances",
                                                               f"arn:aws:ec2:{R}:{ACCT}:security-group/*")]})
    iam.role("demo-other-region", EC2_TRUST, inline={"p": [rb.allow("ec2:StopInstances",
                                                                    f"arn:aws:ec2:{R1}:{ACCT}:instance/*")]})
    iam.role("demo-exact", EC2_TRUST, inline={"p": [rb.allow("ec2:TerminateInstances",
                                                             f"arn:aws:ec2:{R}:{ACCT}:instance/{iid}")]})
    iam.write(s)
    s.write("ec2/instances.json", [rb.ec2_instance(iid, account=ACCT, region=R)])
    edges = S.analyze_tree(_finish(s)).edges("ec2")
    assert S.edges_from(edges, S.iam_arn("role", "demo-exact"), iid)       # positive control
    wrong = {name: [e.get("type") for e in S.edges_from(edges, S.iam_arn("role", name), iid)]
             for name in ("demo-s3-only", "demo-iam-ec2", "demo-sg-only", "demo-other-region")}
    assert {k: v for k, v in wrong.items() if v} == {}


# ── F-077, F-078, F-106: network and IMDS exposure ───────────────────────────
VPC, IGW = "vpc-0a1b2c3d4e5f6aaaa", "igw-0a1b2c3d4e5f6c01"
PUB, PRIV = "subnet-0a1b2c3d4e5f6b001", "subnet-0a1b2c3d4e5f6b002"


def build_network_tree(root: Path) -> Path:
    s, iam = _tree(root)
    iam.write(s)
    rb.write_empty_regional(s, skip={"vpc", "ec2"})
    rb.vpc_network(s, vpc=VPC, public_subnet=PUB, private_subnet=PRIV, igw=IGW)
    tables = json.loads((s.path / "vpc" / "route_tables.json").read_text())
    tables[1]["Routes"][1] = {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": IGW, "State": "active"}  # main -> IGW
    tables.append({"RouteTableId": "rtb-0a1b2c3d4e5f6d01", "VpcId": VPC, "OwnerId": ACCT,
                   "Associations": [{"Main": False, "RouteTableAssociationId": "rtbassoc-0a1b2c3d4e5f6e01",
                                     "RouteTableId": "rtb-0a1b2c3d4e5f6d01", "SubnetId": PRIV}],
                   "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local", "State": "active"}]})
    s.write("vpc/route_tables.json", tables)
    disabled = rb.ec2_instance("i-0a1b2c3d4e5f60f04", account=ACCT, region=R, http_tokens="optional", subnet=PRIV,
                               vpc=VPC)
    disabled["MetadataOptions"]["HttpEndpoint"] = "disabled"
    s.write("ec2/instances.json", [
        rb.ec2_instance("i-0a1b2c3d4e5f60f01", account=ACCT, region=R, public_ip="203.0.113.10", subnet=PUB, vpc=VPC,
                        http_tokens="optional"),
        rb.ec2_instance("i-0a1b2c3d4e5f60f02", account=ACCT, region=R, public_ip="203.0.113.11", subnet=PRIV,
                        vpc=VPC),
        rb.ec2_instance("i-0a1b2c3d4e5f60f03", account=ACCT, region=R, http_tokens="optional", subnet=PRIV, vpc=VPC,
                        state="terminated"),
        disabled,
    ])
    return _finish(s)


def _flagged(analysis, fid):
    return {iid for iid in ("i-0a1b2c3d4e5f60f01", "i-0a1b2c3d4e5f60f02", "i-0a1b2c3d4e5f60f03",
                            "i-0a1b2c3d4e5f60f04")
            if S.findings_for(analysis.findings(), fid, iid)}


@pytest.mark.finding("F-077")
def test_f077_explicit_private_route_table_overrides_the_main_table(tmp_path):
    analysis = S.analyze_tree(build_network_tree(tmp_path))
    assert _flagged(analysis, "EC2-INET-001") == {"i-0a1b2c3d4e5f60f01"}


@pytest.mark.finding("F-078")
def test_f078_terminated_instances_are_not_imds_findings(tmp_path):
    flagged = _flagged(S.analyze_tree(build_network_tree(tmp_path)), "EC2-IMDS-001")
    assert "i-0a1b2c3d4e5f60f01" in flagged                      # running, IMDSv1: still a finding
    assert "i-0a1b2c3d4e5f60f03" not in flagged


@pytest.mark.finding("F-106")
def test_f106_imds_disabled_instances_are_not_imds_findings(tmp_path):
    flagged = _flagged(S.analyze_tree(build_network_tree(tmp_path)), "EC2-IMDS-001")
    assert "i-0a1b2c3d4e5f60f01" in flagged
    assert "i-0a1b2c3d4e5f60f04" not in flagged


@pytest.mark.finding("F-106")
def test_f106_no_ssrf_edge_into_an_instance_with_imds_disabled(tmp_path):
    """Two identical internet-facing IMDSv1 instances with a role; only the one with IMDS enabled is an
    SSRF -> IMDS -> role entry point."""
    s, iam = _tree(tmp_path)
    iam.role("demo-web-role", EC2_TRUST)
    prof = iam.instance_profile("demo-web-profile", ["demo-web-role"])
    iam.write(s)
    rb.write_empty_regional(s, skip={"vpc", "sg", "ec2"})
    rb.vpc_network(s, vpc=VPC, public_subnet=PUB, private_subnet=PRIV, igw=IGW)
    s.write("sg/security_groups.json", [rb.security_group(
        "sg-0a1b2c3d4e5f60e01", "demo-web", vpc=VPC, inbound=[rb.sg_rule("tcp", 80, cidrs=["0.0.0.0/0"])],
        attached_instances=["i-0a1b2c3d4e5f60e01", "i-0a1b2c3d4e5f60e02"])])
    instances = [rb.ec2_instance(iid, account=ACCT, region=R, profile=prof, http_tokens="optional",
                                 public_ip=ip, subnet=PUB, vpc=VPC,
                                 sgs=[{"GroupId": "sg-0a1b2c3d4e5f60e01", "GroupName": "demo-web"}])
                 for iid, ip in (("i-0a1b2c3d4e5f60e01", "203.0.113.21"), ("i-0a1b2c3d4e5f60e02", "203.0.113.22"))]
    instances[1]["MetadataOptions"]["HttpEndpoint"] = "disabled"
    s.write("ec2/instances.json", instances)
    graph = S.analyze_graph(_finish(s))
    enabled, disabled = (f"arn:aws:ec2:{R}:{ACCT}:instance/{i}" for i in ("i-0a1b2c3d4e5f60e01", "i-0a1b2c3d4e5f60e02"))
    assert S.graph_edges(graph, edge_type="SSRF_TO_IMDS", target=enabled)         # positive control
    assert disabled in S.nodes_by_id(graph)
    assert S.graph_edges(graph, edge_type="SSRF_TO_IMDS", target=disabled) == []


# ── F-138 (engine side): bucket regions are normalised ───────────────────────
@pytest.mark.finding("F-138")
def test_f138_legacy_eu_bucket_region_is_normalised_in_the_graph(tmp_path):
    s, iam = _tree(tmp_path)
    iam.write(s)
    s.write("s3/buckets.json", [rb.s3_bucket(s, "demo-legacy-eu-bucket", region="EU"),
                                rb.s3_bucket(s, "demo-us-bucket", region="us-east-1")])
    nodes = S.nodes_by_id(S.analyze_graph(_finish(s)))
    assert nodes["arn:aws:s3:::demo-legacy-eu-bucket"]["region"] == "eu-west-1"
    assert nodes["arn:aws:s3:::demo-us-bucket"]["region"] == "us-east-1"
