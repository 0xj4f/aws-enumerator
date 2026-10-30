"""Posture analyzer (engine/analyzers/posture.py): CloudTrail coverage per region (shadow and organization trails,
IsLogging, event selectors), VPC flow logs, WAF coverage, GuardDuty / Config / Security Hub / Access Analyzer —
findings only, unknown never reads as "off" (F-045, F-046, F-047)."""

from __future__ import annotations

import importlib

import pytest

K = importlib.import_module("tests.fixtures.e-net.kit")
rb = K.rb

W1, W2 = "eu-west-1", "eu-west-2"
MGMT = rb.ACCT_ALT                                       # the organization's management account


def trail_arn(name: str, region: str = W2, account: str = K.ACCT) -> str:
    return f"arn:aws:cloudtrail:{region}:{account}:trail/{name}"


def trail(name: str, home: str, *, multi: bool = True, logging=True, rw: str = "All", data: bool = False,
          shadow: bool = False, account: str = K.ACCT, org: bool = False, details: bool = True):
    rec = {"Name": name, "TrailARN": trail_arn(name, home, account), "HomeRegion": home, "IsShadow": shadow,
           "IsMultiRegionTrail": multi, "IsOrganizationTrail": org, "OwnerAccountId": account,
           "S3BucketName": "demo-trail-logs", "LogFileValidationEnabled": True, "HasCustomEventSelectors": True,
           "HasInsightSelectors": False, "Status": None, "EventSelectors": None, "AdvancedEventSelectors": None,
           "InsightSelectors": None}
    if details:
        rec["Status"] = {"IsLogging": logging}
        resources = [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}] if data else []
        rec["EventSelectors"] = [{"ReadWriteType": rw, "IncludeManagementEvents": True, "DataResources": resources}]
        rec["AdvancedEventSelectors"] = []
    return rec


def run_with(tmp_path, regions=(W1, W2)):
    return K.Run(tmp_path, regions=regions)


def region_node(region: str) -> str:
    return f"aws-enumerator:region/{K.ACCT}/{region}"


# ── CloudTrail (F-045, F-046, F-047) ─────────────────────────────────────────

@pytest.mark.finding("F-045", "F-046")
def test_a_multi_region_trail_covers_every_analysed_region(tmp_path):
    run = run_with(tmp_path)
    home = trail("demo-main", W2, data=True)
    run.write_json(W2, "cloudtrail/trails.json", [home])
    run.write_json(W1, "cloudtrail/trails.json", [trail("demo-main", W2, shadow=True, details=False)])
    run.finish()
    g = run.analyze().graph
    assert K.findings(g, "CLOUDTRAIL-001") == [] and K.findings(g, "CLOUDTRAIL-004") == []
    node = K.nodes_by_id(g)[trail_arn("demo-main")]
    assert node["type"] == "trail" and node["props"]["is_logging"] is True
    assert node["props"]["management_events"] == "all" and node["props"]["data_events"] is True
    assert K.problems(g) == []


@pytest.mark.finding("F-045")
def test_an_organization_trail_of_the_management_account_is_unverified_not_missing(tmp_path):
    run = run_with(tmp_path, regions=(W2,))
    org = trail("demo-org", "us-east-1", shadow=True, account=MGMT, org=True, details=False)
    run.write_json(W2, "cloudtrail/trails.json", [org])
    run.finish()
    g = run.analyze().graph
    [f] = K.findings(g, "CLOUDTRAIL-001", region_node(W2))
    assert f["severity"] == "INFO" and f["confidence"] == "conditional"
    assert f["evidence"]["unverified"] == [trail_arn("demo-org", "us-east-1", MGMT)]
    assert K.nodes_by_id(g)[trail_arn("demo-org", "us-east-1", MGMT)]["account"] == MGMT
    assert K.problems(g) == []


@pytest.mark.finding("F-046", "F-047")
def test_stopped_and_write_only_trails_and_uncovered_regions(tmp_path):
    run = run_with(tmp_path)
    run.write_json(W2, "cloudtrail/trails.json", [trail("demo-stopped", W2, multi=False, logging=False),
                                                  trail("demo-writes", W2, multi=False, rw="WriteOnly")])
    run.write_json(W1, "cloudtrail/trails.json", [])
    run.finish()
    g = run.analyze().graph
    assert K.findings(g, "CLOUDTRAIL-002", trail_arn("demo-stopped"))[0]["severity"] == "HIGH"
    assert K.findings(g, "CLOUDTRAIL-003", trail_arn("demo-writes"))
    [w1] = K.findings(g, "CLOUDTRAIL-001", region_node(W1))                # nothing covers eu-west-1
    assert w1["severity"] == "HIGH" and w1["confidence"] == "definite"
    assert K.findings(g, "CLOUDTRAIL-001", region_node(W2)) == []         # the write-only trail still logs
    assert K.findings(g, "CLOUDTRAIL-004")                                 # no data events anywhere
    assert K.problems(g) == []


@pytest.mark.finding("F-059")
def test_a_denied_trail_listing_is_no_finding(tmp_path):
    run = run_with(tmp_path, regions=(W2,))
    run.write_json(W2, "cloudtrail/trails.json", [], calls=[
        {"api": "cloudtrail:DescribeTrails", "status": "denied", "primary": True}])
    run.finish()
    g = run.analyze().graph
    assert K.findings(g, "CLOUDTRAIL-001") == []


@pytest.mark.finding("F-045", "F-047")
def test_old_reports_get_conditional_cloudtrail_findings(tmp_path):
    t = K.Tree(tmp_path)
    t.write(skip={"cloudtrail"})
    t.scope.write("cloudtrail/trails.json", [])
    g = t.analyze().graph
    [f] = K.findings(g, "CLOUDTRAIL-001", region_node(K.REGION))
    assert f["confidence"] == "conditional" and f["severity"] == "MEDIUM" and "old report" in f["description"]
    t.scope.write("cloudtrail/trails.json", [{"Name": "demo-trail", "TrailARN": trail_arn("demo-trail"),
                                              "HomeRegion": K.REGION, "IsMultiRegionTrail": True,
                                              "Error": "Parameter validation failed"}])
    g = t.analyze().graph
    [f] = K.findings(g, "CLOUDTRAIL-001", region_node(K.REGION))
    assert f["severity"] == "INFO" and K.findings(g, "CLOUDTRAIL-002") == []


# ── flow logs, WAF, detection services (F-046) ───────────────────────────────

@pytest.mark.finding("F-046")
def test_vpcs_without_flow_logs(tmp_path):
    run = run_with(tmp_path, regions=(W2,))
    s = run.unit(W2)
    vpcs = [{"VpcId": "vpc-0a1b2c3d4e5f60001", "CidrBlock": "10.0.0.0/16", "IsDefault": False},
            {"VpcId": "vpc-0a1b2c3d4e5f60002", "CidrBlock": "10.1.0.0/16", "IsDefault": False},
            {"VpcId": "vpc-0a1b2c3d4e5f60003", "CidrBlock": "172.31.0.0/16", "IsDefault": True},
            {"VpcId": "vpc-0a1b2c3d4e5f60004", "CidrBlock": "10.2.0.0/16", "IsDefault": False}]
    s.write("vpc/vpcs.json", vpcs)
    run.write_json(W2, "vpc/subnets.json", [{"SubnetId": "subnet-0a1b2c3d4e5f60004",
                                             "VpcId": "vpc-0a1b2c3d4e5f60004"}])
    run.write_json(W2, "flowlogs/flowlogs.json", [
        {"FlowLogId": "fl-0a1b2c3d4e5f60001", "ResourceId": "vpc-0a1b2c3d4e5f60001", "FlowLogStatus": "ACTIVE"},
        {"FlowLogId": "fl-0a1b2c3d4e5f60004", "ResourceId": "subnet-0a1b2c3d4e5f60004", "FlowLogStatus": "ACTIVE"}])
    run.write_json(W2, "ec2/instances.json", [rb.ec2_instance("i-0a1b2c3d4e5f6c001", account=K.ACCT, region=W2,
                                                              vpc="vpc-0a1b2c3d4e5f60002")])
    run.finish()
    g = run.analyze().graph
    sev = {f["node_id"].rsplit("/", 1)[-1]: f["severity"] for f in K.findings(g, "FLOWLOGS-001")}
    assert sev == {"vpc-0a1b2c3d4e5f60002": "MEDIUM", "vpc-0a1b2c3d4e5f60003": "INFO"}
    assert K.problems(g) == []


@pytest.mark.finding("F-046")
def test_waf_coverage_of_load_balancers_rest_apis_and_cloudfront(tmp_path):
    run = run_with(tmp_path, regions=(W2,))
    alb = f"arn:aws:elasticloadbalancing:{W2}:{K.ACCT}:loadbalancer/app/demo-alb/0a1b2c3d4e5f6a7b"
    alb2 = f"arn:aws:elasticloadbalancing:{W2}:{K.ACCT}:loadbalancer/app/demo-alb2/0a1b2c3d4e5f6a7c"
    common = {"Type": "elb", "Scheme": "internet-facing", "LBType": "application", "SecurityGroups": [],
              "Listeners": [], "TargetGroups": [], "Targets": []}
    run.write_json(W2, "elb/resources.json", [{**common, "Arn": alb, "Name": "demo-alb"},
                                              {**common, "Arn": alb2, "Name": "demo-alb2"}])
    run.write_json(W2, "waf/web_acls.json", [{"Name": "demo-acl", "ARN": f"arn:aws:wafv2:{W2}:{K.ACCT}:regional/"
                                              "webacl/demo-acl/1", "AssociatedResources": [
                                                  {"ResourceType": "APPLICATION_LOAD_BALANCER", "Arn": alb2}],
                                              "UncheckedResourceTypes": []}])
    api = f"arn:aws:apigateway:{W2}::/restapis/a1b2c3d4e5"
    run.write_json(W2, "apigateway/resources.json", [
        {"Type": "apigw", "Arn": api, "Name": "demo-api", "Protocol": "REST", "EndpointTypes": ["REGIONAL"],
         "Stages": [{"StageName": "prod", "WebAclArn": None}, {"StageName": "dev", "WebAclArn": "arn:aws:wafv2:x"}]},
        {"Type": "apigw", "Arn": f"arn:aws:apigateway:{W2}::/restapis/f6g7h8i9j0", "Name": "demo-private",
         "Protocol": "REST", "EndpointTypes": ["PRIVATE"], "Stages": [{"StageName": "prod", "WebAclArn": None}]},
        {"Type": "apigw", "Arn": f"arn:aws:apigateway:{W2}::/apis/k1l2m3n4o5", "Name": "demo-http",
         "Protocol": "HTTP", "EndpointTypes": None, "Stages": [{"StageName": "$default", "WebAclArn": None}]}])
    dist = f"arn:aws:cloudfront::{K.ACCT}:distribution/E1A2B3C4D5E6F7"
    run.write_json("global", "cloudfront/distributions.json", [
        {"Id": "E1A2B3C4D5E6F7", "ARN": dist, "DomainName": "d1a2b3c4.cloudfront.net", "Enabled": True,
         "WebACLId": ""}])
    run.finish()
    g = run.analyze().graph
    waf = {f["node_id"] for f in K.findings(g, "WAF-001")}
    assert waf == {alb, api, dist}
    [api_f] = K.findings(g, "WAF-001", api)
    assert api_f["evidence"]["stages"] == ["prod"]
    [edge] = K.edges(g, "PUBLIC_INBOUND", K.ANON, dist)
    assert edge["traversable"] is False
    assert K.problems(g) == []


@pytest.mark.finding("F-046", "F-059")
def test_detection_services_off_and_unknown(tmp_path):
    run = run_with(tmp_path)
    run.write_json(W2, "guardduty/detectors.json", [])
    run.write_json(W1, "guardduty/detectors.json", [{"DetectorId": "d1", "Status": "ENABLED"}])
    run.write_json(W2, "config/recorders.json", [{"name": "default", "status": {"recording": False}}])
    run.write_json(W1, "config/recorders.json", [{"name": "default", "status": None}])
    run.write_json(W2, "securityhub/hub.json", {"Enabled": False, "Standards": []})
    run.write_json(W1, "securityhub/hub.json", {"Enabled": None, "Standards": None})
    run.write_json(W2, "accessanalyzer/analyzers.json", [{"name": "unused", "type": "ACCOUNT_UNUSED_ACCESS",
                                                          "status": "ACTIVE"}])
    run.write_json(W1, "accessanalyzer/analyzers.json", [], calls=[
        {"api": "accessanalyzer:ListAnalyzers", "status": "denied", "primary": True}])
    run.finish()
    g = run.analyze().graph
    by_region = {}
    for fid in ("GUARDDUTY-001", "CONFIG-001", "SECURITYHUB-001", "ACCESSANALYZER-001"):
        for f in K.findings(g, fid):
            by_region.setdefault(f["node_id"], set()).add(fid)
    assert by_region == {region_node(W2): {"GUARDDUTY-001", "CONFIG-001", "SECURITYHUB-001", "ACCESSANALYZER-001"}}
    assert not [e for e in g["edges"] if e["source"].startswith("aws-enumerator:region/")]
    assert K.problems(g) == []
