"""EC2 analyzer (engine/analyzers/ec2.py): control edges through the evaluator, network exposure (effective routes,
NACLs, CIDR coverage, IPv6 / EIP / ENI addresses), IMDS, launch templates, AMIs (engine.md §5 "S3 and EC2")."""

from __future__ import annotations

import importlib

import pytest

K = importlib.import_module("tests.fixtures.e-net.kit")
rb = K.rb

IID = "i-0a1b2c3d4e5f6c001"
IID2 = "i-0a1b2c3d4e5f6c002"
SG = "sg-0a1b2c3d4e5f6d001"
SG2 = "sg-0a1b2c3d4e5f6d002"
WEB_SGS = [{"GroupId": SG, "GroupName": "demo-web"}]
#: The default NACL of a dual-stack VPC (an IPv4-only NACL denies all IPv6 traffic).
ALLOW_ALL_V4_V6 = [
    {"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow", "Egress": False, "CidrBlock": "0.0.0.0/0"},
    {"RuleNumber": 101, "Protocol": "-1", "RuleAction": "allow", "Egress": False, "Ipv6CidrBlock": "::/0"}]


def _net_tree(tmp_path, *, inbound, instances, nacl_entries=None, extra_routes=(), main_igw=False):
    """A VPC with a public (IGW-routed, explicit) and a private subnet, one security group and ``instances``."""
    t = K.Tree(tmp_path)
    t.iam.role("demo-web-role", K.EC2_TRUST)
    t.prof = t.iam.instance_profile("demo-web-profile", ["demo-web-role"])
    t.write(skip={"vpc", "sg", "ec2"})
    rb.vpc_network(t.scope, vpc=K.VPC, public_subnet=K.PUB, private_subnet=K.PRIV, igw=K.IGW)
    import json
    tables = json.loads((t.path / "vpc" / "route_tables.json").read_text())
    tables[0]["Routes"].extend(extra_routes)
    if main_igw:
        tables[1]["Routes"][1] = {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": K.IGW, "State": "active"}
    t.scope.write("vpc/route_tables.json", tables)
    if nacl_entries is not None:
        t.scope.write("vpc/nacls.json", [{"NetworkAclId": "acl-0a1b2c3d4e5f6e001", "VpcId": K.VPC,
                                          "IsDefault": True, "Entries": nacl_entries}])
    t.scope.write("sg/security_groups.json", [rb.security_group(SG, "demo-web", vpc=K.VPC, inbound=inbound)])
    t.scope.write("ec2/instances.json", [i(t) if callable(i) else i for i in instances])
    return t


def _inst(iid=IID, **kw):
    kw.setdefault("subnet", K.PUB)
    kw.setdefault("vpc", K.VPC)
    kw.setdefault("sgs", WEB_SGS)

    def make(t):
        prof = kw.pop("profile", None)
        return rb.ec2_instance(iid, account=K.ACCT, region=K.REGION,
                               profile=t.prof if prof == "web" else prof, **kw)
    return make


# ── control edges (F-003, F-004, F-075, F-001, F-014) ────────────────────────

@pytest.mark.finding("F-004")
def test_ec2_edge_types_split_control_from_impact(tmp_path):
    t = K.Tree(tmp_path)
    chain = ["ec2:ModifyInstanceAttribute", "ec2:StopInstances", "ec2:StartInstances"]
    t.iam.role("demo-full", K.EC2_TRUST, inline={"p": [rb.allow("ec2:*", "*")]})
    t.iam.role("demo-userdata", K.EC2_TRUST, inline={"p": [rb.allow(chain, "*")]})
    t.iam.role("demo-reboot", K.EC2_TRUST, inline={"p": [rb.allow(["ec2:RebootInstances", "ec2:StopInstances"], "*")]})
    t.iam.role("demo-terminate", K.EC2_TRUST, inline={"p": [rb.allow("ec2:TerminateInstances", "*")]})
    t.iam.role("demo-launch", K.EC2_TRUST, inline={"p": [rb.allow("ec2:RunInstances", "*")]})
    t.iam.role("demo-sg-admin", K.EC2_TRUST, inline={"p": [rb.allow("ec2:AuthorizeSecurityGroupIngress", "*")]})
    t.write(skip={"ec2", "sg"})
    t.scope.write("sg/security_groups.json", [rb.security_group(SG, "demo-web", vpc=K.VPC)])
    t.scope.write("ec2/instances.json", [rb.ec2_instance(IID, account=K.ACCT, region=K.REGION, sgs=WEB_SGS)])
    g = t.analyze().graph
    inst = K.instance(IID)
    by_role = {name: K.types_between(g, K.iam_arn("role", name), inst) for name in
               ("demo-full", "demo-userdata", "demo-reboot", "demo-terminate", "demo-launch")}
    assert by_role == {"demo-full": ["EC2_FULL_ACCESS"], "demo-userdata": ["CAN_MODIFY_USERDATA"],
                       "demo-reboot": ["CAN_MANAGE"], "demo-terminate": ["CAN_TERMINATE"], "demo-launch": []}
    trav = {e["type"]: e["traversable"] for e in K.edges(g, target=inst) if e["source"].startswith("arn:aws:iam")}
    assert trav == {"EC2_FULL_ACCESS": True, "CAN_MODIFY_USERDATA": True, "CAN_MANAGE": False, "CAN_TERMINATE": False}
    assert K.types_between(g, K.iam_arn("role", "demo-sg-admin"), K.sg_arn(SG)) == ["CAN_ADMIN_SG"]
    assert K.types_between(g, K.iam_arn("role", "demo-sg-admin"), inst) == []
    assert not [e for e in g["edges"] if e["type"] == "CAN_LAUNCH"]
    assert K.problems(g) == []


@pytest.mark.finding("F-003", "F-075")
def test_every_matching_instance_gets_an_edge_and_arns_are_matched_exactly(tmp_path):
    t = K.Tree(tmp_path)
    ids = [f"i-0a1b2c3d4e5f6c10{n}" for n in range(5)]
    t.iam.role("demo-ssm", K.EC2_TRUST, inline={"p": [rb.allow("ssm:StartSession", "*")]})
    t.iam.role("demo-prefix", K.EC2_TRUST, inline={"p": [rb.allow(
        "ec2:TerminateInstances", f"arn:aws:ec2:{K.REGION}:{K.ACCT}:instance/i-0a1b2c3d4e5f6c10[01]")]})
    t.iam.role("demo-other-account", K.EC2_TRUST, inline={"p": [rb.allow(
        "ec2:TerminateInstances", f"arn:aws:ec2:{K.REGION}:{K.FOREIGN}:instance/*")]})
    t.iam.role("demo-volume", K.EC2_TRUST, inline={"p": [rb.allow(
        "ec2:TerminateInstances", f"arn:aws:ec2:{K.REGION}:{K.ACCT}:volume/*")]})
    t.write(skip={"ec2"})
    t.scope.write("ec2/instances.json", [rb.ec2_instance(i, account=K.ACCT, region=K.REGION) for i in ids])
    out = t.analyze()
    g = out.graph
    assert {e["target"] for e in K.edges(g, "CAN_CONNECT", K.iam_arn("role", "demo-ssm"))} == {
        K.instance(i) for i in ids}
    # IAM globs: [ and ] are literal, so the "prefix" pattern matches no instance
    for name in ("demo-prefix", "demo-other-account", "demo-volume"):
        assert K.edges(g, source=K.iam_arn("role", name)) == [] or all(
            not e["target"].startswith("arn:aws:ec2:") for e in K.edges(g, source=K.iam_arn("role", name))), name
    legacy = out.legacy("ec2_relationships.json")["edges"]
    assert sorted(e["target"] for e in legacy if e["source"] == K.iam_arn("role", "demo-ssm")) == sorted(ids)
    assert K.problems(g) == []


@pytest.mark.finding("F-001", "F-014")
def test_notaction_deny_and_conditions_decide_instance_control(tmp_path):
    t = K.Tree(tmp_path)
    t.iam.role("demo-poweruser", K.EC2_TRUST, inline={"p": [{"Effect": "Allow", "NotAction": "iam:*",
                                                             "Resource": "*"}]})
    t.iam.role("demo-quarantined", K.EC2_TRUST, inline={"p": [rb.allow("*", "*"), rb.deny("*", "*")]})
    mfa = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    t.iam.role("demo-mfa-ssm", K.EC2_TRUST, inline={"p": [rb.allow("ssm:StartSession", "*", cond=mfa)]})
    t.write(skip={"ec2"})
    t.scope.write("ec2/instances.json", [rb.ec2_instance(IID, account=K.ACCT, region=K.REGION)])
    g = t.analyze().graph
    inst = K.instance(IID)
    assert K.types_between(g, K.iam_arn("role", "demo-poweruser"), inst) == ["CAN_CONNECT", "EC2_FULL_ACCESS"]
    assert K.types_between(g, K.iam_arn("role", "demo-quarantined"), inst) == []
    [cond] = K.edges(g, "CAN_CONNECT", K.iam_arn("role", "demo-mfa-ssm"), inst)
    assert cond["confidence"] == "conditional"
    assert K.problems(g) == []


def test_ssm_connect_is_conditional_on_an_unmanaged_instance(tmp_path):
    run = K.Run(tmp_path)
    run.iam.role("demo-ssm", K.EC2_TRUST, inline={"p": [rb.allow("ssm:StartSession", "*")]})
    run.write_json(K.REGION, "ec2/instances.json", [rb.ec2_instance(IID, account=K.ACCT, region=K.REGION),
                                                    rb.ec2_instance(IID2, account=K.ACCT, region=K.REGION)])
    run.write_json(K.REGION, "ssm/managed_instances.json", [{"InstanceId": IID, "PingStatus": "Online"}])
    run.finish()
    g = run.analyze().graph
    role = K.iam_arn("role", "demo-ssm")
    [managed] = K.edges(g, "CAN_CONNECT", role, K.instance(IID))
    [unmanaged] = K.edges(g, "CAN_CONNECT", role, K.instance(IID2))
    assert managed["confidence"] == "definite" and unmanaged["confidence"] == "conditional"
    assert "ssm:instance-not-managed" in unmanaged["evidence"]["gaps"]
    assert K.problems(g) == []


# ── instance role (bridge) ───────────────────────────────────────────────────

def test_instance_role_by_exact_profile_arn_and_unresolved_profiles(tmp_path):
    t = K.Tree(tmp_path)
    t.iam.role("demo-node-role", K.EC2_TRUST)
    t.iam.role("demo-node-profile", K.EC2_TRUST)                  # same NAME as the profile, different role
    prof = t.iam.instance_profile("demo-node-profile", ["demo-node-role"])
    t.write(skip={"ec2"})
    t.scope.write("ec2/instances.json", [
        rb.ec2_instance(IID, account=K.ACCT, region=K.REGION, profile=prof),
        rb.ec2_instance(IID2, account=K.ACCT, region=K.REGION,
                        profile=f"arn:aws:iam::{K.ACCT}:instance-profile/demo-deleted")])
    g = t.analyze().graph
    assert K.types_between(g, K.instance(IID), K.iam_arn("role", "demo-node-role")) == ["INSTANCE_ROLE"]
    assert K.types_between(g, K.instance(IID), K.iam_arn("role", "demo-node-profile")) == []
    [f] = K.findings(g, "EC2-PROFILE-001", K.instance(IID2))
    assert f["severity"] == "MEDIUM"
    assert K.problems(g) == []


# ── exposure (F-070, F-076, F-077, F-105) ────────────────────────────────────

@pytest.mark.finding("F-070", "F-037")
def test_public_inbound_from_anonymous_with_ports_and_groups(tmp_path):
    t = _net_tree(tmp_path, inbound=[rb.sg_rule("tcp", 22, cidrs=["0.0.0.0/0"]),
                                     rb.sg_rule("tcp", 5432, cidrs=["10.0.0.0/8"])],
                  instances=[_inst(public_ip="203.0.113.10")])
    out = t.analyze()
    g = out.graph
    [edge] = K.edges(g, "PUBLIC_INBOUND", K.ANON, K.instance(IID))
    assert edge["traversable"] is False and edge["traversal"] == "exposure" and edge["confidence"] == "definite"
    assert edge["evidence"]["ports"] == ["22/tcp"] and edge["evidence"]["security_groups"] == [SG]
    [f] = K.findings(g, "EC2-EXPOSURE-001", K.instance(IID))
    assert f["severity"] == "HIGH" and f["evidence"]["sources"] == ["0.0.0.0/0"]
    node = K.nodes_by_id(g)[K.instance(IID)]
    assert node["props"]["igw_routed"] is True and node["props"]["public"] is True
    assert K.findings(g, "EC2-INET-001", K.instance(IID))
    assert [e["type"] for e in out.legacy("ec2_relationships.json")["edges"] if e["type"] == "PUBLIC_INBOUND"]
    assert K.problems(g) == []


@pytest.mark.finding("F-076")
def test_split_cidrs_and_ipv6_only_exposure_are_detected(tmp_path):
    t = _net_tree(tmp_path, inbound=[rb.sg_rule("tcp", 3389, cidrs=["0.0.0.0/1", "128.0.0.0/1"]),
                                     rb.sg_rule("tcp", 443, cidrs6=["::/0"])],
                  instances=[_inst(public_ip="203.0.113.10"), _inst(IID2)], nacl_entries=ALLOW_ALL_V4_V6,
                  extra_routes=[{"DestinationIpv6CidrBlock": "::/0", "GatewayId": K.IGW, "State": "active"}])
    recs = [rb.ec2_instance(IID, account=K.ACCT, region=K.REGION, public_ip="203.0.113.10", subnet=K.PUB, vpc=K.VPC,
                            sgs=WEB_SGS),
            rb.ec2_instance(IID2, account=K.ACCT, region=K.REGION, subnet=K.PUB, vpc=K.VPC, sgs=WEB_SGS)]
    recs[1]["Ipv6Address"] = "2001:db8:1234::10"
    recs[1]["NetworkInterfaces"][0]["Ipv6Addresses"] = [{"Ipv6Address": "2600:1f18:1234::10"}]
    t.scope.write("ec2/instances.json", recs)
    g = t.analyze().graph
    v4 = K.findings(g, "EC2-EXPOSURE-001", K.instance(IID))[0]
    assert "3389/tcp" in v4["evidence"]["ports"]
    v6 = K.findings(g, "EC2-EXPOSURE-001", K.instance(IID2))[0]
    assert v6["evidence"]["ports"] == ["443/tcp"] and v6["evidence"]["addresses"] == ["2600:1f18:1234::10"]
    assert K.edges(g, "PUBLIC_INBOUND", K.ANON, K.instance(IID2))
    assert K.problems(g) == []


@pytest.mark.finding("F-076", "F-105")
def test_prefix_lists_elastic_ips_and_eni_addresses_in_a_v2_run(tmp_path):
    run = K.Run(tmp_path)
    s = run.unit(K.REGION)
    rb.vpc_network(s, vpc=K.VPC, public_subnet=K.PUB, private_subnet=K.PRIV, igw=K.IGW)
    run.v2.coverage("vpc", K.REGION)
    run.write_json(K.REGION, "vpc/managed_prefix_lists.json", [
        {"PrefixListId": "pl-0a1b2c3d4e5f60001", "OwnerId": K.ACCT, "Entries": [{"Cidr": "0.0.0.0/0"}]},
        {"PrefixListId": "pl-0a1b2c3d4e5f60002", "OwnerId": "AWS", "Entries": None}], module="vpc")
    rule_pl = rb.sg_rule("tcp", 22)
    rule_pl["PrefixListIds"] = [{"PrefixListId": "pl-0a1b2c3d4e5f60001"}]
    rule_aws = rb.sg_rule("tcp", 443)
    rule_aws["PrefixListIds"] = [{"PrefixListId": "pl-0a1b2c3d4e5f60002"}]
    run.write_json(K.REGION, "sg/security_groups.json", [
        rb.security_group(SG, "demo-pl", vpc=K.VPC, inbound=[rule_pl]),
        rb.security_group(SG2, "demo-cloudfront", vpc=K.VPC, inbound=[rule_aws])])
    eip = rb.ec2_instance(IID, account=K.ACCT, region=K.REGION, subnet=K.PUB, vpc=K.VPC, sgs=WEB_SGS)
    eni = rb.ec2_instance(IID2, account=K.ACCT, region=K.REGION, subnet=K.PUB, vpc=K.VPC,
                          sgs=[{"GroupId": SG2, "GroupName": "demo-cloudfront"}])
    eni["NetworkInterfaces"][0]["Association"] = {"PublicIp": "198.51.100.7", "IpOwnerId": "amazon"}
    run.write_json(K.REGION, "ec2/instances.json", [eip, eni])
    run.write_json(K.REGION, "ec2/elastic_ips.json", [{"AllocationId": "eipalloc-0a1b2c3d4e5f60001",
                                                       "PublicIp": "198.51.100.5", "InstanceId": IID}], module="ec2")
    run.finish()
    g = run.analyze().graph
    [via_pl] = K.findings(g, "EC2-EXPOSURE-001", K.instance(IID))
    assert via_pl["evidence"]["addresses"] == ["198.51.100.5"] and via_pl["confidence"] == "definite"
    assert via_pl["evidence"]["sources"] == ["pl-0a1b2c3d4e5f60001:0.0.0.0/0"]
    [unresolved] = K.findings(g, "EC2-EXPOSURE-001", K.instance(IID2))
    assert unresolved["confidence"] == "conditional" and "ec2:sg-unresolved-source" in unresolved["gaps"]
    assert unresolved["severity"] == "MEDIUM"
    assert K.problems(g) == []


@pytest.mark.finding("F-077")
def test_effective_route_table_blackhole_and_detached_gateway(tmp_path):
    t = _net_tree(tmp_path, inbound=[rb.sg_rule("tcp", 80, cidrs=["0.0.0.0/0"])], main_igw=True,
                  instances=[_inst(public_ip="203.0.113.10", subnet=K.PRIV)])
    import json
    tables = json.loads((t.path / "vpc" / "route_tables.json").read_text())
    tables.append({"RouteTableId": "rtb-0a1b2c3d4e5f6ab09", "VpcId": K.VPC, "OwnerId": K.ACCT,
                   "Associations": [{"Main": False, "SubnetId": K.PRIV}],
                   "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": K.IGW, "State": "blackhole"}]})
    t.scope.write("vpc/route_tables.json", tables)
    g = t.analyze().graph
    node = K.nodes_by_id(g)[K.instance(IID)]
    assert node["props"]["igw_routed"] is False            # explicit table wins over the main one; blackhole ignored
    assert K.findings(g, "EC2-INET-001") == [] and K.findings(g, "EC2-EXPOSURE-001") == []
    t.scope.write("vpc/internet_gateways.json", [{"InternetGatewayId": K.IGW, "Attachments": []}])
    t.scope.write("vpc/route_tables.json", tables[:2])
    t.scope.write("ec2/instances.json", [rb.ec2_instance(IID, account=K.ACCT, region=K.REGION, public_ip="203.0.113.10",
                                                         subnet=K.PUB, vpc=K.VPC, sgs=WEB_SGS)])
    g = t.analyze().graph
    assert K.nodes_by_id(g)[K.instance(IID)]["props"]["igw_routed"] is False   # IGW not attached


@pytest.mark.finding("F-105", "F-046")
def test_nacl_deny_blocks_exposure_and_unknown_routes_stay_conditional(tmp_path):
    deny_ssh = [{"RuleNumber": 50, "Protocol": "6", "RuleAction": "deny", "Egress": False, "CidrBlock": "0.0.0.0/0",
                 "PortRange": {"From": 22, "To": 22}},
                {"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow", "Egress": False,
                 "CidrBlock": "0.0.0.0/0"}]
    t = _net_tree(tmp_path, inbound=[rb.sg_rule("tcp", 22, cidrs=["0.0.0.0/0"])], nacl_entries=deny_ssh,
                  instances=[_inst(public_ip="203.0.113.10")])
    g = t.analyze().graph
    assert K.findings(g, "EC2-EXPOSURE-001") == [] and K.edges(g, "PUBLIC_INBOUND") == []
    # no VPC data at all: exposure is reported, conditionally (unknown is never "not public")
    t2 = K.Tree(tmp_path / "b")
    t2.write(skip={"ec2", "sg", "vpc"})
    t2.scope.write("sg/security_groups.json", [rb.security_group(SG, "demo-web", vpc=K.VPC, inbound=[
        rb.sg_rule("tcp", 22, cidrs=["0.0.0.0/0"])])])
    t2.scope.write("ec2/instances.json", [rb.ec2_instance(IID, account=K.ACCT, region=K.REGION,
                                                          public_ip="203.0.113.10", sgs=WEB_SGS)])
    g2 = t2.analyze().graph
    [edge] = K.edges(g2, "PUBLIC_INBOUND", K.ANON, K.instance(IID))
    assert edge["confidence"] == "conditional"
    assert {"ec2:nacl-unknown", "ec2:route-unknown"} <= set(edge["evidence"]["gaps"])
    assert K.problems(g2) == []


# ── IMDS (F-078, F-106) ──────────────────────────────────────────────────────

@pytest.mark.finding("F-078", "F-106")
def test_imds_finding_wording_severity_and_ssrf_only_with_a_role(tmp_path):
    no_role = _inst(IID2, public_ip="203.0.113.11", http_tokens="optional")
    stopped = _inst("i-0a1b2c3d4e5f6c003", public_ip="203.0.113.12", http_tokens="optional", profile="web",
                    state="stopped")
    t = _net_tree(tmp_path, inbound=[rb.sg_rule("tcp", 80, cidrs=["0.0.0.0/0"])],
                  instances=[_inst(public_ip="203.0.113.10", http_tokens="optional", profile="web"), no_role,
                             stopped])
    g = t.analyze().graph
    sev = {f["node_id"]: f for f in K.findings(g, "EC2-IMDS-001")}
    assert sev[K.instance(IID)]["severity"] == "MEDIUM" and "role" in sev[K.instance(IID)]["description"]
    assert sev[K.instance(IID2)]["severity"] == "LOW" and "no role" in sev[K.instance(IID2)]["description"]
    assert sev[K.instance("i-0a1b2c3d4e5f6c003")]["severity"] == "LOW"           # stopped: lowered
    ssrf = {e["target"] for e in K.edges(g, "SSRF_TO_IMDS")}
    assert ssrf == {K.instance(IID)}                                              # running + public + role
    [e] = K.edges(g, "SSRF_TO_IMDS")
    assert e["confidence"] == "conditional" and e["weight"] == 6
    path = K.engine("graph.traverse").shortest_path(g, K.ANON, K.iam_arn("role", "demo-web-role"))
    assert path is not None and path.edge_types == ("SSRF_TO_IMDS", "INSTANCE_ROLE")
    assert K.problems(g) == []


# ── launch templates, user data, AMIs (F-105, F-116) ─────────────────────────

@pytest.mark.finding("F-105", "F-116")
def test_launch_templates_userdata_and_public_amis(tmp_path):
    run = K.Run(tmp_path)
    inst = rb.ec2_instance(IID, account=K.ACCT, region=K.REGION)
    inst["UserData"] = {"Present": True, "Sha256": "ab" * 32, "Length": 120}
    run.write_json(K.REGION, "ec2/instances.json", [inst])
    run.write_json(K.REGION, "ec2/launch_templates.json", [{
        "LaunchTemplateId": "lt-0a1b2c3d4e5f60001", "LaunchTemplateName": "demo-template",
        "DefaultVersionNumber": 1, "Versions": [{"VersionNumber": 1, "UserDataPresent": True,
                                                 "IamInstanceProfile": {"Arn": "arn:aws:iam::123456789012:"
                                                                               "instance-profile/demo"},
                                                 "MetadataOptions": {"HttpTokens": "optional"}}]}], module="ec2")
    run.write_json(K.REGION, "ec2/images.json", [
        {"ImageId": "ami-0a1b2c3d4e5f60001", "Name": "demo-golden", "Public": True, "SharedAccounts": [K.FOREIGN],
         "State": "available"},
        {"ImageId": "ami-0a1b2c3d4e5f60002", "Name": "demo-private", "Public": False, "SharedAccounts": []},
        {"ImageId": "ami-0a1b2c3d4e5f60003", "Name": "demo-unknown", "Public": None, "SharedAccounts": None}],
        module="ec2")
    run.write_json(K.REGION, "ec2/account_settings.json", {"ImageBlockPublicAccessState": "block-new-sharing"},
                   module="ec2")
    run.finish()
    g = run.analyze().graph
    lt = f"arn:aws:ec2:{K.REGION}:{K.ACCT}:launch-template/lt-0a1b2c3d4e5f60001"
    nodes = K.nodes_by_id(g)
    assert nodes[lt]["props"]["userdata_present"] is True and nodes[lt]["props"]["http_tokens"] == "optional"
    assert {f["node_id"] for f in K.findings(g, "EC2-USERDATA-001")} == {lt, K.instance(IID)}
    ami = f"arn:aws:ec2:{K.REGION}::image/ami-0a1b2c3d4e5f60001"
    assert K.edges(g, "AMI_SHARED_PUBLIC", K.ANON, ami)
    [pub] = K.findings(g, "AMI-PUB-001", ami)
    assert "only blocks new public sharing" in pub["description"]
    [shared] = K.findings(g, "AMI-XACCT-001", ami)
    foreign = f"arn:aws:iam::{K.FOREIGN}:root"
    [edge] = K.edges(g, "AMI_SHARED_CROSS_ACCOUNT", foreign, ami)             # F-116, D-52
    assert edge["traversable"] is True and shared["related_node_ids"] == [foreign]
    assert nodes[foreign]["type"] == "external_account"
    unknown = nodes[f"arn:aws:ec2:{K.REGION}::image/ami-0a1b2c3d4e5f60003"]
    assert unknown["coverage"]["status"] == "partial" and K.findings(g, "AMI-PUB-001", unknown["id"]) == []
    assert K.problems(g) == []


def test_terminated_instances_are_inventory_only(tmp_path):
    t = K.Tree(tmp_path)
    t.iam.role("demo-app", K.EC2_TRUST)
    prof = t.iam.instance_profile("demo-app", ["demo-app"])
    t.iam.role("demo-ops", K.EC2_TRUST, inline={"p": [rb.allow("ec2:*", "*")]})
    t.write(skip={"ec2"})
    t.scope.write("ec2/instances.json", [rb.ec2_instance(IID, account=K.ACCT, region=K.REGION, profile=prof,
                                                         state="terminated", http_tokens="optional",
                                                         public_ip="203.0.113.10")])
    g = t.analyze().graph
    assert K.nodes_by_id(g)[K.instance(IID)]["props"]["state"] == "terminated"
    assert K.edges(g, target=K.instance(IID)) == [] and K.edges(g, source=K.instance(IID)) == []
    assert K.findings(g, node_id=K.instance(IID)) == []
