"""Route 53 collector (collectors-cli.md §5.6): takeover candidates with claimable levels, minimised records."""

from __future__ import annotations

import copy
import importlib

import pytest

from tests.fixtures.worlds import acme
from tests.support import targets

KIT = importlib.import_module("tests.fixtures.c-b.kit")
pytestmark = pytest.mark.collectors

PUBLIC, PRIVATE = "Z0DEMOPUBLIC00001", "Z0DEMOPRIVATE0002"


def module():
    return targets.collector_module("route53")


def run(tmp_path, w=None, **kw):
    return KIT.run("route53", tmp_path, w, region="global", **kw)


@pytest.fixture
def zones(monkeypatch):
    """A private copy of acme's hosted zones the test may edit (the handlers close over the list)."""
    data = copy.deepcopy(acme.ROUTE53_ZONES)
    w = KIT.world()
    by_id = {z["Id"].rsplit("/", 1)[-1]: z for z in data}

    @w.op("route53", "ListHostedZones")
    def list_zones(req):
        return {"HostedZones": [{k: v for k, v in z.items() if k != "records"} for z in data],
                "Marker": req.params.get("Marker", ""), "IsTruncated": False, "MaxItems": "100"}

    @w.op("route53", "ListResourceRecordSets")
    def list_records(req):
        return {"ResourceRecordSets": by_id[req.params["HostedZoneId"]]["records"], "IsTruncated": False,
                "MaxItems": "300"}

    w.clear_errors("route53")
    return w, by_id


@pytest.mark.finding("F-057", "F-112", "F-059")
def test_zones_candidates_and_minimised_records(tmp_path):
    r = run(tmp_path)
    KIT.assert_contract(r, statuses=("partial",))           # acme denies the private zone's records
    zones = KIT.by(r.load("resources.json"), "Id")
    public = zones[PUBLIC]
    assert public["Arn"] == f"arn:aws:route53:::hostedzone/{PUBLIC}" and public["Private"] is False
    candidates = [(c["Name"], c["Kind"], c["Claimable"], c["Alias"]) for c in public["TakeoverCandidates"]]
    assert candidates == [("old.example.com.", "s3-website", "likely", False),
                          ("app.example.com.", "elb", "unlikely", True),
                          ("www.example.com.", "cloudfront", "info", False)]
    records = {(rec["Name"], rec["Type"]): rec for rec in public["Records"]}
    txt = records[("example.com.", "TXT")]
    assert txt["Values"] is None and txt["ValuesOmitted"] is True and txt["ValueCount"] == 1     # F-112
    assert records[("example.com.", "NS")]["Values"] == ["ns-1.awsdns-01.org.", "ns-2.awsdns-02.co.uk."]
    assert records[("old.example.com.", "CNAME")]["CnameTarget"] == "demo-old-site.s3-website-eu-west-1.amazonaws.com"
    KIT.assert_no_canaries(r, "route53_txt")
    private = zones[PRIVATE]
    assert private["Records"] is None and private["TakeoverCandidates"] is None and private["RecordCount"] is None
    assert KIT.collection_errors(private) == [("route53:ListResourceRecordSets", "denied")]


@pytest.mark.finding("F-057")
def test_s3_website_alias_records_are_flagged_and_private_zones_labelled(tmp_path, zones):
    w, by_id = zones
    def alias(name, rtype, zone_id, dns):
        return {"Name": name, "Type": rtype,
                "AliasTarget": {"HostedZoneId": zone_id, "EvaluateTargetHealth": False, "DNSName": dns}}

    by_id[PUBLIC]["records"].append(alias("static.example.com.", "A", "Z3GKZC51ZF0DB4",
                                          "s3-website.eu-west-2.amazonaws.com."))
    by_id[PUBLIC]["records"].append(alias("legacy.example.com.", "AAAA", "Z3AQBSTGFYJSTF",
                                          "s3-website-us-east-1.amazonaws.com."))
    by_id[PRIVATE]["records"].append(alias("api.internal.example.com.", "A", "ZD4D7Y8KGAS4G",
                                           "demo-internal-nlb-fedcba9876543210.elb.eu-west-2.amazonaws.com."))
    by_id[PRIVATE]["records"].append({"Name": "host.internal.example.com.", "Type": "A", "TTL": 60,
                                      "ResourceRecords": [{"Value": "10.20.1.10"}]})
    r = run(tmp_path, w)
    KIT.assert_contract(r)
    zones_out = KIT.by(r.load("resources.json"), "Id")
    public = {c["Name"]: c for c in zones_out[PUBLIC]["TakeoverCandidates"]}
    static = public["static.example.com."]
    assert static["Kind"] == "s3-website" and static["Claimable"] == "likely" and static["Alias"] is True
    assert public["legacy.example.com."]["Type"] == "AAAA"
    private = zones_out[PRIVATE]["TakeoverCandidates"]
    assert [(c["Name"], c["Claimable"], c["Private"]) for c in private] == [
        ("api.internal.example.com.", "unlikely", True)]
    host = [rec for rec in zones_out[PRIVATE]["Records"] if rec["Name"] == "host.internal.example.com."][0]
    assert host["Values"] is None and host["ValuesOmitted"] is True                   # private A value (F-112)
    assert KIT.S.grep_tree("10.20.1.10", r.out) == []


@pytest.mark.finding("F-112")
def test_full_dns_keeps_every_value(tmp_path, zones):
    w, _by_id = zones
    r = run(tmp_path, w, options={"full_dns": True})
    public = KIT.by(r.load("resources.json"), "Id")[PUBLIC]
    txt = [rec for rec in public["Records"] if rec["Type"] == "TXT"][0]
    assert txt["Values"] and "ValuesOmitted" not in txt and acme.CANARIES["route53_txt"] in txt["Values"][0]


@pytest.mark.finding("F-057")
@pytest.mark.parametrize("target, expected", [
    ("s3-website.eu-west-2.amazonaws.com.", ("s3-website", "likely")),
    ("s3-website-us-east-1.amazonaws.com.", ("s3-website", "likely")),
    ("bucket.s3-website.eu-west-2.amazonaws.com", ("s3-website", "likely")),
    ("bucket.s3-website-eu-west-1.amazonaws.com", ("s3-website", "likely")),
    ("bucket.s3.eu-west-2.amazonaws.com", ("s3", "likely")),
    ("bucket.s3-eu-west-1.amazonaws.com", ("s3", "likely")),
    ("bucket.s3.amazonaws.com", ("s3", "likely")),
    ("app.cloudapp.net", ("azure-cloudapp", "likely")),
    ("app.westeurope.cloudapp.azure.com", ("azure-cloudapp", "likely")),
    ("app.trafficmanager.net", ("azure-trafficmanager", "likely")),
    ("demo.eu-west-2.elasticbeanstalk.com", ("elasticbeanstalk", "likely")),
    ("DualStack.demo-alb-123.eu-west-2.ELB.amazonaws.com.", ("elb", "unlikely")),
    ("demo-nlb-0123.elb.eu-west-2.amazonaws.com", ("elb", "unlikely")),
    ("d1234abcd.cloudfront.net.", ("cloudfront", "info")),
    ("demo-db.abcdefghij.eu-west-2.rds.amazonaws.com", None),
    ("www.example.org", None),
    (None, None),
])
def test_classify_target(target, expected):
    assert module().classify_target(target) == expected


@pytest.mark.finding("F-103", "F-061")
def test_listing_denied_is_denied_with_an_empty_list(tmp_path):
    w = KIT.world()
    w.deny("route53", "ListHostedZones")
    r = run(tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("resources.json") == []


@pytest.mark.finding("F-059", "F-103")
def test_each_api_denied_in_turn_is_survivable(tmp_path):
    assert KIT.assert_each_api_denied_is_survivable("route53", tmp_path, region="global") == [
        "route53:ListHostedZones", "route53:ListResourceRecordSets"]


@pytest.mark.finding("F-151")
def test_calls_are_read_only_and_declared(tmp_path):
    r = run(tmp_path)
    KIT.assert_declared_and_read_only(r)
    assert len(r.fake.calls_for(service="route53", operation="ListHostedZones")) == 2      # one zone per page
