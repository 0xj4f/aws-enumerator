"""EC2 collector (collectors-cli.md §5.3): full IMDS options, pagination, IPv6 / secondary public IPs, Elastic
IPs, launch templates and UserData (digest only), owned AMIs, the AMI block-public-access setting."""

from __future__ import annotations

import base64
import hashlib
import importlib

import pytest

from tests.fixtures.worlds import acme

KIT = importlib.import_module("tests.fixtures.c-a.kit")
WORLDS = importlib.import_module("tests.fixtures.c-a.worlds")
pytestmark = pytest.mark.collectors

W1, W2 = KIT.W1, KIT.W2
METADATA_KEYS = {"State", "HttpTokens", "HttpPutResponseHopLimit", "HttpEndpoint", "HttpProtocolIpv6",
                 "InstanceMetadataTags"}


def instances(r):
    return KIT.by(r.load("instances.json"), "InstanceId")


def _w2_ids():
    return [i["InstanceId"] for res in acme.REGIONAL[W2]["ec2"]["Reservations"] for i in res["Instances"]]


@pytest.mark.finding("F-106")
def test_metadata_options_keep_every_field_including_http_endpoint(tmp_path):
    r = KIT.run("ec2", tmp_path / "w1", KIT.world(), region=W1)
    (only,) = r.load("instances.json")
    assert set(only["MetadataOptions"]) == METADATA_KEYS
    assert only["MetadataOptions"]["HttpEndpoint"] == "disabled"
    assert only["MetadataOptions"]["HttpTokens"] == "optional"
    assert only["MetadataOptions"]["State"] is None                    # not returned: unknown, not a default
    r = KIT.run("ec2", tmp_path / "v6", WORLDS.ipv6())
    v6 = instances(r)[WORLDS.IPV6_INSTANCE_ID]["MetadataOptions"]
    assert v6 == {"State": "applied", "HttpTokens": "required", "HttpPutResponseHopLimit": 1,
                  "HttpEndpoint": "enabled", "HttpProtocolIpv6": "enabled", "InstanceMetadataTags": "disabled"}


@pytest.mark.finding("F-117")
def test_describe_instances_follows_next_token(tmp_path):
    w = KIT.world()
    w.page_sizes[("ec2", "DescribeInstances")] = 1
    r = KIT.run("ec2", tmp_path, w)
    pages = KIT.sent(r, "ec2", "DescribeInstances")
    assert len(pages) == 2 and all(p.get("MaxResults") == 1000 for p in pages)
    assert sorted(instances(r)) == sorted(_w2_ids())
    assert KIT.is_sorted_by(r.load("instances.json"), "InstanceId")


@pytest.mark.finding("F-105", "F-076")
def test_ipv6_secondary_public_ips_key_name_and_platform_are_kept(tmp_path):
    r = KIT.run("ec2", tmp_path, WORLDS.ipv6())
    KIT.assert_contract(r)
    inst = instances(r)[WORLDS.IPV6_INSTANCE_ID]
    assert inst["Ipv6Address"] == WORLDS.IPV6_ADDRESS
    assert (inst["KeyName"], inst["Platform"]) == ("demo-ops-key", "windows")
    (eni,) = inst["NetworkInterfaces"]
    assert eni["Ipv6Addresses"] == [WORLDS.IPV6_ADDRESS]
    assert eni["Association"] is None
    secondary = [p for p in eni["PrivateIpAddresses"] if not p["Primary"]]
    assert secondary == [{"PrivateIpAddress": "10.20.1.31", "Primary": False, "Association": {
        "PublicIp": WORLDS.SECONDARY_PUBLIC_IP, "PublicDnsName": "ec2-203-0-113-77.eu-west-2.compute.amazonaws.com",
        "IpOwnerId": "amazon"}}]
    web = instances(r)["i-0dec0eeb000000002"]
    assert web["NetworkInterfaces"][0]["Association"]["PublicIp"] == "203.0.113.10"
    assert web["IamInstanceProfile"]["Arn"].endswith(":instance-profile/demo-app-profile")
    assert web["LaunchTime"].endswith("Z")                                    # UTC ISO-8601 (F-171 style)


@pytest.mark.finding("F-058")
def test_denied_instances_keep_the_other_inventories(tmp_path):
    w = KIT.world()
    w.deny("ec2", "DescribeInstances")
    r = KIT.run("ec2", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))
    assert r.load("instances.json") == []
    assert len(r.load("elastic_ips.json")) == 2
    assert [lt["LaunchTemplateName"] for lt in r.load("launch_templates.json")] == ["demo-web-lt"]


@pytest.mark.finding("F-105")
def test_elastic_ips_are_collected(tmp_path):
    r = KIT.run("ec2", tmp_path, KIT.world())
    assert KIT.sent(r, "ec2", "DescribeAddresses") == [{}]   # DescribeAddresses has no pagination
    eips = r.load("elastic_ips.json")
    assert [e["AllocationId"] for e in eips] == ["eipalloc-0dec0000002", "eipalloc-0dec0000003"]
    assert eips[0]["NetworkInterfaceId"] == "eni-0dec0a7a0000002"


@pytest.mark.finding("F-105")
def test_launch_template_user_data_is_never_stored_only_its_digest(tmp_path):
    r = KIT.run("ec2", tmp_path, KIT.world())
    KIT.assert_no_canaries(r)
    (lt,) = r.load("launch_templates.json")
    assert lt["Arn"] == f"arn:aws:ec2:{W2}:{KIT.ACCT}:launch-template/lt-0dec0eeb000000002"
    assert [p["Versions"] for p in KIT.sent(r, "ec2", "DescribeLaunchTemplateVersions")] == [["$Default", "$Latest"]]
    v1, v2 = lt["Versions"]
    expected = base64.b64decode(acme.REGIONAL[W2]["ec2"]["LaunchTemplateVersions"]["lt-0dec0eeb000000002"][0]
                                ["LaunchTemplateData"]["UserData"])
    assert (v1["VersionNumber"], v1["DefaultVersion"]) == (1, True)
    assert v1["UserDataPresent"] is True and v1["UserDataLength"] == len(expected)
    assert v1["UserDataSha256"] == hashlib.sha256(expected).hexdigest()
    assert "UserData" not in v1
    assert (v2["UserDataPresent"], v2["UserDataSha256"], v2["UserDataLength"]) == (False, None, 0)
    assert v2["MetadataOptions"]["HttpTokens"] == "required"
    assert v1["IamInstanceProfile"]["Arn"].endswith(":instance-profile/demo-app-profile")


def test_unreadable_template_versions_are_null_and_marked(tmp_path):
    w = KIT.world()
    w.deny("ec2", "DescribeLaunchTemplateVersions")
    r = KIT.run("ec2", tmp_path, w)
    (lt,) = r.load("launch_templates.json")
    assert lt["Versions"] is None
    assert KIT.collection_errors(lt) == [("ec2:DescribeLaunchTemplateVersions", "denied")]
    assert r.result.status == "partial"


@pytest.mark.finding("F-105")
def test_owned_images_record_their_sharing(tmp_path):
    r = KIT.run("ec2", tmp_path, KIT.world())
    assert KIT.sent(r, "ec2", "DescribeImages")[0]["Owners"] == ["self"]
    images = KIT.by(r.load("images.json"), "ImageId")
    shared = images["ami-0dec0000000000002"]
    assert (shared["Public"], shared["SharedAccounts"]) == (False, [KIT.EXT])
    assert shared["Arn"] == f"arn:aws:ec2:{W2}::image/ami-0dec0000000000002"
    public = images["ami-0dec0b0b11c000002"]
    assert (public["Public"], public["SharedAccounts"]) == (True, [])
    assert r.load("account_settings.json") == {"ImageBlockPublicAccessState": "unblocked"}
    r = KIT.run("ec2", tmp_path / "w1", KIT.world(), region=W1)
    assert r.load("account_settings.json") == {"ImageBlockPublicAccessState": "block-new-sharing"}


def test_a_denied_optional_setting_is_null_and_does_not_degrade(tmp_path):
    w = KIT.clean_world()
    w.deny("ec2", "GetImageBlockPublicAccessState")
    r = KIT.run("ec2", tmp_path, w)
    assert r.load("account_settings.json") == {"ImageBlockPublicAccessState": None}
    assert r.result.status == "ok"


@pytest.mark.finding("F-105")
def test_userdata_check_stores_presence_and_digest_only(tmp_path):
    r = KIT.run("ec2", tmp_path / "off", KIT.world())
    assert KIT.sent(r, "ec2", "DescribeInstanceAttribute") == []
    assert {i["UserData"] for i in r.load("instances.json")} == {None}
    r = KIT.run("ec2", tmp_path / "on", KIT.world(), options={"ec2_userdata_check": True})
    KIT.assert_no_canaries(r)
    assert sorted(p["InstanceId"] for p in KIT.sent(r, "ec2", "DescribeInstanceAttribute")) == sorted(_w2_ids())
    raw = base64.b64decode(acme.REGIONAL[W2]["ec2"]["UserData"]["i-0dec0eeb000000002"])
    got = instances(r)
    assert got["i-0dec0eeb000000002"]["UserData"] == {"Present": True, "Sha256": hashlib.sha256(raw).hexdigest(),
                                                      "Length": len(raw)}
    assert got["i-0dec0abb000000002"]["UserData"] == {"Present": False, "Sha256": None, "Length": 0}
