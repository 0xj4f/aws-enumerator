"""World extensions for the C-A collector tests (ownership.md §3.1: ``acme.py`` stays frozen; streams build
``acme.build_world()`` and add their own handlers here).

Each builder returns a fresh :class:`World`; the extra data uses the placeholder account ids and
``demo-*`` names only.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List

from tests.fixtures.worlds import acme
from tests.support.fakeaws import PaginationSpec, Request, World

W1, W2 = "eu-west-1", "eu-west-2"
ACCT = acme.ACCOUNT_ID
MGMT_ACCOUNT = "999999999999"   # the organization's management account (placeholder id)

#: An instance reachable over IPv6 and through a secondary private IP's public association (F-105, F-076).
IPV6_INSTANCE_ID = "i-0dec0f6f6000000002"
IPV6_ADDRESS = "2001:db8:1234:1a00::10"
SECONDARY_PUBLIC_IP = "203.0.113.77"
#: A fourth network interface (two groups) so the region-wide ENI listing spans two pages (F-167).
EXTRA_ENI_ID = "eni-0dec0f0f0000002"
#: A management-account organization trail as a member account sees it (F-045).
ORG_TRAIL_ARN = f"arn:aws:cloudtrail:{W2}:{MGMT_ACCOUNT}:trail/demo-management-org-trail"


def base() -> World:
    """acme plus ``NextMarker`` pagination models for the wafv2 listings acme serves whole (F-107)."""
    w = acme.build_world()
    for op, key in (("ListRuleGroups", "RuleGroups"), ("ListIPSets", "IPSets"),
                    ("ListLoggingConfigurations", "LoggingConfigurations")):
        w.pagination[("wafv2", op)] = PaginationSpec("NextMarker", "NextMarker", key, None, "Limit")
    return w


#: A second eu-west-2 rule group, IP set and logging configuration, so each wafv2 listing has two pages.
EXTRA_RULE_GROUP = {
    "Name": "demo-geo-rules", "Id": "b2b2b2b2-0000-4000-8000-0000000000b2", "Description": "demo-geo-rules (c-a)",
    "ARN": f"arn:aws:wafv2:{W2}:{ACCT}:regional/rulegroup/demo-geo-rules/b2b2b2b2-0000-4000-8000-0000000000b2",
    "Capacity": 10, "Rules": [],
    "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True, "MetricName": "geo"},
}
EXTRA_IP_SET = {
    "Name": "demo-partner-ips", "Id": "b3b3b3b3-0000-4000-8000-0000000000b3", "Description": "demo partners",
    "ARN": f"arn:aws:wafv2:{W2}:{ACCT}:regional/ipset/demo-partner-ips/b3b3b3b3-0000-4000-8000-0000000000b3",
    "IPAddressVersion": "IPV4", "Addresses": ["198.51.100.0/24", "192.0.2.0/24"],
}
EXTRA_LOGGING = {"ResourceArn": f"arn:aws:wafv2:{W2}:{ACCT}:regional/webacl/demo-api-acl/extra",
                 "LogDestinationConfigs": [f"arn:aws:logs:{W2}:{ACCT}:log-group:aws-waf-logs-demo"]}


def _summary(item: Dict[str, Any]) -> Dict[str, Any]:
    return {"Name": item["Name"], "Id": item["Id"], "ARN": item["ARN"], "Description": item["Description"],
            "LockToken": "0000000b-lock-4000-8000-000000000000"}


def waf_paged() -> World:
    """Every wafv2 listing one item per page, with two items in each eu-west-2 listing (F-107)."""
    w = base()
    for op in ("ListWebACLs", "ListRuleGroups", "ListIPSets", "ListLoggingConfigurations"):
        w.page_sizes[("wafv2", op)] = 1
    extra = {"ListRuleGroups": ("RuleGroups", _summary(EXTRA_RULE_GROUP)),
             "ListIPSets": ("IPSets", _summary(EXTRA_IP_SET)),
             "ListLoggingConfigurations": ("LoggingConfigurations", dict(EXTRA_LOGGING))}
    for op, (key, item) in extra.items():
        original = w.handlers[("wafv2", op)]

        def listing(req: Request, _orig=original, _key=key, _item=item):
            resp = _orig(req)
            if req.region == W2:
                resp = {_key: list(resp.get(_key) or []) + [copy.deepcopy(_item)]}
            return resp

        w.handlers[("wafv2", op)] = listing
    for op, key, item in (("GetRuleGroup", "RuleGroup", EXTRA_RULE_GROUP), ("GetIPSet", "IPSet", EXTRA_IP_SET)):
        original = w.handlers[("wafv2", op)]

        def getter(req: Request, _orig=original, _key=key, _item=item):
            if req.params.get("Name") == _item["Name"]:
                return {_key: copy.deepcopy(_item), "LockToken": "0000000b-lock-4000-8000-000000000000"}
            return _orig(req)

        w.handlers[("wafv2", op)] = getter
    return w


def ipv6() -> World:
    """acme plus one eu-west-2 instance with an IPv6 address and a secondary public IP."""
    w = base()
    original = w.handlers[("ec2", "DescribeInstances")]
    instance = {
        "InstanceId": IPV6_INSTANCE_ID, "InstanceType": "t3.micro", "ImageId": "ami-0dec0000000000002",
        "State": {"Code": 16, "Name": "running"}, "LaunchTime": acme.ts(12), "KeyName": "demo-ops-key",
        "Placement": {"AvailabilityZone": f"{W2}a"}, "PrivateIpAddress": "10.20.1.30",
        "SubnetId": acme.REGIONAL[W2]["ec2"]["Subnets"][0]["SubnetId"],
        "VpcId": acme.REGIONAL[W2]["ec2"]["Vpcs"][0]["VpcId"], "Ipv6Address": IPV6_ADDRESS,
        "Platform": "windows", "PlatformDetails": "Windows", "Architecture": "x86_64",
        "MetadataOptions": {"State": "applied", "HttpTokens": "required", "HttpPutResponseHopLimit": 1,
                            "HttpEndpoint": "enabled", "HttpProtocolIpv6": "enabled",
                            "InstanceMetadataTags": "disabled"},
        "NetworkInterfaces": [{
            "NetworkInterfaceId": "eni-0dec0f6f60000002", "PrivateIpAddress": "10.20.1.30",
            "SubnetId": acme.REGIONAL[W2]["ec2"]["Subnets"][0]["SubnetId"], "Status": "in-use",
            "MacAddress": "0a:00:00:00:00:30", "Ipv6Addresses": [{"Ipv6Address": IPV6_ADDRESS}],
            "PrivateIpAddresses": [
                {"PrivateIpAddress": "10.20.1.30", "Primary": True},
                {"PrivateIpAddress": "10.20.1.31", "Primary": False,
                 "Association": {"PublicIp": SECONDARY_PUBLIC_IP, "IpOwnerId": "amazon",
                                 "PublicDnsName": "ec2-203-0-113-77.eu-west-2.compute.amazonaws.com"}}]}],
        "SecurityGroups": [], "Tags": [{"Key": "Name", "Value": "demo-ipv6"}],
    }

    def describe_instances(req: Request):
        resp = original(req)
        if req.region == W2:
            resp = {"Reservations": list(resp["Reservations"]) + [
                {"ReservationId": "r-0dec0f6f6000000002", "OwnerId": ACCT, "Instances": [instance]}]}
        return resp

    w.handlers[("ec2", "DescribeInstances")] = describe_instances
    return w


def extra_eni(page_size: int = 2) -> World:
    """acme plus a fourth eu-west-2 ENI in two groups; DescribeNetworkInterfaces ``page_size`` per page."""
    w = base()
    original = w.handlers[("ec2", "DescribeNetworkInterfaces")]
    groups = [g["GroupId"] for g in acme.REGIONAL[W2]["ec2"]["SecurityGroups"]]
    eni = {"NetworkInterfaceId": EXTRA_ENI_ID, "PrivateIpAddress": "10.20.1.40", "Status": "in-use",
           "Description": "demo shared interface", "InterfaceType": "interface",
           "Groups": [{"GroupId": groups[1], "GroupName": "demo-app"}, {"GroupId": groups[2], "GroupName": "default"}],
           "Association": {"PublicIp": "203.0.113.40", "IpOwnerId": "amazon"},
           "Attachment": {"AttachmentId": "eni-attach-0dec0f0f0000002", "InstanceId": "i-0dec0abb000000002",
                          "DeviceIndex": 1, "Status": "attached"}}

    def describe_enis(req: Request):
        resp = original(req)
        if req.region == W2:
            resp = {"NetworkInterfaces": list(resp["NetworkInterfaces"]) + [eni]}
        return resp

    w.handlers[("ec2", "DescribeNetworkInterfaces")] = describe_enis
    w.page_sizes[("ec2", "DescribeNetworkInterfaces")] = page_size
    return w


def org_trail(*, details_denied: bool = True) -> World:
    """acme plus a management-account organization trail homed in eu-west-2 (seen from member 111122223333)."""
    w = base()
    original = w.handlers[("cloudtrail", "DescribeTrails")]
    trail = {"Name": "demo-management-org-trail", "S3BucketName": "demo-org-logs", "IncludeGlobalServiceEvents": True,
             "IsMultiRegionTrail": True, "HomeRegion": W2, "TrailARN": ORG_TRAIL_ARN,
             "LogFileValidationEnabled": True, "HasCustomEventSelectors": True, "HasInsightSelectors": False,
             "IsOrganizationTrail": True}

    def describe_trails(req: Request):
        resp = original(req)
        if req.params.get("includeShadowTrails", True) or req.region == W2:
            resp = {"trailList": list(resp["trailList"]) + [dict(trail)]}
        return resp

    w.handlers[("cloudtrail", "DescribeTrails")] = describe_trails
    if details_denied:
        for op, key in (("GetTrailStatus", "Name"), ("GetEventSelectors", "TrailName")):
            w.deny("cloudtrail", op, {key: ORG_TRAIL_ARN})
    return w


def hardware_mfa() -> World:
    """acme where demo-ci has a hardware MFA device (credential report ``mfa_active`` true, no virtual one)."""
    w = base()
    report = w.handlers[("iam", "GetCredentialReport")]
    list_mfa = w.handlers[("iam", "ListMFADevices")]
    serial = "GAHT12345678"

    def get_report(req: Request):
        resp = report(req)
        lines = resp["Content"].decode("utf-8").split("\n")
        header = lines[0].split(",")
        col = header.index("mfa_active")
        for i, line in enumerate(lines[1:], start=1):
            cells = line.split(",")
            if cells[0] == "demo-ci":
                cells[col] = "true"
                lines[i] = ",".join(cells)
        return dict(resp, Content="\n".join(lines).encode("utf-8"))

    def mfa_devices(req: Request):
        if req.params.get("UserName") == "demo-ci":
            return {"MFADevices": [{"UserName": "demo-ci", "SerialNumber": serial, "EnableDate": acme.ts(6)}],
                    "IsTruncated": False}
        return list_mfa(req)

    w.handlers[("iam", "GetCredentialReport")] = get_report
    w.handlers[("iam", "ListMFADevices")] = mfa_devices
    w.meta["hardware_mfa_serial"] = serial
    return w


def names(items: List[Dict[str, Any]], key: str) -> List[Any]:
    return [i.get(key) for i in items]
