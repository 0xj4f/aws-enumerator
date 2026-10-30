"""EC2 compute inventory (regional): instances, Elastic IPs, launch templates, owned AMIs and the AMI
block-public-access setting.

UserData is **never stored**: launch-template versions record only whether UserData is present, its
SHA-256 and its decoded length; per-instance UserData is read only with ``--ec2-userdata-check`` and
recorded the same way (F-105, F-116).

Options (``ctx.option``): ``ec2_userdata_check`` (bool, default off): one ``DescribeInstanceAttribute``
(``userData``) per instance.

Output (``<region>/ec2/``):

``instances.json``
    list, sorted by ``InstanceId`` (all pages of ``DescribeInstances``, F-117)::

        {InstanceId, InstanceType, State, LaunchTime, AvailabilityZone, AmiId, KeyName, Platform,
         PlatformDetails, Architecture, PublicIpAddress, PublicDnsName, PrivateIpAddress, Ipv6Address,
         SubnetId, VpcId, IamInstanceProfile: {Arn, Id} | {},
         SecurityGroups: [{GroupId, GroupName}],
         NetworkInterfaces: [{NetworkInterfaceId, PrivateIpAddress, SubnetId, VpcId, MacAddress, Status,
                              Association: {PublicIp, PublicDnsName, IpOwnerId} | null,
                              PrivateIpAddresses: [{PrivateIpAddress, Primary,
                                                    Association: {PublicIp, PublicDnsName, IpOwnerId} | null}],
                              Ipv6Addresses: [str]}],
         MetadataOptions: {State, HttpTokens, HttpPutResponseHopLimit, HttpEndpoint, HttpProtocolIpv6,
                           InstanceMetadataTags},
         Monitoring, Tags: {key: value},
         UserData: {Present, Sha256, Length} | null, CollectionErrors?}

    ``MetadataOptions`` keeps every IMDS field, ``HttpEndpoint`` included (F-106); a field AWS did not
    return is ``null``. ``UserData`` is ``null`` unless ``--ec2-userdata-check`` read it.

``elastic_ips.json``
    list, sorted by ``AllocationId`` / ``PublicIp``: each ``DescribeAddresses`` record.

``launch_templates.json``
    list, sorted by ``LaunchTemplateId``::

        {LaunchTemplateId, LaunchTemplateName, Arn, DefaultVersionNumber, LatestVersionNumber, CreateTime,
         CreatedBy, Tags,
         Versions: [{VersionNumber, DefaultVersion, ImageId, InstanceType, KeyName, IamInstanceProfile,
                     SecurityGroupIds, SecurityGroups, NetworkInterfaces, MetadataOptions,
                     UserDataPresent, UserDataSha256, UserDataLength}] | null,
         CollectionErrors?}

    ``Versions`` holds the ``$Default`` and ``$Latest`` versions; ``null`` when they could not be read.

``images.json``
    list, sorted by ``ImageId``: AMIs owned by the account::

        {ImageId, Arn, Name, Public, State, CreationDate, OwnerId, PlatformDetails,
         SharedAccounts: [str] | null, SharedOrganizations: [str] | null,
         SharedOrganizationalUnits: [str] | null, CollectionErrors?}

    The ``Shared*`` lists come from ``DescribeImageAttribute(launchPermission)``; ``null`` when unread.

``account_settings.json``
    object ``{ImageBlockPublicAccessState: str | null}`` (``GetImageBlockPublicAccessState``).

``_coverage.json``
    every call (docs/contracts/coverage-schema.md).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any, Dict, List, Optional

from aws_enumerator.collectors._common import add_error
from aws_enumerator.collectors.base import CollectContext
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="ec2", scope="regional", output_dir="ec2", services=("ec2",),
    tier=1, cost="low", noise="low", default=True, groups=("@compute",),
    actions=(
        "ec2:DescribeInstances", "ec2:DescribeAddresses", "ec2:DescribeLaunchTemplates",
        "ec2:DescribeLaunchTemplateVersions", "ec2:DescribeImages", "ec2:DescribeImageAttribute",
        "ec2:GetImageBlockPublicAccessState",
    ),
    optional_actions=("ec2:DescribeInstanceAttribute",),
    probe=("ec2", "DescribeInstances", (("MaxResults", 5),)),
    outputs=(
        ("instances.json", "list"), ("elastic_ips.json", "list"), ("launch_templates.json", "list"),
        ("images.json", "list"), ("account_settings.json", "dict"),
    ),
    description="EC2 instances (network placement, instance profile, IMDS), EIPs, launch templates, owned AMIs",
)

_METADATA_KEYS = ("State", "HttpTokens", "HttpPutResponseHopLimit", "HttpEndpoint", "HttpProtocolIpv6",
                  "InstanceMetadataTags")
_LT_KEYS = ("ImageId", "InstanceType", "KeyName", "IamInstanceProfile", "SecurityGroupIds", "SecurityGroups",
            "NetworkInterfaces", "MetadataOptions")


def collect(ctx: CollectContext) -> None:
    """Instances first (the module's primary listing), then the other inventories, each isolated."""
    ec2 = ctx.client("ec2")
    instances: List[Dict[str, Any]] = []
    with ctx.section("instances"):
        instances = _instances(ctx, ec2)
    ctx.out.write("instances.json", instances)

    addresses: List[Dict[str, Any]] = []
    with ctx.section("elastic_ips"):
        result = ctx.paginate(ec2, "describe_addresses", "Addresses")
        addresses = sorted((dict(a) for a in result.value if isinstance(a, dict)),
                           key=lambda a: (str(a.get("AllocationId")), str(a.get("PublicIp"))))
    ctx.out.write("elastic_ips.json", addresses)

    templates: List[Dict[str, Any]] = []
    with ctx.section("launch_templates"):
        templates = _launch_templates(ctx, ec2)
    ctx.out.write("launch_templates.json", templates)

    images: List[Dict[str, Any]] = []
    with ctx.section("images"):
        images = _images(ctx, ec2)
    ctx.out.write("images.json", images)

    settings: Dict[str, Any] = {"ImageBlockPublicAccessState": None}
    with ctx.section("account_settings"):
        state = ctx.call(ec2, "get_image_block_public_access_state", optional=True)
        if state.has_data:
            settings["ImageBlockPublicAccessState"] = state.get("ImageBlockPublicAccessState")
    ctx.out.write("account_settings.json", settings)


# ── instances ────────────────────────────────────────────────────────────────
def _instances(ctx: CollectContext, ec2: Any) -> List[Dict[str, Any]]:
    result = ctx.paginate(ec2, "describe_instances", "Reservations", page_size=1000, primary=True)
    raw = [i for r in result.value if isinstance(r, dict) for i in r.get("Instances") or [] if isinstance(i, dict)]
    records = sorted((_instance(i) for i in raw), key=lambda i: str(i["InstanceId"]))
    if ctx.option("ec2_userdata_check", False):
        for record in records:
            _userdata_check(ctx, ec2, record)
    return records


def _association(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, dict):
        return None
    return {"PublicIp": value.get("PublicIp"), "PublicDnsName": value.get("PublicDnsName"),
            "IpOwnerId": value.get("IpOwnerId")}


def _eni(ni: Dict[str, Any]) -> Dict[str, Any]:
    private = [{"PrivateIpAddress": p.get("PrivateIpAddress"), "Primary": p.get("Primary"),
                "Association": _association(p.get("Association"))}
               for p in ni.get("PrivateIpAddresses") or [] if isinstance(p, dict)]
    return {
        "NetworkInterfaceId": ni.get("NetworkInterfaceId"),
        "PrivateIpAddress": ni.get("PrivateIpAddress"),
        "SubnetId": ni.get("SubnetId"),
        "VpcId": ni.get("VpcId"),
        "MacAddress": ni.get("MacAddress"),
        "Status": ni.get("Status"),
        "Association": _association(ni.get("Association")),
        "PrivateIpAddresses": private,
        "Ipv6Addresses": sorted(a["Ipv6Address"] for a in ni.get("Ipv6Addresses") or []
                                if isinstance(a, dict) and a.get("Ipv6Address")),
    }


def _instance(inst: Dict[str, Any]) -> Dict[str, Any]:
    metadata = inst.get("MetadataOptions") if isinstance(inst.get("MetadataOptions"), dict) else {}
    profile = inst.get("IamInstanceProfile") if isinstance(inst.get("IamInstanceProfile"), dict) else {}
    return {
        "InstanceId": inst.get("InstanceId"),
        "InstanceType": inst.get("InstanceType"),
        "State": (inst.get("State") or {}).get("Name"),
        "LaunchTime": inst.get("LaunchTime"),
        "AvailabilityZone": (inst.get("Placement") or {}).get("AvailabilityZone"),
        "AmiId": inst.get("ImageId"),
        "KeyName": inst.get("KeyName"),
        "Platform": inst.get("Platform"),
        "PlatformDetails": inst.get("PlatformDetails"),
        "Architecture": inst.get("Architecture"),
        "PublicIpAddress": inst.get("PublicIpAddress"),
        "PublicDnsName": inst.get("PublicDnsName") or None,
        "PrivateIpAddress": inst.get("PrivateIpAddress"),
        "Ipv6Address": inst.get("Ipv6Address"),
        "SubnetId": inst.get("SubnetId"),
        "VpcId": inst.get("VpcId"),
        "IamInstanceProfile": {"Arn": profile.get("Arn"), "Id": profile.get("Id")} if profile else {},
        "SecurityGroups": [{"GroupId": g.get("GroupId"), "GroupName": g.get("GroupName")}
                           for g in inst.get("SecurityGroups") or [] if isinstance(g, dict)],
        "NetworkInterfaces": [_eni(ni) for ni in inst.get("NetworkInterfaces") or [] if isinstance(ni, dict)],
        "MetadataOptions": {key: metadata.get(key) for key in _METADATA_KEYS},
        "Monitoring": (inst.get("Monitoring") or {}).get("State"),
        "Tags": {t["Key"]: t.get("Value") for t in inst.get("Tags") or [] if isinstance(t, dict) and "Key" in t},
        "UserData": None,
    }


def _userdata_digest(value: Any) -> Dict[str, Any]:
    """``{Present, Sha256, Length}`` of base64 UserData; the content itself is dropped here."""
    if not value:
        return {"Present": False, "Sha256": None, "Length": 0}
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, TypeError):
        raw = str(value).encode("utf-8")
    return {"Present": True, "Sha256": hashlib.sha256(raw).hexdigest(), "Length": len(raw)}


def _userdata_check(ctx: CollectContext, ec2: Any, record: Dict[str, Any]) -> None:
    arn = ctx.arn("ec2", f"instance/{record['InstanceId']}")
    result = ctx.call(ec2, "describe_instance_attribute", item=arn, InstanceId=record["InstanceId"],
                      Attribute="userData")
    if result.has_data:
        record["UserData"] = _userdata_digest((result.get("UserData") or {}).get("Value"))
    else:
        add_error(record, result)


# ── launch templates ─────────────────────────────────────────────────────────
def _launch_templates(ctx: CollectContext, ec2: Any) -> List[Dict[str, Any]]:
    listed = ctx.paginate(ec2, "describe_launch_templates", "LaunchTemplates", page_size=200)
    out = []
    for lt in sorted((t for t in listed.value if isinstance(t, dict) and t.get("LaunchTemplateId")),
                     key=lambda t: str(t["LaunchTemplateId"])):
        arn = ctx.arn("ec2", f"launch-template/{lt['LaunchTemplateId']}")
        record = {"LaunchTemplateId": lt["LaunchTemplateId"], "LaunchTemplateName": lt.get("LaunchTemplateName"),
                  "Arn": arn, "DefaultVersionNumber": lt.get("DefaultVersionNumber"),
                  "LatestVersionNumber": lt.get("LatestVersionNumber"), "CreateTime": lt.get("CreateTime"),
                  "CreatedBy": lt.get("CreatedBy"), "Tags": list(lt.get("Tags") or []), "Versions": None}
        result = ctx.call(ec2, "describe_launch_template_versions", item=arn,
                          LaunchTemplateId=lt["LaunchTemplateId"], Versions=["$Default", "$Latest"])
        if result.ok:
            versions = {v.get("VersionNumber"): _lt_version(v)
                        for v in result.get("LaunchTemplateVersions") or [] if isinstance(v, dict)}
            record["Versions"] = [versions[n] for n in sorted(versions, key=lambda n: (n is None, n or 0))]
        else:
            add_error(record, result)
        out.append(record)
    return out


def _lt_version(version: Dict[str, Any]) -> Dict[str, Any]:
    data = version.get("LaunchTemplateData") if isinstance(version.get("LaunchTemplateData"), dict) else {}
    digest = _userdata_digest(data.get("UserData"))
    out: Dict[str, Any] = {"VersionNumber": version.get("VersionNumber"),
                           "DefaultVersion": version.get("DefaultVersion")}
    out.update({key: data.get(key) for key in _LT_KEYS})
    out.update(UserDataPresent=digest["Present"], UserDataSha256=digest["Sha256"], UserDataLength=digest["Length"])
    return out


# ── images ───────────────────────────────────────────────────────────────────
def _images(ctx: CollectContext, ec2: Any) -> List[Dict[str, Any]]:
    listed = ctx.paginate(ec2, "describe_images", "Images", page_size=1000, Owners=["self"])
    out = []
    for image in sorted((i for i in listed.value if isinstance(i, dict) and i.get("ImageId")),
                        key=lambda i: str(i["ImageId"])):
        arn = ctx.arn("ec2", f"image/{image['ImageId']}", account="")
        record = {"ImageId": image["ImageId"], "Arn": arn, "Name": image.get("Name"), "Public": image.get("Public"),
                  "State": image.get("State"), "CreationDate": image.get("CreationDate"),
                  "OwnerId": image.get("OwnerId"), "PlatformDetails": image.get("PlatformDetails"),
                  "SharedAccounts": None, "SharedOrganizations": None, "SharedOrganizationalUnits": None}
        result = ctx.call(ec2, "describe_image_attribute", item=arn, ImageId=image["ImageId"],
                          Attribute="launchPermission")
        if result.ok:
            perms = [p for p in result.get("LaunchPermissions") or [] if isinstance(p, dict)]
            record["SharedAccounts"] = sorted({p["UserId"] for p in perms if p.get("UserId")})
            record["SharedOrganizations"] = sorted({p["OrganizationArn"] for p in perms if p.get("OrganizationArn")})
            record["SharedOrganizationalUnits"] = sorted({p["OrganizationalUnitArn"] for p in perms
                                                          if p.get("OrganizationalUnitArn")})
        else:
            add_error(record, result)
        out.append(record)
    return out
