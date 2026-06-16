try:
    from app.utils.aws_utils import safe, save_json
except ImportError:
    from utils.aws_utils import safe, save_json


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m Security Groups Enumeration Starting...")
    ec2_client = session.client("ec2")

    security_groups = safe(
        "SG describe_security_groups",
        lambda: ec2_client.describe_security_groups()["SecurityGroups"],
        default=[],
    )

    detailed_sg_info = []
    for sg in security_groups:
        sg_info = {
            "GroupId": sg["GroupId"],
            "GroupName": sg.get("GroupName"),
            "Description": sg.get("Description"),
            "VpcId": sg.get("VpcId"),
            "InboundRules": sg.get("IpPermissions", []),
            "OutboundRules": sg.get("IpPermissionsEgress", [])
        }

        # Find associated ENIs (network interfaces) — isolated per group.
        enis = safe(
            f"SG {sg['GroupId']} describe_network_interfaces",
            lambda gid=sg["GroupId"]: ec2_client.describe_network_interfaces(
                Filters=[{"Name": "group-id", "Values": [gid]}]
            )["NetworkInterfaces"],
            default=[],
        )

        sg_info["AssociatedResources"] = [
            {
                "NetworkInterfaceId": eni["NetworkInterfaceId"],
                "PrivateIpAddress": eni.get("PrivateIpAddress"),
                "Attachment": eni.get("Attachment"),
                "Description": eni.get("Description"),
                "InstanceId": eni.get("Attachment", {}).get("InstanceId")
            }
            for eni in enis
        ]
        detailed_sg_info.append(sg_info)

    save_json(path, "security_groups.json", detailed_sg_info)

    print("    \033[1;32m[+]\033[0m Security Groups Enumeration Finished!")
