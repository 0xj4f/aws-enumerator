import json, os

def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m Security Groups Enumeration Starting...")
    os.makedirs(path, exist_ok=True)
    ec2_client = session.client("ec2")

    # Describe security groups
    response = ec2_client.describe_security_groups()
    security_groups = response["SecurityGroups"]

    # Prepare a detailed list
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

        # Find associated ENIs (network interfaces)
        enis = ec2_client.describe_network_interfaces(
            Filters=[
                {"Name": "group-id", "Values": [sg["GroupId"]]}
            ]
        )["NetworkInterfaces"]

        associated_resources = []
        for eni in enis:
            association = {
                "NetworkInterfaceId": eni["NetworkInterfaceId"],
                "PrivateIpAddress": eni.get("PrivateIpAddress"),
                "Attachment": eni.get("Attachment"),
                "Description": eni.get("Description"),
                "InstanceId": eni.get("Attachment", {}).get("InstanceId")
            }
            associated_resources.append(association)

        sg_info["AssociatedResources"] = associated_resources
        detailed_sg_info.append(sg_info)

    with open(f"{path}/security_groups.json", "w") as f:
        json.dump(detailed_sg_info, f, indent=2, default=str)

    print("    \033[1;32m[+]\033[0m Security Groups Enumeration Finished!")
