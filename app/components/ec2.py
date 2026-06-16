try:
    from app.utils.aws_utils import safe, save_json
except ImportError:
    from utils.aws_utils import safe, save_json


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m EC2 Enumeration Starting...")
    ec2_client = session.client("ec2")

    all_instances = []
    reservations = safe(
        "EC2 describe_instances",
        lambda: ec2_client.describe_instances().get("Reservations", []),
        default=[],
    )

    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            # Extract tags into a dict
            tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}

            # Extract security groups
            security_groups = [
                {"GroupId": sg.get("GroupId"), "GroupName": sg.get("GroupName")}
                for sg in instance.get("SecurityGroups", [])
            ]

            # Extract network interfaces
            network_interfaces = [
                {
                    "NetworkInterfaceId": ni.get("NetworkInterfaceId"),
                    "PrivateIpAddress": ni.get("PrivateIpAddress"),
                    "SubnetId": ni.get("SubnetId"),
                    "VpcId": ni.get("VpcId"),
                    "MacAddress": ni.get("MacAddress"),
                    "Status": ni.get("Status"),
                }
                for ni in instance.get("NetworkInterfaces", [])
            ]

            instance_data = {
                "InstanceId": instance.get("InstanceId"),
                "InstanceType": instance.get("InstanceType"),
                "State": instance.get("State", {}).get("Name"),
                "LaunchTime": str(instance.get("LaunchTime")),
                "AvailabilityZone": instance.get("Placement", {}).get("AvailabilityZone"),
                "AmiId": instance.get("ImageId"),
                "PublicIpAddress": instance.get("PublicIpAddress"),
                "PrivateIpAddress": instance.get("PrivateIpAddress"),
                "SubnetId": instance.get("SubnetId"),
                "VpcId": instance.get("VpcId"),
                "IamInstanceProfile": instance.get("IamInstanceProfile", {}),
                "SecurityGroups": security_groups,
                "NetworkInterfaces": network_interfaces,
                "MetadataOptions": {
                    "HttpTokens": instance.get("MetadataOptions", {}).get("HttpTokens"),
                    "HttpPutResponseHopLimit": instance.get("MetadataOptions", {}).get("HttpPutResponseHopLimit"),
                },
                "Monitoring": instance.get("Monitoring", {}).get("State"),
                "Tags": tags
            }

            all_instances.append(instance_data)

    save_json(path, "instances.json", all_instances)

    print("    \033[1;32m[+]\033[0m EC2 Enumeration Finished!")
