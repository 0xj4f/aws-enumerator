import json
import os

def enumerate(session, path):
    print("[+] Ec2 Enumeration Starting...")
    os.makedirs(path, exist_ok=True)
    ec2_client = session.client("ec2")

    all_instances = []

    response = ec2_client.describe_instances()
    reservations = response.get("Reservations", [])

    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            # Extract tags into a dict
            tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}

            instance_data = {
                "InstanceId": instance.get("InstanceId"),
                "InstanceType": instance.get("InstanceType"),
                "State": instance.get("State", {}).get("Name"),
                "LaunchTime": str(instance.get("LaunchTime")),
                "PublicIpAddress": instance.get("PublicIpAddress"),
                "PrivateIpAddress": instance.get("PrivateIpAddress"),
                "SubnetId": instance.get("SubnetId"),
                "VpcId": instance.get("VpcId"),
                "IamInstanceProfile": instance.get("IamInstanceProfile", {}),
                "MetadataOptions": {
                    "HttpTokens": instance.get("MetadataOptions", {}).get("HttpTokens"),
                    "HttpPutResponseHopLimit": instance.get("MetadataOptions", {}).get("HttpPutResponseHopLimit")
                },
                "Tags": tags
            }

            all_instances.append(instance_data)

    # Save to file
    with open(f"{path}/instances.json", "w") as f:
        json.dump(all_instances, f, indent=2, default=str)
        
    print("[+] Ec2 Enumeration Finished!")