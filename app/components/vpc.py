import json, os

def enumerate(session, path):
    os.makedirs(path, exist_ok=True)
    ec2_client = session.client('ec2')

    # VPCs
    vpcs = ec2_client.describe_vpcs()['Vpcs']
    with open(f"{path}/vpcs.json", "w") as f:
        json.dump(vpcs, f, default=str, indent=2)

    # Subnets
    subnets = ec2_client.describe_subnets()['Subnets']
    with open(f"{path}/subnets.json", "w") as f:
        json.dump(subnets, f, default=str, indent=2)

    # Route Tables
    route_tables = ec2_client.describe_route_tables()['RouteTables']
    with open(f"{path}/route_tables.json", "w") as f:
        json.dump(route_tables, f, default=str, indent=2)

    # Internet Gateways
    igws = ec2_client.describe_internet_gateways()['InternetGateways']
    with open(f"{path}/internet_gateways.json", "w") as f:
        json.dump(igws, f, default=str, indent=2)

    # NAT Gateways
    try:
        nat_gateways = ec2_client.describe_nat_gateways()['NatGateways']
    except ec2_client.exceptions.ClientError as e:
        nat_gateways = []
    with open(f"{path}/nat_gateways.json", "w") as f:
        json.dump(nat_gateways, f, default=str, indent=2)

    # Network ACLs
    nacls = ec2_client.describe_network_acls()['NetworkAcls']
    with open(f"{path}/nacls.json", "w") as f:
        json.dump(nacls, f, default=str, indent=2)
