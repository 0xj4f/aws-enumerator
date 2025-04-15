import os
import json

def enumerate(session, path):
    os.makedirs(path, exist_ok=True)
    ec2_client = session.client("ec2")

    # VPCs
    vpcs = ec2_client.describe_vpcs()["Vpcs"]
    with open(f"{path}/vpcs.json", "w") as f:
        json.dump(vpcs, f, indent=2, default=str)

    # Subnets
    subnets = ec2_client.describe_subnets()["Subnets"]
    with open(f"{path}/subnets.json", "w") as f:
        json.dump(subnets, f, indent=2, default=str)

    # Route Tables
    route_tables = ec2_client.describe_route_tables()["RouteTables"]
    with open(f"{path}/route_tables.json", "w") as f:
        json.dump(route_tables, f, indent=2, default=str)

    # Internet Gateways
    igws = ec2_client.describe_internet_gateways()["InternetGateways"]
    with open(f"{path}/internet_gateways.json", "w") as f:
        json.dump(igws, f, indent=2, default=str)

    # NAT Gateways
    nat_gateways = ec2_client.describe_nat_gateways()["NatGateways"]
    with open(f"{path}/nat_gateways.json", "w") as f:
        json.dump(nat_gateways, f, indent=2, default=str)

    # Network ACLs
    nacls = ec2_client.describe_network_acls()["NetworkAcls"]
    with open(f"{path}/nacls.json", "w") as f:
        json.dump(nacls, f, indent=2, default=str)

    # VPC Endpoints
    vpc_endpoints = ec2_client.describe_vpc_endpoints()["VpcEndpoints"]
    with open(f"{path}/vpc_endpoints.json", "w") as f:
        json.dump(vpc_endpoints, f, indent=2, default=str)

    # DHCP Options
    dhcp_options = ec2_client.describe_dhcp_options()["DhcpOptions"]
    with open(f"{path}/dhcp_options.json", "w") as f:
        json.dump(dhcp_options, f, indent=2, default=str)

    # VPC Peering Connections
    peering_connections = ec2_client.describe_vpc_peering_connections()["VpcPeeringConnections"]
    with open(f"{path}/vpc_peering_connections.json", "w") as f:
        json.dump(peering_connections, f, indent=2, default=str)
