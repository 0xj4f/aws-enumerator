try:
    from app.utils.aws_utils import safe, save_json
except ImportError:
    from utils.aws_utils import safe, save_json


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m VPC Enumeration Starting...")
    ec2 = session.client("ec2")

    # (output filename, response key, API call) — each call is isolated so one
    # AccessDenied/throttle doesn't abort the rest of the VPC enumeration.
    items = [
        ("vpcs.json",                    "Vpcs",                  ec2.describe_vpcs),
        ("subnets.json",                 "Subnets",               ec2.describe_subnets),
        ("route_tables.json",            "RouteTables",           ec2.describe_route_tables),
        ("internet_gateways.json",       "InternetGateways",      ec2.describe_internet_gateways),
        ("nat_gateways.json",            "NatGateways",           ec2.describe_nat_gateways),
        ("nacls.json",                   "NetworkAcls",           ec2.describe_network_acls),
        ("vpc_endpoints.json",           "VpcEndpoints",          ec2.describe_vpc_endpoints),
        ("dhcp_options.json",            "DhcpOptions",           ec2.describe_dhcp_options),
        ("vpc_peering_connections.json", "VpcPeeringConnections", ec2.describe_vpc_peering_connections),
    ]

    for filename, key, call in items:
        data = safe(f"VPC {key}", lambda c=call, k=key: c()[k], default=[])
        save_json(path, filename, data)

    print("    \033[1;32m[+]\033[0m VPC Enumeration Finished!")
