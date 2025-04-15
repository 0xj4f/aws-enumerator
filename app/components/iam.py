import boto3, json, os

def enumerate(session, path):
    os.makedirs(path, exist_ok=True)
    iam_client = session.client('iam')

    # Users
    users = iam_client.list_users()['Users']
    with open(f"{path}/users.json", "w") as f:
        json.dump(users, f, default=str, indent=2)

    # Roles
    roles = iam_client.list_roles()['Roles']
    with open(f"{path}/roles.json", "w") as f:
        json.dump(roles, f, default=str, indent=2)

    # Policies
    policies = iam_client.list_policies(Scope='Local')['Policies']
    with open(f"{path}/policies.json", "w") as f:
        json.dump(policies, f, default=str, indent=2)

    # Attached Policies per Role
    role_attached_policies = {}

    for role in roles:
        role_name = role['RoleName']
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
        role_attached_policies[role_name] = attached_policies

    with open(f"{path}/role_attached_policies.json", "w") as f:
        json.dump(role_attached_policies, f, default=str, indent=2)
