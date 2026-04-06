"""
IAM Enumeration Module

Collects:
- Users (enriched: access keys, MFA, login profile, permission boundaries)
- Groups (with attached policies)
- Roles (with attached policies)
- Custom policies (with full policy document content)
- Inline policies (per user, role, group)
- User-to-group memberships
- Account password policy & summary

reports/{account}/{region}/iam/
├── users.json
├── groups.json
├── roles.json
├── policies.json
├── user_group_memberships.json
├── role_attached_policies.json
├── user_attached_policies.json
├── group_attached_policies.json
├── account_password_policy.json
├── account_summary.json
├── policy_documents/{policy_name}_v{N}.json
├── inline_policies/
│   ├── users/{username}.json
│   ├── roles/{rolename}.json
│   └── groups/{groupname}.json
└── permission_boundaries/{entity_name}.json
"""

import json
import os
from botocore.exceptions import ClientError


def _paginate_iam(iam_client, method_name, key, **kwargs):
    """Generic IAM paginator handling Marker/IsTruncated pattern."""
    results = []
    marker = None
    while True:
        if marker:
            kwargs['Marker'] = marker
        response = getattr(iam_client, method_name)(**kwargs)
        results.extend(response.get(key, []))
        if response.get('IsTruncated', False):
            marker = response['Marker']
        else:
            break
    return results


def _enumerate_account_level(iam_client, path):
    """Fetch account password policy and account summary."""
    # Account password policy
    try:
        password_policy = iam_client.get_account_password_policy()
        with open(f"{path}/account_password_policy.json", "w") as f:
            json.dump(password_policy.get('PasswordPolicy', {}), f, indent=2, default=str)
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            with open(f"{path}/account_password_policy.json", "w") as f:
                json.dump({"Status": "No password policy configured"}, f, indent=2)
        else:
            with open(f"{path}/account_password_policy.json", "w") as f:
                json.dump({"Error": str(e)}, f, indent=2)

    # Account summary
    try:
        summary = iam_client.get_account_summary()
        with open(f"{path}/account_summary.json", "w") as f:
            json.dump(summary.get('SummaryMap', {}), f, indent=2, default=str)
    except ClientError as e:
        with open(f"{path}/account_summary.json", "w") as f:
            json.dump({"Error": str(e)}, f, indent=2)


def _enumerate_users(iam_client, path):
    """Enumerate users with enriched data: access keys, MFA, login profile."""
    users = _paginate_iam(iam_client, 'list_users', 'Users')

    enriched_users = []
    user_group_map = {}
    user_attached_policies = {}

    for user in users:
        username = user['UserName']
        user_data = {
            "UserName": username,
            "UserId": user.get('UserId', ''),
            "Arn": user.get('Arn', ''),
            "CreateDate": str(user.get('CreateDate', '')),
            "PasswordLastUsed": str(user.get('PasswordLastUsed', '')),
            "Path": user.get('Path', '/'),
            "Tags": user.get('Tags', []),
        }

        # Access keys
        try:
            keys = iam_client.list_access_keys(UserName=username)
            user_data["AccessKeys"] = [
                {
                    "AccessKeyId": k['AccessKeyId'],
                    "Status": k['Status'],
                    "CreateDate": str(k['CreateDate'])
                }
                for k in keys.get('AccessKeyMetadata', [])
            ]
        except ClientError as e:
            user_data["AccessKeysError"] = str(e)

        # MFA devices
        try:
            mfa = iam_client.list_mfa_devices(UserName=username)
            user_data["MFADevices"] = [
                {
                    "SerialNumber": d['SerialNumber'],
                    "EnableDate": str(d.get('EnableDate', ''))
                }
                for d in mfa.get('MFADevices', [])
            ]
        except ClientError as e:
            user_data["MFADevicesError"] = str(e)

        # Login profile (console access)
        try:
            login_profile = iam_client.get_login_profile(UserName=username)
            user_data["HasLoginProfile"] = True
            user_data["LoginProfileCreateDate"] = str(
                login_profile['LoginProfile']['CreateDate']
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                user_data["HasLoginProfile"] = False
            else:
                user_data["LoginProfileError"] = str(e)

        # Permission boundary
        pb = user.get('PermissionsBoundary')
        user_data["PermissionsBoundary"] = pb if pb else None

        # Groups for this user
        try:
            user_groups = iam_client.list_groups_for_user(UserName=username)['Groups']
            user_group_map[username] = user_groups
        except ClientError as e:
            user_group_map[username] = {"Error": str(e)}

        # Attached policies for this user
        try:
            attached = _paginate_iam(
                iam_client, 'list_attached_user_policies', 'AttachedPolicies',
                UserName=username
            )
            user_attached_policies[username] = attached
        except ClientError as e:
            user_attached_policies[username] = {"Error": str(e)}

        enriched_users.append(user_data)

    # Save users
    with open(f"{path}/users.json", "w") as f:
        json.dump(enriched_users, f, indent=2, default=str)

    # Save user-group memberships
    with open(f"{path}/user_group_memberships.json", "w") as f:
        json.dump(user_group_map, f, indent=2, default=str)

    # Save user attached policies
    with open(f"{path}/user_attached_policies.json", "w") as f:
        json.dump(user_attached_policies, f, indent=2, default=str)

    return enriched_users


def _enumerate_groups(iam_client, path):
    """Enumerate groups with attached policies."""
    groups = _paginate_iam(iam_client, 'list_groups', 'Groups')

    with open(f"{path}/groups.json", "w") as f:
        json.dump(groups, f, indent=2, default=str)

    # Attached policies per group
    group_attached_policies = {}
    for group in groups:
        group_name = group['GroupName']
        try:
            attached = _paginate_iam(
                iam_client, 'list_attached_group_policies', 'AttachedPolicies',
                GroupName=group_name
            )
            group_attached_policies[group_name] = attached
        except ClientError as e:
            group_attached_policies[group_name] = {"Error": str(e)}

    with open(f"{path}/group_attached_policies.json", "w") as f:
        json.dump(group_attached_policies, f, indent=2, default=str)

    return groups


def _enumerate_roles(iam_client, path):
    """Enumerate roles with attached policies."""
    roles = _paginate_iam(iam_client, 'list_roles', 'Roles')

    with open(f"{path}/roles.json", "w") as f:
        json.dump(roles, f, indent=2, default=str)

    # Attached policies per role
    role_attached_policies = {}
    for role in roles:
        role_name = role['RoleName']
        try:
            attached = _paginate_iam(
                iam_client, 'list_attached_role_policies', 'AttachedPolicies',
                RoleName=role_name
            )
            role_attached_policies[role_name] = attached
        except ClientError as e:
            role_attached_policies[role_name] = {"Error": str(e)}

    with open(f"{path}/role_attached_policies.json", "w") as f:
        json.dump(role_attached_policies, f, indent=2, default=str)

    return roles


def _enumerate_policies(iam_client, path):
    """Enumerate custom policies and fetch their policy document content."""
    policies = _paginate_iam(iam_client, 'list_policies', 'Policies', Scope='Local')

    with open(f"{path}/policies.json", "w") as f:
        json.dump(policies, f, indent=2, default=str)

    # Fetch policy documents
    docs_dir = os.path.join(path, "policy_documents")
    os.makedirs(docs_dir, exist_ok=True)

    for policy in policies:
        policy_name = policy['PolicyName']
        policy_arn = policy['Arn']
        version_id = policy.get('DefaultVersionId', 'v1')

        try:
            version = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id
            )
            doc = {
                "PolicyName": policy_name,
                "PolicyArn": policy_arn,
                "VersionId": version_id,
                "Document": version['PolicyVersion']['Document']
            }
            safe_name = policy_name.replace('/', '_')
            with open(f"{docs_dir}/{safe_name}_{version_id}.json", "w") as f:
                json.dump(doc, f, indent=2, default=str)
        except ClientError as e:
            with open(f"{docs_dir}/{policy_name}_error.json", "w") as f:
                json.dump({"PolicyName": policy_name, "Error": str(e)}, f, indent=2)

    return policies


def _enumerate_inline_policies(iam_client, path, users, roles, groups):
    """Fetch inline policies for all users, roles, and groups."""
    inline_dir = os.path.join(path, "inline_policies")
    os.makedirs(os.path.join(inline_dir, "users"), exist_ok=True)
    os.makedirs(os.path.join(inline_dir, "roles"), exist_ok=True)
    os.makedirs(os.path.join(inline_dir, "groups"), exist_ok=True)

    # User inline policies
    for user in users:
        username = user['UserName'] if isinstance(user, dict) else user
        try:
            policy_names = iam_client.list_user_policies(UserName=username).get('PolicyNames', [])
            if not policy_names:
                continue
            inline_policies = {}
            for pname in policy_names:
                try:
                    pol = iam_client.get_user_policy(UserName=username, PolicyName=pname)
                    inline_policies[pname] = pol.get('PolicyDocument', {})
                except ClientError as e:
                    inline_policies[pname] = {"Error": str(e)}

            with open(f"{inline_dir}/users/{username}.json", "w") as f:
                json.dump({
                    "UserName": username,
                    "InlinePolicies": inline_policies
                }, f, indent=2, default=str)
        except ClientError:
            pass

    # Role inline policies
    for role in roles:
        rolename = role['RoleName'] if isinstance(role, dict) else role
        try:
            policy_names = iam_client.list_role_policies(RoleName=rolename).get('PolicyNames', [])
            if not policy_names:
                continue
            inline_policies = {}
            for pname in policy_names:
                try:
                    pol = iam_client.get_role_policy(RoleName=rolename, PolicyName=pname)
                    inline_policies[pname] = pol.get('PolicyDocument', {})
                except ClientError as e:
                    inline_policies[pname] = {"Error": str(e)}

            with open(f"{inline_dir}/roles/{rolename}.json", "w") as f:
                json.dump({
                    "RoleName": rolename,
                    "InlinePolicies": inline_policies
                }, f, indent=2, default=str)
        except ClientError:
            pass

    # Group inline policies
    for group in groups:
        groupname = group['GroupName'] if isinstance(group, dict) else group
        try:
            policy_names = iam_client.list_group_policies(GroupName=groupname).get('PolicyNames', [])
            if not policy_names:
                continue
            inline_policies = {}
            for pname in policy_names:
                try:
                    pol = iam_client.get_group_policy(GroupName=groupname, PolicyName=pname)
                    inline_policies[pname] = pol.get('PolicyDocument', {})
                except ClientError as e:
                    inline_policies[pname] = {"Error": str(e)}

            with open(f"{inline_dir}/groups/{groupname}.json", "w") as f:
                json.dump({
                    "GroupName": groupname,
                    "InlinePolicies": inline_policies
                }, f, indent=2, default=str)
        except ClientError:
            pass


def _enumerate_permission_boundaries(path, users, roles):
    """Extract permission boundaries from users and roles that have them."""
    pb_dir = os.path.join(path, "permission_boundaries")
    os.makedirs(pb_dir, exist_ok=True)

    for user in users:
        if isinstance(user, dict) and user.get('PermissionsBoundary'):
            with open(f"{pb_dir}/{user['UserName']}.json", "w") as f:
                json.dump({
                    "EntityType": "User",
                    "EntityName": user['UserName'],
                    "PermissionsBoundary": user['PermissionsBoundary']
                }, f, indent=2, default=str)

    for role in roles:
        if isinstance(role, dict) and role.get('PermissionsBoundary'):
            with open(f"{pb_dir}/{role['RoleName']}.json", "w") as f:
                json.dump({
                    "EntityType": "Role",
                    "EntityName": role['RoleName'],
                    "PermissionsBoundary": role['PermissionsBoundary']
                }, f, indent=2, default=str)


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m IAM Enumeration Starting...")
    os.makedirs(path, exist_ok=True)
    iam_client = session.client('iam')

    # Account-level data
    _enumerate_account_level(iam_client, path)

    # Core entities
    users = _enumerate_users(iam_client, path)
    groups = _enumerate_groups(iam_client, path)
    roles = _enumerate_roles(iam_client, path)
    policies = _enumerate_policies(iam_client, path)

    # Inline policies for all entity types
    _enumerate_inline_policies(iam_client, path, users, roles, groups)

    # Permission boundaries
    _enumerate_permission_boundaries(path, users, roles)

    print("    \033[1;32m[+]\033[0m IAM Enumeration Finished!")
