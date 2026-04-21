"""
IAM Policy Parser & Privilege Escalation Detection Engine

Reads collected IAM data from the report directory and produces:
- findings.json: Privesc paths, dangerous permissions, trust issues
- permission_map.json: Entity → effective permissions matrix
- trust_relationships.json: Role trust policy analysis
- summary.json: Severity counts and top findings

reports/{account}/{region}/analysis/
├── findings.json
├── permission_map.json
├── trust_relationships.json
├── s3_relationships.json
└── summary.json
"""

import json
import os
import fnmatch
from collections import defaultdict


# ──────────────────────────────────────────────────────────────
# Privilege Escalation Rules (20 patterns)
# ──────────────────────────────────────────────────────────────

PRIVESC_RULES = [
    # Direct policy manipulation
    {"id": "PRIVESC-001", "name": "CreatePolicyVersion", "severity": "CRITICAL",
     "actions": ["iam:CreatePolicyVersion"],
     "description": "Can create new policy version with arbitrary permissions",
     "remediation": "Restrict iam:CreatePolicyVersion to specific policy ARNs or remove"},

    {"id": "PRIVESC-002", "name": "SetDefaultPolicyVersion", "severity": "CRITICAL",
     "actions": ["iam:SetDefaultPolicyVersion"],
     "description": "Can activate older permissive policy versions",
     "remediation": "Remove iam:SetDefaultPolicyVersion or restrict to specific policies"},

    # Inline policy injection
    {"id": "PRIVESC-003", "name": "PutUserPolicy", "severity": "CRITICAL",
     "actions": ["iam:PutUserPolicy"],
     "description": "Can create arbitrary inline policy on any user",
     "remediation": "Remove iam:PutUserPolicy or restrict Resource to specific user ARNs"},

    {"id": "PRIVESC-004", "name": "PutGroupPolicy", "severity": "CRITICAL",
     "actions": ["iam:PutGroupPolicy"],
     "description": "Can create arbitrary inline policy on any group",
     "remediation": "Remove iam:PutGroupPolicy or restrict Resource to specific group ARNs"},

    {"id": "PRIVESC-005", "name": "PutRolePolicy", "severity": "CRITICAL",
     "actions": ["iam:PutRolePolicy"],
     "description": "Can create arbitrary inline policy on any role",
     "remediation": "Remove iam:PutRolePolicy or restrict Resource to specific role ARNs"},

    # Managed policy attachment
    {"id": "PRIVESC-006", "name": "AttachUserPolicy", "severity": "HIGH",
     "actions": ["iam:AttachUserPolicy"],
     "description": "Can attach managed policies (including AdministratorAccess) to users",
     "remediation": "Remove or restrict iam:AttachUserPolicy"},

    {"id": "PRIVESC-007", "name": "AttachGroupPolicy", "severity": "HIGH",
     "actions": ["iam:AttachGroupPolicy"],
     "description": "Can attach managed policies to groups",
     "remediation": "Remove or restrict iam:AttachGroupPolicy"},

    {"id": "PRIVESC-008", "name": "AttachRolePolicy", "severity": "HIGH",
     "actions": ["iam:AttachRolePolicy"],
     "description": "Can attach managed policies to roles",
     "remediation": "Remove or restrict iam:AttachRolePolicy"},

    # Credential theft / account takeover
    {"id": "PRIVESC-009", "name": "CreateAccessKey", "severity": "HIGH",
     "actions": ["iam:CreateAccessKey"],
     "description": "Can create access keys for other users",
     "remediation": "Restrict iam:CreateAccessKey Resource to self only (${aws:username})"},

    {"id": "PRIVESC-010", "name": "CreateLoginProfile", "severity": "HIGH",
     "actions": ["iam:CreateLoginProfile"],
     "description": "Can create console login for users without one",
     "remediation": "Restrict iam:CreateLoginProfile Resource to self only"},

    {"id": "PRIVESC-011", "name": "UpdateLoginProfile", "severity": "HIGH",
     "actions": ["iam:UpdateLoginProfile"],
     "description": "Can reset console passwords for other users",
     "remediation": "Restrict iam:UpdateLoginProfile Resource to self only"},

    {"id": "PRIVESC-012", "name": "AddUserToGroup", "severity": "MEDIUM",
     "actions": ["iam:AddUserToGroup"],
     "description": "Can add self or others to privileged groups",
     "remediation": "Remove or restrict iam:AddUserToGroup to specific groups"},

    # Trust policy manipulation
    {"id": "PRIVESC-013", "name": "UpdateAssumeRolePolicy", "severity": "CRITICAL",
     "actions": ["iam:UpdateAssumeRolePolicy"],
     "description": "Can modify role trust policies to allow self to assume any role",
     "remediation": "Remove iam:UpdateAssumeRolePolicy or restrict to specific role ARNs"},

    # PassRole + compute combos
    {"id": "PRIVESC-014", "name": "PassRole+Lambda", "severity": "CRITICAL",
     "actions_all": ["iam:PassRole"],
     "actions_any": ["lambda:CreateFunction", "lambda:UpdateFunctionCode"],
     "description": "Can pass privileged role to Lambda and execute arbitrary code",
     "remediation": "Restrict iam:PassRole Resource to specific role ARNs"},

    {"id": "PRIVESC-015", "name": "PassRole+EC2", "severity": "CRITICAL",
     "actions_all": ["iam:PassRole", "ec2:RunInstances"],
     "description": "Can launch EC2 with privileged role, access credentials via IMDS",
     "remediation": "Restrict iam:PassRole Resource to specific role ARNs"},

    {"id": "PRIVESC-016", "name": "PassRole+CloudFormation", "severity": "CRITICAL",
     "actions_all": ["iam:PassRole", "cloudformation:CreateStack"],
     "description": "Can create CloudFormation stack with privileged role",
     "remediation": "Restrict iam:PassRole and cloudformation:CreateStack"},

    {"id": "PRIVESC-017", "name": "PassRole+ECS", "severity": "HIGH",
     "actions_all": ["iam:PassRole"],
     "actions_any": ["ecs:RunTask", "ecs:StartTask", "ecs:RegisterTaskDefinition"],
     "description": "Can run ECS task with privileged role",
     "remediation": "Restrict iam:PassRole Resource to specific role ARNs"},

    {"id": "PRIVESC-018", "name": "PassRole+Glue", "severity": "HIGH",
     "actions_all": ["iam:PassRole"],
     "actions_any": ["glue:CreateDevEndpoint", "glue:UpdateDevEndpoint", "glue:CreateJob"],
     "description": "Can create Glue endpoint/job with privileged role",
     "remediation": "Restrict iam:PassRole Resource to specific role ARNs"},

    {"id": "PRIVESC-019", "name": "PassRole+CodeBuild", "severity": "HIGH",
     "actions_all": ["iam:PassRole"],
     "actions_any": ["codebuild:CreateProject", "codebuild:StartBuild"],
     "description": "Can create CodeBuild project with privileged role",
     "remediation": "Restrict iam:PassRole Resource to specific role ARNs"},

    {"id": "PRIVESC-020", "name": "PassRole+SageMaker", "severity": "HIGH",
     "actions_all": ["iam:PassRole", "sagemaker:CreateNotebookInstance"],
     "description": "Can create SageMaker notebook with privileged role",
     "remediation": "Restrict iam:PassRole Resource to specific role ARNs"},
]

# ──────────────────────────────────────────────────────────────
# Dangerous Permission Rules
# ──────────────────────────────────────────────────────────────

DANGEROUS_RULES = [
    {"id": "DANGER-001", "severity": "CRITICAL",
     "action_pattern": "*", "resource_pattern": "*",
     "title": "Full administrator access (Action:* Resource:*)"},

    {"id": "DANGER-002", "severity": "CRITICAL",
     "action_pattern": "iam:*", "resource_pattern": "*",
     "title": "Full IAM control"},

    {"id": "DANGER-003", "severity": "HIGH",
     "action_pattern": "s3:*", "resource_pattern": "*",
     "title": "Unrestricted S3 access across all buckets"},

    {"id": "DANGER-004", "severity": "HIGH",
     "action_pattern": "ec2:*", "resource_pattern": "*",
     "title": "Full EC2 control"},

    {"id": "DANGER-005", "severity": "HIGH",
     "action_pattern": "sts:AssumeRole", "resource_pattern": "*",
     "title": "Can assume any role in the account"},

    {"id": "DANGER-006", "severity": "MEDIUM",
     "action_pattern": "iam:PassRole", "resource_pattern": "*",
     "title": "Unrestricted PassRole (can pass any role to any service)"},

    {"id": "DANGER-007", "severity": "HIGH",
     "action_pattern": "lambda:*", "resource_pattern": "*",
     "title": "Full Lambda control (code execution)"},

    {"id": "DANGER-008", "severity": "MEDIUM",
     "action_pattern": "secretsmanager:GetSecretValue", "resource_pattern": "*",
     "title": "Can read all secrets"},

    {"id": "DANGER-009", "severity": "MEDIUM",
     "action_pattern": "ssm:GetParameter*", "resource_pattern": "*",
     "title": "Can read all SSM parameters (may contain secrets)"},

    {"id": "DANGER-010", "severity": "HIGH",
     "action_pattern": "kms:Decrypt", "resource_pattern": "*",
     "title": "Can decrypt with any KMS key"},
]

# ──────────────────────────────────────────────────────────────
# S3 Action Classifications
# ──────────────────────────────────────────────────────────────

S3_READ_ACTIONS = [
    "s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket",
    "s3:ListBucketVersions", "s3:HeadObject", "s3:GetBucketLocation"
]
S3_WRITE_ACTIONS = [
    "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion",
    "s3:AbortMultipartUpload", "s3:RestoreObject"
]
S3_ADMIN_ACTIONS = [
    "s3:PutBucketPolicy", "s3:DeleteBucket", "s3:PutBucketAcl",
    "s3:PutBucketVersioning", "s3:PutEncryptionConfiguration",
    "s3:PutLifecycleConfiguration", "s3:PutBucketPublicAccessBlock"
]

S3_ACCESS_WEIGHTS = {
    "FULL_ACCESS": 0,
    "CAN_ADMIN": 0.5,
    "CAN_READ": 1,
    "CAN_WRITE": 1,
    "GRANTS_ACCESS": 1,
    "GRANTS_PUBLIC": 0,
    "GRANTS_CROSS_ACCOUNT": 2,
    "ENCRYPTED_BY": 3,
    "NOTIFIES": 5,
}

# ──────────────────────────────────────────────────────────────
# EC2 Action Classifications
# ──────────────────────────────────────────────────────────────

EC2_LAUNCH_ACTIONS = ["ec2:RunInstances"]
EC2_TERMINATE_ACTIONS = ["ec2:TerminateInstances"]
EC2_MANAGE_ACTIONS = [
    "ec2:StartInstances", "ec2:StopInstances", "ec2:RebootInstances",
    "ec2:ModifyInstanceAttribute"
]
EC2_CONNECT_ACTIONS = [
    "ssm:StartSession", "ssm:SendCommand",
    "ec2-instance-connect:SendSSHPublicKey"
]
EC2_SG_ADMIN_ACTIONS = [
    "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress",
    "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup"
]

EC2_ACCESS_WEIGHTS = {
    "INSTANCE_ROLE": 0,
    "EC2_FULL_ACCESS": 0,
    "CAN_LAUNCH": 1,
    "CAN_TERMINATE": 1,
    "CAN_MANAGE": 1,
    "CAN_CONNECT": 0.5,
    "CAN_ADMIN_SG": 1,
    "HAS_SG": 0,
    "SG_ALLOWS_FROM": 1,
    "PUBLIC_INBOUND": 0,
    "INTERNET_FACING": 0,
}


# ──────────────────────────────────────────────────────────────
# Data Loaders
# ──────────────────────────────────────────────────────────────

def _load_json(filepath):
    """Load a JSON file, return empty structure on failure."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _load_policy_documents(report_path):
    """Load all policy documents from policy_documents/ directory."""
    docs_dir = os.path.join(report_path, "iam", "policy_documents")
    docs = {}
    if not os.path.isdir(docs_dir):
        return docs
    for fname in os.listdir(docs_dir):
        if fname.endswith('.json') and not fname.endswith('_error.json'):
            data = _load_json(os.path.join(docs_dir, fname))
            if data and 'Document' in data:
                policy_name = data.get('PolicyName', fname.replace('.json', ''))
                docs[policy_name] = data
    return docs


def _load_inline_policies(report_path):
    """Load all inline policies from inline_policies/ directory."""
    inline = {"users": {}, "roles": {}, "groups": {}}
    inline_dir = os.path.join(report_path, "iam", "inline_policies")
    if not os.path.isdir(inline_dir):
        return inline

    for entity_type in ["users", "roles", "groups"]:
        type_dir = os.path.join(inline_dir, entity_type)
        if not os.path.isdir(type_dir):
            continue
        for fname in os.listdir(type_dir):
            if fname.endswith('.json'):
                data = _load_json(os.path.join(type_dir, fname))
                entity_name = fname.replace('.json', '')
                if data and 'InlinePolicies' in data:
                    inline[entity_type][entity_name] = data['InlinePolicies']
    return inline


def _load_roles(report_path):
    """Load roles from roles.json."""
    data = _load_json(os.path.join(report_path, "iam", "roles.json"))
    return data if isinstance(data, list) else []


def _load_users(report_path):
    """Load users from users.json."""
    data = _load_json(os.path.join(report_path, "iam", "users.json"))
    return data if isinstance(data, list) else []


def _load_attached(report_path, entity_type):
    """Load attached policies map for an entity type."""
    filename = f"{entity_type}_attached_policies.json"
    data = _load_json(os.path.join(report_path, "iam", filename))
    return data if isinstance(data, dict) else {}


def _load_user_group_memberships(report_path):
    """Load user-to-groups mapping."""
    data = _load_json(os.path.join(report_path, "iam", "user_group_memberships.json"))
    return data if isinstance(data, dict) else {}


# ──────────────────────────────────────────────────────────────
# Policy Statement Extraction
# ──────────────────────────────────────────────────────────────

def _normalize_to_list(value):
    """Ensure a value is a list (handles single string or list)."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []


def _extract_statements(policy_document):
    """Extract Allow statements from a policy document."""
    if not isinstance(policy_document, dict):
        return []
    statements = policy_document.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]
    return [s for s in statements if isinstance(s, dict) and s.get('Effect') == 'Allow']


def _action_matches(pattern, action):
    """Check if an IAM action pattern matches a specific action using fnmatch."""
    return fnmatch.fnmatch(action.lower(), pattern.lower())


def _entity_has_action(entity_actions, target_action):
    """Check if an entity's action set includes a target action (with wildcard matching)."""
    for action in entity_actions:
        if _action_matches(action, target_action):
            return True
        if _action_matches(target_action, action):
            return True
    return False


# ──────────────────────────────────────────────────────────────
# Permission Map Builder
# ──────────────────────────────────────────────────────────────

def _build_permission_map(users, roles, role_attached, user_attached, group_attached,
                          policy_docs, inline_policies, user_groups):
    """Build a map of entity → effective permissions."""
    perm_map = {"users": {}, "roles": {}, "groups": {}}

    # Process users
    for user in users:
        username = user.get('UserName', '')
        if not username:
            continue
        user_entry = {
            "arn": user.get('Arn', ''),
            "attached_policies": [],
            "inline_policies": [],
            "groups": [],
            "effective_statements": []
        }

        # Attached policies
        attached = user_attached.get(username, [])
        if isinstance(attached, list):
            for pol in attached:
                pol_name = pol.get('PolicyName', '')
                user_entry["attached_policies"].append(pol_name)
                if pol_name in policy_docs:
                    doc = policy_docs[pol_name].get('Document', {})
                    for stmt in _extract_statements(doc):
                        user_entry["effective_statements"].append({
                            "actions": _normalize_to_list(stmt.get('Action', [])),
                            "resources": _normalize_to_list(stmt.get('Resource', [])),
                            "source": pol_name,
                            "source_type": "managed"
                        })

        # Inline policies
        user_inline = inline_policies.get("users", {}).get(username, {})
        for pol_name, doc in user_inline.items():
            if isinstance(doc, dict) and 'Error' not in doc:
                user_entry["inline_policies"].append(pol_name)
                for stmt in _extract_statements(doc):
                    user_entry["effective_statements"].append({
                        "actions": _normalize_to_list(stmt.get('Action', [])),
                        "resources": _normalize_to_list(stmt.get('Resource', [])),
                        "source": pol_name,
                        "source_type": "inline"
                    })

        # Group memberships
        groups_for_user = user_groups.get(username, [])
        if isinstance(groups_for_user, list):
            for g in groups_for_user:
                gname = g.get('GroupName', '') if isinstance(g, dict) else str(g)
                user_entry["groups"].append(gname)

        perm_map["users"][username] = user_entry

    # Process roles
    for role in roles:
        rolename = role.get('RoleName', '')
        if not rolename:
            continue
        role_entry = {
            "arn": role.get('Arn', ''),
            "attached_policies": [],
            "inline_policies": [],
            "effective_statements": []
        }

        attached = role_attached.get(rolename, [])
        if isinstance(attached, list):
            for pol in attached:
                pol_name = pol.get('PolicyName', '')
                role_entry["attached_policies"].append(pol_name)
                if pol_name in policy_docs:
                    doc = policy_docs[pol_name].get('Document', {})
                    for stmt in _extract_statements(doc):
                        role_entry["effective_statements"].append({
                            "actions": _normalize_to_list(stmt.get('Action', [])),
                            "resources": _normalize_to_list(stmt.get('Resource', [])),
                            "source": pol_name,
                            "source_type": "managed"
                        })

        role_inline = inline_policies.get("roles", {}).get(rolename, {})
        for pol_name, doc in role_inline.items():
            if isinstance(doc, dict) and 'Error' not in doc:
                role_entry["inline_policies"].append(pol_name)
                for stmt in _extract_statements(doc):
                    role_entry["effective_statements"].append({
                        "actions": _normalize_to_list(stmt.get('Action', [])),
                        "resources": _normalize_to_list(stmt.get('Resource', [])),
                        "source": pol_name,
                        "source_type": "inline"
                    })

        perm_map["roles"][rolename] = role_entry

    # Process groups
    for gname, attached_list in group_attached.items():
        group_entry = {
            "attached_policies": [],
            "inline_policies": [],
            "effective_statements": []
        }

        if isinstance(attached_list, list):
            for pol in attached_list:
                pol_name = pol.get('PolicyName', '')
                group_entry["attached_policies"].append(pol_name)
                if pol_name in policy_docs:
                    doc = policy_docs[pol_name].get('Document', {})
                    for stmt in _extract_statements(doc):
                        group_entry["effective_statements"].append({
                            "actions": _normalize_to_list(stmt.get('Action', [])),
                            "resources": _normalize_to_list(stmt.get('Resource', [])),
                            "source": pol_name,
                            "source_type": "managed"
                        })

        group_inline = inline_policies.get("groups", {}).get(gname, {})
        for pol_name, doc in group_inline.items():
            if isinstance(doc, dict) and 'Error' not in doc:
                group_entry["inline_policies"].append(pol_name)
                for stmt in _extract_statements(doc):
                    group_entry["effective_statements"].append({
                        "actions": _normalize_to_list(stmt.get('Action', [])),
                        "resources": _normalize_to_list(stmt.get('Resource', [])),
                        "source": pol_name,
                        "source_type": "inline"
                    })

        perm_map["groups"][gname] = group_entry

    return perm_map


# ──────────────────────────────────────────────────────────────
# Privilege Escalation Detection
# ──────────────────────────────────────────────────────────────

def _get_all_actions_for_entity(entity_data):
    """Collect all allowed actions for an entity from its effective statements."""
    actions = set()
    for stmt in entity_data.get('effective_statements', []):
        for action in stmt.get('actions', []):
            actions.add(action)
    return actions


def _find_statement_source(entity_data, action):
    """Find which policy grants a specific action."""
    for stmt in entity_data.get('effective_statements', []):
        for a in stmt.get('actions', []):
            if _action_matches(a, action) or _action_matches(action, a):
                return {
                    "source": stmt.get('source', 'unknown'),
                    "source_type": stmt.get('source_type', 'unknown'),
                    "resources": stmt.get('resources', [])
                }
    return {"source": "unknown", "source_type": "unknown", "resources": []}


def _detect_privesc_paths(permission_map):
    """Detect privilege escalation paths across all entities."""
    findings = []

    for entity_type in ["users", "roles"]:
        for entity_name, entity_data in permission_map.get(entity_type, {}).items():
            all_actions = _get_all_actions_for_entity(entity_data)
            if not all_actions:
                continue

            for rule in PRIVESC_RULES:
                matched = False

                if "actions" in rule:
                    # Simple rule: all listed actions must be present
                    matched = all(
                        _entity_has_action(all_actions, a)
                        for a in rule["actions"]
                    )

                elif "actions_all" in rule:
                    # Combo rule: all 'actions_all' must be present
                    has_all = all(
                        _entity_has_action(all_actions, a)
                        for a in rule["actions_all"]
                    )
                    if has_all:
                        if "actions_any" in rule:
                            # Plus at least one from 'actions_any'
                            matched = any(
                                _entity_has_action(all_actions, a)
                                for a in rule["actions_any"]
                            )
                        else:
                            matched = True

                if matched:
                    # Find the source policy for the first matching action
                    trigger_action = (rule.get("actions") or rule.get("actions_all", []))[0]
                    source_info = _find_statement_source(entity_data, trigger_action)

                    findings.append({
                        "id": rule["id"],
                        "severity": rule["severity"],
                        "category": "privilege_escalation",
                        "title": f"{rule['name']}: {rule['description']}",
                        "entity": f"{entity_type.rstrip('s')}/{entity_name}",
                        "entity_arn": entity_data.get("arn", ""),
                        "description": f"{entity_type.rstrip('s').title()} '{entity_name}' "
                                       f"has {rule['name']} privilege escalation path. "
                                       f"{rule['description']}.",
                        "matched_actions": rule.get("actions", rule.get("actions_all", [])),
                        "source_policy": source_info["source"],
                        "source_type": source_info["source_type"],
                        "resource": source_info["resources"],
                        "remediation": rule.get("remediation", "Review and restrict permissions")
                    })

    return findings


# ──────────────────────────────────────────────────────────────
# Dangerous Permission Detection
# ──────────────────────────────────────────────────────────────

def _detect_dangerous_permissions(permission_map):
    """Detect overly permissive or dangerous permission patterns."""
    findings = []

    for entity_type in ["users", "roles", "groups"]:
        for entity_name, entity_data in permission_map.get(entity_type, {}).items():
            for stmt in entity_data.get('effective_statements', []):
                actions = stmt.get('actions', [])
                resources = stmt.get('resources', [])

                for rule in DANGEROUS_RULES:
                    action_match = any(
                        _action_matches(a, rule["action_pattern"]) or
                        _action_matches(rule["action_pattern"], a)
                        for a in actions
                    )
                    resource_match = any(
                        r == rule["resource_pattern"] or r == "*"
                        for r in resources
                    ) if rule["resource_pattern"] == "*" else True

                    if action_match and resource_match:
                        findings.append({
                            "id": rule["id"],
                            "severity": rule["severity"],
                            "category": "dangerous_permission",
                            "title": rule["title"],
                            "entity": f"{entity_type.rstrip('s')}/{entity_name}",
                            "entity_arn": entity_data.get("arn", ""),
                            "description": f"{entity_type.rstrip('s').title()} '{entity_name}' "
                                           f"has {rule['title']}.",
                            "matched_actions": actions,
                            "source_policy": stmt.get("source", "unknown"),
                            "source_type": stmt.get("source_type", "unknown"),
                            "resource": resources,
                            "remediation": "Restrict to specific actions and resource ARNs"
                        })

    return findings


# ──────────────────────────────────────────────────────────────
# Trust Policy Analysis
# ──────────────────────────────────────────────────────────────

def _extract_principals(principal):
    """Extract principal entries from a Principal field."""
    principals = []
    if isinstance(principal, str):
        principals.append({"type": "AWS", "value": principal})
        return principals

    if isinstance(principal, dict):
        for ptype, pvalues in principal.items():
            if isinstance(pvalues, str):
                pvalues = [pvalues]
            for pv in pvalues:
                principals.append({"type": ptype, "value": pv})

    return principals


def _extract_account_from_arn(arn):
    """Extract account ID from an ARN."""
    if not isinstance(arn, str):
        return None
    parts = arn.split(':')
    if len(parts) >= 5:
        return parts[4] if parts[4] else None
    return None


def _analyze_trust_policies(roles, account_id=None):
    """Analyze role trust policies for cross-account access and wildcards."""
    trust_relationships = []
    findings = []

    for role in roles:
        trust_doc = role.get('AssumeRolePolicyDocument', {})
        if isinstance(trust_doc, str):
            try:
                trust_doc = json.loads(trust_doc)
            except json.JSONDecodeError:
                continue

        role_account = _extract_account_from_arn(role.get('Arn', ''))

        for stmt in trust_doc.get('Statement', []):
            if stmt.get('Effect') != 'Allow':
                continue

            principals = _extract_principals(stmt.get('Principal', {}))
            conditions = stmt.get('Condition', {})

            for principal in principals:
                principal_account = _extract_account_from_arn(principal['value'])
                is_cross_account = (
                    principal_account is not None and
                    role_account is not None and
                    principal_account != role_account
                )
                is_wildcard = principal['value'] == '*'

                trust_entry = {
                    "role_name": role['RoleName'],
                    "role_arn": role.get('Arn', ''),
                    "trusted_principal": principal['value'],
                    "principal_type": principal['type'],
                    "conditions": conditions if conditions else None,
                    "is_cross_account": is_cross_account,
                    "is_wildcard": is_wildcard
                }
                trust_relationships.append(trust_entry)

                # Flag risky trust configs
                if is_wildcard and not conditions:
                    findings.append({
                        "id": "TRUST-001",
                        "severity": "CRITICAL",
                        "category": "trust_policy",
                        "title": "Role trusts wildcard principal without conditions",
                        "entity": f"role/{role['RoleName']}",
                        "entity_arn": role.get('Arn', ''),
                        "description": f"Role '{role['RoleName']}' has Principal: * "
                                       f"without Condition constraints. Any AWS account "
                                       f"can assume this role.",
                        "matched_actions": ["sts:AssumeRole"],
                        "source_policy": "AssumeRolePolicyDocument",
                        "source_type": "trust_policy",
                        "resource": [role.get('Arn', '')],
                        "remediation": "Add Condition constraints or restrict Principal to specific accounts"
                    })

                if is_cross_account:
                    findings.append({
                        "id": "TRUST-002",
                        "severity": "MEDIUM",
                        "category": "trust_policy",
                        "title": f"Cross-account trust to {principal_account}",
                        "entity": f"role/{role['RoleName']}",
                        "entity_arn": role.get('Arn', ''),
                        "description": f"Role '{role['RoleName']}' trusts principal "
                                       f"'{principal['value']}' from account {principal_account}.",
                        "matched_actions": ["sts:AssumeRole"],
                        "source_policy": "AssumeRolePolicyDocument",
                        "source_type": "trust_policy",
                        "resource": [role.get('Arn', '')],
                        "remediation": "Verify cross-account trust is intended and add ExternalId condition"
                    })

    return trust_relationships, findings


# ──────────────────────────────────────────────────────────────
# Report Generation
# ──────────────────────────────────────────────────────────────

def _generate_summary(findings):
    """Generate a summary of findings by severity and category."""
    severity_counts = defaultdict(int)
    category_counts = defaultdict(int)

    for f in findings:
        severity_counts[f["severity"]] += 1
        category_counts[f["category"]] += 1

    # Deduplicate findings by (id, entity) for counting
    unique_findings = set()
    for f in findings:
        unique_findings.add((f["id"], f["entity"]))

    return {
        "total_findings": len(findings),
        "unique_findings": len(unique_findings),
        "by_severity": dict(severity_counts),
        "by_category": dict(category_counts),
        "critical_count": severity_counts.get("CRITICAL", 0),
        "high_count": severity_counts.get("HIGH", 0),
        "medium_count": severity_counts.get("MEDIUM", 0),
    }


# ──────────────────────────────────────────────────────────────
# S3 Resource Relationship Analysis
# ──────────────────────────────────────────────────────────────

def _extract_bucket_from_arn(resource_arn):
    """Extract bucket name from an S3 ARN. Returns (bucket_pattern, is_wildcard)."""
    if not isinstance(resource_arn, str):
        return None, False
    if resource_arn == '*':
        return '*', True
    if not resource_arn.startswith('arn:aws:s3:::'):
        return None, False
    # Strip arn:aws:s3:::
    remainder = resource_arn[13:]
    # Split on / to get bucket name (ignore object path)
    bucket_part = remainder.split('/')[0]
    is_wildcard = '*' in bucket_part or '?' in bucket_part
    return bucket_part, is_wildcard


def _arn_matches_bucket(resource_arn, bucket_name):
    """Check if an S3 resource ARN matches a specific bucket name."""
    bucket_pattern, is_wildcard = _extract_bucket_from_arn(resource_arn)
    if bucket_pattern is None:
        return False
    if bucket_pattern == '*':
        return True
    if is_wildcard:
        return fnmatch.fnmatch(bucket_name, bucket_pattern)
    return bucket_pattern == bucket_name


def _classify_s3_access(actions, resources, bucket_name):
    """Classify what kind of S3 access a statement grants to a bucket.
    Returns set of access types and list of matched actions."""
    # Check if any resource matches the bucket
    resource_matches = any(_arn_matches_bucket(r, bucket_name) for r in resources)
    if not resource_matches:
        return set(), []

    access_types = set()
    matched_actions = []

    for action in actions:
        # Check for full S3 wildcard
        if _action_matches(action, 's3:*') or action == '*':
            access_types.add('FULL_ACCESS')
            matched_actions.append(action)
            continue

        for read_action in S3_READ_ACTIONS:
            if _action_matches(action, read_action):
                access_types.add('CAN_READ')
                matched_actions.append(action)
                break

        for write_action in S3_WRITE_ACTIONS:
            if _action_matches(action, write_action):
                access_types.add('CAN_WRITE')
                matched_actions.append(action)
                break

        for admin_action in S3_ADMIN_ACTIONS:
            if _action_matches(action, admin_action):
                access_types.add('CAN_ADMIN')
                matched_actions.append(action)
                break

    return access_types, list(set(matched_actions))


def _analyze_s3_relationships(report_path, permission_map, roles, users):
    """Analyze S3 resource relationships from IAM policies, bucket policies, encryption, and notifications."""
    edges = []
    findings = []

    # Load S3 data
    s3_path = os.path.join(report_path, "s3")
    buckets_data = _load_json(os.path.join(s3_path, "buckets.json"))
    if not isinstance(buckets_data, list):
        buckets_data = []

    bucket_names = [b.get('Name') for b in buckets_data if b.get('Name')]

    # Detect account ID from roles
    account_id = None
    for r in roles:
        account_id = _extract_account_from_arn(r.get('Arn', ''))
        if account_id:
            break

    # ── Step 1: IAM → Bucket edges (from permission_map) ──
    for entity_type in ["users", "roles"]:
        for entity_name, entity_data in permission_map.get(entity_type, {}).items():
            entity_arn = entity_data.get('arn', '')

            for stmt in entity_data.get('effective_statements', []):
                actions = stmt.get('actions', [])
                resources = stmt.get('resources', [])

                # Check if any action is S3-related
                has_s3 = any(
                    _action_matches(a, 's3:*') or a == '*' or a.lower().startswith('s3:')
                    for a in actions
                )
                if not has_s3:
                    continue

                for bucket_name in bucket_names:
                    access_types, matched = _classify_s3_access(actions, resources, bucket_name)
                    if not access_types:
                        continue

                    # Pick the highest-privilege access type for the edge
                    if 'FULL_ACCESS' in access_types:
                        edge_type = 'FULL_ACCESS'
                    elif 'CAN_ADMIN' in access_types:
                        edge_type = 'CAN_ADMIN'
                    elif 'CAN_WRITE' in access_types:
                        edge_type = 'CAN_WRITE'
                    else:
                        edge_type = 'CAN_READ'

                    is_wildcard = any(r == '*' for r in resources)
                    matched_resources = [r for r in resources if _arn_matches_bucket(r, bucket_name)]

                    edges.append({
                        "source": entity_arn,
                        "target": f"bucket:{bucket_name}",
                        "type": edge_type,
                        "weight": S3_ACCESS_WEIGHTS.get(edge_type, 1),
                        "category": "s3_access",
                        "direction": "entity_to_bucket",
                        "access_types": sorted(access_types),
                        "source_policy": stmt.get('source', 'unknown'),
                        "source_type": stmt.get('source_type', 'unknown'),
                        "matched_actions": matched,
                        "matched_resources": matched_resources,
                        "is_wildcard_resource": is_wildcard
                    })

    # ── Step 2: Bucket → Entity edges (from bucket policies) ──
    policies_dir = os.path.join(s3_path, "policies")
    if os.path.isdir(policies_dir):
        # Build ARN lookup for matching principals
        known_arns = set()
        for u in users:
            if u.get('Arn'):
                known_arns.add(u['Arn'])
        for r in roles:
            if r.get('Arn'):
                known_arns.add(r['Arn'])

        for bucket_name in bucket_names:
            policy_file = os.path.join(policies_dir, f"{bucket_name}.json")
            policy_doc = _load_json(policy_file)
            if not isinstance(policy_doc, dict):
                continue

            for stmt in policy_doc.get('Statement', []):
                effect = stmt.get('Effect', '')
                if effect != 'Allow':
                    continue

                principals = _extract_principals(stmt.get('Principal', {}))
                granted_actions = _normalize_to_list(stmt.get('Action', []))
                conditions = stmt.get('Condition', {})

                for principal in principals:
                    pval = principal['value']
                    ptype = principal['type']

                    # Public access
                    if pval == '*':
                        edge_type = 'GRANTS_PUBLIC'
                        edges.append({
                            "source": f"bucket:{bucket_name}",
                            "target": "principal:*",
                            "type": edge_type,
                            "weight": S3_ACCESS_WEIGHTS.get(edge_type, 0),
                            "category": "s3_grant",
                            "direction": "bucket_to_entity",
                            "granted_actions": granted_actions,
                            "has_conditions": bool(conditions),
                            "is_cross_account": False
                        })
                        # Only flag as finding if no conditions restrict it
                        if not conditions:
                            findings.append({
                                "id": "S3-PUBLIC-001",
                                "severity": "HIGH",
                                "category": "s3_public_access",
                                "title": f"Bucket '{bucket_name}' has public access via bucket policy",
                                "entity": f"bucket/{bucket_name}",
                                "entity_arn": f"arn:aws:s3:::{bucket_name}",
                                "description": f"S3 bucket '{bucket_name}' grants access to "
                                               f"Principal '*' for actions: {', '.join(granted_actions)}",
                                "matched_actions": granted_actions,
                                "source_policy": "BucketPolicy",
                                "source_type": "bucket_policy",
                                "resource": [f"arn:aws:s3:::{bucket_name}"],
                                "remediation": "Remove wildcard Principal or add restrictive Conditions"
                            })
                        continue

                    if ptype == 'Service':
                        continue  # Skip service principals (e.g. logging.s3.amazonaws.com)

                    # Check cross-account
                    principal_account = _extract_account_from_arn(pval)
                    is_cross_account = (
                        principal_account is not None and
                        account_id is not None and
                        principal_account != account_id
                    )

                    if is_cross_account:
                        edge_type = 'GRANTS_CROSS_ACCOUNT'
                    else:
                        edge_type = 'GRANTS_ACCESS'

                    # Use the principal ARN as target if it's a known entity, otherwise raw
                    target_id = pval if pval in known_arns else pval

                    edges.append({
                        "source": f"bucket:{bucket_name}",
                        "target": target_id,
                        "type": edge_type,
                        "weight": S3_ACCESS_WEIGHTS.get(edge_type, 1),
                        "category": "s3_grant",
                        "direction": "bucket_to_entity",
                        "granted_actions": granted_actions,
                        "has_conditions": bool(conditions),
                        "is_cross_account": is_cross_account
                    })

    # ── Step 3: KMS edges (from encryption configs) ──
    encryption_dir = os.path.join(s3_path, "encryption")
    if os.path.isdir(encryption_dir):
        for bucket_name in bucket_names:
            enc_data = _load_json(os.path.join(encryption_dir, f"{bucket_name}.json"))
            if not isinstance(enc_data, dict):
                continue
            rules = enc_data.get('Rules', [])
            for rule in rules:
                default_enc = rule.get('ApplyServerSideEncryptionByDefault', {})
                if default_enc.get('SSEAlgorithm') == 'aws:kms':
                    kms_key = default_enc.get('KMSMasterKeyID', '')
                    if kms_key:
                        edges.append({
                            "source": f"bucket:{bucket_name}",
                            "target": f"kms:{kms_key}",
                            "type": "ENCRYPTED_BY",
                            "weight": S3_ACCESS_WEIGHTS.get("ENCRYPTED_BY", 3),
                            "category": "kms",
                            "kms_key_arn": kms_key
                        })

    # ── Step 4: Notification edges (from notification configs) ──
    notifications_dir = os.path.join(s3_path, "notifications")
    if os.path.isdir(notifications_dir):
        for bucket_name in bucket_names:
            notif_data = _load_json(os.path.join(notifications_dir, f"{bucket_name}.json"))
            if not isinstance(notif_data, dict):
                continue

            # Lambda
            for config in notif_data.get('LambdaFunctionConfigurations', []):
                arn = config.get('LambdaFunctionArn', '')
                events = config.get('Events', [])
                if arn:
                    edges.append({
                        "source": f"bucket:{bucket_name}",
                        "target": f"lambda:{arn}",
                        "type": "NOTIFIES",
                        "weight": S3_ACCESS_WEIGHTS.get("NOTIFIES", 5),
                        "category": "notification",
                        "target_type": "lambda",
                        "events": events
                    })

            # SQS
            for config in notif_data.get('QueueConfigurations', []):
                arn = config.get('QueueArn', '')
                events = config.get('Events', [])
                if arn:
                    edges.append({
                        "source": f"bucket:{bucket_name}",
                        "target": f"sqs:{arn}",
                        "type": "NOTIFIES",
                        "weight": S3_ACCESS_WEIGHTS.get("NOTIFIES", 5),
                        "category": "notification",
                        "target_type": "sqs",
                        "events": events
                    })

            # SNS
            for config in notif_data.get('TopicConfigurations', []):
                arn = config.get('TopicArn', '')
                events = config.get('Events', [])
                if arn:
                    edges.append({
                        "source": f"bucket:{bucket_name}",
                        "target": f"sns:{arn}",
                        "type": "NOTIFIES",
                        "weight": S3_ACCESS_WEIGHTS.get("NOTIFIES", 5),
                        "category": "notification",
                        "target_type": "sns",
                        "events": events
                    })

    return {"edges": edges, "findings": findings}


# ──────────────────────────────────────────────────────────────
# EC2 Compute Relationship Analysis
# ──────────────────────────────────────────────────────────────

def _load_ec2_data(report_path):
    """Load EC2 instances, SGs, VPC data. Handles both single-region and --all mode."""
    instances = []
    security_groups = []
    route_tables = []
    internet_gateways = []
    subnets = []

    # Try local (single-region mode)
    local_instances = _load_json(os.path.join(report_path, "ec2", "instances.json"))
    if isinstance(local_instances, list) and local_instances:
        instances.extend(local_instances)
        sg_data = _load_json(os.path.join(report_path, "sg", "security_groups.json"))
        if isinstance(sg_data, list):
            security_groups.extend(sg_data)
        rt_data = _load_json(os.path.join(report_path, "vpc", "route_tables.json"))
        if isinstance(rt_data, list):
            route_tables.extend(rt_data)
        igw_data = _load_json(os.path.join(report_path, "vpc", "internet_gateways.json"))
        if isinstance(igw_data, list):
            internet_gateways.extend(igw_data)
        sub_data = _load_json(os.path.join(report_path, "vpc", "subnets.json"))
        if isinstance(sub_data, list):
            subnets.extend(sub_data)
    else:
        # --all mode: scan sibling region directories
        parent = os.path.dirname(report_path)
        if os.path.isdir(parent):
            for entry in os.listdir(parent):
                region_path = os.path.join(parent, entry)
                if not os.path.isdir(region_path) or entry == 'global':
                    continue
                inst = _load_json(os.path.join(region_path, "ec2", "instances.json"))
                if isinstance(inst, list):
                    instances.extend(inst)
                sg = _load_json(os.path.join(region_path, "sg", "security_groups.json"))
                if isinstance(sg, list):
                    security_groups.extend(sg)
                rt = _load_json(os.path.join(region_path, "vpc", "route_tables.json"))
                if isinstance(rt, list):
                    route_tables.extend(rt)
                igw = _load_json(os.path.join(region_path, "vpc", "internet_gateways.json"))
                if isinstance(igw, list):
                    internet_gateways.extend(igw)
                sub = _load_json(os.path.join(region_path, "vpc", "subnets.json"))
                if isinstance(sub, list):
                    subnets.extend(sub)

    return instances, security_groups, route_tables, internet_gateways, subnets


def _classify_ec2_access(actions):
    """Classify what kind of EC2 access a set of actions grants."""
    access_types = set()
    matched = []

    for action in actions:
        if _action_matches(action, 'ec2:*') or action == '*':
            access_types.add('EC2_FULL_ACCESS')
            matched.append(action)
            continue

        for a in EC2_LAUNCH_ACTIONS:
            if _action_matches(action, a):
                access_types.add('CAN_LAUNCH')
                matched.append(action)

        for a in EC2_TERMINATE_ACTIONS:
            if _action_matches(action, a):
                access_types.add('CAN_TERMINATE')
                matched.append(action)

        for a in EC2_MANAGE_ACTIONS:
            if _action_matches(action, a):
                access_types.add('CAN_MANAGE')
                matched.append(action)

        for a in EC2_CONNECT_ACTIONS:
            if _action_matches(action, a):
                access_types.add('CAN_CONNECT')
                matched.append(action)

        for a in EC2_SG_ADMIN_ACTIONS:
            if _action_matches(action, a):
                access_types.add('CAN_ADMIN_SG')
                matched.append(action)

    return access_types, list(set(matched))


def _is_resource_match_ec2(resources, instance_id):
    """Check if a resource list matches an EC2 instance (wildcard or specific)."""
    for r in resources:
        if r == '*':
            return True
        if isinstance(r, str) and instance_id in r:
            return True
        if isinstance(r, str) and 'ec2' in r.lower() and r.endswith('*'):
            return True
    return False


def _check_sg_public_access(sg_data):
    """Check if a security group allows inbound from 0.0.0.0/0 or ::/0.
    Returns list of (port_desc, cidr) tuples for public rules."""
    public_rules = []
    for rule in sg_data.get('InboundRules', []):
        # Check IPv4
        for ip_range in rule.get('IpRanges', []):
            cidr = ip_range.get('CidrIp', '')
            if cidr == '0.0.0.0/0':
                port_desc = _describe_port(rule)
                public_rules.append((port_desc, cidr))

        # Check IPv6
        for ip_range in rule.get('Ipv6Ranges', []):
            cidr = ip_range.get('CidrIpv6', '')
            if cidr == '::/0':
                port_desc = _describe_port(rule)
                public_rules.append((port_desc, cidr))

    return public_rules


def _describe_port(rule):
    """Create a human-readable port description from an SG rule."""
    protocol = rule.get('IpProtocol', '-1')
    if protocol == '-1':
        return 'all traffic'
    from_port = rule.get('FromPort', 0)
    to_port = rule.get('ToPort', 0)
    if from_port == to_port:
        return f"{from_port}/{protocol}"
    return f"{from_port}-{to_port}/{protocol}"


def _analyze_ec2_relationships(report_path, permission_map, roles):
    """Analyze EC2 compute relationships: instance→role, IAM→EC2 access,
    network exposure (SG/VPC), SG-to-SG references, IMDS findings."""
    edges = []
    findings = []

    instances, security_groups, route_tables, internet_gateways, subnets = _load_ec2_data(report_path)

    if not instances:
        return {"edges": [], "findings": []}

    # Build lookups
    sg_lookup = {sg.get('GroupId'): sg for sg in security_groups}
    role_lookup = {r.get('RoleName'): r for r in roles}
    role_arn_lookup = {r.get('Arn'): r for r in roles}

    # Build subnet → has_igw_route mapping
    subnet_has_igw = set()
    igw_vpcs = set()
    for igw in internet_gateways:
        for att in igw.get('Attachments', []):
            igw_vpcs.add(att.get('VpcId'))

    for rt in route_tables:
        has_igw_route = False
        for route in rt.get('Routes', []):
            gw = route.get('GatewayId', '')
            dest = route.get('DestinationCidrBlock', '')
            if gw.startswith('igw-') and dest == '0.0.0.0/0':
                has_igw_route = True
                break
        if has_igw_route:
            for assoc in rt.get('Associations', []):
                sid = assoc.get('SubnetId')
                if sid:
                    subnet_has_igw.add(sid)
            # If it's the main route table, all subnets in the VPC without explicit association get it
            for assoc in rt.get('Associations', []):
                if assoc.get('Main', False):
                    vpc_id = rt.get('VpcId')
                    for sub in subnets:
                        if sub.get('VpcId') == vpc_id:
                            subnet_has_igw.add(sub.get('SubnetId'))

    # ── Step 1: Instance → Role edges ──
    for inst in instances:
        profile = inst.get('IamInstanceProfile', {})
        if not profile or not profile.get('Arn'):
            continue

        profile_arn = profile['Arn']
        # Extract name: arn:aws:iam::ACCT:instance-profile/NAME
        profile_name = profile_arn.split('/')[-1] if '/' in profile_arn else ''
        if not profile_name:
            continue

        # Match to role
        role = role_lookup.get(profile_name)
        if role:
            edges.append({
                "source": inst['InstanceId'],
                "target": role['Arn'],
                "type": "INSTANCE_ROLE",
                "weight": EC2_ACCESS_WEIGHTS["INSTANCE_ROLE"],
                "category": "compute",
                "instance_profile_arn": profile_arn
            })

    # ── Step 2: IAM → EC2 access edges ──
    instance_ids = [inst['InstanceId'] for inst in instances]

    for entity_type in ["users", "roles"]:
        for entity_name, entity_data in permission_map.get(entity_type, {}).items():
            entity_arn = entity_data.get('arn', '')

            for stmt in entity_data.get('effective_statements', []):
                actions = stmt.get('actions', [])
                resources = stmt.get('resources', [])

                access_types, matched = _classify_ec2_access(actions)
                if not access_types:
                    continue

                # Pick highest privilege type
                if 'EC2_FULL_ACCESS' in access_types:
                    edge_type = 'EC2_FULL_ACCESS'
                elif 'CAN_CONNECT' in access_types:
                    edge_type = 'CAN_CONNECT'
                elif 'CAN_TERMINATE' in access_types:
                    edge_type = 'CAN_TERMINATE'
                elif 'CAN_MANAGE' in access_types:
                    edge_type = 'CAN_MANAGE'
                elif 'CAN_LAUNCH' in access_types:
                    edge_type = 'CAN_LAUNCH'
                else:
                    edge_type = 'CAN_ADMIN_SG'

                is_wildcard = any(r == '*' for r in resources)

                # Create edges to matching instances
                for inst_id in instance_ids:
                    if is_wildcard or _is_resource_match_ec2(resources, inst_id):
                        edges.append({
                            "source": entity_arn,
                            "target": inst_id,
                            "type": edge_type,
                            "weight": EC2_ACCESS_WEIGHTS.get(edge_type, 1),
                            "category": "ec2_access",
                            "access_types": sorted(access_types),
                            "source_policy": stmt.get('source', 'unknown'),
                            "source_type": stmt.get('source_type', 'unknown'),
                            "matched_actions": matched,
                            "is_wildcard_resource": is_wildcard
                        })
                        break  # One edge per entity→instance (avoid duplicates per statement)

    # ── Step 3: Instance → SG edges + network exposure ──
    seen_sgs = set()

    for inst in instances:
        inst_id = inst['InstanceId']
        has_public_ip = bool(inst.get('PublicIpAddress'))
        subnet_id = inst.get('SubnetId', '')

        for sg_ref in inst.get('SecurityGroups', []):
            sg_id = sg_ref.get('GroupId', '')
            if not sg_id:
                continue

            edges.append({
                "source": inst_id,
                "target": sg_id,
                "type": "HAS_SG",
                "weight": EC2_ACCESS_WEIGHTS["HAS_SG"],
                "category": "ec2_network"
            })

            # Check public exposure
            sg_data = sg_lookup.get(sg_id, {})
            if sg_data:
                public_rules = _check_sg_public_access(sg_data)
                if public_rules and has_public_ip:
                    ports = ', '.join(r[0] for r in public_rules)
                    findings.append({
                        "id": "EC2-EXPOSURE-001",
                        "severity": "HIGH",
                        "category": "ec2_exposure",
                        "title": f"Instance {inst_id} publicly exposed on {ports}",
                        "entity": f"instance/{inst_id}",
                        "entity_arn": inst_id,
                        "description": f"Instance '{inst_id}' has a public IP "
                                       f"({inst.get('PublicIpAddress')}) and security group "
                                       f"'{sg_id}' allows inbound from 0.0.0.0/0 on {ports}.",
                        "matched_actions": [],
                        "source_policy": sg_id,
                        "source_type": "security_group",
                        "resource": [inst_id],
                        "remediation": "Restrict inbound rules to specific CIDR ranges"
                    })

            seen_sgs.add(sg_id)

        # Internet-facing check (IGW route)
        if has_public_ip and subnet_id in subnet_has_igw:
            findings.append({
                "id": "EC2-INET-001",
                "severity": "MEDIUM",
                "category": "ec2_exposure",
                "title": f"Instance {inst_id} is internet-facing (IGW route)",
                "entity": f"instance/{inst_id}",
                "entity_arn": inst_id,
                "description": f"Instance '{inst_id}' has a public IP and its subnet "
                               f"'{subnet_id}' routes to an Internet Gateway.",
                "matched_actions": [],
                "source_policy": "route_table",
                "source_type": "vpc",
                "resource": [inst_id],
                "remediation": "Move to private subnet or remove public IP"
            })

        # IMDS vulnerability
        metadata = inst.get('MetadataOptions', {})
        if metadata.get('HttpTokens') == 'optional':
            findings.append({
                "id": "EC2-IMDS-001",
                "severity": "MEDIUM",
                "category": "ec2_imds",
                "title": f"Instance {inst_id} allows IMDSv1 (SSRF risk)",
                "entity": f"instance/{inst_id}",
                "entity_arn": inst_id,
                "description": f"Instance '{inst_id}' has HttpTokens set to 'optional', "
                               f"allowing IMDSv1. An SSRF vulnerability could expose "
                               f"instance role credentials.",
                "matched_actions": [],
                "source_policy": "MetadataOptions",
                "source_type": "ec2_config",
                "resource": [inst_id],
                "remediation": "Set HttpTokens to 'required' to enforce IMDSv2"
            })

    # ── Step 4: SG-to-SG references ──
    for sg_data in security_groups:
        sg_id = sg_data.get('GroupId', '')
        for rule in sg_data.get('InboundRules', []):
            for pair in rule.get('UserIdGroupPairs', []):
                source_sg = pair.get('GroupId', '')
                if source_sg and source_sg != sg_id:
                    port_desc = _describe_port(rule)
                    edges.append({
                        "source": source_sg,
                        "target": sg_id,
                        "type": "SG_ALLOWS_FROM",
                        "weight": EC2_ACCESS_WEIGHTS["SG_ALLOWS_FROM"],
                        "category": "ec2_network",
                        "ports": port_desc,
                        "direction": "inbound"
                    })

    return {"edges": edges, "findings": findings}


# ──────────────────────────────────────────────────────────────
# Main Entry Point
# ──────────────────────────────────────────────────────────────

def analyze(report_path):
    """Main entry point. Reads IAM data from report_path/iam/, produces analysis."""
    print("    \033[1;32m[+]\033[0m Policy Analysis Starting...")

    iam_path = os.path.join(report_path, "iam")
    if not os.path.isdir(iam_path):
        print("    \033[1;33m[!]\033[0m No IAM data found, skipping policy analysis")
        return

    analysis_dir = os.path.join(report_path, "analysis")
    os.makedirs(analysis_dir, exist_ok=True)

    # 1. Load all data
    policy_docs = _load_policy_documents(report_path)
    inline = _load_inline_policies(report_path)
    roles = _load_roles(report_path)
    users = _load_users(report_path)
    role_attached = _load_attached(report_path, 'role')
    user_attached = _load_attached(report_path, 'user')
    group_attached = _load_attached(report_path, 'group')
    user_groups = _load_user_group_memberships(report_path)

    # 2. Build permission map
    permission_map = _build_permission_map(
        users, roles, role_attached, user_attached, group_attached,
        policy_docs, inline, user_groups
    )

    # 3. Run detections
    findings = []
    findings.extend(_detect_privesc_paths(permission_map))
    findings.extend(_detect_dangerous_permissions(permission_map))

    trust_relationships, trust_findings = _analyze_trust_policies(roles)
    findings.extend(trust_findings)

    # 4. S3 resource relationships
    s3_relationships = _analyze_s3_relationships(report_path, permission_map, roles, users)
    findings.extend(s3_relationships.get("findings", []))
    s3_edge_count = len(s3_relationships.get("edges", []))

    # 5. EC2 compute relationships
    ec2_relationships = _analyze_ec2_relationships(report_path, permission_map, roles)
    findings.extend(ec2_relationships.get("findings", []))
    ec2_edge_count = len(ec2_relationships.get("edges", []))

    # 6. Save reports
    with open(os.path.join(analysis_dir, "findings.json"), "w") as f:
        json.dump({"findings": findings}, f, indent=2, default=str)

    with open(os.path.join(analysis_dir, "permission_map.json"), "w") as f:
        json.dump(permission_map, f, indent=2, default=str)

    with open(os.path.join(analysis_dir, "trust_relationships.json"), "w") as f:
        json.dump(trust_relationships, f, indent=2, default=str)

    with open(os.path.join(analysis_dir, "s3_relationships.json"), "w") as f:
        json.dump(s3_relationships, f, indent=2, default=str)

    with open(os.path.join(analysis_dir, "ec2_relationships.json"), "w") as f:
        json.dump(ec2_relationships, f, indent=2, default=str)

    summary = _generate_summary(findings)
    with open(os.path.join(analysis_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    # Print summary
    crit = summary["critical_count"]
    high = summary["high_count"]
    med = summary["medium_count"]
    total = summary["total_findings"]

    if total > 0:
        print(f"    \033[1;31m[!]\033[0m Findings: {crit} CRITICAL, {high} HIGH, {med} MEDIUM ({total} total)")
    else:
        print("    \033[1;32m[+]\033[0m No findings detected")

    if s3_edge_count > 0:
        print(f"    \033[1;32m[+]\033[0m S3 relationships: {s3_edge_count} edges discovered")

    if ec2_edge_count > 0:
        print(f"    \033[1;32m[+]\033[0m EC2 relationships: {ec2_edge_count} edges discovered")

    print("    \033[1;32m[+]\033[0m Policy Analysis Finished!")
