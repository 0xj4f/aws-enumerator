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

    # Load instance profile metadata for canonical profile→role mapping.
    # Without this, profiles with names that differ from their role names
    # (common for EKS managed node groups) get silently dropped.
    instance_profiles = _load_json(os.path.join(report_path, "iam", "instance_profiles.json"))
    if not isinstance(instance_profiles, list):
        # In --all mode, IAM lives in ../global/iam/
        parent = os.path.dirname(report_path)
        if os.path.isdir(parent):
            instance_profiles = _load_json(os.path.join(parent, "global", "iam", "instance_profiles.json"))
        if not isinstance(instance_profiles, list):
            instance_profiles = []

    profile_to_role_arn = {}  # profile_arn -> role_arn (from the profile's Roles[] array)
    for prof in instance_profiles:
        if not isinstance(prof, dict):
            continue
        prof_arn = prof.get('Arn')
        prof_roles = prof.get('Roles', [])
        if prof_arn and prof_roles and isinstance(prof_roles, list):
            first_role = prof_roles[0] if prof_roles else None
            if isinstance(first_role, dict):
                role_arn_in_prof = first_role.get('Arn')
                if role_arn_in_prof:
                    profile_to_role_arn[prof_arn] = role_arn_in_prof

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
        profile_name = profile_arn.split('/')[-1] if '/' in profile_arn else ''
        if not profile_name:
            continue

        # Primary: ARN-based lookup using instance profile metadata.
        # This works even when profile_name != role_name (e.g., EKS).
        role = None
        match_method = None
        role_arn_from_profile = profile_to_role_arn.get(profile_arn)
        if role_arn_from_profile:
            role = role_arn_lookup.get(role_arn_from_profile)
            if role:
                match_method = "arn"

        # Fallback: legacy name-based match (when profile metadata wasn't loaded)
        if not role:
            role = role_lookup.get(profile_name)
            if role:
                match_method = "name_fallback"

        if role:
            edges.append({
                "source": inst['InstanceId'],
                "target": role['Arn'],
                "type": "INSTANCE_ROLE",
                "weight": EC2_ACCESS_WEIGHTS["INSTANCE_ROLE"],
                "category": "compute",
                "instance_profile_arn": profile_arn,
                "match_method": match_method
            })
        else:
            # Profile exists but no role could be resolved — actionable misconfiguration
            # or sign that instance_profiles.json wasn't enumerated (insufficient IAM perms).
            findings.append({
                "id": "EC2-PROFILE-001",
                "severity": "MEDIUM",
                "category": "ec2_misconfig",
                "title": f"Instance {inst['InstanceId']} has unresolved instance profile",
                "entity": f"instance/{inst['InstanceId']}",
                "entity_arn": inst['InstanceId'],
                "description": f"Instance has IamInstanceProfile '{profile_arn}' "
                               f"but no IAM role could be resolved. The profile may be "
                               f"missing, deleted, in a different account, or "
                               f"iam:ListInstanceProfiles permission was unavailable "
                               f"during enumeration.",
                "matched_actions": [],
                "source_policy": profile_arn,
                "source_type": "ec2_config",
                "resource": [inst['InstanceId']],
                "remediation": "Verify the instance profile exists and contains a role; "
                               "ensure the enumerator has iam:ListInstanceProfiles permission"
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
# Secrets Manager + SSM Parameter Store Relationship Analysis
# ──────────────────────────────────────────────────────────────

SECRET_READ_ACTIONS = [
    "secretsmanager:GetSecretValue",
    "secretsmanager:DescribeSecret",
    "secretsmanager:ListSecretVersionIds",
    "secretsmanager:GetSecretValueBatch",
]
SECRET_WRITE_ACTIONS = [
    "secretsmanager:UpdateSecret",
    "secretsmanager:PutSecretValue",
    "secretsmanager:DeleteSecret",
    "secretsmanager:RotateSecret",
    "secretsmanager:PutResourcePolicy",
]
SSM_READ_ACTIONS = [
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParameterHistory",
    "ssm:GetParametersByPath",
    "ssm:DescribeParameters",
]

SECRETS_ACCESS_WEIGHTS = {
    "CAN_READ_SECRET": 1,
    "CAN_WRITE_SECRET": 1,
    "SECRET_ENCRYPTED_BY": 3,
    "SECRET_GRANTS_ACCESS": 1,
    "SECRET_GRANTS_CROSS_ACCOUNT": 2,
    "SECRET_GRANTS_PUBLIC": 0,
    "CAN_READ_PARAM": 1,
    "PARAM_ENCRYPTED_BY": 3,
}

# Patterns that suggest a parameter contains a credential
SENSITIVE_PARAM_PATTERNS = [
    "*password*", "*passwd*", "*secret*", "*token*",
    "*api[-_]key*", "*apikey*", "*credential*", "*cred*",
    "*private[-_]key*", "*db[-_]pass*",
]


def _arn_matches_secret(resource_arn, secret_arn):
    """Check if a policy resource ARN matches a Secrets Manager secret ARN.

    Secret ARN format: arn:aws:secretsmanager:REGION:ACCT:secret:NAME-suffix
    The trailing 6-char suffix is auto-generated; resources may match by full
    ARN, by name pattern, or by the *.
    """
    if not isinstance(resource_arn, str) or not secret_arn:
        return False
    if resource_arn == '*':
        return True
    if not resource_arn.startswith('arn:aws:secretsmanager:'):
        return False
    # Convert wildcard pattern matching
    return fnmatch.fnmatch(secret_arn.lower(), resource_arn.lower())


def _arn_matches_param(resource_arn, param_name, region, account_id):
    """Check if a resource ARN matches an SSM parameter.

    SSM Parameter ARN format: arn:aws:ssm:REGION:ACCT:parameter/NAME
    (the "parameter" prefix; name may include slashes for hierarchy)
    """
    if not isinstance(resource_arn, str):
        return False
    if resource_arn == '*':
        return True
    if not resource_arn.startswith('arn:aws:ssm:'):
        return False
    # Build the canonical parameter ARN. SSM parameter names can start with /
    # but the ARN form drops a leading slash and has "parameter/" prefix.
    name_for_arn = param_name.lstrip('/')
    canonical = f"arn:aws:ssm:{region or '*'}:{account_id or '*'}:parameter/{name_for_arn}"
    return (
        fnmatch.fnmatch(canonical.lower(), resource_arn.lower())
        or fnmatch.fnmatch(resource_arn.lower(), canonical.lower())
    )


def _classify_secret_access(actions):
    """Return a set of (CAN_READ_SECRET, CAN_WRITE_SECRET) and matched actions."""
    access = set()
    matched = []
    for action in actions:
        if _action_matches(action, 'secretsmanager:*') or action == '*':
            access.add('CAN_READ_SECRET')
            access.add('CAN_WRITE_SECRET')
            matched.append(action)
            continue
        for ra in SECRET_READ_ACTIONS:
            if _action_matches(action, ra):
                access.add('CAN_READ_SECRET')
                matched.append(action)
                break
        for wa in SECRET_WRITE_ACTIONS:
            if _action_matches(action, wa):
                access.add('CAN_WRITE_SECRET')
                matched.append(action)
                break
    return access, list(set(matched))


def _classify_param_access(actions):
    """Return whether actions grant SSM read access and matched actions."""
    matched = []
    for action in actions:
        if _action_matches(action, 'ssm:*') or action == '*':
            matched.append(action)
            return True, list(set(matched))
        for ra in SSM_READ_ACTIONS:
            if _action_matches(action, ra):
                matched.append(action)
    return (len(matched) > 0), list(set(matched))


def _looks_sensitive_param_name(name):
    """Heuristic: does the parameter name suggest credentials/secrets?"""
    n = (name or "").lower()
    return any(fnmatch.fnmatch(n, pat) for pat in SENSITIVE_PARAM_PATTERNS)


def _load_secrets_data(report_path):
    """Load Secrets Manager + SSM data, handling both single-region and --all modes."""
    secrets, resource_policies, params = [], {}, []

    def _load_region(region_path):
        sm_secrets = _load_json(os.path.join(region_path, "secretsmanager", "secrets.json"))
        if isinstance(sm_secrets, list):
            secrets.extend(sm_secrets)

        rp_dir = os.path.join(region_path, "secretsmanager", "resource_policies")
        if os.path.isdir(rp_dir):
            for fname in os.listdir(rp_dir):
                if fname.endswith('.json'):
                    rp = _load_json(os.path.join(rp_dir, fname))
                    if isinstance(rp, dict) and rp.get('SecretArn'):
                        resource_policies[rp['SecretArn']] = rp

        ssm_params = _load_json(os.path.join(region_path, "ssm", "parameters.json"))
        if isinstance(ssm_params, list):
            params.extend(ssm_params)

    # Try local (single-region mode)
    if os.path.isdir(os.path.join(report_path, "secretsmanager")) or \
       os.path.isdir(os.path.join(report_path, "ssm")):
        _load_region(report_path)
    else:
        # --all mode: scan sibling region dirs
        parent = os.path.dirname(report_path)
        if os.path.isdir(parent):
            for entry in os.listdir(parent):
                rp = os.path.join(parent, entry)
                if os.path.isdir(rp) and entry != 'global':
                    _load_region(rp)

    return secrets, resource_policies, params


def _analyze_secrets_relationships(report_path, permission_map, roles, users):
    """Build CAN_READ_SECRET / CAN_READ_PARAM and resource-policy edges + findings."""
    edges = []
    findings = []

    secrets, resource_policies, params = _load_secrets_data(report_path)
    if not secrets and not params:
        return {"edges": [], "findings": []}

    # Detect account ID from any role ARN
    account_id = None
    for r in roles:
        account_id = _extract_account_from_arn(r.get('Arn', ''))
        if account_id:
            break

    # Known principal ARNs (for matching resource policy principals to graph entities)
    known_arns = set()
    for u in users:
        if u.get('Arn'):
            known_arns.add(u['Arn'])
    for r in roles:
        if r.get('Arn'):
            known_arns.add(r['Arn'])

    # ── Step 1: IAM → Secret edges (from permission_map) ──
    for entity_type in ["users", "roles"]:
        for entity_name, entity_data in permission_map.get(entity_type, {}).items():
            entity_arn = entity_data.get('arn', '')

            for stmt in entity_data.get('effective_statements', []):
                actions = stmt.get('actions', [])
                resources = stmt.get('resources', [])

                # Secrets Manager
                has_sm = any(
                    _action_matches(a, 'secretsmanager:*') or a == '*' or
                    a.lower().startswith('secretsmanager:')
                    for a in actions
                )
                if has_sm:
                    access, matched_acts = _classify_secret_access(actions)
                    if access:
                        for secret in secrets:
                            secret_arn = secret.get('ARN')
                            if not secret_arn:
                                continue
                            if not any(_arn_matches_secret(r, secret_arn) for r in resources):
                                continue

                            secret_node = f"secret:{secret_arn}"
                            # Pick the higher-privilege edge type if both
                            if 'CAN_WRITE_SECRET' in access:
                                edge_type = 'CAN_WRITE_SECRET'
                            else:
                                edge_type = 'CAN_READ_SECRET'

                            edges.append({
                                "source": entity_arn,
                                "target": secret_node,
                                "type": edge_type,
                                "weight": SECRETS_ACCESS_WEIGHTS.get(edge_type, 1),
                                "category": "secrets",
                                "access_types": sorted(access),
                                "source_policy": stmt.get('source', 'unknown'),
                                "source_type": stmt.get('source_type', 'unknown'),
                                "matched_actions": matched_acts,
                                "is_wildcard_resource": any(r == '*' for r in resources),
                            })

                # SSM Parameters
                has_ssm = any(
                    _action_matches(a, 'ssm:*') or a == '*' or a.lower().startswith('ssm:')
                    for a in actions
                )
                if has_ssm:
                    grants_read, matched_acts = _classify_param_access(actions)
                    if grants_read:
                        for param in params:
                            pname = param.get('Name')
                            if not pname:
                                continue
                            if not any(
                                _arn_matches_param(r, pname, param.get('ARN', '').split(':')[3] if param.get('ARN') else None, account_id)
                                for r in resources
                            ):
                                continue

                            param_node = f"ssmparam:{param.get('ARN') or pname}"
                            edges.append({
                                "source": entity_arn,
                                "target": param_node,
                                "type": "CAN_READ_PARAM",
                                "weight": SECRETS_ACCESS_WEIGHTS.get("CAN_READ_PARAM", 1),
                                "category": "secrets",
                                "source_policy": stmt.get('source', 'unknown'),
                                "source_type": stmt.get('source_type', 'unknown'),
                                "matched_actions": matched_acts,
                                "is_wildcard_resource": any(r == '*' for r in resources),
                                "param_type": param.get('Type'),
                            })

    # ── Step 2: Secret KMS encryption edges ──
    for secret in secrets:
        secret_arn = secret.get('ARN')
        kms_key = secret.get('KmsKeyId')
        if secret_arn and kms_key:
            edges.append({
                "source": f"secret:{secret_arn}",
                "target": f"kms:{kms_key}",
                "type": "SECRET_ENCRYPTED_BY",
                "weight": SECRETS_ACCESS_WEIGHTS["SECRET_ENCRYPTED_BY"],
                "category": "kms",
                "kms_key_arn": kms_key,
            })

    # ── Step 3: SSM Parameter KMS edges ──
    for param in params:
        pname = param.get('Name')
        kms_key = param.get('KeyId')
        # Only SecureString uses KMS encryption (others use plain storage)
        if pname and kms_key and param.get('Type') == 'SecureString':
            param_node = f"ssmparam:{param.get('ARN') or pname}"
            edges.append({
                "source": param_node,
                "target": f"kms:{kms_key}",
                "type": "PARAM_ENCRYPTED_BY",
                "weight": SECRETS_ACCESS_WEIGHTS["PARAM_ENCRYPTED_BY"],
                "category": "kms",
                "kms_key_arn": kms_key,
            })

    # ── Step 4: Secret resource policy edges + findings ──
    for secret_arn, rp_data in resource_policies.items():
        policy_doc = rp_data.get('ResourcePolicy', {})
        if not isinstance(policy_doc, dict):
            continue

        for stmt in policy_doc.get('Statement', []):
            if stmt.get('Effect') != 'Allow':
                continue
            principals = _extract_principals(stmt.get('Principal', {}))
            granted_actions = _normalize_to_list(stmt.get('Action', []))
            conditions = stmt.get('Condition', {})

            for principal in principals:
                pval = principal['value']
                ptype = principal['type']

                if pval == '*':
                    edges.append({
                        "source": f"secret:{secret_arn}",
                        "target": "principal:*",
                        "type": "SECRET_GRANTS_PUBLIC",
                        "weight": SECRETS_ACCESS_WEIGHTS["SECRET_GRANTS_PUBLIC"],
                        "category": "secrets",
                        "granted_actions": granted_actions,
                        "has_conditions": bool(conditions),
                    })
                    if not conditions:
                        findings.append({
                            "id": "SECRET-PUB-001",
                            "severity": "HIGH",
                            "category": "secrets_public",
                            "title": f"Secret '{rp_data.get('SecretName', secret_arn)}' has public access via resource policy",
                            "entity": f"secret/{rp_data.get('SecretName', secret_arn)}",
                            "entity_arn": secret_arn,
                            "description": f"Secret resource policy grants Principal '*' "
                                           f"without Condition constraints. Anyone in any "
                                           f"AWS account could potentially read the secret "
                                           f"if they have appropriate IAM permissions.",
                            "matched_actions": granted_actions,
                            "source_policy": "ResourcePolicy",
                            "source_type": "secret_resource_policy",
                            "resource": [secret_arn],
                            "remediation": "Remove wildcard Principal or add restrictive Conditions",
                        })
                    continue

                if ptype == 'Service':
                    continue  # service principals (e.g., lambda.amazonaws.com) — not a graph node

                principal_account = _extract_account_from_arn(pval)
                is_cross_account = (
                    principal_account is not None and
                    account_id is not None and
                    principal_account != account_id
                )

                edge_type = "SECRET_GRANTS_CROSS_ACCOUNT" if is_cross_account else "SECRET_GRANTS_ACCESS"
                edges.append({
                    "source": f"secret:{secret_arn}",
                    "target": pval,
                    "type": edge_type,
                    "weight": SECRETS_ACCESS_WEIGHTS.get(edge_type, 1),
                    "category": "secrets",
                    "granted_actions": granted_actions,
                    "has_conditions": bool(conditions),
                    "is_cross_account": is_cross_account,
                })

                if is_cross_account:
                    findings.append({
                        "id": "SECRET-XAUTH-001",
                        "severity": "MEDIUM",
                        "category": "secrets_cross_account",
                        "title": f"Secret '{rp_data.get('SecretName', secret_arn)}' shared cross-account to {principal_account}",
                        "entity": f"secret/{rp_data.get('SecretName', secret_arn)}",
                        "entity_arn": secret_arn,
                        "description": f"Secret resource policy grants access to principal "
                                       f"'{pval}' from account {principal_account}.",
                        "matched_actions": granted_actions,
                        "source_policy": "ResourcePolicy",
                        "source_type": "secret_resource_policy",
                        "resource": [secret_arn],
                        "remediation": "Verify cross-account sharing is intended; "
                                       "consider adding ExternalId condition for trust boundary",
                    })

    # ── Step 5: SSM parameter findings (sensitive name + plaintext type) ──
    for param in params:
        pname = param.get('Name', '')
        ptype = param.get('Type', '')
        if not pname:
            continue
        if ptype == 'String' and _looks_sensitive_param_name(pname):
            findings.append({
                "id": "PARAM-PLAIN-001",
                "severity": "MEDIUM",
                "category": "ssm_plaintext_secret",
                "title": f"Parameter '{pname}' looks like a secret but stored as plaintext String",
                "entity": f"ssmparam/{pname}",
                "entity_arn": param.get('ARN', pname),
                "description": f"SSM parameter '{pname}' has type 'String' (plaintext) "
                               f"but its name suggests it contains a credential. "
                               f"Anyone with ssm:GetParameter on this name reads the "
                               f"value in plaintext, no KMS gate.",
                "matched_actions": ["ssm:GetParameter"],
                "source_policy": "Parameter Type",
                "source_type": "ssm_config",
                "resource": [param.get('ARN', pname)],
                "remediation": "Migrate the parameter to type 'SecureString' with a KMS key",
            })

    return {"edges": edges, "findings": findings}


# ──────────────────────────────────────────────────────────────
# Kubernetes (EKS + IRSA) Relationship Analysis
# ──────────────────────────────────────────────────────────────

K8S_ACCESS_WEIGHTS = {
    "IRSA_BRIDGE": 1,
    "RUNS_AS": 0,
    "BOUND_TO": 0,
    "MOUNTS_SECRET": 1,
    "SELECTS": 0,
    "EXPOSES": 0,
    "IN_CLUSTER": 0,
    "NODE_ROLE": 0,
    "CLUSTER_ROLE": 0,
}


def _load_k8s_data(report_path):
    """Load EKS + K8s data. Handles both single-region and --all mode.
    Returns dict: {cluster_name: {'cluster_meta': {...}, 'pods': [...], 'service_accounts': [...], ...}}"""
    clusters = {}

    def _load_region(region_path):
        eks_clusters_file = os.path.join(region_path, "eks", "clusters.json")
        eks_nodegroups_file = os.path.join(region_path, "eks", "nodegroups.json")
        k8s_dir = os.path.join(region_path, "k8s")

        eks_clusters = _load_json(eks_clusters_file)
        if not isinstance(eks_clusters, list):
            return

        nodegroups_map = _load_json(eks_nodegroups_file)
        if not isinstance(nodegroups_map, dict):
            nodegroups_map = {}

        for c in eks_clusters:
            if not isinstance(c, dict):
                continue
            name = c.get('name')
            if not name:
                continue

            cluster_data = {
                "cluster_meta": c,
                "nodegroups": nodegroups_map.get(name, []),
                "pods": [],
                "service_accounts": [],
                "roles": [],
                "cluster_roles": [],
                "role_bindings": [],
                "cluster_role_bindings": [],
                "secrets": [],
                "services": [],
                "ingresses": [],
                "namespaces": [],
                "auth_status": "unknown"
            }

            cluster_dir = os.path.join(k8s_dir, name)
            if os.path.isdir(cluster_dir):
                info = _load_json(os.path.join(cluster_dir, "cluster_info.json"))
                if isinstance(info, dict):
                    cluster_data["auth_status"] = info.get("auth_status", "unknown")

                for key in ["pods", "service_accounts", "roles", "cluster_roles",
                            "role_bindings", "cluster_role_bindings", "secrets",
                            "services", "ingresses", "namespaces"]:
                    data = _load_json(os.path.join(cluster_dir, f"{key}.json"))
                    if isinstance(data, list):
                        cluster_data[key] = data

            clusters[name] = cluster_data

    # Try local (single-region mode)
    if os.path.isdir(os.path.join(report_path, "eks")):
        _load_region(report_path)

    # Try sibling regions (--all mode)
    if not clusters:
        parent = os.path.dirname(report_path)
        if os.path.isdir(parent):
            for entry in os.listdir(parent):
                rp = os.path.join(parent, entry)
                if os.path.isdir(rp) and entry != 'global':
                    _load_region(rp)

    return clusters


def _safe_get(obj, *keys, default=None):
    """Walk a dict path safely."""
    for k in keys:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(k)
        if obj is None:
            return default
    return obj


def _normalize_subjects(binding):
    """Extract subject list from a RoleBinding/ClusterRoleBinding."""
    return binding.get('subjects') or []


def _analyze_k8s_relationships(report_path, permission_map, roles):
    """Build K8s + IRSA edges and findings."""
    edges = []
    findings = []

    clusters = _load_k8s_data(report_path)
    if not clusters:
        return {"edges": [], "findings": []}

    # Build IAM role lookup
    role_arns = {r.get('Arn') for r in roles if r.get('Arn')}
    role_by_name = {r.get('RoleName'): r for r in roles if r.get('RoleName')}

    for cluster_name, cdata in clusters.items():
        cluster_meta = cdata['cluster_meta']
        cluster_id = f"cluster:{cluster_name}"

        # Cluster service role edge
        cluster_role_arn = cluster_meta.get('roleArn')
        if cluster_role_arn and cluster_role_arn in role_arns:
            edges.append({
                "source": cluster_id,
                "target": cluster_role_arn,
                "type": "CLUSTER_ROLE",
                "weight": K8S_ACCESS_WEIGHTS["CLUSTER_ROLE"],
                "category": "k8s_compute",
                "cluster": cluster_name
            })

        # Nodegroup roles
        for ng in cdata.get('nodegroups', []) if isinstance(cdata.get('nodegroups'), list) else []:
            ng_name = ng.get('nodegroupName', '')
            ng_role = ng.get('nodeRole', '')
            ng_id = f"nodegroup:{cluster_name}/{ng_name}"
            if ng_role and ng_role in role_arns:
                edges.append({
                    "source": ng_id,
                    "target": ng_role,
                    "type": "NODE_ROLE",
                    "weight": K8S_ACCESS_WEIGHTS["NODE_ROLE"],
                    "category": "k8s_compute",
                    "cluster": cluster_name
                })

        # Service Account → IRSA bridge → IAM Role (the killer edge)
        sa_lookup = {}  # (namespace, name) -> sa_id
        for sa in cdata.get('service_accounts', []):
            ns = _safe_get(sa, 'metadata', 'namespace', default='default')
            sa_name = _safe_get(sa, 'metadata', 'name', default='')
            if not sa_name:
                continue
            sa_id = f"sa:{cluster_name}/{ns}/{sa_name}"
            sa_lookup[(ns, sa_name)] = sa_id

            # IRSA detection
            annotations = _safe_get(sa, 'metadata', 'annotations', default={}) or {}
            irsa_arn = annotations.get('eks.amazonaws.com/role-arn')
            if irsa_arn:
                weight = K8S_ACCESS_WEIGHTS["IRSA_BRIDGE"]
                edges.append({
                    "source": sa_id,
                    "target": irsa_arn,
                    "type": "IRSA_BRIDGE",
                    "weight": weight,
                    "category": "k8s_irsa",
                    "annotation": "eks.amazonaws.com/role-arn",
                    "cluster": cluster_name,
                    "namespace": ns,
                    "service_account": sa_name,
                    "iam_role_arn": irsa_arn,
                    "iam_role_known": irsa_arn in role_arns
                })

                # Check if IRSA role has admin-level AWS perms
                role_name_from_arn = irsa_arn.split('/')[-1] if '/' in irsa_arn else None
                if role_name_from_arn and role_name_from_arn in permission_map.get('roles', {}):
                    role_data = permission_map['roles'][role_name_from_arn]
                    has_admin = False
                    for stmt in role_data.get('effective_statements', []):
                        for action in stmt.get('actions', []):
                            if action == '*' or _action_matches(action, 'iam:*'):
                                for r in stmt.get('resources', []):
                                    if r == '*':
                                        has_admin = True
                                        break
                            if has_admin:
                                break
                        if has_admin:
                            break
                    if has_admin:
                        findings.append({
                            "id": "K8S-IRSA-ADMIN",
                            "severity": "CRITICAL",
                            "category": "k8s_irsa",
                            "title": f"ServiceAccount {ns}/{sa_name} (cluster {cluster_name}) has IRSA -> admin IAM role",
                            "entity": f"sa/{cluster_name}/{ns}/{sa_name}",
                            "entity_arn": sa_id,
                            "description": f"ServiceAccount '{sa_name}' in namespace '{ns}' "
                                           f"of cluster '{cluster_name}' is bound to IAM role "
                                           f"'{irsa_arn}' which has admin-level AWS permissions. "
                                           f"Pod compromise = AWS account compromise.",
                            "matched_actions": ["iam:*", "*"],
                            "source_policy": "ServiceAccount IRSA annotation",
                            "source_type": "k8s_irsa",
                            "resource": [sa_id],
                            "remediation": "Restrict IRSA role permissions to minimum required"
                        })

        # Pods
        pod_lookup = {}  # (namespace, name) -> pod_id
        for pod in cdata.get('pods', []):
            ns = _safe_get(pod, 'metadata', 'namespace', default='default')
            pod_name = _safe_get(pod, 'metadata', 'name', default='')
            if not pod_name:
                continue
            pod_id = f"pod:{cluster_name}/{ns}/{pod_name}"
            pod_lookup[(ns, pod_name)] = pod_id

            # Pod runs in cluster
            edges.append({
                "source": pod_id,
                "target": cluster_id,
                "type": "IN_CLUSTER",
                "weight": K8S_ACCESS_WEIGHTS["IN_CLUSTER"],
                "category": "k8s_structural",
                "cluster": cluster_name
            })

            # Pod -> ServiceAccount
            sa_name = _safe_get(pod, 'spec', 'service_account_name') or \
                      _safe_get(pod, 'spec', 'service_account') or 'default'
            sa_id = sa_lookup.get((ns, sa_name)) or f"sa:{cluster_name}/{ns}/{sa_name}"
            edges.append({
                "source": pod_id,
                "target": sa_id,
                "type": "RUNS_AS",
                "weight": K8S_ACCESS_WEIGHTS["RUNS_AS"],
                "category": "k8s_workload",
                "cluster": cluster_name,
                "namespace": ns
            })

            # Default SA finding
            if sa_name == 'default':
                findings.append({
                    "id": "K8S-DEFAULT-SA",
                    "severity": "MEDIUM",
                    "category": "k8s_workload",
                    "title": f"Pod {ns}/{pod_name} uses default ServiceAccount",
                    "entity": f"pod/{cluster_name}/{ns}/{pod_name}",
                    "entity_arn": pod_id,
                    "description": f"Pod '{pod_name}' in namespace '{ns}' uses the default "
                                   f"ServiceAccount. Best practice is to use a dedicated SA.",
                    "matched_actions": [],
                    "source_policy": "PodSpec",
                    "source_type": "k8s_pod",
                    "resource": [pod_id],
                    "remediation": "Create a dedicated ServiceAccount for this workload"
                })

            # Security context findings
            spec = pod.get('spec') or {}
            sec_ctx = spec.get('security_context') or {}
            host_network = spec.get('host_network')
            host_pid = spec.get('host_pid')

            # Check container security contexts
            privileged = False
            for container in spec.get('containers', []) or []:
                c_sec = container.get('security_context') or {}
                if c_sec.get('privileged'):
                    privileged = True
                    break

            if privileged:
                findings.append({
                    "id": "K8S-PRIV-001",
                    "severity": "CRITICAL",
                    "category": "k8s_security_context",
                    "title": f"Pod {ns}/{pod_name} runs privileged container (cluster {cluster_name})",
                    "entity": f"pod/{cluster_name}/{ns}/{pod_name}",
                    "entity_arn": pod_id,
                    "description": f"Pod '{pod_name}' has at least one privileged container. "
                                   f"Privileged containers can escape to the node.",
                    "matched_actions": [],
                    "source_policy": "PodSpec.containers[].securityContext.privileged",
                    "source_type": "k8s_pod",
                    "resource": [pod_id],
                    "remediation": "Remove privileged: true from container securityContext"
                })

            if host_network:
                findings.append({
                    "id": "K8S-HOSTNET-001",
                    "severity": "HIGH",
                    "category": "k8s_security_context",
                    "title": f"Pod {ns}/{pod_name} uses hostNetwork (cluster {cluster_name})",
                    "entity": f"pod/{cluster_name}/{ns}/{pod_name}",
                    "entity_arn": pod_id,
                    "description": f"Pod '{pod_name}' shares the host's network namespace, "
                                   f"giving it access to all node-level network interfaces.",
                    "matched_actions": [],
                    "source_policy": "PodSpec.hostNetwork",
                    "source_type": "k8s_pod",
                    "resource": [pod_id],
                    "remediation": "Set hostNetwork: false unless absolutely required"
                })

            if host_pid:
                findings.append({
                    "id": "K8S-HOSTPID-001",
                    "severity": "HIGH",
                    "category": "k8s_security_context",
                    "title": f"Pod {ns}/{pod_name} uses hostPID (cluster {cluster_name})",
                    "entity": f"pod/{cluster_name}/{ns}/{pod_name}",
                    "entity_arn": pod_id,
                    "description": f"Pod '{pod_name}' shares the host's PID namespace and "
                                   f"can see/signal all processes on the node.",
                    "matched_actions": [],
                    "source_policy": "PodSpec.hostPID",
                    "source_type": "k8s_pod",
                    "resource": [pod_id],
                    "remediation": "Set hostPID: false unless absolutely required"
                })

            # Mounted secrets
            for vol in spec.get('volumes') or []:
                secret_vol = vol.get('secret') or {}
                secret_name = secret_vol.get('secret_name')
                if secret_name:
                    sec_id = f"k8ssecret:{cluster_name}/{ns}/{secret_name}"
                    edges.append({
                        "source": pod_id,
                        "target": sec_id,
                        "type": "MOUNTS_SECRET",
                        "weight": K8S_ACCESS_WEIGHTS["MOUNTS_SECRET"],
                        "category": "k8s_workload",
                        "cluster": cluster_name,
                        "namespace": ns,
                        "secret_name": secret_name
                    })

        # RBAC: bindings link subjects (SAs) to roles
        # RoleBinding (namespaced)
        for rb in cdata.get('role_bindings', []):
            rb_ns = _safe_get(rb, 'metadata', 'namespace', default='default')
            role_ref = rb.get('role_ref') or {}
            ref_kind = role_ref.get('kind')  # Role | ClusterRole
            ref_name = role_ref.get('name', '')
            if not ref_name:
                continue

            if ref_kind == 'ClusterRole':
                target_id = f"k8srole:{cluster_name}/cluster/{ref_name}"
            else:
                target_id = f"k8srole:{cluster_name}/{rb_ns}/{ref_name}"

            for subj in _normalize_subjects(rb):
                if subj.get('kind') == 'ServiceAccount':
                    s_ns = subj.get('namespace', rb_ns)
                    s_name = subj.get('name', '')
                    if not s_name:
                        continue
                    sa_id = sa_lookup.get((s_ns, s_name)) or f"sa:{cluster_name}/{s_ns}/{s_name}"
                    edges.append({
                        "source": sa_id,
                        "target": target_id,
                        "type": "BOUND_TO",
                        "weight": K8S_ACCESS_WEIGHTS["BOUND_TO"],
                        "category": "k8s_rbac",
                        "cluster": cluster_name,
                        "binding_name": _safe_get(rb, 'metadata', 'name'),
                        "binding_kind": "RoleBinding",
                        "role_kind": ref_kind,
                        "role_name": ref_name
                    })

        # ClusterRoleBinding (cluster-wide)
        for crb in cdata.get('cluster_role_bindings', []):
            role_ref = crb.get('role_ref') or {}
            ref_name = role_ref.get('name', '')
            if not ref_name:
                continue
            target_id = f"k8srole:{cluster_name}/cluster/{ref_name}"
            is_cluster_admin = (ref_name == 'cluster-admin')

            for subj in _normalize_subjects(crb):
                if subj.get('kind') == 'ServiceAccount':
                    s_ns = subj.get('namespace', 'default')
                    s_name = subj.get('name', '')
                    if not s_name:
                        continue
                    sa_id = sa_lookup.get((s_ns, s_name)) or f"sa:{cluster_name}/{s_ns}/{s_name}"
                    edges.append({
                        "source": sa_id,
                        "target": target_id,
                        "type": "BOUND_TO",
                        "weight": K8S_ACCESS_WEIGHTS["BOUND_TO"],
                        "category": "k8s_rbac",
                        "cluster": cluster_name,
                        "binding_name": _safe_get(crb, 'metadata', 'name'),
                        "binding_kind": "ClusterRoleBinding",
                        "role_kind": "ClusterRole",
                        "role_name": ref_name
                    })

                    if is_cluster_admin:
                        findings.append({
                            "id": "K8S-RBAC-001",
                            "severity": "CRITICAL",
                            "category": "k8s_rbac",
                            "title": f"ServiceAccount {s_ns}/{s_name} bound to cluster-admin (cluster {cluster_name})",
                            "entity": f"sa/{cluster_name}/{s_ns}/{s_name}",
                            "entity_arn": sa_id,
                            "description": f"ServiceAccount '{s_name}' in namespace '{s_ns}' "
                                           f"is bound to cluster-admin via ClusterRoleBinding "
                                           f"'{_safe_get(crb, 'metadata', 'name')}'. "
                                           f"This SA has full cluster control.",
                            "matched_actions": ["*"],
                            "source_policy": _safe_get(crb, 'metadata', 'name', default='cluster-admin-binding'),
                            "source_type": "k8s_rbac",
                            "resource": [sa_id],
                            "remediation": "Use a more restrictive ClusterRole or namespaced Role"
                        })

        # Wildcard RBAC findings (Role/ClusterRole with verb * on resource *)
        for role in cdata.get('roles', []) + cdata.get('cluster_roles', []):
            r_kind = 'ClusterRole' if 'kind' in role and role.get('kind') == 'ClusterRole' else 'Role'
            r_ns = _safe_get(role, 'metadata', 'namespace', default='cluster')
            r_name = _safe_get(role, 'metadata', 'name', default='')
            if not r_name:
                continue
            for rule in role.get('rules') or []:
                verbs = rule.get('verbs') or []
                resources = rule.get('resources') or []
                if '*' in verbs and '*' in resources:
                    findings.append({
                        "id": "K8S-RBAC-002",
                        "severity": "HIGH",
                        "category": "k8s_rbac",
                        "title": f"{r_kind} {r_ns}/{r_name} has * on * (cluster {cluster_name})",
                        "entity": f"k8srole/{cluster_name}/{r_ns}/{r_name}",
                        "entity_arn": f"k8srole:{cluster_name}/{r_ns}/{r_name}",
                        "description": f"{r_kind} '{r_name}' allows verb '*' on resource '*'. "
                                       f"Anyone bound to this role has unrestricted cluster access.",
                        "matched_actions": ["*"],
                        "source_policy": r_name,
                        "source_type": "k8s_rbac",
                        "resource": [f"k8srole:{cluster_name}/{r_ns}/{r_name}"],
                        "remediation": "Restrict verbs and resources to least-privilege"
                    })

        # Services
        svc_lookup = {}
        for svc in cdata.get('services', []):
            ns = _safe_get(svc, 'metadata', 'namespace', default='default')
            svc_name = _safe_get(svc, 'metadata', 'name', default='')
            if not svc_name:
                continue
            svc_id = f"k8sservice:{cluster_name}/{ns}/{svc_name}"
            svc_lookup[(ns, svc_name)] = svc_id

            svc_type = _safe_get(svc, 'spec', 'type', default='ClusterIP')
            selector = _safe_get(svc, 'spec', 'selector', default={}) or {}

            if svc_type == 'LoadBalancer':
                findings.append({
                    "id": "K8S-NET-001",
                    "severity": "HIGH",
                    "category": "k8s_network",
                    "title": f"Service {ns}/{svc_name} is LoadBalancer (public exposure) in cluster {cluster_name}",
                    "entity": f"k8sservice/{cluster_name}/{ns}/{svc_name}",
                    "entity_arn": svc_id,
                    "description": f"Service '{svc_name}' is of type LoadBalancer, "
                                   f"likely exposing the workload to the internet via an ELB.",
                    "matched_actions": [],
                    "source_policy": "Service.spec.type",
                    "source_type": "k8s_service",
                    "resource": [svc_id],
                    "remediation": "Use Ingress with auth or restrict via NetworkPolicy"
                })

            # Service -> Pod via selector
            for (p_ns, p_name), pod_id in pod_lookup.items():
                if p_ns != ns:
                    continue
                # Match selector against pod labels
                # Find the pod's labels
                for pod in cdata.get('pods', []):
                    if _safe_get(pod, 'metadata', 'namespace') == p_ns and \
                       _safe_get(pod, 'metadata', 'name') == p_name:
                        labels = _safe_get(pod, 'metadata', 'labels', default={}) or {}
                        if selector and all(labels.get(k) == v for k, v in selector.items()):
                            edges.append({
                                "source": svc_id,
                                "target": pod_id,
                                "type": "SELECTS",
                                "weight": K8S_ACCESS_WEIGHTS["SELECTS"],
                                "category": "k8s_network",
                                "cluster": cluster_name,
                                "namespace": ns
                            })
                        break

        # Ingresses
        for ing in cdata.get('ingresses', []):
            ns = _safe_get(ing, 'metadata', 'namespace', default='default')
            ing_name = _safe_get(ing, 'metadata', 'name', default='')
            if not ing_name:
                continue
            ing_id = f"k8singress:{cluster_name}/{ns}/{ing_name}"
            annotations = _safe_get(ing, 'metadata', 'annotations', default={}) or {}

            # Ingress -> Service
            for rule in _safe_get(ing, 'spec', 'rules', default=[]) or []:
                http = rule.get('http') or {}
                for p in http.get('paths') or []:
                    backend = p.get('backend') or {}
                    svc_ref = backend.get('service') or {}
                    svc_name = svc_ref.get('name')
                    if svc_name:
                        target_svc = svc_lookup.get((ns, svc_name)) or f"k8sservice:{cluster_name}/{ns}/{svc_name}"
                        edges.append({
                            "source": ing_id,
                            "target": target_svc,
                            "type": "EXPOSES",
                            "weight": K8S_ACCESS_WEIGHTS["EXPOSES"],
                            "category": "k8s_network",
                            "cluster": cluster_name,
                            "namespace": ns
                        })

            # Auth annotation check
            has_auth = any(
                key.startswith('nginx.ingress.kubernetes.io/auth') or
                key.startswith('alb.ingress.kubernetes.io/auth')
                for key in annotations.keys()
            )
            if not has_auth:
                findings.append({
                    "id": "K8S-NET-002",
                    "severity": "MEDIUM",
                    "category": "k8s_network",
                    "title": f"Ingress {ns}/{ing_name} has no auth annotation (cluster {cluster_name})",
                    "entity": f"k8singress/{cluster_name}/{ns}/{ing_name}",
                    "entity_arn": ing_id,
                    "description": f"Ingress '{ing_name}' has no auth-related annotation. "
                                   f"Verify the underlying service handles authentication.",
                    "matched_actions": [],
                    "source_policy": "Ingress.metadata.annotations",
                    "source_type": "k8s_ingress",
                    "resource": [ing_id],
                    "remediation": "Add auth annotation or ensure service-level auth"
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

    # 6. Kubernetes (EKS + IRSA) relationships
    k8s_relationships = _analyze_k8s_relationships(report_path, permission_map, roles)
    findings.extend(k8s_relationships.get("findings", []))
    k8s_edge_count = len(k8s_relationships.get("edges", []))

    # 7. Secrets Manager + SSM Parameter Store relationships
    secrets_relationships = _analyze_secrets_relationships(report_path, permission_map, roles, users)
    findings.extend(secrets_relationships.get("findings", []))
    secrets_edge_count = len(secrets_relationships.get("edges", []))

    # 8. Save reports
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

    with open(os.path.join(analysis_dir, "k8s_relationships.json"), "w") as f:
        json.dump(k8s_relationships, f, indent=2, default=str)

    with open(os.path.join(analysis_dir, "secrets_relationships.json"), "w") as f:
        json.dump(secrets_relationships, f, indent=2, default=str)

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

    if k8s_edge_count > 0:
        print(f"    \033[1;32m[+]\033[0m K8s relationships: {k8s_edge_count} edges discovered")

    if secrets_edge_count > 0:
        print(f"    \033[1;32m[+]\033[0m Secrets/SSM relationships: {secrets_edge_count} edges discovered")

    print("    \033[1;32m[+]\033[0m Policy Analysis Finished!")
