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

    # 4. Save reports
    with open(os.path.join(analysis_dir, "findings.json"), "w") as f:
        json.dump({"findings": findings}, f, indent=2, default=str)

    with open(os.path.join(analysis_dir, "permission_map.json"), "w") as f:
        json.dump(permission_map, f, indent=2, default=str)

    with open(os.path.join(analysis_dir, "trust_relationships.json"), "w") as f:
        json.dump(trust_relationships, f, indent=2, default=str)

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

    print("    \033[1;32m[+]\033[0m Policy Analysis Finished!")
