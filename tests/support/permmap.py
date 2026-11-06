"""In-memory access to the legacy permission map and rule detectors.

Wraps the baseline private engine calls (``_build_permission_map`` with its eight
positional arguments, ``_detect_privesc_paths``, ``_detect_dangerous_permissions``,
``_action_matches``) so the engine split only breaks :mod:`tests.support.targets`.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence

from tests.support import targets

DEFAULT_ACCOUNT = "123456789012"
KINDS = ("role", "user", "group")


def policy_doc(statements: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def permission_map_for(statements: Sequence[Dict[str, Any]], kind: str = "role", *,
                       name: Optional[str] = None, account: str = DEFAULT_ACCOUNT,
                       extra_entity_fields: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Permission map for ONE principal holding ``statements`` as a single inline policy.

    ``kind`` is ``role``, ``user`` or ``group``. For ``group`` a member user
    ``<name>-member`` is created so group propagation is exercised as well.
    """
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}, got {kind!r}")
    name = name or f"example-{kind}"
    doc = policy_doc(statements)
    users: List[Dict[str, Any]] = []
    roles: List[Dict[str, Any]] = []
    group_attached: Dict[str, Any] = {}
    user_groups: Dict[str, Any] = {}
    inline: Dict[str, Dict[str, Any]] = {"users": {}, "roles": {}, "groups": {}}
    if kind == "role":
        role = {"RoleName": name, "Arn": f"arn:aws:iam::{account}:role/{name}",
                "AssumeRolePolicyDocument": {"Statement": []}}
        role.update(extra_entity_fields or {})
        roles.append(role)
        inline["roles"][name] = {"p": doc}
    elif kind == "user":
        user = {"UserName": name, "Arn": f"arn:aws:iam::{account}:user/{name}"}
        user.update(extra_entity_fields or {})
        users.append(user)
        inline["users"][name] = {"p": doc}
        user_groups[name] = []
    else:
        member = f"{name}-member"
        users.append({"UserName": member, "Arn": f"arn:aws:iam::{account}:user/{member}"})
        user_groups[member] = [{"GroupName": name}]
        group_attached[name] = []
        inline["groups"][name] = {"p": doc}
    build = targets.legacy_fn("_build_permission_map")
    # users, roles, role_attached, user_attached, group_attached, policy_docs, inline, user_groups
    return build(users, roles, {}, {}, group_attached, {}, inline, user_groups)


def privesc_findings(pm: Dict[str, Any]) -> List[Dict[str, Any]]:
    return targets.legacy_fn("_detect_privesc_paths")(pm)


def danger_findings(pm: Dict[str, Any]) -> List[Dict[str, Any]]:
    return targets.legacy_fn("_detect_dangerous_permissions")(pm)


def ids(findings: Iterable[Dict[str, Any]]) -> List[str]:
    return sorted({f["id"] for f in findings})


def privesc_ids(statements: Sequence[Dict[str, Any]], kind: str = "role", **kw) -> List[str]:
    return ids(privesc_findings(permission_map_for(statements, kind, **kw)))


def danger_ids(statements: Sequence[Dict[str, Any]], kind: str = "role", **kw) -> List[str]:
    return ids(danger_findings(permission_map_for(statements, kind, **kw)))


def action_matches(pattern: str, action: str) -> bool:
    return bool(targets.legacy_fn("_action_matches")(pattern, action))


def allow(actions, resources: Any = "*", cond: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """An Allow statement (same helper as internal-docs/repro/off_technique_matrix.py)."""
    stmt: Dict[str, Any] = {"Effect": "Allow", "Action": actions, "Resource": resources}
    if cond:
        stmt["Condition"] = cond
    return stmt


def deny(actions, resources: Any = "*") -> Dict[str, Any]:
    return {"Effect": "Deny", "Action": actions, "Resource": resources}
