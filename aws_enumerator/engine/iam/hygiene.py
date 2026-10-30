"""IAM credential hygiene (E-compute; F-148, the hygiene half of F-110).

The collectors record the credential report, the account summary, the password policy and per-user credentials
(access keys, MFA devices, console passwords, SSH keys, service-specific credentials, signing certificates), but
d13c215 never evaluated them. This analyzer (phase IDENTITY) turns them into findings:

==================  ========  ===============================================================================
id                  severity  condition
==================  ========  ===============================================================================
IAM-ROOT-MFA-001    HIGH      the root user has no MFA (credential report ``mfa_active``, else the account
                              summary ``AccountMFAEnabled``)
IAM-ROOT-KEY-001    CRITICAL  the root user has an active access key (report ``access_key_N_active``, else the
                              summary ``AccountAccessKeysPresent``)
IAM-USER-MFA-001    MEDIUM    an IAM user with a console password has no MFA device
IAM-KEY-AGE-001     LOW       an **active** access key older than 90 days at ``ctx.reference_time`` (MEDIUM
                              past 365 days); one finding per key
IAM-PWPOL-001       MEDIUM    no account password policy while console users exist (LOW without them); LOW for
                              a weak policy (length < 14, missing character classes, reuse prevention < 24)
IAM-ALTCRED-001     LOW       active alternate long-term credentials (SSH public keys, service-specific
                              credentials, X.509 signing certificates) that bypass access-key controls
==================  ========  ===============================================================================

Account-wide findings are anchored at the account anchor (``aws-enumerator:account/<id>``), per-user findings at
the user's node. Ages are computed against ``ctx.reference_time`` (``SOURCE_DATE_EPOCH`` / the run's start), so a
re-analysis of the same report gives the same findings (F-162, F-171).

**Unknown is not "fine"** (F-059): a value the collector could not read (``null``, ``*Error`` keys of the d13c215
layout, a missing credential report) never produces a "has no MFA" finding and never clears one; the analyzer
records the gap ``iam-hygiene:<what>-unknown`` instead.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.model import AnalyzerSkipped, AnalyzerSpec, Phase

log = logging.getLogger(__name__)

KEY_AGE_DAYS = 90
KEY_AGE_SEVERE_DAYS = 365
MIN_PASSWORD_LENGTH = 14
MIN_REUSE_PREVENTION = 24
_ROOT_USER = "<root_account>"
_TRUE, _FALSE = "true", "false"


@dataclass(frozen=True)
class AccessKey:
    """One access key of a user: status, creation / rotation time, last use."""

    key_id: Optional[str]
    active: bool
    created: Optional[datetime]
    last_used: Optional[datetime]


def parse_time(value: Any) -> Optional[datetime]:
    """An aware UTC datetime from an ISO-8601 string (``Z`` or offset; ``str(datetime)`` of d13c215), else ``None``."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value or value[0] not in "0123456789":
        return None
    text = value.strip().replace(" ", "T", 1)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if value else None


def _flag(value: Any) -> Optional[bool]:
    """``true`` / ``false`` cells (or booleans); anything else (``not_supported``, ``N/A``, null) is unknown."""
    if isinstance(value, bool):
        return value
    text = str(value).lower() if value is not None else ""
    return True if text == _TRUE else (False if text == _FALSE else None)


# ── inputs ───────────────────────────────────────────────────────────────────

def report_rows(iam: Any) -> Optional[Dict[str, Mapping[str, Any]]]:
    """Credential report rows by ARN (the root row under ``<root_account>``); ``None`` when not available."""
    report = getattr(iam, "credential_report", None)
    rows = report.get("Rows") if isinstance(report, Mapping) else None
    if not isinstance(rows, list):
        return None
    out: Dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if isinstance(row, Mapping):
            key = _ROOT_USER if row.get("user") == _ROOT_USER else str(row.get("arn"))
            out[key] = row
    return out


def user_keys(record: Mapping[str, Any]) -> Optional[List[AccessKey]]:
    """The user's access keys (v2 ``LastRotated`` or d13c215 ``CreateDate``); ``None`` when unknown."""
    keys = record.get("AccessKeys")
    if not isinstance(keys, list) or "AccessKeysError" in record:
        return None
    out = []
    for k in keys:
        if isinstance(k, Mapping):
            out.append(AccessKey(k.get("AccessKeyId") if isinstance(k.get("AccessKeyId"), str) else None,
                                 str(k.get("Status") or "").lower() == "active",
                                 parse_time(k.get("LastRotated") or k.get("CreateDate")),
                                 parse_time(k.get("LastUsedDate"))))
    return out


def console_access(record: Mapping[str, Any], row: Optional[Mapping[str, Any]]) -> Optional[bool]:
    if row is not None and _flag(row.get("password_enabled")) is not None:
        return _flag(row.get("password_enabled"))
    if "LoginProfileError" in record:
        return None
    value = record.get("HasLoginProfile")
    return value if isinstance(value, bool) else None


def mfa_active(record: Mapping[str, Any], row: Optional[Mapping[str, Any]]) -> Optional[bool]:
    if row is not None and _flag(row.get("mfa_active")) is not None:
        return _flag(row.get("mfa_active"))
    if isinstance(record.get("MFAActive"), bool):
        return bool(record["MFAActive"])
    devices = record.get("MFADevices")
    if isinstance(devices, list) and "MFADevicesError" not in record:
        return bool(devices)
    return None


# ── root user ────────────────────────────────────────────────────────────────

def root_state(iam: Any) -> Tuple[Optional[bool], Optional[bool], Dict[str, Any]]:
    """``(mfa active, has an active access key, evidence)`` of the root user, ``None`` when unknown."""
    rows = report_rows(iam)
    root = (rows or {}).get(_ROOT_USER)
    summary = getattr(iam, "account_summary", None) or {}
    evidence: Dict[str, Any] = {}
    if root is not None:
        mfa = _flag(root.get("mfa_active"))
        actives = [_flag(root.get(f"access_key_{i}_active")) for i in (1, 2)]
        keys = True if any(a is True for a in actives) else (False if all(a is False for a in actives) else None)
        evidence["source"] = "credential-report"
        last_used = [root.get(f"access_key_{i}_last_used_date") for i in (1, 2) if actives[i - 1]]
        if last_used:
            evidence["key_last_used"] = sorted(str(v) for v in last_used if v)
        return mfa, keys, evidence
    mfa_n, keys_n = summary.get("AccountMFAEnabled"), summary.get("AccountAccessKeysPresent")
    mfa = bool(mfa_n) if isinstance(mfa_n, int) else None
    keys = bool(keys_n) if isinstance(keys_n, int) else None
    if mfa is not None or keys is not None:
        evidence["source"] = "account-summary"
    return mfa, keys, evidence


def root_findings(ctx: Any, builder: Any, iam: Any) -> List[str]:
    """IAM-ROOT-MFA-001 / IAM-ROOT-KEY-001; returns the gaps of what could not be decided."""
    mfa, keys, evidence = root_state(iam)
    anchor = ids.account_anchor_id(ctx.account_id)
    gaps = []
    if mfa is False:
        builder.add_finding(
            "IAM-ROOT-MFA-001", anchor, severity="HIGH", title="The root user has no MFA device",
            description="The account's root user can sign in with its password alone. Whoever obtains the root "
                        "password (phishing, reuse, a recovery e-mail compromise) controls the whole account.",
            evidence=dict(evidence, mfa_active=False))
    elif mfa is None:
        gaps.append("iam-hygiene:root-mfa-unknown")
    if keys is True:
        builder.add_finding(
            "IAM-ROOT-KEY-001", anchor, severity="CRITICAL", title="The root user has an active access key",
            description="Root access keys are long-lived credentials with unrestricted access that no policy, "
                        "boundary or SCP can limit. A leaked root key is a full account takeover.",
            evidence=dict(evidence, access_keys_present=True))
    elif keys is None:
        gaps.append("iam-hygiene:root-keys-unknown")
    return gaps


# ── users ────────────────────────────────────────────────────────────────────

def _anchor(builder: Any, ctx: Any, arn: str) -> Tuple[str, str]:
    """``(node id, discriminator prefix)``: the user's node, else the account anchor keyed by the user ARN."""
    if builder.has_node(arn):
        return arn, ""
    return ids.account_anchor_id(ctx.account_id), arn


def user_findings(ctx: Any, builder: Any, user: Any, row: Optional[Mapping[str, Any]]) -> List[str]:
    """IAM-USER-MFA-001, IAM-KEY-AGE-001 and IAM-ALTCRED-001 for one user; returns the unknown gaps."""
    rec = user.record
    node, disc = _anchor(builder, ctx, user.arn)
    gaps: List[str] = []
    console, mfa = console_access(rec, row), mfa_active(rec, row)
    if console is True and mfa is False:
        builder.add_finding(
            "IAM-USER-MFA-001", node, severity="MEDIUM", discriminator=disc,
            title=f"IAM user '{user.name}' can sign in to the console without MFA",
            description="The user has a console password and no MFA device: a phished or reused password is "
                        "enough to act as this user.", evidence={"console_password": True, "mfa_active": False})
    elif console is None or (console is True and mfa is None):
        gaps.append("iam-hygiene:user-mfa-unknown")
    keys = user_keys(rec)
    if keys is None:
        gaps.append("iam-hygiene:access-keys-unknown")
    for index, key in enumerate(keys or ()):
        _key_age(ctx, builder, user, key, index, node, disc)
    _alternate_credentials(builder, user, node, disc)
    return gaps


def _key_age(ctx: Any, builder: Any, user: Any, key: AccessKey, index: int, node: str, disc: str) -> None:
    if not key.active or key.created is None:
        return
    age = (ctx.reference_time - key.created).days
    if age <= KEY_AGE_DAYS:
        return
    severity = "MEDIUM" if age > KEY_AGE_SEVERE_DAYS else "LOW"
    label = key.key_id or f"key {index + 1}"
    unused = key.last_used is None or (ctx.reference_time - key.last_used).days > KEY_AGE_DAYS
    builder.add_finding(
        "IAM-KEY-AGE-001", node, severity=severity, discriminator=f"{disc}#{key.key_id or index + 1}",
        title=f"IAM user '{user.name}' has an active access key {age} days old",
        description=(f"Access key {label} has not been rotated for {age} days (limit {KEY_AGE_DAYS})"
                     + (" and has not been used recently: deactivate it." if unused else ": rotate it.")),
        evidence={"access_key_id": key.key_id, "age_days": age, "created": _iso(key.created),
                  "last_used": _iso(key.last_used), "reference_time": _iso(ctx.reference_time)})


_ALT_KEYS: Tuple[Tuple[str, str], ...] = (
    ("SSHPublicKeys", "SSH public keys (CodeCommit)"),
    ("ServiceSpecificCredentials", "service-specific credentials"),
    ("SigningCertificates", "X.509 signing certificates"),
)


def _alternate_credentials(builder: Any, user: Any, node: str, disc: str) -> None:
    found: Dict[str, int] = {}
    for key, label in _ALT_KEYS:
        items = user.record.get(key)
        active = [i for i in items if isinstance(i, Mapping) and str(i.get("Status")).lower() == "active"] \
            if isinstance(items, list) else []
        if active:
            found[label] = len(active)
    if not found:
        return
    builder.add_finding(
        "IAM-ALTCRED-001", node, severity="LOW", discriminator=disc,
        title=f"IAM user '{user.name}' has active alternate long-term credentials",
        description="Active " + ", ".join(f"{label} ({n})" for label, n in sorted(found.items()))
                    + ": they authenticate outside access-key rotation and monitoring.",
        evidence={"credentials": dict(sorted(found.items()))})


# ── password policy ──────────────────────────────────────────────────────────

def policy_weaknesses(policy: Mapping[str, Any]) -> List[str]:
    """What a configured password policy lacks (CIS-style minimums)."""
    out = []
    length = policy.get("MinimumPasswordLength")
    if not isinstance(length, int) or length < MIN_PASSWORD_LENGTH:
        out.append(f"minimum length {length} < {MIN_PASSWORD_LENGTH}")
    for key in ("RequireSymbols", "RequireNumbers", "RequireUppercaseCharacters", "RequireLowercaseCharacters"):
        if policy.get(key) is False or (key not in policy and "MinimumPasswordLength" in policy):
            out.append(f"{key} not set")
    reuse = policy.get("PasswordReusePrevention")
    if not isinstance(reuse, int) or reuse < MIN_REUSE_PREVENTION:
        out.append(f"password reuse prevention {reuse} < {MIN_REUSE_PREVENTION}")
    return out


def password_state(iam: Any) -> Optional[Tuple[bool, Mapping[str, Any]]]:
    """``(configured, policy)``; ``None`` when unknown (unreadable or not collected)."""
    policy = getattr(iam, "password_policy", None)
    if not isinstance(policy, Mapping):
        return None
    configured = policy.get("Configured")
    if configured is None and "Configured" in policy:
        return None
    if configured is False or policy.get("Status") == "No password policy configured":
        return False, {}
    return True, policy


def password_findings(ctx: Any, builder: Any, iam: Any, console_users: int) -> List[str]:
    state = password_state(iam)
    if state is None:
        return ["iam-hygiene:password-policy-unknown"]
    configured, policy = state
    anchor = ids.account_anchor_id(ctx.account_id)
    if not configured:
        builder.add_finding(
            "IAM-PWPOL-001", anchor, severity="MEDIUM" if console_users else "LOW",
            title="The account has no IAM password policy",
            description=f"No password policy is set: console passwords only need the AWS defaults "
                        f"({console_users} user(s) with a console password).",
            evidence={"configured": False, "console_users": console_users})
        return []
    weak = policy_weaknesses(policy)
    if weak:
        builder.add_finding(
            "IAM-PWPOL-001", anchor, severity="LOW", title="The account password policy is weak",
            description="The IAM password policy is below common baselines: " + "; ".join(weak) + ".",
            evidence={"configured": True, "weaknesses": weak, "console_users": console_users})
    return []


# ── the analyzer ─────────────────────────────────────────────────────────────

def analyze_hygiene(ctx: Any, builder: Any) -> None:
    """Analyzer ``iam-hygiene`` (phase IDENTITY)."""
    iam = (ctx.data or {}).get("iam")
    if iam is None or getattr(iam, "layout", "missing") == "missing":
        raise AnalyzerSkipped("iam.credential_report", reason="IAM data was not collected")
    gaps = root_findings(ctx, builder, iam)          # the account anchor is created with its first finding
    rows = report_rows(iam) or {}
    console_users = 0
    for user in iam.entities("user"):
        row = rows.get(user.arn)
        console_users += console_access(user.record, row) is True
        gaps += user_findings(ctx, builder, user, row)
    gaps += password_findings(ctx, builder, iam, console_users)
    _record_gaps(ctx, gaps)


def _record_gaps(ctx: Any, gaps: Sequence[str]) -> None:
    counts: Dict[str, int] = {}
    for gap in gaps:
        counts[gap] = counts.get(gap, 0) + 1
    for code, n in sorted(counts.items()):
        ctx.add_gap(code, "IAM credential hygiene could not be decided for some identities because the "
                    "collector could not read the value (unknown, not compliant).", n)


def _run(ctx: Any, builder: Any) -> None:
    analyze_hygiene(ctx, builder)       # looked up at call time (tests may patch the module attribute)


def _findings() -> Tuple[Any, ...]:
    from aws_enumerator.engine.findings.catalog import A_EXTERNAL, CatalogEntry

    entry = CatalogEntry
    return (
        entry("IAM-ROOT-MFA-001", "HIGH", "iam_hygiene", "The root user has no MFA device",
              "Enable a hardware or virtual MFA device on the root user and store the recovery material offline.",
              A_EXTERNAL),
        entry("IAM-ROOT-KEY-001", "CRITICAL", "iam_hygiene", "The root user has an active access key",
              "Delete the root access keys; use IAM roles or users with least privilege instead.", A_EXTERNAL),
        entry("IAM-USER-MFA-001", "MEDIUM", "iam_hygiene", "Console user without MFA",
              "Require MFA for every console user (an MFA device plus a policy denying actions without "
              "aws:MultiFactorAuthPresent), or move people to IAM Identity Center.", A_EXTERNAL),
        entry("IAM-KEY-AGE-001", "LOW", "iam_hygiene", "Active access key older than 90 days",
              "Rotate the key (create a new one, switch, deactivate and delete the old one) or delete it if "
              "unused; prefer short-lived role credentials.", A_EXTERNAL, discriminator="access-key"),
        entry("IAM-PWPOL-001", "MEDIUM", "iam_hygiene", "Missing or weak IAM password policy",
              "Set an account password policy: length >= 14, all character classes, reuse prevention 24.",
              A_EXTERNAL),
        entry("IAM-ALTCRED-001", "LOW", "iam_hygiene", "Active alternate long-term credentials",
              "Delete unused SSH public keys, service-specific credentials and signing certificates; prefer "
              "federated or role-based access.", A_EXTERNAL),
    )


#: Finding ids this module emits (findings/catalog.py merges them, DECISIONS.md D-33).
FINDINGS: Tuple[Any, ...] = _findings()

ANALYZERS: Tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec("iam-hygiene", Phase.IDENTITY, _run, inputs=("iam.credential_report",), requires=("iam-graph",)),
)

__all__ = ["ANALYZERS", "FINDINGS", "analyze_hygiene", "parse_time", "policy_weaknesses", "root_state",
           "user_keys"]
