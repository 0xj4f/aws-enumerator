"""IAM credential hygiene (engine/iam/hygiene.py; F-148, the hygiene half of F-110).

Ages are relative to ``ctx.reference_time`` (``SOURCE_DATE_EPOCH`` = 2026-01-01T00:00:00Z in the kit), so the
findings are reproducible. Unknown values never produce or clear a finding (F-059).
"""

from __future__ import annotations

import importlib

import pytest

K = importlib.import_module("tests.fixtures.e-compute.kit")
rb = K.rb
ACCOUNT_ANCHOR = f"aws-enumerator:account/{K.ACCT}"
STRONG_POLICY = {"MinimumPasswordLength": 16, "RequireSymbols": True, "RequireNumbers": True,
                 "RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True,
                 "PasswordReusePrevention": 24, "AllowUsersToChangePassword": True}


def _tree(tmp_path):
    t = K.LegacyTree(tmp_path)
    t.iam.password_policy = dict(STRONG_POLICY)
    return t


def _hygiene(g):
    return sorted((f["id"], f["severity"], f["node_id"]) for f in g["findings"] if f["id"].startswith("IAM-"))


@pytest.mark.finding("F-148")
def test_a_clean_account_has_no_hygiene_findings(tmp_path):
    t = _tree(tmp_path)
    t.iam.user("demo-dev", login=True, mfa=True, access_keys=1)
    g = t.analyze().graph
    assert K.status_of(g, "iam-hygiene") == "ok"
    assert _hygiene(g) == []


@pytest.mark.finding("F-148")
def test_root_without_mfa_and_with_keys_from_the_account_summary(tmp_path):
    t = _tree(tmp_path)
    t.iam.account_summary.update(AccountMFAEnabled=0, AccountAccessKeysPresent=1)
    g = t.analyze().graph
    assert K.problems(g) == []
    found = {f["id"]: f for f in g["findings"] if f["id"].startswith("IAM-ROOT")}
    assert found["IAM-ROOT-MFA-001"]["severity"] == "HIGH" and found["IAM-ROOT-MFA-001"]["node_id"] == ACCOUNT_ANCHOR
    assert found["IAM-ROOT-KEY-001"]["severity"] == "CRITICAL"
    assert found["IAM-ROOT-KEY-001"]["evidence"]["source"] == "account-summary"
    assert K.nodes(g)[ACCOUNT_ANCHOR]["type"] == "account"


@pytest.mark.finding("F-148")
def test_root_state_from_the_credential_report_wins(tmp_path):
    run = K.RunTree(tmp_path)
    run.iam.password_policy = dict(STRONG_POLICY)
    run.iam.root_account.update(mfa_active="false", access_key_1_active="true",
                                access_key_1_last_used_date="2025-12-01T00:00:00+00:00")
    run.iam.account_summary.update(AccountMFAEnabled=1, AccountAccessKeysPresent=0)    # stale summary
    g = run.analyze().graph
    assert K.problems(g) == []
    ids = {f["id"]: f for f in g["findings"]}
    assert "IAM-ROOT-MFA-001" in ids
    assert ids["IAM-ROOT-KEY-001"]["evidence"]["source"] == "credential-report"
    assert ids["IAM-ROOT-KEY-001"]["evidence"]["key_last_used"] == ["2025-12-01T00:00:00+00:00"]


@pytest.mark.finding("F-148")
def test_console_users_without_mfa(tmp_path):
    t = _tree(tmp_path)
    no_mfa = t.iam.user("demo-console", login=True, mfa=False)
    t.iam.user("demo-safe", login=True, mfa=True)
    t.iam.user("demo-api-only", login=False, mfa=False)
    g = t.analyze().graph
    assert [(i, n) for i, _s, n in _hygiene(g)] == [("IAM-USER-MFA-001", no_mfa)]


@pytest.mark.finding("F-148")
def test_active_keys_older_than_90_days_against_the_reference_time(tmp_path):
    t = _tree(tmp_path)
    arn = t.iam.user("demo-keys", access_keys=2)
    stale_user = t.iam.users[-1]
    stale_user["AccessKeys"][0]["CreateDate"] = "2024-06-01 00:00:00+00:00"       # 579 days: MEDIUM
    stale_user["AccessKeys"][1]["CreateDate"] = "2025-09-01 00:00:00+00:00"       # 122 days: LOW
    t.iam.user("demo-inactive", access_keys=1, key_status="Inactive")
    t.iam.users[-1]["AccessKeys"][0]["CreateDate"] = "2020-01-01 00:00:00+00:00"   # inactive: ignored
    t.iam.user("demo-fresh", access_keys=1)
    t.iam.users[-1]["AccessKeys"][0]["CreateDate"] = "2025-11-01 00:00:00+00:00"   # 61 days
    g = t.analyze().graph
    ages = sorted((f["severity"], f["evidence"]["age_days"]) for f in K.findings(g, "IAM-KEY-AGE-001"))
    assert ages == [("LOW", 122), ("MEDIUM", 579)]
    assert {f["node_id"] for f in K.findings(g, "IAM-KEY-AGE-001")} == {arn}
    assert len({f["fingerprint"] for f in K.findings(g, "IAM-KEY-AGE-001")}) == 2              # one per key
    assert {f["evidence"]["reference_time"] for f in K.findings(g, "IAM-KEY-AGE-001")} == {"2026-01-01T00:00:00Z"}


@pytest.mark.finding("F-148")
@pytest.mark.parametrize("policy, severity", [
    ({"Status": "No password policy configured"}, "MEDIUM"),
    ({"MinimumPasswordLength": 8, "RequireSymbols": False, "RequireNumbers": True,
      "RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True, "PasswordReusePrevention": 24}, "LOW"),
    (STRONG_POLICY, None),
])
def test_password_policy(tmp_path, policy, severity):
    t = _tree(tmp_path)
    t.iam.password_policy = dict(policy)
    t.iam.user("demo-console", login=True, mfa=True)
    g = t.analyze().graph
    found = K.findings(g, "IAM-PWPOL-001")
    if severity is None:
        assert found == []
    else:
        assert K.only(found)["severity"] == severity
        assert K.only(found)["node_id"] == ACCOUNT_ANCHOR
    if severity == "LOW":
        weak = K.only(found)["evidence"]["weaknesses"]
        assert "minimum length 8 < 14" in weak and "RequireSymbols not set" in weak


@pytest.mark.finding("F-148", "F-110")
def test_alternate_credentials(tmp_path):
    run = K.RunTree(tmp_path)
    run.iam.password_policy = dict(STRONG_POLICY)
    arn = run.iam.user("demo-git", access_keys=0)
    run.iam.user_credentials("demo-git", ssh_keys=2, service_credentials=["codecommit.amazonaws.com"])
    run.iam.user("demo-clean")
    g = run.analyze().graph
    alt = K.only(K.findings(g, "IAM-ALTCRED-001"))
    assert alt["node_id"] == arn and alt["severity"] == "LOW"
    assert alt["evidence"]["credentials"] == {"SSH public keys (CodeCommit)": 2, "service-specific credentials": 1}


@pytest.mark.finding("F-148", "F-059")
def test_unknown_values_never_produce_or_clear_findings(tmp_path):
    t = _tree(tmp_path)
    t.iam.user("demo-unknown", login=True)
    rec = t.iam.users[-1]
    del rec["MFADevices"]
    rec["MFADevicesError"] = "AccessDenied"
    del rec["AccessKeys"]
    rec["AccessKeysError"] = "AccessDenied"
    t.iam.account_summary = {}
    t.iam.override("account_password_policy.json", {"Error": "AccessDenied"})
    g = t.analyze().graph
    assert _hygiene(g) == []
    gaps = {gap["code"] for gap in g["evaluation_gaps"]}
    assert {"iam-hygiene:user-mfa-unknown", "iam-hygiene:access-keys-unknown", "iam-hygiene:root-mfa-unknown",
            "iam-hygiene:root-keys-unknown", "iam-hygiene:password-policy-unknown"} <= gaps


def test_parse_time_accepts_every_collector_format():
    hygiene = K.engine("iam.hygiene")
    for text in ("2026-01-01T00:00:00Z", "2026-01-01 00:00:00+00:00", "2026-01-01T00:00:00+00:00",
                 "2026-01-01T00:00:00"):
        assert hygiene.parse_time(text).isoformat() == "2026-01-01T00:00:00+00:00", text
    for text in ("N/A", "no_information", "not_supported", "", None, 5):
        assert hygiene.parse_time(text) is None
