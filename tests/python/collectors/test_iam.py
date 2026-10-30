"""IAM collector (collectors-cli.md §5.1): GAAD, per-entity fallback, every policy version, credential report,
alternate credentials, federation providers, coverage markers."""

from __future__ import annotations

import importlib
import json

import pytest

from tests.fixtures.worlds import acme
from tests.support.fakeaws import Request

KIT = importlib.import_module("tests.fixtures.c-a.kit")
WORLDS = importlib.import_module("tests.fixtures.c-a.worlds")
pytestmark = pytest.mark.collectors

PER_ENTITY = {"iam_mode": "per-entity"}
W2_REGION = KIT.W2
ALICE, BOB, CI = (acme.iam_arn("user", n) for n in ("demo-alice", "demo-bob", "demo-ci"))
PER_ENTITY_OPS = {"ListUsers", "ListGroups", "ListPolicies", "ListInstanceProfiles", "GetUser", "GetRole",
                  "ListGroupsForUser", "ListAttachedUserPolicies", "ListAttachedRolePolicies",
                  "ListAttachedGroupPolicies", "ListUserPolicies", "ListRolePolicies", "ListGroupPolicies",
                  "GetUserPolicy", "GetRolePolicy", "GetGroupPolicy", "ListPolicyVersions"}


@pytest.fixture(autouse=True)
def _fast_report(monkeypatch):
    KIT.no_report_wait(monkeypatch)


def iam_ops(r):
    return {op for svc, op in KIT.operations(r) if svc == "iam"}


def documents(r):
    """``{PolicyArn: document record}`` from ``policy_documents/``."""
    return {d["PolicyArn"]: d for rel, d in KIT.data_files(r).items() if rel.startswith("policy_documents/")}


# ── entities ─────────────────────────────────────────────────────────────────
@pytest.mark.finding("F-052", "F-109")
def test_gaad_mode_reads_boundaries_tags_and_last_use_without_per_entity_calls(tmp_path):
    r = KIT.run("iam", tmp_path, KIT.clean_world())
    KIT.assert_contract(r)
    assert not iam_ops(r) & PER_ENTITY_OPS, sorted(iam_ops(r) & PER_ENTITY_OPS)
    users = KIT.by(r.load("users.json"), "UserName")
    assert users["demo-ci"]["PermissionsBoundary"] == {
        "PermissionsBoundaryType": "PermissionsBoundaryPolicy",
        "PermissionsBoundaryArn": acme.managed_arn("ReadOnlyAccess")}
    assert users["demo-ci"]["Tags"] == [{"Key": "purpose", "Value": "ci"}]
    assert users["demo-bob"]["PermissionsBoundary"] is None and users["demo-bob"]["Tags"] == []
    roles = KIT.by(r.load("roles.json"), "RoleName")
    assert roles["demo-lambda-role"]["PermissionsBoundary"]["PermissionsBoundaryArn"] == \
        acme.policy_arn("demo-app-policy")
    assert roles["demo-admin-role"]["RoleLastUsed"]["Region"] == W2_REGION
    assert roles["demo-admin-role"]["Tags"] == [{"Key": "tier", "Value": "admin"}]
    # GAAD has no Description / MaxSessionDuration: one ListRoles listing is merged in
    assert roles["demo-app-role"]["Description"] == "demo-app-role (acme synthetic)"
    assert roles["demo-app-role"]["MaxSessionDuration"] == 3600
    assert roles["demo-app-role"]["InstanceProfileArns"] == [acme.iam_arn("instance-profile", "demo-app-profile")]
    assert roles["demo-app-role"]["AssumeRolePolicyDocument"]["Statement"][0]["Principal"] == \
        {"Service": "ec2.amazonaws.com"}
    boundaries = {rel: d for rel, d in KIT.data_files(r).items() if rel.startswith("permission_boundaries/")}
    assert boundaries == {
        "permission_boundaries/demo-ci.json": {
            "EntityType": "User", "EntityName": "demo-ci", "EntityArn": CI,
            "PermissionsBoundary": users["demo-ci"]["PermissionsBoundary"]},
        "permission_boundaries/demo-lambda-role.json": {
            "EntityType": "Role", "EntityName": "demo-lambda-role", "EntityArn": acme.role_arn("demo-lambda-role"),
            "PermissionsBoundary": roles["demo-lambda-role"]["PermissionsBoundary"]}}
    for name in ("users.json", "roles.json", "groups.json", "policies.json", "instance_profiles.json"):
        assert KIT.is_sorted_by(r.load(name), {"users.json": "UserName", "roles.json": "RoleName",
                                                "groups.json": "GroupName"}.get(name, "Arn")), name



@pytest.mark.finding("F-107", "F-109")
def test_gaad_follows_every_page_with_all_five_filters(tmp_path):
    r = KIT.run("iam", tmp_path, KIT.clean_world())       # acme serves GAAD 10 items per page
    pages = KIT.sent(r, "iam", "GetAccountAuthorizationDetails")
    assert len(pages) == 3, pages
    assert all(sorted(p["Filter"]) == sorted(["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"])
               for p in pages)
    assert [bool(p.get("Marker")) for p in pages] == [False, True, True]
    assert sorted(u["UserName"] for u in r.load("users.json")) == sorted(u["UserName"] for u in acme.USERS)
    assert sorted(x["RoleName"] for x in r.load("roles.json")) == sorted(x["RoleName"] for x in acme.ROLES)
    assert sorted(g["GroupName"] for g in r.load("groups.json")) == sorted(g["GroupName"] for g in acme.GROUPS)
    assert sorted(p["PolicyName"] for p in r.load("policies.json")) == sorted(acme.CUSTOMER_POLICIES)
    assert r.load("user_group_memberships.json")["demo-alice"] == [
        {"GroupName": "demo-developers", "GroupId": "AGPAEXAMPLEDEVS000001",
         "Arn": acme.iam_arn("group", "demo-developers"), "Path": "/"}]
    assert r.load("role_attached_policies.json")["demo-admin-role"] == [
        {"PolicyName": "AdministratorAccess", "PolicyArn": acme.managed_arn("AdministratorAccess")}]


@pytest.mark.finding("F-013", "F-110")
def test_policy_documents_are_keyed_by_arn_and_keep_every_local_version(tmp_path, monkeypatch):
    monkeypatch.setitem(acme.CUSTOMER_POLICIES, "AdministratorAccess", {
        "id": "ANPAEXAMPLEADMINCOLL1", "default": "v3", "attachments": 0,
        "versions": {"v1": acme._doc(acme._allow("s3:ListAllMyBuckets")),
                     "v2": acme._doc(acme._allow("ec2:Describe*")), "v3": acme._doc(acme._allow("iam:Get*"))}})
    r = KIT.run("iam", tmp_path, KIT.clean_world())
    docs = documents(r)
    local, aws = acme.policy_arn("AdministratorAccess"), acme.managed_arn("AdministratorAccess")
    assert {local, aws} <= set(docs)
    assert docs[aws]["PolicyType"] == "AWS" and docs[aws]["Versions"] == []
    assert docs[aws]["Document"]["Statement"][0]["Action"] == "*"
    assert docs[local]["PolicyType"] == "Local" and docs[local]["DefaultVersionId"] == "v3"
    assert [v["VersionId"] for v in docs[local]["Versions"]] == ["v1", "v2", "v3"]
    assert [v["IsDefaultVersion"] for v in docs[local]["Versions"]] == [False, False, True]
    assert docs[local]["Document"] == docs[local]["Versions"][2]["Document"]
    dev = docs[acme.policy_arn("demo-dev-policy")]
    assert [v["VersionId"] for v in dev["Versions"]] == ["v1", "v2"] and dev["VersionId"] == "v2"
    names = [rel for rel in KIT.data_files(r) if rel.startswith("policy_documents/")]
    assert len(names) == len(set(names)) == len(docs)


@pytest.mark.finding("F-052", "F-110", "F-053")
def test_per_entity_mode_reads_details_and_every_version_in_isolated_sections(tmp_path):
    r = KIT.run("iam", tmp_path, KIT.clean_world(), options=PER_ENTITY)
    doc = KIT.assert_contract(r)
    assert "GetAccountAuthorizationDetails" not in iam_ops(r)
    assert {"GetUser", "GetRole", "ListPolicyVersions"} <= iam_ops(r)
    assert {s["name"] for s in doc["sections"]} >= {"users", "groups", "roles", "instance_profiles", "policies"}
    users = KIT.by(r.load("users.json"), "UserName")
    assert users["demo-ci"]["PermissionsBoundary"]["PermissionsBoundaryArn"] == acme.managed_arn("ReadOnlyAccess")
    assert users["demo-alice"]["Tags"] == [{"Key": "team", "Value": "demo-dev"}, {"Key": "owner", "Value": "demo-team"}]
    roles = KIT.by(r.load("roles.json"), "RoleName")
    assert roles["demo-admin-role"]["RoleLastUsed"] == {"LastUsedDate": "2024-01-14T10:00:00Z", "Region": "eu-west-2"}
    dev = documents(r)[acme.policy_arn("demo-dev-policy")]
    assert [v["VersionId"] for v in dev["Versions"]] == ["v1", "v2"]
    versions = KIT.sent(r, "iam", "GetPolicyVersion")
    assert {(p["PolicyArn"], p["VersionId"]) for p in versions} >= {
        (acme.policy_arn("demo-dev-policy"), "v1"), (acme.policy_arn("demo-dev-policy"), "v2")}


@pytest.mark.finding("F-109")
def test_gaad_and_per_entity_modes_write_the_same_core_files(tmp_path):
    gaad = KIT.data_files(KIT.run("iam", tmp_path / "gaad", KIT.clean_world()))
    per_entity = KIT.data_files(KIT.run("iam", tmp_path / "pe", KIT.clean_world(), options=PER_ENTITY))
    assert sorted(gaad) == sorted(per_entity)
    for rel in sorted(gaad):
        a, b = gaad[rel], per_entity[rel]
        if rel == "policies.json":  # acme's ListPolicies does not model PermissionsBoundaryUsageCount
            a = [{k: v for k, v in p.items() if k != "PermissionsBoundaryUsageCount"} for p in a]
            b = [{k: v for k, v in p.items() if k != "PermissionsBoundaryUsageCount"} for p in b]
        assert a == b, rel


@pytest.mark.finding("F-053")
def test_denied_gaad_falls_back_and_an_optional_denial_keeps_the_module_ok(tmp_path):
    w = KIT.clean_world()
    w.deny("iam", "GetAccountAuthorizationDetails")
    r = KIT.run("iam", tmp_path, w)
    KIT.assert_contract(r, statuses=("ok",))
    rows = KIT.calls(r, "iam:GetAccountAuthorizationDetails")
    assert [(x["status"], x["optional"]) for x in rows] == [("denied", True)]
    assert {u["UserName"] for u in r.load("users.json")} == {u["UserName"] for u in acme.USERS}


@pytest.mark.finding("F-053")
def test_every_fallback_list_denied_still_writes_stable_files(tmp_path):
    w = KIT.clean_world()
    for op in ("GetAccountAuthorizationDetails", "ListUsers", "ListGroups", "ListRoles", "ListPolicies",
               "ListInstanceProfiles"):
        w.deny("iam", op)
    r = KIT.run("iam", tmp_path, w)
    KIT.assert_contract(r, statuses=("denied",))        # ListRoles is the fallback's primary listing
    for name in ("users.json", "roles.json", "groups.json", "policies.json", "instance_profiles.json"):
        assert r.load(name) == [], name
    for name in ("user_attached_policies.json", "role_attached_policies.json", "user_group_memberships.json"):
        assert r.load(name) == {}, name


@pytest.mark.finding("F-111")
def test_failed_inline_listings_and_reads_are_recorded_per_entity(tmp_path):
    w = KIT.clean_world()
    w.deny("iam", "ListUserPolicies", {"UserName": "demo-alice"})
    w.deny("iam", "GetRolePolicy", {"RoleName": "demo-lambda-role", "PolicyName": "demo-lambda-inline"})
    r = KIT.run("iam", tmp_path, w, options=PER_ENTITY)
    KIT.assert_contract(r, statuses=("partial",))
    assert KIT.item_errors(r, "iam:ListUserPolicies") == [
        {"resource": ALICE, "api": "iam:ListUserPolicies", "status": "denied", "error_code": "AccessDenied"}]
    files = r.files()
    assert "inline_policies/users/demo-alice.json" not in files       # unknown, not "none"
    assert "inline_policies/users/demo-ci.json" in files
    lam = r.load("inline_policies/roles/demo-lambda-role.json")
    assert sorted(lam["InlinePolicies"]) == ["demo-lambda-logs"]
    assert KIT.collection_errors(lam) == [("iam:GetRolePolicy", "denied")]
    assert lam["EntityArn"] == acme.role_arn("demo-lambda-role")


@pytest.mark.finding("F-111")
def test_failed_attachment_listing_omits_the_entity_and_records_it(tmp_path):
    w = KIT.clean_world()
    w.deny("iam", "ListAttachedRolePolicies", {"RoleName": "demo-admin-role"})
    r = KIT.run("iam", tmp_path, w, options=PER_ENTITY)
    attached = r.load("role_attached_policies.json")
    assert "demo-admin-role" not in attached and "demo-build-role" in attached
    assert [e["resource"] for e in KIT.item_errors(r, "iam:ListAttachedRolePolicies")] == [
        acme.role_arn("demo-admin-role")]


@pytest.mark.finding("F-110")
def test_a_policy_gaad_did_not_return_is_fetched_by_arn(tmp_path):
    w = KIT.clean_world()
    gaad = w.handlers[("iam", "GetAccountAuthorizationDetails")]
    missing = acme.managed_arn("AmazonEKSWorkerNodePolicy")

    def without_one(req: Request):
        resp = gaad(req)
        return dict(resp, Policies=[p for p in resp["Policies"] if p["Arn"] != missing])

    w.handlers[("iam", "GetAccountAuthorizationDetails")] = without_one
    r = KIT.run("iam", tmp_path, w)
    assert [p["PolicyArn"] for p in KIT.sent(r, "iam", "GetPolicy")] == [missing]
    assert [(p["PolicyArn"], p["VersionId"]) for p in KIT.sent(r, "iam", "GetPolicyVersion")] == [(missing, "v3")]
    doc = documents(r)[missing]
    assert doc["PolicyType"] == "AWS" and doc["Versions"] == [] and doc["VersionId"] == "v3"


def test_gaad_export_file_is_imported_without_calling_gaad(tmp_path):
    first = KIT.run("iam", tmp_path / "api", KIT.clean_world())
    export = tmp_path / "gaad.json"
    fake = first.fake
    pages = []
    session = fake.session("us-east-1")
    client = session.client("iam", region_name="us-east-1")
    for page in client.get_paginator("get_account_authorization_details").paginate():
        page.pop("ResponseMetadata", None)
        pages.append(page)
    export.write_text(json.dumps(pages, default=str), encoding="utf-8")
    r = KIT.run("iam", tmp_path / "imported", KIT.clean_world(), options={"iam_gaad_file": str(export)})
    KIT.assert_contract(r)
    assert "GetAccountAuthorizationDetails" not in iam_ops(r)
    assert [(x["status"], x["error_code"]) for x in KIT.calls(r, "iam:GetAccountAuthorizationDetails")] == [
        ("skipped", "imported from --iam-gaad-file")]
    assert {u["UserName"] for u in r.load("users.json")} == {u["UserName"] for u in acme.USERS}
    assert set(documents(r)) == set(documents(first))


# ── account settings ─────────────────────────────────────────────────────────
def test_password_policy_not_configured_configured_and_denied(tmp_path):
    r = KIT.run("iam", tmp_path / "none", KIT.clean_world())
    assert r.load("account_password_policy.json") == {"Configured": False}
    w = KIT.clean_world()
    w.static("iam", "GetAccountPasswordPolicy", {"PasswordPolicy": {"MinimumPasswordLength": 14,
                                                                    "RequireSymbols": True}})
    r = KIT.run("iam", tmp_path / "set", w)
    assert r.load("account_password_policy.json") == {"Configured": True, "MinimumPasswordLength": 14,
                                                      "RequireSymbols": True}
    w = KIT.clean_world()
    w.deny("iam", "GetAccountPasswordPolicy")
    r = KIT.run("iam", tmp_path / "denied", w)
    assert r.load("account_password_policy.json") == {"Configured": None}
    assert r.result.status == "partial"
    assert r.load("account_summary.json")["AccountMFAEnabled"] == 1


# ── credentials ──────────────────────────────────────────────────────────────
@pytest.mark.finding("F-148", "F-167")
def test_credential_report_is_polled_parsed_and_replaces_per_user_calls(tmp_path):
    r = KIT.run("iam", tmp_path, KIT.clean_world())
    assert len(KIT.sent(r, "iam", "GenerateCredentialReport")) == 2      # STARTED, then COMPLETE
    assert len(KIT.sent(r, "iam", "GetCredentialReport")) == 1
    assert not iam_ops(r) & {"GetLoginProfile", "ListMFADevices"}       # no NoSuchEntity bursts (F-167)
    report = r.load("credential_report.json")
    assert report["GeneratedTime"] == "2024-01-15T09:00:00Z"
    assert report["Rows"][0]["user"] == "<root_account>" and report["Rows"][0]["mfa_active"] == "true"
    assert [row["user"] for row in report["Rows"][1:]] == ["demo-alice", "demo-bob", "demo-ci"]
    users = KIT.by(r.load("users.json"), "UserName")
    alice = users["demo-alice"]
    assert (alice["HasLoginProfile"], alice["MFAActive"]) == (True, True)
    assert alice["PasswordLastUsed"] == "2024-01-14T10:00:00Z"
    assert alice["MFADevices"] == [{"SerialNumber": f"arn:aws:iam::{KIT.ACCT}:mfa/demo-alice", "Source": "virtual"}]
    assert alice["AccessKeys"] == [{"AccessKeyId": "AKIAEXAMPLEALICE0001", "Status": "Active",
                                    "LastRotated": "2024-01-03T10:00:00Z", "LastUsedDate": "2024-01-14T10:00:00Z",
                                    "LastUsedService": "s3", "LastUsedRegion": "eu-west-2"}]
    bob = users["demo-bob"]
    assert (bob["HasLoginProfile"], bob["MFAActive"], bob["MFADevices"]) == (False, False, [])
    assert [(k["AccessKeyId"], k["Status"], k["LastUsedDate"]) for k in bob["AccessKeys"]] == [
        ("AKIAEXAMPLEBOB000001", "Active", "2024-01-14T10:00:00Z"), ("AKIAEXAMPLEBOB000002", "Inactive", None)]


@pytest.mark.finding("F-148")
def test_without_a_report_each_user_gets_login_and_mfa_calls(tmp_path):
    w = KIT.world()                         # acme denies ListMFADevices for demo-bob
    w.deny("iam", "GenerateCredentialReport")
    r = KIT.run("iam", tmp_path, w)
    assert r.load("credential_report.json") == {"GeneratedTime": None, "Rows": None}
    assert len(KIT.sent(r, "iam", "GetLoginProfile")) == len(acme.USERS)
    users = KIT.by(r.load("users.json"), "UserName")
    assert users["demo-alice"]["HasLoginProfile"] is True and users["demo-ci"]["HasLoginProfile"] is False
    assert users["demo-alice"]["MFAActive"] is True
    assert users["demo-bob"]["MFAActive"] is None and users["demo-bob"]["MFADevices"] == []
    assert ("iam:ListMFADevices", "denied") in KIT.collection_errors(users["demo-bob"])
    assert [(x["status"], x["optional"]) for x in KIT.calls(r, "iam:GenerateCredentialReport")] == [
        ("denied", True)]


@pytest.mark.parametrize("options", [{"no_credential_report": True}, {"credential_report": False}])
def test_credential_report_can_be_turned_off(tmp_path, options):
    r = KIT.run("iam", tmp_path, KIT.clean_world(), options=options)
    assert "GenerateCredentialReport" not in iam_ops(r)
    assert [x["status"] for x in KIT.calls(r, "iam:GenerateCredentialReport")] == ["skipped"]
    assert r.load("credential_report.json")["Rows"] is None


@pytest.mark.finding("F-167")
def test_a_hardware_mfa_device_is_listed_with_one_targeted_call(tmp_path):
    w = WORLDS.hardware_mfa()
    w.errors = []
    r = KIT.run("iam", tmp_path, w)
    assert [p["UserName"] for p in KIT.sent(r, "iam", "ListMFADevices")] == ["demo-ci"]
    ci = KIT.by(r.load("users.json"), "UserName")["demo-ci"]
    assert ci["MFAActive"] is True
    assert ci["MFADevices"] == [{"SerialNumber": w.meta["hardware_mfa_serial"], "Source": "hardware"}]


@pytest.mark.finding("F-110", "F-111")
def test_alternate_credentials_are_listed_and_a_denial_is_marked_on_the_user(tmp_path):
    r = KIT.run("iam", tmp_path, KIT.world())     # acme denies ListSSHPublicKeys for demo-bob
    KIT.assert_contract(r, statuses=("partial",))
    users = KIT.by(r.load("users.json"), "UserName")
    assert users["demo-alice"]["SSHPublicKeys"] == [
        {"SSHPublicKeyId": "APKAEXAMPLEALICESSH01", "Status": "Active", "UploadDate": "2024-01-04T10:00:00Z"}]
    assert users["demo-ci"]["ServiceSpecificCredentials"] == [
        {"ServiceName": "codecommit.amazonaws.com", "ServiceSpecificCredentialId": "ACCAEXAMPLESERVICE001",
         "Status": "Active", "CreateDate": "2024-01-05T10:00:00Z"}]
    assert users["demo-bob"]["SigningCertificates"] == [
        {"CertificateId": "DEMOCERTBOB0000000000000000000001", "Status": "Active",
         "UploadDate": "2024-01-05T10:00:00Z"}]
    assert "BEGIN CERTIFICATE" not in json.dumps(r.load("users.json"))      # certificate bodies never kept
    assert users["demo-bob"]["SSHPublicKeys"] is None                        # unknown, not []
    assert KIT.collection_errors(users["demo-bob"]) == [("iam:ListSSHPublicKeys", "denied")]
    assert KIT.item_errors(r) == [{"resource": BOB, "api": "iam:ListSSHPublicKeys", "status": "denied",
                                   "error_code": "AccessDenied"}]


@pytest.mark.parametrize("options", [{"no_iam_user_details": True}, {"iam_user_details": False}])
def test_user_details_off_skips_the_per_user_listings(tmp_path, options):
    r = KIT.run("iam", tmp_path, KIT.clean_world(), options=options)
    assert not iam_ops(r) & {"ListAccessKeys", "ListSSHPublicKeys", "ListServiceSpecificCredentials",
                             "ListSigningCertificates"}
    alice = KIT.by(r.load("users.json"), "UserName")["demo-alice"]
    assert alice["AccessKeys"] == [{"AccessKeyId": None, "Status": "Active", "LastRotated": "2024-01-03T10:00:00Z",
                                    "LastUsedDate": "2024-01-14T10:00:00Z", "LastUsedService": "s3",
                                    "LastUsedRegion": "eu-west-2"}]
    assert (alice["SSHPublicKeys"], alice["ServiceSpecificCredentials"], alice["SigningCertificates"]) == \
        (None, None, None)
    assert {x["api"] for x in KIT.coverage(r)["calls"] if x["status"] == "skipped"} >= {
        "iam:ListAccessKeys", "iam:ListSSHPublicKeys"}


@pytest.mark.finding("F-110")
def test_oidc_and_saml_providers_are_collected(tmp_path):
    r = KIT.run("iam", tmp_path, KIT.clean_world())
    providers = r.load("identity_providers.json")
    assert [p["Arn"] for p in providers["oidc"]] == sorted(p["Arn"] for p in acme.OIDC_PROVIDERS)
    eks = KIT.by(providers["oidc"], "Arn")[acme.OIDC_PROVIDER_ARN]
    assert eks["Url"] == acme.OIDC_ISSUER and eks["ClientIDList"] == ["sts.amazonaws.com"]
    assert providers["saml"] == [{"Arn": acme.SAML_PROVIDER_ARN, "ValidUntil": "2034-01-01T10:00:00Z",
                                  "CreateDate": "2024-01-03T10:00:00Z"}]
    w = KIT.clean_world()
    w.deny("iam", "ListSAMLProviders")
    w.deny("iam", "GetOpenIDConnectProvider", {"OpenIDConnectProviderArn": acme.OIDC_PROVIDER_ARN})
    r = KIT.run("iam", tmp_path / "denied", w)
    providers = r.load("identity_providers.json")
    assert providers["saml"] is None
    eks = KIT.by(providers["oidc"], "Arn")[acme.OIDC_PROVIDER_ARN]
    assert eks["Url"] is None and KIT.collection_errors(eks) == [("iam:GetOpenIDConnectProvider", "denied")]
