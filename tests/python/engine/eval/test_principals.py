"""Principal models (``iam/principals.py``; engine.md §2.1, §2.6) and the extended legacy permission map.

F-052: the permissions boundary is a layer of the model (a boundary whose document was not collected is
``"missing"``); F-001/F-014/F-015: NotAction, Deny and conditions survive into the model and the legacy view;
group statements are inherited with ``via_group``; F-126: the SCP chain comes from the organisation model.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from aws_enumerator.engine.iam import principals as P
from aws_enumerator.engine.io.loaders.iam import load_iam
from aws_enumerator.engine.model import Decision, Strength
from aws_enumerator.engine.policy.evaluator import Evaluator
from aws_enumerator.engine.policy.org import OrgModel
from tests.support import report_builder as rb

ACCT = "111122223333"
ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
RO_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
CUST = f"arn:aws:iam::{ACCT}:policy/demo-app"


def _doc(*stmts):
    return {"Version": "2012-10-17", "Statement": list(stmts)}


def _pol(arn, name, doc, versions=None):
    versions = versions or {"v1": doc}
    return SimpleNamespace(arn=arn, name=name, default_version="v1", versions=versions,
                           document=versions.get("v1"))


def _ent(kind, name, **kw):
    arn = f"arn:aws:iam::{ACCT}:{kind}{kw.pop('path', '/')}{name}"
    base = dict(kind=kind, arn=arn, name=name, path="/", record={}, attached=[], attached_status="complete",
                inline={}, inline_status="complete", boundary_arn=None, groups=[], groups_status="complete",
                tags=[], trust_policy=None, gaps=set())
    base.update(kw)
    return SimpleNamespace(**base)


def _iam(users=(), roles=(), groups=(), policies=(), layout="gaad", gaps=None, profiles=None):
    return SimpleNamespace(layout=layout, users={u.arn: u for u in users}, roles={r.arn: r for r in roles},
                           groups={g.arn: g for g in groups}, policies={p.arn: p for p in policies},
                           gaps=gaps or {}, instance_profiles=profiles,
                           account_id=lambda: ACCT)


def _evaluator(pset, org=None):
    return Evaluator(None, pset.models, pset.resource_index(), org, account_id=pset.account_id,
                     partition=pset.partition)


@pytest.mark.finding("F-052")
def test_boundary_layer_from_the_collected_document():
    ro = _pol(RO_ARN, "ReadOnlyAccess", _doc({"Effect": "Allow", "Action": ["s3:Get*", "s3:List*"], "Resource": "*"}))
    role = _ent("role", "capped", inline={"p": _doc({"Effect": "Allow", "Action": "*", "Resource": "*"})},
                boundary_arn=RO_ARN)
    pset = P.build_principal_set(_iam(roles=[role], policies=[ro]))
    model = pset.models[role.arn]
    assert isinstance(model.boundary, tuple) and model.boundary[0].source.layer == "boundary"
    ev = _evaluator(pset)
    assert ev.evaluate(model, "s3:GetObject", "arn:aws:s3:::b/k").decision is Decision.ALLOW
    result = ev.evaluate(model, "iam:CreateUser", "*")
    assert result.decision is Decision.NOT_ALLOWED and result.reason == "boundary"


@pytest.mark.finding("F-052")
def test_boundary_without_document_is_missing_and_conditional():
    role = _ent("role", "capped", inline={"p": _doc({"Effect": "Allow", "Action": "*", "Resource": "*"})},
                boundary_arn=RO_ARN)
    pset = P.build_principal_set(_iam(roles=[role]))
    assert pset.models[role.arn].boundary == "missing"
    result = _evaluator(pset).evaluate(role.arn, "iam:CreateUser", "*")
    assert result.decision is Decision.CONDITIONAL and result.strength is Strength.STRONG
    assert "boundary:doc-missing" in result.gaps


@pytest.mark.finding("F-001", "F-014")
def test_group_statements_are_inherited_with_via_group_and_denies_count():
    group = _ent("group", "power", attached=[CUST])
    cust = _pol(CUST, "demo-app", _doc({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}))
    user = _ent("user", "dev", groups=[group.arn],
                inline={"guard": _doc({"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"})})
    pset = P.build_principal_set(_iam(users=[user], groups=[group], policies=[cust]))
    model = pset.models[user.arn]
    assert {s.source.via_group for s in model.identity} == {None, group.arn}
    assert pset.group_members == {group.arn: [user.arn]}
    assert pset.policy_holders == {CUST: [group.arn]}
    ev = _evaluator(pset)
    assert ev.evaluate(model, "s3:GetObject", "arn:aws:s3:::b/k").decision is Decision.ALLOW
    assert ev.evaluate(model, "s3:DeleteObject", "arn:aws:s3:::b/k").decision is Decision.DENY
    assert ev.evaluate(model, "iam:PassRole", f"arn:aws:iam::{ACCT}:role/x").decision is Decision.NOT_ALLOWED
    group_model = pset.models[group.arn]
    assert group_model.identity and all(s.source.via_group is None for s in group_model.identity)


def test_action_index_prefilters_by_service():
    stmts = P.build_principal_set(_iam(roles=[_ent("role", "r", inline={"p": _doc(
        {"Effect": "Allow", "Action": ["s3:GetObject", "ec2:Describe*"], "Resource": "*"},
        {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
        {"Effect": "Allow", "Action": "*", "Resource": "*"})})])).models[f"arn:aws:iam::{ACCT}:role/r"]
    idx = stmts.action_index
    assert idx.by_service == {"ec2": (0,), "s3": (0,)} and idx.wildcard == (1, 2)
    assert idx.may_cover("lambda") and P.build_action_index(()).may_cover("s3") is False


def test_gaps_tags_service_linked_trust_versions_and_profiles():
    trust = _doc({"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"})
    slr = _ent("role", "AWSServiceRoleForDemo", path="/aws-service-role/demo.amazonaws.com/",
               trust_policy=trust)
    slr.path = "/aws-service-role/demo.amazonaws.com/"
    role = _ent("role", "app", trust_policy=trust, attached=[CUST], attached_status="denied",
                tags=[("team", "red")])
    cust = _pol(CUST, "demo-app", _doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}),
                versions={"v1": _doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}),
                          "v2": _doc({"Effect": "Allow", "Action": "*", "Resource": "*"})})
    user = _ent("user", "dev", record={"HasLoginProfile": True}, inline_status="partial")
    profiles = [{"InstanceProfileName": "p", "Roles": [{"Arn": role.arn}]}]
    pset = P.build_principal_set(_iam(users=[user], roles=[slr, role], policies=[cust], profiles=profiles,
                                      gaps={"iam:groups-denied": "groups.json is denied"}))
    assert pset.models[slr.arn].is_service_linked and not pset.models[role.arn].is_service_linked
    assert "iam:attached-unknown" in pset.models[role.arn].gaps and pset.models[role.arn].tags == {"team": "red"}
    assert "iam:inline-unknown" in pset.models[user.arn].gaps
    assert set(pset.trust) == {slr.arn, role.arn}
    assert sorted(pset.policy_versions[CUST]) == ["v1", "v2"]
    assert pset.policy_versions[CUST]["v1"].is_default_version
    assert pset.login_profiles == {user.arn: True}
    assert pset.instance_profile_roles == frozenset({role.arn})
    assert pset.listing_complete["group"] is False and pset.listing_complete["user"] is True
    trust_idx = pset.resource_index()
    assert trust_idx.status(role.arn, "trust") == "present"


def test_unreadable_policies_make_allows_conditional():
    role = _ent("role", "app", inline={"p": _doc({"Effect": "Allow", "Action": "s3:*", "Resource": "*"})},
                inline_status="partial")
    ev = _evaluator(P.build_principal_set(_iam(roles=[role])))
    result = ev.evaluate(role.arn, "s3:GetObject", "arn:aws:s3:::b/k")
    assert result.decision is Decision.CONDITIONAL and "iam:inline-unknown" in result.gaps


def test_legacy_layout_marks_tags_unknown_and_has_no_versions():
    role = _ent("role", "app", attached=[CUST], tags=[])
    cust = _pol(CUST, "demo-app", _doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}))
    pset = P.build_principal_set(_iam(roles=[role], policies=[cust], layout="legacy"))
    assert "iam:tags-unknown" in pset.models[role.arn].gaps
    assert pset.policy_versions[CUST] is None


@pytest.mark.finding("F-126")
def test_scp_chain_comes_from_the_org_model():
    org = OrgModel.from_documents(
        {"InOrganization": True, "Id": "o-exampleorgid", "ManagementAccountId": "000000000000",
         "AvailablePolicyTypes": [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}]},
        ["r-ex12", ACCT],
        [{"PolicyId": "p-1", "Type": "SERVICE_CONTROL_POLICY", "Targets": ["r-ex12", ACCT],
          "Content": _doc({"Effect": "Allow", "Action": "*", "Resource": "*"},
                          {"Effect": "Deny", "Action": "iam:*", "Resource": "*"})}], account_id=ACCT)
    role = _ent("role", "admin", inline={"p": _doc({"Effect": "Allow", "Action": "*", "Resource": "*"})})
    pset = P.build_principal_set(_iam(roles=[role]), org=org)
    assert pset.models[role.arn].scp_chain is not None and len(pset.models[role.arn].scp_chain) == 2
    assert _evaluator(pset, org).evaluate(role.arn, "iam:CreateUser", "*").decision is Decision.DENY


@pytest.mark.finding("F-052", "F-001", "F-014")
def test_gaad_tree_through_the_iam_loader(tmp_path):
    """End to end through E-core's loader: the boundary document is collected in the GAAD layout."""
    iam = rb.Iam(ACCT)
    iam.managed("ReadOnlyAccess", rb.AWS_MANAGED_DOCS["ReadOnlyAccess"])
    boundary = {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": RO_ARN}
    iam.role("demo-capped", rb.trust({"Service": "ec2.amazonaws.com"}), inline={"p": [rb.allow("*", "*")]},
             extra={"PermissionsBoundary": boundary})
    iam.group("demo-power", attached=["PowerUserAccess"])
    iam.user("demo-dev", groups=["demo-power"], inline={"q": [rb.deny("s3:DeleteObject", "*")]})
    scope = rb.Scope(tmp_path, ACCT, "global")
    iam.write(scope, layout="gaad")
    pset = P.build_principal_set(load_iam(scope.path), account_id=ACCT, partition="aws")
    ev = _evaluator(pset)
    capped = f"arn:aws:iam::{ACCT}:role/demo-capped"
    assert isinstance(pset.models[capped].boundary, tuple)
    assert ev.evaluate(capped, "iam:CreateUser", "*").decision is Decision.NOT_ALLOWED
    assert ev.evaluate(capped, "s3:GetObject", "arn:aws:s3:::b/k").decision is Decision.ALLOW
    dev = f"arn:aws:iam::{ACCT}:user/demo-dev"
    assert ev.evaluate(dev, "lambda:UpdateFunctionCode", f"arn:aws:lambda:eu-west-2:{ACCT}:function:f").decision \
        is Decision.ALLOW
    assert ev.evaluate(dev, "s3:DeleteObject", "arn:aws:s3:::b/k").decision is Decision.DENY


# ── legacy permission map ────────────────────────────────────────────────────

def _legacy_map(doc, *, boundary=None, docs=None, attached=None):
    role = {"RoleName": "r", "Arn": f"arn:aws:iam::{ACCT}:role/r",
            "AssumeRolePolicyDocument": _doc({"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                                              "Action": "sts:AssumeRole"})}
    if boundary:
        role["PermissionsBoundary"] = {"PermissionsBoundaryArn": boundary}
    inline = {"users": {}, "roles": {"r": {"p": doc}}, "groups": {}}
    return P._build_permission_map([], [role], {"r": attached or []}, {}, {}, docs or {}, inline, {})


@pytest.mark.finding("F-001", "F-014", "F-015")
def test_legacy_map_keeps_what_d13c215_dropped():
    pm = _legacy_map(_doc({"Sid": "Power", "Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
                          {"Effect": "Deny", "Action": "s3:*", "NotResource": "arn:aws:s3:::keep/*",
                           "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}}))
    entry = pm["roles"]["r"]
    (allow_entry,) = entry["effective_statements"]
    assert allow_entry["actions"] == [] and allow_entry["not_actions"] == ["iam:*"] and allow_entry["sid"] == "Power"
    (deny_entry,) = entry["deny_statements"]
    assert deny_entry["not_resources"] == ["arn:aws:s3:::keep/*"] and "conditions" in deny_entry
    assert entry["trust_policy"]["Statement"][0]["Principal"] == {"Service": "ec2.amazonaws.com"}


def test_legacy_map_entry_without_new_features_keeps_the_d13c215_shape():
    pm = _legacy_map(_doc({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}))
    assert pm["roles"]["r"]["effective_statements"] == [
        {"actions": ["s3:GetObject"], "resources": ["*"], "source": "p", "source_type": "inline"}]
    assert list(pm["roles"]["r"]) == ["arn", "attached_policies", "inline_policies", "effective_statements",
                                      "trust_policy"]


@pytest.mark.finding("F-052")
def test_legacy_map_records_the_boundary_and_the_models_honour_it():
    ro = {"PolicyName": "ReadOnlyAccess", "PolicyArn": RO_ARN,
          "Document": _doc({"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"})}
    pm = _legacy_map(_doc({"Effect": "Allow", "Action": "*", "Resource": "*"}), boundary=RO_ARN,
                     docs={"ReadOnlyAccess": ro})
    assert pm["roles"]["r"]["permissions_boundary"]["status"] == "collected"
    pset = P.models_from_permission_map(pm)
    ev = _evaluator(pset)
    arn = f"arn:aws:iam::{ACCT}:role/r"
    assert ev.evaluate(arn, "iam:CreateUser", "*").decision is Decision.NOT_ALLOWED
    missing = _legacy_map(_doc({"Effect": "Allow", "Action": "*", "Resource": "*"}), boundary=RO_ARN)
    assert missing["roles"]["r"]["permissions_boundary"] == {"arn": RO_ARN, "status": "missing"}
    assert P.models_from_permission_map(missing).models[arn].boundary == "missing"


def test_legacy_map_group_propagation_includes_denies_and_policy_arns():
    users = [{"UserName": "u", "Arn": f"arn:aws:iam::{ACCT}:user/u"}]
    docs = {"demo-app": {"PolicyName": "demo-app", "PolicyArn": CUST,
                         "Document": _doc({"Effect": "Allow", "Action": "s3:*", "Resource": "*"})}}
    inline = {"users": {}, "roles": {}, "groups": {"g": {"x": _doc({"Effect": "Deny", "Action": "s3:Delete*",
                                                                     "Resource": "*"})}}}
    pm = P._build_permission_map(users, [], {}, {}, {"g": [{"PolicyName": "demo-app", "PolicyArn": CUST}]}, docs,
                                 inline, {"u": [{"GroupName": "g"}]})
    user = pm["users"]["u"]
    assert user["effective_statements"][0]["via_group"] == "g" and user["effective_statements"][0]["policy_arn"] == CUST
    assert user["deny_statements"][0]["via_group"] == "g"
    pset = P.models_from_permission_map(pm)
    assert pset.policy_holders == {CUST: [f"arn:aws:iam::{ACCT}:group/g"]}
    ev = _evaluator(pset)
    assert ev.evaluate(f"arn:aws:iam::{ACCT}:user/u", "s3:DeleteObject", "arn:aws:s3:::b/k").decision is Decision.DENY


def test_legacy_map_records_unreadable_policies_as_gaps():
    users = [{"UserName": "u", "Arn": f"arn:aws:iam::{ACCT}:user/u"}]
    inline = {"users": {"u": {"bad": {"Error": "AccessDenied"}}}, "roles": {}, "groups": {}}
    pm = P._build_permission_map(users, [], {}, {"u": {"Error": "AccessDenied"}}, {}, {}, inline, {})
    assert pm["users"]["u"]["inline_policy_errors"] == ["bad"]
    assert pm["users"]["u"]["attached_policies_error"] == "AccessDenied"
    gaps = P.models_from_permission_map(pm).models[f"arn:aws:iam::{ACCT}:user/u"].gaps
    assert {"iam:inline-unknown", "iam:attached-unknown"} <= gaps


def test_principals_analyzer_registers_phase_principals():
    (spec,) = P.ANALYZERS
    assert (spec.name, spec.phase.name, spec.inputs) == ("principals", "PRINCIPALS", ("iam.authorization_details",))
