"""The rules runner (engine.md §3; F-001, F-012, F-014, F-015, F-017, F-019, F-052, F-069, F-071, F-126).

Every rule goes through the evaluator per principal and per target; tests build a small IAM world (the loader's
``IamData`` shape), run the catalogue and assert findings, severities, targets, provenance and edges.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from aws_enumerator.engine.graph.builder import GraphBuilder
from aws_enumerator.engine.iam.principals import build_principal_set
from aws_enumerator.engine.model import Decision, Strength
from aws_enumerator.engine.policy.evaluator import Evaluator
from aws_enumerator.engine.policy.org import OrgModel
from aws_enumerator.engine.rules import runner as R
from aws_enumerator.engine.rules import severity as sev

ACCT = "111122223333"
ADMIN_DOC = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
CUST = f"arn:aws:iam::{ACCT}:policy/demo-app"


def doc(*stmts):
    return {"Version": "2012-10-17", "Statement": list(stmts)}


def allow(action="*", resource="*", cond=None, **kw):
    s = {"Effect": "Allow", "Action": action, "Resource": resource}
    if cond:
        s["Condition"] = cond
    s.update(kw)
    return s


def deny(action="*", resource="*"):
    return {"Effect": "Deny", "Action": action, "Resource": resource}


def trusts(service):
    return doc({"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"})


class World:
    """A tiny IAM world in the loader's ``IamData`` shape."""

    def __init__(self):
        self.users: Dict[str, Any] = {}
        self.roles: Dict[str, Any] = {}
        self.groups: Dict[str, Any] = {}
        self.policies: Dict[str, Any] = {}
        self.layout = "gaad"
        self.org: Optional[OrgModel] = None

    def _ent(self, kind, name, statements=(), **kw):
        arn = f"arn:aws:iam::{ACCT}:{kind}{kw.pop('path', '/')}{name}"
        ent = SimpleNamespace(kind=kind, arn=arn, name=name, path=kw.pop("ent_path", "/"), record=kw.pop("record", {}),
                              attached=kw.pop("attached", []), attached_status="complete",
                              inline={"p": doc(*statements)} if statements else {}, inline_status="complete",
                              boundary_arn=kw.pop("boundary_arn", None), groups=kw.pop("groups", []),
                              groups_status="complete", tags=[], trust_policy=kw.pop("trust", None), gaps=set())
        getattr(self, kind + "s")[arn] = ent
        return arn

    def user(self, name, statements=(), **kw):
        return self._ent("user", name, statements, **kw)

    def role(self, name, statements=(), trust=None, **kw):
        return self._ent("role", name, statements, trust=trust or trusts("ec2.amazonaws.com"), **kw)

    def group(self, name, statements=(), **kw):
        return self._ent("group", name, statements, **kw)

    def policy(self, arn, versions, default="v1"):
        self.policies[arn] = SimpleNamespace(arn=arn, name=arn.rsplit("/", 1)[-1], default_version=default,
                                             versions=versions, document=versions[default])
        return arn

    def data(self):
        return SimpleNamespace(layout=self.layout, users=self.users, roles=self.roles, groups=self.groups,
                               policies=self.policies, gaps={}, instance_profiles=None, account_id=lambda: ACCT)

    def run(self, **kw):
        pset = build_principal_set(self.data(), account_id=ACCT, partition="aws", org=self.org)
        ev = Evaluator(None, pset.models, pset.resource_index(), self.org, account_id=ACCT, partition="aws")
        return R.run_rules(ev, pset, **kw), pset, ev


def hits(result, principal_arn: str, rule_id: Optional[str] = None) -> List[R.RuleHit]:
    return [h for h in result.hits if h.principal.id == principal_arn and (rule_id is None or h.rule_id == rule_id)]


def ids(result, principal_arn):
    return sorted({h.rule_id for h in hits(result, principal_arn)})


@pytest.fixture
def world():
    return World()


# ── PassRole target selection (F-012) ────────────────────────────────────────

LAMBDA_CHAIN = [allow(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"])]


@pytest.mark.finding("F-012")
def test_no_role_trusting_the_service_gives_an_info_note(world):
    dev = world.user("dev", LAMBDA_CHAIN)
    world.role("ec2-admin", [allow()], trust=trusts("ec2.amazonaws.com"))
    (hit,) = hits(world.run()[0], dev, "PRIVESC-014")
    assert (hit.severity, hit.no_candidate, hit.edges) == ("INFO", True, [])
    assert "lambda.amazonaws.com" in hit.title


@pytest.mark.finding("F-012")
def test_admin_role_trusting_the_service_is_critical_with_a_pass_role_edge(world):
    dev = world.user("dev", LAMBDA_CHAIN)
    admin = world.role("fn-admin", [allow()], trust=trusts("lambda.amazonaws.com"))
    (hit,) = hits(world.run()[0], dev, "PRIVESC-014")
    assert hit.severity == "CRITICAL" and [t.target.arn for t in hit.targets] == [admin]
    assert hit.targets[0].tier == "admin"
    (edge,) = hit.edges
    assert (edge.source, edge.edge_type, edge.target) == (dev, "CAN_PASS_ROLE_TO", admin)
    assert edge.evidence["via"] == ["lambda"] and edge.evidence["rule_ids"] == ["PRIVESC-014"]


@pytest.mark.finding("F-012", "F-017")
def test_passrole_scoped_to_a_low_privilege_role_is_medium(world):
    low = world.role("fn-low", [allow("logs:CreateLogStream")], trust=trusts("lambda.amazonaws.com"))
    world.role("fn-admin", [allow()], trust=trusts("lambda.amazonaws.com"))
    dev = world.user("dev", [allow("iam:PassRole", low), allow(["lambda:CreateFunction", "lambda:InvokeFunction"])])
    (hit,) = hits(world.run()[0], dev, "PRIVESC-014")
    assert hit.severity == "MEDIUM" and [t.target.arn for t in hit.targets] == [low]


@pytest.mark.finding("F-012")
def test_roles_no_more_privileged_than_the_caller_are_not_candidates(world):
    caller = world.role("caller", [allow(["iam:PassRole", "lambda:*", "s3:*"])])
    world.role("fn-s3", [allow("s3:*")], trust=trusts("lambda.amazonaws.com"))
    (hit,) = hits(world.run()[0], caller, "PRIVESC-014")
    assert hit.no_candidate and hit.severity == "INFO"


@pytest.mark.finding("F-015")
def test_passed_to_service_scoped_to_another_service_does_not_fire(world):
    world.role("fn-admin", [allow()], trust=trusts("lambda.amazonaws.com"))
    ec2_only = {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}
    dev = world.user("dev", [allow("iam:PassRole", "*", ec2_only),
                             allow(["lambda:CreateFunction", "lambda:InvokeFunction"])])
    lambda_only = {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}
    ok = world.user("ok", [allow("iam:PassRole", "*", lambda_only),
                           allow(["lambda:CreateFunction", "lambda:InvokeFunction"])])
    result = world.run()[0]
    assert hits(result, dev, "PRIVESC-014") == []
    assert hits(result, ok, "PRIVESC-014")[0].severity == "CRITICAL"


@pytest.mark.finding("F-015")
def test_an_mfa_condition_makes_the_finding_conditional_and_lower(world):
    world.role("fn-admin", [allow()], trust=trusts("lambda.amazonaws.com"))
    mfa = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    dev = world.user("dev", [allow(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "*", mfa)])
    (hit,) = hits(world.run()[0], dev, "PRIVESC-014")
    assert hit.decision is Decision.CONDITIONAL and hit.strength is Strength.WEAK
    assert (hit.base_severity, hit.severity) == ("CRITICAL", "HIGH")


# ── chain completeness (F-069) ───────────────────────────────────────────────

@pytest.mark.finding("F-069")
@pytest.mark.parametrize("actions,fires", [
    (["lambda:CreateFunction"], False),
    (["lambda:CreateFunction", "lambda:CreateEventSourceMapping"], True),
    (["lambda:CreateFunction", "lambda:AddPermission"], False),
    (["lambda:CreateFunction", "lambda:AddPermission", "lambda:CreateFunctionUrlConfig"], True),
    (["lambda:UpdateFunctionCode"], False),
])
def test_lambda_chain(world, actions, fires):
    world.role("fn-admin", [allow()], trust=trusts("lambda.amazonaws.com"))
    dev = world.user("dev", [allow(["iam:PassRole"] + actions)])
    assert bool(hits(world.run()[0], dev, "PRIVESC-014")) is fires


@pytest.mark.finding("F-069")
@pytest.mark.parametrize("actions,fires", [
    (["ecs:RegisterTaskDefinition"], False),
    (["ecs:RegisterTaskDefinition", "ecs:CreateService"], True),
    (["ecs:RegisterTaskDefinition", "ecs:UpdateService"], True),
    (["ecs:RunTask"], True),
    (["ecs:CreateService"], False),
])
def test_ecs_chain(world, actions, fires):
    world.role("task-admin", [allow()], trust=trusts("ecs-tasks.amazonaws.com"))
    dev = world.user("dev", [allow(["iam:PassRole"] + actions)])
    assert bool(hits(world.run()[0], dev, "PRIVESC-017")) is fires


@pytest.mark.finding("F-069")
@pytest.mark.parametrize("actions,fires", [
    (["glue:CreateJob"], False), (["glue:CreateJob", "glue:StartJobRun"], True), (["glue:CreateDevEndpoint"], True),
])
def test_glue_chain(world, actions, fires):
    world.role("glue-admin", [allow()], trust=trusts("glue.amazonaws.com"))
    dev = world.user("dev", [allow(["iam:PassRole"] + actions)])
    assert bool(hits(world.run()[0], dev, "PRIVESC-018")) is fires


@pytest.mark.finding("F-069")
def test_existing_resource_hijack_needs_no_passrole(world):
    admin = world.role("fn-admin", [allow()], trust=trusts("lambda.amazonaws.com"))
    dev = world.user("dev", [allow("lambda:UpdateFunctionCode")])
    fn = f"arn:aws:lambda:eu-west-2:{ACCT}:function:demo"
    existing = {"lambda_function": [R.ExistingResource("lambda_function", fn, admin, "demo")]}
    result = world.run(existing=existing)[0]
    (hit,) = hits(result, dev, "PRIVESC-021")
    assert hit.severity == "CRITICAL" and hit.edges[0].edge_type == "CAN_UPDATE_CODE" and hit.edges[0].target == fn
    assert hits(world.run()[0], dev, "PRIVESC-021") == []          # nothing collected, nothing claimed


def test_existing_inventory_from_loader_data():
    data = {"lambda": {"functions": {"eu-west-2": [{"FunctionArn": f"arn:aws:lambda:eu-west-2:{ACCT}:function:f:3",
                                                    "Role": f"arn:aws:iam::{ACCT}:role/r", "FunctionName": "f"}]}},
            "compute": {"glue": {"eu-west-2": [{"Type": "gluedevendpoint", "Arn": "arn:aws:glue:eu-west-2:"
                                                f"{ACCT}:devEndpoint/e", "Roles": [f"arn:aws:iam::{ACCT}:role/g"]}]},
                        "codebuild": {"eu-west-2": [{"Type": "gluejob", "Arn": "x", "Roles": ["y"]}]}}}
    inv = R.existing_from_data(data)
    assert inv["lambda_function"][0].arn == f"arn:aws:lambda:eu-west-2:{ACCT}:function:f"
    assert inv["glue_dev_endpoint"][0].role_arn == f"arn:aws:iam::{ACCT}:role/g"
    assert inv["codebuild_project"] == []


# ── resource scope and self-scope (F-017) ────────────────────────────────────

@pytest.mark.finding("F-017")
def test_self_service_credentials_are_not_takeover(world):
    other = world.user("victim")
    dev = world.user("dev", [allow(["iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile"],
                                   f"arn:aws:iam::{ACCT}:user/${{aws:username}}")])
    result = world.run()[0]
    assert ids(result, dev) == []
    assert other in world.users


@pytest.mark.finding("F-017")
def test_takeover_targets_are_concrete_other_users(world):
    admin = world.user("admin", [allow()])
    world.user("reader", [allow("s3:GetObject")], record={"HasLoginProfile": True})
    dev = world.user("dev", [allow("iam:CreateAccessKey", f"arn:aws:iam::{ACCT}:user/admin"),
                             allow("iam:CreateLoginProfile")])
    result = world.run()[0]
    (keys,) = hits(result, dev, "PRIVESC-009")
    assert [t.target.arn for t in keys.targets] == [admin] and keys.severity == "CRITICAL"
    assert [(e.edge_type, e.target) for e in keys.edges] == [("CAN_TAKEOVER", admin)]
    (login,) = hits(result, dev, "PRIVESC-010")
    assert {t.target.arn for t in login.targets} == {admin}    # 'reader' already has a console password


@pytest.mark.finding("F-017")
def test_put_role_policy_on_self_is_critical_on_another_role_high(world):
    self_role = world.role("self", [allow("iam:PutRolePolicy", f"arn:aws:iam::{ACCT}:role/self")])
    other = world.role("other", [allow("s3:GetObject")])
    scoped = world.role("scoped", [allow("iam:PutRolePolicy", other)])
    result = world.run()[0]
    (mine,) = hits(result, self_role, "PRIVESC-005")
    assert mine.severity == "CRITICAL" and mine.edges[0].edge_type == "CAN_ESCALATE"
    assert mine.edges[0].target == f"aws-enumerator:account-admin/{ACCT}"
    (theirs,) = hits(result, scoped, "PRIVESC-005")
    assert theirs.severity == "HIGH" and [(e.edge_type, e.target) for e in theirs.edges] == [
        ("CAN_MODIFY_PERMISSIONS_OF", other)]


@pytest.mark.finding("F-017")
def test_probe_target_when_no_principal_of_the_kind_exists(world):
    role = world.role("r", [allow("iam:AttachUserPolicy")])
    (hit,) = hits(world.run()[0], role, "PRIVESC-006")
    assert hit.targets[0].target.probe and hit.targets[0].tier == "probe" and hit.severity == "HIGH"
    assert hit.edges == []


def test_attach_policy_probes_the_admin_policy_arn(world):
    only_ro = {"ArnEquals": {"iam:PolicyARN": "arn:aws:iam::aws:policy/ReadOnlyAccess"}}
    role = world.role("r", [allow("iam:AttachRolePolicy", f"arn:aws:iam::{ACCT}:role/r", only_ro)])
    assert hits(world.run()[0], role, "PRIVESC-008") == []


def test_add_user_to_group_severity_follows_the_group(world):
    admins = world.group("admins", [allow()])
    readers = world.group("readers", [allow("s3:GetObject")])
    dev = world.user("dev", [allow("iam:AddUserToGroup", f"arn:aws:iam::{ACCT}:group/*")], groups=[readers])
    (hit,) = hits(world.run()[0], dev, "PRIVESC-012")
    assert [t.target.arn for t in hit.targets] == [admins] and hit.severity == "CRITICAL"


def test_update_assume_role_policy_skips_service_linked_roles(world):
    world.role("AWSServiceRoleForDemo", [allow()], ent_path="/aws-service-role/demo.amazonaws.com/")
    dev = world.user("dev", [allow("iam:UpdateAssumeRolePolicy")])
    (hit,) = hits(world.run()[0], dev, "PRIVESC-013")
    assert hit.targets[0].target.probe


def test_policy_version_rules(world):
    v1 = doc(allow("s3:GetObject"))
    world.policy(CUST, {"v1": v1, "v2": doc(allow())})
    holder = world.role("app", attached=[CUST])
    dev = world.user("dev", [allow(["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"])])
    result = world.run()[0]
    (create,) = hits(result, dev, "PRIVESC-001")
    assert create.severity == "HIGH" and create.edges[0].target == holder
    (setdef,) = hits(result, dev, "PRIVESC-002")
    assert setdef.decision is Decision.ALLOW
    same = World()
    same.policy(CUST, {"v1": v1, "v2": doc(allow("s3:ListBucket"))})
    same.role("app", attached=[CUST])
    dev2 = same.user("dev", [allow("iam:SetDefaultPolicyVersion")])
    assert hits(same.run()[0], dev2, "PRIVESC-002") == []      # no version grants more (F-110)
    legacy = World()
    legacy.layout = "legacy"
    legacy.policy(CUST, {"v1": v1})
    legacy.role("app", attached=[CUST])
    dev3 = legacy.user("dev", [allow("iam:SetDefaultPolicyVersion")])
    (cond,) = hits(legacy.run()[0], dev3, "PRIVESC-002")
    assert cond.decision is Decision.CONDITIONAL and "iam:versions-not-collected" in cond.gaps


# ── provenance (F-071) ───────────────────────────────────────────────────────

@pytest.mark.finding("F-071")
def test_provenance_lists_the_any_alternative_and_wildcard_statements_first(world):
    world.role("fn-admin", [allow()], trust=trusts("lambda.amazonaws.com"))
    dev = world.user("dev", [allow("iam:PassRole", f"arn:aws:iam::{ACCT}:role/limited", Sid="Narrow"),
                             allow("iam:PassRole", "*", Sid="Wide"),
                             allow(["lambda:CreateFunction", "lambda:CreateEventSourceMapping"], Sid="Fn")])
    (hit,) = hits(world.run()[0], dev, "PRIVESC-014")
    assert set(hit.matched_actions) == {"iam:passrole", "lambda:createfunction", "lambda:createeventsourcemapping"}
    passrole = next(s for s in hit.steps if s["rule_action"] == "iam:passrole")
    assert [g["sid"] for g in passrole["granted"]] == ["Wide"]
    assert passrole["context"] == {"iam:PassedToService": "lambda.amazonaws.com"}
    legacy = R.legacy_finding(hit, entity_kind="user", entity_name="dev", entity_arn=dev)
    assert legacy["source_policy"] == "p" and legacy["resource"] == ["*"]
    assert legacy["matched_actions"] == list(hit.matched_actions)
    assert legacy["evidence"]["steps"][0]["granted"][0]["statement_index"] == 1


# ── DANGER capabilities (F-019, F-001, F-014, F-052, F-126) ──────────────────

POWER = {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"], "Resource": "*"}


@pytest.mark.finding("F-001")
def test_poweruser_gets_the_capabilities_it_really_grants(world):
    role = world.role("power", [POWER])
    result = world.run()[0]
    assert ids(result, role) == ["DANGER-003", "DANGER-004", "DANGER-005", "DANGER-007", "DANGER-008",
                                 "DANGER-009", "DANGER-010"]


@pytest.mark.finding("F-001")
def test_star_with_notresource_is_full_iam_control_not_admin(world):
    role = world.role("star", [{"Effect": "Allow", "Action": "*", "NotResource": ["arn:aws:s3:::demo/*"]}])
    found = ids(world.run()[0], role)
    assert "DANGER-002" in found and "DANGER-001" not in found and "DANGER-003" not in found


@pytest.mark.finding("F-019")
@pytest.mark.parametrize("statement,rule_id", [
    (allow("iam:PassRole", f"arn:aws:iam::{ACCT}:role/*"), "DANGER-006"),
    (allow("iam:PassRole", "arn:aws:iam::*:role/*"), "DANGER-006"),
    (allow("sts:AssumeRole", "arn:aws:iam::*:role/*"), "DANGER-005"),
    (allow("secretsmanager:GetSecretValue", "arn:aws:secretsmanager:*:*:secret:*"), "DANGER-008"),
    (allow("kms:Decrypt", "arn:aws:kms:*:*:key/*"), "DANGER-010"),
    (allow("s3:*", "arn:aws:s3:::*"), "DANGER-003"),
    (allow("iam:*", "arn:aws:iam::*:*"), "DANGER-002"),
    (allow("ssm:GetParameter"), "DANGER-009"),
    (allow("ssm:GetParametersByPath"), "DANGER-009"),
])
def test_unrestricted_means_every_resource_of_the_type(world, statement, rule_id):
    role = world.role("r", [statement])
    assert rule_id in ids(world.run(privesc=False)[0], role)


@pytest.mark.finding("F-019")
def test_scoped_grants_are_not_unrestricted(world):
    role = world.role("r", [allow("iam:PassRole", f"arn:aws:iam::{ACCT}:role/app-*"),
                            allow("secretsmanager:GetSecretValue", "arn:aws:secretsmanager:*:*:secret:app/*")])
    assert ids(world.run(privesc=False)[0], role) == []


@pytest.mark.finding("F-014")
def test_denies_remove_rules(world):
    deny_iam = world.role("deny-iam", [allow(), deny("iam:*")])
    quarantined = world.role("quarantined", [allow(), deny()])
    world.role("fn-admin", [allow()], trust=trusts("lambda.amazonaws.com"))
    result = world.run()[0]
    assert not [i for i in ids(result, deny_iam) if i.startswith("PRIVESC")]
    assert "DANGER-001" not in ids(result, deny_iam) and "DANGER-002" not in ids(result, deny_iam)
    assert ids(result, quarantined) == []


@pytest.mark.finding("F-052")
def test_boundary_caps_an_admin(world):
    ro = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    world.policy(ro, {"v1": doc(allow(["s3:Get*", "s3:List*"]))})
    capped = world.role("capped", [allow()], boundary_arn=ro)
    missing = world.role("capped-missing", [allow()], boundary_arn="arn:aws:iam::aws:policy/NotCollected")
    result = world.run()[0]
    assert ids(result, capped) == []
    hit = hits(result, missing, "DANGER-001")[0]
    assert hit.decision is Decision.CONDITIONAL and hit.strength is Strength.STRONG and hit.severity == "MEDIUM"


@pytest.mark.finding("F-126")
def test_scp_removes_iam_escalation(world):
    world.org = OrgModel.from_documents(
        {"InOrganization": True, "Id": "o-exampleorgid", "ManagementAccountId": "000000000000",
         "AvailablePolicyTypes": [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}]},
        ["r-ex12", ACCT], [{"PolicyId": "p-1", "Type": "SERVICE_CONTROL_POLICY", "Targets": ["r-ex12", ACCT],
                            "Content": doc(allow(), deny("iam:*"))}], account_id=ACCT)
    admin = world.role("admin", [allow()])
    found = ids(world.run()[0], admin)
    assert not [i for i in found if i.startswith("PRIVESC-0") and int(i[-3:]) <= 13]
    assert "DANGER-002" not in found and "DANGER-003" in found


# ── severity policy ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("base,strength,conditional,expected", [
    ("CRITICAL", Strength.NONE, True, "CRITICAL"), ("CRITICAL", Strength.WEAK, True, "HIGH"),
    ("CRITICAL", Strength.STRONG, True, "MEDIUM"), ("LOW", Strength.STRONG, True, "INFO"),
    ("INFO", Strength.WEAK, True, "INFO"), ("HIGH", Strength.STRONG, False, "HIGH"),
])
def test_conditional_downgrade(base, strength, conditional, expected):
    assert sev.adjust(base, strength, conditional=conditional) == expected


def test_base_severity_by_class():
    assert sev.base_severity("principal-modification", "CRITICAL", self_target=True, tiers=[]) == "CRITICAL"
    assert sev.base_severity("principal-modification", "CRITICAL", self_target=False, tiers=["admin"]) == "HIGH"
    assert sev.base_severity("new-passrole", "derived", self_target=False, tiers=["medium", "admin"]) == "CRITICAL"
    assert sev.base_severity("new-passrole", "derived", self_target=False, tiers=["high"]) == "HIGH"
    assert sev.base_severity("new-passrole", "derived", self_target=False, tiers=[], no_candidate=True) == "INFO"
    assert sev.base_severity("principal-access", "derived", self_target=False, tiers=["probe"]) == "HIGH"


# ── sinks and registration ───────────────────────────────────────────────────

def test_emit_to_builder_writes_findings_and_typed_edges(world):
    dev = world.user("dev", LAMBDA_CHAIN + [allow("iam:CreateAccessKey")])
    admin = world.role("fn-admin", [allow()], trust=trusts("lambda.amazonaws.com"))
    world.user("victim")
    result, _, _ = world.run()
    builder = GraphBuilder(account_id=ACCT)
    R.emit_to_builder(result, builder, rule_version="2.0.0")
    found = {(f.id, f.node_id) for f in builder.findings()}
    assert ("PRIVESC-014", dev) in found and ("PRIVESC-009", dev) in found
    edge = next(builder.edges("CAN_PASS_ROLE_TO"))
    assert (edge.source, edge.target, edge.traversable, edge.confidence) == (dev, admin, True, "definite")
    finding = next(f for f in builder.findings() if f.id == "PRIVESC-014" and f.node_id == dev)
    assert finding.evidence["steps"] and finding.targets[0]["tier"] == "CRITICAL" and finding.rule_version == "2.0.0"


def test_analyzers_register_phase_rules():
    (spec,) = R.ANALYZERS
    assert (spec.name, spec.phase.name, spec.requires) == ("rules", "RULES", ("principals",))


def test_results_are_deterministic(world):
    world.role("fn-admin", [allow()], trust=trusts("lambda.amazonaws.com"))
    for name in ("b", "a", "c"):
        world.user(name, LAMBDA_CHAIN)
    first = [(h.principal.id, h.rule_id, h.severity) for h in world.run()[0].hits]
    second = [(h.principal.id, h.rule_id, h.severity) for h in world.run()[0].hits]
    assert first == second
    users = [principal for principal, _, _ in first if ":user/" in principal]
    assert users == sorted(users)
