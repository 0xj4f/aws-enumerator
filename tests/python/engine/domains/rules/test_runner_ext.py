"""Runner extensions of Wave 2 (E-rules): selectors and filters the imported rules need, administrator
equivalence, uncollected resource types, and the ``finding.targets`` contract shape (``requests/e-core-1.md``)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict

import pytest

from aws_enumerator.engine.graph.builder import GraphBuilder
from aws_enumerator.engine.iam.principals import build_principal_set
from aws_enumerator.engine.model import Decision
from aws_enumerator.engine.policy.evaluator import Evaluator
from aws_enumerator.engine.rules import runner as R
from aws_enumerator.engine.rules.catalogue import load_catalogue

ACCT = "111122223333"


def doc(*stmts):
    return {"Version": "2012-10-17", "Statement": list(stmts)}


def allow(action="*", resource="*", cond=None):
    s: Dict[str, Any] = {"Effect": "Allow", "Action": action, "Resource": resource}
    if cond:
        s["Condition"] = cond
    return s


def trusts(**principal):
    return doc({"Effect": "Allow", "Principal": principal,
                "Action": "sts:AssumeRoleWithWebIdentity" if "Federated" in principal else "sts:AssumeRole"})


class World:
    def __init__(self):
        self.users: Dict[str, Any] = {}
        self.roles: Dict[str, Any] = {}
        self.groups: Dict[str, Any] = {}

    def _ent(self, kind, name, statements=(), **kw):
        arn = f"arn:aws:iam::{ACCT}:{kind}/{name}"
        getattr(self, kind + "s")[arn] = SimpleNamespace(
            kind=kind, arn=arn, name=name, path="/", record=kw.pop("record", {}), attached=[],
            attached_status="complete", inline={"p": doc(*statements)} if statements else {},
            inline_status="complete", boundary_arn=None, groups=kw.pop("groups", []), groups_status="complete",
            tags=[], trust_policy=kw.pop("trust", None), gaps=set())
        return arn

    def user(self, name, *statements, **kw):
        return self._ent("user", name, statements, **kw)

    def role(self, name, *statements, trust=None):
        return self._ent("role", name, statements, trust=trust or trusts(Service="ec2.amazonaws.com"))

    def group(self, name, *statements):
        return self._ent("group", name, statements)

    def run(self, **kw):
        data = SimpleNamespace(layout="gaad", users=self.users, roles=self.roles, groups=self.groups, policies={},
                               gaps={}, instance_profiles=None, account_id=lambda: ACCT)
        pset = build_principal_set(data, account_id=ACCT, partition="aws", org=None)
        ev = Evaluator(None, pset.models, pset.resource_index(), None, account_id=ACCT, partition="aws")
        return R.run_rules(ev, pset, **kw)


def hits(result, who, rule_id):
    return [h for h in result.hits if h.principal.id == who and h.rule_id == rule_id]


@pytest.mark.finding("F-011")
def test_trusted_services_any_of_several_service_principals():
    """Data Pipeline (PRIVESC-031): the passed role may trust datapipeline, EMR or EC2 (resource role)."""
    w = World()
    admin = w.role("dp-admin", allow(), trust=trusts(Service="elasticmapreduce.amazonaws.com"))
    dev = w.user("dev", allow(["iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition",
                               "datapipeline:ActivatePipeline"]))
    (hit,) = hits(w.run(), dev, "PRIVESC-031")
    assert hit.severity == "CRITICAL" and [t.target.arn for t in hit.targets] == [admin]


@pytest.mark.finding("F-011")
def test_web_identity_trust_for_cognito_identity_pools():
    w = World()
    pool_role = w.role("pool-admin", allow(), trust=trusts(Federated="cognito-identity.amazonaws.com"))
    w.role("svc-admin", allow(), trust=trusts(Service="cognito-identity.amazonaws.com"))   # not a web identity
    dev = w.user("dev", allow(["iam:PassRole", "cognito-identity:SetIdentityPoolRoles"]))
    (hit,) = hits(w.run(), dev, "PRIVESC-030")
    assert [t.target.arn for t in hit.targets] == [pool_role]


@pytest.mark.finding("F-011", "F-017")
def test_access_key_limit_splits_create_from_delete_and_create():
    w = World()
    full = w.user("full", allow())
    w.user("free", allow())
    dev = w.user("dev", allow("iam:CreateAccessKey"))
    both = w.user("both", allow(["iam:CreateAccessKey", "iam:DeleteAccessKey"]))
    keys = {full: 2, f"arn:aws:iam::{ACCT}:user/free": 0, dev: 0}       # 'both' unknown: either filter keeps it
    result = w.run(access_keys=keys)
    (create,) = hits(result, dev, "PRIVESC-009")
    assert full not in [t.target.arn for t in create.targets]          # its two keys leave no free slot
    (replace,) = hits(result, both, "PRIVESC-024")
    assert [t.target.arn for t in replace.targets] == [full] and replace.severity == "CRITICAL"
    assert hits(result, dev, "PRIVESC-024") == []


@pytest.mark.finding("F-011")
def test_uncollected_resource_types_only_with_probing_enabled():
    w = World()
    dev = w.user("dev", allow(["states:UpdateStateMachine", "states:StartExecution"]))
    assert hits(w.run(), dev, "PRIVESC-063") == []                    # run_rules default: nothing claimed
    (hit,) = hits(w.run(probe_uncollected=True), dev, "PRIVESC-063")
    assert hit.decision is Decision.CONDITIONAL and hit.severity == "LOW" and hit.edges == []
    assert "sfn_state_machine:not-collected" in hit.gaps and hit.targets[0].tier == "uncollected"
    scoped = World()
    s_dev = scoped.user("dev", allow(["states:UpdateStateMachine", "states:StartExecution"],
                                     f"arn:aws:states:eu-west-2:{ACCT}:stateMachine:orders"))
    assert hits(scoped.run(probe_uncollected=True), s_dev, "PRIVESC-063")   # some state machine is enough


@pytest.mark.finding("F-011")
def test_condition_gap_makes_launch_template_hijack_conditional():
    w = World()
    admin = w.role("lt-admin", allow())
    dev = w.user("dev", allow(["ec2:CreateLaunchTemplateVersion", "ec2:ModifyLaunchTemplate"]))
    lt = f"arn:aws:ec2:eu-west-2:{ACCT}:launch-template/lt-0a1b2c3d4e5f60001"
    existing = {"ec2_launch_template": [R.ExistingResource("ec2_launch_template", lt, admin, "lt")]}
    (hit,) = hits(w.run(existing=existing), dev, "PRIVESC-052")
    assert (hit.decision, hit.base_severity, hit.severity) == (Decision.CONDITIONAL, "CRITICAL", "HIGH")
    assert "ec2:launch-template-consumers-unknown" in hit.gaps


@pytest.mark.finding("F-018")
def test_admin_principals_allow_star_and_iam_self_escalation():
    w = World()
    star = w.role("star", allow())
    iam_all = w.role("iam-all", allow("iam:*"))
    mfa = w.role("iam-mfa", allow("iam:*", "*", {"Bool": {"aws:MultiFactorAuthPresent": "true"}}))
    group = w.group("admins", allow())
    plain = w.user("plain", allow("s3:GetObject"))
    admins = w.run().admins
    assert admins[star]["basis"] == "allow-star" and admins[group]["basis"] == "allow-star"
    assert admins[iam_all]["basis"] == "iam-self-escalation" and "DANGER-002" in admins[iam_all]["rule_ids"]
    assert mfa not in admins and plain not in admins


@pytest.mark.finding("F-016", "F-071")
def test_finding_targets_have_the_contract_shape_and_the_details_go_to_evidence():
    """requests/e-core-1.md item 2: targets = [{node_id, tier (severity), decision}], facts in evidence."""
    w = World()
    admin = w.role("fn-admin", allow(), trust=trusts(Service="lambda.amazonaws.com"))
    dev = w.user("dev", allow(["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]),
                 allow("iam:AttachUserPolicy", "*"))
    result = w.run()
    builder = GraphBuilder(account_id=ACCT)
    R.emit_to_builder(result, builder, rule_version=load_catalogue().version)
    f14 = next(f for f in builder.findings() if f.id == "PRIVESC-014" and f.node_id == dev)
    assert f14.targets == [{"node_id": admin, "tier": "CRITICAL", "decision": "allow"}]
    (detail,) = f14.evidence["targets_detail"]
    assert detail["tier_class"] == "admin" and detail["arn"] == admin and detail["trust_decision"] == "allow"
    assert f14.evidence["rule_class"] == "new-passrole"
    f06 = next(f for f in builder.findings() if f.id == "PRIVESC-006" and f.node_id == dev)
    assert {"node_id": dev, "tier": "CRITICAL", "decision": "allow"} in f06.targets     # self tier -> CRITICAL
    assert any(d.get("tier_class") == "self" for d in f06.evidence["targets_detail"])


@pytest.mark.finding("F-011")
def test_every_rule_of_the_catalogue_loads_with_a_known_selector():
    cat = load_catalogue()
    assert [r.id for r in cat.privesc] == [f"PRIVESC-{n:03d}" for n in range(1, len(cat.privesc) + 1)]
    assert len(cat.privesc) >= 63
    for rule in cat.privesc:
        if rule.selector == "passable_service_role":
            assert rule.rule_class == "new-passrole", rule.id


@pytest.mark.finding("F-012", "F-011")
def test_instance_profile_roles_need_a_profile_or_the_right_to_create_one():
    """e-policy handoff limit: PassRole + RunInstances needs the role in an instance profile."""
    w = World()
    admin = w.role("ec2-admin", allow(), trust=trusts(Service="ec2.amazonaws.com"))
    plain = w.user("plain", allow(["iam:PassRole", "ec2:RunInstances"]))
    maker = w.user("maker", allow(["iam:PassRole", "ec2:RunInstances", "iam:CreateInstanceProfile",
                                   "iam:AddRoleToInstanceProfile"]))
    data = SimpleNamespace(layout="gaad", users=w.users, roles=w.roles, groups=w.groups, policies={}, gaps={},
                           instance_profiles=[], account_id=lambda: ACCT)          # profiles collected: none
    pset = build_principal_set(data, account_id=ACCT, partition="aws", org=None)
    ev = Evaluator(None, pset.models, pset.resource_index(), None, account_id=ACCT, partition="aws")
    result = R.run_rules(ev, pset)
    (none,) = hits(result, plain, "PRIVESC-015")
    assert none.no_candidate and none.severity == "INFO"
    (made,) = hits(result, maker, "PRIVESC-015")
    assert made.severity == "CRITICAL" and [t.target.arn for t in made.targets] == [admin]
    assert dict(made.targets[0].target.meta)["instance_profile"] == "creatable"
    (unknown,) = hits(w.run(), plain, "PRIVESC-015")        # World.run(): instance profiles not collected
    assert unknown.severity == "CRITICAL"                       # unknown profiles never drop a candidate
