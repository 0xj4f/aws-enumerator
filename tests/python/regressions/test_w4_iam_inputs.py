"""Regression tests of group W4-IAM: trust-policy Deny guards and NotPrincipal (F-031, trust half) and inline
policies the v2 IAM collector could not list or read (F-111, engine half).

* **F-031.** ``Allow Principal *`` plus ``Deny Principal * … StringNotEquals aws:PrincipalOrgID`` (the "org guard"
  pattern) only admits members of the organisation: TRUST-001 must not stay CRITICAL, and the guard must be in the
  finding evidence. A Deny whose condition an outsider can satisfy (a principal tag, an unclassified key) keeps
  TRUST-001 CRITICAL but conditional. ``Allow`` + ``NotPrincipal`` trusts everyone except the listed principals
  ("public-except"). Trees are legacy single-region reports built with ``tests/support/report_builder`` and
  analysed with ``engine.analyze_report``.
* **F-111.** The v2 collector records a failed ``iam:ListRolePolicies`` as a per-entity ``item_errors`` entry and
  writes no inline file, and a failed ``iam:GetRolePolicy`` as ``CollectionErrors`` in the inline file. The loader
  must turn both into ``inline_status != complete`` + gap ``iam:inline-unknown``, so the principal's decisions are
  conditional. The end-to-end test runs the real IAM collector (``--iam-mode per-entity``) against the routed fake
  AWS and the synthetic ``acme`` world (account 111122223333), offline, then ``engine.analyze_run``.

Placeholder accounts only (123456789012, 999999999999, 111122223333); ``demo-*`` names.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from tests.fixtures.regressions import support as S
from tests.fixtures.worlds import acme
from tests.support import report_builder as rb
from tests.support import targets

ACCT, FOREIGN, R = S.ACCT, S.ACCT_EXT, S.REGION
ANON = "aws-enumerator:anonymous"
ORG_ID = "o-exampleorg1"


# ── helpers ──────────────────────────────────────────────────────────────────
def _allow(principal: Any = None, cond: Optional[Dict[str, Any]] = None, action: Any = "sts:AssumeRole",
           not_principal: Any = None) -> Dict[str, Any]:
    stmt: Dict[str, Any] = {"Effect": "Allow"}
    if not_principal is not None:
        stmt["NotPrincipal"] = not_principal
    else:
        stmt["Principal"] = principal
    stmt["Action"] = action
    if cond:
        stmt["Condition"] = cond
    return stmt


def _deny(cond: Optional[Dict[str, Any]] = None, principal: Any = "*", action: Any = "sts:AssumeRole",
          not_principal: Any = None, sid: str = "") -> Dict[str, Any]:
    stmt: Dict[str, Any] = {"Sid": sid} if sid else {}
    stmt["Effect"] = "Deny"
    if not_principal is not None:
        stmt["NotPrincipal"] = not_principal
    else:
        stmt["Principal"] = principal
    stmt["Action"] = action
    if cond:
        stmt["Condition"] = cond
    return stmt


def _doc(*statements: Dict[str, Any]) -> Dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _role_arn(name: str, account: str = ACCT) -> str:
    return f"arn:aws:iam::{account}:role/{name}"


def _analyze_roles(tmp_path: Path, roles: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Legacy single-region tree with one role per trust document; returns the graph and the legacy rows."""
    scope = rb.Scope(tmp_path, ACCT, R)
    iam = rb.Iam(ACCT)
    iam.user("demo-ops", access_keys=1)
    for name, doc in roles.items():
        iam.role(name, doc)
    iam.write(scope, layout="legacy")
    rb.write_empty_regional(scope)
    rb.write_manifest(scope.path, account=ACCT, mode="single_region", region=R)
    result = targets.engine_module("").analyze_report(str(scope.path), None)
    graph = S.load_json(Path(result.graph_path))
    rows = S.load_json(Path(result.analysis_dir) / "trust_relationships.json", [])
    assert S.graph_problems(graph) == []
    return {"graph": graph, "rows": rows}


def _findings(graph: Dict[str, Any], fid: str, node: str) -> List[Dict[str, Any]]:
    return [f for f in graph["findings"] if f["id"] == fid and f["node_id"] == node]


def _edges(graph: Dict[str, Any], etype: str, source: str, target: str) -> List[Dict[str, Any]]:
    return [e for e in graph["edges"] if e["type"] == etype and e["source"] == source and e["target"] == target]


def _row(rows: List[Dict[str, Any]], role: str) -> Dict[str, Any]:
    [row] = [r for r in rows if r["role_name"] == role]
    return row


ORG_GUARD = {"StringNotEquals": {"aws:PrincipalOrgID": ORG_ID}}
STRONG_GUARDS = {
    "demo-org-guard": ORG_GUARD,
    "demo-account-guard": {"StringNotEquals": {"aws:PrincipalAccount": [ACCT]}},
    "demo-vpce-guard": {"StringNotEquals": {"aws:SourceVpce": "vpce-0example0000000001"}},
}
WEAK_GUARDS = {
    "demo-tag-guard": {"StringNotEquals": {"aws:PrincipalTag/team": "demo-team"}},
    "demo-unknown-key-guard": {"StringNotEquals": {"demo:customkey": "demo-value"}},
}


@pytest.fixture(scope="module")
def trust_analysis(tmp_path_factory) -> Dict[str, Any]:
    roles: Dict[str, Dict[str, Any]] = {name: _doc(_allow({"AWS": "*"}), _deny(cond, sid="DemoGuard"))
                                        for name, cond in {**STRONG_GUARDS, **WEAK_GUARDS}.items()}
    roles.update({
        "demo-open": _doc(_allow({"AWS": "*"})),
        "demo-wildcard-org": _doc(_allow({"AWS": "*"}, {"StringEquals": {"aws:PrincipalOrgID": ORG_ID}})),
        "demo-weak-allow-org-guard": _doc(_allow({"AWS": "*"}, {"StringEquals": {"aws:PrincipalTag/team": "x"}}),
                                          _deny(ORG_GUARD)),
        "demo-deny-all": _doc(_allow({"AWS": "*"}), _deny()),
        "demo-deny-tls-only": _doc(_allow({"AWS": "*"}), _deny({"Bool": {"aws:SecureTransport": "false"}})),
        "demo-deny-tagsession-only": _doc(_allow({"AWS": "*"}), _deny(ORG_GUARD, action="sts:TagSession")),
        "demo-deny-notprincipal": _doc(_allow({"AWS": "*"}),
                                       _deny(not_principal={"AWS": f"arn:aws:iam::{ACCT}:user/demo-ops"})),
        "demo-public-except": _doc(_allow(not_principal={"AWS": f"arn:aws:iam::{FOREIGN}:role/demo-blocked"})),
        "demo-xacct-org-guard": _doc(_allow({"AWS": FOREIGN}), _deny(ORG_GUARD)),
        "demo-xacct-account-guard": _doc(_allow({"AWS": FOREIGN}),
                                         _deny({"StringNotEquals": {"aws:PrincipalAccount": [ACCT]}})),
    })
    return _analyze_roles(tmp_path_factory.mktemp("w4-trust"), roles)


# ── F-031 (a): an org guard Deny lowers TRUST-001 and is recorded ────────────
@pytest.mark.finding("F-031")
@pytest.mark.parametrize("role", sorted(STRONG_GUARDS))
def test_f031_wildcard_trust_behind_a_strong_deny_guard_is_not_critical(trust_analysis, role):
    g = trust_analysis["graph"]
    [f] = _findings(g, "TRUST-001", _role_arn(role))
    assert f["severity"] == "INFO" and f["base_severity"] == "CRITICAL"
    assert f["confidence"] == "conditional"
    ev = f["evidence"]
    assert ev["condition_strength"] == "none"                  # the Allow statement itself is unconditioned
    assert ev["effective_strength"] == "strong" and ev["denied"] == "conditional"
    [guard] = ev["denied_by"]
    assert guard["statement_index"] == 1 and guard["sid"] == "DemoGuard" and guard["effect"] == "Deny"
    assert guard["applies"] == "conditional" and guard["escape_strength"] == "strong"
    assert guard["lowers_severity"] is True
    [cond] = guard["conditions"]
    [written_key] = STRONG_GUARDS[role]["StringNotEquals"]
    assert cond["operator"] == "StringNotEquals" and cond["key"] == written_key
    assert ev["mitigated_by"] == ["trust-deny:statement-1"]
    assert "Deny" in f["title"] and "statement 1" in f["description"]
    # the assume edge an attacker would walk is conditional and graded strong (no longer definite)
    [edge] = _edges(g, "CAN_ASSUME", ANON, _role_arn(role))
    assert edge["confidence"] == "conditional"
    assert edge["evidence"]["condition_strength"] == "strong" and edge["evidence"]["trust_deny"] == "conditional"
    row = _row(trust_analysis["rows"], role)
    assert row["is_wildcard"] is True and row["condition_strength"] == "none"
    assert row["effective_strength"] == "strong" and row["denied_by"] == ev["denied_by"]


@pytest.mark.finding("F-031")
def test_f031_org_guard_on_a_cross_account_trust_counts_as_the_org_guard(trust_analysis):
    g = trust_analysis["graph"]
    [f] = _findings(g, "TRUST-002", _role_arn("demo-xacct-org-guard"))
    assert f["severity"] == "INFO" and f["confidence"] == "conditional"
    assert f["evidence"]["guard"] == "org" and f["evidence"]["denied_by"][0]["lowers_severity"] is True
    # "Deny unless the caller is in this account" removes a foreign-account trust definitely
    assert _findings(g, "TRUST-002", _role_arn("demo-xacct-account-guard")) == []
    assert not [e for e in g["edges"] if e["target"] == _role_arn("demo-xacct-account-guard")
                and e["type"] == "CAN_ASSUME"]


@pytest.mark.finding("F-031")
def test_f031_deny_everyone_but_one_principal_is_a_strong_guard_naming_who_remains(trust_analysis):
    g = trust_analysis["graph"]
    [f] = _findings(g, "TRUST-001", _role_arn("demo-deny-notprincipal"))
    assert f["severity"] == "INFO" and f["confidence"] == "conditional"
    [guard] = f["evidence"]["denied_by"]
    assert guard["escape_strength"] == "strong" and guard["lowers_severity"] is True
    assert guard["not_principals"] == [{"type": "AWS", "value": f"arn:aws:iam::{ACCT}:user/demo-ops"}]


# ── F-031 (b): a guard an outsider can satisfy keeps TRUST-001 CRITICAL ──────
@pytest.mark.finding("F-031")
@pytest.mark.parametrize("role", sorted(WEAK_GUARDS))
def test_f031_wildcard_trust_behind_a_weak_or_unknown_deny_guard_stays_critical_conditional(trust_analysis, role):
    g = trust_analysis["graph"]
    [f] = _findings(g, "TRUST-001", _role_arn(role))
    assert f["severity"] == "CRITICAL" and f["confidence"] == "conditional"
    ev = f["evidence"]
    assert ev["denied"] == "conditional" and ev["effective_strength"] == "none"
    [guard] = ev["denied_by"]
    assert guard["escape_strength"] == "weak" and guard["lowers_severity"] is False
    assert "mitigated_by" not in ev
    [edge] = _edges(g, "CAN_ASSUME", ANON, _role_arn(role))
    assert edge["confidence"] == "conditional" and edge["evidence"]["trust_deny"] == "conditional"


@pytest.mark.finding("F-031")
def test_f031_denies_that_do_not_guard_the_assumption_change_nothing(trust_analysis):
    g = trust_analysis["graph"]
    # Deny unless TLS: every STS call uses TLS, so the Deny never applies (shared attacker model)
    # Deny of sts:TagSession only: sts:AssumeRole stays allowed to everyone
    for role in ("demo-deny-tls-only", "demo-deny-tagsession-only", "demo-open"):
        [f] = _findings(g, "TRUST-001", _role_arn(role))
        assert (f["severity"], f["confidence"]) == ("CRITICAL", "definite"), role
        assert "denied_by" not in f["evidence"] and f["evidence"]["denied"] == "no", role
        [edge] = _edges(g, "CAN_ASSUME", ANON, _role_arn(role))
        assert edge["confidence"] == "definite", role
    # an unconditional Deny of everyone removes the trust: no finding, no edge
    assert _findings(g, "TRUST-001", _role_arn("demo-deny-all")) == []
    assert _edges(g, "CAN_ASSUME", ANON, _role_arn("demo-deny-all")) == []


@pytest.mark.finding("F-031")
def test_f031_allow_side_grading_is_unchanged(trust_analysis):
    g = trust_analysis["graph"]
    [org] = _findings(g, "TRUST-001", _role_arn("demo-wildcard-org"))
    assert (org["severity"], org["confidence"]) == ("INFO", "conditional")
    assert org["evidence"]["condition_strength"] == "strong" and "denied_by" not in org["evidence"]
    assert org["title"] == "Role 'demo-wildcard-org' trusts any AWS principal (Principal: *)"
    [open_] = _findings(g, "TRUST-001", _role_arn("demo-open"))
    assert open_["description"] == ("The trust policy of 'demo-open' allows Principal '*' without conditions: any "
                                    "AWS account can assume it.")


@pytest.mark.finding("F-031")
def test_f031_a_strong_deny_guard_also_lowers_a_weakly_conditioned_wildcard_trust(trust_analysis):
    [f] = _findings(trust_analysis["graph"], "TRUST-001", _role_arn("demo-weak-allow-org-guard"))
    assert f["severity"] == "INFO" and f["confidence"] == "conditional"
    assert f["evidence"]["condition_strength"] == "weak" and f["evidence"]["effective_strength"] == "strong"


# ── F-031 (c): Allow + NotPrincipal is public-except ─────────────────────────
@pytest.mark.finding("F-031")
def test_f031_allow_notprincipal_trust_is_reported_as_public_except(trust_analysis):
    g = trust_analysis["graph"]
    role = _role_arn("demo-public-except")
    [f] = _findings(g, "TRUST-001", role)
    assert (f["severity"], f["confidence"]) == ("CRITICAL", "definite")
    ev = f["evidence"]
    assert ev["principal_scope"] == "public-except"
    assert ev["not_principals"] == [{"type": "AWS", "value": f"arn:aws:iam::{FOREIGN}:role/demo-blocked"}]
    assert "NotPrincipal" in f["title"] and "demo-blocked" in f["description"]
    assert _edges(g, "CAN_ASSUME", ANON, role)
    row = _row(trust_analysis["rows"], "demo-public-except")
    assert row["is_wildcard"] is True and row["trusted_principal"] == "*"
    assert row["not_principals"] == ev["not_principals"]


@pytest.mark.finding("F-031")
def test_f031_trust_model_unit_classification():
    """The trust model on its own (no graph): guards, strengths and NotPrincipal."""
    trust = targets.engine_module("iam.trust")
    loaders = targets.engine_module("io.loaders.iam")

    iam = loaders.IamData("legacy")
    docs = {"demo-org-guard": _doc(_allow({"AWS": "*"}), _deny(ORG_GUARD)),
            "demo-public-except": _doc(_allow(not_principal={"AWS": FOREIGN})),
            "demo-named-deny": _doc(_allow({"AWS": FOREIGN}), _deny(principal={"AWS": FOREIGN}))}
    for name, doc in docs.items():
        arn = _role_arn(name)
        iam.roles[arn] = loaders.IamEntity("role", arn, name, "/", {"RoleName": name}, trust_policy=doc)
    ctx = SimpleNamespace(data={"iam": iam}, account_id=ACCT, partition="aws")
    model = trust.build_trust_model(ctx)
    by_role = {g.role_name: g for g in model.grants}
    org = by_role["demo-org-guard"]
    assert (org.category, org.allow_strength, org.strength, org.denied) == ("wildcard", "none", "strong",
                                                                           "conditional")
    assert [d.credited for d in org.deny_guards] == [True]
    pub = by_role["demo-public-except"]
    assert pub.category == "wildcard" and pub.public_except and pub.not_principals == (("AWS", FOREIGN),)
    assert by_role["demo-named-deny"].denied == "yes"           # F-073 kept: an explicit Deny removes the trust


# ── F-111: inline policies that could not be listed or read ──────────────────
PER_ENTITY = {"iam_mode": "per-entity"}
W2 = "eu-west-2"


def _collect_and_analyze(tmp_path: Path, world: Any) -> Dict[str, Any]:
    """Run the IAM collector (per entity) into a v2 run root, then analyse that run."""
    run = S.V2Run(tmp_path, account=acme.ACCOUNT_ID, regions=[W2])
    collected = S.run_module("iam", world, run.path, options=PER_ENTITY, account=acme.ACCOUNT_ID)
    run.write_manifest()
    _result, graph = S.analyze_run_graph(run.path, [W2])
    assert S.graph_problems(graph) == []
    data = targets.engine_module("io.loaders.iam").load_iam(run.path / "global")
    return {"collected": collected, "graph": graph, "iam": data}


def _clean_world() -> Any:
    w = acme.build_world()
    w.errors = []                     # only the denials each test adds
    return w


@pytest.fixture(scope="module")
def denied_listing(tmp_path_factory) -> Dict[str, Any]:
    w = _clean_world()
    w.deny("iam", "ListRolePolicies", {"RoleName": "demo-admin-role"})
    w.deny("iam", "GetRolePolicy", {"RoleName": "demo-lambda-role", "PolicyName": "demo-lambda-inline"})
    return _collect_and_analyze(tmp_path_factory.mktemp("w4-f111"), w)


@pytest.mark.finding("F-111")
def test_f111_denied_inline_listing_end_to_end_makes_the_role_unknown_and_its_decisions_conditional(denied_listing):
    admin, control = acme.role_arn("demo-admin-role"), acme.role_arn("demo-build-role")
    # collector side (precondition): an item_errors entry and no inline file for the role
    collected = denied_listing["collected"]
    errors = [e for e in collected.coverage()["item_errors"] if e["api"] == "iam:ListRolePolicies"]
    assert errors == [{"resource": admin, "api": "iam:ListRolePolicies", "status": "denied",
                       "error_code": "AccessDenied"}]
    assert "inline_policies/roles/demo-admin-role.json" not in collected.files()
    # loader: unknown, not "no inline policies"
    ent = denied_listing["iam"].roles[admin]
    assert ent.inline_status == "denied" and "iam:inline-unknown" in ent.gaps and ent.inline == {}
    # graph: the role node carries the gap; the identical control role (AdministratorAccess too) does not
    nodes = S.nodes_by_id(denied_listing["graph"])
    assert "iam:inline-unknown" in nodes[admin]["coverage"]["gaps"]
    assert nodes[admin]["coverage"]["status"] == "partial"
    assert "iam:inline-unknown" not in nodes[control]["coverage"]["gaps"]
    # decisions: an unread inline policy may hold a Deny, so the role's capabilities are conditional
    edges = denied_listing["graph"]["edges"]
    escalate = [e for e in edges if e["source"] == admin and e["type"] == "CAN_ESCALATE"]
    assert escalate and all(e["confidence"] == "conditional" for e in escalate)
    caps = [e for e in edges if e["source"] == admin and e["type"].startswith("CAN_")]
    assert caps and all(e["confidence"] == "conditional" for e in caps), sorted(
        (e["type"], e["confidence"]) for e in caps if e["confidence"] != "conditional")
    control_caps = [e for e in edges if e["source"] == control and e["type"] == "CAN_ESCALATE"]
    assert control_caps and all(e["confidence"] == "definite" for e in control_caps)


@pytest.mark.finding("F-111")
def test_f111_denied_inline_read_keeps_the_readable_documents_and_marks_the_rest_unknown(denied_listing):
    lam = acme.role_arn("demo-lambda-role")
    inline_file = denied_listing["collected"].load("inline_policies/roles/demo-lambda-role.json")
    assert [e["api"] for e in inline_file["CollectionErrors"]] == ["iam:GetRolePolicy"]
    ent = denied_listing["iam"].roles[lam]
    assert ent.inline_status == "partial" and "iam:inline-unknown" in ent.gaps
    assert sorted(ent.inline) == ["demo-lambda-logs"]
    assert "iam:inline-unknown" in S.nodes_by_id(denied_listing["graph"])[lam]["coverage"]["gaps"]
    # every other role was read completely
    complete = [e.name for e in denied_listing["iam"].entities("role") if e.inline_status == "complete"]
    assert "demo-app-role" in complete and "demo-build-role" in complete


# ── F-111 unit cases: the loader on hand-written v2 files ────────────────────
def _gaad_tree(tmp_path: Path, coverage: Optional[Dict[str, Any]] = None) -> Path:
    scope = rb.Scope(tmp_path, ACCT, "global")
    iam = rb.Iam(ACCT)
    iam.role("demo-listed-role", _doc(_allow({"Service": "ec2.amazonaws.com"})),
             inline={"demo-read": [rb.allow("s3:GetObject", "*")]})
    iam.role("demo-quiet-role", _doc(_allow({"Service": "ec2.amazonaws.com"})))
    iam.role("demo-denied-role", _doc(_allow({"Service": "ec2.amazonaws.com"})))
    iam.write(scope, layout="gaad")
    if coverage is not None:
        rb.dump_json(scope.path / "iam" / "_coverage.json", coverage)
    return scope.path


def _coverage(item_errors: List[Dict[str, Any]], *, truncated: bool = False,
              calls: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    return {"schema_version": "1.0", "module": "iam", "region": "global", "status": "partial",
            "calls": calls or [], "item_errors": item_errors, "item_errors_truncated": truncated}


def _load(path: Path) -> Any:
    return targets.engine_module("io.loaders.iam").load_iam(path)


@pytest.mark.finding("F-111")
def test_f111_unit_collection_errors_in_an_inline_file_make_the_entity_partial(tmp_path):
    root = _gaad_tree(tmp_path)
    inline = root / "iam" / "inline_policies" / "roles" / "demo-listed-role.json"
    rec = json.loads(inline.read_text(encoding="utf-8"))
    rec["CollectionErrors"] = [{"api": "iam:GetRolePolicy", "status": "denied", "error_code": "AccessDenied"}]
    inline.write_text(json.dumps(rec), encoding="utf-8")
    data = _load(root)
    ent = data.roles[_role_arn("demo-listed-role")]
    assert ent.inline_status == "partial" and "iam:inline-unknown" in ent.gaps
    assert sorted(ent.inline) == ["demo-read"]                 # what was read is kept
    quiet = data.roles[_role_arn("demo-quiet-role")]
    assert quiet.inline_status == "complete" and not quiet.gaps
    loader = targets.engine_module("io.loaders.iam")
    assert loader.load(SimpleNamespace(global_dir=root)).status == "partial"


@pytest.mark.finding("F-111")
def test_f111_unit_item_errors_and_open_circuit_breakers_mark_the_entity(tmp_path):
    errors = [{"resource": _role_arn("demo-denied-role"), "api": "iam:ListRolePolicies", "status": "denied",
               "error_code": "AccessDenied"},
              {"resource": _role_arn("demo-quiet-role"), "api": "iam:ListRolePolicies", "status": "skipped",
               "error_code": "CircuitOpen:AccessDenied"},
              {"resource": _role_arn("demo-listed-role"), "api": "iam:ListAttachedRolePolicies",
               "status": "denied", "error_code": "AccessDenied"}]       # not an inline listing
    data = _load(_gaad_tree(tmp_path, _coverage(errors)))
    denied = data.roles[_role_arn("demo-denied-role")]
    assert denied.inline_status == "denied" and "iam:inline-unknown" in denied.gaps
    skipped = data.roles[_role_arn("demo-quiet-role")]
    assert skipped.inline_status == "denied" and "iam:inline-unknown" in skipped.gaps
    listed = data.roles[_role_arn("demo-listed-role")]
    assert listed.inline_status == "complete" and "iam:inline-unknown" not in listed.gaps


@pytest.mark.finding("F-111")
def test_f111_unit_truncated_item_errors_leave_every_unlisted_entity_unknown(tmp_path):
    calls = [{"api": "iam:ListRolePolicies", "status": "ok", "count": 1},
             {"api": "iam:ListRolePolicies", "status": "denied", "count": 600, "error_code": "AccessDenied"}]
    data = _load(_gaad_tree(tmp_path, _coverage([], truncated=True, calls=calls)))
    for name in ("demo-quiet-role", "demo-denied-role"):              # no inline file: cannot tell
        ent = data.roles[_role_arn(name)]
        assert ent.inline_status == "partial" and "iam:inline-unknown" in ent.gaps, name
    listed = data.roles[_role_arn("demo-listed-role")]               # its listing succeeded (file written)
    assert listed.inline_status == "complete" and not listed.gaps
    assert "iam:item-errors-truncated" in data.gaps


@pytest.mark.finding("F-111")
def test_f111_unit_a_clean_coverage_file_marks_nothing(tmp_path):
    calls = [{"api": "iam:ListRolePolicies", "status": "ok", "count": 3}]
    data = _load(_gaad_tree(tmp_path, _coverage([], truncated=True, calls=calls)))
    assert all(e.inline_status == "complete" and not e.gaps for e in data.entities("role"))
    assert "iam:item-errors-truncated" not in data.gaps
