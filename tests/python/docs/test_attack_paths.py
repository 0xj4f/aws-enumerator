"""``docs/attack_paths.md`` describes the graph the tool produces (DOC2, Wave 3b).

* F-158: the inaccurate technique statements are gone and their corrections are present;
* F-067 / F-070: no dead edge names (``CAN_ASSUME_CROSS_ACCOUNT``, ``INTERNET_FACING``, ``CAN_LAUNCH``), the real
  Kubernetes node-role path, the dashboard controls the guide names exist, every finding id and edge type the guide
  names exists;
* F-135 / F-088: every finding ``reference`` anchor lands on a heading whose section has a heading naming the id
  (ELB, SECRET-XACCT-001 with its alias, KMS_GRANTS_DECRYPT included).
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
GUIDE = REPO / "docs" / "attack_paths.md"
BLOCK_RE = re.compile(r"^<!-- BEGIN GENERATED:([a-z0-9:-]+) .*?-->$.*?^<!-- END GENERATED:\1 -->$",
                      re.MULTILINE | re.DOTALL)


def _gen_docs():
    name = "aws_enumerator_gen_docs"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / "gen_docs.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


@pytest.fixture(scope="module")
def gen():
    return _gen_docs()


@pytest.fixture(scope="module")
def guide() -> str:
    return GUIDE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def prose(guide) -> str:
    """The hand-written text: generated blocks and fenced code removed."""
    text = BLOCK_RE.sub("", guide)
    return re.sub(r"^```.*?^```$", "", text, flags=re.MULTILINE | re.DOTALL)


# ── F-158: technique statements ───────────────────────────────────────────────

F158_BANNED = [
    "blind ssrf",                                   # IMDSv1 matters for a GET-only SSRF that can READ the response
    "overwrite the zip",                            # Lambda keeps its own copy of the package
    "function uses your code",
    "unauthenticated assume",                       # Principal "*" needs the attacker's own AWS credentials
    "anyone can assume",
    "buckets with `secretsmanager:getsecretvalue",  # DANGER-008 is about principals, not buckets
]


@pytest.mark.finding("F-158")
@pytest.mark.parametrize("phrase", F158_BANNED)
def test_inaccurate_technique_statements_are_gone(guide, phrase):
    assert phrase not in guide.lower()


@pytest.mark.finding("F-158")
def test_confused_deputy_is_only_used_for_service_principals(guide, prose):
    assert "confused" not in prose.lower()
    for line in guide.splitlines():
        if "confused" in line.lower():
            assert "SERVICE_CAN_ASSUME" in line, line


@pytest.mark.finding("F-158")
def test_corrected_technique_statements_are_present(prose):
    assert "can only send GET requests without custom headers but **can read the response**" in prose
    assert "takes effect only at the next deployment" in prose and "Lambda keeps its own copy" in prose
    principal_star = [line for line in prose.splitlines() if "Principal: *" in line and "TRUST-001" in line]
    assert len(principal_star) >= 2, principal_star
    for line in principal_star:
        assert "any principal in any aws account" in line.lower(), line
        assert "own aws credentials" in line.lower(), line
    assert "**Principals with `secretsmanager:GetSecretValue` on every secret**: `DANGER-008`" in prose


@pytest.mark.finding("F-158")
def test_danger_008_is_documented_as_a_principal_capability(guide, gen):
    from aws_enumerator.engine.rules.catalogue import load_catalogue

    rule = load_catalogue().get("DANGER-008")
    assert rule.capability["action_glob"] == "secretsmanager:GetSecretValue"
    section = "\n".join(gen.section_lines(guide, "#danger-008"))
    assert "Reported for principals whose effective permissions allow `secretsmanager:GetSecretValue`" in section


# ── F-067 / F-070: the graph the tool produces ────────────────────────────────

@pytest.mark.finding("F-067", "F-070")
@pytest.mark.parametrize("dead", ["CAN_ASSUME_CROSS_ACCOUNT", "INTERNET_FACING", "CAN_LAUNCH", "IRSA edge is rendered",
                                  "Structural / direct", "PassRole chain or trust assumption"])
def test_dead_edge_names_and_the_old_weight_table_are_gone(prose, dead):
    assert dead not in prose


@pytest.mark.finding("F-067", "F-070")
def test_every_edge_type_named_in_the_prose_exists(prose):
    from aws_enumerator.engine.graph import edge_types as ET

    named = set(re.findall(r"`([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)`", prose))
    patterns = {n for n in named if "*" in n}
    unknown = sorted(n for n in named - patterns if n not in ET.EDGE_TYPES)
    assert not unknown, unknown
    for wildcard in re.findall(r"`(\*?[A-Z_]*\*[A-Z_]*)`", prose):
        rx = re.compile("^" + re.escape(wildcard).replace(r"\*", "[A-Z0-9_]+") + "$")
        assert any(rx.match(t) for t in ET.EDGE_TYPES), wildcard
    assert len(named) > 40


@pytest.mark.finding("F-067", "F-135")
def test_every_finding_id_named_in_the_guide_exists(guide):
    from aws_enumerator.engine.findings.catalog import build_catalog

    catalog = build_catalog()
    named = set(re.findall(r"\b((?:PRIVESC|DANGER|ADMIN|TRUST|EC2|S3|K8S|EKS|IAM|COGNITO|RDS|ECR|DDB|KMS|LAMBDA|MSG|"
                           r"SECRET|PARAM|SSMDOC|AMI|EBS|ELB|APIGW|ROUTE53|CLOUDTRAIL|FLOWLOGS|GUARDDUTY|CONFIG|"
                           r"SECURITYHUB|ACCESSANALYZER|WAF|CODEBUILD|COLLECTION|SUPPRESSION)-[A-Z0-9-]*[A-Z0-9])\b",
                           guide))
    unknown = sorted(n for n in named if n not in catalog)
    assert not unknown, unknown


@pytest.mark.finding("F-067")
def test_kubernetes_node_role_path_is_the_one_the_engine_emits(prose):
    """e-k8s-1 item 3 / F-033: pod -> node group -> NODE_ROLE, never pod -> IN_CLUSTER -> cluster -> NODE_ROLE."""
    from aws_enumerator.engine.graph import edge_types as ET

    reach, node_role = ET.EDGE_TYPES["CAN_REACH_NODE_IMDS"], ET.EDGE_TYPES["NODE_ROLE"]
    assert reach.sources == ("pod",) and reach.targets == ("nodegroup",) and reach.may_traverse
    assert node_role.sources == ("nodegroup",) and node_role.targets == ("role",) and node_role.may_traverse
    assert not ET.EDGE_TYPES["IN_CLUSTER"].may_traverse and not ET.EDGE_TYPES["CLUSTER_ROLE"].may_traverse
    assert "pod -CAN_REACH_NODE_IMDS-> node group -NODE_ROLE-> IAM role" in GUIDE.read_text(encoding="utf-8")
    assert "`IN_CLUSTER` → `cluster` → `NODE_ROLE`" not in prose
    assert "`CAN_REACH_NODE_IMDS` → node group → `NODE_ROLE` → role" in prose


@pytest.mark.finding("F-067")
def test_path_semantics_statements_match_the_table(prose):
    from aws_enumerator.engine.graph import edge_types as ET

    # "invoking a function never gives you its role, updating its code does"
    assert not ET.EDGE_TYPES["CAN_INVOKE"].may_traverse and ET.EDGE_TYPES["CAN_UPDATE_CODE"].traversal == "control"
    assert "invoking a function (`CAN_INVOKE`) never gives you its role" in prose
    # structural and info edges are never path steps; exposure PUBLIC_INBOUND is context
    for et in ET.EDGE_TYPES.values():
        if et.traversal in ("structural", "info"):
            assert not et.may_traverse, et.name
    assert not ET.EDGE_TYPES["PUBLIC_INBOUND"].may_traverse and not ET.EDGE_TYPES["LAMBDA_GRANTS_PUBLIC"].may_traverse
    assert "`PUBLIC_INBOUND` (network reachability) and `LAMBDA_GRANTS_PUBLIC` (public invoke) are context" in prose
    # the anonymous node is a default source; the account admin node the default target
    assert ET.NODE_TYPES["anonymous"].default_source and ET.NODE_TYPES["anonymous"].synthetic
    assert "`aws-enumerator:anonymous`" in prose and "`aws-enumerator:account-admin/<account>`" in prose
    # privilege escalation is edges
    for name in ("CAN_ESCALATE", "CAN_MODIFY_PERMISSIONS_OF", "CAN_TAKEOVER", "CAN_PASS_ROLE_TO",
                 "IS_ADMIN_EQUIVALENT"):
        assert f"`{name}`" in prose, name
    assert ET.EDGE_TYPES["CAN_ESCALATE"].targets == ("account_admin",)


@pytest.mark.finding("F-067")
def test_dashboard_controls_named_in_the_guide_exist():
    """Owned / operator sources, directed path finding and the filter options are real dashboard controls."""
    dash = REPO / "aws_enumerator" / "dashboard"
    ui = (dash / "js" / "ui.js").read_text(encoding="utf-8") + (dash / "index.html").read_text(encoding="utf-8")
    text = GUIDE.read_text(encoding="utf-8")
    for label in ("Discover all paths", "Find path", "Mark owned", "Path from here", "Path to here", "Focus",
                  "Show more", "Play", "Hidden types and classes restrict paths", "Include conditional edges",
                  "Data assets are Discover targets", "Reference", "high value", "Coverage", "Findings", "Details",
                  "Filters"):
        assert label in ui, label
        assert label in text, label
    core = (dash / "js" / "graph-core.js").read_text(encoding="utf-8")
    assert "if (ownedPresent.length > 0) return ownedPresent;" in core      # owned nodes are the sources
    assert "S.owned = S.operator.id ? [S.operator.id] : [];" in ui          # the operator is pre-marked owned
    assert "var source = S.path.source || S.operator.id;" in ui             # Find path defaults to the operator


@pytest.mark.finding("F-067")
def test_console_reference_lines_are_described_as_the_engine_logs_them(prose):
    from aws_enumerator.engine import console

    assert console.MAX_CRITICAL_LINES == 20
    assert "lists up to 20 open CRITICAL findings with their reference" in prose


# ── F-135 / F-088: every reference anchor lands on its finding ────────────────

@pytest.mark.finding("F-135", "F-088", "F-163")
def test_every_reference_anchor_resolves_to_a_section_naming_the_finding(gen, guide):
    from aws_enumerator.engine.findings.catalog import build_catalog

    anchors = {h.anchor for h in gen.headings(guide)}
    for entry in build_catalog():
        anchor = entry.reference.rsplit("#", 1)[1]
        assert anchor in anchors, (entry.id, anchor)
        section = gen.section_lines(guide, anchor)
        assert section is not None and section[0].startswith("## "), (entry.id, anchor)
        titles = {gen.heading_text(line.lstrip("#")) for line in section if line.startswith("#")}
        assert entry.id in titles, (entry.id, anchor)
        body = "\n".join(gen.section_lines(guide, "#" + gen.github_slug(entry.id)))
        for alias in entry.legacy_ids:
            assert alias in body, (entry.id, alias)


@pytest.mark.finding("F-088", "F-135")
def test_elb_secret_alias_and_kms_grants_decrypt_are_documented(gen, guide):
    from aws_enumerator.engine.findings.catalog import build_catalog

    catalog = build_catalog()
    elb = catalog.get("ELB-PUB-001")
    assert elb.reference.split("#", 1)[1], "ELB-PUB-001 links to the bare document (F-088)"
    assert any(h.anchor == "elb-pub-001" for h in gen.headings(guide))
    assert catalog.canonical("SECRET-XAUTH-001") == "SECRET-XACCT-001"
    section = "\n".join(gen.section_lines(guide, "#secret-xacct-001"))
    assert "`SECRET-XAUTH-001`" in section and "ExternalId" not in section
    assert "[`KMS_GRANTS_DECRYPT`](reference/edges.md#kms_grants_decrypt)" in guide
    assert "`KMS_GRANTS_DECRYPT`" in BLOCK_RE.sub("", guide)


@pytest.mark.finding("F-135")
def test_each_finding_block_sits_in_the_section_its_anchor_opens(gen, guide):
    for anchor, (name, _title) in gen.ANCHOR_BLOCKS.items():
        section = "\n".join(gen.section_lines(guide, anchor) or [])
        assert f"<!-- BEGIN GENERATED:{name} " in section and f"<!-- END GENERATED:{name} -->" in section, anchor


@pytest.mark.finding("F-135")
def test_the_crude_anchor_reading_of_older_tests_agrees(guide):
    """``test_findings_lifecycle`` strips ``[^a-z0-9 -]``; the catalogue anchors must survive both readings."""
    from aws_enumerator.engine.findings.catalog import build_catalog

    crude = set()
    for line in guide.splitlines():
        if line.startswith("#"):
            text = line.lstrip("#").strip().lower()
            crude.add("#" + re.sub(r"[^a-z0-9 -]", "", text).replace(" ", "-"))
    for entry in build_catalog():
        assert entry.doc_anchor in crude, entry.id
