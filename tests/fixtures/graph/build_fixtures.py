"""Builds the hand-written graph.json fixtures in this directory and in ../graph-invalid/.

The node, edge and finding *content* of every fixture is written by hand below. The script only fills in
the mechanical parts from the contract modules (edge ids, weights, fingerprints, registries, ``meta``,
``max_severity``, canonical order), so the fixtures cannot disagree with the frozen table.

    .venv/bin/python tests/fixtures/graph/build_fixtures.py --write   # regenerate
    .venv/bin/python tests/fixtures/graph/build_fixtures.py --check   # exit 1 if a committed file differs

``tests/python/engine/core/test_contracts_engine.py`` runs the check. Placeholder accounts only.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tests.support.ref_paths import engine_module  # noqa: E402

_et = engine_module("graph.edge_types")
_ids = engine_module("graph.ids")
_graph = engine_module("graph")

MAIN = "111122223333"
EXT = "999999999999"
HOSTILE_ACCT = "123456789012"
REGION = "eu-west-2"
GENERATED_AT = "2026-01-01T00:00:00Z"
RUN_ID = "20260101T000000Z-a1b2c3"
GENERATOR = {"tool": "aws-enumerator", "version": "0.3.0", "engine_version": "1.0.0", "rules_version": "2.0.0",
             "git_sha": None}
DOC_BASE = "https://github.com/0xj4f/aws-enumerator/blob/v0.3.0/docs/attack_paths.md"

ALWAYS_GAPS = [
    {"code": "external-identity", "detail": "Identity policies of external principals are not visible; "
     "cross-account edges are conditional.", "count": None},
    {"code": "runtime-conditions", "detail": "Condition values only known at request time are treated as "
     "conditional.", "count": None},
    {"code": "session-policies", "detail": "Session policies are not evaluated.", "count": None},
]


# ── Builders ──────────────────────────────────────────────────────────────────

class G:
    """Accumulates one graph document."""

    def __init__(self, account: str = MAIN, partition: str = "aws", regions: Iterable[str] = (REGION,)):
        self.account = account
        self.partition = partition
        self.regions = list(regions)
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: Dict[str, Dict[str, Any]] = {}
        self.findings: List[Dict[str, Any]] = []
        self.operator = {"arn": None, "node_id": None, "resolution": "unavailable", "redacted": False}
        self.coverage: Dict[str, Any] = {"source": "ledger", "status": "complete", "modules": []}
        self.gaps: List[Dict[str, Any]] = []
        self.analyzers: List[Dict[str, Any]] = []
        self.node("aws-enumerator:anonymous", "anonymous", "Anyone (internet)", account=None)
        self.node(_ids.account_admin_id(account), "account_admin", "Account administrator")

    # nodes ----------------------------------------------------------------
    def node(self, nid: str, ntype: str, label: Optional[str] = None, *, account: Optional[str] = "default",
             region: Optional[str] = None, props: Optional[Dict[str, Any]] = None,
             tags: Optional[List[Tuple[str, str]]] = None, coverage: str = "complete",
             gaps: Iterable[str] = (), entry_point: Optional[bool] = None,
             high_value: Optional[str] = None) -> str:
        nt = _et.NODE_TYPES[ntype]
        p: Dict[str, Any] = {}
        if (entry_point if entry_point is not None else nt.default_source):
            p["entry_point"] = True
        if nt.data_asset:
            p["data_asset"] = True
        if ntype in ("external_account", "external_principal"):
            p["external"] = True
        if ntype in ("user", "role", "group"):
            p["attached_policies_status"] = "complete"
        if ntype == "account_admin":
            high_value = "account-admin"
        if high_value:
            p["high_value"] = True
            p["high_value_reason"] = high_value
        p.update(props or {})
        if account == "default":
            account = None if nt.synthetic and ntype not in ("account_admin", "account", "region") else self.account
            if ntype in ("external_account", "external_principal"):
                account = EXT
        if nt.synthetic and ntype in ("anonymous", "service_principal"):
            account = None
        self.nodes[nid] = {
            "id": nid, "type": ntype, "label": label or nid, "account": account, "region": region,
            "partition": None if ntype in ("anonymous", "service_principal") else self.partition,
            "props": p, "tags": [{"key": k, "value": v} for k, v in sorted(tags or [])],
            "coverage": {"status": "not-applicable" if nt.synthetic else coverage, "gaps": sorted(gaps)},
            "findings": [], "inherited_findings": [], "max_severity": None,
        }
        return nid

    # edges ----------------------------------------------------------------
    def edge(self, src: str, etype: str, tgt: str, *, confidence: str = "definite", strength: str = "none",
             holds: Optional[bool] = None, extra: float = 0, evidence: Optional[Dict[str, Any]] = None,
             props: Optional[Dict[str, Any]] = None, traversable: Optional[bool] = None) -> str:
        et = _et.EDGE_TYPES[etype]
        ev: Dict[str, Any] = {"decision": "conditional" if confidence == "conditional" else "allow"}
        if confidence == "conditional":
            ev["condition_strength"] = strength
        if extra:
            ev["weight_extra"] = extra
        if et.traversable_rule:
            if holds is None:
                raise ValueError(f"{etype} needs holds=")
            ev["traversable_rule"] = {"rule": et.traversable_rule, "holds": holds}
            trav = holds
        else:
            trav = bool(et.traversable)
        if traversable is not None:
            trav = traversable
        ev.update(evidence or {})
        eid = _ids.edge_id(src, etype, tgt)
        rec = {
            "id": eid, "source": src, "target": tgt, "type": etype, "category": et.category,
            "traversal": et.traversal, "traversable": trav,
            "weight": _et.edge_weight(etype, confidence, strength if confidence == "conditional" else "none", extra),
            "confidence": confidence, "evidence": ev,
        }
        if props:
            rec["props"] = props
        self.edges[eid] = rec
        return eid

    # findings -------------------------------------------------------------
    def finding(self, fid: str, node_id: str, severity: str, title: str, *, discriminator: str = "",
                description: str = "", remediation: str = "Review and restrict the grant.",
                base_severity: Optional[str] = None, confidence: str = "definite",
                evidence: Optional[Dict[str, Any]] = None, status: str = "open",
                suppression: Optional[Dict[str, Any]] = None, affected_members: Iterable[str] = (),
                related: Iterable[str] = (), extra: Optional[Dict[str, Any]] = None,
                reference: Optional[str] = "default") -> str:
        fp = _ids.finding_fingerprint(fid, self.account, node_id, discriminator)
        rec: Dict[str, Any] = {
            "fingerprint": fp, "id": fid, "legacy_ids": [], "severity": severity,
            "base_severity": base_severity or severity, "confidence": confidence, "node_id": node_id,
            "title": title, "description": description or title, "evidence": evidence or {},
            "remediation": remediation,
            "reference": f"{DOC_BASE}#{fid.split('-')[0].lower()}" if reference == "default" else reference,
            "status": status, "account": self.account,
        }
        if suppression:
            rec["suppression"] = suppression
        if affected_members:
            rec["affected_members"] = sorted(affected_members)
        if related:
            rec["related_node_ids"] = sorted(related)
        rec.update(extra or {})
        self.findings.append(rec)
        if node_id in self.nodes:
            self.nodes[node_id]["findings"].append(fp)
        for m in affected_members:
            self.nodes[m]["inherited_findings"].append(fp)
        return fp

    # document -------------------------------------------------------------
    def doc(self) -> Dict[str, Any]:
        rank = _graph.SEVERITY_RANK
        by_fp = {f["fingerprint"]: f for f in self.findings}
        nodes = []
        for n in self.nodes.values():
            n = copy.deepcopy(n)
            n["findings"] = sorted(set(n["findings"]))
            n["inherited_findings"] = sorted(set(n["inherited_findings"]))
            sev = [by_fp[fp]["severity"] for fp in n["findings"] + n["inherited_findings"]
                   if fp in by_fp and by_fp[fp]["status"] == "open"]
            n["max_severity"] = min(sev, key=lambda s: rank[s]) if sev else None
            nodes.append(n)
        nodes.sort(key=_graph.node_sort_key)
        edges = sorted(self.edges.values(), key=_graph.edge_sort_key)
        findings = sorted(self.findings, key=_graph.finding_sort_key)
        sources = {n["id"] for n in nodes if n["props"].get("entry_point") is True}
        if self.operator.get("node_id") in self.nodes:
            sources.add(self.operator["node_id"])
        targets_ = {n["id"] for n in nodes if n["props"].get("high_value") is True}
        node_reg, edge_reg = _et.registries_for((n["type"] for n in nodes), (e["type"] for e in edges))
        return {
            "schema_version": _graph.GRAPH_SCHEMA_VERSION,
            "generator": dict(GENERATOR),
            "run": {
                "run_id": RUN_ID, "account_id": self.account, "partition": self.partition, "mode": "run",
                "regions": self.regions, "generated_at": GENERATED_AT,
                "source_manifest_sha256": hashlib.sha256(b"demo-manifest").hexdigest(),
                "operator": dict(self.operator),
            },
            "meta": {"default_sources": sorted(sources), "default_targets": sorted(targets_)},
            "node_types": node_reg, "edge_types": edge_reg,
            "nodes": nodes, "edges": edges, "findings": findings,
            "coverage": copy.deepcopy(self.coverage),
            "evaluation_gaps": sorted(copy.deepcopy(self.gaps), key=lambda g: g["code"]),
            "analyzer_status": copy.deepcopy(self.analyzers),
        }


def arn_user(name: str, acct: str = MAIN, path: str = "/") -> str:
    return f"arn:aws:iam::{acct}:user{path}{name}"


def arn_role(name: str, acct: str = MAIN, path: str = "/") -> str:
    return f"arn:aws:iam::{acct}:role{path}{name}"


def arn_group(name: str, acct: str = MAIN) -> str:
    return f"arn:aws:iam::{acct}:group/{name}"


CLUSTER = f"arn:aws:eks:{REGION}:{MAIN}:cluster/demo-cluster"


def k8s(ntype: str, ns: str, name: str, kind: Optional[str] = None) -> str:
    return _ids.node_id_for(ntype, cluster_arn=CLUSTER, namespace=ns, name=name, **({"k8s_kind": kind} if kind else {}))


# ── minimal.json ──────────────────────────────────────────────────────────────

def minimal() -> Dict[str, Any]:
    """The smallest valid document: the two synthetic nodes the engine always emits."""
    return G().doc()


# ── example.json ──────────────────────────────────────────────────────────────

def example() -> Dict[str, Any]:
    g = G()
    user = g.node(arn_user("demo-user"), "user", "demo-user")
    grp = g.node(arn_group("demo-devs"), "group", "demo-devs")
    pol = g.node(f"arn:aws:iam::{MAIN}:policy/demo-deploy-policy", "policy", "demo-deploy-policy")
    app = g.node(arn_role("demo-app-role"), "role", "demo-app-role")
    adm = g.node(arn_role("demo-admin-role", path="/admin/"), "role", "demo-admin-role",
                 high_value="admin-equivalent")
    deploy = g.node(arn_role("demo-deploy-role"), "role", "demo-deploy-role")
    gh = g.node(f"arn:aws:iam::{MAIN}:oidc-provider/token.actions.githubusercontent.com", "idp",
                "token.actions.githubusercontent.com", props={"provider": "github"})
    xa = g.node(_ids.external_account_id(EXT), "external_account", f"account {EXT}")
    inst = g.node(_ids.node_id_for("instance", region=REGION, account=MAIN, id="i-0123456789abcdef0"), "instance",
                  "demo-web-1", region=REGION, props={"imds_v1": True, "igw_routed": True, "state": "running"})
    bkt = g.node("arn:aws:s3:::demo-data-bucket", "bucket", "demo-data-bucket", region=REGION,
                 tags=[("env", "demo"), ("owner", "example-team")], coverage="partial",
                 gaps=["s3:GetBucketPolicy:denied"])
    key = g.node(f"arn:aws:kms:{REGION}:{MAIN}:key/1234abcd-12ab-34cd-56ef-1234567890ab", "kms", "alias/demo-data",
                 region=REGION, props={"aliases": ["alias/demo-data"]})
    fn = g.node(f"arn:aws:lambda:{REGION}:{MAIN}:function:demo-fn", "lambda", "demo-fn", region=REGION,
                props={"qualifiers": ["$LATEST", "live"]})
    sec = g.node(f"arn:aws:secretsmanager:{REGION}:{MAIN}:secret:demo/db-AbCdEf", "secret", "demo/db",
                 region=REGION)
    g.node(CLUSTER, "cluster", "demo-cluster", region=REGION)
    ng = g.node(f"arn:aws:eks:{REGION}:{MAIN}:nodegroup/demo-cluster/demo-ng/0a1b2c3d-1111-2222-3333-444455556666",
                "nodegroup", "demo-ng", region=REGION)
    node_role = g.node(arn_role("demo-node-role"), "role", "demo-node-role")
    irsa = g.node(arn_role("demo-irsa-web"), "role", "demo-irsa-web")
    pod = g.node(k8s("pod", "default", "Deployment:demo-web"), "pod", "default/demo-web", region=REGION)
    sa = g.node(k8s("sa", "default", "demo-web"), "sa", "default/demo-web", region=REGION)
    acct = g.node(_ids.account_anchor_id(MAIN), "account", f"account {MAIN}")

    g.edge(user, "MEMBER_OF", grp, holds=True)
    g.edge(user, "HAS_POLICY", pol)
    g.edge(grp, "CAN_PASS_ROLE_TO", adm, evidence={"via": ["lambda"], "rule_ids": ["PRIVESC-014"]})
    g.edge(adm, "IS_ADMIN_EQUIVALENT", _ids.account_admin_id(MAIN), evidence={"rule_ids": ["ADMIN-001"]})
    g.edge(user, "CAN_ASSUME", app, evidence={"actions": ["sts:AssumeRole"]})
    g.edge(xa, "CAN_ASSUME", app, confidence="conditional", strength="weak",
           evidence={"gaps": ["external-identity-unknown"]}, props={"cross_account": True})
    g.edge(gh, "CAN_ASSUME_WEB_IDENTITY", deploy, confidence="conditional", strength="strong",
           props={"admits": "pattern"})
    g.edge(app, "CAN_READ", bkt, evidence={"actions": ["s3:GetObject", "s3:ListBucket"]})
    g.edge(app, "CAN_DECRYPT", key)
    g.edge(app, "CAN_READ_SECRET", sec)
    g.edge(bkt, "ENCRYPTED_BY", key)
    g.edge(sec, "SECRET_ENCRYPTED_BY", key)
    g.edge(inst, "INSTANCE_ROLE", app)
    g.edge("aws-enumerator:anonymous", "SSRF_TO_IMDS", inst, confidence="conditional", strength="weak")
    g.edge("aws-enumerator:anonymous", "PUBLIC_INBOUND", inst, evidence={"ports": ["tcp/80", "tcp/443"]})
    g.edge("aws-enumerator:anonymous", "GRANTS_PUBLIC", bkt, evidence={"actions": ["s3:GetObject"]})
    g.edge(user, "CAN_INVOKE", fn)
    g.edge(fn, "USES_ROLE", app)
    g.edge(pod, "RUNS_AS", sa)
    g.edge(sa, "IRSA_BRIDGE", irsa, holds=True)
    g.edge(pod, "IN_CLUSTER", CLUSTER)
    g.edge(pod, "CAN_REACH_NODE_IMDS", ng, extra=1, evidence={"technique": "hop-limit-2"})
    g.edge(ng, "NODE_ROLE", node_role)

    g.finding("ADMIN-001", adm, "CRITICAL", "Principal is administrator-equivalent",
              evidence={"capability": "*:*"}, extra={"category": "privilege-escalation"})
    g.finding("PRIVESC-014", grp, "CRITICAL", "PassRole to a new Lambda function", affected_members=[user],
              related=[adm], extra={"matched_actions": ["iam:PassRole", "lambda:CreateFunction",
                                                        "lambda:InvokeFunction"],
                                    "targets": [{"node_id": adm, "tier": "CRITICAL", "decision": "allow"}]})
    g.finding("S3-PUBLIC-001", bkt, "HIGH", "Bucket policy allows public read")
    g.finding("EC2-IMDS-001", inst, "MEDIUM", "Public instance with IMDSv1 and a role", confidence="conditional",
              base_severity="HIGH")
    g.finding("TRUST-002", app, "MEDIUM", "Role trusts another account without a guard", discriminator=EXT,
              related=[xa])
    g.finding("IAM-USER-MFA-001", user, "LOW", "Console user without MFA")
    g.finding("COLLECTION-GAP-001", acct, "INFO", "s3:GetBucketPolicy denied for 1 bucket",
              evidence={"facet": "s3.bucket_policy", "status": "denied"})
    g.finding("LAMBDA-URL-001", fn, "HIGH", "Function URL with NONE auth", status="suppressed",
              suppression={"reason": "Demo endpoint, accepted risk", "expires": "2099-12-31",
                           "owner": "example-team", "match": "fingerprint"})

    g.operator = {"arn": f"arn:aws:sts::{MAIN}:assumed-role/demo-app-role/demo-session", "node_id": app,
                  "resolution": "assumed-role", "redacted": False}
    g.coverage = {
        "source": "ledger", "status": "partial",
        "modules": [
            {"module": "iam", "region": "global", "status": "ok", "error_code": None, "detail": None},
            {"module": "s3", "region": "global", "status": "partial", "error_code": "AccessDenied",
             "detail": "s3:GetBucketPolicy denied for 1 of 1 buckets"},
            {"module": "ec2", "region": REGION, "status": "ok", "error_code": None, "detail": None},
        ],
        "denied_apis": [{"api": "s3:GetBucketPolicy", "regions": ["global"]}],
        "facets": [{"facet": "s3.bucket_policy", "region": "global", "status": "denied", "detail": None}],
    }
    g.gaps = ALWAYS_GAPS + [{"code": "org:scp-unknown", "detail": "Organizations SCPs were not collected.",
                             "count": None}]
    g.analyzers = [
        {"name": "iam.principals", "phase": "principals", "status": "ok", "duration_seconds": 0.01, "error": None,
         "inputs_missing": []},
        {"name": "s3", "phase": "resources", "status": "ok", "duration_seconds": 0.01, "error": None,
         "inputs_missing": ["s3.bucket_policy"]},
        {"name": "posture", "phase": "resources", "status": "not_implemented", "duration_seconds": None,
         "error": None, "inputs_missing": []},
    ]
    return g.doc()


# ── hostile.json ──────────────────────────────────────────────────────────────

HOSTILE = [
    "<img src=x onerror=window.__aeXssCanary=1>",
    "\"><svg onload=window.__aeXssCanary=1>",
    "</script><script>window.__aeXssCanary=1</script>",
    "javascript:window.__aeXssCanary=1",
    "' onmouseover='window.__aeXssCanary=1' x='",
    "\" onfocus=\"window.__aeXssCanary=1\" autofocus=\"",
    "demo\\\\path\\\"quote\\'single",
    "${window.__aeXssCanary=1}",
    "{{constructor.constructor('window.__aeXssCanary=1')()}}",
    "demo‮​unicode line",
]
PROTO = ["constructor", "__proto__", "hasOwnProperty", "toString"]
# IAM paths allow printable ASCII except space: a canary without spaces fits in a role path.
PATH_CANARY = "/<img/src=x/onerror=window.__aeXssCanary=1>/"


def hostile() -> Dict[str, Any]:
    g = G(account=HOSTILE_ACCT)
    acct = HOSTILE_ACCT
    roles = []
    for i, name in enumerate(PROTO):
        roles.append(g.node(arn_role(name, acct), "role", name, props={"note": HOSTILE[i]},
                            tags=[(PROTO[(i + 1) % 4], HOSTILE[i]), ("name", HOSTILE[(i + 5) % 10])]))
    path_role = g.node(arn_role("demo-canary", acct, PATH_CANARY), "role", HOSTILE[0],
                       props={"path": PATH_CANARY, "description": HOSTILE[1]}, high_value="admin-equivalent")
    quote_user = g.node(arn_user("demo-quote", acct, "/\"'\\/"), "user", HOSTILE[6],
                        props={"nested": {"toString": HOSTILE[2], "hasOwnProperty": [HOSTILE[3], {"x": HOSTILE[4]}]}})
    bkt = g.node("arn:aws:s3:::demo-hostile-bucket", "bucket", HOSTILE[5], region=REGION,
                 tags=[("constructor", HOSTILE[7]), ("toString", HOSTILE[8])])
    ext = g.node(f"arn:aws:iam::{EXT}:role/__proto__", "external_principal", "__proto__")
    cluster = f"arn:aws:eks:{REGION}:{acct}:cluster/demo-hostile"
    g.node(cluster, "cluster", HOSTILE[9], region=REGION)
    pod = g.node(_ids.node_id_for("pod", cluster_arn=cluster, namespace="constructor", name="Deployment:toString"),
                 "pod", HOSTILE[2], region=REGION)
    sa = g.node(_ids.node_id_for("sa", cluster_arn=cluster, namespace="constructor", name="hasownproperty"),
                "sa", HOSTILE[4], region=REGION)

    g.edge(quote_user, "CAN_ASSUME", roles[1], evidence={"statements": [{"sid": HOSTILE[0], "policy_name": HOSTILE[2]}],
                                                       "actions": [HOSTILE[3]]})
    g.edge(roles[1], "CAN_PASS_ROLE_TO", path_role, evidence={"via": [HOSTILE[5]], "technique": HOSTILE[8]})
    g.edge(path_role, "IS_ADMIN_EQUIVALENT", _ids.account_admin_id(acct))
    g.edge(ext, "GRANTS_CROSS_ACCOUNT", bkt, evidence={"conditions": [{"key": HOSTILE[1], "values": HOSTILE[:3]}]})
    g.edge("aws-enumerator:anonymous", "GRANTS_PUBLIC", bkt)
    g.edge(pod, "RUNS_AS", sa)
    g.edge(sa, "IRSA_BRIDGE", roles[0], holds=True, evidence={"annotation": HOSTILE[9]})
    g.edge(roles[0], "CAN_READ", bkt)

    g.finding("ADMIN-001", path_role, "CRITICAL", HOSTILE[0], description=HOSTILE[1], remediation=HOSTILE[2],
              evidence={"capability": HOSTILE[3], "steps": [{"rule_action": HOSTILE[4]}]},
              reference="https://example.invalid/docs?\"><img/src=x/onerror=window.__aeXssCanary=1>")
    g.finding("S3-PUBLIC-001", bkt, "HIGH", HOSTILE[5], description=HOSTILE[6], remediation=HOSTILE[7],
              related=[ext], extra={"matched_actions": [HOSTILE[8]], "entity": HOSTILE[9]})
    g.finding("K8S-IRSA-001", sa, "MEDIUM", "__proto__", description="constructor", remediation="toString",
              extra={"category": "hasOwnProperty"})
    g.finding("TRUST-002", roles[2], "LOW", HOSTILE[8], discriminator=HOSTILE[3])
    g.operator = {"arn": f"arn:aws:sts::{acct}:assumed-role/__proto__/demo-session", "node_id": roles[1],
                  "resolution": "assumed-role", "redacted": False}
    g.coverage = {"source": "ledger", "status": "partial", "modules": [
        {"module": HOSTILE[0], "region": HOSTILE[1], "status": "denied", "error_code": HOSTILE[2],
         "detail": HOSTILE[3]}]}
    g.gaps = [{"code": "external-identity", "detail": HOSTILE[4], "count": 1}]
    g.analyzers = [{"name": HOSTILE[5], "phase": "resources", "status": "error", "duration_seconds": 0.0,
                    "error": {"type": "ValueError", "message": HOSTILE[6]}, "inputs_missing": [HOSTILE[7]]}]
    return g.doc()


# ── path_cases.json ───────────────────────────────────────────────────────────

A, B = arn_user("demo-alice"), arn_user("demo-bob")
GRP = arn_group("demo-devs")
POL = f"arn:aws:iam::{MAIN}:policy/demo-shared-policy"
R1, R2 = arn_role("demo-role-a"), arn_role("demo-role-b")
ADMIN = _ids.account_admin_id(MAIN)
ANON = _ids.ANONYMOUS_ID
BKT = "arn:aws:s3:::demo-shared-bucket"
XP = arn_role("demo-partner-role", EXT)
XA = _ids.external_account_id(EXT)
FN = f"arn:aws:lambda:{REGION}:{MAIN}:function:demo-fn"
EXEC = arn_role("demo-fn-exec")
SEC = f"arn:aws:secretsmanager:{REGION}:{MAIN}:secret:demo/api-key-Ab12Cd"
KEY = f"arn:aws:kms:{REGION}:{MAIN}:key/1234abcd-12ab-34cd-56ef-1234567890ab"
INST = f"arn:aws:ec2:{REGION}:{MAIN}:instance/i-0123456789abcdef0"
POOL = f"arn:aws:cognito-identity:{REGION}:{MAIN}:identitypool/{REGION}:00000000-1111-2222-3333-444444444444"
NG = f"arn:aws:eks:{REGION}:{MAIN}:nodegroup/demo-cluster/demo-ng/0a1b2c3d-1111-2222-3333-444455556666"
NODE_ROLE = arn_role("demo-node-role")
IRSA1, IRSA2 = arn_role("demo-irsa-web"), arn_role("demo-irsa-worker")
TIE_A, TIE_C = arn_role("demo-tie-a"), arn_role("demo-tie-c")


def _types() -> Dict[str, str]:
    return {A: "user", B: "user", GRP: "group", POL: "policy", R1: "role", R2: "role", BKT: "bucket",
            XP: "external_principal", XA: "external_account", FN: "lambda", EXEC: "role", SEC: "secret",
            KEY: "kms", INST: "instance", POOL: "cognito", NG: "nodegroup", NODE_ROLE: "role", IRSA1: "role",
            IRSA2: "role", CLUSTER: "cluster", TIE_A: "role", TIE_C: "role"}


def _k8s_ids() -> Dict[str, str]:
    return {
        "POD1": k8s("pod", "default", "Deployment:demo-web"), "POD2": k8s("pod", "default", "Deployment:demo-worker"),
        "SA1": k8s("sa", "default", "demo-web"), "SA2": k8s("sa", "default", "demo-worker"),
        "K8SROLE": k8s("k8srole", "default", "demo-pod-creator", "Role"),
    }


def _case_graph(edges: List[Tuple]) -> Dict[str, Any]:
    """A graph from ``(src, type, tgt, kwargs)`` tuples; endpoint nodes are created from their ids."""
    g = G()
    types = {**_types(), **{v: k.lower().rstrip("12") if k != "K8SROLE" else "k8srole"
                            for k, v in _k8s_ids().items()}}
    for e in edges:
        for nid in (e[0], e[2]):
            if nid not in g.nodes:
                nt = types[nid]
                region = REGION if _et.NODE_TYPES[nt].group in ("compute", "kubernetes", "data", "edge") \
                    and nt not in ("bucket",) else None
                g.node(nid, nt, nid.rsplit("/", 1)[-1].rsplit(":", 1)[-1], region=region)
    for src, etype, tgt, *kw in edges:
        g.edge(src, etype, tgt, **(kw[0] if kw else {}))
    return g.doc()


def path_cases() -> List[Dict[str, Any]]:
    k = _k8s_ids()
    pod1, pod2, sa1, sa2, krole = k["POD1"], k["POD2"], k["SA1"], k["SA2"], k["K8SROLE"]
    shared_group = [(A, "MEMBER_OF", GRP, {"holds": True}), (B, "MEMBER_OF", GRP, {"holds": True}),
                    (GRP, "CAN_PASS_ROLE_TO", R1)]
    shared_policy = [(A, "HAS_POLICY", POL), (R1, "HAS_POLICY", POL)]
    shared_bucket = [(A, "CAN_READ", BKT), (XP, "GRANTS_CROSS_ACCOUNT", BKT)]
    assume = [(R1, "CAN_ASSUME", R2)]
    lam_invoke = [(A, "CAN_INVOKE", FN), (FN, "USES_ROLE", EXEC)]
    lam_code = [(A, "CAN_UPDATE_CODE", FN), (FN, "USES_ROLE", EXEC)]
    k8s_pods = [(pod1, "IN_CLUSTER", CLUSTER), (pod2, "IN_CLUSTER", CLUSTER), (pod1, "RUNS_AS", sa1),
                (pod2, "RUNS_AS", sa2), (sa1, "IRSA_BRIDGE", IRSA1, {"holds": True}),
                (sa2, "IRSA_BRIDGE", IRSA2, {"holds": True})]
    cond = [(XA, "CAN_ASSUME", R1, {"confidence": "conditional", "strength": "weak"}),
            (R1, "CAN_READ_SECRET", SEC)]
    # demo-tie-a sorts before demo-tie-c by node id, but the edge into demo-tie-c has the smaller edge id,
    # so this vector distinguishes the edge-id tie-break from a node-id one.
    tie_edges = [(A, "CAN_ASSUME", TIE_A), (TIE_A, "IS_ADMIN_EQUIVALENT", ADMIN),
                 (A, "CAN_ASSUME", TIE_C), (TIE_C, "IS_ADMIN_EQUIVALENT", ADMIN)]
    tie_path = min(([A, r, ADMIN] for r in (TIE_A, TIE_C)),
                   key=lambda p: (_ids.edge_id(p[0], "CAN_ASSUME", p[1]),
                                  _ids.edge_id(p[1], "IS_ADMIN_EQUIVALENT", p[2])))
    cases: List[Dict[str, Any]] = [
        dict(name="shared_group_no_path_between_members", findings=["F-007"],
             description="Two users in one group: membership is user → group only, so no member reaches another.",
             edges=shared_group, source=A, target=B, expect={"reachable": False}),
        dict(name="shared_group_member_reaches_group_capability", findings=["F-007"],
             description="A member reaches what the group can do (MEMBER_OF weight 0).",
             edges=shared_group, source=B, target=R1,
             expect={"reachable": True, "cost": 2, "hops": 2, "path": [B, GRP, R1],
                     "edge_types": ["MEMBER_OF", "CAN_PASS_ROLE_TO"]}),
        dict(name="shared_policy_no_path", findings=["F-007"],
             description="A user and a role share a managed policy: HAS_POLICY is structural, not traversable.",
             edges=shared_policy, source=A, target=R1, expect={"reachable": False}),
        dict(name="shared_policy_attachment_not_walkable", findings=["F-007"],
             description="Not even the policy node itself is reachable.",
             edges=shared_policy, source=A, target=POL, expect={"reachable": False}),
        dict(name="shared_bucket_no_path_to_grantee", findings=["F-007", "F-039"],
             description="A reader of a bucket does not reach the external grantee of the same bucket; the grant "
                         "edge is normalised grantee → bucket.",
             edges=shared_bucket, source=A, target=XP, expect={"reachable": False}),
        dict(name="shared_bucket_grantee_reaches_bucket", findings=["F-007"],
             description="The normalised cross-account grant is walkable from the grantee.",
             edges=shared_bucket, source=XP, target=BKT,
             expect={"reachable": True, "cost": 2, "hops": 1, "path": [XP, BKT],
                     "edge_types": ["GRANTS_CROSS_ACCOUNT"]}),
        dict(name="reversed_edge_not_walkable", findings=["F-007"],
             description="R1 can assume R2; R2 cannot reach R1 by walking the edge backwards.",
             edges=assume, source=R2, target=R1, expect={"reachable": False}),
        dict(name="forward_edge_walkable", findings=["F-007"], description="The same edge, forwards.",
             edges=assume, source=R1, target=R2,
             expect={"reachable": True, "cost": 1, "hops": 1, "path": [R1, R2], "edge_types": ["CAN_ASSUME"]}),
        dict(name="zero_weight_path_honoured", findings=["F-040"],
             description="pod → service account → IRSA role costs 0; a zero-cost path is a real path.",
             edges=k8s_pods, source=pod1, target=IRSA1,
             expect={"reachable": True, "cost": 0, "hops": 2, "path": [pod1, sa1, IRSA1],
                     "edge_types": ["RUNS_AS", "IRSA_BRIDGE"]}),
        dict(name="zero_weight_edge_preferred", findings=["F-040"],
             description="FULL_ACCESS (0) is cheaper than CAN_ADMIN (0.5); weight 0 must not become 1.",
             edges=[(A, "CAN_ADMIN", BKT), (A, "FULL_ACCESS", BKT)], source=A, target=BKT,
             expect={"reachable": True, "cost": 0, "hops": 1, "path": [A, BKT], "edge_types": ["FULL_ACCESS"]}),
        dict(name="lower_cost_beats_fewer_hops", findings=["F-040", "F-037"],
             description="A 1-hop conditional (strong, weight 4) trust loses to a 2-hop zero-cost Cognito path.",
             edges=[(ANON, "CAN_ASSUME", R2, {"confidence": "conditional", "strength": "strong"}),
                    (ANON, "COGNITO_PUBLIC_IDENTITY", POOL), (POOL, "POOL_UNAUTH_ROLE", R2)],
             source=ANON, target=R2,
             expect={"reachable": True, "cost": 0, "hops": 2, "path": [ANON, POOL, R2],
                     "edge_types": ["COGNITO_PUBLIC_IDENTITY", "POOL_UNAUTH_ROLE"]}),
        dict(name="equal_cost_prefers_fewer_hops", findings=[],
             description="Cost 2 either way; the 1-hop path wins the tie.",
             edges=[(A, "CAN_PASS_ROLE_TO", R2), (A, "CAN_ASSUME", R1), (R1, "CAN_ASSUME", R2)],
             source=A, target=R2,
             expect={"reachable": True, "cost": 2, "hops": 1, "path": [A, R2], "edge_types": ["CAN_PASS_ROLE_TO"]}),
        dict(name="equal_cost_and_hops_breaks_tie_on_edge_ids", findings=[],
             description="Two paths of cost 1 and 2 hops: the one whose edge-id sequence sorts first wins.",
             edges=tie_edges, source=A, target=ADMIN,
             expect={"reachable": True, "cost": 1, "hops": 2, "path": tie_path,
                     "edge_types": ["CAN_ASSUME", "IS_ADMIN_EQUIVALENT"]}),
        dict(name="conditional_edge_included_by_default", findings=["F-036"],
             description="Cross-account trust is conditional (weak): weight 1 + 1.",
             edges=cond, source=XA, target=SEC,
             expect={"reachable": True, "cost": 3, "hops": 2, "path": [XA, R1, SEC],
                     "edge_types": ["CAN_ASSUME", "CAN_READ_SECRET"]}),
        dict(name="conditional_edge_excluded_with_definite_only", findings=["F-036"],
             description="Option definite_only drops conditional edges.",
             edges=cond, source=XA, target=SEC, options={"definite_only": True}, expect={"reachable": False}),
        dict(name="anonymous_reaches_public_bucket", findings=["F-037"],
             description="A public bucket policy is an edge from the anonymous node.",
             edges=[(ANON, "GRANTS_PUBLIC", BKT)], source=ANON, target=BKT,
             expect={"reachable": True, "cost": 0, "hops": 1, "path": [ANON, BKT], "edge_types": ["GRANTS_PUBLIC"]}),
        dict(name="lambda_invoke_does_not_reach_execution_role", findings=["F-004"],
             description="CAN_INVOKE is not traversable: invoking a function does not give its role.",
             edges=lam_invoke, source=A, target=EXEC, expect={"reachable": False}),
        dict(name="lambda_invoke_does_not_enter_function", findings=["F-004"],
             description="Not even the function node is reachable through CAN_INVOKE.",
             edges=lam_invoke, source=A, target=FN, expect={"reachable": False}),
        dict(name="lambda_update_code_reaches_execution_role", findings=["F-004"],
             description="CAN_UPDATE_CODE is control; USES_ROLE carries on to the role.",
             edges=lam_code, source=A, target=EXEC,
             expect={"reachable": True, "cost": 1, "hops": 2, "path": [A, FN, EXEC],
                     "edge_types": ["CAN_UPDATE_CODE", "USES_ROLE"],
                     "must_not_traverse_types": ["CAN_INVOKE", "LAMBDA_GRANTS_INVOKE"]}),
        dict(name="lambda_resource_policy_grant_not_walkable", findings=["F-004", "F-039"],
             description="A cross-account invoke grant enters the function but never as control.",
             edges=[(XP, "LAMBDA_GRANTS_CROSS_ACCOUNT", FN), (FN, "USES_ROLE", EXEC)], source=XP, target=EXEC,
             expect={"reachable": False}),
        dict(name="irsa_unverified_not_traversable", findings=["F-034"],
             description="The annotation exists but the role's trust does not admit the service account.",
             edges=[(pod2, "RUNS_AS", sa2), (sa2, "IRSA_BRIDGE", IRSA2, {"holds": False})], source=pod2,
             target=IRSA2, expect={"reachable": False}),
        dict(name="irsa_unverified_still_reaches_service_account", findings=["F-034"],
             description="The pod → service-account step is unaffected.",
             edges=[(pod2, "RUNS_AS", sa2), (sa2, "IRSA_BRIDGE", IRSA2, {"holds": False})], source=pod2,
             target=sa2, expect={"reachable": True, "cost": 0, "hops": 1, "path": [pod2, sa2],
                                 "edge_types": ["RUNS_AS"]}),
        dict(name="k8s_pods_sharing_cluster_not_connected", findings=["F-007"],
             description="IN_CLUSTER is structural: two pods in one cluster do not reach each other.",
             edges=k8s_pods, source=pod1, target=pod2, expect={"reachable": False}),
        dict(name="k8s_pod_does_not_reach_other_pods_role", findings=["F-007", "F-034"],
             description="Nor does a pod reach the IRSA role of another pod in the cluster.",
             edges=k8s_pods, source=pod1, target=IRSA2, expect={"reachable": False}),
        dict(name="k8s_rbac_pivot_to_other_service_account", findings=["F-035"],
             description="A service account bound to a role that can create pods runs as another service account.",
             edges=[(sa1, "BOUND_TO", krole), (krole, "CAN_RUN_AS_SA", sa2),
                    (sa2, "IRSA_BRIDGE", IRSA2, {"holds": True})], source=sa1, target=IRSA2,
             expect={"reachable": True, "cost": 1, "hops": 3, "path": [sa1, krole, sa2, IRSA2],
                     "edge_types": ["BOUND_TO", "CAN_RUN_AS_SA", "IRSA_BRIDGE"]}),
        dict(name="pod_reaches_node_role_through_imds", findings=["F-033"],
             description="weight_extra (hop limit) is part of the stored weight: 1 + 2.",
             edges=[(pod1, "CAN_REACH_NODE_IMDS", NG, {"extra": 2}), (NG, "NODE_ROLE", NODE_ROLE)],
             source=pod1, target=NODE_ROLE,
             expect={"reachable": True, "cost": 3, "hops": 2, "path": [pod1, NG, NODE_ROLE],
                     "edge_types": ["CAN_REACH_NODE_IMDS", "NODE_ROLE"]}),
        dict(name="hidden_category_excluded", findings=["F-096"],
             description="Option exclude_categories: a hidden edge category is not used for paths.",
             edges=lam_code, source=A, target=EXEC, options={"exclude_categories": ["lambda"]},
             expect={"reachable": False}),
        dict(name="hidden_node_type_excluded", findings=["F-096"],
             description="Option exclude_node_types: an edge touching a hidden node type is not used.",
             edges=lam_code, source=A, target=EXEC, options={"exclude_node_types": ["lambda"]},
             expect={"reachable": False}),
        dict(name="escalation_reaches_account_admin", findings=["F-016"],
             description="PassRole to an admin-equivalent role reaches the account-admin target.",
             edges=[(A, "CAN_PASS_ROLE_TO", R1), (R1, "IS_ADMIN_EQUIVALENT", ADMIN)], source=A, target=ADMIN,
             expect={"reachable": True, "cost": 2, "hops": 2, "path": [A, R1, ADMIN],
                     "edge_types": ["CAN_PASS_ROLE_TO", "IS_ADMIN_EQUIVALENT"]}),
        dict(name="data_asset_is_terminal", findings=["F-007"],
             description="Reading a secret does not lead on to its KMS key (SECRET_ENCRYPTED_BY is structural).",
             edges=[(R1, "CAN_READ_SECRET", SEC), (SEC, "SECRET_ENCRYPTED_BY", KEY)], source=R1, target=KEY,
             expect={"reachable": False}),
        dict(name="ssrf_reaches_instance_role_not_via_exposure", findings=["F-037", "F-106"],
             description="SSRF_TO_IMDS (5 + 1 conditional) then INSTANCE_ROLE (0); PUBLIC_INBOUND is exposure "
                         "only and never walked.",
             edges=[(ANON, "PUBLIC_INBOUND", INST), (ANON, "SSRF_TO_IMDS", INST,
                                                     {"confidence": "conditional", "strength": "weak"}),
                    (INST, "INSTANCE_ROLE", R1)], source=ANON, target=R1,
             expect={"reachable": True, "cost": 6, "hops": 2, "path": [ANON, INST, R1],
                     "edge_types": ["SSRF_TO_IMDS", "INSTANCE_ROLE"], "must_not_traverse_types": ["PUBLIC_INBOUND"]}),
    ]
    out = []
    for c in cases:
        out.append({
            "name": c["name"], "description": c["description"], "findings": c["findings"],
            "graph": _case_graph(c["edges"]), "source": c["source"], "target": c["target"],
            "options": c.get("options", {}), "expect": c["expect"],
        })
    return out


# ── graph-invalid/ ────────────────────────────────────────────────────────────

def _first(doc: Dict[str, Any], key: str, pred) -> int:
    return next(i for i, x in enumerate(doc[key]) if pred(x))


def invalid_cases() -> List[Tuple[str, Dict[str, Any], Dict[str, Any]]]:
    """``(file name, document, expectation)``.

    ``layer: schema`` → ``errors`` is a list of ``[keyword, instance JSON pointer]``. Every schema error must
    match one entry (the keyword appears in the error's schema path, the instance path is equal) and every
    entry must be matched by at least one error. ``layer: semantic`` → the document is schema-valid and
    ``validate_graph`` returns exactly ``codes`` (with ``strict_order`` when set)."""
    base = example()
    out: List[Tuple[str, Dict[str, Any], Dict[str, Any]]] = []

    def case(name: str, expect: Dict[str, Any], mutate) -> None:
        d = copy.deepcopy(base)
        mutate(d)
        out.append((name, d, expect))

    def fidx(d, fid):
        return _first(d, "findings", lambda f: f["id"] == fid)

    def eidx(d, etype):
        return _first(d, "edges", lambda e: e["type"] == etype)

    def nidx(d, ntype):
        return _first(d, "nodes", lambda n: n["type"] == ntype)

    # schema layer
    case("finding_missing_node_id.json", {"layer": "schema", "errors": [["required", "/findings/0"]]},
         lambda d: d["findings"][0].pop("node_id"))
    case("negative_weight.json", {"layer": "schema", "errors": [["minimum", "/edges/0/weight"]]},
         lambda d: d["edges"][0].__setitem__("weight", -1))
    case("non_numeric_weight.json", {"layer": "schema", "errors": [["type", "/edges/0/weight"]]},
         lambda d: d["edges"][0].__setitem__("weight", "1"))
    case("traversable_not_boolean.json", {"layer": "schema", "errors": [["type", "/edges/0/traversable"]]},
         lambda d: d["edges"][0].__setitem__("traversable", "true"))
    case("wrong_schema_major.json", {"layer": "schema", "errors": [["pattern", "/schema_version"]]},
         lambda d: d.__setitem__("schema_version", "2.0.0"))

    def proto(d):
        i = nidx(d, "bucket")
        d["nodes"][i]["props"]["__proto__"] = {"polluted": True}
    case("proto_props.json", {"layer": "schema", "errors": [["propertyNames", "/nodes/{bucket}/props"]]}, proto)

    def proto_nested(d):
        i = eidx(d, "CAN_READ")
        d["edges"][i]["evidence"]["statements"] = [{"sid": "demo", "__proto__": {"polluted": True}}]
    case("proto_nested_evidence.json",
         {"layer": "schema", "errors": [["propertyNames", "/edges/{CAN_READ}/evidence/statements/0"]]},
         proto_nested)

    def wildcard_node(d):
        g_ = G()
        g_.node("principal:*", "external_principal", "principal:*")
        d["nodes"].append(g_.nodes["principal:*"])
    case("principal_wildcard_node.json", {"layer": "schema", "errors": [["not", "/nodes/{last}/id"]]},
         wildcard_node)
    case("reference_not_https.json", {"layer": "schema", "errors": [["anyOf", "/findings/0/reference"]]},
         lambda d: d["findings"][0].__setitem__("reference", "javascript:window.__aeXssCanary=1"))
    case("unknown_top_level_key.json", {"layer": "schema", "errors": [["additionalProperties", ""]]},
         lambda d: d.__setitem__("caller", {"arn": None}))

    # semantic layer
    def dangling(d):
        src = arn_user("demo-user")
        tgt = f"arn:aws:iam::{MAIN}:role/demo-missing-role"
        e = {"id": _ids.edge_id(src, "CAN_ASSUME", tgt), "source": src, "target": tgt, "type": "CAN_ASSUME",
             "category": "trust", "traversal": "control", "traversable": True, "weight": 1,
             "confidence": "definite", "evidence": {}}
        d["edges"].append(e)
    case("dangling_edge.json", {"layer": "semantic", "codes": ["dangling-edge-target"]}, dangling)

    def dangling_finding(d):
        f = copy.deepcopy(d["findings"][fidx(d, "IAM-USER-MFA-001")])
        f["node_id"] = arn_user("demo-deleted-user")
        f["fingerprint"] = _ids.finding_fingerprint(f["id"], MAIN, f["node_id"])
        d["findings"].append(f)
    case("finding_dangling_node_id.json", {"layer": "semantic", "codes": ["finding-node-missing"]},
         dangling_finding)

    case("duplicate_node_ids.json", {"layer": "semantic", "codes": ["duplicate-node-id"]},
         lambda d: d["nodes"].append(copy.deepcopy(d["nodes"][nidx(d, "kms")])))
    case("duplicate_edge_ids.json", {"layer": "semantic", "codes": ["duplicate-edge-id"]},
         lambda d: d["edges"].append(copy.deepcopy(d["edges"][eidx(d, "CAN_READ")])))
    case("edge_id_mismatch.json", {"layer": "semantic", "codes": ["edge-id-mismatch"]},
         lambda d: d["edges"][eidx(d, "CAN_READ")].__setitem__("id", "e:" + "0" * 20))
    case("traversal_mismatch.json", {"layer": "semantic", "codes": ["edge-traversal-mismatch"]},
         lambda d: d["edges"][eidx(d, "CAN_ASSUME")].__setitem__("traversal", "access"))
    case("bridge_invariant.json", {"layer": "semantic", "codes": ["bridge-invariant", "edge-traversable-not-allowed"]},
         lambda d: d["edges"][eidx(d, "CAN_INVOKE")].__setitem__("traversable", True))

    def unknown_type(d):
        i = eidx(d, "CAN_READ")
        e = d["edges"][i]
        e["type"] = "CAN_TELEPORT"
        e["id"] = _ids.edge_id(e["source"], "CAN_TELEPORT", e["target"])
        d["edge_types"]["CAN_TELEPORT"] = dict(d["edge_types"]["CAN_READ"])
    case("unknown_edge_type.json", {"layer": "semantic", "codes": ["unknown-edge-type"]}, unknown_type)

    def operator_missing(d):
        d["meta"]["default_sources"].remove(d["run"]["operator"]["node_id"])
        d["run"]["operator"]["node_id"] = arn_role("demo-not-collected")
    case("operator_node_missing.json", {"layer": "semantic", "codes": ["operator-node-missing"]}, operator_missing)
    case("weight_below_base.json", {"layer": "semantic", "codes": ["weight-below-base"]},
         lambda d: d["edges"][eidx(d, "CAN_PASS_ROLE_TO")].__setitem__("weight", 1))

    def wrong_source(d):
        i = eidx(d, "CAN_READ")
        e = d["edges"][i]
        inst = d["nodes"][nidx(d, "instance")]["id"]
        e["source"] = inst
        e["id"] = _ids.edge_id(inst, "CAN_READ", e["target"])
    case("edge_source_type.json", {"layer": "semantic", "codes": ["edge-source-type"]}, wrong_source)

    def rule_missing(d):
        d["edges"][eidx(d, "IRSA_BRIDGE")]["evidence"].pop("traversable_rule")
    case("traversable_rule_missing.json", {"layer": "semantic", "codes": ["traversable-rule-missing"]}, rule_missing)

    case("registry_mismatch.json", {"layer": "semantic", "codes": ["edge-registry-mismatch"]},
         lambda d: d["edge_types"]["CAN_READ"].__setitem__("base_weight", 0))

    def max_sev(d):
        d["nodes"][nidx(d, "bucket")]["max_severity"] = "CRITICAL"
    case("max_severity_mismatch.json", {"layer": "semantic", "codes": ["max-severity-mismatch"]}, max_sev)

    def missing_anon(d):
        d["nodes"].pop(_first(d, "nodes", lambda n: n["type"] == "anonymous"))
        d["meta"]["default_sources"].remove(_ids.ANONYMOUS_ID)
        for e in [e for e in d["edges"] if e["source"] == _ids.ANONYMOUS_ID]:
            d["edges"].remove(e)
        d["node_types"].pop("anonymous")
        for t in ("SSRF_TO_IMDS", "PUBLIC_INBOUND", "GRANTS_PUBLIC"):
            d["edge_types"].pop(t)
    case("missing_anonymous_node.json", {"layer": "semantic", "codes": ["synthetic-node-missing"]}, missing_anon)

    def legacy_id(d):
        i = nidx(d, "group")
        old = d["nodes"][i]["id"]
        new = "group:demo-devs"
        d["nodes"][i]["id"] = new
        for e in d["edges"]:
            for k_ in ("source", "target"):
                if e[k_] == old:
                    e[k_] = new
            e["id"] = _ids.edge_id(e["source"], e["type"], e["target"])
        for f in d["findings"]:
            if f["node_id"] == old:
                f["node_id"] = new
    case("legacy_node_id_scheme.json", {"layer": "semantic", "codes": ["node-id-pattern"]}, legacy_id)

    def meta_targets(d):
        d["meta"]["default_targets"] = [_ids.account_admin_id(MAIN)]
    case("meta_targets_mismatch.json", {"layer": "semantic", "codes": ["meta-targets-mismatch"]}, meta_targets)

    case("out_of_order.json", {"layer": "semantic", "codes": ["order"], "strict_order": True},
         lambda d: d["nodes"].reverse())

    # resolve placeholders in expectation paths
    resolved = []
    for name, d, exp in out:
        if exp["layer"] == "schema":
            errs = []
            for kw, ptr in exp["errors"]:
                ptr = ptr.replace("{bucket}", str(nidx(d, "bucket")))
                if "{CAN_READ}" in ptr:
                    ptr = ptr.replace("{CAN_READ}", str(eidx(d, "CAN_READ")))
                ptr = ptr.replace("{last}", str(len(d["nodes"]) - 1))
                errs.append([kw, ptr])
            exp = {**exp, "errors": errs}
        resolved.append((name, d, {"file": name, **exp}))
    return resolved


# ── write / check ─────────────────────────────────────────────────────────────

def _dump(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=True, sort_keys=False) + "\n"


def outputs() -> Dict[Path, str]:
    files: Dict[Path, str] = {
        HERE / "minimal.json": _dump(minimal()),
        HERE / "example.json": _dump(example()),
        HERE / "hostile.json": _dump(hostile()),
        HERE / "path_cases.json": _dump(path_cases()),
    }
    inv_dir = HERE.parent / "graph-invalid"
    expectations = []
    for name, doc, exp in invalid_cases():
        files[inv_dir / name] = _dump(doc)
        expectations.append(exp)
    files[inv_dir / "expectations.json"] = _dump(sorted(expectations, key=lambda e: e["file"]))
    return files


def main(argv: List[str]) -> int:
    if argv not in (["--write"], ["--check"]):
        sys.stderr.write("usage: build_fixtures.py --write | --check\n")
        return 64
    stale = []
    for path, text in outputs().items():
        if argv == ["--write"]:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
        else:
            try:
                current = path.read_text(encoding="utf-8")
            except FileNotFoundError:
                current = None
            if current != text:
                stale.append(str(path.relative_to(REPO)))
    for s in stale:
        sys.stderr.write(f"stale fixture: {s}\n")
    return 1 if stale else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
