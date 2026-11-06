"""pathfinding.cloud coverage harness (engine.md §3.6; F-011).

For each of the 92 vendored paths a minimal synthetic report is built (``tests/fixtures/e-rules/worlds.py``):

* the **attacker** principal holds exactly the path's required permissions on ``*`` (a user by default; a role,
  or a user in a group, where the path says so);
* the **target** the path needs is present and administrator-equivalent: a role trusting the path's service
  principals (new-passrole), an existing resource running as an admin role (existing-passrole), an admin user,
  group or role (principal-access, self-escalation), or a low-privilege principal the attacker must first modify
  (the "modify + act as" paths iam-014 … iam-021);

then the whole engine runs (``analyze_report``). A path is **covered** when ``graph.json`` has a CRITICAL finding
of a rule that references the path (``references.pathfinding_cloud``) on the attacker, or a directed path over
traversable edges from the attacker to the account-admin node (the reference traversal of graph-json.md §11).

**Negative twins** (precision): for every required permission the same world is built without it; the twin must
not be covered. A twin is skipped only when the removed permission is pure reconnaissance (:data:`RECON`: the
technique does not depend on it). A twin that fires is a false positive unless the remaining permissions complete
another catalogued path (then firing is correct and it is reported as ``justified``).

Resource types aws-enumerator does not collect (App Runner services, Batch job definitions, Bedrock AgentCore
resources, CodeDeploy deployment groups, Step Functions state machines) cannot be planted; their rules report a
conditional LOW finding and the path counts as not covered. ``python -m tests.python.engine.bench.pathfinding_harness
--write`` regenerates ``coverage.json``.
"""

from __future__ import annotations

import argparse
import importlib
import json
import logging
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from tests.python.engine.bench import import_pathfinding as PF

W = importlib.import_module("tests.fixtures.e-rules.worlds")
rb = W.rb

COVERAGE_FILE = Path(__file__).resolve().parent / "coverage.json"
ATTACKER = "demo-attacker"
ADMIN_ROLE = "demo-target-admin"
#: Paths whose admin target cannot be planted: no aws-enumerator collector lists the resource type.
UNCOLLECTED = {
    "apprunner-002": "App Runner services", "batch-002": "Batch job definitions",
    "bedrock-002": "Bedrock AgentCore code interpreters", "bedrock-004": "Bedrock AgentCore runtimes",
    "bedrock-007": "Bedrock AgentCore browsers", "codedeploy-001": "CodeDeploy deployment groups",
    "stepfunctions-002": "Step Functions state machines",
}
#: existing-passrole paths -> the resource the world plants (rules/inventory.py types).
EXISTING = {
    "cloudformation-002": "cfn_stack", "cloudformation-005": "cfn_stack", "codebuild-002": "codebuild_project",
    "codebuild-003": "codebuild_project", "ec2instanceconnect-003": "ec2_instance", "ec2-002": "ec2_instance",
    "ssm-001": "ec2_instance", "ssm-002": "ec2_instance", "ec2-004": "ec2_launch_template",
    "ec2-005": "ec2_launch_template", "ecs-006": "ecs_exec_service", "glue-002": "glue_dev_endpoint",
    "lambda-003": "lambda_function", "lambda-004": "lambda_function", "lambda-005": "lambda_function",
    "sagemaker-004": "sagemaker_notebook", "sagemaker-005": "sagemaker_notebook",
}
#: Service principals the admin role trusts when the path's prerequisites name none.
SERVICE_OVERRIDES = {"cloudformation-004": ("cloudformation.amazonaws.com",)}
EXISTING_SERVICE = {
    "cfn_stack": "cloudformation.amazonaws.com", "codebuild_project": "codebuild.amazonaws.com",
    "ec2_instance": "ec2.amazonaws.com", "ec2_launch_template": "ec2.amazonaws.com",
    "ecs_exec_service": "ecs-tasks.amazonaws.com", "glue_dev_endpoint": "glue.amazonaws.com",
    "lambda_function": "lambda.amazonaws.com", "sagemaker_notebook": "sagemaker.amazonaws.com",
}


# ── worlds ───────────────────────────────────────────────────────────────────

def _arn(service: str, resource: str) -> str:
    return f"arn:aws:{service}:{W.REGION}:{W.ACCT}:{resource}"


def _instance_profile(w: Any) -> str:
    return w.iam.instance_profile("demo-admin-profile", [ADMIN_ROLE])


def _plant(w: Any, rtype: str) -> None:
    """An existing resource of ``rtype`` running as the admin role."""
    admin = w.admin_role(ADMIN_ROLE, W.trusts_service(EXISTING_SERVICE[rtype]))
    planters: Dict[str, Callable[[], None]] = {
        "lambda_function": lambda: w.write("lambda/functions.json", [W.lambda_function("demo-target-fn", admin)]),
        "codebuild_project": lambda: w.write("codebuild/resources.json", [rb.compute_resource(
            "codebuild", _arn("codebuild", "project/demo-build"), "demo-build", [admin])]),
        "glue_dev_endpoint": lambda: w.write("glue/resources.json", [rb.compute_resource(
            "gluejob", _arn("glue", "devEndpoint/demo-endpoint"), "demo-endpoint", [admin], Kind="dev_endpoint")]),
        "cfn_stack": lambda: w.write("cloudformation/resources.json", [rb.compute_resource(
            "cfnstack", _arn("cloudformation", "stack/demo-stack/0a1b2c3d-0000-4000-8000-000000000001"),
            "demo-stack", [admin])]),
        "sagemaker_notebook": lambda: w.write("sagemaker/resources.json", [rb.compute_resource(
            "sagemaker", _arn("sagemaker", "notebook-instance/demo-notebook"), "demo-notebook", [admin],
            Kind="notebook")]),
        "ecs_exec_service": lambda: _plant_ecs(w, admin),
        "ec2_instance": lambda: w.write("ec2/instances.json", [rb.ec2_instance(
            "i-0a1b2c3d4e5f60001", account=W.ACCT, region=W.REGION, profile=_instance_profile(w))]),
        "ec2_launch_template": lambda: w.write("ec2/launch_templates.json", [{
            "LaunchTemplateId": "lt-0a1b2c3d4e5f60001", "LaunchTemplateName": "demo-lt",
            "Arn": _arn("ec2", "launch-template/lt-0a1b2c3d4e5f60001"),
            "Versions": [{"VersionNumber": 1, "DefaultVersion": True,
                          "IamInstanceProfile": {"Arn": _instance_profile(w)}}]}]),
    }
    planters[rtype]()


def _plant_ecs(w: Any, admin: str) -> None:
    task = _arn("ecs", "task-definition/demo-task:1")
    w.write("ecs/resources.json", [rb.compute_resource("ecstask", task, "demo-task", [admin], Family="demo-task",
                                                       TaskRole=admin, ExecutionRole=None)])
    w.write("ecs/services.json", [{"ClusterArn": _arn("ecs", "cluster/demo-cluster"),
                                   "ServiceArn": _arn("ecs", "service/demo-cluster/demo-svc"), "Name": "demo-svc",
                                   "TaskDefinition": task, "EnableExecuteCommand": True}])


def _attacker(w: Any, path: PF.PathDef, actions: Sequence[str]) -> str:
    stmt = W.allow(sorted(actions), "*") if actions else None
    kw: Dict[str, Any] = {"inline": {"p": W.policy(stmt)}} if stmt else {}
    if path.id in ("iam-005", "iam-009"):                       # PutRolePolicy / AttachRolePolicy on itself
        return w.iam.role(ATTACKER, W.trusts_account(), **kw)
    if path.id in ("iam-010", "iam-011"):                       # Attach/PutGroupPolicy on its own group
        w.iam.group("demo-attacker-group")
        kw["groups"] = ["demo-attacker-group"]
    if path.id == "iam-001":                                    # a customer-managed policy attached to itself
        kw["attached"] = [w.customer_policy("demo-attacker-policy", W.allow("s3:ListAllMyBuckets"))]
    return w.iam.user(ATTACKER, **kw)


def _principal_target(w: Any, path: PF.PathDef) -> None:
    """Targets of the self-escalation and principal-access paths."""
    pid = path.id
    low = W.allow("s3:ListAllMyBuckets")
    if pid in ("iam-002", "iam-003", "iam-004", "iam-006"):
        w.admin_user("demo-victim", access_keys=2 if pid == "iam-003" else 0, login=pid == "iam-006")
    elif pid == "iam-012":
        w.admin_role(ADMIN_ROLE, W.trusts_service("ec2.amazonaws.com"))
    elif pid == "sts-001":
        w.admin_role(ADMIN_ROLE, W.trusts_account())
    elif pid == "iam-013":
        w.iam.group("demo-admins", attached=[W.ADMIN_POLICY])
    elif pid in ("iam-014", "iam-016", "iam-017"):
        attached = [w.customer_policy("demo-low-policy", low)] if pid == "iam-016" else []
        w.iam.role("demo-low", W.trusts_account(), attached=attached, inline={} if attached else {"p": W.policy(low)})
    elif pid in ("iam-015", "iam-018"):
        w.iam.user("demo-low-user", inline={"p": W.policy(low)})
    elif pid in ("iam-019", "iam-020", "iam-021"):
        attached = [w.customer_policy("demo-low-policy", low)] if pid == "iam-020" else []
        w.iam.role("demo-low", W.trusts_service("ec2.amazonaws.com"), attached=attached,
                   inline={} if attached else {"p": W.policy(low)})


def build_world(root: Path, path: PF.PathDef, actions: Sequence[str]) -> Tuple[Any, str]:
    """The synthetic report for ``path`` with the attacker holding ``actions``; returns (world, attacker ARN)."""
    w = W.World(root)
    attacker = _attacker(w, path, actions)
    if path.id in UNCOLLECTED:
        pass                                                     # nothing the tool could see
    elif path.id in EXISTING:
        _plant(w, EXISTING[path.id])
    elif path.category == "new-passrole":
        services = SERVICE_OVERRIDES.get(path.id) or path.trusted_services
        if path.id == "cognitoidentity-001":
            trust = W.rb.trust({"Federated": "cognito-identity.amazonaws.com"},
                               action="sts:AssumeRoleWithWebIdentity")
        else:
            trust = W.trusts_service(*services)
        w.admin_role(ADMIN_ROLE, trust)
        if "ec2.amazonaws.com" in services:                      # handed to instances as an instance profile
            _instance_profile(w)
    else:
        _principal_target(w, path)
    return w, attacker


# ── evaluation ───────────────────────────────────────────────────────────────

@dataclass
class Verdict:
    covered: bool
    by: List[str] = field(default_factory=list)      # "finding:<rule id>" and/or "path:<edge types>"


def judge(out: Any, attacker: str, rule_ids: Iterable[str]) -> Verdict:
    rule_ids = set(rule_ids)
    by = sorted(f"finding:{f['id']}" for f in out.graph["findings"]
                if f["id"] in rule_ids and f["severity"] == "CRITICAL" and f.get("status") == "open"
                and (f["node_id"] == attacker or attacker in (f.get("affected_members") or ())))
    p = out.path(attacker)
    if p is not None:
        by.append("path:" + ">".join(p.edge_types))
    return Verdict(bool(by), by)


def analyse(path: PF.PathDef, actions: Sequence[str], rule_ids: Sequence[str]) -> Verdict:
    with tempfile.TemporaryDirectory(prefix="pf-") as tmp:
        w, attacker = build_world(Path(tmp), path, actions)
        return judge(w.analyze(), attacker, rule_ids)


#: Required permissions that only discover targets; removing one does not stop the technique (twins skipped).
RECON = frozenset({"ec2:describeinstances", "ecs:describetasks", "codedeploy:getdeploymentconfig",
                   "bedrock-agentcore:getagentruntime", "bedrock-agentcore:getharness"})


def twin_skip_reason(removed: str) -> Optional[str]:
    return "reconnaissance permission" if removed.lower() in RECON else None


def twin_justification(path: PF.PathDef, removed: str, paths: Sequence[PF.PathDef]) -> Optional[str]:
    """Why a fired twin is still right: the remaining permissions complete another catalogued path."""
    rest = path.required_lower - {removed.lower()}
    others = sorted(o.id for o in paths if o.id != path.id and o.required_lower <= rest)
    return f"remaining permissions complete {', '.join(others)}" if others else None


def run(paths: Optional[Sequence[PF.PathDef]] = None, *, twins: bool = True) -> Dict[str, Any]:
    """Run the benchmark; returns the ``coverage.json`` document."""
    logging.disable(logging.WARNING)
    try:
        return _run(paths or PF.load_paths(), twins=twins)
    finally:
        logging.disable(logging.NOTSET)


def _run(paths: Sequence[PF.PathDef], *, twins: bool) -> Dict[str, Any]:
    cmap = PF.coverage_map(paths, PF.catalogue_rules())["by_path"]
    per_path: Dict[str, Any] = {}
    twin_total = twin_fired = twin_justified = 0
    for path in paths:
        rules = cmap.get(path.id, [])
        verdict = analyse(path, path.required, rules)
        entry: Dict[str, Any] = {"category": path.category, "rules": rules, "covered": verdict.covered,
                                 "by": verdict.by}
        if path.id in UNCOLLECTED:
            entry["note"] = f"{UNCOLLECTED[path.id]} are not collected"
        if twins:
            entry["twins"] = {}
            for removed in path.required:
                reason = twin_skip_reason(removed)
                if reason:
                    entry["twins"][removed] = {"skipped": reason}
                    continue
                tv = analyse(path, [a for a in path.required if a != removed], rules)
                twin: Dict[str, Any] = {"fired": tv.covered, "by": tv.by}
                why = twin_justification(path, removed, paths) if tv.covered else None
                if why:
                    twin["justified"] = why
                entry["twins"][removed] = twin
                twin_total += 1
                twin_fired += int(tv.covered and not why)
                twin_justified += int(bool(why))
        per_path[path.id] = entry
    covered = sorted(pid for pid, e in per_path.items() if e["covered"])
    by_cat: Dict[str, List[int]] = {}
    for e in per_path.values():
        by_cat.setdefault(e["category"], [0, 0])
        by_cat[e["category"]][0] += int(e["covered"])
        by_cat[e["category"]][1] += 1
    return {
        "dataset": {k: v for k, v in PF.read_pin().items() if k in ("repository", "commit", "commit_date")},
        "total": len(paths), "covered_count": len(covered), "covered": covered,
        "not_covered": sorted(set(per_path) - set(covered)),
        "by_category": {k: f"{c}/{t}" for k, (c, t) in sorted(by_cat.items())},
        "twins": {"evaluated": twin_total, "fired": twin_fired, "fired_justified": twin_justified,
                  "precision": round(1 - twin_fired / twin_total, 4) if twin_total else None},
        "baseline_d13c215": {"rule_fires": 40, "rule_or_edge": 55},
        "paths": per_path,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="pathfinding.cloud coverage benchmark")
    parser.add_argument("--write", action="store_true", help=f"write {COVERAGE_FILE.name}")
    args = parser.parse_args(argv)
    doc = run()
    text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    if args.write:
        COVERAGE_FILE.write_text(text, encoding="utf-8")
    sys.stdout.write(json.dumps({k: doc[k] for k in ("covered_count", "total", "by_category", "twins")}) + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - development tool
    raise SystemExit(main())
