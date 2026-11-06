"""Least-privilege permission documents and the pre-flight access check (F-151, F-161; cli.md §3.4, §3.5).

**Generator** (``aws-enumerator permissions``, offline): builds an IAM policy, Kubernetes RBAC or a Markdown
page from the selected registry specs and the active flags:

* ``AwsEnumeratorTier1``: the ``SPEC.actions`` of tier-1 modules and the runner's own region discovery
  (``ec2:DescribeRegions``), ``Resource: "*"``;
* ``AwsEnumeratorApiGatewayRead``: ``apigateway:GET`` on partition-aware API Gateway ARNs only (a blanket
  ``apigateway:GET`` on ``*`` would also read API key values);
* ``AwsEnumeratorTier2SecretBearingConfig``: tier-2 modules (APIs that return secret-bearing configuration);
  omitted with ``--max-tier 1``;
* ``AwsEnumeratorOptional``: ``SPEC.optional_actions`` (fallbacks, opt-in flags, expected denials) and the
  ``preflight --mode simulate`` actions, only with ``--include-optional``;
* ``AwsEnumeratorDenyDataPlane`` (``--guardrail``): an explicit Deny on data-plane reads, so a policy edited by
  mistake can never read object contents, secret values or messages.

Every module's actions come from its own ``SPEC.actions``; there is no other inventory. A module that makes no
AWS call (``k8s``: the EKS token is presigned locally, access is Kubernetes RBAC) declares none and adds no action.

**Pre-flight** (``aws-enumerator preflight``, ``collect --preflight``): ``probe`` makes one cheap read per
selected module (``SPEC.probe``, else :data:`DEFAULT_PROBES`); ``simulate`` asks
``iam:SimulatePrincipalPolicy`` about every action of the selected modules. Probes are real API calls and
appear in CloudTrail.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import botocore.exceptions
from botocore import xform_name

from aws_enumerator.coverage import classify
from aws_enumerator.iam_actions import APIGATEWAY_READ, iam_action_for

__all__ = [
    "DEFAULT_PROBES", "GUARDRAIL_DENY", "RUNNER_ACTIONS", "SIMULATE_ACTIONS", "PolicyOptions", "PreflightError",
    "PreflightResult", "build_iam_policy",
    "build_k8s_rbac", "module_actions", "preflight_block", "preflight_exit_code", "render_markdown",
    "render_preflight", "run_probe", "run_simulate",
]

log = logging.getLogger("aws_enumerator.permissions")

#: API Gateway resources the collectors read (``apigateway:GET`` is scoped to these).
APIGATEWAY_RESOURCES = (
    "arn:{partition}:apigateway:*::/restapis", "arn:{partition}:apigateway:*::/restapis/*",
    "arn:{partition}:apigateway:*::/apis", "arn:{partition}:apigateway:*::/apis/*",
)

#: Data-plane reads the tool never needs (``--guardrail``): object contents, secret values, messages, logs.
GUARDRAIL_DENY = (
    "dynamodb:BatchGetItem", "dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan",
    "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "kms:Decrypt", "lambda:GetFunction", "lambda:InvokeFunction",
    "logs:FilterLogEvents", "logs:GetLogEvents", "s3:GetObject", "s3:GetObjectVersion",
    "secretsmanager:GetSecretValue", "sqs:ReceiveMessage", "ssm:GetParameter", "ssm:GetParameterHistory",
    "ssm:GetParameters", "ssm:GetParametersByPath",
)

#: Calls the runner itself makes: region discovery for ``--all`` (``sts:GetCallerIdentity`` needs no permission).
RUNNER_ACTIONS = ("ec2:DescribeRegions",)
#: Only ``preflight --mode simulate`` needs these (resolve the role path, then simulate).
SIMULATE_ACTIONS = ("iam:GetRole", "iam:SimulatePrincipalPolicy")

#: Cheap pre-flight call per module when ``SPEC.probe`` is not set: (service, Operation, params).
DEFAULT_PROBES: Dict[str, Tuple[str, str, Tuple[Tuple[str, Any], ...]]] = {
    "iam": ("iam", "ListUsers", (("MaxItems", 1),)),
    "organizations": ("organizations", "DescribeOrganization", ()),
    "s3": ("s3", "ListBuckets", ()),
    "cloudfront": ("cloudfront", "ListDistributions", (("MaxItems", "1"),)),
    "waf_cloudfront": ("wafv2", "ListWebACLs", (("Scope", "CLOUDFRONT"), ("Limit", 1))),
    "route53": ("route53", "ListHostedZones", (("MaxItems", "1"),)),
    "vpc": ("ec2", "DescribeVpcs", (("MaxResults", 5),)),
    "sg": ("ec2", "DescribeSecurityGroups", (("MaxResults", 5),)),
    "ec2": ("ec2", "DescribeInstances", (("MaxResults", 5),)),
    "cloudtrail": ("cloudtrail", "DescribeTrails", ()),
    "flowlogs": ("ec2", "DescribeFlowLogs", (("MaxResults", 5),)),
    "waf": ("wafv2", "ListWebACLs", (("Scope", "REGIONAL"), ("Limit", 1))),
    "eks": ("eks", "ListClusters", (("maxResults", 1),)),
    # the Kubernetes API itself cannot be probed through AWS; k8s needs the EKS cluster list first
    "k8s": ("eks", "ListClusters", (("maxResults", 1),)),
    "secretsmanager": ("secretsmanager", "ListSecrets", (("MaxResults", 1),)),
    "ssm": ("ssm", "DescribeParameters", (("MaxResults", 1),)),
    "lambda": ("lambda", "ListFunctions", (("MaxItems", 1),)),
    "kms": ("kms", "ListKeys", (("Limit", 1),)),
    "ecs": ("ecs", "ListTaskDefinitions", (("maxResults", 1),)),
    "cloudformation": ("cloudformation", "DescribeStacks", ()),
    "glue": ("glue", "GetJobs", (("MaxResults", 1),)),
    "codebuild": ("codebuild", "ListProjects", ()),
    "sagemaker": ("sagemaker", "ListNotebookInstances", (("MaxResults", 1),)),
    "sns": ("sns", "ListTopics", ()),
    "sqs": ("sqs", "ListQueues", (("MaxResults", 1),)),
    "ecr": ("ecr", "DescribeRepositories", (("maxResults", 1),)),
    "rds": ("rds", "DescribeDBInstances", (("MaxRecords", 20),)),
    "dynamodb": ("dynamodb", "ListTables", (("Limit", 1),)),
    "apigateway": ("apigateway", "GetRestApis", (("limit", 1),)),
    "cognito": ("cognito-idp", "ListUserPools", (("MaxResults", 1),)),
    "ebs": ("ec2", "DescribeSnapshots", (("OwnerIds", ["self"]), ("MaxResults", 5))),
    "elb": ("elbv2", "DescribeLoadBalancers", (("PageSize", 1),)),
    "guardduty": ("guardduty", "ListDetectors", (("MaxResults", 1),)),
    "securityhub": ("securityhub", "DescribeHub", ()),
    "config": ("config", "DescribeConfigurationRecorders", ()),
    "accessanalyzer": ("accessanalyzer", "ListAnalyzers", (("maxResults", 1),)),
}

#: Kubernetes RBAC used when no spec declares ``k8s_rbac``: (apiGroup, resource, verbs, resourceNames).
DEFAULT_K8S_RBAC: Tuple[Tuple[str, str, Tuple[str, ...], Tuple[str, ...]], ...] = (
    ("", "namespaces", ("get", "list"), ()), ("", "pods", ("get", "list"), ()),
    ("", "serviceaccounts", ("get", "list"), ()), ("", "services", ("get", "list"), ()),
    ("", "nodes", ("get", "list"), ()),
    ("rbac.authorization.k8s.io", "roles", ("get", "list"), ()),
    ("rbac.authorization.k8s.io", "rolebindings", ("get", "list"), ()),
    ("rbac.authorization.k8s.io", "clusterroles", ("get", "list"), ()),
    ("rbac.authorization.k8s.io", "clusterrolebindings", ("get", "list"), ()),
    ("networking.k8s.io", "ingresses", ("get", "list"), ()),
    ("authorization.k8s.io", "selfsubjectrulesreviews", ("create",), ()),
)
K8S_GROUP = "aws-enumerator-readers"


class PreflightError(Exception):
    """The pre-flight could not run at all (credentials): exit 1."""


@dataclass(frozen=True)
class PolicyOptions:
    partition: str = "aws"
    max_tier: int = 2
    include_optional: bool = False
    guardrail: bool = False
    k8s_secrets: bool = False


# ── generator ────────────────────────────────────────────────────────────────
def module_actions(spec: Any) -> Tuple[List[str], str]:
    """``(actions, source)``: the spec's declared actions, sorted and de-duplicated; ``source`` is always ``"spec"``.

    The d13c215 inventory fallback (``"baseline"``) was removed in 0.3.0: every module that makes AWS calls
    declares ``SPEC.actions``, so it only ever fired for ``k8s`` and wrongly attributed ``eks:DescribeCluster``
    to it.
    """
    return sorted(set(spec.actions)), "spec"


def _scoped_resources(specs: Sequence[Any], partition: str) -> Dict[str, List[str]]:
    out: Dict[str, set] = {}
    for spec in specs:
        scoped = tuple(spec.resource_scoped)
        if not scoped and APIGATEWAY_READ in module_actions(spec)[0]:
            scoped = ((APIGATEWAY_READ, APIGATEWAY_RESOURCES),)
        for action, templates in scoped:
            out.setdefault(action, set()).update(t.format(partition=partition) for t in templates)
    return {a: sorted(r) for a, r in sorted(out.items())}


def build_iam_policy(specs: Sequence[Any], opts: PolicyOptions) -> Dict[str, Any]:
    """The IAM policy document for ``specs`` (already filtered by ``registry.select``)."""
    scoped = _scoped_resources(specs, opts.partition)
    tier1: set = set()
    tier2: set = set()
    optional: set = set()
    for spec in specs:
        actions = [a for a in module_actions(spec)[0] if a not in scoped]
        (tier1 if spec.tier == 1 else tier2).update(actions)
        optional.update(a for a in spec.optional_actions if a not in scoped)
    tier1.update(RUNNER_ACTIONS)
    optional.update(SIMULATE_ACTIONS)
    tier2 -= tier1
    optional -= tier1 | tier2
    statements: List[Dict[str, Any]] = []
    if tier1:
        statements.append({"Sid": "AwsEnumeratorTier1", "Effect": "Allow", "Action": sorted(tier1), "Resource": "*"})
    for action, resources in scoped.items():
        sid = "AwsEnumeratorApiGatewayRead" if action == APIGATEWAY_READ else _sid(action)
        statements.append({"Sid": sid, "Effect": "Allow", "Action": [action], "Resource": resources})
    if tier2 and opts.max_tier >= 2:
        statements.append({"Sid": "AwsEnumeratorTier2SecretBearingConfig", "Effect": "Allow",
                           "Action": sorted(tier2), "Resource": "*"})
    if optional and opts.include_optional:
        statements.append({"Sid": "AwsEnumeratorOptional", "Effect": "Allow", "Action": sorted(optional),
                           "Resource": "*"})
    if opts.guardrail:
        statements.append({"Sid": "AwsEnumeratorDenyDataPlane", "Effect": "Deny", "Action": list(GUARDRAIL_DENY),
                           "Resource": "*"})
    return {"Version": "2012-10-17", "Statement": statements}


def _sid(action: str) -> str:
    return "AwsEnumeratorScoped" + "".join(ch for ch in action.title() if ch.isalnum())


def policy_allows(policy: Mapping[str, Any], action: str) -> bool:
    """Whether an Allow statement of ``policy`` names ``action`` (exact match; the generator emits no wildcards)."""
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") == "Allow" and action in stmt.get("Action", []):
            return True
    return False


def _rbac_rules(specs: Sequence[Any], opts: PolicyOptions) -> List[Dict[str, Any]]:
    declared = [rule for spec in specs for rule in spec.k8s_rbac]
    rules = list(declared or DEFAULT_K8S_RBAC)
    if opts.k8s_secrets:
        rules.append(("", "secrets", ("list",), ()))
    grouped: Dict[Tuple[str, Tuple[str, ...], Tuple[str, ...]], List[str]] = {}
    for group, resource, verbs, names in rules:
        key = (group, tuple(sorted(verbs)), tuple(names))
        grouped.setdefault(key, []).append(resource)
    out = []
    for (group, verbs, names), resources in sorted(grouped.items()):
        if names:
            continue  # resource-named rules (aws-auth) go into the kube-system Role
        out.append({"apiGroups": [group], "resources": sorted(set(resources)), "verbs": list(verbs)})
    return out


def _yaml_list(values: Iterable[str]) -> str:
    return "[" + ", ".join(json.dumps(v) for v in values) + "]"


def build_k8s_rbac(specs: Sequence[Any], opts: PolicyOptions) -> str:
    """ClusterRole + kube-system Role for ``aws-auth`` + bindings to group ``aws-enumerator-readers``."""
    lines = ["# aws-enumerator read-only Kubernetes access (aws-enumerator permissions --format k8s)",
             "apiVersion: rbac.authorization.k8s.io/v1", "kind: ClusterRole",
             "metadata:", "  name: aws-enumerator-read", "rules:"]
    for rule in _rbac_rules(specs, opts):
        lines += [f"  - apiGroups: {_yaml_list(rule['apiGroups'])}", f"    resources: {_yaml_list(rule['resources'])}",
                  f"    verbs: {_yaml_list(rule['verbs'])}"]
    if opts.k8s_secrets:
        lines.append("# --k8s-secrets: the tool asks for Secret metadata only, but 'list secrets' RBAC still "
                     "lets this identity read every Secret value.")
    lines += ["---", "apiVersion: rbac.authorization.k8s.io/v1", "kind: Role", "metadata:",
              "  name: aws-enumerator-aws-auth", "  namespace: kube-system", "rules:",
              '  - apiGroups: [""]', '    resources: ["configmaps"]', '    resourceNames: ["aws-auth"]',
              '    verbs: ["get"]']
    for kind, name, ns in (("ClusterRoleBinding", "aws-enumerator-read", None),
                           ("RoleBinding", "aws-enumerator-aws-auth", "kube-system")):
        role_kind = "ClusterRole" if kind == "ClusterRoleBinding" else "Role"
        lines += ["---", "apiVersion: rbac.authorization.k8s.io/v1", f"kind: {kind}", "metadata:", f"  name: {name}"]
        if ns:
            lines.append(f"  namespace: {ns}")
        lines += ["roleRef:", "  apiGroup: rbac.authorization.k8s.io", f"  kind: {role_kind}", f"  name: {name}",
                  "subjects:", "  - apiGroup: rbac.authorization.k8s.io", "    kind: Group", f"    name: {K8S_GROUP}"]
    lines += ["# EKS access entry for the scanning role (example):",
              f"#   aws eks create-access-entry --cluster-name <cluster> --principal-arn <role-arn> "
              f"--kubernetes-groups {K8S_GROUP}"]
    return "\n".join(lines) + "\n"


def render_markdown(specs: Sequence[Any], opts: PolicyOptions) -> str:
    """The body of ``docs/permissions.md`` (regenerated by ``permissions --format markdown``)."""
    policy = build_iam_policy(specs, opts)
    rows = ["| Module | Scope | Tier | Source | Actions |", "|---|---|---|---|---|"]
    for spec in specs:
        actions, source = module_actions(spec)
        rows.append(f"| `{spec.name}` | {spec.scope} | {spec.tier} | {source} | "
                    f"{', '.join(f'`{a}`' for a in actions) or '—'} |")
    parts = [
        "# Permissions", "",
        "Generated by `aws-enumerator permissions --format markdown`. The tool only calls List, Describe and "
        "Get APIs (plus `iam:GenerateCredentialReport` and the Kubernetes `SelfSubjectRulesReview`).", "",
        "## IAM policy", "", "```json", json.dumps(policy, indent=2), "```", "",
        "## Kubernetes RBAC", "", "```yaml", build_k8s_rbac(specs, opts).rstrip("\n"), "```", "",
        "## Actions per module", "", *rows, "",
    ]
    return "\n".join(parts)


# ── pre-flight ───────────────────────────────────────────────────────────────
@dataclass
class PreflightResult:
    module: str
    actions: List[str]
    result: str
    error_code: Optional[str] = None

    def to_json(self) -> Dict[str, Any]:
        return {"module": self.module, "actions": list(self.actions), "result": self.result,
                "error_code": self.error_code}


def probe_for(spec: Any) -> Optional[Tuple[str, str, Dict[str, Any]]]:
    probe = spec.probe or DEFAULT_PROBES.get(spec.name)
    if not probe:
        return None
    service, operation, params = probe
    return service, operation, dict(params)


_PROBE_RESULT = {"ok": "ok", "denied": "denied", "skipped": "skipped", "throttled": "error", "error": "error"}


def _probe_one(aws: Any, spec: Any, region: str) -> PreflightResult:
    actions = module_actions(spec)[0]
    probe = probe_for(spec)
    if probe is None:
        return PreflightResult(spec.name, actions, "skipped", "no-probe")
    service, operation, params = probe
    api = f"{service}:{operation}"
    try:
        getattr(aws.client(service, region), xform_name(operation))(**params)
        return PreflightResult(spec.name, [iam_action_for(api) or api], "ok", None)
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
        status, code, fatal = classify(exc, api)
        if fatal:
            raise PreflightError(f"{api} failed ({code}): credentials expired or invalid") from None
        return PreflightResult(spec.name, [iam_action_for(api) or api], _PROBE_RESULT[status], code)


def run_probe(aws: Any, specs: Sequence[Any], *, home_region: str, global_region: str) -> List[PreflightResult]:
    """One probe call per module, in the global region for global modules and the home region otherwise."""
    return [_probe_one(aws, spec, global_region if spec.scope == "global" else home_region) for spec in specs]


def _simulation_arn(aws: Any, identity: Any, region: str) -> str:
    if identity.principal_type == "assumed-role" and identity.principal_arn:
        name = identity.principal_arn.rsplit("/", 1)[-1]
        role = aws.client("iam", region).get_role(RoleName=name)
        return str(role["Role"]["Arn"])
    if identity.principal_type == "user" and identity.principal_arn:
        return identity.principal_arn
    raise PreflightError(f"simulate mode cannot simulate a {identity.principal_type} principal; use --mode probe")


def _simulate_actions(aws: Any, source_arn: str, actions: Sequence[str], region: str) -> Dict[str, str]:
    decisions: Dict[str, str] = {}
    client = aws.client("iam", region)
    for start in range(0, len(actions), 50):
        batch = list(actions[start:start + 50])
        kwargs: Dict[str, Any] = {"PolicySourceArn": source_arn, "ActionNames": batch}
        while True:
            resp = client.simulate_principal_policy(**kwargs)
            for item in resp.get("EvaluationResults", []):
                decisions[item["EvalActionName"]] = str(item.get("EvalDecision", "implicitDeny"))
            if not resp.get("IsTruncated"):
                break
            kwargs["Marker"] = resp["Marker"]
    return decisions


_DECISION = {"allowed": "allowed", "explicitDeny": "explicit_deny", "implicitDeny": "implicit_deny"}


def run_simulate(aws: Any, identity: Any, specs: Sequence[Any], *, global_region: str) -> List[PreflightResult]:
    """``iam:SimulatePrincipalPolicy`` over every action of ``specs`` (explicit deny wins per module)."""
    per_module = {spec.name: module_actions(spec)[0] for spec in specs}
    every = sorted({a for actions in per_module.values() for a in actions})
    try:
        source = _simulation_arn(aws, identity, global_region)
        decisions = _simulate_actions(aws, source, every, global_region)
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
        status, code, fatal = classify(exc, "iam:SimulatePrincipalPolicy")
        if fatal:
            raise PreflightError(f"iam:SimulatePrincipalPolicy failed ({code})") from None
        return [PreflightResult(name, actions, "error", code) for name, actions in per_module.items()]
    results = []
    for name, actions in per_module.items():
        found = {_DECISION.get(decisions.get(a, "implicitDeny"), "implicit_deny") for a in actions}
        result = ("explicit_deny" if "explicit_deny" in found else
                  "implicit_deny" if "implicit_deny" in found else "allowed")
        results.append(PreflightResult(name, actions, result, None))
    return results


def preflight_block(mode: str, results: Sequence[PreflightResult], ran_at: str) -> Dict[str, Any]:
    """``manifest.preflight`` (manifest.md §3.6)."""
    return {"mode": mode, "ran_at": ran_at, "results": [r.to_json() for r in results]}


def preflight_exit_code(results: Sequence[PreflightResult]) -> int:
    """0 when every module is ok/allowed/skipped, else 2 (cli.md §3.4)."""
    return 0 if all(r.result in ("ok", "allowed", "skipped") for r in results) else 2


def render_preflight(results: Sequence[PreflightResult], fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps([r.to_json() for r in results], indent=2)
    width = max([len("module")] + [len(r.module) for r in results])
    lines = [f"{'module':<{width}}  {'result':<13}  error_code  actions"]
    for r in results:
        lines.append(f"{r.module:<{width}}  {r.result:<13}  {(r.error_code or '-'):<10}  {', '.join(r.actions)}")
    return "\n".join(lines)
