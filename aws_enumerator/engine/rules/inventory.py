"""Existing-resource inventory for the rules runner (engine.md §3.1 ``existing:<type>``; F-011, F-069, F-113).

An *existing-resource* rule takes over a resource that already runs as a role (update a function's code, start a
build with a buildspec override, open a shell on an instance, run a command in an ECS task …). The rule's
``$target`` steps are evaluated against each collected resource's ARN, and the rule's tier comes from the role the
resource runs as (:attr:`ExistingResource.role_arn`).

:data:`EXISTING_TYPES` lists every resource type a rule may select. Two kinds exist:

* **collected** types (``collected=True``): an aws-enumerator collector lists them, so the inventory is the truth.
  When the loader data holds no resource of the type, the rule does not fire ("nothing collected, nothing
  claimed");
* **uncollected** types (``collected=False``: App Runner services, Batch job definitions, Bedrock AgentCore
  resources, CodeDeploy deployment groups, Step Functions state machines). No collector lists them, so the rule
  runs against a *probe* target that stands for "any such resource" and the finding is conditional, with the
  gap ``<type>:not-collected`` and a low severity: whether one of them runs as a privileged role is unknown.

:func:`existing_from_data` reads the loader outputs (``ctx.data``) in both collector layouts (d13c215 and the
Wave 1 collectors, whose unknown values are ``null``); records with an unknown role are skipped, never guessed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set

PROBE_NAME = "~any~"          # never a valid IAM or resource name


@dataclass(frozen=True)
class ExistingType:
    """One resource type existing-resource rules can select."""

    name: str
    node_type: Optional[str]        # graph node type, or None when the graph has no node for it
    template: str                   # ARN template with {partition} / {account}
    collected: bool
    label: str

    def probe_arn(self, *, partition: str, account: Optional[str]) -> str:
        """An ARN standing for "any resource of this type" (matches only wildcard grants)."""
        return expand(self.template, partition=partition, account=account).rstrip("*") + PROBE_NAME


def expand(template: str, *, partition: str, account: Optional[str]) -> str:
    """Fill ``{partition}`` and ``{account}`` (an unknown account becomes ``*``)."""
    return template.replace("{partition}", partition).replace("{account}", account or "*")


def _t(name: str, node_type: Optional[str], template: str, collected: bool, label: str) -> ExistingType:
    return ExistingType(name, node_type, template, collected, label)


#: Every resource type an ``existing`` selector may name (``target.resource_type`` in ``privesc.json``).
EXISTING_TYPES: Mapping[str, ExistingType] = {t.name: t for t in (
    _t("lambda_function", "lambda", "arn:{partition}:lambda:*:{account}:function:*", True, "Lambda function"),
    _t("glue_dev_endpoint", "gluedevendpoint", "arn:{partition}:glue:*:{account}:devEndpoint/*", True,
       "Glue development endpoint"),
    _t("codebuild_project", "codebuild", "arn:{partition}:codebuild:*:{account}:project/*", True,
       "CodeBuild project"),
    _t("cfn_stack", "cfnstack", "arn:{partition}:cloudformation:*:{account}:stack/*", True, "CloudFormation stack"),
    _t("cfn_stack_set", "stackset", "arn:{partition}:cloudformation:*:{account}:stackset/*", True,
       "CloudFormation StackSet"),
    _t("sagemaker_notebook", "sagemaker", "arn:{partition}:sagemaker:*:{account}:notebook-instance/*", True,
       "SageMaker notebook instance"),
    _t("sagemaker_user_profile", "sagemakerdomain", "arn:{partition}:sagemaker:*:{account}:user-profile/*", True,
       "SageMaker Studio user profile"),
    _t("ecs_exec_service", "ecsservice", "arn:{partition}:ecs:*:{account}:service/*", True,
       "ECS service with ECS Exec enabled"),
    _t("ec2_instance", "instance", "arn:{partition}:ec2:*:{account}:instance/*", True,
       "EC2 instance with an instance profile"),
    _t("ec2_launch_template", "launchtemplate", "arn:{partition}:ec2:*:{account}:launch-template/*", True,
       "EC2 launch template with an instance profile"),
    _t("apprunner_service", None, "arn:{partition}:apprunner:*:{account}:service/*", False, "App Runner service"),
    _t("batch_job_definition", None, "arn:{partition}:batch:*:{account}:job-definition/*", False,
       "AWS Batch job definition"),
    _t("bedrock_code_interpreter", None, "arn:{partition}:bedrock-agentcore:*:{account}:code-interpreter-custom/*",
       False, "Bedrock AgentCore code interpreter"),
    _t("bedrock_agent_runtime", None, "arn:{partition}:bedrock-agentcore:*:{account}:runtime/*", False,
       "Bedrock AgentCore runtime"),
    _t("bedrock_browser", None, "arn:{partition}:bedrock-agentcore:*:{account}:browser-custom/*", False,
       "Bedrock AgentCore browser"),
    _t("codedeploy_deployment_group", None, "arn:{partition}:codedeploy:*:{account}:deploymentgroup:*", False,
       "CodeDeploy deployment group"),
    _t("sfn_state_machine", None, "arn:{partition}:states:*:{account}:stateMachine:*", False,
       "Step Functions state machine"),
)}


@dataclass(frozen=True)
class ExistingResource:
    """A collected compute resource an existing-resource rule can take over."""

    resource_type: str
    arn: str
    role_arn: Optional[str]
    name: str = ""


# ── reading the loader outputs ───────────────────────────────────────────────

def _domain(data: Mapping[str, Any], name: str) -> Any:
    value = data.get(name)
    return getattr(value, "data", value)


def _units(domain: Any, key: str) -> List[List[Mapping[str, Any]]]:
    """``domain[key][unit]`` record lists in unit order (loader shape ``{key: {unit: [record]}}``)."""
    table = domain.get(key) if isinstance(domain, Mapping) else None
    if not isinstance(table, Mapping):
        return []
    return [[r for r in table[u] if isinstance(r, Mapping)] for u in sorted(table) if isinstance(table[u], list)]


def _records(domain: Any, key: str) -> Iterable[Mapping[str, Any]]:
    for records in _units(domain, key):
        yield from records


def _unqualified(arn: str) -> str:
    parts = arn.split(":")
    return ":".join(parts[:7]) if len(parts) > 7 and parts[5] == "function" else arn


def _first_role(rec: Mapping[str, Any]) -> Optional[str]:
    roles = rec.get("Roles")
    if isinstance(roles, list):
        named = sorted(r for r in roles if isinstance(r, str) and r.startswith("arn:"))
        return named[0] if named else None
    role = rec.get("Role") or rec.get("RoleArn")
    return role if isinstance(role, str) and role.startswith("arn:") else None


def _arn(rec: Mapping[str, Any]) -> Optional[str]:
    arn = rec.get("Arn")
    return arn if isinstance(arn, str) and arn.startswith("arn:") else None


def _lambda(data: Mapping[str, Any]) -> List[ExistingResource]:
    out = []
    for rec in _records(_domain(data, "lambda"), "functions"):
        arn, role = rec.get("FunctionArn"), rec.get("Role")
        if isinstance(arn, str) and arn.startswith("arn:"):
            out.append(ExistingResource("lambda_function", _unqualified(arn),
                                        role if isinstance(role, str) and role.startswith("arn:") else None,
                                        str(rec.get("FunctionName") or "")))
    return out


def _is_dev_endpoint(rec: Mapping[str, Any]) -> bool:
    arn = rec.get("Arn")
    return (str(rec.get("Type", "")).lower() in ("gluedevendpoint", "devendpoint") or rec.get("Kind") == "dev_endpoint"
            or (isinstance(arn, str) and ":devEndpoint/" in arn))


def _compute_records(data: Mapping[str, Any], key: str, keep: Any, rtype: str) -> List[ExistingResource]:
    out = []
    for rec in _records(_domain(data, "compute"), key):
        arn, role = _arn(rec), _first_role(rec)
        if arn and keep(rec):
            out.append(ExistingResource(rtype, arn, role, str(rec.get("Name") or "")))
    return out


def _type_is(*names: str) -> Any:
    return lambda rec: str(rec.get("Type", "")).lower() in names


def _sso_domain_ids(data: Mapping[str, Any]) -> Set[str]:
    """SageMaker Studio domains with ``AuthMode: SSO`` (``CreatePresignedDomainUrl`` does not work there)."""
    return {str(r["DomainId"]) for r in _records(_domain(data, "compute"), "sagemaker")
            if _type_is("sagemakerdomain")(r) and r.get("Kind") == "domain" and r.get("DomainId")
            and str(r.get("AuthMode") or "").upper() == "SSO"}


def _enterable_profile(sso: Set[str]) -> Any:
    """A Studio user profile a presigned domain URL can enter: not of an SSO-auth domain (request e-compute-3)."""
    def keep(rec: Mapping[str, Any]) -> bool:
        return _type_is("sagemakerdomain")(rec) and rec.get("Kind") == "user_profile" \
            and str(rec.get("DomainId") or "") not in sso and str(rec.get("AuthMode") or "").upper() != "SSO"
    return keep


def _ecs_exec_services(data: Mapping[str, Any]) -> List[ExistingResource]:
    """ECS services with ECS Exec enabled, with the task role of their task definition (v2 collectors)."""
    comp = _domain(data, "compute")
    task_roles: Dict[str, Optional[str]] = {}
    for rec in _records(comp, "ecs"):
        role = rec.get("TaskRole") if isinstance(rec.get("TaskRole"), str) else _first_role(rec)
        for key in (rec.get("Arn"), rec.get("Family")):
            if isinstance(key, str):
                task_roles.setdefault(key, role)
    out = []
    for svc in _records(comp, "ecs_services"):
        arn = svc.get("ServiceArn") or svc.get("Arn")
        if svc.get("EnableExecuteCommand") is not True or not isinstance(arn, str):
            continue
        td = svc.get("TaskDefinition")
        family = td.rsplit("/", 1)[-1].split(":", 1)[0] if isinstance(td, str) else None
        role = task_roles.get(td) if isinstance(td, str) else None
        out.append(ExistingResource("ecs_exec_service", arn, role or task_roles.get(family or ""),
                                    str(svc.get("Name") or "")))
    return out


def instance_profile_roles(iam: Any) -> Dict[str, List[str]]:
    """Instance-profile ARN → role ARNs, from the IAM loader's ``instance_profiles``."""
    out: Dict[str, List[str]] = {}
    for prof in getattr(iam, "instance_profiles", None) or ():
        if not isinstance(prof, Mapping) or not isinstance(prof.get("Arn"), str):
            continue
        roles = [r.get("Arn") for r in prof.get("Roles") or () if isinstance(r, Mapping)]
        out[prof["Arn"]] = sorted(r for r in roles if isinstance(r, str))
    return out


def _instances(data: Mapping[str, Any], profiles: Mapping[str, Sequence[str]], *, partition: str,
               account: Optional[str]) -> List[ExistingResource]:
    out = []
    ec2 = _domain(data, "ec2")
    table = ec2.get("instances") if isinstance(ec2, Mapping) else None
    if not isinstance(table, Mapping):
        return out
    for unit in sorted(table):
        for rec in table[unit] if isinstance(table[unit], list) else ():
            if not isinstance(rec, Mapping) or str(rec.get("State", "running")).lower() in ("terminated",
                                                                                            "shutting-down"):
                continue
            iid, prof = rec.get("InstanceId"), (rec.get("IamInstanceProfile") or {}).get("Arn") \
                if isinstance(rec.get("IamInstanceProfile"), Mapping) else None
            roles = profiles.get(prof) if isinstance(prof, str) else None
            if not isinstance(iid, str) or not roles or not account:
                continue
            arn = f"arn:{partition}:ec2:{unit}:{account}:instance/{iid}"
            out.append(ExistingResource("ec2_instance", arn, roles[0], iid))
    return out


def _profile_roles(ref: Any, profiles: Mapping[str, Sequence[str]]) -> List[str]:
    """Roles of a launch template's ``IamInstanceProfile`` (``{Arn}`` or ``{Name}``)."""
    if not isinstance(ref, Mapping):
        return []
    arn, name = ref.get("Arn"), ref.get("Name")
    if isinstance(arn, str):
        return list(profiles.get(arn, ()))
    if isinstance(name, str):
        for parn in sorted(profiles):
            if parn.rsplit("/", 1)[-1] == name:
                return list(profiles[parn])
    return []


def _launch_templates(data: Mapping[str, Any], profiles: Mapping[str, Sequence[str]]) -> List[ExistingResource]:
    """Launch templates whose ``$Default`` or ``$Latest`` version names an instance profile (Wave 1 collectors)."""
    out = []
    for unit_records in _units(_domain(data, "ec2"), "launch_templates"):
        for rec in unit_records:
            arn, versions = _arn(rec), rec.get("Versions")
            if not arn or not isinstance(versions, list):
                continue
            roles = sorted({r for v in versions if isinstance(v, Mapping)
                            for r in _profile_roles(v.get("IamInstanceProfile"), profiles)})
            if roles:
                out.append(ExistingResource("ec2_launch_template", arn, roles[0],
                                            str(rec.get("LaunchTemplateName") or rec.get("LaunchTemplateId") or "")))
    return out


def existing_from_data(data: Mapping[str, Any], *, partition: str = "aws", account: Optional[str] = None,
                       iam: Any = None) -> Dict[str, List[ExistingResource]]:
    """Existing-resource inventory from the loader outputs (``ctx.data``), one list per collected type."""
    profiles = instance_profile_roles(iam if iam is not None else _domain(data, "iam"))
    out: Dict[str, List[ExistingResource]] = {
        "lambda_function": _lambda(data),
        "glue_dev_endpoint": _compute_records(data, "glue", _is_dev_endpoint, "glue_dev_endpoint"),
        "codebuild_project": _compute_records(data, "codebuild", _type_is("codebuild", "codebuildproject"),
                                              "codebuild_project"),
        "cfn_stack": _compute_records(data, "cloudformation", _type_is("cfnstack"), "cfn_stack"),
        "cfn_stack_set": _compute_records(data, "cloudformation", _type_is("stackset"), "cfn_stack_set"),
        "sagemaker_notebook": _compute_records(
            data, "sagemaker", lambda r: _type_is("sagemaker")(r) and r.get("Kind") in (None, "notebook"),
            "sagemaker_notebook"),
        "sagemaker_user_profile": _compute_records(data, "sagemaker", _enterable_profile(_sso_domain_ids(data)),
                                                   "sagemaker_user_profile"),
        "ecs_exec_service": _ecs_exec_services(data),
        "ec2_instance": _instances(data, profiles, partition=partition, account=account),
        "ec2_launch_template": _launch_templates(data, profiles),
    }
    return {k: sorted(v, key=lambda r: r.arn) for k, v in out.items()}


def access_key_counts(iam: Any) -> Dict[str, Optional[int]]:
    """User ARN → number of access keys (``None`` when unknown), for the two-key limit of CreateAccessKey."""
    out: Dict[str, Optional[int]] = {}
    for ent in (getattr(iam, "users", None) or {}).values():
        rec = getattr(ent, "record", None) or {}
        keys = rec.get("AccessKeys") if isinstance(rec, Mapping) else None
        out[ent.arn] = len(keys) if isinstance(keys, list) and "AccessKeysError" not in rec else None
    return out


def resource_label(resource_type: str) -> str:
    t = EXISTING_TYPES.get(resource_type)
    return t.label if t else resource_type


__all__ = [
    "EXISTING_TYPES", "ExistingResource", "ExistingType", "PROBE_NAME", "access_key_counts", "existing_from_data",
    "expand", "instance_profile_roles", "resource_label",
]
