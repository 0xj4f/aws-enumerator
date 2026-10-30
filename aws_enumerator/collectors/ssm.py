"""SSM: Parameter Store metadata, parameter resource policies, documents and their sharing, and
managed instances (never parameter values or document content).

Output (``<region>/ssm/``):

* ``parameters.json`` (list), sorted by ``ARN``::

    {Name, ARN, Type, KeyId, Tier, DataType, Version, LastModifiedDate, PolicyStatus, CollectionErrors?}

  ``LastModifiedUser`` (often an SSO e-mail), ``Description`` and ``Policies`` are kept only with
  ``--keep-sensitive-metadata`` (F-112). ``PolicyStatus`` is the resource-policy read: only
  Advanced-tier parameters can carry one, so Standard ones are ``absent`` without a call.
* ``parameter_policies/<slug(name)>-<sha256(ARN)[:12]>.json`` (dict): ``{ParameterArn, ParameterName,
  Policies: [{PolicyId, PolicyHash, Policy}]}`` for each parameter with a resource policy (F-114, F-116).
* ``parameters_shared_with_account.json`` (list): parameters other accounts share **with** this one
  (``DescribeParameters(Shared=True)``; an inbound signal), same projection without ``PolicyStatus``.
* ``documents.json`` (list), documents owned by the account, sorted by ``Name``::

    {Name, Arn, DocumentType, DocumentFormat, DocumentVersion, PlatformTypes, Public: bool|null,
     SharedAccounts: [...]|null, CollectionErrors?}

  ``Public`` means shared with ``all`` (anyone can run or read it, F-116).
* ``managed_instances.json`` (list): ``{InstanceId, PingStatus, ResourceType, PlatformType, PlatformName,
  PlatformVersion, AgentVersion, IsLatestVersion, LastPingDateTime, IamRole}`` (no IP addresses or host names).
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Tuple

from aws_enumerator.collectors._common import add_error, policy_doc
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="ssm", scope="regional", output_dir="ssm", services=("ssm",),
    tier=1, cost="low", noise="low", default=True, groups=("@data",),
    actions=("ssm:DescribeParameters", "ssm:GetResourcePolicies", "ssm:ListDocuments",
             "ssm:DescribeDocumentPermission", "ssm:DescribeInstanceInformation"),
    probe=("ssm", "DescribeParameters", (("MaxResults", 1),)),
    outputs=(("parameters.json", "list"), ("parameter_policies/*.json", "dict"),
             ("parameters_shared_with_account.json", "list"), ("documents.json", "list"),
             ("managed_instances.json", "list")),
    description="SSM parameter metadata and policies, documents and sharing, managed instances (never values)",
)

_API_POLICIES = "ssm:GetResourcePolicies"
_PARAM_FIELDS = ("Name", "ARN", "Type", "KeyId", "Tier", "DataType", "Version", "LastModifiedDate")
_SENSITIVE_FIELDS = ("LastModifiedUser", "Description", "Policies")
_INSTANCE_FIELDS = ("InstanceId", "PingStatus", "ResourceType", "PlatformType", "PlatformName", "PlatformVersion",
                    "AgentVersion", "IsLatestVersion", "LastPingDateTime", "IamRole")


def project_parameter(meta: Dict[str, Any], keep_sensitive: bool) -> Dict[str, Any]:
    """The stored projection of one ``ParameterMetadata`` (F-112)."""
    item = {k: meta.get(k) for k in _PARAM_FIELDS}
    if keep_sensitive:
        item.update({k: meta.get(k) for k in _SENSITIVE_FIELDS})
    item["PolicyStatus"] = None
    return item


def _write_policies(ctx: Any, item: Dict[str, Any], policies: List[Dict[str, Any]]) -> None:
    data = {"ParameterArn": item["ARN"], "ParameterName": item["Name"], "Policies": policies}
    try:
        ctx.out.write_item("parameter_policies", item["ARN"], data, hint=item["Name"])
    except OSError as exc:
        ctx.cov.item_error(item["ARN"], _API_POLICIES, "error", type(exc).__name__)
        item["PolicyStatus"] = "error"
        item.setdefault("CollectionErrors", []).append(
            {"api": _API_POLICIES, "status": "error", "error_code": type(exc).__name__})


def _parameter_policy(ctx: Any, ssm: Any, item: Dict[str, Any]) -> None:
    if item.get("Tier") != "Advanced" or not item.get("ARN"):
        item["PolicyStatus"] = "absent"   # only Advanced-tier parameters can have a resource policy
        return
    result = ctx.paginate(ssm, "get_resource_policies", "Policies", item=item["ARN"], ResourceArn=item["ARN"])
    if not result.ok:
        item["PolicyStatus"] = result.policy_status()
        add_error(item, result)
        return
    policies = [{"PolicyId": p.get("PolicyId"), "PolicyHash": p.get("PolicyHash"),
                 "Policy": policy_doc(p.get("Policy"))} for p in result.value]
    item["PolicyStatus"] = "present" if policies else "absent"
    if policies:
        _write_policies(ctx, item, policies)


def _parameters(ctx: Any, ssm: Any, keep_sensitive: bool, out: List[Dict[str, Any]], *, shared: bool) -> None:
    params = {"Shared": True} if shared else {}
    listed = ctx.paginate(ssm, "describe_parameters", "Parameters", page_size=50, primary=not shared, **params)
    out.extend(sorted((project_parameter(m, keep_sensitive) for m in listed.value), key=lambda p: str(p["ARN"])))
    for item in out:
        if shared:
            del item["PolicyStatus"]   # another account's parameter: its policy is not ours to read
        else:
            _parameter_policy(ctx, ssm, item)


def _document(ctx: Any, ssm: Any, doc: Dict[str, Any]) -> Dict[str, Any]:
    name = doc.get("Name")
    item: Dict[str, Any] = {
        "Name": name, "Arn": ctx.arn("ssm", f"document/{name}"), "DocumentType": doc.get("DocumentType"),
        "DocumentFormat": doc.get("DocumentFormat"), "DocumentVersion": doc.get("DocumentVersion"),
        "PlatformTypes": sorted(doc.get("PlatformTypes") or []), "Public": None, "SharedAccounts": None,
    }
    result = ctx.paginate(ssm, "describe_document_permission", "AccountIds", item=item["Arn"], Name=name,
                          PermissionType="Share")
    if result.ok:
        accounts = [str(a) for a in result.value]
        item["Public"] = "all" in [a.lower() for a in accounts]
        item["SharedAccounts"] = sorted({a for a in accounts if a.lower() != "all"})
    else:
        add_error(item, result)
    return item


def _documents(ctx: Any, ssm: Any, out: List[Dict[str, Any]]) -> None:
    listed = ctx.paginate(ssm, "list_documents", "DocumentIdentifiers", page_size=50,
                          Filters=[{"Key": "Owner", "Values": ["Self"]}])
    for doc in sorted((d for d in listed.value if d.get("Name")), key=lambda d: d["Name"]):
        out.append(_document(ctx, ssm, doc))


def _instances(ctx: Any, ssm: Any, out: List[Dict[str, Any]]) -> None:
    listed = ctx.paginate(ssm, "describe_instance_information", "InstanceInformationList", page_size=50)
    out.extend(sorted(({k: i.get(k) for k in _INSTANCE_FIELDS} for i in listed.value),
                      key=lambda i: str(i["InstanceId"])))


def collect(ctx: Any) -> None:
    ssm = ctx.client("ssm")
    keep_sensitive = bool(ctx.option("keep_sensitive_metadata", False))
    outputs: Tuple[Tuple[str, str, Callable[[List[Dict[str, Any]]], None]], ...] = (
        ("parameters", "parameters.json", lambda out: _parameters(ctx, ssm, keep_sensitive, out, shared=False)),
        ("shared_parameters", "parameters_shared_with_account.json",
         lambda out: _parameters(ctx, ssm, keep_sensitive, out, shared=True)),
        ("documents", "documents.json", lambda out: _documents(ctx, ssm, out)),
        ("managed_instances", "managed_instances.json", lambda out: _instances(ctx, ssm, out)),
    )
    counts: Dict[str, int] = {}
    for section, name, build in outputs:
        data: List[Dict[str, Any]] = []
        with ctx.section(section):      # a failure keeps what was built so far (F-103)
            build(data)
        ctx.out.write(name, data)
        counts[section] = len(data)
    ctx.log.info("%(parameters)d parameters, %(documents)d documents, %(managed_instances)d managed instances",
                 counts)
