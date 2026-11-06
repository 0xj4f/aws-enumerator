"""Identity scheme for graph nodes, edges and findings (docs/contracts/node-ids.md).

Rules (engine.md §6.1, F-039, F-146):

* A node id is the resource ARN wherever one exists, account-, region- and partition-qualified.
  IAM ARNs are used **exactly as collected** (the role path is part of the id).
* Principals found in policies are resolved by **exact ARN** only. A principal that is not a node becomes a
  placeholder (same account) or an external node (other account). Nothing is ever matched by the last
  path segment of an ARN. The one name-based lookup is an STS ``assumed-role`` session mapped to the role
  of the same name **in the same account** (role names are unique per account).
* Synthetic nodes use the ``aws-enumerator:`` scheme, Kubernetes objects ``k8s://<cluster ARN>/...``.

Pure functions, standard library only.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Optional, Tuple, Union

# ── Synthetic ids ─────────────────────────────────────────────────────────────

SYNTHETIC_PREFIX = "aws-enumerator:"
ANONYMOUS_ID = "aws-enumerator:anonymous"
K8S_PREFIX = "k8s://"
SERVICE_PREFIX = "svc:"

#: Kubernetes kind used in the id, per node type.
K8S_KINDS: Mapping[str, Tuple[str, ...]] = {
    "pod": ("Pod",),
    "sa": ("ServiceAccount",),
    "k8srole": ("Role", "ClusterRole"),
    "k8ssecret": ("Secret",),
    "k8sservice": ("Service",),
    "k8singress": ("Ingress",),
    "k8sgroup": ("Group",),
    "k8suser": ("User",),
}
#: Namespace segment for cluster-scoped Kubernetes objects.
K8S_CLUSTER_SCOPE = "_"

#: Well-known web identity providers that have no IAM provider ARN (trust ``Federated`` values).
WELL_KNOWN_WEB_IDPS: Tuple[str, ...] = (
    "accounts.google.com", "cognito-identity.amazonaws.com", "graph.facebook.com", "www.amazon.com",
    "appleid.apple.com",
)


def account_admin_id(account: str) -> str:
    return f"aws-enumerator:account-admin/{_acct(account)}"


def account_anchor_id(account: str) -> str:
    return f"aws-enumerator:account/{_acct(account)}"


def region_anchor_id(account: str, region: str) -> str:
    return f"aws-enumerator:region/{_acct(account)}/{_region(region)}"


def all_buckets_id(account: str, partition: str = "aws") -> str:
    """The ``bucket`` node that stands for every bucket of ``account`` (S3 fan-out summary, F-022).

    ``arn:<p>:s3:::*:<account>``: ``*`` and ``:`` never occur in a bucket name, so the id cannot collide with a
    real bucket, and the account keeps the summaries of merged accounts apart (node-ids.md §2).
    """
    return f"arn:{_part(partition)}:s3:::*:{_acct(account)}"


def web_idp_id(host: str) -> str:
    return f"aws-enumerator:idp/{host.lower()}"


def service_principal_id(service: str) -> str:
    return SERVICE_PREFIX + service.lower()


def external_account_id(account: str, partition: str = "aws") -> str:
    return f"arn:{_part(partition)}:iam::{_acct(account)}:root"


# ── ARN parsing ───────────────────────────────────────────────────────────────

_ACCT_RE = re.compile(r"^\d{12}$")
_PART_RE = re.compile(r"^aws(?:-[a-z]+)*$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d+$")
_UNIQUE_ID_RE = re.compile(r"^(?:AROA|AIDA|AGPA|ANPA|ANVA|AIPA|ASIA|AKIA)[A-Z0-9]{12,}$")


@dataclass(frozen=True)
class ArnParts:
    partition: str
    service: str
    region: str
    account: str
    resource: str


def parse_arn(arn: str) -> Optional[ArnParts]:
    """Split ``arn:partition:service:region:account:resource`` (the resource may contain ``:`` and ``/``)."""
    if not isinstance(arn, str) or not arn.startswith("arn:"):
        return None
    parts = arn.split(":", 5)
    if len(parts) != 6 or not parts[1] or not parts[2]:
        return None
    return ArnParts(parts[1], parts[2], parts[3], parts[4], parts[5])


def _acct(account: str) -> str:
    if not isinstance(account, str) or not _ACCT_RE.match(account):
        raise ValueError(f"account must be 12 digits, got {account!r}")
    return account


def _part(partition: str) -> str:
    if not isinstance(partition, str) or not _PART_RE.match(partition):
        raise ValueError(f"bad partition {partition!r}")
    return partition


def _region(region: str) -> str:
    if not isinstance(region, str) or not _REGION_RE.match(region):
        raise ValueError(f"bad region {region!r}")
    return region


def _nonempty(value: object, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{what} must be a non-empty string")
    return value


# ── Node id patterns (validated by graph.validate_graph) ──────────────────────

_P = r"arn:aws(?:-[a-z]+)*"
_R = r"[a-z]{2}(?:-[a-z]+)+-\d+"
_A = r"\d{12}"
_K8S = rf"k8s://{_P}:eks:{_R}:{_A}:cluster/[^/]+"

NODE_ID_PATTERNS: Mapping[str, "re.Pattern[str]"] = {k: re.compile(v) for k, v in {
    "user": rf"^{_P}:iam::{_A}:user/.+$",
    "role": rf"^{_P}:iam::{_A}:role/.+$",
    "group": rf"^{_P}:iam::{_A}:group/.+$",
    "policy": rf"^{_P}:iam::(?:{_A}|aws):policy/.+$",
    "idp": rf"^(?:{_P}:iam::{_A}:(?:oidc-provider|saml-provider)/.+|aws-enumerator:idp/[a-z0-9.-]+)$",
    "service_principal": r"^svc:[a-z0-9.-]+$",
    "anonymous": r"^aws-enumerator:anonymous$",
    "account_admin": rf"^aws-enumerator:account-admin/{_A}$",
    "external_account": rf"^{_P}:iam::{_A}:root$",
    "external_principal": rf"^{_P}:(?:iam|sts)::{_A}:(?:user|role|assumed-role|federated-user)/.+$",
    "account": rf"^aws-enumerator:account/{_A}$",
    "region": rf"^aws-enumerator:region/{_A}/{_R}$",
    "trail": rf"^{_P}:cloudtrail:{_R}:{_A}:trail/.+$",
    "instance": rf"^{_P}:ec2:{_R}:{_A}:instance/i-[0-9a-f]+$",
    "lambda": rf"^{_P}:lambda:{_R}:{_A}:function:[^:]+$",
    "lambdalayer": rf"^{_P}:lambda:{_R}:{_A}:layer:[^:]+(?::\d+)?$",
    "ecstask": rf"^{_P}:ecs:{_R}:{_A}:task-definition/[^:?]+(?:\?roles=[0-9a-f]{{8}})?$",
    "ecsservice": rf"^{_P}:ecs:{_R}:{_A}:service/.+$",
    "cfnstack": rf"^{_P}:cloudformation:{_R}:{_A}:stack/.+$",
    "stackset": rf"^{_P}:cloudformation:{_R}:{_A}:stackset/.+$",
    "gluejob": rf"^{_P}:glue:{_R}:{_A}:job/.+$",
    "gluedevendpoint": rf"^{_P}:glue:{_R}:{_A}:devEndpoint/.+$",
    "codebuild": rf"^{_P}:codebuild:{_R}:{_A}:project/.+$",
    "sagemaker": rf"^{_P}:sagemaker:{_R}:{_A}:(?:notebook-instance|training-job|processing-job)/.+$",
    "sagemakerdomain": rf"^{_P}:sagemaker:{_R}:{_A}:(?:domain|user-profile)/.+$",
    "sg": rf"^{_P}:ec2:{_R}:{_A}:security-group/sg-[0-9a-f]+$",
    "vpc": rf"^{_P}:ec2:{_R}:{_A}:vpc/vpc-[0-9a-f]+$",
    "subnet": rf"^{_P}:ec2:{_R}:{_A}:subnet/subnet-[0-9a-f]+$",
    "elb": rf"^{_P}:elasticloadbalancing:{_R}:{_A}:loadbalancer/.+$",
    "apigw": rf"^{_P}:apigateway:{_R}:(?:{_A})?:/(?:restapis|apis)/[^/]+$",
    "cloudfront": rf"^{_P}:cloudfront::{_A}:distribution/.+$",
    "route53zone": rf"^{_P}:route53:::hostedzone/[A-Z0-9]+$",
    "ami": rf"^{_P}:ec2:{_R}::image/ami-[0-9a-f]+$",
    "launchtemplate": rf"^{_P}:ec2:{_R}:{_A}:launch-template/lt-[0-9a-f]+$",
    "bucket": rf"^{_P}:s3:::[^/]+$",
    "secret": rf"^{_P}:secretsmanager:{_R}:{_A}:secret:.+$",
    "ssmparam": rf"^{_P}:ssm:{_R}:{_A}:parameter/.+$",
    "ssmdocument": rf"^{_P}:ssm:{_R}:{_A}:document/.+$",
    "kms": rf"^{_P}:kms:{_R}:{_A}:(?:key|alias)/.+$",
    "dynamodb": rf"^{_P}:dynamodb:{_R}:{_A}:table/[^/]+$",
    "ecr": rf"^{_P}:ecr:{_R}:{_A}:repository/.+$",
    "rds": rf"^{_P}:rds:{_R}:{_A}:(?:db|cluster):.+$",
    "rdssnapshot": rf"^{_P}:rds:{_R}:{_A}:(?:snapshot|cluster-snapshot):.+$",
    "ebssnapshot": rf"^{_P}:ec2:{_R}::snapshot/snap-[0-9a-f]+$",
    "sns": rf"^{_P}:sns:{_R}:{_A}:[^:]+$",
    "sqs": rf"^{_P}:sqs:{_R}:{_A}:[^:]+$",
    "cognito": rf"^{_P}:cognito-identity:{_R}:{_A}:identitypool/.+$",
    "cognitouserpool": rf"^{_P}:cognito-idp:{_R}:{_A}:userpool/.+$",
    "cluster": rf"^{_P}:eks:{_R}:{_A}:cluster/[^/]+$",
    "nodegroup": rf"^{_P}:eks:{_R}:{_A}:nodegroup/.+$",
    "pod": rf"^{_K8S}/Pod/[^/]+/[^/]+$",
    "sa": rf"^{_K8S}/ServiceAccount/[^/]+/[^/]+$",
    "k8srole": rf"^{_K8S}/(?:Role/[^/]+|ClusterRole/_)/[^/]+$",
    "k8ssecret": rf"^{_K8S}/Secret/[^/]+/[^/]+$",
    "k8sservice": rf"^{_K8S}/Service/[^/]+/[^/]+$",
    "k8singress": rf"^{_K8S}/Ingress/[^/]+/[^/]+$",
    "k8sgroup": rf"^{_K8S}/Group/_/.+$",
    "k8suser": rf"^{_K8S}/User/_/.+$",
}.items()}


def node_id_matches(node_type: str, node_id: str) -> bool:
    """True when ``node_id`` has the shape the scheme prescribes for ``node_type`` (unknown types: True)."""
    pat = NODE_ID_PATTERNS.get(node_type)
    return True if pat is None else bool(pat.match(node_id))


# ── Building node ids ─────────────────────────────────────────────────────────

def lambda_unqualified(arn: str) -> Tuple[str, Optional[str]]:
    """``arn:...:function:name[:qualifier]`` → ``(unqualified ARN, qualifier or None)`` (F-082, F-055)."""
    p = parse_arn(arn)
    if p is None or p.service != "lambda" or not p.resource.startswith("function:"):
        raise ValueError(f"not a Lambda function ARN: {arn!r}")
    rest = p.resource[len("function:"):]
    name, _, qualifier = rest.partition(":")
    if not name:
        raise ValueError(f"not a Lambda function ARN: {arn!r}")
    return f"arn:{p.partition}:lambda:{p.region}:{p.account}:function:{name}", (qualifier or None)


def role_set_suffix(role_arns: Iterable[str]) -> str:
    """``?roles=<sha8>`` suffix for an ECS family that has several role sets (engine.md §6.1)."""
    roles = sorted({r for r in role_arns if r})
    digest = hashlib.sha256("\x1f".join(roles).encode("utf-8")).hexdigest()[:8]
    return f"?roles={digest}"


def _arn_kind(kind: str, parts: Mapping[str, object]) -> str:
    arn = _nonempty(parts.get("arn"), f"{kind}: arn")
    if not node_id_matches(kind, arn):
        raise ValueError(f"{kind}: {arn!r} does not match the {kind} id scheme")
    return arn


def _regional(service: str, resource_fmt: str):
    def build(kind: str, parts: Mapping[str, object]) -> str:
        if "arn" in parts:
            return _arn_kind(kind, parts)
        p = _part(str(parts.get("partition", "aws")))
        r = _region(str(parts.get("region")))
        a = _acct(str(parts.get("account")))
        values = {k: _nonempty(v, f"{kind}: {k}") for k, v in parts.items()
                  if k not in ("partition", "region", "account")}
        try:
            resource = resource_fmt.format(**values)
        except KeyError as exc:
            raise ValueError(f"{kind}: missing part {exc.args[0]!r}") from None
        out = f"arn:{p}:{service}:{r}:{a}:{resource}"
        if not node_id_matches(kind, out):
            raise ValueError(f"{kind}: built id {out!r} does not match the scheme")
        return out
    return build


def _k8s(kind: str, parts: Mapping[str, object]) -> str:
    cluster_arn = _nonempty(parts.get("cluster_arn"), f"{kind}: cluster_arn")
    if not node_id_matches("cluster", cluster_arn):
        raise ValueError(f"{kind}: cluster_arn {cluster_arn!r} is not an EKS cluster ARN")
    kinds = K8S_KINDS[kind]
    k8s_kind = str(parts.get("k8s_kind") or kinds[0])
    if k8s_kind not in kinds:
        raise ValueError(f"{kind}: k8s_kind must be one of {kinds}")
    ns = parts.get("namespace")
    cluster_scoped = kind in ("k8sgroup", "k8suser") or k8s_kind == "ClusterRole"
    if cluster_scoped:
        ns = K8S_CLUSTER_SCOPE
    ns = _nonempty(ns, f"{kind}: namespace")
    name = _nonempty(parts.get("name"), f"{kind}: name")
    if kind not in ("k8sgroup", "k8suser") and "/" in name:
        raise ValueError(f"{kind}: name must not contain '/'")
    out = f"{K8S_PREFIX}{cluster_arn}/{k8s_kind}/{ns}/{name}"
    if not node_id_matches(kind, out):
        raise ValueError(f"{kind}: built id {out!r} does not match the scheme")
    return out


def _build_bucket(kind: str, parts: Mapping[str, object]) -> str:
    if "arn" in parts:
        return _arn_kind(kind, parts)
    return f"arn:{_part(str(parts.get('partition', 'aws')))}:s3:::{_nonempty(parts.get('name'), 'bucket: name')}"


def _build_lambda(kind: str, parts: Mapping[str, object]) -> str:
    if "arn" in parts:
        return lambda_unqualified(_nonempty(parts["arn"], "lambda: arn"))[0]
    return _regional("lambda", "function:{name}")(kind, parts)


def _build_kms(kind: str, parts: Mapping[str, object]) -> str:
    if "arn" in parts:
        return _arn_kind(kind, parts)
    return _regional("kms", "key/{key_id}")(kind, parts)


def _build_ssmparam(kind: str, parts: Mapping[str, object]) -> str:
    if "arn" in parts:
        return _arn_kind(kind, parts)
    name = _nonempty(parts.get("name"), "ssmparam: name").lstrip("/")
    return _regional("ssm", "parameter/{name}")(kind, {**parts, "name": name})


def _build_ecstask(kind: str, parts: Mapping[str, object]) -> str:
    base = _regional("ecs", "task-definition/{family}")(kind, {k: v for k, v in parts.items() if k != "roles"})
    roles = parts.get("roles")
    return base + role_set_suffix(roles) if roles else base  # type: ignore[arg-type]


def _build_ec2_global(resource_fmt: str):
    def build(kind: str, parts: Mapping[str, object]) -> str:
        if "arn" in parts:
            return _arn_kind(kind, parts)
        p = _part(str(parts.get("partition", "aws")))
        r = _region(str(parts.get("region")))
        out = f"arn:{p}:ec2:{r}::" + resource_fmt.format(id=_nonempty(parts.get("id"), f"{kind}: id"))
        if not node_id_matches(kind, out):
            raise ValueError(f"{kind}: built id {out!r} does not match the scheme")
        return out
    return build


def _build_route53(kind: str, parts: Mapping[str, object]) -> str:
    if "arn" in parts:
        return _arn_kind(kind, parts)
    zone = _nonempty(parts.get("zone_id"), "route53zone: zone_id").rsplit("/", 1)[-1]
    out = f"arn:{_part(str(parts.get('partition', 'aws')))}:route53:::hostedzone/{zone}"
    if not node_id_matches(kind, out):
        raise ValueError(f"route53zone: built id {out!r} does not match the scheme")
    return out


def _build_elb(kind: str, parts: Mapping[str, object]) -> str:
    if "arn" in parts:
        return _arn_kind(kind, parts)
    # classic load balancers have no ARN in old reports (F-051)
    return _regional("elasticloadbalancing", "loadbalancer/{name}")(kind, parts)


def _synthetic(kind: str, parts: Mapping[str, object]) -> str:
    if kind == "anonymous":
        return ANONYMOUS_ID
    if kind == "account_admin":
        return account_admin_id(str(parts.get("account")))
    if kind == "account":
        return account_anchor_id(str(parts.get("account")))
    if kind == "region":
        return region_anchor_id(str(parts.get("account")), str(parts.get("region")))
    if kind == "external_account":
        return external_account_id(str(parts.get("account")), str(parts.get("partition", "aws")))
    if kind == "service_principal":
        return service_principal_id(_nonempty(parts.get("service"), "service_principal: service"))
    raise ValueError(kind)  # pragma: no cover


def _build_idp(kind: str, parts: Mapping[str, object]) -> str:
    if "host" in parts:
        return web_idp_id(_nonempty(parts["host"], "idp: host"))
    return _arn_kind(kind, parts)


_BUILDERS = {
    **{k: _arn_kind for k in ("user", "role", "group", "policy", "external_principal", "trail", "lambdalayer",
                              "ecsservice", "cfnstack", "stackset", "codebuild", "sagemaker", "sagemakerdomain",
                              "secret", "ssmdocument", "rds", "rdssnapshot", "apigw", "cloudfront",
                              "cognitouserpool", "nodegroup", "sns")},
    "idp": _build_idp,
    **{k: _synthetic for k in ("anonymous", "account_admin", "account", "region", "external_account",
                               "service_principal")},
    "instance": _regional("ec2", "instance/{id}"),
    "sg": _regional("ec2", "security-group/{id}"),
    "vpc": _regional("ec2", "vpc/{id}"),
    "subnet": _regional("ec2", "subnet/{id}"),
    "launchtemplate": _regional("ec2", "launch-template/{id}"),
    "ami": _build_ec2_global("image/{id}"),
    "ebssnapshot": _build_ec2_global("snapshot/{id}"),
    "bucket": _build_bucket,
    "lambda": _build_lambda,
    "kms": _build_kms,
    "ssmparam": _build_ssmparam,
    "sqs": _regional("sqs", "{name}"),
    "dynamodb": _regional("dynamodb", "table/{name}"),
    "ecr": _regional("ecr", "repository/{name}"),
    "gluejob": _regional("glue", "job/{name}"),
    "gluedevendpoint": _regional("glue", "devEndpoint/{name}"),
    "elb": _build_elb,
    "ecstask": _build_ecstask,
    "cognito": _regional("cognito-identity", "identitypool/{pool_id}"),
    "route53zone": _build_route53,
    "cluster": _regional("eks", "cluster/{name}"),
    **{k: _k8s for k in K8S_KINDS},
}


def node_id_for(kind: str, **parts: object) -> str:
    """Build the node id for ``kind`` (a node type) from its parts; raises ``ValueError`` on bad input.

    Every type accepts ``arn=`` (validated against the scheme; Lambda ARNs are unqualified). Types with
    builders also accept parts, for example::

        node_id_for("instance", partition="aws", region="eu-west-2", account="111122223333", id="i-0abc")
        node_id_for("bucket", name="demo-bucket")
        node_id_for("ecstask", region=..., account=..., family="web", roles=[task_role_arn])
        node_id_for("sa", cluster_arn=..., namespace="default", name="app")
        node_id_for("k8srole", cluster_arn=..., k8s_kind="ClusterRole", name="admin")
        node_id_for("account_admin", account="111122223333")
        node_id_for("idp", host="accounts.google.com")
    """
    builder = _BUILDERS.get(kind)
    if builder is None:
        raise ValueError(f"unknown node kind {kind!r}")
    return builder(kind, parts)


def edge_id(source: str, edge_type: str, target: str) -> str:
    """``"e:" + sha256(source \\x1f type \\x1f target)[:20]`` (engine.md §6.2). Stable across runs."""
    key = f"{source}\x1f{edge_type}\x1f{target}".encode("utf-8")
    return "e:" + hashlib.sha256(key).hexdigest()[:20]


def finding_fingerprint(canonical_id: str, account: str, node_id: str, discriminator: str = "") -> str:
    """Finding fingerprint, algorithm ``fp1`` (docs/contracts/finding-identity.md)."""
    key = f"fp1\x1f{canonical_id}\x1f{account}\x1f{node_id}\x1f{discriminator}".encode("utf-8")
    return hashlib.sha256(key).hexdigest()[:32]


# ── Principals ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class StsPrincipal:
    """A caller identity (``sts:GetCallerIdentity`` ``Arn``) decomposed.

    ``kind``: ``user`` | ``role`` | ``root`` | ``assumed-role`` | ``sso`` | ``federated-user``.
    ``iam_arn`` is the exact IAM ARN when it can be derived without lookup (user, role, root); an
    assumed-role session has no path, so its role must be looked up by name in the same account.
    """

    kind: str
    partition: str
    account: str
    name: Optional[str]
    session: Optional[str]
    iam_arn: Optional[str]


def principal_from_sts_arn(arn: str) -> Optional[StsPrincipal]:
    """Decompose a caller ARN; ``None`` when it is not an IAM/STS principal ARN."""
    p = parse_arn(arn)
    if p is None or not _ACCT_RE.match(p.account) or not _PART_RE.match(p.partition):
        return None
    res = p.resource
    if p.service == "iam":
        if res == "root":
            return StsPrincipal("root", p.partition, p.account, None, None, arn)
        for kind in ("user", "role"):
            if res.startswith(kind + "/") and len(res) > len(kind) + 1:
                return StsPrincipal(kind, p.partition, p.account, res.rsplit("/", 1)[-1], None, arn)
        return None
    if p.service == "sts":
        if res.startswith("assumed-role/"):
            bits = res.split("/")
            if len(bits) < 3 or not bits[1]:
                return None
            role, session = bits[1], "/".join(bits[2:])
            kind = "sso" if role.startswith("AWSReservedSSO_") else "assumed-role"
            return StsPrincipal(kind, p.partition, p.account, role, session or None, None)
        if res.startswith("federated-user/") and len(res) > len("federated-user/"):
            return StsPrincipal("federated-user", p.partition, p.account, res.split("/", 1)[1], None, None)
    return None


class PrincipalLookup:
    """Index of the graph's nodes for principal resolution.

    ``ids`` maps node id → node type. ``roles_by_name`` maps ``(account, lower-case role name)`` → role id
    and is used **only** for STS assumed-role sessions in the same account.
    """

    def __init__(self, nodes: Union[Mapping[str, str], Iterable[Tuple[str, str]]]):
        items = nodes.items() if isinstance(nodes, Mapping) else nodes
        self.ids: Dict[str, str] = {}
        self.roles_by_name: Dict[Tuple[str, str], str] = {}
        for node_id, node_type in items:
            self.ids[node_id] = node_type
            if node_type == "role":
                p = parse_arn(node_id)
                if p and p.service == "iam" and p.resource.startswith("role/"):
                    self.roles_by_name[(p.account, p.resource.rsplit("/", 1)[-1].lower())] = node_id

    def __contains__(self, node_id: object) -> bool:
        return node_id in self.ids


@dataclass(frozen=True)
class PrincipalRef:
    """Result of :func:`resolve_principal`.

    * ``node_id``/``node_type``: the node an edge should use, or ``None`` (no edge: see ``reason``).
    * ``placeholder``: the builder must create the node (it was not collected).
    * ``external``: the node belongs to another account (``props.external = true``).
    """

    node_id: Optional[str]
    node_type: Optional[str]
    kind: str
    reason: str
    external: bool = False
    placeholder: bool = False
    same_account: bool = False


def resolve_principal(raw: str, index: Union[PrincipalLookup, Mapping[str, str]], account: str, *,
                      principal_type: str = "AWS", partition: str = "aws") -> PrincipalRef:
    """Resolve one policy principal value to a node (F-039). Never matches by name across ARNs.

    ``principal_type`` is the policy key: ``AWS``, ``Service``, ``Federated`` or ``CanonicalUser``.
    ``account``/``partition`` are the assessed account's. Outcomes (``kind`` / ``reason``):

    ================================  ============================================================
    ``*``                             anonymous node
    12-digit id / ``:root``, local    no node: ``same-account-root-delegation`` (identity policies decide)
    12-digit id / ``:root``, foreign  ``external_account`` node
    exact id of an existing node      that node
    local IAM ARN, not a node         placeholder of the ARN's type (``local-not-collected``)
    foreign IAM/STS ARN               ``external_principal`` node (the exact ARN)
    local ``assumed-role`` session    the role of that name in the same account, else no node
    unique id (AROA…, AIDA…)          no node: ``stale-principal``
    ``Service``                       ``service_principal`` node ``svc:<service>``
    ``Federated`` provider ARN        ``idp`` node (the ARN); well-known hosts ``aws-enumerator:idp/<host>``
    ``CanonicalUser``                 no node: ``canonical-user``
    ================================  ============================================================
    """
    look = index if isinstance(index, PrincipalLookup) else PrincipalLookup(index)
    acct = _acct(account)
    part = _part(partition)
    if not isinstance(raw, str) or not raw.strip():
        return PrincipalRef(None, None, "invalid", "empty-principal")
    raw = raw.strip()

    if principal_type == "Service":
        return PrincipalRef(service_principal_id(raw), "service_principal", "service", "service-principal")
    if principal_type == "CanonicalUser":
        return PrincipalRef(None, None, "canonical_user", "canonical-user")
    if principal_type == "Federated":
        if raw.lower() in WELL_KNOWN_WEB_IDPS:
            return PrincipalRef(web_idp_id(raw), "idp", "web_idp", "well-known-web-idp")
        p = parse_arn(raw)
        if p and p.service == "iam" and node_id_matches("idp", raw):
            local = p.account == acct
            return PrincipalRef(raw, "idp", "idp", "exact" if raw in look else "provider-not-collected",
                                external=not local, placeholder=raw not in look, same_account=local)
        return PrincipalRef(None, None, "federated", "unsupported-federated-principal")
    if principal_type != "AWS":
        return PrincipalRef(None, None, "invalid", "unknown-principal-type")

    if raw == "*":
        return PrincipalRef(ANONYMOUS_ID, "anonymous", "anonymous", "wildcard")
    if _ACCT_RE.match(raw):
        raw = f"arn:{part}:iam::{raw}:root"
    if _UNIQUE_ID_RE.match(raw):
        return PrincipalRef(None, None, "unique_id", "stale-principal")
    p = parse_arn(raw)
    if p is None or not _ACCT_RE.match(p.account):
        return PrincipalRef(None, None, "invalid", "unparseable")
    local = p.account == acct
    if p.service == "iam" and p.resource == "root":
        if local:
            return PrincipalRef(None, None, "account_root", "same-account-root-delegation", same_account=True)
        return PrincipalRef(raw, "external_account", "account_root", "foreign-account", external=True)
    if raw in look:
        node_type = look.ids[raw]
        return PrincipalRef(raw, node_type, node_type, "exact",
                            external=node_type in ("external_account", "external_principal"), same_account=local)
    sts = principal_from_sts_arn(raw)
    if p.service == "sts":
        if sts is None:
            return PrincipalRef(None, None, "invalid", "unparseable")
        if local and sts.kind in ("assumed-role", "sso"):
            role_id = look.roles_by_name.get((acct, (sts.name or "").lower()))
            if role_id:
                return PrincipalRef(role_id, "role", sts.kind, "session-mapped-to-role", same_account=True)
            return PrincipalRef(None, None, sts.kind, "local-session-role-not-collected", same_account=True)
        if local:
            return PrincipalRef(None, None, sts.kind, "local-federated-user", same_account=True)
        return PrincipalRef(raw, "external_principal", sts.kind, "foreign-principal", external=True)
    if p.service == "iam" and sts is not None and sts.kind in ("user", "role"):
        if local:
            return PrincipalRef(raw, sts.kind, sts.kind, "local-not-collected", placeholder=True, same_account=True)
        return PrincipalRef(raw, "external_principal", sts.kind, "foreign-principal", external=True)
    if p.service == "iam" and p.resource.startswith("group/"):
        if local:
            return PrincipalRef(raw, "group", "group", "local-not-collected", placeholder=True, same_account=True)
    return PrincipalRef(None, None, "unsupported", "unsupported-principal-arn", same_account=local)


@dataclass(frozen=True)
class OperatorRef:
    """``run.operator`` (docs/contracts/graph-json.md): the identity that ran the collection."""

    arn: Optional[str]
    node_id: Optional[str]
    resolution: str
    redacted: bool = False

    def to_json(self) -> Dict[str, object]:
        return {"arn": self.arn, "node_id": self.node_id, "resolution": self.resolution, "redacted": self.redacted}


#: ``run.operator.resolution`` values.
OPERATOR_RESOLUTIONS: Tuple[str, ...] = (
    "exact", "assumed-role", "sso", "root", "federated", "not-in-graph", "cross-account", "unavailable",
)


def resolve_operator(caller_arn: Optional[str], index: Union[PrincipalLookup, Mapping[str, str]], account: str,
                     *, principal_arn: Optional[str] = None, redacted: bool = False) -> OperatorRef:
    """Map the manifest's operator identity to a node (F-146).

    With ``redacted`` (``--redact-identity``) the caller ARN is not published; ``principal_arn`` (the role
    or user ARN without the session name) is used and becomes ``arn``. An exact node id wins; otherwise an
    assumed-role session, or a role ARN whose path the manifest did not know, maps to the role of that name
    in the same account (``assumed-role``, or ``sso`` for ``AWSReservedSSO_*``).
    """
    look = index if isinstance(index, PrincipalLookup) else PrincipalLookup(index)
    acct = _acct(account)
    arn = principal_arn if redacted else (caller_arn or principal_arn)
    if not arn:
        return OperatorRef(None, None, "unavailable", redacted)
    sts = principal_from_sts_arn(arn)
    if sts is None:
        return OperatorRef(arn, None, "not-in-graph", redacted)
    if sts.account != acct:
        return OperatorRef(arn, None, "cross-account", redacted)
    if sts.kind == "root":
        return OperatorRef(arn, account_admin_id(acct), "root", redacted)
    if sts.kind == "federated-user":
        return OperatorRef(arn, None, "federated", redacted)
    if arn in look:
        return OperatorRef(arn, arn, "exact", redacted)
    if sts.kind == "user":
        return OperatorRef(arn, None, "not-in-graph", redacted)
    # an assumed-role session, or a role ARN derived from one without its path (manifest principal_arn):
    # the role of that name in the same account (role names are unique per account)
    role_id = look.roles_by_name.get((acct, (sts.name or "").lower()))
    if role_id is None:
        return OperatorRef(arn, None, "not-in-graph", redacted)
    is_sso = (sts.name or "").startswith("AWSReservedSSO_")
    return OperatorRef(arn, role_id, "sso" if is_sso else "assumed-role", redacted)


# ── KMS key references (F-027) ────────────────────────────────────────────────

@dataclass(frozen=True)
class KmsRef:
    """A KMS reference normalised to a node id.

    ``kind``: ``key-arn`` | ``key-id`` | ``alias-resolved`` | ``alias-unresolved`` | ``default-alias``.
    ``resolved`` is False only for an alias that could not be mapped to a key; the node id is then the
    region-qualified alias ARN (a placeholder ``kms`` node with ``props.unresolved_alias = true``).
    """

    node_id: str
    resolved: bool
    kind: str


def kms_key_node_id(ref: Optional[str], *, partition: str, region: str, account: str,
                    aliases: Optional[Mapping[str, str]] = None,
                    default_alias: Optional[str] = None) -> Optional[KmsRef]:
    """Normalise a KMS reference from any collector field to the key's node id.

    ``ref`` may be a key ARN, a key id (UUID or ``mrk-…``), an alias ARN or an alias name (``alias/x``).
    ``aliases`` maps alias ARN → target key ARN (from ``kms:ListAliases``). An empty ``ref`` uses
    ``default_alias`` (for example ``alias/aws/secretsmanager``) or returns ``None``. A key ARN is kept even
    when it belongs to another account or region (each multi-Region replica is a distinct key).
    """
    p_ = _part(partition)
    r_ = _region(region)
    a_ = _acct(account)
    aliases = aliases or {}
    kind_default = False
    if not ref:
        if not default_alias:
            return None
        ref, kind_default = default_alias, True
    ref = ref.strip()
    parsed = parse_arn(ref)
    if parsed is not None:
        if parsed.service != "kms":
            raise ValueError(f"not a KMS ARN: {ref!r}")
        if parsed.resource.startswith("key/"):
            return KmsRef(ref, True, "key-arn")
        if parsed.resource.startswith("alias/"):
            alias_arn = ref
        else:
            raise ValueError(f"not a KMS key or alias ARN: {ref!r}")
    elif ref.startswith("alias/"):
        alias_arn = f"arn:{p_}:kms:{r_}:{a_}:{ref}"
    else:
        return KmsRef(f"arn:{p_}:kms:{r_}:{a_}:key/{ref}", True, "key-id")
    target = aliases.get(alias_arn)
    if target:
        return KmsRef(target, True, "default-alias" if kind_default else "alias-resolved")
    return KmsRef(alias_arn, False, "alias-unresolved")
