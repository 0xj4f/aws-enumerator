"""ARN parsing and matching (engine.md §2.2; F-072, F-079, F-119).

One shared matcher for every analyzer: a policy ``Resource`` pattern is matched **one way** against a
concrete ARN, component by component (AWS "IAM JSON policy elements: Resource" and the ``ArnLike`` operator:
"each of the six colon-delimited components of the ARN is checked separately"):

* partition, service and region: glob, case-insensitive. The partition is never hard-coded: ``aws``,
  ``aws-cn``, ``aws-us-gov`` and the ISO partitions all match (F-079, F-119);
* account: glob;
* resource part: glob, **case-sensitive** (secret, parameter, queue and object names are case-sensitive,
  F-079); it may span ``:`` and ``/``.

``normalize_account_principal`` turns a bare 12-digit principal into ``arn:<partition>:iam::<id>:root``
(AWS "IAM JSON policy elements: Principal": an account id is shorthand for the account root, F-072).

The d13c215 per-service helpers (``_extract_account_from_arn``, ``_arn_matches_bucket`` …) were removed in Wave 3
with the d13c215 analyzers (DECISIONS.md D-53); every caller uses :func:`arn_match` / :func:`account_of`.
"""

from __future__ import annotations

import functools
import re
from dataclasses import dataclass
from typing import Iterable, Mapping, Optional, Tuple

from aws_enumerator.engine.policy.glob import glob_covers, glob_match, glob_overlap

#: AWS partitions known to botocore (aws, China, GovCloud, the ISO partitions, European Sovereign Cloud).
PARTITIONS: Tuple[str, ...] = ("aws", "aws-cn", "aws-us-gov", "aws-iso", "aws-iso-b", "aws-iso-e", "aws-iso-f",
                               "aws-eusc")
_ACCOUNT_RE = re.compile(r"^\d{12}$")
_REGION_PARTITION = (("cn-", "aws-cn"), ("us-gov-", "aws-us-gov"), ("us-isob-", "aws-iso-b"),
                     ("us-iso-", "aws-iso"), ("eu-isoe-", "aws-iso-e"), ("us-isof-", "aws-iso-f"),
                     ("eusc-", "aws-eusc"))


@dataclass(frozen=True)
class Arn:
    """The six components of an ARN (``resource`` may contain ``:`` and ``/``)."""

    partition: str
    service: str
    region: str
    account: str
    resource: str

    def __str__(self) -> str:
        return f"arn:{self.partition}:{self.service}:{self.region}:{self.account}:{self.resource}"

    @property
    def resource_type(self) -> str:
        """``role`` for ``role/path/name``, ``function`` for ``function:name`` (empty when untyped)."""
        for sep in ("/", ":"):
            if sep in self.resource:
                return self.resource.split(sep, 1)[0]
        return ""


@functools.lru_cache(maxsize=65536)
def parse_arn(value: str) -> Optional[Arn]:
    """Parse ``arn:partition:service:region:account:resource``; ``None`` when it is not an ARN."""
    if not isinstance(value, str) or not value.startswith("arn:"):
        return None
    parts = value.split(":", 5)
    if len(parts) != 6:
        return None
    return Arn(parts[1], parts[2], parts[3], parts[4], parts[5])


def is_account_id(value: object) -> bool:
    """A bare 12-digit AWS account id."""
    return isinstance(value, str) and bool(_ACCOUNT_RE.match(value))


def partition_for_region(region: Optional[str], default: str = "aws") -> str:
    """The partition a region belongs to (``cn-north-1`` → ``aws-cn``)."""
    if not region:
        return default
    for prefix, partition in _REGION_PARTITION:
        if region.startswith(prefix):
            return partition
    return "aws"


def account_of(value: object) -> Optional[str]:
    """The account of an ARN or bare account id (``None`` for ``*``, service principals and garbage)."""
    if is_account_id(value):
        return str(value)
    arn = parse_arn(value) if isinstance(value, str) else None
    if arn is None or not arn.account or not is_account_id(arn.account):
        return None
    return arn.account


def normalize_account_principal(value: str, partition: str = "aws") -> str:
    """``123456789012`` → ``arn:<partition>:iam::123456789012:root``; anything else unchanged (F-072)."""
    if is_account_id(value):
        return f"arn:{partition}:iam::{value}:root"
    return value


def root_arn(account: str, partition: str = "aws") -> str:
    return f"arn:{partition}:iam::{account}:root"


# ── Matching ─────────────────────────────────────────────────────────────────

def _split6(value: str) -> Optional[Tuple[str, ...]]:
    if not value.startswith("arn:"):
        return None
    parts = value.split(":", 5)
    return tuple(parts) if len(parts) == 6 else None


def arn_match(pattern: str, concrete: str) -> bool:
    """One-directional match of a policy ARN pattern against a concrete ARN (component-wise, see module doc)."""
    if not isinstance(pattern, str) or not isinstance(concrete, str):
        return False
    if pattern == "*":
        return True
    p, c = _split6(pattern), _split6(concrete)
    if p is None or c is None:
        return glob_match(pattern, concrete)
    return (glob_match(p[1], c[1], case_sensitive=False) and glob_match(p[2], c[2], case_sensitive=False)
            and glob_match(p[3], c[3], case_sensitive=False) and glob_match(p[4], c[4])
            and glob_match(p[5], c[5]))


def arn_overlap(a: str, b: str) -> bool:
    """Do two ARN patterns share at least one concrete ARN? (existential template queries)"""
    if a == "*" or b == "*":
        return True
    pa, pb = _split6(a), _split6(b)
    if pa is None or pb is None:
        return glob_overlap(a, b)
    return (glob_overlap(pa[1], pb[1], case_sensitive=False) and glob_overlap(pa[2], pb[2], case_sensitive=False)
            and glob_overlap(pa[3], pb[3], case_sensitive=False) and glob_overlap(pa[4], pb[4])
            and glob_overlap(pa[5], pb[5]))


def arn_covers(pattern: str, template: str) -> bool:
    """Does ``pattern`` provably match every ARN that ``template`` matches? (sound, not complete)"""
    if pattern == "*":
        return True
    if template == "*":
        return False
    pp, pt = _split6(pattern), _split6(template)
    if pp is None or pt is None:
        return glob_covers(pattern, template)
    return (glob_covers(pp[1], pt[1], case_sensitive=False) and glob_covers(pp[2], pt[2], case_sensitive=False)
            and glob_covers(pp[3], pt[3], case_sensitive=False) and glob_covers(pp[4], pt[4])
            and glob_covers(pp[5], pt[5]))


def any_arn_match(patterns: Iterable[str], concrete: str) -> bool:
    return any(arn_match(p, concrete) for p in patterns)


def ssm_parameter_arn(name: str, *, partition: str, region: str, account: str) -> str:
    """The ARN of an SSM parameter (the leading ``/`` of a hierarchical name is dropped)."""
    return f"arn:{partition}:ssm:{region}:{account}:parameter/{name.lstrip('/')}"


def ssm_parameter_matches(pattern: str, parameter_arn: str, *, by_path: bool = False) -> bool:
    """Match a policy resource against a collected parameter ARN (F-079).

    ``by_path``: the action is ``ssm:GetParametersByPath``, whose resource is the *path*: a pattern equal to an
    ancestor path (``parameter/prod`` for ``parameter/prod/db/password``) grants the parameters below it.
    """
    if arn_match(pattern, parameter_arn):
        return True
    if not by_path:
        return False
    pp, pc = parse_arn(pattern), parse_arn(parameter_arn)
    if pp is None or pc is None or not pc.resource.startswith("parameter/"):
        return False
    path = pc.resource
    while "/" in path[len("parameter/"):]:
        path = path.rsplit("/", 1)[0]
        if arn_match(pattern, str(Arn(pc.partition, pc.service, pc.region, pc.account, path))):
            return True
    return False


def resource_account(resource_arn: str, default: Optional[str] = None) -> Optional[str]:
    """The account that owns a concrete resource ARN; S3 ARNs carry none, so ``default`` (the bucket owner)."""
    arn = parse_arn(resource_arn)
    if arn is None:
        return default
    if arn.account and is_account_id(arn.account):
        return arn.account
    return default


def bucket_arn(resource_arn: str) -> Optional[str]:
    """``arn:<p>:s3:::bucket`` for a bucket or object ARN (``None`` for other ARNs)."""
    arn = parse_arn(resource_arn)
    if arn is None or arn.service != "s3" or not arn.resource:
        return None
    return f"arn:{arn.partition}:s3:::{arn.resource.split('/', 1)[0]}"


def unqualified_lambda_arn(resource_arn: str) -> str:
    """Strip a ``:version`` / ``:alias`` qualifier from a Lambda function ARN."""
    arn = parse_arn(resource_arn)
    if arn is None or arn.service != "lambda" or not arn.resource.startswith("function:"):
        return resource_arn
    name = arn.resource.split(":")[1] if arn.resource.count(":") >= 1 else ""
    return str(Arn(arn.partition, arn.service, arn.region, arn.account, f"function:{name}"))


def principal_tags_map(tags: object) -> Mapping[str, str]:
    """AWS tag lists (``[{Key, Value}]``) or plain mappings to ``{key: value}``."""
    if isinstance(tags, Mapping):
        return {str(k): str(v) for k, v in tags.items()}
    out = {}
    if isinstance(tags, list):
        for t in tags:
            if isinstance(t, Mapping) and "Key" in t:
                out[str(t["Key"])] = str(t.get("Value", ""))
    return out
