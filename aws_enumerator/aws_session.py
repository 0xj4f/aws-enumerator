"""One AWS session per run: identity, partition, regions, retries, user agent, clients (cli.md §3.1).

:class:`AwsContext` implements the ``AwsProvider`` protocol of :mod:`aws_enumerator.collectors.base`:

* **Credentials are resolved once** (F-060, F-167). Every session the run creates (one per region, behind
  ``ctx.client``) shares the same ``Credentials`` object through a fixed credential provider, so refreshable
  SSO / assume-role credentials refresh in one place.
* **Retries** (F-125): the user's ``AWS_RETRY_MODE`` / ``AWS_MAX_ATTEMPTS`` or profile ``retry_mode`` /
  ``max_attempts`` win; the tool's defaults (adaptive, 5 attempts) apply only where neither is set, and
  ``--retry-mode`` / ``--max-attempts`` override both. ``os.environ`` is never written.
* **User agent** (F-170): ``Config(user_agent_appid="aws-enumerator/<version>/<run id[-6:]>")`` unless the user
  already set ``AWS_SDK_UA_APP_ID`` / ``sdk_ua_app_id`` (then theirs is kept), ``--ua-app-id`` overrides,
  and ``--no-ua-tag`` sends no app id at all.
* **Identity and partition** (F-119): ``sts:GetCallerIdentity`` in the **home** region; the partition comes
  from the caller ARN, the global region from :func:`aws_enumerator.registry.global_region_for`.
* **Regions** (F-064, F-124, F-140): no hard-coded default region; ``--all`` uses ``ec2:DescribeRegions`` in the
  home region and, when that is denied, the offline region list for the partition (botocore's endpoint data plus
  the shipped ``util/regions.json``) filtered by a short regional STS probe (``region_source:
  "fallback:sts-probe"``).
* **Rate limiting** (F-154): the run's :class:`~aws_enumerator.ratelimit.RateLimiter` is installed on every
  session before any client exists, so every client draws from the shared buckets.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

import boto3
import botocore.config
import botocore.credentials
import botocore.exceptions
import botocore.session

from aws_enumerator._version import PRODUCT_NAME, __version__
from aws_enumerator.collectors.base import AwsProvider
from aws_enumerator.coverage import classify, error_code_of
from aws_enumerator.ratelimit import RateLimiter
from aws_enumerator.registry import global_region_for

__all__ = [
    "AwsContext", "AwsOptions", "AwsSetupError", "Identity", "RegionPlan", "RegionUsageError",
    "available_regions", "default_ua_app_id", "describe_enabled_regions", "home_region_from_env",
    "partition_from_arn", "plan_regions", "principal_from_sts_arn", "probe_regions", "shipped_regions",
    "validate_region",
]

log = logging.getLogger("aws_enumerator.aws")

REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-[0-9]+$")
_ARN_RE = re.compile(r"^arn:(?P<partition>aws[a-z-]*):(?P<service>[a-z0-9-]+):[^:]*:(?P<account>\d{12}):"
                     r"(?P<resource>.+)$")
DEFAULT_RETRY_MODE = "adaptive"
DEFAULT_MAX_ATTEMPTS = 5
OPT_IN_FILTER = [{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
_PROBE_WORKERS = 8


class AwsSetupError(Exception):
    """The AWS context cannot be built (unknown profile, no credentials, STS failure): exit 1."""


class RegionUsageError(ValueError):
    """Bad region flags or no home region: exit 64."""


# ── identity ─────────────────────────────────────────────────────────────────
def partition_from_arn(arn: str) -> str:
    match = _ARN_RE.match(arn or "")
    return match.group("partition") if match else "aws"


def principal_from_sts_arn(arn: str) -> Tuple[Optional[str], str]:
    """``(principal_arn, principal_type)`` for a caller ARN (manifest.md §3.4).

    ``arn:aws:sts::<acct>:assumed-role/<name>/<session>`` -> ``(arn:aws:iam::<acct>:role/<name>, assumed-role)``;
    IAM users and the root keep their ARN; ``federated-user`` keeps its STS ARN.
    """
    match = _ARN_RE.match(arn or "")
    if not match:
        return None, "unknown"
    partition, service, account, resource = (match.group("partition"), match.group("service"),
                                             match.group("account"), match.group("resource"))
    if service == "sts" and resource.startswith("assumed-role/"):
        parts = resource.split("/")
        if len(parts) >= 3:
            return f"arn:{partition}:iam::{account}:role/{parts[1]}", "assumed-role"
    if service == "sts" and resource.startswith("federated-user/"):
        return arn, "federated-user"
    if service == "iam" and resource == "root":
        return arn, "root"
    if service == "iam" and resource.startswith("user/"):
        return arn, "user"
    return arn, "unknown"


@dataclass(frozen=True)
class Identity:
    """Who the run is (``sts:GetCallerIdentity`` in the home region)."""

    account_id: str
    caller_arn: str
    caller_user_id: str
    partition: str
    principal_arn: Optional[str]
    principal_type: str

    @property
    def global_region(self) -> str:
        return global_region_for(self.partition)

    def operator_block(self, *, redact: bool) -> Dict[str, Any]:
        """``manifest.operator`` (manifest.md §3.4); with ``redact`` the caller ARN and user id are dropped."""
        return {
            "caller_arn": None if redact else self.caller_arn,
            "caller_user_id": None if redact else self.caller_user_id,
            "caller_arn_sha256": hashlib.sha256(self.caller_arn.encode("utf-8")).hexdigest(),
            "principal_arn": self.principal_arn,
            "principal_type": self.principal_type,
            "redacted": bool(redact),
        }

    @classmethod
    def from_sts(cls, response: Mapping[str, Any]) -> "Identity":
        arn = str(response.get("Arn") or "")
        account = str(response.get("Account") or "")
        if not re.match(r"^\d{12}$", account):
            raise AwsSetupError("sts:GetCallerIdentity returned no valid account id")
        principal, ptype = principal_from_sts_arn(arn)
        return cls(account_id=account, caller_arn=arn, caller_user_id=str(response.get("UserId") or ""),
                   partition=partition_from_arn(arn), principal_arn=principal, principal_type=ptype)


# ── options and client configuration ─────────────────────────────────────────
@dataclass
class AwsOptions:
    """The ``collect`` flags that shape the AWS session (cli.md §3.1)."""

    profile: Optional[str] = None
    retry_mode: Optional[str] = None
    max_attempts: Optional[int] = None
    ua_app_id: Optional[str] = None
    ua_tag: bool = True
    run_id: Optional[str] = None
    connect_timeout: float = 10.0
    read_timeout: float = 60.0
    max_pool_connections: int = 10


def default_ua_app_id(run_id: Optional[str]) -> str:
    """``aws-enumerator/0.3.0/a1b2c3``; botocore renders it as ``app/aws-enumerator-0.3.0-a1b2c3``."""
    suffix = (run_id or "")[-6:]
    return f"{PRODUCT_NAME}/{__version__}" + (f"/{suffix}" if suffix else "")


def _user_setting(bc: Any, env_name: str, config_name: str) -> bool:
    if os.environ.get(env_name):
        return True
    try:
        return bool(bc.get_scoped_config().get(config_name))
    except botocore.exceptions.ProfileNotFound:
        return False


def _retries(options: AwsOptions, bc: Any) -> Dict[str, Any]:
    retries: Dict[str, Any] = {}
    if options.retry_mode:
        retries["mode"] = options.retry_mode
    elif not _user_setting(bc, "AWS_RETRY_MODE", "retry_mode"):
        retries["mode"] = DEFAULT_RETRY_MODE
    if options.max_attempts:
        retries["total_max_attempts"] = int(options.max_attempts)
    elif not _user_setting(bc, "AWS_MAX_ATTEMPTS", "max_attempts"):
        retries["total_max_attempts"] = DEFAULT_MAX_ATTEMPTS
    return retries


def _ua_app_id(options: AwsOptions, bc: Any) -> Optional[str]:
    """``None`` keeps botocore's own resolution (the user's setting); ``""`` sends no app id."""
    if not options.ua_tag:
        return ""
    if options.ua_app_id:
        return options.ua_app_id
    if _user_setting(bc, "AWS_SDK_UA_APP_ID", "sdk_ua_app_id"):
        return None
    return default_ua_app_id(options.run_id)


def build_client_config(options: AwsOptions, bc: Any) -> botocore.config.Config:
    kwargs: Dict[str, Any] = {
        "connect_timeout": options.connect_timeout, "read_timeout": options.read_timeout,
        "max_pool_connections": options.max_pool_connections,
    }
    retries = _retries(options, bc)
    if retries:
        kwargs["retries"] = retries
    app_id = _ua_app_id(options, bc)
    if app_id is not None:
        kwargs["user_agent_appid"] = app_id
    return botocore.config.Config(**kwargs)


def _probe_config() -> botocore.config.Config:
    return botocore.config.Config(connect_timeout=3, read_timeout=5, retries={"total_max_attempts": 1,
                                                                               "mode": "standard"})


class _SharedCredentialProvider(botocore.credentials.CredentialProvider):
    """Hands every session of the run the one resolved ``Credentials`` object."""

    METHOD = "aws-enumerator-shared"
    CANONICAL_NAME = "aws-enumerator-shared"

    def __init__(self, credentials: Any):
        super().__init__()
        self._credentials = credentials

    def load(self) -> Any:
        return self._credentials


# ── the context ──────────────────────────────────────────────────────────────
class AwsContext(AwsProvider):
    """The run's AWS layer (``AwsProvider`` for collectors), built once per command."""

    def __init__(self, options: Optional[AwsOptions] = None):
        self.options = options or AwsOptions()
        self.rate_limiter: Optional[RateLimiter] = None
        self._base = self._new_botocore_session(shared=False)
        try:
            self._base.get_scoped_config()
        except botocore.exceptions.ProfileNotFound:
            raise AwsSetupError(f"AWS profile {self.options.profile!r} not found in the AWS config files") from None
        self._credentials = self._resolve_credentials()
        self.client_config = build_client_config(self.options, self._base)
        self._lock = threading.Lock()
        self._factory_sessions: Dict[str, Any] = {}
        self._clients: Dict[Tuple[str, str], Any] = {}

    # -- sessions -------------------------------------------------------------
    def _new_botocore_session(self, *, shared: bool = True, limited: bool = True) -> Any:
        bc = botocore.session.Session(profile=self.options.profile)
        if shared:
            bc.register_component("credential_provider",
                                  botocore.credentials.CredentialResolver([_SharedCredentialProvider(self._credentials)]))
            bc.set_default_client_config(self.client_config)
            if limited and self.rate_limiter is not None:
                self.rate_limiter.install(bc.get_component("event_emitter"))
        if not _user_setting(bc, "AWS_STS_REGIONAL_ENDPOINTS", "sts_regional_endpoints"):
            bc.set_config_variable("sts_regional_endpoints", "regional")
        return bc

    def _resolve_credentials(self) -> Any:
        try:
            creds = self._base.get_credentials()
        except botocore.exceptions.ProfileNotFound:
            raise AwsSetupError(f"AWS profile {self.options.profile!r} not found") from None
        except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as exc:
            raise AwsSetupError(f"cannot load AWS credentials ({type(exc).__name__})") from None
        if creds is None:
            raise AwsSetupError("no AWS credentials found (set AWS_PROFILE / --profile, or the AWS_* variables)")
        return creds

    def install_rate_limiter(self, limiter: Optional[RateLimiter]) -> None:
        """Use ``limiter`` for every session created from now on (call before the first client)."""
        self.rate_limiter = limiter

    def _factory(self, region: str) -> Any:
        sess = self._factory_sessions.get(region)
        if sess is None:
            sess = boto3.Session(botocore_session=self._new_botocore_session(), region_name=region)
            self._factory_sessions[region] = sess
        return sess

    def client(self, service: str, region: str) -> Any:
        """A cached client for ``(service, region)``; thread-safe after creation."""
        key = (service, region)
        with self._lock:
            cli = self._clients.get(key)
            if cli is None:
                cli = self._factory(region).client(service, region_name=region, config=self.client_config)
                self._clients[key] = cli
            return cli

    def probe_client(self, service: str, region: str) -> Any:
        """An uncached, unlimited client with short timeouts and no retries (region probes, preflight)."""
        sess = boto3.Session(botocore_session=self._new_botocore_session(limited=False), region_name=region)
        return sess.client(service, region_name=region, config=self.client_config.merge(_probe_config()))

    # -- configuration lookups ------------------------------------------------
    @property
    def profile_region(self) -> Optional[str]:
        try:
            value = self._base.get_scoped_config().get("region")
        except botocore.exceptions.ProfileNotFound:
            return None
        return str(value) if value else None

    def partition_for_region(self, region: str) -> Optional[str]:
        try:
            return self._base.get_partition_for_region(region)
        except Exception:  # noqa: BLE001 - unknown region names raise various botocore errors
            return None

    def identify(self, region: str) -> Identity:
        """``sts:GetCallerIdentity`` in ``region`` (the home region): fatal on any failure."""
        try:
            response = self.client("sts", region).get_caller_identity()
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
            code = error_code_of(exc) or type(exc).__name__
            raise AwsSetupError(f"sts:GetCallerIdentity failed in {region} ({code}); check the credentials "
                                f"and the region") from None
        return Identity.from_sts(response)


# ── regions ──────────────────────────────────────────────────────────────────
def validate_region(region: str, flag: str) -> str:
    region = region.strip()
    if not REGION_RE.match(region):
        raise RegionUsageError(f"{flag}: {region!r} is not a region name (e.g. eu-west-2)")
    return region


def home_region_from_env(aws: Optional[AwsContext]) -> Optional[str]:
    """``AWS_REGION``, ``AWS_DEFAULT_REGION``, then the profile's ``region`` (cli.md §3.1)."""
    for name in ("AWS_REGION", "AWS_DEFAULT_REGION"):
        if os.environ.get(name):
            return os.environ[name].strip()
    return aws.profile_region if aws is not None else None


#: Shipped region list (``util/regions.json``): supplements botocore's endpoint data in the offline fallback.
SHIPPED_REGIONS = Path(__file__).resolve().parent / "util" / "regions.json"
_PARTITION_PREFIXES = (("cn-", "aws-cn"), ("us-gov-", "aws-us-gov"), ("us-isob-", "aws-iso-b"),
                       ("us-iso-", "aws-iso"), ("eu-isoe-", "aws-iso-e"), ("us-isof-", "aws-iso-f"),
                       ("eusc-", "aws-eusc"))


def _partition_of(region: str) -> str:
    return next((part for prefix, part in _PARTITION_PREFIXES if region.startswith(prefix)), "aws")


def shipped_regions(partition: str) -> List[str]:
    """Region codes of ``util/regions.json`` that belong to ``partition`` (F-140; empty when unreadable)."""
    try:
        records = json.loads(SHIPPED_REGIONS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    codes = {str(r.get("code")) for r in records if isinstance(r, dict) and isinstance(r.get("code"), str)}
    return sorted(c for c in codes if REGION_RE.match(c) and _partition_of(c) == partition)


def available_regions(partition: str, service: str = "ec2") -> List[str]:
    """Offline candidate regions for ``partition``: botocore's endpoint data plus the shipped region list."""
    known = botocore.session.get_session().get_available_regions(service, partition_name=partition)
    return sorted(set(known) | set(shipped_regions(partition)))


def describe_enabled_regions(aws: AwsContext, region: str) -> List[str]:
    """``ec2:DescribeRegions`` with the opt-in filter, called in ``region`` (the home region, F-064)."""
    resp = aws.client("ec2", region).describe_regions(Filters=OPT_IN_FILTER)
    return sorted(str(r["RegionName"]) for r in resp.get("Regions", []) if r.get("RegionName"))


def _probe_one(aws: AwsContext, region: str) -> Tuple[str, Optional[str]]:
    try:
        aws.probe_client("sts", region).get_caller_identity()
        return region, None
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
        return region, error_code_of(exc) or type(exc).__name__


def probe_regions(aws: AwsContext, candidates: Sequence[str]) -> Tuple[List[str], List[Dict[str, str]]]:
    """Regions whose regional STS endpoint accepts the credentials (opt-in regions that are not enabled fail)."""
    with ThreadPoolExecutor(max_workers=_PROBE_WORKERS, thread_name_prefix="region-probe") as pool:
        results = list(pool.map(lambda r: _probe_one(aws, r), candidates))
    ok = sorted(r for r, err in results if err is None)
    skipped = [{"region": r, "reason": f"sts probe failed ({err})"} for r, err in sorted(results) if err]
    return ok, skipped


@dataclass
class RegionPlan:
    """The regional units of a run (``manifest.target``)."""

    home_region: str
    regions: List[str]
    region_source: str
    regions_requested: List[str]
    regions_skipped: List[Dict[str, str]] = field(default_factory=list)


def _discover_all(aws: AwsContext, identity: Identity, home: str) -> Tuple[List[str], str, List[Dict[str, str]]]:
    import aws_enumerator.aws_session as this  # looked up at call time: tests patch describe_enabled_regions

    try:
        return this.describe_enabled_regions(aws, home), "describe_regions", []
    except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as exc:
        _status, code, fatal = classify(exc, "ec2:DescribeRegions")
        if fatal:
            raise AwsSetupError(f"ec2:DescribeRegions failed ({code}): credentials expired or invalid") from None
        log.warning("ec2:DescribeRegions failed in %s (%s); probing %s regions with sts:GetCallerIdentity",
                    home, code, identity.partition)
    ok, skipped = probe_regions(aws, available_regions(identity.partition))
    return ok, "fallback:sts-probe", skipped


def plan_regions(aws: AwsContext, identity: Identity, *, home_region: str, region: Optional[str],
                 regions: Sequence[str], all_regions: bool, exclude: Sequence[str]) -> RegionPlan:
    """Resolve ``--region`` / ``--regions`` / ``--all`` (+ ``--exclude-regions``) into a :class:`RegionPlan`."""
    if all_regions:
        found, source, skipped = _discover_all(aws, identity, home_region)
        excluded = set(exclude)
        skipped = skipped + [{"region": r, "reason": "excluded by --exclude-regions"}
                             for r in sorted(excluded & set(found))]
        return RegionPlan(home_region, sorted(set(found) - excluded), source, ["all"],
                          sorted(skipped, key=lambda s: s["region"]))
    if region or regions:
        wanted = [region] if region else list(dict.fromkeys(regions))
        for name in wanted:
            part = aws.partition_for_region(name)
            if part is not None and part != identity.partition:
                raise RegionUsageError(f"region {name!r} is in partition {part}, but the credentials are for "
                                       f"{identity.partition}")
        return RegionPlan(home_region, sorted(wanted), "explicit", list(wanted))
    return RegionPlan(home_region, [home_region], "profile", [])
