"""Defensive-posture analyzer (E-net, Wave 2; F-045, F-046, F-047): logging, detection and WAF coverage.

Findings only (the posture nodes are anchors, nothing here is graph-traversable), read from ``ctx.data["posture"]``
(explicit regions only) plus the EC2 / edge-services loader data for VPC, load balancer and instance context:

* **CloudTrail** — per analysed region, is some trail that logs management events delivering for it? Trails are
  listed with shadow trails (multi-region trails homed elsewhere, other accounts' organization trails), so an
  organization trail of the management account covers a member account (F-045); a shadow trail's status is read
  from its home region when that region was analysed, else it is *unverified* (conditional). ``CLOUDTRAIL-001``
  (region without logging), ``CLOUDTRAIL-002`` (``IsLogging`` false, F-047), ``CLOUDTRAIL-003`` (management events
  ``WriteOnly``: reads such as this tool's are not logged), ``CLOUDTRAIL-004`` (no trail records data events).
  Trails are ``trail`` nodes; region findings anchor at ``aws-enumerator:region/<acct>/<region>``.
* **VPC flow logs** — ``FLOWLOGS-001`` for a VPC with no active flow log on the VPC or any of its subnets.
* **WAF** — ``WAF-001`` for an internet-facing application load balancer, a public REST API stage or an enabled
  CloudFront distribution without a web ACL (regional associations, stage ``WebAclArn``, distribution
  ``WebACLId``). Enabled distributions also get ``anonymous -PUBLIC_INBOUND-> distribution`` (exposure, F-070).
* **Detection services** — ``GUARDDUTY-001``, ``CONFIG-001``, ``SECURITYHUB-001``, ``ACCESSANALYZER-001`` per region.

Unknown is never "off": a listing that was denied, failed or not collected gives no finding (the coverage-gap
findings are E-compute's ``coverage_gaps``). Old (d13c215) reports listed trails without shadow trails and lost
every trail's status (F-045, F-047), so their CloudTrail findings are conditional.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from aws_enumerator.engine.findings.catalog import A_METHOD, CatalogEntry
from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.io.loaders.ec2 import document, table, table_status, units_of
from aws_enumerator.engine.model import AnalyzerSkipped, AnalyzerSpec, Phase

log = logging.getLogger(__name__)

_KNOWN = frozenset({"complete", "partial"})


def _e(fid: str, severity: str, category: str, title: str, remediation: str) -> CatalogEntry:
    return CatalogEntry(fid, severity, category, title, remediation, A_METHOD)


FINDINGS: Tuple[CatalogEntry, ...] = (
    _e("CLOUDTRAIL-001", "HIGH", "posture_logging", "No CloudTrail trail logs this region",
       "Create a multi-region trail (or an organization trail) that logs management events, with log file "
       "validation and a protected destination bucket."),
    _e("CLOUDTRAIL-002", "HIGH", "posture_logging", "CloudTrail trail is not logging",
       "Start logging on the trail (cloudtrail:StartLogging) and alert on StopLogging / DeleteTrail."),
    _e("CLOUDTRAIL-003", "MEDIUM", "posture_logging", "CloudTrail trail logs write management events only",
       "Log read and write management events (ReadWriteType All) so that reconnaissance is recorded."),
    _e("CLOUDTRAIL-004", "LOW", "posture_logging", "No CloudTrail trail records data events",
       "Add data-event selectors (S3 objects, Lambda invocations) for the sensitive resources."),
    _e("FLOWLOGS-001", "MEDIUM", "posture_logging", "VPC has no flow logs",
       "Enable VPC flow logs (at least REJECT traffic, preferably ALL) to a protected destination."),
    _e("WAF-001", "MEDIUM", "posture_waf", "Internet-facing endpoint without a WAF web ACL",
       "Associate an AWS WAF web ACL (managed rule groups for common exploits and bad inputs) with the endpoint."),
    _e("GUARDDUTY-001", "MEDIUM", "posture_detection", "GuardDuty is not enabled in this region",
       "Enable GuardDuty in every region (organization-wide through a delegated administrator)."),
    _e("CONFIG-001", "LOW", "posture_detection", "AWS Config is not recording in this region",
       "Enable an AWS Config recorder for all resource types and a delivery channel."),
    _e("SECURITYHUB-001", "LOW", "posture_detection", "Security Hub is not enabled in this region",
       "Enable Security Hub with the AWS Foundational Security Best Practices standard."),
    _e("ACCESSANALYZER-001", "LOW", "posture_detection", "No IAM Access Analyzer for external access in this region",
       "Create an account (or organization) analyzer for external access in every region."),
)


# ── anchors ──────────────────────────────────────────────────────────────────

def region_anchor(ctx: Any, builder: Any, region: str) -> str:
    node = ids.region_anchor_id(ctx.account_id, region)
    builder.add_node(node, "region", region, region=region, account=ctx.account_id)
    return node


def account_anchor(ctx: Any, builder: Any) -> str:
    node = ids.account_anchor_id(ctx.account_id)
    builder.add_node(node, "account", f"Account {ctx.account_id}", account=ctx.account_id)
    return node


def _regions(data: Any, *keys: str) -> List[str]:
    return sorted({u for k in keys for u in units_of(data, k) if u != "global"})


def _known(data: Any, key: str, unit: str) -> bool:
    return table_status(data, key, unit) in _KNOWN


# ══════════════════════════════════════════════════════════════════════════════
# CloudTrail (F-045, F-046, F-047)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Trail:
    """One trail, merged over every region that listed it (home-region details win)."""

    arn: str
    record: Dict[str, Any]
    seen_in: Set[str] = field(default_factory=set)
    detailed: bool = False                  # the record comes from the trail's home region (status read there)

    @property
    def home(self) -> Optional[str]:
        return self.record.get("HomeRegion") or None

    @property
    def multi_region(self) -> bool:
        return bool(self.record.get("IsMultiRegionTrail"))

    @property
    def logging(self) -> Optional[bool]:
        status = self.record.get("Status")
        value = status.get("IsLogging") if isinstance(status, Mapping) else None
        return value if isinstance(value, bool) else None

    def covers(self, region: str) -> bool:
        return self.multi_region or self.home == region or (self.home is None and region in self.seen_in)


def management_events(rec: Mapping[str, Any]) -> Optional[str]:
    """``all`` / ``write-only`` / ``read-only`` / ``none``, or ``None`` when the selectors are unknown."""
    advanced = rec.get("AdvancedEventSelectors")
    basic = rec.get("EventSelectors")
    if isinstance(advanced, list) and advanced:
        modes = set()
        for sel in advanced:
            fields = {f.get("Field"): f for f in sel.get("FieldSelectors") or () if isinstance(f, Mapping)} \
                if isinstance(sel, Mapping) else {}
            if "Management" not in ((fields.get("eventCategory") or {}).get("Equals") or ()):
                continue
            ro = (fields.get("readOnly") or {}).get("Equals")
            modes.add("all" if not ro else ("read-only" if ro == ["true"] else "write-only"))
        return _combine_modes(modes)
    if isinstance(basic, list):
        modes = {{"All": "all", "ReadOnly": "read-only", "WriteOnly": "write-only"}.get(
            str(s.get("ReadWriteType") or "All"), "all") for s in basic
            if isinstance(s, Mapping) and s.get("IncludeManagementEvents", True)}
        return _combine_modes(modes)
    if rec.get("HasCustomEventSelectors") is False:
        return "all"                       # the default selector: all management events
    return None


def _combine_modes(modes: Set[str]) -> str:
    if not modes:
        return "none"
    if "all" in modes or {"read-only", "write-only"} <= modes:
        return "all"
    return modes.pop()


def data_events(rec: Mapping[str, Any]) -> Optional[bool]:
    advanced = rec.get("AdvancedEventSelectors")
    if isinstance(advanced, list) and advanced:
        return any("Data" in ((f.get("Equals") or ()) if f.get("Field") == "eventCategory" else ())
                   for sel in advanced if isinstance(sel, Mapping)
                   for f in sel.get("FieldSelectors") or () if isinstance(f, Mapping))
    basic = rec.get("EventSelectors")
    if isinstance(basic, list):
        return any(s.get("DataResources") for s in basic if isinstance(s, Mapping))
    return False if rec.get("HasCustomEventSelectors") is False else None


def collect_trails(data: Any, regions: Iterable[str]) -> Dict[str, Trail]:
    trails: Dict[str, Trail] = {}
    for region in regions:
        for rec in table(data, "trails", region):
            arn = str(rec.get("TrailARN") or rec.get("Name") or "")
            if not arn:
                continue
            home = rec.get("HomeRegion")
            detailed = (home == region or home is None) and not rec.get("IsShadow")
            t = trails.get(arn)
            if t is None:
                t = trails[arn] = Trail(arn, dict(rec), detailed=detailed)
            elif detailed and not t.detailed:
                t.record, t.detailed = dict(rec), True
            t.seen_in.add(region)
    return trails


class TrailAnalysis:
    """CloudTrail coverage of the analysed regions (module docstring)."""

    def __init__(self, ctx: Any, builder: Any, data: Any):
        self.ctx, self.builder, self.data = ctx, builder, data
        self.regions = [r for r in _regions(data, "trails") if table_status(data, "trails", r) != "missing"]
        self.trails = collect_trails(data, self.regions)
        self.legacy = bool(getattr(ctx, "is_legacy", False))
        self.nodes: Dict[str, str] = {}

    def trail_node(self, t: Trail) -> Optional[str]:
        if t.arn in self.nodes:
            return self.nodes[t.arn]
        if not ids.node_id_matches("trail", t.arn):
            return None
        rec = t.record
        props = {"home_region": t.home, "multi_region": t.multi_region,
                 "organization_trail": bool(rec.get("IsOrganizationTrail")), "shadow": bool(rec.get("IsShadow")),
                 "is_logging": t.logging, "management_events": management_events(rec),
                 "data_events": data_events(rec), "log_file_validation": rec.get("LogFileValidationEnabled"),
                 "s3_bucket": rec.get("S3BucketName")}
        self.builder.add_node(t.arn, "trail", str(rec.get("Name") or t.arn), region=t.home,
                              props={k: v for k, v in props.items() if v is not None},
                              coverage_status=None if t.detailed else "partial",
                              coverage_gaps=() if t.detailed else ("cloudtrail:details-in-home-region",))
        self.nodes[t.arn] = t.arn
        return t.arn

    def run(self) -> None:
        for t in sorted(self.trails.values(), key=lambda x: x.arn):
            node = self.trail_node(t)
            if node is not None:
                self._trail_findings(t, node)
        for region in self.regions:
            if _known(self.data, "trails", region):
                self._region(region)
        self._data_events()

    def _trail_findings(self, t: Trail, node: str) -> None:
        name = str(t.record.get("Name") or t.arn)
        if t.detailed and t.logging is False:
            self.builder.add_finding(
                "CLOUDTRAIL-002", node, severity="HIGH", title=f"CloudTrail trail '{name}' is not logging",
                description=f"Trail '{name}' exists but IsLogging is false: no events are delivered.",
                evidence={"status": t.record.get("Status")}, region=t.home)
        mode = management_events(t.record) if t.detailed else None
        if mode == "write-only" and t.logging is not False:
            self.builder.add_finding(
                "CLOUDTRAIL-003", node, severity="MEDIUM", title=f"Trail '{name}' logs write management events only",
                description=f"Trail '{name}' records only write management events: read calls (Describe*, List*, "
                            "Get*), the bulk of an enumeration, leave no trace.",
                evidence={"management_events": mode}, region=t.home)

    def _region(self, region: str) -> None:
        covering = [t for t in self.trails.values() if t.covers(region)]
        modes = ("all", "read-only", "write-only")
        if any(t.logging is True and management_events(t.record) in modes for t in covering):
            return
        unverified = [t for t in covering if t.logging is not False and (t.logging is None
                                                                          or management_events(t.record) is None)]
        if unverified:
            severity, conditional = "INFO", True
            why = (f"{len(unverified)} trail(s) cover this region but their status or event selectors could not be "
                   "read here (for example another account's organization trail): logging is unverified")
        else:
            severity, conditional = ("MEDIUM", True) if self.legacy else ("HIGH", False)
            why = ("no trail covers this region" if not covering else
                   "no trail that covers this region is logging management events")
        if self.legacy:
            why += ("; this is an old report, which listed trails without shadow / organization trails and lost every "
                    "trail's status (F-045, F-047): re-collect to confirm")
        self.builder.add_finding(
            "CLOUDTRAIL-001", region_anchor(self.ctx, self.builder, region), severity=severity, base_severity="HIGH",
            title=f"No CloudTrail trail is verified logging region {region}", description=f"In region {region}, {why}.",
            confidence="conditional" if conditional else "definite",
            evidence={"trails": sorted(t.arn for t in covering), "unverified": sorted(t.arn for t in unverified)},
            region=region, gaps=["cloudtrail:legacy-layout"] if self.legacy else [])

    def _data_events(self) -> None:
        active = [t for t in self.trails.values() if t.detailed and t.logging is True]
        if not active or self.legacy:
            return
        flags = [data_events(t.record) for t in active]
        if any(flags) or any(f is None for f in flags):
            return
        self.builder.add_finding(
            "CLOUDTRAIL-004", account_anchor(self.ctx, self.builder), severity="LOW",
            title="No CloudTrail trail records data events",
            description="None of the logging trails has data-event selectors: S3 object reads/writes and Lambda "
                        "invocations are not recorded.", evidence={"trails": sorted(t.arn for t in active)})


# ══════════════════════════════════════════════════════════════════════════════
# Flow logs, WAF, detection services
# ══════════════════════════════════════════════════════════════════════════════

def vpc_node(ctx: Any, builder: Any, region: str, vpc: Mapping[str, Any]) -> Optional[str]:
    vid = str(vpc.get("VpcId") or "")
    try:
        node = ids.node_id_for("vpc", partition=ctx.partition, region=region, account=ctx.account_id, id=vid)
    except ValueError:
        return None
    name = next((str(t.get("Value")) for t in vpc.get("Tags") or () if isinstance(t, Mapping)
                 and t.get("Key") == "Name" and t.get("Value")), vid)
    builder.add_node(node, "vpc", name, region=region, props={"cidr": vpc.get("CidrBlock"),
                                                              "is_default": bool(vpc.get("IsDefault"))})
    return node


def flow_logs(ctx: Any, builder: Any, data: Any, ec2: Any, region: str) -> None:
    if not (_known(data, "vpcs", region) and _known(data, "flow_logs", region)):
        return
    subnet_vpc = {str(s.get("SubnetId")): str(s.get("VpcId")) for s in table(ec2, "subnets", region)}
    covered: Set[str] = set()
    for fl in table(data, "flow_logs", region):
        if str(fl.get("FlowLogStatus") or "ACTIVE").upper() != "ACTIVE":
            continue
        rid = str(fl.get("ResourceId") or "")
        covered.add(subnet_vpc.get(rid, rid))
    used = {str(i.get("VpcId")) for i in table(ec2, "instances", region)}
    for vpc in table(data, "vpcs", region):
        vid = str(vpc.get("VpcId") or "")
        if not vid or vid in covered:
            continue
        node = vpc_node(ctx, builder, region, vpc)
        if node is None:
            continue
        idle_default = bool(vpc.get("IsDefault")) and vid not in used
        builder.add_finding(
            "FLOWLOGS-001", node, severity="INFO" if idle_default else "MEDIUM", base_severity="MEDIUM",
            title=f"VPC {vid} has no flow logs",
            description=f"No active flow log on VPC '{vid}' or any of its subnets: network activity in it is not "
                        "recorded" + (" (an unused default VPC)." if idle_default else "."),
            evidence={"is_default": bool(vpc.get("IsDefault")), "instances": vid in used}, region=region)


def _waf_associations(data: Any, key: str, unit: str) -> Tuple[Set[str], Set[str]]:
    """``(associated resource ARNs, resource types whose associations are unknown)``."""
    arns: Set[str] = set()
    unknown: Set[str] = set()
    for acl in table(data, key, unit):
        assoc = acl.get("AssociatedResources")
        if assoc is None:
            unknown.add("*")
            continue
        arns.update(str(a.get("Arn")) for a in assoc if isinstance(a, Mapping) and a.get("Arn"))
        unknown.update(str(t) for t in acl.get("UncheckedResourceTypes") or ())
    return arns, unknown


def _waf_finding(builder: Any, node: str, region: Optional[str], what: str, evidence: Mapping[str, Any],
                 conditional: bool = False) -> None:
    builder.add_finding(
        "WAF-001", node, severity="MEDIUM", title=f"{what} has no WAF web ACL",
        description=f"{what} is reachable from the internet and no AWS WAF web ACL inspects its requests.",
        confidence="conditional" if conditional else "definite", evidence=dict(evidence), region=region,
        gaps=["waf:associations-unknown"] if conditional else [])


def waf_regional(ctx: Any, builder: Any, data: Any, edge: Any, region: str) -> None:
    if not _known(data, "web_acls", region):
        return
    arns, unknown = _waf_associations(data, "web_acls", region)
    for lb in table(edge, "elb", region):
        arn = str(lb.get("Arn") or "")
        if (str(lb.get("Scheme") or "").lower() != "internet-facing" or str(lb.get("LBType")) != "application"
                or not ids.node_id_matches("elb", arn) or arn in arns):
            continue
        builder.add_node(arn, "elb", str(lb.get("Name") or arn), region=region, account=ctx.account_id)
        _waf_finding(builder, arn, region, f"Internet-facing load balancer '{lb.get('Name') or arn}'",
                     {"resource_type": "APPLICATION_LOAD_BALANCER"},
                     conditional=bool(unknown & {"*", "APPLICATION_LOAD_BALANCER"}))
    for api in table(data, "apis", region):
        _api_waf(ctx, builder, api, region, arns, bool(unknown & {"*", "API_GATEWAY"}))


def _api_waf(ctx: Any, builder: Any, api: Mapping[str, Any], region: str, arns: Set[str], unknown: bool) -> None:
    arn = str(api.get("Arn") or "")
    if str(api.get("Protocol") or "REST") != "REST" or not ids.node_id_matches("apigw", arn):
        return                                         # WAF supports REST APIs only
    if "PRIVATE" in (api.get("EndpointTypes") or ()):
        return
    stages = api.get("Stages")
    if not isinstance(stages, list):
        return
    open_stages = sorted(str(s.get("StageName")) for s in stages if isinstance(s, Mapping) and not s.get("WebAclArn")
                         and f"{arn}/stages/{s.get('StageName')}" not in arns)
    if not open_stages:
        return
    builder.add_node(arn, "apigw", str(api.get("Name") or arn), region=region, account=ctx.account_id)
    _waf_finding(builder, arn, region, f"REST API '{api.get('Name') or arn}' (stages {', '.join(open_stages)})",
                 {"resource_type": "API_GATEWAY", "stages": open_stages}, conditional=unknown)


def waf_cloudfront(ctx: Any, builder: Any, data: Any) -> None:
    acls_known = _known(data, "web_acls_cloudfront", "global")
    for dist in table(data, "distributions", "global"):
        arn = str(dist.get("ARN") or dist.get("Arn") or "")
        if not ids.node_id_matches("cloudfront", arn) or dist.get("Enabled") is False:
            continue
        builder.add_node(arn, "cloudfront", str(dist.get("DomainName") or arn), account=ctx.account_id,
                         props={k: v for k, v in {"domain_name": dist.get("DomainName"),
                                                  "web_acl": dist.get("WebACLId") or None}.items() if v is not None})
        builder.add_edge(ids.ANONYMOUS_ID, "PUBLIC_INBOUND", arn, evidence={"domain_name": dist.get("DomainName")},
                         props={"technique": "internet-inbound"})
        if dist.get("WebACLId"):
            continue
        _waf_finding(builder, arn, None, f"CloudFront distribution '{dist.get('DomainName') or arn}'",
                     {"resource_type": "CLOUDFRONT"}, conditional=not acls_known and "WebACLId" not in dist)


def detection(ctx: Any, builder: Any, data: Any, region: str) -> None:
    """GuardDuty, Config, Security Hub and Access Analyzer per region (only from data that was read)."""
    checks: List[Tuple[str, str, str]] = []
    if _known(data, "guardduty", region):
        detectors = table(data, "guardduty", region)
        if not any(str(d.get("Status") or "").upper() == "ENABLED" for d in detectors) and \
                not any(d.get("Status") is None for d in detectors):
            checks.append(("GUARDDUTY-001", "GuardDuty is not enabled", "no enabled GuardDuty detector"))
    if _known(data, "config", region):
        recs = table(data, "config", region)
        status = [r.get("status") for r in recs]
        if not recs or (all(isinstance(s, Mapping) for s in status)
                        and not any(s.get("recording") for s in status)):
            checks.append(("CONFIG-001", "AWS Config is not recording",
                           "no configuration recorder" if not recs else "the recorder is stopped"))
    hub = document(data, "securityhub", region)
    if hub is not None and hub.get("Enabled") is False:
        checks.append(("SECURITYHUB-001", "Security Hub is not enabled", "the account is not subscribed"))
    if _known(data, "access_analyzers", region):
        active = [a for a in table(data, "access_analyzers", region)
                  if str(a.get("type")) in ("ACCOUNT", "ORGANIZATION") and str(a.get("status")) == "ACTIVE"]
        if not active:
            checks.append(("ACCESSANALYZER-001", "No IAM Access Analyzer for external access",
                           "no active ACCOUNT or ORGANIZATION analyzer"))
    for fid, title, why in checks:
        builder.add_finding(fid, region_anchor(ctx, builder, region), severity=_severity(fid),
                            title=f"{title} in {region}", description=f"In region {region}: {why}.",
                            evidence={"region": region}, region=region)


def _severity(fid: str) -> str:
    return next(e.severity for e in FINDINGS if e.id == fid)


# ── the analyzer ─────────────────────────────────────────────────────────────

def run_posture(ctx: Any, builder: Any) -> None:
    """Phase RESOURCES: posture findings (module docstring)."""
    data = (ctx.data or {}).get("posture")
    if not isinstance(data, Mapping):
        raise AnalyzerSkipped("posture", reason="no posture data was loaded")
    ec2 = (ctx.data or {}).get("ec2")
    edge = (ctx.data or {}).get("edge_services")
    TrailAnalysis(ctx, builder, data).run()
    for region in _regions(data, "trails", "vpcs", "web_acls", "guardduty", "config", "access_analyzers"):
        flow_logs(ctx, builder, data, ec2, region)
        waf_regional(ctx, builder, data, edge, region)
        detection(ctx, builder, data, region)
    waf_cloudfront(ctx, builder, data)


ANALYZERS: Tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec("posture", Phase.RESOURCES, run_posture,
                 inputs=("cloudtrail", "flowlogs", "waf", "cloudfront", "guardduty", "config", "securityhub",
                         "accessanalyzer")),
)

__all__ = ["ANALYZERS", "FINDINGS", "Trail", "collect_trails", "data_events", "management_events", "run_posture"]
