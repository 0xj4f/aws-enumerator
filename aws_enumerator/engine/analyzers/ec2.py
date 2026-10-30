"""EC2 analyzer (E-net, Wave 2): instances, their roles, who controls them and who can reach them from the internet.

Native on the policy evaluator and :class:`~aws_enumerator.engine.graph.builder.GraphBuilder` (engine.md §5 "S3 and
EC2", §6.3; ``requests/e-policy-1.md``). Reads ``ctx.data["ec2"]`` (explicit regions only, F-010/F-025/F-063), in
the d13c215 and the Wave 1 (C-A) layouts.

* **INSTANCE_ROLE** (``instance → role``, the bridge): the instance profile is resolved to its role by exact ARN
  through the collected instance profiles; ``EC2-PROFILE-001`` when it cannot be (deleted profile, listing denied).
* **Principal → instance** through ``ctx.evaluator`` per action on the instance ARN (F-001, F-014, F-015, F-075:
  service, resource type, region and account are matched by the evaluator, never by substring), one edge per
  (principal, type, instance) with no ``break`` (F-003): ``EC2_FULL_ACCESS`` (``ec2:*`` including the user-data
  chain), ``CAN_MODIFY_USERDATA`` (``ModifyInstanceAttribute`` + ``StopInstances`` + ``StartInstances``, control),
  ``CAN_CONNECT`` (SSM session / command, EC2 Instance Connect; conditional when the instance is known not to be
  SSM-managed), and the info types ``CAN_MANAGE`` and ``CAN_TERMINATE`` (F-004). ``CAN_LAUNCH`` is not emitted:
  ``RunInstances`` with a role is the rules engine's ``CAN_PASS_ROLE_TO``. ``CAN_ADMIN_SG`` targets the security
  group (F-004).
* **Network exposure** (F-070, F-076, F-077, F-105, F-046's NACL part): an instance is reachable from the internet
  when it has a public address (public IPv4, Elastic IP, ENI association or secondary address, or a global IPv6
  address), its security groups admit the whole address space on some port (CIDRs collapsed with :mod:`ipaddress`,
  so ``0.0.0.0/1`` + ``128.0.0.0/1`` is open; ``::/0``; customer prefix lists resolved, AWS-managed ones
  ``unresolved``), the subnet's **effective** route table (explicit association, else the VPC's main table) routes
  that family to an attached internet gateway (blackhole routes ignored), and the subnet's NACL lets the traffic in.
  That is ``anonymous -PUBLIC_INBOUND-> instance`` (exposure, not traversable) plus ``EC2-EXPOSURE-001``; unknown
  inputs make the edge conditional, never absent. ``INTERNET_FACING`` is ``props.igw_routed`` (``EC2-INET-001``).
* **IMDS** (F-078, F-106): ``EC2-IMDS-001`` only for instances that are not terminated or shutting down and whose
  metadata endpoint is enabled; worded and graded by whether the instance has a role. ``SSRF_TO_IMDS``
  (``anonymous → instance``, always conditional) only for running, publicly reachable IMDSv1 instances with a role.
* ``HAS_SG``, ``SG_ALLOWS_FROM``; launch templates as nodes (instance profile, IMDS, user-data presence);
  ``EC2-USERDATA-001`` (INFO) where user data is present (its content is never collected); public AMIs
  (``anonymous -AMI_SHARED_PUBLIC-> ami``, ``AMI-PUB-001``) and AMIs shared with other accounts (``AMI-XACCT-001``)
  (F-116).

AMIs shared with named accounts also get ``external_account -AMI_SHARED_CROSS_ACCOUNT-> ami`` (F-116, D-52).

The legacy ``ec2_relationships.json`` (one release) is rendered from these edges (s3.py ``store_legacy_file``).
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from aws_enumerator.engine.analyzers.s3 import (
    AccessClass, PrincipalAccess, Resolve, as_conditional, layout_status, legacy_evidence, lower_severity,
    store_legacy_file,
)
from aws_enumerator.engine.findings.catalog import A_EC2, A_EXPOSURE, CatalogEntry
from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.io.loaders.ec2 import document, table, table_status, units_of
from aws_enumerator.engine.model import AnalyzerSkipped, AnalyzerSpec, EvalResult, Phase, Strength

log = logging.getLogger(__name__)

LEGACY_FILE = "ec2_relationships.json"
_GONE = frozenset({"terminated", "shutting-down"})
_ALIVE = frozenset({"running", "pending"})
_KNOWN = frozenset({"complete", "partial"})

FINDINGS: Tuple[CatalogEntry, ...] = (
    CatalogEntry("EC2-PROFILE-001", "MEDIUM", "ec2_misconfig", "Instance has an unresolved instance profile",
                 "Verify the instance profile exists and contains a role; ensure the enumerator has "
                 "iam:ListInstanceProfiles permission.", A_EC2),
    CatalogEntry("EC2-EXPOSURE-001", "HIGH", "ec2_exposure", "Instance is reachable from the internet",
                 "Restrict the security-group ingress to specific source ranges, or move the instance behind a load "
                 "balancer in a private subnet.", A_EC2),
    CatalogEntry("EC2-INET-001", "MEDIUM", "ec2_exposure", "Instance has a public address in an internet-routed subnet",
                 "Move the instance to a private subnet or remove its public address.", A_EC2),
    CatalogEntry("EC2-IMDS-001", "MEDIUM", "ec2_imds", "Instance allows IMDSv1",
                 "Set HttpTokens to 'required' to enforce IMDSv2 (or disable the metadata endpoint).", A_EC2),
    CatalogEntry("EC2-USERDATA-001", "INFO", "ec2_userdata", "User data is present (may hold secrets)",
                 "Review the user data for embedded credentials; move secrets to Secrets Manager or SSM "
                 "SecureString parameters read at boot.", A_EC2),
    CatalogEntry("AMI-PUB-001", "HIGH", "ami_public", "AMI is shared publicly",
                 "Make the AMI private (remove the 'all' launch permission) and turn on AMI Block Public Access.",
                 A_EXPOSURE),
    CatalogEntry("AMI-XACCT-001", "MEDIUM", "ami_cross_account", "AMI is shared with another account",
                 "Verify the cross-account launch permission is intended.", A_EXPOSURE,
                 discriminator="target-account"),
)


# ══════════════════════════════════════════════════════════════════════════════
# Network model (per region)
# ══════════════════════════════════════════════════════════════════════════════

_PROTO = {"tcp": "6", "udp": "17", "icmp": "1", "icmpv6": "58", "-1": "-1", "all": "-1"}
_BROAD_PREFIX = {4: 8, 6: 16}
_DEFAULT = {4: ipaddress.ip_network("0.0.0.0/0"), 6: ipaddress.ip_network("::/0")}
Net = "ipaddress.IPv4Network | ipaddress.IPv6Network"


#: Address space that is never reached from the internet (RFC 1918, CGNAT, loopback, link-local, ULA).
_NON_INTERNET = {4: tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                                             "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16")),
                 6: tuple(ipaddress.ip_network(n) for n in ("fc00::/7", "fe80::/10", "::1/128"))}


def internet_capable(n: Any) -> bool:
    """True when ``n`` holds internet addresses (``ipaddress.is_private`` is True for 0.0.0.0/0, so it is not used)."""
    return not any(n.subnet_of(p) for p in _NON_INTERNET[n.version])


def _net(value: Any) -> Optional[Any]:
    try:
        return ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        return None


def _proto(value: Any) -> str:
    v = str(value if value is not None else "-1").lower()
    return _PROTO.get(v, v)


def _covers_default(nets: Iterable[Any], family: int) -> bool:
    same = [n for n in nets if n is not None and n.version == family]
    return any(c.prefixlen == 0 for c in ipaddress.collapse_addresses(same)) if same else False


@dataclass(frozen=True)
class Opening:
    """Security-group ingress open to (part of) the internet for one protocol and port range."""

    proto: str              # IANA number as text, "-1" = all
    lo: Optional[int]
    hi: Optional[int]
    family: int             # 4 | 6
    level: str              # "open" | "broad" | "unresolved"
    sources: Tuple[str, ...]
    groups: Tuple[str, ...]

    def text(self) -> str:
        if self.proto == "-1":
            return "all traffic"
        name = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}.get(self.proto, self.proto)
        if self.lo is None or self.lo < 0:
            return f"all/{name}"
        return f"{self.lo}/{name}" if self.lo == self.hi else f"{self.lo}-{self.hi}/{name}"


@dataclass
class RegionNet:
    """Routing, NACL, security-group and address data of one region (``None`` / ``False`` flags = unknown)."""

    region: str
    sgs: Dict[str, Mapping[str, Any]] = field(default_factory=dict)
    sgs_known: bool = False
    subnet_vpc: Dict[str, str] = field(default_factory=dict)
    rtb_explicit: Dict[str, Mapping[str, Any]] = field(default_factory=dict)
    rtb_main: Dict[str, Mapping[str, Any]] = field(default_factory=dict)
    routes_known: bool = False
    igw_vpcs: Optional[Dict[str, Set[str]]] = None
    nacl_explicit: Dict[str, Mapping[str, Any]] = field(default_factory=dict)
    nacl_default: Dict[str, Mapping[str, Any]] = field(default_factory=dict)
    nacls_known: bool = False
    prefix_lists: Dict[str, Optional[List[str]]] = field(default_factory=dict)
    eips: Dict[str, Set[str]] = field(default_factory=dict)          # instance id / ENI id -> public IPs
    managed: Optional[Set[str]] = None                                # SSM-managed instance ids

    @classmethod
    def build(cls, data: Mapping[str, Any], region: str) -> "RegionNet":
        net = cls(region)
        net.sgs = {str(g["GroupId"]): g for g in table(data, "security_groups", region) if g.get("GroupId")}
        net.sgs_known = table_status(data, "security_groups", region) in _KNOWN
        net.subnet_vpc = {str(s["SubnetId"]): str(s.get("VpcId")) for s in table(data, "subnets", region)
                          if s.get("SubnetId")}
        net._routes(data)
        net._nacls(data)
        for pl in table(data, "prefix_lists", region):
            entries = pl.get("Entries")
            net.prefix_lists[str(pl.get("PrefixListId"))] = (
                [str(e.get("Cidr")) for e in entries if isinstance(e, Mapping)] if isinstance(entries, list) else None)
        for eip in table(data, "elastic_ips", region):
            ip = eip.get("PublicIp")
            for key in ("InstanceId", "NetworkInterfaceId"):
                if ip and eip.get(key):
                    net.eips.setdefault(str(eip[key]), set()).add(str(ip))
        if table_status(data, "managed_instances", region) in _KNOWN:
            net.managed = {str(m.get("InstanceId")) for m in table(data, "managed_instances", region)}
        return net

    def _routes(self, data: Mapping[str, Any]) -> None:
        self.routes_known = table_status(data, "route_tables", self.region) in _KNOWN
        for rtb in table(data, "route_tables", self.region):
            for assoc in rtb.get("Associations") or ():
                if not isinstance(assoc, Mapping):
                    continue
                if assoc.get("Main"):
                    self.rtb_main[str(rtb.get("VpcId"))] = rtb
                elif assoc.get("SubnetId"):
                    self.rtb_explicit[str(assoc["SubnetId"])] = rtb
        if table_status(data, "internet_gateways", self.region) in _KNOWN:
            self.igw_vpcs = {}
            for igw in table(data, "internet_gateways", self.region):
                vpcs = {str(a.get("VpcId")) for a in igw.get("Attachments") or ()
                        if isinstance(a, Mapping) and str(a.get("State") or "available") in ("available", "attached")}
                self.igw_vpcs[str(igw.get("InternetGatewayId"))] = vpcs

    def _nacls(self, data: Mapping[str, Any]) -> None:
        self.nacls_known = table_status(data, "nacls", self.region) in _KNOWN
        for acl in table(data, "nacls", self.region):
            if acl.get("IsDefault"):
                self.nacl_default[str(acl.get("VpcId"))] = acl
            for assoc in acl.get("Associations") or ():
                if isinstance(assoc, Mapping) and assoc.get("SubnetId"):
                    self.nacl_explicit[str(assoc["SubnetId"])] = acl

    # routing ----------------------------------------------------------------
    def route(self, subnet: Optional[str], vpc: Optional[str], family: int) -> str:
        """``full`` / ``partial`` / ``none`` / ``unknown``: does the effective table route ``family`` to an IGW?"""
        if not self.routes_known or not subnet:
            return "unknown"
        vpc = vpc or self.subnet_vpc.get(subnet)
        rtb = self.rtb_explicit.get(subnet) or self.rtb_main.get(str(vpc))
        if rtb is None:
            return "unknown"
        key = "DestinationCidrBlock" if family == 4 else "DestinationIpv6CidrBlock"
        dests = []
        for r in rtb.get("Routes") or ():
            gw = str(r.get("GatewayId") or "") if isinstance(r, Mapping) else ""
            if not gw.startswith("igw-") or str(r.get("State") or "active") == "blackhole":
                continue
            if self.igw_vpcs is not None and str(vpc) not in self.igw_vpcs.get(gw, set()):
                continue                                   # a detached gateway carries no traffic
            n = _net(r.get(key)) if r.get(key) else None
            if n is not None:
                dests.append(n)
        if not dests:
            return "none"
        return "full" if _covers_default(dests, family) else "partial"

    # NACLs ------------------------------------------------------------------
    def nacl_allows(self, subnet: Optional[str], vpc: Optional[str], o: Opening) -> Optional[bool]:
        """Does the subnet's NACL let some internet source in for ``o``? ``None`` = unknown."""
        if not self.nacls_known or not subnet:
            return None
        vpc = vpc or self.subnet_vpc.get(subnet)
        acl = self.nacl_explicit.get(subnet) or self.nacl_default.get(str(vpc))
        if acl is None:
            return None
        entries = [e for e in acl.get("Entries") or () if isinstance(e, Mapping) and not e.get("Egress")]
        for e in sorted(entries, key=lambda x: int(x.get("RuleNumber") or 0)):
            n = _net(e.get("CidrBlock") or e.get("Ipv6CidrBlock"))
            if n is None or n.version != o.family or not _nacl_matches(e, o):
                continue
            if str(e.get("RuleAction")).lower() == "allow":
                if internet_capable(n):
                    return True
                continue
            if n.prefixlen == 0 and _nacl_ports_cover(e, o):
                return False
        return False


def _nacl_matches(entry: Mapping[str, Any], o: Opening) -> bool:
    proto = _proto(entry.get("Protocol"))
    if proto != "-1" and o.proto != "-1" and proto != o.proto:
        return False
    rng = entry.get("PortRange") if isinstance(entry.get("PortRange"), Mapping) else None
    if rng is None or o.lo is None or o.lo < 0:
        return True
    return not (int(rng.get("To", 65535)) < o.lo or int(rng.get("From", 0)) > (o.hi if o.hi is not None else o.lo))


def _nacl_ports_cover(entry: Mapping[str, Any], o: Opening) -> bool:
    if _proto(entry.get("Protocol")) not in ("-1", o.proto):
        return False
    rng = entry.get("PortRange") if isinstance(entry.get("PortRange"), Mapping) else None
    if rng is None:
        return True
    if o.lo is None or o.lo < 0:
        return False
    return int(rng.get("From", 0)) <= o.lo and int(rng.get("To", 65535)) >= (o.hi if o.hi is not None else o.lo)


# ══════════════════════════════════════════════════════════════════════════════
# Security groups: internet openings (F-076)
# ══════════════════════════════════════════════════════════════════════════════

def _rule_sources(rule: Mapping[str, Any], net: RegionNet) -> List[Tuple[int, Optional[Any], str]]:
    """``(family, network or None for unresolved, source text)`` of one ingress rule's internet-capable sources."""
    out: List[Tuple[int, Optional[Any], str]] = []
    for r in rule.get("IpRanges") or ():
        n = _net(r.get("CidrIp")) if isinstance(r, Mapping) else None
        if n is not None and internet_capable(n):
            out.append((4, n, str(n)))
    for r in rule.get("Ipv6Ranges") or ():
        n = _net(r.get("CidrIpv6")) if isinstance(r, Mapping) else None
        if n is not None and internet_capable(n):
            out.append((6, n, str(n)))
    for pl in rule.get("PrefixListIds") or ():
        pid = str(pl.get("PrefixListId")) if isinstance(pl, Mapping) else None
        if not pid:
            continue
        entries = net.prefix_lists.get(pid)
        if entries is None:
            out.extend([(4, None, f"{pid} (unresolved)"), (6, None, f"{pid} (unresolved)")])
            continue
        for cidr in entries:
            n = _net(cidr)
            if n is not None and internet_capable(n):
                out.append((n.version, n, f"{pid}:{n}"))
    return out


def openings(groups: Sequence[str], net: RegionNet) -> List[Opening]:
    """Internet openings of the union of ``groups`` (CIDRs of the same port range are collapsed together)."""
    buckets: Dict[Tuple[str, Optional[int], Optional[int], int], List[Tuple[Optional[Any], str, str]]] = {}
    for gid in groups:
        for rule in (net.sgs.get(gid) or {}).get("InboundRules") or ():
            if not isinstance(rule, Mapping):
                continue
            proto = _proto(rule.get("IpProtocol"))
            lo = None if proto == "-1" else rule.get("FromPort")
            hi = None if proto == "-1" else rule.get("ToPort", lo)
            for fam, n, text in _rule_sources(rule, net):
                buckets.setdefault((proto, lo, hi, fam), []).append((n, text, gid))
    everything = {k[3]: v for k, v in buckets.items() if k[0] == "-1"}
    out = []
    for (proto, lo, hi, fam), items in sorted(buckets.items(), key=lambda kv: str(kv[0])):
        pool = items + ([] if proto == "-1" else everything.get(fam, []))
        nets = [n for n, _t, _g in pool if n is not None]
        if _covers_default(nets, fam):
            level = "open"
        elif any(n.prefixlen <= _BROAD_PREFIX[fam] for n in nets):
            level = "broad"
        elif any(n is None for n, _t, _g in items):
            level = "unresolved"
        else:
            continue
        out.append(Opening(proto, lo, hi, fam, level, tuple(sorted({t for _n, t, _g in items})),
                           tuple(sorted({g for _n, _t, g in items}))))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# Instances
# ══════════════════════════════════════════════════════════════════════════════

def _state(rec: Mapping[str, Any]) -> Optional[str]:
    st = rec.get("State")
    st = st.get("Name") if isinstance(st, Mapping) else st
    return str(st).lower() if st else None


def _tags(value: Any) -> List[Tuple[str, str]]:
    if isinstance(value, Mapping):
        return sorted((str(k), "" if v is None else str(v)) for k, v in value.items())
    return sorted((str(t.get("Key")), str(t.get("Value") or "")) for t in value or ()
                  if isinstance(t, Mapping) and t.get("Key") is not None)


def _label(iid: str, rec: Mapping[str, Any]) -> str:
    for k, v in _tags(rec.get("Tags")):
        if k == "Name" and v:
            return v
    return iid


@dataclass
class Imds:
    """IMDS settings: ``endpoint`` False when disabled; ``v1`` None when HttpTokens is unknown."""

    endpoint: bool
    v1: Optional[bool]
    hop_limit: Optional[int]

    @classmethod
    def of(cls, rec: Mapping[str, Any]) -> "Imds":
        meta = rec.get("MetadataOptions") if isinstance(rec.get("MetadataOptions"), Mapping) else {}
        endpoint = str(meta.get("HttpEndpoint") or "enabled").lower() != "disabled"
        tokens = meta.get("HttpTokens")
        v1 = None if tokens is None else str(tokens).lower() == "optional"
        hop = meta.get("HttpPutResponseHopLimit")
        return cls(endpoint, v1 if endpoint else False, hop if isinstance(hop, int) else None)


def addresses(rec: Mapping[str, Any], net: RegionNet) -> Tuple[List[str], List[str]]:
    """``(public IPv4, global IPv6)`` addresses of an instance: primary, ENI associations, secondary, EIPs."""
    v4: Set[str] = set()
    v6: Set[str] = set()
    if rec.get("PublicIpAddress"):
        v4.add(str(rec["PublicIpAddress"]))
    if rec.get("Ipv6Address"):
        v6.add(str(rec["Ipv6Address"]))
    v4 |= net.eips.get(str(rec.get("InstanceId")), set())
    for eni in rec.get("NetworkInterfaces") or ():
        if not isinstance(eni, Mapping):
            continue
        v4 |= net.eips.get(str(eni.get("NetworkInterfaceId")), set())
        assoc = eni.get("Association") if isinstance(eni.get("Association"), Mapping) else {}
        if assoc.get("PublicIp"):
            v4.add(str(assoc["PublicIp"]))
        for sec in eni.get("PrivateIpAddresses") or ():
            a = sec.get("Association") if isinstance(sec, Mapping) and isinstance(sec.get("Association"), Mapping) \
                else {}
            if a.get("PublicIp"):
                v4.add(str(a["PublicIp"]))
        for v6addr in eni.get("Ipv6Addresses") or ():
            value = v6addr.get("Ipv6Address") if isinstance(v6addr, Mapping) else v6addr
            if value:
                v6.add(str(value))
    v6 = {a for a in v6 if _global_v6(a)}
    return sorted(v4), sorted(v6)


def _global_v6(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_global
    except ValueError:
        return False


@dataclass
class Exposure:
    """Internet reachability of one instance (module docstring)."""

    v4: List[str]
    v6: List[str]
    opened: List[Opening] = field(default_factory=list)
    blocked: List[Opening] = field(default_factory=list)
    routes: Dict[int, str] = field(default_factory=dict)
    gaps: List[str] = field(default_factory=list)
    reachable: Optional[bool] = False
    conditional: bool = False

    @property
    def igw_routed(self) -> Optional[bool]:
        fams = [f for f, addrs in ((4, self.v4), (6, self.v6)) if addrs] or [4]
        states = [self.routes.get(f, "unknown") for f in fams]
        if any(s in ("full", "partial") for s in states):
            return True
        return None if any(s == "unknown" for s in states) else False

    @property
    def public_addresses(self) -> List[str]:
        return self.v4 + self.v6


def exposure(rec: Mapping[str, Any], net: RegionNet) -> Exposure:
    v4, v6 = addresses(rec, net)
    x = Exposure(v4, v6)
    subnet, vpc = rec.get("SubnetId"), rec.get("VpcId")
    x.routes = {4: net.route(subnet, vpc, 4), 6: net.route(subnet, vpc, 6)}
    if not (v4 or v6):
        return x
    groups = [str(g.get("GroupId")) for g in rec.get("SecurityGroups") or () if isinstance(g, Mapping)
              and g.get("GroupId")]
    if not net.sgs_known or any(g not in net.sgs for g in groups):
        x.gaps.append("ec2:security-group-rules-unknown")
    reachable_any = False
    for o in openings(groups, net):
        addrs = v4 if o.family == 4 else v6
        route = x.routes[o.family]
        if not addrs or route == "none":
            continue
        allowed = net.nacl_allows(subnet, vpc, o)
        if allowed is False:
            x.blocked.append(o)
            continue
        x.opened.append(o)
        reachable_any = True
        if allowed is None:
            x.gaps.append("ec2:nacl-unknown")
        if route in ("unknown", "partial"):
            x.gaps.append(f"ec2:route-{route}")
        if o.level != "open":
            x.gaps.append(f"ec2:sg-{o.level}-source")
    x.gaps = sorted(set(x.gaps))
    x.conditional = bool(x.gaps)
    if reachable_any:
        x.reachable = True
    elif "ec2:security-group-rules-unknown" in x.gaps:
        x.reachable = None
    return x


# ══════════════════════════════════════════════════════════════════════════════
# The analyzer
# ══════════════════════════════════════════════════════════════════════════════

FULL = AccessClass("EC2_FULL_ACCESS", (("ec2:*", "instance"), ("ec2:ModifyInstanceAttribute", "instance"),
                                       ("ec2:StopInstances", "instance"), ("ec2:StartInstances", "instance")),
                   mode="all")
USERDATA = AccessClass("CAN_MODIFY_USERDATA", (("ec2:ModifyInstanceAttribute", "instance"),
                                               ("ec2:StopInstances", "instance"), ("ec2:StartInstances", "instance")),
                       mode="all")
CONNECT = AccessClass("CAN_CONNECT", (("ssm:StartSession", "instance"), ("ssm:SendCommand", "instance"),
                                      ("ec2-instance-connect:SendSSHPublicKey", "instance")))
MANAGE = AccessClass("CAN_MANAGE", (("ec2:StartInstances", "instance"), ("ec2:StopInstances", "instance"),
                                    ("ec2:RebootInstances", "instance"), ("ec2:ModifyInstanceAttribute", "instance")))
TERMINATE = AccessClass("CAN_TERMINATE", (("ec2:TerminateInstances", "instance"),))
SG_ADMIN = AccessClass("CAN_ADMIN_SG", (("ec2:AuthorizeSecurityGroupIngress", "sg"),
                                        ("ec2:AuthorizeSecurityGroupEgress", "sg"),
                                        ("ec2:RevokeSecurityGroupIngress", "sg"),
                                        ("ec2:ModifySecurityGroupRules", "sg")))
INSTANCE_CLASSES: Tuple[AccessClass, ...] = (FULL, USERDATA, CONNECT, MANAGE, TERMINATE)
EC2_DOMINANCE: Mapping[str, Tuple[str, ...]] = {
    "EC2_FULL_ACCESS": ("CAN_MODIFY_USERDATA", "CAN_MANAGE", "CAN_TERMINATE"),
    "CAN_MODIFY_USERDATA": ("CAN_MANAGE",),
}


@dataclass
class Placed:
    """An instance node with what the access pass needs."""

    node_id: str
    state: Optional[str]
    managed: Optional[bool]


class Ec2Analysis:
    """One run of the EC2 analyzer (module docstring)."""

    def __init__(self, ctx: Any, builder: Any):
        self.ctx, self.builder = ctx, builder
        self.data = (ctx.data or {}).get("ec2")
        self.profiles, self.profiles_known = _profile_roles(ctx)
        self.placed: List[Placed] = []
        self.sg_nodes: List[str] = []

    # nodes ------------------------------------------------------------------
    def _id(self, kind: str, region: str, value: str) -> Optional[str]:
        try:
            return ids.node_id_for(kind, partition=self.ctx.partition, region=region, account=self.ctx.account_id,
                                   id=value)
        except ValueError:
            self.ctx.add_gap("ec2:resource-id-invalid", f"An EC2 {kind} id does not follow the AWS id format; that "
                             "resource was not analysed.")
            return None

    def security_groups(self, region: str, net: RegionNet) -> Dict[str, str]:
        nodes: Dict[str, str] = {}
        for gid in sorted(net.sgs):
            sg = net.sgs[gid]
            node = self._id("sg", region, gid)
            if node is None:
                continue
            open_ports = [o.text() for o in openings([gid], net) if o.level == "open"]
            props = {"vpc_id": sg.get("VpcId"), "open_to_internet": sorted(set(open_ports)) or None}
            self.builder.add_node(node, "sg", str(sg.get("GroupName") or gid), region=region,
                                  props={k: v for k, v in props.items() if v is not None}, tags=_tags(sg.get("Tags")),
                                  coverage_status=layout_status(self.ctx))
            nodes[gid] = node
        self.sg_nodes.extend(nodes.values())
        for gid in sorted(net.sgs):
            self._sg_pairs(gid, net.sgs[gid], nodes)
        return nodes

    def _sg_pairs(self, gid: str, sg: Mapping[str, Any], nodes: Mapping[str, str]) -> None:
        for rule in sg.get("InboundRules") or ():
            for pair in (rule.get("UserIdGroupPairs") or ()) if isinstance(rule, Mapping) else ():
                src = str(pair.get("GroupId") or "") if isinstance(pair, Mapping) else ""
                owner = pair.get("UserId") if isinstance(pair, Mapping) else None
                if not src or src == gid or src not in nodes or (owner and owner != self.ctx.account_id):
                    continue
                proto = _proto(rule.get("IpProtocol"))
                port = Opening(proto, rule.get("FromPort"), rule.get("ToPort"), 4, "open", (), ()).text()
                self.builder.add_edge(nodes[src], "SG_ALLOWS_FROM", nodes[gid], evidence={
                    **legacy_evidence("SG_ALLOWS_FROM", "sg"), "ports": [port]})

    def instance(self, region: str, rec: Mapping[str, Any], net: RegionNet, sgs: Mapping[str, str]) -> None:
        iid = str(rec.get("InstanceId") or "")
        node = self._id("instance", region, iid) if iid else None
        if node is None:
            return
        state, imds = _state(rec), Imds.of(rec)
        x = exposure(rec, net) if state not in _GONE else Exposure([], [])
        props = _instance_props(rec, state, imds, x)
        status = "complete" if table_status(self.data, "instances", region) == "complete" else "partial"
        self.builder.add_node(node, "instance", _label(iid, rec), region=region, props=props,
                              tags=_tags(rec.get("Tags")), coverage_status=layout_status(self.ctx, status),
                              coverage_gaps=[g for g in x.gaps if g == "ec2:security-group-rules-unknown"])
        managed = None if net.managed is None else iid in net.managed
        self.placed.append(Placed(node, state, managed))
        if state in _GONE:
            return
        role = self.instance_role(node, iid, region, rec)
        for g in rec.get("SecurityGroups") or ():
            gid = str(g.get("GroupId")) if isinstance(g, Mapping) else ""
            if gid in sgs:
                self.builder.add_edge(node, "HAS_SG", sgs[gid], evidence=legacy_evidence("HAS_SG", "instance"))
        self.exposure_findings(node, iid, region, state, x)
        self.imds(node, iid, region, state, imds, role, x)
        self.userdata(node, iid, region, rec.get("UserData"))

    def instance_role(self, node: str, iid: str, region: str, rec: Mapping[str, Any]) -> Optional[str]:
        """INSTANCE_ROLE by exact profile ARN (EC2-PROFILE-001 when the profile cannot be resolved)."""
        prof = rec.get("IamInstanceProfile") if isinstance(rec.get("IamInstanceProfile"), Mapping) else {}
        parn = prof.get("Arn")
        if not parn:
            return None
        role_arn, method = self.profiles.get(str(parn)), "arn"
        if role_arn is None and not self.profiles_known:
            role_arn, method = self._role_by_profile_name(str(parn)), "name_fallback"
        ref = self.builder.ensure_principal(role_arn) if role_arn else None
        if ref is None or ref.node_id is None or ref.node_type != "role":
            self._profile_finding(node, iid, region, str(parn))
            return None
        fallback = method == "name_fallback"
        self.builder.add_edge(node, "INSTANCE_ROLE", ref.node_id, confidence="conditional" if fallback else None,
                              strength="weak" if fallback else None,
                              evidence={**legacy_evidence("INSTANCE_ROLE", "instance"), "instance_profile_arn": parn,
                                        "match_method": method,
                                        "gaps": ["iam:instance-profiles-unknown"] if fallback else []})
        return ref.node_id

    def _role_by_profile_name(self, parn: str) -> Optional[str]:
        """d13c215's fallback when the profiles were not collected: the role named like the profile (same account)."""
        p = ids.parse_arn(parn)
        name = p.resource.rsplit("/", 1)[-1] if p is not None else ""
        if not name or p is None or p.account != self.ctx.account_id:
            return None
        hits = [n.id for n in self.builder.nodes("role") if n.id.rsplit("/", 1)[-1] == name
                and n.account == self.ctx.account_id]
        return hits[0] if len(hits) == 1 else None

    def _profile_finding(self, node: str, iid: str, region: str, parn: str) -> None:
        why = ("the instance profile is not among the collected ones (deleted, or in another account)"
               if self.profiles_known else "the instance profiles could not be listed (iam:ListInstanceProfiles)")
        self.builder.add_finding(
            "EC2-PROFILE-001", node, severity="MEDIUM" if self.profiles_known else "LOW",
            title=f"Instance {iid} has an unresolved instance profile",
            description=f"Instance '{iid}' has instance profile '{parn}' but no role could be resolved: {why}.",
            confidence="definite" if self.profiles_known else "conditional", evidence={"instance_profile_arn": parn},
            region=region, entity=f"instance/{iid}", entity_arn=node, resource=[node], source_type="ec2_config",
            gaps=[] if self.profiles_known else ["iam:instance-profiles-unknown"])

    def exposure_findings(self, node: str, iid: str, region: str, state: Optional[str], x: Exposure) -> None:
        if x.igw_routed and x.public_addresses:
            self.builder.add_finding(
                "EC2-INET-001", node, severity="MEDIUM",
                title=f"Instance {iid} has a public address in an internet-routed subnet",
                description=f"Instance '{iid}' has public address(es) {', '.join(x.public_addresses)} and its "
                            "subnet's effective route table routes to an attached internet gateway.",
                evidence={"addresses": x.public_addresses, "routes": {str(k): v for k, v in x.routes.items()}},
                region=region, entity=f"instance/{iid}", entity_arn=node, resource=[node], source_type="vpc")
        if not x.reachable:
            return
        alive = state in _ALIVE or state is None
        ports = sorted({o.text() for o in x.opened})
        severity = "HIGH" if alive else "MEDIUM"
        if x.conditional:
            severity = lower_severity(severity, 1) if any(o.level != "open" for o in x.opened) else severity
        sgs = sorted({g for o in x.opened for g in o.groups})
        self.builder.add_finding(
            "EC2-EXPOSURE-001", node, severity=severity, base_severity="HIGH",
            title=f"Instance {iid} is reachable from the internet on {', '.join(ports)}",
            description=f"Instance '{iid}' ({state or 'state unknown'}) has public address(es) "
                        f"{', '.join(x.public_addresses)}; security group(s) {', '.join(sgs)} admit "
                        f"{', '.join(sorted({s for o in x.opened for s in o.sources}))} on {', '.join(ports)}."
                        + (f" Not verified: {', '.join(x.gaps)}." if x.gaps else ""),
            confidence="conditional" if x.conditional else "definite",
            evidence={"security_groups": sgs, "ports": ports, "addresses": x.public_addresses,
                      "sources": sorted({s for o in x.opened for s in o.sources}),
                      "blocked_by_nacl": sorted({o.text() for o in x.blocked}),
                      "routes": {str(k): v for k, v in x.routes.items()}},
            gaps=x.gaps, region=region, entity=f"instance/{iid}", entity_arn=node, resource=[node],
            source_type="security_group")
        if alive:
            self.builder.add_edge(ids.ANONYMOUS_ID, "PUBLIC_INBOUND", node,
                                  confidence="conditional" if x.conditional else "definite",
                                  strength="weak" if x.conditional else None,
                                  evidence={**legacy_evidence("PUBLIC_INBOUND", "anonymous"), "ports": ports,
                                            "security_groups": sgs, "addresses": x.public_addresses,
                                            "gaps": x.gaps},
                                  props={"technique": "internet-inbound"})

    def imds(self, node: str, iid: str, region: str, state: Optional[str], imds: Imds, role: Optional[str],
             x: Exposure) -> None:
        """EC2-IMDS-001 and SSRF_TO_IMDS (F-078, F-106)."""
        if not imds.endpoint or imds.v1 is not True:
            return
        stopped = state not in _ALIVE and state is not None
        base = "MEDIUM" if role else "LOW"
        what = ("SSRF can read the instance role's temporary credentials" if role else
                "SSRF can read instance metadata and user data (no role is attached)")
        self.builder.add_finding(
            "EC2-IMDS-001", node, severity=lower_severity(base, 1) if stopped else base, base_severity=base,
            title=f"Instance {iid} allows IMDSv1" + (" (instance role exposed to SSRF)" if role else ""),
            description=f"Instance '{iid}' ({state or 'state unknown'}) has HttpTokens 'optional' with the metadata "
                        f"endpoint enabled: {what}."
                        + (f" The hop limit is {imds.hop_limit}, so containers on the host reach IMDS too."
                           if (imds.hop_limit or 1) > 1 else ""),
            evidence={"http_tokens": "optional", "hop_limit": imds.hop_limit, "role": role, "state": state},
            region=region, entity=f"instance/{iid}", entity_arn=node, resource=[node], source_type="ec2_config")
        if role and x.reachable and state in _ALIVE:
            self.builder.add_edge(ids.ANONYMOUS_ID, "SSRF_TO_IMDS", node, confidence="conditional", strength="weak",
                                  evidence={"technique": "ssrf-imdsv1", "preconditions": [
                                      "public", "imdsv1", "running", "instance-role"]},
                                  props={"technique": "ssrf-imdsv1"})

    def userdata(self, node: str, name: str, region: str, ud: Any, kind: str = "instance") -> None:
        present = ud.get("Present") if isinstance(ud, Mapping) else ud
        if present is not True:
            return
        digest = ud.get("Sha256") if isinstance(ud, Mapping) else None
        self.builder.add_finding(
            "EC2-USERDATA-001", node, severity="INFO", title=f"User data is present on {kind} {name}",
            description=f"The {kind} '{name}' has user data (content not collected). User data is readable by "
                        "anyone with ec2:DescribeInstanceAttribute / DescribeLaunchTemplateVersions and through "
                        "IMDS on the host; review it for embedded credentials.",
            evidence={"sha256": digest}, region=region, entity=f"{kind}/{name}", entity_arn=node, resource=[node],
            source_type="ec2_config")


def _instance_props(rec: Mapping[str, Any], state: Optional[str], imds: Imds, x: Exposure) -> Dict[str, Any]:
    ud = rec.get("UserData")
    props = {
        "state": state, "imds_v1": imds.v1, "imds_endpoint": imds.endpoint, "imds_hop_limit": imds.hop_limit,
        "public_ip": bool(x.v4) if state not in _GONE else None, "public_addresses": x.public_addresses or None,
        "igw_routed": x.igw_routed if state not in _GONE else None,
        "public": x.reachable if state not in _GONE else False,
        "subnet_id": rec.get("SubnetId"), "vpc_id": rec.get("VpcId"), "instance_type": rec.get("InstanceType"),
        "ami_id": rec.get("AmiId"), "key_name": rec.get("KeyName"), "platform": rec.get("Platform"),
        "userdata_present": ud.get("Present") if isinstance(ud, Mapping) else None,
    }
    return {k: v for k, v in props.items() if v is not None}


def _profile_roles(ctx: Any) -> Tuple[Dict[str, str], bool]:
    """``{instance profile ARN: role ARN}`` from the collected instance profiles, and whether they were read."""
    iam = (ctx.data or {}).get("iam")
    profiles = getattr(iam, "instance_profiles", None) or []
    known = getattr(iam, "instance_profiles_status", "missing") in ("complete", "ok") and iam is not None \
        and getattr(iam, "layout", "missing") != "missing"
    out: Dict[str, str] = {}
    for prof in profiles:
        roles = [r for r in prof.get("Roles") or () if isinstance(r, Mapping) and r.get("Arn")] \
            if isinstance(prof, Mapping) else []
        if prof.get("Arn") and roles:
            out[str(prof["Arn"])] = str(roles[0]["Arn"])
    return out, known


# ── launch templates and AMIs ────────────────────────────────────────────────

def launch_templates(an: Ec2Analysis, region: str) -> None:
    for lt in table(an.data, "launch_templates", region):
        lid = str(lt.get("LaunchTemplateId") or "")
        node = an._id("launchtemplate", region, lid) if lid else None
        if node is None:
            continue
        versions = lt.get("Versions")
        latest = versions[-1] if isinstance(versions, list) and versions and isinstance(versions[-1], Mapping) else {}
        prof = latest.get("IamInstanceProfile") if isinstance(latest.get("IamInstanceProfile"), Mapping) else {}
        meta = latest.get("MetadataOptions") if isinstance(latest.get("MetadataOptions"), Mapping) else {}
        present = any(isinstance(v, Mapping) and v.get("UserDataPresent") for v in versions or ()) \
            if isinstance(versions, list) else None
        props = {"name": lt.get("LaunchTemplateName"), "default_version": lt.get("DefaultVersionNumber"),
                 "instance_profile": prof.get("Arn") or prof.get("Name"), "http_tokens": meta.get("HttpTokens"),
                 "userdata_present": present}
        known = isinstance(versions, list)
        an.builder.add_node(node, "launchtemplate", str(lt.get("LaunchTemplateName") or lid), region=region,
                            props={k: v for k, v in props.items() if v is not None}, tags=_tags(lt.get("Tags")),
                            coverage_status=None if known else "partial",
                            coverage_gaps=() if known else ("ec2:launch-template-versions-unknown",))
        an.userdata(node, str(lt.get("LaunchTemplateName") or lid), region, {"Present": present},
                    kind="launch template")


def images(an: Ec2Analysis, region: str) -> None:
    settings = document(an.data, "account_settings", region) or {}
    block = settings.get("ImageBlockPublicAccessState")
    for img in table(an.data, "images", region):
        aid = str(img.get("ImageId") or "")
        try:
            node = ids.node_id_for("ami", partition=an.ctx.partition, region=region, id=aid)
        except ValueError:
            continue
        public, shared = img.get("Public"), img.get("SharedAccounts")
        gaps = [g for g, v in (("ec2:ami-public-unknown", public), ("ec2:ami-sharing-unknown", shared)) if v is None]
        an.builder.add_node(node, "ami", str(img.get("Name") or aid), region=region, account=an.ctx.account_id,
                            props={k: v for k, v in {"public": public, "state": img.get("State")}.items()
                                   if v is not None}, coverage_status="partial" if gaps else None, coverage_gaps=gaps)
        if public is True:
            an.builder.add_finding(
                "AMI-PUB-001", node, severity="HIGH", title=f"AMI {aid} is public",
                description=f"Anyone can launch an instance from AMI '{aid}' and read its volumes"
                            + (" (AMI Block Public Access is on, but it only blocks new public sharing)."
                               if block == "block-new-sharing" else "."),
                evidence={"image_block_public_access": block}, region=region, entity=f"ami/{aid}", entity_arn=node,
                resource=[node], source_type="ami_config")
            an.builder.add_edge(ids.ANONYMOUS_ID, "AMI_SHARED_PUBLIC", node, evidence={"launch_permission": "all"})
        _image_shares(an, region, node, aid, shared)


def _image_shares(an: Ec2Analysis, region: str, node: str, aid: str, shared: Any) -> None:
    """``external_account -AMI_SHARED_CROSS_ACCOUNT-> ami`` and ``AMI-XACCT-001`` per foreign account (F-116)."""
    for acct in sorted({str(a) for a in shared or () if str(a) not in ("all", an.ctx.account_id)}):
        ref = an.builder.ensure_principal(acct)
        related = []
        if ref.node_id is not None and ref.node_type == "external_account":
            an.builder.add_edge(ref.node_id, "AMI_SHARED_CROSS_ACCOUNT", node,
                                evidence={"launch_permission": "account", "account": acct},
                                props={"cross_account": True})
            related = [ref.node_id]
        an.builder.add_finding(
            "AMI-XACCT-001", node, severity="MEDIUM", title=f"AMI {aid} is shared with account {acct}",
            description=f"Account {acct} can launch instances from AMI '{aid}' (launch permission).",
            discriminator=acct, evidence={"account": acct}, region=region, related_node_ids=related,
            entity=f"ami/{aid}", entity_arn=node, resource=[node], source_type="ami_config")


# ── principal access ─────────────────────────────────────────────────────────

def _instance_resolver(access: PrincipalAccess, arn: str, managed: Optional[bool]) -> Resolve:
    forms = (arn,)

    def resolve(who: Any, action: str, form: str) -> EvalResult:
        r = access.cache.evaluate(who, action, arn, forms=forms, shareable=True)
        if action.startswith("ssm:") and managed is False and r.decision.grants:
            return as_conditional(r, Strength.WEAK, "ssm:instance-not-managed")
        return r
    return resolve


def access_edges(an: Ec2Analysis) -> int:
    access = PrincipalAccess(an.ctx, an.builder, EC2_DOMINANCE)
    count = 0
    who_instances = access.candidates(("ec2", "ssm", "ec2-instance-connect"))
    for p in an.placed:
        if p.state in _GONE:
            continue
        resolve = _instance_resolver(access, p.node_id, p.managed)
        for who in who_instances:
            source = access.source_of(who)
            if source is not None:
                count += access.emit(source, p.node_id, access.results(who, INSTANCE_CLASSES, resolve),
                                     evidence={"ssm_managed": p.managed} if p.managed is not None else None)
    who_sg = access.candidates(("ec2",))
    for sg in an.sg_nodes:
        def resolve_sg(who: Any, action: str, form: str, _arn: str = sg) -> EvalResult:
            return access.cache.evaluate(who, action, _arn, forms=(_arn,), shareable=True)
        for who in who_sg:
            source = access.source_of(who)
            if source is not None:
                count += access.emit(source, sg, access.results(who, (SG_ADMIN,), resolve_sg))
    return count


def run_ec2(ctx: Any, builder: Any) -> None:
    """Phase RESOURCES: every instance, security group, launch template and AMI of the analysed regions."""
    an = Ec2Analysis(ctx, builder)
    regions = sorted(set(units_of(an.data, "instances")) | set(units_of(an.data, "security_groups"))
                     | set(units_of(an.data, "images")) | set(units_of(an.data, "launch_templates")))
    if not any(table_status(an.data, key, r) != "missing" for r in regions
               for key in ("instances", "security_groups", "images", "launch_templates")):
        raise AnalyzerSkipped("ec2.instances", reason="no EC2 data was collected in the analysed regions")
    for region in regions:
        net = RegionNet.build(an.data, region)
        sgs = an.security_groups(region, net)
        for rec in table(an.data, "instances", region):
            an.instance(region, rec, net, sgs)
        launch_templates(an, region)
        images(an, region)
    edges = access_edges(an)
    store_legacy_file(ctx, builder, "ec2", LEGACY_FILE)
    log.debug("ec2: %d instances, %d principal edge types", len(an.placed), edges)


ANALYZERS: Tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec("ec2", Phase.RESOURCES, run_ec2, inputs=("ec2.instances", "sg", "vpc"), legacy_files=(LEGACY_FILE,)),
)
