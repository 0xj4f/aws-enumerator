"""Edge-services analyzer (E-net, Wave 2; the d13c215 "extra" analysis): EBS snapshot sharing, load balancers and
Route 53 takeover candidates.

Native on :class:`~aws_enumerator.engine.graph.builder.GraphBuilder` (engine.md §5 "Data stores, edge services";
§6.3). Reads ``ctx.data["edge_services"]`` (explicit regions only) in the d13c215 and the Wave 1 (C-B) layouts; a
``null`` field (``Public``, ``SharedAccounts``, ``Targets``, ``Listeners``, ``TakeoverCandidates`` …) is **unknown**:
a node coverage gap, never "not shared" or "no targets" (``requests/c-b-1.md``, F-059, F-104).

* **EBS snapshots** (F-080): ``anonymous -EBS_SHARED_PUBLIC-> snapshot`` and ``EBS-PUB-001`` for public snapshots,
  unless the region's snapshot Block Public Access is ``block-all-sharing`` (then ``INFO`` with
  ``evidence.mitigated_by`` and no edge; ``block-new-sharing`` leaves existing public snapshots public);
  ``external_account -EBS_SHARED_CROSS_ACCOUNT-> snapshot`` and ``EBS-XACCT-001`` per account; ``EBS_ENCRYPTED_BY``
  to the resolved KMS key (F-027).
* **Load balancers** (F-051, F-083): ELBv2 ARNs, classic load balancers of old reports get their synthesised ARN;
  internet-facing ones get ``anonymous -PUBLIC_INBOUND-> elb`` and ``ELB-PUB-001`` when their security groups admit
  the internet (``INFO`` when they do not); targets are ``EXPOSES`` (internet-facing) or ``FRONTS`` (internal).
* **Route 53** (F-057, F-083): hosted zones are nodes; each takeover candidate is checked against the collected
  data — an S3 website / REST alias against the account's buckets, an ELB alias against the collected load
  balancers' DNS names — and graded by ``Claimable`` (``likely`` MEDIUM, ``unlikely`` / ``info`` INFO); private-zone
  records are INFO (internal only). ``ROUTE53-DANGLING-001`` is anchored at the zone. Literal A / AAAA values of
  public zones are compared with the addresses the account holds (zone props ``address_values`` /
  ``address_values_owned``); an address it does not hold is not reported (it may be another provider's).

Cognito identity pools are E-compute's ``analyzers/cognito.py`` (engine-api.md §7): this module emits nothing for
them. The legacy ``extra_relationships.json`` (one release) is rendered from the graph by the legacy writer.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from aws_enumerator.engine.analyzers.ec2 import RegionNet, addresses, openings
from aws_enumerator.engine.analyzers.s3 import kms_target, layout_status, legacy_evidence, placeholder_node
from aws_enumerator.engine.findings.catalog import A_EXPOSURE, CatalogEntry
from aws_enumerator.engine.graph import ids
from aws_enumerator.engine.io.loaders.ec2 import document, table, table_status, units_of
from aws_enumerator.engine.io.loaders.s3 import buckets as loaded_buckets
from aws_enumerator.engine.model import AnalyzerSkipped, AnalyzerSpec, Phase

log = logging.getLogger(__name__)

LEGACY_FILE = "extra_relationships.json"
_KNOWN = frozenset({"complete", "partial"})

FINDINGS: Tuple[CatalogEntry, ...] = (
    CatalogEntry("EBS-PUB-001", "HIGH", "ebs_public", "EBS snapshot is shared publicly",
                 "Remove the public createVolumePermission and set snapshot Block Public Access to "
                 "block-all-sharing.", A_EXPOSURE),
    CatalogEntry("EBS-XACCT-001", "MEDIUM", "ebs_cross_account", "EBS snapshot is shared with another account",
                 "Verify the cross-account sharing is intended.", A_EXPOSURE, discriminator="target-account"),
    CatalogEntry("ELB-PUB-001", "MEDIUM", "elb_public", "Load balancer is internet-facing",
                 "Confirm the public exposure is intended; otherwise use an internal scheme, and protect it with a "
                 "WAF web ACL.", A_EXPOSURE),
    CatalogEntry("ROUTE53-DANGLING-001", "MEDIUM", "route53_dangling", "Potential dangling DNS record",
                 "Verify the target resource still exists and belongs to you; remove the record if not.",
                 A_EXPOSURE, discriminator="record-name"),
)


def _records(data: Any, key: str, region: str) -> List[Mapping[str, Any]]:
    return table(data, key, region)


def _region_units(data: Any, *keys: str) -> List[str]:
    return sorted({u for k in keys for u in units_of(data, k) if u != "global"})


# ══════════════════════════════════════════════════════════════════════════════
# EBS snapshots (F-080, F-104)
# ══════════════════════════════════════════════════════════════════════════════

def _snapshot_node(ctx: Any, builder: Any, region: str, snap: Mapping[str, Any]) -> Optional[str]:
    sid = str(snap.get("Id") or snap.get("SnapshotId") or "")
    try:
        node = ids.node_id_for("ebssnapshot", partition=ctx.partition, region=region, id=sid)
    except ValueError:
        return None
    public, shared = snap.get("Public"), snap.get("SharedAccounts")
    gaps = []
    if public is None and "Public" in snap:
        gaps.append("ebs:public-unknown")
    if shared is None and ("SharedAccounts" in snap or snap.get("SharingChecked") is False):
        gaps.append("ebs:sharing-not-checked" if snap.get("SharingChecked") is False else "ebs:sharing-unknown")
    props = {"public": public, "encrypted": snap.get("Encrypted"), "volume_id": snap.get("VolumeId"),
             "sharing_checked": snap.get("SharingChecked")}
    builder.add_node(node, "ebssnapshot", str(snap.get("Name") or sid), region=region, account=ctx.account_id,
                     props={k: v for k, v in props.items() if v is not None},
                     coverage_status=layout_status(ctx, "partial" if gaps else None), coverage_gaps=gaps)
    return node


def _snapshot_public(builder: Any, region: str, node: str, sid: str, bpa: Optional[str]) -> None:
    mitigated = bpa == "block-all-sharing"
    desc = ("The snapshot's createVolumePermission includes the 'all' group: anyone can create a volume from it "
            "and read the data")
    if mitigated:
        desc += "; snapshot Block Public Access (block-all-sharing) blocks it while that setting stays on"
    builder.add_finding("EBS-PUB-001", node, severity="INFO" if mitigated else "HIGH", base_severity="HIGH",
                        title=f"EBS snapshot '{sid}' is shared publicly", description=desc + ".",
                        evidence={"snapshot_block_public_access": bpa,
                                  "mitigated_by": ["account:snapshot-block-public-access"] if mitigated else []},
                        region=region, entity=f"ebssnapshot/{sid}", entity_arn=node, resource=[node],
                        source_type="ebs_config")
    if not mitigated:
        builder.add_edge(ids.ANONYMOUS_ID, "EBS_SHARED_PUBLIC", node, evidence={
            **legacy_evidence("EBS_SHARED_PUBLIC", "anonymous"), "snapshot_block_public_access": bpa})


def _snapshot_shares(ctx: Any, builder: Any, region: str, node: str, sid: str, shared: Any) -> None:
    for acct in sorted({str(a) for a in shared or () if str(a) not in ("all", ctx.account_id)}):
        ref = builder.ensure_principal(acct)
        if ref.node_id is None or ref.node_type != "external_account":
            continue
        builder.add_edge(ref.node_id, "EBS_SHARED_CROSS_ACCOUNT", node, evidence={
            **legacy_evidence("EBS_SHARED_CROSS_ACCOUNT", "external_account"), "account": acct},
            props={"cross_account": True})
        builder.add_finding("EBS-XACCT-001", node, severity="MEDIUM",
                            title=f"EBS snapshot '{sid}' is shared with account {acct}",
                            description=f"Account {acct} can create volumes from the snapshot "
                                        "(createVolumePermission).",
                            discriminator=acct, related_node_ids=[ref.node_id], evidence={"account": acct},
                            region=region, entity=f"ebssnapshot/{sid}", entity_arn=node, resource=[node],
                            source_type="ebs_config")


def ebs(ctx: Any, builder: Any, data: Any, region: str) -> None:
    settings = document(data, "ebs_settings", region) or {}
    bpa = settings.get("SnapshotBlockPublicAccessState")
    for snap in _records(data, "ebs", region):
        node = _snapshot_node(ctx, builder, region, snap)
        if node is None:
            continue
        sid = node.rsplit("/", 1)[-1]
        if snap.get("Public") is True:
            _snapshot_public(builder, region, node, sid, bpa)
        _snapshot_shares(ctx, builder, region, node, sid, snap.get("SharedAccounts"))
        if snap.get("KmsKeyId"):
            key = kms_target(ctx, builder, str(snap["KmsKeyId"]), region)
            if key is not None:
                builder.add_edge(node, "EBS_ENCRYPTED_BY", key, evidence={
                    **legacy_evidence("EBS_ENCRYPTED_BY", "ebssnapshot"), "kms_key_ref": snap["KmsKeyId"]})


# ══════════════════════════════════════════════════════════════════════════════
# Load balancers (F-051, F-083)
# ══════════════════════════════════════════════════════════════════════════════

def elb_node_id(ctx: Any, region: str, lb: Mapping[str, Any]) -> Tuple[Optional[str], bool]:
    """``(node id, synthesised)``: the ELBv2 / classic ARN, or the classic ARN built from the name (F-051)."""
    arn = lb.get("Arn")
    if isinstance(arn, str) and arn.startswith("arn:") and ids.node_id_matches("elb", arn):
        return arn, False
    name = str(lb.get("Name") or arn or "")
    if not name:
        return None, False
    try:
        return ids.node_id_for("elb", region=region, account=ctx.account_id, partition=ctx.partition,
                               name=name), True
    except ValueError:
        return None, False


@dataclass
class LbExposure:
    """Whether an internet-facing load balancer admits the internet (security groups; NLBs may have none)."""

    reachable: bool
    conditional: bool
    ports: List[str]
    gaps: List[str]


def lb_exposure(lb: Mapping[str, Any], net: Optional[RegionNet]) -> LbExposure:
    groups = lb.get("SecurityGroups")
    if not isinstance(groups, list) or not groups:
        listeners = lb.get("Listeners") if isinstance(lb.get("Listeners"), list) else []
        ports = sorted({f"{li.get('Port')}/{str(li.get('Protocol') or '').lower()}" for li in listeners
                        if isinstance(li, Mapping) and li.get("Port") is not None})
        return LbExposure(True, groups is None and "SecurityGroups" in lb, ports,
                          ["elb:security-groups-unknown"] if groups is None and "SecurityGroups" in lb else [])
    gids = [str(g) for g in groups]
    if net is None or not net.sgs_known or any(g not in net.sgs for g in gids):
        return LbExposure(True, True, [], ["ec2:security-group-rules-unknown"])
    opened = openings(gids, net)
    gaps = sorted({f"ec2:sg-{o.level}-source" for o in opened if o.level != "open"})
    return LbExposure(bool(opened), bool(gaps), sorted({o.text() for o in opened}), gaps)


def _lb_target(ctx: Any, builder: Any, region: str, tgt: Mapping[str, Any]) -> Optional[str]:
    kind, tid = tgt.get("kind"), tgt.get("id")
    if not isinstance(tid, str) or not tid:
        return None
    try:
        if kind == "instance":
            return placeholder_node(builder, "instance", ids.node_id_for(
                "instance", partition=ctx.partition, region=region, account=ctx.account_id, id=tid))
        if kind == "lambda":
            return placeholder_node(builder, "lambda", ids.node_id_for("lambda", arn=tid))
    except ValueError:
        return None
    return None                                            # ip / alb targets have no graph node


def _lb_props(lb: Mapping[str, Any], synthesised: bool, internet: bool) -> Dict[str, Any]:
    listeners = lb.get("Listeners") if isinstance(lb.get("Listeners"), list) else None
    auth = sorted({a.get("Type") for li in listeners or () if isinstance(li, Mapping)
                   for a in li.get("AuthenticateActions") or () if isinstance(a, Mapping) and a.get("Type")})
    props = {"scheme": lb.get("Scheme"), "lb_type": lb.get("LBType"), "dns_name": lb.get("DNSName"),
             "internet_facing": internet, "vpc_id": lb.get("VpcId"), "arn_synthesised": True if synthesised else None,
             "authenticate_actions": auth or None}
    return {k: v for k, v in props.items() if v is not None}


def elb(ctx: Any, builder: Any, data: Any, region: str, net: Optional[RegionNet]) -> List[str]:
    """Load balancer nodes, exposure and targets of one region; returns the collected DNS names."""
    names: List[str] = []
    for lb in _records(data, "elb", region):
        node, synthesised = elb_node_id(ctx, region, lb)
        if node is None:
            continue
        internet = str(lb.get("Scheme") or "").lower() == "internet-facing"
        targets = lb.get("Targets")
        gaps = ["elb:targets-unknown"] if targets is None and "Targets" in lb else []
        builder.add_node(node, "elb", str(lb.get("Name") or node), region=region, account=ctx.account_id,
                         props=_lb_props(lb, synthesised, internet),
                         coverage_status=layout_status(ctx, "partial" if gaps else None), coverage_gaps=gaps)
        if lb.get("DNSName"):
            names.append(str(lb["DNSName"]).rstrip(".").lower())
        if internet:
            _lb_public(builder, region, node, lb, lb_exposure(lb, net))
        etype = "EXPOSES" if internet else "FRONTS"
        for tgt in targets or ():
            target = _lb_target(ctx, builder, region, tgt) if isinstance(tgt, Mapping) else None
            if target is not None:
                builder.add_edge(node, etype, target, evidence={
                    **legacy_evidence(etype, "elb"), "scheme": lb.get("Scheme"),
                    "target_group": tgt.get("TargetGroupArn")})
    return names


def _lb_public(builder: Any, region: str, node: str, lb: Mapping[str, Any], x: LbExposure) -> None:
    name = str(lb.get("Name") or node)
    if not x.reachable:
        desc = ("The load balancer scheme is 'internet-facing', but none of its security groups admits the internet; "
                "it becomes reachable as soon as one does.")
    else:
        desc = ("The load balancer scheme is 'internet-facing': its listeners"
                + (f" ({', '.join(x.ports)})" if x.ports else "") + " are reachable from the internet and forward to "
                "its targets.")
    builder.add_finding("ELB-PUB-001", node, severity="MEDIUM" if x.reachable else "INFO", base_severity="MEDIUM",
                        title=f"Load balancer '{name}' is internet-facing", description=desc,
                        confidence="conditional" if x.conditional else "definite", gaps=x.gaps,
                        evidence={"scheme": lb.get("Scheme"), "ports": x.ports, "security_groups":
                                  lb.get("SecurityGroups") if isinstance(lb.get("SecurityGroups"), list) else None},
                        region=region, entity=f"elb/{name}", entity_arn=node, resource=[node],
                        source_type="elb_config")
    if x.reachable:
        builder.add_edge(ids.ANONYMOUS_ID, "PUBLIC_INBOUND", node,
                         confidence="conditional" if x.conditional else "definite",
                         strength="weak" if x.conditional else None,
                         evidence={**legacy_evidence("PUBLIC_INBOUND", "anonymous"), "ports": x.ports,
                                   "gaps": x.gaps}, props={"technique": "internet-inbound"})


# ══════════════════════════════════════════════════════════════════════════════
# Route 53 takeover candidates (F-057, F-083)
# ══════════════════════════════════════════════════════════════════════════════

#: (pattern, kind, claimable) — the collector's classification, for d13c215 records that lack ``Kind``.
TAKEOVER_PATTERNS: Tuple[Tuple[str, str, str], ...] = (
    ("s3-website*.amazonaws.com", "s3-website", "likely"), ("s3-website.*.amazonaws.com", "s3-website", "likely"),
    ("*.s3-website*.amazonaws.com", "s3-website", "likely"), ("*.s3-website.*.amazonaws.com", "s3-website", "likely"),
    ("*.s3.amazonaws.com", "s3", "likely"), ("*.s3.*.amazonaws.com", "s3", "likely"),
    ("*.s3-*.amazonaws.com", "s3", "likely"), ("*.elasticbeanstalk.com", "elasticbeanstalk", "likely"),
    ("*.github.io", "github-pages", "likely"), ("*.herokuapp.com", "heroku", "likely"),
    ("*.azurewebsites.net", "azure-app-service", "likely"), ("*.cloudapp.net", "azure-cloudapp", "likely"),
    ("*.cloudapp.azure.com", "azure-cloudapp", "likely"), ("*.trafficmanager.net", "azure-trafficmanager", "likely"),
    ("*.elb.amazonaws.com", "elb", "unlikely"), ("*.elb.*.amazonaws.com", "elb", "unlikely"),
    ("*.cloudfront.net", "cloudfront", "info"),
)


def classify_target(target: str) -> Optional[Tuple[str, str]]:
    t = target.strip().rstrip(".").lower()
    if t.startswith("dualstack."):
        t = t[len("dualstack."):]
    for pattern, kind, claimable in TAKEOVER_PATTERNS:
        if fnmatch.fnmatchcase(t, pattern):
            return kind, claimable
    return None


def s3_bucket_for(record_name: str, target: str, kind: str) -> str:
    """The bucket a website / REST endpoint serves: the label before ``.s3`` or, for the alias form without a
    bucket label, the record name itself (a website alias must point at a bucket named like the record)."""
    t = target.rstrip(".").lower()
    if t.startswith(("s3-website", "s3.")) or ".s3" not in t:
        return record_name.rstrip(".").lower()
    return t.split(".s3", 1)[0]


@dataclass
class Verdict:
    """How one takeover candidate was checked against the collected data."""

    severity: Optional[str]          # None: verified owned, no finding
    confidence: str
    reason: str
    gaps: List[str]


class TakeoverCheck:
    """Cross-checks takeover candidates against the account's buckets and load balancers (F-057)."""

    def __init__(self, ctx: Any, lb_names: Set[str]):
        s3 = (ctx.data or {}).get("s3")
        self.buckets = {b.name for b in loaded_buckets(s3)}
        self.buckets_known = table_status(s3, "buckets", "global") == "complete"
        self.lb_names = lb_names

    def verdict(self, cand: Mapping[str, Any], kind: str, claimable: str, private: bool) -> Verdict:
        target = str(cand.get("Target") or "").rstrip(".").lower()
        if kind in ("s3", "s3-website"):
            bucket = s3_bucket_for(str(cand.get("Name") or ""), target, kind)
            if bucket in self.buckets:
                return Verdict(None, "definite", f"bucket '{bucket}' exists in this account", [])
            if not self.buckets_known:
                v = Verdict("MEDIUM", "conditional", f"bucket '{bucket}' could not be checked (S3 bucket list not "
                            "read completely)", ["s3:ListBuckets:unknown"])
            else:
                v = Verdict("MEDIUM", "definite", f"no bucket '{bucket}' in this account: anyone may create it", [])
        elif kind == "elb":
            bare = target[len("dualstack."):] if target.startswith("dualstack.") else target
            if bare in self.lb_names:
                return Verdict(None, "definite", "the load balancer exists in this account", [])
            v = Verdict("INFO", "definite", "no load balancer with this DNS name in the analysed regions: a stale "
                        "record (ELB names carry a random suffix and cannot be re-registered)", [])
        elif claimable == "likely":
            v = Verdict("MEDIUM", "conditional", f"{kind} target: verify it still exists",
                        [f"route53:{kind}-unverified"])
        else:
            v = Verdict("INFO", "definite", f"{kind} target ({claimable} to be claimable)", [])
        if private and v.severity is not None:
            v.severity, v.reason = "INFO", v.reason + "; private zone (internal clients only)"
        return v


def owned_ips(ctx: Any) -> Optional[Set[str]]:
    """Every public address the account holds in the analysed regions (``None`` when EC2 was not collected)."""
    ec2 = (ctx.data or {}).get("ec2")
    regions = [r for r in units_of(ec2, "instances") if table_status(ec2, "instances", r) != "missing"]
    if not regions:
        return None
    out: Set[str] = set()
    for region in regions:
        net = RegionNet.build(ec2, region)
        out.update(str(e["PublicIp"]) for e in table(ec2, "elastic_ips", region) if e.get("PublicIp"))
        for rec in table(ec2, "instances", region):
            v4, v6 = addresses(rec, net)
            out.update(v4 + v6)
    return out


def _address_records(zone: Mapping[str, Any], owned: Optional[Set[str]]) -> Dict[str, Any]:
    """Zone props for literal A / AAAA values: how many point at addresses this account holds (F-057).

    A value the account does not hold may be another provider's or a released Elastic IP: without AWS's address
    ranges the engine cannot tell, so this is context for the operator, never a finding.
    """
    values = sorted({str(v) for r in zone.get("Records") or () if isinstance(r, Mapping)
                     and r.get("Type") in ("A", "AAAA") and not r.get("AliasTarget")
                     for v in r.get("Values") or ()})
    if not values or owned is None:
        return {}
    mine = [v for v in values if v in owned]
    return {"address_values": len(values), "address_values_owned": len(mine)}


def route53(ctx: Any, builder: Any, data: Any, lb_names: Set[str]) -> None:
    check = TakeoverCheck(ctx, lb_names)
    owned = owned_ips(ctx)
    for zone in _records(data, "route53", "global"):
        zid = str(zone.get("Id") or "").rsplit("/", 1)[-1]
        try:
            node = ids.node_id_for("route53zone", zone_id=zid, partition=ctx.partition)
        except ValueError:
            continue
        private = bool(zone.get("Private"))
        cands = zone.get("TakeoverCandidates")
        gaps = ["route53:records-unknown"] if cands is None and "TakeoverCandidates" in zone else []
        props = {"zone_name": zone.get("Name"), "private": private, "record_count": zone.get("RecordCount"),
                 **(_address_records(zone, owned) if not private else {})}
        builder.add_node(node, "route53zone", str(zone.get("Name") or zid), account=ctx.account_id,
                         props={k: v for k, v in props.items() if v is not None},
                         coverage_status=layout_status(ctx, "partial" if gaps else None), coverage_gaps=gaps)
        for cand in cands or ():
            if isinstance(cand, Mapping):
                _candidate(builder, check, node, zone, cand, private)


def _candidate(builder: Any, check: TakeoverCheck, node: str, zone: Mapping[str, Any], cand: Mapping[str, Any],
               zone_private: bool) -> None:
    target = str(cand.get("Target") or "")
    kind, claimable = (cand.get("Kind"), cand.get("Claimable")) if cand.get("Kind") else (
        classify_target(target) or ("unknown", "info"))
    private = bool(cand.get("Private", zone_private))
    v = check.verdict(cand, str(kind), str(claimable), private)
    if v.severity is None:
        return
    name = str(cand.get("Name") or "")
    rtype = str(cand.get("Type") or "CNAME")
    builder.add_finding(
        "ROUTE53-DANGLING-001", node, severity=v.severity, confidence=v.confidence, gaps=v.gaps,
        title=f"Potential dangling DNS record: {name}",
        description=f"Record '{name}' ({rtype}) points at '{target}' ({kind}, takeover {claimable}): {v.reason}.",
        discriminator=f"{name}/{rtype}",
        evidence={"record": name, "type": rtype, "target": target, "kind": kind, "claimable": claimable,
                  "private": private, "alias": cand.get("Alias"), "check": v.reason},
        entity=f"route53/{zone.get('Name')}", entity_arn=node, resource=[name], source_type="route53_record")


# ══════════════════════════════════════════════════════════════════════════════
# The analyzer
# ══════════════════════════════════════════════════════════════════════════════

def run_edge_services(ctx: Any, builder: Any) -> None:
    """Phase RESOURCES: EBS snapshots, load balancers, Route 53 zones (module docstring)."""
    data = (ctx.data or {}).get("edge_services")
    if not isinstance(data, Mapping):
        raise AnalyzerSkipped("edge_services", reason="no edge-service data was loaded")
    ec2 = (ctx.data or {}).get("ec2")
    lb_names: Set[str] = set()
    for region in _region_units(data, "ebs", "elb"):
        ebs(ctx, builder, data, region)
        net = RegionNet.build(ec2, region) if isinstance(ec2, Mapping) else None
        lb_names.update(elb(ctx, builder, data, region, net))
    route53(ctx, builder, data, lb_names)


ANALYZERS: Tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec("edge_services", Phase.RESOURCES, run_edge_services, inputs=("route53", "ebs", "elb"),
                 legacy_files=(LEGACY_FILE,)),
)
