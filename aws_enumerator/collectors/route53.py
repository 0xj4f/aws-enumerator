"""Route 53 (global): hosted zones, minimised record sets and subdomain-takeover candidates.

Output (``global/route53/``):

* ``resources.json`` (list), one item per hosted zone, sorted by ``Id``::

    {Type: "route53zone", Id, Arn, Name, Private: bool, ResourceRecordSetCount,
     RecordCount: int|null, Records: [...]|null, TakeoverCandidates: [...]|null, CollectionErrors?}

  ``Records`` items are ``{Name, Type, SetIdentifier, AliasTarget: {DNSName, HostedZoneId,
  EvaluateTargetHealth}|null, CnameTarget: str|null, ValueCount, Values: [...]|null, ValuesOmitted?}``.
  Record **values** are kept only where the analysis uses them: CNAME and NS values, and A/AAAA values
  in public zones. TXT/MX/SRV/CAA/SPF values (verification tokens, mail topology) and A/AAAA values of private
  zones are omitted (``Values: null, ValuesOmitted: true``) unless ``--full-dns`` (option
  ``full_dns``, F-112). ``Records``/``TakeoverCandidates`` are ``null`` when the zone's records could
  not be listed.

  ``TakeoverCandidates`` items are ``{Name, Type, Target, Kind, Claimable, Private, Alias}`` for A,
  AAAA and CNAME records (alias targets included) pointing at a provider whose name can be
  re-registered (F-057). ``Claimable`` is ``likely`` (S3 website and REST endpoints, Elastic
  Beanstalk, GitHub Pages, Heroku, Azure App Service / cloudapp / Traffic Manager), ``unlikely``
  (ELB names carry a random suffix) or ``info`` (CloudFront needs a valid certificate for the alias).
  Whether the target still exists is the engine's job (it has the S3/ELB/EIP data).
"""

from __future__ import annotations

import fnmatch
from typing import Any, Dict, List, Optional, Tuple

from aws_enumerator.collectors._common import add_error
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="route53", scope="global", output_dir="route53", services=("route53",),
    tier=1, cost="medium", noise="low", default=True, groups=("@network", "@edge"),
    actions=("route53:ListHostedZones", "route53:ListResourceRecordSets"),
    probe=("route53", "ListHostedZones", (("MaxItems", "1"),)),
    outputs=(("resources.json", "list"),),
    description="Route 53 hosted zones, minimised records and takeover candidates",
)

#: (glob on the lower-cased target without the trailing dot, kind, claimable), first match wins.
TAKEOVER_PATTERNS: Tuple[Tuple[str, str, str], ...] = (
    ("s3-website*.amazonaws.com", "s3-website", "likely"),          # alias form: no bucket label
    ("s3-website.*.amazonaws.com", "s3-website", "likely"),
    ("*.s3-website*.amazonaws.com", "s3-website", "likely"),
    ("*.s3-website.*.amazonaws.com", "s3-website", "likely"),
    ("*.s3.amazonaws.com", "s3", "likely"),
    ("*.s3.*.amazonaws.com", "s3", "likely"),
    ("*.s3-*.amazonaws.com", "s3", "likely"),
    ("*.elasticbeanstalk.com", "elasticbeanstalk", "likely"),
    ("*.github.io", "github-pages", "likely"),
    ("*.herokuapp.com", "heroku", "likely"),
    ("*.azurewebsites.net", "azure-app-service", "likely"),
    ("*.cloudapp.net", "azure-cloudapp", "likely"),
    ("*.cloudapp.azure.com", "azure-cloudapp", "likely"),
    ("*.trafficmanager.net", "azure-trafficmanager", "likely"),
    ("*.elb.amazonaws.com", "elb", "unlikely"),                    # ALB / classic: <name>.<region>.elb...
    ("*.elb.*.amazonaws.com", "elb", "unlikely"),                  # NLB: <name>.elb.<region>.amazonaws.com
    ("*.cloudfront.net", "cloudfront", "info"),
)
_CANDIDATE_TYPES = frozenset({"A", "AAAA", "CNAME"})
_PUBLIC_VALUE_TYPES = frozenset({"A", "AAAA", "CNAME", "NS"})   # values kept by default (public zones)
_PRIVATE_VALUE_TYPES = frozenset({"CNAME", "NS"})              # values kept by default (private zones)
_CLAIMABLE_ORDER = {"likely": 0, "unlikely": 1, "info": 2}


def classify_target(target: Optional[str]) -> Optional[Tuple[str, str]]:
    """``(kind, claimable)`` for a takeover-prone DNS target, else ``None``."""
    t = (target or "").strip().rstrip(".").lower()
    if t.startswith("dualstack."):
        t = t[len("dualstack."):]
    for pattern, kind, claimable in TAKEOVER_PATTERNS:
        if fnmatch.fnmatchcase(t, pattern):
            return kind, claimable
    return None


def project_record(rr: Dict[str, Any], *, private: bool, full_dns: bool) -> Dict[str, Any]:
    """The stored projection of one record set (values minimised, F-112)."""
    rtype = rr.get("Type")
    values = [v.get("Value") for v in rr.get("ResourceRecords") or []]
    alias = rr.get("AliasTarget")
    record: Dict[str, Any] = {
        "Name": rr.get("Name"), "Type": rtype, "SetIdentifier": rr.get("SetIdentifier"),
        "AliasTarget": {"DNSName": alias.get("DNSName"), "HostedZoneId": alias.get("HostedZoneId"),
                        "EvaluateTargetHealth": alias.get("EvaluateTargetHealth")} if alias else None,
        "CnameTarget": values[0] if rtype == "CNAME" and values else None,
        "ValueCount": len(values),
    }
    keep = full_dns or not values or rtype in (_PRIVATE_VALUE_TYPES if private else _PUBLIC_VALUE_TYPES)
    record["Values"] = values if keep else None
    if not keep:
        record["ValuesOmitted"] = True
    return record


def takeover_candidates(record: Dict[str, Any], *, private: bool) -> List[Dict[str, Any]]:
    if record["Type"] not in _CANDIDATE_TYPES:
        return []
    targets = [(record["CnameTarget"], False)] if record["CnameTarget"] else []
    if record["AliasTarget"]:
        targets.append((record["AliasTarget"]["DNSName"], True))
    out = []
    for target, alias in targets:
        hit = classify_target(target)
        if hit:
            out.append({"Name": record["Name"], "Type": record["Type"], "Target": (target or "").rstrip(".").lower(),
                        "Kind": hit[0], "Claimable": hit[1], "Private": private, "Alias": alias})
    return out


def _zone(ctx: Any, r53: Any, zone: Dict[str, Any], full_dns: bool) -> Dict[str, Any]:
    zone_id = str(zone.get("Id", "")).rsplit("/", 1)[-1]
    private = bool((zone.get("Config") or {}).get("PrivateZone", False))
    arn = ctx.arn("route53", f"hostedzone/{zone_id}", region="", account="")
    item: Dict[str, Any] = {"Type": "route53zone", "Id": zone_id, "Arn": arn, "Name": zone.get("Name"),
                            "Private": private, "ResourceRecordSetCount": zone.get("ResourceRecordSetCount"),
                            "RecordCount": None, "Records": None, "TakeoverCandidates": None}
    result = ctx.paginate(r53, "list_resource_record_sets", "ResourceRecordSets", item=arn, HostedZoneId=zone_id)
    if not result.ok:
        add_error(item, result)
        return item
    records = [project_record(rr, private=private, full_dns=full_dns) for rr in result.value]
    candidates = [c for r in records for c in takeover_candidates(r, private=private)]
    item["Records"] = records
    item["RecordCount"] = len(records)
    item["TakeoverCandidates"] = sorted(candidates, key=lambda c: (_CLAIMABLE_ORDER[c["Claimable"]], c["Name"],
                                                                   c["Type"], c["Target"]))
    return item


def collect(ctx: Any) -> None:
    r53 = ctx.client("route53")
    full_dns = bool(ctx.option("full_dns", False))
    zones: List[Dict[str, Any]] = []
    with ctx.section("zones"):
        listed = ctx.paginate(r53, "list_hosted_zones", "HostedZones", primary=True)
        for zone in sorted(listed.value, key=lambda z: str(z.get("Id"))):
            zones.append(_zone(ctx, r53, zone, full_dns))
    zones.sort(key=lambda z: z["Id"])
    ctx.out.write("resources.json", zones)
    candidates = sum(len(z["TakeoverCandidates"] or []) for z in zones)
    ctx.log.info("%d hosted zones, %d takeover candidates", len(zones), candidates)
