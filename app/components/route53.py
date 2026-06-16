"""
AWS Route53 Enumeration Module

Collects hosted zones + record sets (global service). Flags CNAME/ALIAS records
pointing at takeover-prone targets (S3 website, CloudFront, ELB, Beanstalk, …) as
dangling-record candidates — useful for subdomain-takeover recon.

reports/{account}/route53/   (global)
└── resources.json   # Normalized: {Type, Id, Name, Private, Records, TakeoverCandidates}
"""

import fnmatch
import json
import os
from botocore.exceptions import ClientError

# Targets commonly associated with subdomain takeover when the backing
# resource has been de-provisioned but the DNS record remains.
TAKEOVER_PATTERNS = [
    "*.s3.amazonaws.com", "*.s3-website*.amazonaws.com", "*.cloudfront.net",
    "*.elasticbeanstalk.com", "*.elb.amazonaws.com", "*.*.elb.amazonaws.com",
    "*.github.io", "*.herokuapp.com", "*.azurewebsites.net",
]


def _is_takeover_candidate(target):
    t = (target or "").rstrip(".").lower()
    return any(fnmatch.fnmatch(t, p) for p in TAKEOVER_PATTERNS)


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m Route53 Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    client = session.client("route53")

    zones = []
    try:
        for page in client.get_paginator("list_hosted_zones").paginate():
            zones.extend(page.get("HostedZones", []))
    except ClientError as e:
        with open(f"{path}/resources.json", "w") as f:
            json.dump({"Error": str(e)}, f, indent=2)
        print(f"    \033[1;33m[!]\033[0m Route53 list_hosted_zones failed: {e}")
        return

    resources = []
    for zone in zones:
        zone_id = zone.get("Id", "").split("/")[-1]
        records, candidates = [], []
        try:
            for page in client.get_paginator("list_resource_record_sets").paginate(HostedZoneId=zone_id):
                for rr in page.get("ResourceRecordSets", []):
                    rtype = rr.get("Type")
                    targets = [v.get("Value") for v in rr.get("ResourceRecords", [])]
                    alias = rr.get("AliasTarget", {}).get("DNSName")
                    if alias:
                        targets.append(alias)
                    records.append({"Name": rr.get("Name"), "Type": rtype, "Targets": targets})
                    if rtype in ("CNAME", "A"):
                        for tgt in targets:
                            if _is_takeover_candidate(tgt):
                                candidates.append({"Name": rr.get("Name"), "Target": tgt})
        except ClientError:
            pass
        resources.append({
            "Type": "route53zone",
            "Id": zone_id,
            "Name": zone.get("Name"),
            "Private": zone.get("Config", {}).get("PrivateZone", False),
            "RecordCount": len(records),
            "Records": records,
            "TakeoverCandidates": candidates,
        })

    with open(f"{path}/resources.json", "w") as f:
        json.dump(resources, f, indent=2, default=str)

    cand = sum(len(z["TakeoverCandidates"]) for z in resources)
    print(f"    \033[1;32m[+]\033[0m Route53 Enumeration Finished ({len(resources)} zones, {cand} takeover candidates)")
