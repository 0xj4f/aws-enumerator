import json
import os

def enumerate(session, path):
    os.makedirs(path, exist_ok=True)
    client = session.client("cloudfront")

    distributions = []
    paginator = client.get_paginator("list_distributions")

    for page in paginator.paginate():
        for dist in page.get("DistributionList", {}).get("Items", []):
            dist_id = dist["Id"]
            # Fetch full config
            try:
                config = client.get_distribution_config(Id=dist_id)
                summary = {
                    "Id": dist_id,
                    "ARN": dist.get("ARN"),
                    "DomainName": dist.get("DomainName"),
                    "Enabled": dist.get("Enabled"),
                    "Comment": dist.get("Comment"),
                    "Status": dist.get("Status"),
                    "Origins": config["DistributionConfig"].get("Origins", {}),
                    "DefaultCacheBehavior": config["DistributionConfig"].get("DefaultCacheBehavior", {}),
                    "ViewerCertificate": config["DistributionConfig"].get("ViewerCertificate", {}),
                    "PriceClass": config["DistributionConfig"].get("PriceClass"),
                    "WebACLId": config["DistributionConfig"].get("WebACLId"),
                    "Logging": config["DistributionConfig"].get("Logging", {}),
                    "HttpVersion": config["DistributionConfig"].get("HttpVersion"),
                    "IsIPV6Enabled": config["DistributionConfig"].get("IsIPV6Enabled"),
                }
                distributions.append(summary)
            except Exception as e:
                distributions.append({
                    "Id": dist_id,
                    "Error": str(e)
                })

    with open(f"{path}/distributions.json", "w") as f:
        json.dump(distributions, f, default=str, indent=2)
