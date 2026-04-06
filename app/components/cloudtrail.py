import json
import os

def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m CloudTrail Enumeration Starting...")
    os.makedirs(path, exist_ok=True)
    client = session.client("cloudtrail")

    # Describe trails
    trails_response = client.describe_trails(includeShadowTrails=False)
    trails = trails_response.get("trailList", [])

    # Fetch additional details for each trail
    enriched_trails = []
    for trail in trails:
        trail_name = trail.get("Name")
        try:
            status = client.get_trail_status(Name=trail_name)
            insight_selectors = client.get_insight_selectors(Name=trail_name).get("InsightSelectors", [])
            trail["Status"] = status
            trail["InsightSelectors"] = insight_selectors
        except Exception as e:
            trail["Error"] = str(e)

        enriched_trails.append(trail)

    with open(f"{path}/trails.json", "w") as f:
        json.dump(enriched_trails, f, default=str, indent=2)

    print("    \033[1;32m[+]\033[0m CloudTrail Enumeration Finished!")
