# v3 
import json
import os

def enumerate(session, path):
    os.makedirs(path, exist_ok=True)

    all_web_acls = []

    scopes = ["REGIONAL", "CLOUDFRONT"]

    for scope in scopes:
        # WAF for CLOUDFRONT requires a us-east-1 client
        region_session = session
        if scope == "CLOUDFRONT":
            region_session = session.__class__(profile_name=session.profile_name, region_name="us-east-1")
        
        client = region_session.client("wafv2")

        next_marker = None
        try:
            while True:
                kwargs = {"Scope": scope}
                if next_marker:
                    kwargs["NextMarker"] = next_marker

                response = client.list_web_acls(**kwargs)

                for acl in response.get("WebACLs", []):
                    acl_detail = {
                        "Id": acl["Id"],
                        "Name": acl["Name"],
                        "ARN": acl["ARN"],
                        "Scope": scope,
                    }

                    try:
                        details = client.get_web_acl(
                            Name=acl["Name"],
                            Scope=scope,
                            Id=acl["Id"]
                        )
                        acl_config = details.get("WebACL", {})
                        acl_detail.update({
                            "DefaultAction": acl_config.get("DefaultAction"),
                            "Description": acl_config.get("Description"),
                            "Rules": acl_config.get("Rules"),
                            "VisibilityConfig": acl_config.get("VisibilityConfig"),
                            "Capacity": acl_config.get("Capacity")
                        })

                        assoc = client.list_resources_for_web_acl(
                            WebACLArn=acl["ARN"],
                            ResourceType="CLOUDFRONT" if scope == "CLOUDFRONT" else "APPLICATION_LOAD_BALANCER"
                        )
                        acl_detail["AssociatedResources"] = assoc.get("ResourceArns", [])

                    except Exception as e:
                        acl_detail["Error"] = f"Error getting ACL config: {str(e)}"

                    all_web_acls.append(acl_detail)

                next_marker = response.get("NextMarker")
                if not next_marker:
                    break

        except Exception as e:
            all_web_acls.append({
                "Scope": scope,
                "Error": f"Error listing WAF WebACLs: {str(e)}"
            })

    with open(f"{path}/web_acls.json", "w") as f:
        json.dump(all_web_acls, f, default=str, indent=2)
