# V4 
import json
import os

def enumerate(session, path):
    os.makedirs(path, exist_ok=True)

    all_web_acls = []
    all_rule_groups = []
    all_ip_sets = []
    all_logging_configs = []

    scopes = ["REGIONAL", "CLOUDFRONT"]

    for scope in scopes:
        # WAF for CLOUDFRONT requires a us-east-1 client
        region_session = session
        if scope == "CLOUDFRONT":
            region_session = session.__class__(profile_name=session.profile_name, region_name="us-east-1")

        client = region_session.client("wafv2")

        # --- WebACLs ---
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

        # --- Rule Groups ---
        try:
            response = client.list_rule_groups(Scope=scope)
            for rule_group in response.get("RuleGroups", []):
                try:
                    details = client.get_rule_group(
                        Name=rule_group["Name"],
                        Scope=scope,
                        Id=rule_group["Id"]
                    )
                    all_rule_groups.append(details.get("RuleGroup", {}))
                except Exception as e:
                    all_rule_groups.append({
                        "Scope": scope,
                        "Error": f"Error getting Rule Group {rule_group['Name']}: {str(e)}"

                    })
        except Exception as e:
            all_rule_groups.append({
                "Scope": scope,
                "Error": f"Error listing Rule Groups: {str(e)}"
            })

        # --- IP Sets ---
        try:
            response = client.list_ip_sets(Scope=scope)
            for ip_set in response.get("IPSets", []):
                try:
                    details = client.get_ip_set(
                        Name=ip_set["Name"],
                        Scope=scope,
                        Id=ip_set["Id"]
                    )
                    all_ip_sets.append(details.get("IPSet", {}))
                except Exception as e:
                    all_ip_sets.append({
                        "Scope": scope,
                        "Error": f"Error getting IP Set {ip_set['Name']}: {str(e)}"
                    })
        except Exception as e:
            all_ip_sets.append({
                "Scope": scope,
                "Error": f"Error listing IP Sets: {str(e)}"
            })

        # --- Logging Configurations ---
        try:
            response = client.list_logging_configurations(Scope=scope)
            all_logging_configs.extend(response.get("LoggingConfigurations", []))
        except Exception as e:
            all_logging_configs.append({
                "Scope": scope,
                "Error": f"Error getting Logging Configs: {str(e)}"
            })

    with open(f"{path}/web_acls.json", "w") as f:
        json.dump(all_web_acls, f, default=str, indent=2)

    with open(f"{path}/rule_groups.json", "w") as f:
        json.dump(all_rule_groups, f, default=str, indent=2)

    with open(f"{path}/ip_sets.json", "w") as f:
        json.dump(all_ip_sets, f, default=str, indent=2)

    with open(f"{path}/logging_configs.json", "w") as f:
        json.dump(all_logging_configs, f, default=str, indent=2)