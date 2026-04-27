"""
EKS Enumeration Module

Collects:
- Clusters (full DescribeCluster: endpoint, OIDC, role, version, encryption, logging)
- Node groups (per cluster)
- Fargate profiles (per cluster)
- Addons (per cluster)

reports/{account}/{region}/eks/
├── clusters.json
├── nodegroups.json       # {cluster_name: [...]}
├── fargate_profiles.json # {cluster_name: [...]}
└── addons.json           # {cluster_name: [...]}
"""

import json
import os
from botocore.exceptions import ClientError


def enumerate(session, path):
    print("    \033[1;32m[+]\033[0m EKS Enumeration Starting...")
    os.makedirs(path, exist_ok=True)

    eks_client = session.client('eks')

    clusters = []
    nodegroups_by_cluster = {}
    fargate_by_cluster = {}
    addons_by_cluster = {}

    # List all clusters in the region
    cluster_names = []
    try:
        paginator = eks_client.get_paginator('list_clusters')
        for page in paginator.paginate():
            cluster_names.extend(page.get('clusters', []))
    except ClientError as e:
        with open(f"{path}/clusters.json", "w") as f:
            json.dump({"Error": str(e)}, f, indent=2)
        print(f"    \033[1;33m[!]\033[0m EKS list_clusters failed: {e}")
        return

    if not cluster_names:
        with open(f"{path}/clusters.json", "w") as f:
            json.dump([], f, indent=2)
        print("    \033[1;32m[+]\033[0m EKS Enumeration Finished (no clusters)")
        return

    # Per-cluster details
    for name in cluster_names:
        # Cluster details
        try:
            resp = eks_client.describe_cluster(name=name)
            cluster_info = resp.get('cluster', {})
            clusters.append(cluster_info)
        except ClientError as e:
            clusters.append({"name": name, "Error": str(e)})
            continue

        # Node groups
        try:
            ng_resp = eks_client.list_nodegroups(clusterName=name)
            ng_names = ng_resp.get('nodegroups', [])
            ng_details = []
            for ng_name in ng_names:
                try:
                    ng_detail = eks_client.describe_nodegroup(
                        clusterName=name, nodegroupName=ng_name
                    )
                    ng_details.append(ng_detail.get('nodegroup', {}))
                except ClientError as e:
                    ng_details.append({"name": ng_name, "Error": str(e)})
            nodegroups_by_cluster[name] = ng_details
        except ClientError as e:
            nodegroups_by_cluster[name] = {"Error": str(e)}

        # Fargate profiles
        try:
            fp_resp = eks_client.list_fargate_profiles(clusterName=name)
            fp_names = fp_resp.get('fargateProfileNames', [])
            fp_details = []
            for fp_name in fp_names:
                try:
                    fp_detail = eks_client.describe_fargate_profile(
                        clusterName=name, fargateProfileName=fp_name
                    )
                    fp_details.append(fp_detail.get('fargateProfile', {}))
                except ClientError as e:
                    fp_details.append({"name": fp_name, "Error": str(e)})
            fargate_by_cluster[name] = fp_details
        except ClientError as e:
            fargate_by_cluster[name] = {"Error": str(e)}

        # Addons
        try:
            addon_resp = eks_client.list_addons(clusterName=name)
            addon_names = addon_resp.get('addons', [])
            addon_details = []
            for addon_name in addon_names:
                try:
                    addon_detail = eks_client.describe_addon(
                        clusterName=name, addonName=addon_name
                    )
                    addon_details.append(addon_detail.get('addon', {}))
                except ClientError as e:
                    addon_details.append({"name": addon_name, "Error": str(e)})
            addons_by_cluster[name] = addon_details
        except ClientError as e:
            addons_by_cluster[name] = {"Error": str(e)}

    # Save outputs
    with open(f"{path}/clusters.json", "w") as f:
        json.dump(clusters, f, indent=2, default=str)

    with open(f"{path}/nodegroups.json", "w") as f:
        json.dump(nodegroups_by_cluster, f, indent=2, default=str)

    with open(f"{path}/fargate_profiles.json", "w") as f:
        json.dump(fargate_by_cluster, f, indent=2, default=str)

    with open(f"{path}/addons.json", "w") as f:
        json.dump(addons_by_cluster, f, indent=2, default=str)

    print(f"    \033[1;32m[+]\033[0m EKS Enumeration Finished ({len(clusters)} clusters)")
