"""
Kubernetes API Enumeration Module

Reads EKS clusters from the eks/ directory output and enumerates each cluster's
K8s API for namespaces, pods, service accounts, RBAC, secrets (names only),
services, and ingresses.

reports/{account}/{region}/k8s/
└── {cluster_name}/
    ├── cluster_info.json       # version, endpoint, OIDC issuer, auth status
    ├── namespaces.json
    ├── pods.json
    ├── service_accounts.json   # CRITICAL: contains IRSA annotations
    ├── roles.json
    ├── cluster_roles.json
    ├── role_bindings.json
    ├── cluster_role_bindings.json
    ├── secrets.json            # names + types only
    ├── services.json
    └── ingresses.json
"""

import json
import os

try:
    from app.utils.eks_auth import build_k8s_client
except ImportError:
    from utils.eks_auth import build_k8s_client


def _safe_call(label, fn):
    """Run a K8s API call, return list on success or {'error': ...} on failure."""
    try:
        return fn()
    except Exception as e:
        return {"error": f"{label}: {type(e).__name__}: {str(e)[:200]}"}


def _serialize_object(obj):
    """Convert a Kubernetes API object to a JSON-friendly dict via its to_dict()."""
    try:
        return obj.to_dict()
    except AttributeError:
        return obj


def _enumerate_cluster(cluster_name, endpoint, ca_data, session, out_dir):
    """Enumerate a single EKS cluster's K8s API."""
    os.makedirs(out_dir, exist_ok=True)

    cluster_info = {
        "name": cluster_name,
        "endpoint": endpoint,
        "auth_status": "unknown"
    }

    api_client = None
    ca_path = None

    try:
        api_client, ca_path = build_k8s_client(cluster_name, endpoint, ca_data, session)
    except Exception as e:
        cluster_info["auth_status"] = "failed"
        cluster_info["error"] = f"{type(e).__name__}: {str(e)[:300]}"
        with open(f"{out_dir}/cluster_info.json", "w") as f:
            json.dump(cluster_info, f, indent=2, default=str)
        return

    try:
        from kubernetes import client as k8s_client

        core_v1 = k8s_client.CoreV1Api(api_client)
        rbac_v1 = k8s_client.RbacAuthorizationV1Api(api_client)
        networking_v1 = k8s_client.NetworkingV1Api(api_client)
        version_api = k8s_client.VersionApi(api_client)

        # Version probe (also tests connectivity)
        try:
            version = version_api.get_code()
            cluster_info["auth_status"] = "ok"
            cluster_info["version"] = {
                "major": version.major,
                "minor": version.minor,
                "git_version": version.git_version,
                "platform": version.platform
            }
        except Exception as e:
            cluster_info["auth_status"] = "failed"
            cluster_info["error"] = f"VersionApi: {type(e).__name__}: {str(e)[:300]}"
            with open(f"{out_dir}/cluster_info.json", "w") as f:
                json.dump(cluster_info, f, indent=2, default=str)
            return

        # Namespaces
        ns_data = _safe_call("namespaces", lambda: [
            _serialize_object(ns) for ns in core_v1.list_namespace().items
        ])
        with open(f"{out_dir}/namespaces.json", "w") as f:
            json.dump(ns_data, f, indent=2, default=str)

        # Pods
        pods_data = _safe_call("pods", lambda: [
            _serialize_object(p) for p in core_v1.list_pod_for_all_namespaces().items
        ])
        with open(f"{out_dir}/pods.json", "w") as f:
            json.dump(pods_data, f, indent=2, default=str)

        # Service Accounts (CRITICAL: IRSA annotations live here)
        sa_data = _safe_call("service_accounts", lambda: [
            _serialize_object(sa) for sa in core_v1.list_service_account_for_all_namespaces().items
        ])
        with open(f"{out_dir}/service_accounts.json", "w") as f:
            json.dump(sa_data, f, indent=2, default=str)

        # Roles
        roles_data = _safe_call("roles", lambda: [
            _serialize_object(r) for r in rbac_v1.list_role_for_all_namespaces().items
        ])
        with open(f"{out_dir}/roles.json", "w") as f:
            json.dump(roles_data, f, indent=2, default=str)

        # ClusterRoles
        cluster_roles_data = _safe_call("cluster_roles", lambda: [
            _serialize_object(r) for r in rbac_v1.list_cluster_role().items
        ])
        with open(f"{out_dir}/cluster_roles.json", "w") as f:
            json.dump(cluster_roles_data, f, indent=2, default=str)

        # RoleBindings
        rb_data = _safe_call("role_bindings", lambda: [
            _serialize_object(rb) for rb in rbac_v1.list_role_binding_for_all_namespaces().items
        ])
        with open(f"{out_dir}/role_bindings.json", "w") as f:
            json.dump(rb_data, f, indent=2, default=str)

        # ClusterRoleBindings
        crb_data = _safe_call("cluster_role_bindings", lambda: [
            _serialize_object(crb) for crb in rbac_v1.list_cluster_role_binding().items
        ])
        with open(f"{out_dir}/cluster_role_bindings.json", "w") as f:
            json.dump(crb_data, f, indent=2, default=str)

        # Secrets (NAMES + TYPES ONLY — never read values)
        def _list_secrets():
            secrets = core_v1.list_secret_for_all_namespaces().items
            return [
                {
                    "name": s.metadata.name,
                    "namespace": s.metadata.namespace,
                    "type": s.type,
                    "creation_timestamp": str(s.metadata.creation_timestamp) if s.metadata.creation_timestamp else None,
                    "annotations": s.metadata.annotations or {}
                }
                for s in secrets
            ]
        secrets_data = _safe_call("secrets", _list_secrets)
        with open(f"{out_dir}/secrets.json", "w") as f:
            json.dump(secrets_data, f, indent=2, default=str)

        # Services
        svc_data = _safe_call("services", lambda: [
            _serialize_object(s) for s in core_v1.list_service_for_all_namespaces().items
        ])
        with open(f"{out_dir}/services.json", "w") as f:
            json.dump(svc_data, f, indent=2, default=str)

        # Ingresses
        ing_data = _safe_call("ingresses", lambda: [
            _serialize_object(i) for i in networking_v1.list_ingress_for_all_namespaces().items
        ])
        with open(f"{out_dir}/ingresses.json", "w") as f:
            json.dump(ing_data, f, indent=2, default=str)

    finally:
        with open(f"{out_dir}/cluster_info.json", "w") as f:
            json.dump(cluster_info, f, indent=2, default=str)

        # Cleanup CA cert temp file
        if ca_path and os.path.exists(ca_path):
            try:
                os.remove(ca_path)
            except OSError:
                pass


def enumerate(session, eks_path, k8s_path):
    """Read clusters from eks_path/clusters.json and enumerate each one's K8s API."""
    clusters_file = os.path.join(eks_path, "clusters.json")
    if not os.path.isfile(clusters_file):
        return

    try:
        with open(clusters_file) as f:
            clusters = json.load(f)
    except (json.JSONDecodeError, OSError):
        return

    if not isinstance(clusters, list) or not clusters:
        return

    print("    \033[1;32m[+]\033[0m K8s Enumeration Starting...")
    os.makedirs(k8s_path, exist_ok=True)

    accessible = 0
    for cluster in clusters:
        if not isinstance(cluster, dict):
            continue
        cluster_name = cluster.get('name')
        endpoint = cluster.get('endpoint')
        ca_data = (cluster.get('certificateAuthority') or {}).get('data')

        if not cluster_name or not endpoint or not ca_data:
            continue

        out_dir = os.path.join(k8s_path, cluster_name)
        _enumerate_cluster(cluster_name, endpoint, ca_data, session, out_dir)

        # Check if it succeeded
        info_file = os.path.join(out_dir, "cluster_info.json")
        if os.path.isfile(info_file):
            try:
                with open(info_file) as f:
                    info = json.load(f)
                if info.get('auth_status') == 'ok':
                    accessible += 1
                else:
                    print(f"    \033[1;33m[!]\033[0m Cluster {cluster_name}: {info.get('error', 'auth failed')[:100]}")
            except Exception:
                pass

    print(f"    \033[1;32m[+]\033[0m K8s Enumeration Finished ({accessible}/{len(clusters)} clusters accessible)")
