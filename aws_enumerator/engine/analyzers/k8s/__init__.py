"""Kubernetes and EKS analysis (E-k8s, Wave 2): the native analyzer of the ``k8s`` domain.

The d13c215 ``_analyze_k8s_relationships`` (one 456-line function) is split into submodules that read the k8s
loader's model (``io/loaders/k8s.py``: v2 projections and d13c215 layouts, ``null`` = unknown) and emit graph
nodes, edges and findings through the :class:`~aws_enumerator.engine.graph.builder.GraphBuilder`:

======================  ===========================================================================================
``util``                accessors for both object layouts, Kubernetes ids (cluster ARN in every id, F-025), pods
                        aggregated by owner, the per-cluster view
``cluster``             cluster / node-group nodes, ``CLUSTER_ROLE``, ``NODE_ROLE``, EKS-ENDPOINT-001,
                        K8S-AUTH-001, K8S-CALLER-001 (F-033, F-152)
``workloads``           service accounts, workloads, ``IN_CLUSTER``, ``RUNS_AS``, ``MOUNTS_SECRET``,
                        ``CAN_REACH_NODE_IMDS``; container-escape and default-SA findings (F-033, F-035, F-086)
``rbac``                roles, ``BOUND_TO`` for every subject kind, ``MEMBER_OF_K8S_GROUP``, ``CAN_RUN_AS_SA``;
                        K8S-RBAC-001/002/003 (F-035, F-086)
``eks_identity``        access entries and ``aws-auth``: ``EKS_ACCESS_ENTRY``, ``AWS_AUTH_MAPPING`` (F-050)
``irsa``                ``IRSA_BRIDGE`` / ``POD_IDENTITY`` verified against the role's trust (F-034, F-085, F-050)
``network``             ``SELECTS`` (indexed, F-087), ``INGRESS_ROUTES_TO``, internet-facing services (F-083)
======================  ===========================================================================================

One analyzer spec (``k8s``) runs them in that order, so a failure rolls the whole domain back (status ``error``,
the rest of the analysis still runs; F-002). The legacy output ``k8s_relationships.json`` is rendered from the graph
by the legacy writer. The d13c215 function is gone (Wave 3, D-53).
"""

from __future__ import annotations

import logging
from typing import Any, Tuple

from aws_enumerator.engine.analyzers.k8s.cluster import run_clusters
from aws_enumerator.engine.analyzers.k8s.eks_identity import run_eks_identity
from aws_enumerator.engine.analyzers.k8s.irsa import run_irsa
from aws_enumerator.engine.analyzers.k8s.network import run_network
from aws_enumerator.engine.analyzers.k8s.rbac import run_rbac
from aws_enumerator.engine.analyzers.k8s.util import LEGACY_FILE, cluster_views, loader_model
from aws_enumerator.engine.analyzers.k8s.workloads import run_workloads
from aws_enumerator.engine.findings.catalog import A_EXPOSURE, A_K8S, CatalogEntry
from aws_enumerator.engine.model import AnalyzerSpec, Phase

log = logging.getLogger("aws_enumerator.engine.analyzers.k8s")


def run_k8s(ctx: Any, builder: Any) -> None:
    """Every Kubernetes / EKS node, edge and finding of the analysed clusters (module docstring)."""
    model = loader_model(ctx)
    run_clusters(ctx, builder)
    workloads = run_workloads(ctx, builder)
    bindings = run_rbac(ctx, builder)
    mappings = run_eks_identity(ctx, builder)
    bridges = run_irsa(ctx, builder)
    network = run_network(ctx, builder)
    unrepresentable = sum(v.unrepresentable for v in cluster_views(ctx))
    if unrepresentable:
        ctx.add_gap("k8s:objects-unrepresentable", "Kubernetes objects whose names cannot form a node id "
                    "(node-ids.md) were left out of the graph.", unrepresentable)
    if model.regions_unknown:
        ctx.add_gap("k8s:clusters-unknown", "The EKS cluster list of some regions could not be read: their "
                    "clusters are unknown, not absent: " + ", ".join(model.regions_unknown), len(model.regions_unknown))
    log.info("k8s: %d cluster(s), %d workload(s), %d binding(s), %d IAM mapping edge(s), %d IAM bridge(s), "
             "%d service/ingress object(s)", len(model.clusters), workloads, bindings, mappings, bridges, network)


ANALYZERS: Tuple[AnalyzerSpec, ...] = (
    AnalyzerSpec("k8s", Phase.RESOURCES, run_k8s, inputs=("eks", "k8s"), legacy_files=(LEGACY_FILE,)),
)


def _k(fid: str, severity: str, category: str, title: str, remediation: str, anchor: str = A_K8S,
       discriminator: str = "") -> CatalogEntry:
    return CatalogEntry(fid, severity, category, title, remediation, anchor, discriminator=discriminator)


#: The finding ids this domain emits (engine-api.md §5, DECISIONS.md D-33).
FINDINGS: Tuple[CatalogEntry, ...] = (
    _k("EKS-ENDPOINT-001", "MEDIUM", "eks_exposure", "EKS API endpoint is public and open to the internet",
       "Disable public endpoint access, or restrict publicAccessCidrs to known administration networks.",
       A_EXPOSURE),
    _k("EKS-ADMIN-001", "INFO", "eks_identity", "IAM principal is a cluster administrator",
       "Review which IAM principals are mapped to system:masters or AmazonEKSClusterAdminPolicy; prefer "
       "namespaced access policies.", discriminator="principal"),
    _k("EKS-AUTH-MAP-001", "MEDIUM", "eks_identity", "aws-auth maps every principal of an account",
       "Replace mapAccounts entries by explicit mapRoles / access entries for the principals that need access.",
       discriminator="account"),
    _k("K8S-AUTH-001", "INFO", "k8s_coverage", "Kubernetes objects of the cluster were not enumerated",
       "Give the collecting identity read access to the cluster (an access entry or aws-auth mapping with the "
       "read-only RBAC of 'aws-enumerator permissions --k8s'), or use --k8s-auth kubeconfig/token, and re-run."),
    _k("K8S-CALLER-001", "INFO", "k8s_coverage", "Kubernetes permissions of the collecting identity",
       "No action needed; review whether the collecting identity's Kubernetes rights are broader than intended."),
    _k("K8S-IRSA-ADMIN", "CRITICAL", "k8s_irsa", "Service account can assume an admin IAM role",
       "Restrict the role to the permissions the workload needs, and scope its trust policy to this service "
       "account (exact sub and aud conditions).", discriminator="role-arn"),
    _k("K8S-IRSA-002", "LOW", "k8s_irsa", "Service account names an IAM role whose trust does not admit it",
       "Remove the stale eks.amazonaws.com/role-arn annotation or Pod Identity association, or fix the role's "
       "trust policy if the workload needs it.", discriminator="role-arn"),
    _k("K8S-IRSA-003", "INFO", "k8s_irsa", "Service account names an IAM role whose trust could not be evaluated",
       "Collect the role (or its account) to verify the trust policy.", discriminator="role-arn"),
    _k("K8S-DEFAULT-SA", "MEDIUM", "k8s_workload", "Workload runs as the default service account",
       "Create a dedicated ServiceAccount for this workload, or set automountServiceAccountToken: false."),
    _k("K8S-PRIV-001", "HIGH", "k8s_workload", "Privileged container",
       "Remove privileged: true (regular, init and ephemeral containers)."),
    _k("K8S-HOSTNET-001", "HIGH", "k8s_workload", "Pod uses the host network", "Remove hostNetwork: true."),
    _k("K8S-HOSTPID-001", "HIGH", "k8s_workload", "Pod shares the host PID namespace", "Remove hostPID: true."),
    _k("K8S-HOSTIPC-001", "HIGH", "k8s_workload", "Pod shares the host IPC namespace", "Remove hostIPC: true."),
    _k("K8S-HOSTPATH-001", "HIGH", "k8s_workload", "Pod mounts a hostPath volume",
       "Replace hostPath volumes by persistent volumes or projected sources; never mount the container runtime "
       "socket, the kubelet directory or the node's root filesystem."),
    _k("K8S-CAP-001", "HIGH", "k8s_workload", "Container adds dangerous Linux capabilities",
       "Drop the added capabilities (SYS_ADMIN, SYS_PTRACE, NET_ADMIN, ALL ...) and run with the default set."),
    _k("K8S-ESCALATION-001", "LOW", "k8s_workload", "Container explicitly allows privilege escalation",
       "Set allowPrivilegeEscalation: false."),
    _k("K8S-RBAC-001", "CRITICAL", "k8s_rbac", "Service account bound to cluster-admin or a wildcard role",
       "Use a more restrictive ClusterRole or a namespaced Role."),
    _k("K8S-RBAC-002", "HIGH", "k8s_rbac", "Role allows every verb on every resource",
       "Restrict verbs and resources to least privilege."),
    _k("K8S-RBAC-003", "CRITICAL", "k8s_rbac", "An all-identities group or user is bound to an admin role",
       "Remove the binding of system:authenticated / system:unauthenticated / system:anonymous / "
       "system:serviceaccounts to cluster-admin or wildcard roles."),
    _k("K8S-NET-001", "HIGH", "k8s_network", "Service is an internet-facing load balancer",
       "Use an internal load balancer (service.beta.kubernetes.io/aws-load-balancer-scheme: internal) or restrict "
       "loadBalancerSourceRanges.", A_EXPOSURE),
    _k("K8S-NET-002", "MEDIUM", "k8s_network", "Ingress exposes services without an authentication annotation",
       "Restrict the ingress or add authentication in front of it.", A_EXPOSURE),
)

__all__ = ["ANALYZERS", "FINDINGS", "run_k8s"]
