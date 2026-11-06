"""Synthetic EKS clusters for the E-k8s analyzer tests (placeholder accounts, ``demo-*`` names only).

Kubernetes objects are written as the API server sends them (camelCase) and projected with the production
projections of the C-K8s collector (``aws_enumerator.k8s.projections``, through ``tests.support.targets``), so
the analyzers read exactly the v2 collector shapes: snake_case keys, annotation values ``null`` unless
allow-listed, env entries ``{name, value_from, value_present}``. ``layout="legacy"`` writes the same objects in
a d13c215 single-region report instead (no manifest 2.x, no ``_coverage.json``).

::

    rep = K8sReport(tmp_path)
    c = rep.cluster("demo-eks")
    c.sa("payments", "payments-sa", role_arn=rep.iam.arn("role", "demo-irsa"))
    c.pod("payments", "api-0", sa="payments-sa", owner=("ReplicaSet", "api-5d9f8c7b6d"),
          labels={"app": "api", "pod-template-hash": "5d9f8c7b6d"})
    rep.iam.role("demo-irsa", c.irsa_trust("payments", "payments-sa"), attached=["AdministratorAccess"])
    graph = rep.analyze().graph
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from tests.support import report_builder as rb
from tests.support import targets

ACCT = "123456789012"
FOREIGN = "999999999999"
REGION = "eu-west-2"
OTHER = "eu-west-1"
ADMIN_POLICY = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
EDIT_POLICY = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSEditPolicy"
VIEW_POLICY = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
#: Strings that must never reach any analysis output (env values, Secret data).
CANARY = "AE-K8S-CANARY-not-a-real-secret"


def proj() -> Any:
    return targets.k8s_module("projections")


# ── raw Kubernetes objects (API JSON) ────────────────────────────────────────

def meta(name: str, namespace: Optional[str] = None, *, labels: Optional[Mapping[str, str]] = None,
         annotations: Optional[Mapping[str, str]] = None,
         owner: Optional[Tuple[str, str]] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {"name": name, "uid": f"uid-{namespace}-{name}", "resourceVersion": "1",
                           "managedFields": [{"manager": "kubectl", "fieldsV1": {"f:data": {}}}]}
    if namespace is not None:
        out["namespace"] = namespace
    if labels:
        out["labels"] = dict(labels)
    if annotations:
        out["annotations"] = dict(annotations)
    if owner:
        out["ownerReferences"] = [{"apiVersion": "apps/v1", "kind": owner[0], "name": owner[1], "controller": True,
                                   "uid": "uid-owner"}]
    return out


def container(name: str = "main", *, privileged: Optional[bool] = None, escalation: Optional[bool] = None,
              caps: Sequence[str] = (), env: Sequence[Mapping[str, Any]] = (),
              env_from: Sequence[Mapping[str, Any]] = ()) -> Dict[str, Any]:
    sc: Dict[str, Any] = {}
    if privileged is not None:
        sc["privileged"] = privileged
    if escalation is not None:
        sc["allowPrivilegeEscalation"] = escalation
    if caps:
        sc["capabilities"] = {"add": list(caps)}
    out: Dict[str, Any] = {"name": name, "image": "public.ecr.aws/docker/library/busybox:1.36",
                           "command": ["sh", "-c", f"echo {CANARY}"]}
    if sc:
        out["securityContext"] = sc
    if env:
        out["env"] = [dict(e) for e in env]
    if env_from:
        out["envFrom"] = [dict(e) for e in env_from]
    return out


def env_value(name: str, value: str = CANARY) -> Dict[str, Any]:
    return {"name": name, "value": value}


def env_secret(name: str, secret: str, key: str = "password") -> Dict[str, Any]:
    return {"name": name, "valueFrom": {"secretKeyRef": {"name": secret, "key": key}}}


def env_from_secret(secret: str) -> Dict[str, Any]:
    return {"secretRef": {"name": secret}}


def secret_volume(secret: str) -> Dict[str, Any]:
    return {"name": f"vol-{secret}", "secret": {"secretName": secret}}


def host_path_volume(path: str, name: str = "host") -> Dict[str, Any]:
    return {"name": name, "hostPath": {"path": path, "type": "Directory"}}


def token_volume(audience: str, name: str = "aws-token") -> Dict[str, Any]:
    return {"name": name, "projected": {"sources": [{"serviceAccountToken": {"audience": audience,
                                                                              "expirationSeconds": 86400,
                                                                              "path": "token"}}]}}


def rule(verbs: Sequence[str], resources: Sequence[str], groups: Sequence[str] = ("",),
         names: Sequence[str] = ()) -> Dict[str, Any]:
    out: Dict[str, Any] = {"apiGroups": list(groups), "resources": list(resources), "verbs": list(verbs)}
    if names:
        out["resourceNames"] = list(names)
    return out


def subject(kind: str, name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {"kind": kind, "name": name}
    if kind != "ServiceAccount":
        out["apiGroup"] = "rbac.authorization.k8s.io"
    if namespace is not None:
        out["namespace"] = namespace
    return out


# ── one cluster ──────────────────────────────────────────────────────────────

@dataclass
class Cluster:
    """One EKS cluster: its DescribeCluster record, EKS maps and Kubernetes objects (raw API JSON)."""

    name: str
    region: str
    account: str
    auth_status: Optional[str] = "ok"
    mode: Optional[str] = "API_AND_CONFIG_MAP"
    public: Optional[bool] = True
    cidrs: Optional[List[str]] = field(default_factory=lambda: ["0.0.0.0/0"])
    lists: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    nodegroups: List[Dict[str, Any]] = field(default_factory=list)
    fargate: List[Dict[str, Any]] = field(default_factory=list)
    access_entries: List[Dict[str, Any]] = field(default_factory=list)
    pod_identity: List[Dict[str, Any]] = field(default_factory=list)
    aws_auth: Optional[Dict[str, str]] = None           # raw ConfigMap data; None = no aws-auth
    self_rules: Optional[List[Dict[str, Any]]] = None
    resource_status: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    omit: Tuple[str, ...] = ()                          # list files not written (unknown)
    extra_info: Dict[str, Any] = field(default_factory=dict)

    @property
    def arn(self) -> str:
        return f"arn:aws:eks:{self.region}:{self.account}:cluster/{self.name}"

    @property
    def issuer_host(self) -> str:
        return f"oidc.eks.{self.region}.amazonaws.com/id/{('DEMO' + self.name.upper().replace('-', ''))[:32]:0<32}"

    @property
    def provider_arn(self) -> str:
        return f"arn:aws:iam::{self.account}:oidc-provider/{self.issuer_host}"

    def id(self, kind: str, namespace: Optional[str], name: str) -> str:
        return f"k8s://{self.arn}/{kind}/{namespace or '_'}/{name}"

    def record(self) -> Dict[str, Any]:
        vpc: Dict[str, Any] = {"subnetIds": ["subnet-0a1b2c3d4e5f6aaaa"], "vpcId": "vpc-0a1b2c3d4e5f6aaaa",
                               "endpointPrivateAccess": True}
        if self.public is not None:
            vpc["endpointPublicAccess"] = self.public
        if self.cidrs is not None:
            vpc["publicAccessCidrs"] = list(self.cidrs)
        rec: Dict[str, Any] = {
            "name": self.name, "arn": self.arn, "version": "1.30", "status": "ACTIVE",
            "endpoint": f"https://{self.name}.gr7.{self.region}.eks.amazonaws.com",
            "roleArn": f"arn:aws:iam::{self.account}:role/demo-eks-cluster-role", "resourcesVpcConfig": vpc,
            "identity": {"oidc": {"issuer": f"https://{self.issuer_host}"}}, "tags": {"env": "demo"},
        }
        if self.mode is not None:
            rec["accessConfig"] = {"authenticationMode": self.mode}
        return rec

    # objects --------------------------------------------------------------
    def _add(self, kind: str, obj: Dict[str, Any]) -> Dict[str, Any]:
        self.lists.setdefault(kind, []).append(obj)
        return obj

    def namespace(self, name: str) -> None:
        self._add("namespaces", {"metadata": meta(name), "status": {"phase": "Active"}})

    def sa(self, namespace: str, name: str, *, role_arn: Optional[str] = None, audience: Optional[str] = None,
           automount: Optional[bool] = None) -> Dict[str, Any]:
        ann = {"kubectl.kubernetes.io/last-applied-configuration": json.dumps({"data": CANARY})}
        if role_arn:
            ann["eks.amazonaws.com/role-arn"] = role_arn
        if audience:
            ann["eks.amazonaws.com/audience"] = audience
        obj: Dict[str, Any] = {"metadata": meta(name, namespace, annotations=ann)}
        if automount is not None:
            obj["automountServiceAccountToken"] = automount
        return self._add("service_accounts", obj)

    def pod(self, namespace: str, name: str, *, sa: Optional[str] = None, owner: Optional[Tuple[str, str]] = None,
            labels: Optional[Mapping[str, str]] = None, node: Optional[str] = "ip-10-0-1-10.demo.internal",
            containers: Sequence[Dict[str, Any]] = (), init: Sequence[Dict[str, Any]] = (),
            ephemeral: Sequence[Dict[str, Any]] = (), volumes: Sequence[Dict[str, Any]] = (),
            host_network: bool = False, host_pid: bool = False, host_ipc: bool = False,
            automount: Optional[bool] = None) -> Dict[str, Any]:
        spec: Dict[str, Any] = {"containers": list(containers) or [container()]}
        if sa is not None:
            spec["serviceAccountName"] = sa
        if node is not None:
            spec["nodeName"] = node
        if init:
            spec["initContainers"] = list(init)
        if ephemeral:
            spec["ephemeralContainers"] = list(ephemeral)
        if volumes:
            spec["volumes"] = list(volumes)
        for key, on in (("hostNetwork", host_network), ("hostPID", host_pid), ("hostIPC", host_ipc)):
            if on:
                spec[key] = True
        if automount is not None:
            spec["automountServiceAccountToken"] = automount
        return self._add("pods", {"metadata": meta(name, namespace, labels=labels, owner=owner), "spec": spec,
                                  "status": {"phase": "Running"}})

    def role(self, namespace: Optional[str], name: str, rules: Sequence[Dict[str, Any]],
             labels: Optional[Mapping[str, str]] = None) -> None:
        kind = "roles" if namespace else "cluster_roles"
        self._add(kind, {"metadata": meta(name, namespace, labels=labels), "rules": list(rules)})

    def binding(self, namespace: Optional[str], name: str, role_kind: str, role_name: str,
                subjects: Sequence[Dict[str, Any]]) -> None:
        kind = "role_bindings" if namespace else "cluster_role_bindings"
        self._add(kind, {"metadata": meta(name, namespace), "subjects": list(subjects),
                         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": role_kind,
                                     "name": role_name}})

    def service(self, namespace: str, name: str, *, svc_type: str = "ClusterIP",
                selector: Optional[Mapping[str, str]] = None, annotations: Optional[Mapping[str, str]] = None,
                source_ranges: Sequence[str] = (), lb_class: Optional[str] = None,
                lb_hostname: Optional[str] = None) -> None:
        spec: Dict[str, Any] = {"type": svc_type, "ports": [{"port": 443, "targetPort": 8443, "protocol": "TCP"}]}
        if selector:
            spec["selector"] = dict(selector)
        if source_ranges:
            spec["loadBalancerSourceRanges"] = list(source_ranges)
        if lb_class:
            spec["loadBalancerClass"] = lb_class
        status = {"loadBalancer": {"ingress": [{"hostname": lb_hostname}]}} if lb_hostname else {}
        self._add("services", {"metadata": meta(name, namespace, annotations=annotations), "spec": spec,
                               "status": status})

    def ingress(self, namespace: str, name: str, backend: str, *, ingress_class: Optional[str] = "alb",
                annotations: Optional[Mapping[str, str]] = None) -> None:
        spec: Dict[str, Any] = {"rules": [{"host": "demo.example.com", "http": {"paths": [
            {"path": "/", "pathType": "Prefix", "backend": {"service": {"name": backend, "port": {"number": 443}}}}]}}]}
        if ingress_class:
            spec["ingressClassName"] = ingress_class
        self._add("ingresses", {"metadata": meta(name, namespace, annotations=annotations), "spec": spec})

    def node(self, name: str, *, instance_id: Optional[str] = None, nodegroup: Optional[str] = None,
             fargate: bool = False) -> None:
        labels = {"topology.kubernetes.io/zone": f"{self.region}a"}
        if nodegroup:
            labels["eks.amazonaws.com/nodegroup"] = nodegroup
        if fargate:
            labels["eks.amazonaws.com/compute-type"] = "fargate"
        provider = f"aws:///{self.region}a/{instance_id}" if instance_id else None
        spec = {"providerID": provider} if provider else {}
        self._add("nodes", {"metadata": meta(name, labels=labels), "spec": spec, "status": {}})

    # EKS ------------------------------------------------------------------
    def nodegroup(self, name: str, role_arn: str) -> str:
        arn = f"arn:aws:eks:{self.region}:{self.account}:nodegroup/{self.name}/{name}/0a1b2c3d"
        self.nodegroups.append({"nodegroupName": name, "nodegroupArn": arn, "clusterName": self.name,
                                "nodeRole": role_arn, "capacityType": "ON_DEMAND", "amiType": "AL2023_x86_64"})
        return arn

    def access_entry(self, principal_arn: str, *, groups: Sequence[str] = (), username: Optional[str] = None,
                     policies: Sequence[Tuple[str, Optional[Sequence[str]]]] = (),
                     entry_type: str = "STANDARD") -> None:
        assoc = [{"policyArn": p, "accessScope": ({"type": "namespace", "namespaces": list(ns)} if ns else
                                                  {"type": "cluster", "namespaces": []})} for p, ns in policies]
        self.access_entries.append({"clusterName": self.name, "principalArn": principal_arn,
                                    "kubernetesGroups": list(groups), "username": username or principal_arn,
                                    "type": entry_type, "associatedAccessPolicies": assoc})

    def pod_identity_association(self, namespace: str, sa: str, role_arn: Optional[str]) -> None:
        self.pod_identity.append({"clusterName": self.name, "namespace": namespace, "serviceAccount": sa,
                                  "roleArn": role_arn, "associationId": f"a-{namespace}-{sa}",
                                  "associationArn": f"arn:aws:eks:{self.region}:{self.account}:"
                                                    f"podidentityassociation/{self.name}/a-{namespace}-{sa}"})

    # trust documents ------------------------------------------------------
    def irsa_trust(self, namespace: str, sa: str, *, operator: str = "StringEquals",
                   aud: Optional[str] = "sts.amazonaws.com", provider: Optional[str] = None) -> Dict[str, Any]:
        cond: Dict[str, Any] = {f"{self.issuer_host}:sub": f"system:serviceaccount:{namespace}:{sa}"}
        if aud:
            cond[f"{self.issuer_host}:aud"] = aud
        return rb.trust({"Federated": provider or self.provider_arn}, "sts:AssumeRoleWithWebIdentity", {operator: cond})


@dataclass
class K8sReport:
    """A report holding IAM plus any number of clusters, in the legacy single-region or the v2 run layout."""

    root: Path
    account: str = ACCT
    regions: Tuple[str, ...] = (REGION,)
    layout: str = "legacy"
    iam: rb.Iam = field(init=False)
    clusters: List[Cluster] = field(default_factory=list)
    instances: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    k8s_module_status: Optional[str] = None             # v2: "skipped" for --no-k8s
    coverage: Dict[Tuple[str, str], Dict[str, Any]] = field(default_factory=dict)   # (module, region) -> kwargs
    extra_cluster_records: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.iam = rb.Iam(self.account)
        self.iam.role("demo-eks-cluster-role", rb.trust({"Service": "eks.amazonaws.com"}))
        self.iam.role("demo-eks-node-role", rb.trust({"Service": "ec2.amazonaws.com"}),
                      inline={"node": [rb.allow(["ec2:DescribeInstances", "eks:DescribeCluster"], "*")]})

    def cluster(self, name: str = "demo-eks", *, region: Optional[str] = None, **kw: Any) -> Cluster:
        c = Cluster(name, region or self.regions[0], self.account, **kw)
        for ns in ("default", "kube-system"):
            c.namespace(ns)
        self.clusters.append(c)
        return c

    def instance(self, region: str, instance_id: str, *, dns: str, nodegroup: Optional[str], cluster: str,
                 tokens: str = "optional", hop_limit: int = 1, endpoint: str = "enabled") -> None:
        self.instances.setdefault(region, []).append({
            "InstanceId": instance_id, "PrivateDnsName": dns, "State": {"Name": "running"},
            "MetadataOptions": {"HttpTokens": tokens, "HttpPutResponseHopLimit": hop_limit, "HttpEndpoint": endpoint},
            "Tags": [{"Key": "eks:cluster-name", "Value": cluster}]
            + ([{"Key": "eks:nodegroup-name", "Value": nodegroup}] if nodegroup else []),
        })

    # writing --------------------------------------------------------------
    def _write_region(self, scope: rb.Scope, region: str) -> None:
        clusters = [c for c in self.clusters if c.region == region]
        if self.layout == "legacy":
            rb.write_empty_regional(scope, skip=("eks", "ec2"))
        scope.write("ec2/instances.json", self.instances.get(region, []))
        scope.write("eks/clusters.json", [c.record() for c in clusters] + self.extra_cluster_records.get(region, []))
        scope.write("eks/nodegroups.json", {c.name: c.nodegroups for c in clusters})
        scope.write("eks/fargate_profiles.json", {c.name: c.fargate for c in clusters})
        if self.layout == "v2":
            scope.write("eks/access_entries.json", {c.name: c.access_entries for c in clusters})
            scope.write("eks/pod_identity_associations.json", {c.name: c.pod_identity for c in clusters})
        for c in clusters:
            self._write_k8s(scope, c)

    def _write_k8s(self, scope: rb.Scope, c: Cluster) -> None:
        if c.auth_status is None:
            return
        p = proj()
        projectors = {
            "namespaces": p.project_namespace, "pods": p.project_pod, "service_accounts": p.project_service_account,
            "roles": lambda o: p.project_role(o, "Role"), "cluster_roles": lambda o: p.project_role(o, "ClusterRole"),
            "role_bindings": lambda o: p.project_binding(o, "RoleBinding"),
            "cluster_role_bindings": lambda o: p.project_binding(o, "ClusterRoleBinding"),
            "services": p.project_service, "ingresses": p.project_ingress, "nodes": p.project_node,
        }
        base = f"k8s/{c.name}"
        resources: Dict[str, Any] = {}
        if c.auth_status == "ok":
            for kind, fn in projectors.items():
                if kind in c.omit:
                    continue
                items = p.project_all(c.lists.get(kind, []), fn)
                scope.write(f"{base}/{kind}.json", items)
                resources[kind] = c.resource_status.get(kind) or {"status": "ok", "scope": "cluster",
                                                                   "error_code": None, "items": len(items)}
            auth = p.parse_aws_auth({"data": c.aws_auth} if c.aws_auth is not None else None)
            scope.write(f"{base}/aws_auth.json", auth)
            scope.write(f"{base}/self_rules.json", c.self_rules or [])
        info = {"name": c.name, "arn": c.arn, "auth_status": c.auth_status, "auth_mode": "eks-token",
                "error_code": None if c.auth_status == "ok" else "Unauthorized", "resources": resources}
        info.update(c.extra_info)
        scope.write(f"{base}/cluster_info.json", info)

    def write(self) -> Path:
        if self.layout == "v2":
            return self._write_v2()
        assert len(self.regions) == 1, "the legacy layout is single-region"
        scope = rb.Scope(self.root, self.account, self.regions[0])
        self.iam.write(scope)
        self._write_region(scope, self.regions[0])
        rb.write_manifest(scope.path, account=self.account, mode="single_region", region=self.regions[0])
        return scope.path

    def _write_v2(self) -> Path:
        run = rb.V2Run(self.root, account=self.account, regions=list(self.regions))
        g = run.unit("global")
        self.iam.write(g, layout="gaad")
        run.coverage("iam", "global")
        for region in self.regions:
            scope = run.unit(region)
            self._write_region(scope, region)
            run.coverage("eks", region, **self.coverage.get(("eks", region), {}))
            run.coverage("ec2", region)
            if self.k8s_module_status == "skipped":
                run.skip("k8s", region, "disabled by --no-k8s")
            else:
                run.coverage("k8s", region)
        run.finalize()
        return run.path

    def analyze(self, **options: Any) -> SimpleNamespace:
        path = self.write()
        engine = targets.engine_module()
        opts = targets.engine_module("model").AnalysisOptions(**options) if options else None
        result = engine.analyze_report(str(path), opts)
        graph = json.loads(Path(result.graph_path).read_text(encoding="utf-8")) if result.graph_path else None
        return SimpleNamespace(result=result, graph=graph, path=path,
                               dir=Path(result.analysis_dir or path / "analysis"))


# ── graph helpers ────────────────────────────────────────────────────────────

def nodes_by_id(graph: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {n["id"]: n for n in graph["nodes"]}


def edges(graph: Mapping[str, Any], edge_type: Optional[str] = None, *, source: Optional[str] = None,
          target: Optional[str] = None) -> List[Dict[str, Any]]:
    return [e for e in graph["edges"] if (edge_type is None or e["type"] == edge_type)
            and (source is None or e["source"] == source) and (target is None or e["target"] == target)]


def edge(graph: Mapping[str, Any], edge_type: str, source: str, target: str) -> Optional[Dict[str, Any]]:
    hits = edges(graph, edge_type, source=source, target=target)
    return hits[0] if hits else None


def findings(graph: Mapping[str, Any], fid: str, node_id: Optional[str] = None) -> List[Dict[str, Any]]:
    return [f for f in graph["findings"] if f["id"] == fid and (node_id is None or f["node_id"] == node_id)]


def problems(graph: Mapping[str, Any]) -> List[str]:
    return targets.engine_module("writers.graph_json").problems(graph)


def path(graph: Mapping[str, Any], source: str, target: str) -> Any:
    from tests.support import ref_paths

    return ref_paths.shortest_path(graph, source, target)


def iam_arn(kind: str, name: str, account: str = ACCT, path_: str = "/") -> str:
    return f"arn:aws:iam::{account}:{kind}{path_}{name}"


def status(graph: Mapping[str, Any], name: str = "k8s") -> Optional[str]:
    for s in graph["analyzer_status"]:
        if s["name"] == name:
            return s["status"]
    return None
