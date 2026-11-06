"""The Kubernetes API of each EKS cluster (collectors-cli.md §5.16).

On by default (owner decision); ``--no-k8s`` turns it off (F-062). Clusters come from the eks module's
return value in the same unit (``ctx.deps["eks"]``), never from files on disk. For each cluster:

1. authenticate (``--k8s-auth``: ``eks-token`` with a partition-aware presigned STS URL, ``kubeconfig``,
   ``token`` or ``in-cluster``; F-119, F-152) and probe ``GET /version``;
2. list namespaces, then run a ``SelfSubjectRulesReview`` per namespace (the only non-GET request, and it
   persists nothing; ``--no-k8s-self-review`` disables it) and save it (F-152);
3. list pods, service accounts, roles, cluster roles, role bindings, cluster role bindings, services,
   ingresses and nodes with ``limit=500``/``continue`` paging and one restart on ``410 Gone`` (F-149); a
   namespaced resource whose cluster-wide list is forbidden is listed in each namespace the rules review
   allows (F-152);
4. read ``kube-system/aws-auth`` and keep only ``mapRoles``/``mapUsers``/``mapAccounts`` (F-050);
5. only with ``--k8s-secrets``: list Secret **metadata** (``PartialObjectMetadataList``, one
   ``fieldSelector=type=<T>`` list per known type). Without it no ``/secrets`` request is made (F-009, F-150).

Every request has a ``(connect, read)`` timeout (``--k8s-timeout``, default ``5,60``; 3 s connect for a
private or CIDR-restricted endpoint, with a hint) and urllib3 retries set to 1 (F-120). Objects are
projected (:mod:`aws_enumerator.k8s.projections`): no Secret value, no ``last-applied-configuration``, no
``managedFields``, no env value (F-009, F-054). If the ``kubernetes`` package is missing, each cluster gets
``auth_status: "dependency_missing"``, one WARNING is logged and the module is ``skipped`` (F-136).

Options read (cli.md §3.1): ``k8s``/``no_k8s``, ``k8s_secrets``, ``k8s_auth``, ``kubeconfig``,
``kube_context``, ``k8s_token_file``, ``k8s_ca_file``, ``k8s_clusters``, ``k8s_timeout``,
``k8s_self_review``/``no_k8s_self_review``, ``no_rate_limit``, ``max_rps``, ``rate_limit``, ``no_ua_tag``,
``ua_app_id`` (:mod:`aws_enumerator.k8s.options`).

Output (``<region>/k8s/<cluster>/``):

``cluster_info.json``
    dict ``{name, arn, endpoint, auth_mode, auth_status: ok|failed|unreachable|forbidden|dependency_missing|
    skipped, error_code, error, version{major, minor, git_version, platform}, endpoint_public_access,
    endpoint_private_access, public_access_cidrs, endpoint_hint, self_rules_reviewed, self_rules_namespaces,
    self_rules_truncated, secrets_listed, resources{<file stem>: {status, scope, error_code, items,
    namespaces}}}``. Written for every cluster, including skipped ones.
``namespaces.json``, ``pods.json``, ``service_accounts.json``, ``roles.json``, ``cluster_roles.json``,
``role_bindings.json``, ``cluster_role_bindings.json``, ``services.json``, ``ingresses.json``, ``nodes.json``
    lists of projected objects (snake_case keys), sorted by (namespace, name); written once the cluster
    answered ``/version``.
``self_rules.json``
    list ``[{namespace, resource_rules, non_resource_rules, incomplete, evaluation_error}]``.
``aws_auth.json``
    dict ``{present, map_roles, map_users, map_accounts, parse_errors}`` (``null`` values when unreadable).
``secrets.json``
    only with ``--k8s-secrets``: list ``[{name, namespace, type, labels, annotations}]``.

Plus ``<region>/k8s/_coverage.json``: Kubernetes requests are recorded as ``k8s:<Operation>`` calls with the
cluster ARN (or ``k8s://<cluster ARN>/Namespace/_/<ns>``) as the item.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from aws_enumerator.coverage import CIRCUIT_OPEN_DENIED, CallResult
from aws_enumerator.k8s import projections as proj
from aws_enumerator.k8s.auth import ClusterTarget, K8sAuthError, connect, kubernetes_available
from aws_enumerator.k8s.options import K8sOptions
from aws_enumerator.k8s.rbac import REQUIRED_RULES
from aws_enumerator.k8s.reader import RESOURCES, K8sReader, ListOutcome, ReadOutcome, Resource, rules_allow
from aws_enumerator.k8s.transport import PRIVATE_CONNECT_TIMEOUT, ApiClientTransport, K8sRequestError, RateGate
from aws_enumerator.registry import CollectorSpec
from aws_enumerator.util import fsio

SPEC = CollectorSpec(
    name="k8s", scope="k8s", output_dir="k8s", services=("eks",),
    tier=1, cost="medium", noise="high", default=True, groups=("@k8s",), depends_on=("eks",),
    actions=(),  # no AWS API call: the EKS token is presigned locally; access is granted by Kubernetes RBAC
    k8s_rbac=REQUIRED_RULES,
    outputs=(("*/cluster_info.json", "dict"), ("*/aws_auth.json", "dict"), ("*/*.json", "list")),
    description=("Kubernetes API of each EKS cluster (on by default, --no-k8s turns it off; Secret metadata "
                 "only with --k8s-secrets)"),
)

#: SelfSubjectRulesReview requests per cluster at most (one per namespace).
MAX_REVIEW_NAMESPACES = 100
SECRETS_NOTICE = ("--k8s-secrets: listing Secret metadata only (names, namespaces, types; never values). The "
                  "RBAC permission 'list secrets' still lets its holder read every Secret value.")
_FALLBACK_NAMESPACES = ("default", "kube-system")
_AWS_AUTH_PATH = "/api/v1/namespaces/kube-system/configmaps/aws-auth"

#: The lists read for every reachable cluster, in order, with their projection.
_LISTS: Tuple[Tuple[str, Callable[[Mapping[str, Any]], Dict[str, Any]]], ...] = (
    ("pods", proj.project_pod),
    ("service_accounts", proj.project_service_account),
    ("roles", lambda o: proj.project_role(o, "Role")),
    ("cluster_roles", lambda o: proj.project_role(o, "ClusterRole")),
    ("role_bindings", lambda o: proj.project_binding(o, "RoleBinding")),
    ("cluster_role_bindings", lambda o: proj.project_binding(o, "ClusterRoleBinding")),
    ("services", proj.project_service),
    ("ingresses", proj.project_ingress),
    ("nodes", proj.project_node),
)

_ERRORS = {
    "unreachable": "the API endpoint could not be reached",
    "timeout": "the API endpoint did not answer in time",
    "tls": "TLS verification of the API endpoint failed",
    401: "the API server rejected the credentials (HTTP 401); is the principal mapped by an EKS access entry "
         "or aws-auth?",
}


def _call_status(err: K8sRequestError) -> str:
    if err.status in (401, 403):
        return "denied"
    if err.status == 429:
        return "throttled"
    return "error"


def _cluster_dir(target: ClusterTarget) -> str:
    """The cluster name when it is one safe path segment (always, for real EKS names), else a hashed name."""
    try:
        if len(fsio.validate_relpath(target.name)) == 1 and not target.name.startswith("_"):
            return target.name
    except fsio.UnsafePathError:
        pass
    return fsio.hashed_filename(target.arn, target.name, ext="")


def _ns_item(cluster_arn: str, namespace: str) -> str:
    return f"k8s://{cluster_arn}/Namespace/_/{namespace}"


class _Cluster:
    """Collects one cluster; ``cluster_info.json`` is always written (``run``'s ``finally``)."""

    def __init__(self, ctx: Any, target: ClusterTarget, opts: K8sOptions):
        self.ctx = ctx
        self.target = target
        self.opts = opts
        self.dir = _cluster_dir(target)
        self.reader: Optional[K8sReader] = None
        self._deny_streak: Dict[str, int] = {}
        self._open_apis: Set[str] = set()
        self.info: Dict[str, Any] = {
            "name": target.name, "arn": target.arn, "endpoint": target.endpoint, "auth_mode": opts.auth_mode,
            "auth_status": None, "error_code": None, "error": None, "version": None,
            "endpoint_public_access": target.endpoint_public_access,
            "endpoint_private_access": target.endpoint_private_access,
            "public_access_cidrs": list(target.public_access_cidrs) if target.public_access_cidrs is not None
            else None,
            "endpoint_hint": target.endpoint_hint(), "self_rules_reviewed": False, "self_rules_namespaces": 0,
            "self_rules_truncated": False, "secrets_listed": False, "resources": {},
        }

    # bookkeeping ---------------------------------------------------------------
    def _write(self, name: str, data: Any) -> None:
        self.ctx.out.write(f"{self.dir}/{name}", data)

    def _fail(self, status: str, code: str, message: str) -> None:
        self.info.update(auth_status=status, error_code=code, error=message)

    def _record(self, api: str, error: Optional[K8sRequestError], *, item: str, pages: int = 0,
                items: Optional[int] = None, not_configured: Optional[str] = None) -> CallResult:
        """Record one request in the module coverage; failures also go to ``item_errors`` and the breaker.

        Calls are recorded without ``item=`` so the module-wide deny breaker (keyed by api, shared by every
        cluster of the unit) never counts them: each cluster has its own RBAC, so :meth:`_note` keeps a
        breaker per cluster instead.
        """
        if error is None:
            result = CallResult(api=api, status="ok", pages=pages, items=items)
        elif not_configured is not None and error.code == not_configured:
            result = CallResult(api=api, status="ok", error_code=error.code, not_configured=True)
        else:
            result = CallResult(api=api, status=_call_status(error), error_code=error.code, pages=pages,
                                items=items)
            self.ctx.cov.item_error(item, api, result.status, error.code)
            self.ctx.log.debug("%s %s (%s) for %s", api, result.status, error.code, item)
        self._note(api, result.status)
        return self.ctx.cov.record(result)

    def _note(self, api: str, status: str) -> None:
        """Per-cluster deny breaker: ``deny_breaker`` consecutive denials of one api open it (0 disables)."""
        threshold = int(getattr(self.ctx.run, "deny_breaker", 3) or 0)
        if status != "denied":
            self._deny_streak.pop(api, None)
            return
        self._deny_streak[api] = streak = self._deny_streak.get(api, 0) + 1
        if threshold and streak >= threshold and api not in self._open_apis:
            self._open_apis.add(api)
            self.ctx.log.warning("cluster %s: circuit breaker opened for %s (%s); remaining calls are skipped",
                                 self.target.name, api, CIRCUIT_OPEN_DENIED)

    def _open(self, api: str, item: str) -> Optional[K8sRequestError]:
        """An error standing in for a call a breaker skips (recorded), else ``None``.

        The cluster's own deny breaker is checked first, then the module's throttle breaker (HTTP 429 answers
        feed it through :meth:`Coverage.record`).
        """
        if api in self._open_apis:
            skipped: Optional[CallResult] = self.ctx.cov.record(
                CallResult(api=api, status="skipped", error_code=CIRCUIT_OPEN_DENIED))
        else:
            skipped = self.ctx.cov.circuit_skip(api)
        if skipped is None:
            return None
        code = skipped.error_code or CIRCUIT_OPEN_DENIED
        self.ctx.cov.item_error(item, api, "skipped", code)
        return K8sRequestError(code, kind="skipped")

    def _list(self, res: Resource, *, namespace: Optional[str] = None, selector: Optional[str] = None,
              metadata_only: bool = False) -> ListOutcome:
        assert self.reader is not None
        item = self.target.arn if namespace is None else _ns_item(self.target.arn, namespace)
        skipped = self._open(res.api, item)
        if skipped is not None:
            return ListOutcome(error=skipped)
        out = self.reader.list(res, namespace=namespace, field_selector=selector, metadata_only=metadata_only)
        self._record(res.api, out.error, item=item, pages=out.pages, items=len(out.items))
        return out

    def _read(self, api: str, fn: Callable[[], ReadOutcome], *, item: Optional[str] = None,
              not_configured: Optional[str] = None) -> ReadOutcome:
        item = item or self.target.arn
        skipped = self._open(api, item)
        if skipped is not None:
            return ReadOutcome(error=skipped)
        out = fn()
        self._record(api, out.error, item=item, not_configured=not_configured)
        return out

    # flow ----------------------------------------------------------------------
    def run(self, skip: Optional[Tuple[str, str]] = None) -> None:
        try:
            if skip is not None:
                self._fail("skipped", *skip)
                self.ctx.cov.skip("k8s:Authenticate", skip[0], item=self.target.arn)
                return
            self._connect_and_read()
        finally:
            self._write("cluster_info.json", self.info)
            self._log_summary()

    def _connect_and_read(self) -> None:
        try:
            conn = connect(self.target, self.opts, sts_client=lambda: self.ctx.client("sts"))
        except K8sAuthError as err:
            self._fail(err.status, err.code, err.message)
            if err.status == "skipped":
                self.ctx.cov.skip("k8s:Authenticate", err.code, item=self.target.arn)
            else:
                self.ctx.cov.item_error(self.target.arn, "k8s:Authenticate", "error", err.code)
            return
        try:
            self.reader = K8sReader(self._transport(conn), check_stop=self.ctx.check_stop)
            if self._probe():
                self._read_cluster()
        finally:
            conn.close()

    def _transport(self, conn: Any) -> ApiClientTransport:
        connect_timeout = self.opts.connect_timeout
        if self.info["endpoint_hint"] and self.opts.auth_mode != "in-cluster":
            connect_timeout = min(connect_timeout, PRIVATE_CONNECT_TIMEOUT)
            self.ctx.log.info("cluster %s: %s; trying with a %.0f s connect timeout", self.target.name,
                              self.info["endpoint_hint"], connect_timeout)
        gate = (RateGate(self.opts.rate, self.opts.burst, check_stop=self.ctx.check_stop)
                if self.opts.rate else None)
        return ApiClientTransport(conn.api_client, timeout=(connect_timeout, self.opts.read_timeout),
                                  refresh=conn.refresh, gate=gate, user_agent=self.opts.user_agent)

    def _probe(self) -> bool:
        """``GET /version``. Unreachable, TLS and 401 answers stop here; 403 goes on (authenticated)."""
        assert self.reader is not None
        out = self._read("k8s:GetVersion", self.reader.version)
        if out.ok and out.doc is not None:
            self.info["version"] = proj.project_version(out.doc)
            return True
        err = out.error or K8sRequestError("NoResponse", kind="error")
        if err.status == 403:
            return True
        if err.kind in ("unreachable", "timeout", "tls"):
            status = "unreachable" if err.kind != "tls" else "failed"
            message = _ERRORS[err.kind] + (f"; {self.info['endpoint_hint']}" if self.info["endpoint_hint"] else "")
        else:
            status, message = "failed", _ERRORS.get(err.status, "the version probe failed")
        self._fail(status, err.code, message)
        return False

    def _read_cluster(self) -> None:
        namespaces = self._read_list("namespaces", proj.project_namespace, None)
        names = [n["metadata"]["name"] for n in namespaces if isinstance(n["metadata"].get("name"), str)]
        reviews = self._self_review(names)
        for key, project in _LISTS:
            self._read_list(key, project, reviews)
        self._aws_auth()
        if self.opts.secrets:
            self._secrets(reviews)
        if self.info["auth_status"] is None:
            read = any(r["status"] in ("ok", "partial") for r in self.info["resources"].values())
            if read:
                self.info["auth_status"] = "ok"
            else:
                self._fail("forbidden", "Forbidden", "authenticated, but every request was forbidden")

    # lists ---------------------------------------------------------------------
    def _gather(self, res: Resource, selectors: Sequence[Tuple[Optional[str], Optional[str]]],
                reviews: Optional[Dict[str, Dict[str, Any]]], *, metadata_only: bool = False,
                ) -> Tuple[List[Tuple[Dict[str, Any], Optional[str]]], Dict[str, Any]]:
        """Raw items tagged with their selector's tag, cluster-wide or (after a 403) per allowed namespace."""
        found: List[Tuple[Dict[str, Any], Optional[str]]] = []
        errors: List[K8sRequestError] = []
        for selector, tag in selectors:
            out = self._list(res, selector=selector, metadata_only=metadata_only)
            if out.error is not None and out.error.status == 403 and res.namespaced and reviews is not None:
                return self._gather_namespaced(res, selectors, reviews, metadata_only)
            found.extend((i, tag) for i in out.items)
            if out.error is not None:
                errors.append(out.error)
        status = {"status": _call_status(errors[0]) if errors else "ok", "scope": "cluster",
                  "error_code": errors[0].code if errors else None, "namespaces": None}
        if errors and errors[0].kind == "skipped":
            status["status"] = "skipped"
        return found, status

    def _gather_namespaced(self, res: Resource, selectors: Sequence[Tuple[Optional[str], Optional[str]]],
                           reviews: Dict[str, Dict[str, Any]], metadata_only: bool,
                           ) -> Tuple[List[Tuple[Dict[str, Any], Optional[str]]], Dict[str, Any]]:
        found: List[Tuple[Dict[str, Any], Optional[str]]] = []
        read: List[str] = []
        for namespace in sorted(ns for ns, review in reviews.items() if rules_allow(review, "list", res)):
            complete = True
            for selector, tag in selectors:
                out = self._list(res, namespace=namespace, selector=selector, metadata_only=metadata_only)
                found.extend((i, tag) for i in out.items)
                complete = complete and out.ok
            if complete:
                read.append(namespace)
        status = {"status": "partial" if read else "denied", "scope": "namespaced", "error_code": "Forbidden",
                  "namespaces": read}
        return found, status

    def _read_list(self, key: str, project: Callable[[Mapping[str, Any]], Dict[str, Any]],
                   reviews: Optional[Dict[str, Dict[str, Any]]]) -> List[Dict[str, Any]]:
        found, status = self._gather(RESOURCES[key], [(None, None)], reviews)
        items = proj.project_all((raw for raw, _tag in found), project)
        self._write(f"{key}.json", items)
        self.info["resources"][key] = dict(status, items=len(items))
        return items

    def _secrets(self, reviews: Optional[Dict[str, Dict[str, Any]]]) -> None:
        """Secret metadata, one list per type (metadata-only lists carry no type field; F-009)."""
        selectors = [(f"type={t}", t) for t in proj.SECRET_TYPES]
        selectors.append((",".join(f"type!={t}" for t in proj.SECRET_TYPES), "other"))
        found, status = self._gather(RESOURCES["secrets"], selectors, reviews, metadata_only=True)
        unique: Dict[Tuple[Any, Any], Dict[str, Any]] = {}
        for raw, tag in found:
            item = proj.project_secret_metadata(raw, tag or "other")
            unique.setdefault((item["namespace"], item["name"]), item)
        items = sorted(unique.values(), key=proj.sort_key)
        self._write("secrets.json", items)
        self.info["secrets_listed"] = True
        self.info["resources"]["secrets"] = dict(status, items=len(items))

    # identity --------------------------------------------------------------------
    def _self_review(self, namespaces: List[str]) -> Optional[Dict[str, Dict[str, Any]]]:
        """Rules reviews per namespace (``None`` when disabled); saved to ``self_rules.json``."""
        if not self.opts.self_review:
            return None
        assert self.reader is not None
        reader = self.reader
        candidates = sorted(set(namespaces) | set(_FALLBACK_NAMESPACES) | set(self.target.hint_namespaces))
        reviews: Dict[str, Dict[str, Any]] = {}
        for namespace in candidates[:MAX_REVIEW_NAMESPACES]:
            out = self._read("k8s:CreateSelfSubjectRulesReview", lambda ns=namespace: reader.rules_review(ns),
                             item=_ns_item(self.target.arn, namespace))
            if out.ok and out.doc is not None:
                reviews[namespace] = proj.project_rules_review(namespace, out.doc)
            elif out.error is not None and (out.error.denied or out.error.kind != "http"):
                break  # forbidden or unreachable for one namespace means the same for the others
        self._write("self_rules.json", [reviews[ns] for ns in sorted(reviews)])
        self.info.update(self_rules_reviewed=bool(reviews), self_rules_namespaces=len(reviews),
                         self_rules_truncated=len(candidates) > MAX_REVIEW_NAMESPACES)
        return reviews

    def _aws_auth(self) -> None:
        assert self.reader is not None
        reader = self.reader
        out = self._read("k8s:GetConfigMap", lambda: reader.read(_AWS_AUTH_PATH), not_configured="NotFound")
        if out.ok and out.doc is not None:
            data, status = proj.parse_aws_auth(out.doc), "ok"
        elif out.error is not None and out.error.code == "NotFound":
            data, status = proj.parse_aws_auth(None), "ok"
        else:
            data, status = proj.denied_aws_auth(), _call_status(out.error) if out.error else "error"
        self._write("aws_auth.json", data)
        self.info["resources"]["aws_auth"] = {"status": status, "scope": "kube-system",
                                              "error_code": out.error.code if out.error else None,
                                              "items": None, "namespaces": None}

    def _log_summary(self) -> None:
        status = self.info["auth_status"]
        if status in ("failed", "unreachable", "forbidden"):
            self.ctx.log.warning("cluster %s: %s (%s): %s", self.target.name, status, self.info["error_code"],
                                 self.info["error"])
        elif status == "skipped":
            self.ctx.log.info("cluster %s: skipped (%s)", self.target.name, self.info["error"])
        else:
            counts = ", ".join(f"{k} {v['items']}" for k, v in sorted(self.info["resources"].items())
                               if v.get("items") is not None)
            self.ctx.log.info("cluster %s: %s (%s)", self.target.name, status or "incomplete", counts or "no data")


def _targets(ctx: Any) -> Optional[List[ClusterTarget]]:
    """Clusters from the eks module's return value, or ``None`` when it returned none."""
    eks = ctx.deps.get("eks")
    if not isinstance(eks, Mapping) or not isinstance(eks.get("clusters"), list):
        return None
    hints = eks.get("namespaces") if isinstance(eks.get("namespaces"), Mapping) else {}
    targets = []
    for cluster in eks["clusters"]:
        name = cluster.get("name") if isinstance(cluster, Mapping) else None
        if isinstance(name, str) and name:
            ns = tuple(n for n in hints.get(name) or () if isinstance(n, str))
            targets.append(ClusterTarget.from_describe(cluster, ctx.arn("eks", f"cluster/{name}"), ns))
    return sorted(targets, key=lambda t: t.name)


def _skip_reason(target: ClusterTarget, opts: K8sOptions, selected: int) -> Optional[Tuple[str, str]]:
    if not opts.selects(target.name):
        return "NotSelected", "not in --k8s-clusters"
    if opts.auth_mode == "in-cluster":
        if selected != 1:
            return "InClusterNeedsOneCluster", "in-cluster auth needs exactly one cluster (use --k8s-clusters)"
        return None
    if not target.endpoint:
        return "NoEndpoint", "no API endpoint (DescribeCluster failed or the cluster is not active)"
    return None


def _dependency_missing(ctx: Any, targets: List[ClusterTarget], opts: K8sOptions, selected: int) -> None:
    """One WARNING, ``auth_status: dependency_missing`` per cluster that would have been contacted (F-136)."""
    ctx.log.warning("python package 'kubernetes' is not installed: Kubernetes enumeration skipped for %d "
                    "cluster(s); install it with 'pip install kubernetes' (it is a declared dependency)",
                    len(targets))
    for target in targets:
        cluster = _Cluster(ctx, target, opts)
        skip = _skip_reason(target, opts, selected)
        if skip is not None:
            cluster._fail("skipped", *skip)
        else:
            cluster._fail("dependency_missing", "DependencyMissing", "python package 'kubernetes' is not installed")
        cluster._write("cluster_info.json", cluster.info)
    ctx.cov.mark_skipped("python package 'kubernetes' is not installed")


def collect(ctx: Any) -> None:
    opts = K8sOptions.from_mapping(ctx.run.options, run_id=ctx.run.run_id)
    if not opts.enabled:
        ctx.cov.mark_skipped("disabled by --no-k8s")
        return None
    targets = _targets(ctx)
    if targets is None:
        ctx.cov.mark_skipped("dependency 'eks' returned no cluster list")
        return None
    if not targets:
        return None
    if opts.secrets:
        ctx.log.info(SECRETS_NOTICE)  # the run-level WARNING is logged once by the runner
    selected = sum(1 for t in targets if opts.selects(t.name))
    if not kubernetes_available():
        _dependency_missing(ctx, targets, opts, selected)
        return None
    for target in targets:
        with ctx.section("cluster"):
            _Cluster(ctx, target, opts).run(_skip_reason(target, opts, selected))
    return None
