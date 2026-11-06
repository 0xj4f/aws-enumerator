"""Read-only access to one cluster's API (collectors-cli.md §5.16; F-149, F-152).

:class:`K8sReader` lists with ``limit=500`` / ``continue`` paging and restarts a list once when the API
server answers ``410 Gone`` for an expired continue token (F-149). It never raises for request failures:
:meth:`K8sReader.list` returns a :class:`ListOutcome` holding whatever was read before the failure, so
writers keep stable shapes. The only non-GET request is the non-persistent ``SelfSubjectRulesReview``
POST (:meth:`K8sReader.rules_review`).

Requests go through a transport exposing ``request(method, path, query=..., headers=..., body=...)``
(:class:`aws_enumerator.k8s.transport.ApiClientTransport` in production, any fake in tests).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from aws_enumerator.k8s.transport import METADATA_ONLY_ACCEPT, K8sRequestError

__all__ = ["DEFAULT_PAGE_SIZE", "ListOutcome", "RESOURCES", "K8sReader", "ReadOutcome", "Resource",
           "rules_allow"]

DEFAULT_PAGE_SIZE = 500
_MAX_PAGES = 10_000

_CORE = "/api/v1"
_RBAC = "/apis/rbac.authorization.k8s.io/v1"
_NETWORKING = "/apis/networking.k8s.io/v1"
_SELF_RULES = "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"


@dataclass(frozen=True)
class Resource:
    """One listable resource: output key, API group, REST prefix and plural, scope, coverage API name."""

    key: str
    group: str
    prefix: str
    plural: str
    namespaced: bool
    api: str

    def path(self, namespace: Optional[str] = None) -> str:
        if namespace is not None and self.namespaced:
            return f"{self.prefix}/namespaces/{namespace}/{self.plural}"
        return f"{self.prefix}/{self.plural}"


#: Every list the collector makes, keyed by output file stem (``pods`` -> ``pods.json``).
RESOURCES: Dict[str, Resource] = {r.key: r for r in (
    Resource("namespaces", "", _CORE, "namespaces", False, "k8s:ListNamespaces"),
    Resource("pods", "", _CORE, "pods", True, "k8s:ListPods"),
    Resource("service_accounts", "", _CORE, "serviceaccounts", True, "k8s:ListServiceAccounts"),
    Resource("services", "", _CORE, "services", True, "k8s:ListServices"),
    Resource("nodes", "", _CORE, "nodes", False, "k8s:ListNodes"),
    Resource("roles", "rbac.authorization.k8s.io", _RBAC, "roles", True, "k8s:ListRoles"),
    Resource("cluster_roles", "rbac.authorization.k8s.io", _RBAC, "clusterroles", False, "k8s:ListClusterRoles"),
    Resource("role_bindings", "rbac.authorization.k8s.io", _RBAC, "rolebindings", True, "k8s:ListRoleBindings"),
    Resource("cluster_role_bindings", "rbac.authorization.k8s.io", _RBAC, "clusterrolebindings", False,
             "k8s:ListClusterRoleBindings"),
    Resource("ingresses", "networking.k8s.io", _NETWORKING, "ingresses", True, "k8s:ListIngresses"),
    Resource("secrets", "", _CORE, "secrets", True, "k8s:ListSecretsMetadata"),
)}


@dataclass
class ListOutcome:
    """Result of one (possibly multi-page) list. ``items`` holds what was read, even after a failure."""

    items: List[Dict[str, Any]] = field(default_factory=list)
    pages: int = 0
    restarted: bool = False
    error: Optional[K8sRequestError] = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class ReadOutcome:
    """Result of one single request (``/version``, a named GET, a rules review)."""

    doc: Optional[Dict[str, Any]] = None
    error: Optional[K8sRequestError] = None

    @property
    def ok(self) -> bool:
        return self.error is None


class K8sReader:
    """Paged, read-only access to one API server through ``transport``."""

    def __init__(self, transport: Any, *, page_size: int = DEFAULT_PAGE_SIZE,
                 check_stop: Optional[Callable[[], None]] = None):
        self.transport = transport
        self.page_size = int(page_size)
        self._check_stop = check_stop

    def _stop(self) -> None:
        if self._check_stop is not None:
            self._check_stop()

    def _get(self, path: str, query: Sequence[Tuple[str, Any]] = (), headers: Optional[Dict[str, str]] = None,
             ) -> Dict[str, Any]:
        self._stop()
        return self.transport.request("GET", path, query=query, headers=headers)

    def read(self, path: str) -> ReadOutcome:
        try:
            return ReadOutcome(doc=self._get(path))
        except K8sRequestError as err:
            return ReadOutcome(error=err)

    def version(self) -> ReadOutcome:
        return self.read("/version")

    def list(self, resource: Resource, *, namespace: Optional[str] = None, field_selector: Optional[str] = None,
             metadata_only: bool = False) -> ListOutcome:
        """Every item of ``resource`` (cluster-wide, or in ``namespace``), page by page.

        A ``410 Gone`` on a continued page restarts the list from the first page once (F-149).
        """
        path = resource.path(namespace)
        headers = {"Accept": METADATA_ONLY_ACCEPT} if metadata_only else None
        out = ListOutcome()
        token: Optional[str] = None
        seen = set()
        while True:
            query: List[Tuple[str, Any]] = [("limit", self.page_size)]
            if field_selector:
                query.append(("fieldSelector", field_selector))
            if token:
                query.append(("continue", token))
            try:
                doc = self._get(path, query, headers)
            except K8sRequestError as err:
                if err.status == 410 and token and not out.restarted:
                    out.restarted, out.items, token, seen = True, [], None, set()
                    continue
                out.error = err
                return out
            out.pages += 1
            out.items.extend(i for i in doc.get("items") or [] if isinstance(i, dict))
            token = (doc.get("metadata") or {}).get("continue") or None
            if not token or token in seen:
                return out
            if out.pages >= _MAX_PAGES:
                out.error = K8sRequestError("TooManyPages", kind="error")
                return out
            seen.add(token)

    def rules_review(self, namespace: str) -> ReadOutcome:
        """``SelfSubjectRulesReview`` for ``namespace`` (a non-persistent POST; F-152)."""
        body = {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview",
                "spec": {"namespace": namespace}}
        self._stop()
        try:
            return ReadOutcome(doc=self.transport.request("POST", _SELF_RULES, body=body))
        except K8sRequestError as err:
            return ReadOutcome(error=err)


def _matches(values: Optional[Sequence[str]], wanted: str) -> bool:
    return bool(values) and ("*" in values or wanted in values)


def rules_allow(review: Optional[Dict[str, Any]], verb: str, resource: Resource) -> bool:
    """Whether a projected rules review grants ``verb`` on every object of ``resource`` (no resourceNames)."""
    if not review:
        return False
    for rule in review.get("resource_rules") or []:
        if rule.get("resource_names"):
            continue
        if (_matches(rule.get("verbs"), verb) and _matches(rule.get("api_groups"), resource.group)
                and _matches(rule.get("resources"), resource.plural)):
            return True
    return False
