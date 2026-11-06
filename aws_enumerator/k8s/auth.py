"""Authentication to EKS cluster API servers (collectors-cli.md §5.16; F-119, F-136, F-152).

Four modes (``--k8s-auth``):

``eks-token`` (default)
    The ``aws eks get-token`` flow: a presigned STS ``GetCallerIdentity`` URL carrying the
    ``x-k8s-aws-id: <cluster>`` header, base64url-encoded behind ``k8s-aws-v1.``. The URL is presigned by
    the run's own STS client (``ctx.client("sts")``), so the endpoint and signing region are the
    partition's (``sts.cn-north-1.amazonaws.com.cn`` in China, F-119). Signing is local; the token is
    re-signed when it is older than :data:`TOKEN_MAX_AGE` (10 minutes; EKS accepts it for 15).
``kubeconfig``
    A context of the user's kubeconfig (``--kubeconfig``, else ``$KUBECONFIG``, else ``~/.kube/config``)
    whose cluster ``server`` equals the EKS endpoint; ``--kube-context`` picks one explicitly.
``token``
    A bearer token read from ``--k8s-token-file`` (for example a ServiceAccount token), with the CA from
    ``--k8s-ca-file`` or from ``DescribeCluster``.
``in-cluster``
    The pod's own ServiceAccount (``load_incluster_config``).

Every mode builds a ``kubernetes.client.ApiClient`` with urllib3 retries set to 1. Nothing here logs or
returns a token; :class:`K8sAuthError` carries a stable ``code`` and a fixed, data-free message.
:func:`kubernetes_available` is the one dependency check (F-136).
"""

from __future__ import annotations

import base64
import binascii
import importlib
import logging
import os
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from aws_enumerator.k8s.options import K8sOptions
from aws_enumerator.util.optional import is_available

__all__ = [
    "CLUSTER_ID_HEADER", "ClusterTarget", "Connection", "EksTokenSigner", "K8sAuthError", "TOKEN_MAX_AGE",
    "TOKEN_PREFIX", "connect", "decode_token", "kubeconfig_contexts", "kubernetes_available", "normalize_server",
]

log = logging.getLogger("aws_enumerator.k8s")

TOKEN_PREFIX = "k8s-aws-v1."
CLUSTER_ID_HEADER = "x-k8s-aws-id"
#: Lifetime of the presigned URL itself (as ``aws eks get-token``).
TOKEN_URL_EXPIRES = 60
#: Re-sign after 10 minutes.
TOKEN_MAX_AGE = 600.0
_HANDLER_ID = "aws-enumerator-k8s-aws-id"
_DEFAULT_KUBECONFIG = os.path.join("~", ".kube", "config")


class K8sAuthError(Exception):
    """A connection could not be set up. ``status`` is the cluster's ``auth_status``: ``failed`` or ``skipped``."""

    def __init__(self, code: str, message: str, *, status: str = "failed"):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def kubernetes_available() -> bool:
    """Whether the ``kubernetes`` package can be imported (checked once per module run, F-136)."""
    return is_available("kubernetes")


def _client_module() -> Any:
    return importlib.import_module("kubernetes.client")


def _config_module() -> Any:
    return importlib.import_module("kubernetes.config")


# ── targets ──────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class ClusterTarget:
    """What the k8s collector knows about one EKS cluster (from the eks module's ``DescribeCluster``)."""

    name: str
    arn: str
    endpoint: Optional[str] = None
    ca_data: Optional[str] = None
    endpoint_public_access: Optional[bool] = None
    endpoint_private_access: Optional[bool] = None
    public_access_cidrs: Optional[Tuple[str, ...]] = None
    status: Optional[str] = None
    hint_namespaces: Tuple[str, ...] = ()

    @classmethod
    def from_describe(cls, cluster: Mapping[str, Any], default_arn: str,
                      hint_namespaces: Tuple[str, ...] = ()) -> "ClusterTarget":
        vpc = cluster.get("resourcesVpcConfig") if isinstance(cluster.get("resourcesVpcConfig"), dict) else {}
        ca = cluster.get("certificateAuthority") if isinstance(cluster.get("certificateAuthority"), dict) else {}
        cidrs = vpc.get("publicAccessCidrs")
        return cls(
            name=str(cluster.get("name")),
            arn=cluster.get("arn") if isinstance(cluster.get("arn"), str) else default_arn,
            endpoint=cluster.get("endpoint") if isinstance(cluster.get("endpoint"), str) else None,
            ca_data=ca.get("data") if isinstance(ca.get("data"), str) else None,
            endpoint_public_access=vpc.get("endpointPublicAccess") if "endpointPublicAccess" in vpc else None,
            endpoint_private_access=vpc.get("endpointPrivateAccess") if "endpointPrivateAccess" in vpc else None,
            public_access_cidrs=tuple(c for c in cidrs if isinstance(c, str)) if isinstance(cidrs, list) else None,
            status=cluster.get("status") if isinstance(cluster.get("status"), str) else None,
            hint_namespaces=tuple(sorted(set(hint_namespaces))),
        )

    def endpoint_hint(self) -> Optional[str]:
        """Why the endpoint may be unreachable from here (F-120), or ``None``."""
        if self.endpoint_public_access is False:
            return ("the API endpoint is private (endpointPublicAccess=false): it is reachable only from the "
                    "cluster VPC or a connected network")
        if self.public_access_cidrs is not None and "0.0.0.0/0" not in self.public_access_cidrs:
            return (f"the public API endpoint only accepts {len(self.public_access_cidrs)} CIDR range(s) "
                    "(publicAccessCidrs); requests from other addresses time out")
        return None


# ── EKS token ────────────────────────────────────────────────────────────────
def _move_cluster_id_to_context(params: Dict[str, Any], context: Dict[str, Any], **_: Any) -> None:
    if CLUSTER_ID_HEADER in params:
        context[CLUSTER_ID_HEADER] = params.pop(CLUSTER_ID_HEADER)


def _inject_cluster_id_header(request: Any, **_: Any) -> None:
    value = (getattr(request, "context", None) or {}).get(CLUSTER_ID_HEADER)
    if value:
        request.headers[CLUSTER_ID_HEADER] = value


def _install_token_handlers(sts_client: Any) -> None:
    """Handlers that carry ``x-k8s-aws-id`` into the signed headers; inert for every other call."""
    events = sts_client.meta.events
    events.register("provide-client-params.sts.GetCallerIdentity", _move_cluster_id_to_context,
                    unique_id=f"{_HANDLER_ID}-params")
    events.register("before-sign.sts.GetCallerIdentity", _inject_cluster_id_header, unique_id=f"{_HANDLER_ID}-sign")


def presign_token(sts_client: Any, cluster_name: str) -> str:
    """A fresh ``k8s-aws-v1.`` token for ``cluster_name`` (local signing; no request is sent)."""
    _install_token_handlers(sts_client)
    url = sts_client.generate_presigned_url("get_caller_identity", Params={CLUSTER_ID_HEADER: cluster_name},
                                            ExpiresIn=TOKEN_URL_EXPIRES, HttpMethod="GET")
    return TOKEN_PREFIX + base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def decode_token(token: str) -> str:
    """The presigned URL inside a ``k8s-aws-v1.`` token (tests and debugging)."""
    if not token.startswith(TOKEN_PREFIX):
        raise ValueError("not an EKS token")
    body = token[len(TOKEN_PREFIX):]
    return base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode("utf-8")


class EksTokenSigner:
    """Caches one cluster's token and re-signs it when older than ``max_age`` seconds."""

    def __init__(self, sts_client: Any, cluster_name: str, *, clock: Callable[[], float] = time.monotonic,
                 max_age: float = TOKEN_MAX_AGE):
        self._sts = sts_client
        self.cluster_name = cluster_name
        self._clock = clock
        self.max_age = float(max_age)
        self._token: Optional[str] = None
        self._issued = 0.0
        self.signed = 0

    def token(self) -> str:
        now = self._clock()
        if self._token is None or now - self._issued >= self.max_age:
            self._token = presign_token(self._sts, self.cluster_name)
            self._issued = now
            self.signed += 1
        return self._token


# ── connections ──────────────────────────────────────────────────────────────
@dataclass
class Connection:
    """An authenticated ``ApiClient`` plus what must happen before each request and at the end."""

    api_client: Any
    mode: str
    refresh: Callable[[], None] = lambda: None
    temp_files: List[str] = field(default_factory=list)

    def close(self) -> None:
        try:
            close = getattr(self.api_client, "close", None)
            if callable(close):
                close()
        finally:
            for path in self.temp_files:
                try:
                    os.remove(path)
                except OSError:
                    log.debug("could not remove a temporary CA file")
            self.temp_files.clear()


def _write_ca(ca_data: Optional[str]) -> str:
    """The base64 CA bundle from ``DescribeCluster`` as a private (0600) temporary PEM file."""
    if not ca_data:
        raise K8sAuthError("NoCertificateAuthority", "the cluster has no certificate authority data")
    try:
        pem = base64.b64decode(ca_data, validate=True)
    except (binascii.Error, ValueError):
        raise K8sAuthError("InvalidCertificateAuthority", "the certificate authority data is not base64") from None
    if b"BEGIN CERTIFICATE" not in pem:
        raise K8sAuthError("InvalidCertificateAuthority", "the certificate authority data is not a PEM certificate")
    fd, path = tempfile.mkstemp(prefix="aws-enumerator-ca-", suffix=".pem")
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    return path


def _api_client(cfg: Any) -> Any:
    cfg.retries = 1  # urllib3 default is 3 retries per request
    return _client_module().ApiClient(configuration=cfg)


def _static_client(target: ClusterTarget, bearer: str, ca_file: Optional[str]) -> Tuple[Any, Any, List[str]]:
    if not target.endpoint:
        raise K8sAuthError("NoEndpoint", "the cluster has no API endpoint", status="skipped")
    temp: List[str] = []
    if ca_file is None:
        ca_file = _write_ca(target.ca_data)
        temp.append(ca_file)
    try:
        cfg = _client_module().Configuration()
        cfg.host = target.endpoint
        cfg.verify_ssl = True
        cfg.ssl_ca_cert = ca_file
        cfg.api_key = {"authorization": f"Bearer {bearer}"}
        return cfg, _api_client(cfg), temp
    except BaseException:
        for path in temp:
            os.remove(path)
        raise


def _connect_eks_token(target: ClusterTarget, sts_client: Any, clock: Callable[[], float]) -> Connection:
    signer = EksTokenSigner(sts_client, target.name, clock=clock)
    try:
        token = signer.token()
    except Exception as exc:  # botocore credential / endpoint errors while presigning
        raise K8sAuthError("TokenSigningFailed", f"could not presign the EKS token ({type(exc).__name__})") from None
    cfg, api, temp = _static_client(target, token, None)

    def refresh() -> None:
        cfg.api_key["authorization"] = f"Bearer {signer.token()}"

    return Connection(api, "eks-token", refresh, temp)


def _connect_token(target: ClusterTarget, opts: K8sOptions) -> Connection:
    path = os.path.expanduser(opts.token_file or "")
    try:
        with open(path, encoding="utf-8") as fh:
            token = fh.read().strip()
    except OSError:
        raise K8sAuthError("TokenFileUnreadable", "the --k8s-token-file could not be read") from None
    if not token:
        raise K8sAuthError("TokenFileEmpty", "the --k8s-token-file is empty")
    ca_file = os.path.expanduser(opts.ca_file) if opts.ca_file else None
    _cfg, api, temp = _static_client(target, token, ca_file)
    return Connection(api, "token", lambda: None, temp)


def normalize_server(url: Optional[str]) -> Optional[str]:
    """``https://Host:443/`` and ``https://host`` compare equal."""
    if not url:
        return None
    parts = urlsplit(url.strip())
    if not parts.hostname:
        return None
    scheme = (parts.scheme or "https").lower()
    port = parts.port or (443 if scheme == "https" else 80)
    return f"{scheme}://{parts.hostname.lower()}:{port}{parts.path.rstrip('/')}"


def _kubeconfig_spec(opts: K8sOptions) -> str:
    return opts.kubeconfig or os.environ.get("KUBECONFIG") or _DEFAULT_KUBECONFIG


def kubeconfig_contexts(spec: str) -> Tuple[Dict[str, Optional[str]], Optional[str]]:
    """``({context: server}, current_context)`` from one or more kubeconfig files (``os.pathsep``-separated).

    Files are merged first-wins by name, as kubectl does. Raises :class:`K8sAuthError` when no file can
    be read or parsed.
    """
    import yaml  # PyYAML ships with the kubernetes package

    servers: Dict[str, Optional[str]] = {}
    clusters: Dict[str, Optional[str]] = {}
    contexts: Dict[str, Optional[str]] = {}
    current: Optional[str] = None
    loaded = 0
    for path in (p for p in spec.split(os.pathsep) if p):
        try:
            with open(os.path.expanduser(path), encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(doc, dict):
            continue
        loaded += 1
        current = current or (doc.get("current-context") if isinstance(doc.get("current-context"), str) else None)
        for entry in doc.get("clusters") or []:
            if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                server = (entry.get("cluster") or {}).get("server") if isinstance(entry.get("cluster"), dict) else None
                clusters.setdefault(entry["name"], server if isinstance(server, str) else None)
        for entry in doc.get("contexts") or []:
            if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                ctx = entry.get("context") if isinstance(entry.get("context"), dict) else {}
                contexts.setdefault(entry["name"], ctx.get("cluster") if isinstance(ctx.get("cluster"), str) else None)
    if not loaded:
        raise K8sAuthError("KubeconfigUnreadable", "no kubeconfig file could be read")
    for name, cluster in contexts.items():
        servers[name] = clusters.get(cluster) if cluster else None
    return servers, current


def _pick_context(target: ClusterTarget, opts: K8sOptions, spec: str) -> str:
    servers, current = kubeconfig_contexts(spec)
    wanted = normalize_server(target.endpoint)
    if opts.kube_context:
        if opts.kube_context not in servers:
            raise K8sAuthError("KubeContextNotFound", "the --kube-context is not in the kubeconfig")
        if normalize_server(servers[opts.kube_context]) != wanted:
            raise K8sAuthError("KubeContextMismatch", "the --kube-context points at another API server",
                               status="skipped")
        return opts.kube_context
    matches = sorted(name for name, server in servers.items() if wanted and normalize_server(server) == wanted)
    if not matches:
        raise K8sAuthError("NoKubeContext", "no kubeconfig context points at this cluster's endpoint",
                           status="skipped")
    return current if current in matches else matches[0]


def _connect_kubeconfig(target: ClusterTarget, opts: K8sOptions) -> Connection:
    spec = _kubeconfig_spec(opts)
    context = _pick_context(target, opts, spec)
    cfg = _client_module().Configuration()
    try:
        _config_module().load_kube_config(config_file=spec, context=context, client_configuration=cfg,
                                          persist_config=False)
    except Exception as exc:  # ConfigException, exec-plugin failures, bad files
        raise K8sAuthError("KubeconfigError", f"the kubeconfig context could not be loaded ({type(exc).__name__})"
                           ) from None
    return Connection(_api_client(cfg), "kubeconfig")


def _connect_in_cluster() -> Connection:
    cfg = _client_module().Configuration()
    try:
        _config_module().load_incluster_config(client_configuration=cfg)
    except Exception as exc:
        raise K8sAuthError("InClusterConfigError",
                           f"not running in a cluster or no ServiceAccount token ({type(exc).__name__})") from None
    return Connection(_api_client(cfg), "in-cluster")


def connect(target: ClusterTarget, opts: K8sOptions, *, sts_client: Callable[[], Any],
            clock: Callable[[], float] = time.monotonic) -> Connection:
    """An authenticated connection to ``target`` in ``opts.auth_mode``.

    ``sts_client`` is called only for ``eks-token`` (``lambda: ctx.client("sts")``). Raises
    :class:`K8sAuthError`; any other exception from the client library is wrapped the same way.
    """
    try:
        if opts.auth_mode == "eks-token":
            return _connect_eks_token(target, sts_client(), clock)
        if opts.auth_mode == "kubeconfig":
            return _connect_kubeconfig(target, opts)
        if opts.auth_mode == "token":
            return _connect_token(target, opts)
        if opts.auth_mode == "in-cluster":
            return _connect_in_cluster()
    except K8sAuthError:
        raise
    except Exception as exc:
        raise K8sAuthError("ClientSetupFailed", f"the Kubernetes client could not be built ({type(exc).__name__})"
                           ) from None
    raise K8sAuthError("UnknownAuthMode", "unknown --k8s-auth mode")
