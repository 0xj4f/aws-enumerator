"""Kubernetes collection options, parsed from ``RunInfo.options`` (cli.md §3.1, collector-context.md §4).

Option names are the CLI flag names without the dashes, ``-`` replaced by ``_``. Both spellings of the
negative flags are accepted, because the CLI may store ``--no-k8s`` either as ``k8s=False`` or as
``no_k8s=True``:

========================  ====================================  =========================================
option                    CLI flag                              default
========================  ====================================  =========================================
``k8s`` / ``no_k8s``      ``--k8s`` / ``--no-k8s``              on (owner decision, F-062)
``k8s_secrets``           ``--k8s-secrets``                     off: no ``/secrets`` request (F-009/F-150)
``k8s_auth``              ``--k8s-auth``                        ``eks-token`` (F-152)
``kubeconfig``            ``--kubeconfig``                      ``$KUBECONFIG``, else ``~/.kube/config``
``kube_context``          ``--kube-context``                    matched by server URL
``k8s_token_file``        ``--k8s-token-file``                  required for ``token`` auth
``k8s_ca_file``           ``--k8s-ca-file``                     the CA from ``DescribeCluster``
``k8s_clusters``          ``--k8s-clusters a,b``                every cluster from eks
``k8s_timeout``           ``--k8s-timeout CONNECT,READ``        ``5,60`` seconds (F-120)
``k8s_self_review``       ``--no-k8s-self-review``              on (F-152)
``no_rate_limit``,        ``--no-rate-limit``, ``--max-rps``,   5 requests/s per cluster, burst 10;
``max_rps``,              ``--rate-limit k8s=N``                ``k8s=N`` wins over ``--max-rps``
``rate_limit``
``no_ua_tag``,            ``--no-ua-tag``, ``--ua-app-id``      ``aws-enumerator/<version>/<run id tail>``
``ua_app_id``
========================  ====================================  =========================================

``rate_limit`` may also be the runner's ``RateLimitConfig`` or its manifest form (see :func:`_rate_settings`).

:func:`parse_timeout` and :func:`parse_cluster_list` are exported so the CLI can validate the flags at
parse time (exit 64) instead of when the module runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from aws_enumerator._version import __version__

__all__ = [
    "AUTH_MODES", "DEFAULT_BURST", "DEFAULT_RATE", "DEFAULT_TIMEOUT", "K8sOptionError", "K8sOptions",
    "parse_cluster_list", "parse_timeout",
]

#: ``--k8s-auth`` values (cli.md §3.1).
AUTH_MODES: Tuple[str, ...] = ("eks-token", "kubeconfig", "token", "in-cluster")
#: (connect, read) seconds per request (F-120).
DEFAULT_TIMEOUT: Tuple[float, float] = (5.0, 60.0)
#: Per-cluster request budget (collectors-cli.md §4: "k8s (per cluster) 5/10").
DEFAULT_RATE = 5.0
DEFAULT_BURST = 10

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off", ""})


class K8sOptionError(ValueError):
    """An option value cannot be used (the CLI maps it to exit 64)."""


def _as_bool(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str) and value.strip().lower() in _TRUE | _FALSE:
        return value.strip().lower() in _TRUE
    raise K8sOptionError(f"{name}: expected a boolean, got {value!r}")


def _flag(options: Mapping[str, Any], positive: str, negative: str, default: bool) -> bool:
    """``positive`` (``k8s``) wins over ``negative`` (``no_k8s``); either may be absent or ``None``."""
    if options.get(positive) is not None:
        return _as_bool(options[positive], positive)
    if options.get(negative) is not None:
        return not _as_bool(options[negative], negative)
    return default


def parse_timeout(value: Any) -> Tuple[float, float]:
    """``"5,60"`` / ``(5, 60)`` / ``7`` -> ``(connect, read)`` seconds, each in ``(0, 600]``."""
    if value is None or value == "":
        return DEFAULT_TIMEOUT
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        parts: Tuple[Any, ...] = (value, value)
    elif isinstance(value, str):
        parts = tuple(p.strip() for p in value.split(","))
    elif isinstance(value, (list, tuple)):
        parts = tuple(value)
    else:
        raise K8sOptionError(f"k8s_timeout: expected 'CONNECT,READ', got {value!r}")
    if len(parts) == 1:
        parts = (parts[0], parts[0])
    if len(parts) != 2:
        raise K8sOptionError(f"k8s_timeout: expected 'CONNECT,READ', got {value!r}")
    try:
        connect, read = float(parts[0]), float(parts[1])
    except (TypeError, ValueError):
        raise K8sOptionError(f"k8s_timeout: expected numbers, got {value!r}") from None
    for seconds in (connect, read):
        if not 0 < seconds <= 600:
            raise K8sOptionError(f"k8s_timeout: each value must be in (0, 600] seconds, got {value!r}")
    return connect, read


def parse_cluster_list(value: Any) -> Optional[Tuple[str, ...]]:
    """``"a,b"`` / ``["a", "b,c"]`` -> sorted unique names; ``None`` / empty -> ``None`` (every cluster)."""
    if value is None:
        return None
    items: Iterable[Any] = [value] if isinstance(value, str) else value
    names = set()
    for item in items:
        if not isinstance(item, str):
            raise K8sOptionError(f"k8s_clusters: expected cluster names, got {item!r}")
        names.update(n.strip() for n in item.split(",") if n.strip())
    return tuple(sorted(names)) or None


def _optional_str(options: Mapping[str, Any], name: str) -> Optional[str]:
    value = options.get(name)
    if value is None or value == "":
        return None
    return str(value)


def _number(value: Any, name: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        raise K8sOptionError(f"{name}: expected a number, got {value!r}") from None


def _rate_settings(options: Mapping[str, Any]) -> Tuple[bool, Optional[float], Mapping[str, Any]]:
    """``(enabled, max_rps, overrides)`` from the flat option keys or from ``rate_limit``.

    ``rate_limit`` may be the runner's ``RateLimitConfig`` (attributes ``enabled``/``max_rps``/``overrides``),
    its manifest form (``{"enabled", "max_rps", "overrides"}``), a plain ``{service: rps}`` mapping, or the
    raw ``--rate-limit SERVICE=RPS`` strings.
    """
    enabled = _flag(options, "rate_limit_enabled", "no_rate_limit", True)
    max_rps = options.get("max_rps")
    raw = options.get("rate_limit")
    overrides: Dict[str, Any] = {}
    if raw is not None and all(hasattr(raw, a) for a in ("enabled", "max_rps", "overrides")):
        raw = {"enabled": raw.enabled, "max_rps": raw.max_rps, "overrides": raw.overrides}
    if isinstance(raw, str):
        raw = [raw]
    if isinstance(raw, (list, tuple)):
        for entry in raw:
            service, _, value = str(entry).partition("=")
            if service.strip() == "k8s" and value.strip():
                overrides["k8s"] = value
    elif isinstance(raw, Mapping) and isinstance(raw.get("overrides"), Mapping):
        if raw.get("enabled") is False:
            enabled = False
        max_rps = raw.get("max_rps") if max_rps is None else max_rps
        overrides = dict(raw["overrides"])
    elif isinstance(raw, Mapping):
        overrides = dict(raw)
    return enabled, max_rps, overrides


def _rate(options: Mapping[str, Any]) -> Optional[float]:
    """Requests per second per cluster, or ``None`` when rate limiting is off (``--no-rate-limit``)."""
    enabled, max_rps, overrides = _rate_settings(options)
    if not enabled:
        return None
    rate = DEFAULT_RATE
    if overrides.get("k8s") is not None:
        rate = _number(overrides["k8s"], "rate_limit k8s")
    elif max_rps is not None:
        rate = min(rate, _number(max_rps, "max_rps"))
    if rate <= 0:
        raise K8sOptionError(f"k8s rate must be positive, got {rate!r}")
    return rate


def _user_agent(options: Mapping[str, Any], run_id: str) -> Optional[str]:
    if _flag(options, "ua_tag", "no_ua_tag", True) is False:
        return None
    app_id = _optional_str(options, "ua_app_id")
    if app_id:
        return app_id
    tail = f"/{run_id[-6:]}" if run_id else ""
    return f"aws-enumerator/{__version__}{tail}"


@dataclass(frozen=True)
class K8sOptions:
    """Everything the k8s collector reads from the run options (see the module docstring)."""

    enabled: bool = True
    secrets: bool = False
    auth_mode: str = "eks-token"
    kubeconfig: Optional[str] = None
    kube_context: Optional[str] = None
    token_file: Optional[str] = None
    ca_file: Optional[str] = None
    clusters: Optional[Tuple[str, ...]] = None
    connect_timeout: float = DEFAULT_TIMEOUT[0]
    read_timeout: float = DEFAULT_TIMEOUT[1]
    self_review: bool = True
    rate: Optional[float] = DEFAULT_RATE
    burst: int = DEFAULT_BURST
    user_agent: Optional[str] = None

    @classmethod
    def from_mapping(cls, options: Mapping[str, Any], *, run_id: str = "") -> "K8sOptions":
        """Parse ``RunInfo.options``; raises :class:`K8sOptionError` for unusable values."""
        mode = _optional_str(options, "k8s_auth") or "eks-token"
        if mode not in AUTH_MODES:
            raise K8sOptionError(f"k8s_auth: {mode!r} is not one of {', '.join(AUTH_MODES)}")
        connect, read = parse_timeout(options.get("k8s_timeout"))
        if mode == "token" and not _optional_str(options, "k8s_token_file"):
            raise K8sOptionError("k8s_auth token needs k8s_token_file (--k8s-token-file)")
        return cls(
            enabled=_flag(options, "k8s", "no_k8s", True),
            secrets=_flag(options, "k8s_secrets", "no_k8s_secrets", False),
            auth_mode=mode,
            kubeconfig=_optional_str(options, "kubeconfig"),
            kube_context=_optional_str(options, "kube_context"),
            token_file=_optional_str(options, "k8s_token_file"),
            ca_file=_optional_str(options, "k8s_ca_file"),
            clusters=parse_cluster_list(options.get("k8s_clusters")),
            connect_timeout=connect,
            read_timeout=read,
            self_review=_flag(options, "k8s_self_review", "no_k8s_self_review", True),
            rate=_rate(options),
            user_agent=_user_agent(options, run_id),
        )

    @property
    def timeout(self) -> Tuple[float, float]:
        return self.connect_timeout, self.read_timeout

    def selects(self, cluster_name: str) -> bool:
        """``--k8s-clusters`` filter (``None`` selects every cluster)."""
        return self.clusters is None or cluster_name in self.clusters
