"""The Kubernetes RBAC the k8s collector needs (cli.md §3.5 ``permissions --format k8s``; F-150, F-152).

Rules are ``(apiGroup, resource, verbs, resourceNames)`` tuples, the ``CollectorSpec.k8s_rbac`` format.
A rule with ``resourceNames`` (``configmaps/aws-auth``) belongs in a **Role in kube-system**, not in the
ClusterRole. Secrets are **not** listed unless ``--k8s-secrets`` is given (:data:`SECRETS_RULES`), and even
then the grant is "list secrets", which lets the holder read every Secret value whatever the client asks
for: the collector only requests metadata, but the permission is not narrower for it.
"""

from __future__ import annotations

from typing import Tuple

__all__ = ["AWS_AUTH_NAMESPACE", "REQUIRED_RULES", "Rule", "SECRETS_RULES", "rules_for"]

Rule = Tuple[str, str, Tuple[str, ...], Tuple[str, ...]]

#: Namespace of the ``aws-auth`` ConfigMap (the only namespaced rule).
AWS_AUTH_NAMESPACE = "kube-system"

REQUIRED_RULES: Tuple[Rule, ...] = (
    ("", "namespaces", ("list",), ()),
    ("", "pods", ("list",), ()),
    ("", "serviceaccounts", ("list",), ()),
    ("", "services", ("list",), ()),
    ("", "nodes", ("list",), ()),
    ("rbac.authorization.k8s.io", "roles", ("list",), ()),
    ("rbac.authorization.k8s.io", "clusterroles", ("list",), ()),
    ("rbac.authorization.k8s.io", "rolebindings", ("list",), ()),
    ("rbac.authorization.k8s.io", "clusterrolebindings", ("list",), ()),
    ("networking.k8s.io", "ingresses", ("list",), ()),
    ("", "configmaps", ("get",), ("aws-auth",)),
    # Granted to every authenticated user by the default system:basic-user ClusterRole.
    ("authorization.k8s.io", "selfsubjectrulesreviews", ("create",), ()),
)

#: Added only with ``--k8s-secrets`` (metadata-only listing).
SECRETS_RULES: Tuple[Rule, ...] = (("", "secrets", ("list",), ()),)


def rules_for(*, secrets: bool = False) -> Tuple[Rule, ...]:
    return REQUIRED_RULES + (SECRETS_RULES if secrets else ())
