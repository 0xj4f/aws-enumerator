"""Map AWS API operations to the IAM actions that authorise them (F-151, F-161).

Coverage records API calls as ``"<botocore service>:<OperationName>"`` (coverage-schema.md §2); a policy needs
IAM actions. They usually coincide, but not always: ``s3:ListBuckets`` is authorised by
``s3:ListAllMyBuckets``, elbv2 operations by ``elasticloadbalancing:*``, every API Gateway read by the
resource-scoped ``apigateway:GET``. :func:`iam_action_for` is the one place that knows the difference; the
permissions generator, preflight and the permission-coverage tests use it.

The IAM actions a module needs are declared by the module itself (``SPEC.actions`` and
``SPEC.optional_actions``, registry.md); this module only translates API strings. The permission-coverage test
(``tests/python/cli/test_permissions.py``) checks that ``permissions --include-optional`` allows every call a
``collect --all`` run against the fake acme world makes; the recorded call inventory of such runs is
``tests/golden/collectors-v2/calls-*.json``.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

__all__ = [
    "APIGATEWAY_READ", "NO_PERMISSION_NEEDED", "iam_action_for", "iam_prefix_for",
    "split_api", "actions_for_operations",
]

#: botocore service name -> IAM service prefix, where they differ.
_PREFIX_OVERRIDES: Dict[str, str] = {
    "elbv2": "elasticloadbalancing",
    "elb": "elasticloadbalancing",
    "s3control": "s3",
    "apigatewayv2": "apigateway",
    "accessanalyzer": "access-analyzer",
    "stepfunctions": "states",
    "es": "es",
    "opensearch": "es",
    "sso-admin": "sso",
    "identitystore": "identitystore",
}

#: ``service:Operation`` -> IAM action, for operations whose action name differs.
_ACTION_OVERRIDES: Dict[str, str] = {
    "s3:ListBuckets": "s3:ListAllMyBuckets",
    "s3:GetBucketEncryption": "s3:GetEncryptionConfiguration",
    "s3:GetBucketCors": "s3:GetBucketCORS",
    "s3:GetBucketNotificationConfiguration": "s3:GetBucketNotification",
    "s3:GetPublicAccessBlock": "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketReplication": "s3:GetReplicationConfiguration",
    "s3:GetBucketLifecycleConfiguration": "s3:GetLifecycleConfiguration",
    "s3:GetBucketPolicyStatus": "s3:GetBucketPolicyStatus",
    "s3:HeadBucket": "s3:ListBucket",
    "s3:ListObjectsV2": "s3:ListBucket",
    "s3control:GetPublicAccessBlock": "s3:GetAccountPublicAccessBlock",
    "lambda:ListFunctionUrlConfigs": "lambda:ListFunctionUrlConfigs",
    "kms:ListResourceTags": "kms:ListResourceTags",
}

#: Calls that need no IAM permission (``sts:GetCallerIdentity`` works even under an explicit deny).
NO_PERMISSION_NEEDED = frozenset({"sts:GetCallerIdentity"})

#: The one IAM action behind every API Gateway (v1 and v2) read; it is resource-scoped (permissions.md).
APIGATEWAY_READ = "apigateway:GET"


def split_api(api: str) -> Tuple[str, str]:
    """``"s3:GetBucketPolicy"`` -> ``("s3", "GetBucketPolicy")``."""
    service, sep, operation = api.partition(":")
    if not sep or not service or not operation:
        raise ValueError(f"not a 'service:Operation' api string: {api!r}")
    return service, operation


def iam_prefix_for(service: str) -> str:
    """IAM service prefix for a botocore service name (``elbv2`` -> ``elasticloadbalancing``)."""
    return _PREFIX_OVERRIDES.get(service, service)


def iam_action_for(api: str) -> Optional[str]:
    """IAM action authorising ``api`` (``"service:Operation"``); ``None`` when no permission is needed."""
    if api in NO_PERMISSION_NEEDED:
        return None
    if api in _ACTION_OVERRIDES:
        return _ACTION_OVERRIDES[api]
    service, operation = split_api(api)
    if service in ("apigateway", "apigatewayv2"):
        return APIGATEWAY_READ if operation.startswith("Get") else f"apigateway:{operation.upper()}"
    return f"{iam_prefix_for(service)}:{operation}"


def actions_for_operations(apis: Iterable[str]) -> List[str]:
    """Sorted, de-duplicated IAM actions for a set of api strings (calls needing none are dropped)."""
    out = {iam_action_for(api) for api in apis}
    return sorted(a for a in out if a)
