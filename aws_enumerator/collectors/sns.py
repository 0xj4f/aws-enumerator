"""SNS topics: access policies, encryption and subscriptions (never message data).

Output (``<region>/sns/``):

* ``resources.json`` (list), one item per topic, sorted by ``Arn``::

    {Type: "sns", Arn, Name, Policy: {...}|null, PolicyStatus, KmsMasterKeyId: str|null,
     Subscriptions: [{Protocol, Endpoint, Owner, SubscriptionArn}]|null, CollectionErrors?}

  Every listed topic is kept, also when its attributes cannot be read (F-102, F-059).
  Subscription endpoints are minimised (F-116): ARN endpoints (sqs, lambda, firehose,
  application) are kept, ``http``/``https`` endpoints keep ``scheme://host`` only (query strings
  often carry tokens), ``email``/``email-json`` keep the domain only and ``sms`` is masked.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from aws_enumerator.collectors._common import add_error, policy_doc
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="sns", scope="regional", output_dir="sns", services=("sns",),
    tier=1, cost="low", noise="low", default=True, groups=("@messaging",),
    actions=("sns:ListTopics", "sns:GetTopicAttributes", "sns:ListSubscriptionsByTopic"),
    probe=("sns", "ListTopics", ()),
    outputs=(("resources.json", "list"),),
    description="SNS topics, their access policies, encryption and subscriptions",
)

REDACTED = "<redacted>"


def minimise_endpoint(protocol: Optional[str], endpoint: Optional[str]) -> Optional[str]:
    """The part of a subscription endpoint that is safe to store (see the module docstring)."""
    if not endpoint:
        return endpoint
    proto = (protocol or "").lower()
    if endpoint.startswith("arn:"):
        return endpoint
    if proto in ("http", "https"):
        parsed = urlparse(endpoint)
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme or proto}://{host}{port}" if host else REDACTED
    if proto in ("email", "email-json"):
        domain = endpoint.rpartition("@")[2]
        return f"{REDACTED}@{domain}" if "@" in endpoint and domain else REDACTED
    return REDACTED


def _subscriptions(ctx: Any, sns: Any, arn: str, item: Dict[str, Any]) -> None:
    result = ctx.paginate(sns, "list_subscriptions_by_topic", "Subscriptions", item=arn, TopicArn=arn)
    if not result.ok:
        item["Subscriptions"] = None
        add_error(item, result)
        return
    subs = [{"Protocol": s.get("Protocol"), "Endpoint": minimise_endpoint(s.get("Protocol"), s.get("Endpoint")),
             "Owner": s.get("Owner"), "SubscriptionArn": s.get("SubscriptionArn")} for s in result.value]
    item["Subscriptions"] = sorted(subs, key=lambda s: (str(s["Protocol"]), str(s["Endpoint"]),
                                                        str(s["SubscriptionArn"])))


def _topic(ctx: Any, sns: Any, arn: str) -> Dict[str, Any]:
    item: Dict[str, Any] = {"Type": "sns", "Arn": arn, "Name": arn.split(":")[-1], "Policy": None,
                            "PolicyStatus": None, "KmsMasterKeyId": None, "Subscriptions": None}
    result = ctx.call(sns, "get_topic_attributes", item=arn, TopicArn=arn)
    if result.ok:
        attrs = result.get("Attributes") or {}
        item["Policy"] = policy_doc(attrs.get("Policy"))
        item["PolicyStatus"] = "present" if item["Policy"] else "absent"
        item["KmsMasterKeyId"] = attrs.get("KmsMasterKeyId")
    else:
        item["PolicyStatus"] = result.policy_status()
        add_error(item, result)
    _subscriptions(ctx, sns, arn, item)
    return item


def collect(ctx: Any) -> None:
    sns = ctx.client("sns")
    topics: List[Dict[str, Any]] = []
    with ctx.section("topics"):
        listed = ctx.paginate(sns, "list_topics", "Topics", primary=True)
        for arn in sorted({t["TopicArn"] for t in listed.value if t.get("TopicArn")}):
            topics.append(_topic(ctx, sns, arn))
    topics.sort(key=lambda t: t["Arn"])
    ctx.out.write("resources.json", topics)
    ctx.log.info("%d topics", len(topics))
