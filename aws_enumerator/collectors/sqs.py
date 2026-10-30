"""SQS queues: access policies and encryption settings (never messages).

Output (``<region>/sqs/``):

* ``resources.json`` (list), one item per queue, sorted by ``Arn``::

    {Type: "sqs", Arn, Name, Url, Policy: {...}|null, PolicyStatus, KmsMasterKeyId: str|null,
     SqsManagedSseEnabled: bool|null, CollectionErrors?}

  ``Arn`` is derived from the queue URL when ``GetQueueAttributes`` fails, so a queue whose
  attributes cannot be read is still listed (F-102); its unknown fields are ``null`` and
  ``CollectionErrors`` says why (F-059). ``PolicyStatus`` is ``present``/``absent``/``denied``/
  ``error``/``skipped`` (coverage-schema.md §1).

``ListQueues`` is paginated with ``MaxResults=1000``: without it SQS returns at most 1,000 queues
and no ``NextToken`` (F-115).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from aws_enumerator.collectors._common import add_error, policy_doc
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="sqs", scope="regional", output_dir="sqs", services=("sqs",),
    tier=1, cost="low", noise="low", default=True, groups=("@messaging",),
    actions=("sqs:ListQueues", "sqs:GetQueueAttributes"),
    probe=("sqs", "ListQueues", (("MaxResults", 1),)),
    outputs=(("resources.json", "list"),),
    description="SQS queues, their access policies and encryption (never messages)",
)

#: ListQueues page size; also what makes SQS return a NextToken at all (F-115).
PAGE_SIZE = 1000
_ATTRIBUTES = ["QueueArn", "Policy", "KmsMasterKeyId", "SqsManagedSseEnabled"]


def _bool_attr(value: Any) -> Optional[bool]:
    if value is None:
        return None
    return str(value).lower() == "true"


def queue_identity(ctx: Any, url: str) -> Tuple[str, str]:
    """``(arn, name)`` of a queue from its URL (``https://sqs.<region>.amazonaws.com/<account>/<name>``)."""
    parts = [p for p in urlparse(url).path.split("/") if p]
    name = parts[-1] if parts else url
    account = parts[-2] if len(parts) >= 2 and parts[-2].isdigit() else ctx.account_id
    return ctx.arn("sqs", name, account=account), name


def _queue(ctx: Any, sqs: Any, url: str) -> Dict[str, Any]:
    arn, name = queue_identity(ctx, url)
    item: Dict[str, Any] = {"Type": "sqs", "Arn": arn, "Name": name, "Url": url, "Policy": None,
                            "PolicyStatus": None, "KmsMasterKeyId": None, "SqsManagedSseEnabled": None}
    result = ctx.call(sqs, "get_queue_attributes", item=arn, QueueUrl=url, AttributeNames=list(_ATTRIBUTES))
    if result.ok:
        attrs = result.get("Attributes") or {}
        item["Arn"] = attrs.get("QueueArn") or arn
        item["Policy"] = policy_doc(attrs.get("Policy"))
        item["PolicyStatus"] = "present" if item["Policy"] else "absent"
        item["KmsMasterKeyId"] = attrs.get("KmsMasterKeyId")
        item["SqsManagedSseEnabled"] = _bool_attr(attrs.get("SqsManagedSseEnabled"))
    else:
        item["PolicyStatus"] = result.policy_status()
        add_error(item, result)
    return item


def collect(ctx: Any) -> None:
    sqs = ctx.client("sqs")
    queues: List[Dict[str, Any]] = []
    with ctx.section("queues"):
        urls = ctx.paginate(sqs, "list_queues", "QueueUrls", page_size=PAGE_SIZE, primary=True)
        for url in sorted(set(urls.value)):
            queues.append(_queue(ctx, sqs, url))
    queues.sort(key=lambda q: q["Arn"])
    ctx.out.write("resources.json", queues)
    ctx.log.info("%d queues", len(queues))
