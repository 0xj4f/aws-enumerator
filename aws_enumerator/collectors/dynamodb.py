"""DynamoDB tables and their resource-based policies (never table data or items).

Output (``<region>/dynamodb/``):

* ``resources.json`` (list), one item per table, sorted by ``Arn``::

    {Type: "dynamodb", Arn, Name, Policy: {...}|null, PolicyStatus, CollectionErrors?}

The table ARN is deterministic (``arn:<partition>:dynamodb:<region>:<account>:table/<name>``), so
``DescribeTable`` is not called (F-100) and a table whose policy cannot be read is still listed
(F-102). ``PolicyNotFoundException`` is "not configured" (``PolicyStatus: absent``); a denial is
``denied`` (F-059).
"""

from __future__ import annotations

from typing import Any, Dict, List

from aws_enumerator.collectors._common import add_error, policy_doc
from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="dynamodb", scope="regional", output_dir="dynamodb", services=("dynamodb",),
    tier=1, cost="low", noise="low", default=True, groups=("@data",),
    actions=("dynamodb:ListTables", "dynamodb:GetResourcePolicy"),
    probe=("dynamodb", "ListTables", (("Limit", 1),)),
    outputs=(("resources.json", "list"),),
    description="DynamoDB tables and their resource policies",
)


def _table(ctx: Any, ddb: Any, name: str) -> Dict[str, Any]:
    arn = ctx.arn("dynamodb", f"table/{name}")
    item: Dict[str, Any] = {"Type": "dynamodb", "Arn": arn, "Name": name, "Policy": None, "PolicyStatus": None}
    result = ctx.call(ddb, "get_resource_policy", item=arn, ResourceArn=arn)
    item["Policy"] = policy_doc(result.get("Policy")) if result.ok else None
    item["PolicyStatus"] = ("present" if item["Policy"] else "absent") if result.ok else result.policy_status()
    add_error(item, result)
    return item


def collect(ctx: Any) -> None:
    ddb = ctx.client("dynamodb")
    tables: List[Dict[str, Any]] = []
    with ctx.section("tables"):
        names = ctx.paginate(ddb, "list_tables", "TableNames", page_size=100, primary=True)
        for name in sorted(set(names.value)):
            tables.append(_table(ctx, ddb, name))
    tables.sort(key=lambda t: t["Arn"])
    ctx.out.write("resources.json", tables)
    ctx.log.info("%d tables", len(tables))
