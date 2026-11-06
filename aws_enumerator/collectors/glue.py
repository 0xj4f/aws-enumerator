"""Glue: jobs and development endpoints and the IAM role each runs as (PRIVESC-018).

Job ``DefaultArguments`` are **never** stored (they routinely carry passwords and tokens).

Output (``<region>/glue/``):

* ``resources.json`` (list), sorted by ``Arn``::

    {Type: "gluejob", Kind: "job"|"dev_endpoint", Arn, Name, Roles: [role], ...}

  ``Arn`` is the real, partition-aware ARN (``arn:<p>:glue:<region>:<account>:job/<name>``,
  ``devEndpoint/<name>``) instead of the bare name, so ARN-scoped IAM grants match and same-named
  jobs in two regions stay separate (F-051). Jobs add ``Command``, dev endpoints add ``Status`` and
  ``PublicAddress``.
"""

from __future__ import annotations

from typing import Any, Dict, List

from aws_enumerator.registry import CollectorSpec

SPEC = CollectorSpec(
    name="glue", scope="regional", output_dir="glue", services=("glue",),
    tier=2, cost="low", noise="low", default=True, groups=("@compute",),
    actions=("glue:GetJobs", "glue:GetDevEndpoints"),
    probe=("glue", "GetJobs", (("MaxResults", 1),)),
    outputs=(("resources.json", "list"),),
    description="Glue jobs and development endpoints and their roles (never job arguments)",
)


def _jobs(ctx: Any, glue: Any, out: List[Dict[str, Any]]) -> None:
    listed = ctx.paginate(glue, "get_jobs", "Jobs", page_size=200, primary=True)
    for job in listed.value:
        name, role = job.get("Name"), job.get("Role")
        out.append({"Type": "gluejob", "Kind": "job", "Arn": ctx.arn("glue", f"job/{name}"), "Name": name,
                    "Roles": [role] if role else [], "Command": (job.get("Command") or {}).get("Name")})


def _dev_endpoints(ctx: Any, glue: Any, out: List[Dict[str, Any]]) -> None:
    listed = ctx.paginate(glue, "get_dev_endpoints", "DevEndpoints", page_size=100)
    for ep in listed.value:
        name, role = ep.get("EndpointName"), ep.get("RoleArn")
        out.append({"Type": "gluejob", "Kind": "dev_endpoint", "Arn": ctx.arn("glue", f"devEndpoint/{name}"),
                    "Name": name, "Roles": [role] if role else [], "Status": ep.get("Status"),
                    "PublicAddress": ep.get("PublicAddress")})


def collect(ctx: Any) -> None:
    glue = ctx.client("glue")
    resources: List[Dict[str, Any]] = []
    with ctx.section("jobs"):
        _jobs(ctx, glue, resources)
    with ctx.section("dev_endpoints"):
        _dev_endpoints(ctx, glue, resources)
    resources.sort(key=lambda r: r["Arn"])
    ctx.out.write("resources.json", resources)
    ctx.log.info("%d jobs and development endpoints", len(resources))
