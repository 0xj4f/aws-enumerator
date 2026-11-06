"""ECS, CloudFormation, Glue, CodeBuild and SageMaker loader (E-compute).

Reads only the explicit units of the analysis context (``ctx.region_dirs``), never sibling directories (F-010,
F-025, F-063). Both collector layouts share the record shape ``{Type, Arn, Name, Roles}``; the v2 collectors add
fields (ECS ``Family`` / ``TaskRole`` / ``ExecutionRole`` / ``Revisions``, StackSets, SageMaker domains and user
profiles, CodeBuild ``Webhook`` / ``Source``, ``CollectionErrors``) and write ``null`` for unknown values.

``data`` (``ctx.data["compute"]``)::

    {"ecs": {unit: [record]}, "ecs_services": {unit: [record]}, "cloudformation": {unit: [record]},
     "glue": {unit: [record]}, "codebuild": {unit: [record]}, "codebuild_credentials": {unit: [record]},
     "sagemaker": {unit: [record]}}

Normalisation (records are copies; the collected files are never changed):

* **Glue ARNs (F-051).** The d13c215 collector stored the bare job / endpoint name as ``Arn``, so ARN-scoped
  grants never matched and same-named jobs of two regions collapsed. A bare name gets the real, partition-aware
  ARN ``arn:<p>:glue:<region>:<account>:job/<name>`` (``ArnSynthesised: true``). A v2 development endpoint
  (``Kind: dev_endpoint`` or a ``devEndpoint/`` ARN) gets ``Type: gluedevendpoint``, the node type of
  traversability-table.md (the collector writes ``gluejob`` for both).
* Everything else is passed through unchanged (the rules engine reads ``Type`` / ``Arn`` / ``Roles``).
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from aws_enumerator.engine.io.loaders import LoadResult, read_scoped

GLOBAL_FILES: Dict[str, str] = {}
REGIONAL_FILES: Dict[str, str] = {
    "ecs": "ecs/resources.json",
    "ecs_services": "ecs/services.json",
    "cloudformation": "cloudformation/resources.json",
    "glue": "glue/resources.json",
    "codebuild": "codebuild/resources.json",
    "codebuild_credentials": "codebuild/source_credentials.json",
    "sagemaker": "sagemaker/resources.json",
}


def normalise_glue(rec: Mapping[str, Any], *, partition: str, region: str, account: str) -> Dict[str, Any]:
    """A Glue record with a real ARN (synthesised for a bare name, F-051) and the dev-endpoint node type."""
    out = dict(rec)
    arn = out.get("Arn")
    name = out.get("Name") or arn
    is_endpoint = out.get("Kind") == "dev_endpoint" or (isinstance(arn, str) and ":devEndpoint/" in arn)
    if isinstance(name, str) and name and not (isinstance(arn, str) and arn.startswith("arn:")):
        kind = "devEndpoint" if is_endpoint else "job"
        out["Arn"] = f"arn:{partition}:glue:{region}:{account}:{kind}/{name}"
        out["ArnSynthesised"] = True
    if is_endpoint:
        out["Type"] = "gluedevendpoint"
    return out


def load(ctx: Any) -> LoadResult:
    """``ctx.data["compute"]`` (module docstring)."""
    result = read_scoped(ctx, GLOBAL_FILES, REGIONAL_FILES)
    data: Dict[str, Any] = dict(result.data)
    glue: Dict[str, List[Dict[str, Any]]] = {}
    for unit, records in sorted((data.get("glue") or {}).items()):
        if unit == "global":
            glue[unit] = list(records)
            continue
        glue[unit] = [normalise_glue(r, partition=ctx.partition, region=unit, account=ctx.account_id)
                      for r in records]
    data["glue"] = glue
    return LoadResult(data, result.status, dict(result.gaps), files=result.files)


__all__ = ["GLOBAL_FILES", "REGIONAL_FILES", "load", "normalise_glue"]
