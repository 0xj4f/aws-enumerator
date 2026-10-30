"""AWS Security Finding Format export (exports.md §5).

``{"Findings": [...]}``, each element ready for ``aws securityhub batch-import-findings`` (the tool never calls
Security Hub; batching into groups of 100 is the user's job). Field mapping:

* ``Id`` = ``aws-enumerator/<account>/<fingerprint>``, ``GeneratorId`` = ``aws-enumerator/<finding id>``;
* ``ProductArn`` = ``arn:<partition>:securityhub:<region>:<account>:product/<account>/default``; ``<account>`` is
  the finding's account (falling back to ``run.account_id``, D-50) and ``<region>`` the finding's region, or the
  **global region of the partition** for a global resource, because ``graph.json`` carries no home region;
* ``Severity`` = ``{Label: <ASFF label>, Original: <stored severity>}`` (D-24);
* ``Types`` from the category (privilege escalation, exposure, credentials, else best practices);
* ``Resources[0].Type`` from the node type (``AwsIamRole`` … ``Other``);
* ``Workflow.Status`` is ``SUPPRESSED`` for suppressed findings (exported only with ``include_suppressed``);
* title, description and remediation text are truncated to 256, 1,024 and 512 characters.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Mapping, Optional

from aws_enumerator.engine.writers.csv import Selection, select_findings, severity_class

SCHEMA_VERSION = "2018-10-08"
LABELS = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFORMATIONAL"}
#: Global control-plane region per partition (manifest.md §3.3; registry.global_region_for).
GLOBAL_REGIONS = {
    "aws": "us-east-1", "aws-us-gov": "us-gov-west-1", "aws-cn": "cn-north-1", "aws-iso": "us-iso-east-1",
    "aws-iso-b": "us-isob-east-1", "aws-iso-e": "eu-isoe-west-1", "aws-iso-f": "us-isof-south-1",
    "aws-eusc": "eusc-de-east-1",
}
#: exports.md §5 resource type map (node type → ASFF resource type).
RESOURCE_TYPES = {
    "role": "AwsIamRole", "user": "AwsIamUser", "group": "AwsIamGroup", "policy": "AwsIamPolicy",
    "bucket": "AwsS3Bucket", "instance": "AwsEc2Instance", "sg": "AwsEc2SecurityGroup",
    "lambda": "AwsLambdaFunction", "kms": "AwsKmsKey", "secret": "AwsSecretsManagerSecret", "sqs": "AwsSqsQueue",
    "sns": "AwsSnsTopic", "cluster": "AwsEksCluster", "rds": "AwsRdsDbInstance", "dynamodb": "AwsDynamoDbTable",
    "ecr": "AwsEcrRepository",
}
TYPE_PRIVESC = "TTPs/Privilege Escalation"
TYPE_EXPOSURE = "Effects/Data Exposure"
TYPE_CREDENTIALS = "TTPs/Credential Access"
TYPE_DEFAULT = "Software and Configuration Checks/AWS Security Best Practices"
_PRIVESC_WORDS = ("privilege", "escalation", "privesc")
_EXPOSURE_WORDS = ("public", "exposure", "cross_account", "cross-account", "xacct")
_CREDENTIAL_WORDS = ("credential", "plaintext", "password", "access_key", "access-key")
LIMITS = {"Title": 256, "Description": 1024, "Remediation": 512}


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def finding_types(category: Any) -> List[str]:
    """``Types`` for a finding category (exports.md §5); matching is by keyword, privilege escalation first."""
    cat = _text(category).lower()
    if any(w in cat for w in _PRIVESC_WORDS):
        return [TYPE_PRIVESC]
    if any(w in cat for w in _EXPOSURE_WORDS):
        return [TYPE_EXPOSURE]
    if any(w in cat for w in _CREDENTIAL_WORDS):
        return [TYPE_CREDENTIALS]
    return [TYPE_DEFAULT]


def global_region(partition: Any) -> str:
    """The partition's global region (``us-east-1`` for an unknown partition)."""
    return GLOBAL_REGIONS.get(_text(partition), "us-east-1")


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _finding(sel: Selection, f: Mapping[str, Any], partition: str) -> Dict[str, Any]:
    account = sel.account(f) or "000000000000"
    region = _text(f.get("region")) or global_region(partition)
    fid, fp = _text(f.get("id")), _text(f.get("fingerprint"))
    generated = _text(sel.run.get("generated_at"))
    remediation: Dict[str, Any] = {"Text": _clip(_text(f.get("remediation")) or "Review the finding.",
                                                 LIMITS["Remediation"])}
    if _text(f.get("reference")):
        remediation["Url"] = f["reference"]
    product_fields = {"aws-enumerator/fingerprint": fp, "aws-enumerator/confidence": _text(f.get("confidence")),
                      "aws-enumerator/run_id": _text(sel.run.get("run_id")),
                      "aws-enumerator/rule_version": _text(f.get("rule_version"))}
    return {
        "SchemaVersion": SCHEMA_VERSION,
        "Id": f"aws-enumerator/{account}/{fp}",
        "ProductArn": f"arn:{partition}:securityhub:{region}:{account}:product/{account}/default",
        "GeneratorId": f"aws-enumerator/{fid}",
        "AwsAccountId": account,
        "Types": finding_types(f.get("category")),
        "CreatedAt": generated,
        "UpdatedAt": generated,
        "Severity": {"Label": LABELS[severity_class(f.get("severity"))], "Original": _text(f.get("severity"))},
        "Title": _clip(_text(f.get("title")) or fid, LIMITS["Title"]),
        "Description": _clip(_text(f.get("description")) or _text(f.get("title")) or fid, LIMITS["Description"]),
        "Remediation": {"Recommendation": remediation},
        "Resources": [{"Type": RESOURCE_TYPES.get(sel.node_type(f), "Other"), "Id": _text(f.get("node_id")),
                       "Partition": partition, "Region": region}],
        "RecordState": "ACTIVE",
        "Workflow": {"Status": "SUPPRESSED" if f.get("status") == "suppressed" else "NEW"},
        "ProductFields": {k: v for k, v in product_fields.items() if v},
    }


def document(sel: Selection) -> Dict[str, Any]:
    partition = _text(sel.run.get("partition")) or "aws"
    return {"Findings": [_finding(sel, f, partition) for f in sel.findings]}


def render(graph: Mapping[str, Any], *, min_severity: Optional[str] = None, include_suppressed: bool = False,
           all_edges: bool = False) -> bytes:
    """``findings.asff.json`` (exports.md §5). ``all_edges`` does not apply to findings and is ignored."""
    del all_edges
    sel = select_findings(graph, min_severity=min_severity, include_suppressed=include_suppressed)
    return (json.dumps(document(sel), indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


__all__ = ["GLOBAL_REGIONS", "LABELS", "RESOURCE_TYPES", "SCHEMA_VERSION", "document", "finding_types",
           "global_region", "render"]
