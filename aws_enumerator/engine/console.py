"""End-of-analysis summary for the operator (engine.md §1.1 ``console.py``; F-074, F-061, F-164).

d13c215 printed coloured lines to stdout and counted only CRITICAL, HIGH and MEDIUM, so LOW and INFO
findings disappeared from the run summary (F-074). The summary now goes through :mod:`logging` (the CLI decides
where it is shown; stdout carries only command results, cli.md §5), lists all five severities, the analysis
status with every failed analyzer (F-061), and per-domain edge counts with domain labels (F-164: the
"Cognito/EBS/ELB" line now names Route 53 too).
"""

from __future__ import annotations

import logging
from typing import Any, Iterable, List, Mapping, Optional

from aws_enumerator.engine.model import SEVERITIES

log = logging.getLogger("aws_enumerator.engine")

MAX_CRITICAL_LINES = 20

#: Console label of each legacy domain (F-164).
DOMAIN_LABELS: Mapping[str, str] = {
    "s3": "S3", "ec2": "EC2", "k8s": "Kubernetes/EKS", "secrets": "Secrets Manager/SSM", "lambda": "Lambda",
    "kms": "KMS", "compute": "ECS/CloudFormation/Glue/CodeBuild/SageMaker", "messaging": "SNS/SQS",
    "data_stores": "ECR/RDS/API Gateway/DynamoDB", "edge_services": "Cognito/EBS/ELB/Route 53",
}


def severity_line(summary: Mapping[str, Any]) -> str:
    """``Findings: 1 CRITICAL, 2 HIGH, 0 MEDIUM, 3 LOW, 0 INFO (6 total)`` (open findings)."""
    by = summary.get("by_severity") or {}
    parts = ", ".join(f"{int(by.get(s, 0))} {s}" for s in SEVERITIES)
    extra = []
    if summary.get("suppressed_count"):
        extra.append(f"{summary['suppressed_count']} suppressed")
    tail = f" ({int(summary.get('total_findings', 0))} total" + ("; " + ", ".join(extra) if extra else "") + ")"
    return f"Findings: {parts}{tail}"


def summary_lines(summary: Mapping[str, Any], findings: Iterable[Mapping[str, Any]] = (),
                  legacy_edge_counts: Optional[Mapping[str, int]] = None) -> List[str]:
    """Every line of the end-of-analysis summary, in order."""
    lines = [severity_line(summary)]
    failed = [s for s in summary.get("analyzer_status") or () if s.get("status") == "error"]
    status = summary.get("status", "ok")
    lines.append(f"Analysis status: {status}" + (
        f" ({len(failed)} analyzer(s) failed: " + ", ".join(sorted(str(s.get('name')) for s in failed)) + ")"
        if failed else ""))
    criticals = [f for f in findings if f.get("severity") == "CRITICAL" and f.get("status", "open") == "open"]
    if criticals:
        lines.append(f"{len(criticals)} CRITICAL finding(s); see the attack-path documentation:")
        for f in criticals[:MAX_CRITICAL_LINES]:
            lines.append(f"  {f.get('id')}  {f.get('node_id')}  {f.get('reference') or ''}".rstrip())
        if len(criticals) > MAX_CRITICAL_LINES:
            lines.append(f"  ... and {len(criticals) - MAX_CRITICAL_LINES} more")
    for domain, count in sorted((legacy_edge_counts or {}).items()):
        if count:
            lines.append(f"{DOMAIN_LABELS.get(domain, domain)} relationships: {count} edges")
    return lines


def report(summary: Mapping[str, Any], findings: Iterable[Mapping[str, Any]] = (),
           legacy_edge_counts: Optional[Mapping[str, int]] = None, logger: Optional[logging.Logger] = None) -> None:
    """Log the summary at INFO (a failed analyzer at WARNING)."""
    out = logger or log
    for line in summary_lines(summary, findings, legacy_edge_counts):
        level = logging.WARNING if line.startswith("Analysis status:") and "failed" in line else logging.INFO
        out.log(level, "%s", line)


__all__ = ["DOMAIN_LABELS", "report", "severity_line", "summary_lines"]
