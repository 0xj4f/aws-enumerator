"""SARIF 2.1.0 and ASFF exports (exports.md §1, §2, §5; F-165), merged graphs included (D-50)."""

from __future__ import annotations

import json

import jsonschema
import pytest

from aws_enumerator.engine import writers
from aws_enumerator.engine.writers import asff
from aws_enumerator.engine.writers import sarif as sarif_writer
from tests.support import targets

SARIF_SCHEMA = json.loads((targets.FIXTURES_DIR / "e-rules" / "sarif-2.1.0-subset.schema.json").read_text("utf-8"))
LEVELS = {"CRITICAL": ("error", "9.5"), "HIGH": ("error", "8.0"), "MEDIUM": ("warning", "5.5"),
          "LOW": ("note", "3.0"), "INFO": ("note", "0.0")}


def _sarif(graph, **kw):
    doc = json.loads(writers.export(graph, "sarif", **kw))
    errors = [e.message for e in jsonschema.Draft202012Validator(SARIF_SCHEMA).iter_errors(doc)]
    assert errors == []
    return doc


@pytest.mark.finding("F-165")
@pytest.mark.parametrize("name", ["example", "hostile", "analysed"])
def test_sarif_is_structurally_valid_and_consistent(name, request):
    graph = request.getfixturevalue(name)
    doc = _sarif(graph)
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == sorted({f["id"] for f in graph["findings"] if f["status"] == "open"})
    assert run["automationDetails"]["id"] == f"aws-enumerator/{graph['run']['account_id']}/{graph['run']['run_id']}"
    assert run["invocations"][0]["endTimeUtc"] == graph["run"]["generated_at"]
    by_fp = {f["fingerprint"]: f for f in graph["findings"]}
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        f = by_fp[res["partialFingerprints"]["awsEnumeratorFingerprint/v1"]]
        assert res["level"] == LEVELS[f["severity"].upper()][0]
        assert res["properties"]["severity"] == f["severity"]                 # copied unchanged (D-24)
        assert res["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] == f["node_id"]
        assert res["locations"][0]["physicalLocation"]["artifactLocation"] == {"uri": "analysis/graph.json",
                                                                                "uriBaseId": "RUNROOT"}
        assert res["properties"]["region"] == (f.get("region") or "global")   # D-25
    for rule in rules:
        worst = min((f for f in graph["findings"] if f["id"] == rule["id"] and f["status"] == "open"),
                    key=lambda f: list(LEVELS).index(f["severity"].upper()))
        assert rule["properties"]["security-severity"] == LEVELS[worst["severity"].upper()][1]


@pytest.mark.finding("F-165", "F-143")
def test_sarif_suppressed_findings_only_on_request(example):
    suppressed = [f for f in example["findings"] if f["status"] == "suppressed"]
    assert suppressed
    plain = _sarif(example)["runs"][0]["results"]
    assert all("suppressions" not in r for r in plain)
    every = _sarif(example, include_suppressed=True)["runs"][0]["results"]
    marked = [r for r in every if r.get("suppressions")]
    assert len(marked) == len(suppressed)
    assert marked[0]["suppressions"][0]["kind"] == "external" and marked[0]["suppressions"][0]["justification"]


@pytest.mark.finding("F-165")
def test_sarif_min_severity_and_the_empty_document(example):
    high = _sarif(example, min_severity="high")["runs"][0]["results"]
    assert high and all(r["level"] == "error" for r in high)
    empty = _sarif({"schema_version": "1.0.0", "run": {}, "generator": {}, "nodes": [], "findings": []})
    assert empty["runs"][0]["results"] == [] and empty["runs"][0]["tool"]["driver"]["rules"] == []
    assert sarif_writer.SARIF_VERSION == "2.1.0"


@pytest.mark.finding("F-165")
def test_sarif_per_finding_account_in_a_merged_graph(analysed, merged):
    doc = merged(analysed)
    results = _sarif(doc)["runs"][0]["results"]
    accounts = {r["properties"]["account"] for r in results}
    assert accounts == {analysed["run"]["account_id"], "999999999999"}      # missing account -> run's (D-50)


# ── ASFF ─────────────────────────────────────────────────────────────────────

ASFF_REQUIRED = {"SchemaVersion", "Id", "ProductArn", "GeneratorId", "AwsAccountId", "Types", "CreatedAt",
                 "UpdatedAt", "Severity", "Title", "Description", "Resources"}


@pytest.mark.finding("F-165")
@pytest.mark.parametrize("name", ["example", "hostile", "analysed"])
def test_asff_fields(name, request):
    graph = request.getfixturevalue(name)
    findings = json.loads(writers.export(graph, "asff"))["Findings"]
    by_fp = {f["fingerprint"]: f for f in graph["findings"]}
    nodes = {n["id"]: n for n in graph["nodes"]}
    assert len(findings) == sum(1 for f in graph["findings"] if f["status"] == "open")
    for a in findings:
        assert ASFF_REQUIRED <= set(a) and a["SchemaVersion"] == "2018-10-08"
        f = by_fp[a["ProductFields"]["aws-enumerator/fingerprint"]]
        acct = f.get("account") or graph["run"]["account_id"]
        region = f.get("region") or "us-east-1"                              # partition's global region
        assert a["Id"] == f"aws-enumerator/{acct}/{f['fingerprint']}" and a["AwsAccountId"] == acct
        assert a["ProductArn"] == f"arn:aws:securityhub:{region}:{acct}:product/{acct}/default"
        assert a["GeneratorId"] == f"aws-enumerator/{f['id']}"
        assert a["Severity"]["Original"] == f["severity"]
        assert a["Severity"]["Label"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
        assert len(a["Title"]) <= 256 and len(a["Description"]) <= 1024
        assert len(a["Remediation"]["Recommendation"]["Text"]) <= 512
        res = a["Resources"][0]
        assert res["Id"] == f["node_id"] and res["Region"] == region and res["Partition"] == "aws"
        assert res["Type"] == asff.RESOURCE_TYPES.get(nodes.get(f["node_id"], {}).get("type"), "Other")
        assert a["RecordState"] == "ACTIVE" and a["Workflow"]["Status"] == "NEW"
        assert a["CreatedAt"] == a["UpdatedAt"] == graph["run"]["generated_at"]


@pytest.mark.finding("F-165")
def test_asff_types_and_global_regions():
    assert asff.finding_types("privilege_escalation") == ["TTPs/Privilege Escalation"]
    assert asff.finding_types("public-exposure") == ["Effects/Data Exposure"]
    assert asff.finding_types("credentials") == ["TTPs/Credential Access"]
    assert asff.finding_types("logging") == ["Software and Configuration Checks/AWS Security Best Practices"]
    assert asff.global_region("aws-us-gov") == "us-gov-west-1" and asff.global_region("aws-cn") == "cn-north-1"


@pytest.mark.finding("F-165")
def test_asff_gov_partition_suppressed_and_truncation():
    long = "x" * 3000
    graph = {"schema_version": "1.0.0", "generator": {"version": "0.3.0"},
             "run": {"account_id": "111122223333", "partition": "aws-us-gov", "run_id": "r1",
                     "generated_at": "2026-01-01T00:00:00Z"},
             "nodes": [{"id": "arn:aws-us-gov:iam::111122223333:role/demo", "type": "role", "label": "demo"}],
             "findings": [{"id": "ADMIN-001", "severity": "CRITICAL", "node_id": "arn:aws-us-gov:iam::111122223333:"
                           "role/demo", "fingerprint": "f" * 32, "status": "suppressed", "title": long,
                           "description": long, "remediation": long, "region": None,
                           "category": "dangerous_permission", "suppression": {"reason": "accepted"}}]}
    assert json.loads(writers.export(graph, "asff"))["Findings"] == []
    (a,) = json.loads(writers.export(graph, "asff", include_suppressed=True))["Findings"]
    assert a["ProductArn"].startswith("arn:aws-us-gov:securityhub:us-gov-west-1:111122223333:")
    assert a["Resources"][0]["Type"] == "AwsIamRole" and a["Workflow"]["Status"] == "SUPPRESSED"
    assert (len(a["Title"]), len(a["Description"]), len(a["Remediation"]["Recommendation"]["Text"])) == (
        256, 1024, 512)


@pytest.mark.finding("F-165")
def test_asff_per_finding_account_in_a_merged_graph(analysed, merged):
    findings = json.loads(writers.export(merged(analysed), "asff"))["Findings"]
    assert {a["AwsAccountId"] for a in findings} == {analysed["run"]["account_id"], "999999999999"}
    for a in findings:
        assert a["Id"].split("/")[1] == a["AwsAccountId"] and f":{a['AwsAccountId']}:product/" in a["ProductArn"]
