"""The committed scenario trees match tests/support/report_builder.py and follow the rules.

Regenerate after an intentional builder change:
    .venv/bin/python -m tests.support.report_builder --write-fixtures
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from tests.support import report_builder as rb
from tests.support import targets

REQUIRED = {"single_region_minimal", "all_mode", "malformed", "eks_irsa", "data_services", "cross_account",
            "public_exposure", "poweruser_notaction", "hostile_strings", "ir_leaked_key",
            "ir_leaked_key_quarantine", "microbench"}
NON_CORE = ["secretsmanager", "ssm", "lambda", "kms", "ecs", "cloudformation", "glue", "codebuild", "sagemaker",
            "sns", "sqs", "ecr", "rds", "dynamodb", "apigateway", "cognito", "ebs", "elb", "route53"]
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
TWELVE = re.compile(r"(?<!\d)\d{12}(?!\d)")
FORBIDDEN_DIR_NAMES = {"reports", "build", "dist", "env", "venv"}


def test_required_scenarios_registered():
    assert REQUIRED <= set(rb.scenario_names())


@pytest.mark.parametrize("name", rb.scenario_names())
def test_committed_tree_matches_builder(name, tmp_path):
    built = tmp_path / "built"
    rb.build(name, built)
    committed = rb.fixture_tree(name)
    assert committed.is_dir(), f"{committed} missing; run python -m tests.support.report_builder --write-fixtures"
    expected, actual = rb.tree_files(committed), rb.tree_files(built)
    assert sorted(expected) == sorted(actual), "file sets differ; regenerate fixtures"
    stale = [rel for rel in expected if expected[rel] != actual[rel]]
    assert not stale, f"committed fixture content drifted from the builder: {stale[:10]}"
    meta_path = rb.FIXTURES_DIR / name / "scenario.json"
    with open(meta_path, encoding="utf-8") as fh:
        assert json.load(fh) == rb.get(name).meta()


@pytest.mark.parametrize("name", rb.scenario_names())
def test_tree_is_nested_two_levels(name):
    sc = rb.get(name)
    tree = rb.fixture_tree(name)
    assert sorted(os.listdir(tree)) == [sc.account]
    entries = sorted(os.listdir(tree / sc.account))
    scopes = sorted(d.split("/", 1)[1] for d in sc.scope_dirs)
    if sc.layout == "all_mode":
        assert entries == sorted(scopes + ["manifest.json"])
    else:
        assert entries == scopes
    for rd in sc.report_dirs:
        assert (tree / rd / "iam").is_dir()


@pytest.mark.parametrize("name", rb.scenario_names())
def test_only_placeholder_accounts_and_safe_names(name):
    tree = rb.fixture_tree(name)
    for path in sorted(p for p in tree.rglob("*")):
        rel = path.relative_to(tree)
        for part in rel.parts:
            assert SAFE_NAME.match(part), f"unsafe file name component {part!r} in {rel}"
            assert part.lower() not in FORBIDDEN_DIR_NAMES or path.is_file(), rel
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            assert set(TWELVE.findall(text)) <= rb.PLACEHOLDER_ACCOUNTS, rel
            json.loads(text)


def test_data_services_covers_every_non_core_collector():
    root = rb.fixture_tree("data_services") / rb.ACCT_MAIN / "eu-west-2"
    for svc in NON_CORE:
        files = [p for p in (root / svc).rglob("*.json")]
        assert files, svc
        if (root / svc / "resources.json").is_file():
            with open(root / svc / "resources.json", encoding="utf-8") as fh:
                assert json.load(fh), f"{svc}/resources.json is empty"


def test_hostile_strings_present_in_content_not_filenames():
    tree = rb.fixture_tree("hostile_strings")
    blob = []
    for p in tree.rglob("*.json"):
        with open(p, encoding="utf-8") as fh:
            blob.append(json.dumps(json.load(fh), ensure_ascii=False))
    text = "\n".join(blob)
    for h in rb.HOSTILE_STRINGS + rb.PROTO_NAMES:
        assert json.dumps(h, ensure_ascii=False)[1:-1] in text, h


def test_microbench_labels_written():
    with open(rb.FIXTURES_DIR / "microbench" / "labels.json", encoding="utf-8") as fh:
        labels = json.load(fh)
    assert len(labels) == 10
    assert sum(1 for v in labels.values() if v["positive"]) == 5


def test_materialize_returns_report_dirs(tmp_path):
    dirs = rb.materialize("all_mode", tmp_path)
    assert dirs == [Path(tmp_path) / rb.ACCT_ALT / "global"]
    assert (dirs[0] / "iam" / "roles.json").is_file()
    assert (Path(tmp_path) / rb.ACCT_ALT / "eu-west-1" / "ec2" / "instances.json").is_file()


# ── node-id conformity of the synthetic ids (request regressions-py-1) ───────
_EC2_ID = re.compile(r"^(i|sg|subnet|vpc|snap|ami|lt)-[0-9A-Za-z]+$")
_EC2_KIND = {"i": "instance", "sg": "sg", "subnet": "subnet", "vpc": "vpc", "snap": "ebssnapshot", "ami": "ami",
             "lt": "launchtemplate"}
_NOT_AN_ID_KEYS = {"addonName", "name", "Name", "GroupName", "Description", "description"}


def _walk(obj, key=None):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, k)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v, key)
    elif isinstance(obj, str):
        yield key, obj


def _node_id(kind: str, raw: str, account: str, region: str) -> str:
    if kind in ("ami", "ebssnapshot"):
        res = "image" if kind == "ami" else "snapshot"
        return f"arn:aws:ec2:{region}::{res}/{raw}"
    res = {"instance": "instance", "sg": "security-group", "subnet": "subnet", "vpc": "vpc",
           "launchtemplate": "launch-template"}[kind]
    return f"arn:aws:ec2:{region}:{account}:{res}/{raw}"


@pytest.mark.parametrize("name", rb.scenario_names())
def test_ec2_family_ids_match_the_node_id_scheme(name):
    """docs/contracts/node-ids.md: i-/sg-/subnet-/vpc-/snap-/ami- ids are hexadecimal (regressions-py-1)."""
    ids = targets.engine_module("graph.ids")
    sc = rb.get(name)
    bad = []
    for path in sorted(rb.fixture_tree(name).rglob("*.json")):
        region = sc.regions[0] if "global" in path.parts else next(
            (r for r in sc.regions if r in path.parts), sc.regions[0])
        for key, value in _walk(json.loads(path.read_text(encoding="utf-8"))):
            m = _EC2_ID.match(value)
            if not m or key in _NOT_AN_ID_KEYS:
                continue
            kind = _EC2_KIND[m.group(1)]
            if not ids.node_id_matches(kind, _node_id(kind, value, sc.account, region)):
                bad.append((path.name, key, value))
    assert bad == []


@pytest.mark.parametrize("name", rb.scenario_names())
def test_bucket_and_kubernetes_names_contain_no_slash(name):
    """Real S3 bucket and Kubernetes object names cannot contain '/', and node ids key on it (node-ids.md)."""
    tree = rb.fixture_tree(name)
    bad = []
    for path in sorted(tree.rglob("s3/buckets.json")):
        bad += [b["Name"] for b in json.loads(path.read_text()) if isinstance(b, dict) and "/" in b["Name"]]
    for path in sorted(tree.rglob("k8s/*/*.json")):
        items = json.loads(path.read_text())
        for item in items if isinstance(items, list) else []:
            meta = item.get("metadata") or {}
            bad += [v for v in (meta.get("name"), meta.get("namespace")) if isinstance(v, str) and "/" in v]
    assert bad == []


# ── v2 run builders (request contracts-runtime-3) ────────────────────────────
def _validator(name):
    jsonschema = pytest.importorskip("jsonschema")
    return jsonschema.Draft202012Validator(json.loads(targets.schema_path(name).read_text(encoding="utf-8")))


def _errors(validator, doc):
    return [f"{list(e.absolute_path)}: {e.message}" for e in validator.iter_errors(doc)]


def test_v2_example_run_validates_against_the_runtime_schemas(tmp_path):
    run = rb.build_v2_example(tmp_path)
    assert run.path == tmp_path / rb.ACCT_MAIN / rb.V2_RUN_ID
    manifest = json.loads((run.path / "manifest.json").read_text())
    assert _errors(_validator("manifest-2.0.schema.json"), manifest) == []
    cov_validator = _validator("coverage-1.schema.json")
    coverage_files = sorted(run.path.rglob("_coverage.json"))
    assert len(coverage_files) == 6
    for path in coverage_files:
        assert _errors(cov_validator, json.loads(path.read_text())) == [], path
    # report-layout.md §1.1: only the allowed entries at the run root
    assert sorted(p.name for p in run.path.iterdir()) == sorted(
        ["HANDLING.txt", "SHA256SUMS", "manifest.json", "global", "eu-west-1", "eu-west-2"])
    assert manifest["target"]["regions"] == ["eu-west-1", "eu-west-2"]
    assert manifest["run"]["status"] == "partial" and manifest["run"]["exit_code"] == 2
    assert manifest["coverage_summary"]["partial_modules"] == ["s3@global"]
    assert [(m["name"], m["region"]) for m in manifest["modules"]][:2] == [("iam", "global"), ("s3", "global")]
    skipped = [m for m in manifest["modules"] if m["status"] == "skipped"]
    assert {m["name"] for m in skipped} == {"k8s"} and all(m["dir"] is None for m in skipped)
    assert not (run.path / "eu-west-1" / "k8s").exists()


def test_v2_digests_and_sha256sums(tmp_path):
    import hashlib
    run = rb.build_v2_example(tmp_path)
    manifest = json.loads((run.path / "manifest.json").read_text())
    listed = {f["path"]: f for f in manifest["files"]}
    assert "manifest.json" not in listed and "SHA256SUMS" not in listed and "HANDLING.txt" in listed
    for rel, entry in listed.items():
        data = (run.path / rel).read_bytes()
        assert entry == {"path": rel, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    lines = (run.path / "SHA256SUMS").read_text().splitlines()
    assert [ln[66:] for ln in lines] == sorted(list(listed) + ["manifest.json"])
    for ln in lines:
        assert hashlib.sha256((run.path / ln[66:]).read_bytes()).hexdigest() == ln[:64]


@pytest.mark.parametrize("status", ["ok", "partial", "denied", "failed", "interrupted", "skipped", "not_run"])
def test_v2_coverage_helper_gives_each_module_status(tmp_path, status):
    run = rb.V2Run(tmp_path, regions=["eu-west-2"])
    doc = run.coverage("lambda", "eu-west-2", status=status)
    entry = run.modules()[0]
    assert entry["status"] == status
    if status in ("skipped", "not_run"):
        assert doc == {} and entry["dir"] is None and entry["coverage"] is None
        assert not (run.path / "eu-west-2" / "lambda").exists()
    else:
        assert _errors(_validator("coverage-1.schema.json"), doc) == []
        assert json.loads((run.path / "eu-west-2" / "lambda" / "_coverage.json").read_text()) == doc
        assert entry["coverage"] == doc["summary"] and entry["dir"] == "eu-west-2/lambda"
    assert _errors(_validator("manifest-2.0.schema.json"), run.manifest()) == []


def test_v2_coverage_records_item_errors_sections_and_not_configured(tmp_path):
    run = rb.V2Run(tmp_path)
    doc = run.coverage("s3", "global", calls=[
        {"api": "s3:ListBuckets", "primary": True, "items": 3, "pages": 1},
        {"api": "s3:GetBucketPolicy", "error_code": "NoSuchBucketPolicy", "not_configured": True, "count": 2},
        {"api": "s3:GetBucketPolicy", "status": "denied", "item": "arn:aws:s3:::demo-a"}],
        item_errors=[{"resource": "arn:aws:s3:::demo-b", "api": "s3:GetBucketAcl", "status": "error",
                      "error_code": "InternalError"}],
        sections=["buckets", ("policies", RuntimeError("boom"))])
    assert doc["status"] == "partial"
    assert doc["summary"] == {"calls": 4, "ok": 3, "denied": 1, "error": 0, "throttled": 0, "skipped": 0,
                              "not_configured": 2, "item_errors": 2}
    assert [s["status"] for s in doc["sections"]] == ["ok", "error"]
    assert {e["resource"] for e in doc["item_errors"]} == {"arn:aws:s3:::demo-a", "arn:aws:s3:::demo-b"}
    assert doc["started_at"] == doc["ended_at"] == rb.TS_Z and doc["duration_seconds"] == 0.0
    summary = run.coverage_summary()
    assert summary["denied_apis"] == [{"api": "s3:GetBucketPolicy", "regions": ["global"]}]
    with pytest.raises(ValueError, match="not 'ok'"):
        run.coverage("iam", "global", status="ok", calls=[{"api": "iam:ListUsers", "status": "denied",
                                                           "primary": True}])


def test_v2_redacted_manifest_has_no_caller_identity(tmp_path):
    run = rb.V2Run(tmp_path, redacted=True)
    run.coverage("iam", "global")
    doc = run.manifest()
    assert doc["operator"]["caller_arn"] is None and doc["operator"]["caller_user_id"] is None
    assert doc["operator"]["principal_arn"] == f"arn:aws:iam::{rb.ACCT_MAIN}:role/demo-operator"
    assert _errors(_validator("manifest-2.0.schema.json"), doc) == []
    assert "demo-session" not in json.dumps(doc)


def test_v2_units_are_scopes_at_the_run_root(tmp_path):
    run = rb.ReportBuilder(tmp_path).v2_run(regions=["eu-west-1"], partition="aws-us-gov")
    g, r = run.unit("global"), run.unit("eu-west-1")
    assert g.path == run.path / "global" and r.path == run.path / "eu-west-1"
    assert g.region == "us-gov-west-1" and run.manifest()["target"]["global_region"] == "us-gov-west-1"
    with pytest.raises(KeyError):
        run.unit("eu-west-2")


def test_mark_item_adds_markers_and_nulls():
    rec = rb.mark_item({"Name": "demo", "Public": False}, rb.collection_error("s3:GetBucketPolicy"),
                       policy_status="denied", unknown=["Public"])
    assert rec == {"Name": "demo", "Public": None, "PolicyStatus": "denied",
                   "CollectionErrors": [{"api": "s3:GetBucketPolicy", "status": "denied",
                                         "error_code": "AccessDenied"}]}
    assert "CollectionErrors" not in rb.mark_item({"Name": "ok"}, policy_status="present")
    with pytest.raises(ValueError):
        rb.mark_item({}, policy_status="unknown")
    with pytest.raises(ValueError):
        rb.collection_error("s3:GetBucketPolicy", "ok")


def test_gaad_layout_keys_policy_documents_by_arn(tmp_path):
    """collectors-cli.md §5.1: a customer policy named like an AWS one gets its own file (F-013 shape)."""
    s = rb.Scope(tmp_path, rb.ACCT_MAIN, "global")
    iam = rb.Iam(rb.ACCT_MAIN)
    customer = iam.managed("ReadOnlyAccess", [rb.allow("*", "*")], customer=True)
    aws = iam.managed("ReadOnlyAccess", rb.AWS_MANAGED_DOCS["ReadOnlyAccess"], version="v118")
    iam.role("demo-a", rb.trust({"Service": "ec2.amazonaws.com"}), attached=[customer])
    iam.role("demo-b", rb.trust({"Service": "ec2.amazonaws.com"}), attached=[aws])
    iam.write(s, layout="gaad")
    docs = [json.loads(p.read_text()) for p in sorted((s.path / "iam" / "policy_documents").glob("*.json"))]
    # Iam.managed keeps one document per (name, version) file in the legacy layout; GAAD keys by ARN
    assert {d["PolicyArn"] for d in docs} >= {customer["PolicyArn"], aws["PolicyArn"]}
    by_arn = {d["PolicyArn"]: d for d in docs}
    assert by_arn[customer["PolicyArn"]]["PolicyType"] == "Local"
    assert by_arn[aws["PolicyArn"]]["PolicyType"] == "AWS" and by_arn[aws["PolicyArn"]]["Versions"] == []
    assert json.loads((s.path / "iam" / "account_password_policy.json").read_text())["Configured"] is True
    report = json.loads((s.path / "iam" / "credential_report.json").read_text())
    assert report["Rows"][0]["user"] == "<root_account>"
    assert not (s.path / "iam" / "inline_policies").exists()
