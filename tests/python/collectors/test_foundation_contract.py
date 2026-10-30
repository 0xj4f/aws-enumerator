"""Collector foundation contract: ``CollectContext`` / ``ModuleOutput`` / ``run_collector`` against FakeAWS
(docs/contracts/collector-context.md, coverage-schema.md, manifest.md).

A small new-style demo collector (defined here, not shipped) exercises the contract:
denied primary -> module ``denied``; "not configured" codes -> ``ok`` + ``not_configured``;
a BotoCoreError inside a section -> ``partial`` with the data already written kept;
pagination (botocore paginator and the manual token loop); the deny breaker skipping the
remaining items; fatal credentials; interruption. The d13c215 ``collect(session, path)`` protocol and its
legacy adapter are gone (0.3.0): an old-style ``collect`` fails with a ``TypeError``.

Production code is reached through ``tests.support.targets`` (package name, collector modules).
"""

from __future__ import annotations

import datetime as dt
import importlib
import json
import os
import stat

import jsonschema
import pytest

from tests.support import targets
from tests.support.fakeaws import FakeAWS, PaginationSpec, World, botocore_error

pytestmark = pytest.mark.collectors


def _mod(name: str):
    return importlib.import_module(f"{targets.PACKAGE_NAME}.{name}")


base = _mod("collectors.base")
registry = _mod("registry")
coverage = _mod("coverage")
fsio = _mod("util.fsio")

ACCOUNT = "111122223333"
SCHEMAS = targets.PACKAGE_DIR / "schemas"
COVERAGE_VALIDATOR = jsonschema.Draft202012Validator(json.loads((SCHEMAS / "coverage-1.schema.json").read_text()))
MANIFEST_SCHEMA = json.loads((SCHEMAS / "manifest-2.0.schema.json").read_text())
MANIFEST_VALIDATOR = jsonschema.Draft202012Validator(MANIFEST_SCHEMA)

DEMO_SPEC = registry.CollectorSpec(
    name="demo_s3", scope="global", output_dir="demo_s3", services=("s3",),
    outputs=(("buckets.json", "list"), ("policies/*.json", "dict")), module="tests.demo_s3",
)


# ── the demo world and collector ─────────────────────────────────────────────
def make_world(n_buckets: int = 4, policies=None) -> World:
    w = World("foundation", ACCOUNT, regions=["eu-west-2"])
    created = dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)
    w.static("s3", "ListBuckets", {"Buckets": [{"Name": f"demo-bucket-{i}", "CreationDate": created}
                                               for i in range(n_buckets)],
                                   "Owner": {"ID": "demo-owner"}})
    w.meta["policies"] = dict(policies if policies is not None else {
        "demo-bucket-0": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*",
                                                                   "Action": "s3:GetObject",
                                                                   "Resource": "arn:aws:s3:::demo-bucket-0/*"}]}})

    @w.op("s3", "GetBucketPolicy")
    def _get_policy(req):
        doc = req.world.meta["policies"].get(req.params["Bucket"])
        if doc is None:
            raise req.error("NoSuchBucketPolicy", "The bucket policy does not exist", 404)
        return {"Policy": World.json_doc(doc)}

    return w


def demo_collect(ctx):
    """A new-style collector following docs/contracts/collector-context.md."""
    s3 = ctx.client("s3")
    buckets = []
    with ctx.section("buckets"):
        listed = ctx.paginate(s3, "list_buckets", "Buckets", primary=True, page_size=ctx.option("page_size"))
        for b in listed.value:
            buckets.append({"Name": b["Name"], "Arn": ctx.arn("s3", b["Name"], region="", account=""),
                            "PolicyStatus": None})
        ctx.out.write("buckets.json", buckets)  # written first: a later failure keeps it
    if ctx.option("raw_failure"):
        with ctx.section("unwrapped"):
            s3.get_bucket_tagging(Bucket=buckets[0]["Name"])  # deliberately not wrapped: raises
    with ctx.section("policies"):
        for b in buckets:
            r = ctx.call(s3, "GetBucketPolicy", item=b["Arn"], Bucket=b["Name"])
            b["PolicyStatus"] = r.policy_status()
            if r.collection_error():
                b.setdefault("CollectionErrors", []).append(r.collection_error())
            if r.has_data:
                ctx.out.write(f"policies/{b['Name']}.json", json.loads(r.get("Policy")))
        ctx.out.write("buckets.json", buckets)
    return {"buckets": [b["Name"] for b in buckets]}


def make_ctx(tmp_path, fake, *, spec=DEMO_SPEC, region="global", partition="aws", options=None, stop=False):
    provider = base.SessionAwsProvider(fake.session_factory())
    run = base.RunInfo(run_id="20261015T101500Z-a1b2c3", aws=provider, options=dict(options or {}),
                       run_root=tmp_path)
    if stop:
        run.stop_event.set()
    unit_dir = tmp_path / region
    return base.CollectContext.create(spec, region=region, account_id=ACCOUNT, partition=partition, run=run,
                                      unit_dir=unit_dir)


def coverage_doc(ctx):
    doc = json.loads((ctx.out.root / base.COVERAGE_FILE).read_text())
    COVERAGE_VALIDATOR.validate(doc)
    return doc


def manifest_module_item_validator():
    schema = dict(MANIFEST_SCHEMA["properties"]["modules"]["items"])
    schema["$defs"] = MANIFEST_SCHEMA["$defs"]
    return jsonschema.Draft202012Validator(schema)


def rows(doc, api):
    return [r for r in doc["calls"] if r["api"] == api]


# ── happy path, not configured, stable shapes ────────────────────────────────
def test_happy_path_not_configured_is_ok_and_absent(tmp_path):
    fake = FakeAWS(make_world())
    ctx = make_ctx(tmp_path, fake)
    result = base.run_collector(ctx, collect_fn=demo_collect)

    assert result.status == "ok" and result.control is None
    assert result.value == {"buckets": [f"demo-bucket-{i}" for i in range(4)]}
    buckets = json.loads((ctx.out.root / "buckets.json").read_text())
    assert [b["PolicyStatus"] for b in buckets] == ["present", "absent", "absent", "absent"]
    assert all("CollectionErrors" not in b for b in buckets)
    assert buckets[0]["Arn"] == "arn:aws:s3:::demo-bucket-0"
    assert json.loads((ctx.out.root / "policies" / "demo-bucket-0.json").read_text())["Statement"]
    doc = coverage_doc(ctx)
    assert doc["protocol"] == "ctx" and doc["status"] == "ok"
    nc = [r for r in rows(doc, "s3:GetBucketPolicy") if r["not_configured"]]
    assert nc == [{"api": "s3:GetBucketPolicy", "status": "ok", "count": 3, "items": None, "pages": 0,
                   "error_code": "NoSuchBucketPolicy", "not_configured": True, "primary": False,
                   "optional": False}]
    assert rows(doc, "s3:ListBuckets")[0]["items"] == 4 and rows(doc, "s3:ListBuckets")[0]["primary"] is True
    assert doc["summary"]["not_configured"] == 3
    assert result.dir == "global/demo_s3"
    manifest_module_item_validator().validate(result.manifest_entry())
    fake.assert_clean()


def test_denied_primary_makes_the_module_denied_and_keeps_stable_shapes(tmp_path):
    world = make_world()
    world.deny("s3", "ListBuckets")
    fake = FakeAWS(world)
    ctx = make_ctx(tmp_path, fake)
    result = base.run_collector(ctx, collect_fn=demo_collect)

    assert result.status == "denied"
    assert result.denied_apis == ["s3:ListBuckets"]
    assert json.loads((ctx.out.root / "buckets.json").read_text()) == []  # a list, never {"Error": ...}
    doc = coverage_doc(ctx)
    assert rows(doc, "s3:ListBuckets") == [{"api": "s3:ListBuckets", "status": "denied", "count": 1, "items": 0,
                                            "pages": 0, "error_code": "AccessDenied", "not_configured": False,
                                            "primary": True, "optional": False}]
    assert "primary call denied: s3:ListBuckets" == doc["status_reason"]
    manifest_module_item_validator().validate(result.manifest_entry())


def test_item_denials_make_the_module_partial_with_collection_errors(tmp_path):
    world = make_world()
    world.deny("s3", "GetBucketPolicy", match={"Bucket": "demo-bucket-1"})
    ctx = make_ctx(tmp_path, FakeAWS(world))
    result = base.run_collector(ctx, collect_fn=demo_collect)

    assert result.status == "partial"
    buckets = {b["Name"]: b for b in json.loads((ctx.out.root / "buckets.json").read_text())}
    assert buckets["demo-bucket-1"]["PolicyStatus"] == "denied"
    assert buckets["demo-bucket-1"]["CollectionErrors"] == [
        {"api": "s3:GetBucketPolicy", "status": "denied", "error_code": "AccessDenied"}]
    assert buckets["demo-bucket-2"]["PolicyStatus"] == "absent"  # siblings continue
    doc = coverage_doc(ctx)
    assert doc["item_errors"] == [{"resource": "arn:aws:s3:::demo-bucket-1", "api": "s3:GetBucketPolicy",
                                   "status": "denied", "error_code": "AccessDenied"}]


# ── BotoCoreError inside a section -> partial, data kept ─────────────────────
def test_botocore_error_in_an_unwrapped_call_is_isolated_by_its_section(tmp_path):
    world = make_world()
    world.raise_exc("s3", "GetBucketTagging",
                    botocore_error("EndpointConnectionError", endpoint_url="https://s3.amazonaws.com/"))
    ctx = make_ctx(tmp_path, FakeAWS(world), options={"raw_failure": True})
    result = base.run_collector(ctx, collect_fn=demo_collect)

    assert result.status == "partial"
    doc = coverage_doc(ctx)
    assert [(s["name"], s["status"], s["error_type"]) for s in doc["sections"]] == [
        ("buckets", "ok", None), ("unwrapped", "error", "EndpointConnectionError"), ("policies", "ok", None)]
    # data from before and after the failing section is kept
    buckets = json.loads((ctx.out.root / "buckets.json").read_text())
    assert len(buckets) == 4 and buckets[0]["PolicyStatus"] == "present"


def test_botocore_error_in_a_wrapped_call_is_recorded_not_raised(tmp_path):
    world = make_world()
    world.raise_exc("s3", "GetBucketPolicy", botocore_error("ReadTimeoutError", endpoint_url="https://s3/"),
                    match={"Bucket": "demo-bucket-2"})
    ctx = make_ctx(tmp_path, FakeAWS(world))
    result = base.run_collector(ctx, collect_fn=demo_collect)

    assert result.status == "partial"
    buckets = json.loads((ctx.out.root / "buckets.json").read_text())
    assert buckets[2]["PolicyStatus"] == "error"
    assert buckets[2]["CollectionErrors"][0]["error_code"] == "ReadTimeoutError"
    assert buckets[3]["PolicyStatus"] == "absent"


def test_unhandled_exception_outside_sections_fails_the_module_but_writes_coverage(tmp_path):
    def broken(ctx):
        ctx.out.write("partial.json", [1])
        raise RuntimeError("bug in collector")

    ctx = make_ctx(tmp_path, FakeAWS(make_world()))
    result = base.run_collector(ctx, collect_fn=broken)
    assert result.status == "failed" and result.control is None
    assert result.error == {"type": "RuntimeError", "code": None, "message": "bug in collector"}
    assert json.loads((ctx.out.root / "partial.json").read_text()) == [1]
    assert coverage_doc(ctx)["status"] == "failed"


# ── pagination ───────────────────────────────────────────────────────────────
def test_paginate_uses_the_botocore_paginator(tmp_path):
    world = make_world(n_buckets=5, policies={})
    world.page_sizes[("s3", "ListBuckets")] = 2
    fake = FakeAWS(world)
    ctx = make_ctx(tmp_path, fake)
    result = base.run_collector(ctx, collect_fn=demo_collect)

    assert result.status == "ok"
    assert len(json.loads((ctx.out.root / "buckets.json").read_text())) == 5
    assert len(fake.calls_for(operation="ListBuckets")) == 3
    row = rows(coverage_doc(ctx), "s3:ListBuckets")[0]
    assert (row["pages"], row["items"], row["count"]) == (3, 5, 1)


def test_paginate_page_size_reaches_the_limit_key(tmp_path):
    fake = FakeAWS(make_world(n_buckets=3, policies={}))
    ctx = make_ctx(tmp_path, fake, options={"page_size": 2})
    base.run_collector(ctx, collect_fn=demo_collect)
    first = fake.calls_for(operation="ListBuckets")[0]
    assert first.params.get("MaxBuckets") == 2
    assert len(fake.calls_for(operation="ListBuckets")) == 2


def _waf_world(n_acls: int) -> World:
    w = World("waf", ACCOUNT)
    acls = [{"Name": f"demo-acl-{i}", "Id": f"{i:08d}-0000-0000-0000-000000000000",
             "ARN": f"arn:aws:wafv2:eu-west-2:{ACCOUNT}:regional/webacl/demo-acl-{i}/{i:08d}",
             "LockToken": "demo-lock"} for i in range(n_acls)]
    w.static("wafv2", "ListWebACLs", {"WebACLs": acls})
    w.pagination[("wafv2", "ListWebACLs")] = PaginationSpec("NextMarker", "NextMarker", "WebACLs", limit_key="Limit")
    w.page_sizes[("wafv2", "ListWebACLs")] = 2
    return w


def test_paginate_manual_token_loop_without_a_botocore_paginator(tmp_path):
    fake = FakeAWS(_waf_world(5))
    ctx = make_ctx(tmp_path, fake, region="eu-west-2")
    waf = ctx.client("wafv2")
    assert not waf.can_paginate("list_web_acls")
    r = ctx.paginate(waf, "ListWebACLs", "WebACLs", Scope="REGIONAL")
    assert r.ok and [a["Name"] for a in r.value] == [f"demo-acl-{i}" for i in range(5)]
    assert (r.pages, r.items) == (3, 5)
    calls = fake.calls_for(operation="ListWebACLs")
    assert [c.params.get("NextMarker") for c in calls] == [None, "fakeaws-ListWebACLs-2", "fakeaws-ListWebACLs-4"]
    r2 = ctx.paginate(waf, "list_web_acls", "WebACLs", page_size=50, Scope="REGIONAL")
    assert r2.items == 5 and fake.calls_for(operation="ListWebACLs")[-1].params.get("Limit") == 50


def test_paginate_keeps_items_collected_before_a_failure(tmp_path):
    world = make_world(n_buckets=5, policies={})
    world.page_sizes[("s3", "ListBuckets")] = 2
    world.deny("s3", "ListBuckets", match={"ContinuationToken": "fakeaws-ListBuckets-4"})
    ctx = make_ctx(tmp_path, FakeAWS(world))
    r = ctx.paginate(ctx.client("s3"), "list_buckets", "Buckets", primary=True)
    assert r.status == "denied" and r.pages == 2 and len(r.value) == 4 and r.items == 4
    assert ctx.cov.status == "denied"


def test_paginate_multiple_result_keys(tmp_path):
    w = World("multi", ACCOUNT)
    w.static("iam", "GetAccountAuthorizationDetails", {
        "UserDetailList": [{"UserName": "demo-user", "UserId": "AIDAEXAMPLE000000001",
                            "Arn": f"arn:aws:iam::{ACCOUNT}:user/demo-user", "Path": "/",
                            "CreateDate": dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc)}],
        "RoleDetailList": [], "IsTruncated": False})
    ctx = make_ctx(tmp_path, FakeAWS(w))
    r = ctx.paginate(ctx.client("iam"), "GetAccountAuthorizationDetails", ("UserDetailList", "RoleDetailList"))
    assert r.ok and r.value == {"UserDetailList": r.value["UserDetailList"], "RoleDetailList": []}
    assert r.items == 1


# ── circuit breakers ─────────────────────────────────────────────────────────
def test_deny_breaker_skips_the_remaining_items(tmp_path):
    world = make_world(n_buckets=6, policies={})
    world.deny("s3", "GetBucketPolicy")
    fake = FakeAWS(world)
    ctx = make_ctx(tmp_path, fake)
    result = base.run_collector(ctx, collect_fn=demo_collect)

    assert result.status == "partial"
    assert len(fake.calls_for(operation="GetBucketPolicy")) == 3  # default --deny-breaker 3
    buckets = json.loads((ctx.out.root / "buckets.json").read_text())
    assert [b["PolicyStatus"] for b in buckets] == ["denied"] * 3 + ["skipped"] * 3
    assert buckets[5]["CollectionErrors"] == [
        {"api": "s3:GetBucketPolicy", "status": "skipped", "error_code": "CircuitOpen:AccessDenied"}]
    doc = coverage_doc(ctx)
    assert doc["breakers"] == [{"api": "s3:GetBucketPolicy", "kind": "deny", "reason": "CircuitOpen:AccessDenied",
                                "opened_after": 3, "skipped": 3}]


def test_deny_breaker_zero_disables_it(tmp_path):
    world = make_world(n_buckets=6, policies={})
    world.deny("s3", "GetBucketPolicy")
    fake = FakeAWS(world)
    base.run_collector(make_ctx(tmp_path, fake, options={"deny_breaker": 0}), collect_fn=demo_collect)
    assert len(fake.calls_for(operation="GetBucketPolicy")) == 6


def test_throttle_breaker(tmp_path):
    world = make_world(n_buckets=7, policies={})
    world.throttle("s3", "GetBucketPolicy")
    fake = FakeAWS(world)
    ctx = make_ctx(tmp_path, fake)
    base.run_collector(ctx, collect_fn=demo_collect)
    assert len(fake.calls_for(operation="GetBucketPolicy")) == 5
    doc = coverage_doc(ctx)
    assert doc["breakers"][0]["reason"] == "CircuitOpen:Throttling" and doc["breakers"][0]["skipped"] == 2
    assert doc["summary"]["throttled"] == 5


# ── fatal credentials and interruption ───────────────────────────────────────
def test_expired_token_aborts_the_run(tmp_path):
    world = make_world()
    world.fail("s3", "ListBuckets", "ExpiredToken", "The provided token has expired.", 400)
    ctx = make_ctx(tmp_path, FakeAWS(world))
    result = base.run_collector(ctx, collect_fn=demo_collect)
    assert result.status == "failed"
    assert isinstance(result.control, coverage.RunAborted) and result.control.code == "ExpiredToken"
    with pytest.raises(coverage.RunAborted):
        result.reraise()
    assert coverage_doc(ctx)["error"]["type"] == "RunAborted"


def test_stop_event_interrupts_the_module(tmp_path):
    fake = FakeAWS(make_world())
    ctx = make_ctx(tmp_path, fake, stop=True)
    result = base.run_collector(ctx, collect_fn=demo_collect)
    assert result.status == "interrupted"
    assert isinstance(result.control, coverage.RunInterrupted)
    assert fake.calls_for() == []  # nothing was called after the stop
    doc = coverage_doc(ctx)
    assert doc["sections"] == [{"name": "buckets", "status": "interrupted", "error_type": None,
                                "error_code": None, "message": None}]


def test_planned_specs_are_skipped_without_a_directory(tmp_path):
    spec = registry.CollectorSpec(name="guardduty", scope="regional", output_dir="guardduty",
                                  services=("guardduty",), planned=True,
                                  module=f"{targets.COLLECTORS_PACKAGE}.guardduty")
    ctx = make_ctx(tmp_path, FakeAWS(make_world()), spec=spec, region="eu-west-2")
    result = base.run_collector(ctx)
    assert (result.status, result.dir) == ("skipped", None)
    assert not ctx.out.root.exists()


# ── context helpers ──────────────────────────────────────────────────────────
def test_arn_is_partition_aware(tmp_path):
    fake = FakeAWS(make_world())
    gctx = make_ctx(tmp_path, fake, partition="aws-us-gov")
    assert gctx.client_region == "us-gov-west-1"
    assert gctx.arn("iam", "role/demo-role") == f"arn:aws-us-gov:iam::{ACCOUNT}:role/demo-role"
    rctx = make_ctx(tmp_path, fake, region="cn-north-1", partition="aws-cn")
    assert rctx.arn("lambda", "function:demo-fn") == f"arn:aws-cn:lambda:cn-north-1:{ACCOUNT}:function:demo-fn"
    assert rctx.arn("s3", "demo-bucket", region="", account="") == "arn:aws-cn:s3:::demo-bucket"


def test_call_accepts_both_spellings_and_strips_response_metadata(tmp_path):
    fake = FakeAWS(make_world())
    ctx = make_ctx(tmp_path, fake)
    s3 = ctx.client("s3")
    assert ctx.client("s3") is s3  # cached per (service, region)
    a = ctx.call(s3, "list_buckets")
    b = ctx.call(s3, "ListBuckets")
    assert a.api == b.api == "s3:ListBuckets"
    assert "ResponseMetadata" not in a.value and len(a.value["Buckets"]) == 4
    with pytest.raises(AttributeError):
        ctx.call(s3, "no_such_operation")


def test_spec_not_configured_codes_are_merged(tmp_path):
    w = World("gd", ACCOUNT)
    w.fail("s3", "GetBucketAcl", "NoSuchThing", "absent", 404)
    spec = registry.CollectorSpec(name="demo_nc", scope="global", output_dir="demo_nc", services=("s3",),
                                  not_configured=(("s3:GetBucketAcl", ("NoSuchThing",)),))
    ctx = make_ctx(tmp_path, FakeAWS(w), spec=spec)
    r = ctx.call(ctx.client("s3"), "get_bucket_acl", Bucket="demo")
    assert (r.status, r.not_configured, r.error_code) == ("ok", True, "NoSuchThing")


# ── ModuleOutput ─────────────────────────────────────────────────────────────
def test_module_output_refuses_error_objects_and_wrong_shapes(tmp_path):
    out = base.ModuleOutput(tmp_path / "global" / "demo_s3", DEMO_SPEC)
    with pytest.raises(base.ShapeError):
        out.write("other.json", {"Error": "An error occurred (AccessDenied)"})
    with pytest.raises(base.ShapeError):
        out.write("other.json", [{"Scope": "REGIONAL", "Error": "Error listing WAF WebACLs"}])
    with pytest.raises(base.ShapeError):
        out.write("map.json", {"demo-user": {"Error": "denied"}})
    with pytest.raises(base.ShapeError, match="must be a list"):
        out.write("buckets.json", {"Buckets": []})
    with pytest.raises(base.ShapeError, match="must be an object"):
        out.write("policies/demo.json", [])
    with pytest.raises(base.ShapeError, match="reserved"):
        out.write("_coverage.json", {})
    for bad in ("../escape.json", "/abs.json", "a//b.json", "sp ace.json", "a\\b.json"):
        with pytest.raises(fsio.UnsafePathError):
            out.write(bad, [])
    assert not (tmp_path / "global").exists()  # nothing was written
    out.write("account.json", {"Configured": False, "Error": None, "Status": "ok", "Extra": 1})  # not a stub


def test_module_output_permissions_and_atomicity(tmp_path):
    old = os.umask(0o022)
    try:
        out = base.ModuleOutput(tmp_path / "run" / "eu-west-2" / "demo", None)
        p = out.write("nested/dir/file.json", {"When": dt.datetime(2026, 10, 15, 10, 15, 2, tzinfo=dt.timezone.utc)})
    finally:
        os.umask(old)
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    for d in (tmp_path / "run", tmp_path / "run" / "eu-west-2", out.root, out.root / "nested", p.parent):
        assert stat.S_IMODE(d.stat().st_mode) == 0o700, d
    assert json.loads(p.read_text()) == {"When": "2026-10-15T10:15:02Z"}  # UTC 'Z' (F-171 helper)
    assert [n for n in os.listdir(p.parent) if ".tmp-" in n] == []
    with pytest.raises(TypeError):
        out.write("blob.json", {"Content": b"\x00binary"})
    assert not (out.root / "blob.json").exists()


def test_write_item_uses_collision_free_names(tmp_path):
    out = base.ModuleOutput(tmp_path / "secretsmanager", None)
    a = out.write_item("resource_policies", "arn:aws:secretsmanager:eu-west-2:111122223333:secret:prod/db-AbC",
                       {"k": 1}, hint="prod/db")
    b = out.write_item("resource_policies", "arn:aws:secretsmanager:eu-west-2:111122223333:secret:prod_db-XyZ",
                       {"k": 2}, hint="prod_db")
    assert a != b and a.startswith("resource_policies/prod_db-") and b.startswith("resource_policies/prod_db-")
    long = out.write_item("resource_policies", "k" * 300, {}, hint="n" * 300)
    assert len(long.split("/")[1]) <= 48 + 1 + 12 + 5
    assert sorted(out.files) == sorted([a, b, long])


# ── one protocol: collect(ctx) ───────────────────────────────────────────────
@pytest.mark.finding("F-084", "F-166")
def test_an_old_style_collect_fails_with_a_type_error_and_calls_nothing(tmp_path):
    """The d13c215 ``collect(session, path)`` signature is refused (no adapter is left): ``failed``, no call."""
    seen = []

    def old_style(session, path):
        seen.append(path)

    fake = FakeAWS(make_world())
    ctx = make_ctx(tmp_path, fake, spec=registry.get_registry().get("sqs"), region="eu-west-2")
    result = base.run_collector(ctx, collect_fn=old_style)
    assert result.status == "failed" and result.control is None
    assert result.error["type"] == "TypeError" and "ctx" in result.error["message"]
    doc = coverage_doc(ctx)
    assert doc["protocol"] == "ctx" and doc["calls"] == []
    assert seen == [] and fake.calls_for() == []
    assert not hasattr(base, "_run_legacy") and not hasattr(base, "_StdoutRouter")


def test_is_ctx_protocol():
    assert base.is_ctx_protocol(demo_collect)
    assert base.is_ctx_protocol(lambda ctx, extra=None: None)
    assert not base.is_ctx_protocol(lambda session, path: None)
    assert not base.is_ctx_protocol(lambda session, path, scope="BOTH": None)
    assert not base.is_ctx_protocol(lambda context: None)
    import inspect
    for name in targets.collector_names():  # every shipped collector takes exactly (ctx)
        entry = targets.collector_entry(name)
        assert base.is_ctx_protocol(entry), name
        assert list(inspect.signature(entry).parameters) == ["ctx"], name


# ── manifest example (docs/contracts/manifest.md) validates ──────────────────
def test_manifest_example_validates(tmp_path):
    ctx = make_ctx(tmp_path, FakeAWS(make_world()))
    entry = base.run_collector(ctx, collect_fn=demo_collect).manifest_entry()
    entry.update(name="s3", dir="global/s3")
    skipped = base.ModuleResult.skipped(registry.get_registry().get("k8s"), "eu-west-2",
                                        "disabled by --no-k8s").manifest_entry()
    manifest = {
        "schema_version": "2.0",
        "tool": {"name": "aws-enumerator", "version": "0.3.0", "git_sha": None, "python": "3.10.11",
                 "boto3": "1.37.34", "botocore": "1.37.34", "kubernetes": "33.1.0"},
        "run": {"run_id": "20261015T101500Z-a1b2c3", "kind": "collect", "status": "complete",
                "started_at": "2026-10-15T10:15:00Z", "ended_at": "2026-10-15T10:17:31Z", "duration_seconds": 151.2,
                "exit_code": 0, "argv": ["collect", "--regions", "eu-west-2", "--no-k8s"],
                "options": {"regions_requested": ["eu-west-2"], "modules": ["iam", "s3"],
                            "skipped_modules": [{"name": "k8s", "reason": "disabled by --no-k8s"}],
                            "k8s": False, "k8s_secrets": False, "concurrency": 3,
                            "rate_limit": {"enabled": True, "default_rps": 5, "max_rps": None, "overrides": {}},
                            "iam_mode": "gaad", "max_tier": 2, "deny_breaker": 3, "redact_identity": True,
                            "zip": False},
                "resumes": [], "global_source": None},
        "target": {"account_id": ACCOUNT, "partition": "aws", "home_region": "eu-west-2",
                   "global_region": "us-east-1", "regions": ["eu-west-2"], "region_source": "explicit",
                   "regions_skipped": []},
        "operator": {"caller_arn": None, "caller_user_id": None, "caller_arn_sha256": "0" * 64,
                     "principal_arn": f"arn:aws:iam::{ACCOUNT}:role/demo-operator",
                     "principal_type": "assumed-role", "redacted": True},
        "classification": "CONFIDENTIAL: pre-computed attack map of the target account; see HANDLING.txt",
        "preflight": None,
        "modules": [entry, skipped],
        "analysis": {"status": "ok", "engine": "v2", "started_at": "2026-10-15T10:17:20Z",
                     "duration_seconds": 11.0, "error": None, "dir": "analysis", "graph_schema_version": "1.0.0"},
        "coverage_summary": {"modules_by_status": {"ok": 1, "skipped": 1}, "denied_apis": [], "partial_modules": [],
                             "failed_modules": [], "throttled_calls": 0, "item_errors": 0},
        "files": [{"path": "global/s3/buckets.json", "sha256": "a" * 64, "bytes": 1234}],
    }
    MANIFEST_VALIDATOR.validate(manifest)
    bad = json.loads(json.dumps(manifest))
    bad["operator"]["caller_arn"] = f"arn:aws:sts::{ACCOUNT}:assumed-role/demo-operator/s"
    with pytest.raises(jsonschema.ValidationError):
        MANIFEST_VALIDATOR.validate(bad)  # redacted manifests must not carry the caller ARN
