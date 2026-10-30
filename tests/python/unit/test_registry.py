"""Unit tests for the collector registry (docs/contracts/registry.md).

Production code is reached through ``tests.support.targets`` (package name, collector modules).
"""

from __future__ import annotations

import dataclasses
import importlib
import textwrap

import pytest

from tests.support import targets


def _mod(name: str):
    return importlib.import_module(f"{targets.PACKAGE_NAME}.{name}")


reg_mod = _mod("registry")


@pytest.fixture(scope="module")
def reg():
    return reg_mod.reload_registry()


# ── every existing collector declares its own SPEC ───────────────────────────
@pytest.mark.parametrize("module_name", targets.collector_names())
def test_each_existing_collector_declares_a_spec(module_name):
    mod = targets.collector_module(module_name)
    spec = getattr(mod, "SPEC", None)
    assert isinstance(spec, reg_mod.CollectorSpec), module_name
    # the spec keeps today's report layout (directory name per module)
    assert spec.output_dir == targets.collector_output_dir(module_name)
    assert spec.default is True and not spec.planned
    assert all(":" in a for a in spec.actions + spec.optional_actions)  # filled by each collector stream
    assert callable(getattr(mod, targets.COLLECTOR_ENTRY))


@pytest.mark.finding("F-084", "F-166")
def test_no_legacy_adapter_fields_and_no_planned_entries_are_left(reg):
    """0.3.0 removed the d13c215 adapter: no spec carries legacy_args/legacy_kwargs, PLANNED is empty."""
    fields = {f.name for f in dataclasses.fields(reg_mod.CollectorSpec)}
    assert not {"legacy_args", "legacy_kwargs"} & fields
    assert not hasattr(reg_mod.CollectorSpec, "legacy_kwargs_map")
    assert reg_mod.PLANNED == {}
    assert [s.name for s in reg if s.planned] == []


def test_registry_has_36_entries_in_order(reg):
    assert len(reg) == 36
    assert reg.names() == list(reg_mod.ORDER)
    assert len(reg.implemented()) == 36
    for spec in reg:
        assert spec.module.startswith(f"{targets.COLLECTORS_PACKAGE}."), spec


def test_scopes_follow_the_design(reg):
    globals_ = [s.name for s in reg if s.scope == "global"]
    assert globals_ == ["iam", "organizations", "s3", "cloudfront", "waf_cloudfront", "route53"]
    assert reg.get("k8s").scope == "k8s" and reg.get("k8s").depends_on == ("eks",)
    assert reg.names().index("eks") < reg.names().index("k8s")
    assert all(s.scope == "regional" for s in reg if s.name in ("guardduty", "securityhub", "config",
                                                                   "accessanalyzer", "waf", "ebs"))


def test_waf_scopes_have_their_own_modules(reg):
    waf, wafcf = reg.get("waf"), reg.get("waf_cloudfront")
    assert (waf.scope, waf.output_dir) == ("regional", "waf")
    assert (wafcf.scope, wafcf.output_dir, wafcf.primary_service) == ("global", "waf_cloudfront", "cloudfront")
    assert not wafcf.planned
    assert wafcf.module == f"{targets.COLLECTORS_PACKAGE}.waf_cloudfront"


def test_lambda_module_alias_and_tiers(reg):
    assert reg.get("lambda").module == targets.collector_module("lambda_").__name__
    assert reg.get("lambda_") is reg.get("lambda")
    assert {s.name for s in reg if s.tier == 2} == {"lambda", "ecs", "cloudformation", "glue", "codebuild"}


def test_new_collectors_have_the_announced_identity(reg):
    expected = {"organizations": ("organizations", "global"), "guardduty": ("guardduty", "regional"),
                "securityhub": ("securityhub", "regional"), "config": ("config_service", "regional"),
                "accessanalyzer": ("accessanalyzer", "regional")}
    for name, (module, scope) in expected.items():
        spec = reg.get(name)  # the identity announced in registry.md §4 when they were planned
        assert spec.module == f"{targets.COLLECTORS_PACKAGE}.{module}"
        assert (spec.scope, spec.output_dir) == (scope, name)
        assert "@posture" in spec.groups


def test_groups(reg):
    for group in reg_mod.GROUPS:
        assert reg.group(group), group
    assert {s.name for s in reg.group("@k8s")} == {"eks", "k8s"}
    assert {s.name for s in reg.group("@messaging")} == {"sns", "sqs"}
    assert "lambda" not in {s.name for s in reg.group("@tier1")}
    assert {s.name for s in reg.group("@tier2")} == {"lambda", "ecs", "cloudformation", "glue", "codebuild"}
    with pytest.raises(KeyError):
        reg.group("@nope")


# ── select ───────────────────────────────────────────────────────────────────
def test_default_selection_runs_every_implemented_module_with_k8s_on(reg):
    sel = reg_mod.select(registry=reg)
    assert sel.names() == [s.name for s in reg.implemented()]
    assert "k8s" in sel.names()  # owner decision: K8s on by default
    assert sel.skipped == ()
    assert [s.name for s in sel.global_specs] == [s.name for s in reg.implemented() if s.scope == "global"]
    assert {"iam", "s3", "cloudfront", "waf_cloudfront", "route53"} <= set(sel.names())


def test_no_k8s_skips_with_reason_and_conflicts_are_rejected(reg):
    sel = reg_mod.select(k8s=False, registry=reg)
    assert "k8s" not in sel.names() and ("k8s", "disabled by --no-k8s") in sel.skipped
    assert "eks" in sel.names()
    with pytest.raises(reg_mod.SelectionError, match="--no-k8s"):
        reg_mod.select("k8s", k8s=False, registry=reg)
    assert reg_mod.select("@all", k8s=False, registry=reg).skipped == (("k8s", "disabled by --no-k8s"),)


def test_dependencies_are_added_and_reported(reg):
    sel = reg_mod.select("k8s", registry=reg)
    assert sel.names() == ["eks", "k8s"]
    assert sel.added_dependencies == ("eks",)
    assert sel.warnings and "eks" in sel.warnings[0]


def test_skipping_a_dependency_skips_its_dependents(reg):
    sel = reg_mod.select(skip="eks", registry=reg)
    skipped = dict(sel.skipped)
    assert skipped["eks"] == "skipped by --skip"
    assert skipped["k8s"].startswith("dependency 'eks' not selected")
    assert "k8s" not in sel.names()


def test_comma_strings_aliases_groups_and_registry_order(reg):
    sel = reg_mod.select(["sqs,lambda_", "@identity", "iam"], registry=reg)
    assert sel.names() == ["iam", "organizations", "lambda", "sqs", "cognito"]
    assert sel.skipped == ()
    assert reg_mod.select("IAM,S3", registry=reg).names() == ["iam", "s3"]


def test_explicitly_requested_planned_module_is_skipped_not_an_error():
    planned = reg_mod.CollectorSpec(name="guardduty", scope="regional", output_dir="guardduty",
                                    services=("guardduty",), groups=("@posture",), planned=True,
                                    module=f"{targets.COLLECTORS_PACKAGE}.guardduty")
    reg = reg_mod.Registry((planned,))
    sel = reg_mod.select("guardduty", registry=reg)
    assert sel.specs == () and sel.skipped == (("guardduty", "not implemented in this version"),)
    assert reg_mod.select(registry=reg).skipped == ()  # never selected by default, silently


@pytest.mark.parametrize("modules,skip,match", [
    ("lamda", None, "did you mean 'lambda'"),
    ("@dat", None, "did you mean '@data'"),
    (None, "sqss", "--skip: unknown module 'sqss'; did you mean 'sqs'"),
    ("nothing_like_it", None, "unknown module 'nothing_like_it'"),
])
def test_unknown_names_are_rejected_with_a_suggestion(reg, modules, skip, match):
    with pytest.raises(reg_mod.SelectionError, match=match):
        reg_mod.select(modules, skip, registry=reg)


def test_max_tier_and_bad_arguments(reg):
    sel = reg_mod.select(max_tier=1, registry=reg)
    assert {n for n, _ in sel.skipped} == {"lambda", "ecs", "cloudformation", "glue", "codebuild"}
    assert all("--max-tier 1" in reason for _, reason in sel.skipped)
    with pytest.raises(reg_mod.SelectionError):
        reg_mod.select(max_tier=3, registry=reg)
    with pytest.raises(reg_mod.SelectionError, match="partition"):
        reg_mod.select(partition="aws-mars", registry=reg)


def test_partition_availability_is_checked_offline(reg):
    gov = reg_mod.select(partition="aws-us-gov", registry=reg)
    skipped = dict(gov.skipped)
    assert skipped["cloudfront"] == "unavailable in partition aws-us-gov"
    assert skipped["waf_cloudfront"] == "unavailable in partition aws-us-gov"
    assert "iam" in gov.names() and "route53" in gov.names()
    assert reg_mod.select(partition=None, registry=reg).skipped == ()


def test_skip_global(reg):
    sel = reg_mod.select(skip_global=True, registry=reg)
    assert sel.global_specs == []
    assert {n for n, _ in sel.skipped} == {s.name for s in reg.implemented() if s.scope == "global"}


def test_explicit_skip_wins_over_explicit_request(reg):
    sel = reg_mod.select("iam,s3", "s3", registry=reg)
    assert sel.names() == ["iam"] and sel.skipped == (("s3", "skipped by --skip"),)


def test_global_region_per_partition():
    assert reg_mod.global_region_for("aws") == "us-east-1"
    assert reg_mod.global_region_for("aws-us-gov") == "us-gov-west-1"
    assert reg_mod.global_region_for("aws-cn") == "cn-north-1"
    with pytest.raises(ValueError):
        reg_mod.global_region_for("nope")


# ── CollectorSpec validation ─────────────────────────────────────────────────
def _spec(**kw):
    base = dict(name="demo", scope="regional", output_dir="demo", services=("ec2",))
    base.update(kw)
    return reg_mod.CollectorSpec(**base)


@pytest.mark.parametrize("kw,match", [
    ({"name": "Bad-Name"}, "name"),
    ({"scope": "planet"}, "scope"),
    ({"output_dir": "../x"}, "output_dir"),
    ({"services": ()}, "services"),
    ({"services": "ec2"}, "services"),
    ({"tier": 3}, "tier"),
    ({"cost": "free"}, "cost"),
    ({"groups": ("@nope",)}, "unknown group"),
    ({"actions": ("DescribeInstances",)}, "service:Action"),
    ({"actions": ["ec2:DescribeInstances"]}, "tuple"),
])
def test_spec_validation(kw, match):
    with pytest.raises(reg_mod.RegistryError, match=match):
        _spec(**kw)


def test_spec_is_frozen_and_hashable():
    s = _spec(probe=("ec2", "DescribeInstances", (("MaxResults", 5),)))
    assert hash(s) == hash(_spec(probe=("ec2", "DescribeInstances", (("MaxResults", 5),))))
    assert s.probe_params() == {"MaxResults": 5}
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.name = "other"  # type: ignore[misc]
    assert s.to_json()["services"] == ["ec2"]


# ── building from a package (discovery, planned replacement, errors) ─────────
def _make_pkg(tmp_path, monkeypatch, name, modules):
    pkg = tmp_path / name
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    for mod, body in modules.items():
        (pkg / f"{mod}.py").write_text(textwrap.dedent(body))
    monkeypatch.syspath_prepend(str(tmp_path))
    return name


SPEC_IMPORT = f"from {targets.PACKAGE_NAME}.registry import CollectorSpec\n"


def test_a_new_module_replaces_its_planned_entry(tmp_path, monkeypatch):
    pkg = _make_pkg(tmp_path, monkeypatch, "aefake_pkg_ok", {
        "iam": SPEC_IMPORT + "SPEC = CollectorSpec(name='iam', scope='global', output_dir='iam', services=('iam',))\n"
                             "def collect(ctx):\n    return None\n",
        "guardduty": SPEC_IMPORT + "SPEC = CollectorSpec(name='guardduty', scope='regional', output_dir='guardduty',"
                                   " services=('guardduty',), groups=('@posture',))\n",
        "zeta": SPEC_IMPORT + "SPEC = CollectorSpec(name='zeta', scope='regional', output_dir='zeta',"
                              " services=('ec2',))\n",
    })
    planned = {"guardduty": reg_mod.CollectorSpec(name="guardduty", scope="regional", output_dir="guardduty",
                                                  services=("guardduty",), planned=True),
               "config": reg_mod.CollectorSpec(name="config", scope="regional", output_dir="config",
                                               services=("config",), planned=True)}
    reg = reg_mod.build_registry(pkg, planned=planned)
    assert reg.names() == ["iam", "guardduty", "config", "zeta"]  # ORDER first, unknown names appended
    assert not reg.get("guardduty").planned and reg.get("guardduty").module == f"{pkg}.guardduty"
    assert reg.get("config").planned


@pytest.mark.parametrize("modules,match", [
    ({"a": SPEC_IMPORT + "SPEC = CollectorSpec(name='dup', scope='regional', output_dir='a', services=('ec2',))\n",
      "b": SPEC_IMPORT + "SPEC = CollectorSpec(name='dup', scope='regional', output_dir='b', services=('ec2',))\n"},
     "duplicate collector name"),
    ({"a": SPEC_IMPORT + "SPEC = CollectorSpec(name='a', scope='regional', output_dir='same', services=('ec2',))\n",
      "b": SPEC_IMPORT + "SPEC = CollectorSpec(name='b', scope='regional', output_dir='same', services=('ec2',))\n"},
     "output_dir 'same'"),
    ({"a": "def collect(ctx):\n    pass\n"}, "has no module-level SPEC"),
    ({"a": "SPEC = {'name': 'a'}\n"}, "expected CollectorSpec"),
    ({"a": "raise ImportError('kaboom')\n"}, "cannot import collector module"),
    ({"a": SPEC_IMPORT + "SPEC = CollectorSpec(name='a', scope='k8s', output_dir='a', services=('eks',),"
                         " depends_on=('ghost',))\n"}, "unknown collector 'ghost'"),
])
def test_registry_errors(tmp_path, monkeypatch, modules, match):
    pkg = _make_pkg(tmp_path, monkeypatch, f"aefake_pkg_{abs(hash(match)) % 10_000}", modules)
    with pytest.raises(reg_mod.RegistryError, match=match):
        reg_mod.build_registry(pkg, planned={})


def test_base_module_is_not_a_collector(reg):
    assert "base" not in reg.names()


def test_private_helper_modules_are_not_collectors(reg, tmp_path, monkeypatch):
    """``collectors/_common.py`` (D-47) is skipped by name: a ``_`` module never needs a SPEC."""
    assert "_common" not in reg.names() and "common" not in reg.names()
    pkg = _make_pkg(tmp_path, monkeypatch, "aefake_pkg_private", {
        "_helpers": "def add_error(item, result):\n    pass\n",
        "zeta": SPEC_IMPORT + "SPEC = CollectorSpec(name='zeta', scope='regional', output_dir='zeta',"
                              " services=('ec2',))\n",
    })
    assert reg_mod.build_registry(pkg, planned={}).names() == ["zeta"]
