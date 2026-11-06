"""Every collector option reaches ``RunInfo.options`` under its exact name, with parse-time validation
(cli.md §3.1; requests ``c-b-3`` and the option lists of the C-A / C-K8s handoffs).

The option names are the ``collect`` flag names with ``-`` → ``_``. A drift test scans the collectors and
``k8s/options.py`` for the names they read, so a new collector option without a CLI flag fails here.
"""

from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

from tests.python.orchestration import r_harness as R
from tests.support import targets

W2 = "eu-west-2"

#: The values a default ``collect`` passes (cli.md §3.1 defaults). Path options are absent when not given.
DEFAULTS = {
    "iam_mode": "gaad", "credential_report": True, "iam_user_details": True, "s3_subresources": "basic",
    "ecs_max_revisions": 5, "ebs_share_check": "cap:1000", "lambda_versions": False, "ec2_userdata_check": False,
    "full_dns": False, "keep_sensitive_metadata": False, "k8s": True, "k8s_secrets": False, "k8s_auth": "eks-token",
    "k8s_timeout": "5,60", "k8s_self_review": True, "deny_breaker": 3, "max_tier": 2,
}
PATH_KEYS = ("iam_gaad_file", "scp_file", "kubeconfig", "k8s_token_file", "k8s_ca_file")
#: Names collectors may read that are alternative spellings or internal settings, not flags of their own.
NOT_FLAGS = {"no_k8s", "no_k8s_secrets", "no_k8s_self_review", "no_credential_report", "no_iam_user_details",
             "no_rate_limit", "no_ua_tag", "throttle_breaker", "rate_limit_enabled",
             "ua_tag", "token"}


def _capture(monkeypatch):
    seen = {}
    owner, attr = targets.collector_patch_point("vpc")
    real = getattr(owner, attr)

    def collect(ctx):
        seen.update(dict(ctx.run.options))
        return real(ctx)

    monkeypatch.setattr(owner, attr, collect)
    R.fake_engine(monkeypatch)
    return seen


@pytest.mark.finding("F-062", "F-104", "F-112", "F-126")
def test_default_options_carry_the_documented_defaults(tmp_path, monkeypatch):
    seen = _capture(monkeypatch)
    run = R.collect(["collect", "--region", W2, "--modules", "vpc"], tmp_path, monkeypatch)
    assert run.exit_code == 0, run.err[-1500:]
    assert {k: seen.get(k) for k in DEFAULTS} == DEFAULTS
    assert not any(k in seen for k in PATH_KEYS) and "k8s_clusters" not in seen


@pytest.mark.finding("F-062", "F-104", "F-112", "F-126")
def test_every_tuning_flag_reaches_run_options_under_its_exact_name(tmp_path, monkeypatch):
    files = {}
    for key in PATH_KEYS:
        files[key] = tmp_path / f"demo-{key}.txt"
        files[key].write_text("{}", encoding="utf-8")
    seen = _capture(monkeypatch)
    argv = ["collect", "--region", W2, "--modules", "vpc",
            "--iam-mode", "per-entity", "--iam-gaad-file", str(files["iam_gaad_file"]), "--no-credential-report",
            "--no-iam-user-details", "--s3-subresources", "full", "--ecs-max-revisions", "2",
            "--ebs-share-check", "CAP:10", "--lambda-versions", "--ec2-userdata-check", "--full-dns",
            "--keep-sensitive-metadata", "--scp-file", str(files["scp_file"]), "--k8s-secrets",
            "--k8s-auth", "kubeconfig", "--kubeconfig", str(files["kubeconfig"]), "--kube-context", "demo-context",
            "--k8s-token-file", str(files["k8s_token_file"]), "--k8s-ca-file", str(files["k8s_ca_file"]),
            "--k8s-clusters", "demo-b,demo-a", "--k8s-timeout", "3,30", "--no-k8s-self-review"]
    run = R.collect(argv, tmp_path, monkeypatch)
    assert run.exit_code == 0, run.err[-1500:]
    expected = {
        "iam_mode": "per-entity", "iam_gaad_file": str(files["iam_gaad_file"]), "credential_report": False,
        "iam_user_details": False, "s3_subresources": "full", "ecs_max_revisions": 2, "ebs_share_check": "cap:10",
        "lambda_versions": True, "ec2_userdata_check": True, "full_dns": True, "keep_sensitive_metadata": True,
        "scp_file": str(files["scp_file"]), "k8s": True, "k8s_secrets": True, "k8s_auth": "kubeconfig",
        "kubeconfig": str(files["kubeconfig"]), "kube_context": "demo-context",
        "k8s_token_file": str(files["k8s_token_file"]), "k8s_ca_file": str(files["k8s_ca_file"]),
        "k8s_clusters": "demo-b,demo-a", "k8s_timeout": "3,30", "k8s_self_review": False,
    }
    assert {k: seen.get(k) for k in expected} == expected
    # …and the collectors' own readers understand them.
    k8s = targets.k8s_module("options").K8sOptions.from_mapping(seen, run_id="20261016T000000Z-a1b2c3")
    assert (k8s.enabled, k8s.secrets, k8s.auth_mode, k8s.kube_context, k8s.clusters, k8s.timeout, k8s.self_review) \
        == (True, True, "kubeconfig", "demo-context", ("demo-a", "demo-b"), (3.0, 30.0), False)
    assert targets.collector_module("ebs").share_check_budget(seen["ebs_share_check"]) == 10
    ctx = SimpleNamespace(option=lambda name, default=None: seen.get(name, default))
    iam = targets.collector_module("iam")
    assert iam._option_on(ctx, "credential_report") is False and iam._option_on(ctx, "iam_user_details") is False
    # Local paths never reach the manifest (manifest.md §3.2).
    options = run.manifest()["run"]["options"]
    assert not any(k in options for k in PATH_KEYS)
    assert all(str(tmp_path) not in str(v) for v in options.values())


@pytest.mark.parametrize("argv", [
    ["collect", "--ecs-max-revisions", "-1"],
    ["collect", "--ecs-max-revisions", "five"],
    ["collect", "--ebs-share-check", "cap:"],
    ["collect", "--ebs-share-check", "cap:-1"],
    ["collect", "--ebs-share-check", "cap:10x"],
    ["collect", "--iam-mode", "gaad2"],
    ["collect", "--s3-subresources", "all"],
    ["collect", "--k8s-auth", "password"],
    ["collect", "--k8s-timeout", "0"],
    ["collect", "--k8s-timeout", "a,b"],
    ["collect", "--k8s-timeout", "1,2,3"],
    ["collect", "--iam-user-details=yes"],
    ["collect", "--no-k8s", "--k8s"],
])
def test_bad_collector_option_values_are_usage_errors_at_parse_time(monkeypatch, argv):
    code, out, err = R.invoke(argv, monkeypatch)
    assert code == 64, (argv, out, err)
    assert out == ""


def _names_read_by_collectors():
    """Option names in ``ctx.option("…")`` calls of every collector and in ``k8s/options.py``."""
    names = set()
    collectors = targets.package_dir() / "collectors"
    for path in sorted(collectors.glob("*.py")):
        if path.name in ("base.py", "__init__.py"):
            continue
        names.update(re.findall(r"""\.option\(\s*["']([a-z0-9_]+)["']""", path.read_text(encoding="utf-8")))
    k8s = (targets.package_dir() / "k8s" / "options.py").read_text(encoding="utf-8")
    names.update(re.findall(r"""options(?:\.get\(|\[)\s*["']([a-z0-9_]+)["']""", k8s))
    pairs = re.findall(r"""_(?:flag|optional_str)\(options,\s*["']([a-z0-9_]+)["'](?:,\s*["']([a-z0-9_]+)["'])?""", k8s)
    names.update(n for pair in pairs for n in pair if n)
    return names


def test_every_option_a_collector_reads_is_a_collect_flag():
    """Drift guard: a collector option without a ``collect`` flag would silently keep its default."""
    names = _names_read_by_collectors()
    assert {"ecs_max_revisions", "ebs_share_check", "scp_file", "k8s_timeout", "kubeconfig"} <= names
    parser = targets.main_module().build_parser()
    sub = next(a for a in parser._actions if getattr(a, "choices", None) and "collect" in a.choices)
    flags = {opt.lstrip("-").replace("-", "_") for action in sub.choices["collect"]._actions
             for opt in action.option_strings}
    runner_set = {"k8s", "k8s_secrets", "max_rps", "rate_limit", "deny_breaker", "max_tier", "ua_app_id"}
    missing = sorted(n for n in names - NOT_FLAGS - runner_set if n not in flags and f"no_{n}" not in flags)
    assert missing == [], f"collector options without a collect flag: {missing}"
    # credential_report / iam_user_details / k8s_self_review are the positive names of --no-… flags.
    assert {"no_credential_report", "iam_user_details", "no_k8s_self_review"} <= flags
