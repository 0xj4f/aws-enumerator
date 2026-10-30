"""Drift tests for docs/detection.md (F-167, F-170, F-046).

The per-module CloudTrail footprint table and the operation/action table of docs/detection.md are generated from
the collector registry (``SPEC.actions``, ``SPEC.optional_actions``, the preflight probe, ``SPEC.noise``) and from
``iam_actions``. The functions below are the generator: when a collector's declared actions change, this test fails
and prints the block to paste between the markers. The user-agent and Kubernetes statements are checked against
the code that sets them.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from aws_enumerator import iam_actions, permissions
from aws_enumerator._version import __version__
from aws_enumerator.registry import get_registry

ROOT = Path(__file__).resolve().parents[3]
DOC = ROOT / "docs" / "detection.md"

MODULES_BEGIN = "<!-- BEGIN GENERATED:detection-modules (tests/python/docs/test_security_docs_detection.py) -->"
MODULES_END = "<!-- END GENERATED:detection-modules -->"
OPS_BEGIN = "<!-- BEGIN GENERATED:detection-operations (tests/python/docs/test_security_docs_detection.py) -->"
OPS_END = "<!-- END GENERATED:detection-operations -->"


def _text() -> str:
    return DOC.read_text(encoding="utf-8")


def _block(text: str, begin: str, end: str) -> str:
    assert begin in text and end in text, f"markers missing in {DOC.name}: {begin!r} / {end!r}"
    return text.split(begin, 1)[1].split(end, 1)[0].strip("\n")


def _group(actions: Tuple[str, ...]) -> str:
    """``iam:A, iam:B, s3:C`` -> ```iam`: A, B; `s3`: C``, prefixes in first-seen order."""
    by_prefix: Dict[str, List[str]] = {}
    for action in actions:
        prefix, name = action.split(":", 1)
        by_prefix.setdefault(prefix, []).append(name)
    return "; ".join(f"`{p}`: " + ", ".join(names) for p, names in by_prefix.items())


def _sources(actions: Tuple[str, ...]) -> str:
    prefixes = sorted({a.split(":", 1)[0] for a in actions})
    return ", ".join(f"`{p}.amazonaws.com`" for p in prefixes)


def render_modules_table() -> str:
    """The per-module table of docs/detection.md, in registry (= execution) order."""
    rows = [
        "| Module | Scope | Event sources | Declared actions | Optional actions | Preflight probe | Noise |",
        "|---|---|---|---|---|---|---|",
    ]
    for spec in get_registry():
        if spec.scope == "k8s":
            sources, actions = "Kubernetes audit log (no AWS call)", "see [Kubernetes](#kubernetes-audit-pattern)"
        else:
            sources, actions = _sources(tuple(spec.actions) + tuple(spec.optional_actions)), _group(spec.actions)
        optional = _group(spec.optional_actions) if spec.optional_actions else "—"
        probe = permissions.probe_for(spec)
        probe_text = f"`{probe[0]}` {probe[1]}" if probe else "—"
        rows.append(f"| `{spec.name}` | {spec.scope} | {sources} | {actions} | {optional} | {probe_text} | "
                    f"{spec.noise} |")
    return "\n".join(rows)


def render_operations_table() -> str:
    """API operations whose IAM action has another name, limited to actions some collector declares."""
    declared = {a for s in get_registry() for a in tuple(s.actions) + tuple(s.optional_actions)}
    rows = ["| API call (botocore service, operation) | IAM action in the table above |", "|---|---|"]
    for api, action in sorted(iam_actions._ACTION_OVERRIDES.items()):  # noqa: SLF001 - the one mapping table
        service, operation = api.split(":", 1)
        if action in declared and operation != action.split(":", 1)[1]:
            rows.append(f"| `{service}` {operation} | `{action}` |")
    return "\n".join(rows)


@pytest.mark.finding("F-167", "F-170")
def test_module_footprint_table_matches_the_registry():
    expected = render_modules_table()
    actual = _block(_text(), MODULES_BEGIN, MODULES_END)
    assert actual == expected, "docs/detection.md module table is stale; paste:\n" + expected


@pytest.mark.finding("F-167")
def test_operation_name_table_matches_iam_actions():
    expected = render_operations_table()
    actual = _block(_text(), OPS_BEGIN, OPS_END)
    assert actual == expected, "docs/detection.md operation table is stale; paste:\n" + expected


@pytest.mark.finding("F-167")
def test_every_registered_module_is_documented():
    text = _text()
    for spec in get_registry():
        assert f"| `{spec.name}` |" in text, spec.name


@pytest.mark.finding("F-170")
def test_user_agent_statements_match_the_code():
    from aws_enumerator import aws_session
    from aws_enumerator.k8s import options as k8s_options

    text = _text()
    run_id = "20261015T101500Z-a1b2c3"
    app_id = aws_session.default_ua_app_id(run_id)
    assert app_id == f"aws-enumerator/{__version__}/a1b2c3"
    # botocore renders the app id as app/<id> with '/' replaced by '-'
    assert "app/aws-enumerator-<version>-<run id tail>" in text
    assert "app/aws-enumerator-0.3.0-a1b2c3" in text and __version__ == "0.3.0"
    assert "aws-enumerator/<version>/<run id tail>" in text
    assert k8s_options._user_agent({}, run_id) == app_id  # noqa: SLF001 - the Kubernetes User-Agent
    assert k8s_options._user_agent({"no_ua_tag": True}, run_id) is None  # noqa: SLF001
    for flag in ("--ua-app-id", "--no-ua-tag", "AWS_SDK_UA_APP_ID"):
        assert flag in text, flag


@pytest.mark.finding("F-167", "F-170")
def test_kubernetes_audit_section_matches_the_declared_rbac():
    spec = get_registry().get("k8s")
    section = _text().split("## Kubernetes audit pattern", 1)[1].split("\n## ", 1)[0]
    for _group_name, resource, verbs, _names in spec.k8s_rbac:
        assert f"`{resource}`" in section, resource
        for verb in verbs:
            assert verb in section, (resource, verb)
    for fact in ("limit=500", "PartialObjectMetadataList", "--k8s-secrets", "--no-k8s-self-review", "/version",
                 "aws-auth"):
        assert fact in section, fact


@pytest.mark.finding("F-167")
def test_non_read_calls_are_listed_with_their_opt_outs():
    from tests.support.fakeaws import READ_ONLY_OPERATIONS

    text = _text()
    section = text.split("## Calls that are not plain reads", 1)[1].split("\n## ", 1)[0]
    for api in READ_ONLY_OPERATIONS:  # the allow-listed non-read AWS operations
        assert api.split(":", 1)[1] in section, api
    for fact in ("--no-credential-report", "SelfSubjectRulesReview", "--no-k8s-self-review",
                 "SimulatePrincipalPolicy", "--mode simulate"):
        assert fact in section, fact
    for action in permissions.SIMULATE_ACTIONS + permissions.RUNNER_ACTIONS:
        assert action.split(":", 1)[1] in text, action


@pytest.mark.finding("F-046", "F-167")
def test_detection_page_names_no_real_identifiers():
    text = _text()
    accounts = set(re.findall(r"(?<!\d)\d{12}(?!\d)", text))
    assert accounts <= {"123456789012", "111122223333", "999999999999", "000000000000"}, accounts


@pytest.mark.finding("F-167")
def test_api_gateway_operations_listed_match_the_collector():
    source = (ROOT / "aws_enumerator" / "collectors" / "apigateway.py").read_text(encoding="utf-8")
    operations = {"".join(part.title() for part in op.split("_")) for op in re.findall(r'"(get_[a-z_]+)"', source)}
    assert operations, "no API Gateway operations found in the collector"
    note = _text().split("**API Gateway.**", 1)[1].split("\n- ", 1)[0]
    for operation in sorted(operations):
        assert operation in note, operation


# ── F-154: shared, account-wide API quotas (operator guidance) ───────────────
#: What both the README's "Load" paragraph and the "Volume and shape" section must tell an operator.
QUOTA_FACTS = ("shared, account-wide", "Route 53", "EC2 `Describe*`", "ECS", "Lambda", "busy production account",
               "off-peak", "--max-rps", "--rate-limit", "run.options.rate_limit")
#: The service names the detection page uses for the limiter's global control planes.
GLOBAL_NAMES = {"IAM": "iam", "Route 53": "route53", "Organizations": "organizations", "CloudFront": "cloudfront",
                "STS": "sts"}


def _flat(text: str) -> str:
    """Line wrapping removed, so a fact may be split across two source lines."""
    return " ".join(text.split())


def _readme_load_paragraph() -> str:
    readme = (ROOT / "readme.md").read_text(encoding="utf-8")
    section = readme.split("\n## OPSEC and detection footprint\n", 1)[1].split("\n## ", 1)[0]
    return section.split("- **Load.**", 1)[1].split("\n- **", 1)[0]


def _volume_section() -> str:
    return _text().split("\n## Volume and shape\n", 1)[1].split("\n## ", 1)[0]


def _collect_parser() -> argparse.ArgumentParser:
    from aws_enumerator import cli

    for action in cli.build_parser()._actions:  # noqa: SLF001 - argparse has no public accessor for subparsers
        if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            return action.choices["collect"]
    raise AssertionError("no collect subcommand")


@pytest.mark.finding("F-154")
@pytest.mark.parametrize("where", ("readme-load", "detection-volume"))
def test_load_guidance_names_the_shared_quotas_off_peak_and_a_lower_max_rps(where):
    """Both places warn that a scan competes with co-tenant automation for the account's control-plane quotas."""
    text = _flat(_readme_load_paragraph() if where == "readme-load" else _volume_section())
    missing = [fact for fact in QUOTA_FACTS if fact not in text]
    assert missing == [], f"{where} lacks {missing}"
    assert re.search(r"--max-rps \d", text) and re.search(r"--rate-limit [a-z0-9-]+=\d", text), where
    assert re.search(r"cannot see (anyone else's|the other callers') traffic", text), where


@pytest.mark.finding("F-154")
def test_documented_rate_limits_match_the_limiter_and_the_manifest():
    """The defaults, the global buckets, AIMD, the flags' effect and the manifest block are what the code does."""
    from types import SimpleNamespace

    from aws_enumerator import cli, coverage, runner
    from aws_enumerator.ratelimit import DEFAULT_RATES, GLOBAL_SERVICES, RateLimitConfig, RateLimiter, TokenBucket

    section = _flat(_volume_section())
    # default rates quoted on the page
    assert "A bucket allows 5 requests per second" in section and DEFAULT_RATES["default"][0] == 5
    assert "for example 8 for EC2, 3 for Lambda, and 2 for Route 53 and API Gateway, whose quotas are small" in section
    assert [DEFAULT_RATES[s][0] for s in ("ec2", "lambda", "route53", "apigateway", "apigatewayv2")] == [8, 3, 2, 2, 2]
    assert max(DEFAULT_RATES["route53"][0], DEFAULT_RATES["apigateway"][0]) < DEFAULT_RATES["default"][0]
    # one bucket for the whole run for the global control planes, one per region otherwise
    listed = re.search(r"global control planes \(([^)]+)\)", section).group(1)
    names = {GLOBAL_NAMES[n.strip()] for n in re.split(r",| and ", listed) if n.strip()}
    assert names == set(GLOBAL_SERVICES)
    limiter = RateLimiter(RateLimitConfig(), global_region="us-east-1", clock=lambda: 0.0, sleep=lambda _s: None)
    assert limiter.key("route53", "eu-west-2") == limiter.key("route53", "us-west-2")
    assert limiter.key("ec2", "eu-west-2") != limiter.key("ec2", "us-west-2")
    # "Each throttle the run receives halves that bucket's rate"
    bucket = TokenBucket(4.0, 4.0, clock=lambda: 0.0, sleep=lambda _s: None)
    bucket.on_throttle()
    assert "halves that bucket's rate" in section and bucket.rate == 2.0
    # the documented example invocation lowers every bucket, and an override is per service and may exceed the cap
    parser = _collect_parser()
    argv = ["--region", "eu-west-2", "--max-rps", "2", "--rate-limit", "route53=1"]
    req = cli._collect_request(parser.parse_args(argv), ["collect", *argv], parser)  # noqa: SLF001
    assert req.rate_limit.enabled and req.rate_limit.rate_for("ec2")[0] == 2.0
    assert req.rate_limit.rate_for("lambda")[0] == 2.0 and req.rate_limit.rate_for("route53")[0] == 1.0
    assert RateLimitConfig(max_rps=2, overrides={"route53": 4}).rate_for("route53")[0] == 4.0
    assert "an override may also be higher than the `--max-rps` cap" in section
    # the manifest block the page points to: run.options.rate_limit with the four documented fields
    selection = SimpleNamespace(names=lambda: ["route53"], skipped=[])
    plan = SimpleNamespace(regions_requested=["eu-west-2"])
    block = runner._manifest_options(req, selection, plan)["rate_limit"]  # noqa: SLF001 - becomes run.options
    assert block == {"enabled": True, "default_rps": 5.0, "max_rps": 2.0, "overrides": {"route53": 1.0}}
    documented = re.search(r"under `run\.options\.rate_limit` \(([^)]+)\)", section).group(1)
    assert set(re.findall(r"`(\w+)`", documented)) == set(block)
    schema = json.loads((ROOT / "aws_enumerator/schemas/manifest-2.0.schema.json").read_text(encoding="utf-8"))
    options = schema["properties"]["run"]["properties"]["options"]
    assert "rate_limit" in options["required"] and set(options["properties"]["rate_limit"]["properties"]) == set(block)
    # a call still throttled after the retries is recorded as such, and the run is partial
    assert "throttled" in coverage.CALL_STATUSES and "`throttled` in `_coverage.json`" in section
    assert "exit code 2" in section
