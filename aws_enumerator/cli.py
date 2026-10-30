"""Command-line interface: the ``aws-enumerator`` console script and ``python -m aws_enumerator``.

Contract: docs/contracts/cli.md. This module only parses arguments, translates the old flag-style
invocation (one release, with a deprecation warning, cli.md §4), configures logging
(:mod:`aws_enumerator.logging_setup`) and dispatches to the subcommand implementations in
:mod:`aws_enumerator.runner` (``collect``, ``preflight``) and :mod:`aws_enumerator.commands` (everything
else). It is one of the two modules allowed to write to stdout (cli.md §5): stdout carries only the
command's result; the banner, progress, warnings and errors go to stderr through logging.

Exit codes (cli.md §6): 0 complete, 2 partial, 1 fatal, 64 usage (argparse errors included: argparse's own
exit 2 would collide with "partial"), 130/143 interrupted.
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from aws_enumerator import logging_setup
from aws_enumerator._version import PRODUCT_NAME
from aws_enumerator.buildinfo import version_line

__all__ = ["EXIT_USAGE", "SUBCOMMANDS", "build_parser", "main", "port_type", "translate_legacy"]

log = logging.getLogger("aws_enumerator.cli")

PROG = PRODUCT_NAME
EXIT_USAGE = 64
AUTHORIZED_USE = "Authorized use only: run only against accounts you have written permission to assess."
SUBCOMMANDS = ("collect", "analyze", "export", "merge", "dashboard", "preflight", "permissions", "modules",
               "package", "verify", "version")
EXPORT_FORMATS = ("sarif", "csv", "md", "asff", "opengraph")
SEVERITIES = ("critical", "high", "medium", "low", "info")
LEGACY_OUTPUTS_HELP = ("do not write the d13c215 legacy files (permission_map.json, trust_relationships.json, "
                       "*_relationships.json) to analysis/; graph.json holds the same data")
_PASSTHROUGH_FIRST = ("-h", "--help", "--version")
_EBS_SHARE_RE = re.compile(r"^(all|none|cap:[0-9]{1,7})$")
#: Flags whose value is a local path or an identifying name: recorded as ``<redacted>`` in ``run.argv``.
_PRIVATE_VALUE_FLAGS = frozenset({
    "--output", "--log-file", "--kubeconfig", "--k8s-token-file", "--k8s-ca-file", "--iam-gaad-file",
    "--scp-file", "--global-from", "--resume", "--baseline", "--suppress",
})


#: Flags of the offline subcommands that take a value (so ``recorded_argv(positionals=True)`` keeps it).
_VALUE_FLAGS = frozenset({"--run-id", "--log-format", "--format", "--min-severity", "--host", "--port",
                          "--allowed-host", "--partition", "--encrypt", "--sign"})


# ── argument types ───────────────────────────────────────────────────────────
class _Parser(argparse.ArgumentParser):
    """``error()`` exits 64 (cli.md §1); subparsers inherit the class."""

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def port_type(value: str) -> int:
    """A TCP port 0-65535 (0 picks a free port; F-129)."""
    try:
        port = int(value, 10)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"invalid port {value!r} (expected 0-65535)") from None
    if not 0 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"port {port} is out of range (expected 0-65535)")
    return port


def _int_range(low: int, high: Optional[int] = None) -> Callable[[str], int]:
    def parse(value: str) -> int:
        try:
            number = int(value, 10)
        except (TypeError, ValueError):
            raise argparse.ArgumentTypeError(f"invalid integer {value!r}") from None
        if number < low or (high is not None and number > high):
            bound = f"{low}-{high}" if high is not None else f">= {low}"
            raise argparse.ArgumentTypeError(f"{number} is out of range ({bound})")
        return number
    return parse


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"invalid number {value!r}") from None
    if not number > 0 or number != number or number == float("inf"):
        raise argparse.ArgumentTypeError(f"{value!r} must be a positive number")
    return number


def _non_negative_float(value: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"invalid number {value!r}") from None
    if not 0 <= number < float("inf"):
        raise argparse.ArgumentTypeError(f"{value!r} must be >= 0")
    return number


def _csv(value: str) -> List[str]:
    """``"a, b,,c"`` -> ``["a", "b", "c"]``."""
    return [part.strip() for part in str(value).split(",") if part.strip()]


def _timeout_pair(value: str) -> str:
    parts = _csv(value)
    try:
        numbers = [float(p) for p in parts]
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected CONNECT,READ seconds, got {value!r}") from None
    if len(numbers) not in (1, 2) or not all(0 < n <= 600 for n in numbers):
        raise argparse.ArgumentTypeError(f"expected CONNECT,READ seconds in (0, 600], got {value!r}")
    return ",".join(parts)


def _ebs_share_check(value: str) -> str:
    """``all | none | cap:N`` (case-insensitive), normalised to lower case as ``ebs.share_check_budget`` reads it."""
    normalised = (value or "").strip().lower()
    if not _EBS_SHARE_RE.match(normalised):
        raise argparse.ArgumentTypeError(f"expected all, none or cap:N, got {value!r}")
    return normalised


def _flatten(values: Optional[Sequence[Sequence[str]]]) -> List[str]:
    return [item for group in (values or []) for item in group]


# ── legacy invocation (cli.md §4) ────────────────────────────────────────────
def translate_legacy(argv: Sequence[str]) -> Tuple[List[str], Optional[str]]:
    """Map the d13c215 flag-style invocation onto subcommands; returns ``(argv, deprecation notice)``."""
    argv = list(argv)
    if argv and (argv[0] in SUBCOMMANDS or argv[0] in _PASSTHROUGH_FIRST):
        return argv, None
    if "--dashboard" in argv:
        new, dropped = ["dashboard"], []
        index = 0
        while index < len(argv):
            arg = argv[index]
            if arg == "--port":
                new.extend(argv[index:index + 2])
                index += 2
                continue
            if arg.startswith("--port="):
                new.append(arg)
            elif arg != "--dashboard":
                dropped.append(arg)
            index += 1
        notice = _deprecation(argv, new)
        if dropped:
            notice += f"; ignored with --dashboard: {' '.join(dropped)}"
        return new, notice
    new = ["collect", *argv]
    return new, _deprecation(argv, new)


def _deprecation(old: Sequence[str], new: Sequence[str]) -> str:
    before = " ".join([PROG, *old])
    return f"'{before}' is deprecated; use '{' '.join([PROG, *new])}' (removed in 0.4.0)"


def recorded_argv(argv: Sequence[str], *, redact_profile: bool = False, positionals: bool = False) -> List[str]:
    """``run.argv``: the translated arguments with local paths (and, when redacting, the profile) hidden.

    ``positionals``: also hide every positional argument after the subcommand (``merge``'s ``RUN_DIR``s,
    manifest.md §3.2). The values of the flags that take one are never mistaken for positionals.
    """
    private = set(_PRIVATE_VALUE_FLAGS) | ({"--profile"} if redact_profile else set())
    out: List[str] = []
    hide_next = keep_next = only_positionals = False
    for index, arg in enumerate(argv):
        if hide_next or keep_next:
            out.append("<redacted>" if hide_next else arg)
            hide_next = keep_next = False
            continue
        if positionals and index > 0 and (only_positionals or not arg.startswith("-") or arg == "-"):
            out.append("<redacted>")
            continue
        if arg == "--":
            only_positionals = True
            out.append(arg)
            continue
        flag, eq, _value = arg.partition("=")
        if flag in private and eq:
            out.append(f"{flag}=<redacted>")
        else:
            out.append(arg)
            hide_next = arg in private
            keep_next = positionals and not eq and arg in _VALUE_FLAGS and not hide_next
    return out


# ── parser ───────────────────────────────────────────────────────────────────
def _common_parent() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    group = parent.add_argument_group("logging (every subcommand)")
    group.add_argument("-q", "--quiet", action="store_true", help="only warnings and errors on stderr; no banner")
    group.add_argument("-v", "--verbose", action="count", default=0,
                       help="-v: debug logging; -vv: also botocore/urllib3 debug (logs request parameters)")
    group.add_argument("--log-format", choices=("text", "json"), default="text", help="stderr log format")
    group.add_argument("--no-color", action="store_true",
                       help="no ANSI colours (also off without a TTY or with NO_COLOR)")
    group.add_argument("--log-file", metavar="PATH",
                       help="JSON-lines log file, mode 0600 (collect: <run root>/run.log)")
    parent.add_argument("--version", action="version", version=version_line())
    return parent


def _add_selection(p: argparse.ArgumentParser, *, k8s_flags: bool = True) -> None:
    group = p.add_argument_group("module selection")
    group.add_argument("--modules", action="append", type=_csv, metavar="A,@GROUP",
                       help="modules, aliases or @groups (repeatable or comma-separated); see 'aws-enumerator modules'")
    group.add_argument("--skip", action="append", type=_csv, metavar="A,@GROUP", help="modules to remove")
    group.add_argument("--max-tier", type=int, choices=(1, 2), default=2,
                       help="1 drops tier-2 modules (APIs returning secret-bearing configuration)")
    if k8s_flags:
        k8s = group.add_mutually_exclusive_group()
        k8s.add_argument("--no-k8s", action="store_true", help="do not query the Kubernetes API of EKS clusters")
        k8s.add_argument("--k8s", action="store_true", help="Kubernetes collection on (the default)")


def _add_regions(p: argparse.ArgumentParser) -> None:
    group = p.add_argument_group("AWS identity and regions")
    group.add_argument("--profile", metavar="NAME", help="AWS profile (one session for the whole run)")
    regions = group.add_mutually_exclusive_group()
    regions.add_argument("--region", metavar="R", help="collect one region (also the home region)")
    regions.add_argument("--regions", type=_csv, metavar="A,B", help="collect these regions")
    regions.add_argument("--all", action="store_true", dest="all_regions", help="collect every enabled region")
    group.add_argument("--exclude-regions", type=_csv, metavar="A,B", default=[], help="with --all only")


def _add_collect_output(p: argparse.ArgumentParser) -> None:
    group = p.add_argument_group("output")
    group.add_argument("--output", metavar="DIR",
                       help="output root (default $AWS_ENUMERATOR_OUTPUT, else ~/.aws-enumerator/reports)")
    group.add_argument("--allow-in-repo", action="store_true", help="allow an output inside a git work tree")
    group.add_argument("--run-id", metavar="ID", help="run id (default <UTC timestamp>-<6 hex>)")
    group.add_argument("--resume", metavar="RUN_DIR|RUN_ID", help="re-run the units of an existing run that did not "
                       "finish cleanly")
    group.add_argument("--retry-denied", action="store_true", help="with --resume: also re-run denied modules")
    group.add_argument("--no-analysis", action="store_true", help="collect only (run 'aws-enumerator analyze' later)")
    group.add_argument("--zip", action="store_true", help="write <output>/<account>/<run_id>.zip")
    group.add_argument("--encrypt", metavar="age:RCPT|gpg:RCPT",
                       help="encrypt the zip with an external tool (implies --zip)")
    group.add_argument("--sign", metavar="gpg:KEYID|minisign:KEY",
                       help="detached signature of the archive (implies --zip)")
    group.add_argument("--redact-identity", action="store_true",
                       help="drop the caller ARN and user id from the manifest and logs")
    group.add_argument("--shutdown-grace", type=_non_negative_float, default=20.0, metavar="SECONDS",
                       help="after SIGINT/SIGTERM, how long running units may finish (default 20)")
    group.add_argument("--skip-global", action="store_true", help="do not collect global services")
    group.add_argument("--global-from", metavar="RUN_DIR", help="copy global/ from another run of the same account")
    analysis = p.add_argument_group("analysis")
    analysis.add_argument("--baseline", metavar="PATH", help="previous run or findings.json; writes analysis/diff.json")
    analysis.add_argument("--suppress", metavar="FILE", help="suppression file")
    analysis.add_argument("--no-legacy-outputs", action="store_true", help=LEGACY_OUTPUTS_HELP)


def _add_k8s(p: argparse.ArgumentParser) -> None:
    group = p.add_argument_group("Kubernetes (on by default)")
    group.add_argument("--k8s-secrets", action="store_true",
                       help="list Secret metadata only (names, never values); off by default")
    group.add_argument("--k8s-auth", choices=("eks-token", "kubeconfig", "token", "in-cluster"), default="eks-token")
    group.add_argument("--kubeconfig", metavar="PATH")
    group.add_argument("--kube-context", metavar="NAME")
    group.add_argument("--k8s-token-file", metavar="PATH")
    group.add_argument("--k8s-ca-file", metavar="PATH")
    group.add_argument("--k8s-clusters", type=_csv, metavar="A,B", help="only these cluster names")
    group.add_argument("--k8s-timeout", type=_timeout_pair, default="5,60", metavar="CONNECT,READ")
    group.add_argument("--no-k8s-self-review", action="store_true", help="skip SelfSubjectRulesReview")


def _add_load(p: argparse.ArgumentParser) -> None:
    group = p.add_argument_group("load and resilience")
    group.add_argument("--concurrency", type=_int_range(1, 16), default=3, metavar="N",
                       help="units (global + each region) in parallel (default 3, max 16)")
    group.add_argument("--max-rps", type=_positive_float, metavar="N", help="cap every rate-limit bucket")
    group.add_argument("--rate-limit", action="append", default=[], metavar="SVC=RPS", help="override one service")
    group.add_argument("--no-rate-limit", action="store_true", help="disable the client-side rate limiter (labs)")
    group.add_argument("--retry-mode", choices=("legacy", "standard", "adaptive"),
                       help="botocore retry mode (default: your config, else adaptive)")
    group.add_argument("--max-attempts", type=_int_range(1, 20), metavar="N",
                       help="botocore total attempts (default: your config, else 5)")
    group.add_argument("--deny-breaker", type=_int_range(0), default=3, metavar="N",
                       help="consecutive per-item denials of one API before the rest are skipped (0 disables)")


def _add_tuning(p: argparse.ArgumentParser) -> None:
    group = p.add_argument_group("collector tuning")
    group.add_argument("--iam-mode", choices=("gaad", "per-entity"), default="gaad")
    group.add_argument("--iam-gaad-file", metavar="PATH", help="import an exported GAAD JSON")
    group.add_argument("--no-credential-report", action="store_true", help="skip GenerateCredentialReport")
    group.add_argument("--iam-user-details", action=argparse.BooleanOptionalAction, default=True,
                       help="per-user keys, SSH keys, service credentials, certificates")
    group.add_argument("--s3-subresources", choices=("basic", "full"), default="basic")
    group.add_argument("--ecs-max-revisions", type=_int_range(0), default=5, metavar="K")
    group.add_argument("--ebs-share-check", type=_ebs_share_check, default="cap:1000", metavar="all|none|cap:N")
    group.add_argument("--lambda-versions", action="store_true")
    group.add_argument("--ec2-userdata-check", action="store_true", help="UserData presence/hash/length only")
    group.add_argument("--full-dns", action="store_true", help="keep TXT/MX/SRV/CAA/SPF and private A/AAAA values")
    group.add_argument("--keep-sensitive-metadata", action="store_true")
    group.add_argument("--scp-file", metavar="PATH", help="import SCPs/RCPs")
    ua = p.add_argument_group("user agent")
    ua.add_argument("--ua-app-id", metavar="STR", help="botocore user_agent_appid (default aws-enumerator/<ver>/<run>)")
    ua.add_argument("--no-ua-tag", action="store_true", help="send no app id (documented red-team opt-out)")
    pre = p.add_argument_group("pre-flight")
    pre.add_argument("--preflight", action="store_true", help="probe the selected modules first; record the result")
    pre.add_argument("--preflight-only", action="store_true", help="run the pre-flight only; write nothing")


def _sub(subs: Any, name: str, parent: argparse.ArgumentParser, help_text: str) -> argparse.ArgumentParser:
    return subs.add_parser(name, parents=[parent], help=help_text, description=f"{help_text}. {AUTHORIZED_USE}",
                           allow_abbrev=False)


def _build_collect(subs: Any, parent: argparse.ArgumentParser) -> None:
    p = _sub(subs, "collect", parent, "Enumerate an AWS account and analyse it")
    _add_regions(p)
    _add_selection(p)
    _add_k8s(p)
    _add_collect_output(p)
    _add_load(p)
    _add_tuning(p)
    p.set_defaults(handler=_cmd_collect)


def _build_offline(subs: Any, parent: argparse.ArgumentParser) -> None:
    p = _sub(subs, "analyze", parent, "(Re-)run the analysis of a run or a legacy report")
    p.add_argument("dir", metavar="DIR")
    p.add_argument("--force", action="store_true", help="analyse a run that is still in progress")
    p.add_argument("--allow-in-repo", action="store_true")
    p.add_argument("--baseline", metavar="PATH")
    p.add_argument("--suppress", metavar="FILE")
    p.add_argument("--redact-identity", action="store_true", help="publish the principal ARN, not the caller ARN")
    p.add_argument("--no-legacy-outputs", action="store_true", help=LEGACY_OUTPUTS_HELP)
    p.set_defaults(handler=_cmd_analyze)

    p = _sub(subs, "export", parent, "Write findings or graph exports from analysis/graph.json")
    p.add_argument("dir", metavar="DIR")
    p.add_argument("--format", required=True, choices=EXPORT_FORMATS, dest="export_format")
    p.add_argument("--output", metavar="PATH|-", help="default <dir>/analysis/exports/<file>; '-' for stdout")
    p.add_argument("--min-severity", type=str.lower, choices=SEVERITIES)
    p.add_argument("--include-suppressed", action="store_true")
    p.add_argument("--all-edges", action="store_true", help="OpenGraph: also non-traversable edges")
    p.add_argument("--allow-in-repo", action="store_true")
    p.set_defaults(handler=_cmd_export)

    p = _sub(subs, "merge", parent, "Merge the analysed graphs of runs of different accounts (graph.json 1.1)")
    p.add_argument("runs", nargs="+", metavar="RUN_DIR",
                   help="two or more analysed runs (directories holding analysis/graph.json), one per account")
    p.add_argument("--output", metavar="DIR",
                   help="output root (default $AWS_ENUMERATOR_OUTPUT, else ~/.aws-enumerator/reports); "
                        "writes <output>/merged/<run_id>/")
    p.add_argument("--run-id", metavar="ID", help="run id of the merge (default <UTC timestamp>-<6 hex>)")
    p.add_argument("--allow-in-repo", action="store_true", help="allow an output inside a git work tree")
    p.set_defaults(handler=_cmd_merge)

    p = _sub(subs, "dashboard", parent, "Serve the dashboard locally")
    p.add_argument("path", nargs="?", metavar="PATH", help="a run directory or zip (printed as a hint only)")
    p.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    p.add_argument("--port", type=port_type, default=8000, help="0-65535; 0 picks a free port (default 8000)")
    p.add_argument("--no-browser", action="store_true")
    p.add_argument("--allowed-host", action="append", default=[], metavar="H", help="extra Host header to accept")
    p.set_defaults(handler=_cmd_dashboard)


def _build_aws_tools(subs: Any, parent: argparse.ArgumentParser) -> None:
    p = _sub(subs, "preflight", parent, "Check the permissions the selected modules need")
    _add_regions(p)
    _add_selection(p)
    p.add_argument("--mode", choices=("probe", "simulate"), default="probe")
    p.add_argument("--format", choices=("text", "json"), default="text", dest="output_format")
    p.set_defaults(handler=_cmd_preflight)

    p = _sub(subs, "permissions", parent, "Print the IAM policy / Kubernetes RBAC the selected modules need")
    _add_selection(p)
    p.add_argument("--format", choices=("iam", "k8s", "markdown"), default="iam", dest="output_format")
    p.add_argument("--k8s-secrets", action="store_true")
    p.add_argument("--partition", default="aws", help="aws, aws-us-gov, aws-cn, ...")
    p.add_argument("--include-optional", action="store_true")
    p.add_argument("--guardrail", action="store_true", help="add the data-plane Deny statement")
    p.set_defaults(handler=_cmd_permissions)

    p = _sub(subs, "modules", parent, "List the collector registry")
    p.add_argument("--format", choices=("table", "json"), default="table", dest="output_format")
    p.set_defaults(handler=_cmd_modules)

    p = _sub(subs, "package", parent, "Zip (and optionally encrypt/sign) a run")
    p.add_argument("dir", metavar="RUN_DIR")
    p.add_argument("--output", metavar="PATH", help="archive path (default next to the run root)")
    p.add_argument("--encrypt", metavar="age:RCPT|gpg:RCPT")
    p.add_argument("--sign", metavar="gpg:KEYID|minisign:KEY")
    p.add_argument("--allow-in-repo", action="store_true")
    p.add_argument("--force", action="store_true", help="package a run that is still in progress")
    p.set_defaults(handler=_cmd_package)

    p = _sub(subs, "verify", parent, "Check a run's digests")
    p.add_argument("path", metavar="RUN_DIR|ZIP")
    p.set_defaults(handler=_cmd_verify)

    p = _sub(subs, "version", parent, "Print the version")
    p.add_argument("--json", action="store_true", help="the manifest's tool block as JSON")
    p.set_defaults(handler=_cmd_version)


def build_parser() -> argparse.ArgumentParser:
    """The full parser; building it imports no collector (registry.md §1 rule 6)."""
    parser = _Parser(prog=PROG, allow_abbrev=False,
                     description=f"Enumerate an AWS account, analyse its attack paths and visualise them locally. "
                                 f"{AUTHORIZED_USE}",
                     epilog="Run 'aws-enumerator <subcommand> --help' for the options of a subcommand.")
    parser.add_argument("--version", action="version", version=version_line())
    parent = _common_parent()
    subs = parser.add_subparsers(dest="command", metavar="<subcommand>", parser_class=_Parser)
    subs.required = True
    _build_collect(subs, parent)
    _build_offline(subs, parent)
    _build_aws_tools(subs, parent)
    return parser


# ── handlers ─────────────────────────────────────────────────────────────────
def _tool_spec(parser_error: Callable[[str], None], value: Optional[str], allowed: Tuple[str, ...],
               flag: str) -> Optional[Tuple[str, str]]:
    if not value:
        return None
    from aws_enumerator.archive import parse_tool_spec

    try:
        return parse_tool_spec(value, allowed, flag)
    except ValueError as exc:
        parser_error(str(exc))
    return None


def _collector_options(args: argparse.Namespace) -> Dict[str, Any]:
    """Collector tuning flags, by option name (``ctx.option``; cli.md §3.1)."""
    options = {
        "iam_mode": args.iam_mode, "iam_gaad_file": args.iam_gaad_file,
        "credential_report": not args.no_credential_report, "iam_user_details": args.iam_user_details,
        "s3_subresources": args.s3_subresources, "ecs_max_revisions": args.ecs_max_revisions,
        "ebs_share_check": args.ebs_share_check, "lambda_versions": args.lambda_versions,
        "ec2_userdata_check": args.ec2_userdata_check, "full_dns": args.full_dns,
        "keep_sensitive_metadata": args.keep_sensitive_metadata, "scp_file": args.scp_file,
        "k8s_auth": args.k8s_auth, "kubeconfig": args.kubeconfig, "kube_context": args.kube_context,
        "k8s_token_file": args.k8s_token_file, "k8s_ca_file": args.k8s_ca_file,
        "k8s_clusters": ",".join(args.k8s_clusters) if args.k8s_clusters else None,
        "k8s_timeout": args.k8s_timeout, "k8s_self_review": not args.no_k8s_self_review,
    }
    return {k: v for k, v in options.items() if v is not None}


def _check_collect_flags(args: argparse.Namespace, error: Callable[[str], None]) -> None:
    if args.exclude_regions and not args.all_regions:
        error("--exclude-regions needs --all")
    if args.retry_denied and not args.resume:
        error("--retry-denied needs --resume")
    if args.resume and (args.run_id or args.global_from):
        error("--resume reuses the run's id and global data: drop --run-id / --global-from")
    if args.k8s_auth == "token" and not args.k8s_token_file:
        error("--k8s-auth token needs --k8s-token-file")


def _collect_request(args: argparse.Namespace, argv: Sequence[str], parser: argparse.ArgumentParser) -> Any:
    from aws_enumerator import runner
    from aws_enumerator.archive import ENCRYPT_TOOLS, SIGN_TOOLS
    from aws_enumerator.ratelimit import RateLimitConfig, parse_rate_overrides

    _check_collect_flags(args, parser.error)
    try:
        overrides = parse_rate_overrides(args.rate_limit)
    except ValueError as exc:
        parser.error(str(exc))
    encrypt = _tool_spec(parser.error, args.encrypt, ENCRYPT_TOOLS, "--encrypt")
    sign = _tool_spec(parser.error, args.sign, SIGN_TOOLS, "--sign")
    return runner.CollectRequest(
        argv=recorded_argv(argv, redact_profile=args.redact_identity), profile=args.profile, region=args.region,
        regions=list(args.regions or []), all_regions=args.all_regions, exclude_regions=list(args.exclude_regions),
        skip_global=args.skip_global, global_from=args.global_from, modules=_flatten(args.modules),
        skip=_flatten(args.skip), max_tier=args.max_tier, k8s=not args.no_k8s, k8s_secrets=args.k8s_secrets,
        output=args.output, allow_in_repo=args.allow_in_repo, run_id=args.run_id, resume=args.resume,
        retry_denied=args.retry_denied, no_analysis=args.no_analysis, zip=bool(args.zip or encrypt or sign),
        encrypt=encrypt, sign=sign,
        redact_identity=args.redact_identity, shutdown_grace=args.shutdown_grace, baseline=args.baseline,
        suppress=args.suppress, legacy_outputs=not args.no_legacy_outputs, concurrency=args.concurrency,
        rate_limit=RateLimitConfig(enabled=not args.no_rate_limit, max_rps=args.max_rps, overrides=overrides),
        retry_mode=args.retry_mode, max_attempts=args.max_attempts, deny_breaker=args.deny_breaker,
        ua_app_id=args.ua_app_id, ua_tag=not args.no_ua_tag, preflight=args.preflight,
        preflight_only=args.preflight_only, log_file_given=bool(args.log_file),
        collector_options=_collector_options(args))


def _cmd_collect(args: argparse.Namespace, argv: Sequence[str], parser: argparse.ArgumentParser) -> Any:
    from aws_enumerator import runner

    return runner.run_collect(_collect_request(args, argv, parser))


def _cmd_preflight(args: argparse.Namespace, argv: Sequence[str], parser: argparse.ArgumentParser) -> Any:
    from aws_enumerator import runner

    if args.exclude_regions and not args.all_regions:
        parser.error("--exclude-regions needs --all")
    req = runner.CollectRequest(
        argv=list(argv), profile=args.profile, region=args.region, regions=list(args.regions or []),
        all_regions=args.all_regions, modules=_flatten(args.modules), skip=_flatten(args.skip),
        max_tier=args.max_tier, k8s=not args.no_k8s, preflight_only=True, preflight_mode=args.mode,
        preflight_format=args.output_format)
    return runner.run_collect(req)


def _cmd_analyze(args: argparse.Namespace, _argv: Sequence[str], _parser: argparse.ArgumentParser) -> Any:
    from aws_enumerator import commands

    return commands.analyze(args.dir, force=args.force, allow_in_repo=args.allow_in_repo, baseline=args.baseline,
                            suppress=args.suppress, redact_identity=args.redact_identity,
                            legacy_outputs=not args.no_legacy_outputs)


def _cmd_export(args: argparse.Namespace, _argv: Sequence[str], _parser: argparse.ArgumentParser) -> Any:
    from aws_enumerator import commands

    return commands.export(args.dir, args.export_format, output=args.output, min_severity=args.min_severity,
                           include_suppressed=args.include_suppressed, all_edges=args.all_edges,
                           allow_in_repo=args.allow_in_repo)


def _cmd_merge(args: argparse.Namespace, argv: Sequence[str], parser: argparse.ArgumentParser) -> Any:
    from aws_enumerator import commands

    if len(args.runs) < 2:
        parser.error("merge needs at least two RUN_DIRs (analysed runs of different accounts)")
    return commands.merge(args.runs, output=args.output, run_id=args.run_id, allow_in_repo=args.allow_in_repo,
                          argv=recorded_argv(argv, positionals=True))


def _cmd_dashboard(args: argparse.Namespace, _argv: Sequence[str], _parser: argparse.ArgumentParser) -> Any:
    from aws_enumerator import commands

    return commands.dashboard(args.path, host=args.host, port=args.port, open_browser=not args.no_browser,
                              allowed_hosts=args.allowed_host, announce=_announce)


def _announce(line: str) -> None:
    """stdout for a long-running command's result (the dashboard URL, once listening)."""
    print(line, flush=True)


def _cmd_permissions(args: argparse.Namespace, _argv: Sequence[str], _parser: argparse.ArgumentParser) -> Any:
    from aws_enumerator import commands

    return commands.permissions(args.output_format, modules=_flatten(args.modules), skip=_flatten(args.skip),
                                k8s=not args.no_k8s, k8s_secrets=args.k8s_secrets, max_tier=args.max_tier,
                                partition=args.partition, include_optional=args.include_optional,
                                guardrail=args.guardrail)


def _cmd_modules(args: argparse.Namespace, _argv: Sequence[str], _parser: argparse.ArgumentParser) -> Any:
    from aws_enumerator import commands

    return commands.modules(args.output_format)


def _cmd_package(args: argparse.Namespace, _argv: Sequence[str], parser: argparse.ArgumentParser) -> Any:
    from aws_enumerator import commands
    from aws_enumerator.archive import ENCRYPT_TOOLS, SIGN_TOOLS

    return commands.package(args.dir, output=args.output,
                            encrypt=_tool_spec(parser.error, args.encrypt, ENCRYPT_TOOLS, "--encrypt"),
                            sign=_tool_spec(parser.error, args.sign, SIGN_TOOLS, "--sign"),
                            allow_in_repo=args.allow_in_repo, force=args.force)


def _cmd_verify(args: argparse.Namespace, _argv: Sequence[str], _parser: argparse.ArgumentParser) -> Any:
    from aws_enumerator import commands

    return commands.verify(args.path)


def _cmd_version(args: argparse.Namespace, _argv: Sequence[str], _parser: argparse.ArgumentParser) -> Any:
    from aws_enumerator import commands

    return commands.version(as_json=args.json)


# ── main ─────────────────────────────────────────────────────────────────────
def _exit_code(exc: SystemExit) -> int:
    if exc.code is None:
        return 0
    return exc.code if isinstance(exc.code, int) else EXIT_USAGE


def _emit(outcome: Any) -> None:
    """Write the command's result to stdout (cli.md §5)."""
    data = getattr(outcome, "data", None)
    if data is not None:
        buffer = getattr(sys.stdout, "buffer", None)
        if buffer is not None:
            sys.stdout.flush()
            buffer.write(data)
            buffer.flush()
        else:
            sys.stdout.write(data.decode("utf-8", "replace"))
    for line in getattr(outcome, "stdout", None) or []:
        print(line)
    sys.stdout.flush()


def _log_config(args: argparse.Namespace) -> logging_setup.LogConfig:
    collecting = args.command == "collect" and not getattr(args, "preflight_only", False)
    return logging_setup.LogConfig(quiet=args.quiet, verbose=args.verbose, log_format=args.log_format,
                                   no_color=args.no_color, log_file=args.log_file,
                                   buffer_for_run_log=collecting and not args.log_file)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point; returns the exit code (the console script does ``sys.exit(main())``)."""
    raw = list(sys.argv[1:] if argv is None else argv)
    translated, notice = translate_legacy(raw)
    parser = build_parser()
    try:
        args = parser.parse_args(translated)
    except SystemExit as exc:
        return _exit_code(exc)
    try:
        logging_setup.configure(_log_config(args))
    except OSError as exc:
        print(f"{PROG}: error: cannot open the log file: {exc.strerror or exc}", file=sys.stderr)
        return 1
    try:
        if notice:
            log.warning("%s", notice)
        outcome = args.handler(args, translated, parser)
        _emit(outcome)
        return int(outcome.exit_code)
    except SystemExit as exc:  # parser.error() inside a handler
        return _exit_code(exc)
    except KeyboardInterrupt:
        log.error("interrupted")
        return 130
    finally:
        logging_setup.shutdown()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
