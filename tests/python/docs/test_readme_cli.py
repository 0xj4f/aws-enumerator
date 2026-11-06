"""CLI drift tests for the README and the other DOC1 pages (F-062, F-061, F-124, F-145, F-161).

Every ``aws-enumerator ...`` command line in a code block or inline code span, and every inline ``--flag``, must
exist in the argparse parser of the subcommand it is used with (old flag-style invocations are checked after the
CLI's own legacy translation). The README's subcommand table must equal the parser's subcommands and help texts,
and its exit-code table must equal the codes the runtime uses.
"""

from __future__ import annotations

import argparse
import functools
import re
import shlex
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

import pytest

from aws_enumerator import cli, commands, execution

ROOT = Path(__file__).resolve().parents[3]
DOCS = ("readme.md", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md", "docs/report-handling.md",
        "docs/detection.md")

#: Flags of other programs (docker, pip, git, pytest, scripts) that the pages mention as inline code.
FOREIGN_FLAGS = frozenset({
    "--user", "--rm", "--env-file", "--require-hashes", "--no-deps", "--build-arg", "--branch", "--update-golden",
    "--write", "--check", "--all-files",
})
_PROGRAM = re.compile(r"(?:^|(?<=[\s(\"]))(aws-enumerator(?::[\w.-]+)?|python3? -m aws_enumerator)(?=\s)")
_STOP = {"|", ">", ">>", "&&", ";", "||", "#", "2>&1", ")", "<"}


def _text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


@functools.lru_cache(maxsize=1)
def _parsers() -> Tuple[argparse.ArgumentParser, Dict[str, argparse.ArgumentParser]]:
    parser = cli.build_parser()
    for action in parser._actions:  # noqa: SLF001 - argparse has no public accessor for subparsers
        if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            return parser, dict(action.choices)
    raise AssertionError("no subcommands")


def _options(parser: argparse.ArgumentParser) -> Set[str]:
    return {s for action in parser._actions for s in action.option_strings}  # noqa: SLF001


def _help_texts() -> Dict[str, str]:
    parser, _ = _parsers()
    for action in parser._actions:  # noqa: SLF001
        if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            return {a.dest: " ".join((a.help or "").split()) for a in action._choices_actions}  # noqa: SLF001
    return {}


def _code_blocks(text: str) -> Iterator[str]:
    for block in re.findall(r"^```[^\n]*\n(.*?)^```", text, flags=re.M | re.S):
        joined = re.sub(r"\\\n\s*", " ", block)
        yield from joined.splitlines()


def _inline_spans(text: str) -> Iterator[str]:
    prose = re.sub(r"^```.*?^```", "", text, flags=re.M | re.S)
    yield from re.findall(r"`([^`\n]+)`", prose)


def _commands(line: str) -> Iterator[List[str]]:
    """Token lists after each aws-enumerator program name on a line (up to a shell operator or comment)."""
    line = re.split(r"(?:^|\s)#", line, maxsplit=1)[0]  # drop a shell comment
    _, subs = _parsers()
    for match in _PROGRAM.finditer(line):
        rest = line[match.end():]
        if ":" in match.group(1) and (rest.split() or [""])[0] not in subs:
            continue  # an image tag (docker build -t aws-enumerator:X .), not a command
        try:
            tokens = shlex.split(rest, comments=True)
        except ValueError:
            tokens = rest.split()
        out: List[str] = []
        for token in tokens:
            if token in _STOP or token.startswith(("#", "$(", "`")):
                break
            out.append(token)
        yield out


def _flags(tokens: List[str]) -> List[str]:
    return [t.split("=", 1)[0] for t in tokens if t.startswith("--")]


def _check_command(tokens: List[str]) -> Optional[str]:
    """None when every flag exists for the subcommand used; else a description of the problem."""
    top, subs = _parsers()
    if not tokens:
        return None
    if tokens[0] in subs:
        known = _options(subs[tokens[0]])
        unknown = [f for f in _flags(tokens[1:]) if f not in known]
        return f"{tokens[0]}: unknown {unknown}" if unknown else None
    if tokens[0].startswith("-") and tokens[0] not in _options(top):
        translated, notice = cli.translate_legacy(tokens)
        if notice is None or not translated or translated[0] not in subs:
            return f"not a subcommand or legacy invocation: {tokens}"
        return _check_command(translated)
    if tokens[0].startswith("-"):
        unknown = [f for f in _flags(tokens) if f not in _options(top)]
        return f"top level: unknown {unknown}" if unknown else None
    if tokens[0].isupper() or tokens[0] in {"...", "<subcommand>"}:
        return None  # a placeholder such as "aws-enumerator <subcommand> [options]"
    return f"unknown subcommand {tokens[0]!r}"


def _all_options() -> Set[str]:
    top, subs = _parsers()
    out = set(_options(top))
    for sub in subs.values():
        out |= _options(sub)
    return out


def _legacy_only_flags() -> Set[str]:
    """Flags only the d13c215 invocation knows (the CLI translates them)."""
    out = set()
    for flag in ("--dashboard",):
        translated, notice = cli.translate_legacy([flag])
        if notice is not None and translated and translated[0] in _parsers()[1]:
            out.add(flag)
    return out


@pytest.mark.finding("F-062", "F-124", "F-161")
@pytest.mark.parametrize("rel", DOCS)
def test_every_documented_command_line_uses_existing_flags(rel):
    text = _text(rel)
    problems = []
    for line in list(_code_blocks(text)) + list(_inline_spans(text)):
        for tokens in _commands(line):
            problem = _check_command(tokens)
            if problem:
                problems.append(f"{line.strip()!r}: {problem}")
    assert problems == [], "\n".join(problems)


@pytest.mark.finding("F-062", "F-161")
@pytest.mark.parametrize("rel", DOCS)
def test_every_inline_flag_exists(rel):
    known = _all_options() | _legacy_only_flags() | FOREIGN_FLAGS
    unknown = []
    for span in _inline_spans(_text(rel)):
        if not span.startswith("--"):
            continue  # only flag spans; command spans are checked per subcommand above
        for token in span.split():
            if token.startswith("--") and len(token) > 2:
                flag = token.split("=", 1)[0].rstrip(",.;:)")
                if re.fullmatch(r"--[a-z][a-z0-9-]*", flag) and flag not in known:
                    unknown.append((span, flag))
    assert unknown == [], unknown


@pytest.mark.finding("F-062", "F-145", "F-161")
def test_readme_subcommand_table_matches_the_parser():
    usage = _text("readme.md").split("## Usage", 1)[1].split("\n### ", 1)[0]
    rows = re.findall(r"^\| `([a-z-]+)` \| ([^|]+) \| (yes|no) \|$", usage, flags=re.M)
    documented = {name: purpose.strip() for name, purpose, _ in rows}
    assert documented == _help_texts()
    needs_credentials = {name for name, _, creds in rows if creds == "yes"}
    assert needs_credentials == {"collect", "preflight"}


@pytest.mark.finding("F-061")
def test_readme_exit_codes_match_the_runtime():
    section = _text("readme.md").split("### Exit codes and output streams", 1)[1].split("\n## ", 1)[0]
    codes = re.findall(r"^\| `(\d+)`(?: / `(\d+)`)? \|", section, flags=re.M)
    documented = {int(c) for pair in codes for c in pair if c}
    runtime = {commands.EXIT_OK, commands.EXIT_PARTIAL, commands.EXIT_FATAL, commands.EXIT_USAGE,
               *execution.EXIT_FOR_SIGNAL.values()}
    assert documented == runtime == {0, 1, 2, 64, 130, 143}
    assert cli.EXIT_USAGE == 64


@pytest.mark.finding("F-062", "F-009")
def test_documented_collect_defaults_match_the_parser():
    _, subs = _parsers()
    defaults = subs["collect"].parse_args([])
    assert defaults.no_k8s is False and defaults.k8s_secrets is False  # K8s on, Secret listing off
    assert defaults.max_tier == 2 and defaults.concurrency == 3 and defaults.zip is False
    assert defaults.k8s_timeout == "5,60"
    readme = _text("readme.md")
    assert "| `--no-k8s` | Kubernetes **on** |" in readme
    assert "| `--k8s-secrets` | **off** |" in readme
    assert "| `--max-tier 1` | `2` |" in readme
    assert "3 units in parallel" in readme
    assert "default `5,60`" in _text("docs/detection.md")
