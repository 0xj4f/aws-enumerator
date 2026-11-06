"""The Dockerfile header's profile-mount recipe works with ``--user`` and matches the README (F-160, request doc1-1).

With ``--user "$(id -u):$(id -g)"`` and a uid that has no passwd entry in the image, Docker sets ``HOME=/``, so a
mount at ``/home/app/.aws`` is never read: botocore looks in ``/.aws`` and the named profile is not found. The
recipe therefore sets ``HOME`` to a neutral mount point (``/aws-home``; ``/home/app`` may be 0700 and owned by uid
10001) and mounts ``~/.aws`` there read-only, exactly as the README "Docker" section does. ``docker run`` itself is
not exercised offline (no image build); these checks compare the two recipes flag by flag.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import List, Optional, Tuple

import pytest

from tests.support import targets

ROOT = Path(targets.REPO_ROOT)
#: ``docker run`` options that take a value.
VALUE_FLAGS = ("--user", "-u", "-e", "--env", "-v", "--volume", "-p", "--publish", "--env-file", "-w", "--workdir")


def _dockerfile_header() -> str:
    """The comment block above the first instruction, without the ``#`` markers."""
    lines = []
    for line in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            break
        lines.append(re.sub(r"^\s*#\s?", "", line))
    return "\n".join(lines)


def _readme_docker_section() -> str:
    text = (ROOT / "readme.md").read_text(encoding="utf-8")
    match = re.search(r"^## Docker\n(.*?)(?=^## )", text, re.M | re.S)
    assert match, "readme.md has no '## Docker' section"
    return match.group(1)


def _commands(text: str) -> List[List[str]]:
    """Every ``docker run`` command in ``text`` (continuation lines joined), tokenised like a POSIX shell."""
    joined = re.sub(r"\\\n\s*", " ", text)
    out = []
    for line in joined.splitlines():
        start = line.find("docker run ")
        if start >= 0:
            out.append(shlex.split(line[start:]))
    return out


def _profile_recipe(text: str) -> List[str]:
    found = [cmd for cmd in _commands(text) if any(".aws:" in token for token in cmd)]
    assert len(found) == 1, found
    return found[0]


Recipe = Tuple[Tuple[Tuple[str, str], ...], Tuple[str, ...], Optional[str], Tuple[str, ...]]


def _normalise(cmd: List[str]) -> Recipe:
    """``(sorted value options, sorted switches, image, subcommand)`` with the placeholders made equal."""
    assert cmd[:2] == ["docker", "run"], cmd
    options, switches, rest = [], [], cmd[2:]
    while rest and rest[0].startswith("-"):
        flag = rest.pop(0)
        if flag in VALUE_FLAGS:
            value = rest.pop(0)
            if flag in ("-e", "--env") and value.startswith("AWS_PROFILE="):
                value = "AWS_PROFILE=<profile>"
            options.append((flag, value))
        else:
            switches.append(flag)
    image, args = (rest[0], rest[1:]) if rest else (None, [])
    args = ["<region>" if i > 0 and args[i - 1] == "--region" else a for i, a in enumerate(args)]
    return tuple(sorted(options)), tuple(sorted(switches)), image, tuple(args)


@pytest.mark.finding("F-160")
def test_dockerfile_profile_recipe_sets_a_neutral_home_and_mounts_read_only():
    header = _dockerfile_header()
    cmd = _profile_recipe(header)
    options, switches, _image, args = _normalise(cmd)
    pairs = dict(options)
    assert pairs.get("--user") == "$(id -u):$(id -g)"
    assert ("-e", "HOME=/aws-home") in options
    mounts = [value for flag, value in options if flag in ("-v", "--volume") and ".aws:" in value]
    assert mounts == ["$HOME/.aws:/aws-home/.aws:ro"], mounts
    assert ("-e", "AWS_PROFILE=<profile>") in options and ("-v", "$PWD/out:/reports") in options
    assert "--rm" in switches and args[:1] == ("collect",)
    assert "/home/app/.aws" not in header                      # the mount point HOME=/ makes unreachable
    for target in re.findall(r"\.aws:(\S+)", header):          # every ~/.aws mount in the comment is read-only
        assert target.rstrip('"').endswith(":ro"), target
    # The one-line reason for the neutral mount point is stated next to the recipe.
    assert "HOME=/" in header and "/home/app may be 0700" in header and "uid 10001" in header


@pytest.mark.finding("F-160")
def test_dockerfile_profile_recipe_matches_the_readme_docker_section():
    dockerfile = _normalise(_profile_recipe(_dockerfile_header()))
    readme = _normalise(_profile_recipe(_readme_docker_section()))
    assert dockerfile[0] == readme[0]                          # the same --user, HOME, mounts, profile, reports
    assert dockerfile[1] == readme[1]                          # the same switches (--rm)
    assert dockerfile[3] == readme[3]                          # the same subcommand: collect --region <region>
    assert dockerfile[2] == "<image>"
    assert readme[2] == f"aws-enumerator:{targets.runtime_module('_version').__version__}"


@pytest.mark.finding("F-160", "F-132")
def test_dockerfile_header_keeps_the_frontend_and_base_pinning_notes():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert text.splitlines()[0] == "# syntax=docker/dockerfile:1"   # a parser directive: must stay the first line
    header = _dockerfile_header()
    assert "floating major tag" in header and "RUN --mount" in header and "Pin it" in header
    assert "Bump it deliberately (tag + digest + date)" in header
    assert "RUN --mount=type=bind" in text                     # the instruction the frontend line is kept for
