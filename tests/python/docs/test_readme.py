"""README accuracy tests (F-067, F-108, F-122, F-128, F-136, F-144, F-156, F-159, F-160, F-161, F-167, F-170, F-172).

The README must have its required sections, must not repeat the stale or over-claiming statements of the 0.2.x
README, must describe the install, Docker recipe, report layout and path model the code really has, and every
relative link and in-page anchor must resolve.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

import pytest

from aws_enumerator import cli, output
from aws_enumerator._version import __version__
from aws_enumerator.engine.graph import edge_types
from aws_enumerator.engine.writers import EXPORT_FORMATS
from aws_enumerator.engine.writers.legacy import LEGACY_OUTPUTS
from aws_enumerator.registry import get_registry

ROOT = Path(__file__).resolve().parents[3]
README = ROOT / "readme.md"

REQUIRED_SECTIONS = (
    "Authorized use only", "Install", "Docker", "Quick start", "Usage", "How paths work", "Known limitations",
    "Report layout", "Handling reports", "Required permissions", "OPSEC and detection footprint", "Screenshots",
    "Documentation",
)

#: (pattern, why it is wrong) - statements of the 0.2.x README (and over-claims) that must not come back.
BANNED = (
    (r"python3? app/main\.py", "the app/ package was renamed to aws_enumerator (no shim)"),
    (r"\bapp/(components|utils|main)", "the app/ tree no longer exists"),
    (r":latest\b", "never recommend the floating :latest image"),
    (r"/root/\.aws", "the image runs as a non-root user; never mount ~/.aws into /root"),
    (r"-v\s+~/\.aws:[^\s]*(?<!:ro)(\s|$)", "~/.aws must be mounted read-only"),
    (r"-e\s+AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)=", "never put credential values on the command line"),
    (r"(?mi)^\s*pip install boto3\s*$", "boto3 alone misses kubernetes (F-108, F-136)"),
    (r"(?i)safe to share", "reports are confidential"),
    (r"(?i)never (stores? )?secret values|contains? no secret", "over-claim: free text can still hold secrets"),
    (r"(?i)bloodhound for aws", "over-claim"),
    (r"(?i)default:?\s*`?eu-west-2", "there is no default region any more"),
    (r"reports/\{date\}", "the 0.2.x layout"),
    (r"(?i)SSRF = 3|cross-account = 4|direct access = 0", "the 0.2.x weight model"),
    (r"(?i)from every entity to every", "Discover starts from the owned nodes or the default sources"),
    (r"git\+https://github\.com/0xj4f/aws-enumerator\.git(?!@v\d)", "installs must be pinned to a release tag"),
    (r"(?m)^\s*pipx? install aws-enumerator\b", "the PyPI name is not this project's"),
)


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def _headings(text: str) -> List[str]:
    return [h.strip() for h in re.findall(r"^#{1,6}\s+(.+?)\s*$", text, flags=re.M)]


def _slug(heading: str) -> str:
    """GitHub's heading anchor: lower case, punctuation dropped, spaces to hyphens."""
    text = heading.lower().replace("`", "")
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def _section(text: str, title: str) -> str:
    part = text.split(f"\n## {title}\n", 1)[1]
    return part.split("\n## ", 1)[0]


@pytest.mark.finding("F-067", "F-159", "F-161", "F-172")
def test_required_sections_are_present():
    headings = set(_headings(_readme()))
    missing = [s for s in REQUIRED_SECTIONS if s not in headings]
    assert missing == []


@pytest.mark.finding("F-067", "F-108", "F-136", "F-156", "F-159", "F-160")
@pytest.mark.parametrize("pattern, reason", BANNED, ids=[b[1][:40] for b in BANNED])
def test_stale_or_over_claiming_statements_are_absent(pattern, reason):
    hits = [m.group(0) for m in re.finditer(pattern, _readme())]
    assert hits == [], reason


@pytest.mark.finding("F-122", "F-156")
def test_readme_version_equals_the_package_version():
    text = _readme()
    versions = set(re.findall(r"@v(\d+\.\d+\.\d+)", text))
    versions |= set(re.findall(r"--branch v(\d+\.\d+\.\d+)", text))
    versions |= set(re.findall(r"aws-enumerator:(\d+\.\d+\.\d+)", text))
    versions |= set(re.findall(r"current version is `(\d+\.\d+\.\d+)`", text))
    versions |= set(re.findall(r"# aws-enumerator (\d+\.\d+\.\d+)", text))
    versions |= set(re.findall(r"Version: `(\d+\.\d+\.\d+)`", text))
    assert versions == {__version__}


@pytest.mark.finding("F-156")
def test_every_install_from_git_is_pinned_to_the_release_tag():
    text = _readme()
    urls = re.findall(r"git\+https://github\.com/0xj4f/aws-enumerator\.git\S*", text)
    assert urls, "the README must show the pipx install"
    assert all(u.rstrip('"') == f"git+https://github.com/0xj4f/aws-enumerator.git@v{__version__}" for u in urls), urls
    clones = re.findall(r"git clone (\S+ \S+) https://github\.com/0xj4f/aws-enumerator\.git", text)
    assert clones and all(c == f"--branch v{__version__}" for c in clones), clones
    assert "not published on PyPI" in text


@pytest.mark.finding("F-108", "F-136")
def test_install_from_source_includes_kubernetes():
    text = _section(_readme(), "Install")
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert re.search(r"(?m)^kubernetes==", requirements)
    assert re.search(r"(?m)^boto3==", requirements)
    assert text.count("pip install --require-hashes -r requirements.txt") >= 2
    assert "python -m aws_enumerator collect" in text
    assert "dependency_missing" in text
    k8s_collector = (ROOT / "aws_enumerator" / "collectors" / "k8s.py").read_text(encoding="utf-8")
    assert "dependency_missing" in k8s_collector


@pytest.mark.finding("F-160", "F-128", "F-132")
def test_docker_recipe_matches_the_dockerfile():
    text = _section(_readme(), "Docker")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "USER 10001:10001" in dockerfile and "uid 10001" in text
    assert "AWS_ENUMERATOR_OUTPUT=/reports" in dockerfile and "/reports" in text
    assert 'ENTRYPOINT ["aws-enumerator"]' in dockerfile
    assert "VOLUME [\"/root/.aws\"" not in dockerfile
    mounts = re.findall(r'-v "?(\$HOME|~)/\.aws:(\S+?)"?(?=\s)', text)
    assert mounts and all(target.endswith(":ro") for _, target in mounts), mounts
    assert "--user \"$(id -u):$(id -g)\"" in text
    ports = re.findall(r"(?<![\w-])-p ([0-9.]+:\d+:\d+|\d+:\d+)", text)
    assert ports and all(p.startswith("127.0.0.1:") for p in ports), ports
    assert "dashboard --host 0.0.0.0 --no-browser" in text
    assert "--allowed-host" in text
    images = set(re.findall(r"(?<![\w/])aws-enumerator:([\w.-]+)", text))
    assert images == {__version__}
    assert "--env-file" in text and "env-no-export" in text
    assert "-e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY" in text  # by name only


@pytest.mark.finding("F-128")
def test_dashboard_host_allow_list_statement_matches_the_server():
    from aws_enumerator.dashboard import server

    exact, any_port = server.host_allow_list("0.0.0.0", 8000, ["127.0.0.1:9000", "localhost:9000"])
    assert ("127.0.0.1", "8000") in exact and ("localhost", "8000") in exact and ("::1", "8000") in exact
    assert ("127.0.0.1", "9000") in exact and not any_port
    assert ("127.0.0.1", "9000") not in server.host_allow_list("0.0.0.0", 8000)[0]
    assert "--allowed-host 127.0.0.1:9000 --allowed-host localhost:9000" in _readme()


@pytest.mark.finding("F-172")
def test_authorised_use_statement_matches_the_cli():
    section = _section(_readme(), "Authorized use only")
    assert cli.AUTHORIZED_USE in section
    assert "written authorisation" in section
    assert "EKS" in section and "--no-k8s" in section
    assert "docs/report-handling.md" in section


@pytest.mark.finding("F-144")
def test_name_note_distinguishes_the_unrelated_project():
    text = _readme()
    note = text.split("**Not the same project:**", 1)[1].split("\n\n", 1)[0]
    assert "unrelated" in note and "not published on PyPI" in note
    assert "aws_enumerator" in note


@pytest.mark.finding("F-067")
def test_positioning_does_not_over_claim():
    intro = _readme().split("## Contents", 1)[0]
    for phrase in ("Not an exploitation tool", "Not a compromise assessment", "Not a complete IAM simulator",
                   "not affiliated", "one AWS account"):
        assert phrase in intro, phrase


@pytest.mark.finding("F-067", "F-040", "F-043")
def test_traversal_class_table_matches_edge_types():
    section = _section(_readme(), "How paths work")
    rows = dict(re.findall(r"^\s*\| `([a-z]+)` \| (.+?) \|$", section, flags=re.M))
    assert rows == dict(edge_types.TRAVERSAL_CLASSES)


@pytest.mark.finding("F-067", "F-040")
def test_weight_examples_match_the_traversability_table():
    section = _section(_readme(), "How paths work")
    examples = re.findall(r"`([A-Z_]+)`(?: and `([A-Z_]+)`)? costs? (\d+(?:\.\d+)?)", section)
    assert len(examples) >= 5
    for first, second, weight in examples:
        for name in filter(None, (first, second)):
            entry = edge_types.EDGE_TYPES[name]
            assert entry.base_weight == float(weight), (name, entry.base_weight, weight)
            assert entry.may_traverse, name
    penalties = edge_types.CONDITIONAL_PENALTY
    assert f"+{penalties['weak']} for a weak condition" in section
    assert f"+{penalties['strong']} for a strong one" in section
    assert penalties["none"] == 0
    assert "`0` is a real cost of zero" in section
    for name in ("CAN_PASS_ROLE_TO", "CAN_TAKEOVER", "CAN_ESCALATE", "IS_ADMIN_EQUIVALENT"):
        assert name in edge_types.EDGE_TYPES and name in section


@pytest.mark.finding("F-067", "F-043")
def test_path_sources_and_targets_follow_the_graph_contract():
    section = _section(_readme(), "How paths work")
    assert "**owned**" in section and "default sources" in section and "operator" in section
    assert "account-admin" in section and "high-value" in section
    assert "Directed" in section and "attack direction" in section


@pytest.mark.finding("F-108")
def test_report_tree_lists_every_module_directory_and_analysis_file():
    section = _section(_readme(), "Report layout")
    tree = section.split("```", 2)[1]
    global_line = tree.split("global/", 1)[1].split("<region>/", 1)[0]
    regional_part = tree.split("<region>/", 1)[1].split("analysis/", 1)[0]
    for spec in get_registry():
        where = global_line if spec.scope == "global" else regional_part
        assert f"{spec.output_dir}/" in where, (spec.name, spec.output_dir)
    analysis_part = tree.split("analysis/", 1)[1]
    for name in ("graph.json", "findings.json", "summary.json", "diff.json", *LEGACY_OUTPUTS):
        assert name in analysis_part, name
    for name in ("manifest.json", "HANDLING.txt", "run.log", "SHA256SUMS", "<run_id>.zip", "merged/<run_id>/"):
        assert name in tree, name
    assert output.DEFAULT_OUTPUT in tree and output.OUTPUT_ENV in tree


@pytest.mark.finding("F-141", "F-165")
def test_export_formats_match_the_writers():
    text = _readme()
    listed = re.search(r"`export` formats are (.+?)\. Output", text, flags=re.S).group(1)
    assert set(re.findall(r"`([a-z]+)`", listed)) == set(EXPORT_FORMATS)


@pytest.mark.finding("F-170")
def test_user_agent_statement_matches_the_code():
    from aws_enumerator import aws_session

    section = _section(_readme(), "OPSEC and detection footprint")
    assert aws_session.default_ua_app_id("x-a1b2c3") == f"aws-enumerator/{__version__}/a1b2c3"
    assert "app/aws-enumerator-<version>-<last 6 characters of the run id>" in section
    assert "aws-enumerator/<version>/<run id tail>" in section
    assert "--ua-app-id" in section and "--no-ua-tag" in section and "AWS_SDK_UA_APP_ID" in section


@pytest.mark.finding("F-159", "F-161", "F-167", "F-170", "F-046")
def test_handling_permissions_and_detection_are_linked():
    text = _readme()
    for target in ("docs/report-handling.md", "docs/permissions.md", "docs/detection.md", "SECURITY.md",
                   "CONTRIBUTING.md", "CHANGELOG.md", "docs/attack_paths.md"):
        assert f"]({target}" in text, target
    assert "HANDLING.txt" in _section(text, "Handling reports")
    assert "--guardrail" in _section(text, "Required permissions")


@pytest.mark.finding("F-067", "F-014")
def test_known_limitations_disclose_the_evaluator_gaps():
    from aws_enumerator.engine.context import ALWAYS_GAPS

    section = _section(_readme(), "Known limitations")
    assert set(ALWAYS_GAPS) == {"external-identity", "runtime-conditions", "session-policies"}
    for fact in ("evaluation_gaps", "conditional", "session policies", "external principals", "org:scp-unknown",
                 "--scp-file", "merge", "compromise-assessment", "isolated browser profile", "aws-enumerator analyze"):
        assert fact in section, fact


@pytest.mark.finding("F-159", "F-161")
def test_relative_links_and_anchors_resolve():
    text = _readme()
    own_anchors = {_slug(h) for h in _headings(text)}
    problems = []
    for target in re.findall(r"\]\(([^)\s]+)\)", text):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        path, _, anchor = target.partition("#")
        if not path:
            if anchor not in own_anchors:
                problems.append(target)
            continue
        file = ROOT / path
        if not file.exists():
            problems.append(target)
        elif anchor and file.is_file():
            anchors = {_slug(h) for h in _headings(file.read_text(encoding="utf-8"))}
            if anchor not in anchors:
                problems.append(target)
    assert problems == []


def test_screenshots_are_referenced_by_their_fixed_names():
    text = _section(_readme(), "Screenshots")
    for name in ("docs/00.png", "docs/01.png", "docs/02.png", "docs/03.png"):
        assert f"]({name})" in text and (ROOT / name).is_file(), name
    assert "synthetic" in text
