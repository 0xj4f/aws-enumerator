"""Accuracy tests for SECURITY.md, CONTRIBUTING.md, CHANGELOG.md and docs/report-handling.md
(F-161, F-159, F-123, F-066, F-122, F-144, F-172).

Each statement these pages make about the code (the read-only exceptions, the CSP and server controls, the
classification string, file modes, encryption and signature tools, the redaction fields, the version) is checked
against the code that implements it, so the pages fail a test when the code moves.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

import pytest

from aws_enumerator import archive, output, permissions
from aws_enumerator._version import __version__
from aws_enumerator.dashboard import server

ROOT = Path(__file__).resolve().parents[3]
PAGES = ("SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md", "docs/report-handling.md", "docs/detection.md")
PLACEHOLDER_ACCOUNTS = {"123456789012", "111122223333", "999999999999", "000000000000"}

#: Over-claims and stale statements that must not appear on these pages: (pattern, reason, pages exempted).
#: CHANGELOG.md may name what 0.3.0 removed.
BANNED = (
    (r"(?i)safe to share", "reports are confidential (F-159)", ()),
    (r"(?i)never (stores? )?secret values|contains? no secrets?\b", "over-claim: free text can hold secrets", ()),
    (r"-v\s+~/\.aws:/root/\.aws", "the 0.2.x Docker recipe (F-160)", ()),
    (r":latest\b", "never recommend a floating image tag (F-160)", ()),
    (r"python3? app/main\.py", "the app/ package is gone", ("CHANGELOG.md",)),
    (r"-e\s+AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)=", "credential values on a command line", ()),
)


def _text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _headings(text: str) -> List[str]:
    return [h.strip() for h in re.findall(r"^#{1,6}\s+(.+?)\s*$", text, flags=re.M)]


def _slug(heading: str) -> str:
    text = re.sub(r"[^\w\- ]", "", heading.lower().replace("`", ""))
    return text.replace(" ", "-")


def _section(text: str, title: str) -> str:
    return text.split(f"\n## {title}\n", 1)[1].split("\n## ", 1)[0]


# ── every page ───────────────────────────────────────────────────────────────
@pytest.mark.finding("F-159", "F-160", "F-161")
@pytest.mark.parametrize("rel", PAGES)
def test_no_over_claims_or_stale_recipes(rel):
    text = _text(rel)
    hits = [(reason, m.group(0)) for pattern, reason, exempt in BANNED if rel not in exempt
            for m in re.finditer(pattern, text)]
    assert hits == []


@pytest.mark.finding("F-161", "F-066")
@pytest.mark.parametrize("rel", PAGES)
def test_pages_hold_only_placeholder_identifiers(rel):
    text = _text(rel)
    accounts = set(re.findall(r"(?<![\d.])\d{12}(?!\d)", text))
    assert accounts <= PLACEHOLDER_ACCOUNTS, accounts
    emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)
    assert all(e.endswith(("example.com", "example.org", "example.net")) for e in emails), emails


@pytest.mark.finding("F-159", "F-161")
@pytest.mark.parametrize("rel", PAGES)
def test_relative_links_and_anchors_resolve(rel):
    page = ROOT / rel
    text = page.read_text(encoding="utf-8")
    own = {_slug(h) for h in _headings(text)}
    problems = []
    for target in re.findall(r"\]\(([^)\s]+)\)", text):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        path, _, anchor = target.partition("#")
        if not path:
            if anchor not in own:
                problems.append(target)
            continue
        file = (page.parent / path).resolve()
        if not file.exists():
            problems.append(target)
        elif anchor and file.is_file() and anchor not in {_slug(h) for h in _headings(file.read_text("utf-8"))}:
            problems.append(target)
    assert problems == []


# ── SECURITY.md ──────────────────────────────────────────────────────────────
@pytest.mark.finding("F-161")
def test_security_policy_sections_and_disclosure_channel():
    text = _text("SECURITY.md")
    for title in ("Reporting a vulnerability", "Supported versions", "Scope", "Read-only design", "Data handling",
                  "Dashboard threat model", "Supply chain"):
        assert title in _headings(text), title
    assert "https://github.com/0xj4f/aws-enumerator/security/advisories/new" in text
    contact = re.search(r"^- \*\*Alternative contact:\*\* (.+)$", text, flags=re.M)
    assert contact and contact.group(1).strip(), "a private contact line is required"
    # Until the owner enables private vulnerability reporting and picks a contact, the page must say so; once the
    # placeholder is replaced, the maintainer note goes too.
    placeholder = "SECURITY-CONTACT-TO-BE-SET-BY-THE-MAINTAINER" in contact.group(1)
    assert placeholder == ("Maintainer action required" in text)
    if placeholder:
        assert "Private vulnerability reporting" in text
    major_minor = ".".join(__version__.split(".")[:2])
    assert f"| {major_minor}.x | yes" in text


@pytest.mark.finding("F-161", "F-167")
def test_security_read_only_exceptions_match_the_code():
    from tests.support.fakeaws import READ_ONLY_OPERATIONS

    section = _section(_text("SECURITY.md"), "Read-only design")
    for api in READ_ONLY_OPERATIONS:
        assert f"`{api}`" in section, api
    for action in permissions.SIMULATE_ACTIONS:
        assert f"`{action}`" in section, action
    assert "selfsubjectrulesreviews" in section and "--no-k8s-self-review" in section
    assert "--no-credential-report" in section and "--guardrail" in section
    assert "test_every_aws_call_is_read_only" in section
    golden = _text("tests/python/collectors/test_collectors_v2_golden.py")
    assert "def test_every_aws_call_is_read_only" in golden
    assert {"secretsmanager:GetSecretValue", "s3:GetObject"} <= set(permissions.GUARDRAIL_DENY)


@pytest.mark.finding("F-161", "F-128", "F-139", "F-008", "F-089")
def test_dashboard_threat_model_matches_the_server_and_page():
    section = _section(_text("SECURITY.md"), "Dashboard threat model")
    quoted = re.search(r"`(default-src [^`]+?); \.\.\.`", section).group(1)
    assert server.CONTENT_SECURITY_POLICY.startswith(quoted)
    assert "frame-ancestors" in server.HEADER_CONTENT_SECURITY_POLICY and "frame-ancestors" in section
    assert server.SECURITY_HEADERS["Referrer-Policy"] == "no-referrer" and "no-referrer" in section
    assert "connect-src 'none'" in server.CONTENT_SECURITY_POLICY and "form-action 'none'" in section
    assert server.LOOPBACK_HOSTS == {"127.0.0.1", "localhost", "::1"}
    assert "`127.0.0.1`, `localhost`, `[::1]`" in section and "`421`" in section
    assert server.serve_dashboard.__defaults__[0] == "127.0.0.1" and "binds `127.0.0.1` by default" in section
    vendor = _text("frontend/vendor/VENDOR.md")
    assert "JSZip" in vendor and "frontend/vendor/VENDOR.md" in section and "frontend/package-lock.json" in section
    assert '"lockfileVersion"' in _text("frontend/package-lock.json")
    card = _text("frontend/src/ui/FindingCard.vue")
    assert 'rel="noopener noreferrer"' in card and "noopener noreferrer" in section
    index = _text("aws_enumerator/dashboard/index.html")
    assert 'integrity="sha384-' in index and "js/app.js" in index


# ── docs/report-handling.md ──────────────────────────────────────────────────
@pytest.mark.finding("F-159")
def test_report_handling_classification_and_notice_match_the_code():
    text = _text("docs/report-handling.md")
    assert f'"classification": "{output.CLASSIFICATION}"' in text
    assert "HANDLING.txt" in text and "CONFIDENTIAL" in output.HANDLING_TEMPLATE
    for title in ("Classification", "What a report contains", "What is deliberately left out", "File modes on disk",
                  "Integrity: digests and `verify`", "Encryption and signatures",
                  "Operator identity and `--redact-identity`", "Sharing and viewing", "Retention and deletion"):
        assert title in _headings(text), title


@pytest.mark.finding("F-123", "F-168")
def test_report_handling_modes_encryption_and_verify_match_the_code():
    text = _text("docs/report-handling.md")
    assert "`umask 077`" in text and "`0700`" in text and "`0600`" in text
    assert set(archive.ENCRYPT_TOOLS) == {"age", "gpg"} and set(archive.SIGN_TOOLS) == {"gpg", "minisign"}
    source = _text("aws_enumerator/archive.py")
    for ext in (".age", ".gpg", ".asc", ".minisig"):
        assert f'"{ext}"' in source, ext
        assert f"`{ext}`" in text or f".zip{ext}`" in text, ext
    assert "The plain zip is removed after a successful encryption" in source
    integrity = _text("aws_enumerator/integrity.py")
    for word in ("OK ", "MISMATCH", "MISSING", "UNLISTED"):
        assert word in integrity and word.strip() in text, word
    assert "shasum -a 256 -c SHA256SUMS" in text


@pytest.mark.finding("F-123", "F-146")
def test_report_handling_redaction_matches_the_manifest_contract():
    import json

    text = _section(_text("docs/report-handling.md"), "Operator identity and `--redact-identity`")
    schema = json.loads(_text("aws_enumerator/schemas/manifest-2.0.schema.json"))
    operator = json.dumps(schema)
    for field in ("caller_arn", "caller_user_id", "principal_arn", "caller_arn_sha256"):
        assert field in operator, field
        assert f"`{field}`" in text or f"operator.{field}" in text, field
    assert "run.operator.arn" in text and "`<redacted>`" in text


@pytest.mark.finding("F-009", "F-054", "F-112", "F-159")
def test_report_handling_exclusions_match_the_collectors():
    text = _section(_text("docs/report-handling.md"), "What is deliberately left out")
    checks = {
        "collectors/lambda_.py": "EnvironmentVariableNames",
        "collectors/cloudfront.py": "<redacted>",
        "collectors/route53.py": "ValuesOmitted",
        "collectors/k8s.py": "PartialObjectMetadataList",
        "collectors/eks.py": "configurationValuesPresent",
        "collectors/ec2.py": "UserDataSha256",
        "k8s/projections.py": "last-applied-configuration",
    }
    for rel, needle in checks.items():
        assert needle in _text(f"aws_enumerator/{rel}"), (rel, needle)
    for fact in ("--full-dns", "--keep-sensitive-metadata", "--k8s-secrets", "--ec2-userdata-check",
                 "`\"<redacted>\"`", "`PartialObjectMetadataList`"):
        assert fact in text, fact
    assert "Free text is copied as it is" in text


# ── CHANGELOG.md ─────────────────────────────────────────────────────────────
@pytest.mark.finding("F-122", "F-133")
def test_changelog_top_release_is_the_package_version():
    text = _text("CHANGELOG.md")
    releases = re.findall(r"^## (\d+\.\d+\.\d+)\b", text, flags=re.M)
    assert releases and releases[0] == __version__
    breaking = text.split("### Breaking changes", 1)[1].split("\n### ", 1)[0]
    for fact in ("`aws_enumerator`", "subcommands", output.DEFAULT_OUTPUT, "graph.json", "Directed paths",
                 "--no-k8s", "Exit codes", "--allow-in-repo"):
        assert fact in breaking, fact


# ── CONTRIBUTING.md ──────────────────────────────────────────────────────────
@pytest.mark.finding("F-066", "F-161")
def test_contributing_rules_and_recipe_match_the_code():
    from aws_enumerator.engine import pipeline
    from aws_enumerator.engine.io.loaders import LOADER_MODULES

    text = _text("CONTRIBUTING.md")
    for title in ("Project rules", "Development setup", "Architecture", "Adding an AWS service", "Tests"):
        assert title in _headings(text), title
    rules = _section(text, "Project rules")
    for fact in ("Read-only", "Synthetic data only", "Deception-neutral", "*.local.sh", *sorted(PLACEHOLDER_ACCOUNTS)):
        assert fact in rules, fact
    recipe = _section(text, "Adding an AWS service")
    for fact in ("SPEC = CollectorSpec(", "def collect(ctx)", "ANALYZER_MODULES", "LOADER_MODULES", "edge_types.py",
                 "FINDINGS", "ANALYZERS"):
        assert fact in recipe, fact
    assert "aws_enumerator.engine.analyzers.s3" in pipeline.ANALYZER_MODULES and "s3" in LOADER_MODULES
    assert "pip install --require-hashes -r requirements-dev.txt" in text and "pip install --no-deps -e ." in text
    assert "scripts/hooks/gitleaks.toml" in text and (ROOT / "scripts/hooks/gitleaks.toml").is_file()


@pytest.mark.finding("F-065")
def test_contributing_check_targets_and_test_dirs_exist():
    text = _text("CONTRIBUTING.md")
    check = _text("scripts/check.sh")
    for target in re.findall(r"^\| `([a-z]+)` \|", _section(text, "Development setup"), flags=re.M):
        assert re.search(rf"^t_{target}\(\)", check, flags=re.M) or target == "all", target
    for rel in sorted(set(re.findall(r"`(tests/[a-z0-9_/]+)/`", text))):
        assert (ROOT / rel).is_dir(), rel
    for rel in ("tests/support/fakeaws.py", "tests/conftest.py", "tests/fixtures/graph/build_fixtures.py",
                "tests/fixtures/graph/path_cases.json", "tests/golden/CHANGES.d"):
        assert rel in text and (ROOT / rel).exists(), rel


@pytest.mark.finding("F-066")
def test_contributing_tells_contributors_to_stage_explicit_paths_and_check_a_push():
    """Untracked owner files can sit in the work tree unignored, so `git add .` / `git add docs/` is never safe."""
    section = _section(_text("CONTRIBUTING.md"), "Committing and pushing")
    flat = " ".join(section.split())
    for fact in ("git status --short", "`git add -- <path> ...`",
                 "Never run `git add .`, `git add -A` or `git add docs/`",
                 "`.gitignore` does not list every one of them", "git log --stat origin/main..HEAD",
                 "before the first push", "leaves them in history"):
        assert fact in flat, fact
    # the example of local-only material is a path the repository really ignores
    assert "`internal-docs/`" in flat and re.search(r"(?m)^/internal-docs/$", _text(".gitignore"))


@pytest.mark.finding("F-132", "F-122")
def test_contributing_build_and_release_checks_match_the_build_files():
    text = _text("CONTRIBUTING.md")
    setup = " ".join(_section(text, "Development setup").split())
    # the build requirement quoted is pyproject's, and the tools named are in the dev lock
    requires = re.search(r"(?m)^requires = \[([^\]]*)\]", _text("pyproject.toml")).group(1)
    floor = re.search(r'"setuptools>=(\d+)(?:\.0)*"', requires).group(1)
    assert f"`setuptools>={floor}`" in setup
    lock = _text("requirements-dev.txt")
    for pin in ("pip", "setuptools", "build"):
        assert re.search(rf"(?m)^{pin}==", lock), pin
    assert "`pip` and `setuptools` included" in setup
    assert "pip install --require-hashes -r requirements-dev.txt" in setup
    assert "--no-build-isolation" in _text("tests/python/cli/test_wheel_contents.py")
    assert "`python -m build --no-isolation` checks that requirement" in setup
    releases = _section(text, "Releases")
    for fact in ("aws_enumerator/_version.py", "`ARG VERSION`", "fresh clone", "python -m build --outdir dist/",
                 "'/readme.md$'", "'^# aws-enumerator'", "MANIFEST.in", "docker build", "hadolint Dockerfile",
                 "`PYTHON_IMAGE`", "`# syntax=`", "floating tag"):
        assert fact in releases, fact
    # the facts the checks rely on
    assert _text("readme.md").splitlines()[0] == "# aws-enumerator"  # what the METADATA grep looks for
    assert re.search(r'(?m)^readme = "readme\.md"$', _text("pyproject.toml"))
    dockerfile = _text("Dockerfile")
    assert dockerfile.startswith("# syntax=")
    assert re.search(r"(?m)^ARG PYTHON_IMAGE=\S+@sha256:[0-9a-f]{64}$", dockerfile)
    assert re.search(rf"(?m)^ARG VERSION={re.escape(__version__)}$", dockerfile)
