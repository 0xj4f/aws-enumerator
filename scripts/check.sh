#!/usr/bin/env bash
# Local quality runner (no CI changes; .github/ is frozen by owner decision).
#
#   scripts/check.sh <target> [extra args passed to pytest]
#
# Targets:
#   setup     print (or with --yes run) the hash-locked dev install into .venv: requirements-dev.txt with
#             --require-hashes, then the project with --no-deps -e . (needs the network)
#   lint      ruff on the package, tests and scripts; node --check on dashboard JS
#   py        pytest -m "not perf and not golden" (the goldens are the `golden` target)
#   js        node --test tests/js
#   ui        the dashboard (frontend/, DECISIONS.md D-57, D-59): npm ci, Vitest, npm run build, then fail when
#             the committed build in aws_enumerator/dashboard/ differs from what the sources produce
#   e2e       Playwright against the built page and the real server (uses the installed Google Chrome;
#             E2E_REPORT=/path/to/run.zip adds a real report)
#   golden    pytest -m golden (tests/golden/v1 and tests/golden/collectors-v2)
#   docs      scripts/gen_docs.py --check (no-op until it exists)
#   perf      pytest -m perf (and PERF=1 node --test tests/js/perf when it exists)
#   findings  per-finding coverage (pytest --finding-report + node TAP + Vitest TAP); fails when a suite or the coverage
#             check fails. FINDINGS_REQUIRE_ALL=0 reports only (coverage gaps and test failures are printed)
#   scan      scripts/scan_sensitive.py
#   matrix    `py` and `golden` (pytest -m "not perf") in every .venvs/py3.1x that exists
#   doctor    offline environment check: .venv against requirements-dev.txt and the pyproject build requirement,
#             and local commits not on origin/main that add never-push paths (internal-docs/, docs/features.md,
#             reports, local files). Warnings only; --strict or DOCTOR_STRICT=1 makes a warning fail
#   all       doctor (advisory) then lint py js ui golden docs perf findings scan
#
# Exit status is non-zero when any step fails.
set -u -o pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
PY="$ROOT/.venv/bin/python"
RUFF="$ROOT/.venv/bin/ruff"
PYTEST=("$PY" -I -B -m pytest)

PKG="aws_enumerator"

say() { printf '\n==> %s\n' "$*"; }

need_python() {
  if [ ! -x "$PY" ]; then
    echo "missing $PY; create the venv (python3.10 -m venv .venv) and run: scripts/check.sh setup" >&2
    exit 2
  fi
}

js_test_dirs() {
  # node 20 searches directories recursively for *.test.js / test-*.js / *_test.js files
  [ -d tests/js ] && find tests/js -type f \( -name '*.test.js' -o -name '*.test.mjs' -o -name '*.test.cjs' \
      -o -name 'test-*.js' -o -name '*_test.js' -o -name '*-test.js' \) | grep -q .
}

t_setup() {
  # The hash-locked dev install (requirements-dev.txt pins pip and setuptools too), then the project itself
  # without resolving anything again. `pip install -e ".[dev]"` would resolve the [dev] ranges unhashed.
  local locked=("$PY" -m pip install --require-hashes -r requirements-dev.txt)
  local project=("$PY" -m pip install --no-deps -e .)
  if [ "${1:-}" = "--yes" ]; then
    need_python
    say "setup: ${locked[*]}"
    "${locked[@]}" || return 1
    say "setup: ${project[*]}"
    "${project[@]}"
  else
    echo "setup (needs network; run it yourself or: scripts/check.sh setup --yes):"
    echo "  ${locked[*]}"
    echo "  ${project[*]}"
  fi
}

t_lint() {
  need_python
  local rc=0
  say "lint: ruff check $PKG tests scripts"
  "$RUFF" check "$PKG" tests scripts || rc=1
  local js
  js=$(find "$PKG/dashboard" -name '*.js' -not -path '*/vendor/*' 2>/dev/null || true)
  if [ -n "$js" ]; then
    say "lint: node --check dashboard JS"
    while IFS= read -r f; do node --check "$f" || rc=1; done <<< "$js"
  fi
  if [ -d tests/js/static ]; then
    say "lint: node --test tests/js/static"
    node --test tests/js/static || rc=1
  fi
  return $rc
}

t_py() {
  need_python
  say "py: pytest -m 'not perf and not golden' $*"
  "${PYTEST[@]}" -m "not perf and not golden" "$@"
}

t_js() {
  if ! command -v node >/dev/null 2>&1; then echo "js: node not found" >&2; return 1; fi
  if ! js_test_dirs; then echo "js: no JS tests under tests/js yet (skipped)"; return 0; fi
  say "js: node --test tests/js"
  node --test tests/js
}

need_npm() {
  if ! command -v npm >/dev/null 2>&1; then echo "ui: npm not found (Node 20.17 or later)" >&2; return 1; fi
}

t_ui() {
  need_npm || return 1
  local rc=0
  say "ui: npm ci (frontend/)"
  (cd frontend && npm ci --no-audit --no-fund) || return 1
  say "ui: Vitest"
  (cd frontend && npx vitest run) || rc=1
  say "ui: npm run build (writes aws_enumerator/dashboard/)"
  (cd frontend && npx vite build) || return 1
  say "ui: the committed build matches the sources"
  if [ -n "$(git status --porcelain -- "$PKG/dashboard")" ]; then
    git status --short -- "$PKG/dashboard"
    echo "ui: aws_enumerator/dashboard/ differs from the build of frontend/: commit the new build" >&2
    rc=1
  fi
  return $rc
}

t_e2e() {
  need_npm || return 1
  [ -d frontend/node_modules ] || (cd frontend && npm ci --no-audit --no-fund) || return 1
  say "e2e: playwright test (frontend/e2e)"
  (cd frontend && npx playwright test "$@")
}

t_golden() {
  need_python
  say "golden: pytest -m golden $*"
  "${PYTEST[@]}" -m golden "$@"
}

t_docs() {
  if [ -f scripts/gen_docs.py ]; then
    need_python
    say "docs: scripts/gen_docs.py --check"
    "$PY" -I -B scripts/gen_docs.py --check && "${PYTEST[@]}" -q tests/python/docs "$@"
  else
    echo "docs: no-op (scripts/gen_docs.py does not exist yet)"
  fi
}

t_perf() {
  need_python
  local rc=0
  say "perf: pytest -m perf $*"
  "${PYTEST[@]}" -m perf "$@"
  local prc=$?
  # exit code 5 = no tests collected: fine while no perf tests exist
  if [ $prc -ne 0 ] && [ $prc -ne 5 ]; then rc=1; fi
  if [ -d tests/js/perf ]; then
    say "perf: PERF=1 node --test tests/js/perf"
    PERF=1 node --test tests/js/perf || rc=1
  fi
  return $rc
}

t_findings() {
  need_python
  local tmpd rc=0 prc nrc report_only=0
  [ "${FINDINGS_REQUIRE_ALL:-1}" = "0" ] && report_only=1
  tmpd="$(mktemp -d "${TMPDIR:-/tmp}/aws-enumerator-findings.XXXXXX")"
  say "findings: pytest --finding-report"
  "${PYTEST[@]}" -q -m "not perf" --finding-report "$tmpd/pytest.json" "$@" >"$tmpd/pytest.log" 2>&1
  prc=$?
  echo "pytest exit status: $prc (log: $tmpd/pytest.log)"
  if [ "$prc" -ne 0 ]; then
    tail -n 25 "$tmpd/pytest.log"
    [ "$report_only" -eq 1 ] || rc=1
  fi
  local taps=()
  if command -v node >/dev/null 2>&1 && js_test_dirs; then
    say "findings: node --test --test-reporter=tap tests/js"
    node --test --test-reporter=tap tests/js >"$tmpd/js.tap" 2>&1
    nrc=$?
    echo "node exit status: $nrc (TAP: $tmpd/js.tap)"
    if [ "$nrc" -ne 0 ]; then
      grep -E '^[[:space:]]*not ok' "$tmpd/js.tap" | head -n 25
      [ "$report_only" -eq 1 ] || rc=1
    fi
    taps=(--tap "$tmpd/js.tap")
  fi
  if command -v npm >/dev/null 2>&1 && [ -d frontend/node_modules ]; then
    say "findings: vitest run --reporter=tap (frontend/)"
    (cd frontend && npx vitest run --reporter=tap) >"$tmpd/vitest.tap" 2>&1
    local vrc=$?
    echo "vitest exit status: $vrc (TAP: $tmpd/vitest.tap)"
    if [ "$vrc" -ne 0 ]; then
      grep -E '^[[:space:]]*not ok' "$tmpd/vitest.tap" | head -n 25
      [ "$report_only" -eq 1 ] || rc=1
    fi
    taps+=(--tap "$tmpd/vitest.tap")
  fi
  local req=(--require-all)
  [ "$report_only" -eq 1 ] && req=()
  "$PY" -I -B scripts/finding_coverage.py --pytest-report "$tmpd/pytest.json" ${taps[@]+"${taps[@]}"} \
      ${req[@]+"${req[@]}"} --json "$tmpd/coverage.json" || rc=1
  echo "coverage JSON: $tmpd/coverage.json"
  if [ "$report_only" -eq 1 ] && { [ "$prc" -ne 0 ] || [ "${nrc:-0}" -ne 0 ]; }; then
    echo "findings: report only (FINDINGS_REQUIRE_ALL=0): pytest $prc, node ${nrc:-not run}; not failing the step"
  fi
  return $rc
}

t_scan() {
  need_python
  say "scan: scripts/scan_sensitive.py"
  "$PY" -I -B scripts/scan_sensitive.py
}

t_matrix() {
  local rc=0 found=0 v
  for v in "$ROOT"/.venvs/py3.1*/bin/python; do
    [ -x "$v" ] || continue
    found=1
    say "matrix: $v"
    "$v" -I -B -m pytest -m "not perf" "$@" || rc=1
  done
  [ $found -eq 1 ] || echo "matrix: no .venvs/py3.1x interpreters found (skipped)"
  return $rc
}

#: Paths that must never reach a remote, even through a commit that a later commit deletes them in.
NEVER_PUSH=(internal-docs docs/features.md tmp enum.sh reports out ':(glob)**/*.local.sh')

t_doctor() {
  # Offline and read-only: importlib.metadata for the venv, `git rev-parse` / `git log` for the history.
  # DOCTOR_LOCK / DOCTOR_PYPROJECT / DOCTOR_UPSTREAM override the inputs (tests use synthetic ones).
  need_python
  local strict="${DOCTOR_STRICT:-0}" warn=0 upstream="${DOCTOR_UPSTREAM:-origin/main}"
  [ "${1:-}" = "--strict" ] && strict=1
  local lock="${DOCTOR_LOCK:-requirements-dev.txt}" pyproject="${DOCTOR_PYPROJECT:-pyproject.toml}"
  say "doctor: .venv against $lock and the [build-system] requirement of $pyproject"
  "$PY" -I -B - "$lock" "$pyproject" <<'PYEOF' || warn=1
import re
import sys
from importlib import metadata

lock, pyproject = sys.argv[1], sys.argv[2]
try:
    from packaging.requirements import Requirement
    from packaging.version import InvalidVersion, Version
except ImportError:                      # a venv without packaging: compare the strings
    Requirement = None


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def same(a, b):
    if Requirement is None:
        return a == b
    try:
        return Version(a) == Version(b)
    except InvalidVersion:
        return a == b


installed = {}
for dist in metadata.distributions():
    if dist.metadata["Name"]:
        installed.setdefault(norm(dist.metadata["Name"]), dist.version)
pins = {}
with open(lock, encoding="utf-8") as fh:
    for line in fh:
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)", line)
        if match:
            pins[norm(match.group(1))] = match.group(2)
drift = [f"  {name}: lock {pin}, .venv {installed.get(name, 'missing')}"
         for name, pin in sorted(pins.items()) if not same(installed.get(name, ""), pin)]
problems = []
if drift:
    problems.append(f"{len(drift)} of {len(pins)} pins in {lock} differ or are missing:")
    problems.extend(drift)
with open(pyproject, encoding="utf-8") as fh:
    text = fh.read()
block = re.search(r"^\[build-system\][^\n]*\n(.*?)(?=^\[|\Z)", text, re.M | re.S)
requires = re.search(r"requires\s*=\s*\[(.*?)\]", block.group(1), re.S) if block else None
for raw in re.findall(r'"([^"]+)"', requires.group(1)) if requires else []:
    if Requirement is None:
        problems.append(f"build requirement {raw}: not checked (packaging is not installed)")
        continue
    req = Requirement(raw)
    have = installed.get(norm(req.name))
    if have is None:
        problems.append(f"build requirement {raw}: not installed")
    elif not req.specifier.contains(Version(have), prereleases=True):
        problems.append(f"build requirement {raw}: .venv has {have} (--no-build-isolation builds use it)")
for line in problems:
    print(line)
if problems:
    sys.exit(1)
print(f"doctor: .venv matches the {len(pins)} pins of {lock} and the build requirement")
PYEOF
  if [ "$warn" -ne 0 ]; then
    echo "doctor: resync with scripts/check.sh setup --yes (needs the network), which runs"
    echo "  .venv/bin/python -m pip install --require-hashes -r requirements-dev.txt"
    echo "  .venv/bin/python -m pip install --no-deps -e ."
  fi

  say "doctor: never-push paths in commits not on $upstream"
  if ! command -v git >/dev/null 2>&1 || ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "doctor: not a git work tree (history check skipped)"
  elif ! git rev-parse --verify -q "$upstream^{commit}" >/dev/null; then
    echo "doctor: $upstream not found (history check skipped)"
  else
    local spec commits count found=0
    for spec in "${NEVER_PUSH[@]}"; do
      # Names are counted, never printed: report paths can carry account ids.
      commits="$(git log --format=%h --diff-filter=d "$upstream..HEAD" -- "$spec" | tr '\n' ' ')"
      [ -n "${commits// /}" ] || continue
      count="$(git log --format= --name-only --diff-filter=d "$upstream..HEAD" -- "$spec" | sort -u | grep -c .)"
      echo "doctor: $spec: $count file(s) added or changed by $commits(not on $upstream)"
      found=1
    done
    if [ "$found" -eq 1 ]; then
      warn=1
      echo "doctor: drop or rewrite those commits before any push; a later deletion keeps the files in history"
    else
      echo "doctor: no never-push paths in $upstream..HEAD"
    fi
  fi
  if [ "$warn" -ne 0 ] && [ "$strict" = "1" ]; then
    echo "doctor: FAILED (--strict)" >&2
    return 1
  fi
  return 0
}

t_all() {
  local failed=() t
  # Advisory: doctor only warns, unless DOCTOR_STRICT=1 asks it to fail.
  t_doctor || failed+=("doctor")
  for t in lint py js ui golden docs perf findings scan; do
    "t_$t" || failed+=("$t")
  done
  if [ ${#failed[@]} -gt 0 ]; then
    say "FAILED: ${failed[*]}"
    return 1
  fi
  say "all targets passed"
}

target="${1:-}"
[ $# -gt 0 ] && shift
case "$target" in
  setup|lint|py|js|ui|e2e|golden|docs|perf|findings|scan|matrix|doctor|all) "t_$target" "$@" ;;
  *)
    awk 'NR > 1 && /^#/ { print; next } NR > 1 { exit }' "$0" | sed 's/^# \{0,1\}//'
    exit 64
    ;;
esac
