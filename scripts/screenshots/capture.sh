#!/usr/bin/env bash
# Regenerate the README screenshots docs/00.png, docs/01.png, docs/02.png and docs/03.png (F-134).
#
#   scripts/screenshots/capture.sh [capture.py options, e.g. --out-dir DIR --chrome PATH]
#
# 1. make_demo_report.py builds the synthetic run (placeholder accounts 111122223333 / 999999999999, demo-* names)
#    in a temporary directory outside the work tree, runs `aws-enumerator analyze` on it and zips it with
#    `aws-enumerator package`;
# 2. capture.py serves the real dashboard (`aws-enumerator dashboard --port 0 --no-browser`), opens the zip in
#    headless Google Chrome through the page's own file input and saves the three views.
#
# Offline: nothing talks to AWS, and Chrome runs with a throw-away profile and every non-loopback host blocked.
# Needs Google Chrome (default /Applications/Google Chrome.app; override with --chrome or $CHROME).
# Review the images before committing them (README.md in this directory has the checklist).
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || { echo "capture.sh: missing $PY (create the venv first)" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/aws-enumerator-shots.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

"$PY" -B "$ROOT/scripts/screenshots/make_demo_report.py" "$WORK/run" --zip >/dev/null
"$PY" -B "$ROOT/scripts/screenshots/capture.py" --zip "$WORK/run/demo-run.zip" --out-dir "$ROOT/docs" "$@"
