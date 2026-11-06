#!/usr/bin/env bash
# Collect several accounts in one go (example; F-066).
#
# Copy this file to multi-target.local.sh (*.local.sh is git-ignored and refused by the pre-commit hook),
# replace the placeholder profiles and regions with your authorised targets, and run it from anywhere.
# Reports go to ~/.aws-enumerator/reports/<account>/<run_id>/ (or $AWS_ENUMERATOR_OUTPUT), never into this
# repository. Authorized use only: run only against accounts you have written permission to assess.
#
# Exit codes of `aws-enumerator collect`: 0 complete, 2 partial (some modules denied/failed: the run is still
# usable, see manifest.json), 1 fatal, 64 usage, 130/143 interrupted.
set -euo pipefail

# profile|regions  (regions: one region, a comma-separated list, or "all")
TARGETS=(
  "example-audit-dev|eu-west-2"
  "example-audit-prod|eu-west-1,eu-west-2"
  "example-audit-shared|all"
)

failures=0
for target in "${TARGETS[@]}"; do
  profile="${target%%|*}"
  regions="${target#*|}"
  if [[ "${regions}" == "all" ]]; then
    region_args=(--all)
  else
    region_args=(--regions "${regions}")
  fi
  echo "== ${profile} (${regions})" >&2
  set +e
  run_root="$(aws-enumerator collect --profile "${profile}" "${region_args[@]}" --zip)"
  code=$?
  set -e
  case "${code}" in
    0) echo "   complete: ${run_root}" >&2 ;;
    2) echo "   partial (see ${run_root}/manifest.json coverage_summary): ${run_root}" >&2 ;;
    130|143) echo "   interrupted; stopping" >&2; exit "${code}" ;;
    *) echo "   failed with exit ${code}" >&2; failures=$((failures + 1)) ;;
  esac
done

if (( failures > 0 )); then
  echo "${failures} target(s) failed" >&2
  exit 1
fi
