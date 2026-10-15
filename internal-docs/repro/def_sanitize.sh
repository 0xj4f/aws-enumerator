#!/usr/bin/env bash
# usage: sanitize.sh reports/<date>/<account>/<region>
set -euo pipefail; REP="$1"; LAC='kubectl.kubernetes.io/last-applied-configuration'
inplace() { local f="$1"; shift; if [ -e "$f" ]; then jq "$@" "$f" > "$f.tmp" && mv "$f.tmp" "$f"; fi; }
for f in "$REP"/k8s/*/secrets.json; do inplace "$f" --arg k "$LAC" \
  'if type=="array" then map(.annotations |= ((. // {}) | del(.[$k]))) else . end'; done
for f in "$REP"/k8s/*/*.json; do inplace "$f" --arg k "$LAC" \
  'if type=="array" then map(if type=="object" and .metadata then del(.metadata.annotations[$k], .metadata.managed_fields) else . end) else . end'; done
for f in "$REP"/k8s/*/pods.json; do inplace "$f" \
  'if type=="array" then map(.spec |= (if .==null then . else reduce ("containers","init_containers","ephemeral_containers") as $c (.;
     if .[$c] then .[$c] |= map(if .env then .env |= map(del(.value)) else . end) else . end) end)) else . end'; done
inplace "$REP/cloudfront/distributions.json" \
  'walk(if type=="object" and has("HeaderValue") then .HeaderValue="REDACTED" else . end)'
