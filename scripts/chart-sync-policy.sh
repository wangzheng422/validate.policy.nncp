#!/usr/bin/env bash
# AI-Author: Codex (OpenAI model not exposed by runtime)
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source_policy="$root/policies/nncp-policy.yaml"
chart_policy="$root/charts/network-guardrail/files/nncp-policy.yaml"
if [[ ${1:-} == --check ]]; then
  cmp "$source_policy" "$chart_policy"
  printf 'Chart policy matches policies/nncp-policy.yaml\n'
elif [[ $# == 0 ]]; then
  cp "$source_policy" "$chart_policy"
  printf 'Synchronized chart policy from policies/nncp-policy.yaml\n'
else
  printf 'Usage: %s [--check]\n' "$0" >&2
  exit 2
fi
