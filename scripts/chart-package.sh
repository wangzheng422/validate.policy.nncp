#!/usr/bin/env bash
# AI-Author: Codex (OpenAI model not exposed by runtime)
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
helm_bin=${HELM_BIN:-helm}
output=${1:-/tmp/network-guardrail-packages}
"$root/scripts/chart-sync-policy.sh" --check
"$root/scripts/chart-validate.sh"
mkdir -p -- "$output"
"$helm_bin" package "$root/charts/network-guardrail" --destination "$output"
