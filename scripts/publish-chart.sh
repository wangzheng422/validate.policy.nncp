#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
helm_bin=${HELM_BIN:-helm}
version=$(python3 -c 'import yaml,sys; print(yaml.safe_load(open(sys.argv[1]))["version"])' "$root/charts/network-guardrail/Chart.yaml")
# Published versions are immutable; retain old archives and index entries.
test ! -e "$root/docs/network-guardrail-$version.tgz" || { echo 'Version already packaged; bump Chart.yaml first' >&2; exit 1; }
"$root/scripts/chart-package.sh" "$root/docs"
if [[ -f "$root/docs/index.yaml" ]]; then
  "$helm_bin" repo index "$root/docs" --url https://wangzheng422.github.io/validate.policy.nncp --merge "$root/docs/index.yaml"
else
  "$helm_bin" repo index "$root/docs" --url https://wangzheng422.github.io/validate.policy.nncp
fi
