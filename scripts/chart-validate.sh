#!/usr/bin/env bash
# AI-Author: Codex (OpenAI model not exposed by runtime)
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
helm_bin=${HELM_BIN:-helm}
python_bin=${PYTHON_BIN:-python3}
work=$(mktemp -d /tmp/network-guardrail-chart.XXXXXX)
trap 'rm -rf -- "$work"' EXIT
"$root/scripts/chart-sync-policy.sh" --check
"$helm_bin" lint "$root/charts/network-guardrail" --strict --kube-version 1.29.0 --set policy.apiVersion=admissionregistration.k8s.io/v1beta1
for api in v1beta1 v1; do
  for mode in Disabled Audit Deny; do
    for collector in false true; do
      "$helm_bin" template network-guardrail "$root/charts/network-guardrail" \
        --namespace network-guardrail --include-crds \
        --api-versions "admissionregistration.k8s.io/$api/ValidatingAdmissionPolicy" \
        --set "policy.mode=$mode,collector.enabled=$collector" \
        > "$work/$api-$mode-$collector.yaml"
    done
  done
done
"$helm_bin" template network-guardrail "$root/charts/network-guardrail" \
  --namespace network-guardrail --api-versions admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy \
  --set plugin.enabled=false > "$work/no-plugin.yaml"
expect_failure() {
  local label=$1
  shift
  if "$helm_bin" template network-guardrail "$root/charts/network-guardrail" "$@" > "$work/rejected.yaml" 2> "$work/rejected.log"; then
    printf 'ERROR: expected chart rejection: %s\n' "$label" >&2
    exit 1
  fi
  printf 'Expected rejection (%s): ' "$label"
  sed -n '1p' "$work/rejected.log"
}
expect_failure missing-vap
expect_failure invalid-mode --api-versions admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy --set policy.mode=Allow
expect_failure invalid-version --set policy.apiVersion=v2
"$python_bin" - "$work" <<'PY'
import sys
from pathlib import Path
import yaml
root = Path(sys.argv[1])
for path in sorted(root.glob('v1*.yaml')):
    version, mode, collector = path.stem.split('-')
    docs = [d for d in yaml.safe_load_all(path.read_text()) if d]
    kinds = [d['kind'] for d in docs]
    assert 'NodeNetworkConfigurationPolicy' not in kinds, path
    assert 'NetworkGuardrailParameters' not in kinds, 'Active parameters must be reviewed, not chart managed'
    assert kinds.count('CustomResourceDefinition') == 3, path
    policies = [d for d in docs if d['kind'] == 'ValidatingAdmissionPolicy']
    assert len(policies) == 1 and policies[0]['metadata']['name'] == 'network-guardrail', path
    assert policies[0]['apiVersion'] == f'admissionregistration.k8s.io/{version}', path
    bindings = [d for d in docs if d['kind'] == 'ValidatingAdmissionPolicyBinding']
    assert len(bindings) == (mode != 'Disabled'), path
    if bindings:
        spec = bindings[0]['spec']
        assert spec['paramRef'] == {'name': 'cluster', 'parameterNotFoundAction': 'Deny'}, path
        assert spec['validationActions'] == (['Deny', 'Audit'] if mode == 'Deny' else ['Audit']), path
    for role in [d for d in docs if d['kind'] in ('Role', 'ClusterRole')]:
        for rule in role['rules']:
            resources, verbs = rule['resources'], rule['verbs']
            assert '*' not in resources and '*' not in verbs, path
            assert 'nodes/proxy' not in resources, path
            assert 'nodenetworkconfigurationpolicies' not in resources, path
            if 'networkguardrailparameters' in resources:
                assert set(verbs) <= {'get', 'list', 'watch'}, path
    for binding in [d for d in docs if d['kind'] in ('RoleBinding', 'ClusterRoleBinding')]:
        assert not any(s.get('name') == 'network-guardrail-api' for s in binding['subjects']), path
    plugin = next(d for d in docs if d['kind'] == 'ConsolePlugin')
    assert plugin['spec']['proxy'][0]['authorization'] == 'UserToken', path
    assert plugin['spec']['proxy'][0]['alias'] == 'api', path
    assert ('DaemonSet' in kinds) == (collector == 'true'), path
    assert ('SecurityContextConstraints' in kinds) == (collector == 'true'), path
    if collector == 'true':
        scc = next(d for d in docs if d['kind'] == 'SecurityContextConstraints')
        assert not scc['allowPrivilegedContainer'] and not scc['allowHostNetwork'], path
        assert scc['seLinuxContext'] == {'type': 'MustRunAs', 'seLinuxOptions': {'type': 'spc_t'}}, path
        assert 'allowedHostPaths' not in scc, 'SCC does not support allowedHostPaths'
        ds = next(d for d in docs if d['kind'] == 'DaemonSet')['spec']['template']['spec']
        mounts = ds['containers'][0]['volumeMounts']
        assert next(v for v in mounts if v['name'] == 'audit')['readOnly'], path
    print(f'PASS {path.name}: {len(docs)} resources, policy/RBAC/collector invariants')
no_plugin = [d for d in yaml.safe_load_all((root/'no-plugin.yaml').read_text()) if d]
assert not any(d['kind'] == 'ConsolePlugin' for d in no_plugin)
assert not any(d['kind'] == 'Deployment' and d['metadata']['name'] == 'network-guardrail-console' for d in no_plugin)
print('PASS plugin.enabled=false')
PY
