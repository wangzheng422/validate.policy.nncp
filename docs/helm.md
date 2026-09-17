# Helm installation and packaging

AI-Author: Codex (OpenAI model not exposed by runtime)

The chart installs one cluster-wide Network Guardrail instance. Fixed cluster resource names (`network-guardrail`, inventory/parameters `cluster`) intentionally prevent independent installations from defining competing admission behavior. Use a dedicated namespace, with administration restricted to trusted operators.

## Compatibility and images

OpenShift 4.16 uses Kubernetes 1.29, where ValidatingAdmissionPolicy is not enabled by default in OpenShift; it requires the non-default `TechPreviewNoUpgrade` feature set. This chart never changes feature gates. Prefer a supported OpenShift 4.17+ target, and verify the actual served APIs before installation. Do not enable a technology-preview feature set just to run this example on an existing cluster. See [OpenShift 4.16 feature gates](https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/nodes/working-with-clusters#nodes-cluster-enabling-features-about_nodes-cluster-enabling).

```bash
oc api-resources --api-group=admissionregistration.k8s.io
oc api-resources --api-group=nmstate.io
```

Both `ValidatingAdmissionPolicy` and `ValidatingAdmissionPolicyBinding`, and the Kubernetes NMState Operator's `NodeNetworkState` and `NodeNetworkConfigurationPolicy` APIs, must be served. With `policy.apiVersion=auto`, Helm discovery selects `admissionregistration.k8s.io/v1` first, then `v1beta1`, and refuses to render without a VAP API. An explicit full API version bypasses discovery for offline rendering; it does not enable that API on a cluster, and the API server rejects unsupported versions.

The public chart defaults to immutable Quay digests for the backend and Console plugin. These images support **linux/amd64** and can be pulled anonymously. Override `backend.image` and `plugin.image` only when using your own builds. Private registries may require `imagePullSecrets`; never put registry passwords in values files.

## Install with enforcement disabled

```bash
helm upgrade --install network-guardrail charts/network-guardrail \
  --namespace network-guardrail --create-namespace \
  --set policy.mode=Disabled
oc -n network-guardrail rollout status deployment/network-guardrail-controller
oc -n network-guardrail rollout status deployment/network-guardrail-api
oc -n network-guardrail rollout status deployment/network-guardrail-console
```

`Disabled` creates the admission policy without a binding. The chart never creates or modifies an NNCP, and never installs active `NetworkGuardrailParameters`. Discovery updates only the `PrimaryNetworkInventory/cluster` status and `network-guardrail-candidate` ConfigMap. An administrator must review and apply candidate parameters; later discovery does not silently modify the active protected interface set.

The controller has read-only access to nodes, NodeNetworkStates, CRDs, admission policies/bindings, active parameters, and events. Its only data writes are inventory and candidate ConfigMap. Kubernetes RBAC cannot limit `create` by resource name, so these two create grants are broader than the fixed names used by the application. The API service account has no role bindings. API requests use the console user's token, and NNCP preflight uses that user's permissions with `dryRun=All`; the API service account receives no NNCP create/update permission. `nodes/proxy` is never granted.

## Register and enable the console plugin

`plugin.enabled=true` deploys the static plugin service. `plugin.register=true` additionally creates `ConsolePlugin/network-guardrail`. Registration alone does not enable the plugin in the console operator. The chart deliberately leaves the existing plugin list untouched. The proxy is fixed to `/api/proxy/plugin/network-guardrail/api/`, forwards the caller's token with `authorization: UserToken`, and verifies service-serving HTTPS certificates using OpenShift's service CA. See [OpenShift console plugin service proxy](https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/web_console/dynamic-plugins).

To enable manually while preserving other plugins and detecting concurrent edits:

```bash
oc get console.operator.openshift.io cluster -o json > /tmp/network-guardrail-console.json
python3 - <<'PY'
import json
from pathlib import Path
console = json.loads(Path('/tmp/network-guardrail-console.json').read_text())
plugins = list(console.get('spec', {}).get('plugins', []))
if 'network-guardrail' not in plugins:
    plugins.append('network-guardrail')
patch = [
    {'op': 'test', 'path': '/metadata/resourceVersion', 'value': console['metadata']['resourceVersion']},
    {'op': 'add', 'path': '/spec/plugins', 'value': plugins},
]
Path('/tmp/network-guardrail-console-patch.json').write_text(json.dumps(patch))
PY
oc patch console.operator.openshift.io cluster --type=json \
  --patch-file=/tmp/network-guardrail-console-patch.json
```

A resource-version conflict requires reading the object again and regenerating the patch. Refresh the browser after the console rollout. Service certificates are generated into `network-guardrail-api-tls` and `network-guardrail-console-tls`; their private keys are mounted read-only and never embedded in Helm values.

## Review candidates, then Audit, then Deny

```bash
oc -n network-guardrail get configmap network-guardrail-candidate \
  -o jsonpath='{.data.parameters\.yaml}' > /tmp/network-guardrail-parameters.yaml
oc -n network-guardrail get configmap network-guardrail-candidate \
  -o jsonpath='{.data.policy\.yaml}' > /tmp/network-guardrail-policy.yaml
oc get primarynetworkinventory cluster -o yaml
cat /tmp/network-guardrail-parameters.yaml
cat /tmp/network-guardrail-policy.yaml
```

Compare each node, readiness result, primary interface, bond/bridge membership, and inventory warnings with the actual cluster. Preserve the candidate revision and reject incomplete inventories. Inspect the policy's match scope and validation logic. Only after that review:

```bash
oc apply --dry-run=server -f /tmp/network-guardrail-parameters.yaml
oc apply -f /tmp/network-guardrail-parameters.yaml
helm upgrade network-guardrail charts/network-guardrail \
  -n network-guardrail --set policy.mode=Audit
```

`Audit` creates a binding with `validationActions: [Audit]`; admission denials are not enforced. After reviewing representative safe and unsafe preflights and confirming complete parameters, switch to `--set policy.mode=Deny`, which binds `[Deny, Audit]`. Missing parameters use `parameterNotFoundAction: Deny`, and the policy uses `failurePolicy: Fail`. Under Deny, missing or unready parameters can block matching NNCP CREATE/UPDATE operations. Admission does not retroactively validate existing NNCP objects and does not protect mutations made outside the Kubernetes API.

Re-run discovery review and manually update parameters when node membership or primary network topology changes. Helm upgrades do not own or overwrite active parameters.

## Optional audit collector

`collector.enabled=false` is the default. If enabled, one collector runs per control-plane node selected by `node-role.kubernetes.io/master`, reads `/var/log/kube-apiserver/audit.log` from a read-only host mount, and stores a restart-local cursor under `/var/lib/guardrail` in an `emptyDir`. Restarts can replay retained log records; retention is bounded by `collector.eventLimit`, not durable log storage. Rotations and API-server audit profiles affect which evidence is available; absence of a captured event is not proof that an action did not occur.

The collector has its own service account with only namespaced event create/list/delete permissions. Its dedicated SCC requires UID 0 and SELinux `spc_t` for reading control-plane audit logs, while dropping every Linux capability and forbidding privileged mode, privilege escalation, host network/PID/IPC, and writable root filesystems. The only supplied host mount is the read-only audit directory. **OpenShift SCC has no `allowedHostPaths` field**, so the SCC does not itself constrain the host directory or mount read-only flag. Access to deploy or alter workloads using this service account must remain restricted to trusted administrators; it is not equivalent to granting a broadly privileged SCC. Review the [SCC API](https://docs.redhat.com/en/documentation/openshift_container_platform/4.16/html/security_apis/securitycontextconstraints-security-openshift-io-v1) and validate host file permissions/SELinux on the target before enabling. Audit logs may contain sensitive request metadata; the collector persists only the normalized event fields accepted by the backend.

```bash
helm upgrade network-guardrail charts/network-guardrail \
  -n network-guardrail \
  --set policy.mode=Audit,collector.enabled=true
```

## Upgrade, disable, and uninstall

Helm installs files under `crds/` only on initial installation; it does not upgrade or delete these CRDs. Review CRD schema changes and export existing objects before an upgrade, then apply reviewed CRD changes explicitly before `helm upgrade`:

```bash
oc diff -f charts/network-guardrail/crds/
oc apply -f charts/network-guardrail/crds/
```

`oc diff` returns exit code 1 when changes exist. Deleting a CRD deletes all its stored custom resources, so CRD removal is a separate destructive operation and is not part of chart uninstall.

For a Helm-managed binding, upgrading with `--set policy.mode=Disabled` and the same image values removes that binding. For a UI-created binding, use the Console Disable action and verify actual state; Helm values alone do not remove an object outside its release manifest. For an emergency, a cluster administrator can remove only `ValidatingAdmissionPolicyBinding/network-guardrail`, then reconcile Helm back to Disabled. Before uninstalling, remove only `network-guardrail` from the console operator plugin list, using the resource-version checked procedure above with list filtering. Then run `helm uninstall network-guardrail -n network-guardrail`. CRDs and manually approved parameters remain; document that residual state before any later reinstall.

## Local validation and packaging

These commands need Helm 3 and Python 3 with PyYAML. They do not access a cluster or publish anything:

```bash
scripts/chart-sync-policy.sh
scripts/chart-validate.sh
scripts/chart-package.sh /tmp/network-guardrail-packages
```

Set `HELM_BIN` to an absolute Helm path if needed. The sync script copies the canonical policy into the chart; `--check` verifies exact byte equality. Validation checks Helm lint against Kubernetes 1.29, all twelve API version/mode/collector combinations, rejection of invalid settings and absent API discovery, console token forwarding, no NNCP resources or grants, absence of chart-owned active parameters, and collector isolation. Packaging revalidates and creates only a local `.tgz`. Local render tests do not prove CRD/API acceptance, certificate issuance, SCC admission, caller permissions, audit collection, or admission behavior on an OpenShift cluster.

## Console controls introduced in 0.2

The [UI guide](ui-controls.md) explains reviewed global mode changes, live examples and preflight-source events. The API still has no service-account write privileges: the Console caller must possess binding create/update/delete, parameter create/update when approving a changed snapshot, event create and optional list/delete for retention, and SelfSubjectAccessReview/SelfSubjectReview access. DNS-only examples additionally read NodeNetworkState. The interface reports capability checks; Kubernetes authorizes every actual write.

UI-created bindings carry a `guardrail.openshift.io/managed-by: console-user` annotation and do not update Helm values or release manifests. Existing Helm metadata is preserved when the UI changes a Helm-managed binding. Before uninstalling, disable in the UI and confirm `oc get validatingadmissionpolicybinding network-guardrail --ignore-not-found` is empty; Helm alone may not delete an independently UI-created binding. Explicit Helm modes and later UI changes can override one another, so verify live state after each operation.

The backend image now includes a digest-pinned official UBI Node runtime and a small licensed Archify runtime subset. Node's matching OpenSSL libraries are isolated to its subprocess; Python TLS continues to use the original base libraries. Diagram requests remain caller-authorized, local to the pod, concurrency-limited and timeout-bounded. No additional service, internet diagram API or RBAC grants are installed.
