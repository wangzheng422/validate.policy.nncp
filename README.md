# OpenShift Network Guardrail

Discover the primary network path, review protected interfaces, and guard NNCP changes with Kubernetes ValidatingAdmissionPolicy. Includes an OpenShift Console plugin, server-side dry-run preflight, and an installable Helm chart.

[Helm repository](https://wangzheng422.github.io/validate.policy.nncp/) · [Installation guide](docs/helm.md) · [UI guide](docs/ui-controls.md) · [Design and limits](docs/design.md)

## Install from GitHub Pages

Requires cluster-administrator permissions, Kubernetes NMState Operator, and served `ValidatingAdmissionPolicy` / `ValidatingAdmissionPolicyBinding` APIs. Prefer OpenShift 4.17+ and verify actual API availability; OpenShift 4.16 has a non-default feature-gate limitation. The published images support **linux/amd64**.

```bash
helm repo add network-guardrail https://wangzheng422.github.io/validate.policy.nncp/
helm repo update
helm upgrade --install network-guardrail network-guardrail/network-guardrail \
  --version 0.2.1 --namespace network-guardrail --create-namespace
```

The chart uses public Quay images pinned by digest. No registry login is required. Enforcement and the optional privileged audit collector are **disabled by default**. One installation per cluster is supported. Enable the Console plugin after installation using the [instructions that preserve existing plugins](docs/helm.md#register-and-enable-the-console-plugin).

## Add to the OpenShift Helm catalog

Apply the provided repository registration as a cluster administrator:

```bash
oc apply -f https://wangzheng422.github.io/validate.policy.nncp/helm-repository.yaml
```

This registers the catalog source; it does not install the application or enable enforcement. Select **Network Guardrail** in the Console Helm catalog, then review installation values. Installing cluster-scoped resources still requires administrator permissions.

## What it does

- Discovers observed default routes, bridges, bonds, VLANs and interface dependencies.
- Presents a clean embedded topology and a separate full Archify viewer.
- Enables reviewed global Audit or Deny controls using the Console caller's permissions.
- Uses native admission policies for NNCP CREATE/UPDATE checks.
- Runs NNCP examples through server-side dry-run, without applying node-network changes.
- Records rejected preflight attempts separately from optional host audit evidence.

This is a demonstration project, not an OpenShift-supported product. An accepted dry-run does not prove a network change is operationally safe. Review [security boundaries and limitations](docs/design.md) before enabling enforcement.

## Build and test

```bash
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -v
node topology/test-runtime.mjs
(cd console-plugin && npm ci --ignore-scripts && npm run typecheck && npm run build)
bash scripts/chart-validate.sh
```

Topology tests use an explicitly synthetic fixture. Optional real admission integration tests use an isolated loopback API server and etcd; provide checksum-verified envtest binaries to `python3 scripts/test-admission.py --binaries /path/to/envtest`.

```bash
podman build -t YOUR_REGISTRY/network-guardrail:dev -f Containerfile .
podman build -t YOUR_REGISTRY/network-guardrail-console:dev \
  -f console-plugin/Containerfile console-plugin
```

## Publish a chart update

Increment `charts/network-guardrail/Chart.yaml` for each changed release, then run:

```bash
bash scripts/publish-chart.sh
```

Commit the chart, new versioned package and updated index. GitHub Pages serves `main:/docs`; old chart packages stay available. CI tests the source and chart on push and pull requests.

## Source and third-party notices

Application source, build definitions and tests are included. Credentials, environment access files, private Git history, operational captures and process records are excluded. This repository does not declare a project-wide open-source license; public source visibility does not override dependency licenses. Bundled Archify and its assets retain their [license](topology/vendor/archify/LICENSE), [third-party notices](topology/vendor/archify/THIRD_PARTY_NOTICES.md) and font license.
