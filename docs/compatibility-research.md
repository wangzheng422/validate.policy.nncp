<!-- AI-Author: Codex (OpenAI model not exposed by runtime) -->
# NNCP admission CEL compatibility research

Reviewed: 2026-09-16. This document records upstream source evidence and a local integration-test design. Source inspection alone is not evidence that a particular OpenShift cluster enables or enforces the policy.

## Findings

| Question | Result and primary evidence |
| --- | --- |
| Can VAP inspect the opaque NNCP `spec.desiredState`? | Yes in the Kubernetes 1.29 admission evaluator: `object` is declared dynamic and evaluated from an unstructured map. See [compiler declarations](https://github.com/kubernetes/kubernetes/blob/v1.29.0/staging/src/k8s.io/apiserver/pkg/admission/plugin/cel/compile.go#L225-L240) and [runtime conversion](https://github.com/kubernetes/kubernetes/blob/v1.29.0/staging/src/k8s.io/apiserver/pkg/admission/plugin/cel/filter.go#L107-L126). |
| Why do CRD CEL docs say preserved unknown fields are inaccessible? | That limitation concerns the schema-aware `x-kubernetes-validations` evaluator. Its [schema-aware value implementation](https://github.com/kubernetes/kubernetes/blob/v1.29.0/staging/src/k8s.io/apiserver/pkg/cel/common/values.go#L212-L236) represents inaccessible preserved values separately. It is not the raw-map conversion used by the VAP admission evaluator. |
| What does the NNCP CRD declare? | Both `v1` and `v1beta1` have `desiredState: {type: object, x-kubernetes-preserve-unknown-fields: true}` in the [version-pinned kubernetes-nmstate CRD](https://github.com/nmstate/kubernetes-nmstate/blob/v0.81.0/deploy/crds/nmstate.io_nodenetworkconfigurationpolicies.yaml). The installed operator's actual CRD remains the deployment authority. |
| Which VAP API should target Kubernetes 1.29? | `admissionregistration.k8s.io/v1beta1`. Upstream [1.29 integration tests](https://github.com/kubernetes/kubernetes/blob/v1.29.0/test/integration/apiserver/cel/validatingadmissionpolicy_test.go#L2068-L2193) use that API. The NNCP API `nmstate.io/v1` is a separate version choice. |
| Is VAP enabled by default in upstream Kubernetes 1.29? | No. It is beta and defaults to false in [the version-pinned feature definition](https://github.com/kubernetes/kubernetes/blob/v1.29.0/staging/src/k8s.io/apiserver/pkg/features/kube_features.go#L284-L290). |
| What about OCP 4.16? | The [OpenShift `release-4.16` feature definition](https://github.com/openshift/api/blob/release-4.16/features/features.go#L60-L65) enables `ValidatingAdmissionPolicy` in `DevPreviewNoUpgrade` and `TechPreviewNoUpgrade`. Do not assume default availability, or change the cluster feature set as part of a policy-only exercise. Check discovery and the cluster's enabled feature set first. |

## Hyphenated keys and schema type warnings

At admission runtime, access the original JSON map keys:

```cel
dyn(object.spec.desiredState)['dns-resolver']
route['next-hop-interface']
```

For optional map entries, check membership before indexing:

```cel
!('dns-resolver' in dyn(object.spec.desiredState))
```

The schema-aware escaped form `dns__dash__resolver` is not a replacement for the literal map key in this runtime path. In a dynamic unstructured map, `ds.dns__dash__resolver` requests the literal key `dns__dash__resolver`; it does not transform it into `dns-resolver`. This conclusion follows from the dynamic declaration and raw-map activation linked above. Test the distinction explicitly against the targeted API server.

VAP also has a separate schema-derived type checker. It resolves OpenAPI schemas with `common.SchemaDeclType`; consequently direct traversal into `desiredState` can produce an unknown-field warning even when the admission runtime can read it. The [type-checker source](https://github.com/kubernetes/kubernetes/blob/v1.29.0/staging/src/k8s.io/apiserver/pkg/admission/plugin/validatingadmissionpolicy/typechecking.go#L137-L203) explicitly separates these checks from policy behavior. A targeted `dyn(object.spec.desiredState)` expression makes the opaque subtree dynamic for static checking as well. Keep the outer, declared fields typed where possible.

When using a VAP variable, a suitable access pattern is:

```yaml
variables:
  - name: desiredState
    expression: >-
      has(object.spec) && has(object.spec.desiredState)
        ? dyn(object.spec.desiredState) : dyn({})
```

The empty-map fallback above is only an access convenience. Add a separate validation if `spec.desiredState` is required; do not let a missing field silently satisfy a policy that requires it. Opaque JSON can also contain wrong value types. Validate map/list/string types before traversal and use `failurePolicy: Fail` with a `Deny` binding for fail-closed enforcement. Examples in this section demonstrate field access, not a complete NNCP security policy.

## Evidence from upstream tests

The [Kubernetes 1.29 `TestCRDParams` integration test](https://github.com/kubernetes/kubernetes/blob/v1.29.0/test/integration/apiserver/cel/validatingadmissionpolicy_test.go#L2068-L2193) reads `params.spec.nameCheck` from a custom resource, tests both acceptance and rejection, and uses the [allow-all CRD fixture](https://github.com/kubernetes/kubernetes/blob/v1.29.0/test/integration/apiserver/cel/validatingadmissionpolicy_test.go#L2793-L2837). `params` and `object` use the same `objectToResolveVal` conversion. This is supporting evidence for opaque-map admission evaluation; it is not an NNCP-specific test or a hyphenated-key test.

The same upstream suite waits for an admission canary before asserting enforcement. Policy creation alone does not establish that caches have observed the policy and binding. A deny canary is also more useful than waiting for an empty `status.typeChecking`, particularly with a standalone API server and no status controller.

## Concrete local integration-test approach

An isolated real API-server test does not require worker nodes, an NMState operator, Docker, or Go. The official [controller-tools `envtest-v1.29.5` release](https://github.com/kubernetes-sigs/controller-tools/releases/tag/envtest-v1.29.5) provides Linux amd64 test binaries and a SHA-512 checksum asset. Download and verify the archive, then run its `etcd`, `kube-apiserver`, and `kubectl` locally.

1. Create a private temporary directory; use dedicated loopback ports, dedicated data directories, temporary credentials, and a cleanup trap. Never reuse a remote kubeconfig or an existing etcd data directory.
2. Start etcd bound only to loopback. Start the API server bound only to loopback, with its own serving and service-account keys and explicit local authentication. Enable `ValidatingAdmissionPolicy`, its admission plugin, and `admissionregistration.k8s.io/v1beta1` for this disposable server.
3. Register a minimal faithful NNCP CRD with the actual `desiredState` opaque-object schema. Prefer the installed/exported CRD when available. Do not install NMState controllers or create Nodes, so submitted policy objects cannot change host networking.
4. Create the VAP and binding, then poll a deliberately forbidden server-side dry-run NNCP until the API returns the expected policy denial. Restrict the poll timeout and fail if the expected denial does not arrive.
5. Submit permitted and forbidden cases with `dryRun=All`, recording exit status and full redacted API messages. Cover missing keys, wrong types, hyphenated keys, forbidden values, and allowed values. Assert policy-specific denial messages so API schema failures are not miscounted as policy enforcement.
6. Add a differential probe that reads `['dns-resolver']` and `.dns__dash__resolver` from an object containing only the hyphenated key. Add a route case for `['next-hop-interface']`. This directly establishes the syntax behavior instead of relying only on source inference.
7. Test both CREATE and UPDATE requests if both are in scope. UPDATE requires a seeded object and a dry-run update carrying its current resource version.
8. Stop only the subprocesses created by the test and retain a concise evidence report. A successful upstream API-server test validates CEL/admission behavior; it does not prove the feature is enabled or supported on the target OpenShift cluster.

Only source review and release-asset discovery were performed for this research document. Any actual local or cluster test results must be recorded separately with their observed version and commands.
