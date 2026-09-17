# Design and boundaries

AI-Author: Codex (OpenAI model not exposed by runtime)

## Separation of responsibility

The controller periodically reads Node/NNS and writes `PrimaryNetworkInventory/cluster` status plus a candidate ConfigMap. It has no permissions to create NNCP, edit VAP, or activate parameters. An administrator reviews the candidate and applies `NetworkGuardrailParameters/cluster`, either through the explicit Console control or through Kubernetes tooling. Helm owns the static VAP and optional binding. No controller-owned network configuration exists.

The Console plugin fetches evidence through the Console service proxy with `UserToken`. The backend uses that token for every resource read, dry-run request, explicit mode change and preflight-event write. Its own service account has no role bindings. Users require ordinary Kubernetes read permissions for inventory, parameters, candidate ConfigMap, VAP/binding and events; preflight also requires NNCP get plus create/update rights. The implementation does not impersonate cluster-admin.

Kubernetes RBAC cannot grant only dry-run create/update. The user already possessing NNCP write permission can use other clients to make real writes; this application's hardcoded dry-run path and lack of service-account write permission limit what this application can do. Native VAP protects direct clients when Deny mode is enabled.

## Discovery is observed evidence

Both directions of controller/dependency edges are traversed from default routes, observed InternalIP ownership and known OVN interfaces. Every observed route path is protected, including multiple default paths. The graph is not a claim about an unobserved switch or physical topology. Missing NNS, missing default routes and unresolved dependencies prevent a complete candidate. OVS logical bond ports are tracked without requiring fictitious interface objects.

Parameter revisions hash the semantic protected inventory, including node labels/roles. Timestamps/resource versions are evidence, not hash inputs. Observed profile names and alternative names join the protected set. The primary path diagram retains canonical interface names.

Candidates require manual review, so active parameters are a **snapshot**. Node-label changes, new aliases, new routes or topology changes after approval can make it stale. The UI compares revisions and exposes observation time; there is no claim of transactional live topology enforcement or automatic expiry. Re-review after changes. An outage of the controller leaves the last approved VAP/parameters in place. A stale snapshot can have safety implications, so this release is for controlled demonstrations, not unattended production enforcement.

## Conservative admission scope

All NNCP changes require one explicit known hostname and integer maxUnavailable=1. This intentionally narrows the earlier broad-worker proposal: a static parameter snapshot cannot safely authorize future nodes or arbitrary label selections. Protected interface names are unioned across all observed nodes, which may over-block heterogeneous secondary interfaces.

Unsupported paths include MAC-address identifiers, profile-name changes, wildcard interface names and capture templates. New VRFs, bridges, VLANs, bonds and controller attachments cannot consume a known protected interface. Dynamic DHCP/autoconf must turn off automatic route/gateway/DNS imports. Global OVS database edits and route rules are rejected wholesale.

These are bounded guardrails, not a full NMState semantic interpreter. A wrong DNS server, duplicate static IP, unsupported driver behavior, unobserved alias, external host mutation, or concurrent topology change can still cause an outage. `ALLOWED` means the target API server accepted that exact dry-run at that time. It is never labeled operationally safe. A real production rollout still needs canary validation and change control.

Admission does not re-evaluate previously persisted NNCPs, cannot undo changes already made, and cannot protect manual SSH/NetworkManager operations or a cluster administrator who removes/changes its VAP/binding/parameters. No historical-incident root cause is inferred from the design discussion's unavailable attachments.

## Preflight semantics

The backend rejects multiple documents, YAML aliases, duplicate mapping keys, other API groups/kinds, namespace and generateName. It GETs the candidate name using the user's token. A 404 causes POST; an existing object causes a replacement PUT with its current resourceVersion. Both writes force `dryRun=All&fieldValidation=Strict`. This intentionally tests replacement semantics, not kubectl server-side apply's merge/field-ownership behavior. Concurrent updates cause API errors requiring a fresh preflight.

Only a Kubernetes error containing this policy's name and a GR rule is presented as a guardrail denial. RBAC failures, API failures and schema errors are ERROR, not proof of protection. The policy binding can be disabled, so an accepted dry-run by itself never proves that the guardrails ran.

## Audit history

Version 0.2 also records genuine preflight VAP refusals as `source: preflight` using the caller identity. This is API response evidence, not host audit collection. Only DENIED responses produce these records; creation/retention failures are exposed separately without changing the original result. Records include the actual API audit ID when available. Outside-interface requests still require the optional collector to appear in history. See [UI controls](ui-controls.md).

The collector reads only kube-apiserver audit logs and accepts ResponseComplete NNCP create/update/patch entries containing this VAP's `validation_failure` annotation. It stores audit ID, time, user, source IPs/user agent, request identity, result and structured rule reasons. It discards request/response bodies and credentials. Audit-only failures remain `AUDIT`; `DENY` requires both a Deny action and a failing response status. Individual rule failures get deterministic IDs for deduplication.

History is **rejected/audited guardrail failures**, not a record of every accepted change and not a full desired configuration diff. Default Metadata audit cannot reconstruct the full NNCP. Empty history does not establish that the collector is working. OpenShift audit must actually be enabled; the chart does not modify its profile.

Complete-line checkpoints are stored in emptyDir. The collector drains an already-open rotated file, retries failed CR writes before advancing, and handles truncation. Pod replacement replays the current log, deduplicating events; rotations while stopped can lose records. Oversized malformed lines are skipped with a diagnostic. Retention deletes only this collector's labeled events in its namespace. This is bounded demonstration history, not a durable compliance log.

The optional collector needs host audit access. Its dedicated SCC allows UID0, SELinux spc_t and hostPath, with capabilities dropped and no privileged container. The **DaemonSet** specifies a read-only audit-directory mount. SCC has no allowedHostPaths restriction, so anyone allowed to create workloads under this SA has a broader trust boundary. Keep the namespace administrator-controlled. See [the Helm guide](helm.md) before enabling.

## Sources and compatibility

- [Kubernetes VAP](https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/) describes parameterized validation and Audit actions.
- [Kubernetes dry-run](https://kubernetes.io/docs/reference/using-api/api-concepts/#dry-run) guarantees non-persistence and admission execution for server dry-run.
- [Red Hat audit classification](https://developers.redhat.com/articles/2024/07/29/how-classify-red-hat-openshift-audit-logs) explains the default Metadata profile.
- [NMState MAC identifier](https://nmstate.io/features/mac_identifier.html) and [YAML API](https://nmstate.io/devel/yaml_api.html) describe the aliases and indirect network constructs covered by the conservative restrictions.
- [Compatibility research](compatibility-research.md) distinguishes admission CEL's dynamic preserved fields from CRD-schema CEL restrictions and records the OCP 4.16 feature-gate limitation.
