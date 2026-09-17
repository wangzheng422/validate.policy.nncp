# Global interception, topology presentation and a refusal demo

AI-Author: Codex (OpenAI model not exposed by runtime)

## Operate from the Console

Open **Networking → Network Guardrail → Overview**. The mode shown is read from the actual Kubernetes binding. Review the discovered parameter YAML and revision, acknowledge the global scope, then choose **Deny** to block matching NNCP CREATE/UPDATE requests across the cluster. **Audit** permits requests while emitting VAP audit/warning information. **Disabled** removes this policy's binding. It does not undo previously applied node configuration or remove other policies.

The browser forwards your Console identity. The backend checks your Kubernetes permissions and uses that same identity for each resource write. Its service account has no binding/parameter/event mutation privileges. A stale binding or inventory revision requires a refresh and a new review. Changed parameters cannot be approved while this binding is active: disable first, review, then enable. The disable action remains available even if discovery is incomplete, subject to your delete permission.

The UI changes live Kubernetes objects; it does not edit Helm release values. A future Helm operation with an explicit mode can replace its Helm-managed binding state. A binding first created by this UI is not automatically part of Helm's release manifest. Check the actual UI state after upgrades and use the UI to disable before uninstalling. Do not infer the active state from `helm get values` alone.

## Try a real refusal without changing the network

1. Enable **Deny** after reviewing the ready snapshot.
2. Open **Preflight**, load the **protected primary interface removal** example and inspect its YAML. The target hostname and protected interface are derived from observed inventory.
3. Run the preflight. Every NNCP write uses `dryRun=All`; no NNCP is persisted or executed by NMState. After admission caches observe the new binding, the API should return a GR rule refusal.
4. The result shows the actual API status, refusal reason and audit ID when supplied. **View recorded event** opens History after a successful event write.
5. Try the DNS-only example as a positive admission comparison. It reuses observed resolver addresses. Admission acceptance still does not establish that a real network change is operationally safe.
6. Use **Disabled** to stop this global enforcement when finished.

The removal YAML is intentionally dangerous. Downloading it does not make it safe to apply: use the UI preflight or `oc create --dry-run=server -f example.yaml`. Keep the dry-run flag even after the expected denial; the binding can be disabled or changed independently.

## What the event proves

A History entry marked **Preflight API response** records an actual classified VAP refusal returned by the API server. It is stored as a `NetworkGuardrailEvent` custom resource using the caller's own create permission. Its timestamp is the recording time; its audit ID is the actual response header, never a generated stand-in. The verified caller name comes from Kubernetes SelfSubjectReview when available.

This source is separate from **API server audit log**, which requires the optional host collector. The collector remains disabled unless separately enabled by an authorized administrator. Requests made outside this preflight interface are not automatically collected while it is off. Neither source is a Kubernetes core `Event` stream, and an empty history proves neither absence of refusals nor collector health.

If recording or retention is forbidden, the refusal remains visible and the UI explains why history was not saved or pruned. Retention targets only this application's preflight-source records beyond the configured code limit of 500; it never deletes unrelated or audit-source records. Partial Kubernetes writes and uncertain transport outcomes require refresh rather than automatic retries.

## Present the observed topology

The topology endpoint reads inventory with your identity on every request, converts that snapshot into an Archify architecture specification, renders the real bundled Archify viewer and checks its output. The embedded view is a minimal diagram in a sandboxed, automatically sized frame. Select **Open full architecture** to open a separate full viewer with presentation, zoom/pan, themes and exports. The controls operate on the displayed snapshot.

The main diagram separates default-route dependencies from supporting OVN interfaces. Self-membership edges are omitted visually and retained in the raw evidence. Full interface names remain available. Trace animation illustrates relationships and is not live packet telemetry. Simplified Chinese and English use matching Archify viewer controls; Traditional Chinese diagram content uses the viewer's English control fallback.

The renderer supports at most 12 displayed components. Larger or invalid topology fails explicitly and leaves the raw evidence available. Node subprocesses are bounded in number and duration; rendering never grants a caller additional cluster permissions or sends topology to an external service.
