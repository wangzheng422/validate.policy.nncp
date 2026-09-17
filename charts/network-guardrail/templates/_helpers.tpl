{{/* AI-Author: Codex (OpenAI model not exposed by runtime) */}}
{{- define "network-guardrail.labels" -}}
app.kubernetes.io/name: network-guardrail
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}
{{- define "network-guardrail.podSecurity" -}}
runAsNonRoot: true
seccompProfile:
  type: RuntimeDefault
{{- end }}
{{- define "network-guardrail.containerSecurity" -}}
allowPrivilegeEscalation: false
capabilities:
  drop: [ALL]
readOnlyRootFilesystem: true
{{- end }}
{{- define "network-guardrail.pullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
{{- define "network-guardrail.policyVersion" -}}
{{- $requested := .Values.policy.apiVersion -}}
{{- if not (has $requested (list "auto" "admissionregistration.k8s.io/v1beta1" "admissionregistration.k8s.io/v1")) -}}
{{- fail "policy.apiVersion must be auto, admissionregistration.k8s.io/v1beta1, or admissionregistration.k8s.io/v1" -}}
{{- end -}}
{{- if ne $requested "auto" -}}
{{- $requested -}}
{{- else -}}
{{- $stable := .Capabilities.APIVersions.Has "admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy" -}}
{{- $beta := .Capabilities.APIVersions.Has "admissionregistration.k8s.io/v1beta1/ValidatingAdmissionPolicy" -}}
{{- if and (or (eq $requested "auto") (eq $requested "admissionregistration.k8s.io/v1")) $stable -}}
admissionregistration.k8s.io/v1
{{- else if and (or (eq $requested "auto") (eq $requested "admissionregistration.k8s.io/v1beta1")) $beta -}}
admissionregistration.k8s.io/v1beta1
{{- else -}}
{{- fail "Requested ValidatingAdmissionPolicy API is not served. OCP 4.16 requires a non-default technology-preview feature gate; this chart never enables it. Verify a supported target, preferably OCP 4.17+. Offline rendering needs --api-versions admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy (or v1beta1)." -}}
{{- end -}}
{{- end -}}
{{- end }}
