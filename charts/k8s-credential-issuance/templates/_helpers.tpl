{{/* Expand the chart name. */}}
{{- define "kci.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Create a release-scoped name. */}}
{{- define "kci.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Chart label. */}}
{{- define "kci.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Component names are kept below the Kubernetes 63-character limit. */}}
{{- define "kci.componentName" -}}
{{- printf "%s-%s" (include "kci.fullname" .root) .component | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Common labels. */}}
{{- define "kci.labels" -}}
helm.sh/chart: {{ include "kci.chart" . }}
app.kubernetes.io/name: {{ include "kci.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels for a component. */}}
{{- define "kci.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kci.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/* Full pod labels for a component. */}}
{{- define "kci.componentLabels" -}}
{{ include "kci.labels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- with .root.Values.global.podLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/* Service account selection. */}}
{{- define "kci.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kci.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Image names follow the repositories built by .github/workflows/build-images.yml. */}}
{{- define "kci.image" -}}
{{- $defaultImages := dict "authority" "sa-authority" "signer" "sa-signer" "nodeAgent" "sa-node-agent" -}}
{{- $registry := trimSuffix "/" .root.Values.global.imageRegistry -}}
{{- $repository := printf "%s/%s" $registry (index $defaultImages .component) -}}
{{- if .image.repository }}
{{- $repository = .image.repository -}}
{{- end }}
{{- $tag := default .root.Chart.AppVersion .image.tag -}}
{{- printf "%s:%s" $repository $tag }}
{{- end }}

{{/* Endpoint helpers used when component endpoints are not overridden. */}}
{{- define "kci.authorityURL" -}}
{{- $scheme := ternary "https" "http" .Values.authority.tls.enabled -}}
{{- printf "%s://%s:%v" $scheme (include "kci.componentName" (dict "root" . "component" "authority")) .Values.authority.service.port }}
{{- end }}

{{- define "kci.signerURL" -}}
{{- $scheme := ternary "https" "http" .Values.signer.tls.enabled -}}
{{- printf "%s://%s:%v" $scheme (include "kci.componentName" (dict "root" . "component" "signer")) .Values.signer.service.port }}
{{- end }}

{{- define "kci.authorityEndpoint" -}}
{{- printf "%s/v1/grants" (include "kci.authorityURL" .) }}
{{- end }}

{{- define "kci.signerEndpoint" -}}
{{- printf "%s/v1/sign" (include "kci.signerURL" .) }}
{{- end }}

{{- define "kci.revocationEndpoint" -}}
{{- printf "%s/v1/grants/status" (include "kci.authorityURL" .) }}
{{- end }}

{{/* Secret names. A blank secretName means that the generated release name is used. */}}
{{- define "kci.authoritySigningKeySecretName" -}}
{{- default (printf "%s-authority-signing-key" (include "kci.fullname" .)) .Values.authority.signingKey.secretName }}
{{- end }}

{{- define "kci.signerKMSSecretName" -}}
{{- default (printf "%s-signer-kms" (include "kci.fullname" .)) .Values.signer.kms.authToken.secretName }}
{{- end }}

{{- define "kci.nodeIdentitySecretName" -}}
{{- default (printf "%s-node-identity" (include "kci.fullname" .)) .Values.nodeAgent.identityKey.secretName }}
{{- end }}

{{- define "kci.authorityTLSSecretName" -}}
{{- default (printf "%s-authority-tls" (include "kci.fullname" .)) .Values.authority.tls.secretName }}
{{- end }}

{{- define "kci.signerTLSSecretName" -}}
{{- default (printf "%s-signer-tls" (include "kci.fullname" .)) .Values.signer.tls.secretName }}
{{- end }}

{{- define "kci.nodeTLSSecretName" -}}
{{- default (printf "%s-node-agent-tls" (include "kci.fullname" .)) .Values.nodeAgent.tls.secretName }}
{{- end }}

{{/* JSON configuration emitted into the component ConfigMaps. */}}
{{- define "kci.authorityConfig" -}}
{{- $root := . -}}
{{- $config := dict
  "cluster_id" $root.Values.authority.config.cluster_id
  "issuer" $root.Values.authority.config.issuer
  "policy_version" $root.Values.authority.config.policy_version
  "grant_format" $root.Values.authority.config.grant_format
  "signing_key_id" $root.Values.authority.config.signing_key_id
  "signing_key_file" (printf "%s/%s" (trimSuffix "/" $root.Values.authority.signingKey.mountPath) $root.Values.authority.signingKey.key)
  "proof_replay_state_file" (printf "%s/proof-replay.json" (trimSuffix "/" $root.Values.authority.state.mountPath))
  "grant_ledger_file" (printf "%s/grants.json" (trimSuffix "/" $root.Values.authority.state.mountPath))
  "max_token_lifetime_seconds" $root.Values.authority.config.max_token_lifetime_seconds
  "registrations" (default (list) $root.Values.authority.config.registrations)
-}}
{{- toPrettyJson $config -}}
{{- end }}

{{- define "kci.signerConfig" -}}
{{- $root := . -}}
{{- $kmsTokenFile := "" -}}
{{- if eq (lower $root.Values.signer.kms.provider) "infisical" -}}
{{- $kmsTokenFile = printf "%s/%s" (trimSuffix "/" $root.Values.signer.kms.authToken.mountPath) $root.Values.signer.kms.authToken.key -}}
{{- end -}}
{{- $revocationEndpoint := default (include "kci.revocationEndpoint" $root) $root.Values.signer.config.revocation_endpoint -}}
{{- $config := dict
  "cluster_id" $root.Values.signer.config.cluster_id
  "issuer" $root.Values.signer.config.issuer
  "policy_version" $root.Values.signer.config.policy_version
  "eaa_keys" (default (dict) $root.Values.signer.config.eaa_keys)
  "kms_endpoint" $root.Values.signer.kms.endpoint
  "kms_provider" $root.Values.signer.kms.provider
  "kms_auth_token_file" $kmsTokenFile
  "revocation_endpoint" $revocationEndpoint
  "allow_legacy_token_grant" $root.Values.signer.config.allow_legacy_token_grant
  "ledger_state_file" (printf "%s/ledger.json" (trimSuffix "/" $root.Values.signer.state.mountPath))
  "max_token_lifetime_seconds" $root.Values.signer.config.max_token_lifetime_seconds
  "key_generations" (default (list) $root.Values.signer.config.key_generations)
  "local_key_files" (default (dict) $root.Values.signer.config.local_key_files)
-}}
{{- toPrettyJson $config -}}
{{- end }}

{{- define "kci.nodeAgentConfig" -}}
{{- $root := . -}}
{{- $authorityEndpoint := default (include "kci.authorityEndpoint" $root) $root.Values.nodeAgent.config.authority_endpoint -}}
{{- $signerEndpoint := default (include "kci.signerEndpoint" $root) $root.Values.nodeAgent.config.signer_endpoint -}}
{{- $config := dict
  "authority_endpoint" $authorityEndpoint
  "signer_endpoint" $signerEndpoint
  "identity" $root.Values.nodeAgent.config.identity
  "identity_key_file" (printf "%s/%s" (trimSuffix "/" $root.Values.nodeAgent.identityKey.mountPath) $root.Values.nodeAgent.identityKey.key)
  "attestation_endpoint" $root.Values.nodeAgent.config.attestation_endpoint
  "attestation_identity" $root.Values.nodeAgent.config.attestation_identity
  "attestation_public_key" $root.Values.nodeAgent.config.attestation_public_key
  "bindings" (default (dict) $root.Values.nodeAgent.config.bindings)
-}}
{{- toPrettyJson $config -}}
{{- end }}
