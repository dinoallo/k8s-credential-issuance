# k8s-credential-issuance Helm chart

This chart deploys the three runnable components currently present in this
repository:

| Component | Kubernetes workload | Default endpoint |
| --- | --- | --- |
| `sa-authority` | single-replica Deployment and ClusterIP Service | `http://<release>-k8s-credential-issuance-authority:9441` |
| `sa-signer` | single-replica Deployment and ClusterIP Service | `http://<release>-k8s-credential-issuance-signer:9444` |
| `sa-node-agent` | DaemonSet with a node-local Unix socket | `/var/run/k8s-credential-issuance/sa-node-agent.sock` |

The chart is a deployment wrapper around the reference implementation. It
does not turn the file-backed ledgers into an HA store and does not provision
an attestation service, KMS, mTLS identities, or Kubernetes TokenProvider
integration automatically.

## Prerequisites

- Helm 3.12 or newer.
- A Kubernetes cluster supported by the chart's `kubeVersion` constraint.
- Container images published by the repository workflow, or overrides for the
  three image repositories.
- An Ed25519 authority signing key, a node-agent identity key for every node
  identity, and an Infisical KMS token for the normal signer path.

## Install

Create the required secrets outside the chart. Secret values are deliberately
not placed in the default `values.yaml` or generated ConfigMaps:

```bash
kubectl create namespace issuance
kubectl -n issuance create secret generic kci-authority-signing-key \
  --from-file=eaa-private-key.pem=./eaa-private-key.pem
kubectl -n issuance create secret generic kci-signer-kms \
  --from-file=token=./infisical-kms-token
kubectl -n issuance create secret generic kci-node-identity \
  --from-file=worker-1.pem=./worker-1.pem
```

Set the secret names and the real policy, registration, generation, KMS, and
attestation values in a private values file:

```yaml
authority:
  signingKey:
    secretName: kci-authority-signing-key
  config:
    cluster_id: cluster-1
    issuer: https://issuer.example
    policy_version: sa-policy-v1
    signing_key_id: eaa-2026-01
    registrations: []

signer:
  kms:
    endpoint: https://infisical.example
    authToken:
      secretName: kci-signer-kms
  config:
    eaa_keys:
      eaa-2026-01: REPLACE_BASE64URL_ED25519_PUBLIC_KEY
    key_generations:
      - generation: generation-1
        key_id: jwt-2026-01
        key_ref: REPLACE_INFISICAL_KMS_KEY_UUID
        public_key: REPLACE_BASE64_DER_PUBLIC_KEY
        algorithm: RS256
        state: Active

nodeAgent:
  identityKey:
    secretName: kci-node-identity
  config:
    identity: worker-1
    attestation_endpoint: https://attestor.example/v1/attest
    attestation_identity: node-attestor-1
    attestation_public_key: REPLACE_BASE64URL_ED25519_PUBLIC_KEY
```

Install or upgrade the release:

```bash
helm upgrade --install kci ./charts/k8s-credential-issuance \
  --namespace issuance --create-namespace \
  --values ./values-private.yaml
```

The chart also supports chart-managed Secrets for controlled test clusters:

```bash
helm upgrade --install kci ./charts/k8s-credential-issuance \
  --namespace issuance --create-namespace \
  --set authority.signingKey.create=true \
  --set-file authority.signingKey.value=./eaa-private-key.pem \
  --set signer.kms.authToken.create=true \
  --set-file signer.kms.authToken.value=./infisical-kms-token \
  --set nodeAgent.identityKey.create=true \
  --set-file nodeAgent.identityKey.value=./worker-1.pem
```

For production, enable TLS on the authority and signer, reference pre-created
`kubernetes.io/tls` Secrets, and ensure their certificates contain the
corresponding Service DNS names. The default HTTP listener is intended for
isolated development only. The node-agent defaults to a hostPath-backed Unix
socket; set `nodeAgent.socket.hostPath` to an approved node path and integrate
that path with the local Kubernetes component that consumes the socket.

## Configuration and scaling

- Authority and signer state are stored in separate PVCs by default. Keep
  both workloads at one replica while using the in-tree file stores; scaling
  them requires replacing those stores with transactional shared backends.
- `authority.config.registrations`, `signer.config.key_generations`, and
  `nodeAgent.config` map directly to the JSON configuration consumed by the
  binaries. The chart fills in mounted file paths and in-cluster service URLs.
- `signer.allowLocalKeyProvider` and `nodeAgent.allowStaticBindings` are
  development-only escape hatches and should remain disabled in production.
- The current source tree has no `ca-*` or `etcd-*` command binaries, so this
  chart does not create workloads for those planned components.

See the [ServiceAccount deployment reference](../../docs/deployment/sa-issuance.md)
for the protocol and trust-boundary requirements behind these settings.

## Verify the chart

```bash
helm lint ./charts/k8s-credential-issuance
helm template kci ./charts/k8s-credential-issuance --namespace issuance
```
