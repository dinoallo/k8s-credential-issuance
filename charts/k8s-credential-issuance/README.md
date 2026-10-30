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

## Split-cluster production deployment

The recommended production topology is to keep the issuance services in an
issuance cluster and run the node-agent DaemonSet in each workload cluster:

```text
workload cluster                         issuance cluster
sa-node-agent DaemonSet -- HTTPS -->     sa-authority Service
                                      \-> sa-signer Service
```

Use two Helm releases. The issuance-cluster values disable the DaemonSet:

```yaml
# values-issuance.yaml, applied in the issuance cluster
authority:
  enabled: true
  tls:
    enabled: true
    secretName: sa-authority-tls
  signingKey:
    secretName: sa-authority-signing-key

signer:
  enabled: true
  tls:
    enabled: true
    secretName: sa-signer-tls
  kms:
    authToken:
      secretName: sa-signer-kms

ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: HTTPS
  hosts:
    - host: sa-authority.issuance.example
      service: authority
      paths:
        - path: /
          pathType: Prefix
    - host: sa-signer.issuance.example
      service: signer
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: issuance-ingress-tls
      hosts:
        - sa-authority.issuance.example
        - sa-signer.issuance.example

nodeAgent:
  enabled: false
```

Install it in the issuance cluster after creating the authority signing-key,
signer KMS-token, and TLS Secrets there:

```bash
helm upgrade --install kci-issuance ./charts/k8s-credential-issuance \
  --namespace issuance --create-namespace \
  --values ./values-issuance.yaml
```

When `ingress.enabled` is true, the chart creates a standard
`networking.k8s.io/v1` Ingress that routes the authority and signer hosts to
their Services. An Ingress controller and the referenced TLS Secret must
already exist or be provided by the platform; the chart does not install an
Ingress controller or an IngressClass. The NGINX backend-protocol annotation
is required only when the backend Services use HTTPS; use the equivalent
annotation for another Ingress controller.

The workload-cluster values disable both server Deployments and override the
automatically generated in-cluster endpoints:

```yaml
# values-node-agent.yaml, applied in a workload cluster
authority:
  enabled: false

signer:
  enabled: false

nodeAgent:
  enabled: true
  config:
    authority_endpoint: https://sa-authority.issuance.example/v1/grants
    signer_endpoint: https://sa-signer.issuance.example/v1/sign
    identity: worker-1
    attestation_endpoint: https://attestor.workload.example/v1/attest
    attestation_identity: node-attestor-1
    attestation_public_key: REPLACE_BASE64URL_ED25519_PUBLIC_KEY
  identityKey:
    secretName: sa-node-identity
```

Install it in the workload cluster after creating the node identity Secret:

```bash
helm upgrade --install kci-node-agent ./charts/k8s-credential-issuance \
  --namespace kube-system \
  --values ./values-node-agent.yaml
```

For two namespaces in one cluster, the endpoints can use the issuance
Services' fully qualified names, for example
`https://kci-issuance-k8s-credential-issuance-authority.issuance.svc.cluster.local:9441/v1/grants`.
For separate clusters, ClusterIP Services and `*.svc.cluster.local` names are
not routable; publish stable private DNS names through an internal
LoadBalancer, Gateway, or equivalent network path and use those names in the
node-agent values. The chart does not create that cross-cluster network path.

The current binary and chart provide server-side TLS only. Client
certificates, custom CA bundles, and complete mTLS identity provisioning must
be supplied by the surrounding platform. Also note that one node-agent
DaemonSet currently mounts one configured `identity` and identity-key Secret
on every node; per-node identities require separate node pools/releases or an
additional node-local provisioning mechanism.

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
