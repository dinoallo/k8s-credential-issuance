# Helm deployment

The repository includes a reference Helm chart at
[`charts/k8s-credential-issuance`](../../charts/k8s-credential-issuance/). It
deploys the current `sa-authority`, `sa-signer`, `sa-attestor`, and
`sa-node-agent` command binaries as Kubernetes workloads.

The chart README contains the install example, values layout, Secret
handling, TLS settings, node-agent socket integration, and the limitations of
the file-backed reference stores:

- [Chart README](../../charts/k8s-credential-issuance/README.md)
- [ServiceAccount deployment reference](./sa-issuance.md)

The chart intentionally does not claim HA or production readiness. Configure
the external KMS, mTLS identities, durable audit path, and transactional
ledgers before using it beyond an isolated reference environment. When
enabled, the attestor gets a dedicated ServiceAccount and only `get` access to
Pods and ServiceAccounts; its proof key and mTLS materials must still be
provisioned by the deployment platform.

## Authority signing-key Secret

Generate or provision the authority EAA Ed25519 private key once before the
issuance-cluster release is installed. The binary expects a PKCS#8 PEM file in
a Secret data entry named `eaa-private-key.pem`:

```bash
kubectl create namespace issuance
openssl genpkey -algorithm Ed25519 -out eaa-private-key.pem
chmod 600 eaa-private-key.pem
kubectl -n issuance create secret generic sa-authority-signing-key \
  --from-file=eaa-private-key.pem=./eaa-private-key.pem
```

Reference it explicitly:

```yaml
authority:
  signingKey:
    secretName: sa-authority-signing-key
    key: eaa-private-key.pem
```

Configure the matching public key in `signer.config.eaa_keys` under the same
`signing_key_id`, and keep the private key stable across upgrades. If
`authority.signingKey.secretName` is omitted, the chart references but does not
create a name derived from the release, such as
`kci-issuance-k8s-credential-issuance-authority-signing-key`. Keep private-key
creation outside Helm in production; the chart-managed `--set-file` path is
intended for controlled tests.

## Signer KMS token Secret

The normal signer configuration uses the Infisical provider. Provision the
Infisical bearer token separately and create a Secret whose data key is
`token`:

```bash
kubectl -n issuance create secret generic sa-signer-kms \
  --from-file=token=./infisical-kms-token
```

Reference it in the values file:

```yaml
signer:
  kms:
    provider: infisical
    authToken:
      secretName: sa-signer-kms
      key: token
```

If `signer.kms.authToken.secretName` is omitted, a release named `kci-issuance`
references but does not create
`kci-issuance-k8s-credential-issuance-signer-kms`. To use that default name,
create the Secret and omit `secretName` from the values file:

```bash
kubectl -n issuance create secret generic \
  kci-issuance-k8s-credential-issuance-signer-kms \
  --from-file=token=./infisical-kms-token
```

Keep this Secret outside Helm in production. The chart-managed `--set-file`
token option is for controlled tests; the generic `http` KMS provider does not
require an Infisical token Secret.

## Split-cluster production layout

For production, deploy the issuance services and node agents as separate Helm
releases:

1. In the issuance cluster, install authority and signer and disable the
   node-agent:

   ```yaml
   authority:
     enabled: true
   signer:
     enabled: true
   ingress:
     enabled: true
     className: nginx
     annotations:
       nginx.ingress.kubernetes.io/backend-protocol: HTTPS
   nodeAgent:
     enabled: false
   attestor:
     enabled: false
   ```

   ```bash
   helm upgrade --install kci-issuance ./charts/k8s-credential-issuance \
     --namespace issuance --create-namespace \
     --values ./values-issuance.yaml
   ```

2. In each workload cluster, install the node-agent and, if the attestor runs
   there, enable it with its Kubernetes API RBAC and mTLS Secrets:

   ```yaml
   authority:
     enabled: false
   signer:
     enabled: false
   attestor:
     enabled: true
     tls:
       enabled: true
       secretName: sa-attestor-tls
     attestorKey:
       secretName: sa-attestor-key
   nodeAgent:
     enabled: true
     attestationTLS:
       enabled: true
       secretName: sa-node-attestor-tls
     config:
       authority_endpoint: https://sa-authority.issuance.example/v1/grants
       signer_endpoint: https://sa-signer.issuance.example/v1/sign
       attestation_endpoint: https://kci-node-agent-k8s-credential-issuance-attestor:9445/v1/attest
   ```

   ```bash
   helm upgrade --install kci-node-agent ./charts/k8s-credential-issuance \
     --namespace kube-system \
     --values ./values-node-agent.yaml
   ```

The default endpoint helpers assume that all components share one release and
namespace. They must be overridden for separate releases. For a separate
cluster, expose the issuance services through an internal LoadBalancer,
Gateway, or equivalent private network path; ClusterIP and
`*.svc.cluster.local` addresses are not cross-cluster endpoints. Create the
authority/signer Secrets in the issuance cluster, attestor and node-agent
attestation Secrets in each workload cluster, and the node identity Secret in
each workload cluster. The current chart also uses one configured
node-agent identity and key for the whole DaemonSet; per-node identities need
additional provisioning or separate releases.

With `ingress.enabled: true`, the chart creates a standard
`networking.k8s.io/v1` Ingress for the authority and signer hosts. An Ingress
controller and the TLS Secret must be supplied by the cluster platform; the
chart does not install either one. Set the controller-specific backend
protocol annotation when the authority and signer Services use HTTPS.
