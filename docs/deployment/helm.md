# Helm deployment

The repository includes a reference Helm chart at
[`charts/k8s-credential-issuance`](../../charts/k8s-credential-issuance/). It
deploys the current `sa-authority`, `sa-signer`, and `sa-node-agent` command
binaries as Kubernetes workloads.

The chart README contains the install example, values layout, Secret
handling, TLS settings, node-agent socket integration, and the limitations of
the file-backed reference stores:

- [Chart README](../../charts/k8s-credential-issuance/README.md)
- [ServiceAccount deployment reference](./sa-issuance.md)

The chart intentionally does not claim HA or production readiness. Configure
the external KMS, attestation service, mTLS identities, durable audit path,
and transactional ledgers before using it beyond an isolated reference
environment.

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
   ```

   ```bash
   helm upgrade --install kci-issuance ./charts/k8s-credential-issuance \
     --namespace issuance --create-namespace \
     --values ./values-issuance.yaml
   ```

2. In each workload cluster, install only the node-agent and set explicit
   HTTPS endpoints for the external services:

   ```yaml
   authority:
     enabled: false
   signer:
     enabled: false
   nodeAgent:
     enabled: true
     config:
       authority_endpoint: https://sa-authority.issuance.example/v1/grants
       signer_endpoint: https://sa-signer.issuance.example/v1/sign
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
authority/signer Secrets in the issuance cluster and the node identity Secret
in each workload cluster. The current chart also uses one configured
node-agent identity and key for the whole DaemonSet; per-node identities need
additional provisioning or separate releases.

With `ingress.enabled: true`, the chart creates a standard
`networking.k8s.io/v1` Ingress for the authority and signer hosts. An Ingress
controller and the TLS Secret must be supplied by the cluster platform; the
chart does not install either one. Set the controller-specific backend
protocol annotation when the authority and signer Services use HTTPS.
