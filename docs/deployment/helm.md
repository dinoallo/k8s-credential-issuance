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
