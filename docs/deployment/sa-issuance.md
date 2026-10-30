# ServiceAccount issuance reference deployment

This repository contains a reference SA path for the frozen `issuance/v1`
contract. It is suitable for local integration and security-contract tests;
the file-backed stores and the attestation service are not an HA production
deployment. The node-agent's signed remote-attestation resolver is implemented,
but its attestor and deployment controls remain environment-specific.

## Processes and trust boundaries

```text
sa-node-agent --(worker proof)--> sa-authority --(Grant adapter)--> sa-signer
       |                                                               |
       +-- local Unix socket / TokenProvider API                         +-- constrained KMS
```

Build the three independently deployed processes with:

```bash
go build ./cmd/sa-authority ./cmd/sa-signer ./cmd/sa-node-agent
```

The authority owns the EAA private key and the registration/Grant ledger. The
signer receives only configured EAA public keys and a KMS adapter. The
node-agent owns the worker identity key and must not receive a Kubernetes
administrator credential.

## Configuration

All paths are resolved relative to the configuration file. The following
fields are the minimum shape; values shown as `REPLACE_*` are not usable
secrets.

Authority (`sa-authority`):

```json
{
  "cluster_id": "cluster-1",
  "issuer": "https://issuer.example",
  "policy_version": "sa-policy-v1",
  "grant_format": "compact-jws",
  "signing_key_id": "eaa-2026-01",
  "signing_key_file": "secrets/eaa-private-key.pem",
  "proof_replay_state_file": "state/proof-replay.json",
  "grant_ledger_file": "state/grants.json",
  "max_token_lifetime_seconds": 3600,
  "registrations": [
    {
      "registration_id": "registration-1",
      "identity": "worker-1",
      "identity_public_key": "REPLACE_BASE64URL_ED25519_PUBLIC_KEY",
      "cluster_id": "cluster-1",
      "service_account_namespace": "default",
      "service_account_name": "reader",
      "service_account_uid": "sa-uid-1",
      "pod_uid": "pod-uid-1",
      "issuer": "https://issuer.example",
      "allowed_audiences": ["api"],
      "max_token_lifetime_seconds": 3600,
      "token_generation": "generation-1",
      "key_id": "jwt-2026-01",
      "policy_version": "sa-policy-v1",
      "active": true
    }
  ]
}
```

Signer (`sa-signer`):

```json
{
  "cluster_id": "cluster-1",
  "issuer": "https://issuer.example",
  "policy_version": "sa-policy-v1",
  "allow_legacy_token_grant": false,
  "eaa_keys": {
    "eaa-2026-01": "REPLACE_BASE64URL_ED25519_PUBLIC_KEY"
  },
  "kms_provider": "infisical",
  "kms_endpoint": "https://infisical.example",
  "kms_auth_token_file": "secrets/infisical-kms-token",
  "revocation_endpoint": "https://authority.example/v1/grants/status",
  "ledger_state_file": "state/signer-ledger.json",
  "key_generations": [
    {
      "generation": "generation-1",
      "key_id": "jwt-2026-01",
      "key_ref": "REPLACE_INFISICAL_KMS_KEY_UUID",
      "public_key": "REPLACE_BASE64_DER_PUBLIC_KEY",
      "algorithm": "RS256",
      "state": "Active"
    }
  ],
  "max_token_lifetime_seconds": 3600
}
```

`kms_endpoint` is required for the normal signer process. Set
`kms_provider` to `infisical` to use the native Infisical KMS API; the
default/`http` value retains the generic constrained HTTP adapter. For the
Infisical provider, `kms_auth_token_file` is a signer-local bearer-token file
and must not be stored in Kubernetes control-plane objects or committed to
the repository. Each `key_ref` must be the Infisical KMS key UUID, while
`key_id` remains the issuance/JWT public identifier.

Infisical keys used by the signer must be enabled, `sign-verify`, and
non-exportable. The adapter assembles the JWT header and payload locally,
submits only the JWS signing input to Infisical, and verifies the returned
signature against Infisical's public key. The same adapter boundary can be
used by the CA and etcd X.509 signers: those signers build the leaf and
intermediate chain locally and delegate only the intermediate certificate
signature.

When the signer token is limited to the `Cryptographic Operator` role, each
generation must include the public key material returned by Infisical's
`public-key` endpoint in `public_key` (base64 DER or PEM). This keeps runtime
operation to the signing API; the adapter will not perform management reads.
The Project Admin role is appropriate only for test key lifecycle and
provisioning.

The `--allow-local-key-provider` flag and `local_key_files` are development-only
and intentionally keep an exportable private key in the signer process. They
must not be used for a production deployment.

Node-agent (`sa-node-agent`):

```json
{
  "authority_endpoint": "https://authority.example/v1/grants",
  "signer_endpoint": "https://signer.example/v1/sign",
  "identity": "worker-1",
  "identity_key_file": "secrets/worker-1.pem",
  "attestation_endpoint": "https://attestor.example/v1/attest",
  "attestation_identity": "node-attestor-1",
  "attestation_public_key": "REPLACE_BASE64URL_ED25519_PUBLIC_KEY"
}
```

Production configuration requires the attestation endpoint, its pinned
Ed25519 identity, and the corresponding public key. The resolver sends the
worker identity, namespace/name, complete Kubernetes TokenRequest, and a fresh
nonce; it accepts only a response whose canonical request digest matches and
whose binding proof verifies with the pinned attestor key. The response must
provide immutable ServiceAccount UID, Pod UID, audience, issuer, and token
generation values.

The old `bindings` map is retained only for development and bootstrap tests.
To use it, omit the attestation fields and pass
`--allow-static-bindings` explicitly. Without that flag, the node-agent refuses
to start rather than silently selecting a static resolver.

Default listeners are loopback for the authority and signer and
`unix:///var/run/sa-node-agent.sock` for the node-agent. A non-loopback TCP
listener requires `--tls-cert-file` and `--tls-key-file`; the Unix socket is
created with mode `0600`. These flags establish server-side TLS. Mutual TLS,
service-identity provisioning, HA ledgers, durable audit storage, and KMS
recovery are additional deployment controls and are not supplied by the
file-backed reference configuration.

## Protocol boundary

The endpoint and JSON field shapes remain recognizable to the existing SA
direct path. `issuance/v1` Compact JWS is the default: the authority uses
`grant_format=compact-jws` (or omits the field), and the signer keeps
`allow_legacy_token_grant=false`. In this mode the common core verifies only
the typed Compact JWS contract.

For a migration with the old API-server carrier, set the authority's
`grant_format` to `legacy-token-grant` and the signer's
`allow_legacy_token_grant` to `true`. The authority then returns the old
canonical JSON `TokenGrant` object, and the signer accepts it without requiring
the new `X-Issuance-Identity` header. The SA adapter verifies the old
`ed25519-v1:<key-id>:<signature>` envelope, preserves its binding digest
semantics, and converts it to a typed Grant before entering the common core
pipeline. The node-agent `/v1/token` compatibility envelope returns the
Kubernetes-shaped `status.token` and `status.expirationTimestamp` fields.

The legacy mode is explicit and must not be enabled accidentally: it exists to
complete migration of the old carrier, while new deployments should use JWS.
HA ledgers, complete mTLS identity provisioning, the attestation service, and
production KMS/audit deployment remain separate production gates.

## Verification

```bash
GOCACHE=/tmp/k8s-credential-issuance-gocache go test ./...
GOCACHE=/tmp/k8s-credential-issuance-vetcache go vet -buildvcs=false ./...
GOCACHE=/tmp/k8s-credential-issuance-buildcache go build -buildvcs=false ./cmd/sa-authority ./cmd/sa-signer ./cmd/sa-node-agent
```

The in-tree HTTP end-to-end test uses a handler transport because restricted
test environments may not allow opening a TCP listener. It still exercises the
authority, signer, both Grant response shapes, legacy conversion, Grant
verification, KMS boundary, ledger recovery, Kubernetes TokenRequest envelope,
and node-agent request flow.

## Related documents

- [ServiceAccount `sa.key` migration plan](../migration/sa-key-migration.md)
