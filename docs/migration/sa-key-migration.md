# ServiceAccount `sa.key` Migration and Rotation Runbook

**Status:** Migration design and runbook; production cutover is not implemented
by this repository

**Date:** 2026-10-30

This document covers the Kubernetes ServiceAccount JWT signing key, commonly
`/etc/kubernetes/pki/sa.key`, and its relationship to the external
`sa-signer` and KMS.

It distinguishes three different deployment goals:

1. **Exact-key migration:** move the existing key material into an external KMS
   without changing the token trust relationship.
2. **Key rotation:** generate a new key and update every verifier and issuer
   that must trust it.
3. **Independent issuance:** let `sa-signer` issue JWTs for a separate issuer
   and verifier/JWKS channel. This is the reference path currently deployed by
   the Helm chart; it is not automatically a replacement for kube-apiserver's
   native TokenRequest signer.

A Kubernetes-shaped `status.token` response or a signer `/jwks.json` endpoint
does not by itself make kube-apiserver trust the signer. The issuer, audience,
claims, public-key trust, and TokenRequest integration must also match.

## 1. Target state and key separation

For an exact-key migration, the target state is:

- the external KMS holds the same ServiceAccount JWT key material as the old
  `sa.key`, using non-exportable storage;
- the JWT `kid`, algorithm, issuer, audience rules, and public key remain
  unchanged;
- `sa-signer` uses only a constrained KMS signing API;
- existing and newly issued tokens remain verifiable by the same public key;
- the authority EAA Grant-signing key and worker identity keys remain separate
  from the ServiceAccount JWT key;
- KMS, authority, signer, ledger, and audit failures fail closed for new
  issuance.

The following keys must not be conflated:

| Key | Purpose |
| --- | --- |
| Kubernetes `sa.key` / external KMS equivalent | ServiceAccount JWT signing |
| `authority.signingKey` | EAA Grant signing by `sa-authority` |
| node-agent identity key | Worker identity proof |
| Infisical bearer token | Runtime authentication to the Infisical KMS API |

If the external signer uses a newly generated KMS key, that is a key rotation,
not an exact-key migration. If consumers are intentionally configured to trust
a separate issuance issuer and JWKS, it is independent issuance rather than a
native Kubernetes ServiceAccount-token migration.

## 2. Choose the migration strategy

### 2.1 Exact-key migration without rotation

Use this only when the target KMS supports a controlled private-key import and
can prove that the imported public key is byte-for-byte equivalent to the
existing public key. The KMS internal identifier may be new, but the JWT
metadata must remain compatible:

```text
KMS key id (`key_ref`)  = target KMS resource ID or UUID
JWT `kid` (`key_id`)    = existing token header kid
public_key              = public key corresponding to the old sa.key
generation              = stable issuance metadata name
```

The repository does not provide a generic key-import command. Its Infisical
client can list, create, inspect, read public-key material, and sign, but the
deployment chart does not import an existing private key. The KMS import must
therefore be performed by a controlled provisioning process outside Helm. If
the target KMS cannot import the existing key, this strategy is unavailable;
do not silently generate a replacement key and call it a migration.

### 2.2 Coordinated key rotation

Use this when the old key cannot be imported, is suspected to be exposed, or a
new cryptographic identity is intentionally required. A rotation changes the
public key and normally changes the JWT `kid` and generation. Every verifier
must trust the new public key before the first new token is issued.

The old key must remain available for verification until all old tokens and
verifier/JWKS caches have expired. In this repository, the old generation can
remain `Draining` while the new generation is the only `Active` generation;
`sa-signer` requires exactly one `Active` generation at startup.

### 2.3 Independent issuance JWTs

If the token is intended for an external workload API rather than kube-apiserver
native authentication, a new non-exportable Infisical KMS key is appropriate.
Configure that issuer and its JWKS with the consumers. Do not describe this as
preserving the cluster's native `sa.key` trust relationship.

## 3. Pre-migration inventory

Record the following before changing any key or request path:

1. the current `sa.key` algorithm, JWT `kid`, matching public key, issuer, and
   expected audiences;
2. the kube-apiserver settings for `--service-account-issuer`,
   `--api-audiences`, `--service-account-key-file`, and
   `--service-account-signing-key-file`, including version-specific behavior;
3. every reference to the private key in kube-apiserver,
   controller-manager, token webhooks, scripts, and static Pod manifests;
4. maximum token lifetime, verifier cache TTL, and JWKS cache duration;
5. every verifier that relies on the old public key, including whether it reads
   kube-apiserver configuration or the `sa-signer` JWKS endpoint;
6. whether TokenRequests currently use kube-apiserver's native path or the
   `sa-node-agent`/provider path;
7. whether each workload cluster has a different issuer or ServiceAccount key;
8. acceptable issuance outage and rollback windows.

Do not remove or replace the old private key on a master before this inventory,
the trust update, and the rollback procedure are complete.

## 4. Import the existing signing key for an exact-key migration

Do not generate a new signing key for this migration. In a controlled
provisioning environment, compare the public key derived from the existing
`sa.key` with `sa.pub` and with the JWK used by current verifiers. Keep the
private-key handling inside the KMS's approved import ceremony; do not copy it
to the signer Pod, Helm values, or an ordinary shared filesystem.

The imported KMS key should satisfy at least:

- domain: `sa`;
- purpose: `sa-jwt` / `sign-verify`;
- algorithm compatible with the existing key, for example `RS256`;
- non-exportable private material;
- signer identity or mTLS authorization restricted to this key and purpose;
- operation-ID idempotency or durable result recovery;
- audit records for import, sign, disable, recovery, and future rotation.

After import, `key_ref` is the KMS key's ID or UUID. It is not the JWT `kid` and
it is not the Infisical bearer token. The JWT `key_id` remains the existing
header `kid`. When runtime credentials are limited to Infisical's
`Cryptographic Operator` role, put the matching public-key material returned by
the KMS `public-key` endpoint in `public_key` as PEM or base64-encoded DER.

The KMS must never return the private key through its runtime API. If the
imported public key or JWT `kid` cannot be preserved, stop the exact-key plan
and switch to the coordinated rotation plan. If the old key may have been
exposed, exact-key import does not remove the historical exposure risk; follow
the emergency-key process instead.

## 5. Configure `sa-signer` and the authority

The signer configuration must contain exactly one `Active` generation. The
following is a shape, not a set of usable production values:

```yaml
signer:
  config:
    cluster_id: workload-cluster-1
    issuer: <exact-kube-apiserver-service-account-issuer>
    key_generations:
      - generation: sa-generation-existing
        key_id: <existing-jwt-kid>
        key_ref: <target-kms-key-id-or-uuid>
        public_key: <matching-public-key-pem-or-base64-der>
        algorithm: RS256
        state: Active
  kms:
    provider: infisical
    endpoint: https://infisical.example
    authToken:
      secretName: sa-signer-kms
```

`key_ref` is the target KMS resource ID. It must not be replaced with the
Kubernetes Secret name `kci-issuance-...-signer-kms`. That Secret contains the
Infisical bearer token only. The `eaa_keys` map remains the authority's Ed25519
public-key trust set and is unrelated to the ServiceAccount signing key.

The authority registration must use the same cluster, issuer, generation, key
ID, and allowed audiences that the token consumer expects:

```yaml
authority:
  config:
    cluster_id: workload-cluster-1
    issuer: <exact-kube-apiserver-service-account-issuer>
    registrations:
      - token_generation: sa-generation-existing
        key_id: <existing-jwt-kid>
        allowed_audiences:
          - <cluster-service-account-audience>
```

The `sa-signer` process and the Helm chart currently support one configured
`cluster_id`, issuer, and active generation per release. A separate issuance
cluster cannot use one signer configuration for multiple workload clusters
whose native ServiceAccount keys or issuers differ. Use an isolated release per
workload cluster, or redesign the signer/authority configuration boundary.

The reference chart mounts the KMS bearer token from a Kubernetes Secret for
controlled deployments. A production deployment should use the platform's
approved workload identity or external-secret injection, and must not place
KMS management credentials or private key material in Helm values or ordinary
Kubernetes objects.

## 6. Establish the native Kubernetes trust and request path

The current repository provides a node-agent/provider path that returns a
Kubernetes-shaped TokenRequest response and a signer JWKS endpoint. It does not
configure kube-apiserver to delegate native ServiceAccount TokenRequest signing
to `sa-signer`, install a kubelet TokenRequest provider, or update API-server
trust flags.

Before claiming a native Kubernetes cutover, the deployment must provide and
test all of the following:

1. kube-apiserver or the relevant token verifier trusts the public key that
   corresponds to the signer KMS key;
2. the issued `iss`, `aud`, `sub`, `exp`, `iat`, `nbf`, and
   `kubernetes.io` claims match the cluster's native ServiceAccount-token
   contract;
3. TokenRequest traffic is actually routed through the authenticated
   `sa-node-agent`/provider -> `sa-authority` -> `sa-signer` path;
4. the verifier can discover the key through the configured trust bundle or
   JWKS channel; a standalone `/jwks.json` endpoint does not update
   kube-apiserver automatically;
5. the old API-server signing path is disabled only after the replacement path
   is proven and rollback is available.

If kube-apiserver continues to issue native TokenRequests with the old
`sa.key`, keep that key and its configuration. Deploying an external signer
beside the API server does not, by itself, make it safe to delete `sa.key`.

## 7. Coordinated rotation procedure

For a real key rotation rather than an exact-key migration:

1. Generate a new non-exportable KMS key with the approved algorithm and
   `sign-verify` purpose.
2. Assign a new stable `generation` and JWT `key_id`; record the new public key.
3. Configure the new generation as `Active` and keep the old generation as
   `Draining` where the signer needs to publish or verify old tokens. Do not
   configure two `Active` generations.
4. Update every verifier, API-server trust bundle, and JWKS consumer to trust
   the new public key before issuing new tokens. Keep the old public key during
   the overlap window.
5. Update authority registrations and workload bindings to the new generation,
   key ID, issuer, and audience policy.
6. Issue a short-lived test token and verify its complete claims, signature,
   `kid`, issuer, audience, and binding against the new public key.
7. Wait at least the maximum old-token lifetime plus verifier/JWKS cache and
   propagation windows.
8. Retire or emergency-disable the old generation only after old-token
   verification is no longer required and rollback has been closed.

Changing only `key_ref` while leaving the old public key, `key_id`, or verifier
trust configuration unchanged is not a valid rotation. Changing only the
public key while leaving the KMS resource or algorithm mismatched is also not a
valid deployment.

## 8. Validation and cutover

### Exact-key migration validation

- compare the pre- and post-import public-key fingerprint;
- verify that `key_id`, algorithm, issuer, and expected audiences are unchanged;
- issue a short-lived token through the new path;
- verify old and new tokens with the original public key and the configured JWKS;
- verify the signer header contains the original `kid`;
- verify KMS timeout, authority failure, ledger failure, and signer restart do
  not trigger local-key fallback;
- verify retries return the same recorded token result.

### Native-path cutover validation

- prove which component issues each TokenRequest during the test;
- confirm kube-apiserver accepts a token from the new path and rejects an
  incorrectly issued issuer, audience, or binding;
- confirm the old path is still available for rollback;
- only then route production traffic to the new path.

The old `legacy-token-grant` mode can preserve the old Grant transport format
during an application migration. It does not import `sa.key`, replace worker
identity or attestation, or configure kube-apiserver trust.

The static `bindings` map is for bootstrap and tests. Production use requires
the signed remote-attestation resolver and an attestor that returns immutable
ServiceAccount UID, Pod UID, audience, issuer, and generation bindings.

## 9. Removing the old private key

Remove the old `sa.key` from master nodes only when all of the following are
true:

- the native API-server signing path no longer requires that private key;
- the replacement TokenRequest path is deployed and rollback-tested;
- old and new token verification behavior is understood and monitored;
- new tokens use the approved KMS key and no signer process reads a private-key
  file;
- KMS, authority, signer, ledger, audit, and trust-discovery alerts are active;
- recovery material is stored under the approved security policy.

If kube-apiserver still owns the native ServiceAccount TokenRequest signing
path, do not remove its signing key merely because `sa-signer` is deployed.
The current Helm chart cannot perform this handoff by itself.

## 10. Post-migration key state

For an exact-key migration, the imported KMS key remains active and retains the
existing public-key identity. This is a custody change, not a cryptographic
rotation.

For a rotation, keep the old generation in its approved overlap state until
token lifetime and cache windows have elapsed, then retire it. Preserve the
new generation's `key_id`, public key, issuer, and algorithm as the active
trust identity.

## 11. Repository support and limitations

The repository provides:

- the `sa-jwt` KMS purpose and `key_ref`, generation, algorithm, and `key_id`
  policy binding;
- active, renewing, draining, retired, and emergency-disabled generation
  states;
- constrained JWT signing through the configured KMS adapter;
- JWKS and key-metadata endpoints;
- claims canonicalization, binding checks, Grant idempotency, and result
  recovery;
- the direct token request path through the node-agent/provider;
- a reference Helm chart for separately deploying authority, signer, and
  node-agent.

The repository does not provide:

- target-KMS exact-key import, non-exportability, and recovery procedures;
- consistency checks for the existing public JWK, `kid`, and algorithm;
- the kube-apiserver/controller-manager external TokenRequest cutover;
- kubelet/node-agent Grant transport for existing projected-token consumers;
- automatic kube-apiserver issuer, audience, trust-bundle, or signing-key
  configuration;
- a production kubelet TokenRequest provider installation;
- external mTLS identity provisioning, HA ledger, production-grade KMS recovery,
  master-node private-key removal, and audit tooling;
- a way for one signer release to safely serve multiple native-cluster key and
  issuer pairs;
- failure-injection, token-TTL, and rollback-rehearsal tooling.

The chart's mounted token Secret and file-backed stores are reference
deployment mechanisms. They do not by themselves satisfy a production
control-plane key-removal or credential-injection policy.

## 12. Acceptance criteria

### Exact-key migration

1. New tokens are signed by the existing key material held in external KMS.
2. The pre- and post-import public-key fingerprint, algorithm, issuer, audience
   policy, and `kid` are identical.
3. `sa-signer` contains no exportable JWT private key and never falls back to a
   local `sa.key`.
4. Old and new tokens verify with the original public key.
5. The actual TokenRequest path and verifier trust have been tested end to end.
6. The old master-node private key is removed only after the native API-server
   path no longer requires it.

### Coordinated rotation

1. New tokens use the new KMS key and generation.
2. All verifiers trust the new public key before issuance begins.
3. The old key remains available through the approved overlap window.
4. Old tokens remain verifiable until their lifetime and cache windows expire.
5. The old generation is retired only after rollback is closed and audit evidence
   is complete.

## Related documents

- [ServiceAccount issuance reference deployment](../deployment/sa-issuance.md)
- [Helm deployment](../deployment/helm.md)
- [Credential Issuance Contract v1](../contracts/issuance-v1.md)
