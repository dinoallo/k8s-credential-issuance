# ServiceAccount `sa.key` Migration Plan

**Status:** Archived design; production hardening is still required

**Date:** 2026-10-29

This document covers only the migration of the Kubernetes ServiceAccount JWT
signing key, commonly `/etc/kubernetes/pki/sa.key`, from master nodes to an
external KMS/HSM.

## 1. Objective and scope

After the migration:

- master nodes no longer hold an exportable ServiceAccount JWT private key;
- new tokens continue to use the existing `sa.key` material, held as
  non-exportable key material in an external KMS;
- `sa-signer` uses the key only through a constrained KMS API;
- old and new tokens remain verifiable with the same public key;
- the existing `kid`, algorithm, and issuer remain unchanged;
- new issuance fails closed when the KMS, authority, signer, or ledger is
  unavailable.

This migration does not change the ServiceAccount claims-binding rules. The
authority EAA Grant-signing key and worker identity keys are separate materials
and must not be treated as `sa.key`.

## 2. Recommended strategy

Use an exact-key KMS import. Do not generate a new signing key or copy the old
private key to the signer or to ordinary file storage:

```text
old tokens ----┐
               ├── verified with the same sa.pub/JWKS
new tokens ----┘

worker/provider
      -> sa-node-agent
      -> sa-authority
      -> sa-signer
      -> external KMS
```

The repository does not provide a generic key-import command. The target KMS's
controlled security process must import the existing `sa.key` and prove that the
imported public key exactly matches the existing `sa.pub`.

## 3. Pre-migration inventory

Record the following before changing the key:

1. the current algorithm, `kid`, matching `sa.pub`, and issuer;
2. every reference to the private key in kube-apiserver,
   controller-manager, token webhooks, scripts, and static Pod manifests;
3. the maximum token lifetime, verifier cache TTL, and JWKS cache duration;
4. every verifier that relies on the old public key;
5. whether TokenRequests currently use the old API-server carrier or the
   `sa-node-agent`/provider path;
6. the acceptable issuance outage and rollback windows.

Do not remove or replace the old private key on a master before this inventory
is complete.

## 4. Import the existing signing key

Do not generate a new signing key for this migration. Parse the existing
`sa.key`, compute its public-key fingerprint, and compare it with `sa.pub` and
the JWK currently used by verifiers. After they match, import the same key
material into the KMS:

```text
purpose    = sa-jwt
algorithm  = preserve the existing algorithm, for example RS256
key_ref    = kms/sa/imported-existing-key
key_id     = preserve the existing kid
generation = sa-generation-existing
```

The KMS policy should bind at least:

- domain `sa`;
- purpose `sa-jwt`;
- the existing token algorithm and `key_id`;
- operation-ID idempotency and result recovery;
- the signer's short-lived identity or mTLS identity;
- signing, disable, rotation, and recovery audit records.

After import, the KMS may return the public JWK and signing results, but must
not return the private key through its API. `sa-signer` submits only a typed
claims signing intent after the common core has validated it.

If the KMS cannot preserve the existing public key or `kid` semantics, this is
not a strict no-rotation migration. Resolve the KMS import/metadata mapping
first instead of generating another key in the signer.
No-rotation also means continuing to trust the existing key material. If that key
is suspected to have been exposed, an exact-key import cannot remove the
historical exposure risk; follow the emergency-key process instead.

## 5. Configure the generation and signer

Production signer configuration must use `kms_endpoint` and make the imported
existing key the active generation:

```json
{
  "kms_endpoint": "https://kms.example",
  "key_generations": [
    {
      "generation": "sa-generation-existing",
      "key_id": "existing-sa-kid",
      "key_ref": "kms/sa/imported-existing-key",
      "algorithm": "RS256",
      "state": "Active"
    }
  ]
}
```

`--allow-local-key-provider` and `local_key_files` are for isolated development
and testing only. They must not be the production fallback after migration.

Authority workload registrations must continue to use a generation and `key_id`
compatible with existing tokens. This migration introduces no new signing
generation. The existing SA plugin continues to validate the Grant binding,
claims digest, audience, issuer, ServiceAccount UID, Pod UID, and lifetime.

## 6. Preserve verification of existing tokens

Because the key material is unchanged, both already-issued tokens and new tokens
remain verifiable with the existing `sa.pub`. During migration, keep the
existing public JWK, `kid`, algorithm, and issuer unchanged.

After the KMS import and signing verification succeed, no new-key overlap is
required. Existing public-key discovery must still remain available until every
verifier has completed the cutover.

The current `sa-signer` JWKS endpoint primarily publishes metadata obtained from
the KMS provider. The KMS import must make that endpoint return a JWK matching
the existing `sa.pub`, `kid`, and algorithm. Placing the old private key in
`local_key_files` is not an acceptable migration mechanism.

## 7. Switch the token issuance path

The cutover must separate validation of the KMS-import path from stopping the old
path.

### Phase A: validate the new path

- request a short-lived token using the existing generation;
- verify that the JWT header `kid` exactly matches the pre-migration `kid`;
- verify issuer, audience, subject, ServiceAccount UID, and Pod UID;
- verify new and existing tokens with the migrated JWKS and original `sa.pub`;
- compare the pre- and post-import public-key fingerprint, algorithm, issuer, and
  `kid`;
- verify that retries and signer restarts do not produce different tokens;
- verify that authority, KMS, ledger, or audit failures do not fall back to
  local signing.

### Phase B: stop the old path

Route actual TokenRequest traffic through the authenticated
`sa-node-agent`/provider -> `sa-authority` -> `sa-signer` path, then confirm
that the old API-server signing path no longer creates new tokens.

The old API-server carrier can use the explicit `legacy-token-grant` mode during
the transition. That mode preserves Grant transport compatibility only; it does
not import `sa.key` into the KMS and does not replace worker identity,
attestation, or KMS cutover.

The static `bindings` map in the current command is for bootstrap and tests.
The production cutover uses the implemented signed remote-attestation resolver;
the deployed attestor must return immutable ServiceAccount UID, Pod UID,
audience, issuer, and generation bindings.

## 8. Remove the old private key from master nodes

Remove the old `sa.key` only after all of the following checks pass:

- old signer configuration and startup arguments no longer reference the file;
- new tokens retain the pre-migration `kid`, algorithm, issuer, and public-key
  fingerprint;
- both old and new tokens verify with the same `sa.pub`;
- all token consumers use the new request path;
- KMS, authority, signer, ledger, and audit alerts are configured;
- signer restart, KMS timeout, and network-recovery tests have completed;
- migration audit records and controlled recovery material are stored.

Remove the master-node private-key copies. Since the key material is unchanged,
the existing public key remains the normal verifier/JWKS key; do not revoke or
replace it merely because the file migration is complete.

## 9. Post-migration key state

This plan does not retire the existing key. The imported KMS key remains active:

1. preserve the existing `key_id`, algorithm, issuer, and public JWK;
2. change its state only for KMS emergency disable or a separately approved
   future key rotation;
3. audit that the signer no longer reads a private-key file from a master;
4. retain only encrypted recovery records required by policy, not an active
   private key in an ordinary filesystem.

## 10. Repository support and remaining work

The repository already provides:

- an external HTTP KMS adapter for `sa-signer`;
- `sa-jwt` purpose, `key_ref`, generation, and `key_id` policy binding;
- active, renewing, and draining generation states;
- JWKS and key-metadata endpoints;
- claims canonicalization, binding checks, Grant idempotency, and result
  recovery;
- the direct token request path through the node-agent/provider.

The following must still be supplied before production migration:

- target-KMS exact-key import, non-exportability, and recovery procedures;
- consistency checks for the existing public JWK, `kid`, and algorithm;
- the actual kube-apiserver/controller-manager cutover to the new token path;
- production attestor service, mTLS identity, and an HA ledger;
- master-node private-key reference scanning, removal, and audit tooling;
- failure injection, token-TTL validation, and rollback exercises.

The repository is therefore a testable SA reference path, not a completed
production migration utility.

## 11. Acceptance criteria

The migration is ready for acceptance when:

1. new tokens are signed by the existing key material imported into the external
   KMS;
2. the `sa-signer` process and configuration directory contain no exportable
   JWT private key;
3. new Grants continue to use the agreed generation and `key_id`, with no new
   signing key introduced;
4. the pre- and post-import public-key fingerprint, algorithm, issuer, and `kid`
   are identical;
5. old and new tokens verify with the original `sa.pub`;
6. KMS failure never falls back to the local `sa.key`;
7. master nodes contain no old `sa.key` and no startup or manifest references;
8. retries return the same recorded token result rather than signing a different
   artifact;
9. after import verification, no master node or startup argument references the
   old private-key file.

## Related documents

- [ServiceAccount issuance reference deployment](../deployment/sa-issuance.md)
- [Credential Issuance Contract v1](../contracts/issuance-v1.md)
