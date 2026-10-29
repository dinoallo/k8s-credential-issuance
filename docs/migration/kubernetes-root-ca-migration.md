# Kubernetes Root CA Migration Plan

**Status:** Archived design; production hardening is still required

**Date:** 2026-10-29

This document covers only the migration of a Kubernetes cluster's root CA
private key, commonly `/etc/kubernetes/pki/ca.key`, from master nodes to an
offline HSM/KMS.

This is a key-custody migration, not a root-CA identity replacement. The
existing root certificate, public key, subject, and trust relationship remain
unchanged. Existing leaf certificates do not need to be reissued all at once.

## 1. Objective and scope

After the migration:

- master nodes no longer hold an exportable `ca.key`;
- the existing `ca.crt` remains the trust anchor;
- daily leaf issuance uses an intermediate key signed by the existing root;
- `ca-signer` does not access the root private key or use it as an online generic
  signing key;
- existing root-signed leaf certificates remain valid during their lifetime;
- new issuance, trust-bundle publication, and certificate rotation are
  independently auditable.

This plan does not replace the root CA certificate. If the root key is suspected
to be compromised, a separate plan is required for dual-root trust overlap,
full leaf reissuance, and retirement of the old root.

## 2. Target topology

```text
existing ca.key
    -> offline HSM/KMS (same key material)
    -> controlled ceremony signs CA intermediate

CA intermediate private key
    -> external KMS
    -> ca-signer
    -> ca-authority / CA agent
    -> Kubernetes leaf certificates

existing ca.crt
    -> master, node, and other verifier trust bundles
```

`ca-signer` uses only the intermediate `key_ref`. The repository's X.509
reference backend requires an intermediate issuer and rejects a self-signed
root; certificate responses contain the leaf and intermediate, not the root.

## 3. Pre-migration inventory

Record the following for one cluster at a time:

1. the paths, permissions, algorithm, and public-key fingerprint of `ca.key` and
   `ca.crt`;
2. whether `ca.key` and `ca.crt` match;
3. every root-private-key reference in kube-apiserver, controller-manager, CSR
   controllers, scripts, and backups;
4. which components directly sign with the root key and which only verify
   `ca.crt`;
5. every leaf certificate's issuer, lifetime, purpose, and renewal path;
6. trust-bundle distribution paths for nodes and components;
7. the current CSR carrier, signing service, certificate installation, and
   reload path;
8. acceptable certificate rotation and rollback windows.

Do not delete, overwrite, or copy `ca.key` into another ordinary file directory
before this inventory is complete.

## 4. Verify and custody the existing root key

In a controlled environment:

1. parse `ca.key` and `ca.crt`;
2. compare the private key's public component with the certificate public key;
3. record the root certificate fingerprint, subject, issuer, lifetime, and
   constraints;
4. import the same root key material into a non-exportable HSM/KMS or move it
   into an offline HSM;
5. verify that the HSM/KMS public key exactly matches the original certificate;
6. prohibit any online signer from reading or exporting the root private key.

The repository does not provide a generic PEM-to-KMS import command. The target
HSM/KMS security process must perform the import and retain dual-control review,
import audit records, and controlled recovery material.

If the target KMS cannot preserve the existing root public key, generating a new
root is not an equivalent migration. It becomes a root CA replacement and
requires a separate plan.

## 5. Create and publish a CA intermediate

Generate a non-exportable intermediate private key in an external KMS/HSM, create
a CSR, and use an offline root ceremony to sign the intermediate certificate.
Record:

```text
purpose    = ca-certificate
key_ref    = kms/ca/intermediate-2026-01
key_id     = ca-intermediate-2026-01
generation = ca-generation-2026-01
profile    = approved CA profile
```

The intermediate must define:

- `CA=true` and an appropriate path length;
- allowed issuance purposes, profiles, and signer identity;
- bounded lifetime and generation;
- a valid signature chain to the existing root certificate;
- non-exportability, purpose, algorithm, operation-ID, and audit policy in the
  KMS.

The root certificate may be retained as the intermediate's ancestor chain
material, but it must not be the online `ca-signer` signing-key reference.

## 6. Deploy the CA issuance path

Configure `ca-authority`, `ca-signer`, and the CA agent with separate service
identities, Grant keys, KMS key references, ledger namespaces, and audit streams.

Each CA Grant must bind:

- identity, CSR digest, and public-key digest;
- signer name, profile, Subject, SANs, EKUs, and key usages;
- generation, key ID, TTL, and policy version.

The new path may use a direct request or a constrained CSR carrier. CSR events
are queue triggers only: the signer must re-read the current CSR and update only
status; approval is not external authorization.

Certificate delivery follows the leaf-first contract:

```text
status.certificate = leaf PEM + intermediate PEM
status.ca          = empty
```

The root `ca.crt` continues through a separate trust-bundle channel. It must not
be treated as a `status.ca` trust channel.

The repository includes reference CA plugin, authority, signer, Agent, CSR
status-controller, and rotation-controller packages, but it does not yet include
production `cmd/ca-*` process entrypoints.

## 7. Rotate leaf certificates in stages

Migrate one certificate class or component group at a time within the cluster;
do not reissue every leaf simultaneously.

### Phase A: validate intermediate issuance

- generate a local key and CSR for an approved CA profile;
- obtain a Grant from the authority;
- have `ca-signer` sign with the intermediate KMS key;
- verify the leaf -> intermediate -> existing root chain;
- verify that the response does not contain the root;
- install the certificate and reload/restart the component;
- verify that both old root-signed leaves and new intermediate-signed leaves are
  accepted using the existing `ca.crt`.

### Phase B: staged rotation

Migrate leaf certificates from lower-risk to higher-risk groups. Before moving to
the next group, confirm that:

- the new certificate is installed and active;
- the peer still completes TLS verification;
- reload/restart does not read `ca.key` again;
- the old certificate remains controlled rollback material;
- authority, signer, KMS, ledger, and audit state are healthy.

Existing leaf certificates do not become invalid merely because the root private
key leaves the master. Only the path that issues new certificates must move to
the intermediate.

## 8. Remove `ca.key` from master nodes

Remove the root private key from master nodes only after all of the following
checks pass:

- the root key is in the HSM/KMS and its public key passed fingerprint checks;
- the intermediate certificate was correctly signed by the existing root;
- the CA signer can issue and recover the exact result for a repeated request;
- no new issuance path reads `ca.key` from a master;
- kube-apiserver, controller-manager, scripts, and manifests have no remaining
  reference;
- `ca.crt` remains available to every verifier that needs it;
- signer restart, KMS timeout, CSR conflict, and reload-failure tests completed;
- migration audit, backup, and rollback materials are stored.

Remove the master-node private-key copies. `ca.crt` is public trust material and
must continue to be retained and distributed.

## 9. Rollback and post-migration state

Before the master private key is removed, rollback can pause the new path and
restore the old issuance process. After removal, do not copy the root private key
back to a master. Recovery must use the HSM/KMS ceremony and the same controlled
operation and audit process.

After migration:

1. the existing root certificate remains the trust anchor;
2. the CA intermediate generation handles daily online issuance;
3. the root key is reserved for controlled intermediate, disaster-recovery, or
   explicitly authorized operations;
4. leaf rotation, trust-bundle publication, and root ceremonies are audited
   separately;
5. suspected root-key exposure immediately stops use and starts the independent
   emergency replacement process.

## 10. Repository support and remaining work

The repository already provides:

- bounded CSR parsing and public-key digest binding;
- CA profile, SAN, EKU, key-usage, TTL, and generation validation;
- CA authority, Grant, signer, Agent, and CSR status-controller packages;
- intermediate-only X.509 chain output and root rejection;
- CA rotation-controller interfaces for installation, reload, and result checks.

The following must still be supplied before production migration:

- exact root-key import/offline-HSM ceremony;
- intermediate CSR signing, KMS policy, and public-metadata provisioning;
- production process entrypoints for `ca-authority`, `ca-signer`, and the CA
  agent;
- an HA ledger, mTLS identity, durable audit, and trust-bundle controller;
- certificate installation, reload/restart, and rollback adapters for each
  Kubernetes component;
- master private-key reference scanning and removal audit.

The repository is therefore a testable CA issuance reference path, not a
completed production migration utility.

## 11. Acceptance criteria

One cluster's root CA migration is complete only when:

1. the root certificate fingerprint and public key are unchanged;
2. `ca.key` is absent from master nodes and ordinary signer filesystems;
3. `ca-signer` can access only the intermediate KMS key;
4. new leaf chains contain the leaf and intermediate and validate with the
   existing `ca.crt`;
5. existing root-signed leaves remain unaffected during their lifetime;
6. old and new certificate paths pass reload/restart and TLS verification;
7. KMS, authority, ledger, audit, or control-plane failure cannot trigger a
   local signing fallback;
8. rollback, recovery, and root ceremonies have audit records.

## Related documents

- [Credential Issuance Contract v1](../contracts/issuance-v1.md)
- [External components implementation plan](../architecture/k8s-credential-issuance-platform-implementation.md)
