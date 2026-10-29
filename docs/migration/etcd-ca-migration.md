# etcd CA Migration Plan

**Status:** Archived design; production hardening is still required

**Date:** 2026-10-29

This document covers only the migration of one etcd cluster's CA private key,
commonly `/etc/kubernetes/pki/etcd/ca.key`, from master nodes to an offline
HSM/KMS, together with a staged cutover of peer and client certificate issuance.

This is a key-custody migration, not an etcd CA identity replacement. The
existing etcd CA certificate, public key, and trust relationship remain
unchanged. Existing peer and client certificates do not need to be reissued all
at once.

## 1. Objective and scope

After the migration:

- master nodes no longer hold an exportable etcd CA private key;
- the existing `etcd/ca.crt` remains the etcd trust anchor;
- peer and client certificates are issued by separate intermediate KMS keys;
- `etcd-signer` does not access the etcd CA root private key;
- peer certificates are rotated one member at a time under quorum constraints;
- client certificates are handled as a separate workflow without membership
  changes;
- old and new certificate paths are auditable, recoverable, and rollback-aware.

This plan does not replace the etcd CA certificate. If the etcd CA key is
suspected to be compromised, a separate plan is required for dual trust,
complete certificate reissuance, and retirement of the old CA.

## 2. Target topology

```text
existing etcd/ca.key
    -> offline HSM/KMS (same key material)
    -> controlled ceremony signs peer/client intermediates

peer intermediate key   -> KMS -> etcd-signer -> etcd peer certificates
client intermediate key  -> KMS -> etcd-signer -> etcd client certificates

existing etcd/ca.crt
    -> etcd members and client verifier trust bundles
```

Peer and client must use different profiles, purposes, key references, and
policies. The repository separates `etcd-peer-certificate` and
`etcd-client-certificate`; they must not cross-sign.

## 3. Pre-migration inventory

Record the following for one etcd cluster at a time:

1. the paths, permissions, algorithm, and public-key fingerprint of
   `etcd/ca.key` and `etcd/ca.crt`;
2. whether the CA key and CA certificate match;
3. cluster instance, member IDs, peer URLs, client URLs, and endpoint SANs;
4. each member's peer cert/key, client cert/key, trusted CA file, and reload
   method;
5. CA private-key references in etcd startup arguments, static Pod manifests,
   scripts, and backups;
6. current peer/client certificate issuers, lifetimes, roles, and renewal paths;
7. membership, healthy-member count, quorum, and maintenance windows;
8. mappings from client identities to read/write/root roles;
9. certificate installation, reload/restart, drain, and rollback paths.

Do not delete, overwrite, or copy `etcd/ca.key` into an ordinary file directory
before this inventory is complete.

## 4. Verify and custody the existing etcd CA key

In a controlled environment:

1. parse the CA private key and `etcd/ca.crt`;
2. compare the private key's public component with the CA certificate public key;
3. record the CA certificate fingerprint, subject, issuer, lifetime, and
   constraints;
4. import the same key material into a non-exportable HSM/KMS or move it into an
   offline HSM;
5. verify that the HSM/KMS public key exactly matches the original CA
   certificate;
6. prohibit online `etcd-signer` from reading or exporting the CA root private
   key.

The repository does not provide a generic PEM-to-KMS import command. The target
HSM/KMS security process must perform the import and retain dual-control review,
import audit records, and controlled recovery material.

If the target KMS cannot preserve the existing CA public key, generating a new CA
is not a custody migration; it is an etcd CA replacement.

## 5. Create separate peer and client intermediates

Generate non-exportable peer and client intermediate keys in an external
KMS/HSM, create CSRs, and use an offline ceremony with the existing CA to sign
the corresponding certificates:

```text
peer:
  purpose    = etcd-peer-certificate
  key_ref    = kms/etcd/peer-intermediate-2026-01
  key_id     = etcd-peer-2026-01
  generation = etcd-peer-generation-2026-01

client:
  purpose    = etcd-client-certificate
  key_ref    = kms/etcd/client-intermediate-2026-01
  key_id     = etcd-client-2026-01
  generation = etcd-client-generation-2026-01
```

Each intermediate must provide:

- `CA=true`, an appropriate path length, and a bounded lifetime;
- peer- or client-specific profile, EKU, key-usage, and role policy;
- a valid chain to the existing etcd CA certificate;
- independent KMS purpose, key reference, generation, operation-ID, and audit
  policy.

The existing etcd CA certificate may remain the trust anchor and intermediate
ancestor, but it must not be the online etcd signer's generic signing-key
reference.

## 6. Deploy the etcd issuance path

Configure `etcd-authority`, `etcd-signer`, and the etcd certificate agent with
separate service identities, Grant keys, KMS policies, ledger namespaces, and
audit streams.

The authority must bind and verify:

- cluster instance, member/client ID, and identity;
- peer/client profile and endpoint SANs;
- CSR public-key digest;
- generation, key ID, TTL, and etcd role;
- the authorization boundary for member replacement and snapshot-restore
  workflows.

Certificate issuance must not perform membership mutation. The Agent should
generate the key and CSR locally on the member. The signing result contains the
leaf and intermediate chain; the CA certificate remains in the member/client
trust bundle.

The repository includes reference etcd authority, peer/client profiles, signer,
direct Agent, file installer, and quorum-aware rotation controller packages. It
does not yet include production `cmd/etcd-*` entrypoints or a complete etcd
integration adapter.

## 7. Establish trust, then rotate peers

Within one etcd cluster, validate trust and signing first, then rotate members
one at a time.

### Phase A: validate the intermediate certificate

- generate a new peer key and CSR locally on the target member;
- obtain a Grant bound to member identity, endpoint SANs, and the public key;
- have `etcd-signer` sign with the peer intermediate KMS key;
- verify the leaf -> peer intermediate -> existing etcd CA chain;
- confirm that the member's trusted CA still includes `etcd/ca.crt`;
- validate certificate installation, reload, and the TLS handshake without
  affecting existing members.

### Phase B: rotate peer members one at a time

For each member, perform the following sequence:

1. confirm that healthy members satisfy quorum;
2. confirm that trust overlap is ready;
3. use `CanRotatePeer` to verify that rotating this member preserves quorum;
4. obtain the member's new peer certificate;
5. atomically install it while keeping the private key local to the member;
6. reload/restart and wait for the member to become healthy;
7. run peer TLS, cluster-health, and endpoint checks;
8. record the result before moving to the next member.

Never stop two members in parallel when that could affect quorum. Certificate
issuance does not replace separate authorization for membership changes, member
replacement, or snapshot restore.

## 8. Rotate client certificates separately

After peer rotation is stable, migrate client certificates in a separate flow:

- use the `etcd-client` profile and `etcd-client-certificate` purpose;
- revalidate client identity and read/write/root role at the authority;
- bind the client CSR public key, role, SANs, and TTL to the Grant;
- install and verify one client or client pool at a time;
- never use a peer key or peer Grant for a client certificate;
- do not change etcd membership for client certificate rotation.

## 9. Remove `etcd/ca.key` from master nodes

Remove the etcd CA private key from master nodes only after all of the following
checks pass:

- the existing CA key is in the HSM/KMS and passed fingerprint verification;
- peer and client intermediates were correctly signed by the existing CA;
- both peer and client signers can issue and recover the exact result for a
  repeated request;
- no new peer/client issuance path reads the CA key from a master;
- etcd startup arguments, manifests, scripts, and backup flows contain no
  remaining online reference;
- every member and client verifier can still obtain the existing `etcd/ca.crt`;
- signer restart, KMS timeout, member reload failure, and network-recovery tests
  completed;
- quorum, migration, rollback, and recovery audit records are stored.

Remove the master-node CA private-key copies. `etcd/ca.crt` is public trust
material and must continue to be retained and distributed.

## 10. Rollback and post-migration state

Before the CA key is removed from masters, pause new issuance and restore the old
certificate path if needed. After removal, do not copy the CA private key back to
a master; recovery must use the HSM/KMS ceremony.

After migration:

1. the existing etcd CA certificate remains the trust anchor;
2. peer and client intermediate generations handle online issuance separately;
3. peer rotation always processes one member at a time and preserves quorum;
4. client rotation remains separate from membership workflows;
5. suspected CA-key exposure immediately stops use and starts the independent
   emergency replacement process.

## 11. Repository support and remaining work

The repository already provides:

- typed etcd peer/client Grant payloads and profile isolation;
- cluster/member/client identity, endpoint SAN, role, TTL, and public-key binding;
- the peer/client purpose-separated KMS policy shape;
- etcd authority, signer, direct Agent, and atomic file installer;
- `ValidateQuorum`, `CanRotatePeer`, and peer/client rotation-controller
  interfaces;
- reference authority workflows for member replacement and snapshot restore.

The following must still be supplied before production migration:

- exact etcd CA key import/offline-HSM ceremony;
- peer/client intermediate CSR signing and KMS metadata provisioning;
- production entrypoints for `etcd-authority`, `etcd-signer`, and the certificate
  agent;
- real etcd integration, member health probes, reload/restart, drain, and
  rollback adapters;
- an HA registry/ledger, mTLS identity, durable audit, and failure injection;
- member/client private-key reference scanning and CA-key removal audit.

The repository is therefore a testable etcd issuance/rotation reference path,
not a completed production migration utility.

## 12. Acceptance criteria

One etcd cluster's CA migration is complete only when:

1. the etcd CA certificate fingerprint and public key are unchanged;
2. `etcd/ca.key` is absent from master nodes and ordinary signer filesystems;
3. peer and client use separate intermediate keys, purposes, profiles, and
   Grants;
4. new peer/client chains validate with the existing `etcd/ca.crt`;
5. peer rotation affects one member at a time and always preserves quorum;
6. client rotation does not change membership and role binding is auditable;
7. old certificates work during their lifetime and new certificates pass
   reload/restart and TLS checks;
8. uncertain KMS, authority, ledger, or etcd health cannot trigger a local
   signing fallback;
9. rollback, recovery, quorum, and CA ceremonies have audit records.

## Related documents

- [Credential Issuance Contract v1](../contracts/issuance-v1.md)
- [External components implementation plan](../architecture/k8s-credential-issuance-platform-implementation.md)
