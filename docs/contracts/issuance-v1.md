# Credential Issuance Contract v1

**Status:** Frozen contract
**Date:** 2026-10-28
**Repository:** k8s-credential-issuance
**Domains:** ca, sa, etcd

This document freezes the shared protocol and security boundary for Kubernetes CA Issuance V2, ServiceAccount JWT Issuance V2, and etcd CA Issuance V2. It defines the external authority, signer, agent, ledger, and KMS contracts. It does not prescribe a programming language, database, or deployment platform.

## 1. Normative security boundary

The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

The Kubernetes control plane is an untrusted transport and storage plane. It MUST NOT hold CA private keys, ServiceAccount JWT signing keys, EAA Grant-signing keys, signer credentials, KMS management credentials, or HSM/KMS private key material.

The implementation uses one shared core, three domain plugins, and multiple isolated runtime instances. Shared code MUST NOT imply shared credentials, signing keys, unrestricted policy, or cross-domain authorization.

## 2. Domain and version

Every request and Grant MUST contain exactly one domain:

~~~text
ca       Kubernetes X.509 certificate issuance
sa       ServiceAccount JWT issuance
etcd     etcd peer/client certificate issuance
~~~

The contract version is issuance/v1. Every runtime instance MUST be configured for one fixed domain and MUST reject another domain. Unknown versions, domains, algorithms, or required fields MUST be rejected.

## 3. Grant contract

A Grant is a Compact JWS with:

~~~text
alg = EdDSA
key type = Ed25519
payload canonicalization = RFC 8785 JCS
~~~

The protected header MUST contain alg, kid, typ, and ver. The recommended type is issuance-grant+jws. alg=none, algorithm substitution, compression, external Grant lookup, and request-selected verification keys are forbidden. The signer selects the EAA public key only from its configured kid allowlist.

The canonical payload MUST contain:

~~~text
version
domain
grant_id
request_id
identity_ref
binding_digest
generation
key_id
policy_version
not_before
expires_at
nonce
typed_payload
~~~

The requested lifetime MUST exactly match the Grant lifetime and MUST be within the selected profile maximum TTL. binding_digest is the SHA-256 digest of the domain-specific canonical binding. grant_id, request_id, and nonce MUST have sufficient entropy. All time values use UTC.

The CA carrier limits are:

~~~text
decoded DER CSR <= 64 KiB
Grant JWS <= 16 KiB
total V2 annotations <= 32 KiB
compression = forbidden
~~~

Other domains MUST define equivalent bounded request and response sizes before production use.

## 4. Domain bindings

### 4.1 CA

The CA binding MUST include:

~~~text
csr_request_digest
public_key_sha256
signer_name
profile
subject
dns_names
ip_addresses
uris
key_usages
extended_key_usages
requested_lifetime
generation
key_id
~~~

The signer MUST construct the final X.509 template from an allowlisted profile. Each profile MUST define identity policy, maximum TTL, permitted SAN/EKU, generation policy, and KMS key allowlist. An unrestricted caller-supplied certificate template is forbidden.

### 4.2 ServiceAccount JWT

The SA binding MUST include:

~~~text
claims_digest
serviceaccount_uid
pod_uid              # required for Pod-bound workloads
audience
issuer
cluster_id
requested_lifetime
generation
key_id
~~~

The signer MUST derive JWT claims from the verified binding and policy. Arbitrary claims and generic JWT or byte signing are forbidden.

Complete V2 worker authorization uses a trusted direct worker provider or node-agent. Grant-only annotation relay through an untrusted API Server is compatibility transport, not the complete worker authorization path.

### 4.3 etcd

The etcd binding MUST include:

~~~text
cluster_instance
member_id_or_client_id
member_or_client_identity
endpoint_sans
profile             # etcd-peer or etcd-client
etcd_roles
public_key_sha256
requested_lifetime
generation
key_id
~~~

Peer and client profiles MUST use separate policy and CA key references. A client Grant MUST NOT authorize a peer certificate, and a peer Grant MUST NOT authorize a client certificate. Membership changes, snapshot restore, and member replacement are separate authorized workflows; certificate issuance MUST NOT mutate membership.

## 5. Request and response carriers

Direct requests and constrained relay requests are supported. A carrier MUST NOT change the signed binding.

The CA compatibility carrier uses:

~~~text
spec.request                         DER PKCS#10 CSR
metadata.annotations[ca-grant]       complete Compact JWS Grant
metadata.annotations[request-id]     Grant request_id
spec.expirationSeconds               exact Grant lifetime
~~~

The production annotation prefix MUST use an owned DNS prefix. CSR watch events are queue triggers only; the signer MUST re-read the latest CSR before validation, update only certificatesigningrequests/status, and never treat Approved as external authorization.

On CA success, status.certificate contains the PEM leaf followed by the intermediate chain. Root is excluded. status.ca remains empty and is not a trust-bundle channel.

The complete SA path uses an authenticated direct worker/provider request and returns the bound JWT to the node-agent or kubelet provider. JWKS and key metadata use a separately protected verifier-discovery channel.

The etcd path SHOULD use direct agent-to-signer requests. A constrained CSR relay MAY be used if the signer re-reads the request, validates the complete binding, and writes only CSR status. Direct and relay requests have identical Grant, digest, idempotency, and result semantics.

## 6. Authority contract

An external authority MUST provide:

- domain-specific identity and profile registration;
- independent identity or attestation verification;
- signed, single-use Grant issuance;
- exact identity, request, public key, profile, lifetime, generation, and key binding;
- unconsumed Grant revocation;
- generation blocking and emergency disable;
- an independent authorization audit stream.

The authority MUST NOT use a master-held kubeconfig, ServiceAccount token, CSR approval, Kubernetes Node object, or initial-cluster value as the sole authorization source.

Authority signing keys MUST be separated per security domain or protected by an equivalent domain-level boundary. A signer trusts only its configured authority key set.

## 7. Signer contract

A signer MUST:

1. authenticate the request using its domain identity;
2. parse and canonicalize it through the domain plugin;
3. verify the JWS, kid, validity, generation, and policy version;
4. recompute and compare binding_digest;
5. verify public key, profile, identity, lifetime, and domain fields;
6. atomically reserve the Grant;
7. create a constrained SigningIntent;
8. call KMS only after authorization succeeds;
9. persist the exact result before delivery;
10. deliver through the domain carrier;
11. audit success, rejection, retry, and recovery.

A signer MUST NOT approve CSRs, read Secrets, create Pods, modify Nodes/RBAC, use admin.conf, sign arbitrary bytes or unrestricted templates, copy private keys to local/Kubernetes storage, or fall back to local signing, auto-TLS, plaintext, or an untrusted local key.

## 8. Ledger and idempotency contract

The ledger is outside the control-plane trust boundary and supports atomic operations across signer instances.

Minimum states:

~~~text
issued
reserved
signing
completed
retryable_failure
permanent_failure
revoked
~~~

reserve MUST atomically bind the first request to the Grant. A later request with a different digest, public key, identity, profile, or target UID MUST be rejected.

The reservation contains a stable operation_id. Retries reuse it. After KMS success, the complete certificate or JWT result is durably recorded before delivery. A delivery retry returns that exact result. Grant consumption is single-use across concurrency, reconnects, and retries.

Temporary ledger, KMS, audit, or API conflicts remain retryable. Authorization and binding violations are permanent. Uncertainty MUST fail closed.

## 9. KMS contract

The KMS adapter MUST use non-exportable private keys, constrained domain-authorized signing, key/generation/algorithm/purpose allowlists, key versioning, disable/retirement, audit, short-lived machine identity or mTLS, and operation-ID idempotency or result recovery.

CA and etcd keys MUST support approved X.509-compatible signatures. SA keys MUST support the approved JWT algorithm. KMS management credentials remain outside the control plane.

The internal interface is a constrained intent, not Sign(arbitraryBytes):

~~~text
SigningIntent {
  domain
  purpose
  key_id
  generation
  algorithm
  operation_id
  payload_digest
}
~~~

Without asymmetric signing, non-exportability, audit, and result recovery, a KMS is not production-ready for this contract.

## 10. Errors, retries, and fail-closed behavior

Permanent failures include invalid signature, unknown key, expired Grant, binding mismatch, replay, profile violation, identity mismatch, and cross-domain use. They produce a terminal failure and audit event.

Temporary failures include API conflict, ledger unavailability, KMS timeout with unknown outcome, audit-store unavailability, and transient authority failure. They remain retryable without a new Grant or changed request.

Unknown authorization, ledger, audit, or KMS outcomes MUST NOT produce a different artifact or local fallback. Recovery uses the recorded operation_id and ledger result.

## 11. Generation, trust, and rotation

Each domain and profile/generation has an independent key reference, policy, audit stream, and disable action.

Rotation MUST support active/previous overlap, new public-key or trust-bundle publication, Grant migration to the new generation, leaf/token renewal, connection/cache drain, emergency revocation and disable, old-trust removal after reload/restart and drain, and recovery without copying private keys to the control plane.

Disabling a key stops new signing; it does not immediately revoke already-issued artifacts. Consumers and trust-bundle controllers enforce the documented acceptance window.

## 12. Runtime isolation

Production instances MUST have a fixed domain, independent service and mTLS identities, domain-specific authority public keys, KMS key/purpose allowlists, ledger namespaces, per-service authorization, network egress policy, audit access, and alerts.

Recommended instances:

~~~text
ca-authority    -> ca-signer    -> CA KMS keys
sa-authority    -> sa-signer    -> SA JWT KMS keys
etcd-authority  -> etcd-signer  -> etcd peer/client KMS keys
~~~

Shared databases, KMS endpoints, and binaries are acceptable only when these controls are enforceable and tested.

## 13. Contract tests

The implementation MUST prove that:

1. a Grant from one domain is rejected by every other domain signer;
2. changing identity, public key, profile, SAN, role, endpoint, generation, or lifetime is rejected;
3. concurrent signers consume a Grant once;
4. KMS success followed by delivery failure returns the original result;
5. no public API signs arbitrary bytes or unrestricted templates;
6. authority, ledger, KMS, audit, and control-plane failures fail closed for new issuance;
7. etcd peer and client keys cannot cross-sign;
8. CA status, SA JWT/JWKS, and etcd certificate delivery preserve domain contracts.

## 14. Compatibility and change policy

This is the v1 contract. Changes to Grant encoding, signed fields, binding semantics, KMS intent, ledger states, or result semantics require a new contract version or an explicitly compatible versioned extension.

Programming language, database product, deployment orchestrator, and internal package names MAY change without changing this contract.

## Related documents

- [External Components Implementation Plan](../architecture/k8s-credential-issuance-platform-implementation.md)
