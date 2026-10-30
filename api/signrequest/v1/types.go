// Package v1 contains the versioned direct SA signer and authority carriers.
package v1

import "encoding/json"

// TokenBinding is the exact SA identity and validity context bound by a Grant.
// It deliberately contains immutable UID fields rather than names alone.
type TokenBinding struct {
	ClusterID               string   `json:"cluster_id"`
	ServiceAccountNamespace string   `json:"service_account_namespace"`
	ServiceAccountName      string   `json:"service_account_name"`
	ServiceAccountUID       string   `json:"service_account_uid"`
	PodUID                  string   `json:"pod_uid,omitempty"`
	Subject                 string   `json:"subject"`
	Audience                []string `json:"audience"`
	Issuer                  string   `json:"issuer"`
	NotBefore               int64    `json:"not_before"`
	NotAfter                int64    `json:"not_after"`
	TokenGeneration         string   `json:"token_generation"`
	KeyID                   string   `json:"key_id,omitempty"`
}

// SignRequest keeps the field shape of the existing SA direct signer API.
// token_grant carries either the issuance/v1 Compact JWS or the explicitly
// enabled legacy Kubernetes staging TokenGrant envelope.
type SignRequest struct {
	Claims       json.RawMessage `json:"claims"`
	ClaimsDigest string          `json:"claims_digest"`
	TokenGrant   json.RawMessage `json:"token_grant"`
	Binding      TokenBinding    `json:"binding"`
	IdentityRef  string          `json:"identity_ref,omitempty"`
}

type SignResponse struct {
	Token           string `json:"token"`
	ClaimsDigest    string `json:"claims_digest"`
	GrantID         string `json:"grant_id"`
	TokenGeneration string `json:"token_generation"`
}

type IdentityProof struct {
	Identity  string `json:"identity"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

type GrantRequest struct {
	Identity     string        `json:"identity"`
	ClaimsDigest string        `json:"claims_digest"`
	Binding      TokenBinding  `json:"binding"`
	Proof        IdentityProof `json:"proof"`
}

type GrantResponse struct {
	// Grant is a JSON string for a Compact JWS and a JSON object for the
	// legacy TokenGrant compatibility format. RawMessage preserves both forms.
	Grant     json.RawMessage `json:"grant"`
	GrantID   string          `json:"grant_id,omitempty"`
	ExpiresAt int64           `json:"expires_at,omitempty"`
}

type TokenRequest struct {
	Namespace         string                `json:"namespace"`
	Name              string                `json:"name"`
	Request           json.RawMessage       `json:"request,omitempty"`
	Audiences         []string              `json:"audiences,omitempty"`
	ExpirationSeconds *int64                `json:"expirationSeconds,omitempty"`
	BoundObjectRef    *BoundObjectReference `json:"boundObjectRef,omitempty"`
}

// AttestationRequest asks a trusted node attestor to resolve the immutable
// workload binding for one worker-side TokenRequest. The nonce and complete
// request are included in the digest signed by the attestor.
type AttestationRequest struct {
	Identity  string       `json:"identity"`
	Namespace string       `json:"namespace"`
	Name      string       `json:"name"`
	Request   TokenRequest `json:"request"`
	Nonce     string       `json:"nonce"`
}

// AttestationResponse contains the attestor-signed immutable binding. The
// proof is verified against the configured attestor key, never a key supplied
// by the node-agent request.
type AttestationResponse struct {
	RequestDigest string        `json:"request_digest"`
	Binding       TokenBinding  `json:"binding"`
	Proof         IdentityProof `json:"proof"`
}

// BoundObjectReference mirrors the subset of the Kubernetes TokenRequest
// reference needed by the SA agent. Keeping it in the wire package avoids a
// dependency on the Kubernetes control-plane modules.
type BoundObjectReference struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion,omitempty"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
}

type TokenResponse struct {
	Token               string `json:"token"`
	ExpirationTimestamp int64  `json:"expiration_timestamp"`
}

// CertificateSignRequest is the common direct certificate carrier used by
// the CA and etcd domains. CSR is encoded as base64 by encoding/json. The
// signer derives X.509 identity values from CSR and compares them with the
// signed Grant; callers cannot provide an independent template.
type CertificateSignRequest struct {
	CSR               []byte          `json:"csr"`
	Grant             json.RawMessage `json:"grant"`
	RequestID         string          `json:"request_id"`
	IdentityRef       string          `json:"identity_ref,omitempty"`
	SignerName        string          `json:"signer_name"`
	Profile           string          `json:"profile"`
	KeyUsages         []string        `json:"key_usages"`
	ExtendedKeyUsages []string        `json:"extended_key_usages"`
	ExpirationSeconds int64           `json:"expiration_seconds"`
	NotBefore         int64           `json:"not_before"`
	NotAfter          int64           `json:"not_after"`
	Generation        string          `json:"generation"`
	KeyID             string          `json:"key_id"`
}

type CertificateSignResponse struct {
	Certificate []byte `json:"certificate"`
	GrantID     string `json:"grant_id"`
	RequestID   string `json:"request_id"`
	Profile     string `json:"profile"`
	Generation  string `json:"generation"`
	KeyID       string `json:"key_id"`
}

// CertificateSigningRequestCarrier models the small compatibility surface of
// a Kubernetes CSR without importing Kubernetes control-plane modules. A
// controller must re-read the carrier and update only Status.
type CertificateSigningRequestCarrier struct {
	Metadata CarrierMetadata                 `json:"metadata"`
	Spec     CertificateSigningRequestSpec   `json:"spec"`
	Status   CertificateSigningRequestStatus `json:"status"`
}

type CarrierMetadata struct {
	Name        string            `json:"name"`
	UID         string            `json:"uid"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type CertificateSigningRequestSpec struct {
	Request           []byte   `json:"request"`
	SignerName        string   `json:"signer_name"`
	Profile           string   `json:"profile"`
	Usages            []string `json:"usages"`
	ExtendedKeyUsages []string `json:"extended_key_usages"`
	ExpirationSeconds int64    `json:"expiration_seconds"`
}

type CertificateSigningRequestStatus struct {
	Certificate []byte                 `json:"certificate,omitempty"`
	CA          []byte                 `json:"ca,omitempty"`
	Conditions  []CertificateCondition `json:"conditions,omitempty"`
}

type CertificateCondition struct {
	Type    string `json:"type"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

const (
	CertificateGrantAnnotation = "issuance.example.com/ca-grant"
	RequestIDAnnotation        = "issuance.example.com/request-id"
)

// EtcdCertificateSignRequest is a direct etcd agent-to-signer carrier. The
// CSR public key and every identity/role field are checked against the Grant.
type EtcdCertificateSignRequest struct {
	CSR                    []byte          `json:"csr"`
	Grant                  json.RawMessage `json:"grant"`
	RequestID              string          `json:"request_id"`
	IdentityRef            string          `json:"identity_ref,omitempty"`
	ClusterInstance        string          `json:"cluster_instance"`
	MemberOrClientID       string          `json:"member_or_client_id"`
	MemberOrClientIdentity string          `json:"member_or_client_identity"`
	EndpointSANs           []string        `json:"endpoint_sans"`
	Profile                string          `json:"profile"`
	EtcdRoles              []string        `json:"etcd_roles,omitempty"`
	ExpirationSeconds      int64           `json:"expiration_seconds"`
	NotBefore              int64           `json:"not_before"`
	NotAfter               int64           `json:"not_after"`
	Generation             string          `json:"generation"`
	KeyID                  string          `json:"key_id"`
}

type EtcdCertificateSignResponse struct {
	Certificate      []byte `json:"certificate"`
	GrantID          string `json:"grant_id"`
	RequestID        string `json:"request_id"`
	ClusterInstance  string `json:"cluster_instance"`
	MemberOrClientID string `json:"member_or_client_id"`
	Profile          string `json:"profile"`
	Generation       string `json:"generation"`
	KeyID            string `json:"key_id"`
}
