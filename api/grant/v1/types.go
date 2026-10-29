// Package v1 contains the versioned common Grant contract.
package v1

import "encoding/json"

const ContractVersion = "issuance/v1"

type Domain string

const (
	DomainCA   Domain = "ca"
	DomainSA   Domain = "sa"
	DomainEtcd Domain = "etcd"
)

func (d Domain) Valid() bool {
	return d == DomainCA || d == DomainSA || d == DomainEtcd
}

// Grant is the decoded payload of the common Compact JWS envelope. Signature
// material is kept in the JWS protected header and signature segments.
type Grant struct {
	Version       string          `json:"version"`
	Domain        Domain          `json:"domain"`
	GrantID       string          `json:"grant_id"`
	RequestID     string          `json:"request_id"`
	IdentityRef   string          `json:"identity_ref"`
	BindingDigest string          `json:"binding_digest"`
	Generation    string          `json:"generation"`
	KeyID         string          `json:"key_id"`
	PolicyVersion string          `json:"policy_version"`
	NotBefore     int64           `json:"not_before"`
	ExpiresAt     int64           `json:"expires_at"`
	Nonce         string          `json:"nonce"`
	TypedPayload  json.RawMessage `json:"typed_payload"`
}

// ServiceAccountPayload is the typed payload carried by an SA Grant.
type ServiceAccountPayload struct {
	ClaimsDigest          string   `json:"claims_digest"`
	ServiceAccountUID     string   `json:"serviceaccount_uid"`
	PodUID                string   `json:"pod_uid,omitempty"`
	Audience              []string `json:"audience"`
	Issuer                string   `json:"issuer"`
	ClusterID             string   `json:"cluster_id"`
	RequestedLifetimeSecs int64    `json:"requested_lifetime"`
	Generation            string   `json:"generation"`
	KeyID                 string   `json:"key_id"`
}

// X509Subject is the deliberately small subject surface accepted by the CA
// and etcd certificate domains. ExtraNames and arbitrary ASN.1 attributes
// are intentionally not representable in a Grant.
type X509Subject struct {
	CommonName         string   `json:"common_name,omitempty"`
	SerialNumber       string   `json:"serial_number,omitempty"`
	Country            []string `json:"country,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	Province           []string `json:"province,omitempty"`
	StreetAddress      []string `json:"street_address,omitempty"`
	PostalCode         []string `json:"postal_code,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
}

// CertificatePayload is the typed CA Grant payload. The CSR digest and the
// public-key digest are both present: the former binds the exact request
// carrier, while the latter makes key substitution explicit.
type CertificatePayload struct {
	CSRRequestDigest      string      `json:"csr_request_digest"`
	PublicKeySHA256       string      `json:"public_key_sha256"`
	SignerName            string      `json:"signer_name"`
	Profile               string      `json:"profile"`
	Subject               X509Subject `json:"subject"`
	DNSNames              []string    `json:"dns_names,omitempty"`
	IPAddresses           []string    `json:"ip_addresses,omitempty"`
	URIs                  []string    `json:"uris,omitempty"`
	KeyUsages             []string    `json:"key_usages"`
	ExtendedKeyUsages     []string    `json:"extended_key_usages"`
	RequestedLifetimeSecs int64       `json:"requested_lifetime"`
	Generation            string      `json:"generation"`
	KeyID                 string      `json:"key_id"`
}

// EtcdCertificatePayload is the typed etcd Grant payload. Peer and client
// profiles are distinct authorization domains even when they use the same
// transport and certificate format.
type EtcdCertificatePayload struct {
	ClusterInstance        string   `json:"cluster_instance"`
	MemberOrClientID       string   `json:"member_or_client_id"`
	MemberOrClientIdentity string   `json:"member_or_client_identity"`
	EndpointSANs           []string `json:"endpoint_sans"`
	Profile                string   `json:"profile"`
	EtcdRoles              []string `json:"etcd_roles,omitempty"`
	PublicKeySHA256        string   `json:"public_key_sha256"`
	RequestedLifetimeSecs  int64    `json:"requested_lifetime"`
	Generation             string   `json:"generation"`
	KeyID                  string   `json:"key_id"`
}
