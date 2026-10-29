package sa

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	grantapi "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/canonical"
	coregrant "github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/grant"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/pipeline"
)

const (
	LegacyGrantFormat     = coregrant.LegacyFormat
	legacySignaturePrefix = "ed25519-v1"
	legacyRelayIdentity   = "legacy-relay"
)

// LegacyTokenGrant is the wire envelope used by the existing Kubernetes SA
// staging protocol. It is kept in the SA domain adapter; the common core never
// treats this untyped envelope as an authorization policy.
type LegacyTokenGrant struct {
	GrantID                 string   `json:"grant_id"`
	ClusterID               string   `json:"cluster_id"`
	ClaimsDigest            string   `json:"claims_digest"`
	ServiceAccountNamespace string   `json:"service_account_namespace"`
	ServiceAccountName      string   `json:"service_account_name"`
	ServiceAccountUID       string   `json:"service_account_uid"`
	PodUID                  string   `json:"pod_uid,omitempty"`
	Subject                 string   `json:"subject"`
	Audience                []string `json:"audience"`
	Issuer                  string   `json:"issuer"`
	TokenGeneration         string   `json:"token_generation"`
	NotBefore               int64    `json:"not_before"`
	NotAfter                int64    `json:"not_after"`
	Nonce                   string   `json:"nonce"`
	PolicyVersion           string   `json:"policy_version"`
	IssuerAndSignature      string   `json:"issuer_and_signature"`
}

func IsLegacyTokenGrant(raw []byte) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) > 0 && raw[0] == '{'
}

// CanonicalizeLegacyClaims preserves the old API-server claims digest
// algorithm for requests that still carry a staging TokenGrant.
func CanonicalizeLegacyClaims(claims []byte) ([]byte, error) {
	canonicalClaims, err := legacyCanonicalize(claims)
	if err != nil {
		return nil, fmt.Errorf("canonicalize legacy claims: %w", err)
	}
	return canonicalClaims, nil
}

func LegacyClaimsDigest(claims []byte) string {
	digest := sha256.Sum256(claims)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func LegacySigningBytes(value LegacyTokenGrant) ([]byte, error) {
	value.IssuerAndSignature = ""
	if err := validateLegacyGrant(value); err != nil {
		return nil, err
	}
	return legacyMarshal(value)
}

func SignLegacyGrant(value LegacyTokenGrant, keyID string, privateKey ed25519.PrivateKey) ([]byte, error) {
	if keyID == "" || strings.ContainsAny(keyID, ":\r\n") {
		return nil, fmt.Errorf("invalid legacy EAA key ID")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid legacy EAA private key")
	}
	value.Audience = append([]string(nil), value.Audience...)
	sort.Strings(value.Audience)
	signingBytes, err := LegacySigningBytes(value)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(privateKey, signingBytes)
	value.IssuerAndSignature = legacySignaturePrefix + ":" + keyID + ":" + base64.RawURLEncoding.EncodeToString(signature)
	return legacyMarshal(value)
}

func ParseLegacyTokenGrant(raw []byte) (LegacyTokenGrant, error) {
	if len(raw) == 0 || len(raw) > coregrant.MaxGrantSize {
		return LegacyTokenGrant{}, fmt.Errorf("legacy TokenGrant has an invalid size")
	}
	canonicalRaw, err := legacyCanonicalize(raw)
	if err != nil || !bytes.Equal(canonicalRaw, raw) {
		return LegacyTokenGrant{}, fmt.Errorf("legacy TokenGrant is not canonical")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value LegacyTokenGrant
	if err := decoder.Decode(&value); err != nil {
		return LegacyTokenGrant{}, fmt.Errorf("decode legacy TokenGrant: %w", err)
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return LegacyTokenGrant{}, err
		}
		return LegacyTokenGrant{}, fmt.Errorf("legacy TokenGrant has trailing value %v", token)
	}
	if err := validateLegacyGrant(value); err != nil {
		return LegacyTokenGrant{}, err
	}
	if value.IssuerAndSignature == "" {
		return LegacyTokenGrant{}, fmt.Errorf("legacy TokenGrant signature is empty")
	}
	return value, nil
}

func VerifyLegacyGrant(raw []byte, publicKeys map[string]ed25519.PublicKey, defaultKeyID string) (grantapi.Grant, coregrant.Header, error) {
	if defaultKeyID == "" {
		return grantapi.Grant{}, coregrant.Header{}, fmt.Errorf("legacy verifier has no default JWT key ID")
	}
	value, err := ParseLegacyTokenGrant(raw)
	if err != nil {
		return grantapi.Grant{}, coregrant.Header{}, err
	}
	parts := strings.Split(value.IssuerAndSignature, ":")
	if len(parts) != 3 || parts[0] != legacySignaturePrefix || parts[1] == "" {
		return grantapi.Grant{}, coregrant.Header{}, fmt.Errorf("invalid legacy EAA signature envelope")
	}
	publicKey, ok := publicKeys[parts[1]]
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return grantapi.Grant{}, coregrant.Header{}, fmt.Errorf("unknown legacy EAA signing key %q", parts[1])
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return grantapi.Grant{}, coregrant.Header{}, fmt.Errorf("invalid legacy EAA signature encoding")
	}
	signingBytes, err := LegacySigningBytes(value)
	if err != nil || !ed25519.Verify(publicKey, signingBytes, signature) {
		return grantapi.Grant{}, coregrant.Header{}, fmt.Errorf("legacy EAA signature verification failed")
	}

	// The legacy envelope has no JWT key ID. Its binding digest therefore does
	// not include one. The common typed Grant still carries the signer-selected
	// key ID after the digest is calculated.
	binding := signapi.TokenBinding{ClusterID: value.ClusterID, ServiceAccountNamespace: value.ServiceAccountNamespace, ServiceAccountName: value.ServiceAccountName, ServiceAccountUID: value.ServiceAccountUID, PodUID: value.PodUID, Subject: value.Subject, Audience: append([]string(nil), value.Audience...), Issuer: value.Issuer, NotBefore: value.NotBefore, NotAfter: value.NotAfter, TokenGeneration: value.TokenGeneration}
	bindingDigest, err := BindingDigest(value.ClaimsDigest, binding)
	if err != nil {
		return grantapi.Grant{}, coregrant.Header{}, err
	}
	binding.KeyID = defaultKeyID
	payload, err := GrantPayload(binding, value.ClaimsDigest)
	if err != nil {
		return grantapi.Grant{}, coregrant.Header{}, err
	}
	typedPayload, err := canonical.Marshal(payload)
	if err != nil {
		return grantapi.Grant{}, coregrant.Header{}, err
	}
	return grantapi.Grant{Version: grantapi.ContractVersion, Domain: grantapi.DomainSA, GrantID: value.GrantID, RequestID: value.GrantID, IdentityRef: legacyRelayIdentity, BindingDigest: bindingDigest, Generation: value.TokenGeneration, KeyID: defaultKeyID, PolicyVersion: value.PolicyVersion, NotBefore: value.NotBefore, ExpiresAt: value.NotAfter, Nonce: value.Nonce, TypedPayload: typedPayload}, coregrant.Header{Algorithm: coregrant.Algorithm, KeyID: parts[1], Type: "legacy-token-grant", Version: grantapi.ContractVersion, Format: LegacyGrantFormat}, nil
}

func NewGrantVerifier(defaultKeyID string) pipeline.GrantVerifier {
	return func(raw []byte, publicKeys map[string]ed25519.PublicKey) (grantapi.Grant, coregrant.Header, error) {
		if !IsLegacyTokenGrant(raw) {
			return coregrant.Verify(raw, publicKeys)
		}
		return VerifyLegacyGrant(raw, publicKeys, defaultKeyID)
	}
}

func validateLegacyGrant(value LegacyTokenGrant) error {
	if value.GrantID == "" || value.ClusterID == "" || !coregrant.ValidDigest(value.ClaimsDigest) || value.ServiceAccountNamespace == "" || value.ServiceAccountName == "" || value.ServiceAccountUID == "" || value.Subject == "" || value.Issuer == "" || value.TokenGeneration == "" || value.Nonce == "" || value.PolicyVersion == "" {
		return fmt.Errorf("legacy TokenGrant is missing a required field")
	}
	if len(value.Audience) == 0 {
		return fmt.Errorf("legacy TokenGrant audience is empty")
	}
	for i, audience := range value.Audience {
		if audience == "" || (i > 0 && value.Audience[i-1] >= audience) {
			return fmt.Errorf("legacy TokenGrant audience must be sorted and unique")
		}
	}
	if value.NotBefore <= 0 || value.NotAfter <= value.NotBefore {
		return fmt.Errorf("legacy TokenGrant validity window is invalid")
	}
	return nil
}

// legacyCanonicalize mirrors the staging serviceaccount protocol's
// CanonicalizeClaims implementation. In particular, it uses encoding/json's
// escaping rules after duplicate-key and trailing-value checks. The common
// issuance canonicalizer intentionally uses JCS-style escaping, so it must
// not be used for the old signature bytes.
func legacyCanonicalize(raw []byte) ([]byte, error) {
	value, err := canonical.Parse(raw)
	if err != nil {
		return nil, err
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, fmt.Errorf("legacy TokenGrant must be a JSON object")
	}
	return json.Marshal(value)
}

func legacyMarshal(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return legacyCanonicalize(raw)
}
