// Package grant implements the issuance/v1 Compact JWS envelope.
package grant

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	v1 "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/canonical"
)

const (
	Algorithm    = "EdDSA"
	Type         = "issuance-grant+jws"
	Format       = "compact-jws"
	LegacyFormat = "legacy-token-grant"
	MaxGrantSize = 16 << 10
)

var (
	ErrInvalidGrant = errors.New("invalid issuance Grant")
	ErrUnknownKey   = errors.New("unknown Grant signing key")
)

type Header struct {
	Algorithm string
	KeyID     string
	Type      string
	Version   string
	Format    string
}

func NewID(prefix string) (string, error) {
	if prefix == "" || strings.ContainsAny(prefix, "\r\n:") {
		return "", fmt.Errorf("invalid ID prefix")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return prefix + "-" + base64.RawURLEncoding.EncodeToString(random[:]), nil
}

func ValidDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && hex.EncodeToString(decoded) == strings.TrimPrefix(value, "sha256:")
}

func Sign(value v1.Grant, keyID string, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 Grant signing key")
	}
	if keyID == "" || strings.ContainsAny(keyID, ":\r\n") {
		return nil, fmt.Errorf("invalid Grant signing key ID")
	}
	payload, err := payloadBytes(value)
	if err != nil {
		return nil, err
	}
	header, err := canonical.Marshal(map[string]any{"alg": Algorithm, "kid": keyID, "typ": Type, "ver": v1.ContractVersion})
	if err != nil {
		return nil, err
	}
	protected := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	input := protected + "." + encodedPayload
	signature := ed25519.Sign(privateKey, []byte(input))
	raw := []byte(input + "." + base64.RawURLEncoding.EncodeToString(signature))
	if len(raw) > MaxGrantSize {
		return nil, fmt.Errorf("Grant exceeds %d-byte limit", MaxGrantSize)
	}
	return raw, nil
}

func Verify(raw []byte, publicKeys map[string]ed25519.PublicKey) (v1.Grant, Header, error) {
	if len(raw) == 0 || len(raw) > MaxGrantSize {
		return v1.Grant{}, Header{}, fmt.Errorf("%w: size is invalid", ErrInvalidGrant)
	}
	parts := strings.Split(string(raw), ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return v1.Grant{}, Header{}, fmt.Errorf("%w: Compact JWS must have three segments", ErrInvalidGrant)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return v1.Grant{}, Header{}, fmt.Errorf("%w: decode protected header: %v", ErrInvalidGrant, err)
	}
	canonicalHeader, err := canonical.Canonicalize(headerBytes)
	if err != nil || string(canonicalHeader) != string(headerBytes) {
		return v1.Grant{}, Header{}, fmt.Errorf("%w: protected header is not canonical", ErrInvalidGrant)
	}
	var headerValues map[string]string
	if err := json.Unmarshal(headerBytes, &headerValues); err != nil {
		return v1.Grant{}, Header{}, fmt.Errorf("%w: decode protected header: %v", ErrInvalidGrant, err)
	}
	header := Header{Algorithm: headerValues["alg"], KeyID: headerValues["kid"], Type: headerValues["typ"], Version: headerValues["ver"], Format: Format}
	if header.Algorithm != Algorithm || header.Type != Type || header.Version != v1.ContractVersion || header.KeyID == "" || len(headerValues) != 4 {
		return v1.Grant{}, Header{}, fmt.Errorf("%w: unsupported protected header", ErrInvalidGrant)
	}
	publicKey, ok := publicKeys[header.KeyID]
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return v1.Grant{}, Header{}, fmt.Errorf("%w: %q", ErrUnknownKey, header.KeyID)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return v1.Grant{}, Header{}, fmt.Errorf("%w: invalid signature encoding", ErrInvalidGrant)
	}
	if !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return v1.Grant{}, Header{}, fmt.Errorf("%w: signature verification failed", ErrInvalidGrant)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return v1.Grant{}, Header{}, fmt.Errorf("%w: decode payload: %v", ErrInvalidGrant, err)
	}
	canonicalPayload, err := canonical.Canonicalize(payload)
	if err != nil || string(canonicalPayload) != string(payload) {
		return v1.Grant{}, Header{}, fmt.Errorf("%w: payload is not canonical", ErrInvalidGrant)
	}
	parsedPayload, err := canonical.Parse(payload)
	if err != nil {
		return v1.Grant{}, Header{}, fmt.Errorf("%w: decode payload: %v", ErrInvalidGrant, err)
	}
	object, ok := parsedPayload.(map[string]any)
	if !ok || len(object) != 13 {
		return v1.Grant{}, Header{}, fmt.Errorf("%w: payload fields are not exact", ErrInvalidGrant)
	}
	for _, field := range []string{"version", "domain", "grant_id", "request_id", "identity_ref", "binding_digest", "generation", "key_id", "policy_version", "not_before", "expires_at", "nonce", "typed_payload"} {
		if _, ok := object[field]; !ok {
			return v1.Grant{}, Header{}, fmt.Errorf("%w: payload field %q is missing", ErrInvalidGrant, field)
		}
	}
	var value v1.Grant
	if err := json.Unmarshal(payload, &value); err != nil {
		return v1.Grant{}, Header{}, fmt.Errorf("%w: decode payload: %v", ErrInvalidGrant, err)
	}
	if err := validate(value); err != nil {
		return v1.Grant{}, Header{}, err
	}
	return value, header, nil
}

func payloadBytes(value v1.Grant) ([]byte, error) {
	if err := validate(value); err != nil {
		return nil, err
	}
	typedPayload, err := canonical.Parse(value.TypedPayload)
	if err != nil {
		return nil, fmt.Errorf("invalid typed Grant payload: %w", err)
	}
	return canonical.Marshal(map[string]any{
		"version":        value.Version,
		"domain":         value.Domain,
		"grant_id":       value.GrantID,
		"request_id":     value.RequestID,
		"identity_ref":   value.IdentityRef,
		"binding_digest": value.BindingDigest,
		"generation":     value.Generation,
		"key_id":         value.KeyID,
		"policy_version": value.PolicyVersion,
		"not_before":     value.NotBefore,
		"expires_at":     value.ExpiresAt,
		"nonce":          value.Nonce,
		"typed_payload":  typedPayload,
	})
}

func validate(value v1.Grant) error {
	if value.Version != v1.ContractVersion || !value.Domain.Valid() || value.GrantID == "" || value.RequestID == "" || value.IdentityRef == "" || value.Generation == "" || value.KeyID == "" || value.PolicyVersion == "" || value.Nonce == "" {
		return fmt.Errorf("%w: missing required field", ErrInvalidGrant)
	}
	if !ValidDigest(value.BindingDigest) || value.NotBefore <= 0 || value.ExpiresAt <= value.NotBefore {
		return fmt.Errorf("%w: invalid binding digest or validity window", ErrInvalidGrant)
	}
	if len(value.TypedPayload) == 0 {
		return fmt.Errorf("%w: typed payload is empty", ErrInvalidGrant)
	}
	parsed, err := canonical.Parse(value.TypedPayload)
	if err != nil {
		return fmt.Errorf("%w: typed payload is invalid: %v", ErrInvalidGrant, err)
	}
	if _, ok := parsed.(map[string]any); !ok {
		return fmt.Errorf("%w: typed payload must be an object", ErrInvalidGrant)
	}
	return nil
}
