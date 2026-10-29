// Package identity implements the independent worker proof used to obtain an
// SA Grant. Kubernetes ServiceAccount tokens are not accepted as this proof.
package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/canonical"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/grant"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/replay"
)

type Proof = signapi.IdentityProof

// bindingProofPayload is shared by non-SA domains. SA keeps its historical
// strongly typed proof API above, while CA and etcd sign the same envelope
// with their domain-specific canonical binding. The binding is serialized as
// data here and never interpreted as authorization by this package.
type bindingProofPayload struct {
	Identity      string `json:"identity"`
	Timestamp     int64  `json:"timestamp"`
	Nonce         string `json:"nonce"`
	RequestDigest string `json:"request_digest"`
	Binding       any    `json:"binding"`
}

// SignBindingProof signs a canonical, domain-specific binding proof. It is
// intended for authority registration flows where the public key is
// independently registered and the request digest is bound to the proof.
func SignBindingProof(identity string, privateKey ed25519.PrivateKey, binding any, requestDigest, nonce string, now time.Time) (Proof, error) {
	if identity == "" || len(privateKey) != ed25519.PrivateKeySize || requestDigest == "" || nonce == "" {
		return Proof{}, fmt.Errorf("binding proof is incomplete")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	payload, err := canonical.Marshal(bindingProofPayload{Identity: identity, Timestamp: now.Unix(), Nonce: nonce, RequestDigest: requestDigest, Binding: binding})
	if err != nil {
		return Proof{}, err
	}
	return Proof{Identity: identity, Timestamp: now.Unix(), Nonce: nonce, Signature: "ed25519-v1:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))}, nil
}

type proofPayload struct {
	Identity     string               `json:"identity"`
	Timestamp    int64                `json:"timestamp"`
	Nonce        string               `json:"nonce"`
	ClaimsDigest string               `json:"claims_digest"`
	Binding      signapi.TokenBinding `json:"binding"`
}

func NewNonce() (string, error) { return grant.NewID("proof") }

func SignProof(identity string, privateKey ed25519.PrivateKey, binding signapi.TokenBinding, claimsDigest, nonce string, now time.Time) (Proof, error) {
	if identity == "" || len(privateKey) != ed25519.PrivateKeySize || claimsDigest == "" || nonce == "" {
		return Proof{}, fmt.Errorf("identity proof is incomplete")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	payload, err := signingBytes(identity, binding, claimsDigest, nonce, now.Unix())
	if err != nil {
		return Proof{}, err
	}
	return Proof{Identity: identity, Timestamp: now.Unix(), Nonce: nonce, Signature: "ed25519-v1:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))}, nil
}

type Verifier struct {
	Keys         map[string]ed25519.PublicKey
	Replay       replay.Store
	Now          func() time.Time
	MaxClockSkew time.Duration
}

func NewVerifier(keys map[string]ed25519.PublicKey, store replay.Store) *Verifier {
	if store == nil {
		store = replay.NewMemoryStore(nil)
	}
	copyKeys := make(map[string]ed25519.PublicKey, len(keys))
	for identity, key := range keys {
		copyKeys[identity] = append(ed25519.PublicKey(nil), key...)
	}
	return &Verifier{Keys: copyKeys, Replay: store, Now: time.Now, MaxClockSkew: 30 * time.Second}
}

func (v *Verifier) Verify(ctx context.Context, identity string, proof Proof, binding signapi.TokenBinding, claimsDigest string) error {
	if v == nil || v.Replay == nil {
		return fmt.Errorf("identity verifier is not configured")
	}
	if identity == "" || proof.Identity != identity {
		return fmt.Errorf("identity proof identity mismatch")
	}
	publicKey, ok := v.Keys[identity]
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("identity %q is not registered", identity)
	}
	if proof.Timestamp <= 0 || proof.Nonce == "" {
		return fmt.Errorf("identity proof is incomplete")
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	skew := v.MaxClockSkew
	if skew <= 0 {
		skew = 30 * time.Second
	}
	proofTime := time.Unix(proof.Timestamp, 0)
	if proofTime.Before(now.Add(-skew)) || proofTime.After(now.Add(skew)) {
		return fmt.Errorf("identity proof timestamp is outside the clock-skew window")
	}
	parts := strings.Split(proof.Signature, ":")
	if len(parts) != 2 || parts[0] != "ed25519-v1" {
		return fmt.Errorf("invalid identity signature envelope")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid identity signature encoding")
	}
	payload, err := signingBytes(identity, binding, claimsDigest, proof.Nonce, proof.Timestamp)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return fmt.Errorf("identity signature verification failed")
	}
	if err := v.Replay.Consume(ctx, identity+":"+proof.Nonce, proofTime.Add(skew)); err != nil {
		return fmt.Errorf("identity proof replay check: %w", err)
	}
	return nil
}

// VerifyBindingProof verifies the generic proof envelope used by certificate
// authorities. It has the same clock-skew and single-use guarantees as the SA
// proof verifier.
func (v *Verifier) VerifyBindingProof(ctx context.Context, identity string, proof Proof, binding any, requestDigest string) error {
	if v == nil || v.Replay == nil {
		return fmt.Errorf("identity verifier is not configured")
	}
	if identity == "" || proof.Identity != identity {
		return fmt.Errorf("identity proof identity mismatch")
	}
	publicKey, ok := v.Keys[identity]
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("identity %q is not registered", identity)
	}
	if proof.Timestamp <= 0 || proof.Nonce == "" || requestDigest == "" {
		return fmt.Errorf("identity proof is incomplete")
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	skew := v.MaxClockSkew
	if skew <= 0 {
		skew = 30 * time.Second
	}
	proofTime := time.Unix(proof.Timestamp, 0)
	if proofTime.Before(now.Add(-skew)) || proofTime.After(now.Add(skew)) {
		return fmt.Errorf("identity proof timestamp is outside the clock-skew window")
	}
	parts := strings.Split(proof.Signature, ":")
	if len(parts) != 2 || parts[0] != "ed25519-v1" {
		return fmt.Errorf("invalid identity signature envelope")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid identity signature encoding")
	}
	payload, err := canonical.Marshal(bindingProofPayload{Identity: identity, Timestamp: proof.Timestamp, Nonce: proof.Nonce, RequestDigest: requestDigest, Binding: binding})
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return fmt.Errorf("identity signature verification failed")
	}
	if err := v.Replay.Consume(ctx, identity+":"+proof.Nonce, proofTime.Add(skew)); err != nil {
		return fmt.Errorf("identity proof replay check: %w", err)
	}
	return nil
}

func signingBytes(identity string, binding signapi.TokenBinding, claimsDigest, nonce string, timestamp int64) ([]byte, error) {
	if identity == "" || claimsDigest == "" || nonce == "" || timestamp <= 0 {
		return nil, fmt.Errorf("identity proof payload is incomplete")
	}
	return canonical.Marshal(proofPayload{Identity: identity, Timestamp: timestamp, Nonce: nonce, ClaimsDigest: claimsDigest, Binding: binding})
}

func EncodePublicKey(key ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

func DecodePublicKey(encoded string) (ed25519.PublicKey, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}

func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func ParsePrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("private key is not PEM encoded")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, want Ed25519", key)
	}
	return append(ed25519.PrivateKey(nil), privateKey...), nil
}

func LoadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKeyPEM(data)
}

func EncodePrivateKeyPEM(key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
