// Package kms defines the constrained KMS boundary. Callers submit a typed
// SigningIntent; there is intentionally no Sign([]byte) API.
package kms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	v1 "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/canonical"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/generation"
)

const PurposeServiceAccountJWT = "sa-jwt"

var (
	ErrPolicyDenied = errors.New("KMS signing intent is not allowed by policy")
	ErrBadArtifact  = errors.New("KMS returned an invalid signed artifact")
)

type SigningIntent struct {
	Domain        v1.Domain `json:"domain"`
	Purpose       string    `json:"purpose"`
	KeyID         string    `json:"key_id"`
	Generation    string    `json:"generation"`
	Algorithm     string    `json:"algorithm"`
	OperationID   string    `json:"operation_id"`
	PayloadDigest string    `json:"payload_digest"`
	Payload       []byte    `json:"-"`
}

type Artifact struct {
	Value         []byte
	KeyID         string
	Generation    string
	Algorithm     string
	PayloadDigest string
}

type Policy struct {
	Domain                    v1.Domain
	Purpose                   string
	Generation                string
	KeyID                     string
	KeyRef                    string
	Algorithm                 string
	Profile                   string
	SignerName                string
	MaxLifetime               time.Duration
	RequiredKeyUsages         []string
	AllowedKeyUsages          []string
	RequiredExtendedKeyUsages []string
	AllowedExtendedKeyUsages  []string
}

type Backend interface {
	Sign(context.Context, Policy, SigningIntent) (Artifact, error)
	PublicJWK(context.Context, Policy) (map[string]any, error)
}

type Provider struct {
	mu       sync.Mutex
	backend  Backend
	registry *generation.Registry
	policies map[string]Policy
	results  map[string]Artifact
	inflight map[string]*signingOperation
}

type signingOperation struct {
	done     chan struct{}
	artifact Artifact
	err      error
}

func NewProvider(backend Backend, registry *generation.Registry, policies []Policy) (*Provider, error) {
	if backend == nil {
		return nil, fmt.Errorf("KMS backend is required")
	}
	if len(policies) == 0 {
		return nil, fmt.Errorf("at least one KMS policy is required")
	}
	provider := &Provider{backend: backend, registry: registry, policies: make(map[string]Policy, len(policies)), results: make(map[string]Artifact), inflight: make(map[string]*signingOperation)}
	for _, policy := range policies {
		if !policy.Domain.Valid() || policy.Purpose == "" || policy.Generation == "" || policy.KeyID == "" || policy.Algorithm == "" {
			return nil, fmt.Errorf("incomplete KMS policy")
		}
		if policy.Domain == v1.DomainSA && policy.Purpose != PurposeServiceAccountJWT {
			return nil, fmt.Errorf("SA KMS policy has an invalid purpose")
		}
		if policy.Domain == v1.DomainCA && policy.Purpose != PurposeCACertificate {
			return nil, fmt.Errorf("CA KMS policy has an invalid purpose")
		}
		if policy.Domain == v1.DomainEtcd && policy.Purpose != PurposeEtcdPeerCertificate && policy.Purpose != PurposeEtcdClientCertificate {
			return nil, fmt.Errorf("etcd KMS policy has an invalid purpose")
		}
		key := policyKey(policy.Domain, policy.Purpose, policy.Generation, policy.KeyID, policy.Algorithm)
		if _, exists := provider.policies[key]; exists {
			return nil, fmt.Errorf("duplicate KMS policy %q", key)
		}
		provider.policies[key] = policy
	}
	return provider, nil
}

func NewIntent(domain v1.Domain, purpose, keyID, generation, algorithm, operationID string, payload []byte) (SigningIntent, error) {
	canonicalPayload, err := canonical.Canonicalize(payload)
	if err != nil {
		return SigningIntent{}, fmt.Errorf("canonicalize signing payload: %w", err)
	}
	if canonicalPayload == nil || len(canonicalPayload) == 0 {
		return SigningIntent{}, fmt.Errorf("signing payload is empty")
	}
	return SigningIntent{Domain: domain, Purpose: purpose, KeyID: keyID, Generation: generation, Algorithm: algorithm, OperationID: operationID, PayloadDigest: digest(canonicalPayload), Payload: canonicalPayload}, nil
}

func (i SigningIntent) Validate() error {
	if !i.Domain.Valid() || i.Purpose == "" || i.KeyID == "" || i.Generation == "" || i.Algorithm == "" || i.OperationID == "" || len(i.Payload) == 0 || i.PayloadDigest == "" {
		return fmt.Errorf("signing intent is incomplete")
	}
	canonicalPayload, err := canonical.Canonicalize(i.Payload)
	if err != nil || !bytes.Equal(canonicalPayload, i.Payload) {
		return fmt.Errorf("signing intent payload is not canonical")
	}
	if digest(canonicalPayload) != i.PayloadDigest {
		return fmt.Errorf("signing intent payload digest mismatch")
	}
	return nil
}

func (p *Provider) Sign(ctx context.Context, intent SigningIntent) (Artifact, error) {
	if p == nil || p.backend == nil {
		return Artifact{}, fmt.Errorf("KMS provider is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := intent.Validate(); err != nil {
		return Artifact{}, fmt.Errorf("%w: %v", ErrPolicyDenied, err)
	}
	policy, ok := p.policies[policyKey(intent.Domain, intent.Purpose, intent.Generation, intent.KeyID, intent.Algorithm)]
	if !ok {
		return Artifact{}, fmt.Errorf("%w: domain=%s purpose=%s generation=%s key=%s", ErrPolicyDenied, intent.Domain, intent.Purpose, intent.Generation, intent.KeyID)
	}
	if p.registry != nil {
		metadata, ok := p.registry.Metadata(intent.Generation)
		if !ok || metadata.KeyID != intent.KeyID || metadata.Algorithm != intent.Algorithm || !generation.SigningAllowed(metadata.State) {
			return Artifact{}, fmt.Errorf("%w: generation is unavailable", ErrPolicyDenied)
		}
	}
	p.mu.Lock()
	if previous, ok := p.results[intent.OperationID]; ok {
		p.mu.Unlock()
		if previous.KeyID != intent.KeyID || previous.Generation != intent.Generation || previous.Algorithm != intent.Algorithm || previous.PayloadDigest != intent.PayloadDigest {
			return Artifact{}, fmt.Errorf("%w: operation ID was reused for a different intent", ErrPolicyDenied)
		}
		return cloneArtifact(previous), nil
	}
	if operation, ok := p.inflight[intent.OperationID]; ok {
		p.mu.Unlock()
		select {
		case <-operation.done:
			if operation.err != nil {
				return Artifact{}, operation.err
			}
			return cloneArtifact(operation.artifact), nil
		case <-ctx.Done():
			return Artifact{}, ctx.Err()
		}
	}
	operation := &signingOperation{done: make(chan struct{})}
	p.inflight[intent.OperationID] = operation
	p.mu.Unlock()
	artifact, err := p.backend.Sign(ctx, policy, intent)
	if err == nil && (len(artifact.Value) == 0 || artifact.KeyID != intent.KeyID || artifact.Generation != intent.Generation || artifact.Algorithm != intent.Algorithm || artifact.PayloadDigest != intent.PayloadDigest) {
		err = fmt.Errorf("%w: backend metadata or value mismatch", ErrBadArtifact)
	}
	p.mu.Lock()
	delete(p.inflight, intent.OperationID)
	operation.err = err
	if err == nil {
		operation.artifact = cloneArtifact(artifact)
		p.results[intent.OperationID] = cloneArtifact(artifact)
	}
	close(operation.done)
	p.mu.Unlock()
	if err != nil {
		return Artifact{}, err
	}
	return cloneArtifact(artifact), nil
}

func cloneArtifact(value Artifact) Artifact {
	value.Value = append([]byte(nil), value.Value...)
	return value
}

type PublishedKey struct {
	Policy Policy
	JWK    map[string]any
}

func (p *Provider) PublicKeys(ctx context.Context) ([]PublishedKey, error) {
	if p == nil || p.backend == nil {
		return nil, fmt.Errorf("KMS provider is not configured")
	}
	keys := make([]PublishedKey, 0, len(p.policies))
	for _, policy := range p.policies {
		if p.registry != nil {
			metadata, ok := p.registry.Metadata(policy.Generation)
			if !ok || metadata.KeyID != policy.KeyID || metadata.Algorithm != policy.Algorithm || !generation.PublishingAllowed(metadata.State) {
				continue
			}
		}
		jwk, err := p.backend.PublicJWK(ctx, policy)
		if err != nil {
			return nil, fmt.Errorf("publish KMS key %q: %w", policy.KeyID, err)
		}
		keys = append(keys, PublishedKey{Policy: policy, JWK: jwk})
	}
	return keys, nil
}

func digest(payload []byte) string {
	value := sha256.Sum256(payload)
	return "sha256:" + fmt.Sprintf("%x", value[:])
}

func policyKey(domain v1.Domain, purpose, generationName, keyID, algorithm string) string {
	return string(domain) + "\x00" + purpose + "\x00" + generationName + "\x00" + keyID + "\x00" + algorithm
}

// LocalJWTBackend is only intended for tests and isolated development. It
// keeps the private key inside the backend and exposes only JWT/JWK behavior.
type LocalJWTBackend struct {
	keys map[string]crypto.Signer
}

func NewLocalJWTBackend(policies []Policy, privateKeys map[string]crypto.PrivateKey) (*LocalJWTBackend, error) {
	backend := &LocalJWTBackend{keys: make(map[string]crypto.Signer)}
	for _, policy := range policies {
		key, ok := privateKeys[policy.Generation]
		if !ok {
			return nil, fmt.Errorf("private key for generation %q is missing", policy.Generation)
		}
		signer, err := validateSigner(policy.Algorithm, key)
		if err != nil {
			return nil, err
		}
		backend.keys[policy.Generation] = signer
	}
	return backend, nil
}

func (b *LocalJWTBackend) Sign(_ context.Context, policy Policy, intent SigningIntent) (Artifact, error) {
	signer, ok := b.keys[policy.Generation]
	if !ok {
		return Artifact{}, fmt.Errorf("local signing key for generation %q is unavailable", policy.Generation)
	}
	token, err := signJWT(signer, policy.Algorithm, policy.KeyID, intent.Payload)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{Value: []byte(token), KeyID: policy.KeyID, Generation: policy.Generation, Algorithm: policy.Algorithm, PayloadDigest: intent.PayloadDigest}, nil
}

func (b *LocalJWTBackend) PublicJWK(_ context.Context, policy Policy) (map[string]any, error) {
	signer, ok := b.keys[policy.Generation]
	if !ok {
		return nil, fmt.Errorf("local signing key for generation %q is unavailable", policy.Generation)
	}
	return publicJWK(signer.Public(), policy), nil
}

func validateSigner(algorithm string, key crypto.PrivateKey) (crypto.Signer, error) {
	signer, ok := key.(crypto.Signer)
	if !ok || signer == nil {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}
	switch algorithm {
	case "RS256":
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok || rsaKey.N.BitLen() < 2048 {
			return nil, fmt.Errorf("RS256 requires an RSA key of at least 2048 bits")
		}
	case "ES256":
		if key, ok := key.(*ecdsa.PrivateKey); !ok || key.Curve != elliptic.P256() {
			return nil, fmt.Errorf("ES256 requires P-256")
		}
	case "ES384":
		if key, ok := key.(*ecdsa.PrivateKey); !ok || key.Curve != elliptic.P384() {
			return nil, fmt.Errorf("ES384 requires P-384")
		}
	case "ES512":
		if key, ok := key.(*ecdsa.PrivateKey); !ok || key.Curve != elliptic.P521() {
			return nil, fmt.Errorf("ES512 requires P-521")
		}
	default:
		return nil, fmt.Errorf("unsupported JWT algorithm %q", algorithm)
	}
	return signer, nil
}

func signJWT(signer crypto.Signer, algorithm, keyID string, payload []byte) (string, error) {
	header, err := canonical.Marshal(map[string]any{"alg": algorithm, "kid": keyID, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	protected := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	input := protected + "." + encodedPayload
	digest, hash, err := signingDigest(algorithm, []byte(input))
	if err != nil {
		return "", err
	}
	var signature []byte
	if key, ok := signer.(*ecdsa.PrivateKey); ok {
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return "", err
		}
		width := (key.Curve.Params().BitSize + 7) / 8
		signature = make([]byte, width*2)
		r.FillBytes(signature[:width])
		s.FillBytes(signature[width:])
	} else {
		signature, err = signer.Sign(rand.Reader, digest, hash)
		if err != nil {
			return "", err
		}
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func signingDigest(algorithm string, input []byte) ([]byte, crypto.Hash, error) {
	switch algorithm {
	case "RS256", "ES256":
		digest := sha256.Sum256(input)
		return digest[:], crypto.SHA256, nil
	case "ES384":
		digest := sha512.Sum384(input)
		return digest[:], crypto.SHA384, nil
	case "ES512":
		digest := sha512.Sum512(input)
		return digest[:], crypto.SHA512, nil
	default:
		return nil, 0, fmt.Errorf("unsupported JWT algorithm %q", algorithm)
	}
}

func publicJWK(public crypto.PublicKey, policy Policy) map[string]any {
	jwk := map[string]any{"alg": policy.Algorithm, "kid": policy.KeyID, "use": "sig"}
	switch key := public.(type) {
	case *rsa.PublicKey:
		jwk["kty"] = "RSA"
		jwk["n"] = base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := big.NewInt(int64(key.E)).Bytes()
		jwk["e"] = base64.RawURLEncoding.EncodeToString(e)
	case *ecdsa.PublicKey:
		jwk["kty"] = "EC"
		curve := ""
		switch key.Curve {
		case elliptic.P256():
			curve = "P-256"
		case elliptic.P384():
			curve = "P-384"
		case elliptic.P521():
			curve = "P-521"
		}
		width := (key.Curve.Params().BitSize + 7) / 8
		jwk["crv"] = curve
		jwk["x"] = base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, width)))
		jwk["y"] = base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, width)))
	}
	return jwk
}

// HTTPBackend is a constrained JWT KMS adapter. The endpoint receives a
// claims-only request and returns a compact JWT; arbitrary bytes are not
// accepted by this adapter.
type HTTPBackend struct {
	Endpoint   string
	HTTPClient *http.Client
	MaxBody    int64
}

func (b *HTTPBackend) Sign(ctx context.Context, policy Policy, intent SigningIntent) (Artifact, error) {
	if b == nil || b.Endpoint == "" || policy.KeyRef == "" {
		return Artifact{}, fmt.Errorf("HTTP KMS backend is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	client := copyHTTPClient(b.HTTPClient)
	maxBody := b.MaxBody
	if maxBody <= 0 {
		maxBody = 1 << 20
	}
	payload := map[string]any{"algorithm": policy.Algorithm, "claims": json.RawMessage(intent.Payload), "key_ref": policy.KeyRef, "key_id": policy.KeyID, "operation_id": intent.OperationID, "payload_digest": intent.PayloadDigest}
	body, err := json.Marshal(payload)
	if err != nil {
		return Artifact{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(b.Endpoint, "/")+"/v1/sign-jwt", bytes.NewReader(body))
	if err != nil {
		return Artifact{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return Artifact{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil {
		return Artifact{}, err
	}
	if int64(len(data)) > maxBody {
		return Artifact{}, fmt.Errorf("KMS response exceeds size limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Artifact{}, fmt.Errorf("KMS returned HTTP %s", response.Status)
	}
	var result struct {
		Token string         `json:"token"`
		JWK   map[string]any `json:"jwk"`
	}
	if err := json.Unmarshal(data, &result); err != nil || result.Token == "" {
		return Artifact{}, fmt.Errorf("KMS returned no JWT")
	}
	if err := validateJWTEnvelope(result.Token, policy, intent.Payload); err != nil {
		return Artifact{}, err
	}
	return Artifact{Value: []byte(result.Token), KeyID: policy.KeyID, Generation: policy.Generation, Algorithm: policy.Algorithm, PayloadDigest: intent.PayloadDigest}, nil
}

func (b *HTTPBackend) PublicJWK(ctx context.Context, policy Policy) (map[string]any, error) {
	if b == nil || b.Endpoint == "" || policy.KeyRef == "" {
		return nil, fmt.Errorf("HTTP KMS backend is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	client := copyHTTPClient(b.HTTPClient)
	endpoint := strings.TrimRight(b.Endpoint, "/") + "/v1/keys/" + url.PathEscape(policy.KeyRef)
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	query := parsedEndpoint.Query()
	query.Set("algorithm", policy.Algorithm)
	query.Set("key_id", policy.KeyID)
	parsedEndpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedEndpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("KMS returned HTTP %s", response.Status)
	}
	var jwk map[string]any
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&jwk); err != nil {
		return nil, err
	}
	keyID, keyIDOK := jwk["kid"].(string)
	algorithm, algorithmOK := jwk["alg"].(string)
	if !keyIDOK || !algorithmOK || keyID != policy.KeyID || algorithm != policy.Algorithm {
		return nil, fmt.Errorf("KMS returned a public key outside the configured policy")
	}
	return jwk, nil
}

func copyHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	copyClient := *client
	if copyClient.CheckRedirect == nil {
		copyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	}
	return &copyClient
}

func validateJWTEnvelope(token string, policy Policy, payload []byte) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("%w: JWT is not compact", ErrBadArtifact)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("%w: invalid JWT header", ErrBadArtifact)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("%w: invalid JWT header", ErrBadArtifact)
	}
	if header["alg"] != policy.Algorithm || header["kid"] != policy.KeyID {
		return fmt.Errorf("%w: JWT signing header mismatch", ErrBadArtifact)
	}
	encodedPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !bytes.Equal(encodedPayload, payload) {
		return fmt.Errorf("%w: JWT claims mismatch", ErrBadArtifact)
	}
	return nil
}

func ParsePrivateKeyPEM(data []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("private key is not PEM encoded")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key encoding")
}
