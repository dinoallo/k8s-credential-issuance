package kms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"strings"

	grantapi "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	infisicalapi "github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms/infisical"
)

// InfisicalBackend signs the canonical SA claims locally assembled into a
// compact JWS. Infisical receives only the JWS signing input (or its digest),
// never an instruction to construct arbitrary JWT claims.
type InfisicalBackend struct {
	Client *infisicalapi.Client
}

func NewInfisicalBackend(client *infisicalapi.Client) (*InfisicalBackend, error) {
	if client == nil {
		return nil, fmt.Errorf("Infisical KMS client is required")
	}
	return &InfisicalBackend{Client: client}, nil
}

func (b *InfisicalBackend) Sign(ctx context.Context, policy Policy, intent SigningIntent) (Artifact, error) {
	if b == nil || b.Client == nil || policy.KeyRef == "" {
		return Artifact{}, fmt.Errorf("Infisical KMS backend is not configured")
	}
	if policy.Domain != grantapi.DomainSA || policy.Purpose != PurposeServiceAccountJWT || intent.Domain != grantapi.DomainSA || intent.Purpose != PurposeServiceAccountJWT {
		return Artifact{}, fmt.Errorf("%w: policy is not an SA JWT policy", ErrPolicyDenied)
	}
	public, err := b.keyAndPublicKey(ctx, policy)
	if err != nil {
		return Artifact{}, err
	}
	input, err := jwtSigningInput(policy.Algorithm, policy.KeyID, intent.Payload)
	if err != nil {
		return Artifact{}, err
	}
	signature, err := signWithInfisical(ctx, b.Client, policy.KeyRef, policy.Algorithm, public, []byte(input))
	if err != nil {
		return Artifact{}, err
	}
	token := input + "." + base64.RawURLEncoding.EncodeToString(signature)
	if err := validateJWTEnvelope(token, policy, intent.Payload); err != nil {
		return Artifact{}, err
	}
	return Artifact{Value: []byte(token), KeyID: policy.KeyID, Generation: policy.Generation, Algorithm: policy.Algorithm, PayloadDigest: intent.PayloadDigest}, nil
}

func (b *InfisicalBackend) PublicJWK(ctx context.Context, policy Policy) (map[string]any, error) {
	if b == nil || b.Client == nil || policy.KeyRef == "" {
		return nil, fmt.Errorf("Infisical KMS backend is not configured")
	}
	public, err := b.keyAndPublicKey(ctx, policy)
	if err != nil {
		return nil, err
	}
	return publicJWK(public, policy), nil
}

func (b *InfisicalBackend) keyAndPublicKey(ctx context.Context, policy Policy) (crypto.PublicKey, error) {
	key, public, err := infisicalKeyAndPublicKey(ctx, b.Client, policy)
	if err != nil {
		return nil, err
	}
	if policy.Domain != grantapi.DomainSA || policy.Purpose != PurposeServiceAccountJWT {
		return nil, fmt.Errorf("%w: Infisical SA backend received a non-SA policy", ErrPolicyDenied)
	}
	if key.KeyUsage != infisicalapi.KeyUsageSignVerify {
		return nil, fmt.Errorf("%w: Infisical key is not a sign-verify key", ErrPolicyDenied)
	}
	return public, nil
}

// InfisicalX509Backend constructs the certificate locally and delegates only
// the issuer signature to Infisical. The configured issuer certificate is
// public material; its private key must remain in Infisical and is therefore
// nil in X509Issuer.
type InfisicalX509Backend struct {
	Client  *infisicalapi.Client
	Issuers map[string]X509Issuer
}

func NewInfisicalX509Backend(client *infisicalapi.Client, issuers map[string]X509Issuer) (*InfisicalX509Backend, error) {
	if client == nil || len(issuers) == 0 {
		return nil, fmt.Errorf("Infisical X.509 backend requires a client and issuer certificates")
	}
	copyIssuers := make(map[string]X509Issuer, len(issuers))
	for generation, issuer := range issuers {
		if generation == "" || issuer.Certificate == nil || issuer.PrivateKey != nil {
			return nil, fmt.Errorf("Infisical issuer %q must contain a public intermediate certificate only", generation)
		}
		if !issuer.Certificate.IsCA {
			return nil, fmt.Errorf("Infisical issuer %q is not a CA certificate", generation)
		}
		if isSelfSigned(issuer.Certificate) {
			return nil, fmt.Errorf("Infisical issuer %q must be an intermediate, not a root", generation)
		}
		copyIssuers[generation] = issuer
	}
	return &InfisicalX509Backend{Client: client, Issuers: copyIssuers}, nil
}

func (b *InfisicalX509Backend) Sign(ctx context.Context, policy Policy, intent SigningIntent) (Artifact, error) {
	if b == nil || b.Client == nil || policy.KeyRef == "" {
		return Artifact{}, fmt.Errorf("Infisical X.509 KMS backend is not configured")
	}
	if policy.Domain != grantapi.DomainCA && policy.Domain != grantapi.DomainEtcd || intent.Purpose == PurposeServiceAccountJWT || intent.Purpose != policy.Purpose {
		return Artifact{}, fmt.Errorf("%w: policy is not an X.509 policy", ErrPolicyDenied)
	}
	certificateIntent, err := DecodeCertificateIntent(intent.Payload)
	if err != nil {
		return Artifact{}, fmt.Errorf("%w: %v", ErrPolicyDenied, err)
	}
	if policy.Profile != "" && certificateIntent.Profile != policy.Profile {
		return Artifact{}, fmt.Errorf("%w: profile is not allowed by the KMS policy", ErrPolicyDenied)
	}
	if policy.SignerName != "" && certificateIntent.SignerName != policy.SignerName {
		return Artifact{}, fmt.Errorf("%w: signer name is not allowed by the KMS policy", ErrPolicyDenied)
	}
	if err := validateX509Policy(policy, certificateIntent); err != nil {
		return Artifact{}, fmt.Errorf("%w: %v", ErrPolicyDenied, err)
	}
	issuer, ok := b.Issuers[policy.Generation]
	if !ok {
		return Artifact{}, fmt.Errorf("X.509 issuer for generation %q is unavailable", policy.Generation)
	}
	request, err := x509.ParseCertificateRequest(certificateIntent.CSRDER)
	if err != nil || request.CheckSignature() != nil {
		return Artifact{}, fmt.Errorf("%w: CSR proof of possession is invalid", ErrPolicyDenied)
	}
	if err := validateCSRIdentity(request, certificateIntent); err != nil {
		return Artifact{}, fmt.Errorf("%w: CSR identity does not match certificate intent: %v", ErrPolicyDenied, err)
	}
	public, err := b.keyAndPublicKey(ctx, policy, issuer.Certificate.PublicKey)
	if err != nil {
		return Artifact{}, err
	}
	if err := comparePublicKeys(public, issuer.Certificate.PublicKey); err != nil {
		return Artifact{}, fmt.Errorf("%w: Infisical key does not match the intermediate certificate: %v", ErrPolicyDenied, err)
	}
	if expected := certificateAlgorithmForPublicKey(public); expected == "" || expected != policy.Algorithm {
		return Artifact{}, fmt.Errorf("%w: issuer algorithm does not match policy", ErrPolicyDenied)
	}
	serial := stableCertificateSerial(intent.OperationID)
	template, err := certificateTemplate(certificateIntent, serial, issuer.Certificate)
	if err != nil {
		return Artifact{}, err
	}
	signer := &infisicalCertificateSigner{ctx: ctx, client: b.Client, keyID: policy.KeyRef, algorithm: policy.Algorithm, public: public}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.Certificate, request.PublicKey, signer)
	if err != nil {
		return Artifact{}, fmt.Errorf("create certificate with Infisical KMS: %w", err)
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		return Artifact{}, err
	}
	chain := append([]*x509.Certificate{issuer.Certificate}, issuer.Chain...)
	value := pemEncodeChain(der, chain)
	if _, err := ValidateCertificateChain(value); err != nil {
		return Artifact{}, err
	}
	return Artifact{Value: value, KeyID: policy.KeyID, Generation: policy.Generation, Algorithm: policy.Algorithm, PayloadDigest: intent.PayloadDigest}, nil
}

func (b *InfisicalX509Backend) PublicJWK(ctx context.Context, policy Policy) (map[string]any, error) {
	if b == nil || b.Client == nil || policy.KeyRef == "" {
		return nil, fmt.Errorf("Infisical X.509 KMS backend is not configured")
	}
	issuer, ok := b.Issuers[policy.Generation]
	if !ok {
		return nil, fmt.Errorf("X.509 issuer for generation %q is unavailable", policy.Generation)
	}
	public, err := b.keyAndPublicKey(ctx, policy, issuer.Certificate.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := comparePublicKeys(public, issuer.Certificate.PublicKey); err != nil {
		return nil, fmt.Errorf("%w: Infisical key does not match the intermediate certificate: %v", ErrPolicyDenied, err)
	}
	return publicJWK(public, policy), nil
}

func (b *InfisicalX509Backend) keyAndPublicKey(ctx context.Context, policy Policy, fallback crypto.PublicKey) (crypto.PublicKey, error) {
	if policy.PublicKey == "" && fallback != nil {
		der, err := x509.MarshalPKIXPublicKey(fallback)
		if err != nil {
			return nil, err
		}
		policy.PublicKey = base64.StdEncoding.EncodeToString(der)
	}
	_, public, err := infisicalKeyAndPublicKey(ctx, b.Client, policy)
	return public, err
}

func infisicalKeyAndPublicKey(ctx context.Context, client *infisicalapi.Client, policy Policy) (infisicalapi.Key, crypto.PublicKey, error) {
	if client == nil || policy.KeyRef == "" {
		return infisicalapi.Key{}, nil, fmt.Errorf("%w: Infisical key reference is required", ErrPolicyDenied)
	}
	if policy.PublicKey != "" {
		public, err := parseInfisicalPublicKey([]byte(policy.PublicKey))
		if err != nil {
			return infisicalapi.Key{}, nil, fmt.Errorf("%w: configured Infisical public key is invalid: %v", ErrPolicyDenied, err)
		}
		if err := validatePublicKeyForAlgorithm(public, policy.Algorithm); err != nil {
			return infisicalapi.Key{}, nil, fmt.Errorf("%w: %v", ErrPolicyDenied, err)
		}
		return infisicalapi.Key{ID: policy.KeyRef, KeyUsage: infisicalapi.KeyUsageSignVerify, Algorithm: infisicalKeyTypeForPolicy(policy.Algorithm)}, public, nil
	}
	key, err := client.GetKey(ctx, policy.KeyRef)
	if err != nil {
		return infisicalapi.Key{}, nil, fmt.Errorf("Infisical KMS key metadata: %w", err)
	}
	if key.KeyUsage != infisicalapi.KeyUsageSignVerify || key.IsExportable || key.IsDisabled {
		return infisicalapi.Key{}, nil, fmt.Errorf("%w: Infisical key must be enabled, non-exportable, and sign-verify", ErrPolicyDenied)
	}
	if !infisicalKeyAlgorithmMatches(key.Algorithm, policy.Algorithm) {
		return infisicalapi.Key{}, nil, fmt.Errorf("%w: Infisical key algorithm %q does not match policy algorithm %q", ErrPolicyDenied, key.Algorithm, policy.Algorithm)
	}
	publicPEM, err := client.GetPublicKey(ctx, policy.KeyRef)
	if err != nil {
		return infisicalapi.Key{}, nil, fmt.Errorf("Infisical KMS public key: %w", err)
	}
	public, err := parseInfisicalPublicKey(publicPEM)
	if err != nil {
		return infisicalapi.Key{}, nil, fmt.Errorf("%w: invalid Infisical public key: %v", ErrBadArtifact, err)
	}
	if err := validatePublicKeyForAlgorithm(public, policy.Algorithm); err != nil {
		return infisicalapi.Key{}, nil, fmt.Errorf("%w: %v", ErrPolicyDenied, err)
	}
	return key, public, nil
}

func infisicalKeyTypeForPolicy(algorithm string) string {
	switch algorithm {
	case "ES256", AlgorithmECDSASHA256:
		return "ECC_NIST_P256"
	case "ES384", AlgorithmECDSASHA384:
		return "ECC_NIST_P384"
	case "ES512", AlgorithmECDSASHA512:
		return "ECC_NIST_P521"
	case "EdDSA", AlgorithmEd25519:
		return "ED25519"
	default:
		return "RSA_4096"
	}
}

func parseInfisicalPublicKey(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	var der []byte
	if block != nil && len(block.Bytes) > 0 {
		der = block.Bytes
	} else {
		var err error
		der, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			der, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(data)))
		}
		if err != nil || len(der) == 0 {
			return nil, fmt.Errorf("public key is neither PEM nor base64-encoded DER")
		}
	}
	public, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	return public, nil
}

func infisicalKeyAlgorithmMatches(keyAlgorithm, policyAlgorithm string) bool {
	switch policyAlgorithm {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", AlgorithmRSASHA256, "RSA-SHA384", "RSA-SHA512":
		return strings.HasPrefix(keyAlgorithm, "RSA_")
	case "ES256", AlgorithmECDSASHA256:
		return keyAlgorithm == "ECC_NIST_P256"
	case "ES384", "ECDSA-SHA384":
		return keyAlgorithm == "ECC_NIST_P384"
	case "ES512", "ECDSA-SHA512":
		return keyAlgorithm == "ECC_NIST_P521"
	case "EdDSA", AlgorithmEd25519:
		return keyAlgorithm == "ED25519"
	default:
		return false
	}
}

func validatePublicKeyForAlgorithm(public crypto.PublicKey, algorithm string) error {
	switch algorithm {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", AlgorithmRSASHA256, "RSA-SHA384", "RSA-SHA512":
		key, ok := public.(*rsa.PublicKey)
		if !ok || key.N == nil || key.N.BitLen() < 2048 {
			return fmt.Errorf("RSA policy requires an RSA public key of at least 2048 bits")
		}
	case "ES256", AlgorithmECDSASHA256:
		key, ok := public.(*ecdsa.PublicKey)
		if !ok || key.Curve == nil || key.Curve.Params().Name != "P-256" {
			return fmt.Errorf("ES256 policy requires a P-256 public key")
		}
	case "ES384", "ECDSA-SHA384":
		key, ok := public.(*ecdsa.PublicKey)
		if !ok || key.Curve == nil || key.Curve.Params().Name != "P-384" {
			return fmt.Errorf("ES384 policy requires a P-384 public key")
		}
	case "ES512", "ECDSA-SHA512":
		key, ok := public.(*ecdsa.PublicKey)
		if !ok || key.Curve == nil || key.Curve.Params().Name != "P-521" {
			return fmt.Errorf("ES512 policy requires a P-521 public key")
		}
	case "EdDSA", AlgorithmEd25519:
		if key, ok := public.(ed25519.PublicKey); !ok || len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("EdDSA policy requires an Ed25519 public key")
		}
	default:
		return fmt.Errorf("unsupported KMS algorithm %q", algorithm)
	}
	return nil
}

func comparePublicKeys(left, right crypto.PublicKey) error {
	leftDER, err := x509.MarshalPKIXPublicKey(left)
	if err != nil {
		return err
	}
	rightDER, err := x509.MarshalPKIXPublicKey(right)
	if err != nil {
		return err
	}
	if !bytes.Equal(leftDER, rightDER) {
		return fmt.Errorf("public key mismatch")
	}
	return nil
}

func certificateAlgorithmForPublicKey(public crypto.PublicKey) string {
	switch key := public.(type) {
	case *rsa.PublicKey:
		if key.N != nil && key.N.BitLen() >= 2048 {
			return AlgorithmRSASHA256
		}
	case *ecdsa.PublicKey:
		if key.Curve == nil {
			return ""
		}
		switch key.Curve.Params().Name {
		case "P-256":
			return AlgorithmECDSASHA256
		case "P-384":
			return "ECDSA-SHA384"
		case "P-521":
			return "ECDSA-SHA512"
		}
	case ed25519.PublicKey:
		return AlgorithmEd25519
	}
	return ""
}

func stableCertificateSerial(operationID string) *big.Int {
	hash := sha256.Sum256([]byte(operationID))
	serial := new(big.Int).SetBytes(hash[:20])
	if serial.Sign() == 0 {
		return big.NewInt(1)
	}
	return serial
}

func infisicalAlgorithm(algorithm string) (string, crypto.Hash, bool, error) {
	switch algorithm {
	case "RS256", AlgorithmRSASHA256:
		return "RSASSA_PKCS1_V1_5_SHA_256", crypto.SHA256, true, nil
	case "RS384", "RSA-SHA384":
		return "RSASSA_PKCS1_V1_5_SHA_384", crypto.SHA384, true, nil
	case "RS512", "RSA-SHA512":
		return "RSASSA_PKCS1_V1_5_SHA_512", crypto.SHA512, true, nil
	case "PS256":
		return "RSASSA_PSS_SHA_256", crypto.SHA256, true, nil
	case "PS384":
		return "RSASSA_PSS_SHA_384", crypto.SHA384, true, nil
	case "PS512":
		return "RSASSA_PSS_SHA_512", crypto.SHA512, true, nil
	case "ES256", AlgorithmECDSASHA256:
		return "ECDSA_SHA_256", crypto.SHA256, true, nil
	case "ES384", "ECDSA-SHA384":
		return "ECDSA_SHA_384", crypto.SHA384, true, nil
	case "ES512", "ECDSA-SHA512":
		return "ECDSA_SHA_512", crypto.SHA512, true, nil
	case "EdDSA", AlgorithmEd25519:
		return "ED25519", crypto.Hash(0), false, nil
	default:
		return "", 0, false, fmt.Errorf("unsupported Infisical KMS algorithm %q", algorithm)
	}
}

func signWithInfisical(ctx context.Context, client *infisicalapi.Client, keyID, algorithm string, public crypto.PublicKey, input []byte) ([]byte, error) {
	apiAlgorithm, hash, isDigest, err := infisicalAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	data := input
	if isDigest {
		data, err = hashInput(hash, input)
		if err != nil {
			return nil, err
		}
	}
	response, err := client.Sign(ctx, keyID, data, apiAlgorithm, isDigest)
	if err != nil {
		return nil, fmt.Errorf("Infisical KMS sign: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(response.Signature)
	if err != nil || len(signature) == 0 {
		return nil, fmt.Errorf("%w: Infisical KMS returned an invalid signature", ErrBadArtifact)
	}
	if err := verifySignature(public, algorithm, input, signature); err != nil {
		return nil, fmt.Errorf("%w: Infisical signature verification failed: %v", ErrBadArtifact, err)
	}
	if key, ok := public.(*ecdsa.PublicKey); ok && strings.HasPrefix(apiAlgorithm, "ECDSA_") {
		return ecdsaDERToJWS(signature, (key.Curve.Params().BitSize+7)/8)
	}
	return signature, nil
}

func hashInput(hash crypto.Hash, input []byte) ([]byte, error) {
	switch hash {
	case crypto.SHA256:
		value := sha256.Sum256(input)
		return value[:], nil
	case crypto.SHA384:
		value := sha512.Sum384(input)
		return value[:], nil
	case crypto.SHA512:
		value := sha512.Sum512(input)
		return value[:], nil
	default:
		return nil, fmt.Errorf("unsupported digest %v", hash)
	}
}

func verifySignature(public crypto.PublicKey, algorithm string, input, signature []byte) error {
	apiAlgorithm, hash, isDigest, err := infisicalAlgorithm(algorithm)
	if err != nil {
		return err
	}
	data := input
	if isDigest {
		data, err = hashInput(hash, input)
		if err != nil {
			return err
		}
	}
	return verifySignatureData(public, apiAlgorithm, hash, data, signature)
}

func verifySignatureData(public crypto.PublicKey, apiAlgorithm string, hash crypto.Hash, data, signature []byte) error {
	switch {
	case strings.HasPrefix(apiAlgorithm, "RSASSA_PKCS1_V1_5_"):
		key, ok := public.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("signature key is not RSA")
		}
		if err := rsa.VerifyPKCS1v15(key, hash, data, signature); err != nil {
			return err
		}
	case strings.HasPrefix(apiAlgorithm, "RSASSA_PSS_"):
		key, ok := public.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("signature key is not RSA")
		}
		if err := rsa.VerifyPSS(key, hash, data, signature, nil); err != nil {
			return err
		}
	case strings.HasPrefix(apiAlgorithm, "ECDSA_"):
		key, ok := public.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("signature key is not ECDSA")
		}
		var parsed struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(signature, &parsed)
		if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil || !ecdsa.Verify(key, data, parsed.R, parsed.S) {
			return fmt.Errorf("invalid ECDSA signature")
		}
	case apiAlgorithm == "ED25519":
		key, ok := public.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(key, data, signature) {
			return fmt.Errorf("invalid Ed25519 signature")
		}
	default:
		return fmt.Errorf("unsupported Infisical signing algorithm %q", apiAlgorithm)
	}
	return nil
}

func ecdsaDERToJWS(signature []byte, width int) ([]byte, error) {
	var parsed struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(signature, &parsed)
	if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil || parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 || parsed.R.BitLen() > width*8 || parsed.S.BitLen() > width*8 {
		return nil, fmt.Errorf("%w: invalid ECDSA signature encoding", ErrBadArtifact)
	}
	result := make([]byte, width*2)
	parsed.R.FillBytes(result[:width])
	parsed.S.FillBytes(result[width:])
	return result, nil
}

type infisicalCertificateSigner struct {
	ctx       context.Context
	client    *infisicalapi.Client
	keyID     string
	algorithm string
	public    crypto.PublicKey
}

func (s *infisicalCertificateSigner) Public() crypto.PublicKey { return s.public }

func (s *infisicalCertificateSigner) Sign(_ io.Reader, data []byte, opts crypto.SignerOpts) ([]byte, error) {
	apiAlgorithm, hash, isDigest, err := infisicalAlgorithm(s.algorithm)
	if err != nil {
		return nil, err
	}
	if isDigest {
		if opts == nil || opts.HashFunc() != hash || len(data) == 0 {
			return nil, fmt.Errorf("certificate signer received an unexpected digest")
		}
	} else if opts != nil && opts.HashFunc() != crypto.Hash(0) {
		return nil, fmt.Errorf("Ed25519 certificate signer received a hashed input")
	}
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	response, err := s.client.Sign(ctx, s.keyID, data, apiAlgorithm, isDigest)
	if err != nil {
		return nil, fmt.Errorf("Infisical KMS certificate sign: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(response.Signature)
	if err != nil || len(signature) == 0 {
		return nil, fmt.Errorf("%w: Infisical KMS returned an invalid certificate signature", ErrBadArtifact)
	}
	if err := verifySignatureData(s.public, apiAlgorithm, hash, data, signature); err != nil {
		return nil, fmt.Errorf("%w: Infisical certificate signature verification failed: %v", ErrBadArtifact, err)
	}
	return signature, nil
}
