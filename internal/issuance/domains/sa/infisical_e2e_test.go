//go:build infisical_e2e

package sa_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	grantapi "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/authority/domains/sa"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/audit"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/generation"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms"
	infisicalapi "github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms/infisical"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/ledger"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/pipeline"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/replay"
	sadomain "github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/sa"
)

func TestInfisicalSAEndToEnd(t *testing.T) {
	endpoint := requiredLiveEnv(t, "INFISICAL_KMS_ENDPOINT")
	tokenFile := requiredLiveEnv(t, "INFISICAL_KMS_TOKEN_FILE")
	keyRef := requiredLiveEnv(t, "INFISICAL_KMS_KEY_REF")
	expectedAlgorithm := liveEnvDefault("INFISICAL_KMS_ALGORITHM", "RSA_2048")
	tokenData, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	client, err := infisicalapi.NewClient(endpoint, strings.TrimSpace(string(tokenData)), &http.Client{Timeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	key, err := client.GetKey(context.Background(), keyRef)
	if err != nil {
		t.Fatalf("read Infisical key metadata: %v", err)
	}
	if key.KeyUsage != infisicalapi.KeyUsageSignVerify || key.Algorithm != expectedAlgorithm || key.IsDisabled || key.IsExportable || !key.HasDeleteProtection {
		t.Fatalf("Infisical key is not suitable for the test: %#v", key)
	}
	publicKeyMaterial, err := client.GetPublicKey(context.Background(), keyRef)
	if err != nil {
		t.Fatalf("read Infisical public key: %v", err)
	}
	publicKey, err := parseLiveRSAPublicKey(publicKeyMaterial)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(expectedAlgorithm, "RSA_") {
		expectedBits, err := strconv.Atoi(strings.TrimPrefix(expectedAlgorithm, "RSA_"))
		if err != nil || publicKey.N.BitLen() != expectedBits {
			t.Fatalf("Infisical RSA key does not match %s: %d bits", expectedAlgorithm, publicKey.N.BitLen())
		}
	}

	clusterID := liveEnvDefault("INFISICAL_SA_CLUSTER_ID", "cluster-infisical-e2e")
	issuer := liveEnvDefault("INFISICAL_SA_ISSUER", "https://issuer.infisical-e2e.example")
	policy := liveEnvDefault("INFISICAL_SA_POLICY", "sa-policy-infisical-e2e")
	generationName := liveEnvDefault("INFISICAL_SA_GENERATION", "generation-infisical-e2e")
	keyID := liveEnvDefault("INFISICAL_SA_KEY_ID", "jwt-infisical-e2e")
	worker := liveEnvDefault("INFISICAL_SA_WORKER", "worker-infisical-e2e")
	serviceAccountNamespace := liveEnvDefault("INFISICAL_SA_NAMESPACE", "default")
	serviceAccountName := liveEnvDefault("INFISICAL_SA_NAME", "infisical-e2e")
	serviceAccountUID := liveEnvDefault("INFISICAL_SA_UID", "sa-uid-infisical-e2e")
	podUID := liveEnvDefault("INFISICAL_SA_POD_UID", "pod-uid-infisical-e2e")
	audience := liveEnvDefault("INFISICAL_SA_AUDIENCE", "api")
	registrationID := liveEnvDefault("INFISICAL_SA_REGISTRATION", "registration-infisical-e2e")
	requestHost := liveEnvDefault("INFISICAL_SA_REQUEST_HOST", "authority.infisical-e2e")
	signerHost := liveEnvDefault("INFISICAL_SA_SIGNER_HOST", "signer.infisical-e2e")
	workerSubject := liveEnvDefault("INFISICAL_SA_WORKER_SUBJECT", worker)
	now := time.Now().UTC().Truncate(time.Second)
	eaaPublic, eaaPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	workerPublic, workerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := signapi.TokenBinding{
		ClusterID:               clusterID,
		ServiceAccountNamespace: serviceAccountNamespace,
		ServiceAccountName:      serviceAccountName,
		ServiceAccountUID:       serviceAccountUID,
		PodUID:                  podUID,
		Subject:                 "system:serviceaccount:" + serviceAccountNamespace + ":" + serviceAccountName,
		Audience:                []string{audience},
		Issuer:                  issuer,
		NotBefore:               now.Unix(),
		NotAfter:                now.Add(time.Hour).Unix(),
		TokenGeneration:         generationName,
	}
	registrations := sa.NewMemoryRegistrationStore()
	if err := registrations.Register(context.Background(), sa.WorkloadRegistration{
		RegistrationID:          registrationID,
		Identity:                workerSubject,
		IdentityPublicKey:       identity.EncodePublicKey(workerPublic),
		ClusterID:               clusterID,
		ServiceAccountNamespace: binding.ServiceAccountNamespace,
		ServiceAccountName:      binding.ServiceAccountName,
		ServiceAccountUID:       binding.ServiceAccountUID,
		PodUID:                  binding.PodUID,
		Issuer:                  issuer,
		AllowedAudiences:        append([]string(nil), binding.Audience...),
		MaxTokenLifetimeSecs:    3600,
		TokenGeneration:         generationName,
		KeyID:                   keyID,
		PolicyVersion:           policy,
		Active:                  true,
	}); err != nil {
		t.Fatal(err)
	}
	authority, err := sa.New(sa.Config{
		ClusterID:        clusterID,
		Issuer:           issuer,
		PolicyVersion:    policy,
		KeyID:            "eaa-infisical-e2e",
		PrivateKey:       eaaPrivate,
		Registrations:    registrations,
		ProofReplay:      replay.NewMemoryStore(func() time.Time { return now }),
		Grants:           sa.NewMemoryGrantLedger(),
		Audit:            audit.NopSink{},
		Now:              func() time.Time { return now },
		MaxTokenLifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := generation.NewRegistry([]generation.Metadata{{
		Generation: generationName,
		KeyID:      keyID,
		KeyRef:     keyRef,
		PublicKey:  string(publicKeyMaterial),
		Algorithm:  "RS256",
		State:      generation.Active,
	}})
	if err != nil {
		t.Fatal(err)
	}
	policies := []kms.Policy{{
		Domain:     grantapi.DomainSA,
		Purpose:    kms.PurposeServiceAccountJWT,
		Generation: generationName,
		KeyID:      keyID,
		KeyRef:     keyRef,
		PublicKey:  string(publicKeyMaterial),
		Algorithm:  "RS256",
	}}
	backend, err := kms.NewInfisicalBackend(client)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := kms.NewProvider(backend, registry, policies)
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := sadomain.NewPlugin(sadomain.Config{
		ClusterID:        clusterID,
		Issuer:           issuer,
		PolicyVersion:    policy,
		DefaultKeyID:     keyID,
		DefaultAlgorithm: "RS256",
		MaxTokenLifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := pipeline.New(pipeline.Config{
		Domain:      grantapi.DomainSA,
		GrantKeys:   map[string]ed25519.PublicKey{"eaa-infisical-e2e": eaaPublic},
		Plugin:      plugin,
		Ledger:      ledger.NewMemoryStore(),
		KMS:         provider,
		Revocations: authority,
		Audit:       audit.NopSink{},
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := sadomain.NewSigner(engine, provider)
	if err != nil {
		t.Fatal(err)
	}
	jwksResponse := httptest.NewRecorder()
	signer.Handler().ServeHTTP(jwksResponse, httptest.NewRequest(http.MethodGet, "/jwks.json", nil))
	if jwksResponse.Code != http.StatusOK {
		t.Fatalf("JWKS endpoint returned HTTP %d", jwksResponse.Code)
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(jwksResponse.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("decode signer JWKS: %v", err)
	}
	if len(jwks.Keys) != 1 || jwks.Keys[0]["kid"] != keyID || jwks.Keys[0]["alg"] != "RS256" || jwks.Keys[0]["kty"] != "RSA" {
		t.Fatalf("signer JWKS does not preserve the migrated key metadata: %#v", jwks.Keys)
	}
	jwkN, ok := jwks.Keys[0]["n"].(string)
	if !ok {
		t.Fatal("signer JWKS is missing RSA modulus")
	}
	decodedJWKModulus, err := base64.RawURLEncoding.DecodeString(jwkN)
	if err != nil || !bytes.Equal(decodedJWKModulus, publicKey.N.Bytes()) {
		t.Fatal("signer JWKS RSA modulus does not match the imported public key")
	}
	httpClient := &http.Client{Transport: handlerTransport{authority: authority.Handler(), signer: signer.Handler()}}
	nodeAgent, err := sadomain.NewProvider(sadomain.AgentConfig{
		AuthorityEndpoint: "http://" + requestHost + "/v1/grants",
		SignerEndpoint:    "http://" + signerHost + "/v1/sign",
		Identity:          workerSubject,
		IdentityKey:       workerPrivate,
		HTTPClient:        httpClient,
		Resolver: sadomain.BindingResolverFunc(func(context.Context, string, string, signapi.TokenRequest) (signapi.TokenBinding, error) {
			return binding, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := nodeAgent.GetServiceAccountToken(context.Background(), binding.ServiceAccountNamespace, binding.ServiceAccountName, signapi.TokenRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if response.Token == "" || response.ExpirationTimestamp != binding.NotAfter {
		t.Fatalf("unexpected SA token response: %#v", response)
	}
	if err := verifyLiveJWT(response.Token, publicKey, keyID, binding); err != nil {
		t.Fatal(err)
	}
}

func liveEnvDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func requiredLiveEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Skipf("%s is not set; skipping live Infisical E2E", name)
	}
	return value
}

func parseLiveRSAPublicKey(data []byte) (*rsa.PublicKey, error) {
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	} else {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(data)))
		}
		if err != nil {
			return nil, fmt.Errorf("decode live Infisical public key: %w", err)
		}
		data = decoded
	}
	public, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse live Infisical public key: %w", err)
	}
	rsaPublic, ok := public.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("live Infisical key is %T, not RSA", public)
	}
	return rsaPublic, nil
}

func verifyLiveJWT(token string, publicKey *rsa.PublicKey, keyID string, binding signapi.TokenBinding) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("live token is not compact JWT")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("decode live JWT header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil || header["alg"] != "RS256" || header["kid"] != keyID {
		return fmt.Errorf("unexpected live JWT header: %s", headerBytes)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("decode live JWT payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return fmt.Errorf("decode live JWT claims: %w", err)
	}
	if claims["iss"] != binding.Issuer || claims["sub"] != binding.Subject {
		return fmt.Errorf("live JWT identity claims do not match binding")
	}
	audience, ok := claims["aud"].([]any)
	if !ok || len(audience) != len(binding.Audience) {
		return fmt.Errorf("live JWT audience does not match binding")
	}
	for i, value := range audience {
		if value != binding.Audience[i] {
			return fmt.Errorf("live JWT audience does not match binding")
		}
	}
	for claim, expected := range map[string]int64{"iat": binding.NotBefore, "nbf": binding.NotBefore, "exp": binding.NotAfter} {
		value, ok := claims[claim].(float64)
		if !ok || int64(value) != expected {
			return fmt.Errorf("live JWT %s claim does not match binding", claim)
		}
	}
	private, ok := claims["kubernetes.io"].(map[string]any)
	if !ok || private["namespace"] != binding.ServiceAccountNamespace {
		return fmt.Errorf("live JWT Kubernetes namespace claim does not match binding")
	}
	serviceAccount, ok := private["serviceaccount"].(map[string]any)
	if !ok || serviceAccount["name"] != binding.ServiceAccountName || serviceAccount["uid"] != binding.ServiceAccountUID {
		return fmt.Errorf("live JWT ServiceAccount claim does not match binding")
	}
	pod, ok := private["pod"].(map[string]any)
	if !ok || pod["uid"] != binding.PodUID {
		return fmt.Errorf("live JWT Pod claim does not match binding")
	}
	encodedSignature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decode live JWT signature: %w", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], encodedSignature); err != nil {
		return fmt.Errorf("verify live JWT signature: %w", err)
	}
	return nil
}
