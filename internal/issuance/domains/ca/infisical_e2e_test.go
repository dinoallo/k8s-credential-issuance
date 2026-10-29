//go:build infisical_e2e

package ca_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	grantapi "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/authority/domains/ca"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/audit"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/generation"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms"
	infisicalapi "github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms/infisical"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/ledger"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/pipeline"
	cadomain "github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/ca"
)

func TestInfisicalRootCAEndToEnd(t *testing.T) {
	endpoint := requiredInfisicalEnv(t, "INFISICAL_KMS_ENDPOINT")
	tokenFile := requiredInfisicalEnv(t, "INFISICAL_KMS_TOKEN_FILE")
	keyRef := requiredInfisicalEnv(t, "INFISICAL_KMS_KEY_REF")
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
	if key.KeyUsage != infisicalapi.KeyUsageSignVerify || key.IsDisabled || key.IsExportable {
		t.Fatalf("Infisical key is not suitable for CA issuance: %#v", key)
	}
	publicKeyMaterial, err := client.GetPublicKey(context.Background(), keyRef)
	if err != nil {
		t.Fatalf("read Infisical public key: %v", err)
	}
	publicKey, err := parseInfisicalRSAPublicKey(publicKeyMaterial)
	if err != nil {
		t.Fatal(err)
	}
	if publicKey.N.BitLen() < 2048 {
		t.Fatalf("Infisical RSA key is too small: %d bits", publicKey.N.BitLen())
	}

	const (
		clusterID      = "cluster-infisical-ca-e2e"
		policy         = "ca-policy-infisical-e2e"
		generationName = "generation-infisical-ca-e2e"
		keyID          = "ca-infisical-e2e"
		identityRef    = "agent-infisical-ca-e2e"
		profileName    = "infisical-e2e-client"
		signerName     = "example.com/infisical-e2e"
	)
	now := time.Now().UTC().Truncate(time.Second)
	eaaPublic, eaaPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	workerPublic, workerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootKey, root := makeInfisicalRoot(t, now)
	intermediate := makeInfisicalIntermediate(t, root, rootKey, publicKey, now)

	profiles, err := cadomain.NewRegistry([]cadomain.Profile{{
		Name:              profileName,
		SignerName:        signerName,
		MaxTTL:            time.Hour,
		RequiredKeyUsages: []string{cadomain.UsageDigitalSignature},
		AllowedKeyUsages:  []string{cadomain.UsageDigitalSignature},
	}})
	if err != nil {
		t.Fatal(err)
	}
	subject := grantapi.X509Subject{CommonName: "workload-infisical-e2e", Organization: []string{"example"}}
	registrations := ca.NewMemoryRegistrationStore()
	if err := registrations.Register(context.Background(), ca.Registration{
		Identity:          identityRef,
		IdentityPublicKey: identity.EncodePublicKey(workerPublic),
		ClusterID:         clusterID,
		Profile:           profileName,
		SignerName:        signerName,
		Subject:           subject,
		DNSNames:          []string{"workload.infisical-e2e.example"},
		KeyUsages:         []string{cadomain.UsageDigitalSignature},
		Generation:        generationName,
		KeyID:             keyID,
		MaxTTL:            time.Hour,
		Active:            true,
	}); err != nil {
		t.Fatal(err)
	}
	authority, err := ca.New(ca.Config{
		ClusterID:     clusterID,
		PolicyVersion: policy,
		EAAKeyID:      "eaa-infisical-ca-e2e",
		SigningKey:    eaaPrivate,
		Registrations: registrations,
		Profiles:      profiles,
		Audit:         audit.NopSink{},
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	registry, err := generation.NewRegistry([]generation.Metadata{{
		Generation: generationName,
		KeyID:      keyID,
		KeyRef:     keyRef,
		PublicKey:  string(publicKeyMaterial),
		Algorithm:  kms.AlgorithmRSASHA256,
		State:      generation.Active,
	}})
	if err != nil {
		t.Fatal(err)
	}
	policies := []kms.Policy{{
		Domain:            grantapi.DomainCA,
		Purpose:           kms.PurposeCACertificate,
		Generation:        generationName,
		KeyID:             keyID,
		KeyRef:            keyRef,
		PublicKey:         string(publicKeyMaterial),
		Algorithm:         kms.AlgorithmRSASHA256,
		Profile:           profileName,
		SignerName:        signerName,
		MaxLifetime:       time.Hour,
		RequiredKeyUsages: []string{cadomain.UsageDigitalSignature},
		AllowedKeyUsages:  []string{cadomain.UsageDigitalSignature},
	}}
	backend, err := kms.NewInfisicalX509Backend(client, map[string]kms.X509Issuer{
		generationName: {Certificate: intermediate, Chain: []*x509.Certificate{root}},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := kms.NewProvider(backend, registry, policies)
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := cadomain.NewPlugin(cadomain.Config{PolicyVersion: policy, DefaultAlgorithm: kms.AlgorithmRSASHA256, Profiles: profiles})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := pipeline.New(pipeline.Config{
		Domain:      grantapi.DomainCA,
		GrantKeys:   map[string]ed25519.PublicKey{"eaa-infisical-ca-e2e": eaaPublic},
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
	signer, err := cadomain.NewSigner(engine, provider)
	if err != nil {
		t.Fatal(err)
	}
	clientTransport := &http.Client{Transport: infisicalHandlerTransport{authority: authority.Handler(), signer: signer.Handler()}}
	agent, err := cadomain.NewAgent(cadomain.AgentConfig{
		AuthorityEndpoint: "http://authority.infisical-ca-e2e/v1/grants",
		SignerEndpoint:    "http://signer.infisical-ca-e2e/v1/sign",
		Identity:          identityRef,
		IdentityKey:       workerPrivate,
		SignerName:        signerName,
		Profile:           profileName,
		KeyUsages:         []string{cadomain.UsageDigitalSignature},
		Generation:        generationName,
		KeyID:             keyID,
		HTTPClient:        clientTransport,
		TrustedGrantKeys:  map[string]ed25519.PublicKey{"eaa-infisical-ca-e2e": eaaPublic},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, csrData, err := cadomain.GenerateCSR(subject, []string{"workload.infisical-e2e.example"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := agent.GetCertificate(context.Background(), csrData, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if response.Profile != profileName || response.Generation != generationName || response.KeyID != keyID {
		t.Fatalf("unexpected CA response: %#v", response)
	}
	chain, err := kms.ValidateCertificateChain(response.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 || chain[0].IsCA || chain[1].IsCA == false || bytes.Equal(chain[1].RawSubject, root.RawSubject) {
		t.Fatalf("unexpected CA chain: %d certificates", len(chain))
	}
	if err := chain[0].CheckSignatureFrom(chain[1]); err != nil {
		t.Fatalf("leaf is not signed by the Infisical intermediate: %v", err)
	}
	if err := chain[1].CheckSignatureFrom(root); err != nil {
		t.Fatalf("intermediate is not signed by the offline root: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(chain[1])
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("returned leaf does not verify to the offline root: %v", err)
	}
	if bytes.Contains(response.Certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})) {
		t.Fatal("CA response contains the root certificate")
	}
}

func requiredInfisicalEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Skipf("%s is not set; skipping live Infisical CA E2E", name)
	}
	return value
}

func parseInfisicalRSAPublicKey(data []byte) (*rsa.PublicKey, error) {
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	} else {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(data)))
		}
		if err != nil {
			return nil, fmt.Errorf("decode Infisical public key: %w", err)
		}
		data = decoded
	}
	public, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse Infisical public key: %w", err)
	}
	rsaPublic, ok := public.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Infisical key is %T, not RSA", public)
	}
	return rsaPublic, nil
}

func makeInfisicalRoot(t *testing.T, now time.Time) (crypto.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1001),
		Subject:               pkix.Name{CommonName: "infisical-e2e-root"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, certificate
}

func makeInfisicalIntermediate(t *testing.T, root *x509.Certificate, rootKey crypto.PrivateKey, publicKey *rsa.PublicKey, now time.Time) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1002),
		Subject:               pkix.Name{CommonName: "infisical-e2e-intermediate"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, publicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

type infisicalHandlerTransport struct {
	authority http.Handler
	signer    http.Handler
}

func (t infisicalHandlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	if request.URL.Path == "/v1/grants" {
		t.authority.ServeHTTP(recorder, request)
	} else {
		t.signer.ServeHTTP(recorder, request)
	}
	return recorder.Result(), nil
}
