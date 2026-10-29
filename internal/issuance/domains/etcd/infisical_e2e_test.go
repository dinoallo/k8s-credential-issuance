//go:build infisical_e2e

package etcd_test

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
	"github.com/dinoallo/k8s-credential-issuance/internal/authority/domains/etcd"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/audit"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/generation"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms"
	infisicalapi "github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms/infisical"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/ledger"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/pipeline"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/ca"
	etcdomain "github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/etcd"
)

func TestInfisicalEtcdPeerCAEndToEnd(t *testing.T) {
	endpoint := requiredInfisicalEtcdEnv(t, "INFISICAL_KMS_ENDPOINT")
	tokenFile := requiredInfisicalEtcdEnv(t, "INFISICAL_KMS_TOKEN_FILE")
	keyRef := requiredInfisicalEtcdEnv(t, "INFISICAL_KMS_KEY_REF")
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
		t.Fatalf("Infisical key is not suitable for etcd issuance: %#v", key)
	}
	publicKeyMaterial, err := client.GetPublicKey(context.Background(), keyRef)
	if err != nil {
		t.Fatalf("read Infisical public key: %v", err)
	}
	publicKey, err := parseInfisicalEtcdRSAPublicKey(publicKeyMaterial)
	if err != nil {
		t.Fatal(err)
	}
	if publicKey.N.BitLen() < 2048 {
		t.Fatalf("Infisical RSA key is too small: %d bits", publicKey.N.BitLen())
	}

	const (
		clusterInstance = "cluster-infisical-etcd-e2e"
		policyVersion   = "etcd-policy-infisical-e2e"
		generationName  = "generation-infisical-etcd-peer-e2e"
		keyID           = "etcd-peer-infisical-e2e"
		identityRef     = "agent-infisical-etcd-e2e"
		memberID        = "member-infisical-etcd-e2e"
		profileName     = etcdomain.ProfilePeer
		endpointSAN     = "member.infisical-etcd-e2e.example"
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
	rootKey, root := makeInfisicalEtcdRoot(t, now)
	intermediate := makeInfisicalEtcdIntermediate(t, root, rootKey, publicKey, now)

	profiles, err := etcdomain.NewRegistry([]etcdomain.Profile{{
		Name:                   profileName,
		MaxTTL:                 time.Hour,
		Generation:             generationName,
		KeyID:                  keyID,
		Purpose:                kms.PurposeEtcdPeerCertificate,
		RequiredKeyUsages:      []string{etcdomain.UsageDigitalSignature},
		AllowedKeyUsages:       []string{etcdomain.UsageDigitalSignature},
		RequiredExtendedUsages: []string{"clientAuth", "serverAuth"},
		AllowedExtendedUsages:  []string{"clientAuth", "serverAuth"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	registry := etcd.NewMemoryRegistry(clusterInstance)
	if err := registry.Register(context.Background(), etcd.Registration{
		ClusterInstance:   clusterInstance,
		ID:                memberID,
		Identity:          identityRef,
		IdentityPublicKey: identity.EncodePublicKey(workerPublic),
		Profile:           profileName,
		EndpointSANs:      []string{endpointSAN},
		Generation:        generationName,
		KeyID:             keyID,
		MaxTTL:            time.Hour,
		Active:            true,
	}); err != nil {
		t.Fatal(err)
	}
	authority, err := etcd.New(etcd.Config{
		ClusterInstance: clusterInstance,
		PolicyVersion:   policyVersion,
		EAAKeyID:        "eaa-infisical-etcd-e2e",
		SigningKey:      eaaPrivate,
		Registry:        registry,
		Profiles:        profiles,
		Audit:           audit.NopSink{},
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	generationRegistry, err := generation.NewRegistry([]generation.Metadata{{
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
		Domain:                    grantapi.DomainEtcd,
		Purpose:                   kms.PurposeEtcdPeerCertificate,
		Generation:                generationName,
		KeyID:                     keyID,
		KeyRef:                    keyRef,
		PublicKey:                 string(publicKeyMaterial),
		Algorithm:                 kms.AlgorithmRSASHA256,
		Profile:                   profileName,
		MaxLifetime:               time.Hour,
		RequiredKeyUsages:         []string{etcdomain.UsageDigitalSignature},
		AllowedKeyUsages:          []string{etcdomain.UsageDigitalSignature},
		RequiredExtendedKeyUsages: []string{"clientAuth", "serverAuth"},
		AllowedExtendedKeyUsages:  []string{"clientAuth", "serverAuth"},
	}}
	backend, err := kms.NewInfisicalX509Backend(client, map[string]kms.X509Issuer{
		generationName: {Certificate: intermediate, Chain: []*x509.Certificate{root}},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := kms.NewProvider(backend, generationRegistry, policies)
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := etcdomain.NewPlugin(etcdomain.Config{
		ClusterInstance:  clusterInstance,
		PolicyVersion:    policyVersion,
		DefaultAlgorithm: kms.AlgorithmRSASHA256,
		Profiles:         profiles,
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := pipeline.New(pipeline.Config{
		Domain:      grantapi.DomainEtcd,
		GrantKeys:   map[string]ed25519.PublicKey{"eaa-infisical-etcd-e2e": eaaPublic},
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
	signer, err := etcdomain.NewSigner(engine, provider)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: infisicalEtcdHandlerTransport{authority: authority.Handler(), signer: signer.Handler()}}
	agent, err := etcdomain.NewAgent(etcdomain.AgentConfig{
		AuthorityEndpoint:      "http://authority.infisical-etcd-e2e/v1/grants",
		SignerEndpoint:         "http://signer.infisical-etcd-e2e/v1/sign",
		Identity:               identityRef,
		IdentityKey:            workerPrivate,
		ClusterInstance:        clusterInstance,
		ID:                     memberID,
		MemberOrClientIdentity: identityRef,
		EndpointSANs:           []string{endpointSAN},
		Profile:                profileName,
		Generation:             generationName,
		KeyID:                  keyID,
		HTTPClient:             httpClient,
		TrustedGrantKeys:       map[string]ed25519.PublicKey{"eaa-infisical-etcd-e2e": eaaPublic},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, csrData, err := ca.GenerateCSR(
		grantapi.X509Subject{CommonName: memberID, Organization: []string{"etcd"}},
		[]string{endpointSAN}, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	response, err := agent.GetCertificate(context.Background(), csrData, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if response.ClusterInstance != clusterInstance || response.MemberOrClientID != memberID || response.Profile != profileName || response.Generation != generationName || response.KeyID != keyID {
		t.Fatalf("unexpected etcd response: %#v", response)
	}
	chain, err := kms.ValidateCertificateChain(response.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 || chain[0].IsCA || !chain[1].IsCA || bytes.Equal(chain[1].RawSubject, root.RawSubject) {
		t.Fatalf("unexpected etcd certificate chain: %d certificates", len(chain))
	}
	if err := chain[0].CheckSignatureFrom(chain[1]); err != nil {
		t.Fatalf("peer certificate is not signed by the Infisical intermediate: %v", err)
	}
	if err := chain[1].CheckSignatureFrom(root); err != nil {
		t.Fatalf("intermediate is not signed by the offline root: %v", err)
	}
	if len(chain[0].DNSNames) != 1 || chain[0].DNSNames[0] != endpointSAN {
		t.Fatalf("peer certificate has unexpected endpoint SANs: %#v", chain[0].DNSNames)
	}
	if !hasExtKeyUsage(chain[0], x509.ExtKeyUsageClientAuth) || !hasExtKeyUsage(chain[0], x509.ExtKeyUsageServerAuth) {
		t.Fatalf("peer certificate is missing the required client/server EKUs: %#v", chain[0].ExtKeyUsage)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(chain[1])
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       endpointSAN,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("peer certificate does not verify to the offline root: %v", err)
	}
	if bytes.Contains(response.Certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})) {
		t.Fatal("etcd response contains the root certificate")
	}

	badAgent, err := etcdomain.NewAgent(etcdomain.AgentConfig{
		AuthorityEndpoint:      "http://authority.infisical-etcd-e2e/v1/grants",
		SignerEndpoint:         "http://signer.infisical-etcd-e2e/v1/sign",
		Identity:               identityRef,
		IdentityKey:            workerPrivate,
		ClusterInstance:        clusterInstance,
		ID:                     memberID,
		MemberOrClientIdentity: identityRef,
		EndpointSANs:           []string{endpointSAN},
		Profile:                profileName,
		Roles:                  []string{etcdomain.RoleRead},
		Generation:             generationName,
		KeyID:                  keyID,
		HTTPClient:             httpClient,
		TrustedGrantKeys:       map[string]ed25519.PublicKey{"eaa-infisical-etcd-e2e": eaaPublic},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := badAgent.GetCertificate(context.Background(), csrData, time.Hour); err == nil {
		t.Fatal("etcd authority accepted a peer request with client roles")
	}
}

func requiredInfisicalEtcdEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Skipf("%s is not set; skipping live Infisical etcd E2E", name)
	}
	return value
}

func parseInfisicalEtcdRSAPublicKey(data []byte) (*rsa.PublicKey, error) {
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

func makeInfisicalEtcdRoot(t *testing.T, now time.Time) (crypto.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2001),
		Subject:               pkix.Name{CommonName: "infisical-etcd-e2e-root"},
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

func makeInfisicalEtcdIntermediate(t *testing.T, root *x509.Certificate, rootKey crypto.PrivateKey, publicKey *rsa.PublicKey, now time.Time) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2002),
		Subject:               pkix.Name{CommonName: "infisical-etcd-e2e-intermediate"},
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

func hasExtKeyUsage(certificate *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == want {
			return true
		}
	}
	return false
}

type infisicalEtcdHandlerTransport struct {
	authority http.Handler
	signer    http.Handler
}

func (t infisicalEtcdHandlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	if request.URL.Path == "/v1/grants" {
		t.authority.ServeHTTP(recorder, request)
	} else {
		t.signer.ServeHTTP(recorder, request)
	}
	return recorder.Result(), nil
}
