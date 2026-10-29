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
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	grantapi "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/authority/domains/ca"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/audit"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/generation"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/ledger"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/pipeline"
	cadomain "github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/ca"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/ca/csr"
)

type roundTrip struct{ authority, signer http.Handler }

func (r roundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	if request.URL.Path == "/v1/grants" {
		r.authority.ServeHTTP(recorder, request)
	} else {
		r.signer.ServeHTTP(recorder, request)
	}
	return recorder.Result(), nil
}

func TestCertificateAgentIssuesLeafAndIntermediateWithoutRoot(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	eaaPublic, eaaPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	workerPublic, workerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootKey, root := makeCA(t, nil, nil, "root", now, true)
	intermediateKey, intermediate := makeCA(t, root, rootKey, "intermediate", now, false)
	profiles, err := cadomain.NewRegistry([]cadomain.Profile{{Name: "test-client", SignerName: "example.com/test", MaxTTL: time.Hour, RequiredKeyUsages: []string{cadomain.UsageDigitalSignature}, AllowedKeyUsages: []string{cadomain.UsageDigitalSignature}}})
	if err != nil {
		t.Fatal(err)
	}
	registrations := ca.NewMemoryRegistrationStore()
	subject := grantapi.X509Subject{CommonName: "workload", Organization: []string{"example"}}
	if err := registrations.Register(context.Background(), ca.Registration{Identity: "agent-1", IdentityPublicKey: identity.EncodePublicKey(workerPublic), ClusterID: "cluster-1", Profile: "test-client", SignerName: "example.com/test", Subject: subject, DNSNames: []string{"workload.example"}, KeyUsages: []string{cadomain.UsageDigitalSignature}, Generation: "ca-gen-1", KeyID: "ca-key-1", MaxTTL: time.Hour, Active: true}); err != nil {
		t.Fatal(err)
	}
	authority, err := ca.New(ca.Config{ClusterID: "cluster-1", PolicyVersion: "policy-1", EAAKeyID: "eaa-1", SigningKey: eaaPrivate, Registrations: registrations, Profiles: profiles, Audit: audit.NopSink{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := generation.NewRegistry([]generation.Metadata{{Generation: "ca-gen-1", KeyID: "ca-key-1", Algorithm: kms.AlgorithmRSASHA256, State: generation.Active}})
	if err != nil {
		t.Fatal(err)
	}
	policy := kms.Policy{Domain: grantapi.DomainCA, Purpose: kms.PurposeCACertificate, Generation: "ca-gen-1", KeyID: "ca-key-1", Algorithm: kms.AlgorithmRSASHA256, Profile: "test-client", SignerName: "example.com/test", MaxLifetime: time.Hour, RequiredKeyUsages: []string{cadomain.UsageDigitalSignature}, AllowedKeyUsages: []string{cadomain.UsageDigitalSignature}}
	if _, err := kms.NewLocalX509Backend([]kms.Policy{policy}, map[string]kms.X509Issuer{"ca-gen-1": {Certificate: root, PrivateKey: rootKey}}); err == nil {
		t.Fatal("CA KMS accepted a root key where an intermediate is required")
	}
	backend, err := kms.NewLocalX509Backend([]kms.Policy{policy}, map[string]kms.X509Issuer{"ca-gen-1": {Certificate: intermediate, PrivateKey: intermediateKey, Chain: []*x509.Certificate{root}}})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := kms.NewProvider(backend, registry, []kms.Policy{policy})
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := cadomain.NewPlugin(cadomain.Config{PolicyVersion: "policy-1", DefaultAlgorithm: kms.AlgorithmRSASHA256, Profiles: profiles})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := pipeline.New(pipeline.Config{Domain: grantapi.DomainCA, GrantKeys: map[string]ed25519.PublicKey{"eaa-1": eaaPublic}, Plugin: plugin, Ledger: ledger.NewMemoryStore(), KMS: provider, Revocations: authority, Audit: audit.NopSink{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cadomain.NewSigner(engine, provider)
	if err != nil {
		t.Fatal(err)
	}
	_, csrData, err := cadomain.GenerateCSR(subject, []string{"workload.example"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTrip{authority: authority.Handler(), signer: signer.Handler()}}
	agent, err := cadomain.NewAgent(cadomain.AgentConfig{AuthorityEndpoint: "http://authority.invalid/v1/grants", SignerEndpoint: "http://signer.invalid/v1/sign", Identity: "agent-1", IdentityKey: workerPrivate, SignerName: "example.com/test", Profile: "test-client", KeyUsages: []string{cadomain.UsageDigitalSignature}, Generation: "ca-gen-1", KeyID: "ca-key-1", HTTPClient: client, TrustedGrantKeys: map[string]ed25519.PublicKey{"eaa-1": eaaPublic}})
	if err != nil {
		t.Fatal(err)
	}
	response, err := agent.GetCertificate(context.Background(), csrData, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if response.Profile != "test-client" || response.Generation != "ca-gen-1" {
		t.Fatalf("unexpected response: %#v", response)
	}
	blocks := make([]*x509.Certificate, 0, 3)
	rest := response.Certificate
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil {
			t.Fatal("certificate result contains non-PEM data")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		blocks = append(blocks, certificate)
		rest = next
	}
	if len(blocks) != 2 {
		t.Fatalf("certificate chain has %d certificates, want leaf plus intermediate", len(blocks))
	}
	if blocks[0].IsCA || bytes.Equal(blocks[1].RawSubject, root.RawSubject) {
		t.Fatal("certificate output contains a root or a CA leaf")
	}
	if err := blocks[0].CheckSignatureFrom(blocks[1]); err != nil {
		t.Fatalf("leaf is not signed by intermediate: %v", err)
	}
	badAgent, err := cadomain.NewAgent(cadomain.AgentConfig{AuthorityEndpoint: "http://authority.invalid/v1/grants", SignerEndpoint: "http://signer.invalid/v1/sign", Identity: "agent-1", IdentityKey: workerPrivate, SignerName: "example.com/test", Profile: "different-profile", KeyUsages: []string{cadomain.UsageDigitalSignature}, Generation: "ca-gen-1", KeyID: "ca-key-1", HTTPClient: client, TrustedGrantKeys: map[string]ed25519.PublicKey{"eaa-1": eaaPublic}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := badAgent.GetCertificate(context.Background(), csrData, time.Hour); err == nil {
		t.Fatal("CA authority accepted a Grant request for an unregistered profile")
	}
	parsedCSR, der, err := csr.Parse(csrData)
	if err != nil {
		t.Fatal(err)
	}
	grantInput := signapi.CertificateSignRequest{CSR: csrData, SignerName: "example.com/test", Profile: "test-client", KeyUsages: []string{cadomain.UsageDigitalSignature}, ExpirationSeconds: 3600, Generation: "ca-gen-1", KeyID: "ca-key-1"}
	grantPayload, err := cadomain.Payload(grantInput, parsedCSR, der)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := identity.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignBindingProof("agent-1", workerPrivate, grantPayload, grantPayload.CSRRequestDigest, nonce, now)
	if err != nil {
		t.Fatal(err)
	}
	grantResult, err := authority.Issue(context.Background(), ca.Request{Identity: "agent-1", CSR: csrData, SignerName: "example.com/test", Profile: "test-client", KeyUsages: []string{cadomain.UsageDigitalSignature}, ExpirationSeconds: 3600, Generation: "ca-gen-1", KeyID: "ca-key-1", Proof: proof})
	if err != nil {
		t.Fatal(err)
	}
	carrierStore := &memoryCarrierStore{value: signapi.CertificateSigningRequestCarrier{Metadata: signapi.CarrierMetadata{Name: "csr-1", UID: "uid-1", Annotations: map[string]string{signapi.CertificateGrantAnnotation: grantResult.Grant, signapi.RequestIDAnnotation: grantResult.RequestID, "issuance.example.com/identity": "agent-1"}}, Spec: signapi.CertificateSigningRequestSpec{Request: csrData, SignerName: "example.com/test", Profile: "test-client", Usages: []string{cadomain.UsageDigitalSignature}, ExpirationSeconds: 3600}}}
	controller := cadomain.StatusController{Store: carrierStore, Signer: signer, GrantKeys: map[string]ed25519.PublicKey{"eaa-1": eaaPublic}}
	if err := controller.Process(context.Background(), "csr-1"); err != nil {
		t.Fatal(err)
	}
	if len(carrierStore.value.Status.Certificate) == 0 || len(carrierStore.value.Status.CA) != 0 || carrierStore.updates != 1 {
		t.Fatalf("unexpected CSR status delivery: %#v", carrierStore.value.Status)
	}
	_ = rootKey
}

type memoryCarrierStore struct {
	value   signapi.CertificateSigningRequestCarrier
	updates int
}

func (s *memoryCarrierStore) Get(context.Context, string) (signapi.CertificateSigningRequestCarrier, error) {
	return s.value, nil
}

func (s *memoryCarrierStore) UpdateStatus(_ context.Context, value signapi.CertificateSigningRequestCarrier) error {
	if value.Spec.SignerName != s.value.Spec.SignerName || string(value.Spec.Request) != string(s.value.Spec.Request) {
		return fmt.Errorf("status update modified CSR spec")
	}
	s.value.Status = value.Status
	s.updates++
	return nil
}

func makeCA(t *testing.T, parent *x509.Certificate, parentKey crypto.PrivateKey, name string, now time.Time, selfSigned bool) (crypto.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial := big.NewInt(int64(len(name) + 1))
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	if selfSigned {
		parent = certificate
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, parsed
}
