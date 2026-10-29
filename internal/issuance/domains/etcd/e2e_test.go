package etcd_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	grantapi "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/authority/domains/etcd"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/audit"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/generation"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/ledger"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/pipeline"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/ca"
	etcdomain "github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/etcd"
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

func TestPeerAndClientProfilesRemainSeparated(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	eaaPublic, eaaPrivate, _ := ed25519.GenerateKey(rand.Reader)
	workerPublic, workerPrivate, _ := ed25519.GenerateKey(rand.Reader)
	rootKey, root := makeCA(t, nil, nil, "root", now, true)
	intermediateKey, intermediate := makeCA(t, root, rootKey, "intermediate", now, false)
	profiles, err := etcdomain.NewRegistry([]etcdomain.Profile{{Name: etcdomain.ProfilePeer, MaxTTL: time.Hour, Generation: "peer-gen", KeyID: "peer-key", Purpose: kms.PurposeEtcdPeerCertificate, RequiredKeyUsages: []string{etcdomain.UsageDigitalSignature}, AllowedKeyUsages: []string{etcdomain.UsageDigitalSignature}, RequiredExtendedUsages: []string{"clientAuth", "serverAuth"}, AllowedExtendedUsages: []string{"clientAuth", "serverAuth"}}})
	if err != nil {
		t.Fatal(err)
	}
	registry := etcd.NewMemoryRegistry("cluster-1")
	if err := registry.Register(context.Background(), etcd.Registration{ClusterInstance: "cluster-1", ID: "member-1", Identity: "agent-1", IdentityPublicKey: identity.EncodePublicKey(workerPublic), Profile: etcdomain.ProfilePeer, EndpointSANs: []string{"member-1.etcd"}, Generation: "peer-gen", KeyID: "peer-key", MaxTTL: time.Hour, Active: true}); err != nil {
		t.Fatal(err)
	}
	authority, err := etcd.New(etcd.Config{ClusterInstance: "cluster-1", PolicyVersion: "policy-1", EAAKeyID: "eaa-1", SigningKey: eaaPrivate, Registry: registry, Profiles: profiles, Audit: audit.NopSink{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	gen, err := generation.NewRegistry([]generation.Metadata{{Generation: "peer-gen", KeyID: "peer-key", Algorithm: kms.AlgorithmRSASHA256, State: generation.Active}})
	if err != nil {
		t.Fatal(err)
	}
	policy := kms.Policy{Domain: grantapi.DomainEtcd, Purpose: kms.PurposeEtcdPeerCertificate, Generation: "peer-gen", KeyID: "peer-key", Algorithm: kms.AlgorithmRSASHA256, Profile: etcdomain.ProfilePeer, MaxLifetime: time.Hour, RequiredKeyUsages: []string{etcdomain.UsageDigitalSignature}, AllowedKeyUsages: []string{etcdomain.UsageDigitalSignature}, RequiredExtendedKeyUsages: []string{"clientAuth", "serverAuth"}, AllowedExtendedKeyUsages: []string{"clientAuth", "serverAuth"}}
	backend, err := kms.NewLocalX509Backend([]kms.Policy{policy}, map[string]kms.X509Issuer{"peer-gen": {Certificate: intermediate, PrivateKey: intermediateKey, Chain: []*x509.Certificate{root}}})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := kms.NewProvider(backend, gen, []kms.Policy{policy})
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := etcdomain.NewPlugin(etcdomain.Config{ClusterInstance: "cluster-1", PolicyVersion: "policy-1", DefaultAlgorithm: kms.AlgorithmRSASHA256, Profiles: profiles})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := pipeline.New(pipeline.Config{Domain: grantapi.DomainEtcd, GrantKeys: map[string]ed25519.PublicKey{"eaa-1": eaaPublic}, Plugin: plugin, Ledger: ledger.NewMemoryStore(), KMS: provider, Revocations: authority, Audit: audit.NopSink{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := etcdomain.NewSigner(engine, provider)
	if err != nil {
		t.Fatal(err)
	}
	subject := grantapi.X509Subject{CommonName: "member-1", Organization: []string{"etcd"}}
	_, csrData, err := ca.GenerateCSR(subject, []string{"member-1.etcd"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTrip{authority: authority.Handler(), signer: signer.Handler()}}
	agent, err := etcdomain.NewAgent(etcdomain.AgentConfig{AuthorityEndpoint: "http://authority.invalid/v1/grants", SignerEndpoint: "http://signer.invalid/v1/sign", Identity: "agent-1", IdentityKey: workerPrivate, ClusterInstance: "cluster-1", ID: "member-1", MemberOrClientIdentity: "agent-1", EndpointSANs: []string{"member-1.etcd"}, Profile: etcdomain.ProfilePeer, Generation: "peer-gen", KeyID: "peer-key", HTTPClient: client, TrustedGrantKeys: map[string]ed25519.PublicKey{"eaa-1": eaaPublic}})
	if err != nil {
		t.Fatal(err)
	}
	response, err := agent.GetCertificate(context.Background(), csrData, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if response.Profile != etcdomain.ProfilePeer {
		t.Fatalf("unexpected peer response: %#v", response)
	}
	block, _ := pem.Decode(response.Certificate)
	if block == nil {
		t.Fatal("peer response is not PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.IsCA || certificate.DNSNames[0] != "member-1.etcd" {
		t.Fatalf("unexpected peer certificate: %#v", certificate)
	}
	clientPayload := signapiEtcdRequestForIsolation()
	if _, err := plugin.Prepare(context.Background(), grantapi.Grant{Domain: grantapi.DomainEtcd, KeyID: "peer-key", Generation: "peer-gen", TypedPayload: clientPayload}, pipeline.Binding{}, "op"); err == nil {
		t.Fatal("unexpectedly prepared an invalid profile payload")
	}
}

func signapiEtcdRequestForIsolation() []byte {
	return []byte(`{"cluster_instance":"cluster-1","member_or_client_id":"client-1","member_or_client_identity":"agent-1","endpoint_sans":[],"profile":"etcd-client","etcd_roles":["read"],"public_key_sha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","requested_lifetime":3600,"generation":"peer-gen","key_id":"peer-key"}`)
}

func makeCA(t *testing.T, parent *x509.Certificate, parentKey crypto.PrivateKey, name string, now time.Time, selfSigned bool) (crypto.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(int64(len(name) + 1)), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
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
