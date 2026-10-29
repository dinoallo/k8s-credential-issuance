package pipeline

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	v1 "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/audit"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/generation"
	coregrant "github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/grant"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/ledger"
)

const (
	testGeneration = "generation-1"
	testKeyID      = "jwt-1"
	testDigest     = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testNotBefore  = int64(1700000000)
	testExpiresAt  = int64(1700003600)
)

type testPlugin struct{}

func (testPlugin) Domain() v1.Domain { return v1.DomainSA }

func (testPlugin) Canonicalize(_ context.Context, request Request) (Binding, error) {
	return Binding{Digest: testDigest, IdentityRef: request.IdentityRef, Generation: testGeneration, KeyID: testKeyID, NotBefore: testNotBefore, ExpiresAt: testExpiresAt, RequestedLifetime: 3600, SigningPayload: []byte(`{"sub":"worker"}`)}, nil
}

func (testPlugin) ValidateBinding(context.Context, v1.Grant, Binding) error { return nil }

func (testPlugin) Prepare(_ context.Context, value v1.Grant, binding Binding, operationID string) (kms.SigningIntent, error) {
	return kms.NewIntent(v1.DomainSA, kms.PurposeServiceAccountJWT, value.KeyID, value.Generation, "RS256", operationID, binding.SigningPayload)
}

func (testPlugin) Finalize(_ context.Context, value v1.Grant, _ Binding, artifact kms.Artifact) ([]byte, error) {
	return []byte(fmt.Sprintf("%s:%s", value.GrantID, artifact.Value)), nil
}

type testBackend struct {
	mu      sync.Mutex
	count   int
	failure error
}

func (b *testBackend) Sign(_ context.Context, policy kms.Policy, intent kms.SigningIntent) (kms.Artifact, error) {
	b.mu.Lock()
	b.count++
	b.mu.Unlock()
	if b.failure != nil {
		return kms.Artifact{}, b.failure
	}
	return kms.Artifact{Value: []byte("signed-artifact"), KeyID: policy.KeyID, Generation: policy.Generation, Algorithm: policy.Algorithm, PayloadDigest: intent.PayloadDigest}, nil
}

func (b *testBackend) PublicJWK(context.Context, kms.Policy) (map[string]any, error) {
	return map[string]any{"kty": "RSA"}, nil
}

type failingAudit struct{}

func (failingAudit) Record(context.Context, audit.Event) error {
	return errors.New("audit store unavailable")
}

func newPipelineTest(t *testing.T, auditSink audit.Sink, backend *testBackend) (*Engine, *ledger.MemoryStore, []byte, Request, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := generation.NewRegistry([]generation.Metadata{{Generation: testGeneration, KeyID: testKeyID, Algorithm: "RS256", State: generation.Active}})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := kms.NewProvider(backend, registry, []kms.Policy{{Domain: v1.DomainSA, Purpose: kms.PurposeServiceAccountJWT, Generation: testGeneration, KeyID: testKeyID, Algorithm: "RS256"}})
	if err != nil {
		t.Fatal(err)
	}
	store := ledger.NewMemoryStore()
	now := time.Unix(testNotBefore+1, 0)
	value := v1.Grant{Version: v1.ContractVersion, Domain: v1.DomainSA, GrantID: "grant-1", RequestID: "request-1", IdentityRef: "worker-1", BindingDigest: testDigest, Generation: testGeneration, KeyID: testKeyID, PolicyVersion: "policy-1", NotBefore: testNotBefore, ExpiresAt: testExpiresAt, Nonce: "nonce-1", TypedPayload: []byte(`{"kind":"test"}`)}
	rawGrant, err := coregrant.Sign(value, "eaa-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(Config{Domain: v1.DomainSA, GrantKeys: map[string]ed25519.PublicKey{"eaa-1": publicKey}, Plugin: testPlugin{}, Ledger: store, KMS: provider, Audit: auditSink, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return engine, store, rawGrant, Request{Domain: v1.DomainSA, IdentityRef: "worker-1", Grant: rawGrant, Body: []byte("test")}, privateKey
}

func TestPipelineRejectsCrossDomainBeforeSigning(t *testing.T) {
	backend := &testBackend{}
	engine, _, _, request, privateKey := newPipelineTest(t, audit.NopSink{}, backend)
	request.Domain = v1.DomainCA
	if _, err := engine.Issue(context.Background(), request); !errors.Is(err, ErrDomainDenied) {
		t.Fatalf("Issue error = %v, want domain denial", err)
	}
	caGrant := v1.Grant{Version: v1.ContractVersion, Domain: v1.DomainCA, GrantID: "ca-grant-1", RequestID: "ca-request-1", IdentityRef: "worker-1", BindingDigest: testDigest, Generation: testGeneration, KeyID: testKeyID, PolicyVersion: "policy-1", NotBefore: testNotBefore, ExpiresAt: testExpiresAt, Nonce: "ca-nonce-1", TypedPayload: []byte(`{"kind":"ca"}`)}
	rawCAGrant, err := coregrant.Sign(caGrant, "eaa-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	request.Domain = v1.DomainSA
	request.Grant = rawCAGrant
	if _, err := engine.Issue(context.Background(), request); !errors.Is(err, ErrBindingDenied) {
		t.Fatalf("CA Grant accepted by SA engine: %v", err)
	}
	backend.mu.Lock()
	count := backend.count
	backend.mu.Unlock()
	if count != 0 {
		t.Fatalf("cross-domain request called backend %d times", count)
	}
}

func TestPipelineFailsClosedWhenAuditUnavailable(t *testing.T) {
	backend := &testBackend{}
	engine, store, _, request, _ := newPipelineTest(t, failingAudit{}, backend)
	if _, err := engine.Issue(context.Background(), request); err == nil {
		t.Fatal("Issue succeeded while audit was unavailable")
	}
	reservation, ok, err := store.Lookup(context.Background(), "grant-1")
	if err != nil || !ok || reservation.State != ledger.RetryableFailure {
		t.Fatalf("unexpected audit-failure ledger state: %#v %v %v", reservation, ok, err)
	}
}

func TestPipelineKMSFailureIsRetryableAndDoesNotDeliver(t *testing.T) {
	backend := &testBackend{failure: errors.New("KMS timeout")}
	engine, store, _, request, _ := newPipelineTest(t, audit.NopSink{}, backend)
	if _, err := engine.Issue(context.Background(), request); err == nil {
		t.Fatal("Issue succeeded while KMS failed")
	}
	reservation, ok, err := store.Lookup(context.Background(), "grant-1")
	if err != nil || !ok || reservation.State != ledger.RetryableFailure || len(reservation.Result.Response) != 0 {
		t.Fatalf("unexpected KMS-failure ledger state: %#v %v %v", reservation, ok, err)
	}
}

func TestPipelineRetryReturnsRecordedResult(t *testing.T) {
	backend := &testBackend{}
	engine, _, _, request, _ := newPipelineTest(t, audit.NopSink{}, backend)
	first, err := engine.Issue(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.Issue(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("retry response changed: %q != %q", first, second)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.count != 1 {
		t.Fatalf("backend was called %d times, want one", backend.count)
	}
}
