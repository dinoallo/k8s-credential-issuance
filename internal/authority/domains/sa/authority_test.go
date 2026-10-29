package sa

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/audit"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/replay"
)

func TestAuthorityRefreshesIdentityKeysAfterRegistration(t *testing.T) {
	nodePublic, nodePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_100, 0)
	registrations := NewMemoryRegistrationStore()
	authority, err := New(Config{ClusterID: "cluster-1", Issuer: "https://issuer.example", PolicyVersion: "policy-1", KeyID: "eaa-1", PrivateKey: authorityPrivate, Registrations: registrations, ProofReplay: replay.NewMemoryStore(func() time.Time { return now }), Grants: NewMemoryGrantLedger(), Audit: audit.NopSink{}, Now: func() time.Time { return now }, MaxTokenLifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Register(context.Background(), WorkloadRegistration{RegistrationID: "registration-1", Identity: "worker-1", IdentityPublicKey: identity.EncodePublicKey(nodePublic), ClusterID: "cluster-1", ServiceAccountNamespace: "default", ServiceAccountName: "reader", ServiceAccountUID: "sa-uid-1", Issuer: "https://issuer.example", AllowedAudiences: []string{"api"}, MaxTokenLifetimeSecs: 3600, TokenGeneration: "generation-1", KeyID: "jwt-1", PolicyVersion: "policy-1", Active: true}); err != nil {
		t.Fatal(err)
	}
	binding := signapi.TokenBinding{ClusterID: "cluster-1", ServiceAccountNamespace: "default", ServiceAccountName: "reader", ServiceAccountUID: "sa-uid-1", Subject: "system:serviceaccount:default:reader", Audience: []string{"api"}, Issuer: "https://issuer.example", NotBefore: now.Unix(), NotAfter: now.Add(time.Hour).Unix(), TokenGeneration: "generation-1"}
	digest := "sha256:" + strings.Repeat("a", 64)
	proof, err := identity.SignProof("worker-1", nodePrivate, binding, digest, "proof-1", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Issue(context.Background(), signapi.GrantRequest{Identity: "worker-1", ClaimsDigest: digest, Binding: binding, Proof: proof}); err != nil {
		t.Fatalf("authority rejected a registration added after construction: %v", err)
	}
}
