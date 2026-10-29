package etcd_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/dinoallo/k8s-credential-issuance/internal/authority/domains/etcd"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	etcdomain "github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/etcd"
)

func TestMemberReplacementAndSnapshotRestore(t *testing.T) {
	registry := etcd.NewMemoryRegistry("cluster-1")
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registration := func(id, identityRef string) etcd.Registration {
		return etcd.Registration{ClusterInstance: "cluster-1", ID: id, Identity: identityRef, IdentityPublicKey: identity.EncodePublicKey(publicKey), Profile: etcdomain.ProfilePeer, EndpointSANs: []string{id + ".etcd"}, Generation: "peer-generation", KeyID: "peer-key", MaxTTL: time.Hour, Active: true}
	}
	if err := registry.Register(context.Background(), registration("member-1", "agent-1")); err != nil {
		t.Fatal(err)
	}
	snapshot, err := registry.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.ReplaceMember(context.Background(), "member-1", registration("member-2", "agent-2")); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Find(context.Background(), etcdomain.ProfilePeer, "member-1", "agent-1"); err == nil {
		t.Fatal("replaced member remained active")
	}
	if _, err := registry.Find(context.Background(), etcdomain.ProfilePeer, "member-2", "agent-2"); err != nil {
		t.Fatal(err)
	}
	if err := registry.RestoreSnapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Find(context.Background(), etcdomain.ProfilePeer, "member-1", "agent-1"); err != nil {
		t.Fatalf("snapshot restore did not restore member: %v", err)
	}
	if _, err := registry.Find(context.Background(), etcdomain.ProfilePeer, "member-2", "agent-2"); err == nil {
		t.Fatal("snapshot restore retained replacement member")
	}
}
