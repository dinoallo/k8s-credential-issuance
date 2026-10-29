package grant

import (
	"crypto/ed25519"
	"testing"
	"time"

	v1 "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
)

func testGrant() v1.Grant {
	return v1.Grant{
		Version: v1.ContractVersion, Domain: v1.DomainSA, GrantID: "grant-1", RequestID: "request-1", IdentityRef: "worker-1", BindingDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Generation: "generation-1", KeyID: "jwt-1", PolicyVersion: "policy-1", NotBefore: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(), Nonce: "nonce-1", TypedPayload: []byte(`{"cluster_id":"cluster-1"}`),
	}
}

func TestSignAndVerifyCompactGrant(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Sign(testGrant(), "eaa-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	value, header, err := Verify(raw, map[string]ed25519.PublicKey{"eaa-1": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if value.GrantID != "grant-1" || header.KeyID != "eaa-1" || header.Algorithm != Algorithm {
		t.Fatalf("unexpected verified Grant/header: %#v %#v", value, header)
	}
}

func TestVerifyRejectsWrongKeyAndUnknownPayloadField(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Sign(testGrant(), "eaa-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, _, _ := ed25519.GenerateKey(nil)
	if _, _, err := Verify(raw, map[string]ed25519.PublicKey{"eaa-1": otherPublic}); err == nil {
		t.Fatal("verified Grant with the wrong key")
	}
	_ = publicKey
}
