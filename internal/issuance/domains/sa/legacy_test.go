package sa

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/canonical"
)

func TestLegacyTokenGrantSignParseVerify(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	value := LegacyTokenGrant{
		GrantID:                 "grant-1",
		ClusterID:               "cluster-1",
		ClaimsDigest:            "sha256:" + strings.Repeat("a", 64),
		ServiceAccountNamespace: "default",
		ServiceAccountName:      "reader",
		ServiceAccountUID:       "sa-uid-1",
		PodUID:                  "pod-uid-1",
		Subject:                 "system:serviceaccount:default:reader",
		Audience:                []string{"z-api", "api"},
		Issuer:                  "https://issuer.example",
		TokenGeneration:         "generation-1",
		NotBefore:               100,
		NotAfter:                200,
		Nonce:                   "nonce-1",
		PolicyVersion:           "policy-1",
	}
	raw, err := SignLegacyGrant(value, "eaa-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseLegacyTokenGrant(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Audience[0] != "api" || parsed.Audience[1] != "z-api" || parsed.IssuerAndSignature == "" {
		t.Fatalf("unexpected parsed legacy Grant: %#v", parsed)
	}
	typed, header, err := VerifyLegacyGrant(raw, map[string]ed25519.PublicKey{"eaa-1": publicKey}, "jwt-1")
	if err != nil {
		t.Fatal(err)
	}
	if header.Format != LegacyGrantFormat || header.KeyID != "eaa-1" || typed.GrantID != value.GrantID || typed.KeyID != "jwt-1" {
		t.Fatalf("unexpected common Grant conversion: %#v %#v", typed, header)
	}

	// The staging implementation canonicalizes through encoding/json, whose
	// HTML escaping is part of its signature bytes. Keep that behavior in the
	// adapter even though the common core uses a different canonicalizer.
	withHTML := value
	withHTML.Subject = "system:<serviceaccount>&reader"
	withHTML.Audience = []string{"api", "z-api"}
	unsigned := withHTML
	unsigned.IssuerAndSignature = ""
	unsignedRaw, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(unsignedRaw))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	expectedSigningBytes, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	actualSigningBytes, err := LegacySigningBytes(withHTML)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualSigningBytes, expectedSigningBytes) {
		t.Fatalf("legacy signing bytes changed: got %s want %s", actualSigningBytes, expectedSigningBytes)
	}
}

func TestLegacyTokenGrantRejectsUnknownAndNonCanonicalFields(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	value := LegacyTokenGrant{
		GrantID:                 "grant-1",
		ClusterID:               "cluster-1",
		ClaimsDigest:            "sha256:" + strings.Repeat("a", 64),
		ServiceAccountNamespace: "default",
		ServiceAccountName:      "reader",
		ServiceAccountUID:       "sa-uid-1",
		Subject:                 "system:serviceaccount:default:reader",
		Audience:                []string{"api"},
		Issuer:                  "https://issuer.example",
		TokenGeneration:         "generation-1",
		NotBefore:               100,
		NotAfter:                200,
		Nonce:                   "nonce-1",
		PolicyVersion:           "policy-1",
	}
	raw, err := SignLegacyGrant(value, "eaa-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpected"] = true
	unknown, err := canonical.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseLegacyTokenGrant(unknown); err == nil {
		t.Fatal("legacy parser accepted an unknown field")
	}
	if _, err := ParseLegacyTokenGrant(append([]byte(" "), raw...)); err == nil {
		t.Fatal("legacy parser accepted non-canonical whitespace")
	}
}

func TestLegacyClaimsCanonicalizationMatchesStagingRules(t *testing.T) {
	claims := []byte(`{"sub":"<reader>&","aud":["api"]}`)
	canonicalClaims, err := CanonicalizeLegacyClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	if string(canonicalClaims) != `{"aud":["api"],"sub":"\u003creader\u003e\u0026"}` {
		t.Fatalf("unexpected legacy claims canonicalization: %s", canonicalClaims)
	}
	commonClaims, err := CanonicalizeClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(commonClaims, canonicalClaims) {
		t.Fatal("legacy claims canonicalization unexpectedly used common escaping")
	}
	if LegacyClaimsDigest(canonicalClaims) != ClaimsDigest(canonicalClaims) {
		t.Fatal("legacy claims digest is not SHA-256 over canonical claims")
	}
}
