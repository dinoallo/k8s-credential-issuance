package sa

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/replay"
)

func TestRemoteAttestationResolverVerifiesBindingAndRequestConstraints(t *testing.T) {
	now := time.Unix(1_700_000_100, 0).UTC()
	attestorPublicKey, attestorPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expiration := int64(600)
	rawRequest, err := json.Marshal(map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenRequest",
		"spec": map[string]any{
			"audiences":         []string{"z-api", "api"},
			"expirationSeconds": expiration,
			"boundObjectRef": map[string]any{
				"kind": "Pod",
				"name": "reader",
				"uid":  "pod-uid-1",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := signapi.TokenBinding{
		ClusterID:               "cluster-1",
		ServiceAccountNamespace: "default",
		ServiceAccountName:      "reader",
		ServiceAccountUID:       "sa-uid-1",
		PodUID:                  "pod-uid-1",
		Subject:                 "system:serviceaccount:default:reader",
		Audience:                []string{"api", "z-api"},
		Issuer:                  "https://issuer.example",
		NotBefore:               now.Unix(),
		NotAfter:                now.Add(time.Hour).Unix(),
		TokenGeneration:         "generation-1",
	}
	client := &http.Client{Transport: agentRoundTripper(func(request *http.Request) (*http.Response, error) {
		var attestationRequest signapi.AttestationRequest
		if err := json.NewDecoder(request.Body).Decode(&attestationRequest); err != nil {
			return nil, err
		}
		if attestationRequest.Identity != "worker-1" || attestationRequest.Namespace != "default" || attestationRequest.Name != "reader" || attestationRequest.Nonce == "" {
			t.Fatalf("unexpected attestation request: %#v", attestationRequest)
		}
		digest, err := AttestationRequestDigest(attestationRequest)
		if err != nil {
			return nil, err
		}
		proof, err := identity.SignBindingProof("attestor-1", attestorPrivateKey, binding, digest, attestationRequest.Nonce, now)
		if err != nil {
			return nil, err
		}
		body, err := json.Marshal(signapi.AttestationResponse{RequestDigest: digest, Binding: binding, Proof: proof})
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), Request: request}, nil
	})}
	resolver, err := NewRemoteAttestationResolver(RemoteAttestationConfig{
		Endpoint:          "https://attestor.example/v1/attest",
		Identity:          "worker-1",
		AttestorIdentity:  "attestor-1",
		AttestorPublicKey: attestorPublicKey,
		HTTPClient:        client,
		Replay:            replay.NewMemoryStore(func() time.Time { return now }),
		Now:               func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := resolver.Resolve(context.Background(), "default", "reader", signapi.TokenRequest{Request: rawRequest})
	if err != nil {
		t.Fatal(err)
	}
	if result.NotAfter != now.Add(time.Duration(expiration)*time.Second).Unix() || len(result.Audience) != 2 || result.Audience[0] != "api" || result.Audience[1] != "z-api" {
		t.Fatalf("resolver did not apply TokenRequest constraints: %#v", result)
	}
}

func TestRemoteAttestationResolverFailsClosed(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unixResolver, err := NewRemoteAttestationResolver(RemoteAttestationConfig{Endpoint: "unix:///var/run/sa-attestor.sock", Identity: "worker-1", AttestorIdentity: "attestor-1", AttestorPublicKey: publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if unixResolver.endpoint.String() != "http://attestor/v1/attest" {
		t.Fatalf("Unix attestation endpoint = %q", unixResolver.endpoint.String())
	}
	for _, endpoint := range []string{"http://10.0.0.2:8080/v1/attest", "ftp://attestor.example/v1/attest"} {
		if _, err := NewRemoteAttestationResolver(RemoteAttestationConfig{Endpoint: endpoint, Identity: "worker-1", AttestorIdentity: "attestor-1", AttestorPublicKey: publicKey}); err == nil {
			t.Fatalf("accepted unsafe attestation endpoint %q", endpoint)
		}
	}

	attestorPublicKey, attestorPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	client := &http.Client{Transport: agentRoundTripper(func(request *http.Request) (*http.Response, error) {
		var attestationRequest signapi.AttestationRequest
		if err := json.NewDecoder(request.Body).Decode(&attestationRequest); err != nil {
			return nil, err
		}
		digest, err := AttestationRequestDigest(attestationRequest)
		if err != nil {
			return nil, err
		}
		binding := signapi.TokenBinding{ClusterID: "cluster-1", ServiceAccountNamespace: "default", ServiceAccountName: "reader", ServiceAccountUID: "sa-uid-1", Subject: "system:serviceaccount:default:reader", Audience: []string{"api"}, Issuer: "https://issuer.example", NotBefore: now.Unix(), NotAfter: now.Add(time.Hour).Unix(), TokenGeneration: "generation-1"}
		proof, err := identity.SignBindingProof("attestor-1", attestorPrivateKey, binding, "sha256:"+strings.Repeat("0", 64), attestationRequest.Nonce, now)
		if err != nil {
			return nil, err
		}
		body, err := json.Marshal(signapi.AttestationResponse{RequestDigest: digest, Binding: binding, Proof: proof})
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), Request: request}, nil
	})}
	resolver, err := NewRemoteAttestationResolver(RemoteAttestationConfig{Endpoint: "https://attestor.example/v1/attest", Identity: "worker-1", AttestorIdentity: "attestor-1", AttestorPublicKey: attestorPublicKey, HTTPClient: client, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), "default", "reader", signapi.TokenRequest{}); err == nil {
		t.Fatal("accepted an attestation proof with a mismatched request digest")
	}
}
