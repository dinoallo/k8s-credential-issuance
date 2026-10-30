package kubernetes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/replay"
	sadomain "github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/sa"
)

func TestServiceAttestsNestedKubernetesTokenRequest(t *testing.T) {
	now := time.Unix(1_700_000_100, 0).UTC()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	api := fakeAPI{
		pod:            Pod{UID: "pod-uid-1", NodeName: "node-1", ServiceAccountName: "reader"},
		serviceAccount: ServiceAccount{UID: "sa-uid-1"},
	}
	service, err := NewService(Config{
		AttestorIdentity: "attestor-1",
		AttestorKey:      privateKey,
		ClusterID:        "cluster-1",
		Issuer:           "https://issuer.example",
		TokenGeneration:  "generation-1",
		KeyID:            "jwt-2026-01",
		DefaultAudience:  "api",
		MaxTokenLifetime: time.Hour,
		API:              &api,
		Now:              func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	expiration := int64(900)
	rawRequest, err := json.Marshal(map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenRequest",
		"spec": map[string]any{
			"audiences":         []string{"istio-ca", "api"},
			"expirationSeconds": expiration,
			"boundObjectRef": map[string]any{
				"kind":       "Pod",
				"apiVersion": "v1",
				"name":       "reader-pod",
				"uid":        "pod-uid-1",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := signapi.AttestationRequest{
		Identity:  "node-1",
		Namespace: "default",
		Name:      "reader",
		Request: signapi.TokenRequest{
			Namespace: "default",
			Name:      "reader",
			Request:   rawRequest,
		},
		Nonce: "proof-nonce-1",
	}
	response := invokeAttestation(t, service, input)
	if response.Binding.ServiceAccountUID != "sa-uid-1" || response.Binding.PodUID != "pod-uid-1" {
		t.Fatalf("unexpected immutable binding: %#v", response.Binding)
	}
	if got, want := response.Binding.Audience, []string{"api", "istio-ca"}; !equalStrings(got, want) {
		t.Fatalf("audience = %#v, want %#v", got, want)
	}
	if response.Binding.NotAfter != now.Add(time.Duration(expiration)*time.Second).Unix() {
		t.Fatalf("NotAfter = %d, want %d", response.Binding.NotAfter, now.Add(time.Duration(expiration)*time.Second).Unix())
	}
	digest, err := sadomain.AttestationRequestDigest(input)
	if err != nil {
		t.Fatal(err)
	}
	if response.RequestDigest != digest {
		t.Fatalf("request digest = %q, want %q", response.RequestDigest, digest)
	}
	verifier := identity.NewVerifier(map[string]ed25519.PublicKey{"attestor-1": publicKey}, replay.NewMemoryStore(func() time.Time { return now }))
	verifier.Now = func() time.Time { return now }
	if err := verifier.VerifyBindingProof(context.Background(), "attestor-1", response.Proof, response.Binding, digest); err != nil {
		t.Fatalf("verify attestation proof: %v", err)
	}
	if api.podCalls != 1 || api.serviceAccountCalls != 1 {
		t.Fatalf("Kubernetes API calls = pod %d, serviceaccount %d", api.podCalls, api.serviceAccountCalls)
	}
}

func TestServiceRejectsMismatchedOrUnsafeRequests(t *testing.T) {
	now := time.Unix(1_700_000_100, 0).UTC()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	api := &fakeAPI{
		pod:            Pod{UID: "pod-uid-1", NodeName: "node-1", ServiceAccountName: "reader"},
		serviceAccount: ServiceAccount{UID: "sa-uid-1"},
	}
	service, err := NewService(Config{
		AttestorIdentity: "attestor-1",
		AttestorKey:      privateKey,
		ClusterID:        "cluster-1",
		Issuer:           "https://issuer.example",
		TokenGeneration:  "generation-1",
		KeyID:            "jwt-2026-01",
		DefaultAudience:  "api",
		MaxTokenLifetime: time.Hour,
		API:              api,
		Now:              func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	base := signapi.AttestationRequest{
		Identity:  "node-1",
		Namespace: "default",
		Name:      "reader",
		Request: signapi.TokenRequest{
			Namespace: "default",
			Name:      "reader",
			Request:   nestedTokenRequest(t, "reader-pod", "pod-uid-1", []string{"api"}, 600),
		},
		Nonce: "proof-nonce-1",
	}
	tests := []struct {
		name   string
		modify func(*signapi.AttestationRequest)
	}{
		{name: "wrong node", modify: func(request *signapi.AttestationRequest) { request.Identity = "node-2" }},
		{name: "wrong pod uid", modify: func(request *signapi.AttestationRequest) {
			request.Request.Request = nestedTokenRequest(t, "reader-pod", "pod-uid-2", []string{"api"}, 600)
		}},
		{name: "wrong service account", modify: func(request *signapi.AttestationRequest) { request.Name = "other"; request.Request.Name = "other" }},
		{name: "duplicate audience", modify: func(request *signapi.AttestationRequest) {
			request.Request.Request = nestedTokenRequest(t, "reader-pod", "pod-uid-1", []string{"api", "api"}, 600)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			input.Request.Request = append([]byte(nil), base.Request.Request...)
			test.modify(&input)
			recorder := httptest.NewRecorder()
			body, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "http://attestor/v1/attest", bytes.NewReader(body))
			service.Handler().ServeHTTP(recorder, request)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body = %s", recorder.Code, http.StatusForbidden, recorder.Body.String())
			}
		})
	}
}

func TestServiceRejectsTrailingNestedTokenRequestJSON(t *testing.T) {
	raw := append(nestedTokenRequest(t, "reader-pod", "pod-uid-1", []string{"api"}, 600), []byte(` {"extra":true}`)...)
	if _, _, _, _, err := sadomain.KubernetesTokenRequestDetails(signapi.TokenRequest{Request: raw}); err == nil {
		t.Fatal("accepted a nested TokenRequest with trailing JSON")
	}
}

func TestRequireTLSClientIdentityRequiresVerifiedExactSAN(t *testing.T) {
	certificate := &x509.Certificate{DNSNames: []string{"node-1"}}
	request := &http.Request{TLS: &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}}
	if err := RequireTLSClientIdentity(request, "node-1"); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"node-2", "system:node:node-1"} {
		if err := RequireTLSClientIdentity(request, expected); err == nil {
			t.Fatalf("accepted certificate SAN for identity %q", expected)
		}
	}
	request.TLS.VerifiedChains = nil
	if err := RequireTLSClientIdentity(request, "node-1"); err == nil {
		t.Fatal("accepted an unverified client certificate")
	}
	cnOnly := &http.Request{TLS: &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "node-1"}}},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}}
	if err := RequireTLSClientIdentity(cnOnly, "node-1"); err == nil {
		t.Fatal("accepted Common Name as client identity")
	}
}

type fakeAPI struct {
	pod                 Pod
	serviceAccount      ServiceAccount
	podCalls            int
	serviceAccountCalls int
}

func (f *fakeAPI) GetPod(context.Context, string, string) (Pod, error) {
	f.podCalls++
	return f.pod, nil
}

func (f *fakeAPI) GetServiceAccount(context.Context, string, string) (ServiceAccount, error) {
	f.serviceAccountCalls++
	return f.serviceAccount, nil
}

func invokeAttestation(t *testing.T, service *Service, input signapi.AttestationRequest) signapi.AttestationResponse {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "http://attestor/v1/attest", bytes.NewReader(body))
	service.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response signapi.AttestationResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func nestedTokenRequest(t *testing.T, podName, podUID string, audiences []string, expiration int64) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenRequest",
		"spec": map[string]any{
			"audiences":         audiences,
			"expirationSeconds": expiration,
			"boundObjectRef": map[string]any{
				"kind": "Pod",
				"name": podName,
				"uid":  podUID,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
