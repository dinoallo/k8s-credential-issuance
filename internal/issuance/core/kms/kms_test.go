package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"

	v1 "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/generation"
)

type blockingBackend struct {
	mu      sync.Mutex
	started chan struct{}
	release chan struct{}
	count   int
}

type kmsRoundTripper func(*http.Request) (*http.Response, error)

func (f kmsRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func (b *blockingBackend) Sign(_ context.Context, policy Policy, intent SigningIntent) (Artifact, error) {
	b.mu.Lock()
	b.count++
	if b.count == 1 {
		close(b.started)
	}
	b.mu.Unlock()
	<-b.release
	return Artifact{Value: []byte("artifact"), KeyID: policy.KeyID, Generation: policy.Generation, Algorithm: policy.Algorithm, PayloadDigest: intent.PayloadDigest}, nil
}

func (b *blockingBackend) PublicJWK(context.Context, Policy) (map[string]any, error) {
	return map[string]any{"kty": "RSA"}, nil
}

func TestProviderDeduplicatesConcurrentOperationIDs(t *testing.T) {
	backend := &blockingBackend{started: make(chan struct{}), release: make(chan struct{})}
	registry, err := generation.NewRegistry([]generation.Metadata{{Generation: "generation-1", KeyID: "jwt-1", Algorithm: "RS256", State: generation.Active}})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewProvider(backend, registry, []Policy{{Domain: v1.DomainSA, Purpose: PurposeServiceAccountJWT, Generation: "generation-1", KeyID: "jwt-1", Algorithm: "RS256"}})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := NewIntent(v1.DomainSA, PurposeServiceAccountJWT, "jwt-1", "generation-1", "RS256", "operation-1", []byte(`{"sub":"worker"}`))
	if err != nil {
		t.Fatal(err)
	}

	firstResult := make(chan error, 1)
	go func() {
		_, err := provider.Sign(context.Background(), intent)
		firstResult <- err
	}()
	<-backend.started
	secondResult := make(chan error, 1)
	go func() {
		_, err := provider.Sign(context.Background(), intent)
		secondResult <- err
	}()
	close(backend.release)
	if err := <-firstResult; err != nil {
		t.Fatal(err)
	}
	if err := <-secondResult; err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.count != 1 {
		t.Fatalf("backend was called %d times, want one", backend.count)
	}
}

func TestHTTPBackendUsesConstrainedJWTAndKeyPolicyRequests(t *testing.T) {
	policy := Policy{Domain: v1.DomainSA, Purpose: PurposeServiceAccountJWT, Generation: "generation-1", KeyID: "jwt-1", KeyRef: "kms/sa/jwt-1", Algorithm: "RS256"}
	client := &http.Client{Transport: kmsRoundTripper(func(request *http.Request) (*http.Response, error) {
		var body []byte
		if request.Body != nil {
			var err error
			body, err = io.ReadAll(request.Body)
			if err != nil {
				return nil, err
			}
		}
		if request.Method == http.MethodPost {
			if request.URL.Path != "/v1/sign-jwt" {
				return nil, fmt.Errorf("unexpected sign path %q", request.URL.Path)
			}
			var input map[string]any
			if err := json.Unmarshal(body, &input); err != nil {
				return nil, err
			}
			if input["key_ref"] != policy.KeyRef || input["key_id"] != policy.KeyID || input["algorithm"] != policy.Algorithm || input["operation_id"] != "operation-1" {
				return nil, fmt.Errorf("unexpected KMS sign request: %#v", input)
			}
			claims, ok := input["claims"].(map[string]any)
			if !ok || claims["sub"] != "reader" {
				return nil, fmt.Errorf("unexpected claims: %#v", input["claims"])
			}
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"jwt-1"}`))
			payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"reader"}`))
			return jsonResponse(map[string]any{"token": header + "." + payload + ".signature"}), nil
		}
		if request.Method == http.MethodGet {
			if request.URL.Path != "/v1/keys/kms/sa/jwt-1" || request.URL.Query().Get("algorithm") != policy.Algorithm || request.URL.Query().Get("key_id") != policy.KeyID {
				return nil, fmt.Errorf("unexpected public-key request: %s", request.URL.String())
			}
			return jsonResponse(map[string]any{"kty": "RSA", "kid": policy.KeyID, "alg": policy.Algorithm, "use": "sig"}), nil
		}
		return nil, fmt.Errorf("unexpected method %s", request.Method)
	})}
	backend := &HTTPBackend{Endpoint: "https://kms.invalid", HTTPClient: client}
	intent, err := NewIntent(policy.Domain, policy.Purpose, policy.KeyID, policy.Generation, policy.Algorithm, "operation-1", []byte(`{"sub":"reader"}`))
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := backend.Sign(context.Background(), policy, intent)
	if err != nil {
		t.Fatal(err)
	}
	if string(artifact.Value) == "" || artifact.KeyID != policy.KeyID {
		t.Fatalf("unexpected KMS artifact: %#v", artifact)
	}
	jwk, err := backend.PublicJWK(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if jwk["kid"] != policy.KeyID || jwk["alg"] != policy.Algorithm {
		t.Fatalf("unexpected public JWK: %#v", jwk)
	}
}

func jsonResponse(value any) *http.Response {
	data, _ := json.Marshal(value)
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}
}
