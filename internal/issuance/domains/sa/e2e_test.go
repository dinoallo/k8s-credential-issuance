package sa_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	grantapi "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/authority/domains/sa"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/audit"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/generation"
	coregrant "github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/grant"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/ledger"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/pipeline"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/replay"
	sadomain "github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/sa"
)

type testSystem struct {
	authority *sa.Authority
	signer    *sadomain.Signer
	binding   signapi.TokenBinding
	workerKey ed25519.PrivateKey
}

type handlerTransport struct {
	authority http.Handler
	signer    http.Handler
}

func (t handlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	if request.URL.Path == "/v1/grants" {
		t.authority.ServeHTTP(recorder, request)
	} else {
		t.signer.ServeHTTP(recorder, request)
	}
	return recorder.Result(), nil
}

func newTestSystem(t *testing.T) testSystem {
	return newTestSystemWithFormat(t, coregrant.Format)
}

func newTestSystemWithFormat(t *testing.T, grantFormat string) testSystem {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	eaaPublic, eaaPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	workerPublic, workerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	registration := sa.WorkloadRegistration{RegistrationID: "registration-1", Identity: "worker-1", IdentityPublicKey: identity.EncodePublicKey(workerPublic), ClusterID: "cluster-1", ServiceAccountNamespace: "default", ServiceAccountName: "reader", ServiceAccountUID: "sa-uid-1", PodUID: "pod-uid-1", Issuer: "https://issuer.example", AllowedAudiences: []string{"api"}, MaxTokenLifetimeSecs: 3600, TokenGeneration: "generation-1", KeyID: "jwt-1", PolicyVersion: "policy-1", Active: true}
	registrations := sa.NewMemoryRegistrationStore()
	if err := registrations.Register(context.Background(), registration); err != nil {
		t.Fatal(err)
	}
	authority, err := sa.New(sa.Config{ClusterID: "cluster-1", Issuer: "https://issuer.example", PolicyVersion: "policy-1", KeyID: "eaa-1", PrivateKey: eaaPrivate, GrantFormat: grantFormat, Registrations: registrations, ProofReplay: replay.NewMemoryStore(func() time.Time { return now }), Grants: sa.NewMemoryGrantLedger(), Audit: audit.NopSink{}, Now: func() time.Time { return now }, MaxTokenLifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := generation.NewRegistry([]generation.Metadata{{Generation: "generation-1", KeyID: "jwt-1", Algorithm: "RS256", State: generation.Active}})
	if err != nil {
		t.Fatal(err)
	}
	policies := []kms.Policy{{Domain: grantapi.DomainSA, Purpose: kms.PurposeServiceAccountJWT, Generation: "generation-1", KeyID: "jwt-1", Algorithm: "RS256"}}
	backend, err := kms.NewLocalJWTBackend(policies, map[string]crypto.PrivateKey{"generation-1": rsaKey})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := kms.NewProvider(backend, registry, policies)
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := sadomain.NewPlugin(sadomain.Config{ClusterID: "cluster-1", Issuer: "https://issuer.example", PolicyVersion: "policy-1", DefaultKeyID: "jwt-1", DefaultAlgorithm: "RS256", MaxTokenLifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	var grantVerifier pipeline.GrantVerifier
	allowLegacyRelay := grantFormat == sadomain.LegacyGrantFormat
	if allowLegacyRelay {
		grantVerifier = sadomain.NewGrantVerifier("jwt-1")
	}
	engine, err := pipeline.New(pipeline.Config{Domain: grantapi.DomainSA, GrantKeys: map[string]ed25519.PublicKey{"eaa-1": eaaPublic}, GrantVerifier: grantVerifier, AllowLegacyRelay: allowLegacyRelay, Plugin: plugin, Ledger: ledger.NewMemoryStore(), KMS: provider, Revocations: authority, Audit: audit.NopSink{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := sadomain.NewSigner(engine, provider)
	if err != nil {
		t.Fatal(err)
	}
	return testSystem{authority: authority, signer: signer, workerKey: workerPrivate, binding: signapi.TokenBinding{ClusterID: "cluster-1", ServiceAccountNamespace: "default", ServiceAccountName: "reader", ServiceAccountUID: "sa-uid-1", PodUID: "pod-uid-1", Subject: "system:serviceaccount:default:reader", Audience: []string{"api"}, Issuer: "https://issuer.example", NotBefore: now.Unix(), NotAfter: now.Add(time.Hour).Unix(), TokenGeneration: "generation-1"}}
}

func issueGrantInput(t *testing.T, system testSystem) (signapi.GrantRequest, []byte, string) {
	t.Helper()
	claims, err := sadomain.DefaultClaimsBuilder("default", "reader", signapi.TokenRequest{}, system.binding)
	if err != nil {
		t.Fatal(err)
	}
	claims, err = sadomain.CanonicalizeClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	claimsDigest := sadomain.ClaimsDigest(claims)
	nonce, err := identity.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignProof("worker-1", system.workerKey, system.binding, claimsDigest, nonce, time.Unix(system.binding.NotBefore, 0))
	if err != nil {
		t.Fatal(err)
	}
	return signapi.GrantRequest{Identity: "worker-1", ClaimsDigest: claimsDigest, Binding: system.binding, Proof: proof}, claims, claimsDigest
}

func TestDirectWorkerAuthoritySignerFlowAndExactRetry(t *testing.T) {
	system := newTestSystem(t)
	client := &http.Client{Transport: handlerTransport{authority: system.authority.Handler(), signer: system.signer.Handler()}}
	provider, err := sadomain.NewProvider(sadomain.AgentConfig{AuthorityEndpoint: "http://authority.invalid/v1/grants", SignerEndpoint: "http://signer.invalid/v1/sign", Identity: "worker-1", IdentityKey: system.workerKey, HTTPClient: client, Resolver: sadomain.BindingResolverFunc(func(context.Context, string, string, signapi.TokenRequest) (signapi.TokenBinding, error) {
		return system.binding, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	response, err := provider.GetServiceAccountToken(context.Background(), "default", "reader", signapi.TokenRequest{Namespace: "default", Name: "reader"})
	if err != nil {
		t.Fatal(err)
	}
	if response.Token == "" || response.ExpirationTimestamp != system.binding.NotAfter {
		t.Fatalf("unexpected token response: %#v", response)
	}

	claims, err := sadomain.DefaultClaimsBuilder("default", "reader", signapi.TokenRequest{}, system.binding)
	if err != nil {
		t.Fatal(err)
	}
	claims, err = sadomain.CanonicalizeClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	claimsDigest := sadomain.ClaimsDigest(claims)
	nonce, err := identity.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignProof("worker-1", system.workerKey, system.binding, claimsDigest, nonce, time.Unix(system.binding.NotBefore, 0))
	if err != nil {
		t.Fatal(err)
	}
	rawGrant, err := system.authority.Issue(context.Background(), signapi.GrantRequest{Identity: "worker-1", ClaimsDigest: claimsDigest, Binding: system.binding, Proof: proof})
	if err != nil {
		t.Fatal(err)
	}
	quotedGrant, _ := json.Marshal(string(rawGrant))
	request := signapi.SignRequest{Claims: claims, ClaimsDigest: claimsDigest, TokenGrant: quotedGrant, Binding: system.binding}
	first, err := system.signer.Sign(context.Background(), request, "worker-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := system.signer.Sign(context.Background(), request, "worker-1")
	if err != nil {
		t.Fatal(err)
	}
	if first.Token != second.Token || first.GrantID != second.GrantID || first.ClaimsDigest != second.ClaimsDigest {
		t.Fatal("retry did not return the exact recorded result")
	}
}

func TestSignerRejectsClaimsThatDoNotMatchTheBinding(t *testing.T) {
	system := newTestSystem(t)
	claims, err := sadomain.DefaultClaimsBuilder("default", "reader", signapi.TokenRequest{}, system.binding)
	if err != nil {
		t.Fatal(err)
	}
	var claimObject map[string]any
	if err := json.Unmarshal(claims, &claimObject); err != nil {
		t.Fatal(err)
	}
	claimObject["aud"] = []string{"different-audience"}
	claims, err = json.Marshal(claimObject)
	if err != nil {
		t.Fatal(err)
	}
	claims, err = sadomain.CanonicalizeClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	claimsDigest := sadomain.ClaimsDigest(claims)
	nonce, err := identity.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignProof("worker-1", system.workerKey, system.binding, claimsDigest, nonce, time.Unix(system.binding.NotBefore, 0))
	if err != nil {
		t.Fatal(err)
	}
	rawGrant, err := system.authority.Issue(context.Background(), signapi.GrantRequest{Identity: "worker-1", ClaimsDigest: claimsDigest, Binding: system.binding, Proof: proof})
	if err != nil {
		t.Fatal(err)
	}
	quotedGrant, err := json.Marshal(string(rawGrant))
	if err != nil {
		t.Fatal(err)
	}
	_, err = system.signer.Sign(context.Background(), signapi.SignRequest{Claims: claims, ClaimsDigest: claimsDigest, TokenGrant: quotedGrant, Binding: system.binding}, "worker-1")
	if err == nil {
		t.Fatal("signer accepted JWT claims with an audience outside the verified binding")
	}
}

func TestLegacyTokenGrantCompatibilityFlow(t *testing.T) {
	system := newTestSystemWithFormat(t, sadomain.LegacyGrantFormat)
	client := &http.Client{Transport: handlerTransport{authority: system.authority.Handler(), signer: system.signer.Handler()}}
	provider, err := sadomain.NewProvider(sadomain.AgentConfig{AuthorityEndpoint: "http://authority.invalid/v1/grants", SignerEndpoint: "http://signer.invalid/v1/sign", Identity: "worker-1", IdentityKey: system.workerKey, HTTPClient: client, Resolver: sadomain.BindingResolverFunc(func(context.Context, string, string, signapi.TokenRequest) (signapi.TokenBinding, error) {
		return system.binding, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	response, err := provider.GetServiceAccountToken(context.Background(), "default", "reader", signapi.TokenRequest{Namespace: "default", Name: "reader"})
	if err != nil {
		t.Fatal(err)
	}
	if response.Token == "" || response.ExpirationTimestamp != system.binding.NotAfter {
		t.Fatalf("unexpected legacy token response: %#v", response)
	}
}

func TestGrantHTTPResponseShapes(t *testing.T) {
	for _, test := range []struct {
		name   string
		format string
		quoted bool
	}{
		{name: "compact JWS", format: coregrant.Format, quoted: true},
		{name: "legacy object", format: sadomain.LegacyGrantFormat},
	} {
		t.Run(test.name, func(t *testing.T) {
			system := newTestSystemWithFormat(t, test.format)
			input, _, _ := issueGrantInput(t, system)
			body, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewReader(body))
			request.Header.Set("X-Issuance-Identity", input.Identity)
			recorder := httptest.NewRecorder()
			system.authority.Handler().ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("authority returned HTTP %d: %s", recorder.Code, recorder.Body.String())
			}
			var response signapi.GrantResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			trimmed := bytes.TrimSpace(response.Grant)
			if len(trimmed) == 0 || (trimmed[0] == '"') != test.quoted {
				t.Fatalf("unexpected Grant response shape: %s", trimmed)
			}
			if _, err := sadomain.GrantBytes(response.Grant); err != nil {
				t.Fatalf("response did not carry a usable Grant: %v", err)
			}
		})
	}
}

func TestLegacySignerAcceptsRequestWithoutIdentityHeader(t *testing.T) {
	system := newTestSystemWithFormat(t, sadomain.LegacyGrantFormat)
	input, claims, claimsDigest := issueGrantInput(t, system)
	rawGrant, err := system.authority.Issue(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(signapi.SignRequest{Claims: claims, ClaimsDigest: claimsDigest, TokenGrant: rawGrant, Binding: system.binding})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/sign", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	system.signer.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("legacy signer returned HTTP %d: %s", recorder.Code, recorder.Body.String())
	}
	var response signapi.SignResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Token == "" || response.ClaimsDigest != claimsDigest {
		t.Fatalf("unexpected legacy signer response: %#v", response)
	}

	// Reusing the old Grant with a different binding must fail before the KMS
	// operation. An exact retry remains idempotent and is covered above.
	tamperedBinding := system.binding
	tamperedBinding.Audience = []string{"different-audience"}
	_, err = system.signer.Sign(context.Background(), signapi.SignRequest{Claims: claims, ClaimsDigest: claimsDigest, TokenGrant: rawGrant, Binding: tamperedBinding}, "")
	if err == nil {
		t.Fatal("legacy signer accepted a Grant with a different audience binding")
	}
}

func TestLegacyNodeAgentKubernetesTokenEnvelope(t *testing.T) {
	system := newTestSystemWithFormat(t, sadomain.LegacyGrantFormat)
	client := &http.Client{Transport: handlerTransport{authority: system.authority.Handler(), signer: system.signer.Handler()}}
	provider, err := sadomain.NewProvider(sadomain.AgentConfig{AuthorityEndpoint: "http://authority.invalid/v1/grants", SignerEndpoint: "http://signer.invalid/v1/sign", Identity: "worker-1", IdentityKey: system.workerKey, HTTPClient: client, Resolver: sadomain.StaticBindingResolver{Bindings: map[string]signapi.TokenBinding{"default/reader": system.binding}, Now: func() time.Time { return time.Unix(system.binding.NotBefore, 0) }}})
	if err != nil {
		t.Fatal(err)
	}
	kubernetesRequest := map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": map[string]any{"audiences": []string{"api"}, "expirationSeconds": int64(3600), "boundObjectRef": map[string]any{"kind": "Pod", "apiVersion": "v1", "name": "reader", "uid": "pod-uid-1"}}}
	rawRequest, err := json.Marshal(kubernetesRequest)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(signapi.TokenRequest{Namespace: "default", Name: "reader", Request: rawRequest})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/token", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	provider.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("node-agent returned HTTP %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Status struct {
			Token               string `json:"token"`
			ExpirationTimestamp string `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Status.Token == "" || response.Status.ExpirationTimestamp != time.Unix(system.binding.NotAfter, 0).UTC().Format(time.RFC3339Nano) {
		t.Fatalf("unexpected Kubernetes TokenRequest response: %#v", response)
	}
}
