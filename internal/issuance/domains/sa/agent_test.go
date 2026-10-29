package sa

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
)

type agentRoundTripper func(*http.Request) (*http.Response, error)

func (f agentRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestStaticBindingResolverAppliesTokenRequestConstraints(t *testing.T) {
	now := time.Unix(1000, 0)
	resolver := StaticBindingResolver{Bindings: map[string]signapi.TokenBinding{
		"default/reader": {
			ClusterID:               "cluster-1",
			ServiceAccountNamespace: "default",
			ServiceAccountName:      "reader",
			ServiceAccountUID:       "sa-uid-1",
			PodUID:                  "pod-uid-1",
			Subject:                 "system:serviceaccount:default:reader",
			Audience:                []string{"api"},
			Issuer:                  "https://issuer.example",
			NotBefore:               now.Unix(),
			NotAfter:                now.Add(time.Hour).Unix(),
			TokenGeneration:         "generation-1",
		},
	}, Now: func() time.Time { return now }}
	expiration := int64(600)
	rawRequest, err := json.Marshal(map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenRequest",
		"spec": map[string]any{
			"audiences":         []string{"z-api", "api"},
			"expirationSeconds": expiration,
			"boundObjectRef": map[string]any{
				"kind":       "Pod",
				"apiVersion": "v1",
				"name":       "reader",
				"uid":        "pod-uid-1",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := resolver.Resolve(nil, "default", "reader", signapi.TokenRequest{Namespace: "default", Name: "reader", Request: rawRequest})
	if err != nil {
		t.Fatal(err)
	}
	if binding.NotAfter != now.Add(600*time.Second).Unix() || len(binding.Audience) != 2 || binding.Audience[0] != "api" || binding.Audience[1] != "z-api" {
		t.Fatalf("resolver did not apply TokenRequest constraints: %#v", binding)
	}
}

func TestRemoteProviderAcceptsKubernetesTokenResponseShape(t *testing.T) {
	expiration := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	body, err := json.Marshal(map[string]any{"status": map[string]string{"token": "jwt-token", "expirationTimestamp": expiration}})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: agentRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})}
	provider, err := NewRemoteProvider("http://node-agent.invalid/v1/token", client)
	if err != nil {
		t.Fatal(err)
	}
	response, err := provider.GetServiceAccountToken(context.Background(), signapi.TokenRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if response.Token != "jwt-token" || response.ExpirationTimestamp <= time.Now().Unix() {
		t.Fatalf("unexpected remote provider response: %#v", response)
	}
}

func TestStaticBindingResolverRejectsInvalidTokenRequestConstraints(t *testing.T) {
	now := time.Unix(1000, 0)
	base := signapi.TokenBinding{ClusterID: "cluster-1", ServiceAccountNamespace: "default", ServiceAccountName: "reader", ServiceAccountUID: "sa-uid-1", PodUID: "pod-uid-1", Subject: "system:serviceaccount:default:reader", Audience: []string{"api"}, Issuer: "https://issuer.example", NotBefore: now.Unix(), NotAfter: now.Add(time.Hour).Unix(), TokenGeneration: "generation-1"}
	resolver := StaticBindingResolver{Bindings: map[string]signapi.TokenBinding{"default/reader": base}, Now: func() time.Time { return now }}
	for _, test := range []struct {
		name  string
		ref   map[string]any
		extra map[string]any
	}{
		{name: "wrong pod", ref: map[string]any{"kind": "Pod", "uid": "other"}},
		{name: "non pod", ref: map[string]any{"kind": "Secret", "uid": "pod-uid-1"}},
		{name: "duplicate audience", extra: map[string]any{"audiences": []string{"api", "api"}}},
		{name: "zero expiration", extra: map[string]any{"expirationSeconds": int64(0)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := map[string]any{}
			for key, value := range test.extra {
				spec[key] = value
			}
			if test.ref != nil {
				spec["boundObjectRef"] = test.ref
			}
			rawRequest, err := json.Marshal(map[string]any{"spec": spec})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.Resolve(nil, "default", "reader", signapi.TokenRequest{Namespace: "default", Name: "reader", Request: rawRequest}); err == nil {
				t.Fatal("resolver accepted an invalid TokenRequest constraint")
			}
		})
	}
}
