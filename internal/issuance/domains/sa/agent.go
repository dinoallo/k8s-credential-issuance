package sa

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	coretransport "github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/transport"
)

type BindingResolver interface {
	Resolve(context.Context, string, string, signapi.TokenRequest) (signapi.TokenBinding, error)
}

type BindingResolverFunc func(context.Context, string, string, signapi.TokenRequest) (signapi.TokenBinding, error)

func (f BindingResolverFunc) Resolve(ctx context.Context, namespace, name string, request signapi.TokenRequest) (signapi.TokenBinding, error) {
	return f(ctx, namespace, name, request)
}

type ClaimsBuilder func(string, string, signapi.TokenRequest, signapi.TokenBinding) ([]byte, error)

type AgentConfig struct {
	AuthorityEndpoint string
	SignerEndpoint    string
	Identity          string
	IdentityKey       ed25519.PrivateKey
	Resolver          BindingResolver
	ClaimsBuilder     ClaimsBuilder
	HTTPClient        *http.Client
	Now               func() time.Time
}

type Provider struct {
	authority   *AuthorityClient
	signer      *SignerClient
	identity    string
	identityKey ed25519.PrivateKey
	resolver    BindingResolver
	claims      ClaimsBuilder
	now         func() time.Time
}

func NewProvider(config AgentConfig) (*Provider, error) {
	if config.Identity == "" || len(config.IdentityKey) != ed25519.PrivateKeySize || config.Resolver == nil {
		return nil, fmt.Errorf("SA node-agent configuration is incomplete")
	}
	authority, err := NewAuthorityClient(config.AuthorityEndpoint, config.HTTPClient)
	if err != nil {
		return nil, err
	}
	signer, err := NewSignerClient(config.SignerEndpoint, config.HTTPClient)
	if err != nil {
		return nil, err
	}
	if config.ClaimsBuilder == nil {
		config.ClaimsBuilder = DefaultClaimsBuilder
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Provider{authority: authority, signer: signer, identity: config.Identity, identityKey: append(ed25519.PrivateKey(nil), config.IdentityKey...), resolver: config.Resolver, claims: config.ClaimsBuilder, now: config.Now}, nil
}

func (p *Provider) GetServiceAccountToken(ctx context.Context, namespace, name string, request signapi.TokenRequest) (signapi.TokenResponse, error) {
	if p == nil || p.authority == nil || p.signer == nil {
		return signapi.TokenResponse{}, fmt.Errorf("SA node-agent is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	binding, err := p.resolver.Resolve(ctx, namespace, name, request)
	if err != nil {
		return signapi.TokenResponse{}, fmt.Errorf("resolve trusted token binding: %w", err)
	}
	claims, err := p.claims(namespace, name, request, binding)
	if err != nil {
		return signapi.TokenResponse{}, fmt.Errorf("build token claims: %w", err)
	}
	claims, err = CanonicalizeClaims(claims)
	if err != nil {
		return signapi.TokenResponse{}, err
	}
	claimsDigest := ClaimsDigest(claims)
	nonce, err := identity.NewNonce()
	if err != nil {
		return signapi.TokenResponse{}, err
	}
	proof, err := identity.SignProof(p.identity, p.identityKey, binding, claimsDigest, nonce, p.now())
	if err != nil {
		return signapi.TokenResponse{}, err
	}
	rawGrant, err := p.authority.Issue(ctx, signapi.GrantRequest{Identity: p.identity, ClaimsDigest: claimsDigest, Binding: binding, Proof: proof})
	if err != nil {
		return signapi.TokenResponse{}, fmt.Errorf("obtain SA Grant: %w", err)
	}
	tokenGrant := json.RawMessage(rawGrant)
	if !IsLegacyTokenGrant(rawGrant) {
		tokenGrant = json.RawMessage(strconvQuote(string(rawGrant)))
	}
	response, err := p.signer.Sign(ctx, signapi.SignRequest{Claims: claims, ClaimsDigest: claimsDigest, TokenGrant: tokenGrant, Binding: binding}, p.identity)
	if err != nil {
		return signapi.TokenResponse{}, fmt.Errorf("obtain SA token: %w", err)
	}
	return signapi.TokenResponse{Token: response.Token, ExpirationTimestamp: binding.NotAfter}, nil
}

func DefaultClaimsBuilder(namespace, name string, request signapi.TokenRequest, binding signapi.TokenBinding) ([]byte, error) {
	if binding.NotBefore <= 0 || binding.NotAfter <= binding.NotBefore {
		return nil, fmt.Errorf("token binding has no usable validity window")
	}
	private := map[string]any{"namespace": namespace, "serviceaccount": map[string]string{"name": name, "uid": binding.ServiceAccountUID}}
	if ref, ok, err := KubernetesBoundObjectRef(request); err != nil {
		return nil, err
	} else if ok {
		if ref.Kind != "Pod" {
			return nil, fmt.Errorf("direct node-agent issuance only supports Pod-bound TokenRequests")
		}
		if binding.PodUID == "" || ref.UID == "" || ref.UID != binding.PodUID {
			return nil, fmt.Errorf("TokenRequest Pod binding does not match the trusted Pod UID")
		}
		private["pod"] = map[string]string{"name": ref.Name, "uid": ref.UID}
	} else if binding.PodUID != "" {
		private["pod"] = map[string]string{"uid": binding.PodUID}
	}
	return json.Marshal(map[string]any{"aud": append([]string(nil), binding.Audience...), "exp": binding.NotAfter, "iat": binding.NotBefore, "iss": binding.Issuer, "nbf": binding.NotBefore, "sub": binding.Subject, "kubernetes.io": private})
}

// StaticBindingResolver is intended for bootstrap and tests. It applies the
// request's audience, expiration, and Pod reference only after checking them
// against the immutable registered binding. Production should replace it
// with an attestation-backed resolver.
type StaticBindingResolver struct {
	Bindings map[string]signapi.TokenBinding
	Now      func() time.Time
}

func (r StaticBindingResolver) Resolve(_ context.Context, namespace, name string, request signapi.TokenRequest) (signapi.TokenBinding, error) {
	binding, ok := r.Bindings[namespace+"/"+name]
	if !ok {
		return signapi.TokenBinding{}, fmt.Errorf("no trusted binding for %s/%s", namespace, name)
	}
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	return applyTokenRequestConstraints(binding, namespace, name, request, now)
}

func KubernetesBoundObjectRef(request signapi.TokenRequest) (*signapi.BoundObjectReference, bool, error) {
	_, _, ref, hasRequest, err := requestDetails(request)
	return ref, hasRequest && ref != nil, err
}

func IsKubernetesTokenRequest(request signapi.TokenRequest) bool {
	_, _, _, hasRequest, err := requestDetails(request)
	return err == nil && hasRequest
}

func KubernetesTokenResponse(rawRequest []byte, token string, expiration int64) ([]byte, error) {
	var object map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(rawRequest))
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, fmt.Errorf("decode Kubernetes TokenRequest: %w", err)
	}
	status, err := json.Marshal(map[string]any{"token": token, "expirationTimestamp": time.Unix(expiration, 0).UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return nil, err
	}
	object["status"] = status
	return json.Marshal(object)
}

func requestDetails(request signapi.TokenRequest) (audiences []string, expirationSeconds *int64, ref *signapi.BoundObjectReference, hasKubernetesRequest bool, err error) {
	audiences = append([]string(nil), request.Audiences...)
	expirationSeconds = request.ExpirationSeconds
	ref = request.BoundObjectRef
	if len(request.Request) == 0 || bytes.Equal(bytes.TrimSpace(request.Request), []byte("null")) {
		return audiences, expirationSeconds, ref, ref != nil || len(audiences) > 0 || expirationSeconds != nil, nil
	}
	var envelope struct {
		Spec *struct {
			Audiences         []string                      `json:"audiences"`
			ExpirationSeconds *int64                        `json:"expirationSeconds"`
			BoundObjectRef    *signapi.BoundObjectReference `json:"boundObjectRef"`
		} `json:"spec"`
	}
	decoder := json.NewDecoder(bytes.NewReader(request.Request))
	if err := decoder.Decode(&envelope); err != nil {
		return nil, nil, nil, false, fmt.Errorf("decode Kubernetes TokenRequest: %w", err)
	}
	if envelope.Spec == nil {
		return audiences, expirationSeconds, ref, false, nil
	}
	if len(audiences) == 0 {
		audiences = envelope.Spec.Audiences
	}
	if expirationSeconds == nil {
		expirationSeconds = envelope.Spec.ExpirationSeconds
	}
	if ref == nil {
		ref = envelope.Spec.BoundObjectRef
	}
	return audiences, expirationSeconds, ref, true, nil
}

func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/token", p.handleToken)
	return mux
}

func (p *Provider) handleToken(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var input signapi.TokenRequest
	decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || input.Namespace == "" || input.Name == "" {
		http.Error(writer, "invalid TokenRequest", http.StatusBadRequest)
		return
	}
	response, err := p.GetServiceAccountToken(request.Context(), input.Namespace, input.Name, input)
	if err != nil {
		http.Error(writer, "token issuance unavailable", http.StatusServiceUnavailable)
		return
	}
	if IsKubernetesTokenRequest(input) {
		body, err := KubernetesTokenResponse(input.Request, response.Token, response.ExpirationTimestamp)
		if err != nil {
			http.Error(writer, "invalid Kubernetes TokenRequest", http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(body)
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

type AuthorityClient struct {
	endpoint *url.URL
	client   *coretransport.Client
}

func NewAuthorityClient(endpoint string, client *http.Client) (*AuthorityClient, error) {
	parsed, err := parseHTTPURL(endpoint, "authority")
	if err != nil {
		return nil, err
	}
	return &AuthorityClient{endpoint: parsed, client: coretransport.NewClient(client, coretransport.DefaultMaxBody)}, nil
}

func (c *AuthorityClient) Issue(ctx context.Context, request signapi.GrantRequest) ([]byte, error) {
	var response signapi.GrantResponse
	headers := make(http.Header)
	if request.Identity != "" {
		headers.Set(IdentityHeader, request.Identity)
	}
	if err := c.client.DoJSONWithHeaders(ctx, http.MethodPost, c.endpoint.String(), headers, request, &response); err != nil {
		return nil, err
	}
	rawGrant, err := GrantBytes(response.Grant)
	if err != nil {
		return nil, fmt.Errorf("authority returned an invalid Grant: %w", err)
	}
	return rawGrant, nil
}

type SignerClient struct {
	endpoint *url.URL
	client   *coretransport.Client
}

func NewSignerClient(endpoint string, client *http.Client) (*SignerClient, error) {
	parsed, err := parseHTTPURL(endpoint, "signer")
	if err != nil {
		return nil, err
	}
	return &SignerClient{endpoint: parsed, client: coretransport.NewClient(client, coretransport.DefaultMaxBody)}, nil
}

func (c *SignerClient) Sign(ctx context.Context, request signapi.SignRequest, identityRef string) (signapi.SignResponse, error) {
	headerIdentity := identityRef
	if rawGrant, err := GrantBytes(request.TokenGrant); err == nil && IsLegacyTokenGrant(rawGrant) {
		// The legacy staging request has no identity_ref field. The signed
		// TokenGrant and its worker proof are its authorization carrier.
		request.IdentityRef = ""
		headerIdentity = ""
	}
	headers := make(http.Header)
	if headerIdentity != "" {
		headers.Set(IdentityHeader, headerIdentity)
	}
	var response signapi.SignResponse
	if err := c.client.DoJSONWithHeaders(ctx, http.MethodPost, c.endpoint.String(), headers, request, &response); err != nil {
		return signapi.SignResponse{}, err
	}
	return response, nil
}

type RemoteProvider struct {
	endpoint *url.URL
	client   *coretransport.Client
}

func NewRemoteProvider(endpoint string, client *http.Client) (*RemoteProvider, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse node-agent endpoint: %w", err)
	}
	if parsed.Scheme == "unix" {
		if parsed.Path == "" {
			return nil, fmt.Errorf("node-agent Unix endpoint has no socket path")
		}
		unixTransport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", parsed.Path)
		}}
		client = &http.Client{Transport: unixTransport, Timeout: 15 * time.Second}
		parsed = &url.URL{Scheme: "http", Host: "node-agent", Path: "/v1/token"}
	} else if parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("node-agent endpoint must be an HTTP, HTTPS, or Unix URL")
	}
	return &RemoteProvider{endpoint: parsed, client: coretransport.NewClient(client, coretransport.DefaultMaxBody)}, nil
}

func (p *RemoteProvider) GetServiceAccountToken(ctx context.Context, request signapi.TokenRequest) (signapi.TokenResponse, error) {
	data, err := p.client.DoRawJSON(ctx, http.MethodPost, p.endpoint.String(), nil, request)
	if err != nil {
		return signapi.TokenResponse{}, err
	}
	var response signapi.TokenResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return signapi.TokenResponse{}, err
	}
	if response.Token == "" {
		// The compatibility handler returns the original Kubernetes
		// TokenRequest shape with status.token and an RFC3339 expiration.
		var kubernetesResponse struct {
			Status struct {
				Token               string `json:"token"`
				ExpirationTimestamp string `json:"expirationTimestamp"`
			} `json:"status"`
		}
		if err := json.Unmarshal(data, &kubernetesResponse); err != nil {
			return signapi.TokenResponse{}, fmt.Errorf("decode node-agent response: %w", err)
		}
		if kubernetesResponse.Status.Token == "" || kubernetesResponse.Status.ExpirationTimestamp == "" {
			return signapi.TokenResponse{}, fmt.Errorf("node-agent returned an incomplete token response")
		}
		expiration, err := time.Parse(time.RFC3339Nano, kubernetesResponse.Status.ExpirationTimestamp)
		if err != nil {
			return signapi.TokenResponse{}, fmt.Errorf("decode node-agent expiration timestamp: %w", err)
		}
		response = signapi.TokenResponse{Token: kubernetesResponse.Status.Token, ExpirationTimestamp: expiration.Unix()}
	}
	if response.Token == "" || response.ExpirationTimestamp <= time.Now().Unix() {
		return signapi.TokenResponse{}, fmt.Errorf("node-agent returned an incomplete token response")
	}
	return response, nil
}

func parseHTTPURL(endpoint, name string) (*url.URL, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("%s endpoint must be an absolute HTTP URL", name)
	}
	return parsed, nil
}

func strconvQuote(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}
