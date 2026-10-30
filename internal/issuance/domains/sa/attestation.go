package sa

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/canonical"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/replay"
	coretransport "github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/transport"
)

const (
	defaultAttestationTimeout = 15 * time.Second
	defaultAttestationMaxBody = 1 << 20
	defaultAttestationPath    = "/v1/attest"
)

// RemoteAttestationConfig configures the trust boundary between a node-agent
// and the attestation service that resolves immutable workload bindings.
type RemoteAttestationConfig struct {
	Endpoint          string
	Identity          string
	AttestorIdentity  string
	AttestorPublicKey ed25519.PublicKey
	TLSCAFile         string
	TLSCertFile       string
	TLSKeyFile        string
	HTTPClient        *http.Client
	Replay            replay.Store
	Now               func() time.Time
	MaxClockSkew      time.Duration
}

// RemoteAttestationResolver obtains a binding from a trusted attestor and
// verifies the signed response locally. It never falls back to a static map.
type RemoteAttestationResolver struct {
	endpoint         *url.URL
	client           *coretransport.Client
	identity         string
	attestorIdentity string
	verifier         *identity.Verifier
	now              func() time.Time
}

// NewRemoteAttestationResolver creates a fail-closed resolver. HTTPS is
// allowed for remote attestors; plaintext HTTP is restricted to loopback, and
// Unix sockets are supported for a node-local attestor.
func NewRemoteAttestationResolver(config RemoteAttestationConfig) (*RemoteAttestationResolver, error) {
	if config.Identity == "" || config.AttestorIdentity == "" || len(config.AttestorPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("remote attestation resolver configuration is incomplete")
	}
	endpoint, client, err := newAttestationClient(config.Endpoint, config.HTTPClient, config.TLSCAFile, config.TLSCertFile, config.TLSKeyFile)
	if err != nil {
		return nil, err
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Replay == nil {
		config.Replay = replay.NewMemoryStore(config.Now)
	}
	verifier := identity.NewVerifier(map[string]ed25519.PublicKey{
		config.AttestorIdentity: append(ed25519.PublicKey(nil), config.AttestorPublicKey...),
	}, config.Replay)
	verifier.Now = config.Now
	if config.MaxClockSkew > 0 {
		verifier.MaxClockSkew = config.MaxClockSkew
	}
	return &RemoteAttestationResolver{
		endpoint:         endpoint,
		client:           client,
		identity:         config.Identity,
		attestorIdentity: config.AttestorIdentity,
		verifier:         verifier,
		now:              config.Now,
	}, nil
}

// Resolve implements BindingResolver. The request digest covers the worker
// identity, namespace/name, complete TokenRequest envelope, and fresh nonce.
func (r *RemoteAttestationResolver) Resolve(ctx context.Context, namespace, name string, request signapi.TokenRequest) (signapi.TokenBinding, error) {
	if r == nil || r.client == nil || r.verifier == nil {
		return signapi.TokenBinding{}, fmt.Errorf("remote attestation resolver is not configured")
	}
	if namespace == "" || name == "" {
		return signapi.TokenBinding{}, fmt.Errorf("attestation request requires namespace and name")
	}
	if request.Namespace != "" && request.Namespace != namespace || request.Name != "" && request.Name != name {
		return signapi.TokenBinding{}, fmt.Errorf("TokenRequest identity does not match resolver arguments")
	}
	request.Namespace = namespace
	request.Name = name
	if ctx == nil {
		ctx = context.Background()
	}
	nonce, err := identity.NewNonce()
	if err != nil {
		return signapi.TokenBinding{}, fmt.Errorf("generate attestation nonce: %w", err)
	}
	attestationRequest := signapi.AttestationRequest{
		Identity:  r.identity,
		Namespace: namespace,
		Name:      name,
		Request:   request,
		Nonce:     nonce,
	}
	digest, err := AttestationRequestDigest(attestationRequest)
	if err != nil {
		return signapi.TokenBinding{}, err
	}
	var response signapi.AttestationResponse
	if err := r.client.DoJSON(ctx, http.MethodPost, r.endpoint.String(), attestationRequest, &response); err != nil {
		return signapi.TokenBinding{}, fmt.Errorf("request workload attestation: %w", err)
	}
	if response.RequestDigest != digest {
		return signapi.TokenBinding{}, fmt.Errorf("attestation request digest mismatch")
	}
	if response.Proof.Identity != r.attestorIdentity || response.Proof.Nonce != nonce {
		return signapi.TokenBinding{}, fmt.Errorf("attestation proof identity or nonce mismatch")
	}

	now := r.now()
	binding, err := applyTokenRequestConstraints(response.Binding, namespace, name, request, now)
	if err != nil {
		return signapi.TokenBinding{}, fmt.Errorf("validate attested binding: %w", err)
	}
	if err := validateAttestedBinding(binding, namespace, name, now); err != nil {
		return signapi.TokenBinding{}, err
	}
	if err := r.verifier.VerifyBindingProof(ctx, r.attestorIdentity, response.Proof, response.Binding, digest); err != nil {
		return signapi.TokenBinding{}, fmt.Errorf("verify attestation proof: %w", err)
	}
	return binding, nil
}

// AttestationRequestDigest computes the stable digest that the attestor must
// sign. Canonical JSON prevents map/key ordering or insignificant whitespace
// from changing the authorization input.
func AttestationRequestDigest(request signapi.AttestationRequest) (string, error) {
	if request.Identity == "" || request.Namespace == "" || request.Name == "" || request.Nonce == "" {
		return "", fmt.Errorf("attestation request is incomplete")
	}
	raw, err := canonical.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("canonicalize attestation request: %w", err)
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func applyTokenRequestConstraints(binding signapi.TokenBinding, namespace, name string, request signapi.TokenRequest, now time.Time) (signapi.TokenBinding, error) {
	if namespace == "" || name == "" {
		return signapi.TokenBinding{}, fmt.Errorf("token binding identity is incomplete")
	}
	if binding.ServiceAccountNamespace != namespace || binding.ServiceAccountName != name {
		return signapi.TokenBinding{}, fmt.Errorf("attested ServiceAccount does not match %s/%s", namespace, name)
	}
	binding.Audience = append([]string(nil), binding.Audience...)
	audiences, expirationSeconds, ref, hasKubernetesRequest, err := requestDetails(request)
	if err != nil {
		return signapi.TokenBinding{}, err
	}
	if len(audiences) > 0 {
		seen := make(map[string]struct{}, len(audiences))
		for _, audience := range audiences {
			if audience == "" {
				return signapi.TokenBinding{}, fmt.Errorf("TokenRequest contains an empty audience")
			}
			if _, exists := seen[audience]; exists {
				return signapi.TokenBinding{}, fmt.Errorf("TokenRequest contains a duplicate audience")
			}
			seen[audience] = struct{}{}
		}
		binding.Audience = append([]string(nil), audiences...)
		sort.Strings(binding.Audience)
	}
	if hasKubernetesRequest {
		if ref != nil {
			if ref.Kind != "Pod" || binding.PodUID == "" || ref.UID == "" || ref.UID != binding.PodUID {
				return signapi.TokenBinding{}, fmt.Errorf("TokenRequest Pod binding does not match the trusted Pod UID")
			}
		} else if binding.PodUID != "" {
			return signapi.TokenBinding{}, fmt.Errorf("trusted Pod binding requires a Pod TokenRequest reference")
		}
	}
	if now.IsZero() {
		now = time.Now()
	}
	if binding.NotBefore == 0 {
		binding.NotBefore = now.Unix()
	}
	if expirationSeconds != nil && *expirationSeconds <= 0 {
		return signapi.TokenBinding{}, fmt.Errorf("TokenRequest expirationSeconds must be positive")
	}
	if binding.NotAfter == 0 {
		seconds := int64(3600)
		if expirationSeconds != nil {
			seconds = *expirationSeconds
		}
		binding.NotAfter = binding.NotBefore + seconds
	} else if expirationSeconds != nil {
		requestedNotAfter := binding.NotBefore + *expirationSeconds
		if requestedNotAfter <= binding.NotBefore {
			return signapi.TokenBinding{}, fmt.Errorf("TokenRequest expirationSeconds overflows the validity window")
		}
		if requestedNotAfter < binding.NotAfter {
			binding.NotAfter = requestedNotAfter
		}
	}
	return binding, nil
}

func validateAttestedBinding(binding signapi.TokenBinding, namespace, name string, now time.Time) error {
	if binding.ClusterID == "" || binding.ServiceAccountUID == "" || binding.Subject == "" || binding.Issuer == "" || binding.TokenGeneration == "" {
		return fmt.Errorf("attestation returned an incomplete token binding")
	}
	expectedSubject := "system:serviceaccount:" + namespace + ":" + name
	if binding.Subject != expectedSubject {
		return fmt.Errorf("attestation returned a mismatched ServiceAccount subject")
	}
	if len(binding.Audience) == 0 || !sortedUniqueAudience(binding.Audience) {
		return fmt.Errorf("attestation returned an invalid audience set")
	}
	if binding.NotBefore <= 0 || binding.NotAfter <= binding.NotBefore || !time.Unix(binding.NotAfter, 0).After(now) {
		return fmt.Errorf("attestation returned an invalid validity window")
	}
	return nil
}

func sortedUniqueAudience(values []string) bool {
	for index, value := range values {
		if value == "" || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func newAttestationClient(endpoint string, client *http.Client, caFile, certFile, keyFile string) (*url.URL, *coretransport.Client, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, nil, fmt.Errorf("parse attestation endpoint: %w", err)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, nil, fmt.Errorf("attestation endpoint must not contain user info, query, or fragment")
	}
	switch parsed.Scheme {
	case "unix":
		if caFile != "" || certFile != "" || keyFile != "" {
			return nil, nil, fmt.Errorf("TLS files cannot be used with a Unix attestation endpoint")
		}
		if parsed.Host != "" || parsed.Path == "" || !filepath.IsAbs(parsed.Path) || filepath.Clean(parsed.Path) != parsed.Path {
			return nil, nil, fmt.Errorf("attestation Unix endpoint must contain a clean absolute socket path")
		}
		socketPath := parsed.Path
		unixTransport := &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		}
		if client == nil {
			client = &http.Client{Timeout: defaultAttestationTimeout}
		}
		clientCopy := *client
		if clientCopy.Transport == nil {
			clientCopy.Transport = unixTransport
		}
		clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
		client = &clientCopy
		parsed = &url.URL{Scheme: "http", Host: "attestor", Path: defaultAttestationPath}
	case "http", "https":
		if parsed.Host == "" {
			return nil, nil, fmt.Errorf("attestation endpoint must include a host")
		}
		if parsed.Scheme == "http" && !attestationLoopbackHost(parsed.Hostname()) {
			return nil, nil, fmt.Errorf("attestation HTTP endpoint must use a loopback host")
		}
		if parsed.Scheme == "http" && (caFile != "" || certFile != "" || keyFile != "") {
			return nil, nil, fmt.Errorf("TLS files require an HTTPS attestation endpoint")
		}
		if parsed.Path == "" {
			parsed.Path = defaultAttestationPath
		}
	default:
		return nil, nil, fmt.Errorf("attestation endpoint must use unix, http, or https")
	}
	if client == nil {
		client = &http.Client{Timeout: defaultAttestationTimeout}
	}
	clientCopy := *client
	if parsed.Scheme == "https" {
		configured, err := withAttestationTLS(clientCopy.Transport, caFile, certFile, keyFile)
		if err != nil {
			return nil, nil, err
		}
		clientCopy.Transport = configured
	}
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return parsed, coretransport.NewClient(&clientCopy, defaultAttestationMaxBody), nil
}

func withAttestationTLS(roundTripper http.RoundTripper, caFile, certFile, keyFile string) (http.RoundTripper, error) {
	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("attestation TLS certificate and key must be provided together")
	}
	if caFile == "" && certFile == "" {
		return roundTripper, nil
	}
	base, ok := roundTripper.(*http.Transport)
	if roundTripper != nil && !ok {
		return nil, fmt.Errorf("attestation TLS files require an *http.Transport")
	}
	if base == nil {
		if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok {
			base = defaultTransport
		} else {
			base = &http.Transport{}
		}
	}
	transport := base.Clone()
	tlsConfig := transport.TLSClientConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	if tlsConfig.MinVersion < tls.VersionTLS13 {
		tlsConfig.MinVersion = tls.VersionTLS13
	}
	if caFile != "" {
		caData, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read attestation server CA: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("parse attestation server CA")
		}
		tlsConfig.RootCAs = roots
	}
	if certFile != "" {
		certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load attestation client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	transport.TLSClientConfig = tlsConfig
	return transport, nil
}

func attestationLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
