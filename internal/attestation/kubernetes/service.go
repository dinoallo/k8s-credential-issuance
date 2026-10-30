package kubernetes

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	sadomain "github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/sa"
)

// PeerAuthorizer authenticates the node-agent before a binding is signed.
// Production TCP deployments should use RequireTLSClientIdentity.
type PeerAuthorizer func(*http.Request, string) error

// Config describes the immutable policy that this attestor is allowed to
// issue. The signing key is separate from every node-agent identity key.
type Config struct {
	AttestorIdentity string
	AttestorKey      ed25519.PrivateKey
	ClusterID        string
	Issuer           string
	TokenGeneration  string
	KeyID            string
	DefaultAudience  string
	MaxTokenLifetime time.Duration
	API              API
	Now              func() time.Time
	AuthorizePeer    PeerAuthorizer
}

// Service resolves a Kubernetes-bound TokenRequest and signs the immutable
// binding proof consumed by sa-node-agent.
type Service struct {
	attestorIdentity string
	attestorKey      ed25519.PrivateKey
	clusterID        string
	issuer           string
	tokenGeneration  string
	keyID            string
	defaultAudience  string
	maxTokenLifetime time.Duration
	api              API
	now              func() time.Time
	authorizePeer    PeerAuthorizer
}

func NewService(config Config) (*Service, error) {
	if config.AttestorIdentity == "" || len(config.AttestorKey) != ed25519.PrivateKeySize || config.ClusterID == "" || config.Issuer == "" || config.TokenGeneration == "" || config.KeyID == "" || config.DefaultAudience == "" || config.API == nil {
		return nil, fmt.Errorf("Kubernetes attestor configuration is incomplete")
	}
	if config.MaxTokenLifetime <= 0 {
		return nil, fmt.Errorf("Kubernetes attestor maximum token lifetime must be positive")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Service{
		attestorIdentity: config.AttestorIdentity,
		attestorKey:      append(ed25519.PrivateKey(nil), config.AttestorKey...),
		clusterID:        config.ClusterID,
		issuer:           config.Issuer,
		tokenGeneration:  config.TokenGeneration,
		keyID:            config.KeyID,
		defaultAudience:  config.DefaultAudience,
		maxTokenLifetime: config.MaxTokenLifetime,
		api:              config.API,
		now:              config.Now,
		authorizePeer:    config.AuthorizePeer,
	}, nil
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/attest", s.handleAttest)
	return mux
}

func (s *Service) handleAttest(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var input signapi.AttestationRequest
	decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(writer, "invalid attestation request", http.StatusBadRequest)
		return
	}
	if err := ensureJSONEOF(decoder); err != nil {
		http.Error(writer, "invalid attestation request", http.StatusBadRequest)
		return
	}
	if s.authorizePeer != nil {
		if err := s.authorizePeer(request, input.Identity); err != nil {
			http.Error(writer, "attestation denied", http.StatusForbidden)
			return
		}
	}
	response, err := s.resolve(request.Context(), input)
	if err != nil {
		http.Error(writer, "attestation denied", http.StatusForbidden)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(response); err != nil {
		return
	}
}

func (s *Service) resolve(ctx context.Context, request signapi.AttestationRequest) (signapi.AttestationResponse, error) {
	if request.Identity == "" || request.Namespace == "" || request.Name == "" || request.Nonce == "" {
		return signapi.AttestationResponse{}, fmt.Errorf("attestation request is incomplete")
	}
	if request.Request.Namespace != "" && request.Request.Namespace != request.Namespace || request.Request.Name != "" && request.Request.Name != request.Name {
		return signapi.AttestationResponse{}, fmt.Errorf("TokenRequest identity does not match attestation request")
	}
	ref, ok, err := sadomain.KubernetesBoundObjectRef(request.Request)
	if err != nil || !ok || ref == nil || ref.Kind != "Pod" || ref.Name == "" || ref.UID == "" {
		return signapi.AttestationResponse{}, fmt.Errorf("attestation request is not Pod-bound")
	}
	pod, err := s.api.GetPod(ctx, request.Namespace, ref.Name)
	if err != nil {
		return signapi.AttestationResponse{}, fmt.Errorf("read Pod: %w", err)
	}
	if pod.UID == "" || pod.UID != ref.UID || pod.NodeName != request.Identity || pod.ServiceAccountName != request.Name {
		return signapi.AttestationResponse{}, fmt.Errorf("Pod binding does not match node request")
	}
	serviceAccount, err := s.api.GetServiceAccount(ctx, request.Namespace, request.Name)
	if err != nil {
		return signapi.AttestationResponse{}, fmt.Errorf("read ServiceAccount: %w", err)
	}
	if serviceAccount.UID == "" {
		return signapi.AttestationResponse{}, fmt.Errorf("ServiceAccount has no UID")
	}
	audiences, expirationSeconds, _, _, err := sadomain.KubernetesTokenRequestDetails(request.Request)
	if err != nil {
		return signapi.AttestationResponse{}, err
	}
	if len(audiences) == 0 {
		audiences = []string{s.defaultAudience}
	}
	sort.Strings(audiences)
	for index, audience := range audiences {
		if audience == "" || index > 0 && audiences[index-1] == audience {
			return signapi.AttestationResponse{}, fmt.Errorf("invalid audience set")
		}
	}
	now := s.now().UTC().Truncate(time.Second)
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Second)
	}
	lifetime := s.maxTokenLifetime
	if expirationSeconds != nil {
		if *expirationSeconds <= 0 || *expirationSeconds > int64((time.Duration(1<<63-1))/time.Second) {
			return signapi.AttestationResponse{}, fmt.Errorf("invalid expiration")
		}
		requested := time.Duration(*expirationSeconds) * time.Second
		if requested < lifetime {
			lifetime = requested
		}
	}
	if lifetime <= 0 {
		return signapi.AttestationResponse{}, fmt.Errorf("invalid maximum lifetime")
	}
	notAfter := now.Add(lifetime).Unix()
	if notAfter <= now.Unix() {
		return signapi.AttestationResponse{}, fmt.Errorf("maximum lifetime is shorter than one second")
	}
	binding := signapi.TokenBinding{
		ClusterID:               s.clusterID,
		ServiceAccountNamespace: request.Namespace,
		ServiceAccountName:      request.Name,
		ServiceAccountUID:       serviceAccount.UID,
		PodUID:                  ref.UID,
		Subject:                 "system:serviceaccount:" + request.Namespace + ":" + request.Name,
		Audience:                audiences,
		Issuer:                  s.issuer,
		NotBefore:               now.Unix(),
		NotAfter:                notAfter,
		TokenGeneration:         s.tokenGeneration,
		KeyID:                   s.keyID,
	}
	digest, err := sadomain.AttestationRequestDigest(request)
	if err != nil {
		return signapi.AttestationResponse{}, err
	}
	proof, err := identity.SignBindingProof(s.attestorIdentity, s.attestorKey, binding, digest, request.Nonce, now)
	if err != nil {
		return signapi.AttestationResponse{}, err
	}
	return signapi.AttestationResponse{RequestDigest: digest, Binding: binding, Proof: proof}, nil
}

// RequireTLSClientIdentity authorizes a node-agent whose verified client
// certificate contains the requested node identity as a DNS or URI SAN. The
// Common Name is intentionally not accepted as an identity source.
func RequireTLSClientIdentity(request *http.Request, expected string) error {
	if expected == "" || request == nil || request.TLS == nil || len(request.TLS.PeerCertificates) == 0 {
		return fmt.Errorf("verified client certificate is required")
	}
	if len(request.TLS.VerifiedChains) == 0 {
		return fmt.Errorf("client certificate was not verified by the configured client CA")
	}
	certificate := request.TLS.PeerCertificates[0]
	for _, value := range certificate.DNSNames {
		if value == expected {
			return nil
		}
	}
	for _, value := range certificate.IPAddresses {
		if value.String() == expected {
			return nil
		}
	}
	for _, value := range certificate.URIs {
		if value.String() == expected {
			return nil
		}
	}
	return fmt.Errorf("client certificate identity does not match request")
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("request contains trailing JSON")
		}
		return err
	}
	return nil
}
