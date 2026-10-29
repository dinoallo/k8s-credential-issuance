package sa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/pipeline"
	coretransport "github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/transport"
)

const IdentityHeader = "X-Issuance-Identity"

type Signer struct {
	engine *pipeline.Engine
	kms    *kms.Provider
}

func NewSigner(engine *pipeline.Engine, provider *kms.Provider) (*Signer, error) {
	if engine == nil || provider == nil {
		return nil, fmt.Errorf("SA signer configuration is incomplete")
	}
	return &Signer{engine: engine, kms: provider}, nil
}

func (s *Signer) Sign(ctx context.Context, request signapi.SignRequest, identityRef string) (signapi.SignResponse, error) {
	if s == nil || s.engine == nil {
		return signapi.SignResponse{}, fmt.Errorf("SA signer is not configured")
	}
	request.IdentityRef = identityRef
	grantBytes, err := GrantBytes(request.TokenGrant)
	if err != nil {
		return signapi.SignResponse{}, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return signapi.SignResponse{}, err
	}
	responseBody, err := s.engine.Issue(ctx, pipeline.Request{Domain: "sa", IdentityRef: identityRef, Grant: grantBytes, Body: body})
	if err != nil {
		return signapi.SignResponse{}, err
	}
	var response signapi.SignResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return signapi.SignResponse{}, fmt.Errorf("decode signer result: %w", err)
	}
	if response.Token == "" || response.GrantID == "" || response.ClaimsDigest == "" {
		return signapi.SignResponse{}, fmt.Errorf("signer result is incomplete")
	}
	return response, nil
}

func (s *Signer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/sign", s.handleSign)
	mux.HandleFunc("/jwks.json", s.handleJWKS)
	mux.HandleFunc("/v1/keys", s.handleJWKS)
	mux.HandleFunc("/v1/key-metadata", s.handleKeyMetadata)
	return mux
}

func (s *Signer) handleSign(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	identityRef := request.Header.Get(IdentityHeader)
	var input signapi.SignRequest
	decoder := json.NewDecoder(io.LimitReader(request.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(writer, "invalid signing request", http.StatusBadRequest)
		return
	}
	response, err := s.Sign(request.Context(), input, identityRef)
	if err != nil {
		status := http.StatusForbidden
		if strings.Contains(err.Error(), "KMS") || strings.Contains(err.Error(), "ledger") || errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusServiceUnavailable
		}
		http.Error(writer, "token signing denied", status)
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

func (s *Signer) handleJWKS(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	keys, err := s.kms.PublicKeys(request.Context())
	if err != nil {
		http.Error(writer, "public key set unavailable", http.StatusServiceUnavailable)
		return
	}
	values := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		values = append(values, key.JWK)
	}
	writer.Header().Set("Cache-Control", "public, max-age=30, must-revalidate")
	writeJSON(writer, http.StatusOK, map[string]any{"keys": values})
}

func (s *Signer) handleKeyMetadata(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	keys, err := s.kms.PublicKeys(request.Context())
	if err != nil {
		http.Error(writer, "key metadata unavailable", http.StatusServiceUnavailable)
		return
	}
	metadata := make([]kms.Policy, 0, len(keys))
	for _, key := range keys {
		metadata = append(metadata, key.Policy)
	}
	writeJSON(writer, http.StatusOK, metadata)
}

type RevocationClient struct {
	Endpoint string
	client   *coretransport.Client
}

func NewRevocationClient(endpoint string, client *http.Client) (*RevocationClient, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("revocation endpoint must be an absolute HTTP URL")
	}
	return &RevocationClient{Endpoint: strings.TrimRight(endpoint, "/"), client: coretransport.NewClient(client, 64<<10)}, nil
}

func (c *RevocationClient) IsRevoked(ctx context.Context, grantID string) (bool, error) {
	if c == nil || c.client == nil {
		return false, fmt.Errorf("revocation client is not configured")
	}
	if grantID == "" || strings.ContainsAny(grantID, "/?#") {
		return false, fmt.Errorf("invalid Grant ID")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var result struct {
		GrantID string `json:"grant_id"`
		Revoked bool   `json:"revoked"`
	}
	if err := c.client.DoJSON(ctx, http.MethodGet, c.Endpoint+"/"+url.PathEscape(grantID), nil, &result); err != nil {
		return false, err
	}
	if result.GrantID != grantID {
		return false, fmt.Errorf("revocation endpoint returned a mismatched Grant ID")
	}
	return result.Revoked, nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
