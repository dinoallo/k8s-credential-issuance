package ca

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/pipeline"
)

const IdentityHeader = "X-Issuance-Identity"

type Signer struct {
	engine *pipeline.Engine
	kms    *kms.Provider
}

func NewSigner(engine *pipeline.Engine, provider *kms.Provider) (*Signer, error) {
	if engine == nil || provider == nil {
		return nil, fmt.Errorf("CA signer configuration is incomplete")
	}
	return &Signer{engine: engine, kms: provider}, nil
}

func (s *Signer) Sign(ctx context.Context, request signapi.CertificateSignRequest, identityRef string) (signapi.CertificateSignResponse, error) {
	if s == nil || s.engine == nil {
		return signapi.CertificateSignResponse{}, fmt.Errorf("CA signer is not configured")
	}
	request.IdentityRef = identityRef
	grantBytes, err := GrantBytes(request.Grant)
	if err != nil {
		return signapi.CertificateSignResponse{}, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return signapi.CertificateSignResponse{}, err
	}
	responseBody, err := s.engine.Issue(ctx, pipeline.Request{Domain: "ca", RequestID: request.RequestID, IdentityRef: identityRef, Grant: grantBytes, Body: body})
	if err != nil {
		return signapi.CertificateSignResponse{}, err
	}
	var response signapi.CertificateSignResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return signapi.CertificateSignResponse{}, fmt.Errorf("decode CA signer result: %w", err)
	}
	if len(response.Certificate) == 0 || response.GrantID == "" || response.RequestID == "" || response.Profile == "" {
		return signapi.CertificateSignResponse{}, fmt.Errorf("CA signer result is incomplete")
	}
	return response, nil
}

func (s *Signer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/sign", s.handleSign)
	mux.HandleFunc("/v1/key-metadata", s.handleKeyMetadata)
	return mux
}

func (s *Signer) handleSign(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var input signapi.CertificateSignRequest
	decoder := json.NewDecoder(io.LimitReader(request.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(writer, "invalid certificate signing request", http.StatusBadRequest)
		return
	}
	response, err := s.Sign(request.Context(), input, request.Header.Get(IdentityHeader))
	if err != nil {
		status := http.StatusForbidden
		if strings.Contains(err.Error(), "KMS") || strings.Contains(err.Error(), "ledger") || errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusServiceUnavailable
		}
		http.Error(writer, "certificate signing denied", status)
		return
	}
	writeJSON(writer, http.StatusOK, response)
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

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
