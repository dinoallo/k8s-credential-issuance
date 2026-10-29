package etcd

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
		return nil, fmt.Errorf("etcd signer configuration is incomplete")
	}
	return &Signer{engine: engine, kms: provider}, nil
}
func (s *Signer) Sign(ctx context.Context, request signapi.EtcdCertificateSignRequest, identityRef string) (signapi.EtcdCertificateSignResponse, error) {
	if s == nil || s.engine == nil {
		return signapi.EtcdCertificateSignResponse{}, fmt.Errorf("etcd signer is not configured")
	}
	request.IdentityRef = identityRef
	rawGrant, err := GrantBytes(request.Grant)
	if err != nil {
		return signapi.EtcdCertificateSignResponse{}, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return signapi.EtcdCertificateSignResponse{}, err
	}
	responseBody, err := s.engine.Issue(ctx, pipeline.Request{Domain: "etcd", RequestID: request.RequestID, IdentityRef: identityRef, TargetUID: request.MemberOrClientID, Grant: rawGrant, Body: body})
	if err != nil {
		return signapi.EtcdCertificateSignResponse{}, err
	}
	var response signapi.EtcdCertificateSignResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return signapi.EtcdCertificateSignResponse{}, err
	}
	if len(response.Certificate) == 0 || response.GrantID == "" || response.RequestID == "" || response.Profile == "" {
		return signapi.EtcdCertificateSignResponse{}, fmt.Errorf("etcd signer result is incomplete")
	}
	return response, nil
}
func (s *Signer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/sign", s.handleSign)
	mux.HandleFunc("/v1/key-metadata", s.handleKeyMetadata)
	return mux
}
func (s *Signer) handleSign(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var input signapi.EtcdCertificateSignRequest
	decoder := json.NewDecoder(io.LimitReader(request.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid etcd certificate request", http.StatusBadRequest)
		return
	}
	response, err := s.Sign(request.Context(), input, request.Header.Get(IdentityHeader))
	if err != nil {
		status := http.StatusForbidden
		if strings.Contains(err.Error(), "KMS") || strings.Contains(err.Error(), "ledger") || errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusServiceUnavailable
		}
		http.Error(w, "etcd certificate signing denied", status)
		return
	}
	writeJSON(w, http.StatusOK, response)
}
func (s *Signer) handleKeyMetadata(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	keys, err := s.kms.PublicKeys(request.Context())
	if err != nil {
		http.Error(w, "key metadata unavailable", http.StatusServiceUnavailable)
		return
	}
	metadata := make([]kms.Policy, 0, len(keys))
	for _, key := range keys {
		metadata = append(metadata, key.Policy)
	}
	writeJSON(w, http.StatusOK, metadata)
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
