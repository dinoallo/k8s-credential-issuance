package sa

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/grant"
	sadomain "github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/sa"
)

func (a *Authority) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/grants", a.handleGrant)
	mux.HandleFunc("/v1/grants/status/", a.handleStatus)
	mux.HandleFunc("/v1/grants/revoke", a.handleRevoke)
	return mux
}

func (a *Authority) handleGrant(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var input signapi.GrantRequest
	decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(writer, "invalid Grant request", http.StatusBadRequest)
		return
	}
	identityRef := request.Header.Get("X-Issuance-Identity")
	if identityRef == "" && a.config.GrantFormat != sadomain.LegacyGrantFormat || identityRef != "" && identityRef != input.Identity {
		http.Error(writer, "authenticated issuance identity is required", http.StatusUnauthorized)
		return
	}
	raw, err := a.Issue(request.Context(), input)
	if err != nil {
		http.Error(writer, "Grant denied", http.StatusForbidden)
		return
	}
	grantValue := json.RawMessage(raw)
	if a.config.GrantFormat == grant.Format {
		quoted, err := json.Marshal(string(raw))
		if err != nil {
			http.Error(writer, "Grant response unavailable", http.StatusInternalServerError)
			return
		}
		grantValue = quoted
	}
	response := signapi.GrantResponse{Grant: grantValue}
	if a.config.GrantFormat == sadomain.LegacyGrantFormat {
		if value, err := sadomain.ParseLegacyTokenGrant(raw); err == nil {
			response.GrantID = value.GrantID
			response.ExpiresAt = value.NotAfter
		}
	} else if value, _, err := grant.Verify(raw, map[string]ed25519.PublicKey{a.config.KeyID: a.config.PrivateKey.Public().(ed25519.PublicKey)}); err == nil {
		response.GrantID = value.GrantID
		response.ExpiresAt = value.ExpiresAt
	}
	writeJSON(writer, http.StatusOK, response)
}

func (a *Authority) handleStatus(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	grantID := strings.TrimPrefix(request.URL.Path, "/v1/grants/status/")
	if grantID == "" || strings.Contains(grantID, "/") {
		http.Error(writer, "grant ID is required", http.StatusBadRequest)
		return
	}
	revoked, err := a.IsRevoked(request.Context(), grantID)
	if err != nil {
		http.Error(writer, "grant status unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"grant_id": grantID, "revoked": revoked})
}

func (a *Authority) handleRevoke(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		GrantID string `json:"grant_id"`
	}
	if err := json.NewDecoder(io.LimitReader(request.Body, 64<<10)).Decode(&input); err != nil || input.GrantID == "" {
		http.Error(writer, "grant ID is required", http.StatusBadRequest)
		return
	}
	if err := a.Revoke(request.Context(), input.GrantID); err != nil {
		http.Error(writer, "grant revoke failed", http.StatusConflict)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"grant_id": input.GrantID, "revoked": true})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
