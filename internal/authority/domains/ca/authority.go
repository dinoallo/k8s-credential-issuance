// Package ca implements the external authority for CA certificate Grants.
package ca

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	grantapi "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/audit"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/canonical"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/grant"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/replay"
	cadomain "github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/ca"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/ca/csr"
)

var (
	ErrRegistrationNotFound = errors.New("CA identity registration was not found")
	ErrRegistrationDenied   = errors.New("CA identity registration denied the request")
)

type Registration struct {
	Identity          string
	IdentityPublicKey string
	ClusterID         string
	Profile           string
	SignerName        string
	Subject           grantapi.X509Subject
	DNSNames          []string
	IPAddresses       []string
	URIs              []string
	KeyUsages         []string
	ExtendedKeyUsages []string
	Generation        string
	KeyID             string
	MaxTTL            time.Duration
	Active            bool
}

type RegistrationStore interface {
	Register(context.Context, Registration) error
	Find(context.Context, string) (Registration, error)
}

type MemoryRegistrationStore struct {
	mu            sync.RWMutex
	registrations map[string]Registration
}

func NewMemoryRegistrationStore() *MemoryRegistrationStore {
	return &MemoryRegistrationStore{registrations: make(map[string]Registration)}
}

func (s *MemoryRegistrationStore) Register(_ context.Context, value Registration) error {
	if s == nil {
		return fmt.Errorf("CA registration store is nil")
	}
	if value.Identity == "" || value.IdentityPublicKey == "" || value.ClusterID == "" || value.Profile == "" || value.SignerName == "" || value.Generation == "" || value.KeyID == "" || value.MaxTTL <= 0 {
		return fmt.Errorf("CA registration is incomplete")
	}
	if _, err := identity.DecodePublicKey(value.IdentityPublicKey); err != nil {
		return err
	}
	value.KeyUsages = cadomain.NormalizeUsages(value.KeyUsages)
	value.ExtendedKeyUsages = cadomain.NormalizeUsages(value.ExtendedKeyUsages)
	value.DNSNames = csr.NormalizeDNSNamesMust(value.DNSNames)
	value.IPAddresses = normalizeStrings(value.IPAddresses)
	value.URIs = normalizeStrings(value.URIs)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.registrations[value.Identity]; exists {
		return fmt.Errorf("registration for identity %q already exists", value.Identity)
	}
	s.registrations[value.Identity] = value
	return nil
}

func (s *MemoryRegistrationStore) Find(_ context.Context, identityRef string) (Registration, error) {
	if s == nil {
		return Registration{}, fmt.Errorf("CA registration store is nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.registrations[identityRef]
	if !ok || !value.Active {
		return Registration{}, ErrRegistrationNotFound
	}
	return value, nil
}

type Request struct {
	Identity          string                `json:"identity"`
	CSR               []byte                `json:"csr"`
	SignerName        string                `json:"signer_name"`
	Profile           string                `json:"profile"`
	KeyUsages         []string              `json:"key_usages"`
	ExtendedKeyUsages []string              `json:"extended_key_usages"`
	ExpirationSeconds int64                 `json:"expiration_seconds"`
	Generation        string                `json:"generation"`
	KeyID             string                `json:"key_id"`
	Proof             signapi.IdentityProof `json:"proof"`
}

type GrantResponse struct {
	Grant      string `json:"grant"`
	GrantID    string `json:"grant_id"`
	RequestID  string `json:"request_id"`
	NotBefore  int64  `json:"not_before"`
	ExpiresAt  int64  `json:"expires_at"`
	Generation string `json:"generation"`
	KeyID      string `json:"key_id"`
}

type Config struct {
	ClusterID     string
	PolicyVersion string
	EAAKeyID      string
	SigningKey    ed25519.PrivateKey
	Registrations RegistrationStore
	Profiles      *cadomain.Registry
	ProofReplay   replay.Store
	Grants        *GrantLedger
	Audit         audit.Sink
	Now           func() time.Time
}

type Authority struct {
	clusterID, policyVersion, eaaKeyID string
	signingKey                         ed25519.PrivateKey
	registrations                      RegistrationStore
	profiles                           *cadomain.Registry
	proofs                             *identity.Verifier
	grants                             *GrantLedger
	audit                              audit.Sink
	now                                func() time.Time
}

func New(config Config) (*Authority, error) {
	if config.ClusterID == "" || config.PolicyVersion == "" || config.EAAKeyID == "" || len(config.SigningKey) != ed25519.PrivateKeySize || config.Registrations == nil || config.Profiles == nil {
		return nil, fmt.Errorf("CA authority is not configured")
	}
	if config.ProofReplay == nil {
		config.ProofReplay = replay.NewMemoryStore(config.Now)
	}
	if config.Grants == nil {
		config.Grants = NewGrantLedger()
	}
	if config.Audit == nil {
		config.Audit = audit.NopSink{}
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Authority{clusterID: config.ClusterID, policyVersion: config.PolicyVersion, eaaKeyID: config.EAAKeyID, signingKey: append(ed25519.PrivateKey(nil), config.SigningKey...), registrations: config.Registrations, profiles: config.Profiles, proofs: identity.NewVerifier(nil, config.ProofReplay), grants: config.Grants, audit: config.Audit, now: config.Now}, nil
}

// SetIdentityKeys installs the independently provisioned worker/agent public
// keys used by the generic binding proof. It is kept separate from Grant
// verification keys because those are different trust domains.
func (a *Authority) SetIdentityKeys(keys map[string]ed25519.PublicKey) {
	if a == nil {
		return
	}
	a.proofs = identity.NewVerifier(keys, a.proofs.Replay)
}

func (a *Authority) Issue(ctx context.Context, request Request) (GrantResponse, error) {
	if a == nil || a.registrations == nil || a.profiles == nil || len(a.signingKey) != ed25519.PrivateKeySize {
		return GrantResponse{}, fmt.Errorf("CA authority is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if request.Identity == "" || len(request.CSR) == 0 || request.SignerName == "" || request.Profile == "" || request.ExpirationSeconds <= 0 || request.Generation == "" || request.KeyID == "" {
		return GrantResponse{}, ErrRegistrationDenied
	}
	parsed, der, err := csr.Parse(request.CSR)
	if err != nil {
		return GrantResponse{}, err
	}
	if err := csr.ValidateSubject(parsed); err != nil {
		return GrantResponse{}, err
	}
	registration, err := a.registrations.Find(ctx, request.Identity)
	if err != nil {
		return GrantResponse{}, err
	}
	registeredKey, err := identity.DecodePublicKey(registration.IdentityPublicKey)
	if err != nil {
		return GrantResponse{}, ErrRegistrationDenied
	}
	proofVerifier := identity.NewVerifier(map[string]ed25519.PublicKey{request.Identity: registeredKey}, a.proofs.Replay)
	if registration.ClusterID != a.clusterID || registration.Profile != request.Profile || registration.SignerName != request.SignerName || registration.Generation != request.Generation || registration.KeyID != request.KeyID || time.Duration(request.ExpirationSeconds)*time.Second > registration.MaxTTL {
		return GrantResponse{}, ErrRegistrationDenied
	}
	requestedEKU, err := csr.ExtendedKeyUsages(parsed)
	if err != nil {
		return GrantResponse{}, err
	}
	if !equalStrings(requestedEKU, request.ExtendedKeyUsages) || !equalStrings(csr.NormalizeDNSNamesMust(parsed.DNSNames), registration.DNSNames) || !csr.EqualSubject(csr.Subject(parsed), registration.Subject) || !equalStrings(csr.NormalizeIPAddresses(parsed.IPAddresses), registration.IPAddresses) || !equalStrings(csr.NormalizeURIsMust(parsed.URIs), registration.URIs) || !equalStrings(cadomain.NormalizeUsages(request.KeyUsages), registration.KeyUsages) || !equalStrings(requestedEKU, registration.ExtendedKeyUsages) {
		return GrantResponse{}, ErrRegistrationDenied
	}
	payload, err := cadomain.Payload(signapi.CertificateSignRequest{CSR: request.CSR, SignerName: request.SignerName, Profile: request.Profile, KeyUsages: request.KeyUsages, ExtendedKeyUsages: request.ExtendedKeyUsages, ExpirationSeconds: request.ExpirationSeconds, Generation: request.Generation, KeyID: request.KeyID}, parsed, der)
	if err != nil {
		return GrantResponse{}, err
	}
	if _, err := a.profiles.Validate(payload); err != nil {
		return GrantResponse{}, err
	}
	if a.proofs == nil {
		return GrantResponse{}, ErrRegistrationDenied
	}
	if err := proofVerifier.VerifyBindingProof(ctx, request.Identity, request.Proof, payload, payload.CSRRequestDigest); err != nil {
		return GrantResponse{}, fmt.Errorf("verify CA worker proof: %w", err)
	}
	now := a.now().UTC()
	grantID, err := grant.NewID("ca-grant")
	if err != nil {
		return GrantResponse{}, err
	}
	requestID, err := grant.NewID("ca-request")
	if err != nil {
		return GrantResponse{}, err
	}
	nonce, err := grant.NewID("ca-nonce")
	if err != nil {
		return GrantResponse{}, err
	}
	payloadBytes, err := canonicalPayload(payload)
	if err != nil {
		return GrantResponse{}, err
	}
	bindingDigest, err := cadomain.BindingDigest(payload)
	if err != nil {
		return GrantResponse{}, err
	}
	value := grantapi.Grant{Version: grantapi.ContractVersion, Domain: grantapi.DomainCA, GrantID: grantID, RequestID: requestID, IdentityRef: request.Identity, BindingDigest: bindingDigest, Generation: request.Generation, KeyID: request.KeyID, PolicyVersion: a.policyVersion, NotBefore: now.Unix(), ExpiresAt: now.Add(time.Duration(request.ExpirationSeconds) * time.Second).Unix(), Nonce: nonce, TypedPayload: payloadBytes}
	raw, err := grant.Sign(value, a.eaaKeyID, a.signingKey)
	if err != nil {
		return GrantResponse{}, err
	}
	if err := a.grants.RecordIssued(ctx, grantID, time.Unix(value.ExpiresAt, 0)); err != nil {
		return GrantResponse{}, err
	}
	if err := audit.Record(ctx, a.audit, audit.Event{Component: "ca-authority", Domain: string(grantapi.DomainCA), Action: "grant", Outcome: "allow", GrantID: grantID, RequestID: requestID, IdentityRef: request.Identity}); err != nil {
		return GrantResponse{}, err
	}
	return GrantResponse{Grant: string(raw), GrantID: grantID, RequestID: requestID, NotBefore: value.NotBefore, ExpiresAt: value.ExpiresAt, Generation: value.Generation, KeyID: value.KeyID}, nil
}

func (a *Authority) Revoke(ctx context.Context, grantID string) error {
	if a == nil || a.grants == nil {
		return fmt.Errorf("CA authority is not configured")
	}
	return a.grants.Revoke(ctx, grantID)
}
func (a *Authority) IsRevoked(ctx context.Context, grantID string) (bool, error) {
	if a == nil || a.grants == nil {
		return false, fmt.Errorf("CA authority is not configured")
	}
	return a.grants.IsRevoked(ctx, grantID)
}

func (a *Authority) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/grants", a.handleGrant)
	return mux
}

func (a *Authority) handleGrant(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var input Request
	decoder := json.NewDecoder(http.MaxBytesReader(w, request.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid CA Grant request", http.StatusBadRequest)
		return
	}
	if header := request.Header.Get("X-Issuance-Identity"); header != "" && input.Identity != "" && header != input.Identity {
		http.Error(w, "identity mismatch", http.StatusForbidden)
		return
	}
	result, err := a.Issue(request.Context(), input)
	if err != nil {
		http.Error(w, "CA Grant denied", http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type GrantLedger struct {
	mu      sync.Mutex
	revoked map[string]bool
	issued  map[string]time.Time
}

func NewGrantLedger() *GrantLedger {
	return &GrantLedger{revoked: make(map[string]bool), issued: make(map[string]time.Time)}
}
func (l *GrantLedger) RecordIssued(_ context.Context, id string, expiry time.Time) error {
	if l == nil || id == "" || expiry.IsZero() {
		return fmt.Errorf("invalid CA Grant ledger record")
	}
	l.mu.Lock()
	l.issued[id] = expiry
	l.mu.Unlock()
	return nil
}
func (l *GrantLedger) Revoke(_ context.Context, id string) error {
	if l == nil || id == "" {
		return fmt.Errorf("invalid CA Grant ID")
	}
	l.mu.Lock()
	l.revoked[id] = true
	l.mu.Unlock()
	return nil
}
func (l *GrantLedger) IsRevoked(_ context.Context, id string) (bool, error) {
	if l == nil {
		return false, fmt.Errorf("CA Grant ledger is nil")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.revoked[id], nil
}

func canonicalPayload(value grantapi.CertificatePayload) ([]byte, error) {
	return canonical.Marshal(value)
}
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func normalizeStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	unique := result[:0]
	for _, value := range result {
		if value != "" && (len(unique) == 0 || unique[len(unique)-1] != value) {
			unique = append(unique, value)
		}
	}
	return unique
}
