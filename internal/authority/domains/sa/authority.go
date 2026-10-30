// Package sa implements the ServiceAccount external authorization authority.
package sa

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	grantapi "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/audit"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/grant"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/replay"
	sadomain "github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/sa"
)

var (
	ErrRegistrationNotFound = errors.New("no matching SA workload registration")
	ErrRegistrationExists   = errors.New("SA workload registration already exists")
	ErrGrantRevoked         = errors.New("SA Grant has been revoked")
)

type WorkloadRegistration struct {
	RegistrationID          string   `json:"registration_id"`
	Identity                string   `json:"identity"`
	IdentityPublicKey       string   `json:"identity_public_key"`
	ClusterID               string   `json:"cluster_id"`
	ServiceAccountNamespace string   `json:"service_account_namespace"`
	ServiceAccountName      string   `json:"service_account_name"`
	ServiceAccountUID       string   `json:"service_account_uid"`
	PodUID                  string   `json:"pod_uid,omitempty"`
	Issuer                  string   `json:"issuer"`
	AllowedAudiences        []string `json:"allowed_audiences"`
	MaxTokenLifetimeSecs    int64    `json:"max_token_lifetime_seconds"`
	TokenGeneration         string   `json:"token_generation"`
	KeyID                   string   `json:"key_id"`
	PolicyVersion           string   `json:"policy_version"`
	Active                  bool     `json:"active"`
}

type RegistrationStore interface {
	Register(context.Context, WorkloadRegistration) error
	Find(context.Context, string, signapi.TokenBinding) (WorkloadRegistration, error)
	PublicKeys(context.Context) (map[string]ed25519.PublicKey, error)
}

type MemoryRegistrationStore struct {
	mu            sync.RWMutex
	registrations map[string]WorkloadRegistration
}

func NewMemoryRegistrationStore() *MemoryRegistrationStore {
	return &MemoryRegistrationStore{registrations: make(map[string]WorkloadRegistration)}
}

func (s *MemoryRegistrationStore) Register(_ context.Context, registration WorkloadRegistration) error {
	if s == nil {
		return fmt.Errorf("registration store is nil")
	}
	if err := validateRegistration(registration); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.registrations[registration.RegistrationID]; exists {
		return ErrRegistrationExists
	}
	for _, existing := range s.registrations {
		if existing.Active && existing.Identity == registration.Identity && existing.ServiceAccountNamespace == registration.ServiceAccountNamespace && existing.ServiceAccountName == registration.ServiceAccountName && existing.PodUID == registration.PodUID {
			return fmt.Errorf("%w: active identity/workload binding already exists", ErrRegistrationExists)
		}
	}
	registration.AllowedAudiences = append([]string(nil), registration.AllowedAudiences...)
	s.registrations[registration.RegistrationID] = registration
	return nil
}

func (s *MemoryRegistrationStore) Find(_ context.Context, identityName string, binding signapi.TokenBinding) (WorkloadRegistration, error) {
	if s == nil {
		return WorkloadRegistration{}, fmt.Errorf("registration store is nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, registration := range s.registrations {
		if registration.Active && registration.Identity == identityName && registrationMatches(registration, binding) {
			registration.AllowedAudiences = append([]string(nil), registration.AllowedAudiences...)
			return registration, nil
		}
	}
	return WorkloadRegistration{}, ErrRegistrationNotFound
}

func (s *MemoryRegistrationStore) PublicKeys(_ context.Context) (map[string]ed25519.PublicKey, error) {
	if s == nil {
		return nil, fmt.Errorf("registration store is nil")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make(map[string]ed25519.PublicKey)
	for _, registration := range s.registrations {
		if !registration.Active {
			continue
		}
		key, err := identity.DecodePublicKey(registration.IdentityPublicKey)
		if err != nil {
			return nil, fmt.Errorf("registration %q has invalid public key: %w", registration.RegistrationID, err)
		}
		if existing, ok := keys[registration.Identity]; ok && string(existing) != string(key) {
			return nil, fmt.Errorf("identity %q has conflicting public keys", registration.Identity)
		}
		keys[registration.Identity] = key
	}
	return keys, nil
}

type GrantRecord struct {
	GrantID   string    `json:"grant_id"`
	Domain    string    `json:"domain"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

type GrantLedger interface {
	RecordIssued(context.Context, GrantRecord) error
	IsRevoked(context.Context, string) (bool, error)
	Revoke(context.Context, string) error
}

type MemoryGrantLedger struct {
	mu      sync.RWMutex
	records map[string]GrantRecord
}

func NewMemoryGrantLedger() *MemoryGrantLedger {
	return &MemoryGrantLedger{records: make(map[string]GrantRecord)}
}

func (l *MemoryGrantLedger) RecordIssued(_ context.Context, record GrantRecord) error {
	if l == nil || record.GrantID == "" || record.ExpiresAt.IsZero() {
		return fmt.Errorf("grant ledger record is incomplete")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, exists := l.records[record.GrantID]; exists {
		return fmt.Errorf("Grant %q already exists", record.GrantID)
	}
	l.records[record.GrantID] = record
	return nil
}

func (l *MemoryGrantLedger) IsRevoked(_ context.Context, grantID string) (bool, error) {
	if l == nil {
		return false, fmt.Errorf("grant ledger is nil")
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	record, ok := l.records[grantID]
	return ok && record.Revoked, nil
}

func (l *MemoryGrantLedger) Revoke(_ context.Context, grantID string) error {
	if l == nil {
		return fmt.Errorf("grant ledger is nil")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	record, ok := l.records[grantID]
	if !ok {
		return fmt.Errorf("Grant %q is not in the ledger", grantID)
	}
	record.Revoked = true
	l.records[grantID] = record
	return nil
}

type FileGrantLedger struct {
	mu      sync.Mutex
	path    string
	records map[string]GrantRecord
}

func NewFileGrantLedger(path string) (*FileGrantLedger, error) {
	if path == "" {
		return nil, fmt.Errorf("grant ledger path is empty")
	}
	ledger := &FileGrantLedger{path: path, records: make(map[string]GrantRecord)}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return ledger, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &ledger.records); err != nil {
		return nil, fmt.Errorf("decode Grant ledger: %w", err)
	}
	return ledger, nil
}

func (l *FileGrantLedger) RecordIssued(_ context.Context, record GrantRecord) error {
	if l == nil || record.GrantID == "" || record.ExpiresAt.IsZero() {
		return fmt.Errorf("grant ledger record is incomplete")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, exists := l.records[record.GrantID]; exists {
		return fmt.Errorf("Grant %q already exists", record.GrantID)
	}
	l.records[record.GrantID] = record
	if err := l.persistLocked(); err != nil {
		delete(l.records, record.GrantID)
		return err
	}
	return nil
}

func (l *FileGrantLedger) IsRevoked(_ context.Context, grantID string) (bool, error) {
	if l == nil {
		return false, fmt.Errorf("grant ledger is nil")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	record, ok := l.records[grantID]
	return ok && record.Revoked, nil
}

func (l *FileGrantLedger) Revoke(_ context.Context, grantID string) error {
	if l == nil {
		return fmt.Errorf("grant ledger is nil")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	record, ok := l.records[grantID]
	if !ok {
		return fmt.Errorf("Grant %q is not in the ledger", grantID)
	}
	record.Revoked = true
	l.records[grantID] = record
	if err := l.persistLocked(); err != nil {
		record.Revoked = false
		l.records[grantID] = record
		return err
	}
	return nil
}

func (l *FileGrantLedger) persistLocked() error {
	parent := filepath.Dir(l.path)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(parent, ".grants-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := json.NewEncoder(temporary).Encode(l.records); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, l.path)
}

type Config struct {
	ClusterID        string
	Issuer           string
	PolicyVersion    string
	KeyID            string
	PrivateKey       ed25519.PrivateKey
	GrantFormat      string
	Registrations    RegistrationStore
	ProofReplay      replay.Store
	Grants           GrantLedger
	Audit            audit.Sink
	Now              func() time.Time
	MaxClockSkew     time.Duration
	MaxTokenLifetime time.Duration
}

type Authority struct {
	config        Config
	proofVerifier *identity.Verifier
}

func New(config Config) (*Authority, error) {
	if config.ClusterID == "" || config.Issuer == "" || config.PolicyVersion == "" || config.KeyID == "" || len(config.PrivateKey) != ed25519.PrivateKeySize || config.Registrations == nil || config.ProofReplay == nil || config.Grants == nil {
		return nil, fmt.Errorf("SA authority configuration is incomplete")
	}
	if config.GrantFormat == "" {
		config.GrantFormat = grant.Format
	}
	if config.GrantFormat != grant.Format && config.GrantFormat != sadomain.LegacyGrantFormat {
		return nil, fmt.Errorf("unsupported SA Grant format %q", config.GrantFormat)
	}
	if config.Audit == nil {
		return nil, fmt.Errorf("audit sink is required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.MaxClockSkew <= 0 {
		config.MaxClockSkew = 30 * time.Second
	}
	if config.MaxTokenLifetime <= 0 {
		config.MaxTokenLifetime = time.Hour
	}
	keys, err := config.Registrations.PublicKeys(context.Background())
	if err != nil {
		return nil, err
	}
	proofVerifier := identity.NewVerifier(keys, config.ProofReplay)
	proofVerifier.Now = config.Now
	proofVerifier.MaxClockSkew = config.MaxClockSkew
	return &Authority{config: config, proofVerifier: proofVerifier}, nil
}

// Register adds a workload identity to the authority's policy store. The
// defaults keep bootstrap configuration concise while the registration store
// remains the source of truth for exact binding checks.
func (a *Authority) Register(ctx context.Context, registration WorkloadRegistration) error {
	if a == nil || a.config.Registrations == nil {
		return fmt.Errorf("SA authority is not configured")
	}
	if registration.ClusterID == "" {
		registration.ClusterID = a.config.ClusterID
	}
	if registration.Issuer == "" {
		registration.Issuer = a.config.Issuer
	}
	return a.config.Registrations.Register(ctx, registration)
}

func (a *Authority) Issue(ctx context.Context, request signapi.GrantRequest) ([]byte, error) {
	if a == nil || a.proofVerifier == nil {
		return nil, fmt.Errorf("SA authority is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if request.Identity == "" || !grant.ValidDigest(request.ClaimsDigest) {
		return nil, fmt.Errorf("Grant request is incomplete")
	}
	registration, err := a.config.Registrations.Find(ctx, request.Identity, request.Binding)
	if err != nil {
		return nil, err
	}
	keys, err := a.config.Registrations.PublicKeys(ctx)
	if err != nil {
		return nil, a.deny(ctx, request, fmt.Errorf("load registered identity keys: %w", err))
	}
	proofVerifier := identity.NewVerifier(keys, a.config.ProofReplay)
	proofVerifier.Now = a.config.Now
	proofVerifier.MaxClockSkew = a.config.MaxClockSkew
	if err := proofVerifier.Verify(ctx, request.Identity, request.Proof, request.Binding, request.ClaimsDigest); err != nil {
		return nil, a.deny(ctx, request, err)
	}
	now := a.config.Now()
	if request.Binding.NotBefore <= 0 || request.Binding.NotAfter <= request.Binding.NotBefore || time.Unix(request.Binding.NotBefore, 0).Before(now.Add(-a.config.MaxClockSkew)) || time.Unix(request.Binding.NotAfter, 0).Before(now) {
		return nil, a.deny(ctx, request, fmt.Errorf("binding validity window is outside the authority clock window"))
	}
	legacy := a.config.GrantFormat == sadomain.LegacyGrantFormat
	if request.Binding.ClusterID != a.config.ClusterID || request.Binding.Issuer != a.config.Issuer || request.Binding.TokenGeneration != registration.TokenGeneration || (!legacy && request.Binding.KeyID != "" && request.Binding.KeyID != registration.KeyID) {
		return nil, a.deny(ctx, request, fmt.Errorf("binding does not match authority policy"))
	}
	if !legacy && registration.KeyID == "" {
		return nil, a.deny(ctx, request, fmt.Errorf("registration has no JWT key ID"))
	}
	if !legacy && request.Binding.KeyID == "" {
		request.Binding.KeyID = registration.KeyID
	}
	if registration.PolicyVersion != a.config.PolicyVersion {
		return nil, a.deny(ctx, request, fmt.Errorf("registration policy version is not active"))
	}
	lifetime := request.Binding.NotAfter - request.Binding.NotBefore
	if lifetime <= 0 || time.Duration(lifetime)*time.Second > a.config.MaxTokenLifetime || registration.MaxTokenLifetimeSecs > 0 && lifetime > registration.MaxTokenLifetimeSecs {
		return nil, a.deny(ctx, request, fmt.Errorf("requested lifetime exceeds authority policy"))
	}
	grantID, err := grant.NewID("grant")
	if err != nil {
		return nil, err
	}
	nonce, err := grant.NewID("nonce")
	if err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, a.config.Audit, audit.Event{Component: "sa-authority", Domain: string(grantapi.DomainSA), Action: "grant", Outcome: "allow", GrantID: grantID, RequestID: grantID, IdentityRef: request.Identity}); err != nil {
		return nil, fmt.Errorf("record authority audit: %w", err)
	}
	var rawGrant []byte
	if legacy {
		legacyBinding := request.Binding
		legacyBinding.KeyID = ""
		rawGrant, err = sadomain.SignLegacyGrant(sadomain.LegacyTokenGrant{GrantID: grantID, ClusterID: legacyBinding.ClusterID, ClaimsDigest: request.ClaimsDigest, ServiceAccountNamespace: legacyBinding.ServiceAccountNamespace, ServiceAccountName: legacyBinding.ServiceAccountName, ServiceAccountUID: legacyBinding.ServiceAccountUID, PodUID: legacyBinding.PodUID, Subject: legacyBinding.Subject, Audience: legacyBinding.Audience, Issuer: legacyBinding.Issuer, TokenGeneration: legacyBinding.TokenGeneration, NotBefore: legacyBinding.NotBefore, NotAfter: legacyBinding.NotAfter, Nonce: nonce, PolicyVersion: a.config.PolicyVersion}, a.config.KeyID, a.config.PrivateKey)
	} else {
		payload, err := sadomain.GrantPayload(request.Binding, request.ClaimsDigest)
		if err != nil {
			return nil, a.deny(ctx, request, err)
		}
		typedPayload, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		canonicalPayload, err := sadomain.CanonicalizeClaims(typedPayload)
		if err != nil {
			return nil, err
		}
		bindingDigest, err := sadomain.BindingDigest(request.ClaimsDigest, request.Binding)
		if err != nil {
			return nil, err
		}
		value := grantapi.Grant{Version: grantapi.ContractVersion, Domain: grantapi.DomainSA, GrantID: grantID, RequestID: grantID, IdentityRef: request.Identity, BindingDigest: bindingDigest, Generation: request.Binding.TokenGeneration, KeyID: request.Binding.KeyID, PolicyVersion: a.config.PolicyVersion, NotBefore: request.Binding.NotBefore, ExpiresAt: request.Binding.NotAfter, Nonce: nonce, TypedPayload: canonicalPayload}
		rawGrant, err = grant.Sign(value, a.config.KeyID, a.config.PrivateKey)
	}
	if err != nil {
		return nil, err
	}
	if err := a.config.Grants.RecordIssued(ctx, GrantRecord{GrantID: grantID, Domain: string(grantapi.DomainSA), ExpiresAt: time.Unix(request.Binding.NotAfter, 0)}); err != nil {
		return nil, err
	}
	return rawGrant, nil
}

func (a *Authority) Revoke(ctx context.Context, grantID string) error {
	if a == nil || a.config.Grants == nil {
		return fmt.Errorf("SA authority is not configured")
	}
	if err := a.config.Grants.Revoke(ctx, grantID); err != nil {
		return err
	}
	return audit.Record(ctx, a.config.Audit, audit.Event{Component: "sa-authority", Domain: string(grantapi.DomainSA), Action: "revoke", Outcome: "allow", GrantID: grantID})
}

func (a *Authority) IsRevoked(ctx context.Context, grantID string) (bool, error) {
	if a == nil || a.config.Grants == nil {
		return false, fmt.Errorf("SA authority is not configured")
	}
	return a.config.Grants.IsRevoked(ctx, grantID)
}

func (a *Authority) deny(ctx context.Context, request signapi.GrantRequest, err error) error {
	_ = audit.Record(ctx, a.config.Audit, audit.Event{Component: "sa-authority", Domain: string(grantapi.DomainSA), Action: "grant", Outcome: "deny", IdentityRef: request.Identity, Reason: err.Error()})
	return err
}

func validateRegistration(registration WorkloadRegistration) error {
	if registration.RegistrationID == "" || registration.Identity == "" || registration.IdentityPublicKey == "" || registration.ClusterID == "" || registration.ServiceAccountNamespace == "" || registration.ServiceAccountName == "" || registration.ServiceAccountUID == "" || registration.Issuer == "" || registration.TokenGeneration == "" || registration.PolicyVersion == "" || len(registration.AllowedAudiences) == 0 {
		return fmt.Errorf("workload registration is incomplete")
	}
	if !sortedUnique(registration.AllowedAudiences) {
		return fmt.Errorf("registration audiences must be sorted and unique")
	}
	if _, err := identity.DecodePublicKey(registration.IdentityPublicKey); err != nil {
		return err
	}
	return nil
}

func registrationMatches(registration WorkloadRegistration, binding signapi.TokenBinding) bool {
	return registration.ClusterID == binding.ClusterID && registration.ServiceAccountNamespace == binding.ServiceAccountNamespace && registration.ServiceAccountName == binding.ServiceAccountName && registration.ServiceAccountUID == binding.ServiceAccountUID && registration.PodUID == binding.PodUID && registration.Issuer == binding.Issuer && registration.TokenGeneration == binding.TokenGeneration && audienceSubset(registration.AllowedAudiences, binding.Audience)
}

func sortedUnique(values []string) bool {
	for i, value := range values {
		if value == "" || i > 0 && values[i-1] >= value {
			return false
		}
	}
	return true
}

func audienceSubset(allowed, requested []string) bool {
	if len(requested) == 0 {
		return false
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, audience := range allowed {
		allowedSet[audience] = struct{}{}
	}
	requestedSet := make(map[string]struct{}, len(requested))
	for _, audience := range requested {
		if audience == "" {
			return false
		}
		if _, duplicate := requestedSet[audience]; duplicate {
			return false
		}
		requestedSet[audience] = struct{}{}
		if _, permitted := allowedSet[audience]; !permitted {
			return false
		}
	}
	return true
}
