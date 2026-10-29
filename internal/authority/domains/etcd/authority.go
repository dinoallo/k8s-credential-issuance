// Package etcd implements the external authority and lifecycle registry for
// etcd peer/client certificate Grants. Certificate issuance never mutates
// membership; replacement and snapshot restore are explicit registry calls.
package etcd

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
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
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/ca/csr"
	etcdomain "github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/etcd"
)

var (
	ErrRegistrationNotFound = errors.New("etcd identity registration was not found")
	ErrRegistrationDenied   = errors.New("etcd identity registration denied the request")
)

type Registration struct {
	ClusterInstance   string
	ID                string
	Identity          string
	IdentityPublicKey string
	Profile           string
	EndpointSANs      []string
	Roles             []string
	Generation        string
	KeyID             string
	MaxTTL            time.Duration
	Active            bool
}

type Snapshot struct {
	ClusterInstance string
	Members         []Registration
	Clients         []Registration
	Revision        uint64
}

type RoleMapper interface {
	Map(context.Context, string, []string) ([]string, error)
}

// StaticRoleMapper is a reference identity-to-etcd-role policy. Production
// deployments can replace it with a registry-backed mapper, but callers never
// get to mint roles outside this mapping.
type StaticRoleMapper map[string][]string

func (m StaticRoleMapper) Map(_ context.Context, identityRef string, requested []string) ([]string, error) {
	allowed, ok := m[identityRef]
	if !ok {
		return nil, fmt.Errorf("etcd identity %q has no role mapping", identityRef)
	}
	allowed = etcdomain.Normalize(allowed)
	requested = etcdomain.Normalize(requested)
	for _, role := range requested {
		found := false
		for _, candidate := range allowed {
			if role == candidate {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("etcd role %q is not mapped to identity %q", role, identityRef)
		}
	}
	return requested, nil
}

type Registry interface {
	Register(context.Context, Registration) error
	Find(context.Context, string, string, string) (Registration, error)
	ReplaceMember(context.Context, string, Registration) error
	Snapshot(context.Context) (Snapshot, error)
	RestoreSnapshot(context.Context, Snapshot) error
}

type MemoryRegistry struct {
	mu       sync.RWMutex
	members  map[string]Registration
	clients  map[string]Registration
	cluster  string
	revision uint64
}

func NewMemoryRegistry(cluster string) *MemoryRegistry {
	return &MemoryRegistry{cluster: cluster, members: make(map[string]Registration), clients: make(map[string]Registration)}
}
func (r *MemoryRegistry) Register(_ context.Context, value Registration) error {
	if r == nil || value.ClusterInstance == "" || value.ClusterInstance != r.cluster || value.ID == "" || value.Identity == "" || value.IdentityPublicKey == "" || (value.Profile != etcdomain.ProfilePeer && value.Profile != etcdomain.ProfileClient) || value.Generation == "" || value.KeyID == "" || value.MaxTTL <= 0 {
		return fmt.Errorf("etcd registration is incomplete")
	}
	if _, err := identity.DecodePublicKey(value.IdentityPublicKey); err != nil {
		return err
	}
	value.EndpointSANs = etcdomain.Normalize(value.EndpointSANs)
	value.Roles = etcdomain.Normalize(value.Roles)
	r.mu.Lock()
	defer r.mu.Unlock()
	target := r.target(value.Profile)
	if _, exists := target[value.ID]; exists {
		return fmt.Errorf("etcd registration %q already exists", value.ID)
	}
	target[value.ID] = cloneRegistration(value)
	r.revision++
	return nil
}
func (r *MemoryRegistry) Find(_ context.Context, profile, id, identityRef string) (Registration, error) {
	if r == nil {
		return Registration{}, fmt.Errorf("etcd registry is nil")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	target := r.targetRead(profile)
	value, ok := target[id]
	if !ok || !value.Active || value.Identity != identityRef {
		return Registration{}, ErrRegistrationNotFound
	}
	return cloneRegistration(value), nil
}
func (r *MemoryRegistry) ReplaceMember(_ context.Context, oldID string, value Registration) error {
	if r == nil {
		return fmt.Errorf("etcd registry is nil")
	}
	if value.Profile != etcdomain.ProfilePeer {
		return fmt.Errorf("member replacement requires etcd-peer")
	}
	if err := r.validateRegistration(value); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	old, ok := r.members[oldID]
	if !ok || !old.Active {
		return ErrRegistrationNotFound
	}
	old.Active = false
	r.members[oldID] = old
	if _, exists := r.members[value.ID]; exists {
		return fmt.Errorf("replacement member ID already exists")
	}
	r.members[value.ID] = cloneRegistration(value)
	r.revision++
	return nil
}
func (r *MemoryRegistry) Snapshot(_ context.Context) (Snapshot, error) {
	if r == nil {
		return Snapshot{}, fmt.Errorf("etcd registry is nil")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := Snapshot{ClusterInstance: r.cluster, Revision: r.revision}
	for _, value := range r.members {
		result.Members = append(result.Members, cloneRegistration(value))
	}
	for _, value := range r.clients {
		result.Clients = append(result.Clients, cloneRegistration(value))
	}
	sortRegistrations(result.Members)
	sortRegistrations(result.Clients)
	return result, nil
}
func (r *MemoryRegistry) RestoreSnapshot(_ context.Context, snapshot Snapshot) error {
	if r == nil || snapshot.ClusterInstance != r.cluster {
		return fmt.Errorf("etcd snapshot cluster does not match")
	}
	members, clients := make(map[string]Registration), make(map[string]Registration)
	for _, value := range append(append([]Registration(nil), snapshot.Members...), snapshot.Clients...) {
		if err := r.validateRegistration(value); err != nil {
			return err
		}
		if value.Profile == etcdomain.ProfilePeer {
			members[value.ID] = cloneRegistration(value)
		} else {
			clients[value.ID] = cloneRegistration(value)
		}
	}
	r.mu.Lock()
	r.members, r.clients, r.revision = members, clients, snapshot.Revision
	r.mu.Unlock()
	return nil
}
func (r *MemoryRegistry) validateRegistration(value Registration) error {
	if value.ClusterInstance != r.cluster || value.ID == "" || value.Identity == "" || (value.Profile != etcdomain.ProfilePeer && value.Profile != etcdomain.ProfileClient) || value.Generation == "" || value.KeyID == "" || value.MaxTTL <= 0 {
		return fmt.Errorf("etcd registration is incomplete")
	}
	if _, err := identity.DecodePublicKey(value.IdentityPublicKey); err != nil {
		return err
	}
	return nil
}
func (r *MemoryRegistry) target(profile string) map[string]Registration {
	if profile == etcdomain.ProfilePeer {
		return r.members
	}
	return r.clients
}
func (r *MemoryRegistry) targetRead(profile string) map[string]Registration {
	if profile == etcdomain.ProfilePeer {
		return r.members
	}
	return r.clients
}
func cloneRegistration(value Registration) Registration {
	value.EndpointSANs = append([]string(nil), value.EndpointSANs...)
	value.Roles = append([]string(nil), value.Roles...)
	return value
}
func sortRegistrations(values []Registration) {
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
}

type Request struct {
	Identity               string                `json:"identity"`
	CSR                    []byte                `json:"csr"`
	ClusterInstance        string                `json:"cluster_instance"`
	ID                     string                `json:"id"`
	MemberOrClientIdentity string                `json:"member_or_client_identity"`
	EndpointSANs           []string              `json:"endpoint_sans"`
	Profile                string                `json:"profile"`
	Roles                  []string              `json:"roles,omitempty"`
	ExpirationSeconds      int64                 `json:"expiration_seconds"`
	Generation             string                `json:"generation"`
	KeyID                  string                `json:"key_id"`
	Proof                  signapi.IdentityProof `json:"proof"`
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
	ClusterInstance string
	PolicyVersion   string
	EAAKeyID        string
	SigningKey      ed25519.PrivateKey
	Registry        Registry
	Profiles        *etcdomain.Registry
	RoleMapper      RoleMapper
	ProofReplay     replay.Store
	Audit           audit.Sink
	Now             func() time.Time
}
type Authority struct {
	cluster, policy string
	keyID           string
	signingKey      ed25519.PrivateKey
	registry        Registry
	profiles        *etcdomain.Registry
	roleMapper      RoleMapper
	proofs          *identity.Verifier
	grants          *GrantLedger
	audit           audit.Sink
	now             func() time.Time
}

func New(config Config) (*Authority, error) {
	if config.ClusterInstance == "" || config.PolicyVersion == "" || config.EAAKeyID == "" || len(config.SigningKey) != ed25519.PrivateKeySize || config.Registry == nil || config.Profiles == nil {
		return nil, fmt.Errorf("etcd authority is not configured")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.ProofReplay == nil {
		config.ProofReplay = replay.NewMemoryStore(config.Now)
	}
	if config.Audit == nil {
		config.Audit = audit.NopSink{}
	}
	return &Authority{cluster: config.ClusterInstance, policy: config.PolicyVersion, keyID: config.EAAKeyID, signingKey: append(ed25519.PrivateKey(nil), config.SigningKey...), registry: config.Registry, profiles: config.Profiles, roleMapper: config.RoleMapper, proofs: identity.NewVerifier(nil, config.ProofReplay), grants: NewGrantLedger(), audit: config.Audit, now: config.Now}, nil
}

func (a *Authority) Issue(ctx context.Context, request Request) (GrantResponse, error) {
	if a == nil || a.registry == nil || a.profiles == nil {
		return GrantResponse{}, fmt.Errorf("etcd authority is not configured")
	}
	if request.Identity == "" || len(request.CSR) == 0 || request.ClusterInstance != a.cluster || request.ID == "" || request.MemberOrClientIdentity == "" || request.Profile == "" || request.ExpirationSeconds <= 0 || request.Generation == "" || request.KeyID == "" {
		return GrantResponse{}, ErrRegistrationDenied
	}
	parsed, der, err := csr.Parse(request.CSR)
	if err != nil {
		return GrantResponse{}, err
	}
	endpointSANs, err := etcddomainEndpointSANs(parsed)
	if err != nil {
		return GrantResponse{}, err
	}
	if !equalStrings(endpointSANs, etcdomain.Normalize(request.EndpointSANs)) {
		return GrantResponse{}, ErrRegistrationDenied
	}
	registration, err := a.registry.Find(ctx, request.Profile, request.ID, request.Identity)
	if err != nil {
		return GrantResponse{}, err
	}
	if registration.ClusterInstance != a.cluster || registration.Generation != request.Generation || registration.KeyID != request.KeyID || registration.Profile != request.Profile || time.Duration(request.ExpirationSeconds)*time.Second > registration.MaxTTL || !equalStrings(registration.EndpointSANs, endpointSANs) || !equalStrings(registration.Roles, etcdomain.Normalize(request.Roles)) {
		return GrantResponse{}, ErrRegistrationDenied
	}
	if request.MemberOrClientIdentity != registration.Identity {
		return GrantResponse{}, ErrRegistrationDenied
	}
	roles := etcdomain.Normalize(request.Roles)
	if a.roleMapper != nil {
		mapped, mapErr := a.roleMapper.Map(ctx, request.Identity, roles)
		if mapErr != nil || !equalStrings(mapped, registration.Roles) {
			return GrantResponse{}, ErrRegistrationDenied
		}
	}
	payload, err := etcdomain.Payload(signapi.EtcdCertificateSignRequest{CSR: request.CSR, ClusterInstance: request.ClusterInstance, MemberOrClientID: request.ID, MemberOrClientIdentity: request.MemberOrClientIdentity, EndpointSANs: endpointSANs, Profile: request.Profile, EtcdRoles: roles, ExpirationSeconds: request.ExpirationSeconds, Generation: request.Generation, KeyID: request.KeyID}, parsed, der, endpointSANs)
	if err != nil {
		return GrantResponse{}, err
	}
	if _, err := a.profiles.Validate(payload); err != nil {
		return GrantResponse{}, err
	}
	registeredKey, err := identity.DecodePublicKey(registration.IdentityPublicKey)
	if err != nil {
		return GrantResponse{}, ErrRegistrationDenied
	}
	proofVerifier := identity.NewVerifier(map[string]ed25519.PublicKey{request.Identity: registeredKey}, a.proofs.Replay)
	if err := proofVerifier.VerifyBindingProof(ctx, request.Identity, request.Proof, payload, payload.PublicKeySHA256); err != nil {
		return GrantResponse{}, fmt.Errorf("verify etcd agent proof: %w", err)
	}
	now := a.now().UTC()
	grantID, err := grant.NewID("etcd-grant")
	if err != nil {
		return GrantResponse{}, err
	}
	requestID, err := grant.NewID("etcd-request")
	if err != nil {
		return GrantResponse{}, err
	}
	nonce, err := grant.NewID("etcd-nonce")
	if err != nil {
		return GrantResponse{}, err
	}
	typed, err := canonical.Marshal(payload)
	if err != nil {
		return GrantResponse{}, err
	}
	digest, err := etcdomain.BindingDigest(payload)
	if err != nil {
		return GrantResponse{}, err
	}
	value := grantapi.Grant{Version: grantapi.ContractVersion, Domain: grantapi.DomainEtcd, GrantID: grantID, RequestID: requestID, IdentityRef: request.Identity, BindingDigest: digest, Generation: request.Generation, KeyID: request.KeyID, PolicyVersion: a.policy, NotBefore: now.Unix(), ExpiresAt: now.Add(time.Duration(request.ExpirationSeconds) * time.Second).Unix(), Nonce: nonce, TypedPayload: typed}
	raw, err := grant.Sign(value, a.keyID, a.signingKey)
	if err != nil {
		return GrantResponse{}, err
	}
	if err := a.grants.RecordIssued(ctx, grantID, time.Unix(value.ExpiresAt, 0)); err != nil {
		return GrantResponse{}, err
	}
	if err := audit.Record(ctx, a.audit, audit.Event{Component: "etcd-authority", Domain: string(grantapi.DomainEtcd), Action: "grant", Outcome: "allow", GrantID: grantID, RequestID: requestID, IdentityRef: request.Identity}); err != nil {
		return GrantResponse{}, err
	}
	return GrantResponse{Grant: string(raw), GrantID: grantID, RequestID: requestID, NotBefore: value.NotBefore, ExpiresAt: value.ExpiresAt, Generation: value.Generation, KeyID: value.KeyID}, nil
}

func (a *Authority) Revoke(ctx context.Context, id string) error {
	if a == nil || a.grants == nil {
		return fmt.Errorf("etcd authority is not configured")
	}
	return a.grants.Revoke(ctx, id)
}
func (a *Authority) IsRevoked(ctx context.Context, id string) (bool, error) {
	if a == nil || a.grants == nil {
		return false, fmt.Errorf("etcd authority is not configured")
	}
	return a.grants.IsRevoked(ctx, id)
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
		http.Error(w, "invalid etcd Grant request", http.StatusBadRequest)
		return
	}
	if header := request.Header.Get("X-Issuance-Identity"); header != "" && input.Identity != "" && header != input.Identity {
		http.Error(w, "identity mismatch", http.StatusForbidden)
		return
	}
	result, err := a.Issue(request.Context(), input)
	if err != nil {
		http.Error(w, "etcd Grant denied", http.StatusForbidden)
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
		return fmt.Errorf("invalid etcd Grant ledger record")
	}
	l.mu.Lock()
	l.issued[id] = expiry
	l.mu.Unlock()
	return nil
}
func (l *GrantLedger) Revoke(_ context.Context, id string) error {
	if l == nil || id == "" {
		return fmt.Errorf("invalid etcd Grant ID")
	}
	l.mu.Lock()
	l.revoked[id] = true
	l.mu.Unlock()
	return nil
}
func (l *GrantLedger) IsRevoked(_ context.Context, id string) (bool, error) {
	if l == nil {
		return false, fmt.Errorf("etcd Grant ledger is nil")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.revoked[id], nil
}
func etcddomainEndpointSANs(request *x509.CertificateRequest) ([]string, error) {
	dns, err := csr.NormalizeDNSNames(request.DNSNames)
	if err != nil {
		return nil, err
	}
	result := append([]string(nil), dns...)
	result = append(result, csr.NormalizeIPAddresses(request.IPAddresses)...)
	uris, err := csr.NormalizeURIs(request.URIs)
	if err != nil {
		return nil, err
	}
	result = append(result, uris...)
	return etcdomain.Normalize(result), nil
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
