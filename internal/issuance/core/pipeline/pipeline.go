// Package pipeline owns the order of the security-sensitive issuance steps.
package pipeline

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	v1 "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/audit"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/grant"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/ledger"
)

var (
	ErrNotConfigured = errors.New("issuance pipeline is not configured")
	ErrDomainDenied  = errors.New("request domain is not served by this signer")
	ErrBindingDenied = errors.New("request does not match the signed Grant")
)

type Request struct {
	Domain      v1.Domain
	RequestID   string
	IdentityRef string
	TargetUID   string
	Grant       []byte
	Body        []byte
}

// GrantVerifier permits a domain adapter to accept an explicitly supported
// compatibility envelope while returning the common, typed Grant consumed by
// the rest of the pipeline. The default accepts only the issuance/v1 Compact
// JWS.
type GrantVerifier func([]byte, map[string]ed25519.PublicKey) (v1.Grant, grant.Header, error)

type Binding struct {
	Digest            string
	IdentityRef       string
	TargetUID         string
	Generation        string
	KeyID             string
	NotBefore         int64
	ExpiresAt         int64
	RequestedLifetime int64
	// SigningPayload is produced by the domain plugin after canonicalization.
	// The core carries it opaquely and the KMS broker still enforces its digest
	// and domain/purpose allowlist before any signing operation.
	SigningPayload []byte
	// DomainPayload is the canonical typed payload expected in the signed Grant.
	// Domain plugins use it to compare the request-derived policy payload with
	// the authority-signed payload instead of trusting only the outer digest.
	DomainPayload []byte
}

type SignedResult struct {
	Artifact kms.Artifact
	Response []byte
}

type Plugin interface {
	Domain() v1.Domain
	Canonicalize(context.Context, Request) (Binding, error)
	ValidateBinding(context.Context, v1.Grant, Binding) error
	Prepare(context.Context, v1.Grant, Binding, string) (kms.SigningIntent, error)
	Finalize(context.Context, v1.Grant, Binding, kms.Artifact) ([]byte, error)
}

type RevocationChecker interface {
	IsRevoked(context.Context, string) (bool, error)
}

type Config struct {
	Domain           v1.Domain
	GrantKeys        map[string]ed25519.PublicKey
	GrantVerifier    GrantVerifier
	AllowLegacyRelay bool
	Plugin           Plugin
	Ledger           ledger.Store
	KMS              *kms.Provider
	Revocations      RevocationChecker
	Audit            audit.Sink
	Now              func() time.Time
}

type Engine struct {
	domain           v1.Domain
	grantKeys        map[string]ed25519.PublicKey
	grantVerifier    GrantVerifier
	allowLegacyRelay bool
	plugin           Plugin
	ledger           ledger.Store
	kms              *kms.Provider
	revocations      RevocationChecker
	audit            audit.Sink
	now              func() time.Time
}

func New(config Config) (*Engine, error) {
	if !config.Domain.Valid() || config.Plugin == nil || config.Plugin.Domain() != config.Domain || config.Ledger == nil || config.KMS == nil {
		return nil, ErrNotConfigured
	}
	if len(config.GrantKeys) == 0 {
		return nil, fmt.Errorf("at least one Grant verification key is required")
	}
	keys := make(map[string]ed25519.PublicKey, len(config.GrantKeys))
	for keyID, key := range config.GrantKeys {
		if keyID == "" || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Grant verification key %q", keyID)
		}
		keys[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	if config.Audit == nil {
		return nil, fmt.Errorf("audit sink is required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	verifier := config.GrantVerifier
	if verifier == nil {
		verifier = grant.Verify
	}
	return &Engine{domain: config.Domain, grantKeys: keys, grantVerifier: verifier, allowLegacyRelay: config.AllowLegacyRelay, plugin: config.Plugin, ledger: config.Ledger, kms: config.KMS, revocations: config.Revocations, audit: config.Audit, now: config.Now}, nil
}

func (e *Engine) Issue(ctx context.Context, request Request) ([]byte, error) {
	if e == nil || e.plugin == nil || e.ledger == nil || e.kms == nil {
		return nil, ErrNotConfigured
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if request.Domain != e.domain {
		return nil, ErrDomainDenied
	}
	if len(request.Grant) == 0 || len(request.Body) == 0 {
		return nil, fmt.Errorf("request is incomplete")
	}
	binding, err := e.plugin.Canonicalize(ctx, request)
	if err != nil {
		return nil, e.reject(ctx, request, err)
	}
	value, header, err := e.grantVerifier(request.Grant, e.grantKeys)
	if err != nil {
		return nil, e.reject(ctx, request, err)
	}
	legacyRelay := header.Format == grant.LegacyFormat
	if value.Domain != e.domain || header.KeyID == "" || (request.IdentityRef == "" && (!e.allowLegacyRelay || !legacyRelay)) || (request.IdentityRef != "" && !legacyRelay && value.IdentityRef != request.IdentityRef) || (binding.IdentityRef != "" && !legacyRelay && binding.IdentityRef != value.IdentityRef) {
		return nil, e.reject(ctx, request, fmt.Errorf("%w: domain or identity mismatch", ErrBindingDenied))
	}
	if e.revocations != nil {
		revoked, err := e.revocations.IsRevoked(ctx, value.GrantID)
		if err != nil {
			return nil, e.reject(ctx, request, fmt.Errorf("check Grant revocation: %w", err))
		}
		if revoked {
			return nil, e.reject(ctx, request, fmt.Errorf("Grant %q is revoked", value.GrantID))
		}
	}
	if request.RequestID != "" && request.RequestID != value.RequestID {
		return nil, e.reject(ctx, request, fmt.Errorf("%w: request ID mismatch", ErrBindingDenied))
	}
	now := e.now()
	if now.Unix() < value.NotBefore || now.Unix() > value.ExpiresAt {
		return nil, e.reject(ctx, request, fmt.Errorf("Grant is outside its validity window"))
	}
	if value.BindingDigest != binding.Digest || value.Generation != binding.Generation || value.KeyID != binding.KeyID || value.NotBefore != binding.NotBefore || value.ExpiresAt != binding.ExpiresAt || value.ExpiresAt-value.NotBefore != binding.RequestedLifetime {
		return nil, e.reject(ctx, request, fmt.Errorf("%w: Grant binding digest or key binding mismatch", ErrBindingDenied))
	}
	if err := e.plugin.ValidateBinding(ctx, value, binding); err != nil {
		return nil, e.reject(ctx, request, err)
	}
	operationID := value.GrantID
	reservation, err := e.ledger.Reserve(ctx, ledger.ReservationKey{GrantID: value.GrantID, Domain: value.Domain, RequestID: value.RequestID, RequestDigest: binding.Digest, IdentityRef: value.IdentityRef, TargetUID: binding.TargetUID, OperationID: operationID})
	if err != nil {
		return nil, e.reject(ctx, request, err)
	}
	if reservation.State == ledger.Completed {
		if err := audit.Record(ctx, e.audit, audit.Event{Component: "issuance-core", Domain: string(e.domain), Action: "recover", Outcome: "allow", GrantID: value.GrantID, RequestID: value.RequestID, OperationID: operationID, IdentityRef: value.IdentityRef}); err != nil {
			return nil, fmt.Errorf("record recovery audit: %w", err)
		}
		return append([]byte(nil), reservation.Result.Response...), nil
	}
	if reservation.State == ledger.Revoked || reservation.State == ledger.PermanentFailure {
		return nil, e.reject(ctx, request, fmt.Errorf("Grant cannot be issued in ledger state %s", reservation.State))
	}
	if !reservation.Owned {
		return nil, e.reject(ctx, request, ledger.ErrInProgress)
	}
	if err := audit.Record(ctx, e.audit, audit.Event{Component: "issuance-core", Domain: string(e.domain), Action: "reserve", Outcome: "allow", GrantID: value.GrantID, RequestID: value.RequestID, OperationID: operationID, IdentityRef: value.IdentityRef}); err != nil {
		_ = e.ledger.Fail(ctx, operationID, ledger.RetryableFailure, err)
		return nil, fmt.Errorf("record reservation audit: %w", err)
	}
	if err := e.ledger.MarkSigning(ctx, operationID); err != nil {
		return nil, e.reject(ctx, request, err)
	}
	intent, err := e.plugin.Prepare(ctx, value, binding, operationID)
	if err != nil {
		_ = e.ledger.Fail(ctx, operationID, ledger.PermanentFailure, err)
		return nil, e.reject(ctx, request, err)
	}
	if err := validateIntent(intent, value, binding, operationID); err != nil {
		_ = e.ledger.Fail(ctx, operationID, ledger.PermanentFailure, err)
		return nil, e.reject(ctx, request, err)
	}
	artifact, err := e.kms.Sign(ctx, intent)
	if err != nil {
		_ = e.ledger.Fail(ctx, operationID, ledger.RetryableFailure, err)
		_ = audit.Record(ctx, e.audit, audit.Event{Component: "issuance-core", Domain: string(e.domain), Action: "sign", Outcome: "error", GrantID: value.GrantID, OperationID: operationID, Reason: err.Error()})
		return nil, fmt.Errorf("KMS signing failed: %w", err)
	}
	response, err := e.plugin.Finalize(ctx, value, binding, artifact)
	if err != nil {
		_ = e.ledger.Fail(ctx, operationID, ledger.PermanentFailure, err)
		return nil, e.reject(ctx, request, err)
	}
	result := ledger.Result{Artifact: artifact.Value, Response: response, KeyID: artifact.KeyID, Generation: artifact.Generation, Algorithm: artifact.Algorithm}
	if err := e.ledger.Complete(ctx, operationID, result); err != nil {
		return nil, fmt.Errorf("persist signed result: %w", err)
	}
	if err := audit.Record(ctx, e.audit, audit.Event{Component: "issuance-core", Domain: string(e.domain), Action: "complete", Outcome: "allow", GrantID: value.GrantID, RequestID: value.RequestID, OperationID: operationID, IdentityRef: value.IdentityRef}); err != nil {
		return nil, fmt.Errorf("record completion audit: %w", err)
	}
	return append([]byte(nil), response...), nil
}

func validateIntent(intent kms.SigningIntent, value v1.Grant, binding Binding, operationID string) error {
	if err := intent.Validate(); err != nil {
		return err
	}
	if intent.Domain != value.Domain || intent.KeyID != value.KeyID || intent.Generation != value.Generation || intent.OperationID != operationID || intent.PayloadDigest == "" {
		return fmt.Errorf("KMS SigningIntent is not bound to Grant")
	}
	if binding.KeyID != intent.KeyID || binding.Generation != intent.Generation || string(binding.SigningPayload) != string(intent.Payload) {
		return fmt.Errorf("KMS SigningIntent key binding mismatch")
	}
	return nil
}

func (e *Engine) reject(ctx context.Context, request Request, err error) error {
	if err == nil {
		err = errors.New("issuance request denied")
	}
	_ = audit.Record(ctx, e.audit, audit.Event{Component: "issuance-core", Domain: string(request.Domain), Action: "issue", Outcome: "deny", IdentityRef: request.IdentityRef, Reason: err.Error()})
	return err
}
