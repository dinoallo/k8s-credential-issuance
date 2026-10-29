// Package sa implements the ServiceAccount JWT domain plugin.
package sa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	grantapi "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/canonical"
	coregrant "github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/grant"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/pipeline"
)

type Config struct {
	ClusterID        string
	Issuer           string
	PolicyVersion    string
	DefaultKeyID     string
	DefaultAlgorithm string
	MaxTokenLifetime time.Duration
}

type Plugin struct {
	config Config
}

func NewPlugin(config Config) (*Plugin, error) {
	if config.ClusterID == "" || config.Issuer == "" || config.PolicyVersion == "" || config.DefaultKeyID == "" || config.DefaultAlgorithm == "" {
		return nil, fmt.Errorf("SA plugin configuration is incomplete")
	}
	if config.MaxTokenLifetime <= 0 {
		config.MaxTokenLifetime = time.Hour
	}
	return &Plugin{config: config}, nil
}

func (p *Plugin) Domain() grantapi.Domain { return grantapi.DomainSA }

func (p *Plugin) Canonicalize(_ context.Context, request pipeline.Request) (pipeline.Binding, error) {
	if p == nil {
		return pipeline.Binding{}, fmt.Errorf("SA plugin is nil")
	}
	parsed, err := parseSignRequest(request.Body)
	if err != nil {
		return pipeline.Binding{}, err
	}
	binding := parsed.Binding
	rawGrant, err := GrantBytes(parsed.TokenGrant)
	if err != nil {
		return pipeline.Binding{}, err
	}
	legacyGrant := IsLegacyTokenGrant(rawGrant)
	var claims []byte
	if legacyGrant {
		claims, err = CanonicalizeLegacyClaims(parsed.Claims)
	} else {
		claims, err = CanonicalizeClaims(parsed.Claims)
	}
	if err != nil {
		return pipeline.Binding{}, err
	}
	claimsDigest := ClaimsDigest(claims)
	if legacyGrant {
		claimsDigest = LegacyClaimsDigest(claims)
	}
	if parsed.ClaimsDigest == "" || parsed.ClaimsDigest != claimsDigest {
		return pipeline.Binding{}, fmt.Errorf("claims digest does not match canonical claims")
	}
	digestBinding := binding
	if legacyGrant {
		// The staging TokenGrant did not contain a JWT key ID. Preserve its
		// original digest semantics, then attach the configured key ID to the
		// common binding used by the KMS policy.
		digestBinding.KeyID = ""
	} else if binding.KeyID == "" {
		binding.KeyID = p.config.DefaultKeyID
		digestBinding = binding
	}
	if binding.KeyID == "" {
		binding.KeyID = p.config.DefaultKeyID
	}
	if err := p.validateBinding(binding); err != nil {
		return pipeline.Binding{}, err
	}
	if err := validateClaimsBinding(claims, binding); err != nil {
		return pipeline.Binding{}, err
	}
	digest, err := BindingDigest(claimsDigest, digestBinding)
	if err != nil {
		return pipeline.Binding{}, err
	}
	payload, err := GrantPayload(binding, claimsDigest)
	if err != nil {
		return pipeline.Binding{}, err
	}
	domainPayload, err := canonical.Marshal(payload)
	if err != nil {
		return pipeline.Binding{}, fmt.Errorf("canonicalize SA Grant payload: %w", err)
	}
	return pipeline.Binding{Digest: digest, IdentityRef: parsed.IdentityRef, TargetUID: binding.PodUID, Generation: binding.TokenGeneration, KeyID: binding.KeyID, NotBefore: binding.NotBefore, ExpiresAt: binding.NotAfter, RequestedLifetime: binding.NotAfter - binding.NotBefore, SigningPayload: claims, DomainPayload: domainPayload}, nil
}

func (p *Plugin) ValidateBinding(_ context.Context, value grantapi.Grant, binding pipeline.Binding) error {
	if p == nil {
		return fmt.Errorf("SA plugin is nil")
	}
	if value.Domain != grantapi.DomainSA || value.PolicyVersion != p.config.PolicyVersion || value.BindingDigest != binding.Digest || value.Generation != binding.Generation || value.KeyID != binding.KeyID || value.NotBefore != binding.NotBefore || value.ExpiresAt != binding.ExpiresAt {
		return fmt.Errorf("SA Grant binding mismatch")
	}
	if value.ExpiresAt-value.NotBefore != binding.RequestedLifetime || binding.RequestedLifetime <= 0 || time.Duration(binding.RequestedLifetime)*time.Second > p.config.MaxTokenLifetime {
		return fmt.Errorf("SA Grant lifetime does not match the request")
	}
	canonicalPayload, err := canonical.Canonicalize(value.TypedPayload)
	if err != nil || len(binding.DomainPayload) == 0 || !bytes.Equal(canonicalPayload, binding.DomainPayload) {
		return fmt.Errorf("SA Grant typed payload does not match the request")
	}
	var payload grantapi.ServiceAccountPayload
	decoder := json.NewDecoder(bytes.NewReader(value.TypedPayload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return fmt.Errorf("decode SA Grant payload: %w", err)
	}
	if payload.ClaimsDigest == "" || payload.Generation != value.Generation || payload.KeyID != value.KeyID || payload.RequestedLifetimeSecs != binding.RequestedLifetime {
		return fmt.Errorf("SA Grant payload is not bound to the outer Grant")
	}
	return nil
}

func (p *Plugin) Prepare(_ context.Context, value grantapi.Grant, binding pipeline.Binding, operationID string) (kms.SigningIntent, error) {
	if len(binding.SigningPayload) == 0 || ClaimsDigest(binding.SigningPayload) != payloadClaimsDigest(value) {
		return kms.SigningIntent{}, fmt.Errorf("SA Grant claims digest mismatch")
	}
	return kms.NewIntent(grantapi.DomainSA, kms.PurposeServiceAccountJWT, value.KeyID, value.Generation, p.config.DefaultAlgorithm, operationID, binding.SigningPayload)
}

func (p *Plugin) Finalize(_ context.Context, value grantapi.Grant, binding pipeline.Binding, artifact kms.Artifact) ([]byte, error) {
	if len(artifact.Value) == 0 || artifact.PayloadDigest == "" {
		return nil, fmt.Errorf("SA signing result is empty")
	}
	response := signapi.SignResponse{Token: string(artifact.Value), ClaimsDigest: payloadClaimsDigest(value), GrantID: value.GrantID, TokenGeneration: binding.Generation}
	return canonical.Marshal(response)
}

func (p *Plugin) validateBinding(binding signapi.TokenBinding) error {
	if binding.ClusterID != p.config.ClusterID || binding.Issuer != p.config.Issuer || binding.ServiceAccountNamespace == "" || binding.ServiceAccountName == "" || binding.ServiceAccountUID == "" || binding.Subject == "" || binding.TokenGeneration == "" || len(binding.Audience) == 0 || binding.NotBefore <= 0 || binding.NotAfter <= binding.NotBefore {
		return fmt.Errorf("SA token binding is incomplete or violates policy")
	}
	if time.Duration(binding.NotAfter-binding.NotBefore)*time.Second > p.config.MaxTokenLifetime {
		return fmt.Errorf("requested token lifetime exceeds policy")
	}
	if binding.PodUID == "" && binding.ServiceAccountUID == "" {
		return fmt.Errorf("service account UID is required")
	}
	if !sortedUnique(binding.Audience) {
		return fmt.Errorf("audience must be sorted and unique")
	}
	return nil
}

// validateClaimsBinding keeps the signer from becoming a generic JWT signer.
// The claims digest authenticates the bytes authorized by the Grant, but it is
// not itself a policy check: an identity could otherwise obtain a Grant for a
// digest containing a different audience, issuer, or subject. The signer
// therefore allowlists the supported Kubernetes claims shape and compares all
// security-relevant values with the verified binding.
func validateClaimsBinding(claims []byte, binding signapi.TokenBinding) error {
	parsed, err := canonical.Parse(claims)
	if err != nil {
		return fmt.Errorf("parse canonical SA claims: %w", err)
	}
	object, ok := parsed.(map[string]any)
	if !ok {
		return fmt.Errorf("SA claims must be a JSON object")
	}
	allowed := map[string]bool{
		"aud": true, "exp": true, "iat": true, "iss": true, "nbf": true, "sub": true,
		// kubernetes.io is optional for compatibility with the old direct
		// signer carrier, but when present it is still strictly validated.
		"kubernetes.io": true,
	}
	for key := range object {
		if !allowed[key] {
			return fmt.Errorf("SA claims contain unsupported field %q", key)
		}
	}
	for _, key := range []string{"aud", "exp", "iat", "iss", "nbf", "sub"} {
		if _, ok := object[key]; !ok {
			return fmt.Errorf("SA claims are missing required field %q", key)
		}
	}

	audience, ok := object["aud"].([]any)
	if !ok || len(audience) != len(binding.Audience) {
		return fmt.Errorf("SA claims audience does not match the binding")
	}
	for i, value := range audience {
		actual, ok := value.(string)
		if !ok || actual != binding.Audience[i] {
			return fmt.Errorf("SA claims audience does not match the binding")
		}
	}
	if err := requireIntClaim(object, "exp", binding.NotAfter); err != nil {
		return err
	}
	if err := requireIntClaim(object, "iat", binding.NotBefore); err != nil {
		return err
	}
	if err := requireIntClaim(object, "nbf", binding.NotBefore); err != nil {
		return err
	}
	if err := requireStringClaim(object, "iss", binding.Issuer); err != nil {
		return err
	}
	if err := requireStringClaim(object, "sub", binding.Subject); err != nil {
		return err
	}

	privateClaims, exists := object["kubernetes.io"]
	if !exists {
		return nil
	}
	private, ok := privateClaims.(map[string]any)
	if !ok {
		return fmt.Errorf("SA kubernetes.io claims must be an object")
	}
	if err := validateObjectKeys(private, "namespace", "serviceaccount", "pod"); err != nil {
		return fmt.Errorf("invalid SA kubernetes.io claims: %w", err)
	}
	if err := requireStringClaim(private, "namespace", binding.ServiceAccountNamespace); err != nil {
		return err
	}
	serviceAccount, ok := private["serviceaccount"].(map[string]any)
	if !ok {
		return fmt.Errorf("SA serviceaccount claims must be an object")
	}
	if err := validateObjectKeys(serviceAccount, "name", "uid"); err != nil {
		return fmt.Errorf("invalid SA serviceaccount claims: %w", err)
	}
	if err := requireStringClaim(serviceAccount, "name", binding.ServiceAccountName); err != nil {
		return err
	}
	if err := requireStringClaim(serviceAccount, "uid", binding.ServiceAccountUID); err != nil {
		return err
	}

	if podValue, exists := private["pod"]; exists {
		if binding.PodUID == "" {
			return fmt.Errorf("SA pod claims are not allowed for an unbound token")
		}
		pod, ok := podValue.(map[string]any)
		if !ok {
			return fmt.Errorf("SA pod claims must be an object")
		}
		if err := validateObjectKeys(pod, "name", "uid"); err != nil {
			return fmt.Errorf("invalid SA pod claims: %w", err)
		}
		if err := requireStringClaim(pod, "uid", binding.PodUID); err != nil {
			return err
		}
		if value, exists := pod["name"]; exists {
			name, ok := value.(string)
			if !ok || name == "" {
				return fmt.Errorf("SA pod name claim is invalid")
			}
		}
	} else if binding.PodUID != "" {
		return fmt.Errorf("SA claims are missing the bound Pod UID")
	}
	return nil
}

func validateObjectKeys(object map[string]any, allowedKeys ...string) error {
	allowed := make(map[string]bool, len(allowedKeys))
	for _, key := range allowedKeys {
		allowed[key] = true
	}
	for key := range object {
		if !allowed[key] {
			return fmt.Errorf("unsupported field %q", key)
		}
	}
	return nil
}

func requireStringClaim(object map[string]any, key, expected string) error {
	value, ok := object[key].(string)
	if !ok || value != expected {
		return fmt.Errorf("SA claims field %q does not match the binding", key)
	}
	return nil
}

func requireIntClaim(object map[string]any, key string, expected int64) error {
	value, ok := object[key].(json.Number)
	if !ok {
		return fmt.Errorf("SA claims field %q must be an integer", key)
	}
	actual, err := strconv.ParseInt(value.String(), 10, 64)
	if err != nil || actual != expected {
		return fmt.Errorf("SA claims field %q does not match the binding", key)
	}
	return nil
}

func parseSignRequest(data []byte) (signapi.SignRequest, error) {
	if len(data) == 0 || len(data) > 2<<20 {
		return signapi.SignRequest{}, fmt.Errorf("SA sign request is empty or too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request signapi.SignRequest
	if err := decoder.Decode(&request); err != nil {
		return signapi.SignRequest{}, fmt.Errorf("decode SA sign request: %w", err)
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return signapi.SignRequest{}, err
		}
		return signapi.SignRequest{}, fmt.Errorf("trailing SA sign request value %v", token)
	}
	if len(request.Claims) == 0 || len(request.TokenGrant) == 0 {
		return signapi.SignRequest{}, fmt.Errorf("SA sign request is missing claims or Grant")
	}
	return request, nil
}

func CanonicalizeClaims(claims []byte) ([]byte, error) {
	canonicalClaims, err := canonical.Canonicalize(claims)
	if err != nil {
		return nil, fmt.Errorf("canonicalize claims: %w", err)
	}
	value, err := canonical.Parse(canonicalClaims)
	if err != nil {
		return nil, err
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, fmt.Errorf("claims must be a JSON object")
	}
	return canonicalClaims, nil
}

func ClaimsDigest(claims []byte) string {
	digest := sha256.Sum256(claims)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func BindingDigest(claimsDigest string, binding signapi.TokenBinding) (string, error) {
	if !coregrant.ValidDigest(claimsDigest) {
		return "", fmt.Errorf("invalid claims digest")
	}
	audience := append([]string(nil), binding.Audience...)
	sort.Strings(audience)
	raw, err := canonical.Marshal(map[string]any{
		"claims_digest":      claimsDigest,
		"serviceaccount_uid": binding.ServiceAccountUID,
		"pod_uid":            binding.PodUID,
		"audience":           audience,
		"issuer":             binding.Issuer,
		"cluster_id":         binding.ClusterID,
		"requested_lifetime": binding.NotAfter - binding.NotBefore,
		"generation":         binding.TokenGeneration,
		"key_id":             binding.KeyID,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func GrantPayload(binding signapi.TokenBinding, claimsDigest string) (grantapi.ServiceAccountPayload, error) {
	if !sortedUnique(binding.Audience) {
		return grantapi.ServiceAccountPayload{}, fmt.Errorf("audience must be sorted and unique")
	}
	return grantapi.ServiceAccountPayload{ClaimsDigest: claimsDigest, ServiceAccountUID: binding.ServiceAccountUID, PodUID: binding.PodUID, Audience: append([]string(nil), binding.Audience...), Issuer: binding.Issuer, ClusterID: binding.ClusterID, RequestedLifetimeSecs: binding.NotAfter - binding.NotBefore, Generation: binding.TokenGeneration, KeyID: binding.KeyID}, nil
}

func GrantBytes(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("Grant is empty")
	}
	if raw[0] == '"' {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, err
		}
		return []byte(value), nil
	}
	return append([]byte(nil), raw...), nil
}

func payloadClaimsDigest(value grantapi.Grant) string {
	var payload grantapi.ServiceAccountPayload
	if err := json.Unmarshal(value.TypedPayload, &payload); err != nil {
		return ""
	}
	return payload.ClaimsDigest
}

func sortedUnique(values []string) bool {
	for i, value := range values {
		if value == "" || (i > 0 && values[i-1] >= value) {
			return false
		}
	}
	return true
}
