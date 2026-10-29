// Package ca implements the constrained Kubernetes X.509 issuance domain.
package ca

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	grantapi "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/canonical"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/pipeline"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/ca/csr"
)

type Config struct {
	PolicyVersion    string
	DefaultAlgorithm string
	Profiles         *Registry
}

type Plugin struct{ config Config }

func NewPlugin(config Config) (*Plugin, error) {
	if config.PolicyVersion == "" || config.DefaultAlgorithm == "" || config.Profiles == nil {
		return nil, fmt.Errorf("CA plugin configuration is incomplete")
	}
	return &Plugin{config: config}, nil
}

func (p *Plugin) Domain() grantapi.Domain { return grantapi.DomainCA }

func (p *Plugin) Canonicalize(_ context.Context, request pipeline.Request) (pipeline.Binding, error) {
	if p == nil || p.config.Profiles == nil {
		return pipeline.Binding{}, fmt.Errorf("CA plugin is not configured")
	}
	input, err := parseRequest(request.Body)
	if err != nil {
		return pipeline.Binding{}, err
	}
	if len(input.CSR) == 0 || len(request.Grant) == 0 || input.Profile == "" || input.SignerName == "" || input.ExpirationSeconds <= 0 || input.NotBefore <= 0 || input.NotAfter <= input.NotBefore || input.NotAfter-input.NotBefore != input.ExpirationSeconds {
		return pipeline.Binding{}, fmt.Errorf("CA sign request is incomplete or has a non-exact lifetime")
	}
	parsed, der, err := csr.Parse(input.CSR)
	if err != nil {
		return pipeline.Binding{}, err
	}
	if err := csr.ValidateSubject(parsed); err != nil {
		return pipeline.Binding{}, err
	}
	publicKeyDigest, err := csr.PublicKeyDigest(parsed.PublicKey)
	if err != nil {
		return pipeline.Binding{}, err
	}
	dnsNames, err := csr.NormalizeDNSNames(parsed.DNSNames)
	if err != nil {
		return pipeline.Binding{}, err
	}
	uriNames, err := csr.NormalizeURIs(parsed.URIs)
	if err != nil {
		return pipeline.Binding{}, err
	}
	extUsages, err := csr.ExtendedKeyUsages(parsed)
	if err != nil {
		return pipeline.Binding{}, err
	}
	if !equalStrings(extUsages, input.ExtendedKeyUsages) {
		return pipeline.Binding{}, fmt.Errorf("CA request EKUs do not match the CSR")
	}
	keyUsages := NormalizeUsages(input.KeyUsages)
	if len(keyUsages) == 0 || !equalStrings(keyUsages, input.KeyUsages) {
		return pipeline.Binding{}, fmt.Errorf("CA key usages must be sorted and unique")
	}
	if _, err := p.config.Profiles.Validate(grantapi.CertificatePayload{SignerName: input.SignerName, Profile: input.Profile, Subject: csr.Subject(parsed), KeyUsages: keyUsages, ExtendedKeyUsages: extUsages, RequestedLifetimeSecs: input.ExpirationSeconds}); err != nil {
		return pipeline.Binding{}, err
	}
	subject := csr.NormalizeSubject(csr.Subject(parsed))
	payload := grantapi.CertificatePayload{CSRRequestDigest: csr.RequestDigest(input.CSR), PublicKeySHA256: publicKeyDigest, SignerName: input.SignerName, Profile: input.Profile, Subject: subject, DNSNames: dnsNames, IPAddresses: csr.NormalizeIPAddresses(parsed.IPAddresses), URIs: uriNames, KeyUsages: keyUsages, ExtendedKeyUsages: extUsages, RequestedLifetimeSecs: input.ExpirationSeconds, Generation: "", KeyID: ""}
	// Generation and key ID are part of the Grant binding but are carried by
	// the request as well. They are populated by the authority response before
	// the direct sign call and are checked below.
	if input.Generation == "" || input.KeyID == "" {
		return pipeline.Binding{}, fmt.Errorf("CA sign request is missing generation or key ID")
	}
	payload.Generation, payload.KeyID = input.Generation, input.KeyID
	digest, err := BindingDigest(payload)
	if err != nil {
		return pipeline.Binding{}, err
	}
	intentPayload, err := canonical.Marshal(kms.CertificateIntent{CSRDER: der, Profile: input.Profile, SignerName: input.SignerName, Subject: subject, DNSNames: dnsNames, IPAddresses: payload.IPAddresses, URIs: uriNames, KeyUsages: keyUsages, ExtendedKeyUsages: extUsages, NotBefore: input.NotBefore, NotAfter: input.NotAfter})
	if err != nil {
		return pipeline.Binding{}, err
	}
	target := request.TargetUID
	if target == "" {
		target = payload.CSRRequestDigest
	}
	return pipeline.Binding{Digest: digest, IdentityRef: input.IdentityRef, TargetUID: target, Generation: input.Generation, KeyID: input.KeyID, NotBefore: input.NotBefore, ExpiresAt: input.NotAfter, RequestedLifetime: input.ExpirationSeconds, SigningPayload: intentPayload, DomainPayload: mustCanonical(payload)}, nil
}

func (p *Plugin) ValidateBinding(_ context.Context, value grantapi.Grant, binding pipeline.Binding) error {
	if p == nil || value.Domain != grantapi.DomainCA || value.PolicyVersion != p.config.PolicyVersion {
		return fmt.Errorf("CA Grant policy or domain mismatch")
	}
	if value.BindingDigest != binding.Digest || value.Generation != binding.Generation || value.KeyID != binding.KeyID || value.NotBefore != binding.NotBefore || value.ExpiresAt != binding.ExpiresAt || value.ExpiresAt-value.NotBefore != binding.RequestedLifetime {
		return fmt.Errorf("CA Grant binding mismatch")
	}
	canonicalPayload, err := canonical.Canonicalize(value.TypedPayload)
	if err != nil || !bytes.Equal(canonicalPayload, binding.DomainPayload) {
		return fmt.Errorf("CA Grant payload does not match the request")
	}
	var payload grantapi.CertificatePayload
	if err := strictUnmarshal(value.TypedPayload, &payload); err != nil {
		return fmt.Errorf("decode CA Grant payload: %w", err)
	}
	if payload.Generation != value.Generation || payload.KeyID != value.KeyID || payload.RequestedLifetimeSecs != binding.RequestedLifetime || payload.CSRRequestDigest == "" || payload.PublicKeySHA256 == "" {
		return fmt.Errorf("CA Grant payload is not bound to the outer Grant")
	}
	if _, err := p.config.Profiles.Validate(payload); err != nil {
		return err
	}
	return nil
}

func (p *Plugin) Prepare(_ context.Context, value grantapi.Grant, binding pipeline.Binding, operationID string) (kms.SigningIntent, error) {
	if len(binding.SigningPayload) == 0 {
		return kms.SigningIntent{}, fmt.Errorf("CA certificate intent is empty")
	}
	return kms.NewIntent(grantapi.DomainCA, kms.PurposeCACertificate, value.KeyID, value.Generation, p.config.DefaultAlgorithm, operationID, binding.SigningPayload)
}

func (p *Plugin) Finalize(_ context.Context, value grantapi.Grant, binding pipeline.Binding, artifact kms.Artifact) ([]byte, error) {
	if len(artifact.Value) == 0 || artifact.KeyID != value.KeyID || artifact.Generation != binding.Generation {
		return nil, fmt.Errorf("CA signing result is incomplete")
	}
	var payload grantapi.CertificatePayload
	if err := strictUnmarshal(value.TypedPayload, &payload); err != nil {
		return nil, err
	}
	return canonical.Marshal(signapi.CertificateSignResponse{Certificate: artifact.Value, GrantID: value.GrantID, RequestID: value.RequestID, Profile: payload.Profile, Generation: binding.Generation, KeyID: binding.KeyID})
}

func Payload(input signapi.CertificateSignRequest, parsed *x509.CertificateRequest, der []byte) (grantapi.CertificatePayload, error) {
	if parsed == nil || len(der) == 0 {
		return grantapi.CertificatePayload{}, fmt.Errorf("CSR is required")
	}
	publicKeyDigest, err := csr.PublicKeyDigest(parsed.PublicKey)
	if err != nil {
		return grantapi.CertificatePayload{}, err
	}
	dnsNames, err := csr.NormalizeDNSNames(parsed.DNSNames)
	if err != nil {
		return grantapi.CertificatePayload{}, err
	}
	uriNames, err := csr.NormalizeURIs(parsed.URIs)
	if err != nil {
		return grantapi.CertificatePayload{}, err
	}
	extUsages, err := csr.ExtendedKeyUsages(parsed)
	if err != nil {
		return grantapi.CertificatePayload{}, err
	}
	return grantapi.CertificatePayload{CSRRequestDigest: csr.RequestDigest(input.CSR), PublicKeySHA256: publicKeyDigest, SignerName: input.SignerName, Profile: input.Profile, Subject: csr.NormalizeSubject(csr.Subject(parsed)), DNSNames: dnsNames, IPAddresses: csr.NormalizeIPAddresses(parsed.IPAddresses), URIs: uriNames, KeyUsages: NormalizeUsages(input.KeyUsages), ExtendedKeyUsages: extUsages, RequestedLifetimeSecs: input.ExpirationSeconds, Generation: input.Generation, KeyID: input.KeyID}, nil
}

func BindingDigest(payload grantapi.CertificatePayload) (string, error) {
	raw, err := canonical.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func parseRequest(data []byte) (signapi.CertificateSignRequest, error) {
	if len(data) == 0 || len(data) > 2<<20 {
		return signapi.CertificateSignRequest{}, fmt.Errorf("CA sign request is empty or too large")
	}
	var request signapi.CertificateSignRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return signapi.CertificateSignRequest{}, fmt.Errorf("decode CA sign request: %w", err)
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return signapi.CertificateSignRequest{}, err
		}
		return signapi.CertificateSignRequest{}, fmt.Errorf("trailing CA sign request value %v", token)
	}
	return request, nil
}

func GrantBytes(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("CA Grant is empty")
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

func mustCanonical(value any) []byte {
	data, _ := canonical.Marshal(value)
	return data
}

func strictUnmarshal(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
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
