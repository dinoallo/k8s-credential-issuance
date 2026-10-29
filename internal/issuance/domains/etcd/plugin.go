package etcd

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
	ClusterInstance  string
	PolicyVersion    string
	DefaultAlgorithm string
	Profiles         *Registry
}
type Plugin struct{ config Config }

func NewPlugin(config Config) (*Plugin, error) {
	if config.ClusterInstance == "" || config.PolicyVersion == "" || config.DefaultAlgorithm == "" || config.Profiles == nil {
		return nil, fmt.Errorf("etcd plugin configuration is incomplete")
	}
	return &Plugin{config: config}, nil
}
func (p *Plugin) Domain() grantapi.Domain { return grantapi.DomainEtcd }

func (p *Plugin) Canonicalize(_ context.Context, request pipeline.Request) (pipeline.Binding, error) {
	if p == nil || p.config.Profiles == nil {
		return pipeline.Binding{}, fmt.Errorf("etcd plugin is not configured")
	}
	input, err := parseRequest(request.Body)
	if err != nil {
		return pipeline.Binding{}, err
	}
	if len(input.CSR) == 0 || len(request.Grant) == 0 || input.ClusterInstance != p.config.ClusterInstance || input.MemberOrClientID == "" || input.MemberOrClientIdentity == "" || input.Profile == "" || input.ExpirationSeconds <= 0 || input.NotBefore <= 0 || input.NotAfter <= input.NotBefore || input.NotAfter-input.NotBefore != input.ExpirationSeconds || input.Generation == "" || input.KeyID == "" {
		return pipeline.Binding{}, fmt.Errorf("etcd sign request is incomplete or has a non-exact lifetime")
	}
	parsed, der, err := csr.Parse(input.CSR)
	if err != nil {
		return pipeline.Binding{}, err
	}
	if err := csr.ValidateSubject(parsed); err != nil {
		return pipeline.Binding{}, err
	}
	profile, ok := p.config.Profiles.Get(input.Profile)
	if !ok {
		return pipeline.Binding{}, fmt.Errorf("unknown etcd profile %q", input.Profile)
	}
	if profile.Generation != input.Generation || profile.KeyID != input.KeyID {
		return pipeline.Binding{}, fmt.Errorf("etcd profile generation or key ID mismatch")
	}
	endpointSANs, err := endpointSANs(parsed)
	if err != nil {
		return pipeline.Binding{}, err
	}
	if !equalStrings(endpointSANs, Normalize(input.EndpointSANs)) {
		return pipeline.Binding{}, fmt.Errorf("etcd endpoint SANs do not match the CSR")
	}
	publicKeyDigest, err := csr.PublicKeyDigest(parsed.PublicKey)
	if err != nil {
		return pipeline.Binding{}, err
	}
	roles := Normalize(input.EtcdRoles)
	if !equalStrings(roles, input.EtcdRoles) {
		return pipeline.Binding{}, fmt.Errorf("etcd roles must be sorted and unique")
	}
	payload := grantapi.EtcdCertificatePayload{ClusterInstance: input.ClusterInstance, MemberOrClientID: input.MemberOrClientID, MemberOrClientIdentity: input.MemberOrClientIdentity, EndpointSANs: endpointSANs, Profile: input.Profile, EtcdRoles: roles, PublicKeySHA256: publicKeyDigest, RequestedLifetimeSecs: input.ExpirationSeconds, Generation: input.Generation, KeyID: input.KeyID}
	if _, err := p.config.Profiles.Validate(payload); err != nil {
		return pipeline.Binding{}, err
	}
	intentPayload, err := canonical.Marshal(kms.CertificateIntent{CSRDER: der, Profile: input.Profile, Subject: csr.NormalizeSubject(csr.Subject(parsed)), DNSNames: dnsNames(parsed), IPAddresses: csr.NormalizeIPAddresses(parsed.IPAddresses), URIs: uriNames(parsed), KeyUsages: profile.RequiredKeyUsages, ExtendedKeyUsages: profile.RequiredExtendedUsages, NotBefore: input.NotBefore, NotAfter: input.NotAfter})
	if err != nil {
		return pipeline.Binding{}, err
	}
	digest, err := BindingDigest(payload)
	if err != nil {
		return pipeline.Binding{}, err
	}
	target := request.TargetUID
	if target == "" {
		target = input.MemberOrClientID
	}
	return pipeline.Binding{Digest: digest, IdentityRef: input.IdentityRef, TargetUID: target, Generation: input.Generation, KeyID: input.KeyID, NotBefore: input.NotBefore, ExpiresAt: input.NotAfter, RequestedLifetime: input.ExpirationSeconds, SigningPayload: intentPayload, DomainPayload: mustCanonical(payload)}, nil
}

func (p *Plugin) ValidateBinding(_ context.Context, value grantapi.Grant, binding pipeline.Binding) error {
	if p == nil || value.Domain != grantapi.DomainEtcd || value.PolicyVersion != p.config.PolicyVersion {
		return fmt.Errorf("etcd Grant policy or domain mismatch")
	}
	if value.BindingDigest != binding.Digest || value.Generation != binding.Generation || value.KeyID != binding.KeyID || value.NotBefore != binding.NotBefore || value.ExpiresAt != binding.ExpiresAt || value.ExpiresAt-value.NotBefore != binding.RequestedLifetime {
		return fmt.Errorf("etcd Grant binding mismatch")
	}
	canonicalPayload, err := canonical.Canonicalize(value.TypedPayload)
	if err != nil || !bytes.Equal(canonicalPayload, binding.DomainPayload) {
		return fmt.Errorf("etcd Grant payload does not match the request")
	}
	var payload grantapi.EtcdCertificatePayload
	if err := strictUnmarshal(value.TypedPayload, &payload); err != nil {
		return err
	}
	if payload.Generation != value.Generation || payload.KeyID != value.KeyID || payload.ClusterInstance != p.config.ClusterInstance || payload.PublicKeySHA256 == "" {
		return fmt.Errorf("etcd Grant payload is not bound to the outer Grant")
	}
	if _, err := p.config.Profiles.Validate(payload); err != nil {
		return err
	}
	return nil
}

func (p *Plugin) Prepare(_ context.Context, value grantapi.Grant, binding pipeline.Binding, operationID string) (kms.SigningIntent, error) {
	var payload grantapi.EtcdCertificatePayload
	if err := strictUnmarshal(value.TypedPayload, &payload); err != nil {
		return kms.SigningIntent{}, err
	}
	profile, ok := p.config.Profiles.Get(payload.Profile)
	if !ok {
		return kms.SigningIntent{}, fmt.Errorf("unknown etcd profile %q", payload.Profile)
	}
	return kms.NewIntent(grantapi.DomainEtcd, profile.Purpose, value.KeyID, value.Generation, p.config.DefaultAlgorithm, operationID, binding.SigningPayload)
}

func (p *Plugin) Finalize(_ context.Context, value grantapi.Grant, binding pipeline.Binding, artifact kms.Artifact) ([]byte, error) {
	var payload grantapi.EtcdCertificatePayload
	if err := strictUnmarshal(value.TypedPayload, &payload); err != nil {
		return nil, err
	}
	if len(artifact.Value) == 0 || artifact.KeyID != value.KeyID || artifact.Generation != binding.Generation {
		return nil, fmt.Errorf("etcd signing result is incomplete")
	}
	return canonical.Marshal(signapi.EtcdCertificateSignResponse{Certificate: artifact.Value, GrantID: value.GrantID, RequestID: value.RequestID, ClusterInstance: payload.ClusterInstance, MemberOrClientID: payload.MemberOrClientID, Profile: payload.Profile, Generation: binding.Generation, KeyID: binding.KeyID})
}

func Payload(input signapi.EtcdCertificateSignRequest, parsed *x509.CertificateRequest, der []byte, endpointSANs []string) (grantapi.EtcdCertificatePayload, error) {
	if parsed == nil || len(der) == 0 {
		return grantapi.EtcdCertificatePayload{}, fmt.Errorf("CSR is required")
	}
	publicKeyDigest, err := csr.PublicKeyDigest(parsed.PublicKey)
	if err != nil {
		return grantapi.EtcdCertificatePayload{}, err
	}
	return grantapi.EtcdCertificatePayload{ClusterInstance: input.ClusterInstance, MemberOrClientID: input.MemberOrClientID, MemberOrClientIdentity: input.MemberOrClientIdentity, EndpointSANs: Normalize(endpointSANs), Profile: input.Profile, EtcdRoles: Normalize(input.EtcdRoles), PublicKeySHA256: publicKeyDigest, RequestedLifetimeSecs: input.ExpirationSeconds, Generation: input.Generation, KeyID: input.KeyID}, nil
}
func BindingDigest(payload grantapi.EtcdCertificatePayload) (string, error) {
	raw, err := canonical.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
func GrantBytes(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("etcd Grant is empty")
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
func parseRequest(data []byte) (signapi.EtcdCertificateSignRequest, error) {
	if len(data) == 0 || len(data) > 2<<20 {
		return signapi.EtcdCertificateSignRequest{}, fmt.Errorf("etcd sign request is empty or too large")
	}
	var request signapi.EtcdCertificateSignRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return signapi.EtcdCertificateSignRequest{}, err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return signapi.EtcdCertificateSignRequest{}, err
		}
		return signapi.EtcdCertificateSignRequest{}, fmt.Errorf("trailing etcd sign request value %v", token)
	}
	return request, nil
}
func strictUnmarshal(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}
func mustCanonical(value any) []byte { result, _ := canonical.Marshal(value); return result }
func endpointSANs(parsed *x509.CertificateRequest) ([]string, error) {
	dns, err := csr.NormalizeDNSNames(parsed.DNSNames)
	if err != nil {
		return nil, err
	}
	result := append([]string(nil), dns...)
	result = append(result, csr.NormalizeIPAddresses(parsed.IPAddresses)...)
	uri, err := csr.NormalizeURIs(parsed.URIs)
	if err != nil {
		return nil, err
	}
	result = append(result, uri...)
	return Normalize(result), nil
}
func dnsNames(parsed *x509.CertificateRequest) []string {
	result, _ := csr.NormalizeDNSNames(parsed.DNSNames)
	return result
}
func uriNames(parsed *x509.CertificateRequest) []string {
	result, _ := csr.NormalizeURIs(parsed.URIs)
	return result
}
