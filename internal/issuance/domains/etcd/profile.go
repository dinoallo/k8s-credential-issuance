// Package etcd implements peer/client certificate issuance for etcd.
package etcd

import (
	"fmt"
	"sort"
	"strings"
	"time"

	grantapi "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms"
)

const (
	ProfilePeer           = "etcd-peer"
	ProfileClient         = "etcd-client"
	RoleRead              = "read"
	RoleWrite             = "write"
	RoleRoot              = "root"
	UsageDigitalSignature = "digitalSignature"
	UsageKeyEncipherment  = "keyEncipherment"
)

type Profile struct {
	Name                   string
	MaxTTL                 time.Duration
	Generation             string
	KeyID                  string
	Purpose                string
	RequiredKeyUsages      []string
	AllowedKeyUsages       []string
	RequiredExtendedUsages []string
	AllowedExtendedUsages  []string
	AllowedRoles           []string
}

type Registry struct{ profiles map[string]Profile }

func NewRegistry(profiles []Profile) (*Registry, error) {
	result := &Registry{profiles: make(map[string]Profile, len(profiles))}
	for _, profile := range profiles {
		if profile.Name == "" || profile.MaxTTL <= 0 || profile.Generation == "" || profile.KeyID == "" || profile.Purpose == "" {
			return nil, fmt.Errorf("etcd profile is incomplete")
		}
		if profile.Name != ProfilePeer && profile.Name != ProfileClient {
			return nil, fmt.Errorf("unsupported etcd profile %q", profile.Name)
		}
		if (profile.Name == ProfilePeer && profile.Purpose != kms.PurposeEtcdPeerCertificate) || (profile.Name == ProfileClient && profile.Purpose != kms.PurposeEtcdClientCertificate) {
			return nil, fmt.Errorf("etcd profile %q has an invalid KMS purpose", profile.Name)
		}
		if _, exists := result.profiles[profile.Name]; exists {
			return nil, fmt.Errorf("duplicate etcd profile %q", profile.Name)
		}
		profile.RequiredKeyUsages = normalized(profile.RequiredKeyUsages)
		profile.AllowedKeyUsages = normalized(profile.AllowedKeyUsages)
		profile.RequiredExtendedUsages = normalized(profile.RequiredExtendedUsages)
		profile.AllowedExtendedUsages = normalized(profile.AllowedExtendedUsages)
		profile.AllowedRoles = normalized(profile.AllowedRoles)
		result.profiles[profile.Name] = profile
	}
	if len(result.profiles) == 0 {
		return nil, fmt.Errorf("no etcd profiles configured")
	}
	return result, nil
}

func DefaultRegistry(maxTTL time.Duration, peerGeneration, peerKeyID, clientGeneration, clientKeyID string) (*Registry, error) {
	return NewRegistry([]Profile{
		{Name: ProfilePeer, MaxTTL: maxTTL, Generation: peerGeneration, KeyID: peerKeyID, Purpose: kms.PurposeEtcdPeerCertificate, RequiredKeyUsages: []string{UsageDigitalSignature}, AllowedKeyUsages: []string{UsageDigitalSignature, UsageKeyEncipherment}, RequiredExtendedUsages: []string{"clientAuth", "serverAuth"}, AllowedExtendedUsages: []string{"clientAuth", "serverAuth"}},
		{Name: ProfileClient, MaxTTL: maxTTL, Generation: clientGeneration, KeyID: clientKeyID, Purpose: kms.PurposeEtcdClientCertificate, RequiredKeyUsages: []string{UsageDigitalSignature}, AllowedKeyUsages: []string{UsageDigitalSignature, UsageKeyEncipherment}, RequiredExtendedUsages: []string{"clientAuth"}, AllowedExtendedUsages: []string{"clientAuth"}, AllowedRoles: []string{RoleRead, RoleWrite, RoleRoot}},
	})
}

func (r *Registry) Get(name string) (Profile, bool) {
	if r == nil {
		return Profile{}, false
	}
	value, ok := r.profiles[name]
	return value, ok
}

func (r *Registry) Validate(payload grantapi.EtcdCertificatePayload) (Profile, error) {
	if r == nil {
		return Profile{}, fmt.Errorf("etcd profile registry is nil")
	}
	profile, ok := r.profiles[payload.Profile]
	if !ok {
		return Profile{}, fmt.Errorf("unknown etcd profile %q", payload.Profile)
	}
	if len(payload.EndpointSANs) == 0 {
		return Profile{}, fmt.Errorf("etcd certificate requires at least one endpoint SAN")
	}
	if payload.RequestedLifetimeSecs <= 0 || time.Duration(payload.RequestedLifetimeSecs)*time.Second > profile.MaxTTL {
		return Profile{}, fmt.Errorf("etcd certificate lifetime exceeds profile policy")
	}
	if payload.Generation != profile.Generation || payload.KeyID != profile.KeyID {
		return Profile{}, fmt.Errorf("etcd profile generation or key ID mismatch")
	}
	if err := validateSet("key usage", payloadKeyUsages(profile), profile.RequiredKeyUsages, profile.AllowedKeyUsages); err != nil {
		return Profile{}, err
	}
	if err := validateSet("extended key usage", profile.RequiredExtendedUsages, profile.RequiredExtendedUsages, profile.AllowedExtendedUsages); err != nil {
		return Profile{}, err
	}
	if profile.Name == ProfilePeer && len(payload.EtcdRoles) != 0 {
		return Profile{}, fmt.Errorf("peer certificate cannot carry etcd client roles")
	}
	if profile.Name == ProfileClient {
		for _, role := range payload.EtcdRoles {
			if len(profile.AllowedRoles) > 0 && !contains(profile.AllowedRoles, role) {
				return Profile{}, fmt.Errorf("etcd role %q is not allowed", role)
			}
		}
	}
	return profile, nil
}

func payloadKeyUsages(profile Profile) []string {
	return append([]string(nil), profile.RequiredKeyUsages...)
}
func Normalize(values []string) []string { return normalized(values) }
func validateSet(kind string, values, required, allowed []string) error {
	values = normalized(values)
	for _, value := range required {
		if !contains(values, value) {
			return fmt.Errorf("%s %q is required", kind, value)
		}
	}
	for _, value := range values {
		if len(allowed) > 0 && !contains(allowed, value) {
			return fmt.Errorf("%s %q is not allowed", kind, value)
		}
	}
	return nil
}
func normalized(values []string) []string {
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
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func ValidateIdentity(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("etcd identity is empty")
	}
	return nil
}
