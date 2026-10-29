package ca

import (
	"fmt"
	"sort"
	"strings"
	"time"

	grantapi "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
)

const (
	UsageDigitalSignature = "digitalSignature"
	UsageKeyEncipherment  = "keyEncipherment"
	UsageCertSign         = "certSign"
	UsageCRLSign          = "crlSign"
	UsageClientAuth       = "clientAuth"
	UsageServerAuth       = "serverAuth"
)

type Profile struct {
	Name                   string
	SignerName             string
	MaxTTL                 time.Duration
	RequiredKeyUsages      []string
	AllowedKeyUsages       []string
	RequiredExtendedUsages []string
	AllowedExtendedUsages  []string
	ValidateSubject        func(grantapi.X509Subject) error
}

type Registry struct{ profiles map[string]Profile }

func NewRegistry(profiles []Profile) (*Registry, error) {
	result := &Registry{profiles: make(map[string]Profile, len(profiles))}
	for _, profile := range profiles {
		if profile.Name == "" || profile.SignerName == "" || profile.MaxTTL <= 0 {
			return nil, fmt.Errorf("CA profile is incomplete")
		}
		if _, exists := result.profiles[profile.Name]; exists {
			return nil, fmt.Errorf("duplicate CA profile %q", profile.Name)
		}
		profile.RequiredKeyUsages = normalized(profile.RequiredKeyUsages)
		profile.AllowedKeyUsages = normalized(profile.AllowedKeyUsages)
		profile.RequiredExtendedUsages = normalized(profile.RequiredExtendedUsages)
		profile.AllowedExtendedUsages = normalized(profile.AllowedExtendedUsages)
		result.profiles[profile.Name] = profile
	}
	if len(result.profiles) == 0 {
		return nil, fmt.Errorf("no CA profiles configured")
	}
	return result, nil
}

func DefaultRegistry(maxTTL time.Duration) (*Registry, error) {
	if maxTTL <= 0 {
		return nil, fmt.Errorf("CA profile max TTL must be positive")
	}
	return NewRegistry([]Profile{
		{Name: "kubelet-client", SignerName: "kubernetes.io/kube-apiserver-client-kubelet", MaxTTL: maxTTL,
			RequiredKeyUsages: []string{UsageDigitalSignature}, AllowedKeyUsages: []string{UsageDigitalSignature, UsageKeyEncipherment},
			RequiredExtendedUsages: []string{UsageClientAuth}, AllowedExtendedUsages: []string{UsageClientAuth},
			ValidateSubject: nodeSubject},
		{Name: "kubelet-serving", SignerName: "kubernetes.io/kubelet-serving", MaxTTL: maxTTL,
			RequiredKeyUsages: []string{UsageDigitalSignature}, AllowedKeyUsages: []string{UsageDigitalSignature, UsageKeyEncipherment},
			RequiredExtendedUsages: []string{UsageServerAuth}, AllowedExtendedUsages: []string{UsageServerAuth},
			ValidateSubject: nodeSubject},
	})
}

func nodeSubject(subject grantapi.X509Subject) error {
	if len(subject.Organization) != 1 || subject.Organization[0] != "system:nodes" || !strings.HasPrefix(subject.CommonName, "system:node:") || len(subject.CommonName) <= len("system:node:") {
		return fmt.Errorf("node certificate subject is not a registered node identity")
	}
	return nil
}

func (r *Registry) Get(name string) (Profile, bool) {
	if r == nil {
		return Profile{}, false
	}
	value, ok := r.profiles[name]
	return value, ok
}

func (r *Registry) GetForSigner(signerName string) (Profile, bool) {
	if r == nil {
		return Profile{}, false
	}
	var result Profile
	found := false
	for _, profile := range r.profiles {
		if profile.SignerName != signerName {
			continue
		}
		if found {
			return Profile{}, false
		}
		result, found = profile, true
	}
	return result, found
}

func (r *Registry) Validate(payload grantapi.CertificatePayload) (Profile, error) {
	if r == nil {
		return Profile{}, fmt.Errorf("CA profile registry is nil")
	}
	profile, ok := r.profiles[payload.Profile]
	if !ok {
		return Profile{}, fmt.Errorf("unknown CA profile %q", payload.Profile)
	}
	if profile.SignerName != payload.SignerName {
		return Profile{}, fmt.Errorf("profile %q does not allow signer %q", payload.Profile, payload.SignerName)
	}
	if payload.RequestedLifetimeSecs <= 0 || time.Duration(payload.RequestedLifetimeSecs)*time.Second > profile.MaxTTL {
		return Profile{}, fmt.Errorf("requested lifetime exceeds profile %q maximum", profile.Name)
	}
	if err := validateSet("key usage", payload.KeyUsages, profile.RequiredKeyUsages, profile.AllowedKeyUsages); err != nil {
		return Profile{}, err
	}
	if err := validateSet("extended key usage", payload.ExtendedKeyUsages, profile.RequiredExtendedUsages, profile.AllowedExtendedUsages); err != nil {
		return Profile{}, err
	}
	if profile.ValidateSubject != nil {
		if err := profile.ValidateSubject(payload.Subject); err != nil {
			return Profile{}, err
		}
	}
	return profile, nil
}

func validateSet(kind string, requested, required, allowed []string) error {
	original := append([]string(nil), requested...)
	requested = normalized(requested)
	if !equal(original, requested) {
		return fmt.Errorf("%s values must be sorted and unique", kind)
	}
	for _, want := range required {
		if !contains(requested, want) {
			return fmt.Errorf("%s %q is required", kind, want)
		}
	}
	for _, value := range requested {
		if len(allowed) != 0 && !contains(allowed, value) {
			return fmt.Errorf("%s %q is not allowed", kind, value)
		}
	}
	return nil
}

func NormalizeUsages(values []string) []string { return normalized(values) }

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

func equal(a, b []string) bool {
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

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// CSRProfileValues normalizes values derived from a CSR and the direct
// request. It is kept here so authorities and signers use identical policy
// comparison semantics.
func CSRProfileValues(requested, csrValues []string) error {
	if !equal(normalized(requested), normalized(csrValues)) {
		return fmt.Errorf("certificate usage values do not match CSR/request policy")
	}
	return nil
}
