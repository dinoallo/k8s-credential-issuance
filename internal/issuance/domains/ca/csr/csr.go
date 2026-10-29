// Package csr contains the bounded PKCS#10 surface shared by the CA and etcd
// certificate domains. It deliberately avoids Kubernetes dependencies.
package csr

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	grantapi "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
)

const MaxDERSize = 64 << 10

var extKeyUsageOID = asn1.ObjectIdentifier{2, 5, 29, 37}

// Parse accepts exactly one PEM CSR and verifies its proof-of-possession.
func Parse(data []byte) (*x509.CertificateRequest, []byte, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) != 0 {
		return nil, nil, fmt.Errorf("CSR must contain exactly one CERTIFICATE REQUEST PEM block")
	}
	if len(block.Bytes) == 0 || len(block.Bytes) > MaxDERSize {
		return nil, nil, fmt.Errorf("decoded CSR DER exceeds %d bytes", MaxDERSize)
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := request.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("verify CSR signature: %w", err)
	}
	return request, append([]byte(nil), block.Bytes...), nil
}

func RequestDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func DERDigest(der []byte) string {
	digest := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func PublicKeyDigest(public any) (string, error) {
	key, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", fmt.Errorf("marshal CSR public key: %w", err)
	}
	return DERDigest(key), nil
}

func Subject(request *x509.CertificateRequest) grantapi.X509Subject {
	if request == nil {
		return grantapi.X509Subject{}
	}
	return grantapi.X509Subject{
		CommonName: request.Subject.CommonName, SerialNumber: request.Subject.SerialNumber,
		Country:            append([]string(nil), request.Subject.Country...),
		Locality:           append([]string(nil), request.Subject.Locality...),
		Province:           append([]string(nil), request.Subject.Province...),
		StreetAddress:      append([]string(nil), request.Subject.StreetAddress...),
		PostalCode:         append([]string(nil), request.Subject.PostalCode...),
		Organization:       append([]string(nil), request.Subject.Organization...),
		OrganizationalUnit: append([]string(nil), request.Subject.OrganizationalUnit...),
	}
}

func NormalizeSubject(subject grantapi.X509Subject) grantapi.X509Subject {
	result := subject
	result.Country = sortedUnique(subject.Country)
	result.Locality = sortedUnique(subject.Locality)
	result.Province = sortedUnique(subject.Province)
	result.StreetAddress = sortedUnique(subject.StreetAddress)
	result.PostalCode = sortedUnique(subject.PostalCode)
	result.Organization = sortedUnique(subject.Organization)
	result.OrganizationalUnit = sortedUnique(subject.OrganizationalUnit)
	return result
}

func NormalizeDNSNames(values []string) ([]string, error) {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			return nil, fmt.Errorf("DNS SAN is empty")
		}
		result = append(result, value)
	}
	return uniqueSorted(result), nil
}

func NormalizeDNSNamesMust(values []string) []string {
	result, _ := NormalizeDNSNames(values)
	return result
}

func NormalizeIPAddresses(values []net.IP) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		result = append(result, value.String())
	}
	return uniqueSorted(result)
}

func NormalizeURIs(values []*url.URL) ([]string, error) {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == nil || value.String() == "" {
			return nil, fmt.Errorf("URI SAN is empty")
		}
		result = append(result, value.String())
	}
	return uniqueSorted(result), nil
}

func NormalizeURIsMust(values []*url.URL) []string {
	result, _ := NormalizeURIs(values)
	return result
}

func ValidateSubject(request *x509.CertificateRequest) error {
	if request == nil {
		return fmt.Errorf("CSR is nil")
	}
	if len(request.Subject.ExtraNames) != 0 || len(request.EmailAddresses) != 0 {
		return fmt.Errorf("CSR contains unsupported subject or email SAN attributes")
	}
	for _, attribute := range request.Subject.Names {
		if !supportedSubjectOID(attribute.Type) {
			return fmt.Errorf("CSR contains an unsupported X.509 subject attribute")
		}
		if _, ok := attribute.Value.(string); !ok {
			return fmt.Errorf("CSR subject attributes must be strings")
		}
	}
	return nil
}

func ExtendedKeyUsages(request *x509.CertificateRequest) ([]string, error) {
	if request == nil {
		return nil, fmt.Errorf("CSR is nil")
	}
	var result []string
	seen := map[string]bool{}
	for _, extension := range request.Extensions {
		if !extension.Id.Equal(extKeyUsageOID) {
			continue
		}
		var identifiers []asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(extension.Value, &identifiers)
		if err != nil || len(rest) != 0 || len(identifiers) == 0 {
			return nil, fmt.Errorf("invalid extended key usage extension")
		}
		for _, identifier := range identifiers {
			name := ekuName(identifier)
			if seen[name] {
				return nil, fmt.Errorf("duplicate extended key usage %q", name)
			}
			seen[name] = true
			result = append(result, name)
		}
	}
	return uniqueSorted(result), nil
}

func ekuName(identifier asn1.ObjectIdentifier) string {
	switch {
	case identifier.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}):
		return "serverAuth"
	case identifier.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}):
		return "clientAuth"
	case identifier.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}):
		return "codeSigning"
	default:
		return "oid:" + identifier.String()
	}
}

func supportedSubjectOID(value asn1.ObjectIdentifier) bool {
	for _, supported := range []asn1.ObjectIdentifier{{2, 5, 4, 3}, {2, 5, 4, 5}, {2, 5, 4, 6}, {2, 5, 4, 7}, {2, 5, 4, 8}, {2, 5, 4, 9}, {2, 5, 4, 10}, {2, 5, 4, 11}, {2, 5, 4, 17}} {
		if value.Equal(supported) {
			return true
		}
	}
	return false
}

func EqualSubject(a, b grantapi.X509Subject) bool {
	return NormalizeSubject(a).CommonName == NormalizeSubject(b).CommonName &&
		NormalizeSubject(a).SerialNumber == NormalizeSubject(b).SerialNumber &&
		equalStrings(NormalizeSubject(a).Country, NormalizeSubject(b).Country) &&
		equalStrings(NormalizeSubject(a).Locality, NormalizeSubject(b).Locality) &&
		equalStrings(NormalizeSubject(a).Province, NormalizeSubject(b).Province) &&
		equalStrings(NormalizeSubject(a).StreetAddress, NormalizeSubject(b).StreetAddress) &&
		equalStrings(NormalizeSubject(a).PostalCode, NormalizeSubject(b).PostalCode) &&
		equalStrings(NormalizeSubject(a).Organization, NormalizeSubject(b).Organization) &&
		equalStrings(NormalizeSubject(a).OrganizationalUnit, NormalizeSubject(b).OrganizationalUnit)
}

func EqualStrings(a, b []string) bool {
	return equalStrings(uniqueSorted(append([]string(nil), a...)), uniqueSorted(append([]string(nil), b...)))
}

func uniqueSorted(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if value == "" || len(result) > 0 && result[len(result)-1] == value {
			continue
		}
		result = append(result, value)
	}
	return result
}

func sortedUnique(values []string) []string { return uniqueSorted(append([]string(nil), values...)) }

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
