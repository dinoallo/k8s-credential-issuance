package ca

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	grantapi "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/grant"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/ca/csr"
)

type AgentConfig struct {
	AuthorityEndpoint string
	SignerEndpoint    string
	Identity          string
	IdentityKey       []byte
	SignerName        string
	Profile           string
	KeyUsages         []string
	ExtendedKeyUsages []string
	Generation        string
	KeyID             string
	HTTPClient        *http.Client
	TrustedGrantKeys  map[string]ed25519.PublicKey
}

type Agent struct {
	config AgentConfig
	client *http.Client
}

func NewAgent(config AgentConfig) (*Agent, error) {
	if config.AuthorityEndpoint == "" || config.SignerEndpoint == "" || config.Identity == "" || len(config.IdentityKey) != ed25519.PrivateKeySize || config.SignerName == "" || config.Profile == "" || config.Generation == "" || config.KeyID == "" {
		return nil, fmt.Errorf("CA certificate agent configuration is incomplete")
	}
	for _, endpoint := range []string{config.AuthorityEndpoint, config.SignerEndpoint} {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, fmt.Errorf("CA endpoint must be an HTTP(S) URL with a host")
		}
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	copyClient := *client
	if copyClient.CheckRedirect == nil {
		copyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	}
	return &Agent{config: config, client: &copyClient}, nil
}

func (a *Agent) GetCertificate(ctx context.Context, csrData []byte, lifetime time.Duration) (signapi.CertificateSignResponse, error) {
	if a == nil || a.client == nil {
		return signapi.CertificateSignResponse{}, fmt.Errorf("CA certificate agent is not configured")
	}
	parsed, der, err := csr.Parse(csrData)
	if err != nil {
		return signapi.CertificateSignResponse{}, err
	}
	seconds := int64(lifetime / time.Second)
	if lifetime <= 0 || seconds <= 0 {
		return signapi.CertificateSignResponse{}, fmt.Errorf("CA certificate lifetime is invalid")
	}
	request := signapi.CertificateSignRequest{CSR: csrData, SignerName: a.config.SignerName, Profile: a.config.Profile, KeyUsages: append([]string(nil), a.config.KeyUsages...), ExtendedKeyUsages: append([]string(nil), a.config.ExtendedKeyUsages...), ExpirationSeconds: seconds, Generation: a.config.Generation, KeyID: a.config.KeyID}
	payload, err := Payload(request, parsed, der)
	if err != nil {
		return signapi.CertificateSignResponse{}, err
	}
	nonce, err := identity.NewNonce()
	if err != nil {
		return signapi.CertificateSignResponse{}, err
	}
	proof, err := identity.SignBindingProof(a.config.Identity, ed25519.PrivateKey(a.config.IdentityKey), payload, payload.CSRRequestDigest, nonce, time.Now().UTC())
	if err != nil {
		return signapi.CertificateSignResponse{}, err
	}
	grantRequest := struct {
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
	}{a.config.Identity, csrData, request.SignerName, request.Profile, request.KeyUsages, request.ExtendedKeyUsages, seconds, request.Generation, request.KeyID, proof}
	var authorityResponse struct {
		Grant      string `json:"grant"`
		GrantID    string `json:"grant_id"`
		RequestID  string `json:"request_id"`
		NotBefore  int64  `json:"not_before"`
		ExpiresAt  int64  `json:"expires_at"`
		Generation string `json:"generation"`
		KeyID      string `json:"key_id"`
	}
	if err := a.postJSON(ctx, a.config.AuthorityEndpoint, grantRequest, &authorityResponse); err != nil {
		return signapi.CertificateSignResponse{}, err
	}
	if authorityResponse.Grant == "" || authorityResponse.RequestID == "" || authorityResponse.ExpiresAt-authorityResponse.NotBefore != seconds || authorityResponse.Generation != request.Generation || authorityResponse.KeyID != request.KeyID {
		return signapi.CertificateSignResponse{}, fmt.Errorf("CA authority returned a Grant with mismatched binding")
	}
	if len(a.config.TrustedGrantKeys) > 0 {
		value, _, err := grant.Verify([]byte(authorityResponse.Grant), a.config.TrustedGrantKeys)
		if err != nil {
			return signapi.CertificateSignResponse{}, err
		}
		if value.Domain != grantapi.DomainCA || value.RequestID != authorityResponse.RequestID || value.Generation != request.Generation || value.KeyID != request.KeyID {
			return signapi.CertificateSignResponse{}, fmt.Errorf("CA Grant verification mismatch")
		}
	}
	request.Grant, request.RequestID, request.NotBefore, request.NotAfter = json.RawMessage(strconv.Quote(authorityResponse.Grant)), authorityResponse.RequestID, authorityResponse.NotBefore, authorityResponse.ExpiresAt
	var response signapi.CertificateSignResponse
	if err := a.postJSONWithHeader(ctx, a.config.SignerEndpoint, request, &response, "X-Issuance-Identity", a.config.Identity); err != nil {
		return signapi.CertificateSignResponse{}, err
	}
	if len(response.Certificate) == 0 || response.GrantID != authorityResponse.GrantID || response.RequestID != authorityResponse.RequestID {
		return signapi.CertificateSignResponse{}, fmt.Errorf("CA signer returned an incomplete result")
	}
	return response, nil
}

func GenerateCSR(subject grantapi.X509Subject, dnsNames []string, ipAddresses []string, uriNames []string) (crypto.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	request := &x509.CertificateRequest{Subject: pkix.Name{CommonName: subject.CommonName, SerialNumber: subject.SerialNumber, Country: subject.Country, Locality: subject.Locality, Province: subject.Province, StreetAddress: subject.StreetAddress, PostalCode: subject.PostalCode, Organization: subject.Organization, OrganizationalUnit: subject.OrganizationalUnit}, DNSNames: dnsNames}
	for _, value := range ipAddresses {
		if parsed := net.ParseIP(value); parsed != nil {
			request.IPAddresses = append(request.IPAddresses, parsed)
		}
	}
	for _, value := range uriNames {
		if parsed, err := url.Parse(value); err == nil {
			request.URIs = append(request.URIs, parsed)
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, request, key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

type Installer interface {
	Install(context.Context, []byte, int64) error
}
type MemoryInstaller struct {
	mu          sync.Mutex
	Certificate []byte
	Generation  int64
}

func (i *MemoryInstaller) Install(_ context.Context, certificate []byte, generation int64) error {
	if i == nil {
		return fmt.Errorf("CA installer is nil")
	}
	i.mu.Lock()
	i.Certificate, i.Generation = append([]byte(nil), certificate...), generation
	i.mu.Unlock()
	return nil
}

type RotationRequest struct {
	CSR        []byte
	Lifetime   time.Duration
	Generation int64
}
type RotationController struct {
	Agent     *Agent
	Installer Installer
	Reload    func(context.Context) error
}

func (c *RotationController) Rotate(ctx context.Context, request RotationRequest) (signapi.CertificateSignResponse, error) {
	if c == nil || c.Agent == nil || c.Installer == nil {
		return signapi.CertificateSignResponse{}, fmt.Errorf("CA rotation controller is not configured")
	}
	result, err := c.Agent.GetCertificate(ctx, request.CSR, request.Lifetime)
	if err != nil {
		return signapi.CertificateSignResponse{}, err
	}
	if err := c.Installer.Install(ctx, result.Certificate, request.Generation); err != nil {
		return signapi.CertificateSignResponse{}, err
	}
	if c.Reload != nil {
		if err := c.Reload(ctx); err != nil {
			return signapi.CertificateSignResponse{}, err
		}
	}
	return result, nil
}

type CarrierStore interface {
	Get(context.Context, string) (signapi.CertificateSigningRequestCarrier, error)
	UpdateStatus(context.Context, signapi.CertificateSigningRequestCarrier) error
}
type StatusController struct {
	Store     CarrierStore
	Signer    *Signer
	GrantKeys map[string]ed25519.PublicKey
}

func (c *StatusController) Process(ctx context.Context, name string) error {
	if c == nil || c.Store == nil || c.Signer == nil {
		return fmt.Errorf("CA status controller is not configured")
	}
	current, err := c.Store.Get(ctx, name)
	if err != nil {
		return err
	}
	if len(current.Status.Certificate) != 0 {
		return nil
	}
	grantValue := current.Metadata.Annotations[signapi.CertificateGrantAnnotation]
	requestID := current.Metadata.Annotations[signapi.RequestIDAnnotation]
	identityRef := current.Metadata.Annotations["issuance.example.com/identity"]
	if grantValue == "" || requestID == "" {
		return fmt.Errorf("CSR carrier is missing Grant annotations")
	}
	generation := current.Metadata.Annotations["issuance.example.com/generation"]
	keyID := current.Metadata.Annotations["issuance.example.com/key-id"]
	notBefore := parseInt(current.Metadata.Annotations["issuance.example.com/not-before"])
	notAfter := parseInt(current.Metadata.Annotations["issuance.example.com/not-after"])
	if len(c.GrantKeys) != 0 {
		value, _, verifyErr := grant.Verify([]byte(grantValue), c.GrantKeys)
		if verifyErr != nil || value.RequestID != requestID {
			if verifyErr != nil {
				return verifyErr
			}
			return fmt.Errorf("CSR Grant request ID does not match the annotation")
		}
		generation, keyID, notBefore, notAfter = value.Generation, value.KeyID, value.NotBefore, value.ExpiresAt
	}
	lifetime := current.Spec.ExpirationSeconds
	if lifetime == 0 && notAfter > notBefore {
		lifetime = notAfter - notBefore
	}
	result, err := c.Signer.Sign(ctx, signapi.CertificateSignRequest{CSR: current.Spec.Request, Grant: json.RawMessage(strconv.Quote(grantValue)), RequestID: requestID, IdentityRef: identityRef, SignerName: current.Spec.SignerName, Profile: current.Spec.Profile, KeyUsages: current.Spec.Usages, ExtendedKeyUsages: current.Spec.ExtendedKeyUsages, ExpirationSeconds: lifetime, Generation: generation, KeyID: keyID, NotBefore: notBefore, NotAfter: notAfter}, identityRef)
	if err != nil {
		return err
	}
	latest, err := c.Store.Get(ctx, name)
	if err != nil {
		return err
	}
	if len(latest.Status.Certificate) != 0 {
		return nil
	}
	latest.Status.Certificate = append([]byte(nil), result.Certificate...)
	latest.Status.CA = nil
	return c.Store.UpdateStatus(ctx, latest)
}

func (a *Agent) postJSON(ctx context.Context, endpoint string, input, output any) error {
	return a.postJSONWithHeader(ctx, endpoint, input, output, "", "")
}
func (a *Agent) postJSONWithHeader(ctx context.Context, endpoint string, input, output any, header, headerValue string) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if header != "" {
		request.Header.Set(header, headerValue)
	}
	response, err := a.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return fmt.Errorf("CA endpoint returned HTTP %s: %s", response.Status, strings.TrimSpace(string(data)))
	}
	return json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(output)
}
func parseInt(value string) int64 { var result int64; _, _ = fmt.Sscan(value, &result); return result }
