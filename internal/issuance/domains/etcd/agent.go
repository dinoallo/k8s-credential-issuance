package etcd

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	grantapi "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/grant"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/ca/csr"
)

type AgentConfig struct {
	AuthorityEndpoint      string
	SignerEndpoint         string
	Identity               string
	IdentityKey            ed25519.PrivateKey
	ClusterInstance        string
	ID                     string
	MemberOrClientIdentity string
	EndpointSANs           []string
	Profile                string
	Roles                  []string
	Generation             string
	KeyID                  string
	HTTPClient             *http.Client
	TrustedGrantKeys       map[string]ed25519.PublicKey
}
type Agent struct {
	config AgentConfig
	client *http.Client
}

func NewAgent(config AgentConfig) (*Agent, error) {
	if config.AuthorityEndpoint == "" || config.SignerEndpoint == "" || config.Identity == "" || len(config.IdentityKey) != ed25519.PrivateKeySize || config.ClusterInstance == "" || config.ID == "" || config.MemberOrClientIdentity == "" || config.Profile == "" || config.Generation == "" || config.KeyID == "" {
		return nil, fmt.Errorf("etcd certificate agent configuration is incomplete")
	}
	for _, endpoint := range []string{config.AuthorityEndpoint, config.SignerEndpoint} {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, fmt.Errorf("etcd endpoint must be an HTTP(S) URL with a host")
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

func (a *Agent) GetCertificate(ctx context.Context, csrData []byte, lifetime time.Duration) (signapi.EtcdCertificateSignResponse, error) {
	if a == nil || a.client == nil {
		return signapi.EtcdCertificateSignResponse{}, fmt.Errorf("etcd certificate agent is not configured")
	}
	parsed, der, err := csr.Parse(csrData)
	if err != nil {
		return signapi.EtcdCertificateSignResponse{}, err
	}
	endpointSANs, err := endpointSANs(parsed)
	if err != nil {
		return signapi.EtcdCertificateSignResponse{}, err
	}
	if !equalStrings(endpointSANs, Normalize(a.config.EndpointSANs)) {
		return signapi.EtcdCertificateSignResponse{}, fmt.Errorf("configured endpoint SANs do not match CSR")
	}
	seconds := int64(lifetime / time.Second)
	if lifetime <= 0 || seconds <= 0 {
		return signapi.EtcdCertificateSignResponse{}, fmt.Errorf("etcd certificate lifetime is invalid")
	}
	request := signapi.EtcdCertificateSignRequest{CSR: csrData, ClusterInstance: a.config.ClusterInstance, MemberOrClientID: a.config.ID, MemberOrClientIdentity: a.config.MemberOrClientIdentity, EndpointSANs: endpointSANs, Profile: a.config.Profile, EtcdRoles: append([]string(nil), a.config.Roles...), ExpirationSeconds: seconds, Generation: a.config.Generation, KeyID: a.config.KeyID}
	payload, err := Payload(request, parsed, der, endpointSANs)
	if err != nil {
		return signapi.EtcdCertificateSignResponse{}, err
	}
	nonce, err := identity.NewNonce()
	if err != nil {
		return signapi.EtcdCertificateSignResponse{}, err
	}
	proof, err := identity.SignBindingProof(a.config.Identity, a.config.IdentityKey, payload, payload.PublicKeySHA256, nonce, time.Now().UTC())
	if err != nil {
		return signapi.EtcdCertificateSignResponse{}, err
	}
	authorityRequest := struct {
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
	}{a.config.Identity, csrData, a.config.ClusterInstance, a.config.ID, a.config.MemberOrClientIdentity, endpointSANs, a.config.Profile, a.config.Roles, seconds, a.config.Generation, a.config.KeyID, proof}
	var authorityResponse struct {
		Grant      string `json:"grant"`
		GrantID    string `json:"grant_id"`
		RequestID  string `json:"request_id"`
		NotBefore  int64  `json:"not_before"`
		ExpiresAt  int64  `json:"expires_at"`
		Generation string `json:"generation"`
		KeyID      string `json:"key_id"`
	}
	if err := a.postJSON(ctx, a.config.AuthorityEndpoint, authorityRequest, &authorityResponse, "", ""); err != nil {
		return signapi.EtcdCertificateSignResponse{}, err
	}
	if authorityResponse.Grant == "" || authorityResponse.RequestID == "" || authorityResponse.ExpiresAt-authorityResponse.NotBefore != seconds || authorityResponse.Generation != a.config.Generation || authorityResponse.KeyID != a.config.KeyID {
		return signapi.EtcdCertificateSignResponse{}, fmt.Errorf("etcd authority returned a mismatched Grant")
	}
	if len(a.config.TrustedGrantKeys) > 0 {
		value, _, err := grant.Verify([]byte(authorityResponse.Grant), a.config.TrustedGrantKeys)
		if err != nil {
			return signapi.EtcdCertificateSignResponse{}, err
		}
		if value.Domain != grantapi.DomainEtcd || value.RequestID != authorityResponse.RequestID {
			return signapi.EtcdCertificateSignResponse{}, fmt.Errorf("etcd Grant verification mismatch")
		}
	}
	request.Grant = json.RawMessage(strconv.Quote(authorityResponse.Grant))
	request.RequestID = authorityResponse.RequestID
	request.IdentityRef = a.config.Identity
	request.NotBefore = authorityResponse.NotBefore
	request.NotAfter = authorityResponse.ExpiresAt
	var response signapi.EtcdCertificateSignResponse
	if err := a.postJSON(ctx, a.config.SignerEndpoint, request, &response, "X-Issuance-Identity", a.config.Identity); err != nil {
		return signapi.EtcdCertificateSignResponse{}, err
	}
	if len(response.Certificate) == 0 || response.GrantID != authorityResponse.GrantID || response.RequestID != authorityResponse.RequestID {
		return signapi.EtcdCertificateSignResponse{}, fmt.Errorf("etcd signer returned an incomplete result")
	}
	return response, nil
}

type FileInstaller struct {
	Path string
	Mode os.FileMode
}

func (i FileInstaller) Install(_ context.Context, certificate []byte) error {
	if i.Path == "" || len(certificate) == 0 {
		return fmt.Errorf("etcd certificate path or value is empty")
	}
	mode := i.Mode
	if mode == 0 {
		mode = 0600
	}
	directory := filepath.Dir(i.Path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".etcd-cert-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(certificate); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, i.Path)
}

type PeerState struct {
	ID      string
	Healthy bool
}
type QuorumState struct {
	Members           []PeerState
	RequiredHealthy   int
	TrustOverlapReady bool
}

func Majority(size int) int {
	if size <= 0 {
		return 0
	}
	return size/2 + 1
}
func (s QuorumState) healthy() int {
	count := 0
	for _, member := range s.Members {
		if member.Healthy {
			count++
		}
	}
	return count
}

func ValidateQuorum(state QuorumState) error {
	required := state.RequiredHealthy
	if required <= 0 {
		required = Majority(len(state.Members))
	}
	if !state.TrustOverlapReady {
		return fmt.Errorf("etcd rotation requires an overlapping trust bundle")
	}
	if state.healthy() < required {
		return fmt.Errorf("healthy etcd members are below quorum")
	}
	return nil
}

func CanRotatePeer(state QuorumState) error {
	if err := ValidateQuorum(state); err != nil {
		return err
	}
	required := state.RequiredHealthy
	if required <= 0 {
		required = Majority(len(state.Members))
	}
	if state.healthy()-1 < required {
		return fmt.Errorf("rotating a peer would violate quorum")
	}
	return nil
}

type PeerRotation struct {
	MemberID string
	CSR      []byte
	Lifetime time.Duration
	Install  func(context.Context, []byte) error
	Reload   func(context.Context) error
	Drain    func(context.Context) error
}
type RotationController struct{ Agent *Agent }

func (c *RotationController) RotatePeers(ctx context.Context, state *QuorumState, requests []PeerRotation) error {
	if c == nil || c.Agent == nil || state == nil {
		return fmt.Errorf("etcd rotation controller is not configured")
	}
	if !state.TrustOverlapReady {
		return fmt.Errorf("etcd rotation requires an overlapping trust bundle")
	}
	for _, request := range requests {
		if err := CanRotatePeer(*state); err != nil {
			return fmt.Errorf("rotating member %q would violate quorum", request.MemberID)
		}
		response, err := c.Agent.GetCertificate(ctx, request.CSR, request.Lifetime)
		if err != nil {
			return err
		}
		if request.Install != nil {
			if err := request.Install(ctx, response.Certificate); err != nil {
				return err
			}
		}
		if request.Reload != nil {
			if err := request.Reload(ctx); err != nil {
				return err
			}
		}
		if request.Drain != nil {
			if err := request.Drain(ctx); err != nil {
				return err
			}
		}
		for index := range state.Members {
			if state.Members[index].ID == request.MemberID {
				state.Members[index].Healthy = true
			}
		}
	}
	return nil
}
func (c *RotationController) RotateClient(ctx context.Context, csrData []byte, lifetime time.Duration, install func(context.Context, []byte) error) error {
	if c == nil || c.Agent == nil {
		return fmt.Errorf("etcd rotation controller is not configured")
	}
	response, err := c.Agent.GetCertificate(ctx, csrData, lifetime)
	if err != nil {
		return err
	}
	if install != nil {
		return install(ctx, response.Certificate)
	}
	return nil
}

func (a *Agent) postJSON(ctx context.Context, endpoint string, input, output any, header, headerValue string) error {
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
		return fmt.Errorf("etcd endpoint returned HTTP %s: %s", response.Status, strings.TrimSpace(string(data)))
	}
	return json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(output)
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
