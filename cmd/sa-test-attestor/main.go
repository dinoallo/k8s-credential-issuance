// sa-test-attestor is a disposable test-cluster attestor for the SA issuance
// rehearsal. It resolves a Pod and its ServiceAccount through the Kubernetes
// API, signs the resulting immutable binding, and deliberately exposes no
// mutation endpoint.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	signapi "github.com/dinoallo/k8s-credential-issuance/api/signrequest/v1"
	"github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/identity"
	sadomain "github.com/dinoallo/k8s-credential-issuance/internal/issuance/domains/sa"
)

type config struct {
	attestorIdentity string
	attestorKey      ed25519.PrivateKey
	clusterID        string
	issuer           string
	generation       string
	keyID            string
	defaultAudience  string
	maxLifetime      time.Duration
	kube             *kubeClient
}

type kubeClient struct {
	baseURL string
	token   string
	client  *http.Client
}

type podResponse struct {
	Metadata struct {
		UID string `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		NodeName           string `json:"nodeName"`
		ServiceAccountName string `json:"serviceAccountName"`
	} `json:"spec"`
}

type serviceAccountResponse struct {
	Metadata struct {
		UID string `json:"uid"`
	} `json:"metadata"`
}

func main() {
	listenAddress := flag.String("listen-address", "127.0.0.1:19445", "loopback HTTP listen address")
	attestorIdentity := flag.String("attestor-identity", "test-attestor", "stable attestor identity")
	attestorKeyFile := flag.String("attestor-key-file", "", "PKCS#8 Ed25519 private key")
	clusterID := flag.String("cluster-id", "", "issuance cluster ID")
	issuer := flag.String("issuer", "", "ServiceAccount token issuer")
	generation := flag.String("generation", "", "token key generation")
	keyID := flag.String("key-id", "", "token key ID")
	defaultAudience := flag.String("default-audience", "", "default TokenRequest audience")
	maxLifetime := flag.Duration("max-token-lifetime", time.Hour, "maximum attested token lifetime")
	flag.Parse()

	if *attestorKeyFile == "" || *clusterID == "" || *issuer == "" || *generation == "" || *keyID == "" || *defaultAudience == "" {
		fatal(fmt.Errorf("attestor key, cluster, issuer, generation, key ID, and audience are required"))
	}
	keyData, err := os.ReadFile(*attestorKeyFile)
	if err != nil {
		fatal(err)
	}
	attestorKey, err := identity.ParsePrivateKeyPEM(keyData)
	if err != nil {
		fatal(err)
	}
	kube, err := newKubeClient()
	if err != nil {
		fatal(err)
	}
	cfg := &config{
		attestorIdentity: *attestorIdentity,
		attestorKey:      attestorKey,
		clusterID:        *clusterID,
		issuer:           *issuer,
		generation:       *generation,
		keyID:            *keyID,
		defaultAudience:  *defaultAudience,
		maxLifetime:      *maxLifetime,
		kube:             kube,
	}

	server := &http.Server{Addr: *listenAddress, Handler: cfg.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second}
	ctx, stop := signalContext()
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal(err)
	}
}

func (c *config) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/attest", c.attest)
	return mux
}

func (c *config) attest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var request signapi.AttestationRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid attestation request", http.StatusBadRequest)
		return
	}
	response, err := c.resolve(r.Context(), request)
	if err != nil {
		http.Error(w, "attestation denied", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (c *config) resolve(ctx context.Context, request signapi.AttestationRequest) (signapi.AttestationResponse, error) {
	if request.Identity == "" || request.Namespace == "" || request.Name == "" || request.Nonce == "" {
		return signapi.AttestationResponse{}, fmt.Errorf("attestation request is incomplete")
	}
	ref, ok, err := sadomain.KubernetesBoundObjectRef(request.Request)
	if err != nil || !ok || ref == nil || ref.Kind != "Pod" || ref.Name == "" || ref.UID == "" {
		return signapi.AttestationResponse{}, fmt.Errorf("attestation request is not Pod-bound")
	}
	if ref.UID == "" {
		return signapi.AttestationResponse{}, fmt.Errorf("Pod UID is required")
	}
	var pod podResponse
	if err := c.kube.get(ctx, "/api/v1/namespaces/"+url.PathEscape(request.Namespace)+"/pods/"+url.PathEscape(ref.Name), &pod); err != nil {
		return signapi.AttestationResponse{}, fmt.Errorf("read Pod: %w", err)
	}
	if pod.Metadata.UID == "" || pod.Metadata.UID != ref.UID || pod.Spec.NodeName != request.Identity || pod.Spec.ServiceAccountName != request.Name {
		return signapi.AttestationResponse{}, fmt.Errorf("Pod binding does not match node request")
	}
	var serviceAccount serviceAccountResponse
	if err := c.kube.get(ctx, "/api/v1/namespaces/"+url.PathEscape(request.Namespace)+"/serviceaccounts/"+url.PathEscape(request.Name), &serviceAccount); err != nil {
		return signapi.AttestationResponse{}, fmt.Errorf("read ServiceAccount: %w", err)
	}
	if serviceAccount.Metadata.UID == "" {
		return signapi.AttestationResponse{}, fmt.Errorf("ServiceAccount has no UID")
	}
	audiences := append([]string(nil), request.Request.Audiences...)
	if len(audiences) == 0 {
		audiences = []string{c.defaultAudience}
	}
	sort.Strings(audiences)
	for i, audience := range audiences {
		if audience == "" || i > 0 && audiences[i-1] == audience {
			return signapi.AttestationResponse{}, fmt.Errorf("invalid audience set")
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	lifetime := c.maxLifetime
	if request.Request.ExpirationSeconds != nil {
		if *request.Request.ExpirationSeconds <= 0 {
			return signapi.AttestationResponse{}, fmt.Errorf("invalid expiration")
		}
		requested := time.Duration(*request.Request.ExpirationSeconds) * time.Second
		if requested < lifetime {
			lifetime = requested
		}
	}
	if lifetime <= 0 {
		return signapi.AttestationResponse{}, fmt.Errorf("invalid maximum lifetime")
	}
	binding := signapi.TokenBinding{
		ClusterID:               c.clusterID,
		ServiceAccountNamespace: request.Namespace,
		ServiceAccountName:      request.Name,
		ServiceAccountUID:       serviceAccount.Metadata.UID,
		PodUID:                  ref.UID,
		Subject:                 "system:serviceaccount:" + request.Namespace + ":" + request.Name,
		Audience:                audiences,
		Issuer:                  c.issuer,
		NotBefore:               now.Unix(),
		NotAfter:                now.Add(lifetime).Unix(),
		TokenGeneration:         c.generation,
		KeyID:                   c.keyID,
	}
	digest, err := sadomain.AttestationRequestDigest(request)
	if err != nil {
		return signapi.AttestationResponse{}, err
	}
	proof, err := identity.SignBindingProof(c.attestorIdentity, c.attestorKey, binding, digest, request.Nonce, now)
	if err != nil {
		return signapi.AttestationResponse{}, err
	}
	return signapi.AttestationResponse{RequestDigest: digest, Binding: binding, Proof: proof}, nil
}

func newKubeClient() (*kubeClient, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if host == "" {
		return nil, fmt.Errorf("KUBERNETES_SERVICE_HOST is not set")
	}
	if port == "" {
		port = "443"
	}
	tokenData, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("read in-cluster token: %w", err)
	}
	caData, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("read in-cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("parse in-cluster CA")
	}
	return &kubeClient{
		baseURL: "https://" + host + ":" + port,
		token:   strings.TrimSpace(string(tokenData)),
		client:  &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}},
	}, nil
}

func (c *kubeClient) get(ctx context.Context, path string, output any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		return fmt.Errorf("Kubernetes API returned HTTP %d", response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(output)
}

func signalContext() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
