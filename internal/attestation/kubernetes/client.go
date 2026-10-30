// Package kubernetes contains the Kubernetes-backed attestation service.
package kubernetes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	defaultServiceHost       = "KUBERNETES_SERVICE_HOST"
	defaultServicePort       = "KUBERNETES_SERVICE_PORT_HTTPS"
	defaultTokenFile         = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultCAFile            = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultKubernetesTimeout = 10 * time.Second
	maxKubernetesBody        = 1 << 20
)

// Pod is the immutable subset of a Kubernetes Pod needed to attest a
// ServiceAccount TokenRequest.
type Pod struct {
	UID                string `json:"uid"`
	NodeName           string `json:"nodeName"`
	ServiceAccountName string `json:"serviceAccountName"`
}

// ServiceAccount is the immutable subset of a Kubernetes ServiceAccount
// needed to bind a token to its UID.
type ServiceAccount struct {
	UID string `json:"uid"`
}

// API is the read-only Kubernetes API surface required by the attestor.
type API interface {
	GetPod(context.Context, string, string) (Pod, error)
	GetServiceAccount(context.Context, string, string) (ServiceAccount, error)
}

// ClientConfig configures a read-only Kubernetes API client. When
// APIServer, TokenFile, or CAFile is empty, the in-cluster environment and
// projected ServiceAccount paths are used.
type ClientConfig struct {
	APIServer  string
	TokenFile  string
	CAFile     string
	HTTPClient *http.Client
}

// Client is a small, read-only Kubernetes API client. It reads the bearer
// token for every request so projected ServiceAccount token rotation is
// honored without restarting the attestor.
type Client struct {
	baseURL   string
	tokenFile string
	client    *http.Client
}

// NewClient creates a client for an in-cluster or explicitly configured
// Kubernetes API server. The API endpoint must use HTTPS.
func NewClient(config ClientConfig) (*Client, error) {
	apiServer := strings.TrimSpace(config.APIServer)
	if apiServer == "" {
		host := strings.TrimSpace(os.Getenv(defaultServiceHost))
		if host == "" {
			return nil, fmt.Errorf("Kubernetes API server is not configured")
		}
		port := strings.TrimSpace(os.Getenv(defaultServicePort))
		if port == "" {
			port = "443"
		}
		apiServer = "https://" + net.JoinHostPort(host, port)
	}
	parsed, err := url.Parse(apiServer)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("Kubernetes API server must be an HTTPS URL without credentials or query parameters")
	}
	if parsed.Path == "/" {
		parsed.Path = ""
	}

	tokenFile := config.TokenFile
	if tokenFile == "" {
		tokenFile = defaultTokenFile
	}
	caFile := config.CAFile
	if caFile == "" {
		caFile = defaultCAFile
	}
	caData, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read Kubernetes API CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("parse Kubernetes API CA")
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: defaultKubernetesTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
			},
		}
	} else {
		copyClient := *httpClient
		if copyClient.Timeout == 0 {
			copyClient.Timeout = defaultKubernetesTimeout
		}
		httpClient = &copyClient
	}
	return &Client{baseURL: strings.TrimRight(parsed.String(), "/"), tokenFile: tokenFile, client: httpClient}, nil
}

func (c *Client) GetPod(ctx context.Context, namespace, name string) (Pod, error) {
	if namespace == "" || name == "" {
		return Pod{}, fmt.Errorf("Kubernetes Pod namespace and name are required")
	}
	var response struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
		Spec struct {
			NodeName           string `json:"nodeName"`
			ServiceAccountName string `json:"serviceAccountName"`
		} `json:"spec"`
	}
	if err := c.get(ctx, resourcePath(namespace, "pods", name), &response); err != nil {
		return Pod{}, err
	}
	return Pod{UID: response.Metadata.UID, NodeName: response.Spec.NodeName, ServiceAccountName: response.Spec.ServiceAccountName}, nil
}

func (c *Client) GetServiceAccount(ctx context.Context, namespace, name string) (ServiceAccount, error) {
	if namespace == "" || name == "" {
		return ServiceAccount{}, fmt.Errorf("Kubernetes ServiceAccount namespace and name are required")
	}
	var response struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if err := c.get(ctx, resourcePath(namespace, "serviceaccounts", name), &response); err != nil {
		return ServiceAccount{}, err
	}
	return ServiceAccount{UID: response.Metadata.UID}, nil
}

func (c *Client) get(ctx context.Context, path string, output any) error {
	if c == nil || c.client == nil || c.baseURL == "" || c.tokenFile == "" {
		return fmt.Errorf("Kubernetes API client is not configured")
	}
	tokenData, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return fmt.Errorf("read Kubernetes API token: %w", err)
	}
	token := strings.TrimSpace(string(tokenData))
	if token == "" {
		return fmt.Errorf("Kubernetes API token is empty")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("request Kubernetes API: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxKubernetesBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxKubernetesBody {
		return fmt.Errorf("Kubernetes API response exceeds %d bytes", maxKubernetesBody)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Kubernetes API returned HTTP %d", response.StatusCode)
	}
	if err := json.Unmarshal(body, output); err != nil {
		return fmt.Errorf("decode Kubernetes API response: %w", err)
	}
	return nil
}

func resourcePath(namespace, resource, name string) string {
	return "/api/v1/namespaces/" + url.PathEscape(namespace) + "/" + resource + "/" + url.PathEscape(name)
}
