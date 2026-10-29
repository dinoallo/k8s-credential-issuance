// Package transport contains bounded HTTP helpers shared by external
// authority, signer, and agent processes.
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultMaxBody = 2 << 20

type Client struct {
	HTTPClient *http.Client
	MaxBody    int64
}

func NewClient(client *http.Client, maxBody int64) *Client {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	copyClient := *client
	if copyClient.CheckRedirect == nil {
		copyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	}
	if maxBody <= 0 {
		maxBody = DefaultMaxBody
	}
	return &Client{HTTPClient: &copyClient, MaxBody: maxBody}
}

func (c *Client) DoJSON(ctx context.Context, method, endpoint string, input any, output any) error {
	return c.DoJSONWithHeaders(ctx, method, endpoint, nil, input, output)
}

// DoJSONWithHeaders is DoJSON with a small, explicit header set. Callers use
// this for protocol identity headers while the transport package remains
// independent of any domain-specific header names.
func (c *Client) DoJSONWithHeaders(ctx context.Context, method, endpoint string, headers http.Header, input any, output any) error {
	data, err := c.DoRawJSON(ctx, method, endpoint, headers, input)
	if err != nil {
		return err
	}
	if output == nil || len(data) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("decode response trailer: %w", err)
		}
		return fmt.Errorf("response contains trailing JSON value %v", token)
	}
	return nil
}

// DoRawJSON sends a JSON request and returns the bounded response bytes. It
// is used by compatibility carriers whose response shape is selected after
// the request has been authenticated.
func (c *Client) DoRawJSON(ctx context.Context, method, endpoint string, headers http.Header, input any) ([]byte, error) {
	if c == nil || c.HTTPClient == nil {
		return nil, fmt.Errorf("transport client is not configured")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("endpoint must be an absolute URL")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for key, values := range headers {
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	response, err := c.HTTPClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, c.MaxBody+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > c.MaxBody {
		return nil, fmt.Errorf("response exceeds %d-byte limit", c.MaxBody)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %s: %s", response.Status, strings.TrimSpace(string(data)))
	}
	return data, nil
}

func RequireTLSForNonLoopback(address, certFile, keyFile string) error {
	if strings.HasPrefix(address, "unix://") || strings.HasPrefix(address, "/") {
		if certFile != "" || keyFile != "" {
			return fmt.Errorf("TLS flags cannot be used with a Unix socket")
		}
		return nil
	}
	if (certFile == "") != (keyFile == "") {
		return fmt.Errorf("TLS certificate and key must be provided together")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("parse listen address: %w", err)
	}
	if host == "" || host == "localhost" || net.ParseIP(host).IsLoopback() {
		return nil
	}
	if certFile == "" || keyFile == "" {
		return fmt.Errorf("non-loopback listener requires TLS certificate and key")
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	return nil
}

// Listen creates a TCP or Unix-domain listener for one of the external
// component processes. A pre-existing Unix socket is replaced only when it
// is actually a socket; ordinary files are never removed.
func Listen(address string) (net.Listener, func(), error) {
	if strings.HasPrefix(address, "unix://") || strings.HasPrefix(address, "/") {
		path := strings.TrimPrefix(address, "unix://")
		if path == "" || !filepath.IsAbs(path) || path != filepath.Clean(path) {
			return nil, func() {}, fmt.Errorf("invalid Unix listener %q", address)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, func() {}, err
		}
		if info, err := os.Lstat(path); err == nil {
			if info.Mode()&os.ModeSocket == 0 {
				return nil, func() {}, fmt.Errorf("refusing to replace non-socket path %q", path)
			}
			if err := os.Remove(path); err != nil {
				return nil, func() {}, err
			}
		} else if !os.IsNotExist(err) {
			return nil, func() {}, err
		}
		listener, err := net.Listen("unix", path)
		if err != nil {
			return nil, func() {}, err
		}
		if err := os.Chmod(path, 0600); err != nil {
			_ = listener.Close()
			_ = os.Remove(path)
			return nil, func() {}, err
		}
		return listener, func() {
			_ = listener.Close()
			_ = os.Remove(path)
		}, nil
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, func() {}, err
	}
	return listener, func() { _ = listener.Close() }, nil
}

// Run serves an external component until the context is cancelled, then
// performs a bounded graceful shutdown.
func Run(ctx context.Context, listener net.Listener, handler http.Handler, certFile, keyFile string) error {
	if listener == nil || handler == nil {
		return fmt.Errorf("HTTP server listener and handler are required")
	}
	if (certFile == "") != (keyFile == "") {
		return fmt.Errorf("TLS certificate and key must be provided together")
	}
	var tlsConfig *tls.Config
	if certFile != "" {
		var err error
		tlsConfig, err = NewTLSConfig(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("load TLS certificate: %w", err)
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	server := &http.Server{Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	errors := make(chan error, 1)
	go func() {
		if certFile != "" && keyFile != "" {
			errors <- server.ServeTLS(listener, certFile, keyFile)
			return
		}
		errors <- server.Serve(listener)
	}()
	select {
	case err := <-errors:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return err
		}
		return nil
	}
}

func NewTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("TLS certificate and key are both required")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}, nil
}
