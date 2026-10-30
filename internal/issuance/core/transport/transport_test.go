package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRequireTLSForUnixAndLoopbackListeners(t *testing.T) {
	for _, address := range []string{"unix:///tmp/sa-node-agent.sock", "/tmp/sa-node-agent.sock", "127.0.0.1:9443", "localhost:9443"} {
		if err := RequireTLSForNonLoopback(address, "", ""); err != nil {
			t.Fatalf("listener %q was rejected: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:9443", "[::]:9443", "10.0.0.1:9443"} {
		if err := RequireTLSForNonLoopback(address, "", ""); err == nil {
			t.Fatalf("non-loopback listener %q was allowed without TLS", address)
		}
	}
	if err := RequireTLSForNonLoopback("127.0.0.1:9443", "cert.pem", ""); err == nil {
		t.Fatal("partial TLS configuration was accepted")
	}
}

func TestClientSendsBoundedJSONAndHeaders(t *testing.T) {
	client := NewClient(&http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.Header.Get("X-Test") != "value" {
			return nil, io.ErrUnexpectedEOF
		}
		body, err := io.ReadAll(request.Body)
		if err != nil || string(body) != `{"request":"value"}` {
			return nil, io.ErrUnexpectedEOF
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(bytes.NewReader([]byte(`{"ok":true}`)))}, nil
	})}, 1024)
	var response struct {
		OK bool `json:"ok"`
	}
	if err := client.DoJSONWithHeaders(context.Background(), http.MethodPost, "http://example.invalid/v1", http.Header{"X-Test": {"value"}}, map[string]string{"request": "value"}, &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK {
		t.Fatal("transport did not decode the JSON response")
	}
}

func TestListenUnixSocketDoesNotReplaceRegularFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "agent.sock")
	if err := os.WriteFile(path, []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Listen(path); err == nil {
		t.Fatal("Listen accepted a regular file as a Unix socket")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep me" {
		t.Fatal("Listen modified the regular file")
	}
}

func TestListenRejectsRelativeUnixSocket(t *testing.T) {
	if _, _, err := Listen("unix://relative.sock"); err == nil {
		t.Fatal("Listen accepted a relative Unix socket path")
	}
}

func TestListenUnixSocketSetsPrivateModeAndCleansUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.sock")
	listener, cleanup, err := Listen(path)
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("sandbox does not permit Unix sockets: %v", err)
		}
		t.Fatal(err)
	}
	defer cleanup()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("socket mode = %o, want 0600", info.Mode().Perm())
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("socket cleanup error = %v", err)
	}
}

func TestRunWithTLSConfigServesTLS(t *testing.T) {
	certificate := testServerCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- RunWithTLSConfig(ctx, listener, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path != "/healthz" {
				http.NotFound(writer, request)
				return
			}
			writer.WriteHeader(http.StatusOK)
		}), &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
	}()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}}}
	endpoint := "https://" + listener.Addr().String() + "/healthz"
	var response *http.Response
	var requestErr error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		response, requestErr = client.Get(endpoint)
		if requestErr == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if requestErr != nil {
		t.Fatal(requestErr)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TLS server did not shut down")
	}
}

func testServerCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
