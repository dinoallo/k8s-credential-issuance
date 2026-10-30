package kubernetes

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestClientReadsRotatingBearerTokenForEveryRequest(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("token-one\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var seenTokens []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seenTokens = append(seenTokens, request.Header.Get("Authorization"))
		switch request.URL.Path {
		case "/api/v1/namespaces/default/pods/reader-pod":
			_, _ = fmt.Fprint(writer, `{"metadata":{"uid":"pod-uid-1"},"spec":{"nodeName":"node-1","serviceAccountName":"reader"}}`)
		case "/api/v1/namespaces/default/serviceaccounts/reader":
			_, _ = fmt.Fprint(writer, `{"metadata":{"uid":"sa-uid-1"}}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	caPath := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ClientConfig{APIServer: server.URL, TokenFile: tokenPath, CAFile: caPath})
	if err != nil {
		t.Fatal(err)
	}
	pod, err := client.GetPod(nil, "default", "reader-pod")
	if err != nil {
		t.Fatal(err)
	}
	if pod.UID != "pod-uid-1" || pod.NodeName != "node-1" || pod.ServiceAccountName != "reader" {
		t.Fatalf("unexpected Pod: %#v", pod)
	}
	if err := os.WriteFile(tokenPath, []byte("token-two\n"), 0600); err != nil {
		t.Fatal(err)
	}
	serviceAccount, err := client.GetServiceAccount(nil, "default", "reader")
	if err != nil {
		t.Fatal(err)
	}
	if serviceAccount.UID != "sa-uid-1" {
		t.Fatalf("unexpected ServiceAccount: %#v", serviceAccount)
	}
	if got, want := seenTokens, []string{"Bearer token-one", "Bearer token-two"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("authorization headers = %#v, want %#v", got, want)
	}
}
