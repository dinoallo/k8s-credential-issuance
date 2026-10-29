package infisical

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientUsesInfisicalKMSContract(t *testing.T) {
	const keyID = "11111111-1111-4111-8111-111111111111"
	var seen []string
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("unexpected authorization header %q", got)
		}
		seen = append(seen, request.Method+" "+request.URL.RequestURI())
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/kms/keys" && request.URL.Query().Get("projectId") == "project-1":
			_, _ = fmt.Fprint(writer, `{"keys":[{"id":"`+keyID+`","projectId":"project-1","name":"probe","keyUsage":"sign-verify","algorithm":"RSA_4096"}],"totalCount":1}`)
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/kms/keys":
			var body CreateKeyRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatalf("decode create request: %v", err)
			}
			if body.ProjectID != "project-1" || body.KeyUsage != KeyUsageSignVerify || body.Algorithm != "RSA_4096" || body.IsExportable || !body.HasDeleteProtection {
				t.Fatalf("unexpected create request: %#v", body)
			}
			_, _ = fmt.Fprint(writer, `{"key":{"id":"`+keyID+`","projectId":"project-1","name":"probe","keyUsage":"sign-verify","algorithm":"RSA_4096","isExportable":false,"hasDeleteProtection":true}}`)
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/kms/keys/"+keyID:
			_, _ = fmt.Fprint(writer, `{"key":{"id":"`+keyID+`","projectId":"project-1","name":"probe","keyUsage":"sign-verify","algorithm":"RSA_4096","isExportable":false,"hasDeleteProtection":true}}`)
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/kms/keys/"+keyID+"/public-key":
			_, _ = fmt.Fprint(writer, `{"publicKey":"-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----"}`)
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/kms/keys/"+keyID+"/signing-algorithms":
			_, _ = fmt.Fprint(writer, `{"signingAlgorithms":["RSASSA_PKCS1_V1_5_SHA_256"]}`)
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/kms/keys/"+keyID+"/sign":
			var body struct {
				Data             string `json:"data"`
				SigningAlgorithm string `json:"signingAlgorithm"`
				IsDigest         bool   `json:"isDigest"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatalf("decode sign request: %v", err)
			}
			data, err := base64.StdEncoding.DecodeString(body.Data)
			if err != nil || string(data) != "digest" || body.SigningAlgorithm != "RSASSA_PKCS1_V1_5_SHA_256" || !body.IsDigest {
				t.Fatalf("unexpected sign request: %#v data=%q err=%v", body, data, err)
			}
			_, _ = fmt.Fprint(writer, `{"signature":"c2ln","keyId":"`+keyID+`","signingAlgorithm":"RSASSA_PKCS1_V1_5_SHA_256"}`)
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/kms/keys/"+keyID+"/verify":
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatalf("decode verify request: %v", err)
			}
			_, _ = fmt.Fprint(writer, `{"signatureValid":true,"keyId":"`+keyID+`","signingAlgorithm":"RSASSA_PKCS1_V1_5_SHA_256"}`)
		case request.Method == http.MethodPatch && request.URL.Path == "/api/v1/kms/keys/"+keyID:
			_, _ = fmt.Fprint(writer, `{"key":{"id":"`+keyID+`","projectId":"project-1","name":"probe","keyUsage":"sign-verify","algorithm":"RSA_4096","isDisabled":true}}`)
		default:
			http.NotFound(writer, request)
		}
	})

	client, err := NewClient("https://kms.invalid", "test-token", handlerClient(handler))
	if err != nil {
		t.Fatal(err)
	}
	listed, err := client.ListKeys(nil, "project-1")
	if err != nil || listed.TotalCount != 1 || len(listed.Keys) != 1 || listed.Keys[0].ID != keyID {
		t.Fatalf("list keys: %#v %v", listed, err)
	}
	created, err := client.CreateKey(nil, CreateKeyRequest{ProjectID: "project-1", Name: "probe", KeyUsage: KeyUsageSignVerify, Algorithm: "RSA_4096", IsExportable: false, HasDeleteProtection: true})
	if err != nil || created.ID != keyID {
		t.Fatalf("create key: %#v %v", created, err)
	}
	key, err := client.GetKey(nil, keyID)
	if err != nil || key.ID != keyID || key.IsExportable {
		t.Fatalf("get key: %#v %v", key, err)
	}
	public, err := client.GetPublicKey(nil, keyID)
	if err != nil || !strings.Contains(string(public), "BEGIN PUBLIC KEY") {
		t.Fatalf("get public key: %q %v", public, err)
	}
	algorithms, err := client.ListSigningAlgorithms(nil, keyID)
	if err != nil || len(algorithms) != 1 || algorithms[0] != "RSASSA_PKCS1_V1_5_SHA_256" {
		t.Fatalf("algorithms: %#v %v", algorithms, err)
	}
	signed, err := client.Sign(nil, keyID, []byte("digest"), "RSASSA_PKCS1_V1_5_SHA_256", true)
	if err != nil || signed.Signature != "c2ln" {
		t.Fatalf("sign: %#v %v", signed, err)
	}
	verified, err := client.Verify(nil, keyID, []byte("digest"), []byte("sig"), "RSASSA_PKCS1_V1_5_SHA_256", true)
	if err != nil || !verified.SignatureValid {
		t.Fatalf("verify: %#v %v", verified, err)
	}
	disabled := true
	updated, err := client.UpdateKey(nil, keyID, UpdateKeyRequest{IsDisabled: &disabled})
	if err != nil || !updated.IsDisabled {
		t.Fatalf("update key: %#v %v", updated, err)
	}
	if len(seen) != 8 {
		t.Fatalf("unexpected request count: %v", seen)
	}
}

func TestClientReportsRetryableAPIErrorWithoutCredential(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprint(writer, `{"reqId":"req-1","statusCode":502,"message":"upstream unavailable","error":"BadGateway"}`)
	})
	client, err := NewClient("https://kms.invalid", "secret-token", handlerClient(handler))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetKey(nil, "key-1")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.Retryable() || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("unexpected API error: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func handlerClient(handler http.Handler) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		// The handler-based transport keeps tests usable in sandboxes that do not
		// permit opening a local TCP listener.
		handler.ServeHTTP(recorder, request)
		response := recorder.Result()
		response.Request = request
		return response, nil
	})}
}
