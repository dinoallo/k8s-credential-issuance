package kms_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	grantapi "github.com/dinoallo/k8s-credential-issuance/api/grant/v1"
	kms "github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms"
	infisicalapi "github.com/dinoallo/k8s-credential-issuance/internal/issuance/core/kms/infisical"
)

func TestInfisicalBackendBuildsAndLocallyVerifiesJWT(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	httpClient, calls := newInfisicalSigningClient(t, "jwt-key", "RSA_4096", &privateKey.PublicKey, func(data []byte, algorithm string, isDigest bool) ([]byte, error) {
		if algorithm != "RSASSA_PKCS1_V1_5_SHA_256" || !isDigest {
			return nil, fmt.Errorf("unexpected sign parameters: %s digest=%v", algorithm, isDigest)
		}
		return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, data)
	})

	client, err := infisicalapi.NewClient("https://kms.invalid", "test-token", httpClient)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := kms.NewInfisicalBackend(client)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	policy := kms.Policy{Domain: grantapi.DomainSA, Purpose: kms.PurposeServiceAccountJWT, Generation: "gen-1", KeyID: "jwt-1", KeyRef: "jwt-key", PublicKey: base64.StdEncoding.EncodeToString(publicDER), Algorithm: "RS256"}
	intent, err := kms.NewIntent(grantapi.DomainSA, kms.PurposeServiceAccountJWT, policy.KeyID, policy.Generation, policy.Algorithm, "operation-1", []byte(`{"iss":"https://issuer.example","sub":"worker"}`))
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := backend.Sign(nil, policy, intent)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(artifact.Value), ".")
	if len(parts) != 3 || artifact.KeyID != policy.KeyID || artifact.Generation != policy.Generation || artifact.PayloadDigest != intent.PayloadDigest {
		t.Fatalf("unexpected JWT artifact: %#v", artifact)
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var headerValues map[string]any
	if err := json.Unmarshal(header, &headerValues); err != nil || headerValues["alg"] != "RS256" || headerValues["kid"] != policy.KeyID {
		t.Fatalf("unexpected JWT header: %s %v", header, err)
	}
	jwk, err := backend.PublicJWK(nil, policy)
	if err != nil || jwk["kty"] != "RSA" || jwk["alg"] != policy.Algorithm || jwk["kid"] != policy.KeyID {
		t.Fatalf("unexpected JWK: %#v %v", jwk, err)
	}
	if *calls != 1 {
		t.Fatalf("expected one remote sign call, sign calls=%d", *calls)
	}
}

func TestInfisicalX509BackendIssuesLeafWithIntermediateOnly(t *testing.T) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	intermediateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "offline-root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	intermediateTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "online-intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, root, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf.example"}, DNSNames: []string{"leaf.example"}}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	subject := grantapi.X509Subject{CommonName: "leaf.example"}
	certificateValue := kms.CertificateIntent{CSRDER: csrDER, Profile: "server", SignerName: "example.com/ca", Subject: subject, DNSNames: []string{"leaf.example"}, KeyUsages: []string{"digitalSignature"}, ExtendedKeyUsages: []string{"serverAuth"}, NotBefore: now.Unix(), NotAfter: now.Add(time.Hour).Unix()}
	intent, err := kms.NewCertificateIntent(grantapi.DomainCA, kms.PurposeCACertificate, "ca-1", "gen-1", kms.AlgorithmRSASHA256, "operation-1", certificateValue)
	if err != nil {
		t.Fatal(err)
	}
	httpClient, calls := newInfisicalSigningClient(t, "ca-key", "RSA_4096", &intermediateKey.PublicKey, func(data []byte, algorithm string, isDigest bool) ([]byte, error) {
		if algorithm != "RSASSA_PKCS1_V1_5_SHA_256" || !isDigest {
			return nil, fmt.Errorf("unexpected certificate sign parameters: %s digest=%v", algorithm, isDigest)
		}
		return rsa.SignPKCS1v15(rand.Reader, intermediateKey, crypto.SHA256, data)
	})
	client, err := infisicalapi.NewClient("https://kms.invalid", "test-token", httpClient)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := kms.NewInfisicalX509Backend(client, map[string]kms.X509Issuer{"gen-1": {Certificate: intermediate, Chain: []*x509.Certificate{root}}})
	if err != nil {
		t.Fatal(err)
	}
	policy := kms.Policy{Domain: grantapi.DomainCA, Purpose: kms.PurposeCACertificate, Generation: "gen-1", KeyID: "ca-1", KeyRef: "ca-key", Algorithm: kms.AlgorithmRSASHA256, Profile: "server", SignerName: "example.com/ca", MaxLifetime: time.Hour, RequiredKeyUsages: []string{"digitalSignature"}, AllowedKeyUsages: []string{"digitalSignature"}, RequiredExtendedKeyUsages: []string{"serverAuth"}, AllowedExtendedKeyUsages: []string{"serverAuth"}}
	artifact, err := backend.Sign(nil, policy, intent)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := kms.ValidateCertificateChain(artifact.Value)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 || chain[0].IsCA || !chain[1].IsCA || string(chain[1].RawSubject) == string(root.RawSubject) {
		t.Fatalf("unexpected returned chain: %d", len(chain))
	}
	if err := chain[0].CheckSignatureFrom(intermediate); err != nil {
		t.Fatalf("leaf was not signed by configured intermediate: %v", err)
	}
	if *calls != 1 {
		t.Fatalf("expected one certificate signing call, got %d", *calls)
	}
}

func newInfisicalSigningClient(t *testing.T, keyID, keyAlgorithm string, public crypto.PublicKey, sign func([]byte, string, bool) ([]byte, error)) (*http.Client, *int) {
	t.Helper()
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	publicEncoded := base64.StdEncoding.EncodeToString(publicDER)
	var signCalls int
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet && request.URL.Path == "/api/v1/kms/keys/"+keyID {
			_, _ = fmt.Fprintf(writer, `{"key":{"id":%q,"projectId":"project-1","name":"probe","keyUsage":"sign-verify","algorithm":%q,"isExportable":false,"hasDeleteProtection":true}}`, keyID, keyAlgorithm)
			return
		}
		if request.Method == http.MethodGet && request.URL.Path == "/api/v1/kms/keys/"+keyID+"/public-key" {
			_, _ = fmt.Fprintf(writer, `{"publicKey":%q}`, publicEncoded)
			return
		}
		if request.Method == http.MethodPost && request.URL.Path == "/api/v1/kms/keys/"+keyID+"/sign" {
			var body struct {
				Data             string `json:"data"`
				SigningAlgorithm string `json:"signingAlgorithm"`
				IsDigest         bool   `json:"isDigest"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}
			data, err := base64.StdEncoding.DecodeString(body.Data)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}
			signature, err := sign(data, body.SigningAlgorithm, body.IsDigest)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}
			signCalls++
			_, _ = fmt.Fprintf(writer, `{"signature":%q,"keyId":%q,"signingAlgorithm":%q}`, base64.StdEncoding.EncodeToString(signature), keyID, body.SigningAlgorithm)
			return
		}
		http.NotFound(writer, request)
	})
	return handlerClient(handler), &signCalls
}

type backendRoundTripFunc func(*http.Request) (*http.Response, error)

func (f backendRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func handlerClient(handler http.Handler) *http.Client {
	return &http.Client{Transport: backendRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		response := recorder.Result()
		response.Request = request
		return response, nil
	})}
}
