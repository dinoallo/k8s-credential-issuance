// Package infisical contains the narrow Infisical KMS API client used by the
// issuance KMS adapters. It deliberately does not expose key material or a
// generic remote-signing method to callers outside the constrained adapter.
package infisical

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultMaxBody     = 2 << 20
	apiPrefix          = "/api/v1/kms"
	KeyUsageSignVerify = "sign-verify"
)

var (
	ErrInvalidConfiguration = errors.New("invalid Infisical KMS client configuration")
	ErrResponseTooLarge     = errors.New("Infisical KMS response exceeds size limit")
)

// APIError describes an HTTP error returned by Infisical. The bearer token is
// intentionally never included in its representation.
type APIError struct {
	StatusCode int
	RequestID  string
	Message    string
	Kind       string
}

func (e *APIError) Error() string {
	if e == nil {
		return "Infisical KMS API error"
	}
	message := e.Message
	if message == "" {
		message = http.StatusText(e.StatusCode)
	}
	if e.RequestID != "" {
		return fmt.Sprintf("Infisical KMS API error (HTTP %d, request %s): %s", e.StatusCode, e.RequestID, message)
	}
	return fmt.Sprintf("Infisical KMS API error (HTTP %d): %s", e.StatusCode, message)
}

// Retryable reports whether retrying the same authorized operation may be
// appropriate. The caller still needs durable operation/result recovery for
// an unknown outcome; Infisical's sign endpoint has no operation-id field.
func (e *APIError) Retryable() bool {
	if e == nil {
		return false
	}
	return e.StatusCode == http.StatusRequestTimeout || e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500
}

// Key is the metadata returned by Infisical for a KMS key.
type Key struct {
	ID                  string `json:"id"`
	Description         string `json:"description"`
	IsDisabled          bool   `json:"isDisabled"`
	OrgID               string `json:"orgId"`
	Name                string `json:"name"`
	CreatedAt           string `json:"createdAt"`
	UpdatedAt           string `json:"updatedAt"`
	ProjectID           string `json:"projectId"`
	KeyUsage            string `json:"keyUsage"`
	IsExportable        bool   `json:"isExportable"`
	HasDeleteProtection bool   `json:"hasDeleteProtection"`
	Version             int    `json:"version"`
	Algorithm           string `json:"algorithm"`
}

type ListKeysResponse struct {
	Keys       []Key `json:"keys"`
	TotalCount int   `json:"totalCount"`
}

type CreateKeyRequest struct {
	ProjectID           string `json:"projectId"`
	Name                string `json:"name"`
	Description         string `json:"description,omitempty"`
	KeyUsage            string `json:"keyUsage,omitempty"`
	Algorithm           string `json:"algorithm,omitempty"`
	IsExportable        bool   `json:"isExportable"`
	HasDeleteProtection bool   `json:"hasDeleteProtection"`
}

type UpdateKeyRequest struct {
	Name                *string `json:"name,omitempty"`
	IsDisabled          *bool   `json:"isDisabled,omitempty"`
	Description         *string `json:"description,omitempty"`
	HasDeleteProtection *bool   `json:"hasDeleteProtection,omitempty"`
}

type SignResponse struct {
	Signature        string `json:"signature"`
	KeyID            string `json:"keyId"`
	SigningAlgorithm string `json:"signingAlgorithm"`
}

type VerifyResponse struct {
	SignatureValid   bool   `json:"signatureValid"`
	KeyID            string `json:"keyId"`
	SigningAlgorithm string `json:"signingAlgorithm"`
}

// Client is a bearer-authenticated Infisical KMS client.
type Client struct {
	baseURL    *url.URL
	token      string
	httpClient *http.Client
	MaxBody    int64
}

func NewClient(endpoint, token string, httpClient *http.Client) (*Client, error) {
	if strings.TrimSpace(endpoint) == "" || strings.TrimSpace(token) == "" {
		return nil, ErrInvalidConfiguration
	}
	parsed, err := url.Parse(strings.TrimRight(endpoint, "/"))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%w: endpoint must be an absolute HTTP(S) URL without credentials or query", ErrInvalidConfiguration)
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	copyClient := *httpClient
	if copyClient.CheckRedirect == nil {
		copyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	}
	return &Client{baseURL: parsed, token: strings.TrimSpace(token), httpClient: &copyClient}, nil
}

func (c *Client) GetKey(ctx context.Context, keyID string) (Key, error) {
	segment, err := pathSegment(keyID)
	if err != nil {
		return Key{}, err
	}
	var response struct {
		Key Key `json:"key"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/keys/"+segment, nil, nil, &response); err != nil {
		return Key{}, err
	}
	if response.Key.ID != keyID {
		return Key{}, fmt.Errorf("Infisical KMS returned a mismatched key ID")
	}
	return response.Key, nil
}

func (c *Client) ListKeys(ctx context.Context, projectID string) (ListKeysResponse, error) {
	if strings.TrimSpace(projectID) == "" {
		return ListKeysResponse{}, fmt.Errorf("project ID is required")
	}
	query := url.Values{"projectId": []string{projectID}}
	var response ListKeysResponse
	if err := c.doJSON(ctx, http.MethodGet, "/keys", query, nil, &response); err != nil {
		return ListKeysResponse{}, err
	}
	return response, nil
}

func (c *Client) GetPublicKey(ctx context.Context, keyID string) ([]byte, error) {
	segment, err := pathSegment(keyID)
	if err != nil {
		return nil, err
	}
	var response struct {
		PublicKey string `json:"publicKey"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/keys/"+segment+"/public-key", nil, nil, &response); err != nil {
		return nil, err
	}
	if strings.TrimSpace(response.PublicKey) == "" {
		return nil, fmt.Errorf("Infisical KMS returned an empty public key")
	}
	return []byte(response.PublicKey), nil
}

func (c *Client) ListSigningAlgorithms(ctx context.Context, keyID string) ([]string, error) {
	segment, err := pathSegment(keyID)
	if err != nil {
		return nil, err
	}
	var response struct {
		SigningAlgorithms []string `json:"signingAlgorithms"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/keys/"+segment+"/signing-algorithms", nil, nil, &response); err != nil {
		return nil, err
	}
	return append([]string(nil), response.SigningAlgorithms...), nil
}

func (c *Client) Sign(ctx context.Context, keyID string, data []byte, signingAlgorithm string, isDigest bool) (SignResponse, error) {
	if len(data) == 0 || signingAlgorithm == "" {
		return SignResponse{}, fmt.Errorf("Infisical KMS sign request is incomplete")
	}
	segment, err := pathSegment(keyID)
	if err != nil {
		return SignResponse{}, err
	}
	request := map[string]any{
		"data":             base64.StdEncoding.EncodeToString(data),
		"signingAlgorithm": signingAlgorithm,
		"isDigest":         isDigest,
	}
	var response SignResponse
	if err := c.doJSON(ctx, http.MethodPost, "/keys/"+segment+"/sign", nil, request, &response); err != nil {
		return SignResponse{}, err
	}
	if response.KeyID != keyID || response.SigningAlgorithm != signingAlgorithm || response.Signature == "" {
		return SignResponse{}, fmt.Errorf("Infisical KMS returned an invalid sign response")
	}
	return response, nil
}

func (c *Client) Verify(ctx context.Context, keyID string, data, signature []byte, signingAlgorithm string, isDigest bool) (VerifyResponse, error) {
	if len(data) == 0 || len(signature) == 0 || signingAlgorithm == "" {
		return VerifyResponse{}, fmt.Errorf("Infisical KMS verify request is incomplete")
	}
	segment, err := pathSegment(keyID)
	if err != nil {
		return VerifyResponse{}, err
	}
	request := map[string]any{
		"data":             base64.StdEncoding.EncodeToString(data),
		"signature":        base64.StdEncoding.EncodeToString(signature),
		"signingAlgorithm": signingAlgorithm,
		"isDigest":         isDigest,
	}
	var response VerifyResponse
	if err := c.doJSON(ctx, http.MethodPost, "/keys/"+segment+"/verify", nil, request, &response); err != nil {
		return VerifyResponse{}, err
	}
	if response.KeyID != keyID || response.SigningAlgorithm != signingAlgorithm {
		return VerifyResponse{}, fmt.Errorf("Infisical KMS returned an invalid verify response")
	}
	return response, nil
}

func (c *Client) CreateKey(ctx context.Context, request CreateKeyRequest) (Key, error) {
	if request.ProjectID == "" || request.Name == "" || request.KeyUsage == "" || request.Algorithm == "" {
		return Key{}, fmt.Errorf("Infisical KMS create-key request is incomplete")
	}
	var response struct {
		Key Key `json:"key"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/keys", nil, request, &response); err != nil {
		return Key{}, err
	}
	if response.Key.ID == "" || response.Key.ProjectID != request.ProjectID {
		return Key{}, fmt.Errorf("Infisical KMS returned an invalid created key")
	}
	return response.Key, nil
}

func (c *Client) UpdateKey(ctx context.Context, keyID string, request UpdateKeyRequest) (Key, error) {
	if request.Name == nil && request.IsDisabled == nil && request.Description == nil && request.HasDeleteProtection == nil {
		return Key{}, fmt.Errorf("Infisical KMS update-key request is empty")
	}
	segment, err := pathSegment(keyID)
	if err != nil {
		return Key{}, err
	}
	var response struct {
		Key Key `json:"key"`
	}
	if err := c.doJSON(ctx, http.MethodPatch, "/keys/"+segment, nil, request, &response); err != nil {
		return Key{}, err
	}
	if response.Key.ID != keyID {
		return Key{}, fmt.Errorf("Infisical KMS returned a mismatched updated key ID")
	}
	return response.Key, nil
}

func (c *Client) DisableKey(ctx context.Context, keyID string) (Key, error) {
	disabled := true
	return c.UpdateKey(ctx, keyID, UpdateKeyRequest{IsDisabled: &disabled})
}

func (c *Client) doJSON(ctx context.Context, method, path string, query url.Values, input, output any) error {
	if c == nil || c.baseURL == nil || c.token == "" || c.httpClient == nil {
		return ErrInvalidConfiguration
	}
	if ctx == nil {
		ctx = context.Background()
	}
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + apiPrefix + path
	endpoint.RawPath = ""
	endpoint.RawQuery = query.Encode()

	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("marshal Infisical KMS request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("Infisical KMS request: %w", err)
	}
	defer response.Body.Close()
	maxBody := c.MaxBody
	if maxBody <= 0 {
		maxBody = defaultMaxBody
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("read Infisical KMS response: %w", err)
	}
	if int64(len(data)) > maxBody {
		return ErrResponseTooLarge
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return parseAPIError(response.StatusCode, data)
	}
	if output == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, output); err != nil {
		return fmt.Errorf("decode Infisical KMS response: %w", err)
	}
	return nil
}

func parseAPIError(statusCode int, data []byte) error {
	var response struct {
		ReqID   string          `json:"reqId"`
		Message json.RawMessage `json:"message"`
		Error   string          `json:"error"`
	}
	_ = json.Unmarshal(data, &response)
	message := response.Error
	if len(response.Message) > 0 {
		var text string
		if json.Unmarshal(response.Message, &text) == nil {
			message = text
		} else if string(response.Message) != "null" {
			message = string(response.Message)
		}
	}
	return &APIError{StatusCode: statusCode, RequestID: response.ReqID, Message: message, Kind: response.Error}
}

func pathSegment(value string) (string, error) {
	if value == "" || strings.ContainsAny(value, "/?#") {
		return "", fmt.Errorf("key ID must be a non-empty path segment")
	}
	return url.PathEscape(value), nil
}
