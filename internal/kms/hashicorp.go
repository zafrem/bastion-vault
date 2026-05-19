package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HashiCorpProvider implements Provider using the HashiCorp Vault transit engine.
// All requests use the Vault HTTP API (no extra SDK dependency).
type HashiCorpProvider struct {
	client    *http.Client
	address   string // e.g. "https://vault.example.com:8200"
	token     string // Vault token (X-Vault-Token header)
	mountPath string // transit mount path, e.g. "transit"
	keyName   string // name of the transit key
}

// NewHashiCorpProvider creates a HashiCorpProvider.
// address is the Vault server URL; token is the Vault token; mountPath is the transit mount (e.g. "transit").
// The key name is derived from the masterKeyID passed to each operation.
func NewHashiCorpProvider(address, token, mountPath string) *HashiCorpProvider {
	return &HashiCorpProvider{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		address:   strings.TrimRight(address, "/"),
		token:     token,
		mountPath: mountPath,
	}
}

func (p *HashiCorpProvider) Name() string { return "vault" }

// GenerateDataKey generates a new plaintext data key using the Vault transit datakey endpoint.
func (p *HashiCorpProvider) GenerateDataKey(ctx context.Context, keyID string) (*DataKey, error) {
	keyName := sanitizeKeyName(keyID)
	url := fmt.Sprintf("%s/v1/%s/datakey/plaintext/%s", p.address, p.mountPath, keyName)

	resp, err := p.post(ctx, url, nil)
	if err != nil {
		return nil, fmt.Errorf("vault kms: GenerateDataKey: %w", err)
	}

	data, ok := resp["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("vault kms: GenerateDataKey: unexpected response format")
	}

	plaintextB64, _ := data["plaintext"].(string)
	ciphertext, _ := data["ciphertext"].(string)

	plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, fmt.Errorf("vault kms: GenerateDataKey: decoding plaintext: %w", err)
	}

	return &DataKey{
		Plaintext:  plaintext,
		Ciphertext: []byte(ciphertext),
		KeyID:      keyName,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// DecryptDataKey decrypts a previously generated DEK ciphertext.
func (p *HashiCorpProvider) DecryptDataKey(ctx context.Context, ciphertext []byte, keyID string) ([]byte, error) {
	return p.Decrypt(ctx, keyID, ciphertext)
}

// GenerateHMACKey computes an HMAC over the keyID using the Vault transit HMAC endpoint.
func (p *HashiCorpProvider) GenerateHMACKey(ctx context.Context, keyID string) ([]byte, error) {
	keyName := sanitizeKeyName(keyID)
	url := fmt.Sprintf("%s/v1/%s/hmac/%s", p.address, p.mountPath, keyName)

	body := map[string]any{
		"input":     base64.StdEncoding.EncodeToString([]byte(keyID)),
		"algorithm": "sha2-256",
	}

	resp, err := p.post(ctx, url, body)
	if err != nil {
		return nil, fmt.Errorf("vault kms: GenerateHMACKey: %w", err)
	}

	data, ok := resp["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("vault kms: GenerateHMACKey: unexpected response format")
	}

	hmacVal, _ := data["hmac"].(string)
	// vault:v1:<base64> — strip the prefix and decode.
	parts := strings.SplitN(hmacVal, ":", 3)
	var raw []byte
	if len(parts) == 3 {
		raw, err = base64.StdEncoding.DecodeString(parts[2])
		if err != nil {
			raw = []byte(hmacVal)
		}
	} else {
		raw = []byte(hmacVal)
	}

	// Ensure key material is at least 32 bytes.
	if len(raw) < 32 {
		padded := make([]byte, 32)
		copy(padded, raw)
		return padded, nil
	}
	return raw[:32], nil
}

// Encrypt encrypts plaintext using the Vault transit encrypt endpoint.
func (p *HashiCorpProvider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	keyName := sanitizeKeyName(keyID)
	url := fmt.Sprintf("%s/v1/%s/encrypt/%s", p.address, p.mountPath, keyName)

	body := map[string]any{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	}

	resp, err := p.post(ctx, url, body)
	if err != nil {
		return nil, fmt.Errorf("vault kms: Encrypt: %w", err)
	}

	data, ok := resp["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("vault kms: Encrypt: unexpected response format")
	}

	ciphertext, _ := data["ciphertext"].(string)
	return []byte(ciphertext), nil
}

// Decrypt decrypts ciphertext using the Vault transit decrypt endpoint.
func (p *HashiCorpProvider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	keyName := sanitizeKeyName(keyID)
	url := fmt.Sprintf("%s/v1/%s/decrypt/%s", p.address, p.mountPath, keyName)

	body := map[string]any{
		"ciphertext": string(ciphertext),
	}

	resp, err := p.post(ctx, url, body)
	if err != nil {
		return nil, fmt.Errorf("vault kms: Decrypt: %w", err)
	}

	data, ok := resp["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("vault kms: Decrypt: unexpected response format")
	}

	plaintextB64, _ := data["plaintext"].(string)
	pt, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, fmt.Errorf("vault kms: Decrypt: decoding plaintext: %w", err)
	}
	return pt, nil
}

// DescribeKey returns metadata by querying the transit key endpoint.
func (p *HashiCorpProvider) DescribeKey(ctx context.Context, keyID string) (*KeyInfo, error) {
	keyName := sanitizeKeyName(keyID)
	url := fmt.Sprintf("%s/v1/%s/keys/%s", p.address, p.mountPath, keyName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("vault kms: DescribeKey: building request: %w", err)
	}
	req.Header.Set("X-Vault-Token", p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault kms: DescribeKey: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault kms: DescribeKey: status %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("vault kms: DescribeKey: decoding response: %w", err)
	}

	return &KeyInfo{
		KeyID:       keyID,
		Description: "hashicorp-vault-transit",
		State:       "active",
		CreatedAt:   time.Now().UTC(),
	}, nil
}

// post sends a POST request with the given JSON body and returns the parsed response.
func (p *HashiCorpProvider) post(ctx context.Context, url string, body any) (map[string]any, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshalling request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("X-Vault-Token", p.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(b))
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return result, nil
}

// sanitizeKeyName replaces characters that are invalid in Vault key names.
func sanitizeKeyName(keyID string) string {
	r := strings.NewReplacer(":", "-", "/", "-", " ", "-")
	return r.Replace(keyID)
}
