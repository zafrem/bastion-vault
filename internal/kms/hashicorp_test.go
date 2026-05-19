package kms

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// vaultResponse writes a Vault-style JSON body {"data": ...}.
func vaultData(w http.ResponseWriter, data map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func TestHashiCorpProvider_GenerateDataKey(t *testing.T) {
	plaintext := []byte("0123456789abcdef0123456789abcdef")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vaultData(w, map[string]any{
			"plaintext":  base64.StdEncoding.EncodeToString(plaintext),
			"ciphertext": "vault:v1:abc",
		})
	}))
	defer srv.Close()

	p := NewHashiCorpProvider(srv.URL, "token", "transit")
	dk, err := p.GenerateDataKey(context.Background(), "tenant-key")
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	if string(dk.Plaintext) != string(plaintext) {
		t.Errorf("plaintext = %q, want %q", dk.Plaintext, plaintext)
	}
	if string(dk.Ciphertext) != "vault:v1:abc" {
		t.Errorf("ciphertext = %q, want vault:v1:abc", dk.Ciphertext)
	}
}

func TestHashiCorpProvider_DecryptDataKey(t *testing.T) {
	plaintext := []byte("decrypted-dek-material")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vaultData(w, map[string]any{
			"plaintext": base64.StdEncoding.EncodeToString(plaintext),
		})
	}))
	defer srv.Close()

	p := NewHashiCorpProvider(srv.URL, "token", "transit")
	pt, err := p.DecryptDataKey(context.Background(), []byte("vault:v1:abc"), "tenant-key")
	if err != nil {
		t.Fatalf("DecryptDataKey: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Errorf("plaintext = %q, want %q", pt, plaintext)
	}
}

func TestHashiCorpProvider_GenerateHMACKey(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vaultData(w, map[string]any{
			"hmac": "vault:v1:" + base64.StdEncoding.EncodeToString(raw),
		})
	}))
	defer srv.Close()

	p := NewHashiCorpProvider(srv.URL, "token", "transit")
	key, err := p.GenerateHMACKey(context.Background(), "audit-key")
	if err != nil {
		t.Fatalf("GenerateHMACKey: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("HMAC key length = %d, want 32", len(key))
	}
}

func TestHashiCorpProvider_EncryptDecrypt(t *testing.T) {
	original := []byte("secret-payload")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch {
		case body["plaintext"] != nil:
			// Encrypt request.
			vaultData(w, map[string]any{"ciphertext": "vault:v1:" + body["plaintext"].(string)})
		case body["ciphertext"] != nil:
			// Decrypt request — the ciphertext carries the original base64 plaintext.
			ct := body["ciphertext"].(string)
			vaultData(w, map[string]any{"plaintext": ct[len("vault:v1:"):]})
		default:
			http.Error(w, "bad request", http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	p := NewHashiCorpProvider(srv.URL, "token", "transit")
	ct, err := p.Encrypt(context.Background(), "k", original)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := p.Decrypt(context.Background(), "k", ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != string(original) {
		t.Errorf("round-trip plaintext = %q, want %q", pt, original)
	}
}

func TestSanitizeKeyName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"simple", "simple"},
		{"tenant:acme:category:DC-01", "tenant-acme-category-DC-01"},
		{"path/to/key", "path-to-key"},
		{"key with spaces", "key-with-spaces"},
		{"mixed:slash/and space", "mixed-slash-and-space"},
	}
	for _, c := range cases {
		if got := sanitizeKeyName(c.in); got != c.want {
			t.Errorf("sanitizeKeyName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHashiCorpProvider_ErrorPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := NewHashiCorpProvider(srv.URL, "token", "transit")
	if _, err := p.GenerateDataKey(context.Background(), "tenant-key"); err == nil {
		t.Fatal("expected error on 500 response, got nil")
	}
}
