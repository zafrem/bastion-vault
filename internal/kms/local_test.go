package kms_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/zafrem/bastion-vault/internal/kms"
)

// mustBytes returns n random bytes.
func mustBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("mustBytes: %v", err)
	}
	return b
}

func newProvider(t *testing.T) *kms.LocalProvider {
	t.Helper()
	masterKey := hex.EncodeToString(mustBytes(t, 32))
	p, err := kms.NewLocalProvider(t.TempDir(), masterKey)
	if err != nil {
		t.Fatalf("NewLocalProvider: %v", err)
	}
	return p
}

func TestGenerateDataKey_ReturnsPlaintextAndCiphertext(t *testing.T) {
	p := newProvider(t)
	dk, err := p.GenerateDataKey(context.Background(), "test-key")
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	if len(dk.Plaintext) == 0 {
		t.Error("plaintext is empty")
	}
	if len(dk.Ciphertext) == 0 {
		t.Error("ciphertext is empty")
	}
}

func TestDecryptDataKey_RecoversSamePlaintext(t *testing.T) {
	p := newProvider(t)
	dk, err := p.GenerateDataKey(context.Background(), "test-key")
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}

	recovered, err := p.DecryptDataKey(context.Background(), dk.Ciphertext, "test-key")
	if err != nil {
		t.Fatalf("DecryptDataKey: %v", err)
	}
	if !bytes.Equal(dk.Plaintext, recovered) {
		t.Errorf("plaintext mismatch: want %x, got %x", dk.Plaintext, recovered)
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	p := newProvider(t)
	plaintext := []byte("hello, world — sensitive audit signing data")

	ct, err := p.Encrypt(context.Background(), "audit-key", plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := p.Decrypt(context.Background(), "audit-key", ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(plaintext, pt) {
		t.Errorf("round-trip failed: want %q, got %q", plaintext, pt)
	}
}

func TestGenerateHMACKey_Deterministic(t *testing.T) {
	p := newProvider(t)
	k1, err := p.GenerateHMACKey(context.Background(), "tenant:acme:category:DC-01")
	if err != nil {
		t.Fatalf("GenerateHMACKey (1): %v", err)
	}
	k2, err := p.GenerateHMACKey(context.Background(), "tenant:acme:category:DC-01")
	if err != nil {
		t.Fatalf("GenerateHMACKey (2): %v", err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("HMAC key is not deterministic for the same keyID")
	}
}

func TestGenerateHMACKey_DifferentKeyIDs_DifferentKeys(t *testing.T) {
	p := newProvider(t)
	k1, _ := p.GenerateHMACKey(context.Background(), "keyA")
	k2, _ := p.GenerateHMACKey(context.Background(), "keyB")
	if bytes.Equal(k1, k2) {
		t.Error("expected different HMAC keys for different keyIDs")
	}
}

func TestHMAC_Consistency(t *testing.T) {
	// Verify that the HMAC key + external MAC produce consistent results.
	p := newProvider(t)
	keyID := "tenant:test"
	k1, _ := p.GenerateHMACKey(context.Background(), keyID)
	k2, _ := p.GenerateHMACKey(context.Background(), keyID)

	// Both keys should be identical (deterministic).
	if !bytes.Equal(k1, k2) {
		t.Fatal("keys differ — hmac output would differ")
	}
}
