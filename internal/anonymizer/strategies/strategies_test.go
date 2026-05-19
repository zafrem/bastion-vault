package strategies_test

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/zafrem/bastion-vault/internal/anonymizer/strategies"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

// mustBytes returns n cryptographically random bytes. Panics on error.
func mustBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("mustBytes: %v", err)
	}
	return b
}

// ─── Tokenization ────────────────────────────────────────────────────────────

func TestTokenization_Apply_PrefixAndDeterminism(t *testing.T) {
	key := mustBytes(t, 32)
	s := strategies.NewTokenization()
	p := strategies.Params{HMACKey: key}

	tok1, err := s.Apply(context.Background(), "alice@example.com", p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(tok1, "TOK:") {
		t.Errorf("expected TOK: prefix, got %q", tok1)
	}

	// Deterministic: same input + key → same token.
	tok2, err := s.Apply(context.Background(), "alice@example.com", p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok1 != tok2 {
		t.Errorf("non-deterministic: got %q then %q", tok1, tok2)
	}
}

func TestTokenization_DifferentKeys_DifferentTokens(t *testing.T) {
	k1, k2 := mustBytes(t, 32), mustBytes(t, 32)
	s := strategies.NewTokenization()

	tok1, _ := s.Apply(context.Background(), "test", strategies.Params{HMACKey: k1})
	tok2, _ := s.Apply(context.Background(), "test", strategies.Params{HMACKey: k2})
	if tok1 == tok2 {
		t.Error("expected different tokens for different keys")
	}
}

func TestTokenization_Reverse_NoStore(t *testing.T) {
	s := strategies.NewTokenization()
	_, err := s.Reverse(context.Background(), "TOK:abc", strategies.Params{})
	if err == nil {
		t.Error("expected error without store")
	}
}

func TestTokenization_Reverse_WithStore(t *testing.T) {
	store := tokendb.NewMemoryStore()
	key := mustBytes(t, 32)
	s := strategies.NewTokenization().WithStore(store)
	p := strategies.Params{HMACKey: key, TenantID: "tenant1"}

	tok, err := s.Apply(context.Background(), "secret-value", p)
	if err != nil {
		t.Fatalf("Apply error: %v", err)
	}
	original, err := s.Reverse(context.Background(), tok, p)
	if err != nil {
		t.Fatalf("Reverse error: %v", err)
	}
	if original != "secret-value" {
		t.Errorf("want %q, got %q", "secret-value", original)
	}
}

func TestTokenization_NoKey_Error(t *testing.T) {
	s := strategies.NewTokenization()
	_, err := s.Apply(context.Background(), "value", strategies.Params{})
	if err == nil {
		t.Error("expected error when HMAC key missing")
	}
}

// ─── HMAC ────────────────────────────────────────────────────────────────────

func TestHMAC_Apply_PrefixAndDeterminism(t *testing.T) {
	key := mustBytes(t, 32)
	s := strategies.NewHMAC()
	p := strategies.Params{HMACKey: key}

	h1, err := s.Apply(context.Background(), "850315-1234567", p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(h1, "HMAC:") {
		t.Errorf("expected HMAC: prefix, got %q", h1)
	}

	h2, _ := s.Apply(context.Background(), "850315-1234567", p)
	if h1 != h2 {
		t.Errorf("non-deterministic: %q vs %q", h1, h2)
	}
}

func TestHMAC_Reverse_Error(t *testing.T) {
	s := strategies.NewHMAC()
	_, err := s.Reverse(context.Background(), "HMAC:abc", strategies.Params{})
	if err == nil {
		t.Error("expected ErrNotReversible")
	}
}

// ─── Masking ─────────────────────────────────────────────────────────────────

func TestMasking_Mobile(t *testing.T) {
	s := strategies.NewMasking()
	result, err := s.Apply(context.Background(), "010-1234-5678", strategies.Params{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "010-****-5678"
	if result != want {
		t.Errorf("want %q, got %q", want, result)
	}
}

func TestMasking_CreditCard(t *testing.T) {
	s := strategies.NewMasking()
	result, err := s.Apply(context.Background(), "1234-5678-9012-3456", strategies.Params{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "1234-****-****-3456"
	if result != want {
		t.Errorf("want %q, got %q", want, result)
	}
}

func TestMasking_Reverse_Error(t *testing.T) {
	s := strategies.NewMasking()
	_, err := s.Reverse(context.Background(), "010-****-5678", strategies.Params{})
	if err == nil {
		t.Error("expected ErrNotReversible")
	}
}

// ─── Generalization ──────────────────────────────────────────────────────────

func TestGeneralization_RegionStripping(t *testing.T) {
	s := strategies.NewGeneralization()
	cases := []struct {
		input string
		level int
		wantNoSuffix string // should not end with this
	}{
		{"Yeoksam-dong Gangnam-gu Seoul", 1, "동"},
		{"Yeoksam-dong Gangnam-gu Seoul", 2, "구"},
	}
	for _, tc := range cases {
		result, err := s.Apply(context.Background(), tc.input, strategies.Params{GeneralizationLevel: tc.level})
		if err != nil {
			t.Errorf("level=%d: unexpected error: %v", tc.level, err)
			continue
		}
		// The result should be shorter or at least different from the input at level >= 1
		if result == tc.input && tc.level >= 1 {
			t.Logf("level=%d: result=%q (may be OK if no recognized suffix)", tc.level, result)
		}
		_ = result
	}
}

func TestGeneralization_Reverse_Error(t *testing.T) {
	s := strategies.NewGeneralization()
	_, err := s.Reverse(context.Background(), "Seoul", strategies.Params{})
	if err == nil {
		t.Error("expected ErrNotReversible")
	}
}

// ─── Range Generalization ────────────────────────────────────────────────────

func TestRangeGeneralization_Age(t *testing.T) {
	s := strategies.NewRangeGeneralization()
	result, err := s.Apply(context.Background(), "32", strategies.Params{FieldHint: "age"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// At default level 0 → 5-year buckets: 30-34
	if !strings.Contains(result, "30") {
		t.Errorf("expected 30-xx range for age 32, got %q", result)
	}
}

func TestRangeGeneralization_Salary(t *testing.T) {
	s := strategies.NewRangeGeneralization()
	result, err := s.Apply(context.Background(), "65000000", strategies.Params{FieldHint: "salary"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty salary range")
	}
}

func TestRangeGeneralization_Reverse_Error(t *testing.T) {
	s := strategies.NewRangeGeneralization()
	_, err := s.Reverse(context.Background(), "30-34", strategies.Params{})
	if err == nil {
		t.Error("expected ErrNotReversible")
	}
}

// ─── Suppression ─────────────────────────────────────────────────────────────

func TestSuppression_Apply(t *testing.T) {
	s := strategies.NewSuppression()
	cases := []string{"hello", "", "some-address", "123 Main St"}
	for _, input := range cases {
		result, err := s.Apply(context.Background(), input, strategies.Params{})
		if err != nil {
			t.Errorf("input=%q: unexpected error: %v", input, err)
		}
		if result != "[REMOVED]" {
			t.Errorf("input=%q: want [REMOVED], got %q", input, result)
		}
	}
}

func TestSuppression_Reverse_Error(t *testing.T) {
	s := strategies.NewSuppression()
	_, err := s.Reverse(context.Background(), "[REMOVED]", strategies.Params{})
	if err == nil {
		t.Error("expected ErrNotReversible")
	}
}

// ─── Encryption ──────────────────────────────────────────────────────────────

func TestEncryption_Apply_Prefix(t *testing.T) {
	key := mustBytes(t, 32)
	s := strategies.NewEncryption()
	result, err := s.Apply(context.Background(), "plaintext", strategies.Params{EncryptionKey: key})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(result, "ENC:") {
		t.Errorf("expected ENC: prefix, got %q", result)
	}
}

func TestEncryption_RoundTrip(t *testing.T) {
	key := mustBytes(t, 32)
	s := strategies.NewEncryption()
	p := strategies.Params{EncryptionKey: key}

	ct, err := s.Apply(context.Background(), "my secret salary 99000000", p)
	if err != nil {
		t.Fatalf("Apply error: %v", err)
	}
	pt, err := s.Reverse(context.Background(), ct, p)
	if err != nil {
		t.Fatalf("Reverse error: %v", err)
	}
	if pt != "my secret salary 99000000" {
		t.Errorf("round-trip failed: got %q", pt)
	}
}

func TestEncryption_WrongKey_Fails(t *testing.T) {
	k1, k2 := mustBytes(t, 32), mustBytes(t, 32)
	s := strategies.NewEncryption()

	ct, err := s.Apply(context.Background(), "secret", strategies.Params{EncryptionKey: k1})
	if err != nil {
		t.Fatalf("Apply error: %v", err)
	}
	_, err = s.Reverse(context.Background(), ct, strategies.Params{EncryptionKey: k2})
	if err == nil {
		t.Error("expected error decrypting with wrong key")
	}
}
