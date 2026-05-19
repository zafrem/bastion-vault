package strategies

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/zafrem/bastion-vault/internal/tokendb"
)

// TokenizationStrategy implements deterministic tokenization using HMAC-SHA256.
// The same input always produces the same token, enabling joins on tokenized data.
// When a tokendb.Store is provided, mappings are persisted so that Reverse() can
// recover the original value; without a store Reverse() returns ErrNotReversible.
type TokenizationStrategy struct {
	store tokendb.Store
}

func NewTokenization() *TokenizationStrategy { return &TokenizationStrategy{} }

// WithStore attaches a token registry; the strategy becomes reversible via lookup.
func (s *TokenizationStrategy) WithStore(st tokendb.Store) *TokenizationStrategy {
	s.store = st
	return s
}

func (s *TokenizationStrategy) Name() string     { return "deterministic_tokenization" }
func (s *TokenizationStrategy) Reversible() bool { return s.store != nil }

func (s *TokenizationStrategy) Apply(ctx context.Context, value string, p Params) (string, error) {
	if len(p.HMACKey) == 0 {
		return "", fmt.Errorf("tokenization: HMAC key required")
	}
	mac := hmac.New(sha256.New, p.HMACKey)
	mac.Write([]byte(value))
	sum := mac.Sum(nil)
	// Use URL-safe base64 without padding; truncate to 22 chars for readability
	token := base64.RawURLEncoding.EncodeToString(sum)
	if len(token) > 22 {
		token = token[:22]
	}
	tok := "TOK:" + token

	if s.store != nil {
		entry := tokendb.Entry{
			Token:     token,
			Original:  value,
			TenantID:  p.TenantID,
			PIIType:   p.FieldHint,
			CreatedAt: time.Now().UTC(),
		}
		if err := s.store.Put(ctx, entry); err != nil {
			// Non-fatal: log would go here in production; continue with the token.
			_ = err
		}
	}

	return tok, nil
}

// Reverse reconstructs the original value from the token registry.
// If no store is configured it returns ErrNotReversible.
func (s *TokenizationStrategy) Reverse(ctx context.Context, value string, p Params) (string, error) {
	if s.store == nil {
		return "", ErrNotReversible{Strategy: s.Name()}
	}
	// Strip the "TOK:" prefix before looking up.
	tok := value
	if strings.HasPrefix(tok, "TOK:") {
		tok = tok[4:]
	}
	entry, err := s.store.Get(ctx, tok, p.TenantID)
	if err != nil {
		return "", fmt.Errorf("tokenization: store lookup: %w", err)
	}
	if entry == nil {
		return "", fmt.Errorf("tokenization: token not found in registry")
	}
	return entry.Original, nil
}
