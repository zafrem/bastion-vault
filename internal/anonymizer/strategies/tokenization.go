package strategies

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// TokenizationStrategy implements deterministic tokenization using HMAC-SHA256.
// The same input always produces the same token, enabling joins on tokenized data.
// Reversibility requires a token registry (external store); the strategy itself is
// not directly reversible without that lookup.
type TokenizationStrategy struct{}

func NewTokenization() *TokenizationStrategy { return &TokenizationStrategy{} }

func (s *TokenizationStrategy) Name() string       { return "deterministic_tokenization" }
func (s *TokenizationStrategy) Reversible() bool   { return true }

func (s *TokenizationStrategy) Apply(_ context.Context, value string, p Params) (string, error) {
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
	return "TOK:" + token, nil
}

// Reverse cannot reconstruct the original value from the token alone;
// the caller must perform a reverse-lookup against the token registry.
func (s *TokenizationStrategy) Reverse(_ context.Context, value string, _ Params) (string, error) {
	return "", ErrNotReversible{Strategy: s.Name()}
}
