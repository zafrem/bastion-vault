package strategies

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// HMACStrategy applies a one-way HMAC-SHA256 hash to the value.
// Used for Korean RRN per SRS §3.3 to prevent reconstruction while
// allowing exact-match queries.
type HMACStrategy struct{}

func NewHMAC() *HMACStrategy { return &HMACStrategy{} }

func (s *HMACStrategy) Name() string     { return "hmac_sha256" }
func (s *HMACStrategy) Reversible() bool { return false }

func (s *HMACStrategy) Apply(_ context.Context, value string, p Params) (string, error) {
	if len(p.HMACKey) == 0 {
		return "", fmt.Errorf("hmac_sha256: HMAC key required")
	}
	mac := hmac.New(sha256.New, p.HMACKey)
	mac.Write([]byte(value))
	return "HMAC:" + hex.EncodeToString(mac.Sum(nil)), nil
}

func (s *HMACStrategy) Reverse(_ context.Context, _ string, _ Params) (string, error) {
	return "", ErrNotReversible{Strategy: s.Name()}
}
