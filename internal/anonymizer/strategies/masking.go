package strategies

import (
	"context"
	"strings"
	"unicode/utf8"
)

// MaskingStrategy replaces mid-sections of a value with asterisks while preserving
// prefix and suffix for usability (e.g. 010-****-5678 for mobile numbers).
type MaskingStrategy struct{}

func NewMasking() *MaskingStrategy { return &MaskingStrategy{} }

func (s *MaskingStrategy) Name() string     { return "partial_masking" }
func (s *MaskingStrategy) Reversible() bool { return false }

func (s *MaskingStrategy) Apply(_ context.Context, value string, p Params) (string, error) {
	switch {
	case isMobile(value):
		return maskMobile(value), nil
	case isCreditCard(value):
		return maskCreditCard(value), nil
	default:
		return maskGeneric(value, p.MaskPattern), nil
	}
}

func (s *MaskingStrategy) Reverse(_ context.Context, _ string, _ Params) (string, error) {
	return "", ErrNotReversible{Strategy: s.Name()}
}

// maskMobile produces 010-****-5678 format.
func maskMobile(v string) string {
	digits := stripNonDigits(v)
	if len(digits) < 10 {
		return strings.Repeat("*", utf8.RuneCountInString(v))
	}
	return digits[:3] + "-****-" + digits[len(digits)-4:]
}

// maskCreditCard produces 1234-****-****-3456 format.
func maskCreditCard(v string) string {
	digits := stripNonDigits(v)
	if len(digits) < 8 {
		return strings.Repeat("*", utf8.RuneCountInString(v))
	}
	return digits[:4] + "-****-****-" + digits[len(digits)-4:]
}

func maskGeneric(v, pattern string) string {
	if pattern != "" {
		return pattern
	}
	runes := []rune(v)
	n := len(runes)
	if n <= 2 {
		return strings.Repeat("*", n)
	}
	keep := n / 4
	if keep < 1 {
		keep = 1
	}
	masked := make([]rune, n)
	copy(masked, runes[:keep])
	for i := keep; i < n-keep; i++ {
		masked[i] = '*'
	}
	copy(masked[n-keep:], runes[n-keep:])
	return string(masked)
}

func isMobile(v string) bool {
	digits := stripNonDigits(v)
	return len(digits) >= 10 && strings.HasPrefix(digits, "01")
}

func isCreditCard(v string) bool {
	return len(stripNonDigits(v)) == 16
}

func stripNonDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
