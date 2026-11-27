package strategies

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	encryptedPrefix = "ENC:"
	// encryptedV1 marks values that carry their wrapped data key. Base64url has no ':', so it cannot be
	// confused with the unversioned values of earlier releases.
	encryptedV1 = encryptedPrefix + "v1:"
)

// ErrKeyNotKept reports a value written by a release that encrypted with a data key it never saved.
var ErrKeyNotKept = errors.New("encryption: this value was written by an earlier version, which did not keep its " +
	"data key; it cannot be decrypted and has to be anonymized again from the source")

// ValueCipher encrypts the values of one tenant and category. What Encrypt returns must be enough, together
// with the KMS, to decrypt later.
type ValueCipher interface {
	Encrypt(ctx context.Context, plain []byte) ([]byte, error)
	Decrypt(ctx context.Context, sealed []byte) ([]byte, error)
}

// EncryptionStrategy applies authenticated encryption to a field value.
// Used for salary data per SRS §3.3 where the value must remain recoverable by
// authorised roles (HR Manager) but opaque to all others.
type EncryptionStrategy struct{}

func NewEncryption() *EncryptionStrategy { return &EncryptionStrategy{} }

func (s *EncryptionStrategy) Name() string     { return "encryption" }
func (s *EncryptionStrategy) Reversible() bool { return true }

func (s *EncryptionStrategy) Apply(ctx context.Context, value string, p Params) (string, error) {
	if p.Cipher == nil {
		return "", fmt.Errorf("encryption: cipher required")
	}
	sealed, err := p.Cipher.Encrypt(ctx, []byte(value))
	if err != nil {
		return "", fmt.Errorf("encryption: %w", err)
	}
	return encryptedV1 + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *EncryptionStrategy) Reverse(ctx context.Context, value string, p Params) (string, error) {
	if p.Cipher == nil {
		return "", fmt.Errorf("encryption: cipher required for decryption")
	}
	body, current := strings.CutPrefix(value, encryptedV1)
	if !current {
		if old, ok := strings.CutPrefix(value, encryptedPrefix); ok && old != "" && !strings.Contains(old, ":") {
			return "", ErrKeyNotKept
		}
		return "", fmt.Errorf("encryption: not an encrypted value")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return "", fmt.Errorf("encryption: base64 decode: %w", err)
	}
	plain, err := p.Cipher.Decrypt(ctx, sealed)
	if err != nil {
		return "", fmt.Errorf("encryption: %w", err)
	}
	return string(plain), nil
}
