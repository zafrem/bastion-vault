package strategies

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// EncryptionStrategy applies AES-256-GCM authenticated encryption to a field value.
// Used for salary data per SRS §3.3 where the value must remain recoverable by
// authorised roles (HR Manager) but opaque to all others.
type EncryptionStrategy struct{}

func NewEncryption() *EncryptionStrategy { return &EncryptionStrategy{} }

func (s *EncryptionStrategy) Name() string     { return "encryption" }
func (s *EncryptionStrategy) Reversible() bool { return true }

func (s *EncryptionStrategy) Apply(_ context.Context, value string, p Params) (string, error) {
	if len(p.EncryptionKey) == 0 {
		return "", fmt.Errorf("encryption: key required")
	}
	ct, err := gcmEncrypt(p.EncryptionKey, []byte(value))
	if err != nil {
		return "", fmt.Errorf("encryption: %w", err)
	}
	return "ENC:" + base64.RawURLEncoding.EncodeToString(ct), nil
}

func (s *EncryptionStrategy) Reverse(_ context.Context, value string, p Params) (string, error) {
	if len(p.EncryptionKey) == 0 {
		return "", fmt.Errorf("encryption: key required for decryption")
	}
	const prefix = "ENC:"
	if len(value) <= len(prefix) {
		return "", fmt.Errorf("encryption: not an encrypted value")
	}
	ct, err := base64.RawURLEncoding.DecodeString(value[len(prefix):])
	if err != nil {
		return "", fmt.Errorf("encryption: base64 decode: %w", err)
	}
	pt, err := gcmDecrypt(p.EncryptionKey, ct)
	if err != nil {
		return "", fmt.Errorf("encryption: %w", err)
	}
	return string(pt), nil
}

func gcmEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func gcmDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}
