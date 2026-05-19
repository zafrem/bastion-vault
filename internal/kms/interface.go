package kms

import (
	"context"
	"time"
)

// DataKey holds a plaintext DEK alongside its encrypted form.
// The plaintext must be zeroized after use; the ciphertext is safe to persist.
type DataKey struct {
	Plaintext  []byte
	Ciphertext []byte
	KeyID      string
	CreatedAt  time.Time
}

// KeyInfo describes a key managed by the KMS provider
type KeyInfo struct {
	KeyID       string    `json:"key_id"`
	Description string    `json:"description"`
	State       string    `json:"state"`
	CreatedAt   time.Time `json:"created_at"`
	RotatedAt   time.Time `json:"rotated_at,omitempty"`
}

// Provider is the abstraction over AWS KMS, HashiCorp Vault, and the local file backend.
// All methods must be safe for concurrent use.
type Provider interface {
	// GenerateDataKey produces a new DEK encrypted under the named master key.
	GenerateDataKey(ctx context.Context, keyID string) (*DataKey, error)

	// DecryptDataKey decrypts a previously generated DEK ciphertext.
	DecryptDataKey(ctx context.Context, ciphertext []byte, keyID string) ([]byte, error)

	// GenerateHMACKey returns raw HMAC key material under the named master key.
	GenerateHMACKey(ctx context.Context, keyID string) ([]byte, error)

	// Encrypt encrypts arbitrary plaintext under the named key (for audit signing).
	Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext produced by Encrypt.
	Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error)

	// DescribeKey returns metadata for the named key.
	DescribeKey(ctx context.Context, keyID string) (*KeyInfo, error)

	// Name returns the provider identifier ("local", "aws", "vault")
	Name() string
}
