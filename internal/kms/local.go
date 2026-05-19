package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// LocalProvider implements Provider using a local AES-256-GCM master key stored on disk.
// This is suitable for development and air-gapped environments; in production use AWS KMS
// or HashiCorp Vault instead.
type LocalProvider struct {
	masterKey []byte
	keyDir    string
}

// NewLocalProvider initialises the local KMS from a hex-encoded 32-byte master key.
// If masterKeyHex is empty it reads VAULT_LOCAL_MASTER_KEY from the environment.
func NewLocalProvider(keyDir, masterKeyHex string) (*LocalProvider, error) {
	if masterKeyHex == "" {
		masterKeyHex = os.Getenv("VAULT_LOCAL_MASTER_KEY")
	}
	if masterKeyHex == "" {
		return nil, fmt.Errorf("local KMS: master key not configured")
	}

	key, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("local KMS: decoding master key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("local KMS: master key must be 32 bytes, got %d", len(key))
	}

	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, fmt.Errorf("local KMS: creating key dir: %w", err)
	}

	return &LocalProvider{masterKey: key, keyDir: keyDir}, nil
}

func (p *LocalProvider) Name() string { return "local" }

func (p *LocalProvider) GenerateDataKey(ctx context.Context, keyID string) (*DataKey, error) {
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("local KMS: generating DEK: %w", err)
	}

	ciphertext, err := p.encryptWithMaster(dek)
	if err != nil {
		return nil, fmt.Errorf("local KMS: wrapping DEK: %w", err)
	}

	return &DataKey{
		Plaintext:  dek,
		Ciphertext: ciphertext,
		KeyID:      p.deriveSubKeyID(keyID),
		CreatedAt:  time.Now().UTC(),
	}, nil
}

func (p *LocalProvider) DecryptDataKey(ctx context.Context, ciphertext []byte, keyID string) ([]byte, error) {
	plaintext, err := p.decryptWithMaster(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("local KMS: unwrapping DEK: %w", err)
	}
	return plaintext, nil
}

// GenerateHMACKey derives a deterministic 32-byte HMAC key from the master key and keyID.
// Determinism is required so that tokenization of the same value always yields the same token.
func (p *LocalProvider) GenerateHMACKey(ctx context.Context, keyID string) ([]byte, error) {
	h := sha256.New()
	h.Write(p.masterKey)
	h.Write([]byte("hmac:"))
	h.Write([]byte(keyID))
	return h.Sum(nil), nil
}

func (p *LocalProvider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	subKey := p.deriveKeyMaterial(keyID)
	return p.gcmEncrypt(subKey, plaintext)
}

func (p *LocalProvider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	subKey := p.deriveKeyMaterial(keyID)
	return p.gcmDecrypt(subKey, ciphertext)
}

func (p *LocalProvider) DescribeKey(_ context.Context, keyID string) (*KeyInfo, error) {
	keyFile := filepath.Join(p.keyDir, keyID+".key")
	info, err := os.Stat(keyFile)
	if err != nil {
		return &KeyInfo{
			KeyID:       keyID,
			Description: "local-derived",
			State:       "active",
			CreatedAt:   time.Now().UTC(),
		}, nil
	}
	return &KeyInfo{
		KeyID:       keyID,
		Description: "local-file",
		State:       "active",
		CreatedAt:   info.ModTime().UTC(),
	}, nil
}

// deriveSubKeyID produces a short stable identifier for a derived key
func (p *LocalProvider) deriveSubKeyID(keyID string) string {
	h := sha256.Sum256(append(p.masterKey, []byte(keyID)...))
	return hex.EncodeToString(h[:8])
}

// deriveKeyMaterial derives a 32-byte sub-key deterministically from master + keyID
func (p *LocalProvider) deriveKeyMaterial(keyID string) []byte {
	h := sha256.New()
	h.Write(p.masterKey)
	h.Write([]byte("enc:"))
	h.Write([]byte(keyID))
	return h.Sum(nil)
}

func (p *LocalProvider) encryptWithMaster(plaintext []byte) ([]byte, error) {
	return p.gcmEncrypt(p.masterKey, plaintext)
}

func (p *LocalProvider) decryptWithMaster(ciphertext []byte) ([]byte, error) {
	return p.gcmDecrypt(p.masterKey, ciphertext)
}

func (p *LocalProvider) gcmEncrypt(key, plaintext []byte) ([]byte, error) {
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

func (p *LocalProvider) gcmDecrypt(key, ciphertext []byte) ([]byte, error) {
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
