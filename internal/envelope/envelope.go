// Package envelope encrypts values so that they can be read back for as long as the KMS master key exists.
//
// A data key from the KMS encrypts the value, and the data key, wrapped by the master key, travels with the
// ciphertext. Decrypting needs only the sealed bytes and the KMS, so it works after a restart and on any replica.
//
// Sealed form: uint16 length of the wrapped key | wrapped key | nonce | AES-256-GCM ciphertext.
package envelope

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/zafrem/bastion-vault/internal/kms"
)

const (
	defaultKeyTTL = 5 * time.Minute
	maxCachedKeys = 1024
	dataKeyBytes  = 32
)

var errTruncated = errors.New("the sealed value is truncated")

// Keys is the part of a KMS provider (or of kms.Manager) that envelope encryption needs.
type Keys interface {
	GenerateDataKey(ctx context.Context, keyID string) (*kms.DataKey, error)
	DecryptDataKey(ctx context.Context, ciphertext []byte, keyID string) ([]byte, error)
}

type cachedKey struct {
	aead    cipher.AEAD
	wrapped []byte
	expires time.Time
}

// Sealer seals and opens values. It reuses data keys for a limited time, because a cloud KMS is billed and
// rate limited per call. It is safe for concurrent use.
type Sealer struct {
	keys Keys
	ttl  time.Duration

	mu      sync.Mutex
	sealing map[string]cachedKey // key id → the data key new values are sealed with
	opening map[string]cachedKey // key id + wrapped key → unwrapped data key
}

// New returns a Sealer that reuses each data key for ttl (default 5 minutes).
func New(keys Keys, ttl time.Duration) *Sealer {
	if ttl <= 0 {
		ttl = defaultKeyTTL
	}
	return &Sealer{keys: keys, ttl: ttl, sealing: map[string]cachedKey{}, opening: map[string]cachedKey{}}
}

// Seal encrypts plain under the named master key. boundData is authenticated but not stored: Open needs the
// same bytes, which ties the result to its context.
func (s *Sealer) Seal(ctx context.Context, keyID string, boundData, plain []byte) ([]byte, error) {
	key, ok := s.cached(s.sealing, keyID)
	if !ok {
		dk, err := s.keys.GenerateDataKey(ctx, keyID)
		if err != nil {
			return nil, err
		}
		if key, err = s.newCachedKey(dk.Plaintext, dk.Ciphertext); err != nil {
			return nil, err
		}
		if len(key.wrapped) == 0 || len(key.wrapped) > 0xffff {
			return nil, fmt.Errorf("the KMS returned a wrapped key of %d bytes", len(key.wrapped))
		}
		s.remember(s.sealing, keyID, key)
	}
	nonce := make([]byte, key.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(len(key.wrapped))) // #nosec G115 -- bounded above
	out = append(append(out, key.wrapped...), nonce...)
	return key.aead.Seal(out, nonce, plain, boundData), nil
}

// Open decrypts a value produced by Seal with the same key id and bound data.
func (s *Sealer) Open(ctx context.Context, keyID string, boundData, sealed []byte) ([]byte, error) {
	if len(sealed) < 2 {
		return nil, errTruncated
	}
	n := int(binary.BigEndian.Uint16(sealed))
	rest := sealed[2:]
	if n == 0 || len(rest) < n {
		return nil, errTruncated
	}
	wrapped, rest := rest[:n], rest[n:]

	cacheKey := keyID + "\x00" + string(wrapped)
	key, ok := s.cached(s.opening, cacheKey)
	if !ok {
		plain, err := s.keys.DecryptDataKey(ctx, wrapped, keyID)
		if err != nil {
			return nil, err
		}
		if key, err = s.newCachedKey(plain, wrapped); err != nil {
			return nil, err
		}
		s.remember(s.opening, cacheKey, key)
	}
	if len(rest) < key.aead.NonceSize() {
		return nil, errTruncated
	}
	nonce, ct := rest[:key.aead.NonceSize()], rest[key.aead.NonceSize():]
	return key.aead.Open(nil, nonce, ct, boundData)
}

// newCachedKey builds the cipher and wipes the raw key.
func (s *Sealer) newCachedKey(plain, wrapped []byte) (cachedKey, error) {
	defer clear(plain)
	if len(plain) != dataKeyBytes {
		return cachedKey{}, fmt.Errorf("the KMS returned a %d-byte data key, want %d", len(plain), dataKeyBytes)
	}
	block, err := aes.NewCipher(plain)
	if err != nil {
		return cachedKey{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return cachedKey{}, err
	}
	return cachedKey{aead: aead, wrapped: bytes.Clone(wrapped), expires: time.Now().Add(s.ttl)}, nil
}

func (s *Sealer) cached(m map[string]cachedKey, k string) (cachedKey, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := m[k]
	if ok && !time.Now().Before(c.expires) {
		delete(m, k)
		ok = false
	}
	return c, ok
}

func (s *Sealer) remember(m map[string]cachedKey, k string, c cachedKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(m) >= maxCachedKeys {
		clear(m) // simple bound; the keys are fetched again as needed
	}
	m[k] = c
}
