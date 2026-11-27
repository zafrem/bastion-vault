package tokendb

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
	"log"
	"sync"
	"time"

	"github.com/zafrem/bastion-vault/internal/kms"
)

// Originals are encrypted before they reach a database, with envelope encryption: a data key from the KMS
// encrypts the value, and the data key, wrapped by the KMS master key, is stored in the same column. Reading a
// row therefore needs only the row and the KMS, so it keeps working after a restart and across replicas.
//
// Stored form: magic | uint16 length of the wrapped key | wrapped key | nonce | AES-256-GCM ciphertext.
// The tenant and token are authenticated, so a ciphertext copied to another row does not decrypt there.

// sealedMagic starts every encrypted value. The leading NUL cannot begin a text value, which tells encrypted
// rows apart from plaintext rows written by earlier versions.
const sealedMagic = "\x00bvt1"

const (
	defaultKeyTTL = 5 * time.Minute
	maxCachedKeys = 1024
	dataKeyBytes  = 32
)

// ErrPlaintextRow reports a row that was stored without encryption.
var ErrPlaintextRow = errors.New("tokendb: this row is not encrypted; it was written by an earlier version or " +
	"changed outside Vault. To read such rows once and re-encrypt them, set token_store.allow_legacy_plaintext")

// DataKeys is the part of a KMS provider that envelope encryption needs.
type DataKeys interface {
	GenerateDataKey(ctx context.Context, keyID string) (*kms.DataKey, error)
	DecryptDataKey(ctx context.Context, ciphertext []byte, keyID string) ([]byte, error)
}

// replacer is implemented by stores that can swap a stored value in place, only if it is still the expected one.
// Unlike Put it never re-creates a row that was deleted in the meantime.
type replacer interface {
	replaceOriginal(ctx context.Context, token, tenantID string, old, replacement []byte) error
}

// EncryptedOptions tunes an EncryptedStore.
type EncryptedOptions struct {
	// KeyTTL is how long a data key is reused before a new one is requested (default 5 minutes).
	KeyTTL time.Duration
	// AllowLegacyPlaintext accepts unencrypted rows and re-encrypts each one when it is read. While it is on,
	// anyone who can write to the database can plant values, so turn it off once old rows are converted.
	AllowLegacyPlaintext bool
}

type cachedKey struct {
	aead    cipher.AEAD
	wrapped []byte
	expires time.Time
}

// EncryptedStore encrypts Entry.Original on the way into another Store and decrypts it on the way out.
type EncryptedStore struct {
	Store // deletes pass straight through

	keys DataKeys
	opts EncryptedOptions

	mu      sync.Mutex
	sealing map[string]cachedKey // key id → the data key new values are encrypted with
	opening map[string]cachedKey // key id + wrapped key → unwrapped data key
}

// NewEncryptedStore wraps inner so that originals are never stored in plaintext.
func NewEncryptedStore(inner Store, keys DataKeys, opts EncryptedOptions) *EncryptedStore {
	if opts.KeyTTL <= 0 {
		opts.KeyTTL = defaultKeyTTL
	}
	return &EncryptedStore{Store: inner, keys: keys, opts: opts,
		sealing: map[string]cachedKey{}, opening: map[string]cachedKey{}}
}

// Put encrypts the original and stores the entry.
func (s *EncryptedStore) Put(ctx context.Context, e Entry) error {
	sealed, err := s.seal(ctx, e.TenantID, e.Token, []byte(e.Original))
	if err != nil {
		return fmt.Errorf("tokendb: encrypting the original: %w", err)
	}
	e.Original = string(sealed)
	return s.Store.Put(ctx, e)
}

// Get returns the entry with its original decrypted.
func (s *EncryptedStore) Get(ctx context.Context, token, tenantID string) (*Entry, error) {
	e, err := s.Store.Get(ctx, token, tenantID)
	if err != nil || e == nil {
		return e, err
	}
	stored := []byte(e.Original)
	if !bytes.HasPrefix(stored, []byte(sealedMagic)) {
		if !s.opts.AllowLegacyPlaintext {
			return nil, ErrPlaintextRow
		}
		s.reencrypt(ctx, token, tenantID, stored)
		return e, nil
	}
	plain, err := s.open(ctx, tenantID, token, stored)
	if err != nil {
		return nil, fmt.Errorf("tokendb: decrypting the original: %w", err)
	}
	out := *e
	out.Original = string(plain)
	return &out, nil
}

// reencrypt converts a legacy row. A failure leaves the row as it was and is only logged: the value has
// already been read, and the next read tries again.
func (s *EncryptedStore) reencrypt(ctx context.Context, token, tenantID string, plain []byte) {
	r, ok := s.Store.(replacer)
	if !ok {
		return
	}
	sealed, err := s.seal(ctx, tenantID, token, plain)
	if err == nil {
		err = r.replaceOriginal(ctx, token, tenantID, plain, sealed)
	}
	if err != nil {
		log.Printf("tokendb: could not re-encrypt a legacy row: %q", err.Error())
	}
}

func keyID(tenantID string) string { return "tenant:" + tenantID + ":tokens" }

// boundData ties a ciphertext to its row. Lengths are included so that no two (tenant, token) pairs encode
// to the same bytes.
func boundData(tenantID, token string) []byte {
	return []byte(fmt.Sprintf("%s%d:%s%d:%s", sealedMagic, len(tenantID), tenantID, len(token), token))
}

// newCachedKey builds the cipher and wipes the raw key.
func (s *EncryptedStore) newCachedKey(plain, wrapped []byte) (cachedKey, error) {
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
	return cachedKey{aead: aead, wrapped: bytes.Clone(wrapped), expires: time.Now().Add(s.opts.KeyTTL)}, nil
}

func (s *EncryptedStore) cached(m map[string]cachedKey, k string) (cachedKey, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := m[k]
	if ok && time.Now().After(c.expires) {
		delete(m, k)
		ok = false
	}
	return c, ok
}

func (s *EncryptedStore) remember(m map[string]cachedKey, k string, c cachedKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(m) >= maxCachedKeys {
		clear(m) // simple bound; the keys are fetched again as needed
	}
	m[k] = c
}

func (s *EncryptedStore) seal(ctx context.Context, tenantID, token string, plain []byte) ([]byte, error) {
	id := keyID(tenantID)
	key, ok := s.cached(s.sealing, id)
	if !ok {
		dk, err := s.keys.GenerateDataKey(ctx, id)
		if err != nil {
			return nil, err
		}
		if key, err = s.newCachedKey(dk.Plaintext, dk.Ciphertext); err != nil {
			return nil, err
		}
		if len(key.wrapped) == 0 || len(key.wrapped) > 0xffff {
			return nil, fmt.Errorf("the KMS returned a wrapped key of %d bytes", len(key.wrapped))
		}
		s.remember(s.sealing, id, key)
	}
	nonce := make([]byte, key.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := append([]byte(sealedMagic), 0, 0)
	binary.BigEndian.PutUint16(out[len(sealedMagic):], uint16(len(key.wrapped))) // #nosec G115 -- bounded above
	out = append(append(out, key.wrapped...), nonce...)
	return key.aead.Seal(out, nonce, plain, boundData(tenantID, token)), nil
}

func (s *EncryptedStore) open(ctx context.Context, tenantID, token string, sealed []byte) ([]byte, error) {
	rest := sealed[len(sealedMagic):]
	if len(rest) < 2 {
		return nil, errors.New("the stored value is truncated")
	}
	n := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if n == 0 || len(rest) < n {
		return nil, errors.New("the stored value is truncated")
	}
	wrapped, rest := rest[:n], rest[n:]

	id := keyID(tenantID)
	cacheKey := id + "\x00" + string(wrapped)
	key, ok := s.cached(s.opening, cacheKey)
	if !ok {
		plain, err := s.keys.DecryptDataKey(ctx, wrapped, id)
		if err != nil {
			return nil, err
		}
		if key, err = s.newCachedKey(plain, wrapped); err != nil {
			return nil, err
		}
		s.remember(s.opening, cacheKey, key)
	}
	if len(rest) < key.aead.NonceSize() {
		return nil, errors.New("the stored value is truncated")
	}
	nonce, ct := rest[:key.aead.NonceSize()], rest[key.aead.NonceSize():]
	return key.aead.Open(nil, nonce, ct, boundData(tenantID, token))
}
