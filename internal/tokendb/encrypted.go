package tokendb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/zafrem/bastion-vault/internal/envelope"
)

// Originals are encrypted before they reach a database (see package envelope), so reading a row needs only the
// row and the KMS, and keeps working after a restart and across replicas.
//
// Stored form: magic | sealed value. The tenant and token are authenticated, so a ciphertext copied to another
// row does not decrypt there.

// sealedMagic starts every encrypted value. The leading NUL cannot begin a text value, which tells encrypted
// rows apart from plaintext rows written by earlier versions.
const sealedMagic = "\x00bvt1"

// ErrPlaintextRow reports a row that was stored without encryption.
var ErrPlaintextRow = errors.New("tokendb: this row is not encrypted; it was written by an earlier version or " +
	"changed outside Vault. To read such rows once and re-encrypt them, set token_store.allow_legacy_plaintext")

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

// EncryptedStore encrypts Entry.Original on the way into another Store and decrypts it on the way out.
type EncryptedStore struct {
	Store // deletes pass straight through

	sealer      *envelope.Sealer
	allowLegacy bool
}

// NewEncryptedStore wraps inner so that originals are never stored in plaintext.
func NewEncryptedStore(inner Store, keys envelope.Keys, opts EncryptedOptions) *EncryptedStore {
	return &EncryptedStore{Store: inner, sealer: envelope.New(keys, opts.KeyTTL), allowLegacy: opts.AllowLegacyPlaintext}
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
		if !s.allowLegacy {
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

func (s *EncryptedStore) seal(ctx context.Context, tenantID, token string, plain []byte) ([]byte, error) {
	body, err := s.sealer.Seal(ctx, keyID(tenantID), boundData(tenantID, token), plain)
	if err != nil {
		return nil, err
	}
	return append([]byte(sealedMagic), body...), nil
}

func (s *EncryptedStore) open(ctx context.Context, tenantID, token string, sealed []byte) ([]byte, error) {
	return s.sealer.Open(ctx, keyID(tenantID), boundData(tenantID, token), sealed[len(sealedMagic):])
}
