package tokendb

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/zafrem/bastion-vault/internal/kms"
)

type countingKeys struct {
	kms.Provider
	generated, decrypted int
}

func (c *countingKeys) GenerateDataKey(ctx context.Context, id string) (*kms.DataKey, error) {
	c.generated++
	return c.Provider.GenerateDataKey(ctx, id)
}

func (c *countingKeys) DecryptDataKey(ctx context.Context, ct []byte, id string) ([]byte, error) {
	c.decrypted++
	return c.Provider.DecryptDataKey(ctx, ct, id)
}

// A cloud KMS is billed and rate limited per call, so data keys are reused rather than requested per value.
func TestEncryptedStore_ReusesDataKeys(t *testing.T) {
	p, err := kms.NewLocalProvider(t.TempDir(), "00000000000000000000000000000000000000000000000000000000000000cc")
	if err != nil {
		t.Fatal(err)
	}
	keys, inner, ctx := &countingKeys{Provider: p}, NewMemoryStore(), context.Background()
	writer := NewEncryptedStore(inner, keys, EncryptedOptions{})
	for i := 0; i < 50; i++ {
		if err := writer.Put(ctx, Entry{Token: fmt.Sprint(i), TenantID: "t1", Original: "v"}); err != nil {
			t.Fatal(err)
		}
	}
	reader := NewEncryptedStore(inner, keys, EncryptedOptions{}) // a second replica, with an empty cache
	for i := 0; i < 50; i++ {
		got, err := reader.Get(ctx, fmt.Sprint(i), "t1")
		if err != nil || got.Original != "v" {
			t.Fatalf("Get %d: %+v, %v", i, got, err)
		}
	}
	if keys.generated != 1 || keys.decrypted != 1 {
		t.Errorf("KMS calls for 50 writes and 50 reads: generate=%d decrypt=%d, want 1 and 1", keys.generated, keys.decrypted)
	}
}

// Converting a legacy row must never bring back one that was erased after it was read.
func TestReplaceOriginalDoesNotRecreateAnErasedRow(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Put(ctx, Entry{Token: "a", TenantID: "t1", Original: "old"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteByTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	if err := s.replaceOriginal(ctx, "a", "t1", []byte("old"), []byte("new")); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(ctx, "a", "t1"); err != nil || got != nil {
		t.Errorf("an erased row came back: %+v, %v", got, err)
	}
}
