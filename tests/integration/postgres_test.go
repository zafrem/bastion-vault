//go:build integration

package integration

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

func openPostgres(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("db.Ping: %v", err)
	}
	return db
}

func setupTable(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(context.Background(), `
		CREATE TABLE IF NOT EXISTS token_mappings (
			token      TEXT NOT NULL,
			tenant_id  TEXT NOT NULL,
			original   BYTEA NOT NULL,
			pii_type   TEXT NOT NULL,
			created_at TIMESTAMPTZ DEFAULT now(),
			PRIMARY KEY (token, tenant_id)
		)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	_, err = db.ExecContext(context.Background(), `TRUNCATE token_mappings`)
	if err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

func TestPostgresStore_PutAndGet(t *testing.T) {
	db := openPostgres(t)
	defer db.Close()
	setupTable(t, db)

	store := tokendb.NewPostgresStore(db)
	ctx := context.Background()

	entry := tokendb.Entry{
		Token:     "tok-001",
		TenantID:  "tenant-a",
		Original:  "hello@example.com",
		PIIType:   "email",
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
	}

	if err := store.Put(ctx, entry); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := store.Get(ctx, "tok-001", "tenant-a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil, want entry")
	}
	if got.Token != entry.Token {
		t.Errorf("Token: got %q, want %q", got.Token, entry.Token)
	}
	if got.Original != entry.Original {
		t.Errorf("Original: got %q, want %q", got.Original, entry.Original)
	}
	if got.PIIType != entry.PIIType {
		t.Errorf("PIIType: got %q, want %q", got.PIIType, entry.PIIType)
	}
}

func TestPostgresStore_Delete(t *testing.T) {
	db := openPostgres(t)
	defer db.Close()
	setupTable(t, db)

	store := tokendb.NewPostgresStore(db)
	ctx := context.Background()

	entry := tokendb.Entry{
		Token:    "tok-del",
		TenantID: "tenant-b",
		Original: "delete-me",
		PIIType:  "korean_name",
	}

	if err := store.Put(ctx, entry); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if err := store.Delete(ctx, "tok-del", "tenant-b"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	got, err := store.Get(ctx, "tok-del", "tenant-b")
	if err != nil {
		t.Fatalf("Get after Delete: %v", err)
	}
	if got != nil {
		t.Errorf("Get after Delete: got %+v, want nil", got)
	}
}

func TestPostgresStore_DeleteByTenant(t *testing.T) {
	db := openPostgres(t)
	defer db.Close()
	setupTable(t, db)

	store := tokendb.NewPostgresStore(db)
	ctx := context.Background()

	for i, token := range []string{"t1", "t2", "t3"} {
		_ = i
		if err := store.Put(ctx, tokendb.Entry{
			Token:    token,
			TenantID: "tenant-erase",
			Original: "value-" + token,
			PIIType:  "email",
		}); err != nil {
			t.Fatalf("Put %s: %v", token, err)
		}
	}
	// Also put an entry for a different tenant; should not be deleted.
	if err := store.Put(ctx, tokendb.Entry{
		Token:    "other-tok",
		TenantID: "tenant-other",
		Original: "keep-me",
		PIIType:  "email",
	}); err != nil {
		t.Fatalf("Put other: %v", err)
	}

	n, err := store.DeleteByTenant(ctx, "tenant-erase")
	if err != nil {
		t.Fatalf("DeleteByTenant: %v", err)
	}
	if n != 3 {
		t.Errorf("DeleteByTenant returned %d, want 3", n)
	}

	// Other tenant's entry should still exist.
	got, err := store.Get(ctx, "other-tok", "tenant-other")
	if err != nil {
		t.Fatalf("Get other after erase: %v", err)
	}
	if got == nil {
		t.Error("other tenant's entry was unexpectedly deleted")
	}
}

func TestPostgresStore_ConflictUpsert(t *testing.T) {
	db := openPostgres(t)
	defer db.Close()
	setupTable(t, db)

	store := tokendb.NewPostgresStore(db)
	ctx := context.Background()

	entry := tokendb.Entry{
		Token:    "upsert-tok",
		TenantID: "tenant-c",
		Original: "original-value",
		PIIType:  "email",
	}
	if err := store.Put(ctx, entry); err != nil {
		t.Fatalf("first Put: %v", err)
	}

	// Upsert with different original.
	entry.Original = "updated-value"
	entry.PIIType = "korean_name"
	if err := store.Put(ctx, entry); err != nil {
		t.Fatalf("second Put (upsert): %v", err)
	}

	got, err := store.Get(ctx, "upsert-tok", "tenant-c")
	if err != nil {
		t.Fatalf("Get after upsert: %v", err)
	}
	if got == nil {
		t.Fatal("Get after upsert returned nil")
	}
	if got.Original != "updated-value" {
		t.Errorf("Original after upsert: got %q, want %q", got.Original, "updated-value")
	}
	if got.PIIType != "korean_name" {
		t.Errorf("PIIType after upsert: got %q, want %q", got.PIIType, "korean_name")
	}
}
