package tokendb_test

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/zafrem/bastion-vault/internal/tokendb"
)

func newTestSQLiteStore(t *testing.T) *tokendb.SQLiteStore {
	t.Helper()
	db, err := sql.Open("sqlite", "file::memory:?cache=shared&mode=memory")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	store, err := tokendb.NewSQLiteStore(db)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	return store
}

func TestSQLiteStore_PutAndGet(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	e := makeEntry("tok-sqlite-1", "tenant-1", "original-value", "email")
	if err := s.Put(ctx, e); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := s.Get(ctx, "tok-sqlite-1", "tenant-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("expected entry, got nil")
	}
	if got.Original != "original-value" {
		t.Errorf("want Original=%q, got %q", "original-value", got.Original)
	}
	if got.PIIType != "email" {
		t.Errorf("want PIIType=%q, got %q", "email", got.PIIType)
	}
	if got.Token != "tok-sqlite-1" {
		t.Errorf("want Token=%q, got %q", "tok-sqlite-1", got.Token)
	}
	if got.TenantID != "tenant-1" {
		t.Errorf("want TenantID=%q, got %q", "tenant-1", got.TenantID)
	}
}

func TestSQLiteStore_Delete(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	s.Put(ctx, makeEntry("tok-del", "tenant-1", "value", "email")) //nolint:errcheck
	if err := s.Delete(ctx, "tok-del", "tenant-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	got, err := s.Get(ctx, "tok-del", "tenant-1")
	if err != nil {
		t.Fatalf("Get after delete: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil after delete, got %+v", got)
	}
}

func TestSQLiteStore_DeleteByTenant(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	// Add 3 entries for tenant-A, 2 for tenant-B.
	s.Put(ctx, makeEntry("s1", "tenant-A", "v1", "email"))  //nolint:errcheck
	s.Put(ctx, makeEntry("s2", "tenant-A", "v2", "mobile")) //nolint:errcheck
	s.Put(ctx, makeEntry("s3", "tenant-A", "v3", "rrn"))    //nolint:errcheck
	s.Put(ctx, makeEntry("s4", "tenant-B", "v4", "email"))  //nolint:errcheck
	s.Put(ctx, makeEntry("s5", "tenant-B", "v5", "mobile")) //nolint:errcheck

	n, err := s.DeleteByTenant(ctx, "tenant-A")
	if err != nil {
		t.Fatalf("DeleteByTenant: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 deleted, got %d", n)
	}

	// tenant-A entries should be gone.
	for _, tok := range []string{"s1", "s2", "s3"} {
		got, _ := s.Get(ctx, tok, "tenant-A")
		if got != nil {
			t.Errorf("expected nil for %q after tenant deletion, got %+v", tok, got)
		}
	}

	// tenant-B entries should still exist.
	for _, tok := range []string{"s4", "s5"} {
		got, _ := s.Get(ctx, tok, "tenant-B")
		if got == nil {
			t.Errorf("expected entry for %q in tenant-B, got nil", tok)
		}
	}
}

func TestSQLiteStore_GetMissingToken(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	got, err := s.Get(ctx, "nonexistent-token", "tenant-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for missing token, got %+v", got)
	}
}

func TestSQLiteStore_ConflictUpsert(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	first := makeEntry("tok-upsert", "tenant-1", "first-value", "email")
	if err := s.Put(ctx, first); err != nil {
		t.Fatalf("first Put: %v", err)
	}

	second := makeEntry("tok-upsert", "tenant-1", "second-value", "mobile")
	if err := s.Put(ctx, second); err != nil {
		t.Fatalf("second Put: %v", err)
	}

	got, err := s.Get(ctx, "tok-upsert", "tenant-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("expected entry, got nil")
	}
	if got.Original != "second-value" {
		t.Errorf("want Original=%q (second value wins), got %q", "second-value", got.Original)
	}
	if got.PIIType != "mobile" {
		t.Errorf("want PIIType=%q (second value wins), got %q", "mobile", got.PIIType)
	}
}
