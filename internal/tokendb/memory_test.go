package tokendb_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/zafrem/bastion-vault/internal/tokendb"
)

func makeEntry(token, tenantID, original, piiType string) tokendb.Entry {
	return tokendb.Entry{
		Token:     token,
		TenantID:  tenantID,
		Original:  original,
		PIIType:   piiType,
		CreatedAt: time.Now().UTC(),
	}
}

func TestPutAndGet(t *testing.T) {
	s := tokendb.NewMemoryStore()
	ctx := context.Background()

	e := makeEntry("tok-abc", "tenant-1", "original-value", "email")
	if err := s.Put(ctx, e); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := s.Get(ctx, "tok-abc", "tenant-1")
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
}

func TestGet_WrongTenant_ReturnsNil(t *testing.T) {
	s := tokendb.NewMemoryStore()
	ctx := context.Background()

	s.Put(ctx, makeEntry("tok-abc", "tenant-1", "value", "email")) //nolint:errcheck

	got, err := s.Get(ctx, "tok-abc", "tenant-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for wrong tenant, got %+v", got)
	}
}

func TestDelete_RemovesEntry(t *testing.T) {
	s := tokendb.NewMemoryStore()
	ctx := context.Background()

	s.Put(ctx, makeEntry("tok-xyz", "tenant-1", "value", "email")) //nolint:errcheck
	if err := s.Delete(ctx, "tok-xyz", "tenant-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	got, err := s.Get(ctx, "tok-xyz", "tenant-1")
	if err != nil {
		t.Fatalf("Get after delete: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil after delete, got %+v", got)
	}
}

func TestDeleteByTenant(t *testing.T) {
	s := tokendb.NewMemoryStore()
	ctx := context.Background()

	// Add 3 entries for tenant-A, 2 for tenant-B
	s.Put(ctx, makeEntry("t1", "tenant-A", "v1", "email"))   //nolint:errcheck
	s.Put(ctx, makeEntry("t2", "tenant-A", "v2", "mobile"))  //nolint:errcheck
	s.Put(ctx, makeEntry("t3", "tenant-A", "v3", "rrn"))     //nolint:errcheck
	s.Put(ctx, makeEntry("t4", "tenant-B", "v4", "email"))   //nolint:errcheck
	s.Put(ctx, makeEntry("t5", "tenant-B", "v5", "mobile"))  //nolint:errcheck

	n, err := s.DeleteByTenant(ctx, "tenant-A")
	if err != nil {
		t.Fatalf("DeleteByTenant: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 deleted, got %d", n)
	}

	// tenant-A entries should be gone
	for _, tok := range []string{"t1", "t2", "t3"} {
		got, _ := s.Get(ctx, tok, "tenant-A")
		if got != nil {
			t.Errorf("expected nil for %q after tenant deletion, got %+v", tok, got)
		}
	}

	// tenant-B entries should still exist
	for _, tok := range []string{"t4", "t5"} {
		got, _ := s.Get(ctx, tok, "tenant-B")
		if got == nil {
			t.Errorf("expected entry for %q in tenant-B, got nil", tok)
		}
	}
}

func TestConcurrentPutGet_NoRace(t *testing.T) {
	s := tokendb.NewMemoryStore()
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		i := i
		wg.Add(2)
		go func() {
			defer wg.Done()
			tok := "tok-" + itoa(i)
			s.Put(ctx, makeEntry(tok, "tenant-race", "value", "email")) //nolint:errcheck
		}()
		go func() {
			defer wg.Done()
			tok := "tok-" + itoa(i)
			s.Get(ctx, tok, "tenant-race") //nolint:errcheck
		}()
	}
	wg.Wait()
}

// itoa converts an int to string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
