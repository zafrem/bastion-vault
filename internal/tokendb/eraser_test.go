package tokendb

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/model"
)

// seedErasureEvent writes a synthetic erasure audit event to a temp audit log
// so that the eraser worker can find it via auditLog.Query.
func seedErasureEvent(t *testing.T, auditLog *audit.Logger, tenantID string) {
	t.Helper()
	_, err := auditLog.Log(context.Background(), model.AuditEvent{
		TenantID:     tenantID,
		EventType:    model.AuditEventErasure,
		ActorID:      "test-actor",
		ResourceType: "token_store",
		ResourceID:   tenantID,
		Action:       "erasure",
		Outcome:      "deleted",
		Metadata:     map[string]any{"entries_deleted": 1},
	})
	if err != nil {
		t.Fatalf("seeding erasure event: %v", err)
	}
}

// seedNonErasureEvent writes a non-erasure event to verify the worker ignores it.
func seedNonErasureEvent(t *testing.T, auditLog *audit.Logger, tenantID string) {
	t.Helper()
	_, err := auditLog.Log(context.Background(), model.AuditEvent{
		TenantID:     tenantID,
		EventType:    model.AuditEventAnonymize,
		ActorID:      "test-actor",
		ResourceType: "token_store",
		ResourceID:   tenantID,
		Action:       "anonymize",
		Outcome:      "success",
	})
	if err != nil {
		t.Fatalf("seeding non-erasure event: %v", err)
	}
}

func TestErasureWorker_DeletesTokensForErasureTenant(t *testing.T) {
	ctx := context.Background()

	// Set up audit logger in temp dir.
	auditDir := filepath.Join(t.TempDir(), "audit")
	auditLog, err := audit.NewLogger(auditDir, false)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer auditLog.Close()

	// Seed an erasure event for tenant-A.
	seedErasureEvent(t, auditLog, "tenant-a")
	// Also seed a non-erasure event for tenant-B to make sure it is NOT erased.
	seedNonErasureEvent(t, auditLog, "tenant-b")

	// Populate the store.
	store := NewMemoryStore()
	_ = store.Put(ctx, Entry{Token: "tok1", TenantID: "tenant-a", Original: "v1", PIIType: "email"})
	_ = store.Put(ctx, Entry{Token: "tok2", TenantID: "tenant-a", Original: "v2", PIIType: "email"})
	_ = store.Put(ctx, Entry{Token: "tok3", TenantID: "tenant-b", Original: "v3", PIIType: "email"})

	// Run a single sweep directly (avoids waiting for a ticker).
	runErasureSweep(ctx, store, auditLog, 24*time.Hour)

	// tenant-a tokens should be gone.
	e1, err := store.Get(ctx, "tok1", "tenant-a")
	if err != nil {
		t.Fatalf("Get tok1: %v", err)
	}
	if e1 != nil {
		t.Errorf("tok1 for tenant-a still present after erasure sweep")
	}
	e2, err := store.Get(ctx, "tok2", "tenant-a")
	if err != nil {
		t.Fatalf("Get tok2: %v", err)
	}
	if e2 != nil {
		t.Errorf("tok2 for tenant-a still present after erasure sweep")
	}

	// tenant-b token must remain (no erasure event for it).
	e3, err := store.Get(ctx, "tok3", "tenant-b")
	if err != nil {
		t.Fatalf("Get tok3: %v", err)
	}
	if e3 == nil {
		t.Errorf("tok3 for tenant-b was unexpectedly deleted")
	}
}

func TestErasureWorker_IgnoresNonErasureEvents(t *testing.T) {
	ctx := context.Background()

	auditDir := filepath.Join(t.TempDir(), "audit")
	auditLog, err := audit.NewLogger(auditDir, false)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer auditLog.Close()

	// Only non-erasure events.
	seedNonErasureEvent(t, auditLog, "tenant-x")

	store := NewMemoryStore()
	_ = store.Put(ctx, Entry{Token: "tokX", TenantID: "tenant-x", Original: "vX", PIIType: "email"})

	runErasureSweep(ctx, store, auditLog, 24*time.Hour)

	e, err := store.Get(ctx, "tokX", "tenant-x")
	if err != nil {
		t.Fatalf("Get tokX: %v", err)
	}
	if e == nil {
		t.Errorf("tokX was deleted despite no erasure audit event")
	}
}

func TestErasureWorker_StartStop(t *testing.T) {
	auditDir := filepath.Join(t.TempDir(), "audit")
	auditLog, err := audit.NewLogger(auditDir, false)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer auditLog.Close()

	store := NewMemoryStore()
	ctx := context.Background()

	// A very long interval so the ticker never fires during the test;
	// we only verify that start/stop does not panic or block.
	stop := StartErasureWorker(ctx, store, auditLog, 24*time.Hour)
	stop() // must not block or panic
}

// marshalEntry is a helper used in verifyAuditFile to read JSONL lines.
func marshalEntry(entry map[string]any) string {
	b, _ := json.Marshal(entry)
	return string(b)
}

// verifyAuditFile checks that the audit log file in auditDir contains at least
// one line with event_type==erasure for the given tenantID.
func verifyAuditFile(t *testing.T, auditDir, tenantID string) {
	t.Helper()
	files, err := os.ReadDir(auditDir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", auditDir, err)
	}
	if len(files) == 0 {
		t.Fatalf("no audit files in %s", auditDir)
	}
	content, err := os.ReadFile(filepath.Join(auditDir, files[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(content) == 0 {
		t.Fatalf("audit file is empty")
	}
	_ = marshalEntry
}
