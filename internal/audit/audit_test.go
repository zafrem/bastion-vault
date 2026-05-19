package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zafrem/bastion-vault/internal/model"
)

// readEntries reads every JSONL line from the logger's current file.
func readEntries(t *testing.T, l *Logger) []string {
	t.Helper()
	l.mu.Lock()
	name := l.file.Name()
	l.mu.Unlock()
	f, err := os.Open(name)
	if err != nil {
		t.Fatalf("opening log: %v", err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := sc.Text(); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func sampleEvent(tenantID string) model.AuditEvent {
	return model.AuditEvent{
		TenantID:     tenantID,
		EventType:    model.AuditEventAccess,
		ActorID:      "user-1",
		ResourceType: "DC-01",
		Action:       "read",
		Outcome:      "success",
	}
}

func TestLog_WithoutSigning(t *testing.T) {
	l, err := NewLogger(t.TempDir(), false)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	if _, err := l.Log(context.Background(), sampleEvent("tenant-a")); err != nil {
		t.Fatalf("Log: %v", err)
	}

	lines := readEntries(t, l)
	if len(lines) != 1 {
		t.Fatalf("got %d entries, want 1", len(lines))
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("unmarshalling entry: %v", err)
	}
	if _, ok := entry["hmac"]; ok {
		t.Error("entry should not have hmac field when signing is disabled")
	}
	if entry["tenant_id"] != "tenant-a" {
		t.Errorf("tenant_id = %v, want tenant-a", entry["tenant_id"])
	}
}

func TestLog_WithSigning(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	l, err := NewLogger(t.TempDir(), true, key)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	if _, err := l.Log(context.Background(), sampleEvent("tenant-a")); err != nil {
		t.Fatalf("Log: %v", err)
	}

	lines := readEntries(t, l)
	if len(lines) != 1 {
		t.Fatalf("got %d entries, want 1", len(lines))
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("unmarshalling entry: %v", err)
	}
	if _, ok := entry["hmac"]; !ok {
		t.Error("signed entry must have an hmac field")
	}

	ok, err := l.VerifyEntry([]byte(lines[0]))
	if err != nil {
		t.Fatalf("VerifyEntry: %v", err)
	}
	if !ok {
		t.Error("VerifyEntry returned false for a valid signed entry")
	}
}

func TestVerifyEntry_Tampered(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	l, err := NewLogger(t.TempDir(), true, key)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	if _, err := l.Log(context.Background(), sampleEvent("tenant-a")); err != nil {
		t.Fatalf("Log: %v", err)
	}

	lines := readEntries(t, l)
	// Tamper: change the actor_id value but keep the original hmac.
	tampered := strings.Replace(lines[0], `"actor_id":"user-1"`, `"actor_id":"attacker"`, 1)
	if tampered == lines[0] {
		t.Fatal("test setup: expected to alter the entry")
	}

	ok, err := l.VerifyEntry([]byte(tampered))
	if err != nil {
		t.Fatalf("VerifyEntry returned error for tampered entry: %v", err)
	}
	if ok {
		t.Error("VerifyEntry returned true for a tampered entry")
	}
}

func TestQuery_ByTenantID(t *testing.T) {
	l, err := NewLogger(t.TempDir(), false)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	for _, tid := range []string{"tenant-a", "tenant-b", "tenant-a"} {
		if _, err := l.Log(context.Background(), sampleEvent(tid)); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	entries, err := l.Query(context.Background(), "tenant-a", 0, time.Time{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries for tenant-a, want 2", len(entries))
	}
	for _, e := range entries {
		if e["tenant_id"] != "tenant-a" {
			t.Errorf("entry tenant_id = %v, want tenant-a", e["tenant_id"])
		}
	}
}

func TestQuery_WithLimit(t *testing.T) {
	l, err := NewLogger(t.TempDir(), false)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	for i := 0; i < 5; i++ {
		if _, err := l.Log(context.Background(), sampleEvent("tenant-a")); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	entries, err := l.Query(context.Background(), "", 3, time.Time{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries with limit=3, want 3", len(entries))
	}
}

func TestQuery_WithSince(t *testing.T) {
	l, err := NewLogger(t.TempDir(), false)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	// Two entries before the cutoff.
	for i := 0; i < 2; i++ {
		if _, err := l.Log(context.Background(), sampleEvent("tenant-a")); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	cutoff := time.Now().UTC()
	// Ensure subsequent entries have a timestamp strictly after the cutoff.
	time.Sleep(10 * time.Millisecond)
	for i := 0; i < 3; i++ {
		if _, err := l.Log(context.Background(), sampleEvent("tenant-a")); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	entries, err := l.Query(context.Background(), "", 0, cutoff)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries after cutoff, want 3", len(entries))
	}
	for _, e := range entries {
		ts, _ := e["timestamp"].(string)
		parsed, perr := time.Parse(time.RFC3339Nano, ts)
		if perr != nil {
			t.Fatalf("parsing timestamp %q: %v", ts, perr)
		}
		if parsed.Before(cutoff) {
			t.Errorf("entry timestamp %v is before cutoff %v", parsed, cutoff)
		}
	}
}
