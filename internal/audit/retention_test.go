package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunRetention_DeletesExpiredFiles(t *testing.T) {
	dir := t.TempDir()

	files := map[string]int{
		"audit-old-400.jsonl":   400,
		"audit-mid-300.jsonl":   300,
		"audit-recent-1.jsonl":  1,
	}
	for name, ageDays := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		mtime := time.Now().Add(-time.Duration(ageDays) * 24 * time.Hour)
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatalf("chtimes %s: %v", name, err)
		}
	}

	// StartRetentionWorker should run without blocking; stop it immediately.
	stop := StartRetentionWorker(context.Background(), dir, 365)
	stop()

	// Trigger the cleanup directly via the exported helper.
	if err := runRetention(dir, 365); err != nil {
		t.Fatalf("runRetention: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "audit-old-400.jsonl")); !os.IsNotExist(err) {
		t.Errorf("expected 400-day-old file to be deleted, got err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit-recent-1.jsonl")); err != nil {
		t.Errorf("expected 1-day-old file to remain, got err=%v", err)
	}
}
