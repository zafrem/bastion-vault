package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// StartRetentionWorker launches a background goroutine that scans outputDir
// every 24 hours and deletes audit-*.jsonl files older than retentionDays days.
// It returns a stop() function that cancels the worker; the goroutine also exits
// cleanly when ctx is cancelled.
func StartRetentionWorker(ctx context.Context, outputDir string, retentionDays int) func() {
	ctx, cancel := context.WithCancel(ctx)

	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := runRetention(outputDir, retentionDays); err != nil {
					fmt.Fprintf(os.Stderr, "audit: retention sweep failed: %v\n", err)
				}
			}
		}
	}()

	return cancel
}

// runRetention scans outputDir for audit-*.jsonl files and deletes any whose
// modification time is older than retentionDays days. It is called by the
// retention worker on each tick and is exported for direct testing.
func runRetention(outputDir string, retentionDays int) error {
	if retentionDays <= 0 {
		return nil
	}

	entries, err := os.ReadDir(outputDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("audit: reading retention dir: %w", err)
	}

	cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "audit-") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if rerr := os.Remove(filepath.Join(outputDir, name)); rerr != nil {
				return fmt.Errorf("audit: removing expired log %q: %w", name, rerr)
			}
		}
	}
	return nil
}
