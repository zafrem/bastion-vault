package audit

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zafrem/bastion-vault/internal/model"
)

// Logger writes immutable audit events to an append-only JSONL file.
// In production this would write to a tamper-evident log store (WORM S3, CloudWatch, etc.).
type Logger struct {
	mu         sync.Mutex
	file       *os.File
	outDir     string
	sign       bool
	signingKey []byte
}

// NewLogger constructs an audit Logger that writes to outputDir.
// When signingEnabled is true, signingKey should be a 32-byte key used for HMAC-SHA256.
// signingKey is optional; if omitted and signingEnabled is true, signing is skipped.
func NewLogger(outputDir string, signingEnabled bool, signingKey ...[]byte) (*Logger, error) {
	var key []byte
	if len(signingKey) > 0 {
		key = signingKey[0]
	}
	return newLoggerWithKey(outputDir, signingEnabled, key)
}

func newLoggerWithKey(outputDir string, signingEnabled bool, signingKey []byte) (*Logger, error) {
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: creating output dir: %w", err)
	}
	filename := filepath.Join(outputDir, "audit-"+todayStr()+".jsonl")
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: opening log file: %w", err)
	}
	return &Logger{file: f, outDir: outputDir, sign: signingEnabled, signingKey: signingKey}, nil
}

// Log writes an AuditEvent and returns the generated event ID.
func (l *Logger) Log(_ context.Context, ev model.AuditEvent) (string, error) {
	ev.ID = newID()
	ev.Timestamp = time.Now().UTC()

	data, err := json.Marshal(ev)
	if err != nil {
		return "", fmt.Errorf("audit: marshalling event: %w", err)
	}

	var line string
	if l.sign && len(l.signingKey) > 0 {
		// Compute HMAC over canonical JSON (the entry without the hmac field)
		mac := computeHMAC(l.signingKey, data)

		// Inject hmac field into the JSON
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			return "", fmt.Errorf("audit: unmarshalling for signing: %w", err)
		}
		m["hmac"] = mac
		signed, err := json.Marshal(m)
		if err != nil {
			return "", fmt.Errorf("audit: marshalling signed event: %w", err)
		}
		line = string(signed) + "\n"
	} else {
		line = string(data) + "\n"
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if _, err := l.file.WriteString(line); err != nil {
		return "", fmt.Errorf("audit: writing event: %w", err)
	}

	return ev.ID, nil
}

// Close flushes and closes the underlying file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

// VerifyEntry parses a JSONL entry, strips the hmac field, recomputes HMAC, and compares.
// Returns (true, nil) if the entry is valid, (false, nil) if tampered, or (false, err) on parse error.
func (l *Logger) VerifyEntry(entryJSON []byte) (bool, error) {
	if !l.sign || len(l.signingKey) == 0 {
		return true, nil // signing not enabled; nothing to verify
	}

	var m map[string]any
	if err := json.Unmarshal(entryJSON, &m); err != nil {
		return false, fmt.Errorf("audit: parsing entry for verification: %w", err)
	}

	storedMAC, ok := m["hmac"].(string)
	if !ok {
		return false, fmt.Errorf("audit: entry missing hmac field")
	}

	// Strip hmac field and re-marshal canonical JSON
	delete(m, "hmac")
	canonical, err := json.Marshal(m)
	if err != nil {
		return false, fmt.Errorf("audit: re-marshalling for verification: %w", err)
	}

	expected := computeHMAC(l.signingKey, canonical)
	return hmac.Equal([]byte(storedMAC), []byte(expected)), nil
}

// Query reads the current log file and returns entries matching the given filters.
// tenantID="" matches all tenants. limit=0 returns all. since is optional.
func (l *Logger) Query(_ context.Context, tenantID string, limit int, since time.Time) ([]map[string]any, error) {
	l.mu.Lock()
	filename := l.file.Name()
	l.mu.Unlock()

	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("audit: opening log for query: %w", err)
	}
	defer f.Close()

	var results []map[string]any
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue // skip malformed lines
		}

		// Filter by tenant
		if tenantID != "" {
			if t, _ := entry["tenant_id"].(string); t != tenantID {
				continue
			}
		}

		// Filter by since
		if !since.IsZero() {
			if ts, _ := entry["timestamp"].(string); ts != "" {
				t, err := time.Parse(time.RFC3339Nano, ts)
				if err == nil && t.Before(since) {
					continue
				}
			}
		}

		results = append(results, entry)
		if limit > 0 && len(results) >= limit {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("audit: scanning log: %w", err)
	}
	return results, nil
}

// computeHMAC returns the hex-encoded HMAC-SHA256 of data under key.
func computeHMAC(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func todayStr() string {
	return time.Now().UTC().Format("2006-01-02")
}
