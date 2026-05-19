package audit

import (
	"context"
	"crypto/rand"
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
	mu      sync.Mutex
	file    *os.File
	outDir  string
	sign    bool
}

// NewLogger constructs an audit Logger that writes to outputDir.
func NewLogger(outputDir string, signingEnabled bool) (*Logger, error) {
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: creating output dir: %w", err)
	}
	filename := filepath.Join(outputDir, "audit-"+todayStr()+".jsonl")
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: opening log file: %w", err)
	}
	return &Logger{file: f, outDir: outputDir, sign: signingEnabled}, nil
}

// Log writes an AuditEvent and returns the generated event ID.
func (l *Logger) Log(_ context.Context, ev model.AuditEvent) (string, error) {
	ev.ID = newID()
	ev.Timestamp = time.Now().UTC()

	data, err := json.Marshal(ev)
	if err != nil {
		return "", fmt.Errorf("audit: marshalling event: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if _, err := l.file.WriteString(string(data) + "\n"); err != nil {
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

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func todayStr() string {
	return time.Now().UTC().Format("2006-01-02")
}
