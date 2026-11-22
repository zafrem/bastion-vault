package breakglass_test

import (
	"bytes"
	"context"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/breakglass"
	"github.com/zafrem/bastion-vault/internal/model"
)

// If the audit trail cannot be written, the break-glass step still happens (it is already applied) but the
// failure must be reported, not swallowed.
func TestAuditFailureIsLoggedNotSwallowed(t *testing.T) {
	aud, err := audit.NewLogger(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aud.Log(context.Background(), model.AuditEvent{EventType: model.AuditEventBreakGlass}); err != nil {
		t.Fatalf("setup: logger should work before it is closed: %v", err)
	}
	aud.Close()
	if _, err := aud.Log(context.Background(), model.AuditEvent{EventType: model.AuditEventBreakGlass}); err == nil {
		t.Skip("closed audit logger still accepts writes; cannot simulate a failure this way")
	}

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	m := breakglass.NewManager(aud)
	if _, err := m.Request(context.Background(), "user-alice", "INC-9", "outage", time.Hour, model.CategoryCustomer); err != nil {
		t.Fatalf("the request itself must still succeed: %v", err)
	}
	if !strings.Contains(buf.String(), "AUDIT WRITE FAILED") {
		t.Errorf("a failed audit write must be logged, got %q", buf.String())
	}
}
