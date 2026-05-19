package breakglass_test

import (
	"context"
	"testing"
	"time"

	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/breakglass"
	"github.com/zafrem/bastion-vault/internal/model"
)

func newManager(t *testing.T) *breakglass.Manager {
	t.Helper()
	// Use a temp dir for audit logs so tests don't pollute the project.
	aud, err := audit.NewLogger(t.TempDir(), false)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	t.Cleanup(func() { aud.Close() })
	return breakglass.NewManager(aud)
}

func TestHappyPath_RequestApproveActive(t *testing.T) {
	m := newManager(t)
	ctx := context.Background()

	req, err := m.Request(ctx, "user-alice", "INC-001", "Production incident", 2*time.Hour, model.CategoryCustomer)
	if err != nil {
		t.Fatalf("Request error: %v", err)
	}
	if req.Status != model.BGStatusPending {
		t.Errorf("want pending, got %q", req.Status)
	}

	// First approval
	req, err = m.Approve(ctx, req.ID, "approver-bob")
	if err != nil {
		t.Fatalf("Approve (1) error: %v", err)
	}
	if req.Status != model.BGStatusPending {
		t.Errorf("after 1 approval want pending, got %q", req.Status)
	}

	// Second approval → active
	req, err = m.Approve(ctx, req.ID, "approver-carol")
	if err != nil {
		t.Fatalf("Approve (2) error: %v", err)
	}
	if req.Status != model.BGStatusActive {
		t.Errorf("want active after 2 approvals, got %q", req.Status)
	}
	if req.Token == "" {
		t.Error("expected non-empty token when active")
	}
}

func TestRequesterCannotSelfApprove(t *testing.T) {
	m := newManager(t)
	ctx := context.Background()

	req, _ := m.Request(ctx, "user-alice", "INC-002", "Self-approve test", time.Hour, model.CategoryCustomer)
	_, err := m.Approve(ctx, req.ID, "user-alice")
	if err == nil {
		t.Error("expected error: requester cannot self-approve")
	}
}

func TestSameApproverCannotApproveTwice(t *testing.T) {
	m := newManager(t)
	ctx := context.Background()

	req, _ := m.Request(ctx, "user-alice", "INC-003", "Duplicate approver test", time.Hour, model.CategoryCustomer)
	_, _ = m.Approve(ctx, req.ID, "approver-bob")
	_, err := m.Approve(ctx, req.ID, "approver-bob")
	if err == nil {
		t.Error("expected error: same approver cannot approve twice")
	}
}

func TestMaxDurationExceeded(t *testing.T) {
	m := newManager(t)
	_, err := m.Request(context.Background(), "user", "INC-004", "Too long", 5*time.Hour, model.CategoryCustomer)
	if err == nil {
		t.Error("expected error: duration exceeds maximum 4h")
	}
}

func TestValidateToken_Active(t *testing.T) {
	m := newManager(t)
	ctx := context.Background()

	req, _ := m.Request(ctx, "user-alice", "INC-005", "Validate test", time.Hour, model.CategoryCustomer)
	m.Approve(ctx, req.ID, "approver-bob")  //nolint:errcheck
	req, _ = m.Approve(ctx, req.ID, "approver-carol")

	found, err := m.ValidateToken(req.Token)
	if err != nil {
		t.Fatalf("ValidateToken error: %v", err)
	}
	if found.ID != req.ID {
		t.Errorf("wrong request returned: want %q, got %q", req.ID, found.ID)
	}
}

func TestValidateToken_Invalid(t *testing.T) {
	m := newManager(t)
	_, err := m.ValidateToken("not-a-real-token")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestRevoke_Active_OK(t *testing.T) {
	m := newManager(t)
	ctx := context.Background()

	req, _ := m.Request(ctx, "user-alice", "INC-006", "Revoke test", time.Hour, model.CategoryCustomer)
	m.Approve(ctx, req.ID, "approver-bob")   //nolint:errcheck
	req, _ = m.Approve(ctx, req.ID, "approver-carol")

	if err := m.Revoke(ctx, req.ID, "admin"); err != nil {
		t.Fatalf("Revoke error: %v", err)
	}

	// Verify revoked state.
	got, err := m.Get(req.ID)
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if got.Status != model.BGStatusRevoked {
		t.Errorf("want revoked, got %q", got.Status)
	}
}

func TestRevoke_AlreadyRevoked_Error(t *testing.T) {
	m := newManager(t)
	ctx := context.Background()

	req, _ := m.Request(ctx, "user-alice", "INC-007", "Double-revoke test", time.Hour, model.CategoryCustomer)
	m.Approve(ctx, req.ID, "approver-bob")  //nolint:errcheck
	req, _ = m.Approve(ctx, req.ID, "approver-carol")
	m.Revoke(ctx, req.ID, "admin") //nolint:errcheck

	err := m.Revoke(ctx, req.ID, "admin")
	if err == nil {
		t.Error("expected error revoking an already-revoked request")
	}
}
