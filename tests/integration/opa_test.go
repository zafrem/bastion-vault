//go:build integration

package integration

import (
	"context"
	"os"
	"testing"

	"github.com/zafrem/bastion-vault/internal/access"
	"github.com/zafrem/bastion-vault/internal/model"
)

func opaURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("TEST_OPA_URL")
	if url == "" {
		t.Skip("TEST_OPA_URL not set")
	}
	return url
}

func TestOPA_MarketingAnalyst_CustomerData(t *testing.T) {
	ctrl := access.NewController(opaURL(t))
	user := &model.User{
		UserID:     "u-001",
		Department: "marketing",
		Role:       "analyst",
		TenantID:   "tenant-a",
	}

	decision, err := ctrl.Decide(context.Background(), user, model.CategoryCustomer)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("expected Allowed=true, got false; reason: %s", decision.Reason)
	}
	if decision.AccessLevel != model.AccessKAnonymized {
		t.Errorf("expected AccessLevel=%s, got %s", model.AccessKAnonymized, decision.AccessLevel)
	}
}

func TestOPA_HRStaff_HRFinance_Allowed(t *testing.T) {
	ctrl := access.NewController(opaURL(t))
	user := &model.User{
		UserID:     "u-002",
		Department: "hr",
		Role:       "staff",
		TenantID:   "tenant-a",
	}

	decision, err := ctrl.Decide(context.Background(), user, model.CategoryHRFinance)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("expected Allowed=true, got false; reason: %s", decision.Reason)
	}
	if decision.AccessLevel != model.AccessAnonymized {
		t.Errorf("expected AccessLevel=%s, got %s", model.AccessAnonymized, decision.AccessLevel)
	}
}

func TestOPA_ManufacturingManager_HRFinance_Denied(t *testing.T) {
	ctrl := access.NewController(opaURL(t))
	user := &model.User{
		UserID:     "u-003",
		Department: "manufacturing",
		Role:       "manager",
		TenantID:   "tenant-a",
	}

	decision, err := ctrl.Decide(context.Background(), user, model.CategoryHRFinance)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if decision.Allowed {
		t.Errorf("expected Allowed=false, got true; access_level: %s", decision.AccessLevel)
	}
}

func TestOPA_ReloadPolicies(t *testing.T) {
	ctrl := access.NewController(opaURL(t))
	if err := ctrl.ReloadPolicies(context.Background()); err != nil {
		t.Errorf("ReloadPolicies returned error: %v", err)
	}
}
