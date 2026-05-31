package access_test

import (
	"context"
	"testing"

	"github.com/zafrem/bastion-vault/internal/access"
	"github.com/zafrem/bastion-vault/internal/model"
)

func newUser(dept, role string) *model.User {
	return &model.User{Department: dept, Role: role}
}

func TestDecide_MarketingAnalyst_CustomerCategory(t *testing.T) {
	c := access.NewController("")
	d, err := c.Decide(context.Background(), newUser("marketing", "analyst"), model.CategoryCustomer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.Allowed {
		t.Errorf("expected allowed, got denied: %s", d.Reason)
	}
	if d.AccessLevel != model.AccessKAnonymized {
		t.Errorf("expected k_anonymized, got %q", d.AccessLevel)
	}
}

func TestDecide_MarketingAnalyst_HRFinance(t *testing.T) {
	c := access.NewController("")
	d, err := c.Decide(context.Background(), newUser("marketing", "analyst"), model.CategoryHRFinance)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.Allowed {
		t.Errorf("expected allowed, got denied: %s", d.Reason)
	}
	if d.AccessLevel != model.AccessAggregated {
		t.Errorf("expected aggregated, got %q", d.AccessLevel)
	}
}

func TestDecide_ManufacturingManager_HRFinance_Denied(t *testing.T) {
	c := access.NewController("")
	d, err := c.Decide(context.Background(), newUser("manufacturing", "manager"), model.CategoryHRFinance)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Allowed {
		t.Errorf("expected denied, got allowed with level=%q", d.AccessLevel)
	}
}

func TestDecide_HRManager_HRFinance_Allowed(t *testing.T) {
	c := access.NewController("")
	d, err := c.Decide(context.Background(), newUser("hr", "manager"), model.CategoryHRFinance)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.Allowed {
		t.Errorf("expected allowed, got denied: %s", d.Reason)
	}
	if d.AccessLevel != model.AccessFull {
		t.Errorf("expected full access, got %q", d.AccessLevel)
	}
}

func TestDecide_UnknownRole_Denied(t *testing.T) {
	c := access.NewController("")
	d, err := c.Decide(context.Background(), newUser("ghost", "phantom"), model.CategoryCustomer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Allowed {
		t.Error("expected denied for unknown dept:role")
	}
}

func TestCanDeanonymize(t *testing.T) {
	c := access.NewController("")

	cases := []struct {
		dept, role string
		cat        model.DataCategory
		want       bool
	}{
		{"marketing", "manager", model.CategoryCustomer, true},
		{"hr", "manager", model.CategoryHRFinance, true},
		{"hr", "staff", model.CategoryHRFinance, false},
		{"marketing", "analyst", model.CategoryCustomer, false},
	}

	for _, tc := range cases {
		got := c.CanDeanonymize(newUser(tc.dept, tc.role), tc.cat)
		if got != tc.want {
			t.Errorf("dept=%q role=%q cat=%q: want %v, got %v", tc.dept, tc.role, tc.cat, tc.want, got)
		}
	}
}

func TestEnforceMinimumLevel(t *testing.T) {
	cases := []struct {
		requested model.AccessLevel
		allowed   model.AccessLevel
		want      model.AccessLevel
	}{
		// Requesting more than allowed → capped to allowed
		{model.AccessFull, model.AccessKAnonymized, model.AccessKAnonymized},
		// Requesting less than allowed → keep requested
		{model.AccessAggregated, model.AccessFull, model.AccessAggregated},
		// Same level → unchanged
		{model.AccessAnonymized, model.AccessAnonymized, model.AccessAnonymized},
	}
	for _, tc := range cases {
		got := access.EnforceMinimumLevel(tc.requested, tc.allowed)
		if got != tc.want {
			t.Errorf("requested=%q allowed=%q: want %q, got %q", tc.requested, tc.allowed, tc.want, got)
		}
	}
}

// ─── Data steward role (FR-MR-04-004) ─────────────────────────────────────────

func stewardUser(tenantID, dept string) *model.User {
	return &model.User{TenantID: tenantID, Department: dept, Role: "data_steward"}
}

func TestCanActAsSteward_NotRegistered_Denied(t *testing.T) {
	c := access.NewController("")
	// No stewards registered at all.
	if c.CanActAsSteward(stewardUser("acme", "hr"), "hr_docs") {
		t.Error("expected deny when no stewards registered")
	}
}

func TestCanActAsSteward_RegisteredDomain_Allowed(t *testing.T) {
	c := access.NewController("")
	c.RegisterSteward("acme", "hr", []string{"hr_docs", "payroll_docs"})

	if !c.CanActAsSteward(stewardUser("acme", "hr"), "hr_docs") {
		t.Error("expected allow for registered domain")
	}
	if !c.CanActAsSteward(stewardUser("acme", "hr"), "payroll_docs") {
		t.Error("expected allow for second registered domain")
	}
}

func TestCanActAsSteward_WrongDomain_Denied(t *testing.T) {
	c := access.NewController("")
	c.RegisterSteward("acme", "hr", []string{"hr_docs"})
	// Registered as steward, but not for customer_docs.
	if c.CanActAsSteward(stewardUser("acme", "hr"), "customer_docs") {
		t.Error("expected deny for an unregistered domain")
	}
}

func TestCanActAsSteward_WrongDepartment_Denied(t *testing.T) {
	c := access.NewController("")
	c.RegisterSteward("acme", "hr", []string{"hr_docs"})
	// User is in a different department.
	if c.CanActAsSteward(stewardUser("acme", "marketing"), "hr_docs") {
		t.Error("expected deny for a non-steward department")
	}
}

func TestCanActAsSteward_WrongTenant_Denied(t *testing.T) {
	c := access.NewController("")
	c.RegisterSteward("acme", "hr", []string{"hr_docs"})
	// Same dept/domain, different tenant — must be isolated.
	if c.CanActAsSteward(stewardUser("rival", "hr"), "hr_docs") {
		t.Error("expected deny — steward registry must be tenant-scoped")
	}
}

func TestLoadStewardsFromTenant(t *testing.T) {
	c := access.NewController("")
	cfg := &model.TenantConfig{
		ID: "acme",
		StewardDomains: map[string][]string{
			"hr":    {"hr_docs"},
			"audit": {"customer_docs", "hr_docs"},
		},
	}
	c.LoadStewardsFromTenant(cfg)

	if !c.CanActAsSteward(stewardUser("acme", "hr"), "hr_docs") {
		t.Error("hr steward should be loaded from TenantConfig")
	}
	if !c.CanActAsSteward(stewardUser("acme", "audit"), "customer_docs") {
		t.Error("audit steward should be loaded for customer_docs")
	}
	if c.CanActAsSteward(stewardUser("acme", "audit"), "payroll_docs") {
		t.Error("audit steward should NOT have payroll_docs (not in config)")
	}
}

// A data_steward must remain content-blind: standard RBAC returns AccessNone
// for every category (separation of authority).
func TestDataSteward_ContentBlind(t *testing.T) {
	c := access.NewController("")
	for _, cat := range []model.DataCategory{
		model.CategoryCustomer, model.CategoryManufacturing, model.CategoryHRFinance,
	} {
		d, err := c.Decide(context.Background(), newUser("hr", "data_steward"), cat)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if d.Allowed {
			t.Errorf("data_steward must be denied content access for %q (got allowed)", cat)
		}
		if d.AccessLevel != model.AccessNone {
			t.Errorf("data_steward must have AccessNone for %q, got %q", cat, d.AccessLevel)
		}
	}
}
