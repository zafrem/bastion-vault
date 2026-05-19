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
