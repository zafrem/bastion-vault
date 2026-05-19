package access

import (
	"context"
	"fmt"

	"github.com/zafrem/bastion-vault/internal/model"
)

// rbacMatrix encodes the SRS §3.5 RBAC table.
// Key format: "department:role" → category → AccessLevel
var rbacMatrix = map[string]map[model.DataCategory]model.AccessLevel{
	"marketing:manager": {
		model.CategoryCustomer:      model.AccessFull,
		model.CategoryManufacturing: model.AccessRead,
		model.CategoryHRFinance:     model.AccessAggregated,
	},
	"marketing:analyst": {
		model.CategoryCustomer:      model.AccessKAnonymized,
		model.CategoryManufacturing: model.AccessKAnonymized,
		model.CategoryHRFinance:     model.AccessAggregated,
	},
	"manufacturing:manager": {
		model.CategoryCustomer:      model.AccessSlice,
		model.CategoryManufacturing: model.AccessFull,
		model.CategoryHRFinance:     model.AccessNone,
	},
	"manufacturing:staff": {
		model.CategoryCustomer:      model.AccessSlice,
		model.CategoryManufacturing: model.AccessFull,
		model.CategoryHRFinance:     model.AccessNone,
	},
	"hr:manager": {
		model.CategoryCustomer:      model.AccessNone,
		model.CategoryManufacturing: model.AccessNone,
		model.CategoryHRFinance:     model.AccessFull,
	},
	"hr:staff": {
		model.CategoryCustomer:      model.AccessNone,
		model.CategoryManufacturing: model.AccessNone,
		model.CategoryHRFinance:     model.AccessAnonymized,
	},
	"executive:executive": {
		model.CategoryCustomer:      model.AccessAggregated,
		model.CategoryManufacturing: model.AccessAggregated,
		model.CategoryHRFinance:     model.AccessAggregated,
	},
	"audit:auditor": {
		model.CategoryCustomer:      model.AccessAuditLog,
		model.CategoryManufacturing: model.AccessAuditLog,
		model.CategoryHRFinance:     model.AccessAuditLog,
	},
}

// deanonymizeRoles lists the role keys that have deanonymize rights per SRS §3.5
var deanonymizeRoles = map[string]map[model.DataCategory]bool{
	"marketing:manager": {model.CategoryCustomer: true},
	"hr:manager":        {model.CategoryHRFinance: true},
}

// Controller makes access control decisions using an embedded RBAC matrix
// and optionally delegates to OPA for complex policy evaluation.
type Controller struct {
	opaEndpoint string // empty = OPA disabled, use built-in RBAC only
}

// NewController creates a Controller. Pass an empty opaEndpoint to use built-in RBAC only.
func NewController(opaEndpoint string) *Controller {
	return &Controller{opaEndpoint: opaEndpoint}
}

// Decide returns an AccessDecision for the given user and data category.
func (c *Controller) Decide(ctx context.Context, user *model.User, category model.DataCategory) (*model.AccessDecision, error) {
	key := fmt.Sprintf("%s:%s", user.Department, user.Role)
	catMap, ok := rbacMatrix[key]
	if !ok {
		return &model.AccessDecision{
			Allowed:     false,
			AccessLevel: model.AccessNone,
			Reason:      fmt.Sprintf("no RBAC rule for department=%s role=%s", user.Department, user.Role),
		}, nil
	}

	level, ok := catMap[category]
	if !ok || level == model.AccessNone {
		return &model.AccessDecision{
			Allowed:     false,
			AccessLevel: model.AccessNone,
			Reason:      "access denied by RBAC policy",
		}, nil
	}

	if c.opaEndpoint != "" {
		return c.evaluateOPA(ctx, user, category, level)
	}

	return &model.AccessDecision{
		Allowed:     true,
		AccessLevel: level,
		Reason:      "allowed by RBAC policy",
	}, nil
}

// CanDeanonymize reports whether the user may deanonymize records in the given category.
func (c *Controller) CanDeanonymize(user *model.User, category model.DataCategory) bool {
	key := fmt.Sprintf("%s:%s", user.Department, user.Role)
	cats, ok := deanonymizeRoles[key]
	if !ok {
		return false
	}
	return cats[category]
}

// evaluateOPA delegates to the OPA HTTP API for policy evaluation.
// This is a stub; in production the OPA client SDK (or HTTP call) would be used.
func (c *Controller) evaluateOPA(ctx context.Context, user *model.User, category model.DataCategory, fallback model.AccessLevel) (*model.AccessDecision, error) {
	// OPA policy evaluation is performed via HTTP POST to /v1/data/vault/allow.
	// If OPA is unreachable we fall back to the RBAC decision (fail-open is intentional
	// here because OPA is an additional constraint layer, not a replacement).
	return &model.AccessDecision{
		Allowed:     true,
		AccessLevel: fallback,
		Reason:      "allowed by RBAC (OPA integration placeholder)",
	}, nil
}

// EnforceMinimumLevel checks that the requested access level does not exceed what is allowed.
func EnforceMinimumLevel(requested, allowed model.AccessLevel) model.AccessLevel {
	if model.AccessLevelRank(requested) > model.AccessLevelRank(allowed) {
		return allowed
	}
	return requested
}
