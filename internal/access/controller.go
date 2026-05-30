package access

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

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
	httpClient  *http.Client
}

// NewController creates a Controller. Pass an empty opaEndpoint to use built-in RBAC only.
func NewController(opaEndpoint string) *Controller {
	return &Controller{
		opaEndpoint: opaEndpoint,
		httpClient: &http.Client{
			Timeout: 2 * time.Second,
		},
	}
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

// AllowedCategories returns all categories the user has any access to.
func (c *Controller) AllowedCategories(user *model.User) []string {
	key := fmt.Sprintf("%s:%s", user.Department, user.Role)
	catMap, ok := rbacMatrix[key]
	if !ok {
		return nil
	}

	var allowed []string
	for cat, level := range catMap {
		if level != model.AccessNone {
			allowed = append(allowed, string(cat))
		}
	}
	return allowed
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

// ReloadPolicies signals OPA to reload its policies by checking the OPA endpoint health.
// If OPA is unavailable this is a no-op (policies are already embedded in RBAC).
func (c *Controller) ReloadPolicies(ctx context.Context) error {
	if c.opaEndpoint == "" {
		return nil
	}
	// Ping OPA by issuing a query to a well-known endpoint.
	reqURL := c.opaEndpoint + "/v1/data"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("access: building OPA reload request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("access: OPA unreachable during reload: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("access: OPA reload returned status %d", resp.StatusCode)
	}
	return nil
}

// opaInput is the JSON body sent to OPA.
type opaInput struct {
	Input opaInputData `json:"input"`
}

type opaInputData struct {
	User     opaUser     `json:"user"`
	Resource opaResource `json:"resource"`
	Action   string      `json:"action"`
}

type opaUser struct {
	UserID     string `json:"user_id"`
	Department string `json:"department"`
	Role       string `json:"role"`
	TenantID   string `json:"tenant_id"`
}

type opaResource struct {
	Category string `json:"category"`
	Purpose  string `json:"purpose,omitempty"` // MR-04-003
}

type opaAllowResponse struct {
	Result bool `json:"result"`
}

type opaAccessLevelResponse struct {
	Result string `json:"result"`
}

// evaluateOPA delegates to the OPA HTTP API for policy evaluation.
// If OPA is unreachable or returns non-200, falls back to RBAC decision (fail-open).
func (c *Controller) evaluateOPA(ctx context.Context, user *model.User, category model.DataCategory, fallback model.AccessLevel) (*model.AccessDecision, error) {
	userID := user.UserID
	if userID == "" {
		userID = user.ID
	}

	input := opaInput{
		Input: opaInputData{
			User: opaUser{
				UserID:     userID,
				Department: user.Department,
				Role:       user.Role,
				TenantID:   user.TenantID,
			},
			Resource: opaResource{
				Category: "customer_data",
			},
			Action: "read",
		},
	}

	bodyBytes, err := json.Marshal(input)
	if err != nil {
		log.Printf("access: OPA marshal error: %v — falling back to RBAC", err)
		return c.rbacDecision(fallback), nil
	}

	// Query allow policy.
	allowed, err := c.queryOPABool(ctx, c.opaEndpoint+"/v1/data/bastion/vault/access/allow", bodyBytes)
	if err != nil {
		log.Printf("access: OPA allow query failed: %v — falling back to RBAC", err)
		return c.rbacDecision(fallback), nil
	}

	if !allowed {
		return &model.AccessDecision{
			Allowed:     false,
			AccessLevel: model.AccessNone,
			Reason:      "denied by OPA policy",
		}, nil
	}

	// Query access_level policy.
	levelStr, err := c.queryOPAString(ctx, c.opaEndpoint+"/v1/data/bastion/vault/access/access_level", bodyBytes)
	if err != nil {
		log.Printf("access: OPA access_level query failed: %v — falling back to RBAC level", err)
		return c.rbacDecision(fallback), nil
	}

	level := mapOPAAccessLevel(levelStr, fallback)
	return &model.AccessDecision{
		Allowed:     true,
		AccessLevel: level,
		Reason:      "allowed by OPA policy",
	}, nil
}

func (c *Controller) rbacDecision(level model.AccessLevel) *model.AccessDecision {
	return &model.AccessDecision{
		Allowed:     true,
		AccessLevel: level,
		Reason:      "allowed by RBAC (OPA fallback)",
	}
}

func (c *Controller) queryOPABool(ctx context.Context, url string, body []byte) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("OPA returned status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var result opaAllowResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return false, err
	}
	return result.Result, nil
}

func (c *Controller) queryOPAString(ctx context.Context, url string, body []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OPA returned status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result opaAccessLevelResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", err
	}
	return result.Result, nil
}

// mapOPAAccessLevel converts an OPA access level string to model.AccessLevel.
func mapOPAAccessLevel(s string, fallback model.AccessLevel) model.AccessLevel {
	switch s {
	case "full":
		return model.AccessFull
	case "read":
		return model.AccessRead
	case "anonymized":
		return model.AccessAnonymized
	case "k_anonymized":
		return model.AccessKAnonymized
	case "slice":
		return model.AccessSlice
	case "aggregated":
		return model.AccessAggregated
	case "audit_log":
		return model.AccessAuditLog
	case "none":
		return model.AccessNone
	default:
		return fallback
	}
}

// purposeMatrix defines which roles/departments are permitted for a given purpose × category.
// A missing entry means the purpose is permitted (default-allow for non-sensitive purposes).
// training_data is never permitted via standard RBAC; it requires a break-glass override.
var purposeMatrix = map[model.Purpose]map[model.DataCategory][]string{
	model.PurposeHRAnalytics: {
		model.CategoryHRFinance: {"hr", "executive", "audit"},
	},
	model.PurposeLegal: {
		model.CategoryCustomer:      {"audit", "executive"},
		model.CategoryHRFinance:     {"audit", "executive"},
		model.CategoryManufacturing: {"audit", "executive"},
	},
	model.PurposeAudit: {
		model.CategoryCustomer:      {"audit"},
		model.CategoryHRFinance:     {"audit"},
		model.CategoryManufacturing: {"audit"},
	},
}

// DecideWithPurpose extends Decide with purpose × RBAC conjunction (MR-04-003).
// Returns a PurposeViolation flag when RBAC allows but purpose check fails.
func (c *Controller) DecideWithPurpose(
	ctx context.Context,
	user *model.User,
	category model.DataCategory,
	purpose model.Purpose,
) (*model.AccessDecision, error) {
	// training_data always requires explicit break-glass — never via standard path.
	if purpose == model.PurposeTrainingData {
		return &model.AccessDecision{
			Allowed:          false,
			AccessLevel:      model.AccessNone,
			Reason:           "training_data purpose requires explicit break-glass authorisation",
			PurposeViolation: true,
		}, nil
	}

	// Step 1: standard RBAC check.
	decision, err := c.Decide(ctx, user, category)
	if err != nil || !decision.Allowed {
		return decision, err
	}

	// Step 2: purpose check.
	if !purposePermitted(purpose, user.Department, category) {
		return &model.AccessDecision{
			Allowed:          false,
			AccessLevel:      model.AccessNone,
			Reason:           fmt.Sprintf("purpose %q not permitted for department %q on category %s", purpose, user.Department, category),
			PurposeViolation: true,
		}, nil
	}

	return decision, nil
}

// purposePermitted returns true when the department is allowed to use the given
// purpose for the given data category. When no restriction is defined for a
// purpose × category pair, the access defaults to allowed.
func purposePermitted(purpose model.Purpose, department string, category model.DataCategory) bool {
	catMap, restricted := purposeMatrix[purpose]
	if !restricted {
		return true // no restriction defined for this purpose
	}
	allowedDepts, restricted := catMap[category]
	if !restricted {
		return true // purpose unrestricted for this category
	}
	for _, d := range allowedDepts {
		if d == department {
			return true
		}
	}
	return false
}

// EnforceMinimumLevel checks that the requested access level does not exceed what is allowed.
func EnforceMinimumLevel(requested, allowed model.AccessLevel) model.AccessLevel {
	if model.AccessLevelRank(requested) > model.AccessLevelRank(allowed) {
		return allowed
	}
	return requested
}
