package output

import (
	"context"
	"fmt"
	"time"

	"github.com/zafrem/bastion-vault/internal/access"
	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/kanon"
	"github.com/zafrem/bastion-vault/internal/kms"
	"github.com/zafrem/bastion-vault/internal/model"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

// Per-category k-anonymity thresholds (FR-KO-001).
var categoryKThreshold = map[model.DataCategory]int{
	model.CategoryCustomer:      5,
	model.CategoryManufacturing: 3,
	model.CategoryHRFinance:     10,
}

// Processor wires every Phase 2 component together. It is safe for concurrent use:
// each call constructs its own working slice and the underlying components are
// either stateless or use sync.Map for their internal caches.
type Processor struct {
	resolver    *PermissionResolver
	generator   *ViewGenerator
	tokenRes    *TokenResolver
	inferDet    *InferenceDetector
	aggregator  *Aggregator
	crossTenant *CrossTenantVerifier
	kanon       *kanon.Validator
	access      *access.Controller
	audit       *audit.Logger
}

// NewProcessor constructs the Phase 2 processor with all collaborators initialised.
// kmsProvider and tokenStore may be nil during early bring-up; token resolution
// will then simply skip when invoked.
func NewProcessor(accessCtrl *access.Controller, auditLogger *audit.Logger, tokenStore tokendb.Store, kmsProvider kms.Provider) *Processor {
	canDeanon := func(u *model.UserContext, cat model.DataCategory) bool {
		if accessCtrl == nil || u == nil {
			return false
		}
		// Materialise a *model.User from the UserContext for the controller.
		role := ""
		if len(u.Roles) > 0 {
			role = u.Roles[0]
		}
		return accessCtrl.CanDeanonymize(&model.User{
			UserID:     u.UserID,
			TenantID:   u.TenantID,
			Department: u.Department,
			Role:       role,
		}, cat)
	}

	return &Processor{
		resolver:    NewPermissionResolver(accessCtrl),
		generator:   NewViewGenerator(),
		tokenRes:    NewTokenResolver(tokenStore, kmsProvider, canDeanon),
		inferDet:    NewInferenceDetector(),
		aggregator:  NewAggregator(),
		crossTenant: NewCrossTenantVerifier(),
		kanon:       kanon.New(),
		access:      accessCtrl,
		audit:       auditLogger,
	}
}

// ProcessRequest is the unit of work for Process / ApplyPermissions.
type ProcessRequest struct {
	RequestID string
	User      *model.UserContext
	Records   []model.DataRecord
	Category  model.DataCategory
	Query     QueryParams
}

// Process runs the full Phase 2 pipeline:
//  1. Cross-tenant verification.
//  2. Permission resolution.
//  3. Inference attack detection (may force a more restrictive level).
//  4. Token resolution (only for users with deanonymize rights).
//  5. View generation (per-access-level transformation).
//  6. K-anonymity verification at the set level (k_anonymized only).
//  7. Audit log emission.
func (p *Processor) Process(ctx context.Context, req ProcessRequest) (*model.PermissionResponse, error) {
	return p.process(ctx, req, true /* resolve tokens */)
}

// ApplyPermissions is identical to Process but skips token resolution. This is the
// default Phase 2 entry point: tokens stay opaque, and the caller must use
// ResolveTokens for explicit, audited de-anonymization.
func (p *Processor) ApplyPermissions(ctx context.Context, req ProcessRequest) (*model.PermissionResponse, error) {
	return p.process(ctx, req, false /* skip token resolution */)
}

func (p *Processor) process(ctx context.Context, req ProcessRequest, resolveTokens bool) (*model.PermissionResponse, error) {
	start := time.Now()
	if req.User == nil {
		return nil, fmt.Errorf("processor: nil user context")
	}

	resp := &model.PermissionResponse{
		RequestID: req.RequestID,
		Decisions: model.PermissionDecisions{
			TotalInput: len(req.Records),
		},
	}

	// 1. Cross-tenant filter.
	filtered, err := p.crossTenant.Verify(ctx, req.Records, req.User.TenantID)
	if err != nil {
		return nil, fmt.Errorf("processor: cross-tenant: %w", err)
	}
	resp.Decisions.FilteredOut = len(req.Records) - len(filtered)

	// 2. Permission resolution.
	userForRBAC := &model.User{
		UserID:     req.User.UserID,
		TenantID:   req.User.TenantID,
		Department: req.User.Department,
	}
	if len(req.User.Roles) > 0 {
		userForRBAC.Role = req.User.Roles[0]
	}
	level, err := p.resolver.Resolve(ctx, userForRBAC, req.Category)
	if err != nil {
		return nil, fmt.Errorf("processor: resolving permission: %w", err)
	}
	if level == model.AccessNone {
		resp.Status = "DENIED"
		resp.Decisions.AccessLevelApplied = string(model.AccessNone)
		resp.ProcessingTimeMs = time.Since(start).Milliseconds()
		p.logDecision(ctx, req, resp, "access_denied")
		return resp, nil
	}

	// 3. Inference attack detection. A block here trumps the access level decision.
	risk, ierr := p.inferDet.Detect(ctx, req.User, req.Query)
	if ierr == nil {
		switch risk.Action {
		case "block":
			resp.Status = "DENIED"
			resp.Decisions.AccessLevelApplied = string(level)
			resp.Decisions.Strategy = "inference_block"
			resp.ProcessingTimeMs = time.Since(start).Milliseconds()
			p.logDecision(ctx, req, resp, "inference_attack_blocked")
			return resp, nil
		case "generalize":
			// Force the most-restrictive analytical view.
			if model.AccessLevelRank(level) > model.AccessLevelRank(model.AccessKAnonymized) {
				level = model.AccessKAnonymized
			}
		}
	}

	// 4. Optional token resolution (only if asked & authorised).
	if resolveTokens {
		for i := range filtered {
			if terr := p.tokenRes.ResolveFields(ctx, &filtered[i], req.User); terr != nil {
				return nil, fmt.Errorf("processor: token resolution: %w", terr)
			}
		}
	}

	// 5. Aggregation has set-level semantics. Compute it here and short-circuit.
	if level == model.AccessAggregated {
		agg, aerr := p.aggregator.Aggregate(ctx, filtered, req.Category)
		if aerr != nil {
			return nil, fmt.Errorf("processor: aggregating: %w", aerr)
		}
		resp.FilteredRecords = []model.DataRecord{agg}
		resp.Decisions.AccessLevelApplied = string(level)
		resp.Decisions.Strategy = "aggregation"
		resp.Decisions.Aggregated = len(filtered)
		resp.Decisions.Returned = 1
		resp.Status = "AGGREGATED"
		resp.ProcessingTimeMs = time.Since(start).Milliseconds()
		p.logDecision(ctx, req, resp, "aggregated_view")
		return resp, nil
	}

	// 6. View generation.
	views, disclosures, gerr := p.generator.Generate(ctx, filtered, req.User, level)
	if gerr != nil {
		return nil, fmt.Errorf("processor: view generation: %w", gerr)
	}
	resp.FilteredRecords = views
	resp.Audit = disclosures
	resp.Decisions.AccessLevelApplied = string(level)
	resp.Decisions.Returned = len(views)

	// 7. K-anonymity set-level verification for k_anonymized.
	if level == model.AccessKAnonymized && len(views) > 0 {
		k := categoryKThreshold[req.Category]
		if k == 0 {
			k = 5
		}
		raw := recordsAsMaps(views)
		report, generalized, verr := p.kanon.ValidateAndGeneralize(ctx, raw, req.Category, k)
		if verr == nil {
			if !report.Valid {
				// Could not satisfy K — suppress and return aggregated view instead.
				agg, _ := p.aggregator.Aggregate(ctx, filtered, req.Category)
				resp.FilteredRecords = []model.DataRecord{agg}
				resp.Decisions.Strategy = "k_anon_failed_aggregated"
				resp.Decisions.Aggregated = len(filtered)
				resp.Decisions.Returned = 1
				resp.Status = "GENERALIZED"
			} else if len(report.GeneralizationSteps) > 0 {
				// Merge generalized values back into the view records.
				mergeMapsIntoRecords(views, generalized)
				resp.FilteredRecords = views
				resp.Decisions.Strategy = "k_anon_generalized"
				resp.Status = "GENERALIZED"
			} else {
				resp.Decisions.Strategy = "k_anon_satisfied"
				resp.Status = "SUCCESS"
			}
		} else {
			resp.Decisions.Strategy = "k_anon_unverified"
			resp.Status = "SUCCESS"
		}
		resp.Decisions.Anonymized = resp.Decisions.Returned
	} else {
		if resp.Status == "" {
			resp.Status = "SUCCESS"
		}
		if resp.Decisions.Strategy == "" {
			resp.Decisions.Strategy = strategyFor(level)
		}
		if level == model.AccessAnonymized || level == model.AccessSlice {
			resp.Decisions.Anonymized = resp.Decisions.Returned
		}
	}

	resp.ProcessingTimeMs = time.Since(start).Milliseconds()
	p.logDecision(ctx, req, resp, "permissions_applied")
	return resp, nil
}

// ResolveTokens performs only the token-resolution step. It does NOT apply view
// transformations: the caller is expected to have the necessary deanonymize rights.
func (p *Processor) ResolveTokens(ctx context.Context, records []model.DataRecord, user *model.UserContext) ([]model.DataRecord, error) {
	if user == nil {
		return nil, fmt.Errorf("processor: nil user")
	}
	// Cross-tenant first.
	filtered, err := p.crossTenant.Verify(ctx, records, user.TenantID)
	if err != nil {
		return nil, err
	}
	out := make([]model.DataRecord, len(filtered))
	for i := range filtered {
		out[i] = cloneRecord(filtered[i])
		if terr := p.tokenRes.ResolveFields(ctx, &out[i], user); terr != nil {
			return nil, terr
		}
	}
	return out, nil
}

// VerifyAccess returns the access decision for the user against a category without
// transforming any records. This is the "pre-check" endpoint.
func (p *Processor) VerifyAccess(ctx context.Context, user *model.UserContext, category model.DataCategory) (*model.AccessDecision, error) {
	if user == nil {
		return nil, fmt.Errorf("processor: nil user")
	}
	role := ""
	if len(user.Roles) > 0 {
		role = user.Roles[0]
	}
	mUser := &model.User{
		UserID:     user.UserID,
		TenantID:   user.TenantID,
		Department: user.Department,
		Role:       role,
	}
	return p.access.Decide(ctx, mUser, category)
}

// InferenceDetector exposes the underlying detector so callers can run a standalone
// risk check without going through the full pipeline.
func (p *Processor) InferenceDetector() *InferenceDetector { return p.inferDet }

// KAnonValidator exposes the underlying k-anonymity validator.
func (p *Processor) KAnonValidator() *kanon.Validator { return p.kanon }

// logDecision emits an audit entry for one Phase 2 decision. Errors are swallowed
// after logging — the caller already has the response and must not fail because of
// an audit write.
func (p *Processor) logDecision(ctx context.Context, req ProcessRequest, resp *model.PermissionResponse, outcome string) {
	if p.audit == nil {
		return
	}
	userID := ""
	if req.User != nil {
		userID = req.User.UserID
	}
	tenantID := ""
	if req.User != nil {
		tenantID = req.User.TenantID
	}
	_, _ = p.audit.Log(ctx, model.AuditEvent{
		TenantID:     tenantID,
		EventType:    model.AuditEventAccess,
		ActorID:      userID,
		ResourceType: string(req.Category),
		ResourceID:   req.RequestID,
		Action:       "vault_out_process",
		Outcome:      outcome,
		Metadata: map[string]any{
			"request_id":          req.RequestID,
			"status":              resp.Status,
			"records_in":          resp.Decisions.TotalInput,
			"records_returned":    resp.Decisions.Returned,
			"records_filtered":    resp.Decisions.FilteredOut,
			"records_aggregated":  resp.Decisions.Aggregated,
			"access_level":        resp.Decisions.AccessLevelApplied,
			"strategy":            resp.Decisions.Strategy,
			"processing_time_ms":  resp.ProcessingTimeMs,
			"field_decisions":     len(resp.Audit),
		},
	})
}

// strategyFor returns the default strategy label for a non-aggregated level.
func strategyFor(level model.AccessLevel) string {
	switch level {
	case model.AccessFull:
		return "deanonymization"
	case model.AccessRead:
		return "passthrough"
	case model.AccessAnonymized:
		return "pseudonymization"
	case model.AccessKAnonymized:
		return "generalization"
	case model.AccessSlice:
		return "slice_filter"
	case model.AccessAuditLog:
		return "metadata_only"
	default:
		return "fail_safe"
	}
}

// recordsAsMaps flattens the views into the map[string]any shape the k-anon
// validator expects. Field values are emitted using their .Value directly because
// the validator only inspects quasi-identifier fields by name.
func recordsAsMaps(records []model.DataRecord) []map[string]any {
	out := make([]map[string]any, 0, len(records))
	for _, r := range records {
		m := make(map[string]any, len(r.Fields))
		for k, v := range r.Fields {
			m[k] = v.Value
		}
		out = append(out, m)
	}
	return out
}

// mergeMapsIntoRecords copies generalized field values from the validator's output
// back into the structured DataRecords, preserving their existing FieldValue
// metadata (PII type, state type).
func mergeMapsIntoRecords(records []model.DataRecord, maps []map[string]any) {
	for i := range records {
		if i >= len(maps) {
			return
		}
		for name, val := range maps[i] {
			existing := records[i].Fields[name]
			existing.Value = val
			if existing.Type == "" {
				existing.Type = "generalized"
			}
			records[i].Fields[name] = existing
		}
	}
}

// cloneRecord produces a deep-enough copy of a DataRecord that callers may mutate
// it without affecting the caller's input.
func cloneRecord(rec model.DataRecord) model.DataRecord {
	out := model.DataRecord{
		RecordID: rec.RecordID,
		Category: rec.Category,
		TenantID: rec.TenantID,
		Fields:   make(map[string]model.FieldValue, len(rec.Fields)),
	}
	for k, v := range rec.Fields {
		out.Fields[k] = v
	}
	return out
}
