package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/zafrem/bastion-vault/internal/access"
	"github.com/zafrem/bastion-vault/internal/anonymizer"
	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/breakglass"
	"github.com/zafrem/bastion-vault/internal/cache"
	"github.com/zafrem/bastion-vault/internal/classification"
	"github.com/zafrem/bastion-vault/internal/config"
	"github.com/zafrem/bastion-vault/internal/kanon"
	"github.com/zafrem/bastion-vault/internal/model"
	"github.com/zafrem/bastion-vault/internal/output"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

// Server wraps all service dependencies and exposes the HTTP router.
type Server struct {
	engine      *anonymizer.Engine
	classifier  *classification.Classifier
	controller  *access.Controller
	kanon       *kanon.Validator
	bgManager   *breakglass.Manager
	auditor     *audit.Logger
	tokenStore  tokendb.Store
	processor   *output.Processor
	cfg         *config.Config
	redisClient *cache.Client
	startTime   time.Time
}

// New constructs a Server from its service dependencies. processor may be nil
// (only the Phase 2 endpoints are affected — they will return 503).
// redisClient may be nil — token blacklisting is silently disabled when Redis
// is not configured.
func New(
	eng *anonymizer.Engine,
	cls *classification.Classifier,
	ctrl *access.Controller,
	kv *kanon.Validator,
	bg *breakglass.Manager,
	aud *audit.Logger,
	store tokendb.Store,
	processor *output.Processor,
	cfg *config.Config,
	redisClient *cache.Client,
) *Server {
	return &Server{
		engine:      eng,
		classifier:  cls,
		controller:  ctrl,
		kanon:       kv,
		bgManager:   bg,
		auditor:     aud,
		tokenStore:  store,
		processor:   processor,
		cfg:         cfg,
		redisClient: redisClient,
		startTime:   time.Now(),
	}
}

// Router returns the configured chi router.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(loggingMiddleware)
	r.Use(metricsMiddleware)
	if s.cfg.RateLimit.Enabled {
		r.Use(rateLimitMiddleware(s.cfg.RateLimit.RPS, s.cfg.RateLimit.Burst))
	}
	r.Use(authMiddleware(s.cfg, s.redisClient))
	r.Use(tenantMiddleware)

	r.Get("/v1/health/live", s.handleLive)
	r.Get("/v1/health/ready", s.handleReady)
	r.Handle("/v1/metrics", promhttp.Handler())

	r.Get("/v1/vault/permissions/{userID}", s.handleGetPermissions)
	r.Post("/v1/vault/anonymize", s.handleAnonymize)
	r.Post("/v1/vault/anonymize/batch", s.handleAnonymizeBatch)
	r.Post("/v1/vault/deanonymize", s.handleDeanonymize)
	r.Post("/v1/vault/classify", s.handleClassify)
	r.Post("/v1/vault/detect-pii", s.handleDetectPII)
	r.Post("/v1/vault/k-anonymity/validate", s.handleKAnonymityValidate)
	r.Post("/v1/vault/break-glass/request", s.handleBGRequest)
	r.Post("/v1/vault/break-glass/approve", s.handleBGApprove)
	r.Post("/v1/vault/break-glass/revoke", s.handleBGRevoke)
	r.Get("/v1/vault/break-glass/{id}", s.handleBGStatus)

	// Phase 2 (Vault-OUT) endpoints
	r.Post("/v1/vault/apply-permissions", s.handleApplyPermissions)
	r.Post("/v1/vault/resolve-tokens", s.handleResolveTokens)
	r.Post("/v1/vault/verify-access", s.handleVerifyAccess)
	r.Post("/v1/vault/validate-output-set", s.handleValidateOutputSet)
	r.Post("/v1/vault/detect-inference", s.handleDetectInference)
	r.Post("/v1/vault/process", s.handleProcess)

	r.Delete("/v1/vault/tokens", s.handleErasure)

	r.Get("/v1/config", s.handleGetConfig)
	r.Post("/v1/config/reload", s.handleConfigReload)

	r.Get("/v1/vault/audit", s.handleAuditLog)

	return r
}

// userFromCtx retrieves the authenticated *model.User from the request context.
// Returns nil if no user has been injected (should not happen past authMiddleware).
func userFromCtx(ctx interface{ Value(any) any }) *model.User {
	// Accept context.Context via the standard interface.
	type ctxValuer interface {
		Value(key any) any
	}
	if c, ok := ctx.(ctxValuer); ok {
		if u, ok := c.Value(model.UserContextKey).(*model.User); ok {
			return u
		}
	}
	return nil
}

// categoryK maps a DataCategory to its minimum k-anonymity threshold.
func categoryK(cat model.DataCategory) int {
	switch cat {
	case model.CategoryCustomer:
		return 5
	case model.CategoryManufacturing:
		return 3
	case model.CategoryHRFinance:
		return 10
	default:
		return 5
	}
}

func (s *Server) handleGetPermissions(w http.ResponseWriter, r *http.Request) {
	// For testing purposes, we assume the user exists in our RBAC matrix.
	// In a real system, we'd lookup the user's department/role first.
	// Here we'll default to a "marketing:manager" for demonstration.
	userID := chi.URLParam(r, "userID")
	user := &model.User{
		UserID:     userID,
		Department: "marketing",
		Role:       "manager",
	}

	allowed := s.controller.AllowedCategories(user)
	jsonOK(w, map[string]any{
		"user_id":            userID,
		"allowed_categories": allowed,
	})
}

// handleLive is the Kubernetes liveness probe; always returns 200 when the process is alive.
func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]string{"status": "alive"})
}

// handleReady is the Kubernetes readiness probe.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{
		"status": "ready",
		"uptime": time.Since(s.startTime).String(),
	})
}

func (s *Server) handleAnonymize(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req model.AnonymizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	req.TenantID = tenantFromCtx(r.Context())

	decision, err := s.controller.Decide(r.Context(), user, req.Category)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !decision.Allowed {
		jsonError(w, decision.Reason, http.StatusForbidden)
		return
	}
	req.AccessLevel = decision.AccessLevel

	resp, err := s.engine.Anonymize(r.Context(), &req)
	if err != nil {
		anonymizeOpsTotal.With(prometheus.Labels{
			"category": string(req.Category),
			"outcome":  "error",
		}).Inc()
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	anonymizeOpsTotal.With(prometheus.Labels{
		"category": string(req.Category),
		"outcome":  "success",
	}).Inc()
	for strat, n := range resp.Metadata.StrategiesApplied {
		fieldsAnonymizedTotal.With(prometheus.Labels{"strategy": strat}).Add(float64(n))
	}

	// If access level requires k-anonymity, generalize until the dataset satisfies K.
	if decision.AccessLevel == model.AccessKAnonymized {
		_, generalizedRecords, gerr := s.kanon.ValidateAndGeneralize(r.Context(), resp.Records, req.Category, categoryK(req.Category))
		if gerr == nil {
			resp.Records = generalizedRecords
		}
	}

	jsonOK(w, resp)
}

// handleAnonymizeBatch anonymizes a batch of records in a single request.
// It enforces a maximum batch size and otherwise mirrors handleAnonymize.
func (s *Server) handleAnonymizeBatch(w http.ResponseWriter, r *http.Request) {
	const maxBatchSize = 1000

	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req model.AnonymizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	req.TenantID = tenantFromCtx(r.Context())

	if len(req.Records) > maxBatchSize {
		jsonError(w, fmt.Sprintf("batch size %d exceeds maximum of %d records", len(req.Records), maxBatchSize), http.StatusBadRequest)
		return
	}

	decision, err := s.controller.Decide(r.Context(), user, req.Category)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !decision.Allowed {
		jsonError(w, decision.Reason, http.StatusForbidden)
		return
	}
	req.AccessLevel = decision.AccessLevel

	resp, err := s.engine.Anonymize(r.Context(), &req)
	if err != nil {
		anonymizeOpsTotal.With(prometheus.Labels{
			"category": string(req.Category),
			"outcome":  "error",
		}).Inc()
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	anonymizeOpsTotal.With(prometheus.Labels{
		"category": string(req.Category),
		"outcome":  "success",
	}).Inc()
	for strat, n := range resp.Metadata.StrategiesApplied {
		fieldsAnonymizedTotal.With(prometheus.Labels{"strategy": strat}).Add(float64(n))
	}

	if decision.AccessLevel == model.AccessKAnonymized {
		_, generalizedRecords, gerr := s.kanon.ValidateAndGeneralize(r.Context(), resp.Records, req.Category, categoryK(req.Category))
		if gerr == nil {
			resp.Records = generalizedRecords
		}
	}

	jsonOK(w, resp)
}

func (s *Server) handleDeanonymize(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req model.DeanonymizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	req.TenantID = tenantFromCtx(r.Context())

	if !s.controller.CanDeanonymize(user, req.Category) {
		jsonError(w, "deanonymize not permitted for your role", http.StatusForbidden)
		return
	}

	decision, err := s.controller.Decide(r.Context(), user, req.Category)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !decision.Allowed {
		jsonError(w, decision.Reason, http.StatusForbidden)
		return
	}

	resp, err := s.engine.Deanonymize(r.Context(), &req)
	if err != nil {
		deanonymizeOpsTotal.With(prometheus.Labels{
			"category": string(req.Category),
			"outcome":  "error",
		}).Inc()
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	deanonymizeOpsTotal.With(prometheus.Labels{
		"category": string(req.Category),
		"outcome":  "success",
	}).Inc()
	jsonOK(w, resp)
}

func (s *Server) handleClassify(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	result := s.classifier.Classify(body.Records)
	jsonOK(w, result)
}

func (s *Server) handleDetectPII(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		Record map[string]any `json:"record"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	detections := s.classifier.DetectPII(body.Record)
	jsonOK(w, map[string]any{"detections": detections, "count": len(detections)})
}

func (s *Server) handleKAnonymityValidate(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		Records    []map[string]any   `json:"records"`
		Category   model.DataCategory `json:"category"`
		RequiredK  int                `json:"required_k"`
		Generalize bool               `json:"generalize"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	if body.RequiredK == 0 {
		body.RequiredK = 5
	}

	decision, err := s.controller.Decide(r.Context(), user, body.Category)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !decision.Allowed {
		jsonError(w, decision.Reason, http.StatusForbidden)
		return
	}

	if body.Generalize {
		report, records, err := s.kanon.ValidateAndGeneralize(r.Context(), body.Records, body.Category, body.RequiredK)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]any{"report": report, "records": records})
		return
	}

	report, err := s.kanon.Validate(r.Context(), body.Records, body.Category, body.RequiredK)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, report)
}

func (s *Server) handleBGRequest(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		IncidentID   string             `json:"incident_id"`
		Reason       string             `json:"reason"`
		DurationSecs int64              `json:"duration_seconds"`
		Category     model.DataCategory `json:"category"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Requester ID comes from the authenticated context, not the request body.
	requesterID := user.UserID
	if requesterID == "" {
		requesterID = user.ID
	}

	duration := time.Duration(body.DurationSecs) * time.Second
	req, err := s.bgManager.Request(r.Context(), requesterID, body.IncidentID, body.Reason, duration, body.Category)
	if err != nil {
		breakGlassRequestsTotal.With(prometheus.Labels{"outcome": "error"}).Inc()
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	breakGlassRequestsTotal.With(prometheus.Labels{"outcome": "created"}).Inc()
	jsonOK(w, req)
}

func (s *Server) handleBGApprove(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		RequestID string `json:"request_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Approver ID comes from the authenticated context.
	approverID := user.UserID
	if approverID == "" {
		approverID = user.ID
	}

	req, err := s.bgManager.Approve(r.Context(), body.RequestID, approverID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Status == model.BGStatusActive {
		activeBreakGlassSessions.Inc()
	}
	jsonOK(w, req)
}

// handleBGRevoke immediately revokes an active break-glass session.
// body: {"request_id": "BG-xxx"}
func (s *Server) handleBGRevoke(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		RequestID string `json:"request_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	revokerID := user.UserID
	if revokerID == "" {
		revokerID = user.ID
	}

	if err := s.bgManager.Revoke(r.Context(), body.RequestID, revokerID); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	activeBreakGlassSessions.Dec()
	jsonOK(w, map[string]string{"status": "revoked", "request_id": body.RequestID})
}

// handleBGStatus returns the current state of a break-glass request.
// The original requester or an auditor role may view the request.
func (s *Server) handleBGStatus(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	id := chi.URLParam(r, "id")
	req, err := s.bgManager.Get(id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	// Only the requester or an auditor can view.
	userID := user.UserID
	if userID == "" {
		userID = user.ID
	}
	if req.RequesterID != userID && user.Role != "auditor" {
		jsonError(w, "forbidden: only the requester or an auditor may view this request", http.StatusForbidden)
		return
	}

	jsonOK(w, req)
}

// handleErasure implements the GDPR right-to-erasure: it deletes every token
// mapping for a tenant. Only a member of that tenant or an auditor may invoke it.
// Query param: tenant_id (required). Returns 204 No Content on success.
func (s *Server) handleErasure(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		jsonError(w, "tenant_id query parameter is required", http.StatusBadRequest)
		return
	}

	if user.TenantID != tenantID && user.Role != "auditor" {
		jsonError(w, "forbidden: only a tenant member or an auditor may erase tenant data", http.StatusForbidden)
		return
	}

	if s.tokenStore == nil {
		jsonError(w, "token store not configured", http.StatusInternalServerError)
		return
	}

	deleted, err := s.tokenStore.DeleteByTenant(r.Context(), tenantID)
	if err != nil {
		jsonError(w, fmt.Sprintf("erasure failed: %v", err), http.StatusInternalServerError)
		return
	}

	actorID := user.UserID
	if actorID == "" {
		actorID = user.ID
	}
	s.auditor.Log(r.Context(), model.AuditEvent{ //nolint:errcheck
		TenantID:     tenantID,
		EventType:    model.AuditEventErasure,
		ActorID:      actorID,
		ResourceType: "token_store",
		ResourceID:   tenantID,
		Action:       "erasure",
		Outcome:      "deleted",
		Metadata: map[string]any{
			"entries_deleted": deleted,
		},
	})

	w.WriteHeader(http.StatusNoContent)
}

// handleGetConfig returns the sanitized server configuration.
// Secrets (JWT secret, KMS keys) are omitted. Only auditor or executive role allowed.
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != "auditor" && user.Role != "executive" {
		jsonError(w, "forbidden: auditor or executive role required", http.StatusForbidden)
		return
	}

	// Return sanitized config — omit secrets.
	sanitized := map[string]any{
		"server": map[string]any{
			"http_port": s.cfg.Server.HTTPPort,
			"grpc_port": s.cfg.Server.GRPCPort,
			"host":      s.cfg.Server.Host,
		},
		"kms": map[string]any{
			"provider": s.cfg.KMS.Provider,
		},
		"opa": map[string]any{
			"policy_dir":    s.cfg.OPA.PolicyDir,
			"bundle_server": s.cfg.OPA.BundleServer,
		},
		"audit": map[string]any{
			"output_dir":      s.cfg.Audit.OutputDir,
			"signing_enabled": s.cfg.Audit.SigningEnabled,
			"retention_days":  s.cfg.Audit.Retention,
		},
	}
	jsonOK(w, sanitized)
}

// handleConfigReload triggers an OPA policy reload.
// Only auditor role allowed.
func (s *Server) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != "auditor" {
		jsonError(w, "forbidden: auditor role required", http.StatusForbidden)
		return
	}

	if err := s.controller.ReloadPolicies(r.Context()); err != nil {
		jsonError(w, fmt.Sprintf("policy reload failed: %v", err), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "ok", "message": "policies reloaded"})
}

// handleAuditLog queries the audit log.
// Query params: ?tenant=xxx&limit=100&since=2026-01-01T00:00:00Z
// Only auditor role allowed.
func (s *Server) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != "auditor" {
		jsonError(w, "forbidden: auditor role required", http.StatusForbidden)
		return
	}

	tenantID := r.URL.Query().Get("tenant")
	limitStr := r.URL.Query().Get("limit")
	sinceStr := r.URL.Query().Get("since")

	limit := 0
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	var since time.Time
	if sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = t
		}
	}

	entries, err := s.auditor.Query(r.Context(), tenantID, limit, since)
	if err != nil {
		jsonError(w, fmt.Sprintf("audit query failed: %v", err), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"entries": entries, "count": len(entries)})
}

// ---------- Phase 2 (Vault-OUT) handlers ----------

// userCtxFromAuth materialises a *model.UserContext from the authenticated request
// context, layering on whatever the request body explicitly supplied (department,
// roles, slice). The tenant_id is always taken from the auth context for safety.
func userCtxFromAuth(authUser *model.User, supplied *model.UserContext) *model.UserContext {
	uc := &model.UserContext{
		UserID:     authUser.UserID,
		TenantID:   authUser.TenantID,
		Department: authUser.Department,
		Roles:      []string{authUser.Role},
	}
	if uc.UserID == "" {
		uc.UserID = authUser.ID
	}
	if supplied != nil {
		if supplied.Department != "" {
			uc.Department = supplied.Department
		}
		if len(supplied.Roles) > 0 {
			uc.Roles = supplied.Roles
		}
		uc.AllowedCategories = supplied.AllowedCategories
		uc.AccessLevel = supplied.AccessLevel
		uc.Slice = supplied.Slice
	}
	return uc
}

// handleApplyPermissions runs the Phase 2 pipeline minus token resolution. This is
// the primary read-time view endpoint.
func (s *Server) handleApplyPermissions(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.processor == nil {
		jsonError(w, "phase 2 processor not configured", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		User     *model.UserContext  `json:"user,omitempty"`
		Records  []model.DataRecord  `json:"records"`
		Category model.DataCategory  `json:"category"`
		Query    output.QueryParams  `json:"query,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	uc := userCtxFromAuth(user, body.User)
	body.Query.Category = body.Category

	resp, err := s.processor.ApplyPermissions(r.Context(), output.ProcessRequest{
		RequestID: r.Header.Get("X-Request-ID"),
		User:      uc,
		Records:   body.Records,
		Category:  body.Category,
		Query:     body.Query,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, resp)
}

// handleResolveTokens performs ONLY the selective token-resolution step. The caller
// must have deanonymize rights for the record's category.
func (s *Server) handleResolveTokens(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.processor == nil {
		jsonError(w, "phase 2 processor not configured", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		User    *model.UserContext `json:"user,omitempty"`
		Records []model.DataRecord `json:"records"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	uc := userCtxFromAuth(user, body.User)

	// Per-record deanonymize check (use the first record's category as the gate;
	// mixed-category batches should be split by the caller).
	if len(body.Records) > 0 {
		category := body.Records[0].Category
		role := ""
		if len(uc.Roles) > 0 {
			role = uc.Roles[0]
		}
		if !s.controller.CanDeanonymize(&model.User{
			UserID:     uc.UserID,
			TenantID:   uc.TenantID,
			Department: uc.Department,
			Role:       role,
		}, category) {
			jsonError(w, "deanonymize not permitted for your role", http.StatusForbidden)
			return
		}
	}

	resolved, err := s.processor.ResolveTokens(r.Context(), body.Records, uc)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"resolved_records": resolved})
}

// handleVerifyAccess returns the access decision for the user against a category
// without transforming any records.
func (s *Server) handleVerifyAccess(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.processor == nil {
		jsonError(w, "phase 2 processor not configured", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		Category model.DataCategory `json:"category"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	uc := userCtxFromAuth(user, nil)
	decision, err := s.processor.VerifyAccess(r.Context(), uc, body.Category)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{
		"allowed":      decision.Allowed,
		"access_level": string(decision.AccessLevel),
		"reason":       decision.Reason,
	})
}

// handleValidateOutputSet validates k-anonymity for a posted record set.
func (s *Server) handleValidateOutputSet(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.processor == nil {
		jsonError(w, "phase 2 processor not configured", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		Records    []model.DataRecord `json:"records"`
		KThreshold int                `json:"k_threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	if body.KThreshold <= 0 {
		body.KThreshold = 5
	}
	if len(body.Records) == 0 {
		jsonOK(w, map[string]any{"valid": true, "violations": []any{}, "min_group_size": 0})
		return
	}

	// Flatten DataRecord.Fields into the map shape the validator wants.
	flat := make([]map[string]any, 0, len(body.Records))
	for _, rec := range body.Records {
		m := make(map[string]any, len(rec.Fields))
		for k, v := range rec.Fields {
			m[k] = v.Value
		}
		flat = append(flat, m)
	}
	category := body.Records[0].Category
	report, err := s.processor.KAnonValidator().Validate(r.Context(), flat, category, body.KThreshold)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonOK(w, map[string]any{
		"valid":          report.Valid,
		"violations":     report.Violations,
		"min_group_size": report.K,
		"required_k":     report.RequiredK,
	})
}

// handleDetectInference runs the inference-attack detector on a query without
// modifying the user's history beyond the current call.
func (s *Server) handleDetectInference(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.processor == nil {
		jsonError(w, "phase 2 processor not configured", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		Category            model.DataCategory `json:"category"`
		Filters             map[string]string  `json:"filters"`
		ExpectedResultCount int                `json:"expected_result_count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	uc := userCtxFromAuth(user, nil)
	risk, err := s.processor.InferenceDetector().Detect(r.Context(), uc, output.QueryParams{
		Category:            body.Category,
		Filters:             body.Filters,
		ExpectedResultCount: body.ExpectedResultCount,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, risk)
}

// handleProcess runs the full Phase 2 pipeline including (when permitted) token
// resolution.
func (s *Server) handleProcess(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r.Context())
	if user == nil {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.processor == nil {
		jsonError(w, "phase 2 processor not configured", http.StatusServiceUnavailable)
		return
	}

	var body struct {
		RequestID string             `json:"request_id"`
		User      *model.UserContext `json:"user,omitempty"`
		Records   []model.DataRecord `json:"records"`
		Category  model.DataCategory `json:"category"`
		Query     output.QueryParams `json:"query,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	uc := userCtxFromAuth(user, body.User)
	body.Query.Category = body.Category

	resp, err := s.processor.Process(r.Context(), output.ProcessRequest{
		RequestID: body.RequestID,
		User:      uc,
		Records:   body.Records,
		Category:  body.Category,
		Query:     body.Query,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, resp)
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
}
