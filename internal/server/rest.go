package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/zafrem/bastion-vault/internal/access"
	"github.com/zafrem/bastion-vault/internal/anonymizer"
	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/breakglass"
	"github.com/zafrem/bastion-vault/internal/classification"
	"github.com/zafrem/bastion-vault/internal/kanon"
	"github.com/zafrem/bastion-vault/internal/model"
)

// Server wraps all service dependencies and exposes the HTTP router.
type Server struct {
	engine      *anonymizer.Engine
	classifier  *classification.Classifier
	controller  *access.Controller
	kanon       *kanon.Validator
	bgManager   *breakglass.Manager
	auditor     *audit.Logger
	startTime   time.Time
}

// New constructs a Server from its service dependencies.
func New(
	eng *anonymizer.Engine,
	cls *classification.Classifier,
	ctrl *access.Controller,
	kv *kanon.Validator,
	bg *breakglass.Manager,
	aud *audit.Logger,
) *Server {
	return &Server{
		engine:     eng,
		classifier: cls,
		controller: ctrl,
		kanon:      kv,
		bgManager:  bg,
		auditor:    aud,
		startTime:  time.Now(),
	}
}

// Router returns the configured chi router.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(loggingMiddleware)
	r.Use(metricsMiddleware)
	r.Use(authMiddleware)
	r.Use(tenantMiddleware)

	r.Get("/v1/health/live", s.handleLive)
	r.Get("/v1/health/ready", s.handleReady)
	r.Handle("/v1/metrics", promhttp.Handler())

	r.Post("/v1/vault/anonymize", s.handleAnonymize)
	r.Post("/v1/vault/deanonymize", s.handleDeanonymize)
	r.Post("/v1/vault/classify", s.handleClassify)
	r.Post("/v1/vault/detect-pii", s.handleDetectPII)
	r.Post("/v1/vault/k-anonymity/validate", s.handleKAnonymityValidate)
	r.Post("/v1/vault/break-glass/request", s.handleBGRequest)
	r.Post("/v1/vault/break-glass/approve", s.handleBGApprove)

	return r
}

// handleLive is the Kubernetes liveness probe; always returns 200 when the process is alive.
func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]string{"status": "alive"})
}

// handleReady is the Kubernetes readiness probe.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{
		"status":   "ready",
		"uptime":   time.Since(s.startTime).String(),
	})
}

func (s *Server) handleAnonymize(w http.ResponseWriter, r *http.Request) {
	var req model.AnonymizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	req.TenantID = tenantFromCtx(r.Context())

	resp, err := s.engine.Anonymize(r.Context(), &req)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, resp)
}

func (s *Server) handleDeanonymize(w http.ResponseWriter, r *http.Request) {
	var req model.DeanonymizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	req.TenantID = tenantFromCtx(r.Context())

	resp, err := s.engine.Deanonymize(r.Context(), &req)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, resp)
}

func (s *Server) handleClassify(w http.ResponseWriter, r *http.Request) {
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
	var body struct {
		Records    []map[string]any     `json:"records"`
		Category   model.DataCategory   `json:"category"`
		RequiredK  int                  `json:"required_k"`
		Generalize bool                 `json:"generalize"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	if body.RequiredK == 0 {
		body.RequiredK = 5
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
	var body struct {
		RequesterID  string               `json:"requester_id"`
		IncidentID   string               `json:"incident_id"`
		Reason       string               `json:"reason"`
		DurationSecs int64                `json:"duration_seconds"`
		Category     model.DataCategory   `json:"category"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	duration := time.Duration(body.DurationSecs) * time.Second
	req, err := s.bgManager.Request(r.Context(), body.RequesterID, body.IncidentID, body.Reason, duration, body.Category)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonOK(w, req)
}

func (s *Server) handleBGApprove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RequestID  string `json:"request_id"`
		ApproverID string `json:"approver_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	req, err := s.bgManager.Approve(r.Context(), body.RequestID, body.ApproverID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonOK(w, req)
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
