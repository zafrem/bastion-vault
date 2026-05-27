// Package events — Foundation-standard event publisher for Vault (doc 02).
// Emits to bastion.events.vault.{event_type}; silently no-ops if NATS is unavailable.
package events

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

const (
	vaultModule  = "vault"
	vaultVersion = "3.0.0"
	schemaVer    = "1.0"
	subjectPfx   = "bastion.events.vault"
)

// VaultEvent is a Foundation-standard event (doc 02) emitted by Vault.
type VaultEvent struct {
	EventID       string                 `json:"event_id"`
	EventType     string                 `json:"event_type"`
	SchemaVersion string                 `json:"schema_version"`
	TraceID       string                 `json:"trace_id"`
	SpanID        string                 `json:"span_id"`
	ParentSpanID  string                 `json:"parent_span_id,omitempty"`
	Module        string                 `json:"module"`
	ModuleVersion string                 `json:"module_version"`
	Timestamp     int64                  `json:"timestamp"`
	DurationMs    int64                  `json:"duration_ms,omitempty"`
	TenantID      string                 `json:"tenant_id"`
	UserID        string                 `json:"user_id,omitempty"`
	RequestID     string                 `json:"request_id,omitempty"`
	Severity      string                 `json:"severity"`
	Category      string                 `json:"category"`
	Data          map[string]interface{} `json:"data,omitempty"`
	Status        string                 `json:"status,omitempty"`
	ActionTaken   string                 `json:"action_taken,omitempty"`
}

// TraceContext carries W3C / Bastion trace headers for event correlation.
type TraceContext struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	TenantID     string
	UserID       string
	RequestID    string
}

// Publisher publishes Vault events to NATS (or drops silently if unavailable).
type Publisher struct {
	nc *nats.Conn
}

// New connects to NATS. Returns a silent no-op publisher on error so core
// Vault operations are never blocked by event bus issues.
func New(natsURL string) *Publisher {
	if natsURL == "" {
		return &Publisher{}
	}
	nc, err := nats.Connect(natsURL,
		nats.MaxReconnects(5),
		nats.ReconnectWait(2e9),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			log.Printf("[vault-events] nats error: %v", err)
		}),
	)
	if err != nil {
		log.Printf("[vault-events] nats unavailable (%v), events disabled", err)
		return &Publisher{}
	}
	return &Publisher{nc: nc}
}

// Publish fires the event asynchronously; never blocks the caller.
func (p *Publisher) Publish(ev VaultEvent) {
	if p == nil || p.nc == nil {
		return
	}
	go func() {
		data, err := json.Marshal(ev)
		if err != nil {
			return
		}
		subject := fmt.Sprintf("%s.%s", subjectPfx, ev.EventType)
		_ = p.nc.Publish(subject, data)
	}()
}

func (p *Publisher) Close() {
	if p != nil && p.nc != nil {
		p.nc.Drain() //nolint:errcheck
	}
}

// ─── event constructors ───────────────────────────────────────────────────────

func newEvent(tc TraceContext, eventType, severity, category string, data map[string]interface{}) VaultEvent {
	return VaultEvent{
		EventID:       uuid.New().String(),
		EventType:     eventType,
		SchemaVersion: schemaVer,
		TraceID:       tc.TraceID,
		SpanID:        tc.SpanID,
		ParentSpanID:  tc.ParentSpanID,
		Module:        vaultModule,
		ModuleVersion: vaultVersion,
		Timestamp:     time.Now().UnixNano(),
		TenantID:      tc.TenantID,
		UserID:        tc.UserID,
		RequestID:     tc.RequestID,
		Severity:      severity,
		Category:      category,
		Data:          data,
	}
}

// EventAnonymized is emitted after a successful anonymize operation.
func EventAnonymized(tc TraceContext, dataCategory string, recordCount int, strategies []string) VaultEvent {
	ev := newEvent(tc, "anonymized", "info", "operational", map[string]interface{}{
		"data_category": dataCategory,
		"record_count":  recordCount,
		"strategies":    strategies,
	})
	ev.Status = "anonymized"
	ev.ActionTaken = "anonymize"
	return ev
}

// EventTransformExecuted is emitted after a successful deanonymize/token-resolve operation.
func EventTransformExecuted(tc TraceContext, dataCategory string, recordCount int) VaultEvent {
	ev := newEvent(tc, "transform_executed", "info", "operational", map[string]interface{}{
		"data_category": dataCategory,
		"record_count":  recordCount,
	})
	ev.Status = "resolved"
	ev.ActionTaken = "deanonymize"
	return ev
}

// EventAccessDenied is emitted when the access controller denies an operation.
func EventAccessDenied(tc TraceContext, dataCategory, reason string) VaultEvent {
	ev := newEvent(tc, "access_denied", "warning", "security", map[string]interface{}{
		"data_category": dataCategory,
		"reason":        reason,
	})
	ev.Status = "denied"
	ev.ActionTaken = "block"
	return ev
}

// EventHoneyTokenCreated is emitted when a honey-token record is generated.
func EventHoneyTokenCreated(tc TraceContext, tokenID, tokenType string) VaultEvent {
	ev := newEvent(tc, "honey_token_created", "info", "security", map[string]interface{}{
		"honey_token_id":   tokenID,
		"honey_token_type": tokenType,
	})
	ev.Status = "created"
	ev.ActionTaken = "honey_token_created"
	return ev
}

// EventHoneyTokenInjected is emitted when a honey-token is inserted into a dataset.
func EventHoneyTokenInjected(tc TraceContext, tokenID, dataCategory string, position int) VaultEvent {
	ev := newEvent(tc, "honey_token_injected", "info", "security", map[string]interface{}{
		"honey_token_id": tokenID,
		"data_category":  dataCategory,
		"position":       position,
	})
	ev.Status = "injected"
	ev.ActionTaken = "honey_token_injected"
	return ev
}

// EventHoneyTokenAccessed is emitted when data-layer access to a honey-token is detected.
// This is the data-layer detection point (SRS doc 20, Layer 2).
func EventHoneyTokenAccessed(tc TraceContext, tokenID, tokenType, accessMethod string) VaultEvent {
	ev := newEvent(tc, "honey_token_accessed", "critical", "security", map[string]interface{}{
		"honey_token_id":  tokenID,
		"honey_token_type": tokenType,
		"access_method":   accessMethod,
		"detection_layer": "data",
		"detecting_module": vaultModule,
	})
	ev.Status = "detected"
	ev.ActionTaken = "alert_raised"
	return ev
}

// EventCrossTenantAttempt is emitted when a request tries to operate on a different tenant's data.
// Severity CRITICAL per SRS doc 21 §3.2 (Multi-tenancy).
func EventCrossTenantAttempt(tc TraceContext, requestedTenantID, operation string) VaultEvent {
	ev := newEvent(tc, "cross_tenant_attempt", "critical", "security", map[string]interface{}{
		"requested_tenant_id": requestedTenantID,
		"auth_tenant_id":      tc.TenantID,
		"operation":           operation,
	})
	ev.Status = "blocked"
	ev.ActionTaken = "reject"
	return ev
}

// EventDeanonymizationPerformed is emitted after a successful deanonymize operation (SRS doc 11 §6.4).
func EventDeanonymizationPerformed(tc TraceContext, dataCategory string, recordCount int) VaultEvent {
	ev := newEvent(tc, "deanonymization_performed", "warning", "security", map[string]interface{}{
		"data_category": dataCategory,
		"record_count":  recordCount,
	})
	ev.Status = "deanonymized"
	ev.ActionTaken = "deanonymize"
	return ev
}

// EventKAnonymityEnforced is emitted when k-anonymity generalization is applied to a dataset (SRS doc 11 §6.4).
func EventKAnonymityEnforced(tc TraceContext, dataCategory string, k, recordCount int) VaultEvent {
	ev := newEvent(tc, "k_anonymity_enforced", "info", "security", map[string]interface{}{
		"data_category": dataCategory,
		"k_value":       k,
		"record_count":  recordCount,
	})
	ev.Status = "enforced"
	ev.ActionTaken = "generalize"
	return ev
}

// EventCloudLLMCalled is emitted after every cloud LLM call (mandatory, doc 21 §6).
// anonymizedHash is the SHA-256 of the anonymized payload — never raw PII.
func EventCloudLLMCalled(tc TraceContext, provider, modelName, dataCategory string,
	fieldsAnonymized, tokensInResponse, tokensDeanonymized int, anonymizedHash string) VaultEvent {
	ev := newEvent(tc, "cloud_llm_called", "info", "operational", map[string]interface{}{
		"provider":             provider,
		"model":                modelName,
		"data_category":        dataCategory,
		"fields_anonymized":    fieldsAnonymized,
		"tokens_in_response":   tokensInResponse,
		"tokens_deanonymized":  tokensDeanonymized,
		"anonymized_req_hash":  anonymizedHash,
	})
	ev.Status = "called"
	ev.ActionTaken = "cloud_llm_call"
	return ev
}

// ExtractTraceContext reads W3C / Bastion trace headers, generating new IDs as fallback.
func ExtractTraceContext(traceID, spanID, parentSpanID, tenantID, userID, requestID string) TraceContext {
	if traceID == "" {
		traceID = uuid.New().String()
	}
	if spanID == "" {
		spanID = uuid.New().String()[:16]
	}
	return TraceContext{
		TraceID:      traceID,
		SpanID:       spanID,
		ParentSpanID: parentSpanID,
		TenantID:     tenantID,
		UserID:       userID,
		RequestID:    requestID,
	}
}
