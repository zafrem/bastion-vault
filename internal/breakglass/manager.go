package breakglass

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/model"
)

const (
	maxDuration      = 4 * time.Hour
	approvalWindow   = 15 * time.Minute
	requiredApprovers = 2
)

// Manager handles the break-glass request/approve/revoke lifecycle per SRS §3.6.
type Manager struct {
	mu       sync.RWMutex
	requests map[string]*model.BreakGlassRequest
	auditor  *audit.Logger
}

func NewManager(aud *audit.Logger) *Manager {
	m := &Manager{
		requests: make(map[string]*model.BreakGlassRequest),
		auditor:  aud,
	}
	go m.expiryWatcher()
	return m
}

// Request creates a new break-glass access request.
func (m *Manager) Request(ctx context.Context, requesterID, incidentID, reason string, duration time.Duration, category model.DataCategory) (*model.BreakGlassRequest, error) {
	if duration > maxDuration {
		return nil, fmt.Errorf("break-glass: duration %v exceeds maximum %v", duration, maxDuration)
	}
	if reason == "" {
		return nil, fmt.Errorf("break-glass: reason is required")
	}
	if incidentID == "" {
		return nil, fmt.Errorf("break-glass: incident ID is required")
	}

	req := &model.BreakGlassRequest{
		ID:           newBGID(),
		RequesterID:  requesterID,
		IncidentID:   incidentID,
		Reason:       reason,
		Duration:     duration,
		DataCategory: category,
		Status:       model.BGStatusPending,
		CreatedAt:    time.Now().UTC(),
		Approvers:    []string{},
	}

	m.mu.Lock()
	m.requests[req.ID] = req
	m.mu.Unlock()

	m.auditor.Log(ctx, model.AuditEvent{ //nolint:errcheck
		EventType:   model.AuditEventBreakGlass,
		ActorID:     requesterID,
		ResourceType: "break_glass",
		ResourceID:  req.ID,
		Action:      "request",
		Outcome:     "pending",
		BreakGlass:  true,
		Metadata: map[string]any{
			"incident_id": incidentID,
			"reason":      reason,
			"duration":    duration.String(),
			"category":    string(category),
		},
	})

	return req, nil
}

// Approve records an approver's consent. When requiredApprovers signatures are
// collected within the approvalWindow, the request transitions to Active.
func (m *Manager) Approve(ctx context.Context, requestID, approverID string) (*model.BreakGlassRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	req, ok := m.requests[requestID]
	if !ok {
		return nil, fmt.Errorf("break-glass: request %s not found", requestID)
	}
	if req.Status != model.BGStatusPending {
		return nil, fmt.Errorf("break-glass: request %s is not pending (status=%s)", requestID, req.Status)
	}
	if time.Since(req.CreatedAt) > approvalWindow {
		req.Status = model.BGStatusExpired
		return nil, fmt.Errorf("break-glass: approval window expired for request %s", requestID)
	}
	if approverID == req.RequesterID {
		return nil, fmt.Errorf("break-glass: requester cannot approve their own request")
	}
	for _, a := range req.Approvers {
		if a == approverID {
			return nil, fmt.Errorf("break-glass: approver %s has already approved", approverID)
		}
	}

	req.Approvers = append(req.Approvers, approverID)

	if len(req.Approvers) >= requiredApprovers {
		req.Status = model.BGStatusActive
		req.ExpiresAt = time.Now().UTC().Add(req.Duration)
		req.Token = newBGToken()

		m.auditor.Log(ctx, model.AuditEvent{ //nolint:errcheck
			EventType:    model.AuditEventBreakGlass,
			ActorID:      approverID,
			ResourceType: "break_glass",
			ResourceID:   req.ID,
			Action:       "approve",
			Outcome:      "activated",
			BreakGlass:   true,
			Metadata: map[string]any{
				"approvers":  req.Approvers,
				"expires_at": req.ExpiresAt,
			},
		})
	}

	return req, nil
}

// Revoke immediately deactivates an active break-glass session.
func (m *Manager) Revoke(ctx context.Context, requestID, revokerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	req, ok := m.requests[requestID]
	if !ok {
		return fmt.Errorf("break-glass: request %s not found", requestID)
	}
	if req.Status != model.BGStatusActive {
		return fmt.Errorf("break-glass: request %s is not active (status=%s)", requestID, req.Status)
	}

	req.Status = model.BGStatusRevoked
	req.Token = ""

	m.auditor.Log(ctx, model.AuditEvent{ //nolint:errcheck
		EventType:    model.AuditEventBreakGlass,
		ActorID:      revokerID,
		ResourceType: "break_glass",
		ResourceID:   req.ID,
		Action:       "revoke",
		Outcome:      "revoked",
		BreakGlass:   true,
	})

	return nil
}

// ValidateToken checks whether a break-glass token is currently active.
func (m *Manager) ValidateToken(token string) (*model.BreakGlassRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, req := range m.requests {
		if req.Token == token && req.Status == model.BGStatusActive {
			if time.Now().After(req.ExpiresAt) {
				return nil, fmt.Errorf("break-glass: token expired")
			}
			return req, nil
		}
	}
	return nil, fmt.Errorf("break-glass: invalid or inactive token")
}

// Get returns a break-glass request by ID.
func (m *Manager) Get(requestID string) (*model.BreakGlassRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	req, ok := m.requests[requestID]
	if !ok {
		return nil, fmt.Errorf("break-glass: request %s not found", requestID)
	}
	return req, nil
}

// expiryWatcher auto-revokes sessions that have passed their ExpiresAt time.
func (m *Manager) expiryWatcher() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		m.expireStale()
	}
}

func (m *Manager) expireStale() {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, req := range m.requests {
		if req.Status == model.BGStatusActive && now.After(req.ExpiresAt) {
			req.Status = model.BGStatusExpired
			req.Token = ""
		}
		if req.Status == model.BGStatusPending && now.After(req.CreatedAt.Add(approvalWindow)) {
			req.Status = model.BGStatusExpired
		}
	}
}

func newBGID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "BG-" + hex.EncodeToString(b)
}

func newBGToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
