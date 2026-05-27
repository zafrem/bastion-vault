// Package hooks provides a lightweight, non-blocking hook/extension-point
// system for Vault (Foundation Architecture doc 01 §2.3).
package hooks

import (
	"context"
	"sync"
)

// EventType identifies the operation that fired a hook.
type EventType string

const (
	EventAnonymized            EventType = "anonymized"
	EventTransformExecuted     EventType = "transform_executed"
	EventAccessDenied          EventType = "access_denied"
	EventHoneyTokenHit         EventType = "honey_token_hit"
	EventCrossTenantAttempt    EventType = "cross_tenant_attempt"
	EventDeanonymizationPerformed EventType = "deanonymization_performed"
	EventKAnonymityEnforced    EventType = "k_anonymity_enforced"
)

// Event carries the hook payload.
type Event struct {
	Type      EventType
	RequestID string
	TenantID  string
	TraceID   string
	SpanID    string
	Data      map[string]interface{}
	Ctx       context.Context
}

// Hook is implemented by any object that wants to observe Vault events.
type Hook interface {
	Name() string
	OnEvent(Event)
}

// Manager registers hooks and dispatches events to them.
type Manager struct {
	mu    sync.RWMutex
	hooks map[EventType][]Hook
}

// New returns an empty Manager.
func New() *Manager {
	return &Manager{hooks: make(map[EventType][]Hook)}
}

// Register adds hook h to the listener set for eventType.
func (m *Manager) Register(eventType EventType, h Hook) {
	m.mu.Lock()
	m.hooks[eventType] = append(m.hooks[eventType], h)
	m.mu.Unlock()
}

// Fire dispatches ev to all registered hooks for ev.Type asynchronously.
func (m *Manager) Fire(ev Event) {
	m.mu.RLock()
	hs := m.hooks[ev.Type]
	m.mu.RUnlock()
	for _, h := range hs {
		go h.OnEvent(ev)
	}
}
