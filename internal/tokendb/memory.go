package tokendb

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-memory, thread-safe implementation of Store.
// It is intended for development and testing only; data is lost on restart.
type MemoryStore struct {
	mu      sync.RWMutex
	entries map[string]*Entry // keyed by tenantID + ":" + token
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		entries: make(map[string]*Entry),
	}
}

func storeKey(tenantID, token string) string {
	return tenantID + ":" + token
}

// Put stores or overwrites a token mapping.
func (s *MemoryStore) Put(_ context.Context, e Entry) error {
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	s.mu.Lock()
	s.entries[storeKey(e.TenantID, e.Token)] = &e
	s.mu.Unlock()
	return nil
}

// Get retrieves the entry for the given token and tenant.
// Returns (nil, nil) when not found.
func (s *MemoryStore) Get(_ context.Context, token, tenantID string) (*Entry, error) {
	s.mu.RLock()
	e, ok := s.entries[storeKey(tenantID, token)]
	s.mu.RUnlock()
	if !ok {
		return nil, nil
	}
	// Return a copy to prevent external mutation.
	cp := *e
	return &cp, nil
}

// Delete removes a single token mapping.
func (s *MemoryStore) Delete(_ context.Context, token, tenantID string) error {
	s.mu.Lock()
	delete(s.entries, storeKey(tenantID, token))
	s.mu.Unlock()
	return nil
}

// DeleteByTenant removes all entries for tenantID and returns the count deleted.
func (s *MemoryStore) DeleteByTenant(_ context.Context, tenantID string) (int, error) {
	prefix := tenantID + ":"
	s.mu.Lock()
	count := 0
	for k := range s.entries {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(s.entries, k)
			count++
		}
	}
	s.mu.Unlock()
	return count, nil
}
