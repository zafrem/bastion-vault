package tokendb

import (
	"context"
	"time"
)

// Entry holds one token→original mapping for a specific tenant.
type Entry struct {
	Token     string
	Original  string
	TenantID  string
	PIIType   string
	CreatedAt time.Time
}

// Store is the persistence interface for token mappings.
// Implementations must be safe for concurrent use.
type Store interface {
	// Put stores a new token mapping. If the token already exists for the tenant
	// the entry is overwritten.
	Put(ctx context.Context, e Entry) error

	// Get retrieves the entry for the given token and tenant.
	// Returns (nil, nil) when the token does not exist.
	Get(ctx context.Context, token, tenantID string) (*Entry, error)

	// Delete removes a single token mapping.
	Delete(ctx context.Context, token, tenantID string) error

	// DeleteByTenant removes all token mappings for tenantID (GDPR erasure).
	// Returns the number of entries deleted.
	DeleteByTenant(ctx context.Context, tenantID string) (int, error)
}
