package tenant

import (
	"context"
	"fmt"
	"sync"

	"github.com/zafrem/bastion-vault/internal/model"
)

type contextKey string

const tenantContextKey contextKey = "tenant"

// Registry manages per-tenant configuration in memory.
// In production this would be backed by a database with RLS.
type Registry struct {
	mu      sync.RWMutex
	tenants map[string]*model.TenantConfig
}

func NewRegistry() *Registry {
	return &Registry{tenants: make(map[string]*model.TenantConfig)}
}

// Register adds or updates a tenant configuration.
func (r *Registry) Register(cfg *model.TenantConfig) {
	r.mu.Lock()
	r.tenants[cfg.ID] = cfg
	r.mu.Unlock()
}

// Get returns the configuration for the given tenant ID.
func (r *Registry) Get(tenantID string) (*model.TenantConfig, error) {
	r.mu.RLock()
	cfg, ok := r.tenants[tenantID]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("tenant %s not found", tenantID)
	}
	return cfg, nil
}

// WithTenant stores the tenant ID in the context for downstream handlers.
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantContextKey, tenantID)
}

// FromContext extracts the tenant ID from the context.
func FromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(tenantContextKey).(string)
	return id, ok
}

// MasterKeyID constructs the canonical KMS master key ID for a tenant.
func MasterKeyID(tenantID string) string {
	return fmt.Sprintf("tenant:%s:master", tenantID)
}

// HMACKeyID constructs the canonical HMAC key ID for a tenant.
func HMACKeyID(tenantID string) string {
	return fmt.Sprintf("tenant:%s:hmac", tenantID)
}

// AuditKeyID constructs the canonical audit signing key ID for a tenant.
func AuditKeyID(tenantID string) string {
	return fmt.Sprintf("tenant:%s:audit", tenantID)
}
