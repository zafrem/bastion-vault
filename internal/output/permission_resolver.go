// Package output implements Phase 2 (Vault-OUT) of the Bastion Vault service.
// It applies permission-based transformations at read time: selective token resolution,
// k-anonymity enforcement, inference attack detection, and per-field disclosure auditing.
package output

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zafrem/bastion-vault/internal/access"
	"github.com/zafrem/bastion-vault/internal/model"
)

// resolverCacheTTL is the TTL applied to cached permission decisions (FR-PV / NFR-PE-007).
const resolverCacheTTL = 5 * time.Minute

// cachedDecision wraps a permission decision with its expiry timestamp.
type cachedDecision struct {
	level     model.AccessLevel
	expiresAt time.Time
}

// PermissionResolver computes a user's effective access level for a given data category.
// Results are cached in-process with a 5-minute TTL keyed by the tuple
// "tenantID:dept:role:category". The resolver delegates to *access.Controller for the
// authoritative RBAC/OPA decision.
type PermissionResolver struct {
	access *access.Controller
	cache  sync.Map // key string -> cachedDecision
}

// NewPermissionResolver constructs a resolver backed by the supplied access controller.
func NewPermissionResolver(ctrl *access.Controller) *PermissionResolver {
	return &PermissionResolver{access: ctrl}
}

// userKey builds the cache key for a user/category pair.
func userKey(tenantID, dept, role string, category model.DataCategory) string {
	return strings.Join([]string{tenantID, dept, role, string(category)}, ":")
}

// Resolve returns the effective AccessLevel for the user and category, caching the result.
// Errors from the underlying controller are returned without caching so transient failures
// do not poison the cache. Unknown decisions fail-safe to AccessNone.
func (r *PermissionResolver) Resolve(ctx context.Context, user *model.User, category model.DataCategory) (model.AccessLevel, error) {
	if user == nil {
		return model.AccessNone, fmt.Errorf("permission resolver: nil user")
	}
	key := userKey(user.TenantID, user.Department, user.Role, category)
	if v, ok := r.cache.Load(key); ok {
		entry := v.(cachedDecision)
		if time.Now().Before(entry.expiresAt) {
			return entry.level, nil
		}
		// expired — drop and re-evaluate
		r.cache.Delete(key)
	}

	decision, err := r.access.Decide(ctx, user, category)
	if err != nil {
		return model.AccessNone, err
	}
	level := decision.AccessLevel
	if !decision.Allowed {
		level = model.AccessNone
	}

	r.cache.Store(key, cachedDecision{
		level:     level,
		expiresAt: time.Now().Add(resolverCacheTTL),
	})
	return level, nil
}

// InvalidateCache removes a cached decision so the next Resolve will re-evaluate.
// The userKey argument must be the same composite key returned by userKey().
func (r *PermissionResolver) InvalidateCache(userKey string) {
	r.cache.Delete(userKey)
}

// UserKey is the exported helper for constructing the cache key used by InvalidateCache.
func UserKey(tenantID, dept, role string, category model.DataCategory) string {
	return userKey(tenantID, dept, role, category)
}
