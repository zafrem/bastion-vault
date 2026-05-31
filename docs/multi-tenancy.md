# Vault — Multi-Tenancy

**Module:** Vault (`internal/tenant/`, `internal/tokendb/`, `internal/access/`, `internal/output/`)
**Version:** 3.0
**Last updated:** 2026-05-30

---

## Overview

Vault enforces tenant isolation at four independent layers. A breach of any single layer does not expose another tenant's data because each subsequent layer independently re-checks the tenant identity.

```
Incoming request (tenant_id from Sentinel-IN metadata)
    │
    ▼
Layer 1: Context propagation        tenant.WithTenant(ctx, tenantID)
    │
    ▼
Layer 2: Key namespace isolation    KMS key ID = "tenant:{id}:category:{cat}"
    │
    ▼
Layer 3: Token store isolation      storeKey = "{tenantID}:{token}"
    │
    ▼
Layer 4: RBAC + OPA access control  controller.Decide(ctx, user, category)
    │
    ▼
Layer 5: Cross-tenant verifier      CrossTenantVerifier.Verify(records, userTenantID)
    │
    ▼
Response
```

---

## Layer 1 — Tenant context propagation

`tenant.WithTenant` stores the tenant ID in the Go `context.Context` using an unexported package-level key, making accidental namespace collision with other context values structurally impossible.

```go
// internal/tenant/isolation.go

type contextKey string

const tenantContextKey contextKey = "tenant"

// WithTenant stores the tenant ID in the context for downstream handlers.
func WithTenant(ctx context.Context, tenantID string) context.Context {
    return context.WithValue(ctx, tenantContextKey, tenantID)
}

// FromContext extracts the tenant ID from the context.
// Returns ("", false) when no tenant ID was injected — callers must
// treat the missing case as an authentication failure, not as default tenant.
func FromContext(ctx context.Context) (string, bool) {
    id, ok := ctx.Value(tenantContextKey).(string)
    return id, ok
}
```

The `contextKey` type is unexported, so code in other packages cannot accidentally collide with `"tenant"` as a plain string context key.

---

## Layer 2 — Key namespace isolation

Every cryptographic operation is scoped to a tenant × data-category compound key ID. Two tenants with the same category hold completely different key material derived from different master keys.

### Key ID constructors

```go
// internal/tenant/isolation.go

// MasterKeyID returns the KMS master key ID for a tenant.
// Example: "tenant:acme-corp:master"
func MasterKeyID(tenantID string) string {
    return fmt.Sprintf("tenant:%s:master", tenantID)
}

// HMACKeyID returns the HMAC key ID for a tenant.
// Example: "tenant:acme-corp:hmac"
func HMACKeyID(tenantID string) string {
    return fmt.Sprintf("tenant:%s:hmac", tenantID)
}

// AuditKeyID returns the audit signing key ID for a tenant.
// Example: "tenant:acme-corp:audit"
func AuditKeyID(tenantID string) string {
    return fmt.Sprintf("tenant:%s:audit", tenantID)
}
```

### Per-category DEK derivation in the Anonymizer Engine

The anonymizer engine goes one level deeper: it derives a separate HMAC key and DEK for every tenant × category pair. This means `acme-corp`'s customer HMAC key is different from `acme-corp`'s HR-finance HMAC key, and both are different from `rival-corp`'s customer HMAC key.

```go
// internal/anonymizer/engine.go

func (e *Engine) resolveKeyMaterial(
    ctx context.Context,
    tenantID string,
    cat model.DataCategory,
) (hmacKey, encKey []byte, err error) {

    // masterKeyID is scoped to tenant + category:
    // e.g. "tenant:acme-corp:category:DC-01"
    masterKeyID := fmt.Sprintf("tenant:%s:category:%s", tenantID, string(cat))

    // HMAC key — used by deterministic tokenization and hmac_sha256 strategies.
    // Different tenant×category pairs yield different HMAC keys, so tokens are
    // never transferable across tenants or categories.
    hmacKey, err = e.kmsManager.GetHMACKey(ctx, masterKeyID)
    if err != nil {
        return nil, nil, fmt.Errorf("resolving HMAC key: %w", err)
    }

    // DEK (Data Encryption Key) — used by AES-256-GCM encryption strategy.
    // GetOrGenerateDEK creates a new DEK if none is cached, then caches the
    // plaintext in memory for up to 5 minutes (KMS cache TTL).
    dk, err := e.kmsManager.GetOrGenerateDEK(ctx, masterKeyID, masterKeyID+":dek")
    if err != nil {
        return nil, nil, fmt.Errorf("resolving DEK: %w", err)
    }
    encKey = dk.Plaintext

    return hmacKey, encKey, nil
}
```

### KMS Manager — DEK caching with zeroization

```go
// internal/kms/manager.go

type Manager struct {
    primary   Provider       // AWS KMS, HashiCorp Vault, or local file
    fallbacks []Provider     // tried in order if primary fails
    cache     map[string]*dekCacheEntry
    mu        sync.RWMutex
    cacheTTL  time.Duration  // default 5 minutes
}

// GetOrGenerateDEK returns a cached DEK or generates a new one from the KMS.
// cacheKey is scoped to tenant × category, so different tenants never share
// a cached DEK even if they happen to request keys at the same time.
func (m *Manager) GetOrGenerateDEK(ctx context.Context, masterKeyID, cacheKey string) (*DataKey, error) {
    if dk := m.fromCache(cacheKey); dk != nil {
        return dk, nil  // cache hit — no KMS round-trip
    }
    dk, err := m.generateWithFailover(ctx, masterKeyID)
    if err != nil {
        return nil, err
    }
    m.toCache(cacheKey, dk)
    return dk, nil
}

// evict runs every 30 seconds. Expired entries have their plaintext
// zeroized before deletion, preventing key material from lingering in heap.
func (m *Manager) evict() {
    now := time.Now()
    m.mu.Lock()
    for k, entry := range m.cache {
        if now.After(entry.expiresAt) {
            zeroize(entry.plaintext) // overwrite with zeros
            delete(m.cache, k)
        }
    }
    m.mu.Unlock()
}

// zeroize uses runtime.KeepAlive to prevent the compiler from eliding
// the loop as a dead store. Without this, the optimizer may leave the
// key material intact in memory.
func zeroize(b []byte) {
    for i := range b {
        b[i] = 0
    }
    runtime.KeepAlive(b)
}
```

The `Provider` interface abstracts over AWS KMS, HashiCorp Vault, and a local file backend:

```go
// internal/kms/interface.go

type Provider interface {
    GenerateDataKey(ctx context.Context, keyID string) (*DataKey, error)
    DecryptDataKey(ctx context.Context, ciphertext []byte, keyID string) ([]byte, error)
    GenerateHMACKey(ctx context.Context, keyID string) ([]byte, error)
    Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error)
    Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error)
    DescribeKey(ctx context.Context, keyID string) (*KeyInfo, error)
    Name() string  // "local" | "aws" | "vault"
}
```

---

## Layer 3 — Token store isolation

Every token stored in the registry is keyed by the compound string `"{tenantID}:{token}"`. This means the same HMAC output for two different tenants produces two completely separate registry entries.

### Compound key construction

```go
// internal/tokendb/memory.go

// storeKey is the in-memory map key. Prefixing with tenantID ensures that
// token "TOK:abc123" for tenant "acme-corp" and the same token string for
// tenant "rival-corp" are stored and retrieved independently.
func storeKey(tenantID, token string) string {
    return tenantID + ":" + token
}
```

### `Get` — tenant-scoped lookup

```go
func (s *MemoryStore) Get(_ context.Context, token, tenantID string) (*Entry, error) {
    s.mu.RLock()
    e, ok := s.entries[storeKey(tenantID, token)]  // "acme-corp:TOK:abc123"
    s.mu.RUnlock()
    if !ok {
        return nil, nil  // not found — caller gets (nil, nil), not another tenant's entry
    }
    cp := *e  // return a copy, never the live pointer
    return &cp, nil
}
```

### `DeleteByTenant` — GDPR right-to-erasure

```go
func (s *MemoryStore) DeleteByTenant(_ context.Context, tenantID string) (int, error) {
    prefix := tenantID + ":"
    s.mu.Lock()
    count := 0
    for k := range s.entries {
        // String prefix match: only deletes entries owned by tenantID.
        // A tenant cannot accidentally erase another tenant's entries by
        // choosing a tenantID that is a prefix of another (e.g. "acme" vs "acme-corp")
        // because the separator ":" is appended — "acme:" never matches "acme-corp:...".
        if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
            delete(s.entries, k)
            count++
        }
    }
    s.mu.Unlock()
    return count, nil
}
```

The `Store` interface is implemented by three backends: `MemoryStore` (development), `SQLiteStore`, and `PostgresStore` (production). All three enforce the same compound-key discipline.

```go
// internal/tokendb/store.go

type Store interface {
    Put(ctx context.Context, e Entry) error
    Get(ctx context.Context, token, tenantID string) (*Entry, error)
    Delete(ctx context.Context, token, tenantID string) error
    // DeleteByTenant removes all token mappings for tenantID (GDPR erasure).
    DeleteByTenant(ctx context.Context, tenantID string) (int, error)
}
```

---

## Layer 4 — RBAC + OPA access control

### Tenant Registry

```go
// internal/tenant/isolation.go

// Registry manages per-tenant configuration in memory.
// In production, this would be backed by a database with Row-Level Security.
type Registry struct {
    mu      sync.RWMutex
    tenants map[string]*model.TenantConfig
}

// TenantConfig carries per-tenant key IDs and optional custom OPA policies.
// See model/types.go.
type TenantConfig struct {
    ID             string          // e.g. "acme-corp"
    Name           string
    KMSKeyID       string          // master encryption key
    HMACKeyID      string          // HMAC signing key
    AuditKeyID     string          // audit log signing key
    CustomPolicies map[string]any  // passed verbatim to OPA as policy context
}
```

### RBAC matrix

The embedded RBAC matrix maps `"{department}:{role}"` → data category → `AccessLevel`. Each cell represents the maximum data visibility a role in that department can receive.

```go
// internal/access/controller.go

var rbacMatrix = map[string]map[model.DataCategory]model.AccessLevel{
    "marketing:manager": {
        model.CategoryCustomer:      model.AccessFull,       // sees real PII
        model.CategoryManufacturing: model.AccessRead,
        model.CategoryHRFinance:     model.AccessAggregated, // totals only
    },
    "marketing:analyst": {
        model.CategoryCustomer:      model.AccessKAnonymized, // k-anon groups
        model.CategoryManufacturing: model.AccessKAnonymized,
        model.CategoryHRFinance:     model.AccessAggregated,
    },
    "hr:manager": {
        model.CategoryCustomer:      model.AccessNone,       // no customer data
        model.CategoryManufacturing: model.AccessNone,
        model.CategoryHRFinance:     model.AccessFull,
    },
    "hr:staff": {
        model.CategoryHRFinance:     model.AccessAnonymized, // tokenized fields
    },
    "audit:auditor": {
        model.CategoryCustomer:      model.AccessAuditLog,   // audit events only
        model.CategoryManufacturing: model.AccessAuditLog,
        model.CategoryHRFinance:     model.AccessAuditLog,
    },
    // ... (manufacturing, executive entries omitted for brevity)
}
```

### `Decide()` — RBAC lookup with optional OPA delegation

```go
func (c *Controller) Decide(ctx context.Context, user *model.User, category model.DataCategory) (*model.AccessDecision, error) {
    key := fmt.Sprintf("%s:%s", user.Department, user.Role)
    catMap, ok := rbacMatrix[key]
    if !ok {
        // Unknown department:role — deny immediately without querying OPA.
        return &model.AccessDecision{
            Allowed:     false,
            AccessLevel: model.AccessNone,
            Reason:      fmt.Sprintf("no RBAC rule for department=%s role=%s", user.Department, user.Role),
        }, nil
    }

    level, ok := catMap[category]
    if !ok || level == model.AccessNone {
        return &model.AccessDecision{
            Allowed:     false,
            AccessLevel: model.AccessNone,
            Reason:      "access denied by RBAC policy",
        }, nil
    }

    // If OPA is configured, RBAC result is the fallback; OPA can restrict further.
    // OPA cannot grant more than RBAC allows — it can only reduce the access level.
    if c.opaEndpoint != "" {
        return c.evaluateOPA(ctx, user, category, level)
    }

    return &model.AccessDecision{
        Allowed:     true,
        AccessLevel: level,
        Reason:      "allowed by RBAC policy",
    }, nil
}
```

### OPA fallback — fail-open to RBAC

```go
// If OPA is unreachable or returns non-200, the decision falls back to
// the RBAC-computed level. This fail-open behaviour is intentional:
// an OPA outage should not take down the Vault service.
func (c *Controller) evaluateOPA(...) (*model.AccessDecision, error) {
    // ...
    allowed, err := c.queryOPABool(ctx, c.opaEndpoint+"/v1/data/bastion-rag/vault/access/allow", bodyBytes)
    if err != nil {
        log.Printf("access: OPA allow query failed: %v — falling back to RBAC", err)
        return c.rbacDecision(fallback), nil  // fallback is the RBAC-computed level
    }
    // ...
}
```

### `DecideWithPurpose()` — RBAC × purpose conjunction (MR-04-003)

```go
// purposeMatrix: purpose → category → allowed departments.
// Absent entry = unrestricted (default-allow).
// training_data is never listed — it is unconditionally denied below.
var purposeMatrix = map[model.Purpose]map[model.DataCategory][]string{
    model.PurposeHRAnalytics: {
        model.CategoryHRFinance: {"hr", "executive", "audit"},
    },
    model.PurposeLegal: {
        model.CategoryCustomer:      {"audit", "executive"},
        model.CategoryHRFinance:     {"audit", "executive"},
        model.CategoryManufacturing: {"audit", "executive"},
    },
    model.PurposeAudit: {
        model.CategoryCustomer:      {"audit"},
        model.CategoryHRFinance:     {"audit"},
        model.CategoryManufacturing: {"audit"},
    },
}

func (c *Controller) DecideWithPurpose(
    ctx context.Context,
    user *model.User,
    category model.DataCategory,
    purpose model.Purpose,
) (*model.AccessDecision, error) {

    // training_data always requires explicit break-glass — never via standard path.
    if purpose == model.PurposeTrainingData {
        return &model.AccessDecision{
            Allowed:          false,
            AccessLevel:      model.AccessNone,
            Reason:           "training_data purpose requires explicit break-glass authorisation",
            PurposeViolation: true,
        }, nil
    }

    // Step 1: standard RBAC.
    decision, err := c.Decide(ctx, user, category)
    if err != nil || !decision.Allowed {
        return decision, err
    }

    // Step 2: purpose check — RBAC may allow but purpose may restrict.
    if !purposePermitted(purpose, user.Department, category) {
        return &model.AccessDecision{
            Allowed:          false,
            AccessLevel:      model.AccessNone,
            Reason:           fmt.Sprintf("purpose %q not permitted for department %q on category %s", ...),
            PurposeViolation: true,
        }, nil
    }

    return decision, nil  // both RBAC and purpose passed
}
```

`purposePermitted` defaults to `true` when no restriction is defined for the purpose × category pair, preserving backwards compatibility with callers that do not declare a purpose:

```go
func purposePermitted(purpose model.Purpose, department string, category model.DataCategory) bool {
    catMap, restricted := purposeMatrix[purpose]
    if !restricted {
        return true  // no restriction defined for this purpose → allow
    }
    allowedDepts, restricted := catMap[category]
    if !restricted {
        return true  // purpose unrestricted for this specific category
    }
    for _, d := range allowedDepts {
        if d == department {
            return true
        }
    }
    return false
}
```

---

## Layer 5 — Cross-tenant verifier (Phase 2, last-line defence)

The `CrossTenantVerifier` runs at the **output stage** after records have been fetched and all previous checks have passed. It is the final backstop against a misconfigured upstream query or a compromised Navigator sending records from another tenant.

```go
// internal/output/cross_tenant.go

// crossTenantSuspiciousRatio: if more than 10% of records in a batch belong
// to another tenant, the entire batch is rejected. At ≤10%, mismatched records
// are silently dropped and the clean subset is returned.
const crossTenantSuspiciousRatio = 0.10

func (v *CrossTenantVerifier) Verify(
    _ context.Context,
    records []model.DataRecord,
    userTenantID string,
) ([]model.DataRecord, error) {

    if userTenantID == "" {
        // Reject outright — no tenant identity means we cannot filter safely.
        return nil, fmt.Errorf("cross-tenant verifier: empty user tenant_id")
    }

    out := make([]model.DataRecord, 0, len(records))
    mismatched := 0

    for _, rec := range records {
        if rec.TenantID == userTenantID {
            out = append(out, rec)
            continue
        }
        mismatched++
        // Every mismatch is logged as CRITICAL for SOC correlation.
        log.Printf("CRITICAL vault-out cross_tenant_violation: record_id=%s record_tenant=%s user_tenant=%s",
            rec.RecordID, rec.TenantID, userTenantID)
    }

    // If the mismatch ratio exceeds the threshold, refuse to return even
    // the valid records — the input set is assumed to have been poisoned.
    if mismatched > 0 && float64(mismatched)/float64(len(records)) > crossTenantSuspiciousRatio {
        return nil, fmt.Errorf(
            "cross-tenant verifier: %d of %d records belonged to other tenants — refusing batch",
            mismatched, len(records))
    }

    return out, nil
}
```

### Ratio decision table

| Total records | Mismatched | Ratio | Decision |
|---|---|---|---|
| 100 | 0 | 0% | Return 100 clean records |
| 100 | 10 | 10% | Return 90 clean records (drops 10 with CRITICAL log) |
| 100 | 11 | 11% | **Reject entire batch** |
| 10 | 1 | 10% | Return 9 clean records |
| 10 | 2 | 20% | **Reject entire batch** |

---

## Access level hierarchy

Access levels are comparable by rank. The `EnforceMinimumLevel` helper prevents a caller from requesting more than their RBAC decision grants:

```go
// internal/access/controller.go

func EnforceMinimumLevel(requested, allowed model.AccessLevel) model.AccessLevel {
    if model.AccessLevelRank(requested) > model.AccessLevelRank(allowed) {
        return allowed  // cap at RBAC ceiling
    }
    return requested
}
```

Rank mapping (higher number = more privileged):

```go
// internal/model/types.go

func AccessLevelRank(l AccessLevel) int {
    return map[AccessLevel]int{
        AccessFull:        7,
        AccessRead:        6,
        AccessAnonymized:  5,
        AccessKAnonymized: 4,
        AccessSlice:       3,
        AccessAggregated:  2,
        AccessAuditLog:    1,
        AccessNone:        0,
    }[l]
}
```

---

## Tenant isolation: end-to-end trace

**Request:** `marketing:analyst` at tenant `acme-corp` queries `DC-01` (Customer) data.

```
1. Sentinel-IN validates metadata → tenant_id="acme-corp", user_id="j.kim"
   tenant.WithTenant(ctx, "acme-corp")

2. Vault resolveKeyMaterial:
   masterKeyID = "tenant:acme-corp:category:DC-01"
   hmacKey     = KMS.GenerateHMACKey("tenant:acme-corp:category:DC-01")
   DEK cache key = "tenant:acme-corp:category:DC-01:dek"

   (rival-corp querying DC-01 gets a completely different hmacKey and DEK)

3. RBAC: "marketing:analyst" → DC-01 → AccessKAnonymized
   OPA check (if enabled): may restrict to AccessAnonymized or below.
   Cannot promote above AccessKAnonymized.

4. DecideWithPurpose: purpose="customer_support"
   purposeMatrix has no restriction for customer_support → permitted.

5. Navigator returns records; each record carries TenantID="acme-corp"

6. CrossTenantVerifier.Verify(records, "acme-corp"):
   All record.TenantID == "acme-corp" → 0 mismatches → clean batch returned.

7. Phase-2 ViewGenerator applies AccessKAnonymized view:
   - name field: tokenized (TOK:abc...)
   - mobile field: masked (010-****-5678)
   - address_detail: [REMOVED]
```

---

## Related documents

- `vault/docs/deterministic-deidentification.md` — anonymization strategies and engine detail
- `docs/11_module_vault_srs_v3.md` — full Vault SRS specification
- `docs/21_cross_multi_tenancy_srs.md` — cross-module multi-tenancy requirements
- `docs/32_injection_defense_architecture.md` — injection defense overview (D-05, D-06, D-07)
