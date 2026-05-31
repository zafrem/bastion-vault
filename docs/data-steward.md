# Vault — Data Steward Role

**Module:** Vault (`internal/access/controller.go`, `internal/model/types.go`) + Navigator (`orchestrator.py`)
**Version:** 3.1
**Last updated:** 2026-05-31

---

## Overview

The data steward role (FR-MR-04-004) introduces **separation of authority** into purpose-based access control. A steward governs *who may use a document for which purpose* without ever being able to *read the document content*. This split prevents the person who controls access policy from also being a data-exfiltration risk.

```
Standard RBAC roles:   read data      (marketing:manager → AccessFull)
Data steward role:     govern policy  (hr:data_steward → AccessNone + purpose authority)
```

The role spans two modules:

| Concern | Module | Mechanism |
|---|---|---|
| Authority check | Vault | `CanActAsSteward()`, content-blind `rbacMatrix` entry |
| Purpose mutation | Navigator | `update_document_purposes()` → Qdrant `set_payload()` |

Navigator owns the Qdrant payload where `permitted_purposes` lives, so the actual mutation happens there; Vault is the authority of record for *who is allowed to mutate*.

---

## 1. Content-blind RBAC entry

The `data_steward` role is wired into the RBAC matrix with `AccessNone` for **every** data category. This is the structural guarantee that a steward cannot read content — it is not a runtime check that could be bypassed, it is the absence of any grant:

```go
// internal/access/controller.go

// data_steward: AccessNone for all data categories — a steward manages
// permitted_purposes on documents in their domain but never reads content
// directly (separation of authority per MR-04-004).
var rbacMatrix = map[string]map[model.DataCategory]model.AccessLevel{
    // ... standard roles ...

    // data_steward: content-blind — AccessNone for every data category.
    // The steward operation (update permitted_purposes) is a separate action
    // checked by CanActAsSteward, not by the standard RBAC path.
    "hr:data_steward": {
        model.CategoryCustomer:      model.AccessNone,
        model.CategoryManufacturing: model.AccessNone,
        model.CategoryHRFinance:     model.AccessNone,
    },
    "audit:data_steward": {
        model.CategoryCustomer:      model.AccessNone,
        model.CategoryManufacturing: model.AccessNone,
        model.CategoryHRFinance:     model.AccessNone,
    },
}
```

If a steward calls `Decide()` (the standard read path), they get `AccessNone` for everything — exactly as if they had no role at all. Their authority is exercised only through the separate steward path.

---

## 2. The steward registry

Steward authority is **domain-scoped per tenant**: a steward for `hr_docs` cannot touch `customer_docs`, and a steward in tenant `acme` cannot touch tenant `rival`'s documents. This is a three-level map:

```go
// internal/access/controller.go

// stewardRegistry maps tenantID → department → allowed domain list.
// Populated from TenantConfig.StewardDomains at startup or via RegisterSteward.
type stewardRegistry map[string]map[string][]string

type Controller struct {
    opaEndpoint string
    httpClient  *http.Client
    stewards    stewardRegistry
}
```

### Registration

```go
// internal/access/controller.go

// RegisterSteward records that department in tenantID may act as data steward
// for the given domains (MR-04-004). Typically called during startup from
// TenantConfig.StewardDomains.
func (c *Controller) RegisterSteward(tenantID, department string, domains []string) {
    if c.stewards == nil {
        c.stewards = make(stewardRegistry)
    }
    if c.stewards[tenantID] == nil {
        c.stewards[tenantID] = make(map[string][]string)
    }
    c.stewards[tenantID][department] = domains
}

// LoadStewardsFromTenant reads StewardDomains from a TenantConfig and registers them.
func (c *Controller) LoadStewardsFromTenant(cfg *model.TenantConfig) {
    for dept, domains := range cfg.StewardDomains {
        c.RegisterSteward(cfg.ID, dept, domains)
    }
}
```

Domain assignment lives in per-tenant config:

```go
// internal/model/types.go

type TenantConfig struct {
    ID             string              `json:"id"`
    Name           string              `json:"name"`
    KMSKeyID       string              `json:"kms_key_id"`
    HMACKeyID      string              `json:"hmac_key_id"`
    AuditKeyID     string              `json:"audit_key_id"`
    CustomPolicies map[string]any      `json:"custom_policies,omitempty"`
    // StewardDomains maps department name → list of data domains the department
    // may act as steward for. A data steward may update permitted_purposes on
    // documents in their assigned domains but may not read document content
    // (MR-04-004).
    StewardDomains map[string][]string `json:"steward_domains,omitempty"`
}
```

---

## 3. Authorization check

`CanActAsSteward` is the gate. It walks the registry: tenant → department → domain. Any missing level denies:

```go
// internal/access/controller.go

// CanActAsSteward returns true when the user's department is registered as a
// data steward for domain in their tenant. A steward may update
// permitted_purposes on documents in that domain but may not read content
// (enforced by the AccessNone entry in rbacMatrix for the data_steward role).
func (c *Controller) CanActAsSteward(user *model.User, domain string) bool {
    tenantDomains, ok := c.stewards[user.TenantID]
    if !ok {
        return false  // tenant has no stewards registered
    }
    allowedDomains, ok := tenantDomains[user.Department]
    if !ok {
        return false  // user's department is not a steward in this tenant
    }
    for _, d := range allowedDomains {
        if d == domain {
            return true  // department is steward for THIS domain
        }
    }
    return false  // department is a steward, but not for this domain
}
```

### Authorization decision table

| Tenant registered? | Department is steward? | Domain in list? | Result |
|---|---|---|---|
| no | — | — | deny |
| yes | no | — | deny |
| yes | yes | no | deny (wrong domain) |
| yes | yes | yes | **allow** |

---

## 4. Purpose mutation in Navigator

Once Vault authorizes, the mutation happens in Navigator, which owns the Qdrant payload. The update uses `set_payload` so **no re-embedding** occurs — only the `permitted_purposes` field on every chunk of the document is overwritten:

```python
# navigator/orchestrator.py

def update_document_purposes(self, req: UpdatePurposesRequest) -> UpdatePurposesResponse:
    collection = req.collection or req.tenant_id and "default" or "default"
    pp_str = ",".join(req.permitted_purposes)
    updated = self._searcher.set_payload(
        collection, req.document_id, {"permitted_purposes": pp_str}
    )
    if self._publisher:
        tc = TraceContext(tenant_id=req.tenant_id, user_id=req.steward_user_id)
        self._publisher.publish(event_steward_purposes_updated(
            tc, document_id=req.document_id, collection=collection,
            steward_user_id=req.steward_user_id,
            old_purposes=[], new_purposes=req.permitted_purposes,
        ))
    return UpdatePurposesResponse(
        document_id=req.document_id, collection=collection,
        chunks_updated=updated, permitted_purposes=req.permitted_purposes,
    )
```

The Qdrant-side update filters by `document_id` so all chunks are touched in one server-side operation:

```python
# navigator/searcher.py

def set_payload(self, collection: str, document_id: str, payload_patch: dict) -> int:
    from qdrant_client.models import Filter, FieldCondition, MatchValue
    result = self._client.set_payload(
        collection_name=collection,
        payload=payload_patch,
        points=Filter(
            must=[FieldCondition(key="document_id", match=MatchValue(value=document_id))]
        ),
    )
    return getattr(result, "updated", 0) or 0
```

Endpoint: `PATCH /v1/navigator/documents/{document_id}/purposes`

Every steward action emits `steward_purposes_updated` (category `audit`) to Tracker, so the audit trail records exactly which steward changed which document's purposes and when.

---

## How it composes with purpose × RBAC conjunction

The steward sets the policy; the existing `DecideWithPurpose` (FR-MR-04-003) enforces it at read time. The two are complementary halves of purpose-based access control:

```
Steward (write side):   sets permitted_purposes = ["customer_support", "audit"]
                          on document D, via Navigator set_payload
                          (authorized by CanActAsSteward)

Reader (read side):     DecideWithPurpose(user, category, purpose="audit")
                          → RBAC allows AND purpose ∈ permitted_purposes
                          → access granted

The steward never appears on the read side (AccessNone everywhere).
The reader never appears on the write side (no steward registration).
```

See `vault/docs/multi-tenancy.md` §"DecideWithPurpose" for the read-side conjunction logic.

---

## Security properties

| Property | Mechanism |
|---|---|
| Steward cannot read content | `AccessNone` for all categories in `rbacMatrix` (structural, not runtime) |
| Domain scoping | `CanActAsSteward` checks the exact domain in the registry list |
| Tenant isolation | registry is keyed by `tenantID` first; cross-tenant lookups miss |
| Auditability | every mutation emits `steward_purposes_updated` to Tracker |
| No content exposure during update | `set_payload` touches metadata only; chunk vectors/content untouched |

---

## Related documents

- `vault/docs/multi-tenancy.md` — RBAC matrix, `DecideWithPurpose`, purpose × RBAC conjunction
- `docs/11_module_vault_srs_v3.md` — full Vault SRS (§4.3 Data Steward Role)
- `docs/31_modular_rag_requirements.md` — FR-MR-04-004 specification
