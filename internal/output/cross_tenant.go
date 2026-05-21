package output

import (
	"context"
	"fmt"
	"log"

	"github.com/zafrem/bastion-vault/internal/model"
)

// crossTenantSuspiciousRatio is the fraction above which a batch is rejected outright.
// Beyond this point we assume the input set was poisoned upstream and refuse to leak
// even the records that DO belong to the user's tenant.
const crossTenantSuspiciousRatio = 0.10

// CrossTenantVerifier is the last-line-of-defence check that filters out any record
// whose tenant_id does not match the calling user's tenant_id. It logs every
// rejected record as a CRITICAL security event so SOC tooling can correlate them.
type CrossTenantVerifier struct{}

// NewCrossTenantVerifier constructs a verifier.
func NewCrossTenantVerifier() *CrossTenantVerifier { return &CrossTenantVerifier{} }

// Verify returns only the records whose TenantID matches userTenantID. Each
// mismatched record produces a critical log entry; if the ratio of mismatches to
// total records exceeds crossTenantSuspiciousRatio the call fails outright.
func (v *CrossTenantVerifier) Verify(_ context.Context, records []model.DataRecord, userTenantID string) ([]model.DataRecord, error) {
	if userTenantID == "" {
		return nil, fmt.Errorf("cross-tenant verifier: empty user tenant_id")
	}

	if len(records) == 0 {
		return records, nil
	}

	out := make([]model.DataRecord, 0, len(records))
	mismatched := 0
	for _, rec := range records {
		if rec.TenantID == userTenantID {
			out = append(out, rec)
			continue
		}
		mismatched++
		log.Printf("CRITICAL vault-out cross_tenant_violation: record_id=%s record_tenant=%s user_tenant=%s",
			rec.RecordID, rec.TenantID, userTenantID)
	}

	if mismatched > 0 && float64(mismatched)/float64(len(records)) > crossTenantSuspiciousRatio {
		return nil, fmt.Errorf("cross-tenant verifier: %d of %d records belonged to other tenants — refusing batch",
			mismatched, len(records))
	}

	return out, nil
}
