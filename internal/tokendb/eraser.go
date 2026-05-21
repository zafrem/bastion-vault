package tokendb

import (
	"context"
	"log"
	"time"

	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/model"
)

// StartErasureWorker runs a background goroutine that periodically re-sweeps
// the token store for tenants that have pending erasure audit events.
// This ensures tokens are deleted even if the original DELETE /v1/vault/tokens
// request partially failed or the store was temporarily unavailable.
//
// interval controls how often the sweep runs (production default: 24h).
// The returned stop function cancels the worker; call it (e.g. via defer) during shutdown.
func StartErasureWorker(ctx context.Context, store Store, auditLog *audit.Logger, interval time.Duration) (stop func()) {
	workerCtx, cancel := context.WithCancel(ctx)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-workerCtx.Done():
				return
			case <-ticker.C:
				runErasureSweep(workerCtx, store, auditLog, interval)
			}
		}
	}()

	return cancel
}

// runErasureSweep queries the audit log for erasure events in the last interval
// and calls DeleteByTenant for any tenants found.
func runErasureSweep(ctx context.Context, store Store, auditLog *audit.Logger, interval time.Duration) {
	since := time.Now().Add(-interval)
	entries, err := auditLog.Query(ctx, "", 0, since)
	if err != nil {
		log.Printf("erasure worker: querying audit log: %v", err)
		return
	}

	// Collect unique tenant IDs that had erasure events.
	tenants := make(map[string]struct{})
	for _, entry := range entries {
		evType, _ := entry["event_type"].(string)
		if evType != string(model.AuditEventErasure) {
			continue
		}
		tenantID, _ := entry["tenant_id"].(string)
		if tenantID != "" {
			tenants[tenantID] = struct{}{}
		}
	}

	for tenantID := range tenants {
		n, err := store.DeleteByTenant(ctx, tenantID)
		if err != nil {
			log.Printf("erasure worker: DeleteByTenant %q: %v", tenantID, err)
			continue
		}
		if n > 0 {
			log.Printf("erasure worker: deleted %d token mappings for tenant %q", n, tenantID)
		}
	}
}
