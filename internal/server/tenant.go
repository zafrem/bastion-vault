package server

import (
	"context"
	"net/http"

	"github.com/zafrem/bastion-vault/internal/events"
	"github.com/zafrem/bastion-vault/internal/hooks"
)

// tenantMiddleware puts the request's tenant into the context. It must run after authMiddleware.
//
// The tenant is the one the caller's token was issued for (the "tenant" claim, "default" when
// absent). An X-Tenant-ID header can only restate it: a header naming a different tenant is a
// cross-tenant attempt, so it is reported and rejected with 403 instead of being obeyed.
//
// In dev mode (auth.skip_auth) no token is verified, so the header selects the tenant, as before.
// Public probes carry no identity and fall back to the header/default as well.
func (s *Server) tenantMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("X-Tenant-ID")
		user := userFromCtx(r.Context())

		tenantID := header
		if user != nil && !s.cfg.Auth.SkipAuth {
			tenantID = authTenant(user)
			if header != "" && header != tenantID {
				s.reportCrossTenant(r, user.UserID, tenantID, header)
				jsonError(w, "cross-tenant access denied", http.StatusForbidden)
				return
			}
		}
		if tenantID == "" {
			tenantID = "default"
		}
		ctx := context.WithValue(r.Context(), tenantCtxKey{}, tenantID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) reportCrossTenant(r *http.Request, userID, authTenantID, requested string) {
	op := r.Method + " " + r.URL.Path
	tc := events.ExtractTraceContext(r.Header.Get("X-Trace-ID"), r.Header.Get("X-Span-ID"), r.Header.Get("X-Parent-Span-ID"), authTenantID, userID, r.Header.Get("X-Request-ID"))
	s.pub.Publish(events.EventCrossTenantAttempt(tc, requested, op))
	s.hm.Fire(hooks.Event{
		Type:     hooks.EventCrossTenantAttempt,
		TenantID: authTenantID,
		TraceID:  tc.TraceID,
		SpanID:   tc.SpanID,
		Data: map[string]interface{}{
			"requested_tenant_id": requested,
			"operation":           op,
		},
		Ctx: r.Context(),
	})
}
