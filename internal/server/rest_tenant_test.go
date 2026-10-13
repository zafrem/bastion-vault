package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/zafrem/bastion-vault/internal/config"
	"github.com/zafrem/bastion-vault/internal/hooks"
)

func restAuthConfig() *config.Config {
	return &config.Config{Auth: config.AuthConfig{
		JWTSecret: grpcTestSecret, JWTAlgorithm: "HS256", Issuer: "bastion",
	}}
}

// restCall sends a request through the full router (real JWT auth) and returns the recorder.
func restCall(t *testing.T, router http.Handler, method, path, token, tenantHeader, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if tenantHeader != "" {
		req.Header.Set("X-Tenant-ID", tenantHeader)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

const anonBody = `{"category":"DC-01","purpose":"analytics","access_level":"anonymized","records":[{"name":"Kim","mobile":"010-1234-5678"}]}`

func tenantOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return out.TenantID
}

func TestRESTTenant_ComesFromTokenWhenNoHeader(t *testing.T) {
	router := testServer(t, restAuthConfig()).Router()
	rec := restCall(t, router, http.MethodPost, "/v1/vault/anonymize", managerToken(t), "", anonBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if got := tenantOf(t, rec); got != "acme" {
		t.Errorf("tenant = %q, want the token's tenant acme", got)
	}
}

func TestRESTTenant_HeaderCannotOverrideToken(t *testing.T) {
	router := testServer(t, restAuthConfig()).Router()
	for _, path := range []string{"/v1/vault/anonymize", "/v1/vault/anonymize/batch", "/v1/vault/deanonymize", "/v1/vault/classify"} {
		rec := restCall(t, router, http.MethodPost, path, managerToken(t), "globex", anonBody)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s with X-Tenant-ID of another tenant: status %d, want 403 (%s)", path, rec.Code, rec.Body.String())
		}
	}
}

func TestRESTTenant_MatchingHeaderIsAccepted(t *testing.T) {
	router := testServer(t, restAuthConfig()).Router()
	rec := restCall(t, router, http.MethodPost, "/v1/vault/anonymize", managerToken(t), "acme", anonBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("matching header: status %d: %s", rec.Code, rec.Body.String())
	}
	if got := tenantOf(t, rec); got != "acme" {
		t.Errorf("tenant = %q, want acme", got)
	}
}

func TestRESTTenant_BodyTenantIsCheckedAgainstToken(t *testing.T) {
	router := testServer(t, restAuthConfig()).Router()
	body := strings.Replace(anonBody, `{"category"`, `{"tenant_id":"globex","category"`, 1)
	rec := restCall(t, router, http.MethodPost, "/v1/vault/anonymize", managerToken(t), "", body)
	if rec.Code != http.StatusForbidden {
		t.Errorf("body names another tenant: status %d, want 403", rec.Code)
	}
}

func TestRESTTenant_TokenWithoutTenantCannotClaimOne(t *testing.T) {
	router := testServer(t, restAuthConfig()).Router()
	noTenant := grpcToken(t, grpcTestSecret, jwt.MapClaims{"sub": "mia", "dept": "marketing", "role": "manager", "jti": "n1"})

	rec := restCall(t, router, http.MethodPost, "/v1/vault/anonymize", noTenant, "", anonBody)
	if rec.Code != http.StatusOK || tenantOf(t, rec) != "default" {
		t.Errorf("no claim, no header: status %d tenant %q, want 200 default", rec.Code, tenantOf(t, rec))
	}
	rec = restCall(t, router, http.MethodPost, "/v1/vault/anonymize", noTenant, "acme", anonBody)
	if rec.Code != http.StatusForbidden {
		t.Errorf("no claim but header acme: status %d, want 403", rec.Code)
	}
}

func TestRESTTenant_DevModeStillHonoursHeader(t *testing.T) {
	router := testServer(t, devConfig()).Router()
	rec := restCall(t, router, http.MethodPost, "/v1/vault/anonymize", "", "acme", anonBody)
	if rec.Code != http.StatusOK || tenantOf(t, rec) != "acme" {
		t.Errorf("skip_auth with header: status %d tenant %q, want 200 acme", rec.Code, tenantOf(t, rec))
	}
}

func TestRESTTenant_PublicProbesIgnoreTheHeader(t *testing.T) {
	router := testServer(t, restAuthConfig()).Router()
	rec := restCall(t, router, http.MethodGet, "/v1/health/live", "", "anything", "")
	if rec.Code != http.StatusOK {
		t.Errorf("health with a tenant header and no token: status %d, want 200", rec.Code)
	}
}

type captureHook struct{ ch chan hooks.Event }

func (captureHook) Name() string            { return "capture" }
func (c captureHook) OnEvent(e hooks.Event) { c.ch <- e }

func TestRESTTenant_MismatchIsReportedAsCrossTenantAttempt(t *testing.T) {
	srv := testServer(t, restAuthConfig())
	hook := captureHook{ch: make(chan hooks.Event, 1)}
	srv.hm.Register(hooks.EventCrossTenantAttempt, hook)

	rec := restCall(t, srv.Router(), http.MethodPost, "/v1/vault/deanonymize", managerToken(t), "globex", anonBody)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	select {
	case ev := <-hook.ch:
		if ev.TenantID != "acme" || ev.Data["requested_tenant_id"] != "globex" {
			t.Errorf("event = tenant %q requested %v, want acme/globex", ev.TenantID, ev.Data["requested_tenant_id"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no cross-tenant event was fired")
	}
}
