package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zafrem/bastion-vault/internal/access"
	"github.com/zafrem/bastion-vault/internal/anonymizer"
	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/breakglass"
	"github.com/zafrem/bastion-vault/internal/classification"
	"github.com/zafrem/bastion-vault/internal/config"
	"github.com/zafrem/bastion-vault/internal/kanon"
	"github.com/zafrem/bastion-vault/internal/kms"
	"github.com/zafrem/bastion-vault/internal/model"
	"github.com/zafrem/bastion-vault/internal/output"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

// testServer builds a full *Server with real in-memory dependencies.
func testServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	masterKey := hex.EncodeToString(make([]byte, 32))
	provider, err := kms.NewLocalProvider(t.TempDir(), masterKey)
	if err != nil {
		t.Fatalf("NewLocalProvider: %v", err)
	}
	mgr := kms.NewManager(provider, 0)
	aud, err := audit.NewLogger(t.TempDir(), false)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	t.Cleanup(func() { aud.Close() })

	cls := classification.New()
	store := tokendb.NewMemoryStore()
	eng := anonymizer.NewEngine(mgr, cls, aud, store)
	ctrl := access.NewController("")
	kv := kanon.New()
	bg := breakglass.NewManager(aud)
	processor := output.NewProcessor(ctrl, aud, store, provider)
	return New(eng, cls, ctrl, kv, bg, aud, store, processor, cfg, nil)
}

func devConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Auth.SkipAuth = true
	return cfg
}

// withUser injects a *model.User into the request context.
func withUser(r *http.Request, u *model.User) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), model.UserContextKey, u))
}

func TestBreakGlassRevoke(t *testing.T) {
	cfg := devConfig()
	srv := testServer(t, cfg)
	router := srv.Router()

	// Create a break-glass request as the dev user.
	reqBody := `{"incident_id":"INC-1","reason":"emergency","duration_seconds":600,"category":"DC-01"}`
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/vault/break-glass/request", strings.NewReader(reqBody)))
	if rec.Code != http.StatusOK {
		t.Fatalf("BG request status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var bgReq model.BreakGlassRequest
	if err := json.Unmarshal(rec.Body.Bytes(), &bgReq); err != nil {
		t.Fatalf("decoding BG request: %v", err)
	}

	// Approve twice with two distinct approvers (neither is the requester "dev").
	for _, approver := range []string{"appr-1", "appr-2"} {
		body := `{"request_id":"` + bgReq.ID + `"}`
		ar := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/vault/break-glass/approve", strings.NewReader(body))
		// Inject the approver identity directly.
		req = withUser(req, &model.User{UserID: approver, Role: "manager", TenantID: "default"})
		srv.handleBGApprove(ar, req)
		if ar.Code != http.StatusOK {
			t.Fatalf("approve by %s status = %d, body=%s", approver, ar.Code, ar.Body.String())
		}
	}

	// Revoke.
	rv := httptest.NewRecorder()
	router.ServeHTTP(rv, httptest.NewRequest(http.MethodPost, "/v1/vault/break-glass/revoke", strings.NewReader(`{"request_id":"`+bgReq.ID+`"}`)))
	if rv.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, body=%s", rv.Code, rv.Body.String())
	}
	var revResp map[string]string
	if err := json.Unmarshal(rv.Body.Bytes(), &revResp); err != nil {
		t.Fatalf("decoding revoke response: %v", err)
	}
	if revResp["status"] != "revoked" {
		t.Errorf("status = %q, want revoked", revResp["status"])
	}
}

func TestBreakGlassStatus(t *testing.T) {
	cfg := devConfig()
	srv := testServer(t, cfg)
	router := srv.Router()

	reqBody := `{"incident_id":"INC-2","reason":"emergency","duration_seconds":600,"category":"DC-01"}`
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/vault/break-glass/request", strings.NewReader(reqBody)))
	if rec.Code != http.StatusOK {
		t.Fatalf("BG request status = %d", rec.Code)
	}
	var bgReq model.BreakGlassRequest
	if err := json.Unmarshal(rec.Body.Bytes(), &bgReq); err != nil {
		t.Fatalf("decoding BG request: %v", err)
	}

	// GET the request — the dev user "dev" is the requester so may view it.
	gr := httptest.NewRecorder()
	router.ServeHTTP(gr, httptest.NewRequest(http.MethodGet, "/v1/vault/break-glass/"+bgReq.ID, nil))
	if gr.Code != http.StatusOK {
		t.Fatalf("BG status GET = %d, body=%s", gr.Code, gr.Body.String())
	}
	var got model.BreakGlassRequest
	if err := json.Unmarshal(gr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding BG status: %v", err)
	}
	if got.ID != bgReq.ID {
		t.Errorf("ID = %q, want %q", got.ID, bgReq.ID)
	}
}

func TestGetConfig_RoleEnforcement(t *testing.T) {
	cfg := devConfig()
	cfg.Auth.SkipAuth = false // use injected users
	cfg.Auth.JWTSecret = "x"
	srv := testServer(t, cfg)

	// Manager role -> 403.
	rec := httptest.NewRecorder()
	req := withUser(httptest.NewRequest(http.MethodGet, "/v1/config", nil), &model.User{UserID: "u", Role: "manager", TenantID: "default"})
	srv.handleGetConfig(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("manager config status = %d, want 403", rec.Code)
	}

	// Auditor role -> 200, with no jwt_secret in the response.
	rec = httptest.NewRecorder()
	req = withUser(httptest.NewRequest(http.MethodGet, "/v1/config", nil), &model.User{UserID: "a", Role: "auditor", TenantID: "default"})
	srv.handleGetConfig(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("auditor config status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "jwt_secret") {
		t.Errorf("config response leaked jwt_secret: %s", rec.Body.String())
	}
}

func TestAuditLog_RoleEnforcement(t *testing.T) {
	cfg := devConfig()
	cfg.Auth.SkipAuth = false
	cfg.Auth.JWTSecret = "x"
	srv := testServer(t, cfg)

	// Log a couple of events so the query has data.
	for i := 0; i < 2; i++ {
		if _, err := srv.auditor.Log(context.Background(), model.AuditEvent{
			TenantID:  "default",
			EventType: model.AuditEventAccess,
			Action:    "read",
			Outcome:   "success",
		}); err != nil {
			t.Fatalf("seed audit log: %v", err)
		}
	}

	// Manager role -> 403.
	rec := httptest.NewRecorder()
	req := withUser(httptest.NewRequest(http.MethodGet, "/v1/vault/audit", nil), &model.User{UserID: "u", Role: "manager", TenantID: "default"})
	srv.handleAuditLog(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("manager audit status = %d, want 403", rec.Code)
	}

	// Auditor role -> 200 with count >= 0.
	rec = httptest.NewRecorder()
	req = withUser(httptest.NewRequest(http.MethodGet, "/v1/vault/audit", nil), &model.User{UserID: "a", Role: "auditor", TenantID: "default"})
	srv.handleAuditLog(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("auditor audit status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding audit response: %v", err)
	}
	count, ok := resp["count"].(float64)
	if !ok {
		t.Fatalf("count field missing or wrong type: %v", resp["count"])
	}
	if count < 0 {
		t.Errorf("count = %v, want >= 0", count)
	}
}

func TestErasure(t *testing.T) {
	cfg := devConfig()
	cfg.Auth.SkipAuth = false
	cfg.Auth.JWTSecret = "x"
	srv := testServer(t, cfg)

	// Seed a token mapping for tenant-a.
	if err := srv.tokenStore.Put(context.Background(), tokendb.Entry{
		Token: "tok-1", Original: "orig", TenantID: "tenant-a", PIIType: "korean_name",
	}); err != nil {
		t.Fatalf("seed token store: %v", err)
	}

	// A tenant-a member may erase tenant-a data -> 204.
	rec := httptest.NewRecorder()
	req := withUser(httptest.NewRequest(http.MethodDelete, "/v1/vault/tokens?tenant_id=tenant-a", nil),
		&model.User{UserID: "u", Role: "manager", TenantID: "tenant-a"})
	srv.handleErasure(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("erasure status = %d, want 204, body=%s", rec.Code, rec.Body.String())
	}

	// The mapping must be gone.
	got, err := srv.tokenStore.Get(context.Background(), "tok-1", "tenant-a")
	if err != nil {
		t.Fatalf("Get after erasure: %v", err)
	}
	if got != nil {
		t.Error("token mapping still present after erasure")
	}

	// A non-member, non-auditor may not erase another tenant -> 403.
	rec = httptest.NewRecorder()
	req = withUser(httptest.NewRequest(http.MethodDelete, "/v1/vault/tokens?tenant_id=tenant-b", nil),
		&model.User{UserID: "u", Role: "manager", TenantID: "tenant-a"})
	srv.handleErasure(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant erasure status = %d, want 403", rec.Code)
	}
}
