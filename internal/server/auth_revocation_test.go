package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zafrem/bastion-vault/internal/config"
)

type stubBlacklist struct {
	val string
	err error
}

func (s stubBlacklist) Get(context.Context, string) (string, error) { return s.val, s.err }

func revocationCfg(failOpen bool) *config.Config {
	return &config.Config{Auth: config.AuthConfig{
		JWTSecret:          strings.Repeat("k", 32),
		JWTAlgorithm:       "HS256",
		Issuer:             "bastion",
		RevocationFailOpen: failOpen,
	}}
}

func signedToken(t *testing.T, secret string) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "alice", "iss": "bastion", "jti": "abc",
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func callProtected(cfg *config.Config, bl blacklistReader, token string) int {
	h := authMiddlewareWith(cfg, bl)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/v1/anything", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestRevocationFailsClosedByDefault(t *testing.T) {
	cfg := revocationCfg(false)
	tok := signedToken(t, cfg.Auth.JWTSecret)
	if got := callProtected(cfg, stubBlacklist{err: errors.New("redis down")}, tok); got != http.StatusServiceUnavailable {
		t.Errorf("redis error, fail-closed: want 503, got %d", got)
	}
}

func TestRevocationFailOpenIsOptIn(t *testing.T) {
	cfg := revocationCfg(true)
	tok := signedToken(t, cfg.Auth.JWTSecret)
	if got := callProtected(cfg, stubBlacklist{err: errors.New("redis down")}, tok); got != http.StatusOK {
		t.Errorf("redis error, fail-open: want 200, got %d", got)
	}
}

func TestRevokedTokenRejected(t *testing.T) {
	cfg := revocationCfg(false)
	tok := signedToken(t, cfg.Auth.JWTSecret)
	if got := callProtected(cfg, stubBlacklist{val: "1"}, tok); got != http.StatusUnauthorized {
		t.Errorf("revoked token: want 401, got %d", got)
	}
}

func TestHealthyBlacklistAllowsToken(t *testing.T) {
	cfg := revocationCfg(false)
	tok := signedToken(t, cfg.Auth.JWTSecret)
	if got := callProtected(cfg, stubBlacklist{}, tok); got != http.StatusOK {
		t.Errorf("valid token: want 200, got %d", got)
	}
}
