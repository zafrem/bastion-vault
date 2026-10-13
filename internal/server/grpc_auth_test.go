package server

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/zafrem/bastion-vault/internal/access"
	"github.com/zafrem/bastion-vault/internal/config"
	"github.com/zafrem/bastion-vault/internal/model"
)

const (
	grpcMethodAnonymize   = "/bastion.vault.v1.VaultService/Anonymize"
	grpcMethodDeanonymize = "/bastion.vault.v1.VaultService/Deanonymize"
	grpcMethodClassify    = "/bastion.vault.v1.VaultService/ClassifyData"
	grpcMethodHealth      = "/bastion.vault.v1.VaultService/Health"
)

var grpcTestSecret = strings.Repeat("g", 32)

func grpcTestCfg(skipAuth, failOpen bool) *config.Config {
	return &config.Config{Auth: config.AuthConfig{
		JWTSecret: grpcTestSecret, JWTAlgorithm: "HS256", Issuer: "bastion",
		SkipAuth: skipAuth, RevocationFailOpen: failOpen,
	}}
}

// startAuthVaultGRPC serves a real Vault gRPC server over an in-memory listener so the
// interceptor runs exactly as it does on the wire.
func startAuthVaultGRPC(t *testing.T, cfg *config.Config, bl blacklistReader) *grpc.ClientConn {
	t.Helper()
	g := testGRPCServer(t)
	g.enableAuth(cfg, access.NewController(""), bl)
	srv := grpc.NewServer(grpc.UnaryInterceptor(g.UnaryInterceptor()))
	g.Register(srv)

	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func grpcToken(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	base := jwt.MapClaims{"iss": "bastion", "exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range claims {
		base[k] = v
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, base).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// managerToken is a marketing manager in tenant acme: allowed on DC-01 and may deanonymize it.
func managerToken(t *testing.T) string {
	return grpcToken(t, grpcTestSecret, jwt.MapClaims{
		"sub": "mia", "tenant": "acme", "dept": "marketing", "role": "manager", "jti": "j1",
	})
}

func invoke(conn *grpc.ClientConn, token, method string, in, out any) error {
	ctx := context.Background()
	if token != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	}
	return conn.Invoke(ctx, method, in, out)
}

func code(err error) codes.Code { return status.Code(err) }

func anonReq(tenant string) map[string]any {
	return map[string]any{
		"tenant_id": tenant, "category": "DC-01", "purpose": "analytics", "access_level": "anonymized",
		"records": []map[string]any{{"name": "Kim", "mobile": "010-1234-5678"}},
	}
}

func TestGRPCAuth_RejectsMissingAndInvalidTokens(t *testing.T) {
	conn := startAuthVaultGRPC(t, grpcTestCfg(false, false), nil)
	noneTok, _ := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"iss": "bastion", "exp": time.Now().Add(time.Hour).Unix(), "tenant": "acme",
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)

	cases := map[string]string{
		"no token":     "",
		"garbage":      "not-a-jwt",
		"wrong secret": grpcToken(t, strings.Repeat("x", 32), jwt.MapClaims{"tenant": "acme"}),
		"expired":      grpcToken(t, grpcTestSecret, jwt.MapClaims{"exp": time.Now().Add(-time.Hour).Unix()}),
		"wrong issuer": grpcToken(t, grpcTestSecret, jwt.MapClaims{"iss": "someone-else"}),
		"alg none":     noneTok,
	}
	for name, tok := range cases {
		var out map[string]any
		if err := invoke(conn, tok, grpcMethodClassify, map[string]any{"records": []map[string]any{{"a": "b"}}}, &out); code(err) != codes.Unauthenticated {
			t.Errorf("%s: code = %v (err=%v), want Unauthenticated", name, code(err), err)
		}
	}
}

func TestGRPCAuth_HealthStaysPublic(t *testing.T) {
	conn := startAuthVaultGRPC(t, grpcTestCfg(false, false), nil)
	var out map[string]any
	if err := invoke(conn, "", grpcMethodHealth, map[string]any{}, &out); err != nil {
		t.Errorf("Health without token: %v", err)
	}
}

func TestGRPCAuth_ValidTokenIsAccepted(t *testing.T) {
	conn := startAuthVaultGRPC(t, grpcTestCfg(false, false), nil)
	var out map[string]any
	if err := invoke(conn, managerToken(t), grpcMethodAnonymize, anonReq(""), &out); err != nil {
		t.Fatalf("Anonymize with valid token: %v", err)
	}
	if out["tenant_id"] != "acme" {
		t.Errorf("tenant_id = %v, want the token's tenant acme", out["tenant_id"])
	}
}

func TestGRPCAuth_TenantComesFromTokenNotBody(t *testing.T) {
	conn := startAuthVaultGRPC(t, grpcTestCfg(false, false), nil)
	var out map[string]any
	err := invoke(conn, managerToken(t), grpcMethodAnonymize, anonReq("globex"), &out)
	if code(err) != codes.PermissionDenied {
		t.Errorf("anonymize for another tenant: code = %v (err=%v), want PermissionDenied", code(err), err)
	}
	err = invoke(conn, managerToken(t), grpcMethodDeanonymize, map[string]any{
		"tenant_id": "globex", "category": "DC-01", "justification": "x",
		"records": []map[string]any{{"name": "TOK:abc"}},
	}, &out)
	if code(err) != codes.PermissionDenied {
		t.Errorf("deanonymize for another tenant: code = %v (err=%v), want PermissionDenied", code(err), err)
	}
}

func TestGRPCAuth_AccessPolicyIsEnforced(t *testing.T) {
	conn := startAuthVaultGRPC(t, grpcTestCfg(false, false), nil)
	var out map[string]any

	// No RBAC rule for this department/role: denied.
	intern := grpcToken(t, grpcTestSecret, jwt.MapClaims{"sub": "ivy", "tenant": "acme", "dept": "finance", "role": "intern", "jti": "j2"})
	if err := invoke(conn, intern, grpcMethodAnonymize, anonReq(""), &out); code(err) != codes.PermissionDenied {
		t.Errorf("anonymize without RBAC rule: code = %v (err=%v), want PermissionDenied", code(err), err)
	}

	// An analyst may read DC-01 anonymized but is not allowed to deanonymize it.
	analyst := grpcToken(t, grpcTestSecret, jwt.MapClaims{"sub": "al", "tenant": "acme", "dept": "marketing", "role": "analyst", "jti": "j3"})
	err := invoke(conn, analyst, grpcMethodDeanonymize, map[string]any{
		"category": "DC-01", "justification": "x", "records": []map[string]any{{"name": "TOK:abc"}},
	}, &out)
	if code(err) != codes.PermissionDenied {
		t.Errorf("deanonymize as analyst: code = %v (err=%v), want PermissionDenied", code(err), err)
	}
}

type failingBlacklist struct {
	val string
	err error
}

func (f failingBlacklist) Get(context.Context, string) (string, error) { return f.val, f.err }

func TestGRPCAuth_RevocationFailsClosedByDefault(t *testing.T) {
	bl := failingBlacklist{err: errors.New("redis down")}
	conn := startAuthVaultGRPC(t, grpcTestCfg(false, false), bl)
	var out map[string]any
	if err := invoke(conn, managerToken(t), grpcMethodAnonymize, anonReq(""), &out); code(err) != codes.Unavailable {
		t.Errorf("redis error, fail-closed: code = %v (err=%v), want Unavailable", code(err), err)
	}

	open := startAuthVaultGRPC(t, grpcTestCfg(false, true), bl)
	if err := invoke(open, managerToken(t), grpcMethodAnonymize, anonReq(""), &out); err != nil {
		t.Errorf("redis error, fail-open: %v", err)
	}
}

func TestGRPCAuth_RevokedTokenRejected(t *testing.T) {
	conn := startAuthVaultGRPC(t, grpcTestCfg(false, false), failingBlacklist{val: "1"})
	var out map[string]any
	if err := invoke(conn, managerToken(t), grpcMethodAnonymize, anonReq(""), &out); code(err) != codes.Unauthenticated {
		t.Errorf("revoked token: code = %v (err=%v), want Unauthenticated", code(err), err)
	}
}

func TestGRPCAuth_SkipAuthInjectsDevUser(t *testing.T) {
	conn := startAuthVaultGRPC(t, grpcTestCfg(true, false), nil)
	var out map[string]any
	// Dev mode: no token needed; the dev user is a marketing manager in the default tenant.
	if err := invoke(conn, "", grpcMethodAnonymize, anonReq(""), &out); err != nil {
		t.Fatalf("skip_auth Anonymize: %v", err)
	}
	if out["tenant_id"] != "default" {
		t.Errorf("tenant_id = %v, want default", out["tenant_id"])
	}
}

func TestGRPCAuth_UserContextForPhase2IsBoundToToken(t *testing.T) {
	// A caller must not be able to claim another identity or tenant in the request body.
	authUser := &model.User{UserID: "mia", TenantID: "acme", Department: "marketing", Role: "manager"}
	supplied := &model.UserContext{UserID: "root", TenantID: "globex", Department: "marketing", Roles: []string{"manager"}}
	uc := userCtxFromAuth(authUser, supplied)
	if uc.UserID != "mia" || uc.TenantID != "acme" {
		t.Errorf("identity not bound to token: %+v", uc)
	}
}
