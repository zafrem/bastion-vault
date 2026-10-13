package server

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/zafrem/bastion-vault/internal/access"
	"github.com/zafrem/bastion-vault/internal/cache"
	"github.com/zafrem/bastion-vault/internal/config"
	"github.com/zafrem/bastion-vault/internal/model"
)

// grpcPublicMethods stay reachable without a token so orchestrators can probe health.
var grpcPublicMethods = map[string]bool{
	"/bastion.vault.v1.VaultService/Health": true,
}

// grpcAuth holds what the gRPC server needs to authenticate and authorise callers.
type grpcAuth struct {
	cfg  *config.Config
	ctrl *access.Controller
	bl   blacklistReader
}

// EnableAuth turns on JWT authentication, tenant binding and access-policy checks for
// the gRPC API, using the same rules as REST. Install UnaryInterceptor on the
// grpc.Server as well. A nil redisClient disables revocation checks, as in REST.
func (g *GRPCServer) EnableAuth(cfg *config.Config, ctrl *access.Controller, redisClient *cache.Client) {
	var bl blacklistReader
	if redisClient != nil { // avoid a typed-nil in the interface
		bl = redisClient
	}
	g.enableAuth(cfg, ctrl, bl)
}

func (g *GRPCServer) enableAuth(cfg *config.Config, ctrl *access.Controller, bl blacklistReader) {
	g.auth = &grpcAuth{cfg: cfg, ctrl: ctrl, bl: bl}
}

// UnaryInterceptor authenticates every call except the public health probe and puts the
// caller's identity in the context. With auth.skip_auth (development) it injects the dev user.
// It does nothing until EnableAuth has been called.
func (g *GRPCServer) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		a := g.auth
		if a == nil || grpcPublicMethods[info.FullMethod] {
			return handler(ctx, req)
		}
		if a.cfg.Auth.SkipAuth {
			return handler(context.WithValue(ctx, model.UserContextKey, devUser()), req)
		}

		md, _ := metadata.FromIncomingContext(ctx)
		var tokenStr string
		for _, h := range md.Get("authorization") {
			if t, ok := strings.CutPrefix(h, "Bearer "); ok && t != "" {
				tokenStr = t
				break
			}
		}
		if tokenStr == "" {
			return nil, status.Error(codes.Unauthenticated, "missing or invalid authorization metadata")
		}

		user, err := authenticateToken(ctx, a.cfg, a.bl, tokenStr)
		if err != nil {
			if errors.Is(err, errRevocationUnavailable) {
				return nil, status.Error(codes.Unavailable, err.Error())
			}
			return nil, status.Error(codes.Unauthenticated, err.Error())
		}
		return handler(context.WithValue(ctx, model.UserContextKey, user), req)
	}
}

// caller returns the authenticated user. When auth is not enabled it returns (nil, nil)
// and the handlers keep their legacy behaviour (used by unit tests of the bare handlers).
func (g *GRPCServer) caller(ctx context.Context) (*model.User, error) {
	if g.auth == nil {
		return nil, nil
	}
	u := userFromCtx(ctx)
	if u == nil {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	return u, nil
}

// authTenant is the tenant the token was issued for ("default" when the claim is absent).
func authTenant(u *model.User) string {
	if u.TenantID == "" {
		return "default"
	}
	return u.TenantID
}

// bindTenant makes the token's tenant authoritative: a request that names a different
// tenant is rejected rather than served, and an empty tenant defaults to the token's.
func bindTenant(u *model.User, requested string) (string, error) {
	t := authTenant(u)
	if requested != "" && requested != t {
		return "", status.Error(codes.PermissionDenied, "cross-tenant access denied")
	}
	return t, nil
}

// authorize applies the same RBAC/OPA decision as REST for the caller and category.
func (g *GRPCServer) authorize(ctx context.Context, u *model.User, category model.DataCategory, deanonymize bool) error {
	if g.auth == nil || g.auth.ctrl == nil {
		return nil
	}
	if deanonymize && !g.auth.ctrl.CanDeanonymize(u, category) {
		return status.Error(codes.PermissionDenied, "deanonymize not permitted for your role")
	}
	decision, err := g.auth.ctrl.Decide(ctx, u, category)
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	if !decision.Allowed {
		return status.Error(codes.PermissionDenied, decision.Reason)
	}
	return nil
}
