package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/time/rate"
	"github.com/zafrem/bastion-vault/internal/cache"
	"github.com/zafrem/bastion-vault/internal/config"
	"github.com/zafrem/bastion-vault/internal/model"
)

var (
	httpRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vault_http_requests_total",
		Help: "Total number of HTTP requests by method, path, and status.",
	}, []string{"method", "path", "status"})

	httpRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vault_http_request_duration_seconds",
		Help:    "HTTP request latency distribution.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})
)

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// loggingMiddleware emits a structured log line for every request.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		log.Printf("method=%s path=%s status=%d duration=%s remote=%s",
			r.Method, r.URL.Path, rw.status, time.Since(start), r.RemoteAddr)
	})
}

// metricsMiddleware records Prometheus counters and histograms for each request.
func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		httpRequestsTotal.With(prometheus.Labels{
			"method": r.Method,
			"path":   r.URL.Path,
			"status": strconv.Itoa(rw.status),
		}).Inc()
		httpRequestDuration.With(prometheus.Labels{
			"method": r.Method,
			"path":   r.URL.Path,
		}).Observe(time.Since(start).Seconds())
	})
}

// rateLimitMiddleware applies a per-client-IP token-bucket rate limiter.
// Each remote IP gets its own *rate.Limiter; requests that exceed the bucket
// are rejected with 429 Too Many Requests.
func rateLimitMiddleware(rps float64, burst int) func(http.Handler) http.Handler {
	var limiters sync.Map // ip -> *rate.Limiter

	limiterFor := func(ip string) *rate.Limiter {
		if l, ok := limiters.Load(ip); ok {
			return l.(*rate.Limiter)
		}
		l := rate.NewLimiter(rate.Limit(rps), burst)
		actual, _ := limiters.LoadOrStore(ip, l)
		return actual.(*rate.Limiter)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r.RemoteAddr)
			if !limiterFor(ip).Allow() {
				jsonError(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP strips the port from a RemoteAddr value, returning just the host.
func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// isPublicPath returns true for paths that skip authentication.
func isPublicPath(path string) bool {
	return path == "/v1/health/live" ||
		path == "/v1/health/ready" ||
		path == "/v1/metrics"
}

// jtiBlacklistKey returns the Redis key used to blacklist a JWT by its jti claim.
func jtiBlacklistKey(jti string) string {
	return fmt.Sprintf("bl:jti:%s", jti)
}

// BlacklistJTI adds a JWT jti claim to the Redis blacklist with the given TTL.
// This should be called when a token is revoked (break-glass revoke, GDPR erasure).
// No-op if redisClient is nil.
func BlacklistJTI(ctx context.Context, redisClient *cache.Client, jti string, ttl time.Duration) error {
	if redisClient == nil || jti == "" {
		return nil
	}
	return redisClient.Set(ctx, jtiBlacklistKey(jti), "1", ttl)
}

// authMiddleware validates a Bearer JWT and injects a *model.User into context.
// When cfg.Auth.SkipAuth is true (dev mode) a default user is injected instead.
// If redisClient is non-nil, the middleware checks the JWT blacklist before
// accepting a token (enables immediate revocation for break-glass and GDPR erasure).
func authMiddleware(cfg *config.Config, redisClient ...*cache.Client) func(http.Handler) http.Handler {
	var bl blacklistReader
	// Avoid a typed-nil in the interface: only wire a blacklist when Redis is configured.
	if len(redisClient) > 0 && redisClient[0] != nil {
		bl = redisClient[0]
	}
	return authMiddlewareWith(cfg, bl)
}

// blacklistReader is the read side of the JWT revocation list.
type blacklistReader interface {
	Get(ctx context.Context, key string) (string, error)
}

// Errors returned by authenticateToken. HTTP and gRPC map them to their own status codes.
var (
	errInvalidToken          = errors.New("invalid or expired token")
	errMalformedClaims       = errors.New("malformed token claims")
	errTokenRevoked          = errors.New("token has been revoked")
	errRevocationUnavailable = errors.New("token revocation check unavailable")
)

// devUser is the identity injected when auth.skip_auth is on (development only).
func devUser() *model.User {
	return &model.User{UserID: "dev", Department: "marketing", Role: "manager", TenantID: "default"}
}

// authenticateToken validates a Bearer JWT (HMAC signature, issuer, expiry), checks the
// revocation list, and returns the caller's identity. It is shared by REST and gRPC.
func authenticateToken(ctx context.Context, cfg *config.Config, bl blacklistReader, tokenStr string) (*model.User, error) {
	secret := []byte(cfg.Auth.JWTSecret)
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return secret, nil
	}, jwt.WithIssuer(cfg.Auth.Issuer), jwt.WithExpirationRequired())
	if err != nil || !token.Valid {
		return nil, errInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errMalformedClaims
	}

	// Check Redis blacklist for the jti claim (if Redis is configured).
	// This enables immediate revocation without waiting for the token to expire.
	if bl != nil {
		if jti := claimString(claims, "jti"); jti != "" {
			val, berr := bl.Get(ctx, jtiBlacklistKey(jti))
			if berr != nil {
				log.Printf("auth: blacklist check failed for jti=%q: %v", jti, berr)
				if !cfg.Auth.RevocationFailOpen {
					// Fail closed: a Redis outage must not re-enable revoked tokens.
					return nil, errRevocationUnavailable
				}
			} else if val != "" {
				return nil, errTokenRevoked
			}
		}
	}

	return &model.User{
		UserID:     claimString(claims, "sub"),
		Department: claimString(claims, "dept"),
		Role:       claimString(claims, "role"),
		TenantID:   claimString(claims, "tenant"),
	}, nil
}

func authMiddlewareWith(cfg *config.Config, bl blacklistReader) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Health-check and metrics endpoints are always public.
			if isPublicPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Dev-mode bypass.
			if cfg.Auth.SkipAuth {
				ctx := context.WithValue(r.Context(), model.UserContextKey, devUser())
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Extract Bearer token.
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				jsonError(w, "missing or invalid Authorization header", http.StatusUnauthorized)
				return
			}

			user, err := authenticateToken(r.Context(), cfg, bl, strings.TrimPrefix(authHeader, "Bearer "))
			if err != nil {
				status := http.StatusUnauthorized
				if errors.Is(err, errRevocationUnavailable) {
					status = http.StatusServiceUnavailable
				}
				jsonError(w, err.Error(), status)
				return
			}

			ctx := context.WithValue(r.Context(), model.UserContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// claimString safely extracts a string claim from MapClaims.
func claimString(claims jwt.MapClaims, key string) string {
	if v, ok := claims[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

type tenantCtxKey struct{}

func tenantFromCtx(ctx context.Context) string {
	if id, ok := ctx.Value(tenantCtxKey{}).(string); ok {
		return id
	}
	return "default"
}
