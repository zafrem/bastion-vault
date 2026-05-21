package cache

import (
	"context"
	"os"
	"testing"
	"time"
)

func redisAddr(t *testing.T) (addr string) {
	t.Helper()
	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		t.Skip("TEST_REDIS_URL not set")
	}
	return url
}

func newTestClient(t *testing.T) *Client {
	t.Helper()
	addr := redisAddr(t)
	c, err := NewClient(addr, "", 0)
	if err != nil {
		t.Fatalf("NewClient(%q): %v", addr, err)
	}
	if c == nil {
		t.Fatal("NewClient returned nil without error for a non-empty address")
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestRedis_SetAndGet(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	key := "test:set-get"
	want := "hello-redis"

	if err := c.Set(ctx, key, want, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	t.Cleanup(func() { _ = c.Delete(ctx, key) })

	got, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != want {
		t.Errorf("Get: got %q, want %q", got, want)
	}
}

func TestRedis_Delete(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	key := "test:delete"
	if err := c.Set(ctx, key, "temporary", time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := c.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	got, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get after Delete: %v", err)
	}
	if got != "" {
		t.Errorf("Get after Delete: got %q, want empty string", got)
	}
}

func TestRedis_GetMissing(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	got, err := c.Get(ctx, "test:no-such-key-xyz-12345")
	if err != nil {
		t.Fatalf("Get missing key: %v", err)
	}
	if got != "" {
		t.Errorf("Get missing: got %q, want empty string", got)
	}
}

func TestRedis_TTLExpiry(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()

	const ttl = 100 * time.Millisecond
	key := "test:ttl-expiry"

	if err := c.Set(ctx, key, "expires-soon", ttl); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Wait for TTL to elapse.
	time.Sleep(ttl + 50*time.Millisecond)

	got, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get after TTL: %v", err)
	}
	if got != "" {
		t.Errorf("key still present after TTL: got %q", got)
	}
}

func TestRedis_NilClient_NoOps(t *testing.T) {
	// A nil *Client must not panic.
	var c *Client
	ctx := context.Background()

	if err := c.Set(ctx, "k", "v", time.Minute); err != nil {
		t.Errorf("nil Set returned error: %v", err)
	}
	val, err := c.Get(ctx, "k")
	if err != nil || val != "" {
		t.Errorf("nil Get: got (%q, %v), want (\"\", nil)", val, err)
	}
	if err := c.Delete(ctx, "k"); err != nil {
		t.Errorf("nil Delete returned error: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("nil Close returned error: %v", err)
	}
}

func TestRedis_NewClient_EmptyAddress(t *testing.T) {
	c, err := NewClient("", "", 0)
	if err != nil {
		t.Errorf("NewClient with empty address returned error: %v", err)
	}
	if c != nil {
		t.Errorf("NewClient with empty address returned non-nil client")
	}
}
