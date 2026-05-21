// Package cache provides a thin wrapper around go-redis for session caching
// and JWT token blacklisting. All methods degrade gracefully when the Client
// is nil (Redis not configured), so callers need not guard every call-site.
package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Client wraps go-redis for session caching and token blacklisting.
type Client struct {
	rdb *redis.Client
}

// NewClient parses the redis address from config and returns a Client.
// Returns (nil, nil) if address is empty — callers must handle nil Client gracefully.
func NewClient(address, password string, db int) (*Client, error) {
	if address == "" {
		return nil, nil
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     address,
		Password: password,
		DB:       db,
	})

	// Verify connectivity at startup.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("cache: redis ping failed: %w", err)
	}

	return &Client{rdb: rdb}, nil
}

// Set stores key=value with TTL. No-op if c is nil.
func (c *Client) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if c == nil {
		return nil
	}
	if err := c.rdb.Set(ctx, key, value, ttl).Err(); err != nil {
		return fmt.Errorf("cache: set %q: %w", key, err)
	}
	return nil
}

// Get retrieves a value. Returns ("", nil) if the key is not found.
// Returns ("", nil) if c is nil.
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	if c == nil {
		return "", nil
	}
	val, err := c.rdb.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("cache: get %q: %w", key, err)
	}
	return val, nil
}

// Delete removes a key. No-op if c is nil.
func (c *Client) Delete(ctx context.Context, key string) error {
	if c == nil {
		return nil
	}
	if err := c.rdb.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("cache: delete %q: %w", key, err)
	}
	return nil
}

// Ping checks connectivity. Returns an error if c is nil.
func (c *Client) Ping(ctx context.Context) error {
	if c == nil {
		return fmt.Errorf("cache: client not initialised")
	}
	if err := c.rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("cache: ping: %w", err)
	}
	return nil
}

// Close closes the underlying Redis connection. No-op if c is nil.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	return c.rdb.Close()
}
