package kms

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// dekCacheEntry holds a cached plaintext DEK alongside its encrypted form and expiry.
type dekCacheEntry struct {
	plaintext  []byte
	ciphertext []byte
	keyID      string
	expiresAt  time.Time
}

// Manager wraps one or more KMS providers with DEK caching and failover.
// DEK cache TTL default is 5 minutes per SRS §4.3.2 performance requirements.
type Manager struct {
	primary   Provider
	fallbacks []Provider
	cache     map[string]*dekCacheEntry
	mu        sync.RWMutex
	cacheTTL  time.Duration
}

// NewManager constructs a Manager with the given primary provider.
// Providing additional fallback providers enables automatic failover.
func NewManager(primary Provider, cacheTTL time.Duration, fallbacks ...Provider) *Manager {
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}
	m := &Manager{
		primary:   primary,
		fallbacks: fallbacks,
		cache:     make(map[string]*dekCacheEntry),
		cacheTTL:  cacheTTL,
	}
	go m.evictionLoop()
	return m
}

// GetOrGenerateDEK returns a cached DEK for cacheKey or generates a fresh one.
func (m *Manager) GetOrGenerateDEK(ctx context.Context, masterKeyID, cacheKey string) (*DataKey, error) {
	if dk := m.fromCache(cacheKey); dk != nil {
		return dk, nil
	}
	dk, err := m.generateWithFailover(ctx, masterKeyID)
	if err != nil {
		return nil, err
	}
	m.toCache(cacheKey, dk)
	return dk, nil
}

// DecryptDEK decrypts a ciphertext DEK using provider failover.
func (m *Manager) DecryptDEK(ctx context.Context, ciphertext []byte, masterKeyID string) ([]byte, error) {
	plaintext, err := m.primary.DecryptDataKey(ctx, ciphertext, masterKeyID)
	if err == nil {
		return plaintext, nil
	}
	for _, fb := range m.fallbacks {
		if pt, ferr := fb.DecryptDataKey(ctx, ciphertext, masterKeyID); ferr == nil {
			return pt, nil
		}
	}
	return nil, fmt.Errorf("kms manager: all providers failed to decrypt DEK: %w", err)
}

// GetHMACKey returns the HMAC key for the given master key with failover.
func (m *Manager) GetHMACKey(ctx context.Context, masterKeyID string) ([]byte, error) {
	key, err := m.primary.GenerateHMACKey(ctx, masterKeyID)
	if err == nil {
		return key, nil
	}
	for _, fb := range m.fallbacks {
		if k, ferr := fb.GenerateHMACKey(ctx, masterKeyID); ferr == nil {
			return k, nil
		}
	}
	return nil, fmt.Errorf("kms manager: all providers failed to get HMAC key: %w", err)
}

// Encrypt encrypts plaintext using the primary provider with failover.
func (m *Manager) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	ct, err := m.primary.Encrypt(ctx, keyID, plaintext)
	if err == nil {
		return ct, nil
	}
	for _, fb := range m.fallbacks {
		if c, ferr := fb.Encrypt(ctx, keyID, plaintext); ferr == nil {
			return c, nil
		}
	}
	return nil, fmt.Errorf("kms manager: all providers failed to encrypt: %w", err)
}

// Decrypt decrypts ciphertext using the primary provider with failover.
func (m *Manager) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	pt, err := m.primary.Decrypt(ctx, keyID, ciphertext)
	if err == nil {
		return pt, nil
	}
	for _, fb := range m.fallbacks {
		if p, ferr := fb.Decrypt(ctx, keyID, ciphertext); ferr == nil {
			return p, nil
		}
	}
	return nil, fmt.Errorf("kms manager: all providers failed to decrypt: %w", err)
}

func (m *Manager) generateWithFailover(ctx context.Context, masterKeyID string) (*DataKey, error) {
	dk, err := m.primary.GenerateDataKey(ctx, masterKeyID)
	if err == nil {
		return dk, nil
	}
	for _, fb := range m.fallbacks {
		if d, ferr := fb.GenerateDataKey(ctx, masterKeyID); ferr == nil {
			return d, nil
		}
	}
	return nil, fmt.Errorf("kms manager: all providers failed to generate DEK: %w", err)
}

func (m *Manager) fromCache(key string) *DataKey {
	m.mu.RLock()
	entry, ok := m.cache[key]
	m.mu.RUnlock()
	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}
	return &DataKey{
		Plaintext:  entry.plaintext,
		Ciphertext: entry.ciphertext,
		KeyID:      entry.keyID,
	}
}

func (m *Manager) toCache(key string, dk *DataKey) {
	m.mu.Lock()
	m.cache[key] = &dekCacheEntry{
		plaintext:  dk.Plaintext,
		ciphertext: dk.Ciphertext,
		keyID:      dk.KeyID,
		expiresAt:  time.Now().Add(m.cacheTTL),
	}
	m.mu.Unlock()
}

// evictionLoop periodically removes expired entries and zeroizes their plaintext.
// Zeroization is required by SRS §4.3.2 to prevent key material lingering in heap.
func (m *Manager) evictionLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		m.evict()
	}
}

func (m *Manager) evict() {
	now := time.Now()
	m.mu.Lock()
	for k, entry := range m.cache {
		if now.After(entry.expiresAt) {
			zeroize(entry.plaintext)
			delete(m.cache, k)
		}
	}
	m.mu.Unlock()
}

// zeroize overwrites a byte slice with zeros.
// runtime.KeepAlive prevents the compiler from eliding this as dead store.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
