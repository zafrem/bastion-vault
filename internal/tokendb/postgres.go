package tokendb

// PostgreSQL schema (apply once during migration):
//
//	CREATE TABLE token_mappings (
//	  token      TEXT NOT NULL,
//	  tenant_id  TEXT NOT NULL,
//	  original   BYTEA NOT NULL,  -- AES-256-GCM encrypted
//	  pii_type   TEXT NOT NULL,
//	  created_at TIMESTAMPTZ DEFAULT now(),
//	  PRIMARY KEY (token, tenant_id)
//	);
//	CREATE INDEX idx_token_mappings_tenant ON token_mappings(tenant_id);
//
// NOTE: The `original` column stores ciphertext produced by the tenant's DEK
// (AES-256-GCM). The caller must encrypt the plaintext before calling Put and
// decrypt it after calling Get. See the comment on each method below.

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// PostgresStore persists token mappings in a PostgreSQL table.
// The original field is stored as opaque bytes — callers are responsible for
// encrypting / decrypting with the tenant's DEK.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore wraps an existing *sql.DB connection pool.
func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// Put inserts or replaces a token mapping.
// caller must encrypt e.Original before calling Put.
func (s *PostgresStore) Put(ctx context.Context, e Entry) error {
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO token_mappings (token, tenant_id, original, pii_type, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (token, tenant_id) DO UPDATE
		  SET original   = EXCLUDED.original,
		      pii_type   = EXCLUDED.pii_type,
		      created_at = EXCLUDED.created_at`,
		e.Token, e.TenantID, []byte(e.Original), e.PIIType, e.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("tokendb postgres: put: %w", err)
	}
	return nil
}

// Get retrieves a token mapping.
// The returned Entry.Original contains ciphertext — caller must decrypt it.
// Returns (nil, nil) when the token does not exist for the tenant.
func (s *PostgresStore) Get(ctx context.Context, token, tenantID string) (*Entry, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT token, tenant_id, original, pii_type, created_at
		  FROM token_mappings
		 WHERE token = $1 AND tenant_id = $2`,
		token, tenantID,
	)

	var e Entry
	var original []byte
	err := row.Scan(&e.Token, &e.TenantID, &original, &e.PIIType, &e.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tokendb postgres: get: %w", err)
	}
	e.Original = string(original)
	return &e, nil
}

// Delete removes a single token mapping.
func (s *PostgresStore) Delete(ctx context.Context, token, tenantID string) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM token_mappings WHERE token = $1 AND tenant_id = $2`,
		token, tenantID,
	)
	if err != nil {
		return fmt.Errorf("tokendb postgres: delete: %w", err)
	}
	return nil
}

// DeleteByTenant removes all mappings for tenantID (GDPR right-to-erasure).
// Returns the number of rows deleted.
func (s *PostgresStore) DeleteByTenant(ctx context.Context, tenantID string) (int, error) {
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM token_mappings WHERE tenant_id = $1`, tenantID,
	)
	if err != nil {
		return 0, fmt.Errorf("tokendb postgres: delete by tenant: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("tokendb postgres: rows affected: %w", err)
	}
	return int(n), nil
}
