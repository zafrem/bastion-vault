package tokendb

// SQLite schema is auto-provisioned by NewSQLiteStore. No manual migration needed.
//
//	CREATE TABLE IF NOT EXISTS token_mappings (
//	  token      TEXT NOT NULL,
//	  tenant_id  TEXT NOT NULL,
//	  original   BLOB NOT NULL,  -- AES-256-GCM encrypted
//	  pii_type   TEXT NOT NULL,
//	  created_at DATETIME DEFAULT (datetime('now')),
//	  PRIMARY KEY (token, tenant_id)
//	);
//	CREATE INDEX IF NOT EXISTS idx_token_mappings_tenant ON token_mappings(tenant_id);
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

// SQLiteStore persists token mappings in a SQLite database.
// The original field is stored as opaque bytes — callers are responsible for
// encrypting / decrypting with the tenant's DEK.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore wraps an existing *sql.DB connection pool and auto-provisions
// the schema (CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS).
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS token_mappings (
		  token      TEXT NOT NULL,
		  tenant_id  TEXT NOT NULL,
		  original   BLOB NOT NULL,
		  pii_type   TEXT NOT NULL,
		  created_at DATETIME DEFAULT (datetime('now')),
		  PRIMARY KEY (token, tenant_id)
		)`)
	if err != nil {
		return nil, fmt.Errorf("tokendb sqlite: create table: %w", err)
	}

	_, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_token_mappings_tenant ON token_mappings(tenant_id)`)
	if err != nil {
		return nil, fmt.Errorf("tokendb sqlite: create index: %w", err)
	}

	return &SQLiteStore{db: db}, nil
}

// Put inserts or replaces a token mapping.
// Caller must encrypt e.Original before calling Put.
func (s *SQLiteStore) Put(ctx context.Context, e Entry) error {
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO token_mappings (token, tenant_id, original, pii_type, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (token, tenant_id) DO UPDATE
		  SET original   = excluded.original,
		      pii_type   = excluded.pii_type,
		      created_at = excluded.created_at`,
		e.Token, e.TenantID, []byte(e.Original), e.PIIType, e.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("tokendb sqlite: put: %w", err)
	}
	return nil
}

// Get retrieves a token mapping.
// The returned Entry.Original contains ciphertext — caller must decrypt it.
// Returns (nil, nil) when the token does not exist for the tenant.
func (s *SQLiteStore) Get(ctx context.Context, token, tenantID string) (*Entry, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT token, tenant_id, original, pii_type, created_at
		  FROM token_mappings
		 WHERE token = ? AND tenant_id = ?`,
		token, tenantID,
	)

	var e Entry
	var original []byte
	err := row.Scan(&e.Token, &e.TenantID, &original, &e.PIIType, &e.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tokendb sqlite: get: %w", err)
	}
	e.Original = string(original)
	return &e, nil
}

// Delete removes a single token mapping.
func (s *SQLiteStore) Delete(ctx context.Context, token, tenantID string) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM token_mappings WHERE token = ? AND tenant_id = ?`,
		token, tenantID,
	)
	if err != nil {
		return fmt.Errorf("tokendb sqlite: delete: %w", err)
	}
	return nil
}

// DeleteByTenant removes all mappings for tenantID (GDPR right-to-erasure).
// Returns the number of rows deleted.
func (s *SQLiteStore) DeleteByTenant(ctx context.Context, tenantID string) (int, error) {
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM token_mappings WHERE tenant_id = ?`, tenantID,
	)
	if err != nil {
		return 0, fmt.Errorf("tokendb sqlite: delete by tenant: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("tokendb sqlite: rows affected: %w", err)
	}
	return int(n), nil
}
