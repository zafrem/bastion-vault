package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"

	"github.com/zafrem/bastion-vault/internal/config"
	"github.com/zafrem/bastion-vault/internal/kms"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

const (
	defaultSQLiteDSN   = "vault-tokens.db"
	tokenStoreDeadline = 10 * time.Second
)

// newTokenStore builds the token persistence backend from configuration. A backend that cannot be used is a
// startup error: falling back to memory would silently lose every mapping at the next restart.
func newTokenStore(cfg *config.Config, provider kms.Provider) (tokendb.Store, error) {
	ts := cfg.TokenStore
	switch ts.Driver {
	case "", "memory":
		log.Print("token store: in memory. Mappings are lost on restart and are not shared between replicas; " +
			"set token_store.driver to postgres or sqlite to keep them")
		return tokendb.NewMemoryStore(), nil

	case "postgres":
		if ts.DSN == "" {
			return nil, fmt.Errorf("token store: driver postgres needs token_store.dsn (VAULT_TOKEN_STORE_DSN)")
		}
		db, err := openDB("postgres", ts.DSN)
		if err != nil {
			return nil, err
		}
		if _, err := db.Exec(`SELECT token, tenant_id, original, pii_type, created_at FROM token_mappings LIMIT 0`); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("token store: the token_mappings table is not usable "+
				"(apply deployments/sql/001_token_mappings.sql): %w", err)
		}
		return encrypted(cfg, tokendb.NewPostgresStore(db), provider), nil

	case "sqlite":
		dsn := ts.DSN
		if dsn == "" {
			dsn = defaultSQLiteDSN
		}
		db, err := openDB("sqlite", dsn)
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(1) // SQLite allows one writer; more connections only produce "database is locked"
		store, err := tokendb.NewSQLiteStore(db)
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("token store: %w", err)
		}
		return encrypted(cfg, store, provider), nil

	default:
		return nil, fmt.Errorf("token store: unknown driver %q (want memory, postgres or sqlite)", ts.Driver)
	}
}

// encrypted makes sure a database only ever receives ciphertext.
func encrypted(cfg *config.Config, store tokendb.Store, provider kms.Provider) tokendb.Store {
	if cfg.TokenStore.AllowLegacyPlaintext {
		log.Print("token store: allow_legacy_plaintext is on: unencrypted rows are accepted and re-encrypted when read; " +
			"turn it off once old rows are converted")
	}
	return tokendb.NewEncryptedStore(store, provider, tokendb.EncryptedOptions{
		KeyTTL:               cfg.KMS.DEKCacheTTL,
		AllowLegacyPlaintext: cfg.TokenStore.AllowLegacyPlaintext,
	})
}

// openDB opens the database and checks that it answers, so a wrong DSN stops startup rather than the first request.
func openDB(driver, dsn string) (*sql.DB, error) {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("token store: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), tokenStoreDeadline)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("token store: cannot reach the %s database: %w", driver, err)
	}
	return db, nil
}
