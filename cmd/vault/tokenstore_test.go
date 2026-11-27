package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zafrem/bastion-vault/internal/anonymizer"
	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/classification"
	"github.com/zafrem/bastion-vault/internal/config"
	"github.com/zafrem/bastion-vault/internal/kms"
	"github.com/zafrem/bastion-vault/internal/model"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

const (
	keyA = "00000000000000000000000000000000000000000000000000000000000000aa"
	keyB = "00000000000000000000000000000000000000000000000000000000000000bb"
	pii  = "hong.gildong@example.com"
)

func localKMS(t *testing.T, key string) kms.Provider {
	t.Helper()
	p, err := kms.NewLocalProvider(t.TempDir(), key)
	if err != nil {
		t.Fatalf("local KMS: %v", err)
	}
	return p
}

func sqliteConfig(path string) *config.Config {
	return &config.Config{TokenStore: config.TokenStoreConfig{Driver: "sqlite", DSN: path}}
}

func openStore(t *testing.T, cfg *config.Config, p kms.Provider) tokendb.Store {
	t.Helper()
	s, err := newTokenStore(cfg, p)
	if err != nil {
		t.Fatalf("newTokenStore: %v", err)
	}
	return s
}

func put(t *testing.T, s tokendb.Store, token, tenant, original string) {
	t.Helper()
	if err := s.Put(context.Background(), tokendb.Entry{Token: token, TenantID: tenant, Original: original, PIIType: "email"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

// rawDB reads the table directly, which is what someone with database access (or a stolen backup) sees.
func rawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func rawOriginal(t *testing.T, db *sql.DB, token, tenant string) []byte {
	t.Helper()
	var b []byte
	if err := db.QueryRow(`SELECT original FROM token_mappings WHERE token = ? AND tenant_id = ?`, token, tenant).Scan(&b); err != nil {
		t.Fatalf("reading the stored row: %v", err)
	}
	return b
}

// ─── driver selection ─────────────────────────────────────────────────────────

func TestTokenStore_SQLiteSurvivesARestart(t *testing.T) {
	path, p := filepath.Join(t.TempDir(), "tokens.db"), localKMS(t, keyA)
	put(t, openStore(t, sqliteConfig(path), p), "tok1", "t1", pii)

	got, err := openStore(t, sqliteConfig(path), p).Get(context.Background(), "tok1", "t1")
	if err != nil {
		t.Fatalf("Get after reopening: %v", err)
	}
	if got == nil || got.Original != pii {
		t.Fatalf("the mapping did not survive a restart: got %+v", got)
	}
}

func TestTokenStore_MisconfigurationIsAnError(t *testing.T) {
	p := localKMS(t, keyA)
	for name, ts := range map[string]config.TokenStoreConfig{
		"misspelt driver":      {Driver: "postgre", DSN: "x"},
		"unknown driver":       {Driver: "mysql", DSN: "x"},
		"postgres without DSN": {Driver: "postgres"},
		"unreachable postgres": {Driver: "postgres", DSN: "postgres://u:p@127.0.0.1:1/db?sslmode=disable&connect_timeout=2"},
	} {
		if _, err := newTokenStore(&config.Config{TokenStore: ts}, p); err == nil {
			t.Errorf("%s: want a startup error, got a working store (mappings would silently go elsewhere)", name)
		}
	}
	for _, driver := range []string{"", "memory"} {
		if _, err := newTokenStore(&config.Config{TokenStore: config.TokenStoreConfig{Driver: driver}}, p); err != nil {
			t.Errorf("driver %q must keep working: %v", driver, err)
		}
	}
}

// ─── encryption at rest ───────────────────────────────────────────────────────

func TestTokenStore_OriginalsAreEncryptedAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.db")
	provider := localKMS(t, keyA)
	store := openStore(t, sqliteConfig(path), provider)

	aud, err := audit.NewLogger(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = aud.Close() })
	eng := anonymizer.NewEngine(kms.NewManager(provider, time.Minute), classification.New(), aud, store)
	resp, err := eng.Anonymize(context.Background(), &model.AnonymizeRequest{
		TenantID: "t1", Category: model.CategoryCustomer, RequesterID: "tester",
		Records: []map[string]any{{"email": pii}},
	})
	if err != nil {
		t.Fatalf("Anonymize: %v", err)
	}
	token := strings.TrimPrefix(resp.Records[0]["email"].(string), "TOK:")

	if raw := rawOriginal(t, rawDB(t, path), token, "t1"); strings.Contains(string(raw), pii) {
		t.Errorf("PII is stored in plaintext: %q", raw)
	}
	got, err := store.Get(context.Background(), token, "t1")
	if err != nil || got == nil || got.Original != pii {
		t.Errorf("the store must still return the original: %+v, %v", got, err)
	}
}

// The key must come from the KMS, not from process memory: a new process with the same master key can read the
// rows, and one with a different master key cannot.
func TestTokenStore_EncryptedRowsDependOnTheMasterKeyOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.db")
	put(t, openStore(t, sqliteConfig(path), localKMS(t, keyA)), "tok1", "t1", pii)
	ctx := context.Background()

	got, err := openStore(t, sqliteConfig(path), localKMS(t, keyA)).Get(ctx, "tok1", "t1")
	if err != nil || got == nil || got.Original != pii {
		t.Fatalf("same master key after a restart: %+v, %v", got, err)
	}
	if got, err := openStore(t, sqliteConfig(path), localKMS(t, keyB)).Get(ctx, "tok1", "t1"); err == nil {
		t.Errorf("a different master key must not read the row, got %+v", got)
	}
}

func TestTokenStore_RowsCannotBeSwappedOrAltered(t *testing.T) {
	path, p := filepath.Join(t.TempDir(), "tokens.db"), localKMS(t, keyA)
	store := openStore(t, sqliteConfig(path), p)
	put(t, store, "mine", "t1", "me@example.com")
	put(t, store, "theirs", "t1", "victim@example.com")
	put(t, store, "mine", "t2", "other-tenant@example.com")
	db, ctx := rawDB(t, path), context.Background()
	overwrite := func(token, tenant string, blob []byte) {
		if _, err := db.Exec(`UPDATE token_mappings SET original = ? WHERE token = ? AND tenant_id = ?`, blob, token, tenant); err != nil {
			t.Fatal(err)
		}
	}
	for name, blob := range map[string][]byte{
		"another token's ciphertext":  rawOriginal(t, db, "theirs", "t1"),
		"another tenant's ciphertext": rawOriginal(t, db, "mine", "t2"),
		"injected plaintext":          []byte("attacker@example.com"),
		"truncated":                   rawOriginal(t, db, "theirs", "t1")[:12],
		"empty":                       {},
	} {
		overwrite("mine", "t1", blob)
		if got, err := store.Get(ctx, "mine", "t1"); err == nil {
			t.Errorf("%s: want an error, got %+v", name, got)
		}
	}
}

// Rows written before encryption existed are refused unless the operator opts in; opting in re-encrypts each
// row the first time it is read.
func TestTokenStore_LegacyPlaintextRowsNeedAnExplicitOptIn(t *testing.T) {
	path, p := filepath.Join(t.TempDir(), "tokens.db"), localKMS(t, keyA)
	openStore(t, sqliteConfig(path), p) // creates the table
	db, ctx := rawDB(t, path), context.Background()
	if _, err := db.Exec(`INSERT INTO token_mappings (token, tenant_id, original, pii_type) VALUES ('old', 't1', ?, 'email')`, []byte(pii)); err != nil {
		t.Fatal(err)
	}

	if got, err := openStore(t, sqliteConfig(path), p).Get(ctx, "old", "t1"); err == nil || !strings.Contains(err.Error(), "allow_legacy_plaintext") {
		t.Errorf("want a refusal naming the opt-in, got %+v, %v", got, err)
	}

	cfg := sqliteConfig(path)
	cfg.TokenStore.AllowLegacyPlaintext = true
	got, err := openStore(t, cfg, p).Get(ctx, "old", "t1")
	if err != nil || got == nil || got.Original != pii {
		t.Fatalf("opted in: %+v, %v", got, err)
	}
	if raw := rawOriginal(t, db, "old", "t1"); strings.Contains(string(raw), pii) {
		t.Errorf("the legacy row was not re-encrypted: %q", raw)
	}
}
