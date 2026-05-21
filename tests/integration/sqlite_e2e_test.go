//go:build integration

// Package integration contains integration tests for the bastion-vault module.
// The tests in this file require no external services — they validate the full
// anonymize → token-store → lookup pipeline using an in-memory token store and
// a local (in-process) KMS provider.
package integration

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zafrem/bastion-vault/internal/anonymizer"
	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/classification"
	"github.com/zafrem/bastion-vault/internal/kms"
	"github.com/zafrem/bastion-vault/internal/model"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

// TestE2E_AnonymizeAndRetrieve exercises the full anonymize → store → deanonymize
// pipeline using zero external dependencies (in-memory store + local KMS).
func TestE2E_AnonymizeAndRetrieve(t *testing.T) {
	ctx := context.Background()

	// ── Local KMS ──────────────────────────────────────────────────────────────
	// Use a deterministic 32-byte master key suitable for tests.
	masterKeyHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	keyDir := t.TempDir()

	provider, err := kms.NewLocalProvider(keyDir, masterKeyHex)
	if err != nil {
		t.Fatalf("kms.NewLocalProvider: %v", err)
	}
	kmsMgr := kms.NewManager(provider, 0)

	// ── Audit logger (writes to tmp dir) ──────────────────────────────────────
	auditDir := filepath.Join(t.TempDir(), "audit-logs")
	auditLogger, err := audit.NewLogger(auditDir, false)
	if err != nil {
		t.Fatalf("audit.NewLogger: %v", err)
	}
	defer auditLogger.Close()

	// ── In-memory token store ─────────────────────────────────────────────────
	// Acts as the reverse-lookup registry for deterministically tokenized fields.
	store := tokendb.NewMemoryStore()

	// ── Anonymizer engine ─────────────────────────────────────────────────────
	cls := classification.New()
	eng := anonymizer.NewEngine(kmsMgr, cls, auditLogger, store)

	// ── Anonymize a customer record ───────────────────────────────────────────
	tenantID := "e2e-tenant"
	record := map[string]any{
		"name":    "홍길동",
		"email":   "hong@example.com",
		"mobile":  "010-1234-5678",
		"address": "Seoul Gangnam",
	}

	anonResp, err := eng.Anonymize(ctx, &model.AnonymizeRequest{
		TenantID:    tenantID,
		Category:    model.CategoryCustomer,
		Records:     []map[string]any{record},
		Purpose:     "e2e-test",
		RequesterID: "test-runner",
		AccessLevel: model.AccessAnonymized,
	})
	if err != nil {
		t.Fatalf("Anonymize: %v", err)
	}
	if len(anonResp.Records) == 0 {
		t.Fatal("Anonymize returned no records")
	}
	if anonResp.AuditID == "" {
		t.Error("expected non-empty AuditID")
	}
	if anonResp.Metadata.RecordCount != 1 {
		t.Errorf("RecordCount: got %d, want 1", anonResp.Metadata.RecordCount)
	}

	anonRecord := anonResp.Records[0]
	t.Logf("anonymized record: %v", anonRecord)

	// The name field should be tokenized — must differ from original value.
	nameAnon, ok := anonRecord["name"]
	if !ok {
		t.Fatal("anonymized record missing 'name' field")
	}
	if nameAnon == "홍길동" {
		t.Error("name was not anonymized")
	}
	// Tokenized names are prefixed with "TOK:".
	if nameStr, ok := nameAnon.(string); ok && !strings.HasPrefix(nameStr, "TOK:") {
		t.Errorf("expected name to start with 'TOK:', got %q", nameStr)
	}

	// Email should also be tokenized.
	emailAnon, ok := anonRecord["email"]
	if !ok {
		t.Fatal("anonymized record missing 'email' field")
	}
	if emailAnon == "hong@example.com" {
		t.Error("email was not anonymized")
	}

	// Address (detail suppressed) should be "[REMOVED]" or similar.
	addrAnon, ok := anonRecord["address"]
	if !ok {
		t.Fatal("anonymized record missing 'address' field")
	}
	if addrStr, ok := addrAnon.(string); ok && addrStr == "Seoul Gangnam" {
		t.Error("address was not anonymized")
	}

	// ── Round-trip via token store ─────────────────────────────────────────────
	// The tokenization strategy stores token→original in the in-memory store.
	// Extract the raw token for the email field and look it up directly.
	emailTok, ok := emailAnon.(string)
	if !ok {
		t.Fatalf("email token is not a string: %T %v", emailAnon, emailAnon)
	}
	rawTok := emailTok
	if strings.HasPrefix(rawTok, "TOK:") {
		rawTok = rawTok[4:]
	}

	entry, err := store.Get(ctx, rawTok, tenantID)
	if err != nil {
		t.Fatalf("store.Get for email token: %v", err)
	}
	if entry == nil {
		t.Fatal("email token not found in token store — mapping was not persisted")
	}
	if entry.Original != "hong@example.com" {
		t.Errorf("token store round-trip failed: got Original=%q, want 'hong@example.com'", entry.Original)
	}

	// ── Token store contains entries for the tenant ────────────────────────────
	n, err := store.DeleteByTenant(ctx, tenantID)
	if err != nil {
		t.Fatalf("DeleteByTenant: %v", err)
	}
	if n == 0 {
		t.Error("expected at least one token mapping in store after anonymization")
	}
	t.Logf("DeleteByTenant removed %d entries", n)
}
