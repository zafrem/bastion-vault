package output

import (
	"context"
	"testing"

	"github.com/zafrem/bastion-vault/internal/model"
)

func sampleCustomerRecord() model.DataRecord {
	return model.DataRecord{
		RecordID: "rec-1",
		Category: model.CategoryCustomer,
		TenantID: "tenant-acme",
		Fields: map[string]model.FieldValue{
			"name":        {Value: "Alice", Type: "original", PIIType: "korean_name"},
			"email":       {Value: "alice@example.com", Type: "original", PIIType: "email"},
			"region":      {Value: "Seoul Gangnam-gu", Type: "original"},
			"purchase":    {Value: 5000000, Type: "original"},
			"date":        {Value: "2026-03-15", Type: "original"},
			"rrn":         {Value: "900101-1234567", Type: "original", PIIType: "korean_rrn"},
			"product_id":  {Value: "PROD-001", Type: "original"},
		},
	}
}

func userCtx() *model.UserContext {
	return &model.UserContext{
		UserID:   "u1",
		TenantID: "tenant-acme",
		Roles:    []string{"analyst"},
	}
}

func TestViewGenerator_FullAccess_LeavesEverythingIntact(t *testing.T) {
	g := NewViewGenerator()
	in := []model.DataRecord{sampleCustomerRecord()}
	out, _, err := g.Generate(context.Background(), in, userCtx(), model.AccessFull)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if v := out[0].Fields["name"].Value; v != "Alice" {
		t.Errorf("full: expected name=Alice, got %v", v)
	}
}

func TestViewGenerator_ReadLevel_MasksRRN(t *testing.T) {
	g := NewViewGenerator()
	in := []model.DataRecord{sampleCustomerRecord()}
	out, _, _ := g.Generate(context.Background(), in, userCtx(), model.AccessRead)
	if v := out[0].Fields["rrn"].Value; v != "[MASKED]" {
		t.Errorf("read: expected rrn masked, got %v", v)
	}
	if v := out[0].Fields["region"].Value; v != "Seoul Gangnam-gu" {
		t.Errorf("read: expected region intact, got %v", v)
	}
}

func TestViewGenerator_Anonymized_PseudonymizesName(t *testing.T) {
	g := NewViewGenerator()
	in := []model.DataRecord{sampleCustomerRecord()}
	out, _, _ := g.Generate(context.Background(), in, userCtx(), model.AccessAnonymized)
	v := out[0].Fields["name"].Value.(string)
	if len(v) < 8 || v[:7] != "PSEUDO_" {
		t.Errorf("anonymized: expected PSEUDO_-prefixed pseudonym, got %v", v)
	}
}

func TestViewGenerator_KAnonymized_GeneralizesEmailAndDate(t *testing.T) {
	g := NewViewGenerator()
	in := []model.DataRecord{sampleCustomerRecord()}
	out, _, _ := g.Generate(context.Background(), in, userCtx(), model.AccessKAnonymized)
	if v := out[0].Fields["email"].Value; v != "example.com" {
		t.Errorf("k_anon: expected email->domain example.com, got %v", v)
	}
	if v := out[0].Fields["date"].Value; v != "2026-03" {
		t.Errorf("k_anon: expected date->month 2026-03, got %v", v)
	}
	if v := out[0].Fields["name"].Value; v != "[ANONYMIZED]" {
		t.Errorf("k_anon: expected name anonymized, got %v", v)
	}
}

func TestViewGenerator_Slice_AllowsManufacturingFields(t *testing.T) {
	g := NewViewGenerator()
	in := []model.DataRecord{sampleCustomerRecord()}
	out, _, _ := g.Generate(context.Background(), in, userCtx(), model.AccessSlice)

	// Allowed fields stay (region generalized).
	if v := out[0].Fields["product_id"].Value; v != "PROD-001" {
		t.Errorf("slice: product_id should pass through, got %v", v)
	}
	if v := out[0].Fields["region"].Value; v != "Seoul" {
		t.Errorf("slice: region should be province (Seoul), got %v", v)
	}
	if v := out[0].Fields["date"].Value; v != "2026-03" {
		t.Errorf("slice: date should be month, got %v", v)
	}

	// Blocked fields explicitly scrubbed.
	if v := out[0].Fields["name"].Value; v != "[BLOCKED]" {
		t.Errorf("slice: name should be [BLOCKED], got %v", v)
	}
	if v := out[0].Fields["email"].Value; v != "[BLOCKED]" {
		t.Errorf("slice: email should be [BLOCKED], got %v", v)
	}
	if v := out[0].Fields["rrn"].Value; v != "[BLOCKED]" {
		t.Errorf("slice: rrn should be [BLOCKED], got %v", v)
	}

	// Fields outside the allow-list and not on the block-list are NOT_IN_SLICE.
	if v := out[0].Fields["purchase"].Value; v != "[NOT_IN_SLICE]" {
		t.Errorf("slice: purchase should be [NOT_IN_SLICE], got %v", v)
	}
}

func TestViewGenerator_Aggregated_SuppressesPerRecord(t *testing.T) {
	g := NewViewGenerator()
	in := []model.DataRecord{sampleCustomerRecord()}
	out, _, _ := g.Generate(context.Background(), in, userCtx(), model.AccessAggregated)
	if v := out[0].Fields["name"].Value; v != "[AGGREGATED]" {
		t.Errorf("aggregated: per-field should be [AGGREGATED], got %v", v)
	}
}

func TestViewGenerator_UnknownLevel_FailSafe(t *testing.T) {
	g := NewViewGenerator()
	in := []model.DataRecord{sampleCustomerRecord()}
	out, _, _ := g.Generate(context.Background(), in, userCtx(), model.AccessLevel("bogus"))
	for name, fv := range out[0].Fields {
		if fv.Value != "[HIDDEN]" {
			t.Errorf("fail-safe: field %s should be [HIDDEN], got %v", name, fv.Value)
		}
	}
}

func TestViewGenerator_AuditLog_HidesContents(t *testing.T) {
	g := NewViewGenerator()
	in := []model.DataRecord{sampleCustomerRecord()}
	out, _, _ := g.Generate(context.Background(), in, userCtx(), model.AccessAuditLog)
	for name, fv := range out[0].Fields {
		if fv.Value != "[AUDIT_ONLY]" {
			t.Errorf("audit_log: field %s should be [AUDIT_ONLY], got %v", name, fv.Value)
		}
	}
}

func TestViewGenerator_NilUserErrors(t *testing.T) {
	g := NewViewGenerator()
	if _, _, err := g.Generate(context.Background(), nil, nil, model.AccessFull); err == nil {
		t.Fatal("expected error on nil user")
	}
}
