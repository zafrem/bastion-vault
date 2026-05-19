package anonymizer

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/classification"
	"github.com/zafrem/bastion-vault/internal/kms"
	"github.com/zafrem/bastion-vault/internal/model"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

const testMasterKey = "0000000000000000000000000000000000000000000000000000000000000001"

// newTestEngine builds an Engine backed by a local KMS, in-memory token store,
// and a temp-dir audit logger.
func newTestEngine(t *testing.T) (*Engine, *tokendb.MemoryStore) {
	t.Helper()

	provider, err := kms.NewLocalProvider(t.TempDir(), testMasterKey)
	if err != nil {
		t.Fatalf("local KMS: %v", err)
	}
	mgr := kms.NewManager(provider, 5*time.Minute)

	aud, err := audit.NewLogger(t.TempDir(), false)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	t.Cleanup(func() { _ = aud.Close() })

	store := tokendb.NewMemoryStore()
	eng := NewEngine(mgr, classification.New(), aud, store)
	return eng, store
}

func TestEngine_AnonymizeCustomerRecord(t *testing.T) {
	eng, _ := newTestEngine(t)

	record := map[string]any{
		"name":           "홍길동",
		"rrn":            "900101-1234567",
		"mobile":         "010-1234-5678",
		"email":          "hong@example.com",
		"address_detail": "101동 202호",
		"address_city":   "Seoul",
		"credit_card":    "1234-5678-9012-3456",
		"date_of_birth":  "1990-01-01",
	}
	req := &model.AnonymizeRequest{
		TenantID:    "t1",
		Category:    model.CategoryCustomer,
		Records:     []map[string]any{record},
		RequesterID: "tester",
		AccessLevel: model.AccessAnonymized,
	}

	resp, err := eng.Anonymize(context.Background(), req)
	if err != nil {
		t.Fatalf("Anonymize: %v", err)
	}
	if resp.Metadata.RecordCount != 1 {
		t.Errorf("RecordCount = %d, want 1", resp.Metadata.RecordCount)
	}
	if resp.Metadata.FieldsAnonymized == 0 {
		t.Errorf("FieldsAnonymized = 0, want > 0")
	}
	out := resp.Records[0]
	if out["rrn"] == record["rrn"] {
		t.Errorf("rrn not anonymized: %v", out["rrn"])
	}
	if out["name"] == record["name"] {
		t.Errorf("name not anonymized: %v", out["name"])
	}
	if resp.AuditID == "" {
		t.Errorf("AuditID is empty")
	}
}

func TestEngine_AnonymizeManufacturingRecord(t *testing.T) {
	eng, _ := newTestEngine(t)

	record := map[string]any{
		"worker_id":    "W-00123",
		"product_code": "PC-9988",
	}
	req := &model.AnonymizeRequest{
		TenantID:    "t1",
		Category:    model.CategoryManufacturing,
		Records:     []map[string]any{record},
		RequesterID: "tester",
		AccessLevel: model.AccessAnonymized,
	}

	resp, err := eng.Anonymize(context.Background(), req)
	if err != nil {
		t.Fatalf("Anonymize: %v", err)
	}
	if resp.Metadata.FieldsAnonymized == 0 {
		t.Errorf("FieldsAnonymized = 0, want > 0")
	}
	out := resp.Records[0]
	// worker_id is detected by the classifier's field-name hints and tokenized.
	if out["worker_id"] == record["worker_id"] {
		t.Errorf("worker_id not transformed: %v", out["worker_id"])
	}
}

func TestEngine_AnonymizeHRFinanceRecord(t *testing.T) {
	eng, _ := newTestEngine(t)

	record := map[string]any{
		"employee_id": "E-4455",
		"salary":      "85000000",
		"rrn":         "880515-2345678",
	}
	req := &model.AnonymizeRequest{
		TenantID:    "t1",
		Category:    model.CategoryHRFinance,
		Records:     []map[string]any{record},
		RequesterID: "tester",
		AccessLevel: model.AccessAnonymized,
	}

	resp, err := eng.Anonymize(context.Background(), req)
	if err != nil {
		t.Fatalf("Anonymize: %v", err)
	}
	out := resp.Records[0]
	salary, _ := out["salary"].(string)
	if !strings.HasPrefix(salary, "ENC:") {
		t.Errorf("salary = %q, want ENC: prefix", salary)
	}
}

func TestEngine_MobileSearchToken(t *testing.T) {
	eng, _ := newTestEngine(t)

	record := map[string]any{
		"name":   "김철수",
		"mobile": "010-9876-5432",
	}
	req := &model.AnonymizeRequest{
		TenantID:    "t1",
		Category:    model.CategoryCustomer,
		Records:     []map[string]any{record},
		RequesterID: "tester",
		AccessLevel: model.AccessAnonymized,
	}

	resp, err := eng.Anonymize(context.Background(), req)
	if err != nil {
		t.Fatalf("Anonymize: %v", err)
	}
	if _, ok := resp.Records[0]["mobile_search_token"]; !ok {
		t.Errorf("expected mobile_search_token key in output, got keys %v", keysOf(resp.Records[0]))
	}
}

func TestEngine_Deanonymize(t *testing.T) {
	eng, _ := newTestEngine(t)

	const origSalary = "72000000"
	record := map[string]any{
		"employee_id": "E-7788",
		"salary":      origSalary,
	}
	req := &model.AnonymizeRequest{
		TenantID:    "t1",
		Category:    model.CategoryHRFinance,
		Records:     []map[string]any{record},
		RequesterID: "tester",
		AccessLevel: model.AccessAnonymized,
	}
	resp, err := eng.Anonymize(context.Background(), req)
	if err != nil {
		t.Fatalf("Anonymize: %v", err)
	}

	deReq := &model.DeanonymizeRequest{
		TenantID:    "t1",
		Category:    model.CategoryHRFinance,
		Records:     resp.Records,
		RequesterID: "tester",
	}
	deResp, err := eng.Deanonymize(context.Background(), deReq)
	if err != nil {
		t.Fatalf("Deanonymize: %v", err)
	}
	if got := deResp.Records[0]["salary"]; got != origSalary {
		t.Errorf("deanonymized salary = %v, want %q", got, origSalary)
	}
}

func TestEngine_AccessLevelFullStillAnonymizes(t *testing.T) {
	eng, _ := newTestEngine(t)

	record := map[string]any{
		"name": "이영희",
		"rrn":  "950303-2111111",
	}
	req := &model.AnonymizeRequest{
		TenantID:    "t1",
		Category:    model.CategoryCustomer,
		Records:     []map[string]any{record},
		RequesterID: "tester",
		AccessLevel: model.AccessFull,
	}

	resp, err := eng.Anonymize(context.Background(), req)
	if err != nil {
		t.Fatalf("Anonymize: %v", err)
	}
	out := resp.Records[0]
	if out["name"] == record["name"] {
		t.Errorf("name not anonymized under AccessFull: %v", out["name"])
	}
	if out["rrn"] == record["rrn"] {
		t.Errorf("rrn not anonymized under AccessFull: %v", out["rrn"])
	}
}

func keysOf(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
