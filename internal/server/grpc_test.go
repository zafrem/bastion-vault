package server

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/zafrem/bastion-vault/internal/anonymizer"
	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/classification"
	"github.com/zafrem/bastion-vault/internal/kanon"
	"github.com/zafrem/bastion-vault/internal/kms"
	"github.com/zafrem/bastion-vault/internal/model"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

// testGRPCServer constructs a GRPCServer backed by minimal real dependencies.
func testGRPCServer(t *testing.T) *GRPCServer {
	t.Helper()
	masterKey := hex.EncodeToString(make([]byte, 32))
	provider, err := kms.NewLocalProvider(t.TempDir(), masterKey)
	if err != nil {
		t.Fatalf("NewLocalProvider: %v", err)
	}
	mgr := kms.NewManager(provider, 0)
	aud, err := audit.NewLogger(t.TempDir(), false)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	t.Cleanup(func() { aud.Close() })

	cls := classification.New()
	eng := anonymizer.NewEngine(mgr, cls, aud, tokendb.NewMemoryStore())
	kv := kanon.New()
	return NewGRPCServer(eng, cls, kv, aud)
}

// callMethod invokes a gRPC method handler by name without a network connection.
// in is supplied to the decode function; the handler unmarshals it into its request type.
func callMethod(t *testing.T, srv *GRPCServer, method string, in any) any {
	t.Helper()
	idx := -1
	for i := range vaultServiceDesc.Methods {
		if vaultServiceDesc.Methods[i].MethodName == method {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatalf("method %q not found in vaultServiceDesc", method)
	}
	handler := vaultServiceDesc.Methods[idx].Handler
	dec := func(target any) error {
		// Copy fields from in into target via the JSON codec.
		return JSONCodec{}.Unmarshal(mustMarshal(t, in), target)
	}
	resp, err := handler(srv, context.Background(), dec, nil)
	if err != nil {
		t.Fatalf("handler %q: %v", method, err)
	}
	return resp
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := JSONCodec{}.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestGRPC_Health(t *testing.T) {
	srv := testGRPCServer(t)
	resp := callMethod(t, srv, "Health", grpcHealthRequest{})
	hr, ok := resp.(*grpcHealthResponse)
	if !ok {
		t.Fatalf("response type = %T, want *grpcHealthResponse", resp)
	}
	if hr.Status != "ok" {
		t.Errorf("Status = %q, want ok", hr.Status)
	}
}

func TestGRPC_ClassifyData(t *testing.T) {
	srv := testGRPCServer(t)
	req := grpcClassifyRequest{
		Records: []map[string]any{
			{"name": "홍길동", "customer_id": "C-100"},
		},
	}
	resp := callMethod(t, srv, "ClassifyData", req)
	result, ok := resp.(*model.ClassificationResult)
	if !ok {
		t.Fatalf("response type = %T, want *model.ClassificationResult", resp)
	}
	if result.Category == "" {
		t.Error("Category is empty")
	}
}

func TestGRPC_DetectPII(t *testing.T) {
	srv := testGRPCServer(t)
	req := grpcDetectPIIRequest{
		Record: map[string]any{"rrn": "900101-1234567"},
	}
	resp := callMethod(t, srv, "DetectPII", req)
	m, ok := resp.(map[string]any)
	if !ok {
		t.Fatalf("response type = %T, want map[string]any", resp)
	}
	count, _ := m["count"].(int)
	if count <= 0 {
		t.Errorf("detections count = %d, want > 0", count)
	}
}

func TestGRPC_ValidateKAnon(t *testing.T) {
	srv := testGRPCServer(t)
	req := grpcValidateKAnonRequest{
		Records: []map[string]any{
			{"age": "30", "region": "Seoul"},
			{"age": "30", "region": "Seoul"},
		},
		Category:  model.CategoryCustomer,
		RequiredK: 5,
	}
	resp := callMethod(t, srv, "ValidateKAnon", req)
	report, ok := resp.(*model.KAnonymityReport)
	if !ok {
		t.Fatalf("response type = %T, want *model.KAnonymityReport", resp)
	}
	if report.RequiredK != 5 {
		t.Errorf("RequiredK = %d, want 5", report.RequiredK)
	}
}
