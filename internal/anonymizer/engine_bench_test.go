package anonymizer

import (
	"context"
	"testing"
	"time"

	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/classification"
	"github.com/zafrem/bastion-vault/internal/kms"
	"github.com/zafrem/bastion-vault/internal/model"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

func newBenchEngine(tb testing.TB) *Engine {
	tb.Helper()
	provider, err := kms.NewLocalProvider(tb.TempDir(), testMasterKey)
	if err != nil {
		tb.Fatalf("local KMS: %v", err)
	}
	mgr := kms.NewManager(provider, 5*time.Minute)
	aud, err := audit.NewLogger(tb.TempDir(), false)
	if err != nil {
		tb.Fatalf("audit logger: %v", err)
	}
	tb.Cleanup(func() { _ = aud.Close() })
	store := tokendb.NewMemoryStore()
	return NewEngine(mgr, classification.New(), aud, store)
}

func customerRecord() map[string]any {
	return map[string]any{
		"name":           "Hong Gildong",
		"email":          "hong@example.com",
		"mobile":         "010-1234-5678",
		"rrn":            "900101-1234567",
		"address_city":   "Seoul",
		"address_detail": "Gangnam-gu 123",
	}
}

// BenchmarkAnonymize measures NFR-PE-001: anonymize p95 < 5 ms
func BenchmarkAnonymize(b *testing.B) {
	eng := newBenchEngine(b)
	ctx := context.Background()
	req := &model.AnonymizeRequest{
		TenantID:    "bench-tenant",
		Category:    model.CategoryCustomer,
		Records:     []map[string]any{customerRecord()},
		AccessLevel: model.AccessAnonymized,
		RequesterID: "bench-user",
		Purpose:     "bench",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := eng.Anonymize(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAnonymizeBatch measures throughput with 10-record batches
func BenchmarkAnonymizeBatch(b *testing.B) {
	eng := newBenchEngine(b)
	ctx := context.Background()
	records := make([]map[string]any, 10)
	for i := range records {
		records[i] = customerRecord()
	}
	req := &model.AnonymizeRequest{
		TenantID:    "bench-tenant",
		Category:    model.CategoryCustomer,
		Records:     records,
		AccessLevel: model.AccessAnonymized,
		RequesterID: "bench-user",
		Purpose:     "bench",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := eng.Anonymize(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDeanonymize measures NFR-PE-003: deanonymize p95 < 20 ms
func BenchmarkDeanonymize(b *testing.B) {
	eng := newBenchEngine(b)
	ctx := context.Background()

	anonReq := &model.AnonymizeRequest{
		TenantID:    "bench-tenant",
		Category:    model.CategoryCustomer,
		Records:     []map[string]any{customerRecord()},
		AccessLevel: model.AccessAnonymized,
		RequesterID: "bench-user",
		Purpose:     "bench",
	}
	anonResp, err := eng.Anonymize(ctx, anonReq)
	if err != nil {
		b.Fatalf("setup anonymize: %v", err)
	}

	deReq := &model.DeanonymizeRequest{
		TenantID:      "bench-tenant",
		Category:      model.CategoryCustomer,
		Records:       anonResp.Records,
		RequesterID:   "bench-user",
		Justification: "bench",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := eng.Deanonymize(ctx, deReq); err != nil {
			b.Fatal(err)
		}
	}
}

// TestNFR_Anonymize_P95_Under5ms verifies NFR-PE-001 using statistical timing.
// Runs 200 iterations and checks that p95 stays below 5 ms.
func TestNFR_Anonymize_P95_Under5ms(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping NFR latency test in short mode")
	}
	eng := newBenchEngine(t)
	ctx := context.Background()
	req := &model.AnonymizeRequest{
		TenantID:    "nfr-tenant",
		Category:    model.CategoryCustomer,
		Records:     []map[string]any{customerRecord()},
		AccessLevel: model.AccessAnonymized,
		RequesterID: "nfr-user",
		Purpose:     "nfr",
	}

	const iterations = 200
	durations := make([]time.Duration, iterations)
	for i := range durations {
		start := time.Now()
		if _, err := eng.Anonymize(ctx, req); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		durations[i] = time.Since(start)
	}
	p95 := percentile(durations, 95)
	t.Logf("Anonymize p50=%.2fms p95=%.2fms (NFR-PE-001 target: <5ms)",
		float64(percentile(durations, 50))/float64(time.Millisecond),
		float64(p95)/float64(time.Millisecond))
	if p95 > 5*time.Millisecond {
		t.Errorf("NFR-PE-001 FAIL: anonymize p95=%.2fms exceeds 5ms limit",
			float64(p95)/float64(time.Millisecond))
	}
}

// TestNFR_Deanonymize_P95_Under20ms verifies NFR-PE-003.
func TestNFR_Deanonymize_P95_Under20ms(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping NFR latency test in short mode")
	}
	eng := newBenchEngine(t)
	ctx := context.Background()

	anonResp, err := eng.Anonymize(ctx, &model.AnonymizeRequest{
		TenantID:    "nfr-tenant",
		Category:    model.CategoryCustomer,
		Records:     []map[string]any{customerRecord()},
		AccessLevel: model.AccessAnonymized,
		RequesterID: "nfr-user",
		Purpose:     "nfr",
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	deReq := &model.DeanonymizeRequest{
		TenantID:      "nfr-tenant",
		Category:      model.CategoryCustomer,
		Records:       anonResp.Records,
		RequesterID:   "nfr-user",
		Justification: "nfr",
	}

	const iterations = 200
	durations := make([]time.Duration, iterations)
	for i := range durations {
		start := time.Now()
		if _, err := eng.Deanonymize(ctx, deReq); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		durations[i] = time.Since(start)
	}
	p95 := percentile(durations, 95)
	t.Logf("Deanonymize p50=%.2fms p95=%.2fms (NFR-PE-003 target: <20ms)",
		float64(percentile(durations, 50))/float64(time.Millisecond),
		float64(p95)/float64(time.Millisecond))
	if p95 > 20*time.Millisecond {
		t.Errorf("NFR-PE-003 FAIL: deanonymize p95=%.2fms exceeds 20ms limit",
			float64(p95)/float64(time.Millisecond))
	}
}

// percentile returns the n-th percentile of a sorted duration slice.
func percentile(d []time.Duration, n int) time.Duration {
	if len(d) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(d))
	copy(sorted, d)
	// Insertion sort — fast enough for 200 items.
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	idx := (n * len(sorted)) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
