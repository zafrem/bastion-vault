package output

import (
	"context"
	"testing"
	"time"

	"github.com/zafrem/bastion-vault/internal/access"
	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/model"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

func newBenchProcessor(tb testing.TB) *Processor {
	tb.Helper()
	aud, err := audit.NewLogger(tb.TempDir(), false)
	if err != nil {
		tb.Fatalf("audit: %v", err)
	}
	tb.Cleanup(func() { _ = aud.Close() })
	return NewProcessor(access.NewController(""), aud, tokendb.NewMemoryStore(), nil)
}

func transformRequest() ProcessRequest {
	records := makeRecords(1, "bench-tenant", "Seoul", "30s")
	return ProcessRequest{
		RequestID: "bench-req",
		User: &model.UserContext{
			UserID:     "bench-user",
			TenantID:   "bench-tenant",
			Department: "marketing",
			Roles:      []string{"manager"},
		},
		Records:  records,
		Category: model.CategoryCustomer,
		Query:    QueryParams{Category: model.CategoryCustomer, ExpectedResultCount: 1},
	}
}

// BenchmarkTransform measures NFR-PE-002: transform (apply-permissions) p95 < 10 ms
func BenchmarkTransform(b *testing.B) {
	proc := newBenchProcessor(b)
	ctx := context.Background()
	req := transformRequest()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := proc.ApplyPermissions(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkTransformBatch measures throughput with 10-record batches
func BenchmarkTransformBatch(b *testing.B) {
	proc := newBenchProcessor(b)
	ctx := context.Background()
	records := makeRecords(10, "bench-tenant", "Seoul", "30s")
	req := ProcessRequest{
		RequestID: "bench-batch",
		User: &model.UserContext{
			UserID:     "bench-user",
			TenantID:   "bench-tenant",
			Department: "marketing",
			Roles:      []string{"manager"},
		},
		Records:  records,
		Category: model.CategoryCustomer,
		Query:    QueryParams{Category: model.CategoryCustomer, ExpectedResultCount: 10},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := proc.ApplyPermissions(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

// TestNFR_Transform_P95_Under10ms verifies NFR-PE-002 using statistical timing.
func TestNFR_Transform_P95_Under10ms(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping NFR latency test in short mode")
	}
	proc := newBenchProcessor(t)
	ctx := context.Background()
	req := transformRequest()

	const iterations = 200
	durations := make([]time.Duration, iterations)
	for i := range durations {
		start := time.Now()
		if _, err := proc.ApplyPermissions(ctx, req); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		durations[i] = time.Since(start)
	}
	p95 := transformPercentile(durations, 95)
	t.Logf("Transform p50=%.2fms p95=%.2fms (NFR-PE-002 target: <10ms)",
		float64(transformPercentile(durations, 50))/float64(time.Millisecond),
		float64(p95)/float64(time.Millisecond))
	if p95 > 10*time.Millisecond {
		t.Errorf("NFR-PE-002 FAIL: transform p95=%.2fms exceeds 10ms limit",
			float64(p95)/float64(time.Millisecond))
	}
}

func transformPercentile(d []time.Duration, n int) time.Duration {
	if len(d) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(d))
	copy(sorted, d)
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
