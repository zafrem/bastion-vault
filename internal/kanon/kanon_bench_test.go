package kanon_test

import (
	"context"
	"testing"
	"time"

	kanon "github.com/zafrem/bastion-vault/internal/kanon"
	"github.com/zafrem/bastion-vault/internal/model"
)

func makeKAnonRecords(n int) []map[string]any {
	records := make([]map[string]any, n)
	for i := range records {
		records[i] = map[string]any{
			"address_city": "Seoul",
			"age_range":    "30-39",
			"gender":       "M",
		}
	}
	return records
}

// BenchmarkKAnonymity measures NFR-PE-004: k-anonymity check < 50 ms
func BenchmarkKAnonymity(b *testing.B) {
	v := kanon.New()
	ctx := context.Background()
	records := makeKAnonRecords(20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := v.Validate(ctx, records, model.CategoryCustomer, 5); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkKAnonymityGeneralize measures ValidateAndGeneralize throughput
func BenchmarkKAnonymityGeneralize(b *testing.B) {
	v := kanon.New()
	ctx := context.Background()
	records := makeKAnonRecords(20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := v.ValidateAndGeneralize(ctx, records, model.CategoryCustomer, 5); err != nil {
			b.Fatal(err)
		}
	}
}

// TestNFR_KAnonymity_P95_Under50ms verifies NFR-PE-004 using statistical timing.
func TestNFR_KAnonymity_P95_Under50ms(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping NFR latency test in short mode")
	}
	v := kanon.New()
	ctx := context.Background()
	records := makeKAnonRecords(20)

	const iterations = 200
	durations := make([]time.Duration, iterations)
	for i := range durations {
		start := time.Now()
		if _, err := v.Validate(ctx, records, model.CategoryCustomer, 5); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		durations[i] = time.Since(start)
	}
	p95 := kanonPercentile(durations, 95)
	t.Logf("KAnonymity p50=%.3fms p95=%.3fms (NFR-PE-004 target: <50ms)",
		float64(kanonPercentile(durations, 50))/float64(time.Millisecond),
		float64(p95)/float64(time.Millisecond))
	if p95 > 50*time.Millisecond {
		t.Errorf("NFR-PE-004 FAIL: k-anonymity p95=%.3fms exceeds 50ms limit",
			float64(p95)/float64(time.Millisecond))
	}
}

func kanonPercentile(d []time.Duration, n int) time.Duration {
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
