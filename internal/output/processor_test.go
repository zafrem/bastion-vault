package output

import (
	"context"
	"strings"
	"testing"

	"github.com/zafrem/bastion-vault/internal/access"
	"github.com/zafrem/bastion-vault/internal/audit"
	"github.com/zafrem/bastion-vault/internal/model"
	"github.com/zafrem/bastion-vault/internal/tokendb"
)

func newTestProcessor(t *testing.T) *Processor {
	t.Helper()
	aud, err := audit.NewLogger(t.TempDir(), false)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	t.Cleanup(func() { aud.Close() })
	ctrl := access.NewController("")
	return NewProcessor(ctrl, aud, tokendb.NewMemoryStore(), nil)
}

func makeRecords(n int, tenant string, region, ageGroup string) []model.DataRecord {
	out := make([]model.DataRecord, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, model.DataRecord{
			RecordID: "rec-" + string(rune('0'+i)),
			Category: model.CategoryCustomer,
			TenantID: tenant,
			Fields: map[string]model.FieldValue{
				"age_group":        {Value: ageGroup, Type: "original"},
				"gender":           {Value: "M", Type: "original"},
				"region":           {Value: region, Type: "original"},
				"membership_grade": {Value: "gold", Type: "original"},
				"name":             {Value: "Alice", Type: "original"},
				"email":            {Value: "alice@example.com", Type: "original"},
			},
		})
	}
	return out
}

// Marketing manager → AccessFull on customer data: records pass through.
func TestProcessor_FullAccess_PassThrough(t *testing.T) {
	p := newTestProcessor(t)
	user := &model.UserContext{
		UserID:     "alice",
		TenantID:   "t1",
		Department: "marketing",
		Roles:      []string{"manager"},
	}
	resp, err := p.Process(context.Background(), ProcessRequest{
		RequestID: "r1",
		User:      user,
		Records:   makeRecords(5, "t1", "Seoul", "30s"),
		Category:  model.CategoryCustomer,
		Query:     QueryParams{Category: model.CategoryCustomer, ExpectedResultCount: 5},
	})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if resp.Decisions.AccessLevelApplied != "full" {
		t.Errorf("expected level=full, got %s", resp.Decisions.AccessLevelApplied)
	}
	if resp.Decisions.Returned != 5 {
		t.Errorf("expected 5 returned, got %d", resp.Decisions.Returned)
	}
	if v := resp.FilteredRecords[0].Fields["name"].Value; v != "Alice" {
		t.Errorf("full: name should pass through, got %v", v)
	}
}

// Marketing analyst → AccessKAnonymized: name should be hidden.
func TestProcessor_KAnonymized_HidesIdentifiers(t *testing.T) {
	p := newTestProcessor(t)
	user := &model.UserContext{
		UserID:     "anna",
		TenantID:   "t1",
		Department: "marketing",
		Roles:      []string{"analyst"},
	}
	resp, err := p.Process(context.Background(), ProcessRequest{
		RequestID: "r2",
		User:      user,
		Records:   makeRecords(5, "t1", "Seoul", "30s"),
		Category:  model.CategoryCustomer,
		Query:     QueryParams{Category: model.CategoryCustomer, ExpectedResultCount: 5},
	})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if resp.Decisions.AccessLevelApplied != "k_anonymized" {
		t.Errorf("expected level=k_anonymized, got %s", resp.Decisions.AccessLevelApplied)
	}
	if v := resp.FilteredRecords[0].Fields["name"].Value; v != "[ANONYMIZED]" {
		t.Errorf("k_anon: expected name [ANONYMIZED], got %v", v)
	}
}

// Executive → AccessAggregated: collapses to one record.
func TestProcessor_Aggregated_CollapsesToOneRecord(t *testing.T) {
	p := newTestProcessor(t)
	user := &model.UserContext{
		UserID:     "eve",
		TenantID:   "t1",
		Department: "executive",
		Roles:      []string{"executive"},
	}
	resp, err := p.Process(context.Background(), ProcessRequest{
		RequestID: "r3",
		User:      user,
		Records:   makeRecords(10, "t1", "Seoul", "30s"),
		Category:  model.CategoryCustomer,
		Query:     QueryParams{Category: model.CategoryCustomer, ExpectedResultCount: 10},
	})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if resp.Status != "AGGREGATED" {
		t.Errorf("expected status AGGREGATED, got %s", resp.Status)
	}
	if len(resp.FilteredRecords) != 1 {
		t.Fatalf("expected exactly one aggregated record, got %d", len(resp.FilteredRecords))
	}
	if v, ok := resp.FilteredRecords[0].Fields["count"]; !ok || v.Value != 10 {
		t.Errorf("expected count=10, got %v", v.Value)
	}
}

// Hr department → no customer access.
func TestProcessor_AccessDenied(t *testing.T) {
	p := newTestProcessor(t)
	user := &model.UserContext{
		UserID:     "h",
		TenantID:   "t1",
		Department: "hr",
		Roles:      []string{"manager"},
	}
	resp, err := p.Process(context.Background(), ProcessRequest{
		RequestID: "rdeny",
		User:      user,
		Records:   makeRecords(2, "t1", "Seoul", "30s"),
		Category:  model.CategoryCustomer,
		Query:     QueryParams{Category: model.CategoryCustomer, ExpectedResultCount: 2},
	})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if resp.Status != "DENIED" {
		t.Errorf("expected DENIED, got %s", resp.Status)
	}
}

// Cross-tenant: <10% mismatches → filter them out silently.
func TestProcessor_CrossTenant_LowRatio_Filters(t *testing.T) {
	p := newTestProcessor(t)
	user := &model.UserContext{
		UserID:     "alice",
		TenantID:   "t1",
		Department: "marketing",
		Roles:      []string{"manager"},
	}
	records := makeRecords(20, "t1", "Seoul", "30s")
	// Add one cross-tenant record (5% — within tolerance).
	records = append(records, model.DataRecord{
		RecordID: "evil",
		Category: model.CategoryCustomer,
		TenantID: "t2",
		Fields:   map[string]model.FieldValue{"name": {Value: "Bob"}},
	})
	resp, err := p.Process(context.Background(), ProcessRequest{
		RequestID: "rxt",
		User:      user,
		Records:   records,
		Category:  model.CategoryCustomer,
		Query:     QueryParams{Category: model.CategoryCustomer, ExpectedResultCount: 21},
	})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if resp.Decisions.FilteredOut != 1 {
		t.Errorf("expected 1 cross-tenant filtered out, got %d", resp.Decisions.FilteredOut)
	}
	if resp.Decisions.Returned != 20 {
		t.Errorf("expected 20 returned, got %d", resp.Decisions.Returned)
	}
}

// Cross-tenant: >10% mismatches → reject batch.
func TestProcessor_CrossTenant_HighRatio_Rejects(t *testing.T) {
	p := newTestProcessor(t)
	user := &model.UserContext{
		UserID:     "alice",
		TenantID:   "t1",
		Department: "marketing",
		Roles:      []string{"manager"},
	}
	// 5 good + 2 bad records = 28.5% bad ratio → reject.
	records := makeRecords(5, "t1", "Seoul", "30s")
	for i := 0; i < 2; i++ {
		records = append(records, model.DataRecord{
			RecordID: "evil",
			Category: model.CategoryCustomer,
			TenantID: "t2",
			Fields:   map[string]model.FieldValue{"name": {Value: "Bob"}},
		})
	}
	_, err := p.Process(context.Background(), ProcessRequest{
		RequestID: "rxt2",
		User:      user,
		Records:   records,
		Category:  model.CategoryCustomer,
		Query:     QueryParams{Category: model.CategoryCustomer, ExpectedResultCount: 7},
	})
	if err == nil || !strings.Contains(err.Error(), "cross-tenant") {
		t.Fatalf("expected cross-tenant rejection, got %v", err)
	}
}

// Inference detection thresholds.
func TestInferenceDetector_Thresholds(t *testing.T) {
	d := NewInferenceDetector()
	user := &model.UserContext{UserID: "u1", TenantID: "t1"}

	// First low-risk query.
	r, _ := d.Detect(context.Background(), user, QueryParams{
		Category:            model.CategoryCustomer,
		Filters:             map[string]string{"a": "1"},
		ExpectedResultCount: 100,
	})
	if r.Action != "allow" {
		t.Errorf("expected allow, got %s (score %f)", r.Action, r.Score)
	}

	// High-specificity, small-result query → expect generalize or block.
	for i := 0; i < 12; i++ {
		d.Detect(context.Background(), user, QueryParams{ //nolint:errcheck
			Category:            model.CategoryCustomer,
			Filters:             map[string]string{"a": "1", "b": "2", "c": "3", "d": "4", "e": "5", "f": "6"},
			ExpectedResultCount: 2,
		})
	}
	r2, _ := d.Detect(context.Background(), user, QueryParams{
		Category:            model.CategoryCustomer,
		Filters:             map[string]string{"a": "1", "b": "2", "c": "3", "d": "4", "e": "5", "f": "6"},
		ExpectedResultCount: 1,
	})
	if r2.Action != "block" && r2.Action != "generalize" {
		t.Errorf("expected block/generalize after stacking risky queries, got %s (score %f)", r2.Action, r2.Score)
	}
}

// K-anonymity verification: violation triggers either generalization or
// aggregation in the response.
func TestProcessor_KAnonymity_Verification(t *testing.T) {
	p := newTestProcessor(t)
	user := &model.UserContext{
		UserID:     "anna",
		TenantID:   "t1",
		Department: "marketing",
		Roles:      []string{"analyst"},
	}
	// Single record cannot satisfy K=5 → must collapse to aggregate.
	resp, err := p.Process(context.Background(), ProcessRequest{
		RequestID: "rk",
		User:      user,
		Records:   makeRecords(1, "t1", "Seoul", "30s"),
		Category:  model.CategoryCustomer,
		Query:     QueryParams{Category: model.CategoryCustomer, ExpectedResultCount: 1},
	})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if resp.Decisions.Strategy != "k_anon_failed_aggregated" && resp.Decisions.Strategy != "k_anon_generalized" {
		t.Errorf("expected k_anon failure handling, got strategy=%s", resp.Decisions.Strategy)
	}
}

// Aggregator output format: count, plus numeric stats and categorical top-N.
func TestAggregator_OutputFormat(t *testing.T) {
	a := NewAggregator()
	records := []model.DataRecord{
		{TenantID: "t1", Fields: map[string]model.FieldValue{
			"age": {Value: 30, Type: "original"}, "city": {Value: "Seoul", Type: "original"},
		}},
		{TenantID: "t1", Fields: map[string]model.FieldValue{
			"age": {Value: 40, Type: "original"}, "city": {Value: "Busan", Type: "original"},
		}},
		{TenantID: "t1", Fields: map[string]model.FieldValue{
			"age": {Value: 50, Type: "original"}, "city": {Value: "Seoul", Type: "original"},
		}},
	}
	out, err := a.Aggregate(context.Background(), records, model.CategoryCustomer)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if out.Fields["count"].Value != 3 {
		t.Errorf("expected count=3, got %v", out.Fields["count"].Value)
	}
	if out.Fields["age_min"].Value.(float64) != 30 {
		t.Errorf("expected age_min=30, got %v", out.Fields["age_min"].Value)
	}
	if out.Fields["age_max"].Value.(float64) != 50 {
		t.Errorf("expected age_max=50, got %v", out.Fields["age_max"].Value)
	}
	if out.Fields["age_mean"].Value.(float64) != 40 {
		t.Errorf("expected age_mean=40, got %v", out.Fields["age_mean"].Value)
	}
	top, ok := out.Fields["city_top"].Value.([]map[string]any)
	if !ok || len(top) == 0 {
		t.Fatalf("expected city_top distribution, got %T", out.Fields["city_top"].Value)
	}
	if top[0]["value"] != "Seoul" || top[0]["count"] != 2 {
		t.Errorf("expected Seoul=2 at top, got %v", top[0])
	}
}

func TestPermissionResolver_Caches(t *testing.T) {
	ctrl := access.NewController("")
	r := NewPermissionResolver(ctrl)
	u := &model.User{UserID: "u", TenantID: "t", Department: "marketing", Role: "manager"}
	l1, err := r.Resolve(context.Background(), u, model.CategoryCustomer)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	l2, _ := r.Resolve(context.Background(), u, model.CategoryCustomer)
	if l1 != l2 {
		t.Errorf("expected cached level to match: %s vs %s", l1, l2)
	}
	// Invalidate and re-fetch should still return the same RBAC-derived level.
	r.InvalidateCache(UserKey(u.TenantID, u.Department, u.Role, model.CategoryCustomer))
	l3, _ := r.Resolve(context.Background(), u, model.CategoryCustomer)
	if l1 != l3 {
		t.Errorf("expected post-invalidation level to match: %s vs %s", l1, l3)
	}
}

func TestCrossTenantVerifier_EmptyTenant_Errors(t *testing.T) {
	v := NewCrossTenantVerifier()
	if _, err := v.Verify(context.Background(), nil, ""); err == nil {
		t.Fatal("expected error on empty tenant id")
	}
}
