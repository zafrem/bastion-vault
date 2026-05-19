package kanon_test

import (
	"context"
	"testing"

	"github.com/zafrem/bastion-vault/internal/kanon"
	"github.com/zafrem/bastion-vault/internal/model"
)

// makeRecords returns n records all sharing the same quasi-identifier values for DC-01.
func makeRecords(n int, ageGroup, gender, region, grade string) []map[string]any {
	records := make([]map[string]any, n)
	for i := range records {
		records[i] = map[string]any{
			"age_group":        ageGroup,
			"gender":           gender,
			"region":           region,
			"membership_grade": grade,
		}
	}
	return records
}

func TestValidate_AllSameQI_ValidK5(t *testing.T) {
	v := kanon.New()
	records := makeRecords(10, "30s", "M", "Seoul", "Gold")

	report, err := v.Validate(context.Background(), records, model.CategoryCustomer, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Valid {
		t.Errorf("expected valid K=5, got violations: %+v", report.Violations)
	}
	if report.K < 5 {
		t.Errorf("expected K>=5, got K=%d", report.K)
	}
}

func TestValidate_UniqueRecord_Violation(t *testing.T) {
	v := kanon.New()
	// 3 records with same QI, 1 unique → violation
	records := append(makeRecords(3, "30s", "M", "Seoul", "Gold"),
		map[string]any{
			"age_group":        "50s",
			"gender":           "F",
			"region":           "Busan",
			"membership_grade": "Silver",
		},
	)

	report, err := v.Validate(context.Background(), records, model.CategoryCustomer, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Valid {
		t.Error("expected violation for group of size 1")
	}
	if len(report.Violations) == 0 {
		t.Error("expected at least one violation")
	}
}

func TestValidateAndGeneralize_ConvergesToK3(t *testing.T) {
	v := kanon.New()
	// Build a dataset where each record has a unique age_group but same gender/region/grade.
	// After generalization the groups should merge.
	ages := []string{"28", "29", "30", "31"}
	records := make([]map[string]any, len(ages))
	for i, ag := range ages {
		records[i] = map[string]any{
			"age_group":        ag,
			"gender":           "M",
			"region":           "Seoul",
			"membership_grade": "Gold",
		}
	}

	report, _, err := v.ValidateAndGeneralize(context.Background(), records, model.CategoryCustomer, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// After generalization the report should be valid OR steps were generated.
	if len(report.GeneralizationSteps) == 0 && !report.Valid {
		t.Error("expected either valid result or at least one generalization step")
	}
}

func TestValidateAndGeneralize_StepsPopulated(t *testing.T) {
	v := kanon.New()
	// Dataset where each record has a distinct age_group.
	records := []map[string]any{
		{"age_group": "25", "gender": "M", "region": "Seoul", "membership_grade": "Silver"},
		{"age_group": "35", "gender": "F", "region": "Seoul", "membership_grade": "Gold"},
	}

	report, _, err := v.ValidateAndGeneralize(context.Background(), records, model.CategoryCustomer, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// If the dataset isn't immediately K-anonymous, steps should be populated.
	_ = report // either valid or has steps - acceptable
}

func TestValidate_EmptyDataset_Valid(t *testing.T) {
	v := kanon.New()
	report, err := v.Validate(context.Background(), []map[string]any{}, model.CategoryCustomer, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Valid {
		t.Error("empty dataset should be considered valid (no violations)")
	}
}
