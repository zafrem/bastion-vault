package classification_test

import (
	"testing"

	"github.com/zafrem/bastion-vault/internal/classification"
	"github.com/zafrem/bastion-vault/internal/model"
)

func TestDetectPII_KoreanRRN(t *testing.T) {
	c := classification.New()
	record := map[string]any{"resident_number": "850315-1234567"}
	dets := c.DetectPII(record)
	found := false
	for _, d := range dets {
		if d.PIIType == model.PIIKoreanRRN {
			found = true
		}
	}
	if !found {
		t.Errorf("expected korean_rrn detection for value 850315-1234567, got %+v", dets)
	}
}

func TestDetectPII_Email(t *testing.T) {
	c := classification.New()
	record := map[string]any{"email": "hong@naver.com"}
	dets := c.DetectPII(record)
	found := false
	for _, d := range dets {
		if d.PIIType == model.PIIEmail {
			found = true
		}
	}
	if !found {
		t.Errorf("expected email detection, got %+v", dets)
	}
}

func TestDetectPII_KoreanMobile(t *testing.T) {
	c := classification.New()
	record := map[string]any{"mobile": "010-1234-5678"}
	dets := c.DetectPII(record)
	found := false
	for _, d := range dets {
		if d.PIIType == model.PIIKoreanMobile {
			found = true
		}
	}
	if !found {
		t.Errorf("expected korean_mobile detection, got %+v", dets)
	}
}

func TestDetectPII_CreditCard(t *testing.T) {
	c := classification.New()
	record := map[string]any{"credit_card": "1234-5678-9012-3456"}
	dets := c.DetectPII(record)
	found := false
	for _, d := range dets {
		if d.PIIType == model.PIICreditCard {
			found = true
		}
	}
	if !found {
		t.Errorf("expected credit_card detection, got %+v", dets)
	}
}

func TestDetectPII_SalaryByFieldName(t *testing.T) {
	c := classification.New()
	// Numeric value — detection must come from field-name hint.
	record := map[string]any{"salary": 75000000}
	dets := c.DetectPII(record)
	// The classifier uses anyToString which returns "" for non-strings;
	// salary detection relies on field-name hints.
	found := false
	for _, d := range dets {
		if d.PIIType == model.PIISalary {
			found = true
		}
	}
	if !found {
		t.Errorf("expected salary detection from field name, got %+v", dets)
	}
}

func TestClassify_CustomerRecord(t *testing.T) {
	c := classification.New()
	records := []map[string]any{
		{
			"name":        "홍길동",
			"email":       "hong@naver.com",
			"rrn":         "850315-1234567",
			"credit_card": "1234-5678-9012-3456",
		},
	}
	result := c.Classify(records)
	if result.Category != model.CategoryCustomer {
		t.Errorf("expected DC-01 (customer), got %q", result.Category)
	}
}

func TestClassify_HRRecord(t *testing.T) {
	c := classification.New()
	records := []map[string]any{
		{
			"employee_id": "EMP-001",
			"salary":      "75000000",
		},
	}
	result := c.Classify(records)
	if result.Category != model.CategoryHRFinance {
		t.Errorf("expected DC-03 (hr/finance), got %q", result.Category)
	}
}

func TestDetectPII_NoFalsePositives(t *testing.T) {
	c := classification.New()
	record := map[string]any{
		"product_description": "This widget is great for general use.",
		"quantity":            "42",
		"warehouse_section":   "A3",
	}
	dets := c.DetectPII(record)
	// Some field-name hints might match; we just ensure no L1 PII is flagged.
	for _, d := range dets {
		if d.Sensitivity == model.SensitivityL1DirectIdentifier {
			t.Errorf("false positive L1 PII detected: field=%q pii_type=%q", d.Field, d.PIIType)
		}
	}
}
