package kanon

import (
	"context"
	"fmt"
	"strings"

	"github.com/zafrem/bastion-vault/internal/model"
)

// quasiIdentifiers defines the fields considered quasi-identifiers per SRS §3.4.1
var quasiIdentifiers = map[model.DataCategory][]string{
	model.CategoryCustomer:      {"age_group", "gender", "region", "membership_grade"},
	model.CategoryManufacturing: {"product_category", "factory_id", "shift"},
	model.CategoryHRFinance:     {"department", "position_level", "age_group", "gender", "tenure_years"},
}

// generalizationOrder lists the hierarchy levels in ascending generalization order per SRS §3.4.2
var generalizationOrder = map[string][]string{
	"age_group":      {"5year", "10year", "decade"},
	"region":         {"gu", "si", "province"},
	"tenure_years":   {"5year", "10year"},
	"position_level": {"grade", "category"},
}

// Validator checks whether a dataset satisfies k-anonymity and can auto-generalize to meet it.
type Validator struct{}

func New() *Validator { return &Validator{} }

// Validate checks k-anonymity for the given records and required K.
func (v *Validator) Validate(_ context.Context, records []map[string]any, category model.DataCategory, requiredK int) (*model.KAnonymityReport, error) {
	qids := quasiIdentifiers[category]
	if len(qids) == 0 {
		return nil, fmt.Errorf("k-anonymity: unknown category %s", category)
	}

	groups := v.groupByQIDs(records, qids)
	violations := v.findViolations(groups, requiredK)

	minK := minGroupSize(groups)
	if minK == 0 && len(records) > 0 {
		minK = 1
	}

	return &model.KAnonymityReport{
		Valid:     len(violations) == 0,
		K:         minK,
		RequiredK: requiredK,
		Violations: violations,
	}, nil
}

// ValidateAndGeneralize checks k-anonymity, then auto-generalizes quasi-identifiers
// up the hierarchy until the dataset is K-anonymous or generalization is exhausted.
func (v *Validator) ValidateAndGeneralize(
	ctx context.Context,
	records []map[string]any,
	category model.DataCategory,
	requiredK int,
) (*model.KAnonymityReport, []map[string]any, error) {
	qids := quasiIdentifiers[category]
	current := cloneRecords(records)
	var steps []model.GeneralizationStep
	maxPasses := 5

	for pass := 0; pass < maxPasses; pass++ {
		report, err := v.Validate(ctx, current, category, requiredK)
		if err != nil {
			return nil, nil, err
		}
		if report.Valid {
			report.GeneralizationSteps = steps
			return report, current, nil
		}

		// Auto-generalize the first violating quasi-identifier
		generalized := false
		for _, qid := range qids {
			if levels, ok := generalizationOrder[qid]; ok && len(levels) > pass {
				newLevel := levels[pass]
				for _, rec := range current {
					if val, exists := rec[qid]; exists {
						rec[qid] = applyGeneralizationLevel(fmt.Sprintf("%v", val), qid, newLevel)
					}
				}
				steps = append(steps, model.GeneralizationStep{
					Field: qid,
					From:  safeLevel(levels, pass-1),
					To:    newLevel,
				})
				generalized = true
				break
			}
		}

		if !generalized {
			break
		}
	}

	report, err := v.Validate(ctx, current, category, requiredK)
	if err != nil {
		return nil, nil, err
	}
	report.GeneralizationSteps = steps
	return report, current, nil
}

func (v *Validator) groupByQIDs(records []map[string]any, qids []string) map[string]int {
	groups := make(map[string]int)
	for _, rec := range records {
		key := buildGroupKey(rec, qids)
		groups[key]++
	}
	return groups
}

func (v *Validator) findViolations(groups map[string]int, requiredK int) []model.KAnonymityViolation {
	var violations []model.KAnonymityViolation
	for key, count := range groups {
		if count < requiredK {
			violations = append(violations, model.KAnonymityViolation{
				QuasiIdentifiers: parseGroupKey(key),
				GroupSize:        count,
				RequiredSize:     requiredK,
			})
		}
	}
	return violations
}

func buildGroupKey(rec map[string]any, qids []string) string {
	var parts []string
	for _, qid := range qids {
		val := ""
		if v, ok := rec[qid]; ok {
			val = fmt.Sprintf("%v", v)
		}
		parts = append(parts, qid+"="+val)
	}
	return strings.Join(parts, "|")
}

func parseGroupKey(key string) map[string]any {
	result := make(map[string]any)
	for _, part := range strings.Split(key, "|") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			result[kv[0]] = kv[1]
		}
	}
	return result
}

func minGroupSize(groups map[string]int) int {
	min := int(^uint(0) >> 1)
	for _, v := range groups {
		if v < min {
			min = v
		}
	}
	if min == int(^uint(0)>>1) {
		return 0
	}
	return min
}

func applyGeneralizationLevel(value, field, level string) string {
	switch field {
	case "age_group":
		return generalizeAgeGroup(value, level)
	case "region":
		return generalizeRegionLevel(value, level)
	case "tenure_years":
		return generalizeTenure(value, level)
	default:
		return level + ":" + value
	}
}

func generalizeAgeGroup(value, level string) string {
	switch level {
	case "decade":
		return strings.TrimRight(value, "s0123456789") + "X대"
	default:
		return value
	}
}

func generalizeRegionLevel(value, level string) string {
	parts := strings.Fields(value)
	switch level {
	case "province":
		if len(parts) > 0 {
			return parts[0]
		}
	case "si":
		if len(parts) > 1 {
			return strings.Join(parts[:2], " ")
		}
	}
	return value
}

func generalizeTenure(value, level string) string {
	switch level {
	case "5year":
		return "5년단위:" + value
	case "10year":
		return "10년단위:" + value
	}
	return value
}

func safeLevel(levels []string, i int) string {
	if i < 0 || i >= len(levels) {
		return "original"
	}
	return levels[i]
}

func cloneRecords(records []map[string]any) []map[string]any {
	out := make([]map[string]any, len(records))
	for i, rec := range records {
		clone := make(map[string]any, len(rec))
		for k, v := range rec {
			clone[k] = v
		}
		out[i] = clone
	}
	return out
}
