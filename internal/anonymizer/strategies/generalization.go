package strategies

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// GeneralizationStrategy replaces a precise value with a broader category from
// the SRS §3.4.2 hierarchy (city, province, etc.).
type GeneralizationStrategy struct{}

func NewGeneralization() *GeneralizationStrategy { return &GeneralizationStrategy{} }

func (s *GeneralizationStrategy) Name() string     { return "generalization" }
func (s *GeneralizationStrategy) Reversible() bool { return false }

func (s *GeneralizationStrategy) Apply(_ context.Context, value string, p Params) (string, error) {
	level := p.GeneralizationLevel
	if level < 1 {
		level = 1
	}

	// Region hierarchy: dong → gu → si → province
	if gen := generalizeRegion(value, level); gen != "" {
		return gen, nil
	}
	return value, nil
}

func (s *GeneralizationStrategy) Reverse(_ context.Context, _ string, _ Params) (string, error) {
	return "", ErrNotReversible{Strategy: s.Name()}
}

// RangeGeneralizationStrategy maps a numeric or date value to a bracketed range.
type RangeGeneralizationStrategy struct{}

func NewRangeGeneralization() *RangeGeneralizationStrategy { return &RangeGeneralizationStrategy{} }

func (s *RangeGeneralizationStrategy) Name() string     { return "range_generalization" }
func (s *RangeGeneralizationStrategy) Reversible() bool { return false }

func (s *RangeGeneralizationStrategy) Apply(_ context.Context, value string, p Params) (string, error) {
	hint := strings.ToLower(p.FieldHint)
	switch {
	case strings.Contains(hint, "birth") || strings.Contains(hint, "dob") || strings.Contains(hint, "생년"):
		return generalizeDateToDecade(value)
	case strings.Contains(hint, "age") || strings.Contains(hint, "나이"):
		return generalizeAge(value, p.GeneralizationLevel)
	case strings.Contains(hint, "salary") || strings.Contains(hint, "급여") || strings.Contains(hint, "연봉"):
		return generalizeSalaryRange(value, p.GeneralizationLevel)
	default:
		return generalizeNumericRange(value, 10), nil
	}
}

func (s *RangeGeneralizationStrategy) Reverse(_ context.Context, _ string, _ Params) (string, error) {
	return "", ErrNotReversible{Strategy: s.Name()}
}

// generalizeRegion applies the SRS Korean address hierarchy.
func generalizeRegion(value string, level int) string {
	// Simplified: strip the finest-grained suffix per level.
	// In production, a full geo-hierarchy lookup table would be used.
	parts := strings.Fields(value)
	if len(parts) == 0 {
		return ""
	}
	if level >= 1 && len(parts) > 0 {
		// Remove dong-level (last part if it ends with 동/로/길)
		last := parts[len(parts)-1]
		if strings.HasSuffix(last, "동") || strings.HasSuffix(last, "로") || strings.HasSuffix(last, "길") {
			parts = parts[:len(parts)-1]
		}
	}
	if level >= 2 && len(parts) > 0 {
		last := parts[len(parts)-1]
		if strings.HasSuffix(last, "구") || strings.HasSuffix(last, "군") {
			parts = parts[:len(parts)-1]
		}
	}
	if level >= 3 && len(parts) > 0 {
		last := parts[len(parts)-1]
		if strings.HasSuffix(last, "시") || strings.HasSuffix(last, "군") {
			parts = parts[:len(parts)-1]
		}
	}
	return strings.Join(parts, " ")
}

func generalizeDateToDecade(value string) (string, error) {
	// Accept YYYY-MM-DD or YYYY/MM/DD or YYYYMMDD
	value = strings.ReplaceAll(value, "/", "-")
	parts := strings.Split(value, "-")
	if len(parts) == 0 {
		return value, nil
	}
	yearStr := parts[0]
	if len(yearStr) < 4 {
		return value, nil
	}
	year, err := strconv.Atoi(yearStr[:4])
	if err != nil {
		return value, nil
	}
	decade := (year / 10) * 10
	return fmt.Sprintf("%ds", decade), nil
}

func generalizeAge(value string, level int) (string, error) {
	age, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return value, nil
	}
	switch {
	case level >= 3:
		decade := (age / 10) * 10
		return fmt.Sprintf("%0d대", decade), nil
	case level >= 2:
		bracket := (age / 10) * 10
		return fmt.Sprintf("%d-%d", bracket, bracket+9), nil
	default:
		bracket := (age / 5) * 5
		return fmt.Sprintf("%d-%d", bracket, bracket+4), nil
	}
}

func generalizeSalaryRange(value string, level int) (string, error) {
	// Strip non-numeric characters
	cleaned := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, value)
	if cleaned == "" {
		return value, nil
	}
	n, err := strconv.ParseInt(cleaned, 10, 64)
	if err != nil {
		return value, nil
	}

	// Treat values as KRW; normalise to 만원 (10,000 KRW units)
	if n > 10000 {
		n = n / 10000
	}

	var step int64 = 500 // 500만원 brackets (level 1)
	if level >= 2 {
		step = 1000
	}
	if level >= 3 {
		// Category-based
		switch {
		case n < 3000:
			return "3000만원 미만", nil
		case n < 5000:
			return "3000-5000만원", nil
		case n < 8000:
			return "5000-8000만원", nil
		default:
			return "8000만원 이상", nil
		}
	}

	low := (n / step) * step
	high := low + step
	return fmt.Sprintf("%d-%d만원", low, high), nil
}

func generalizeNumericRange(value string, step int) string {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return value
	}
	low := (n / step) * step
	return fmt.Sprintf("%d-%d", low, low+step-1)
}
