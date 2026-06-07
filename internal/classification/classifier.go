package classification

import (
	"os"
	"regexp"
	"strings"

	"github.com/zafrem/bastion-vault/internal/model"
)

// PatternSet holds the value-level fallback regexes used when a field-name hint
// does not resolve a PII type. Each field is a regex string so the whole set can
// be supplied from configuration (classification.patterns in vault.yaml). Empty
// fields fall back to the corresponding DefaultPatternSet entry.
type PatternSet struct {
	KoreanRRN    string `mapstructure:"korean_rrn"`
	KoreanMobile string `mapstructure:"korean_mobile"`
	Email        string `mapstructure:"email"`
	CreditCard   string `mapstructure:"credit_card"`
	KoreanName   string `mapstructure:"korean_name"`
	DateOfBirth  string `mapstructure:"date_of_birth"`
	Salary       string `mapstructure:"salary"`
}

// DefaultPatternSet returns the built-in fallback patterns. These are used when
// BASTION_PATTERN_DIR is not set (or a YAML file is missing) and no config
// override is provided.
func DefaultPatternSet() PatternSet {
	return PatternSet{
		KoreanRRN:    `\d{6}-[1-4]\d{6}`,
		KoreanMobile: `01[016789]-?\d{3,4}-?\d{4}`,
		Email:        `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
		CreditCard:   `\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}`,
		KoreanName:   `^[\p{Hangul}]{2,5}$`,
		DateOfBirth:  `\d{4}[-/]\d{2}[-/]\d{2}`,
		Salary:       `(?i)(salary|wage|compensation|급여|연봉)`,
	}
}

// compiledPatterns holds the compiled value-level regexes for a Classifier.
type compiledPatterns struct {
	koreanRRN, koreanMobile, email, creditCard, koreanName, dateOfBirth, salary *regexp.Regexp
}

func compilePatternSet(ps PatternSet) compiledPatterns {
	def := DefaultPatternSet()
	pick := func(override, fallback string) *regexp.Regexp {
		if override != "" {
			if re, err := regexp.Compile(override); err == nil {
				return re
			}
		}
		return regexp.MustCompile(fallback)
	}
	return compiledPatterns{
		koreanRRN:    pick(ps.KoreanRRN, def.KoreanRRN),
		koreanMobile: pick(ps.KoreanMobile, def.KoreanMobile),
		email:        pick(ps.Email, def.Email),
		creditCard:   pick(ps.CreditCard, def.CreditCard),
		koreanName:   pick(ps.KoreanName, def.KoreanName),
		dateOfBirth:  pick(ps.DateOfBirth, def.DateOfBirth),
		salary:       pick(ps.Salary, def.Salary),
	}
}

// _loadedPatterns is populated at init time from pii-pattern-engine YAML when
// BASTION_PATTERN_DIR points to the regex root of the submodule.
var _loadedPatterns map[model.PIIType][]*regexp.Regexp

func init() {
	if dir := os.Getenv("BASTION_PATTERN_DIR"); dir != "" {
		_loadedPatterns = LoadPatternsFromDir(dir)
	}
}

// piiFieldHints maps field names (lowercased) to PII type hints
var piiFieldHints = map[string]model.PIIType{
	"name":           model.PIIKoreanName,
	"성명":             model.PIIKoreanName,
	"이름":             model.PIIKoreanName,
	"rrn":            model.PIIKoreanRRN,
	"주민번호":           model.PIIKoreanRRN,
	"resident_number": model.PIIKoreanRRN,
	"mobile":         model.PIIKoreanMobile,
	"phone":          model.PIIKoreanMobile,
	"휴대폰":            model.PIIKoreanMobile,
	"전화":             model.PIIKoreanMobile,
	"email":          model.PIIEmail,
	"이메일":            model.PIIEmail,
	"address":        model.PIIAddressDetail,
	"주소":             model.PIIAddressDetail,
	"credit_card":    model.PIICreditCard,
	"card_number":    model.PIICreditCard,
	"카드번호":           model.PIICreditCard,
	"dob":            model.PIIDateOfBirth,
	"birth_date":     model.PIIDateOfBirth,
	"birthday":       model.PIIDateOfBirth,
	"생년월일":           model.PIIDateOfBirth,
	"salary":         model.PIISalary,
	"급여":             model.PIISalary,
	"연봉":             model.PIISalary,
	"worker_id":      model.PIIWorkerID,
	"employee_id":    model.PIIEmployeeID,
	"사번":             model.PIIEmployeeID,
}

var sensitivityMap = map[model.PIIType]model.SensitivityLevel{
	model.PIIKoreanRRN:    model.SensitivityL1DirectIdentifier,
	model.PIIEmail:        model.SensitivityL1DirectIdentifier,
	model.PIICreditCard:   model.SensitivityL1DirectIdentifier,
	model.PIIKoreanName:   model.SensitivityL2IndirectIdentifier,
	model.PIIKoreanMobile: model.SensitivityL2IndirectIdentifier,
	model.PIIAddressDetail: model.SensitivityL2IndirectIdentifier,
	model.PIIAddressCity:  model.SensitivityL4QuasiIdentifier,
	model.PIIDateOfBirth:  model.SensitivityL4QuasiIdentifier,
	model.PIISalary:       model.SensitivityL3SensitivePersonal,
	model.PIIWorkerID:     model.SensitivityL5Public,
	model.PIIEmployeeID:   model.SensitivityL5Public,
	model.PIIProductCode:  model.SensitivityL5Public,
}

// categoryKeywords maps field-name substrings to data categories for heuristic classification
var categoryKeywords = map[string]model.DataCategory{
	"customer":     model.CategoryCustomer,
	"member":       model.CategoryCustomer,
	"client":       model.CategoryCustomer,
	"고객":           model.CategoryCustomer,
	"credit_card":  model.CategoryCustomer,
	"product_code": model.CategoryManufacturing,
	"factory":      model.CategoryManufacturing,
	"worker_id":    model.CategoryManufacturing,
	"production":   model.CategoryManufacturing,
	"생산":           model.CategoryManufacturing,
	"employee":     model.CategoryHRFinance,
	"salary":       model.CategoryHRFinance,
	"hr":           model.CategoryHRFinance,
	"payroll":      model.CategoryHRFinance,
	"evaluation":   model.CategoryHRFinance,
	"인사":           model.CategoryHRFinance,
	"급여":           model.CategoryHRFinance,
}

var defaultKThresholds = map[model.DataCategory]int{
	model.CategoryCustomer:      5,
	model.CategoryManufacturing: 3,
	model.CategoryHRFinance:     10,
}

// Classifier detects PII fields and classifies records into data categories
type Classifier struct {
	pat compiledPatterns
}

// New builds a Classifier with the built-in default fallback patterns.
func New() *Classifier { return NewWithPatterns(DefaultPatternSet()) }

// NewWithPatterns builds a Classifier whose value-level fallback regexes come
// from ps (empty fields fall back to DefaultPatternSet).
func NewWithPatterns(ps PatternSet) *Classifier {
	return &Classifier{pat: compilePatternSet(ps)}
}

// DetectPII scans the key-value pairs of a record and returns all PII findings
func (c *Classifier) DetectPII(record map[string]any) []model.PIIDetection {
	var detections []model.PIIDetection
	for field, value := range record {
		strVal := anyToString(value)
		piiType, confidence := c.detectField(field, strVal)
		if piiType == "" {
			continue
		}
		detections = append(detections, model.PIIDetection{
			Field:       field,
			PIIType:     piiType,
			Confidence:  confidence,
			Sensitivity: sensitivityMap[piiType],
		})
	}
	return detections
}

// Classify determines the DataCategory and k-anonymity threshold for a set of records
func (c *Classifier) Classify(records []map[string]any) *model.ClassificationResult {
	if len(records) == 0 {
		return &model.ClassificationResult{
			Category:  model.CategoryCustomer,
			KThreshold: 5,
		}
	}

	var allDetections []model.PIIDetection
	for _, r := range records {
		allDetections = append(allDetections, c.DetectPII(r)...)
	}

	category := c.inferCategory(records[0])
	k := defaultKThresholds[category]

	return &model.ClassificationResult{
		Category:       category,
		Detections:     allDetections,
		KThreshold:     k,
		Recommendation: c.buildRecommendation(category, allDetections),
	}
}

func (c *Classifier) detectField(field, value string) (model.PIIType, float64) {
	lower := strings.ToLower(field)

	// Field-name hints are high confidence
	if pt, ok := piiFieldHints[lower]; ok {
		return pt, 0.95
	}

	// Partial field-name matching
	for hint, pt := range piiFieldHints {
		if strings.Contains(lower, hint) {
			return pt, 0.85
		}
	}

	// Value-pattern fallback — loaded patterns preferred, configured set as fallback.
	switch {
	case matchesLoaded(model.PIIKoreanRRN, value) || c.pat.koreanRRN.MatchString(value):
		return model.PIIKoreanRRN, 0.90
	case c.pat.email.MatchString(value):
		return model.PIIEmail, 0.90
	case c.pat.creditCard.MatchString(value):
		return model.PIICreditCard, 0.85
	case matchesLoaded(model.PIIKoreanMobile, value) || c.pat.koreanMobile.MatchString(value):
		return model.PIIKoreanMobile, 0.85
	case c.pat.dateOfBirth.MatchString(value) && (strings.Contains(lower, "birth") || strings.Contains(lower, "dob") || strings.Contains(lower, "생년")):
		return model.PIIDateOfBirth, 0.80
	case c.pat.koreanName.MatchString(value) && len([]rune(value)) <= 4:
		return model.PIIKoreanName, 0.70
	case c.pat.salary.MatchString(value):
		return model.PIISalary, 0.75
	}

	return "", 0
}

func (c *Classifier) inferCategory(sample map[string]any) model.DataCategory {
	scores := map[model.DataCategory]int{
		model.CategoryCustomer:      0,
		model.CategoryManufacturing: 0,
		model.CategoryHRFinance:     0,
	}
	for field := range sample {
		lower := strings.ToLower(field)
		for kw, cat := range categoryKeywords {
			if strings.Contains(lower, kw) {
				scores[cat]++
			}
		}
	}

	best := model.CategoryCustomer
	bestScore := -1
	for cat, score := range scores {
		if score > bestScore {
			bestScore = score
			best = cat
		}
	}
	return best
}

func (c *Classifier) buildRecommendation(cat model.DataCategory, detections []model.PIIDetection) string {
	k := defaultKThresholds[cat]
	l1Count := 0
	for _, d := range detections {
		if d.Sensitivity == model.SensitivityL1DirectIdentifier {
			l1Count++
		}
	}
	if l1Count > 0 {
		return "Apply deterministic tokenization or HMAC for L1 identifiers before storage; enforce k-anonymity K=" + itoa(k)
	}
	return "Apply partial masking for indirect identifiers; enforce k-anonymity K=" + itoa(k)
}

func anyToString(v any) string {
	if v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	default:
		return ""
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n >= 10 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	pos--
	buf[pos] = byte('0' + n)
	return string(buf[pos:])
}
